"""SV1 1.5 tests: login bootstrap, sitemap seeds and resumable scans."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from sv1lib import auth, checkpoint, discovery, report, sarif
from sv1lib.models import Finding, InjectionPoint, ScanStats
from sv1lib.net import Client

LOGIN_PAGE = """<!doctype html>
<form method="post" action="/login">
  <input type="hidden" name="csrf" value="csrf-token">
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
  <button type="submit">sign in</button>
</form>
"""


class LoginHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        return

    def _send(self, status: int, body: str, headers: dict | None = None) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/login":
            self._send(200, LOGIN_PAGE)
        elif path == "/private":
            if "sid=ok" in (self.headers.get("Cookie") or ""):
                self._send(200, "private area")
            else:
                self._send(403, "anonymous")
        else:
            self._send(404, "missing")

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/login":
            self._send(404, "missing")
            return
        length = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(length).decode("utf-8"))
        if (
            fields.get("csrf", [""])[0] == "csrf-token"
            and fields.get("username", [""])[0] == "admin"
            and fields.get("password", [""])[0] == "secret"
        ):
            self._send(302, "", {"Location": "/private", "Set-Cookie": "sid=ok; Path=/"})
        else:
            self._send(200, "invalid credentials")


class ResumeHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        return

    def do_GET(self):
        body = f"<html><body>echo {self.path}</body></html>"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class DiscoveryHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        return

    def _send(self, status: int, body: str, content_type: str = "text/plain") -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/robots.txt":
            self._send(200, "Sitemap: /sitemap.xml\n")
        elif self.path == "/sitemap.xml":
            self._send(
                200,
                "<?xml version='1.0'?><urlset>"
                "<url><loc>/one</loc></url>"
                "<url><loc>/asset.png</loc></url>"
                "<url><loc>https://evil.test/two</loc></url>"
                "</urlset>",
                "application/xml",
            )
        else:
            self._send(404, "missing")


def serve(handler) -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class LoginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server, self.base = serve(LoginHandler)
        self.client = Client(base_url=self.base, rps=0)

    def tearDown(self) -> None:
        self.client.close()
        self.server.shutdown()
        self.server.server_close()

    def test_login_preserves_csrf_and_keeps_the_session(self) -> None:
        result = auth.login(
            self.client,
            self.base,
            login_url=self.base + "/login",
            username="admin",
            password="secret",
            check="private area",
        )
        self.assertTrue(result.ok, result.note)
        self.assertEqual(result.action, self.base + "/login")
        self.assertNotIn("secret", result.note)
        self.assertEqual(self.client.fetch(self.base + "/private").text, "private area")

    def test_wrong_password_is_not_reported_as_success(self) -> None:
        result = auth.login(
            self.client,
            self.base,
            login_url=self.base + "/login",
            username="admin",
            password="wrong",
            check="private area",
        )
        self.assertFalse(result.ok)
        self.assertIn("check string", result.note)

    def test_cli_login_confirms_the_session_before_crawling(self) -> None:
        result = subprocess.run(
            [
                sys.executable, "sv1.py", "-u", self.base + "/private",
                "--login", self.base + "/login", "--username", "admin",
                "--password", "secret", "--login-check", "private area",
                "--xss", "--no-browser", "--no-sqli", "--no-banner",
                "--fail-on", "none",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        output = result.stdout + result.stderr
        self.assertIn("login confirmed by check string", output)
        self.assertNotIn("secret", output)

    def test_text_field_named_pass_is_not_a_login_form(self) -> None:
        html = (
            '<form method="post" action="/login">'
            '<input name="pass" type="text">'
            '<input type="submit" value="go"></form>'
        )
        form, note = auth.find_form(self.base + "/login", html)
        self.assertIsNone(form)
        self.assertIn("password field", note)

    def test_login_form_is_found_without_credentials_in_the_result(self) -> None:
        form, note = auth.find_form(self.base + "/login", LOGIN_PAGE)
        self.assertEqual(note, "")
        self.assertIsNotNone(form)
        assert form is not None
        self.assertEqual(form.username.name, "username")
        self.assertEqual(form.password.name, "password")
        point = InjectionPoint(
            url=form.action,
            method="POST",
            params=tuple((field.name, field.value) for field in form.form.fields),
            param="username",
            source="form",
        )
        self.assertTrue(auth.skip_point(point, form.action))
        self.assertTrue(auth.skip_form(form.page_url, form.form, form.action))


class DiscoveryTests(unittest.TestCase):
    def test_robots_sitemap_adds_only_same_origin_pages(self) -> None:
        server, base = serve(DiscoveryHandler)
        client = Client(base_url=base, rps=0)
        try:
            seeds, note = discovery.discover(client, base)
        finally:
            client.close()
            server.shutdown()
            server.server_close()
        self.assertEqual(seeds, [base + "/one"])
        self.assertIn("sitemap", note)


class CheckpointTests(unittest.TestCase):
    def test_checkpoint_restores_points_completed_work_and_findings(self) -> None:
        point = InjectionPoint(
            url="https://example.com/item",
            method="GET",
            params=(("id", "1"),),
            param="id",
            source="query",
        )
        finding = Finding(
            kind="XSS",
            severity="MEDIUM",
            url=point.url,
            method=point.method,
            param=point.param,
            payload="<svg/onload=alert('sv1')>",
            confidence="MEDIUM",
            evidence="reflection",
        )
        stats = ScanStats(points=1, started=1.0, finished=2.0)
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "scan.json")
            checkpoint.save(
                path,
                "https://example.com",
                [point],
                {checkpoint.key(point)},
                [(finding, point)],
                stats,
                {"scanners": ["xss"], "time_based": False},
            )
            self.assertTrue(Path(path).exists())
            if os.name == "posix":
                self.assertEqual(
                    stat.S_IMODE(Path(path).stat().st_mode), 0o600,
                )
            raw = checkpoint.load(path, "https://EXAMPLE.com/")
            points, completed, pairs = checkpoint.restore(raw)
            self.assertEqual(len(points), 1)
            self.assertEqual(completed, {checkpoint.key(point)})
            self.assertEqual(len(pairs), 1)
            self.assertEqual(pairs[0][0].cwe, "CWE-79")
            self.assertEqual(checkpoint.summary(raw).split(",")[0], "1/1 point(s)")

    def test_checkpoint_refuses_another_target(self) -> None:
        point = InjectionPoint(
            url="https://example.com/",
            method="GET",
            params=(("q", "1"),),
            param="q",
            source="query",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "scan.json")
            checkpoint.save(path, "https://example.com", [point], set(), [], None, {})
            with self.assertRaises(checkpoint.CheckpointError):
                checkpoint.load(path, "https://other.example")

    def test_checkpoint_option_mismatch_is_rejected(self) -> None:
        raw = {"meta": {"scanners": ["xss"], "time_based": False}}
        okay, _ = checkpoint.compatible(raw, {"scanners": ["xss"], "time_based": False})
        self.assertTrue(okay)
        okay, reason = checkpoint.compatible(raw, {"scanners": ["sqli"]})
        self.assertFalse(okay)
        self.assertIn("scanners", reason)
        authenticated = {"meta": {"scanners": ["xss"], "login": True}}
        okay, reason = checkpoint.compatible(authenticated, {"scanners": ["xss"]})
        self.assertFalse(okay)
        self.assertIn("login", reason)
        fields = {"meta": {"hidden_fields": False, "password_fields": False}}
        okay, reason = checkpoint.compatible(
            fields, {"hidden_fields": True, "password_fields": False},
        )
        self.assertFalse(okay)
        self.assertIn("hidden_fields", reason)


class ResumeCliTests(unittest.TestCase):
    def test_second_run_skips_completed_points_from_checkpoint(self) -> None:
        server, base = serve(ResumeHandler)
        target = base + "/echo?q=test"
        try:
            with tempfile.TemporaryDirectory() as temporary:
                checkpoint_path = str(Path(temporary) / "resume.json")
                command = [
                    sys.executable, "sv1.py", "-u", target,
                    "--xss", "--no-browser", "--no-sqli", "--no-banner",
                    "--threads", "1", "--rps", "0", "--fail-on", "none",
                    "--resume", checkpoint_path,
                ]
                first = subprocess.run(
                    command, capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=60,
                )
                self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
                self.assertTrue(Path(checkpoint_path).exists())
                second = subprocess.run(
                    command, capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=60,
                )
                self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
                output = second.stdout + second.stderr
                self.assertIn("already complete, 0 pending", output)
        finally:
            server.shutdown()
            server.server_close()


class FindingMetadataTests(unittest.TestCase):
    def test_severity_classification_and_exports_share_metadata(self) -> None:
        finding = Finding(
            kind="SQLI",
            severity="CRITICAL",
            url="https://example.com/item?id=1",
            method="GET",
            param="id",
            payload="'",
            confidence="HIGH",
            evidence="syntax error",
        )
        self.assertEqual(finding.cwe, "CWE-89")
        self.assertIn("Injection", finding.owasp)
        self.assertIn("parameterized", finding.remediation.lower())
        self.assertEqual(finding.to_row()["cwe"], "CWE-89")
        self.assertIn("parameterized", finding.to_row()["remediation"].lower())

        stats = ScanStats(points=1, started=1.0, finished=2.0)
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "out.csv")
            report.export(path, [finding], stats, {"target": "https://example.com"})
            text = Path(path).read_text(encoding="utf-8-sig")
            self.assertIn("cwe", text.splitlines()[0])
            self.assertIn("remediation", text.splitlines()[0])
            self.assertIn("CWE-89", text)
            self.assertIn("parameterized", text.lower())

            report_path = str(Path(temporary) / "out.sarif")
            sarif.write(report_path, [finding], stats, {"target": "https://example.com"})
            document = json.loads(Path(report_path).read_text(encoding="utf-8"))
            props = document["runs"][0]["results"][0]["properties"]
            self.assertEqual(props["cwe"], "CWE-89")
            self.assertIn("A03:2021", props["owasp"])


class CliSurfaceTests(unittest.TestCase):
    def test_help_lists_auth_and_resume_options(self) -> None:
        result = subprocess.run(
            [sys.executable, "sv1.py", "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for flag in ("--login", "--username", "--password", "--sitemap", "--resume"):
            self.assertIn(flag, result.stdout)


if __name__ == "__main__":
    unittest.main()
