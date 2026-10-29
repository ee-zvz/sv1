"""SV1 1.3 browser integration: the request body must survive Chromium.

These tests are opt-in because they launch a browser and a local server. CI
sets SV1_BROWSER_TESTS=1 after installing Playwright chromium.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sv1lib import browser as browser_mod
from sv1lib import crawl, net, spa
from sv1lib.models import InjectionPoint

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8098


class ResourceServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address) -> None:
        super().__init__(address, ResourceHandler)
        self.other_port = 0
        self.records: list[tuple[str, dict[str, str]]] = []
        self.statuses: list[int] = []


class ResourceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        self.server.records.append(
            (self.path, {name.lower(): value for name, value in self.headers.items()})
        )
        status = 200
        set_cookie = ""
        if self.path in ("/", "/cookie"):
            body = (
                "<html><body>target"
                f"<img src='http://127.0.0.1:{self.server.other_port}/pixel'>"
                "</body></html>"
            ).encode()
            ctype = "text/html; charset=utf-8"
            if self.path == "/cookie":
                set_cookie = "sid=SERVER-SET; Path=/; HttpOnly"
        elif self.path == "/login":
            body = b"login"
            ctype = "text/html; charset=utf-8"
            set_cookie = "sid=CLIENT-SET; Path=/; HttpOnly"
        elif self.path == "/needs":
            if "sid=CLIENT-SET" in self.headers.get("Cookie", ""):
                body = b"authorized"
            else:
                status = 403
                body = b"forbidden"
            ctype = "text/plain; charset=utf-8"
        elif self.path == "/reflect-header":
            body = (
                "<html><body><div>"
                + self.headers.get("X-Sv1-Test", "")
                + "</div></body></html>"
            ).encode()
            ctype = "text/html; charset=utf-8"
        elif self.path == "/reflect-cookie":
            body = (
                "<html><body><div>"
                + self.headers.get("Cookie", "")
                + "</div></body></html>"
            ).encode()
            ctype = "text/html; charset=utf-8"
        elif self.path == "/body-form":
            body = (
                "<html><body>"
                f"<form id='f' method='POST' action='http://127.0.0.1:"
                f"{self.server.other_port}/sink'>"
                "<input name='secret' value='TOKEN-123'>"
                "</form><script>document.getElementById('f').submit()</script>"
                "</body></html>"
            ).encode()
            ctype = "text/html; charset=utf-8"
        else:
            body = b"gif"
            ctype = "image/gif"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        self.wfile.write(body)
        self.server.statuses.append(status)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""
        self.server.records.append(
            ("POST " + self.path, {name.lower(): value for name, value in self.headers.items()})
        )
        self.server.statuses.append(200)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_resource_server() -> ResourceServer:
    server = ResourceServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def stop_resource_server(server: ResourceServer) -> None:
    server.shutdown()
    server.server_close()


def _ready(url: str, timeout: float = 8.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.15)
    return False


@unittest.skipUnless(
    os.environ.get("SV1_BROWSER_TESTS") == "1" and browser_mod.available(),
    "set SV1_BROWSER_TESTS=1 and install playwright chromium",
)
class BrowserCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = subprocess.Popen(
            [sys.executable, os.path.join("lab", "server.py"), str(PORT)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not _ready(f"http://127.0.0.1:{PORT}/"):
            cls.server.terminate()
            raise unittest.SkipTest("local lab did not start")
        cls.base = f"http://127.0.0.1:{PORT}"

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.server.terminate()
            cls.server.wait(timeout=5)
        except Exception:
            try:
                cls.server.kill()
            except Exception:
                pass

    def test_chromium_captures_xhr_post_body(self) -> None:
        engine = browser_mod.Browser(base_url=self.base, timeout_ms=8000)
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.explore(self.base + "/xhr-post", 1800)
        finally:
            engine.close()
        self.assertFalse(result.error)
        posts = [
            item for item in result.requests
            if item.method == "POST" and item.url.endswith("/api/xhr")
        ]
        self.assertTrue(posts)
        self.assertIn("user", posts[0].body)
        self.assertIn("application/json", posts[0].content_type.lower())
        points = spa._points_from_capture(posts[0], result.url)
        self.assertIn("user.name", {point.param for point in points})

    def test_chromium_captures_multipart_xhr_body(self) -> None:
        engine = browser_mod.Browser(base_url=self.base, timeout_ms=8000)
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.explore(self.base + "/xhr-form", 1800)
        finally:
            engine.close()
        self.assertFalse(result.error, result.error)
        posts = [
            item for item in result.requests
            if item.method == "POST" and item.url.endswith("/api/form")
        ]
        self.assertTrue(posts)
        self.assertIn("multipart/form-data", posts[0].content_type.lower())
        self.assertIn("comment", posts[0].body)
        points = spa._points_from_capture(posts[0], result.url)
        self.assertEqual([point.param for point in points], ["comment"])
        self.assertEqual(points[0].source, "multipart")

    def test_browser_proves_multipart_form_and_preserves_origin(self) -> None:
        client = net.Client(rps=0, base_url=self.base)
        self.addCleanup(client.close)
        page = client.fetch(self.base + "/upload")
        self.assertTrue(page.ok)
        parsed = crawl.parse_page(page.url, page.status, page.text)
        point = next(
            item for item in crawl.points_from_page(parsed)
            if item.source == "multipart"
        )
        marker = "sv1multipartproof"
        engine = browser_mod.Browser(base_url=self.base, timeout_ms=8000)
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.visit_point(
                point,
                f"<svg/onload=alert('{marker}')>",
                wait_ms=1200,
            )
        finally:
            engine.close()
        self.assertFalse(result.error, result.error)
        self.assertEqual(result.proof(marker), f"alert:{marker}")

    def test_browser_proves_csrf_form_with_hidden_token(self) -> None:
        client = net.Client(rps=0, base_url=self.base)
        self.addCleanup(client.close)
        page = client.fetch(self.base + "/csrf")
        parsed = crawl.parse_page(page.url, page.status, page.text)
        point = next(
            item for item in crawl.points_from_page(parsed)
            if item.param == "message"
        )
        marker = "sv1csrfproof"
        engine = browser_mod.Browser(base_url=self.base, timeout_ms=8000)
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.visit_point(
                point,
                f"<svg/onload=alert('{marker}')>",
                wait_ms=1200,
            )
        finally:
            engine.close()
        self.assertFalse(result.error, result.error)
        self.assertEqual(result.proof(marker), f"alert:{marker}")
        self.assertEqual(result.url, self.base + "/csrf")

    def test_storage_state_local_storage_is_available_and_exported(self) -> None:
        state = {
            "cookies": [],
            "origins": [
                {
                    "origin": self.base,
                    "localStorage": [{"name": "sv1", "value": "loaded"}],
                }
            ],
        }
        engine = browser_mod.Browser(
            base_url=self.base,
            storage_state=state,
            timeout_ms=8000,
        )
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.visit(self.base + "/")
            exported = engine.export_state()
        finally:
            engine.close()
        self.assertFalse(result.error, result.error)
        origins = {item["origin"]: item for item in exported.get("origins", [])}
        self.assertIn(self.base, origins)
        local = {
            item["name"]: item["value"]
            for item in origins[self.base].get("localStorage", [])
        }
        self.assertEqual(local.get("sv1"), "loaded")

    def test_session_headers_do_not_follow_a_cross_origin_subresource(self) -> None:
        target = start_resource_server()
        other = start_resource_server()
        self.addCleanup(stop_resource_server, target)
        self.addCleanup(stop_resource_server, other)
        target.other_port = int(other.server_address[1])
        target_url = f"http://127.0.0.1:{target.server_address[1]}"
        engine = browser_mod.Browser(
            headers={"X-Secret": "session"},
            base_url=target_url,
            timeout_ms=8000,
        )
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.visit(target_url + "/")
        finally:
            engine.close()
        self.assertFalse(result.error)
        self.assertTrue(other.records)
        _path, headers = other.records[-1]
        self.assertNotIn("x-secret", headers)
        self.assertNotIn("cookie", headers)

    def test_imported_cookie_cannot_reach_another_port(self) -> None:
        target = start_resource_server()
        other = start_resource_server()
        self.addCleanup(stop_resource_server, target)
        self.addCleanup(stop_resource_server, other)
        target.other_port = int(other.server_address[1])
        target_url = f"http://127.0.0.1:{target.server_address[1]}"
        engine = browser_mod.Browser(
            cookies={"sid": "SECRET"},
            base_url=target_url,
            timeout_ms=8000,
        )
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.visit(target_url + "/")
        finally:
            engine.close()
        self.assertFalse(result.error)
        self.assertTrue(target.records)
        _path, headers = target.records[0]
        self.assertIn("sid=SECRET", headers.get("cookie", ""))
        self.assertEqual(other.records, [])

    def test_server_set_cookie_cannot_reach_another_port(self) -> None:
        target = start_resource_server()
        other = start_resource_server()
        self.addCleanup(stop_resource_server, target)
        self.addCleanup(stop_resource_server, other)
        target.other_port = int(other.server_address[1])
        target_url = f"http://127.0.0.1:{target.server_address[1]}"
        engine = browser_mod.Browser(base_url=target_url, timeout_ms=8000)
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.visit(target_url + "/cookie")
            cookies = engine._context.cookies(target_url)
        finally:
            engine.close()
        self.assertFalse(result.error)
        self.assertTrue(target.records)
        self.assertTrue(any(
            cookie.get("name") == "sid" and cookie.get("value") == "SERVER-SET"
            for cookie in cookies
        ))
        self.assertEqual(other.records, [])

    def test_http_client_cookie_is_synced_into_chromium(self) -> None:
        target = start_resource_server()
        self.addCleanup(stop_resource_server, target)
        target_url = f"http://127.0.0.1:{target.server_address[1]}"
        client = net.Client(rps=0, base_url=target_url)
        self.addCleanup(client.close)

        login = client.fetch(target_url + "/login")
        self.assertTrue(login.ok)

        engine = browser_mod.Browser(base_url=target_url, timeout_ms=8000)
        try:
            self.assertTrue(engine.start(), engine.reason)
            self.assertTrue(engine.import_cookies(client.cookies))
            result = engine.visit(target_url + "/needs")
        finally:
            engine.close()

        self.assertFalse(result.error, result.error)
        self.assertTrue(any(
            path == "/needs" and "sid=CLIENT-SET" in headers.get("cookie", "")
            for path, headers in target.records
        ))
        self.assertEqual(target.statuses[-1], 200)

    def test_browser_proves_header_xss(self) -> None:
        target = start_resource_server()
        self.addCleanup(stop_resource_server, target)
        target_url = f"http://127.0.0.1:{target.server_address[1]}"
        point = InjectionPoint(
            url=target_url + "/reflect-header",
            method="GET",
            params=(("X-Sv1-Test", "old"),),
            param="X-Sv1-Test",
            source="header",
        )
        marker = "sv1headerproof"
        engine = browser_mod.Browser(base_url=target_url, timeout_ms=8000)
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.visit_point(
                point, f"<svg/onload=alert('{marker}')>", wait_ms=800,
            )
        finally:
            engine.close()
        self.assertFalse(result.error, result.error)
        self.assertEqual(result.proof(marker), f"alert:{marker}")

    def test_browser_proves_cookie_xss_and_restores_session(self) -> None:
        target = start_resource_server()
        self.addCleanup(stop_resource_server, target)
        target_url = f"http://127.0.0.1:{target.server_address[1]}"
        point = InjectionPoint(
            url=target_url + "/reflect-cookie",
            method="GET",
            params=(("probe", "old"),),
            param="probe",
            source="cookie",
        )
        marker = "sv1cookieproof"
        engine = browser_mod.Browser(
            cookies={"probe": "old", "session": "keep"},
            base_url=target_url,
            timeout_ms=8000,
        )
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.visit_point(
                point, f"<svg/onload=alert('{marker}')>", wait_ms=800,
            )
            cookies = {
                item["name"]: item["value"]
                for item in engine._context.cookies(target_url)
            }
        finally:
            engine.close()
        self.assertFalse(result.error, result.error)
        self.assertEqual(result.proof(marker), f"alert:{marker}")
        self.assertEqual(cookies.get("probe"), "old")
        self.assertEqual(cookies.get("session"), "keep")

    def test_cross_target_form_body_is_not_sent_by_chromium(self) -> None:
        target = start_resource_server()
        other = start_resource_server()
        self.addCleanup(stop_resource_server, target)
        self.addCleanup(stop_resource_server, other)
        target.other_port = int(other.server_address[1])
        target_url = f"http://127.0.0.1:{target.server_address[1]}"
        engine = browser_mod.Browser(
            base_url=target_url,
            allows=lambda _url: True,
            timeout_ms=8000,
        )
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.visit(target_url + "/body-form")
        finally:
            engine.close()

        self.assertFalse(result.error, result.error)
        self.assertTrue(any(path == "/body-form" for path, _headers in target.records))
        self.assertEqual(other.records, [])


if __name__ == "__main__":
    unittest.main()
