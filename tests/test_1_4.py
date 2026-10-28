"""SV1 1.4 tests: form policy, multipart capture, path params and state.

The features here are all about the request leaving the scanner exactly as a
browser would send it: hidden tokens preserved, multipart fields parsed,
OpenAPI path placeholders injected, and authenticated cookies/headers carried
into a replay command.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sv1lib import crawl, formdata, imports, net, openapi, spa, storage
from sv1lib.models import CapturedRequest, InjectionPoint, Response
from sv1lib.net import Client

FORM_HTML = (
    "<html><body>"
    "<form method='post' action='/save'>"
    "<input type='hidden' name='csrf' value='TOKEN'>"
    "<input type='password' name='pw' value='secret'>"
    "<input type='text' name='q' value='hello'>"
    "</form></body></html>"
)


class FormPolicyTests(unittest.TestCase):
    def test_hidden_and_password_are_preserved_but_not_attacked(self) -> None:
        page = crawl.parse_page("https://example.com/page", 200, FORM_HTML)
        points = crawl.points_from_page(page)
        self.assertEqual([point.param for point in points], ["q"])
        self.assertEqual(
            points[0].params,
            (("csrf", "TOKEN"), ("pw", "secret"), ("q", "hello")),
        )
        self.assertEqual(points[0].position(), 2)

    def test_hidden_and_password_are_opt_in(self) -> None:
        page = crawl.parse_page("https://example.com/page", 200, FORM_HTML)
        hidden = crawl.points_from_page(page, include_hidden=True)
        password = crawl.points_from_page(page, include_password=True)
        both = crawl.points_from_page(
            page, include_hidden=True, include_password=True
        )
        self.assertEqual([point.param for point in hidden], ["csrf", "q"])
        self.assertEqual([point.param for point in password], ["pw", "q"])
        self.assertEqual([point.param for point in both], ["csrf", "pw", "q"])

    def test_stored_second_order_and_blind_use_the_same_policy(self) -> None:
        page = crawl.parse_page("https://example.com/page", 200, FORM_HTML)
        form = page.forms[0]
        from sv1lib import blind, secondorder, stored

        self.assertEqual([item.name for item in stored._fields(form)], ["q"])
        self.assertEqual([item.name for item in secondorder._fields(form)], ["q"])
        self.assertEqual(
            [item.name for item in stored._fields(form, True, True)],
            ["csrf", "pw"],
        )
        targets = list(blind._forms([page]))
        self.assertEqual([item.name for item in targets[0][2]], ["q"])


def multipart_body(boundary: str = "----sv1") -> tuple[str, str]:
    content_type = f"multipart/form-data; boundary={boundary}"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="comment"\r\n\r\n'
        "hello\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="doc"; filename="a.txt"\r\n'
        "Content-Type: text/plain\r\n\r\nfile\r\n"
        f"--{boundary}--\r\n"
    )
    return content_type, body


class MultipartTests(unittest.TestCase):
    def test_parser_keeps_text_fields_and_drops_files(self) -> None:
        content_type, body = multipart_body()
        self.assertEqual(formdata.parse(content_type, body), [("comment", "hello")])
        self.assertTrue(formdata.is_multipart(content_type))

    def test_spa_multipart_capture_becomes_a_point(self) -> None:
        content_type, body = multipart_body()
        captured = CapturedRequest(
            url="https://example.com/api/form",
            method="POST",
            body=body,
            content_type=content_type,
        )
        points = spa._points_from_capture(captured, "https://example.com/page")
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].source, "multipart")
        self.assertEqual(points[0].param, "comment")
        self.assertIn("multipart/form-data", points[0].content_type)

    def test_imported_multipart_body_becomes_points(self) -> None:
        content_type, body = multipart_body()
        request = imports.ImportedRequest(
            method="POST",
            url="https://example.com/api/form",
            body=body,
            content_type=content_type,
        )
        points = imports._body_points(request)
        self.assertEqual([point.param for point in points], ["comment"])
        self.assertEqual(points[0].source, "multipart")


class OpenApiPathTests(unittest.TestCase):
    def _spec(self) -> dict:
        return {
            "openapi": "3.0.0",
            "servers": [{"url": "https://example.com"}],
            "paths": {
                "/users/{user}/posts/{post}": {
                    "parameters": [
                        {"name": "user", "in": "path", "schema": {"default": "ali"}},
                    ],
                    "get": {
                        "parameters": [
                            {"name": "post", "in": "path", "schema": {"default": 7}},
                            {"name": "q", "in": "query", "schema": {"default": "x"}},
                        ]
                    },
                }
            },
        }

    def test_path_parameters_are_points_not_fixed_strings(self) -> None:
        points = openapi.points(self._spec(), "https://example.com")
        path_points = [point for point in points if point.source == "path"]
        self.assertEqual({point.param for point in path_points}, {"user", "post"})
        self.assertTrue(all(point.url.endswith("/{user}/posts/{post}") for point in path_points))
        query = [point for point in points if point.source == "query"]
        self.assertEqual(len(query), 1)
        self.assertEqual(query[0].url, "https://example.com/users/ali/posts/7")

    def test_send_and_curl_encode_the_selected_path_value(self) -> None:
        points = openapi.points(self._spec(), "https://example.com")
        point = next(item for item in points if item.source == "path" and item.param == "post")
        client = Client(rps=0)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return Response(200, "ok", 0.0, url, {})

        client.request = fake_request  # type: ignore[method-assign]
        try:
            client.send(point, "' OR 1")
        finally:
            client.close()
        self.assertEqual(
            captured["url"],
            "https://example.com/users/ali/posts/%27%20OR%201",
        )
        command = net.curl(point, "' OR 1")
        self.assertIn("%27%20OR%201", command)
        self.assertNotIn("{post}", command)


class CliSurfaceTests(unittest.TestCase):
    def test_help_lists_the_new_boundaries(self) -> None:
        result = subprocess.run(
            [sys.executable, "sv1.py", "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for flag in (
            "--hidden-fields",
            "--password-fields",
            "--storage-state",
            "--save-storage-state",
        ):
            self.assertIn(flag, result.stdout)


class ContextAndCurlTests(unittest.TestCase):
    def test_form_post_gets_browser_origin_and_referer(self) -> None:
        records: list[tuple[dict[str, str], bytes]] = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format, *args):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body_in = self.rfile.read(length)
                records.append((
                    {name.lower(): value for name, value in self.headers.items()},
                    body_in,
                ))
                body = b"<html><body>ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        client = Client(base_url=base, rps=0)
        point = InjectionPoint(
            url=base + "/save",
            method="POST",
            params=(("q", "hello"),),
            param="q",
            source="form",
        )
        try:
            response = client.send(point, "payload")
        finally:
            client.close()
            server.shutdown()
            server.server_close()
        self.assertTrue(response.ok)
        headers, body = records[0]
        self.assertEqual(headers.get("origin"), base)
        self.assertIn(headers.get("referer"), (base, base + "/"))
        self.assertIn(b"q=payload", body)

    def test_repro_curl_carries_session_headers_and_cookies(self) -> None:
        class FakeClient:
            def repro_headers(self):
                return {"Authorization": "Bearer token", "X-CSRF": "abc"}

            def repro_cookies(self):
                return {"sid": "secret"}

        point = InjectionPoint(
            url="https://example.com/save",
            method="POST",
            params=(("q", "1"),),
            param="q",
            source="form",
        )
        command = net.repro_curl(FakeClient(), point, "'")
        self.assertIn("Authorization: Bearer token", command)
        self.assertIn("X-CSRF: abc", command)
        self.assertIn("sid=secret", command)
        self.assertIn("Origin: https://example.com", command)


class StorageStateTests(unittest.TestCase):
    def _state(self) -> dict:
        return {
            "cookies": [
                {"name": "sid", "value": "ok", "domain": "example.com", "path": "/"},
                {"name": "other", "value": "no", "domain": "evil.test", "path": "/"},
                {"name": "expired", "value": "old", "domain": "example.com",
                 "path": "/", "expires": 1},
            ],
            "origins": [
                {"origin": "https://example.com",
                 "localStorage": [{"name": "theme", "value": "dark"}]},
                {"origin": "https://evil.test",
                 "localStorage": [{"name": "drop", "value": "me"}]},
            ],
        }

    def test_storage_is_scoped_to_the_target(self) -> None:
        state = storage.browser_state(self._state(), "https://example.com")
        self.assertEqual([item["name"] for item in state["cookies"]], ["sid"])
        self.assertEqual([item["origin"] for item in state["origins"]],
                         ["https://example.com"])
        self.assertEqual(state["origins"][0]["localStorage"][0]["name"], "theme")
        self.assertEqual(storage.cookie_values(self._state(), "https://example.com"),
                         {"sid": "ok"})

    def test_secure_cookie_is_not_sent_to_plain_http(self) -> None:
        state = self._state()
        state["cookies"][0]["secure"] = True
        self.assertEqual(storage.cookie_values(state, "http://example.com"), {})
        self.assertEqual(
            storage.cookie_values(state, "https://example.com"),
            {"sid": "ok"},
        )
        self.assertEqual(
            storage.browser_state(state, "http://example.com")["cookies"],
            [],
        )
        self.assertEqual(
            storage.browser_state(state, "https://example.com")["cookies"][0]["name"],
            "sid",
        )

    def test_load_and_save_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "state.json")
            Path(path).write_text(json.dumps(self._state()), encoding="utf-8-sig")
            loaded = storage.load(path)
            self.assertEqual(len(loaded["cookies"]), 3)
            saved = str(Path(temporary) / "saved.json")
            storage.save(saved, loaded, "https://example.com")
            output = json.loads(Path(saved).read_text(encoding="utf-8"))
            self.assertEqual([item["name"] for item in output["cookies"]], ["sid"])

    def test_invalid_encoding_is_a_storage_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_bytes(b"\xff\xfe\x00not-json")
            with self.assertRaises(storage.StorageError):
                storage.load(str(path))


if __name__ == "__main__":
    unittest.main()
