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
from sv1lib import spa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8098


class ResourceServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address) -> None:
        super().__init__(address, ResourceHandler)
        self.other_port = 0
        self.records: list[tuple[str, dict[str, str]]] = []


class ResourceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        self.server.records.append(
            (self.path, {name.lower(): value for name, value in self.headers.items()})
        )
        if self.path in ("/", "/cookie"):
            body = (
                "<html><body>target"
                f"<img src='http://127.0.0.1:{self.server.other_port}/pixel'>"
                "</body></html>"
            ).encode()
            ctype = "text/html; charset=utf-8"
        else:
            body = b"gif"
            ctype = "image/gif"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/cookie":
            self.send_header("Set-Cookie", "sid=SERVER-SET; Path=/; HttpOnly")
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


if __name__ == "__main__":
    unittest.main()
