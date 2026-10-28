"""Regression tests for the 1.3.5 security audit fixes."""

from __future__ import annotations

import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import requests

from sv1lib import browser as browser_mod
from sv1lib import net, scope


class BodyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address) -> None:
        super().__init__(address, BodyHandler)
        self.records: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.redirect_to = ""
        self.redirect_status = 307


class BodyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args) -> None:
        return

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""
        self.server.records.append((
            self.command,
            self.path,
            body,
            {name.lower(): value for name, value in self.headers.items()},
        ))
        return body

    def do_GET(self) -> None:
        self._read_body()
        if self.path == "/final":
            self._send(200, b"final")
        elif self.path == "/login":
            self._send(200, b"login", {"Set-Cookie": "sid=CLIENT-SET; Path=/; HttpOnly"})
        elif self.server.redirect_to:
            self._send(self.server.redirect_status, b"", {"Location": self.server.redirect_to})
        else:
            self._send(200, b"ok")

    def do_POST(self) -> None:
        self._read_body()
        if self.path == "/final":
            self._send(200, b"final")
        elif self.server.redirect_to:
            self._send(self.server.redirect_status, b"", {"Location": self.server.redirect_to})
        else:
            self._send(200, b"ok")

    do_PUT = do_POST

    def _send(self, status: int, body: bytes, headers: dict | None = None) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)


class LocalServer:
    def __init__(self) -> None:
        self.httpd = BodyServer(("127.0.0.1", 0))
        self.port = int(self.httpd.server_address[1])
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


def make_server(test: unittest.TestCase) -> LocalServer:
    server = LocalServer()
    test.addCleanup(server.close)
    return server


class RedirectBodyTests(unittest.TestCase):
    def test_cross_origin_307_does_not_forward_a_post_body(self) -> None:
        source = make_server(self)
        sink = make_server(self)
        source.httpd.redirect_to = sink.url + "/final"
        source.httpd.redirect_status = 307
        client = net.Client(
            rps=0,
            base_url=source.url,
            scope=lambda url: url.startswith(source.url) or url.startswith(sink.url),
        )
        self.addCleanup(client.close)

        response = client.request(
            "POST", source.url + "/start", data={"secret": "TOKEN-123"}
        )

        self.assertFalse(response.ok)
        self.assertIn("request body", response.error)
        self.assertEqual(sink.httpd.records, [])
        self.assertEqual(source.httpd.records[-1][2], b"secret=TOKEN-123")

    def test_cross_origin_307_does_not_forward_files(self) -> None:
        source = make_server(self)
        sink = make_server(self)
        source.httpd.redirect_to = sink.url + "/final"
        source.httpd.redirect_status = 307
        client = net.Client(
            rps=0,
            base_url=source.url,
            scope=lambda url: url.startswith(source.url) or url.startswith(sink.url),
        )
        self.addCleanup(client.close)

        response = client.request(
            "POST",
            source.url + "/start",
            files={"upload": ("secret.txt", b"TOKEN-123")},
        )

        self.assertFalse(response.ok)
        self.assertIn("request body", response.error)
        self.assertEqual(sink.httpd.records, [])
        self.assertIn(b"TOKEN-123", source.httpd.records[-1][2])

    def test_cross_origin_307_allows_a_bodyless_get(self) -> None:
        source = make_server(self)
        sink = make_server(self)
        source.httpd.redirect_to = sink.url + "/final"
        source.httpd.redirect_status = 307
        client = net.Client(
            rps=0,
            base_url=source.url,
            scope=lambda url: url.startswith(source.url) or url.startswith(sink.url),
        )
        self.addCleanup(client.close)

        response = client.fetch(source.url + "/start")

        self.assertTrue(response.ok)
        self.assertEqual(sink.httpd.records[-1][0], "GET")

    def test_same_origin_307_keeps_the_post_body(self) -> None:
        source = make_server(self)
        source.httpd.redirect_to = source.url + "/final"
        source.httpd.redirect_status = 307
        client = net.Client(rps=0, base_url=source.url)
        self.addCleanup(client.close)

        response = client.request(
            "POST", source.url + "/start", data={"secret": "TOKEN-123"}
        )

        self.assertTrue(response.ok)
        self.assertEqual(response.url, source.url + "/final")
        self.assertEqual(source.httpd.records[-1][2], b"secret=TOKEN-123")

    def test_cross_origin_301_turns_post_into_a_bodyless_get(self) -> None:
        source = make_server(self)
        sink = make_server(self)
        source.httpd.redirect_to = sink.url + "/final"
        source.httpd.redirect_status = 301
        client = net.Client(
            rps=0,
            base_url=source.url,
            scope=lambda url: url.startswith(source.url) or url.startswith(sink.url),
        )
        self.addCleanup(client.close)

        response = client.request(
            "POST", source.url + "/start", data={"secret": "TOKEN-123"}
        )

        self.assertTrue(response.ok)
        self.assertEqual(sink.httpd.records[-1][0], "GET")
        self.assertEqual(sink.httpd.records[-1][2], b"")

    def test_cross_origin_302_does_not_forward_a_put_body(self) -> None:
        source = make_server(self)
        sink = make_server(self)
        source.httpd.redirect_to = sink.url + "/final"
        source.httpd.redirect_status = 302
        client = net.Client(
            rps=0,
            base_url=source.url,
            scope=lambda url: url.startswith(source.url) or url.startswith(sink.url),
        )
        self.addCleanup(client.close)

        response = client.request(
            "PUT", source.url + "/start", data={"secret": "TOKEN-123"}
        )

        self.assertFalse(response.ok)
        self.assertIn("request body", response.error)
        self.assertEqual(sink.httpd.records, [])


class BrowserBodyGuardTests(unittest.TestCase):
    def test_cross_target_post_body_is_refused(self) -> None:
        engine = browser_mod.Browser(base_url="http://127.0.0.1:8000")
        request = SimpleNamespace(
            method="POST",
            url="http://127.0.0.1:8001/collect",
            post_data="secret=TOKEN-123",
        )
        self.assertTrue(engine._would_leak_body(request))

    def test_same_target_body_is_allowed(self) -> None:
        engine = browser_mod.Browser(base_url="http://127.0.0.1:8000")
        request = SimpleNamespace(
            method="POST",
            url="http://127.0.0.1:8000/collect",
            post_data="secret=TOKEN-123",
        )
        self.assertFalse(engine._would_leak_body(request))

    def test_cross_target_get_has_no_body_to_leak(self) -> None:
        engine = browser_mod.Browser(base_url="http://127.0.0.1:8000")
        request = SimpleNamespace(
            method="GET",
            url="http://127.0.0.1:8001/pixel",
            post_data=None,
        )
        self.assertFalse(engine._would_leak_body(request))

    def test_unreadable_cross_target_body_fails_closed(self) -> None:
        engine = browser_mod.Browser(base_url="http://127.0.0.1:8000")

        class Request:
            method = "POST"
            url = "http://127.0.0.1:8001/collect"

            @property
            def post_data(self):
                raise RuntimeError("body unavailable")

        self.assertTrue(engine._would_leak_body(Request()))


class ScopeCanonicalizationTests(unittest.TestCase):
    def test_dot_segments_cannot_escape_an_app_prefix(self) -> None:
        checked = scope.Scope([scope.Rule("*", "example.com", "/app/*")])

        self.assertFalse(checked.allows("https://example.com/app/../admin"))
        self.assertFalse(checked.allows("https://example.com/app/%2e%2e/admin"))
        self.assertFalse(checked.allows("https://example.com/app/%252e%252e/admin"))
        self.assertFalse(checked.allows("https://example.com/app/%25252e%25252e/admin"))
        self.assertFalse(checked.allows("https://example.com/app/%2525252e%2525252e/admin"))
        self.assertFalse(checked.allows("https://example.com/app/%2e%2e%2fadmin"))
        self.assertFalse(checked.allows("https://example.com/app/%5c..%5cadmin"))
        self.assertTrue(checked.allows("https://example.com/app/user"))
        self.assertTrue(checked.allows("https://example.com/app/%2e%2e/app/user"))

    def test_ipv6_scope_rules_are_parsed_and_matched(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = folder + "/scope.txt"
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "http://[::1]:8099/app/*\n"
                    "[::1]:8098\n"
                )
            checked = scope.Scope.load(path)

        self.assertTrue(checked.allows("http://[::1]:8099/app/user"))
        self.assertFalse(checked.allows("http://[::1]:8100/app/user"))
        self.assertTrue(checked.allows("http://[::1]:8098/other"))
        self.assertFalse(checked.allows("http://[::1]:8097/other"))

        any_port = scope.Scope([scope._parse("::1")])
        self.assertTrue(any_port.allows("http://[::1]:8097/other"))

    def test_url_rule_without_port_uses_the_scheme_default(self) -> None:
        checked = scope.Scope([scope._parse("https://example.com/app/*")])

        self.assertTrue(checked.allows("https://example.com/app/user"))
        self.assertFalse(checked.allows("https://example.com:8443/app/user"))

    def test_bare_host_keeps_any_port_semantics(self) -> None:
        checked = scope.Scope([scope._parse("example.com")])

        self.assertTrue(checked.allows("http://example.com:8080/"))
        self.assertTrue(checked.allows("https://example.com/"))

    def test_host_encoding_and_trailing_dot_are_canonicalized(self) -> None:
        checked = scope.Scope([scope.Rule("*", "example.com", "/")])

        self.assertTrue(checked.allows("http://%65xample.com/"))
        self.assertTrue(checked.allows("https://example.com./"))
        self.assertFalse(checked.allows("http://%65vil.com/"))

    def test_invalid_ipv6_port_is_a_scope_error(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = folder + "/scope.txt"
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("http://[::1]:99999/\n")
            with self.assertRaises(scope.ScopeError):
                scope.Scope.load(path)


class BrowserCookieImportTests(unittest.TestCase):
    class Context:
        def __init__(self) -> None:
            self.records: list[dict] = []

        def add_cookies(self, records: list[dict]) -> None:
            self.records.extend(records)

    def test_target_cookies_are_anchored_to_the_target_origin(self) -> None:
        jar = requests.cookies.RequestsCookieJar()
        jar.set("sid", "abc", domain="example.com", path="/app")
        jar.set("other", "x", domain="evil.test", path="/")

        records = net.browser_cookies(jar, "https://example.com:8443/app")

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["name"], "sid")
        self.assertEqual(records[0]["url"], "https://example.com:8443/app")
        self.assertNotIn("other", {record["name"] for record in records})

    def test_secure_cookie_is_not_imported_for_plain_http(self) -> None:
        jar = requests.cookies.RequestsCookieJar()
        jar.set("sid", "abc", domain="example.com", path="/", secure=True)

        self.assertEqual(net.browser_cookies(jar, "http://example.com/"), [])

    def test_client_jar_can_be_imported_into_a_browser_context(self) -> None:
        jar = requests.cookies.RequestsCookieJar()
        jar.set("sid", "SERVER-SET", domain="example.com", path="/")
        context = self.Context()
        engine = browser_mod.Browser(base_url="https://example.com")
        engine._context = context  # type: ignore[assignment]

        self.assertTrue(engine.import_cookies(jar))
        self.assertEqual(context.records[0]["name"], "sid")
        self.assertEqual(context.records[0]["value"], "SERVER-SET")

    def test_import_without_a_context_fails_closed(self) -> None:
        jar = requests.cookies.RequestsCookieJar()
        jar.set("sid", "SERVER-SET", domain="example.com", path="/")
        engine = browser_mod.Browser(base_url="https://example.com")

        self.assertFalse(engine.import_cookies(jar))


if __name__ == "__main__":
    unittest.main()
