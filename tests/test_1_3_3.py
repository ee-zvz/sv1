"""SV1 1.3.3 tests: redirect scope, header isolation, body identity."""

from __future__ import annotations

import json
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import sv1
from sv1lib import browser as browser_mod
from sv1lib import config, crawl, net, report, ssrf, stored
from sv1lib.models import Form, FormField, InjectionPoint, Page, Response, ScanStats


class RedirectServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address) -> None:
        super().__init__(address, RedirectHandler)
        self.redirect_to = ""
        self.records: list[tuple[str, dict[str, str]]] = []


class RedirectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        self.server.records.append(
            (self.path, {name.lower(): value for name, value in self.headers.items()})
        )
        if self.path == "/final":
            self._send(200, b"final")
        elif self.path == "/loop":
            self._send(302, b"", {"Location": "/loop"})
        elif self.path == "/same":
            self._send(302, b"", {"Location": "/final"})
        elif self.path == "/file":
            self._send(302, b"", {"Location": "file:///etc/passwd"})
        elif self.server.redirect_to:
            self._send(302, b"", {"Location": self.server.redirect_to})
        else:
            self._send(200, b"ok")

    def _send(self, status: int, body: bytes, headers: dict | None = None) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


class LocalServer:
    def __init__(self) -> None:
        self.httpd = RedirectServer(("127.0.0.1", 0))
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


class RedirectScopeTests(unittest.TestCase):
    def test_cross_origin_redirect_is_refused_by_default(self) -> None:
        first = make_server(self)
        second = make_server(self)
        first.httpd.redirect_to = second.url + "/final"
        client = net.Client(
            rps=0,
            base_url=first.url,
            headers={"X-Secret": "session-token"},
            cookies={"sid": "abc"},
        )
        self.addCleanup(client.close)

        response = client.fetch(first.url + "/to-second")

        self.assertFalse(response.ok)
        self.assertIn("redirect outside scan scope", response.error)
        self.assertEqual(second.httpd.records, [])
        _path, headers = first.httpd.records[0]
        self.assertEqual(headers.get("x-secret"), "session-token")
        self.assertIn("sid=abc", headers.get("cookie", ""))

    def test_scope_may_allow_a_hop_but_never_forwards_session_material(self) -> None:
        first = make_server(self)
        second = make_server(self)
        first.httpd.redirect_to = second.url + "/final"
        client = net.Client(
            rps=0,
            base_url=first.url,
            headers={"X-Secret": "session-token", "Authorization": "Bearer token"},
            cookies={"sid": "abc"},
            scope=lambda url: url.startswith(first.url) or url.startswith(second.url),
        )
        self.addCleanup(client.close)

        response = client.fetch(first.url + "/to-second")

        self.assertTrue(response.ok)
        self.assertEqual(response.url, second.url + "/final")
        _path, headers = second.httpd.records[-1]
        self.assertNotIn("x-secret", headers)
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)

    def test_same_origin_redirect_keeps_the_session(self) -> None:
        server = make_server(self)
        client = net.Client(
            rps=0,
            base_url=server.url,
            headers={"X-Secret": "session-token"},
            cookies={"sid": "abc"},
        )
        self.addCleanup(client.close)

        response = client.fetch(server.url + "/same")

        self.assertTrue(response.ok)
        self.assertEqual(response.url, server.url + "/final")
        _path, headers = server.httpd.records[-1]
        self.assertEqual(headers.get("x-secret"), "session-token")
        self.assertIn("sid=abc", headers.get("cookie", ""))

    def test_plain_http_may_upgrade_to_https_on_the_same_host(self) -> None:
        self.assertTrue(net.same_target("http://example.com/a", "https://example.com/b"))
        self.assertTrue(net.same_target("https://example.com/a", "https://example.com/b"))
        self.assertFalse(net.same_target("https://example.com/a", "http://example.com/b"))
        self.assertFalse(net.same_target("http://example.com:8080", "https://example.com:8443"))
        self.assertFalse(net.same_target("http://example.com", "https://www.example.com"))

    def test_redirect_loop_is_bounded(self) -> None:
        server = make_server(self)
        client = net.Client(rps=0, base_url=server.url)
        self.addCleanup(client.close)

        response = client.fetch(server.url + "/loop")

        self.assertFalse(response.ok)
        self.assertIn("redirect limit", response.error)
        self.assertEqual(len(server.httpd.records), config.MAX_REDIRECTS + 1)

    def test_redirect_to_a_non_http_scheme_is_refused(self) -> None:
        server = make_server(self)
        client = net.Client(rps=0, base_url=server.url)
        self.addCleanup(client.close)

        response = client.fetch(server.url + "/file")

        self.assertFalse(response.ok)
        self.assertIn("redirect scheme blocked", response.error)

    def test_scope_refusal_sends_nothing(self) -> None:
        server = make_server(self)
        client = net.Client(rps=0, base_url=server.url, scope=lambda _url: False)
        self.addCleanup(client.close)

        response = client.fetch(server.url)

        self.assertFalse(response.ok)
        self.assertIn("outside scan scope", response.error)
        self.assertEqual(server.httpd.records, [])

    def test_session_headers_are_not_baked_into_the_requests_session(self) -> None:
        client = net.Client(
            rps=0,
            base_url="https://example.com",
            headers={"Authorization": "Bearer token"},
        )
        self.addCleanup(client.close)

        self.assertEqual(client.session_headers["Authorization"], "Bearer token")
        self.assertNotIn("Authorization", client._session().headers)

    def test_cookie_point_overrides_the_jar_without_duplicating(self) -> None:
        server = make_server(self)
        client = net.Client(
            rps=0,
            base_url=server.url,
            cookies={"sid": "original", "theme": "dark"},
        )
        self.addCleanup(client.close)
        point = InjectionPoint(
            url=server.url + "/final",
            method="GET",
            params=(("sid", "injected"),),
            param="sid",
            source="cookie",
        )

        response = client.send(point, "injected")

        self.assertTrue(response.ok)
        _path, headers = server.httpd.records[-1]
        cookie = headers.get("cookie", "")
        self.assertEqual(cookie.count("sid="), 1)
        self.assertIn("sid=injected", cookie)
        self.assertIn("theme=dark", cookie)


class BrowserIsolationTests(unittest.TestCase):
    def test_session_headers_are_origin_scoped(self) -> None:
        engine = browser_mod.Browser(
            headers={"Authorization": "Bearer token"},
            base_url="https://app.example.com",
        )
        self.assertEqual(
            engine.session_headers_for("https://app.example.com/search"),
            {"Authorization": "Bearer token"},
        )
        self.assertEqual(engine.session_headers_for("https://cdn.example.net/app.js"), {})

    def test_navigation_uses_scope_when_present(self) -> None:
        engine = browser_mod.Browser(
            base_url="https://app.example.com",
            allows=lambda url: url.startswith("https://app.example.com"),
        )
        self.assertFalse(engine._blocks_navigation("https://app.example.com/a"))
        self.assertTrue(engine._blocks_navigation("https://cdn.example.net/a"))

    def test_navigation_defaults_to_the_target_origin(self) -> None:
        engine = browser_mod.Browser(base_url="https://app.example.com")
        self.assertFalse(engine._blocks_navigation("https://app.example.com/a"))
        self.assertTrue(engine._blocks_navigation("https://cdn.example.net/a"))

    def test_make_browser_passes_the_scope_predicate(self) -> None:
        args = sv1.parse_args(["-u", "https://example.com"])
        engine = sv1.make_browser(
            args, "https://example.com", allows=lambda _url: False
        )
        self.assertIsNotNone(engine.allows)
        assert engine.allows is not None
        self.assertFalse(engine.allows("https://example.com"))


class FormEndpointTests(unittest.TestCase):
    def test_action_query_is_kept(self) -> None:
        form = Form("/search?lang=en&page=2", "get", [FormField("q", "", "text")])
        endpoint = crawl.form_endpoint("https://example.com/section/page", form)
        self.assertEqual(endpoint, "https://example.com/search?lang=en&page=2")

    def test_points_keep_the_action_query(self) -> None:
        form = Form("/search?lang=en", "get", [FormField("q", "", "text")])
        page = Page(
            url="https://example.com/page",
            status=200,
            html="",
            forms=[form],
        )
        points = crawl.points_from_page(page)
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].url, "https://example.com/search?lang=en")

    def test_cross_origin_action_is_still_refused(self) -> None:
        form = Form("https://evil.example/search?lang=en", "get", [])
        self.assertEqual(crawl.form_endpoint("https://example.com/page", form), "")


class RequestIdentityTests(unittest.TestCase):
    def test_body_is_part_of_the_point_identity(self) -> None:
        first = crawl.raw_point("https://example.com/api", "q=*&page=1")[0]
        other = crawl.raw_point("https://example.com/api", "q=*&page=2")[0]
        same = crawl.raw_point("https://example.com/api", "q=*&page=1")[0]
        self.assertNotEqual(first.key(), other.key())
        self.assertEqual(first.key(), same.key())

    def test_json_templates_are_part_of_the_point_identity(self) -> None:
        first = crawl.json_points(
            "https://example.com/api", {"user": {"name": "ali"}}
        )[0]
        other = crawl.json_points(
            "https://example.com/api", {"user": {"name": "sara"}}
        )[0]
        self.assertNotEqual(first.key(), other.key())


class SsrfBodyTests(unittest.TestCase):
    def test_nested_json_keeps_siblings(self) -> None:
        data = {
            "user": {"name": "ali"},
            "items": [{"id": 1}, {"id": 2}],
        }
        point = next(
            item for item in crawl.json_points("https://example.com/api", data)
            if item.param == "items[1].id"
        )
        captured: dict = {}

        class FakeClient:
            def request(self, method, url, **kwargs):
                captured.update({"method": method, "url": url, **kwargs})
                return Response(200, "ok", 0.0, url, {})

        result = ssrf._send(FakeClient(), point, "http://127.0.0.1:8777/cb")
        self.assertIsNotNone(result)
        body = json.loads(captured["data"])
        self.assertEqual(body["user"]["name"], "ali")
        self.assertEqual(body["items"][0]["id"], 1)
        self.assertEqual(body["items"][1]["id"], "http://127.0.0.1:8777/cb")
        self.assertTrue(captured["allow_redirects"] is False)


class StoredTokenTests(unittest.TestCase):
    def test_token_is_unique_per_run(self) -> None:
        first = stored._token(1)
        second = stored._token(1)
        self.assertNotEqual(first, second)
        self.assertTrue(re.fullmatch(r"sv1stored[0-9a-f]{8}\d{2}", first))


class StatsTests(unittest.TestCase):
    def test_proof_paths_stay_separate(self) -> None:
        stats = ScanStats(confirmed=2, replayed=3, unverified=1)
        self.assertEqual(stats.verified, 5)

    def test_json_export_reports_both_paths(self) -> None:
        stats = ScanStats(confirmed=2, replayed=3, unverified=1)
        with tempfile.TemporaryDirectory() as folder:
            path = f"{folder}/out.json"
            report.export(path, [], stats, {"target": "https://example.com"})
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        self.assertEqual(payload["stats"]["verified"], 5)
        self.assertEqual(payload["stats"]["confirmed"], 2)
        self.assertEqual(payload["stats"]["replayed"], 3)
        self.assertEqual(payload["stats"]["unverified"], 1)


if __name__ == "__main__":
    unittest.main()
