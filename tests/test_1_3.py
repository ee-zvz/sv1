"""SV1 1.3 tests: imported sessions, nested JSON, SPA bodies, external JS."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import sv1
from sv1lib import crawl, domxss, imports, jsonbody, net, openapi, spa
from sv1lib.history import point_from_dict, point_to_dict
from sv1lib.models import CapturedRequest, Finding, InjectionPoint, Page, Response
from sv1lib.net import Client


class NestedJsonTests(unittest.TestCase):
    def test_every_scalar_leaf_becomes_a_point(self) -> None:
        data = {
            "user": {"name": "ali", "active": True},
            "items": [{"id": 1}, {"id": 2}],
        }
        points = crawl.json_points("https://example.com/api", data)
        labels = {point.param: point for point in points}
        self.assertEqual(set(labels), {"user.name", "user.active", "items[0].id", "items[1].id"})
        self.assertEqual(labels["user.name"].path, ("user", "name"))
        self.assertEqual(labels["items[1].id"].path, ("items", 1, "id"))
        self.assertTrue(all(point.body for point in points))

    def test_send_rebuilds_nested_template_and_keeps_siblings(self) -> None:
        data = {
            "user": {"name": "ali"},
            "items": [{"id": 1}, {"id": 2}],
        }
        point = next(
            item for item in crawl.json_points("https://example.com/api", data)
            if item.param == "items[1].id"
        )
        client = Client(rps=0)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return Response(200, "ok", 0.0, url, {})

        client.request = fake_request  # type: ignore[method-assign]
        try:
            client.send(point, "PAYLOAD")
        finally:
            client.close()
        body = json.loads(captured["data"])
        self.assertEqual(body["user"]["name"], "ali")
        self.assertEqual(body["items"][0]["id"], 1)
        self.assertEqual(body["items"][1]["id"], "PAYLOAD")
        self.assertEqual(captured["method"], "POST")

    def test_ambiguous_labels_keep_distinct_paths(self) -> None:
        points = crawl.json_points(
            "https://example.com/api",
            {"a.b": "flat", "a": {"b": "nested"}},
        )
        self.assertEqual(len(points), 2)
        self.assertEqual(len({point.key() for point in points}), 2)

    def test_scalar_root_uses_dollar_path(self) -> None:
        point = crawl.json_points("https://example.com/api", "old")[0]
        self.assertEqual(point.param, "$")
        self.assertEqual(point.path, ())

    def test_curl_keeps_nested_body(self) -> None:
        point = next(
            item for item in crawl.json_points(
                "https://example.com/api", {"user": {"name": "ali"}}
            )
            if item.param == "user.name"
        )
        command = net.curl(point, "PAY")
        self.assertIn('"user":{"name":"PAY"}', command)
        self.assertIn("Content-Type: application/json", command)

    def test_history_keeps_body_and_path(self) -> None:
        point = next(
            item for item in crawl.json_points(
                "https://example.com/api", {"user": {"name": "ali"}}
            )
            if item.param == "user.name"
        )
        restored = point_from_dict(point_to_dict(point))
        self.assertEqual(restored.body, point.body)
        self.assertEqual(restored.path, point.path)
        self.assertEqual(restored.content_type, point.content_type)


class RawBodyTests(unittest.TestCase):
    def test_raw_marker_is_replaced_once(self) -> None:
        point = crawl.raw_point(
            "https://example.com/api",
            "q=*&page=2&echo=*",
            method="PUT",
            content_type="application/x-www-form-urlencoded",
        )[0]
        client = Client(rps=0)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return Response(200, "ok", 0.0, url, {})

        client.request = fake_request  # type: ignore[method-assign]
        try:
            client.send(point, "PAY")
        finally:
            client.close()
        self.assertEqual(captured["method"], "PUT")
        self.assertEqual(captured["data"], "q=PAY&page=2&echo=*")

    def test_raw_point_requires_marker(self) -> None:
        self.assertEqual(crawl.raw_point("https://example.com", "q=1"), [])

    def test_form_point_uses_declared_method(self) -> None:
        point = InjectionPoint(
            url="https://example.com/api",
            method="PATCH",
            params=(("q", "1"),),
            param="q",
            source="form",
        )
        client = Client(rps=0)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return Response(200, "ok", 0.0, url, {})

        client.request = fake_request  # type: ignore[method-assign]
        try:
            client.send(point, "PAY")
        finally:
            client.close()
        self.assertEqual(captured["method"], "PATCH")


class ImportTests(unittest.TestCase):
    def _har(self, folder: str) -> str:
        path = os.path.join(folder, "session.har")
        payload = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://example.com/api/item?trace=1",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer secret"},
                                {"name": "Content-Type", "value": "application/json"},
                                {"name": "Cookie", "value": "sid=abc; theme=dark"},
                            ],
                            "cookies": [{"name": "sid", "value": "abc"}],
                            "postData": {
                                "mimeType": "application/json",
                                "text": '{"user":{"name":"ali"},"q":"test"}',
                            },
                        }
                    }
                ]
            }
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return path

    def test_har_session_headers_and_cookies(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            entries, note = imports.load_har(self._har(folder))
        self.assertEqual(len(entries), 1)
        self.assertIn("1 request", note)
        headers, cookies = imports.session(entries, "https://example.com")
        self.assertEqual(headers.get("Authorization"), "Bearer secret")
        self.assertNotIn("Cookie", headers)
        self.assertNotIn("Content-Type", headers)
        self.assertEqual(cookies, {"sid": "abc", "theme": "dark"})

    def test_har_points_include_query_and_nested_body(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            entries, _ = imports.load_har(self._har(folder))
        points = imports.points(entries, "https://example.com")
        labels = {point.param for point in points}
        self.assertIn("trace", labels)
        self.assertIn("user.name", labels)
        self.assertIn("q", labels)
        self.assertTrue(any(point.path == ("user", "name") for point in points))

    def test_raw_request_is_resolved_against_target(self) -> None:
        raw = (
            "POST /api/item?trace=1 HTTP/1.1\n"
            "Host: example.com\n"
            "Cookie: sid=abc\n"
            "Authorization: Bearer secret\n"
            "Content-Type: application/json\n"
            "\n"
            '{"user":{"name":"ali"}}'
        )
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "request.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(raw)
            entries, note = imports.load_request(path, "https://example.com")
        self.assertIn("1 raw request", note)
        self.assertEqual(entries[0].url, "https://example.com/api/item?trace=1")
        headers, cookies = imports.session(entries, "https://example.com")
        self.assertEqual(headers.get("Authorization"), "Bearer secret")
        self.assertEqual(cookies, {"sid": "abc"})
        points = imports.points(entries, "https://example.com")
        self.assertTrue(any(point.param == "user.name" for point in points))

    def test_imported_points_respect_scope(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            entries, _ = imports.load_har(self._har(folder))
        points = imports.points(entries, "https://example.com", allows=lambda _url: False)
        self.assertEqual(points, [])


class OpenApiNestedTests(unittest.TestCase):
    def test_nested_json_body_becomes_leaf_points(self) -> None:
        spec = {
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/orders": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json; charset=utf-8": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "customer": {
                                                "type": "object",
                                                "properties": {
                                                    "name": {"type": "string"},
                                                    "vip": {"type": "boolean"},
                                                },
                                            },
                                            "items": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "sku": {"type": "string"}
                                                    },
                                                },
                                            },
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }
        points = openapi.points(spec, "https://example.com")
        labels = {point.param for point in points if point.source == "json"}
        self.assertEqual(labels, {"customer.name", "customer.vip", "items[0].sku"})
        nested = next(point for point in points if point.param == "customer.name")
        self.assertEqual(nested.path, ("customer", "name"))
        self.assertTrue(nested.body)


class SpaCaptureTests(unittest.TestCase):
    def test_json_post_capture_becomes_nested_points(self) -> None:
        captured = CapturedRequest(
            url="https://example.com/api/search",
            method="POST",
            body='{"user":{"name":"ali"},"q":"test"}',
            content_type="application/json; charset=utf-8",
        )
        points = spa._points_from_capture(captured, "https://example.com/app")
        labels = {point.param for point in points}
        self.assertEqual(labels, {"user.name", "q"})
        self.assertTrue(all(point.method == "POST" for point in points))

    def test_post_query_and_json_body_both_become_points(self) -> None:
        captured = CapturedRequest(
            url="https://example.com/api/search?lang=en",
            method="POST",
            body='{"user":{"name":"ali"},"q":"test"}',
            content_type="application/json",
        )
        points = spa._points_from_capture(captured, "https://example.com/app")
        by_label = {point.param: point for point in points}
        self.assertEqual(set(by_label), {"lang", "user.name", "q"})
        self.assertEqual(by_label["lang"].source, "query")
        self.assertEqual(by_label["lang"].method, "POST")
        self.assertEqual(by_label["user.name"].source, "json")

    def test_form_post_capture_becomes_form_points(self) -> None:
        captured = CapturedRequest(
            url="https://example.com/api/search",
            method="POST",
            body="q=test&page=2",
            content_type="application/x-www-form-urlencoded",
        )
        points = spa._points_from_capture(captured, "https://example.com/app")
        self.assertEqual({point.param for point in points}, {"q", "page"})
        self.assertTrue(all(point.source == "form" for point in points))

    def test_cross_origin_capture_is_ignored(self) -> None:
        captured = CapturedRequest(
            url="https://evil.test/collect", method="POST", body='{"q":"1"}'
        )
        self.assertEqual(spa._points_from_capture(captured, "https://example.com/app"), [])


class ExternalDomTests(unittest.TestCase):
    def test_external_bundle_candidate_keeps_origin(self) -> None:
        page = Page(
            url="https://example.com/app",
            status=200,
            html='<script src="/app.js"></script>',
        )
        bundle = (
            "const value = location.hash.slice(1);"
            "document.getElementById('out').innerHTML = value;"
        )
        candidates = domxss.analyze(page, [(bundle, "https://example.com/app.js")])
        self.assertTrue(candidates)
        self.assertEqual(candidates[0].origin, "https://example.com/app.js")

    def test_external_scripts_are_same_origin_and_bounded(self) -> None:
        page = Page(
            url="https://example.com/app",
            status=200,
            html=(
                '<script src="https://evil.test/app.js"></script>'
                '<script src="/app.js"></script>'
            ),
        )

        class FakeClient:
            calls: list[str] = []

            def fetch(self, url: str) -> Response:
                self.calls.append(url)
                return Response(
                    200,
                    "const x = location.hash; document.body.innerHTML = x;",
                    0.0,
                    url,
                    {"Content-Type": "application/javascript"},
                )

        client = FakeClient()
        sources = domxss.external_sources(client, page)
        self.assertEqual([url for _text, url in sources], ["https://example.com/app.js"])
        self.assertEqual(client.calls, ["https://example.com/app.js"])


class ProofFallbackTests(unittest.TestCase):
    def test_reflection_without_browser_is_medium(self) -> None:
        point = InjectionPoint(
            url="https://example.com/api",
            method="POST",
            params=(("q", "1"),),
            param="q",
            source="json",
        )
        finding = Finding(
            kind="XSS",
            severity="HIGH",
            url=point.url,
            method=point.method,
            param=point.param,
            payload="<svg/onload=alert(1)>",
            confidence="HIGH",
            evidence="reflected",
            technique="reflected/text",
        )
        sv1.demote_unproven_xss([(finding, point)], "chromium unavailable")
        self.assertEqual(finding.severity, "MEDIUM")
        self.assertEqual(finding.confidence, "MEDIUM")
        self.assertIn("reflection only", finding.detail)


class JsonBodyHelperTests(unittest.TestCase):
    def test_label_and_set_value(self) -> None:
        data = {"items": [{"name": "a"}]}
        self.assertEqual(jsonbody.label(("items", 0, "name")), "items[0].name")
        changed = jsonbody.set_value(data, ("items", 0, "name"), "b")
        self.assertEqual(changed["items"][0]["name"], "b")


if __name__ == "__main__":
    unittest.main()
