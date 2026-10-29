"""SV1 1.2 tests: request fidelity, context grammar, proof policy."""

from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import sv1
from sv1lib import browser as browser_mod
from sv1lib import context, crawl, domxss, net, openapi, report, secondorder, sqli, stored, xss
from sv1lib.models import Finding, InjectionPoint, Response
from sv1lib.net import Client


def query_point(params=(("id", "1"), ("id", "2"))) -> InjectionPoint:
    return InjectionPoint(
        url="https://example.com/item",
        method="GET",
        params=params,
        param="id",
        source="query",
    )


class RequestFidelityTests(unittest.TestCase):
    def test_send_preserves_duplicate_query_names(self) -> None:
        client = Client(rps=0)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return Response(200, "ok", 0.0, url, {})

        client.request = fake_request  # type: ignore[method-assign]
        try:
            client.send(query_point(), "payload")
        finally:
            client.close()
        self.assertEqual(captured["params"], [("id", "payload"), ("id", "2")])

    def test_send_preserves_duplicate_form_names(self) -> None:
        client = Client(rps=0)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return Response(200, "ok", 0.0, url, {})

        client.request = fake_request  # type: ignore[method-assign]
        point = InjectionPoint(
            url="https://example.com/form",
            method="POST",
            params=(("tag", "a"), ("tag", "b")),
            param="tag",
            source="form",
        )
        try:
            client.send(point, "payload")
        finally:
            client.close()
        self.assertEqual(captured["data"], [("tag", "payload"), ("tag", "b")])

    def test_second_named_parameter_is_replaced(self) -> None:
        client = Client(rps=0)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return Response(200, "ok", 0.0, url, {})

        client.request = fake_request  # type: ignore[method-assign]
        point = InjectionPoint(
            url="https://example.com/item",
            method="GET",
            params=(("id", "1"), ("name", "test")),
            param="name",
            source="query",
        )
        try:
            client.send(point, "payload")
        finally:
            client.close()
        self.assertEqual(captured["params"], [("id", "1"), ("name", "payload")])

    def test_get_form_uses_query_string(self) -> None:
        client = Client(rps=0)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return Response(200, "ok", 0.0, url, {})

        client.request = fake_request  # type: ignore[method-assign]
        point = InjectionPoint(
            url="https://example.com/search",
            method="GET",
            params=(("q", "old"), ("page", "2")),
            param="q",
            source="form",
        )
        try:
            client.send(point, "payload")
        finally:
            client.close()
        self.assertEqual(captured["method"], "GET")
        self.assertEqual(captured["params"], [("q", "payload"), ("page", "2")])

    def test_second_duplicate_occurrence_is_replaced(self) -> None:
        client = Client(rps=0)
        captured = {}

        def fake_request(method, url, **kwargs):
            captured.update({"method": method, "url": url, **kwargs})
            return Response(200, "ok", 0.0, url, {})

        client.request = fake_request  # type: ignore[method-assign]
        point = query_point()
        point = InjectionPoint(
            url=point.url,
            method=point.method,
            params=point.params,
            param=point.param,
            source=point.source,
            param_index=1,
        )
        try:
            client.send(point, "payload")
        finally:
            client.close()
        self.assertEqual(captured["params"], [("id", "1"), ("id", "payload")])

    def test_curl_keeps_both_values(self) -> None:
        command = net.curl(query_point(), "payload")
        self.assertIn("id=payload", command)
        self.assertIn("id=2", command)

    def test_curl_boolean_uses_the_true_branch(self) -> None:
        point = query_point((("id", "1"),))
        command = net.curl(point, "1 AND 1=1|1 AND 1=2")
        self.assertIn("1+AND+1%3D1", command)
        self.assertNotIn("1%3D2", command)

    def test_original_value_uses_the_injected_occurrence(self) -> None:
        point = query_point()
        point = InjectionPoint(
            url=point.url,
            method=point.method,
            params=point.params,
            param=point.param,
            source=point.source,
            param_index=1,
        )
        self.assertEqual(point.original(), "2")
        self.assertEqual(sqli.original_value(point), "2")

    def test_sessions_are_thread_local_but_share_cookies(self) -> None:
        client = Client(rps=0)
        try:
            main = client._session()
            with ThreadPoolExecutor(max_workers=1) as pool:
                worker = pool.submit(client._session).result()
            self.assertIsNot(main, worker)
            self.assertIs(client.cookies, main.cookies)
            self.assertIs(client.cookies, worker.cookies)
        finally:
            client.close()


class BrowserConfigTests(unittest.TestCase):
    def test_insecure_flag_maps_to_browser_certificate_errors(self) -> None:
        default = sv1.make_browser(
            sv1.parse_args(["-u", "https://example.com"]), "https://example.com"
        )
        insecure = sv1.make_browser(
            sv1.parse_args(["-u", "https://example.com", "-k"]), "https://example.com"
        )
        self.assertFalse(default.ignore_https)
        self.assertTrue(insecure.ignore_https)


class FormOriginTests(unittest.TestCase):
    def test_cross_origin_form_action_is_not_an_injection_point(self) -> None:
        page = crawl.parse_page(
            "https://example.com/page",
            200,
            '<form action="https://evil.test/collect" method="post">'
            '<input name="q" value="1"></form>',
        )
        self.assertEqual(crawl.points_from_page(page), [])

    def test_same_origin_form_action_is_still_an_injection_point(self) -> None:
        page = crawl.parse_page(
            "https://example.com/page",
            200,
            '<form action="/search" method="post">'
            '<input name="q" value="1"></form>',
        )
        points = crawl.points_from_page(page)
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].url, "https://example.com/search")
        self.assertEqual(points[0].param, "q")

    def test_get_form_and_query_on_same_parameter_are_one_point(self) -> None:
        page = crawl.parse_page(
            "https://example.com/search?q=test",
            200,
            '<form action="/search" method="get">'
            '<input name="q" value="test"></form>',
        )
        points = crawl.collect_points([page])
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].source, "query")

    def test_post_form_and_query_on_same_parameter_stay_distinct(self) -> None:
        page = crawl.parse_page(
            "https://example.com/search?q=test",
            200,
            '<form action="/search" method="post">'
            '<input name="q" value="test"></form>',
        )
        points = crawl.collect_points([page])
        self.assertEqual(len(points), 2)
        self.assertEqual({point.source for point in points}, {"query", "form"})

    def test_stored_and_second_order_skip_cross_origin_forms(self) -> None:
        page = crawl.parse_page(
            "https://example.com/page",
            200,
            '<form action="https://evil.test/collect" method="post">'
            '<input name="q" value="1"></form>',
        )

        class Engine:
            enabled = True
            submitted: list = []

            def submit_form(self, *args, **kwargs):
                self.submitted.append((args, kwargs))
                raise AssertionError("cross-origin form must not be submitted")

        class HttpClient:
            calls: list = []

            def request(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise AssertionError("cross-origin form must not be posted")

            def fetch(self, *args, **kwargs):
                raise AssertionError("cross-origin form must not be revisited")

        engine = Engine()
        client = HttpClient()
        self.assertEqual(stored.run(engine, [page], ""), [])
        self.assertEqual(secondorder.run(client, [page]), [])
        self.assertEqual(engine.submitted, [])
        self.assertEqual(client.calls, [])

    def test_browser_submit_blocks_cross_origin_form(self) -> None:
        page = crawl.parse_page(
            "https://example.com/page",
            200,
            '<form action="https://evil.test/collect" method="post">'
            '<input name="q" value="1"></form>',
        )
        engine = browser_mod.Browser(ignore_https=True)
        engine.enabled = True
        engine._context = object()
        visit = engine.submit_form(page.url, page.forms[0], "<svg/onload=alert(1)>", "q")
        self.assertIn("cross-origin", visit.error)


class ContextTests(unittest.TestCase):
    def test_title_is_raw_text(self) -> None:
        text = "<html><head><title>sv1TOKEN</title></head></html>"
        index = text.index("sv1TOKEN")
        site = context.analyze(text, index)
        self.assertEqual((site.kind, site.tag), ("raw", "title"))
        self.assertIn("</title><svg/onload=", context.payloads(site, "sv1TOKEN")[0])

    def test_textarea_and_style_are_raw_text(self) -> None:
        for tag in ("textarea", "style", "noscript"):
            text = f"<html><body><{tag}>sv1TOKEN</{tag}></body></html>"
            site = context.analyze(text, text.index("sv1TOKEN"))
            self.assertEqual((site.kind, site.tag), ("raw", tag))
            self.assertTrue(context.payloads(site, "sv1TOKEN")[0].startswith(f"</{tag}>"))

    def test_script_src_gets_a_javascript_data_url_first(self) -> None:
        for quote, call in (('"', "alert('sv1TOKEN')"), ("'", 'alert("sv1TOKEN")')):
            text = f"<script src={quote}https://cdn.example/sv1TOKEN{quote}></script>"
            site = context.analyze(text, text.index("sv1TOKEN"))
            self.assertEqual((site.kind, site.tag, site.attr), ("attr", "script", "src"))
            payloads = context.payloads(site, "sv1TOKEN")
            self.assertTrue(payloads[0].startswith("data:text/javascript,"))
            self.assertIn(call, payloads[0])
            self.assertTrue(any("</script><svg/onload=" in item for item in payloads))

    def test_script_src_unquoted_uses_a_quote_free_data_url(self) -> None:
        text = "<script src=sv1TOKEN></script>"
        site = context.analyze(text, text.index("sv1TOKEN"))
        self.assertEqual((site.kind, site.tag, site.attr, site.quote), ("attr", "script", "src", ""))
        payload = context.payloads(site, "sv1TOKEN")[0]
        self.assertEqual(payload, "data:text/javascript,alert(/sv1TOKEN/)")
        self.assertNotIn('"', payload)
        self.assertNotIn("'", payload)

    def test_unquoted_attribute_gets_a_quote_free_event_handler(self) -> None:
        text = "<div title=sv1TOKEN>x</div>"
        site = context.analyze(text, text.index("sv1TOKEN"))
        self.assertEqual((site.kind, site.attr, site.quote), ("attr", "title", ""))
        payload = context.payloads(site, "sv1TOKEN")[0]
        self.assertEqual(payload, "sv1TOKEN onmouseover=alert(/sv1TOKEN/) x=")
        self.assertNotIn('"', payload)
        self.assertNotIn("'", payload)

    def test_iframe_srcdoc_gets_markup_inside_the_attribute(self) -> None:
        text = '<iframe srcdoc="sv1TOKEN"></iframe>'
        site = context.analyze(text, text.index("sv1TOKEN"))
        self.assertEqual((site.kind, site.attr), ("attr", "srcdoc"))
        self.assertTrue(context.payloads(site, "sv1TOKEN")[0].startswith("<svg/onload="))

    def test_tagname_is_not_an_attribute(self) -> None:
        text = "<html><body><sv1TOKEN></body></html>"
        site = context.analyze(text, text.index("sv1TOKEN"))
        self.assertEqual(site.kind, "tagname")
        self.assertIn("<svg/onload=", context.payloads(site, "sv1TOKEN")[0])

    def test_quoted_event_handler_uses_a_quote_free_payload_first(self) -> None:
        for quote in ("'", '"'):
            text = f'<div onclick={quote}sv1TOKEN{quote}>x</div>'
            site = context.analyze(text, text.index("sv1TOKEN"))
            self.assertEqual((site.kind, site.attr, site.quote), ("attr", "onclick", quote))
            self.assertEqual(context.payloads(site, "sv1TOKEN")[0], "alert(/sv1TOKEN/)")

    def test_iframe_attribute_gets_a_new_srcdoc(self) -> None:
        text = "<iframe src='data:text/html, <h1>x</h1>' attribute='sv1TOKEN'></iframe>"
        site = context.analyze(text, text.index("sv1TOKEN"))
        self.assertEqual((site.kind, site.tag, site.quote), ("attr", "iframe", "'"))
        self.assertIn("srcdoc=", context.payloads(site, "sv1TOKEN")[0])

    def test_raw_attribute_closes_the_raw_element_first(self) -> None:
        for tag in ("style", "textarea"):
            text = f"<{tag} attribute='sv1TOKEN'></{tag}>"
            site = context.analyze(text, text.index("sv1TOKEN"))
            self.assertEqual((site.kind, site.tag, site.attr), ("attr", tag, "attribute"))
            self.assertIn(f"'></{tag}><svg/onload=", context.payloads(site, "sv1TOKEN")[0])

    def test_js_comment_regex_and_eval_get_context_payloads(self) -> None:
        cases = {
            '<script>var x=1; /* "sv1TOKEN" */</script>': "*/",
            "<script>var x=/sv1TOKEN/;</script>": "/;alert(",
            '<script>eval("sv1TOKEN");</script>': '");alert(',
        }
        for text, expected in cases.items():
            site = context.analyze(text, text.index("sv1TOKEN"))
            self.assertEqual(site.kind, "script", text)
            payloads = context.payloads(site, "sv1TOKEN")
            self.assertTrue(any(expected in payload for payload in payloads), text)


class ContentTypeTests(unittest.TestCase):
    class FakeClient:
        def __init__(self, ctype: str) -> None:
            self.ctype = ctype
            self.calls = 0

        def send(self, point, value: str) -> Response:
            self.calls += 1
            return Response(
                200,
                f"<html>{value}</html>",
                0.0,
                point.url,
                {"Content-Type": self.ctype},
            )

    def test_text_plain_is_not_an_xss_candidate(self) -> None:
        client = self.FakeClient("text/plain; charset=utf-8")
        self.assertEqual(xss.scan_point(client, query_point()), [])
        self.assertEqual(client.calls, 1)

    def test_json_is_not_an_xss_candidate(self) -> None:
        client = self.FakeClient("application/json")
        self.assertEqual(xss.scan_point(client, query_point()), [])
        self.assertEqual(client.calls, 1)

    def test_html_still_scans(self) -> None:
        client = self.FakeClient("text/html; charset=utf-8")
        findings = xss.scan_point(client, query_point())
        self.assertTrue(findings)
        self.assertEqual(findings[0].kind, "XSS")

    def test_svg_document_is_markup(self) -> None:
        client = self.FakeClient("image/svg+xml")
        findings = xss.scan_point(client, query_point())
        self.assertTrue(findings)
        self.assertEqual(findings[0].kind, "XSS")


class ProofPolicyTests(unittest.TestCase):
    def test_unexecuted_xss_drops_to_medium(self) -> None:
        finding = Finding(
            kind="XSS",
            severity="HIGH",
            url="https://example.com/item",
            method="GET",
            param="id",
            payload="<svg/onload=alert('sv1abc123')>",
            confidence="HIGH",
            evidence="reflected",
            technique="reflected/text",
        )
        point = query_point((("id", "1"),))
        engine = SimpleNamespace(
            visit_point=lambda *args, **kwargs: SimpleNamespace(
                fired=lambda token: False, error="", screenshot="", proof=lambda token: ""
            )
        )
        sv1.prove_xss(engine, [(finding, point)], SimpleNamespace(artifacts=""))
        self.assertEqual(finding.severity, "MEDIUM")
        self.assertEqual(finding.confidence, "MEDIUM")

    def test_executed_xss_stays_high(self) -> None:
        finding = Finding(
            kind="XSS",
            severity="HIGH",
            url="https://example.com/item",
            method="GET",
            param="id",
            payload="<svg/onload=alert('sv1abc123')>",
            confidence="MEDIUM",
            evidence="reflected",
            technique="reflected/text",
        )
        point = query_point((("id", "1"),))
        engine = SimpleNamespace(
            visit_point=lambda *args, **kwargs: SimpleNamespace(
                fired=lambda token: True,
                error="",
                screenshot="shot.png",
                proof=lambda token: "alert:sv1abc123",
            )
        )
        sv1.prove_xss(engine, [(finding, point)], SimpleNamespace(artifacts=""))
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.confidence, "CONFIRMED")

    def test_header_inputs_are_not_claimed_as_proven(self) -> None:
        finding = Finding(
            kind="XSS",
            severity="HIGH",
            url="https://example.com/item",
            method="GET",
            param="X-Test",
            payload="<svg/onload=alert('sv1abc123')>",
            confidence="HIGH",
            evidence="reflected",
            technique="reflected/text",
        )
        point = InjectionPoint(
            url="https://example.com/item",
            method="GET",
            params=(("X-Test", "1"),),
            param="X-Test",
            source="header",
        )
        engine = SimpleNamespace(visit_point=lambda *args, **kwargs: None)
        sv1.prove_xss(engine, [(finding, point)], SimpleNamespace(artifacts=""))
        self.assertEqual(finding.severity, "MEDIUM")


class OpenAPITests(unittest.TestCase):
    def test_method_is_kept_and_query_is_imported_on_every_method(self) -> None:
        spec = {
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/items/{id}": {
                    "parameters": [
                        {"name": "trace", "in": "query", "schema": {"type": "string"}}
                    ],
                    "put": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {"name": {"type": "string"}}
                                    }
                                }
                            }
                        }
                    },
                }
            },
        }
        points = openapi.points(spec, "https://example.com")
        self.assertTrue(any(point.method == "PUT" and point.source == "json" for point in points))
        self.assertTrue(any(point.method == "PUT" and point.source == "query" for point in points))


class OutputSafetyTests(unittest.TestCase):
    def test_ansi_and_control_bytes_are_removed(self) -> None:
        self.assertEqual(report.clean("\x1b[31mred\x1b[0m\x00"), "red")

    def test_csv_formula_prefix_is_defused(self) -> None:
        self.assertEqual(report.csv_cell("=cmd|calc"), "'=cmd|calc")
        self.assertEqual(report.csv_cell("+1"), "'+1")

    def test_duplicate_values_survive_csv_shape(self) -> None:
        point = query_point()
        command = net.curl(point, "x")
        self.assertIn("id=x", command)
        self.assertIn("id=2", command)


class DomVectorTests(unittest.TestCase):
    def test_referrer_vector_sets_a_referer(self) -> None:
        candidate = domxss.Candidate("document.referrer", "innerHTML", 10, "")
        vectors = domxss._vectors(candidate, "https://example.com/page", "sv1tok")
        self.assertTrue(any(vector.referer for vector in vectors))
        self.assertFalse(any(vector.init_script for vector in vectors if vector.referer))

    def test_window_name_vector_sets_window_name(self) -> None:
        candidate = domxss.Candidate("window.name", "innerHTML", 10, "")
        vectors = domxss._vectors(candidate, "https://example.com/page", "sv1tok")
        self.assertTrue(vectors)
        self.assertIn("window.name", vectors[0].init_script)

    def test_storage_and_postmessage_vectors_exist(self) -> None:
        storage = domxss.Candidate("localStorage", "innerHTML", 10, "")
        message = domxss.Candidate("postMessage event", "innerHTML", 10, "")
        self.assertTrue(domxss._vectors(storage, "https://example.com/", "sv1tok")[0].init_script)
        self.assertTrue(domxss._vectors(message, "https://example.com/", "sv1tok")[0].messages)


if __name__ == "__main__":
    unittest.main()
