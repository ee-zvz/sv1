"""SV1 1.6 tests: path coverage and scope-aware point discovery."""

from __future__ import annotations

import unittest

import sv1
from sv1lib import checkpoint, coverage, crawl, domxss, net, spa, waf
from sv1lib.models import CapturedRequest, Finding, Page, Response


class FakeClient:
    def __init__(self, pages: dict[str, str]) -> None:
        self.pages = pages
        self.calls: list[str] = []

    def fetch(self, url: str) -> Response:
        self.calls.append(url)
        body = self.pages.get(url)
        if body is None:
            return Response(404, "", 0.0, url, {"Content-Type": "text/html"})
        return Response(
            200, body, 0.0, url, {"Content-Type": "text/html; charset=utf-8"},
        )


class PathCoverageTests(unittest.TestCase):
    def test_every_path_segment_becomes_a_replayable_point(self) -> None:
        page = Page(
            url="https://app.test/api/users/42?tab=1",
            status=200,
            html="",
        )
        points = coverage.path_points([page])
        self.assertEqual(len(points), 3)
        self.assertEqual(
            [point.original() for point in points],
            ["api", "users", "42"],
        )
        target = points[-1]
        self.assertEqual(
            target.url,
            "https://app.test/api/users/{sv1_path_3}?tab=1",
        )
        self.assertEqual(
            net.path_url(target.url, [(target.param, "<x>")]),
            "https://app.test/api/users/%3Cx%3E?tab=1",
        )

    def test_path_points_are_bounded_and_skip_assets(self) -> None:
        pages = [
            Page(url="https://app.test/a/b/c", status=200, html=""),
            Page(url="https://app.test/logo.png", status=200, html=""),
        ]
        points = coverage.path_points(pages, max_points=2)
        self.assertEqual(len(points), 2)
        self.assertNotIn("logo", " ".join(point.url for point in points))

    def test_query_variants_do_not_consume_path_slots(self) -> None:
        pages = [
            Page(url="https://app.test/a/b?tab=1", status=200, html=""),
            Page(url="https://app.test/a/b?tab=2", status=200, html=""),
        ]
        points = coverage.path_points(pages)
        self.assertEqual(len(points), 2)
        self.assertEqual(
            [point.url for point in points],
            [
                "https://app.test/{sv1_path_1}/b?tab=1",
                "https://app.test/a/{sv1_path_2}?tab=1",
            ],
        )

    def test_percent_encoded_segment_is_decoded_once(self) -> None:
        page = Page(
            url="https://app.test/search/hello%20world",
            status=200,
            html="",
        )
        points = coverage.path_points([page])
        target = [point for point in points if point.original() == "hello world"]
        self.assertEqual(len(target), 1)
        self.assertEqual(
            net.path_url(target[0].url, [(target[0].param, target[0].original())]),
            "https://app.test/search/hello%20world",
        )


class PageCarrierTests(unittest.TestCase):
    def test_headers_and_cookies_follow_every_page(self) -> None:
        pages = [
            Page(url="https://app.test/one", status=200, html=""),
            Page(url="https://app.test/two", status=200, html=""),
            Page(url="https://app.test/one", status=200, html=""),
        ]
        headers = coverage.header_points(pages)
        self.assertEqual(len(headers), 6)
        self.assertEqual(
            {point.url for point in headers},
            {"https://app.test/one", "https://app.test/two"},
        )
        cookies = coverage.cookie_points(pages, {"sid": "abc"})
        self.assertEqual(len(cookies), 2)
        self.assertEqual({point.param for point in cookies}, {"sid"})

    def test_carrier_caps_are_enforced(self) -> None:
        pages = [Page(url="https://app.test/one", status=200, html="")]
        self.assertEqual(len(coverage.header_points(pages, max_points=1)), 1)
        self.assertEqual(
            len(coverage.cookie_points(pages, {"a": "1", "b": "2"}, max_points=1)),
            1,
        )


class ScopeAwareCrawlTests(unittest.TestCase):
    def test_scope_predicate_can_authorise_an_api_origin(self) -> None:
        client = FakeClient({
            "https://app.test/start": (
                '<a href="https://api.test/users/7">api</a>'
            ),
            "https://api.test/users/7": "<html>api</html>",
        })
        allows = lambda url: url.startswith(("https://app.test/", "https://api.test/"))
        pages = crawl.crawl(client, "https://app.test/start", 10, 2, allows=allows)
        self.assertEqual(
            [page.url for page in pages],
            ["https://app.test/start", "https://api.test/users/7"],
        )

    def test_without_scope_the_crawler_stays_on_origin(self) -> None:
        client = FakeClient({
            "https://app.test/start": (
                '<a href="https://api.test/users/7">api</a>'
            ),
        })
        pages = crawl.crawl(client, "https://app.test/start", 10, 2)
        self.assertEqual([page.url for page in pages], ["https://app.test/start"])

    def test_scoped_cross_origin_form_is_a_point(self) -> None:
        page = crawl.parse_page(
            "https://app.test/page",
            200,
            '<form action="https://api.test/search" method="post">'
            '<input name="q" value="1"></form>',
        )
        self.assertEqual(crawl.points_from_page(page), [])
        points = crawl.points_from_page(
            page,
            allows=lambda url: url.startswith("https://api.test/"),
        )
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].url, "https://api.test/search")


class ScopedSurfaceTests(unittest.TestCase):
    def test_scoped_xhr_capture_keeps_the_api_point(self) -> None:
        captured = CapturedRequest(
            url="https://api.test/users?id=7", method="GET",
        )
        points = spa._points_from_capture(
            captured,
            "https://app.test/",
            allows=lambda url: url.startswith("https://api.test/"),
        )
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].url, "https://api.test/users")
        self.assertEqual(points[0].param, "id")

    def test_unscoped_xhr_capture_is_ignored(self) -> None:
        captured = CapturedRequest(
            url="https://api.test/users?id=7", method="GET",
        )
        self.assertEqual(
            spa._points_from_capture(captured, "https://app.test/"), [],
        )

    def test_scoped_external_script_is_read(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def fetch(self, url: str) -> Response:
                self.calls.append(url)
                return Response(
                    200,
                    "const x = location.hash; document.body.innerHTML = x;",
                    0.0,
                    url,
                    {"Content-Type": "application/javascript"},
                )

        page = Page(
            url="https://app.test/app",
            status=200,
            html='<script src="https://cdn.test/app.js"></script>',
        )
        client = Client()
        self.assertEqual(domxss.external_sources(client, page), [])
        sources = domxss.external_sources(
            client, page, allows=lambda url: url.startswith("https://cdn.test/"),
        )
        self.assertEqual(len(sources), 1)
        self.assertIn("location.hash", sources[0][0])


class WafFingerprintTests(unittest.TestCase):
    def _response(self, headers: dict | None = None, text: str = "") -> Response:
        return Response(
            200, text, 0.0, "https://app.test/", headers or {},
        )

    def test_named_header_wins(self) -> None:
        hit = waf.detect(self._response({"CF-Ray": "8abc123"}))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.name, "Cloudflare")
        self.assertIn("cf-ray", hit.evidence)

    def test_cookie_and_body_signatures(self) -> None:
        hit = waf.detect(self._response({"Set-Cookie": "incap_ses_1=abc; Path=/"}))
        self.assertEqual(hit.name, "Imperva")
        hit = waf.detect(self._response({}, "ModSecurity: Access denied"))
        self.assertEqual(hit.name, "ModSecurity")

    def test_plain_403_is_not_a_fingerprint(self) -> None:
        self.assertIsNone(waf.detect(self._response({}, "forbidden")))
        self.assertIsNone(waf.detect(None))

    def test_probe_uses_one_response(self) -> None:
        def response() -> Response:
            return self._response({"Server": "cloudflare"})

        class Client:
            def __init__(self) -> None:
                self.calls = 0

            def fetch(self, _url: str) -> Response:
                self.calls += 1
                return response()

        client = Client()
        hit = waf.probe(client, "https://app.test/")
        self.assertEqual(hit.name, "Cloudflare")
        self.assertEqual(client.calls, 1)

    def test_probe_never_raises(self) -> None:
        class Client:
            def fetch(self, _url: str) -> Response:
                raise RuntimeError("transport")

        self.assertIsNone(waf.probe(Client(), "https://app.test/"))


class MetadataTests(unittest.TestCase):
    def test_findings_use_owasp_2025(self) -> None:
        finding = Finding(
            kind="XSS",
            severity="MEDIUM",
            url="https://app.test/",
            method="GET",
            param="q",
            payload="x",
            confidence="MEDIUM",
            evidence="reflection",
        )
        self.assertEqual(finding.owasp, "A05:2025 Injection")
        self.assertEqual(finding.cwe, "CWE-79")

    def test_path_option_is_part_of_checkpoint_compatibility(self) -> None:
        meta = {"crawl": True, "path": True}
        self.assertEqual(checkpoint._meta(meta), {"crawl": True, "path": True})
        raw = {"meta": {"crawl": True, "path": False}}
        compatible, _reason = checkpoint.compatible(raw, meta)
        self.assertFalse(compatible)

    def test_cli_accepts_path(self) -> None:
        args = sv1.parse_args(["-u", "https://app.test/", "--path"])
        self.assertTrue(args.path)


if __name__ == "__main__":
    unittest.main()
