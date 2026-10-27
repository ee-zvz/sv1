"""Focused coverage for the UNION and blind paths."""

from __future__ import annotations

import re
import unittest
from types import SimpleNamespace

from sv1lib import blind, union
from sv1lib.models import Form, FormField, Page, Response
from sv1lib.oob import Hit


class FakeUnionClient:
    def __init__(self, columns: int, marker: str = "") -> None:
        self.columns = columns
        self.marker = marker
        self.payloads: list[str] = []

    def send(self, _point, payload: str) -> Response:
        self.payloads.append(payload)
        if "ORDER BY" in payload:
            count = int(re.search(r"ORDER BY (\d+)", payload).group(1))
            body = "<html><body><h1>item</h1></body></html>"
            if count > self.columns:
                body = "<html><body><h1>error</h1>syntax</body></html>"
            return Response(200, body, 0.0, "", {})
        if self.marker and f"UNION SELECT NULL,'{self.marker}'" in payload:
            return Response(200, f"<html>{self.marker}</html>", 0.0, "", {})
        if "version()" in payload:
            return Response(200, "<html>MySQL 8.0.36</html>", 0.0, "", {})
        return Response(200, "<html>item</html>", 0.0, "", {})


class UnionPayloadTests(unittest.TestCase):
    def test_payload_builders(self) -> None:
        self.assertEqual(
            union._column_payload(("'", "-- -"), ["NULL", "'x'", "NULL"]),
            "1' UNION SELECT NULL,'x',NULL-- -",
        )
        self.assertEqual(
            union._order_payload(("'", "#"), 3),
            "1' ORDER BY 3#",
        )

    def test_dump_wrap_per_dialect(self) -> None:
        self.assertIn("::text", union._dump_wrap("PostgreSQL", "version()"))
        self.assertIn("CONVERT(varchar(4000)", union._dump_wrap("MSSQL", "version()"))
        self.assertIn("||", union._dump_wrap("SQLite", "version()"))
        self.assertTrue(union._dump_wrap("MySQL", "version()").startswith("CONCAT("))

    def test_column_count_binary_search(self) -> None:
        client = FakeUnionClient(columns=3)
        base = SimpleNamespace(text="item", matches=lambda text: "item" in text)
        self.assertEqual(union.column_count(client, None, base, ("'", "-- -"), False), 3)

    def test_marker_column_and_extract(self) -> None:
        marker = "sv1uabc"
        client = FakeUnionClient(columns=2, marker=marker)
        index, payload = union.marker_column(client, None, ("'", "-- -"), 2, marker)
        self.assertEqual(index, 1)
        self.assertIn(marker, payload)

        client = FakeUnionClient(columns=2)
        base = SimpleNamespace(text="no version here")
        result = union.extract(client, None, ("'", "-- -"), 2, 1, base.text)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result[0], "MySQL")
        self.assertEqual(result[2], "8.0.36")


class FakeBlindClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return SimpleNamespace(ok=True)


class BlindTests(unittest.TestCase):
    def test_usable_and_forms(self) -> None:
        self.assertTrue(blind._usable(FormField("q", "", "text")))
        self.assertFalse(blind._usable(FormField("go", "", "submit")))
        page = Page(
            "http://target/page",
            200,
            "",
            forms=[
                Form("/post", "post", [
                    FormField("q", "", "text"),
                    FormField("go", "", "submit"),
                ]),
                Form("/get", "get", [FormField("q", "", "text")]),
            ],
        )
        forms = list(blind._forms([page]))
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0][2][0].name, "q")

    def test_shapes(self) -> None:
        shapes = blind._shapes()
        self.assertEqual(len(shapes), 2)
        self.assertIn("{url}", shapes[0])

    def test_submit_encodes_fields_and_rejects_cross_origin(self) -> None:
        client = FakeBlindClient()
        form = Form("/post", "post", [
            FormField("q", "old", "text"),
            FormField("keep", "yes", "hidden"),
        ])
        result = blind._submit(client, "http://target/page", form, "q", "<svg>")
        self.assertIsNotNone(result)
        call = client.calls[0]
        self.assertEqual(call["url"], "http://target/post")
        self.assertEqual(call["data"], {"q": "<svg>", "keep": "yes"})

        external = Form("http://evil/post", "post", [FormField("q", "", "text")])
        self.assertIsNone(blind._submit(client, "http://target/page", external, "q", "x"))
        self.assertEqual(len(client.calls), 1)

    def test_sink_prefers_executed_url_then_referer_then_visit(self) -> None:
        hit = SimpleNamespace(query="p=https%3A%2F%2Fadmin.example", referer="")
        self.assertEqual(
            blind._sink(hit, None, [], "http://target/form"),
            ("https://admin.example", "GET"),
        )
        hit = SimpleNamespace(query="", referer="https://ref.example/a")
        self.assertEqual(
            blind._sink(hit, None, ["https://visit.example"], "http://target/form"),
            ("https://ref.example/a", "GET"),
        )
        script = SimpleNamespace(referer="https://script.example/a")
        self.assertEqual(
            blind._sink(None, script, [], "http://target/form"),
            ("https://script.example/a", "GET"),
        )
        self.assertEqual(
            blind._sink(None, None, ["https://visit.example"], "http://target/form"),
            ("https://visit.example", "GET"),
        )
        self.assertEqual(
            blind._sink(None, None, [], "http://target/form"),
            ("http://target/form", "POST"),
        )

    def test_run_without_forms(self) -> None:
        findings, note = blind.run(None, None, [], None, [], 0)
        self.assertEqual(findings, [])
        self.assertEqual(note, "no post forms to seed")

    def test_script_fetch_is_medium_and_never_confirmed(self) -> None:
        callback = FakeBlindCallback("script")
        client = FakeBlindClient()
        page = Page(
            "http://target/page",
            200,
            "",
            forms=[Form("/post", "post", [FormField("q", "", "text")])],
        )
        findings, note = blind.run(client, None, [page], callback, [], 0)
        self.assertEqual(len(findings), 1, note)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertEqual(findings[0].confidence, "MEDIUM")
        self.assertIn("execution not proven", findings[0].evidence)

    def test_execution_hit_is_high_and_confirmed(self) -> None:
        callback = FakeBlindCallback("exec")
        client = FakeBlindClient()
        page = Page(
            "http://target/page",
            200,
            "",
            forms=[Form("/post", "post", [FormField("q", "", "text")])],
        )
        findings, note = blind.run(client, None, [page], callback, [], 0)
        self.assertEqual(len(findings), 1, note)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].confidence, "CONFIRMED")


class FakeBlindCallback:
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.tokens: list[str] = []

    def register(self, _label: str, _kind: str) -> str:
        token = f"token{len(self.tokens):02d}"
        self.tokens.append(token)
        return token

    def url_for(self, token: str) -> str:
        return f"http://callback.test/t/{token}"

    def settle(self, *_args, **_kwargs) -> None:
        return

    def hits_for(self, token: str) -> list[Hit]:
        return [
            Hit(
                token=token,
                kind=self.kind,
                path=f"/{self.kind}/{token}",
                query="",
                method="GET",
                remote="127.0.0.1",
                user_agent="test",
                referer="http://target/page",
                at=0.0,
            )
        ]


if __name__ == "__main__":
    unittest.main()
