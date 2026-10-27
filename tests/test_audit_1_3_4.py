"""Regression tests for the 1.3.4 audit fixes."""

from __future__ import annotations

import contextlib
import io
import unittest

import requests

import sv1
from sv1lib import net, sqli, verify
from sv1lib.models import Finding, InjectionPoint, Response


def point() -> InjectionPoint:
    return InjectionPoint(
        url="https://example.com/item",
        method="GET",
        params=(("id", "1"),),
        param="id",
        source="query",
    )


def finding(technique: str, payload: str, data: dict[str, str] | None = None) -> Finding:
    return Finding(
        kind="SQLI",
        severity="CRITICAL",
        url="https://example.com/item",
        method="GET",
        param="id",
        payload=payload,
        confidence="HIGH",
        evidence="test",
        technique=technique,
        data=data or {},
    )


class RequestSafetyTests(unittest.TestCase):
    def test_zero_timeout_is_rejected_by_cli_and_client(self) -> None:
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            sv1.parse_args(["-u", "https://example.com", "--timeout", "0"])
        with self.assertRaises(ValueError):
            net.Client(timeout=0)

    def test_origin_strips_credentials_and_keeps_ipv6(self) -> None:
        self.assertEqual(
            net.origin("http://user:secret@Example.com:8080/path"),
            "http://example.com:8080",
        )
        self.assertEqual(net.origin("http://[::1]:8080/path"), "http://[::1]:8080")

    def test_transport_retry_is_safe_method_only(self) -> None:
        client = net.Client(rps=0, base_url="https://example.com")
        calls = {"GET": 0, "POST": 0}

        def fail(_method, _url, *_args, **_kwargs):
            calls[_method] += 1
            raise requests.ConnectionError("network down")

        client._follow = fail  # type: ignore[method-assign]
        try:
            client.request("GET", "https://example.com/item")
            client.request("POST", "https://example.com/item", data={"q": "1"})
        finally:
            client.close()
        self.assertEqual(calls["GET"], 2)
        self.assertEqual(calls["POST"], 1)


class ErrorReplayTests(unittest.TestCase):
    class Client:
        def __init__(self, clean: str, injected: str) -> None:
            self.clean = clean
            self.injected = injected
            self.calls = 0

        def send(self, _point, value: str) -> Response:
            self.calls += 1
            text = self.clean if value == "1" else self.injected
            return Response(200, text, 0.0, "https://example.com/item", {})

    def test_clean_baseline_plus_new_error_reproduces(self) -> None:
        client = self.Client("<html>ok</html>", "<html>SQL syntax error in MySQL</html>")
        self.assertTrue(verify._replay_error(
            client, point(), finding("error", "1'")
        ))

    def test_preexisting_error_is_not_a_finding(self) -> None:
        error = "<html>SQL syntax error in MySQL</html>"
        client = self.Client(error, error)
        self.assertFalse(verify._replay_error(
            client, point(), finding("error", "1'")
        ))


class BooleanReplayTests(unittest.TestCase):
    class Client:
        def __init__(self, cold_text: str) -> None:
            self.cold_text = cold_text

        def send(self, _point, value: str) -> Response:
            text = "<html>catalog page with a stable product list</html>"
            if value == "1 AND 1=2":
                text = self.cold_text
            return Response(200, text, 0.0, "https://example.com/item", {})

    def test_true_branch_matches_baseline_and_false_branch_does_not(self) -> None:
        client = self.Client("<html>no results</html>")
        self.assertTrue(verify._replay_boolean(
            client, point(), finding("boolean", "1 AND 1=1|1 AND 1=2")
        ))

    def test_false_branch_equal_to_baseline_is_rejected(self) -> None:
        client = self.Client("<html>catalog page with a stable product list</html>")
        self.assertFalse(verify._replay_boolean(
            client, point(), finding("boolean", "1 AND 1=1|1 AND 1=2")
        ))


class SecondOrderReplayTests(unittest.TestCase):
    class Client:
        def __init__(self, text: str) -> None:
            self.text = text

        def fetch(self, _url: str) -> Response:
            return Response(200, self.text, 0.0, "https://example.com/item", {})

    def test_same_scan_time_error_is_rejected(self) -> None:
        text = "<html>SQL syntax error in MySQL</html>"
        _dbms, line = sqli.match_error(text)
        client = self.Client(text)
        self.assertFalse(verify._replay_second_order(
            client,
            finding("second-order", "sv1'", {
                "baseline_error": line,
                "baseline_checked": "1",
            }),
        ))

    def test_new_error_after_clean_baseline_is_accepted(self) -> None:
        text = "<html>SQL syntax error in MySQL</html>"
        client = self.Client(text)
        self.assertTrue(verify._replay_second_order(
            client,
            finding("second-order", "sv1'", {
                "baseline_error": "",
                "baseline_checked": "1",
            }),
        ))


if __name__ == "__main__":
    unittest.main()
