"""SV1 P5 unit tests. Stdlib only, no network, no browser."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from sv1lib import config, policy, sarif
from sv1lib.history import History, point_to_dict
from sv1lib.identity import fingerprint
from sv1lib.models import Finding, InjectionPoint, ScanStats
from sv1lib.net import Client, RateLimiter
from sv1lib.scope import Scope, ScopeError


def make_finding(url: str = "https://example.com/item?id=1",
                 param: str = "id", severity: str = "HIGH") -> Finding:
    return Finding(
        kind="XSS",
        severity=severity,
        url=url,
        method="GET",
        param=param,
        payload="<svg/onload=alert(1)>",
        confidence="CONFIRMED",
        evidence="executed in chromium",
        technique="reflected",
    )


def make_point() -> InjectionPoint:
    return InjectionPoint(
        url="https://example.com/item",
        method="GET",
        params=(("id", "1"), ("q", "test")),
        param="id",
        source="query",
    )


class IdentityTests(unittest.TestCase):
    def test_query_order_does_not_change_identity(self) -> None:
        first = make_finding("https://example.com/item?b=2&a=1")
        second = make_finding("https://example.com/item?a=1&b=2")
        self.assertEqual(fingerprint(first), fingerprint(second))

    def test_parameter_change_does_change_identity(self) -> None:
        self.assertNotEqual(fingerprint(make_finding(param="id")),
                            fingerprint(make_finding(param="q")))

    def test_proof_class_change_does_change_identity(self) -> None:
        first = make_finding()
        second = make_finding()
        second.technique = "union"
        self.assertNotEqual(fingerprint(first), fingerprint(second))


class PolicyTests(unittest.TestCase):
    def test_threshold(self) -> None:
        high = make_finding(severity="HIGH")
        medium = make_finding(severity="MEDIUM")
        self.assertTrue(policy.should_fail([medium], "medium"))
        self.assertFalse(policy.should_fail([medium], "high"))
        self.assertTrue(policy.should_fail([high], "high"))
        self.assertFalse(policy.should_fail([high], "critical"))
        self.assertFalse(policy.should_fail([high], "none"))
        self.assertTrue(policy.should_fail([high], "any"))


class ScopeTests(unittest.TestCase):
    def test_rules_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "scope.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "# comment\n"
                    "example.com\n"
                    "*.example.com\n"
                    "https://api.other.test/v1/*\n"
                    "127.0.0.1:8099\n"
                )
            scope = Scope.load(path)
        self.assertTrue(scope.allows("https://example.com/"))
        self.assertTrue(scope.allows("https://shop.example.com/item?id=1"))
        self.assertTrue(scope.allows("https://api.other.test/v1/users"))
        self.assertFalse(scope.allows("https://api.other.test/v2/users"))
        self.assertTrue(scope.allows("http://127.0.0.1:8099/lab"))
        self.assertFalse(scope.allows("https://evil.test/"))

    def test_empty_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "scope.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# nothing\n")
            with self.assertRaises(ScopeError):
                Scope.load(path)


class HistoryTests(unittest.TestCase):
    def test_record_latest_diff_and_point_roundtrip(self) -> None:
        finding = make_finding()
        point = make_point()
        stats = ScanStats(started=100.0, finished=101.0, pages=1, points=1)
        with tempfile.TemporaryDirectory() as folder:
            db = os.path.join(folder, "history.db")
            history = History(db)
            session = history.record(
                "https://example.com/",
                {"target": "https://example.com/"},
                stats,
                [finding],
                [(finding, point)],
            )
            latest = history.latest("https://example.com")
            self.assertIsNotNone(latest)
            self.assertEqual(latest["id"], session)
            rows = history.rows(session)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["point"], point_to_dict(point))
            self.assertEqual(rows[0]["fingerprint"], fingerprint(finding))
            delta = history.diff(session, [finding, make_finding(param="q")])
            self.assertEqual(delta["new"], 1)
            self.assertEqual(delta["same"], 1)
            self.assertEqual(delta["fixed"], 0)
            history.close()


class SarifTests(unittest.TestCase):
    def test_structure(self) -> None:
        finding = make_finding()
        stats = ScanStats(started=100.0, finished=101.0, requests=3)
        payload = sarif.build([finding], stats, {"target": "https://example.com/"})
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["partialFingerprints"]["sv1Fingerprint"],
                         fingerprint(finding))
        self.assertEqual(run["tool"]["driver"]["version"], config.TOOL_VERSION)
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "out.sarif")
            sarif.write(path, [finding], stats, {"target": "https://example.com/"})
            with open(path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            self.assertEqual(len(loaded["runs"][0]["results"]), 1)


class RateLimiterTests(unittest.TestCase):
    def test_penalty_and_recovery(self) -> None:
        limiter = RateLimiter(10.0)
        base = limiter.interval
        limiter.penalize()
        self.assertGreater(limiter.interval, base)
        for _ in range(config.RATE_RECOVERY_AFTER):
            limiter.reward()
        self.assertLess(limiter.interval, base * config.RATE_PENALTY_FACTOR)

    def test_penalty_cap(self) -> None:
        limiter = RateLimiter(10.0)
        for _ in range(10):
            limiter.penalize()
        self.assertLessEqual(limiter.interval,
                             limiter.base_interval * config.RATE_MAX_MULTIPLIER)

    def test_unlimited_never_penalizes(self) -> None:
        limiter = RateLimiter(0)
        limiter.penalize()
        self.assertEqual(limiter.interval, 0.0)

    def test_client_adapts_on_pushback(self) -> None:
        client = Client(rps=10.0)
        try:
            base = client.limiter.interval
            client._adapt(429, "1")
            self.assertGreater(client.limiter.interval, base)
            client._adapt(503, "")
            self.assertGreater(client.limiter.interval, base)
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
