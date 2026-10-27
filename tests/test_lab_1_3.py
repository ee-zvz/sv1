"""SV1 full-lab acceptance test.

This is the release gate, not a unit test: it starts the lab on a fresh port,
runs the complete crawl/XSS/SQLi/SSRF/SPA/external-JS/OpenAPI command, and
requires `verified == findings` in the JSON output.

It is opt-in because it launches Chromium and takes roughly three minutes. CI
sets `SV1_LAB_TESTS=1` after installing Playwright Chromium.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from sv1lib import browser as browser_mod

ROOT = Path(__file__).resolve().parent.parent
PORT = 8099
BASE = f"http://127.0.0.1:{PORT}/"


def _ready(url: str, timeout: float = 12.0) -> bool:
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
    os.environ.get("SV1_LAB_TESTS") == "1",
    "set SV1_LAB_TESTS=1 and install playwright chromium",
)
class FullLabAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not browser_mod.available():
            raise RuntimeError(
                "SV1_LAB_TESTS=1 but Chromium is unavailable; "
                "run playwright install chromium"
            )
        cls.tmp = tempfile.TemporaryDirectory(prefix="sv1-lab-")
        cls.work = Path(cls.tmp.name)
        cls.scope = cls.work / "scope.txt"
        cls.scope.write_text("127.0.0.1:8099\n", encoding="utf-8")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "lab" / "server.py"), str(PORT)],
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not _ready(BASE):
            cls.server.terminate()
            cls.server.wait(timeout=5)
            raise unittest.SkipTest("local lab did not start on port 8099")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server.poll() is None:
            cls.server.terminate()
            try:
                cls.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.server.kill()
                cls.server.wait(timeout=5)
        cls.tmp.cleanup()

    def test_full_lab_verified_equals_findings(self) -> None:
        output = self.work / "lab.json"
        sarif = self.work / "lab.sarif"
        html = self.work / "lab.html"
        artifacts = self.work / "artifacts"
        db = self.work / "lab.db"
        command = [
            sys.executable,
            "sv1.py",
            "-u",
            BASE,
            "--crawl",
            "--stored",
            "--js",
            "--second-order",
            "--dump",
            "--spa",
            "--external-js",
            "--openapi",
            BASE + "openapi.json",
            "--blind",
            "--blind-visit",
            BASE + "blind-admin",
            "--ssrf",
            "--scope",
            str(self.scope),
            "--db",
            str(db),
            "--diff",
            "--sarif",
            str(sarif),
            "--fail-on",
            "none",
            "--html",
            str(html),
            "--no-banner",
            "-o",
            str(output),
            "--artifacts",
            str(artifacts),
        ]
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
        message = (result.stdout[-2500:] + "\n" + result.stderr[-2500:]).strip()
        self.assertEqual(result.returncode, 0, message)
        self.assertTrue(output.is_file(), message)

        data = json.loads(output.read_text(encoding="utf-8"))
        findings = data.get("findings") or []
        stats = data.get("stats") or {}
        counts = data.get("counts") or {}
        self.assertEqual(len(findings), 31)
        self.assertEqual(stats.get("verified"), 31)
        self.assertEqual(stats.get("unverified"), 0)
        self.assertEqual(stats.get("errors"), 0)
        self.assertEqual(stats.get("pages"), 21)
        self.assertEqual(stats.get("points"), 29)
        self.assertEqual(counts.get("by_severity"), {
            "CRITICAL": 10,
            "HIGH": 18,
            "MEDIUM": 3,
        })
        self.assertEqual(counts.get("by_type"), {
            "XSS": 17,
            "SQLI": 13,
            "SSRF": 1,
        })

        by_url = {finding["url"]: finding for finding in findings}
        external = by_url.get(BASE.rstrip("/") + "/external")
        self.assertIsNotNone(external)
        self.assertEqual(external["severity"], "HIGH")
        self.assertEqual(external["confidence"], "CONFIRMED")

        xhr = by_url.get(BASE.rstrip("/") + "/api/xhr")
        self.assertIsNotNone(xhr)
        self.assertEqual(xhr["severity"], "MEDIUM")

        sarif_data = json.loads(sarif.read_text(encoding="utf-8"))
        self.assertEqual(len(sarif_data["runs"][0]["results"]), 31)
        self.assertTrue(html.is_file())


if __name__ == "__main__":
    unittest.main()
