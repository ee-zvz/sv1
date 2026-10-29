"""Regression test for the Firing Range recall measurement."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.recall import summarize

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence"


class RecallMeasurementTests(unittest.TestCase):
    def test_1_5_2_reproduces_43_of_43(self) -> None:
        manifest = json.loads(
            (EVIDENCE / "firing-range-reflected-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        findings = json.loads(
            (EVIDENCE / "firing-range-reflected-1.5.2.json").read_text(
                encoding="utf-8"
            )
        )["findings"]
        reference = json.loads(
            (EVIDENCE / "dalfox-reflected-3.2.4.json").read_text(
                encoding="utf-8"
            )
        )["findings"]

        summary = summarize(manifest, findings, reference)
        get = summary["get"]
        self.assertEqual(get["seen"], 43)
        self.assertEqual(get["confirmed"], 41)
        self.assertEqual(get["union"], 43)
        self.assertEqual(get["index"], 47)
        self.assertEqual(get["missed"], [])
        self.assertEqual(get["coverage"], 1.0)


if __name__ == "__main__":
    unittest.main()
