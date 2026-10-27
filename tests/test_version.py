"""Version has one source: sv1lib/version.py."""

from __future__ import annotations

import unittest
from pathlib import Path

from sv1lib import __version__, config, version

ROOT = Path(__file__).resolve().parents[1]


class VersionSourceTest(unittest.TestCase):
    def test_runtime_uses_one_string(self) -> None:
        self.assertEqual(config.TOOL_VERSION, version.__version__)
        self.assertEqual(__version__, version.__version__)
        self.assertTrue(config.USER_AGENT.endswith(f"SV1/{version.__version__}"))

    def test_pyproject_reads_the_same_string(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('dynamic = ["version"]', text)
        self.assertNotIn('\nversion = "', text)
        self.assertIn('version = {attr = "sv1lib.version.__version__"}', text)


if __name__ == "__main__":
    unittest.main()
