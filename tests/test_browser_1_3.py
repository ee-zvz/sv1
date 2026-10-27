"""SV1 1.3 browser integration: the request body must survive Chromium.

These tests are opt-in because they launch a browser and a local server. CI
sets SV1_BROWSER_TESTS=1 after installing Playwright chromium.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import unittest
import urllib.request

from sv1lib import browser as browser_mod
from sv1lib import spa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8098


def _ready(url: str, timeout: float = 8.0) -> bool:
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
    os.environ.get("SV1_BROWSER_TESTS") == "1" and browser_mod.available(),
    "set SV1_BROWSER_TESTS=1 and install playwright chromium",
)
class BrowserCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = subprocess.Popen(
            [sys.executable, os.path.join("lab", "server.py"), str(PORT)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not _ready(f"http://127.0.0.1:{PORT}/"):
            cls.server.terminate()
            raise unittest.SkipTest("local lab did not start")
        cls.base = f"http://127.0.0.1:{PORT}"

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.server.terminate()
            cls.server.wait(timeout=5)
        except Exception:
            try:
                cls.server.kill()
            except Exception:
                pass

    def test_chromium_captures_xhr_post_body(self) -> None:
        engine = browser_mod.Browser(base_url=self.base, timeout_ms=8000)
        try:
            self.assertTrue(engine.start(), engine.reason)
            result = engine.explore(self.base + "/xhr-post", 1800)
        finally:
            engine.close()
        self.assertFalse(result.error)
        posts = [
            item for item in result.requests
            if item.method == "POST" and item.url.endswith("/api/xhr")
        ]
        self.assertTrue(posts)
        self.assertIn("user", posts[0].body)
        self.assertIn("application/json", posts[0].content_type.lower())
        points = spa._points_from_capture(posts[0], result.url)
        self.assertIn("user.name", {point.param for point in points})


if __name__ == "__main__":
    unittest.main()
