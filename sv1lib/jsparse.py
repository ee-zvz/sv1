"""SV1 - endpoints mined from javascript.

The crawler follows anchors. Single page apps talk to APIs that never appear
in an href. Read the scripts, pull out quoted URLs that carry a query string,
and hand them to the scanner as normal injection points.
"""

from __future__ import annotations

import re
import urllib.parse

from . import config, net
from .models import InjectionPoint, Page

URL_RE = re.compile(r"""["'`]([^"'`\s<>]{1,300}[?&][^"'`\s<>]{0,300})["'`]""")
SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
SCRIPT_BODY_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)

SKIP_PREFIX = ("data:", "javascript:", "mailto:", "tel:", "blob:", "#")


def _sources(client, page: Page) -> list[str]:
    bodies = [
        match.group(1)
        for match in SCRIPT_BODY_RE.finditer(page.html)
        if match.group(1).strip()
    ]
    fetched = 0
    for match in SCRIPT_SRC_RE.finditer(page.html):
        if fetched >= config.JS_MAX_SCRIPTS:
            break
        src = match.group(1).strip()
        if src.lower().startswith(SKIP_PREFIX):
            continue
        url = urllib.parse.urljoin(page.url, src)
        if not net.same_origin(url, page.url):
            continue
        fetched += 1
        response = client.fetch(url)
        if response.ok:
            bodies.append(response.text)
    return bodies


def endpoints(client, pages: list[Page]) -> list[InjectionPoint]:
    seen: set[tuple] = set()
    points: list[InjectionPoint] = []
    mined = 0

    for page in pages:
        sources = _sources(client, page)
        if not sources:
            continue
        mined += 1
        for body in sources:
            for match in URL_RE.finditer(body):
                raw = match.group(1).strip()
                if raw.lower().startswith(SKIP_PREFIX):
                    continue
                url = urllib.parse.urljoin(page.url, raw)
                if not net.same_origin(url, page.url):
                    continue
                parts = urllib.parse.urlsplit(url)
                if not parts.query or net.is_skippable(url):
                    continue
                pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
                if not pairs:
                    continue
                base = urllib.parse.urlunsplit(parts._replace(query="", fragment=""))
                for name, _value in pairs:
                    key = ("GET", base, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    points.append(
                        InjectionPoint(
                            url=base,
                            method="GET",
                            params=tuple(pairs),
                            param=name,
                            source="js",
                        )
                    )
                    if len(points) >= config.JS_MAX_POINTS:
                        return points
        if mined >= config.JS_MAX_PAGES:
            break
    return points
