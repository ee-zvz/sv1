"""SV1 - rendered crawl.

Static HTML hides half the app. Render each script-bearing page in chromium,
listen for xhr/fetch calls, keep the URLs that carry parameters, and pick up
anchors the script built after load. Those endpoints become normal injection
points, so every technique in the scanner applies to them.
"""

from __future__ import annotations

import urllib.parse

from . import config, crawl, net
from .models import InjectionPoint, Page


def _points_from_url(url: str) -> list[InjectionPoint]:
    parts = urllib.parse.urlsplit(url)
    if not parts.query:
        return []
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return []
    base = urllib.parse.urlunsplit(parts._replace(query="", fragment=""))
    counts: dict[str, int] = {}
    points: list[InjectionPoint] = []
    for name, _value in pairs:
        occurrence = counts.get(name, 0)
        counts[name] = occurrence + 1
        points.append(
            InjectionPoint(
                url=base,
                method="GET",
                params=tuple(pairs),
                param=name,
                source="query",
                param_index=occurrence,
            )
        )
    return points


def capture(client, engine, pages: list[Page]) -> tuple[list[Page], list[InjectionPoint], str]:
    """Return (new pages, points, note). Bounded on every axis."""
    known = {page.url for page in pages}
    candidates = [
        page.url for page in pages if "<script" in page.html.lower()
    ][: config.SPA_MAX_PAGES]
    if not candidates and pages:
        candidates = [pages[0].url]

    new_pages: list[Page] = []
    xhr_urls: list[str] = []
    anchor_urls: list[str] = []
    seen_xhr: set[str] = set()
    explored = 0

    for url in candidates:
        result = engine.explore(url, config.SPA_WAIT_MS)
        explored += 1
        if result.error:
            continue
        base = result.url or url
        for raw in result.xhr:
            full = urllib.parse.urljoin(base, raw)
            full = full.split("#", 1)[0]
            if not net.same_origin(full, url) or net.is_skippable(full):
                continue
            if full in seen_xhr:
                continue
            seen_xhr.add(full)
            xhr_urls.append(full)
        for raw in result.anchors:
            full = urllib.parse.urljoin(base, raw).split("#", 1)[0]
            if not net.same_origin(full, url) or net.is_skippable(full):
                continue
            if full in known:
                continue
            if "?" in full:
                if full not in anchor_urls and len(anchor_urls) < config.SPA_MAX_POINTS:
                    anchor_urls.append(full)
                continue
            if len(new_pages) >= config.SPA_MAX_NEW_PAGES:
                continue
            response = client.fetch(full)
            if not response.ok:
                continue
            known.add(full)
            new_pages.append(crawl.parse_page(full, response.status, response.text))

    points: list[InjectionPoint] = []
    seen_points: set[tuple] = set()
    for url in xhr_urls + anchor_urls:
        for point in _points_from_url(url):
            key = point.key()
            if key in seen_points:
                continue
            seen_points.add(key)
            points.append(point)
            if len(points) >= config.SPA_MAX_POINTS:
                break
        if len(points) >= config.SPA_MAX_POINTS:
            break

    note = (f"{explored} rendered page(s), {len(xhr_urls)} xhr call(s), "
            f"{len(anchor_urls)} dynamic link(s), {len(points)} point(s)")
    if new_pages:
        note += f", {len(new_pages)} new page(s)"
    return new_pages, points, note
