"""SV1 - rendered crawl.

Static HTML hides half the app. Render each script-bearing page in chromium,
listen for xhr/fetch calls, keep the URLs and the POST bodies that carry input,
and pick up anchors the script built after load. Those endpoints become normal
injection points, so every technique in the scanner applies to them.
"""

from __future__ import annotations

import json
import urllib.parse

from . import config, crawl, formdata, net
from .models import CapturedRequest, InjectionPoint, Page


def _points_from_url(url: str, method: str = "GET") -> list[InjectionPoint]:
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
                method=method,
                params=tuple(pairs),
                param=name,
                source="query",
                param_index=occurrence,
            )
        )
    return points


def _points_from_form(url: str, body: str, method: str,
                      content_type: str) -> list[InjectionPoint]:
    pairs = tuple(urllib.parse.parse_qsl(body, keep_blank_values=True))
    if not pairs:
        return []
    counts: dict[str, int] = {}
    points: list[InjectionPoint] = []
    for name, _value in pairs:
        occurrence = counts.get(name, 0)
        counts[name] = occurrence + 1
        points.append(
            InjectionPoint(
                url=url,
                method=method,
                params=pairs,
                param=name,
                source="form",
                param_index=occurrence,
                content_type=content_type,
            )
        )
    return points


def _in_scope(url: str, page_url: str, allows=None) -> bool:
    if allows is not None:
        try:
            return bool(allows(url))
        except Exception:
            return False
    return net.same_origin(url, page_url)


def _points_from_capture(captured: CapturedRequest, page_url: str,
                         allows=None) -> list[InjectionPoint]:
    """One browser request can carry query fields and a JSON/form/raw body."""
    full = urllib.parse.urljoin(page_url, captured.url).split("#", 1)[0]
    if not _in_scope(full, page_url, allows) or net.is_skippable(full):
        return []
    method = (captured.method or "GET").upper()
    query_points = _points_from_url(full, method)
    if method in ("GET", "HEAD"):
        return query_points
    body = captured.body or ""
    if not body:
        return query_points
    content_type = (captured.content_type or "").lower()
    stripped = body.lstrip()
    if "json" in content_type or stripped.startswith(("{", "[")):
        try:
            data = json.loads(body)
        except (TypeError, ValueError):
            return query_points
        return query_points + crawl.json_points(
            full,
            data,
            method=method,
            content_type=captured.content_type or "application/json",
        )
    if "multipart/form-data" in content_type:
        return query_points + formdata.points(
            full,
            captured.content_type,
            body,
            method=method,
        )
    if "x-www-form-urlencoded" in content_type:
        return query_points + _points_from_form(full, body, method, captured.content_type)
    if "*" in body:
        return query_points + crawl.raw_point(
            full,
            body,
            method=method,
            content_type=captured.content_type,
        )
    return query_points


def capture(client, engine, pages: list[Page],
            allows=None) -> tuple[list[Page], list[InjectionPoint], str]:
    """Return (new pages, points, note). Bounded on every axis."""
    known = {page.url for page in pages}
    candidates = [
        page.url for page in pages if "<script" in page.html.lower()
    ][: config.SPA_MAX_PAGES]
    if not candidates and pages:
        candidates = [pages[0].url]

    new_pages: list[Page] = []
    captured_requests: list[CapturedRequest] = []
    anchor_urls: list[str] = []
    seen_captured: set[tuple] = set()
    explored = 0

    for url in candidates:
        result = engine.explore(url, config.SPA_WAIT_MS)
        explored += 1
        if result.error:
            continue
        base = result.url or url
        for call in result.requests:
            full = urllib.parse.urljoin(base, call.url).split("#", 1)[0]
            if not _in_scope(full, url, allows) or net.is_skippable(full):
                continue
            key = (
                full,
                (call.method or "GET").upper(),
                call.body or "",
                (call.content_type or "").lower(),
            )
            if key in seen_captured:
                continue
            seen_captured.add(key)
            captured_requests.append(
                CapturedRequest(
                    url=full,
                    method=(call.method or "GET").upper(),
                    body=call.body or "",
                    content_type=call.content_type or "",
                )
            )
        for raw in result.anchors:
            full = urllib.parse.urljoin(base, raw).split("#", 1)[0]
            if not _in_scope(full, url, allows) or net.is_skippable(full):
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
    body_calls = 0
    for captured in captured_requests:
        for point in _points_from_capture(captured, captured.url, allows):
            key = point.key()
            if key in seen_points:
                continue
            seen_points.add(key)
            points.append(point)
            if len(points) >= config.SPA_MAX_POINTS:
                break
        if captured.body:
            body_calls += 1
        if len(points) >= config.SPA_MAX_POINTS:
            break
    for url in anchor_urls:
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

    note = (f"{explored} rendered page(s), {len(captured_requests)} xhr call(s), "
            f"{body_calls} with body, "
            f"{len(anchor_urls)} dynamic link(s), {len(points)} point(s)")
    if new_pages:
        note += f", {len(new_pages)} new page(s)"
    return new_pages, points, note
