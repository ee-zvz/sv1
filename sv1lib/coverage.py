"""SV1 - point coverage for the pages the crawler actually reached.

A page is more than its query string. A route carries path segments, the
session carries cookies, and the edge carries headers. This module turns those
surfaces into normal injection points without inventing requests the scanner
cannot replay.

Every builder is capped and duplicate-free. The crawler remains the source of
truth for reachability; nothing here adds a URL that was not already a page.
"""

from __future__ import annotations

import urllib.parse

from . import config, crawl, net
from .models import InjectionPoint


def page_urls(pages: list) -> list[str]:
    """Unique page URLs in discovery order, with fragments removed."""
    seen: set[str] = set()
    urls: list[str] = []
    for page in pages:
        url = urllib.parse.urldefrag(str(getattr(page, "url", "") or "")).url
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def path_points(pages: list, max_points: int | None = None) -> list[InjectionPoint]:
    """One point per URL path segment.

    ``/api/users/42`` becomes two points, each with a placeholder in the exact
    segment position. The query string is preserved untouched. Values are
    decoded before they are stored so ``net.path_url`` encodes the baseline
    exactly once, not twice.
    """
    limit = config.PATH_MAX_POINTS if max_points is None else max(0, max_points)
    if limit == 0:
        return []

    points: list[InjectionPoint] = []
    seen: set[tuple] = set()
    for url in page_urls(pages):
        if net.is_skippable(url):
            continue
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        segments = parts.path.split("/")
        if len(segments) <= 1:
            continue
        for index, segment in enumerate(segments):
            if not segment or len(segment) > config.PATH_MAX_SEGMENT:
                continue
            name = f"sv1_path_{index}"
            template_segments = list(segments)
            template_segments[index] = "{" + name + "}"
            template = urllib.parse.urlunsplit(parts._replace(
                path="/".join(template_segments),
                fragment="",
            ))
            try:
                original = urllib.parse.unquote(segment, errors="replace")
            except Exception:
                original = segment
            point = InjectionPoint(
                url=template,
                method="GET",
                params=((name, original),),
                param=name,
                source="path",
            )
            # The query is preserved, not injected. Two discoveries of the
            # same route with different query strings must not consume two
            # path slots and re-test the same segment.
            key = (parts.scheme, parts.netloc, template.split("?", 1)[0], "GET")
            if key in seen:
                continue
            seen.add(key)
            points.append(point)
            if len(points) >= limit:
                return points
    return points


def header_points(pages: list, deep: bool = False,
                  max_points: int | None = None) -> list[InjectionPoint]:
    """Test the usual header carriers on every unique page URL."""
    limit = config.EXTRA_MAX_POINTS if max_points is None else max(0, max_points)
    if limit == 0:
        return []

    points: list[InjectionPoint] = []
    seen: set[tuple] = set()
    for url in page_urls(pages):
        for point in crawl.header_points(url, deep=deep):
            key = point.key()
            if key in seen:
                continue
            seen.add(key)
            points.append(point)
            if len(points) >= limit:
                return points
    return points


def cookie_points(pages: list, cookies: dict,
                  max_points: int | None = None) -> list[InjectionPoint]:
    """Test every imported cookie value on every unique page URL."""
    limit = config.EXTRA_MAX_POINTS if max_points is None else max(0, max_points)
    if limit == 0 or not cookies:
        return []

    points: list[InjectionPoint] = []
    seen: set[tuple] = set()
    for url in page_urls(pages):
        for point in crawl.cookie_points(url, cookies):
            key = point.key()
            if key in seen:
                continue
            seen.add(key)
            points.append(point)
            if len(points) >= limit:
                return points
    return points
