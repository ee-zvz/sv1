"""SV1 - robots.txt and sitemap discovery.

A sitemap is a map of pages that are not linked from the home page. It is
cheap to read, same-origin by default, and bounded: no recursive crawl and no
third-party URL is added to the queue. The crawler still applies the normal
scope and extension gates to every seed.
"""

from __future__ import annotations

import re
import urllib.parse
import xml.etree.ElementTree as ElementTree

from . import config, net

ROBOTS_MAX_BYTES = 256_000
LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)


def _clean_loc(value: str) -> str:
    return " ".join(str(value or "").split())


def _sitemap_urls(client, target: str, sitemap: str,
                  allows=None, depth: int = 0,
                  seen: set[str] | None = None) -> list[str]:
    """Read one sitemap or sitemap index. Only one index hop is followed."""
    if depth > 1:
        return []
    if seen is None:
        seen = set()
    if sitemap in seen or len(seen) >= config.SITEMAP_MAX_FILES:
        return []
    seen.add(sitemap)
    response = client.fetch(sitemap)
    if not response.ok or not response.text:
        return []
    if len(response.text) > config.SITEMAP_MAX_BYTES:
        return []

    urls: list[str] = []
    root = None
    try:
        root = ElementTree.fromstring(response.text)
    except ElementTree.ParseError:
        # Some servers emit a plain text loc list. XML is the contract, but a
        # malformed sitemap should not make the whole discovery pass fail.
        candidates = LOC_RE.findall(response.text)
    else:
        candidates = [
            _clean_loc(element.text or "")
            for element in root.iter()
            if element.tag.rsplit("}", 1)[-1].lower() == "loc"
        ]

    is_index = root is not None and root.tag.rsplit("}", 1)[-1].lower() == "sitemapindex"
    if is_index:
        for child in candidates[: config.SITEMAP_MAX_FILES]:
            child_url = urllib.parse.urljoin(sitemap, child)
            if not net.same_origin(child_url, target):
                continue
            if allows is not None and not allows(child_url):
                continue
            urls.extend(_sitemap_urls(
                client, target, child_url, allows, depth + 1, seen,
            ))
        return urls

    for candidate in candidates:
        candidate = _clean_loc(candidate)
        if not candidate:
            continue
        url = urllib.parse.urljoin(sitemap, candidate)
        if not net.same_origin(url, target):
            continue
        if allows is not None and not allows(url):
            continue
        if net.is_skippable(url):
            continue
        urls.append(urllib.parse.urldefrag(url)[0])
    return urls


def robots_sitemaps(client, target: str) -> list[str]:
    origin = net.origin(target)
    if not origin:
        return []
    response = client.fetch(origin + "/robots.txt")
    if not response.ok:
        return []
    found: list[str] = []
    for line in response.text[:ROBOTS_MAX_BYTES].splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() != "sitemap":
            continue
        url = urllib.parse.urljoin(origin + "/", value.strip())
        if net.same_origin(url, target):
            found.append(url)
    return found


def discover(client, target: str, allows=None) -> tuple[list[str], str]:
    """Return (same-origin page seeds, note). Bounded and duplicate-free."""
    origin = net.origin(target)
    if not origin:
        return [], "no target origin"

    sitemaps = robots_sitemaps(client, target)
    source = "robots.txt" if sitemaps else "sitemap.xml"
    if not sitemaps:
        sitemaps = [origin + "/sitemap.xml"]

    urls: list[str] = []
    page_seen: set[str] = set()
    sitemap_seen: set[str] = set()
    for sitemap in sitemaps:
        for url in _sitemap_urls(
            client, target, sitemap, allows, seen=sitemap_seen,
        ):
            if url in page_seen:
                continue
            page_seen.add(url)
            urls.append(url)
            if len(urls) >= config.SITEMAP_MAX_URLS:
                return urls, f"{len(urls)} sitemap seed(s) from {source} (capped)"
    if not urls:
        return [], f"no same-origin sitemap seeds from {source}"
    return urls, f"{len(urls)} sitemap seed(s) from {source}"
