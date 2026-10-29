"""SV1 - DOM XSS. Pair sources with sinks statically, then prove it in Chromium.

The server never sees the payload here: it travels in the fragment, a query
parameter, the referrer, window.name, web storage or a postMessage event.
Static pairing only proposes candidates; a candidate becomes a finding when
the browser runs our marker.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from html import unescape

from . import browser as browser_mod
from . import config, net
from .models import Finding, Page

SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)
SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
SKIP_PREFIX = ("data:", "javascript:", "mailto:", "tel:", "blob:", "#")

SOURCES = (
    ("location.hash", "location.hash"),
    ("location.search", "location.search"),
    ("location.href", "location.href"),
    ("location.pathname", "location.pathname"),
    ("document.url", "document.URL"),
    ("document.documenturi", "document.documentURI"),
    ("document.referrer", "document.referrer"),
    ("window.name", "window.name"),
    ("localstorage.getitem", "localStorage.getItem"),
    ("localstorage", "localStorage"),
    ("sessionstorage.getitem", "sessionStorage.getItem"),
    ("sessionstorage", "sessionStorage"),
    ("addeventlistener('message'", "postMessage event"),
    ('addeventlistener("message"', "postMessage event"),
    ("onmessage", "postMessage event"),
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
STORAGE_KEYS = ("badValue", "payload", "data", "name", "value", "q")


class Candidate:
    def __init__(
        self,
        source: str,
        sink: str,
        distance: int,
        snippet: str,
        origin: str = "inline",
    ) -> None:
        self.source = source
        self.sink = sink
        self.distance = distance
        self.snippet = snippet
        self.origin = origin

    def key(self) -> tuple:
        return (self.source, self.sink)


@dataclass(frozen=True)
class Vector:
    url: str
    payload: str
    referer: str = ""
    init_script: str = ""
    messages: tuple[str, ...] = field(default_factory=tuple)


def analyze(
    page: Page,
    external: list[tuple[str, str]] | None = None,
) -> list[Candidate]:
    sources = [
        (match.group(1), "inline")
        for match in SCRIPT_RE.finditer(page.html)
        if match.group(1).strip()
    ]
    if external:
        sources.extend(external)
    candidates: list[Candidate] = []
    for body, origin in sources:
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
                    Candidate(
                        source_name,
                        sink_name,
                        distance,
                        snippet[:MAX_SNIPPET],
                        origin,
                    )
                )
                break
    return _unique(candidates)


def external_sources(client, page: Page, allows=None) -> list[tuple[str, str]]:
    """Read same-origin or scope-authorized script bodies for source/sink analysis."""
    if client is None:
        return []
    bodies: list[tuple[str, str]] = []
    seen: set[str] = set()
    used = 0
    for match in SCRIPT_SRC_RE.finditer(page.html):
        if used >= config.DOM_EXTERNAL_SCRIPTS:
            break
        src = unescape(match.group(1).strip())
        if not src or src.lower().startswith(SKIP_PREFIX):
            continue
        url = urllib.parse.urljoin(page.url, src)
        if url in seen:
            continue
        if allows is not None:
            if not allows(url):
                continue
        elif not net.same_origin(url, page.url):
            continue
        seen.add(url)
        used += 1
        response = client.fetch(url)
        if not response.ok:
            continue
        if len(response.text) > config.DOM_EXTERNAL_BYTES:
            continue
        bodies.append((response.text, url))
    return bodies


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


def _token(page_url: str, index: int) -> str:
    digest = hashlib.sha1(page_url.encode("utf-8", "replace")).hexdigest()[:8]
    return f"sv1dom{index}{digest}"


def _hash_url(page_url: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(page_url)
    return urllib.parse.urlunsplit(parts._replace(fragment=urllib.parse.quote(payload, safe="")))


def _search_url(page_url: str, name: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(page_url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append((name, payload))
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))


def _window_name_script(payload: str) -> str:
    return f"try {{ window.name = {json.dumps(payload)}; }} catch (e) {{}}"


def _storage_script(storage: str, payload: str) -> str:
    lines = []
    for key in STORAGE_KEYS:
        lines.append(
            f"try {{ {storage}.setItem({json.dumps(key)}, {json.dumps(payload)}); }} catch (e) {{}}"
        )
    return "\n".join(lines)


def _cookie_script(payload: str) -> str:
    encoded = urllib.parse.quote(payload, safe="")
    return (
        "try { document.cookie = 'sv1payload=' + " + json.dumps(encoded) +
        " + '; path=/'; } catch (e) {}"
    )


def _message_payloads(payload: str) -> tuple[str, ...]:
    structured = json.dumps({
        "html": payload,
        "data": payload,
        "message": payload,
        "value": payload,
    })
    return (structured, payload)


def _vectors(candidate: Candidate, page_url: str, token: str) -> list[Vector]:
    vectors: list[Vector] = []
    for payload in _payloads(token):
        if candidate.source == "location.hash":
            vectors.append(Vector(_hash_url(page_url, payload), payload))
        elif candidate.source in (
            "location.search", "location.href", "document.URL", "document.documentURI"
        ):
            for name in config.DOM_PARAM_GUESSES:
                vectors.append(Vector(_search_url(page_url, name, payload), payload))
        elif candidate.source == "document.referrer":
            vectors.append(Vector(
                page_url,
                payload,
                referer=_search_url(page_url, "sv1ref", payload),
            ))
        elif candidate.source == "window.name":
            vectors.append(Vector(
                page_url,
                payload,
                init_script=_window_name_script(payload),
            ))
        elif "localStorage" in candidate.source:
            vectors.append(Vector(
                page_url,
                payload,
                init_script=_storage_script("localStorage", payload),
            ))
        elif "sessionStorage" in candidate.source:
            vectors.append(Vector(
                page_url,
                payload,
                init_script=_storage_script("sessionStorage", payload),
            ))
        elif candidate.source == "postMessage event":
            vectors.append(Vector(
                page_url,
                payload,
                messages=_message_payloads(payload),
            ))
        elif candidate.source == "document.cookie":
            vectors.append(Vector(
                page_url,
                payload,
                init_script=_cookie_script(payload),
            ))
    return vectors[: config.DOM_MAX_CANDIDATES * 6]


def run(
    engine: browser_mod.Browser,
    pages: list[Page],
    artifacts: str,
    client=None,
    external_js: bool = False,
    allows=None,
) -> list[Finding]:
    if not engine.enabled:
        return []

    findings: list[Finding] = []
    for page in pages[: config.BROWSER_MAX_PAGES]:
        external = external_sources(client, page, allows=allows) if external_js else []
        candidates = analyze(page, external)
        if not candidates:
            continue
        for index, candidate in enumerate(candidates):
            token = _token(page.url, index)
            hit: Vector | None = None
            proof = ""
            shot = ""
            for vector in _vectors(candidate, page.url, token):
                shot_path = ""
                if artifacts:
                    shot_path = _shot_path(artifacts, "dom", len(findings) + 1)
                visit = engine.visit(
                    vector.url,
                    shot_path=shot_path,
                    referer=vector.referer,
                    init_script=vector.init_script,
                    messages=vector.messages,
                )
                if visit.fired(token):
                    hit = vector
                    proof = visit.proof(token)
                    shot = visit.screenshot
                    break
            if hit is None:
                continue
            findings.append(
                Finding(
                    kind="XSS",
                    severity="HIGH",
                    url=page.url,
                    method="GET",
                    param=candidate.source,
                    payload=hit.payload,
                    confidence="CONFIRMED",
                    evidence=f"{candidate.source} -> {candidate.sink}: {proof}",
                    technique="dom",
                    detail=(
                        f"client side sink: {candidate.snippet}"
                        + (f" | script: {candidate.origin}"
                           if candidate.origin != "inline" else "")
                    ),
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
