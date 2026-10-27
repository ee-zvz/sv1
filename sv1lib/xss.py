"""SV1 - reflected XSS detection.

Probe first: does the input come back at all? Then read the grammar at the
reflection site and build a payload that closes exactly what is open. Every
candidate must come back byte-identical to count as proof.
"""

from __future__ import annotations

import secrets

from . import config, context, payloads
from .models import Finding


def _header(headers: dict, name: str) -> str:
    target = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == target:
            return str(value)
    return ""


def _renderable(response) -> bool:
    """Only HTML documents can execute an HTML payload.

    text/plain, application/json and friends are still useful for SQLi and
    reflection evidence, but treating them as XSS candidates inflates the
    report and makes a browser proof look optional.
    """
    ctype = _header(response.headers, "content-type").lower()
    if not ctype:
        return True
    return any(kind in ctype for kind in config.XSS_HTML_TYPES)


def _token() -> str:
    return "sv1" + secrets.token_hex(4)


def _snippet(text: str, index: int, length: int) -> str:
    half = config.XSS_SAMPLE_CHARS // 2
    start = max(0, index - half)
    end = min(len(text), index + length + half)
    raw = text[start:end].replace("\r", " ").replace("\n", " ")
    return " ".join(raw.split())


def candidates(site: context.Site, token: str) -> list[str]:
    ordered = context.payloads(site, token)
    ordered.extend(
        template.replace("MARK", token) for template in payloads.XSS_PAYLOADS
    )
    seen: set[str] = set()
    unique: list[str] = []
    for payload in ordered:
        if payload in seen:
            continue
        seen.add(payload)
        unique.append(payload)
    return unique[: config.XSS_MAX_PAYLOADS]


def scan_point(client, point) -> list[Finding]:
    token = _token()
    probe = client.send(point, token)
    if not probe.ok or token not in probe.text:
        return []
    if not _renderable(probe):
        return []

    site = context.analyze(probe.text, probe.text.find(token))
    reflected = 0
    matches: list[tuple[str, str]] = []

    for payload_text in candidates(site, token):
        response = client.send(point, payload_text)
        if not response.ok:
            continue
        if token not in response.text:
            continue
        reflected += 1
        if payload_text in response.text:
            index = response.text.find(payload_text)
            matches.append((payload_text, _snippet(response.text, index, len(payload_text))))

    if matches:
        payload_text, evidence = matches[0]
        alternatives = [item[0] for item in matches[1:config.XSS_MAX_PROOFS]]
        return [
            Finding(
                kind="XSS",
                severity="HIGH",
                url=point.url,
                method=point.method,
                param=point.param,
                payload=payload_text,
                confidence="HIGH",
                evidence=evidence,
                technique=f"reflected/{site.kind}",
                detail=site.summary(),
                alternatives=alternatives,
            )
        ]

    if reflected:
        index = probe.text.find(token)
        return [
            Finding(
                kind="XSS",
                severity="MEDIUM",
                url=point.url,
                method=point.method,
                param=point.param,
                payload="<svg/onload=alert(1)>",
                confidence="MEDIUM",
                evidence=_snippet(probe.text, index, len(token)),
                technique="reflection-encoded",
                detail=f"input reaches the page ({site.summary()}) but markup was "
                       f"encoded or stripped ({reflected} payloads reflected)",
            )
        ]
    return []
