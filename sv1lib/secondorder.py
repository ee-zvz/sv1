"""SV1 - second-order SQL injection.

The first request is harmless: the value is stored. The bug fires when another
page reads that value and puts it into a query. Store a benign value first so
the baseline is clean, then store the payload and walk the site again.
"""

from __future__ import annotations

from . import config, crawl
from .dberrors import match_error
from .models import Finding, InjectionPoint

TEXT_TYPES = ("text", "search", "url", "email", "tel", "textarea", "select", "")
PAYLOAD = "sv1'"
CLEAN = "sv1clean"


def _fields(form) -> list:
    usable = []
    for item in form.fields:
        kind = (item.type or "").lower()
        if kind in ("submit", "button", "image", "reset", "file", "hidden", "checkbox", "radio"):
            continue
        if kind not in TEXT_TYPES:
            continue
        usable.append(item)
    return usable[: config.SECOND_ORDER_FIELDS]


def _data(form, field: str, value: str) -> dict:
    return {
        item.name: (value if item.name == field else (item.value or "test"))
        for item in form.fields
        if item.name
    }


def _revisit(pages, actions: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for url in actions + [page.url for page in pages]:
        if url in seen:
            continue
        seen.add(url)
        ordered.append(url)
    return ordered[: config.SECOND_ORDER_PAGES]


def run(client, pages) -> list[tuple[Finding, InjectionPoint]]:
    forms = []
    for page in pages:
        for form in page.forms:
            if form.method == "post" and _fields(form) and crawl.form_endpoint(page.url, form):
                forms.append((page.url, form))
    forms = forms[: config.SECOND_ORDER_FORMS]
    if not forms:
        return []

    actions = [
        crawl.form_endpoint(page_url, form)
        for page_url, form in forms
    ]
    revisit = _revisit(pages, actions)

    results: list[tuple[Finding, InjectionPoint]] = []
    for page_url, form in forms:
        action = crawl.form_endpoint(page_url, form)
        if not action:
            continue
        for field in _fields(form):
            client.request("POST", action, data=_data(form, field.name, CLEAN))
            baseline: dict[str, str] = {}
            for url in revisit:
                response = client.fetch(url)
                if response.ok:
                    baseline[url] = response.text

            submitted = client.request("POST", action, data=_data(form, field.name, PAYLOAD))
            if submitted.status >= 400:
                continue

            for url in revisit:
                response = client.fetch(url)
                if not response.ok:
                    continue
                dbms, line = match_error(response.text)
                if not dbms:
                    continue
                raw_before = baseline.get(url, "")
                before = " ".join(raw_before.split())
                if line and line in before:
                    continue
                before_dbms, before_line = match_error(raw_before)
                point = InjectionPoint(
                    url=action,
                    method="POST",
                    params=tuple((item.name, item.value) for item in form.fields if item.name),
                    param=field.name,
                    source="form",
                )
                results.append((
                    Finding(
                        kind="SQLI",
                        severity="CRITICAL",
                        url=url,
                        method="GET",
                        param=field.name,
                        payload=PAYLOAD,
                        confidence="HIGH",
                        evidence=f"stored via POST {action} [{field.name}] "
                                 f"then surfaced on {url}: {line}",
                        technique="second-order",
                        detail=f"second-order injection: the value was stored and later "
                               f"used in a query ({dbms})",
                        data={
                            "baseline_error": (
                                before_line or (dbms if before_dbms else "")
                            ),
                            "baseline_checked": "1",
                        },
                    ),
                    point,
                ))
                break
    return _dedupe(results)


def _dedupe(results: list[tuple[Finding, InjectionPoint]]) -> list[tuple[Finding, InjectionPoint]]:
    seen: set[tuple] = set()
    ordered: list[tuple[Finding, InjectionPoint]] = []
    for finding, point in results:
        key = (finding.url, finding.param, finding.technique)
        if key in seen:
            continue
        seen.add(key)
        ordered.append((finding, point))
    return ordered
