"""SV1 - SQL injection detection.

Four independent proofs, cheapest first:
  error   - the backend leaks its own syntax error
  boolean - the truth value of our expression changes the page, repeatably
  time    - the backend sleeps because we told it to
  union   - the database answers with its own version string

UNION only runs on a point that already proved injectable, so the expensive
part pays for itself.
"""

from __future__ import annotations

from . import baseline as baseline_mod
from . import config, payloads, tamper
from . import union as union_mod
from .dberrors import match_error
from .models import Finding, Response


def original_value(point) -> str:
    """Use the exact occurrence, not the first value with the same name."""
    getter = getattr(point, "original", None)
    if callable(getter):
        return getter()
    for name, value in point.params:
        if name == point.param:
            return value
    return ""


def _send(client, point, payload: str, waf: dict) -> tuple[Response, str]:
    """One request, plus an encoded retry if a filter answers instead of the app.

    Returns the response and the payload that actually reached the application,
    so the finding carries something a human can paste and reproduce.
    """
    response = client.send(point, payload)
    if not tamper.blocked(response.status):
        return response, payload
    waf["blocked"] += 1
    for variant in tamper.variants(payload)[1:]:
        attempt = client.send(point, variant)
        if not tamper.blocked(attempt.status):
            waf["bypassed"] += 1
            return attempt, variant
    return response, payload


def _waf_note(waf: dict) -> str:
    if waf["bypassed"]:
        return f" | filter bypassed with {waf['bypassed']} encoded payload(s)"
    if waf["blocked"] >= 2:
        return " | the target answered some payloads with a filter status (403/429)"
    return ""


def _error_based(client, point, base: baseline_mod.Baseline, waf: dict) -> Finding | None:
    base_dbms, _ = match_error(base.text)
    for payload in payloads.ERROR_PAYLOADS:
        response, used = _send(client, point, payload, waf)
        if not response.ok:
            continue
        dbms, line = match_error(response.text)
        if not dbms:
            continue
        if base_dbms and line and line in base.text:
            continue
        if used in base.text:
            continue
        return Finding(
            kind="SQLI",
            severity="CRITICAL",
            url=point.url,
            method=point.method,
            param=point.param,
            payload=used,
            confidence="HIGH",
            evidence=line,
            technique="error",
            detail=f"database error surfaced ({dbms}) - error based injection",
        )
    return None


def _boolean_based(client, point, base: baseline_mod.Baseline, waf: dict) -> Finding | None:
    repeats = 1 if base.stable else config.BOOL_REPEATS
    noise = base.noise()
    floor = min(max(config.PAGE_MIN_DIFF, noise * 3.0), config.PAGE_MAX_FLOOR)
    repeat_threshold = 1.0 - floor

    for true_payload, false_payload in payloads.BOOLEAN_PAIRS:
        hots: list[str] = []
        colds: list[str] = []
        used_true = true_payload
        used_false = false_payload
        for round_index in range(repeats):
            hot, hot_payload = _send(client, point, true_payload, waf)
            cold, cold_payload = _send(client, point, false_payload, waf)
            if not hot.ok or not cold.ok:
                break
            if round_index == 0:
                used_true = hot_payload
                used_false = cold_payload
            hots.append(hot.text)
            colds.append(cold.text)
        if len(hots) != repeats or len(colds) != repeats:
            continue

        # the same branch must reproduce before we compare branches
        if not all(
            baseline_mod.same_text(hots[0], other, repeat_threshold)
            for other in hots[1:]
        ):
            continue
        if not all(
            baseline_mod.same_text(colds[0], other, repeat_threshold)
            for other in colds[1:]
        ):
            continue

        # the true branch must look like the untouched page
        if not base.matches(hots[0]):
            continue

        # ...and the false branch must not, and must differ from the true one
        cold_vs_base = base.similarity(colds[0])
        cross = baseline_mod.text_similarity(hots[0], colds[0])
        if cold_vs_base >= config.PAGE_SAME:
            continue
        if cross > 1.0 - floor:
            continue

        stable_note = "" if base.stable else (
            f" (page is volatile, noise {noise:.1%}, confirmed by {repeats} repeats)"
        )
        return Finding(
            kind="SQLI",
            severity="HIGH" if base.stable else "MEDIUM",
            url=point.url,
            method=point.method,
            param=point.param,
            payload=f"{used_true}  |  {used_false}",
            confidence="HIGH" if base.stable else "MEDIUM",
            evidence=f"true branch {base.similarity(hots[0]):.1%} like baseline, "
                     f"false branch {cold_vs_base:.1%} like baseline, "
                     f"branches {1.0 - cross:.1%} apart{stable_note}",
            technique="boolean",
            detail="boolean based injection: the page changes only on the logical result",
        )
    return None


def _time_based(client, point, base: baseline_mod.Baseline, waf: dict) -> Finding | None:
    for payload, delay in payloads.delimited(payloads.TIME_PAYLOADS, config.SQLI_TIME_DELAY):
        threshold = base.elapsed + (delay * 0.7)
        confirmed = 0
        last_elapsed = 0.0
        used = payload
        for _attempt in range(config.SQLI_TIME_ATTEMPTS):
            response, sent = _send(client, point, payload, waf)
            if not response.ok:
                break
            used = sent
            last_elapsed = response.elapsed
            if response.elapsed >= threshold:
                confirmed += 1
            else:
                break
        if confirmed >= config.SQLI_TIME_ATTEMPTS:
            return Finding(
                kind="SQLI",
                severity="CRITICAL",
                url=point.url,
                method=point.method,
                param=point.param,
                payload=used,
                confidence="HIGH",
                evidence=f"baseline {base.elapsed:.2f}s -> injected {last_elapsed:.2f}s "
                         f"({confirmed} confirmations)",
                technique="time",
                detail="time based injection: the backend sleeps on command",
            )
    return None


def scan_point(
    client,
    point,
    time_based: bool,
    union_probe: bool = True,
    dump: bool = False,
) -> list[Finding]:
    base = baseline_mod.capture(client, point, original_value(point))
    if base is None:
        return []

    waf = {"blocked": 0, "bypassed": 0}

    found = _error_based(client, point, base, waf)
    if found is None:
        found = _boolean_based(client, point, base, waf)
    if found is None and time_based:
        found = _time_based(client, point, base, waf)
    if found is None:
        return []

    note = _waf_note(waf)
    if note:
        found.detail = f"{found.detail}{note}"

    findings = [found]
    if union_probe:
        extracted = union_mod.probe(client, point, base, dump=dump)
        if extracted is not None:
            if note:
                extracted.detail = f"{extracted.detail}{note}"
            findings.append(extracted)
    return findings
