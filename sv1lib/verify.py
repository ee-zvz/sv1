"""SV1 - replay. A finding that cannot be reproduced is not a finding."""

from __future__ import annotations

from . import baseline, config, sqli, tamper, xss
from .models import Finding

DOWNGRADE = {
    "CRITICAL": "HIGH",
    "HIGH": "MEDIUM",
    "MEDIUM": "LOW",
    "LOW": "INFO",
    "INFO": "INFO",
}


def _replay_xss(client, point, finding: Finding) -> bool:
    if finding.technique == "reflection-encoded":
        return bool(xss.scan_point(client, point))
    response = client.send(point, finding.payload)
    return response.ok and finding.payload in response.text


def _baseline(client, point):
    """The untouched endpoint, measured again next to the replay.

    A database error or a page difference is only evidence against this
    baseline. Reusing the scan's response is not enough: the target may have
    changed between passes, and volatile pages must not be promoted.
    """
    return baseline.capture(client, point, sqli.original_value(point))


def _replay_error(client, point, finding: Finding) -> bool:
    base = _baseline(client, point)
    if base is None:
        return False
    response = _replay_send(client, point, finding.payload)
    if not response.ok:
        return False
    dbms, line = sqli.match_error(response.text)
    if not dbms:
        return False
    if line and line in base.text:
        return False
    if finding.payload in base.text:
        return False
    return True


def _replay_boolean(client, point, finding: Finding) -> bool:
    branches = [part.strip() for part in finding.payload.split("|")]
    if len(branches) != 2:
        return False
    base = _baseline(client, point)
    if base is None:
        return False
    hot = _replay_send(client, point, branches[0])
    cold = _replay_send(client, point, branches[1])
    if not hot.ok or not cold.ok:
        return False
    if not base.matches(hot.text):
        return False
    if base.similarity(cold.text) >= config.PAGE_SAME:
        return False
    floor = min(
        max(config.PAGE_MIN_DIFF, base.noise() * 3.0),
        config.PAGE_MAX_FLOOR,
    )
    cross = baseline.text_similarity(hot.text, cold.text)
    return cross <= 1.0 - floor


def _replay_time(client, point, finding: Finding) -> bool:
    base = _baseline(client, point)
    if base is None:
        return False
    response = _replay_send(client, point, finding.payload)
    if not response.ok:
        return False
    threshold = base.elapsed + (config.SQLI_TIME_DELAY * 0.7)
    return response.elapsed >= threshold


def _replay_second_order(client, finding: Finding) -> bool:
    """Fetch the sink twice and reject the scan-time baseline error.

    Re-submitting the payload is not used here: the first replay would leave a
    second stored copy and poison the next baseline. The detection pass records
    its clean baseline, so two fetches are enough to prove the same sink still
    fails in the same way.
    """
    before = str(finding.data.get("baseline_error") or "")
    checked = finding.data.get("baseline_checked") == "1"
    signatures: list[str] = []
    for _ in range(config.BASELINE_SAMPLES):
        response = client.fetch(finding.url)
        if not response.ok:
            return False
        dbms, line = sqli.match_error(response.text)
        if not dbms:
            return False
        signature = line or dbms
        if checked and before and signature == before:
            return False
        signatures.append(signature)
    return len(signatures) == config.BASELINE_SAMPLES and len(set(signatures)) == 1


def _replay_sqli(client, point, finding: Finding) -> bool:
    if finding.technique == "union":
        # the version banner was read out of the database; nothing stronger exists
        return True

    if finding.technique == "second-order":
        return _replay_second_order(client, finding)

    if finding.technique == "error":
        return _replay_error(client, point, finding)

    if finding.technique == "boolean":
        return _replay_boolean(client, point, finding)

    if finding.technique == "time":
        return _replay_time(client, point, finding)

    return False


def _replay_send(client, point, payload: str):
    """Same payload, encoded retries included: a filter must not fake instability."""
    response = client.send(point, payload)
    if not tamper.blocked(response.status):
        return response
    for variant in tamper.variants(payload)[1:]:
        attempt = client.send(point, variant)
        if not tamper.blocked(attempt.status):
            return attempt
    return response


def replay(client, point, finding: Finding) -> bool:
    if finding.kind == "XSS":
        return _replay_xss(client, point, finding)
    return _replay_sqli(client, point, finding)


def verify(client, point, finding: Finding) -> bool:
    for _ in range(config.VERIFY_ROUNDS):
        if not replay(client, point, finding):
            return False
    return True


def demote(finding: Finding) -> Finding:
    finding.severity = DOWNGRADE.get(finding.severity, "INFO")
    finding.confidence = "LOW"
    note = "replay did not reproduce; treated as unstable"
    finding.detail = f"{finding.detail} | {note}" if finding.detail else note
    return finding
