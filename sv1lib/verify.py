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


def _replay_sqli(client, point, finding: Finding) -> bool:
    if finding.technique == "union":
        # the version banner was read out of the database; nothing stronger exists
        return True

    if finding.technique == "second-order":
        response = client.fetch(finding.url)
        if not response.ok:
            return False
        return bool(sqli.match_error(response.text)[0])

    if finding.technique == "error":
        for payload in tamper.variants(finding.payload):
            response = client.send(point, payload)
            if not response.ok:
                continue
            dbms, _line = sqli.match_error(response.text)
            if dbms:
                return True
        return False

    if finding.technique == "boolean":
        branches = [part.strip() for part in finding.payload.split("|")]
        if len(branches) != 2:
            return False
        hot = _replay_send(client, point, branches[0])
        cold = _replay_send(client, point, branches[1])
        if not hot.ok or not cold.ok:
            return False
        return baseline.text_similarity(hot.text, cold.text) < config.PAGE_SAME

    if finding.technique == "time":
        clean = client.send(point, sqli.original_value(point))
        if not clean.ok:
            return False
        response = _replay_send(client, point, finding.payload)
        if not response.ok:
            return False
        threshold = clean.elapsed + (config.SQLI_TIME_DELAY * 0.7)
        return response.elapsed >= threshold

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
