"""SV1 - exit policy. Findings become a build failure only when asked."""

from __future__ import annotations

from . import config


def should_fail(findings: list, fail_on: str) -> bool:
    """Return True when a finding at or above the requested level exists."""
    level = (fail_on or "any").lower()
    if level == "none":
        return False
    if level == "any":
        return bool(findings)
    threshold = config.SEVERITY_ORDER.get(level.upper(), 99)
    for finding in findings:
        if config.SEVERITY_ORDER.get(finding.severity, 99) <= threshold:
            return True
    return False
