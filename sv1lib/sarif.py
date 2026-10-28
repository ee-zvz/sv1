"""SV1 - SARIF 2.1.0 export for code scanning and CI."""

from __future__ import annotations

import json
import time

from . import config
from .identity import fingerprint

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"

LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

SECURITY_SCORE = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 3.0,
    "INFO": 0.0,
}

DESCRIPTION = {
    "XSS": "Cross-site scripting: attacker-controlled input executes in a victim browser.",
    "SQLI": "SQL injection: attacker-controlled input changes a database query.",
    "SSRF": "Server-side request forgery: the target fetches an attacker-controlled URL.",
}


def _rule_id(finding) -> str:
    technique = (finding.technique or "generic").replace("/", "-").replace(" ", "-")
    kind = (finding.kind or "finding").replace("/", "-")
    return f"SV1/{kind}/{technique}"


def _message(finding) -> str:
    target = f"{finding.method} {finding.url} [{finding.param}]"
    proof = f" - {finding.evidence}" if finding.evidence else ""
    return f"{finding.kind} {finding.severity} ({finding.confidence}) at {target}{proof}"[:2000]


def build(findings: list, stats, meta: dict) -> dict:
    rules: list[dict] = []
    index_by_id: dict[str, int] = {}
    for finding in sorted(findings, key=lambda item: _rule_id(item)):
        rule_id = _rule_id(finding)
        if rule_id in index_by_id:
            continue
        index_by_id[rule_id] = len(rules)
        title = f"{finding.kind} - {finding.technique or 'generic'}"
        rules.append(
            {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {
                    "text": DESCRIPTION.get(
                        finding.kind,
                        f"SV1 finding of type {finding.kind}.",
                    )
                },
                "defaultConfiguration": {"level": LEVEL.get(finding.severity, "warning")},
                "properties": {
                    "tags": ["security", finding.kind.lower(), finding.technique or "generic"],
                    "precision": "high" if finding.confidence == "CONFIRMED" else "medium",
                    "security-severity": str(SECURITY_SCORE.get(finding.severity, 5.5)),
                },
            }
        )

    results = []
    for finding in findings:
        rule_id = _rule_id(finding)
        props = {
            "severity": finding.severity,
            "confidence": finding.confidence,
            "kind": finding.kind,
            "method": finding.method,
            "param": finding.param,
            "payload": finding.payload,
            "technique": finding.technique,
            "evidence": finding.evidence,
            "detail": finding.detail,
            "data": finding.data,
            "artifact": finding.artifact,
            "security-severity": str(SECURITY_SCORE.get(finding.severity, 5.5)),
        }
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": index_by_id[rule_id],
                "level": LEVEL.get(finding.severity, "warning"),
                "message": {"text": _message(finding)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.url},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {"sv1Fingerprint": fingerprint(finding)},
                "properties": props,
            }
        )

    started, finished = _timestamps(stats)
    errors = int(getattr(stats, "errors", 0))
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": config.TOOL_NAME,
                        "fullName": "SV1 web vulnerability scanner",
                        "version": config.TOOL_VERSION,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": errors == 0,
                        "startTimeUtc": started,
                        "endTimeUtc": finished,
                    }
                ],
                "columnKind": "utf16CodeUnits",
                "results": results,
                "properties": {
                    "target": meta.get("target", ""),
                    "tool_author": config.TOOL_AUTHOR,
                    "duration_seconds": round(float(getattr(stats, "duration", 0.0)), 2),
                    "requests": int(getattr(stats, "requests", 0)),
                    "errorCount": errors,
                    "scanners": meta.get("scanners", []),
                    "retest": bool(meta.get("retest", False)),
                },
            }
        ],
    }


def write(path: str, findings: list, stats, meta: dict) -> str:
    payload = build(findings, stats, meta)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
    return path


def _timestamps(stats) -> tuple[str, str]:
    """Return wall-clock SARIF times from monotonic or epoch scan stats.

    ScanStats uses ``time.monotonic`` for a stable duration. Feeding that value
    to ``gmtime`` produced 1970 timestamps, which look like corrupt evidence.
    Epoch values are still accepted for callers that already provide them.
    """
    started = float(getattr(stats, "started", 0.0))
    finished = float(getattr(stats, "finished", 0.0))
    if started > 1_000_000_000 and finished > 1_000_000_000:
        return _utc(started), _utc(finished)
    duration = max(0.0, float(getattr(stats, "duration", 0.0)))
    end = time.time()
    return _utc(end - duration), _utc(end)


def _utc(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
