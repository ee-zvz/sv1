"""Compute the Firing Range reflected recall from a manifest and SV1 output.

The comparison unit is the page path, not the finding count. A query point is
counted only when its parameter matches the manifest parameter; header and
cookie findings on the same page do not inflate reflected-query recall.
"""

from __future__ import annotations

import argparse
import json
import urllib.parse
from pathlib import Path


def _path(url: str) -> str:
    return urllib.parse.urlsplit(url).path.rstrip("/") or "/"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def summarize(manifest: list[dict], findings: list[dict],
              reference: list[dict] | None = None) -> dict:
    entries = [
        item for item in manifest
        if str(item.get("method", "")).upper() == "GET"
    ]
    paths: dict[str, dict] = {}
    for item in entries:
        paths.setdefault(_path(item.get("url", "")), item)

    seen: set[str] = set()
    confirmed: set[str] = set()
    by_param: dict[str, str] = {}
    for finding in findings:
        if str(finding.get("kind", "")).upper() != "XSS":
            continue
        if str(finding.get("method", "GET")).upper() != "GET":
            continue
        path = _path(str(finding.get("url", "")))
        entry = paths.get(path)
        if entry is None:
            continue
        if str(finding.get("param", "")) != str(entry.get("param", "")):
            continue
        seen.add(path)
        by_param[path] = str(finding.get("param", ""))
        if str(finding.get("severity", "")).upper() == "HIGH":
            confirmed.add(path)

    reference_paths: set[str] = set()
    for finding in reference or []:
        if str(finding.get("type", "")).upper() != "V":
            continue
        path = _path(str(finding.get("data", "")))
        entry = paths.get(path)
        if entry is None:
            continue
        if str(finding.get("param", "")) != str(entry.get("param", "")):
            continue
        reference_paths.add(path)

    union_paths = set(seen) | reference_paths
    union = len(union_paths)
    missed = sorted(union_paths - seen)
    return {
        "method": "unique page path, query and fragment removed; GET and POST separated",
        "get": {
            "seen": len(seen),
            "confirmed": len(confirmed),
            "missed": missed,
            "coverage": round(len(seen) / union, 6) if union else 0.0,
            "index_coverage": (
                round(len(seen) / len(entries), 6) if entries else 0.0
            ),
            "union": union,
            "index": len(entries),
            "reference_seen": len(reference_paths),
            "by_param": dict(sorted(by_param.items())),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--reference", type=Path, default=None)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    manifest = _load(args.manifest)
    if isinstance(manifest, dict):
        manifest = manifest.get("points") or manifest.get("urls") or []
    findings = _load(args.findings)
    if isinstance(findings, dict):
        findings = findings.get("findings") or []
    reference = _load(args.reference) if args.reference else None
    if isinstance(reference, dict):
        reference = reference.get("findings") or []
    summary = summarize(manifest, findings, reference)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary["get"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
