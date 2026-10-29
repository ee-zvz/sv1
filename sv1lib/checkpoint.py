"""SV1 - resumable point scan.

The crawler and browser phases are cheap compared with a long injection pass.
This checkpoint records the points, the completed point keys, and every finding
that has already survived verification. A second run with ``--resume FILE``
loads the snapshot, keeps the old points, and sends payloads only for work that
is still pending.

The file is JSON and is written atomically. It contains request templates and
findings, so treat it as sensitive: imported header/cookie points can carry
session material and reproduction commands can contain the live cookie. It does
not store login passwords or the operator's CLI credential arguments. The cookie
jar is not serialized, but header points and curl commands may carry cookies, so
the file is session material, not a progress-only record.
"""

from __future__ import annotations

import dataclasses
import json
import os
import time

from . import config, identity
from .history import point_from_dict, point_to_dict
from .models import Finding, InjectionPoint

SCHEMA_VERSION = 1


class CheckpointError(Exception):
    """The checkpoint cannot be read, or belongs to another scan."""


def key(point: InjectionPoint) -> str:
    return json.dumps(
        point.key(), ensure_ascii=False, separators=(",", ":"), default=str,
    )


def target_key(url: str) -> str:
    return identity.normalize_url(url)


def load(path: str, target: str | None = None) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except OSError as exc:
        raise CheckpointError(f"cannot read checkpoint: {exc.strerror}") from exc
    except json.JSONDecodeError as exc:
        raise CheckpointError(f"invalid checkpoint json at line {exc.lineno}") from exc
    if not isinstance(raw, dict):
        raise CheckpointError("checkpoint must be a json object")
    if raw.get("schema") != SCHEMA_VERSION:
        raise CheckpointError("checkpoint schema is not supported")
    if target is not None:
        saved = str(raw.get("target", ""))
        if target_key(saved) != target_key(target):
            raise CheckpointError(
                f"checkpoint target is {saved or '(empty)'}, not {target}"
            )
    points = raw.get("points")
    if not isinstance(points, list):
        raise CheckpointError("checkpoint has no points list")
    return raw


def restore(raw: dict) -> tuple[list[InjectionPoint], set[str], list[tuple[Finding, InjectionPoint]]]:
    points: list[InjectionPoint] = []
    for item in raw.get("points", []):
        if not isinstance(item, dict):
            continue
        try:
            points.append(point_from_dict(item))
        except (TypeError, ValueError):
            continue
    completed = {
        str(item)
        for item in raw.get("completed", [])
        if isinstance(item, str)
    }
    pairs: list[tuple[Finding, InjectionPoint]] = []
    for item in raw.get("findings", []):
        if not isinstance(item, dict):
            continue
        finding_raw = item.get("finding")
        point_raw = item.get("point")
        if not isinstance(finding_raw, dict) or not isinstance(point_raw, dict):
            continue
        try:
            finding = finding_from_dict(finding_raw)
            point = point_from_dict(point_raw)
        except (TypeError, ValueError):
            continue
        pairs.append((finding, point))
    return points, completed, pairs


def finding_from_dict(raw: dict) -> Finding:
    allowed = {field.name for field in dataclasses.fields(Finding)}
    values = {name: value for name, value in raw.items() if name in allowed}
    if not isinstance(values.get("data"), dict):
        values["data"] = {}
    if not isinstance(values.get("alternatives"), list):
        values["alternatives"] = []
    return Finding(**values)


def save(path: str, target: str, points: list[InjectionPoint],
         completed: set[str], pairs: list[tuple[Finding, InjectionPoint]],
         stats=None, meta: dict | None = None) -> str:
    if not path:
        return ""
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    payload = {
        "schema": SCHEMA_VERSION,
        "tool_version": config.TOOL_VERSION,
        "target": target,
        "updated": time.time(),
        "points": [point_to_dict(point) for point in points],
        "completed": sorted(completed),
        "findings": [
            {
                "finding": finding.to_dict(),
                "point": point_to_dict(point),
            }
            for finding, point in pairs
        ],
        "stats": _stats(stats),
        "meta": _meta(meta),
    }
    temporary = f"{path}.{os.getpid()}.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, default=str)
        os.replace(temporary, path)
    except (OSError, TypeError, ValueError):
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return path


def _stats(stats) -> dict:
    if stats is None:
        return {}
    return {
        "pages": int(getattr(stats, "pages", 0)),
        "points": int(getattr(stats, "points", 0)),
        "requests": int(getattr(stats, "requests", 0)),
        "errors": int(getattr(stats, "errors", 0)),
        "confirmed": int(getattr(stats, "confirmed", 0)),
        "replayed": int(getattr(stats, "replayed", 0)),
        "unverified": int(getattr(stats, "unverified", 0)),
    }


def _meta(meta: dict | None) -> dict:
    """Keep restart-relevant scan options; never accept arbitrary secrets."""
    allowed = (
        "crawl", "depth", "scanners", "time_based", "union", "dump",
        "second_order", "blind", "ssrf", "stored", "params", "path",
        "hidden_fields", "password_fields", "login_attack", "js", "spa",
        "openapi", "login", "login_ok",
    )
    source = meta or {}
    return {name: source[name] for name in allowed if name in source}


def compatible(raw: dict, meta: dict) -> tuple[bool, str]:
    """Refuse to mix a checkpoint with a materially different scan."""
    saved = raw.get("meta") or {}
    for name in ("crawl", "depth", "scanners", "time_based", "union", "dump",
                 "second_order", "blind", "ssrf", "stored", "params", "path",
                 "hidden_fields", "password_fields", "login_attack", "js",
                 "spa", "openapi", "login"):
        if name not in saved:
            continue
        fallback = False if isinstance(saved[name], bool) else None
        if saved[name] != meta.get(name, fallback):
            return False, f"checkpoint option '{name}' differs from this run"
    return True, ""


def summary(raw: dict) -> str:
    points = len(raw.get("points") or [])
    completed = len(raw.get("completed") or [])
    findings = len(raw.get("findings") or [])
    updated = float(raw.get("updated", 0.0) or 0.0)
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(updated)) if updated else "?"
    return f"{completed}/{points} point(s), {findings} finding(s), updated {when}"
