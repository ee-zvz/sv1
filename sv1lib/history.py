"""SV1 - SQLite history, session diff and stored-finding retest."""

from __future__ import annotations

import json
import os
import sqlite3
import time

from . import config
from .identity import fingerprint, normalize_url
from .models import Finding, InjectionPoint


class HistoryError(Exception):
    """The history file cannot be opened or used."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    target_key TEXT NOT NULL,
    started REAL NOT NULL,
    finished REAL NOT NULL,
    tool_version TEXT NOT NULL,
    meta TEXT NOT NULL,
    stats TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_target ON sessions(target_key, id DESC);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    param TEXT NOT NULL,
    payload TEXT NOT NULL,
    confidence TEXT NOT NULL,
    technique TEXT NOT NULL,
    evidence TEXT NOT NULL,
    detail TEXT NOT NULL,
    artifact TEXT NOT NULL,
    data TEXT NOT NULL,
    point TEXT
);
CREATE INDEX IF NOT EXISTS findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS findings_fp ON findings(fingerprint);
"""


def point_to_dict(point: InjectionPoint) -> dict:
    return {
        "url": point.url,
        "method": point.method,
        "params": [[name, value] for name, value in point.params],
        "param": point.param,
        "source": point.source,
        "param_index": point.param_index,
    }


def point_from_dict(raw: dict) -> InjectionPoint:
    return InjectionPoint(
        url=str(raw.get("url", "")),
        method=str(raw.get("method", "GET")),
        params=tuple((str(item[0]), str(item[1])) for item in raw.get("params", [])),
        param=str(raw.get("param", "")),
        source=str(raw.get("source", "query")),
        param_index=int(raw.get("param_index", 0) or 0),
    )


def finding_from_row(row: dict) -> Finding:
    data = row.get("data") or {}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            data = {}
    return Finding(
        kind=str(row.get("kind", "")),
        severity=str(row.get("severity", "")),
        url=str(row.get("url", "")),
        method=str(row.get("method", "GET")),
        param=str(row.get("param", "")),
        payload=str(row.get("payload", "")),
        confidence=str(row.get("confidence", "")),
        evidence=str(row.get("evidence", "")),
        technique=str(row.get("technique", "")),
        detail=str(row.get("detail", "")),
        artifact=str(row.get("artifact", "")),
        data=data if isinstance(data, dict) else {},
    )


def row_to_point(row: dict) -> InjectionPoint | None:
    raw = row.get("point")
    if not raw:
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if not isinstance(raw, dict) or not raw.get("url"):
        return None
    try:
        return point_from_dict(raw)
    except (TypeError, ValueError):
        return None


class History:
    def __init__(self, path: str) -> None:
        self.path = path
        try:
            if path != ":memory:":
                parent = os.path.dirname(os.path.abspath(path))
                if parent:
                    os.makedirs(parent, exist_ok=True)
            self.conn = sqlite3.connect(path, timeout=10.0)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.executescript(SCHEMA)
            self.conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema', ?)",
                (str(config.HISTORY_SCHEMA_VERSION),),
            )
            self.conn.commit()
        except (OSError, sqlite3.Error) as exc:
            raise HistoryError(str(exc)) from exc

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def latest(self, target: str) -> dict | None:
        key = normalize_url(target)
        try:
            row = self.conn.execute(
                "SELECT * FROM sessions WHERE target_key = ? ORDER BY id DESC LIMIT 1",
                (key,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise HistoryError(str(exc)) from exc
        if row is None:
            return None
        return _session_row(row)

    def session(self, session_id: int) -> dict | None:
        try:
            row = self.conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise HistoryError(str(exc)) from exc
        return _session_row(row) if row is not None else None

    def rows(self, session_id: int) -> list[dict]:
        try:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY id", (session_id,)
            ).fetchall()
        except sqlite3.Error as exc:
            raise HistoryError(str(exc)) from exc
        result = []
        for row in rows:
            item = dict(row)
            item["data"] = _load_json(item.get("data"), {})
            item["point"] = _load_json(item.get("point"), None)
            result.append(item)
        return result

    def record(self, target: str, meta: dict, stats, findings: list, pairs: list) -> int:
        point_by_finding = {id(finding): point for finding, point in pairs}
        try:
            with self.conn:
                cursor = self.conn.execute(
                    """INSERT INTO sessions
                       (target, target_key, started, finished, tool_version, meta, stats)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        target,
                        normalize_url(target),
                        float(getattr(stats, "started", time.time())),
                        float(getattr(stats, "finished", time.time())),
                        config.TOOL_VERSION,
                        _dump_json(meta),
                        _dump_json(_stats_dict(stats)),
                    ),
                )
                session_id = int(cursor.lastrowid)
                for finding in findings:
                    point = point_by_finding.get(id(finding))
                    self.conn.execute(
                        """INSERT INTO findings
                           (session_id, fingerprint, kind, severity, url, method, param,
                            payload, confidence, technique, evidence, detail, artifact,
                            data, point)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            session_id,
                            fingerprint(finding),
                            finding.kind,
                            finding.severity,
                            finding.url,
                            finding.method,
                            finding.param,
                            finding.payload,
                            finding.confidence,
                            finding.technique,
                            finding.evidence,
                            finding.detail,
                            finding.artifact,
                            _dump_json(finding.data),
                            _dump_json(point_to_dict(point)) if point is not None else None,
                        ),
                    )
            return session_id
        except sqlite3.Error as exc:
            raise HistoryError(str(exc)) from exc

    def fingerprints(self, session_id: int) -> set[str]:
        try:
            rows = self.conn.execute(
                "SELECT fingerprint FROM findings WHERE session_id = ?", (session_id,)
            ).fetchall()
        except sqlite3.Error as exc:
            raise HistoryError(str(exc)) from exc
        return {str(row[0]) for row in rows}

    def diff(self, previous_id: int, findings: list) -> dict:
        previous = self.fingerprints(previous_id)
        current = {fingerprint(finding) for finding in findings}
        return {
            "new": len(current - previous),
            "same": len(current & previous),
            "fixed": len(previous - current),
            "previous": previous_id,
        }


def _session_row(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["meta"] = _load_json(item.get("meta"), {})
    item["stats"] = _load_json(item.get("stats"), {})
    return item


def _stats_dict(stats) -> dict:
    return {
        "pages": int(getattr(stats, "pages", 0)),
        "points": int(getattr(stats, "points", 0)),
        "requests": int(getattr(stats, "requests", 0)),
        "errors": int(getattr(stats, "errors", 0)),
        "verified": int(getattr(stats, "verified", 0)),
        "unverified": int(getattr(stats, "unverified", 0)),
        "fixed": int(getattr(stats, "fixed", 0)),
        "duration_seconds": round(float(getattr(stats, "duration", 0.0)), 2),
    }


def _dump_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _load_json(raw, default):
    if not raw:
        return default
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default
