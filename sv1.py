#!/usr/bin/env python3
"""SV1 - web vulnerability scanner for XSS and SQL injection.

    python sv1.py -u https://target.tld --crawl

Author: ee.zvz
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import traceback

from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.version_info < (3, 10):
    sys.stderr.write("SV1 needs Python 3.10 or newer\n")
    raise SystemExit(2)

from sv1lib import auth, banner, blind, config, crawl, discovery, domxss, hidden
from sv1lib import imports as imports_mod, jsparse, net, oob, openapi, report, spa, sqli, ssrf
from sv1lib import browser as browser_mod
from sv1lib import checkpoint as checkpoint_mod
from sv1lib import history as history_mod
from sv1lib import policy, sarif, scope as scope_mod
from sv1lib import secondorder, storage, stored, verify, xss
from sv1lib.models import ScanStats

TOKEN_RE = re.compile(r"sv1[0-9a-zA-Z]+")


def _positive_float(value: str) -> float:
    """Argparse type: reject zero/negative instead of crashing in requests."""
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number greater than zero") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


BANNER = r"""
  ███████╗██╗   ██╗ ██╗
  ██╔════╝██║   ██║███║
  ███████╗██║   ██║╚██║
  ╚════██║╚██╗ ██╔╝ ██║
  ███████║ ╚████╔╝  ██║
  ╚══════╝  ╚═══╝   ╚═╝
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sv1",
        description="SV1 - XSS, SQL injection, blind and SSRF scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python sv1.py -u http://127.0.0.1:8080/app.php --crawl
  python sv1.py -u https://site.tld/search?q=test --xss
  python sv1.py -u https://site.tld/item?id=1 --sqli --time
  python sv1.py -u https://site.tld --crawl --cookie "PHPSESSID=abc" -o out.json
  python sv1.py -u https://site.tld --crawl --blind --oob https://cb.example.tld
  python sv1.py -u "https://site.tld/fetch?url=x" --ssrf
  python sv1.py -u https://site.tld --crawl --db sv1-history.db --diff
  python sv1.py -u https://site.tld --crawl --sarif sv1.sarif --fail-on high
  python sv1.py -u https://site.tld --db sv1-history.db --retest
  python sv1.py -u https://site.tld --crawl --storage-state state.json
  python sv1.py -u https://site.tld --crawl --hidden-fields --password-fields
""",
    )
    parser.add_argument("--version", action="version",
                        version=f"SV1 {config.TOOL_VERSION} by {config.TOOL_AUTHOR}")
    parser.add_argument("-u", "--url", required=True, help="target url")
    parser.add_argument("--crawl", action="store_true", help="follow links from the target")
    parser.add_argument("--depth", type=int, default=config.DEFAULT_MAX_DEPTH, help="crawl depth (default 2)")
    parser.add_argument("--pages", type=int, default=config.DEFAULT_MAX_PAGES, help="max pages to crawl")
    parser.add_argument("--threads", type=int, default=8, help="worker threads (default 8)")
    parser.add_argument("--timeout", type=_positive_float, default=config.DEFAULT_TIMEOUT,
                        help="request timeout seconds (greater than zero)")
    parser.add_argument("--rps", type=float, default=config.DEFAULT_RPS, help="requests per second (0 = unlimited)")
    parser.add_argument("--fail-on", choices=config.FAIL_ON_CHOICES, default="any",
                        help="exit 1 at or above this severity (default any)")
    parser.add_argument("--scope", default="", metavar="FILE",
                        help="host/path allowlist file; rejects everything else")
    parser.add_argument("--db", default="", metavar="FILE",
                        help="sqlite history file (sessions, diff, retest)")
    parser.add_argument("--diff", action="store_true",
                        help="compare this run with the previous --db session")
    parser.add_argument("--retest", action="store_true",
                        help="replay stored findings from --db instead of crawling")
    parser.add_argument("--sarif", default="", metavar="FILE",
                        help="write a SARIF 2.1.0 report")

    parser.add_argument("--xss", action="store_true", help="run xss checks only")
    parser.add_argument("--sqli", action="store_true", help="run sqli checks only")
    parser.add_argument("--time", dest="time_based", action="store_true", help="enable time based sqli payloads")
    parser.add_argument("--no-xss", action="store_true", help="disable xss checks")
    parser.add_argument("--no-sqli", action="store_true", help="disable sqli checks")
    parser.add_argument("--no-union", action="store_true", help="skip union based extraction")

    parser.add_argument("--headers", action="store_true", help="inject into x-forwarded-for, referer, user-agent")
    parser.add_argument("--deep", action="store_true", help="add more header candidates")
    parser.add_argument("--cookies", action="store_true", help="inject into the cookie values you passed")
    parser.add_argument("--json", default="", help="json endpoint to test (default POST)")
    parser.add_argument("--json-data", default='{"id": "1", "q": "test"}', help="json body template")
    parser.add_argument("--data", default="", help="raw body template; use * as the injection marker")
    parser.add_argument("--method", default="POST", help="method for --data/--json (default POST)")
    parser.add_argument("--content-type", default="", help="content type for --data/--json")
    parser.add_argument("--har", default="", metavar="FILE",
                        help="import cookies, headers and points from a HAR file")
    parser.add_argument("--request", default="", metavar="FILE",
                        help="import one raw HTTP request file")
    parser.add_argument("--storage-state", default="", metavar="FILE",
                        help="playwright storage-state json (target cookies + localStorage)")
    parser.add_argument("--save-storage-state", default="", metavar="FILE",
                        help="write target-scoped browser state after the scan")
    parser.add_argument("--login", nargs="?", const="auto", default="", metavar="URL",
                        help="log in through a same-origin form before crawling (auto = target)")
    parser.add_argument("--username", default=os.environ.get("SV1_USERNAME", ""),
                        help="login username (or set SV1_USERNAME)")
    parser.add_argument("--password", default=os.environ.get("SV1_PASSWORD", ""),
                        help="login password (prefer SV1_PASSWORD over argv)")
    parser.add_argument("--login-user-field", default="", metavar="NAME",
                        help="explicit username input name")
    parser.add_argument("--login-pass-field", default="", metavar="NAME",
                        help="explicit password input name")
    parser.add_argument("--login-check", default="", metavar="TEXT",
                        help="require this text after login (recommended)")
    parser.add_argument("--login-attack", action="store_true",
                        help="also fuzz the username field of the login form")
    parser.add_argument("--sitemap", action="store_true",
                        help="seed the crawler from robots.txt and sitemap.xml")
    parser.add_argument("--resume", default="", metavar="FILE",
                        help="resume a point scan from a checkpoint file")
    parser.add_argument("--hidden-fields", dest="hidden_fields", action="store_true",
                        help="inject into hidden form inputs (off by default; may overwrite CSRF tokens)")
    parser.add_argument("--password-fields", dest="password_fields", action="store_true",
                        help="inject into password form inputs (off by default)")
    parser.add_argument("--params", action="store_true", help="discover hidden query parameters")
    parser.add_argument("--js", action="store_true", help="mine endpoints from javascript")
    parser.add_argument("--second-order", action="store_true",
                        help="probe second-order sqli (writes to the target)")
    parser.add_argument("--dump", action="store_true",
                        help="extract current user, database and table names via union")
    parser.add_argument("--spa", action="store_true",
                        help="render pages in chromium and capture xhr endpoints")
    parser.add_argument("--external-js", action="store_true",
                        help="analyse same-origin external scripts for DOM XSS")
    parser.add_argument("--openapi", default="", help="openapi json spec (url or file)")
    parser.add_argument("--blind", action="store_true",
                        help="seed blind xss with callbacks (writes to the target)")
    parser.add_argument("--blind-visit", action="append", default=[], metavar="URL",
                        help="page to open after seeding, repeatable (simulated admin)")
    parser.add_argument("--ssrf", action="store_true",
                        help="probe url-like parameters for server side fetches")
    parser.add_argument("--oob", default="", help="public callback base url")
    parser.add_argument("--oob-bind", default="",
                        help=f"callback listener host:port (default 127.0.0.1:{config.OOB_PORT})")
    parser.add_argument("--oob-wait", type=float, default=config.OOB_WAIT,
                        help=f"seconds to wait for callbacks after probing (default {config.OOB_WAIT:g})")

    parser.add_argument("-H", "--header", action="append", default=[], help="extra header, repeatable")
    parser.add_argument("--cookie", default="", help='cookie header, e.g. "sid=abc; theme=dark"')
    parser.add_argument("--proxy", default="", help="http(s) proxy url")
    parser.add_argument("-k", "--insecure", action="store_true", help="skip tls verification")
    parser.add_argument("-o", "--output", default="", help="write findings to .json or .csv")
    parser.add_argument("--html", nargs="?", const=config.HTML_REPORT, default="",
                        help="write an html report with screenshots (default sv1-report.html)")
    parser.add_argument("--browser", action="store_true", help="force chromium execution proof")
    parser.add_argument("--no-browser", action="store_true", help="never launch chromium")
    parser.add_argument("--stored", action="store_true", help="probe for stored xss (writes to the target)")
    parser.add_argument("--artifacts", default=config.ARTIFACT_DIR, help="screenshot folder")
    parser.add_argument("--no-verify", action="store_true", help="skip the replay pass")
    parser.add_argument("--no-banner", action="store_true", help="skip the splash animation")
    parser.add_argument("-v", "--verbose", action="store_true", help="show transport errors")
    return parser.parse_args(argv)


def parse_headers(raw: list[str]) -> dict:
    headers = {}
    for item in raw:
        if ":" not in item:
            continue
        key, value = item.split(":", 1)
        key, value = key.strip(), value.strip()
        if key:
            headers[key] = value
    return headers


def parse_cookies(raw: str) -> dict:
    cookies = {}
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        key = key.strip()
        if key:
            cookies[key] = value.strip()
    return cookies


def select_scanners(args: argparse.Namespace) -> list[str]:
    if args.xss and not args.sqli:
        return ["xss"]
    if args.sqli and not args.xss:
        return ["sqli"]
    chosen = []
    if not args.no_xss:
        chosen.append("xss")
    if not args.no_sqli:
        chosen.append("sqli")
    return chosen


def make_browser(args: argparse.Namespace, target: str,
                 headers: dict | None = None, cookies: dict | None = None,
                 allows=None, storage_state: dict | None = None):
    return browser_mod.Browser(
        headers=headers if headers is not None else parse_headers(args.header),
        cookies=cookies if cookies is not None else parse_cookies(args.cookie),
        proxy=args.proxy,
        ignore_https=args.insecure,
        base_url=target,
        artifacts=args.artifacts,
        timeout_ms=config.BROWSER_TIMEOUT_MS,
        allows=allows,
        storage_state=storage_state,
    )


def scan_point(client, point, scanners: list[str], time_based: bool,
               union_probe: bool, dump: bool = False) -> list:
    findings = []
    if "xss" in scanners:
        findings.extend(xss.scan_point(client, point))
    if "sqli" in scanners:
        findings.extend(sqli.scan_point(client, point, time_based, union_probe, dump))
    return findings


def merge_points(points: list, extra: list) -> None:
    seen = {point.key() for point in points}
    for point in extra:
        if point.key() in seen:
            continue
        seen.add(point.key())
        points.append(point)


def extra_points(args: argparse.Namespace, target: str, cookies: dict) -> list:
    """Header, cookie, JSON and raw body points are opt in."""
    extra = []
    if args.headers:
        extra.extend(crawl.header_points(target, deep=args.deep))
    if args.cookies and cookies:
        extra.extend(crawl.cookie_points(target, cookies))

    method = (args.method or "POST").upper()
    content_type = args.content_type or "application/json"
    if args.json:
        try:
            data = json.loads(args.json_data)
        except json.JSONDecodeError:
            report.warn("--json-data is not valid json - json point skipped")
        else:
            points = crawl.json_points(
                args.json, data, method=method, content_type=content_type
            )
            if points:
                extra.extend(points)
            else:
                report.warn("--json-data has no scalar leaves - json point skipped")

    if args.data:
        raw_type = args.content_type
        stripped = args.data.lstrip()
        if "json" in raw_type.lower() or stripped.startswith(("{", "[")):
            try:
                data = json.loads(args.data)
            except json.JSONDecodeError as exc:
                report.warn(f"--data is not valid json - {exc.msg}")
            else:
                points = crawl.json_points(
                    target, data, method=method,
                    content_type=raw_type or "application/json",
                )
                if points:
                    extra.extend(points)
                else:
                    report.warn("--data has no scalar leaves - raw point skipped")
        else:
            points = crawl.raw_point(
                target, args.data, method=method, content_type=raw_type
            )
            if points:
                extra.extend(points)
            else:
                report.warn("--data needs a * marker when it is not JSON")
    return extra


def token_of(payload: str) -> str:
    match = TOKEN_RE.search(payload or "")
    return match.group(0) if match else ""


def artifact_path(root: str, kind: str, index: int) -> str:
    return f"{root}/{kind}-{index:02d}.png" if root else ""


def prove_xss(engine, pairs: list, args: argparse.Namespace, client=None) -> None:
    """Turn 'the payload came back' into 'the payload ran'.

    When Chromium is available, HIGH is reserved for execution. An exact
    reflection that the browser did not run is still useful evidence, but it
    is MEDIUM: reflection alone is not proof.
    """
    xss_pairs = [(finding, point) for finding, point in pairs if finding.kind == "XSS"]
    if not xss_pairs:
        return
    report.section("execution")
    for index, (finding, point) in enumerate(xss_pairs, 1):
        if finding.technique == "reflection-encoded":
            continue
        if point.source not in ("query", "form", "multipart", "path",
                                "json", "raw", "js"):
            finding.severity = "MEDIUM"
            note = f"browser proof unavailable for {point.source} inputs"
            finding.detail = f"{finding.detail} | {note}".strip(" |")
            report.warn(f"{finding.url} [{finding.param}]  {note}")
            continue
        candidates: list[str] = []
        for payload_text in [finding.payload, *finding.alternatives]:
            if token_of(payload_text) and payload_text not in candidates:
                candidates.append(payload_text)
        candidates = candidates[: config.XSS_MAX_PROOFS]
        if not candidates:
            continue
        shot = artifact_path(args.artifacts, "xss", index)
        label = f"{finding.url} [{finding.param}]"
        executed = None
        attempt = 0
        for attempt, payload_text in enumerate(candidates, 1):
            token = token_of(payload_text)
            visit = engine.visit_point(
                point,
                payload_text,
                shot_path=shot,
                interact_marker=token,
            )
            if visit.fired(token):
                executed = (payload_text, token, visit)
                break
        if executed is not None:
            payload_text, token, visit = executed
            finding.payload = payload_text
            finding.curl = (
                net.repro_curl(client, point, payload_text)
                if client is not None else net.curl(point, payload_text)
            )
            finding.alternatives = [
                item for item in finding.alternatives if item != payload_text
            ]
            finding.severity = "HIGH"
            finding.confidence = "CONFIRMED"
            finding.evidence = f"executed in chromium: {visit.proof(token)}"
            detail = finding.detail
            pending = "reflection confirmed; execution not yet proven"
            if detail.startswith(pending):
                detail = "execution confirmed in chromium" + detail[len(pending):]
            finding.detail = f"{detail} | proof: alert fired".strip(" |")
            if attempt > 1:
                finding.detail = f"{finding.detail} | payload {attempt}/{len(candidates)}"
            finding.artifact = visit.screenshot
            report.good(f"{label}  executed")
        else:
            finding.severity = "MEDIUM"
            finding.confidence = "MEDIUM"
            note = "chromium did not execute the payload"
            if len(candidates) > 1:
                note = f"chromium did not execute {len(candidates)} payload(s)"
            finding.detail = f"{finding.detail} | {note}".strip(" |")
            report.warn(f"{label}  not executed")


def demote_unproven_xss(pairs: list, reason: str) -> None:
    """Reflection without a browser is not execution proof."""
    for finding, _point in pairs:
        if finding.kind != "XSS" or finding.technique == "reflection-encoded":
            continue
        finding.severity = "MEDIUM"
        finding.confidence = "MEDIUM"
        note = f"reflection only: {reason}"
        finding.detail = f"{finding.detail} | {note}".strip(" |")


def export_reports(findings: list, stats, meta: dict, args: argparse.Namespace) -> int:
    try:
        if args.output:
            path = report.export(args.output, findings, stats, meta)
            report.good(f"written {os.path.abspath(path)}")
        if args.html:
            path = report.export_html(args.html, findings, stats, meta)
            report.good(f"written {os.path.abspath(path)}")
        if args.sarif:
            path = sarif.write(args.sarif, findings, stats, meta)
            report.good(f"written {os.path.abspath(path)}")
    except OSError as exc:
        report.bad(f"report write failed - {exc}")
        return 2
    return 0


def save_history(history: history_mod.History, args: argparse.Namespace, target: str,
                 findings: list, stats, meta: dict, pairs: list) -> None:
    """One row per finding, one session per run, diff against the last run."""
    try:
        previous = history.latest(target)
        session_id = history.record(target, meta, stats, findings, pairs)
    except history_mod.HistoryError as exc:
        report.warn(f"history {exc}")
        return
    meta["history_session"] = session_id
    report.section("history")
    report.info(f"session #{session_id} · {len(findings)} finding(s) · {os.path.abspath(args.db)}")
    if args.diff:
        if previous is None:
            report.info("diff    no previous session")
        else:
            try:
                delta = history.diff(previous["id"], findings)
            except history_mod.HistoryError as exc:
                report.warn(f"diff {exc}")
            else:
                report.info(
                    f"diff    +{delta['new']} new · {delta['same']} open"
                    f" · -{delta['fixed']} fixed vs #{previous['id']}"
                )


def retest_run(args: argparse.Namespace, target: str, client: net.Client,
               history: history_mod.History, scope_rules, stats: ScanStats) -> int:
    """Replay only the findings that carry a reconstructable HTTP point."""
    try:
        session = history.latest(target)
        if session is None:
            report.bad("retest - no saved session for this target")
            return 2
        rows = history.rows(session["id"])
    except history_mod.HistoryError as exc:
        report.bad(f"retest - {exc}")
        return 2
    if not rows:
        report.bad("retest - the saved session has no findings")
        return 2

    report.section("retest")
    report.info(f"session #{session['id']} · {len(rows)} stored finding(s)")
    findings = []
    fixed = 0
    skipped = 0
    blocked = 0
    for row in rows:
        point = history_mod.row_to_point(row)
        technique = str(row.get("technique", ""))
        if (point is None or row.get("kind") == "SSRF"
                or "oob" in technique or technique == "union"):
            skipped += 1
            continue
        if scope_rules is not None and not scope_rules.allows(point.url):
            blocked += 1
            continue
        finding = history_mod.finding_from_row(row)
        label = f"{finding.kind} {point.url} [{point.param}]"
        try:
            reproduced = verify.verify(client, point, finding)
        except Exception as exc:
            skipped += 1
            if args.verbose:
                report.warn(f"{label} - retest error: {exc}")
            continue
        if reproduced:
            finding.curl = net.repro_curl(client, point, finding.payload)
            finding.detail = f"{finding.detail} | retest: still open".strip(" |")
            findings.append(finding)
            report.good(f"{label}  still open")
        else:
            fixed += 1
            report.warn(f"{label}  fixed")

    report.info(
        f"retest  {len(findings)} open · {fixed} fixed · {skipped} skipped"
        f" · {blocked} outside scope"
    )
    if not findings and fixed == 0:
        report.warn("no HTTP-replayable findings in that session")
        return 2

    stats.points = len(rows)
    stats.replayed = len(findings)
    stats.fixed = fixed
    stats.retest = True
    stats.requests = client.requests_sent
    stats.errors = client.errors
    stats.finished = time.monotonic()
    client.close()
    findings = report.sort_findings(findings)
    report.print_summary(findings, stats)

    meta = {
        "target": target,
        "retest": True,
        "history_db": os.path.abspath(args.db),
        "history_session": session["id"],
        "skipped": skipped,
        "outside_scope": blocked,
        "fail_on": args.fail_on,
        "scope": args.scope,
    }
    write_code = export_reports(findings, stats, meta, args)
    if write_code:
        return write_code
    return 1 if policy.should_fail(findings, args.fail_on) else 0


def run(args: argparse.Namespace) -> int:
    banner.setup_console()
    target = net.with_scheme(args.url)
    stats = ScanStats(started=time.monotonic())

    if not args.no_banner:
        banner.show(animate=True)
    else:
        sys.stdout.write(report.CYAN + BANNER + report.RESET)
        sys.stdout.write(f"  {config.TOOL_NAME} {config.TOOL_VERSION}  BY {config.TOOL_AUTHOR}\n\n")

    report.info(f"target  {target}")
    mode_label = "retest" if args.retest else ("crawl" if args.crawl else "single page")
    report.info(f"mode    {mode_label}"
                f"  ·  threads {args.threads}"
                f"  ·  timeout {args.timeout:g}s"
                f"  ·  rps {args.rps:g}")

    if args.retest and not args.db:
        report.bad("--retest needs --db FILE")
        return 2
    if args.diff and not args.db:
        report.warn("--diff needs --db - diff disabled")
        args.diff = False
    if args.retest and args.diff:
        report.warn("--diff is ignored during retest")
        args.diff = False
    if args.retest and args.resume:
        report.bad("--resume cannot be combined with --retest")
        return 2

    scope_rules = None
    if args.scope:
        try:
            scope_rules = scope_mod.Scope.load(args.scope)
        except scope_mod.ScopeError as exc:
            report.bad(f"scope - {exc}")
            return 2
        if not scope_rules.allows(target):
            report.bad(f"scope - target is outside {args.scope}")
            return 2
        report.info(f"scope   {len(scope_rules)} rule(s) · {args.scope}")

    history = None
    if args.db:
        try:
            history = history_mod.History(args.db)
        except history_mod.HistoryError as exc:
            report.bad(f"history - {exc}")
            return 2

    storage_raw = None
    browser_storage_state = None
    if args.storage_state:
        try:
            storage_raw = storage.load(args.storage_state)
        except storage.StorageError as exc:
            report.bad(f"storage - {exc}")
            if history is not None:
                history.close()
            return 2
        browser_storage_state = storage.browser_state(storage_raw, target)
        if not browser_storage_state["cookies"] and not browser_storage_state["origins"]:
            browser_storage_state = None
            report.warn("storage - no cookies or localStorage for this target")
        else:
            report.info(
                f"storage {len(browser_storage_state['cookies'])} cookie(s)"
                f" · {len(browser_storage_state['origins'])} origin(s)"
            )

    imported: list = []
    import_notes: list[str] = []
    if args.har:
        requests_found, note = imports_mod.load_har(args.har)
        if not requests_found and note.startswith(("cannot", "invalid", "HAR")):
            report.bad(note)
            if history is not None:
                history.close()
            return 2
        imported.extend(requests_found)
        import_notes.append(note)
    if args.request:
        requests_found, note = imports_mod.load_request(args.request, target)
        if not requests_found:
            report.bad(note)
            if history is not None:
                history.close()
            return 2
        imported.extend(requests_found)
        import_notes.append(note)

    import_headers, import_cookies = imports_mod.session(imported, target)
    session_headers = dict(import_headers)
    session_headers.update(parse_headers(args.header))
    session_cookies = {}
    if storage_raw is not None:
        session_cookies.update(storage.cookie_values(storage_raw, target))
    session_cookies.update(import_cookies)
    session_cookies.update(parse_cookies(args.cookie))
    if imported:
        report.info(f"import  {len(imported)} request(s) - {', '.join(import_notes)}")
        if not import_headers and not import_cookies:
            report.warn("import  no same-origin session material found")

    client = net.Client(
        timeout=args.timeout,
        rps=args.rps,
        headers=session_headers,
        cookies=session_cookies,
        verify=not args.insecure,
        proxy=args.proxy,
        base_url=target,
        scope=scope_rules.allows if scope_rules is not None else None,
    )

    login_action = ""
    login_ok = False
    if args.login:
        if not args.username or not args.password:
            report.bad("login needs --username and --password (or SV1_USERNAME/SV1_PASSWORD)")
            client.close()
            if history is not None:
                history.close()
            return 2
        result = auth.login(
            client,
            target,
            login_url=args.login,
            username=args.username,
            password=args.password,
            username_field=args.login_user_field,
            password_field=args.login_pass_field,
            check=args.login_check,
        )
        if not result.ok:
            report.bad(f"login - {result.note}")
            client.close()
            if history is not None:
                history.close()
            return 2
        login_ok = True
        login_action = result.action
        report.good(f"login   {result.note}")
        if not args.login_check:
            report.warn("login   pass --login-check TEXT to require a post-login marker")

    if args.retest:
        if history is None:
            report.bad("retest - history is not available")
            client.close()
            return 2
        code = retest_run(args, target, client, history, scope_rules, stats)
        client.close()
        history.close()
        return code

    depth = max(0, args.depth) if args.crawl else 0
    pages_limit = max(1, args.pages) if args.crawl else 1

    report.section("recon")
    sitemap_seeds: list[str] = []
    if args.sitemap:
        sitemap_seeds, sitemap_note = discovery.discover(
            client,
            target,
            allows=scope_rules.allows if scope_rules is not None else None,
        )
        report.info(f"sitemap {sitemap_note}")
    spinner = report.Spinner("crawling").start()
    start = time.monotonic()
    pages = crawl.crawl(
        client,
        target,
        pages_limit,
        depth,
        allows=scope_rules.allows if scope_rules is not None else None,
        seeds=sitemap_seeds,
    )
    if not pages:
        response = client.fetch(target)
        if response.ok:
            pages = [crawl.parse_page(response.url or target, response.status, response.text)]
        elif args.verbose:
            report.bad(f"target unreachable: {response.error or response.status}")
    spinner.stop()

    if scope_rules is not None:
        before = len(pages)
        pages = [page for page in pages if scope_rules.allows(page.url)]
        if len(pages) != before:
            report.info(f"scope   blocked {before - len(pages)} redirected page(s)")

    if not pages:
        report.bad("nothing to scan")
        stats.requests = client.requests_sent
        stats.finished = time.monotonic()
        report.print_summary([], stats)
        client.close()
        if history is not None:
            history.close()
        return 2

    stats.pages = len(pages)
    use_browser = bool(args.browser) or not args.no_browser
    if args.external_js and not use_browser:
        report.warn("external-js needs chromium - execution proof disabled")
    spa_points: list = []
    if args.spa:
        if not use_browser:
            report.warn("spa skipped - browser disabled")
        elif not browser_mod.available():
            report.warn("spa skipped - chromium not installed")
        else:
            explorer = make_browser(
                args, target, headers=session_headers, cookies=session_cookies,
                allows=scope_rules.allows if scope_rules is not None else None,
                storage_state=browser_storage_state,
            )
            spinner = report.Spinner("rendering pages").start()
            started = explorer.start()
            spinner.stop()
            if not started:
                report.warn(f"spa skipped - {explorer.reason}")
            else:
                if not explorer.import_cookies(client.cookies):
                    report.warn("spa cookie import failed - session may be missing")
                try:
                    new_pages, spa_points, spa_note = spa.capture(client, explorer, pages)
                finally:
                    explorer.close()
                known = {page.url for page in pages}
                for page in new_pages:
                    if page.url not in known:
                        pages.append(page)
                        known.add(page.url)
                if scope_rules is not None:
                    before = len(pages)
                    pages = [page for page in pages if scope_rules.allows(page.url)]
                    if len(pages) != before:
                        report.info(f"scope   blocked {before - len(pages)} rendered page(s)")
                report.info(f"spa     {spa_note}")

    stats.pages = len(pages)
    points = crawl.collect_points(
        pages,
        include_hidden=args.hidden_fields,
        include_password=args.password_fields,
    )
    merge_points(points, spa_points)
    extra = extra_points(args, target, session_cookies)
    merge_points(points, extra)
    imported_points = imports_mod.points(
        imported,
        target,
        allows=scope_rules.allows if scope_rules is not None else None,
    )
    if imported_points:
        report.info(f"import  {len(imported_points)} point(s) from HAR/request")
        merge_points(points, imported_points)
    if args.params:
        hidden_points, note = hidden.discover(client, target)
        report.info(f"params  {note}")
        merge_points(points, hidden_points)
    if args.js:
        js_points = jsparse.endpoints(client, pages)
        report.info(f"js      {len(js_points)} point(s) mined from scripts")
        merge_points(points, js_points)
    if args.openapi:
        spec, note = openapi.load(client, args.openapi)
        if spec is None:
            report.warn(f"openapi {note}")
        else:
            api_points = openapi.points(spec, target)
            report.info(f"openapi {len(api_points)} point(s) imported from the spec")
            merge_points(points, api_points)
    if scope_rules is not None:
        before = len(points)
        points = [point for point in points if scope_rules.allows(point.url)]
        if len(points) != before:
            report.info(f"scope   blocked {before - len(points)} point(s)")
    stats.points = len(points)
    report.good(f"{len(pages)} page(s), {len(points)} injection point(s) "
                f"in {time.monotonic() - start:.1f}s")
    if extra:
        queued = sum(1 for point in extra if point in points)
        report.info(f"extra   {queued} header/cookie/json point(s) queued")

    if not points:
        report.warn("no query parameters or forms found - pass a url with a query string")

    scanners = select_scanners(args)
    scanner_label = ", ".join(scanners) if scanners else (
        "callbacks only" if (args.blind or args.ssrf) else "none"
    )
    report.info(f"checks  {scanner_label}"
                + ("  ·  time based on" if args.time_based and "sqli" in scanners else "")
                + ("  ·  union extraction on" if not args.no_union and "sqli" in scanners else "")
                + ("  ·  dump on" if args.dump and "sqli" in scanners and not args.no_union else "")
                + ("  ·  blind oob" if args.blind else "")
                + ("  ·  ssrf oob" if args.ssrf else ""))

    checkpoint_meta = {
        "crawl": bool(args.crawl),
        "depth": depth,
        "scanners": scanners,
        "time_based": bool(args.time_based),
        "union": not args.no_union,
        "dump": bool(args.dump),
        "second_order": bool(args.second_order),
        "blind": bool(args.blind),
        "ssrf": bool(args.ssrf),
        "stored": bool(args.stored),
        "params": bool(args.params),
        "hidden_fields": bool(args.hidden_fields),
        "password_fields": bool(args.password_fields),
        "login_attack": bool(args.login_attack),
        "js": bool(args.js),
        "spa": bool(args.spa),
        "openapi": bool(args.openapi),
        "login": bool(args.login),
        "login_ok": login_ok,
    }
    findings: list = []
    pairs: list[tuple] = []
    completed: set[str] = set()
    if args.resume:
        if os.path.exists(args.resume):
            try:
                snapshot = checkpoint_mod.load(args.resume, target)
                compatible, reason = checkpoint_mod.compatible(snapshot, checkpoint_meta)
            except checkpoint_mod.CheckpointError as exc:
                report.bad(f"resume - {exc}")
                client.close()
                if history is not None:
                    history.close()
                return 2
            if not compatible:
                report.bad(f"resume - {reason}")
                client.close()
                if history is not None:
                    history.close()
                return 2
            snapshot_points, completed, pairs = checkpoint_mod.restore(snapshot)
            if snapshot_points:
                points = snapshot_points
                stats.points = len(points)
            findings = [finding for finding, _point in pairs]
            report.info(f"resume  {checkpoint_mod.summary(snapshot)}")
        else:
            report.info(f"resume  no checkpoint yet; writing {os.path.abspath(args.resume)}")

    if login_action and not args.login_attack:
        before = len(points)
        points = [point for point in points if not auth.skip_point(point, login_action)]
        if len(points) != before:
            report.info(f"login   skipped {before - len(points)} credential point(s)")
        skipped_forms = 0
        for page in pages:
            kept = []
            for form in page.forms:
                if auth.skip_form(page.url, form, login_action):
                    skipped_forms += 1
                else:
                    kept.append(form)
            page.forms = kept
        if skipped_forms:
            report.info(f"login   skipped {skipped_forms} credential form(s) in later phases")
        stats.points = len(points)

    pending_points = [
        point for point in points
        if checkpoint_mod.key(point) not in completed
    ]
    if completed:
        report.info(f"resume  {len(completed)} point(s) already complete, "
                    f"{len(pending_points)} pending")

    checkpoint_failed = False

    def save_checkpoint() -> None:
        nonlocal checkpoint_failed
        if not args.resume or checkpoint_failed:
            return
        try:
            checkpoint_mod.save(
                args.resume, target, points, completed, pairs,
                stats, checkpoint_meta,
            )
        except (OSError, TypeError, ValueError) as exc:
            checkpoint_failed = True
            report.warn(f"checkpoint write failed - {exc}")

    report.section("scan")
    failures = 0
    done = 0

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        futures = {
            pool.submit(
                scan_point,
                client,
                point,
                scanners,
                args.time_based,
                not args.no_union,
                args.dump,
            ): point
            for point in pending_points
        }
        try:
            for future in as_completed(futures):
                point = futures[future]
                done += 1
                try:
                    found = future.result()
                except Exception as exc:  # a broken page must not kill the run
                    failures += 1
                    save_checkpoint()
                    if args.verbose:
                        sys.stdout.write("\r\x1b[2K")
                        report.bad(f"{point.label()} - {exc}")
                        traceback.print_exc(limit=1)
                    continue
                for finding in found:
                    sys.stdout.write("\r\x1b[2K")
                    finding.curl = net.repro_curl(client, point, finding.payload)
                    findings.append(finding)
                    pairs.append((finding, point))
                    report.print_finding(finding, len(findings))
                completed.add(checkpoint_mod.key(point))
                save_checkpoint()
                if not sys.stdout.isatty():
                    continue
                sys.stdout.write(
                    f"\r\x1b[2K  {report.DIM}scanning {done}/{len(pending_points)}"
                    f"  ·  {len(findings)} finding(s){report.RESET}"
                )
                sys.stdout.flush()
        except KeyboardInterrupt:
            report.warn("interrupted - reporting what finished")
            for future in futures:
                future.cancel()
            save_checkpoint()

    if sys.stdout.isatty():
        sys.stdout.write("\r\x1b[2K")
    save_checkpoint()

    callback = None
    if args.blind or args.ssrf:
        callback = oob.Callback(bind=args.oob_bind, base=args.oob, wait=args.oob_wait)
        spinner = report.Spinner("starting callback listener").start()
        started = callback.start()
        spinner.stop()
        if started:
            report.info(f"oob     {callback.base}  ·  bind {callback.host}:{callback.port}")
        else:
            report.warn(f"oob unavailable - {callback.error}")
            callback = None

    engine = None
    if use_browser and not browser_mod.available():
        report.warn("chromium not installed - execution proof skipped "
                    "(pip install playwright && playwright install chromium)")
        use_browser = False

    try:
        if args.ssrf:
            if callback is None:
                report.warn("ssrf skipped - callback listener unavailable")
            else:
                report.section("ssrf")
                ssrf_findings, note = ssrf.run(client, points, callback, args.oob_wait)
                report.info(f"ssrf    {note}")
                for finding in ssrf_findings:
                    findings.append(finding)
                    stats.confirmed += 1
                    report.print_finding(finding, len(findings))
                if not ssrf_findings:
                    report.info("no callback from url-like parameters")

        if use_browser and (pairs or pages):
            engine = make_browser(
                args, target, headers=session_headers, cookies=session_cookies,
                allows=scope_rules.allows if scope_rules is not None else None,
                storage_state=browser_storage_state,
            )
            spinner = report.Spinner("launching chromium").start()
            started = engine.start()
            spinner.stop()
            if not started:
                report.warn(f"chromium unavailable: {engine.reason}")
                engine = None
            else:
                if not engine.import_cookies(client.cookies):
                    report.warn("chromium cookie import failed - session may be missing")
                report.good("chromium ready - xss must execute to stay high")

        if engine is not None:
            if "xss" in scanners:
                prove_xss(engine, pairs, args, client)

                report.section("dom")
                dom_findings = domxss.run(
                    engine,
                    pages,
                    args.artifacts,
                    client=client,
                    external_js=args.external_js,
                    allows=scope_rules.allows if scope_rules is not None else None,
                )
                for finding in dom_findings:
                    findings.append(finding)
                    stats.confirmed += 1
                    report.print_finding(finding, len(findings))
                if not dom_findings:
                    report.info("no dom injection path executed")

            if args.stored:
                report.section("stored")
                stored_findings = stored.run(
                    engine, pages, args.artifacts,
                    include_hidden=args.hidden_fields,
                    include_password=args.password_fields,
                )
                for finding in stored_findings:
                    findings.append(finding)
                    stats.confirmed += 1
                    report.print_finding(finding, len(findings))
                if not stored_findings:
                    report.info("no stored payload executed")

        if args.blind:
            if callback is None:
                report.warn("blind skipped - callback listener unavailable")
            else:
                report.section("blind")
                blind_visits = list(args.blind_visit)
                if scope_rules is not None:
                    allowed = [url for url in blind_visits if scope_rules.allows(url)]
                    if len(allowed) != len(blind_visits):
                        report.info(
                            f"scope   blocked {len(blind_visits) - len(allowed)} admin visit(s)"
                        )
                    blind_visits = allowed
                blind_findings, note = blind.run(
                    client,
                    engine,
                    pages,
                    callback,
                    blind_visits,
                    args.oob_wait,
                    args.artifacts,
                    include_hidden=args.hidden_fields,
                    include_password=args.password_fields,
                )
                report.info(f"blind   {note}")
                for finding in blind_findings:
                    findings.append(finding)
                    if finding.confidence == "CONFIRMED":
                        stats.confirmed += 1
                    report.print_finding(finding, len(findings))
                if not blind_findings:
                    report.info("no blind callback fired")

        if args.second_order and "sqli" in scanners:
            report.section("second-order")
            doubles = secondorder.run(
                client, pages,
                include_hidden=args.hidden_fields,
                include_password=args.password_fields,
            )
            for finding, point in doubles:
                finding.curl = net.repro_curl(client, point, finding.payload)
                findings.append(finding)
                pairs.append((finding, point))
                report.print_finding(finding, len(findings))
            if not doubles:
                report.info("no stored value reached a query")

        if pairs and args.no_verify:
            stats.confirmed += sum(
                1 for finding, _point in pairs
                if finding.confidence == "CONFIRMED"
            )
        if pairs and not args.no_verify:
            pending = [(f, p) for f, p in pairs if f.confidence != "CONFIRMED"]
            proven = len(pairs) - len(pending)
            stats.confirmed += proven
            if pending:
                report.section("replay")
            for index, (finding, point) in enumerate(pending, 1):
                label = f"{finding.kind} {point.url} [{point.param}]"
                if verify.verify(client, point, finding):
                    stats.replayed += 1
                    report.good(f"{index}/{len(pending)}  {label}")
                else:
                    stats.unverified += 1
                    verify.demote(finding)
                    report.warn(f"{index}/{len(pending)}  {label}  -  not reproducible")
    finally:
        if engine is not None:
            if args.save_storage_state:
                state = engine.export_state()
                if state:
                    try:
                        storage.save(args.save_storage_state, state, target)
                        report.good(
                            f"storage {os.path.abspath(args.save_storage_state)}"
                        )
                    except OSError as exc:
                        report.warn(f"storage write failed - {exc}")
                else:
                    report.warn("storage - browser returned no state to save")
            engine.close()
        if callback is not None:
            callback.close()

    if args.save_storage_state and engine is None:
        report.warn("storage - no browser ran, state not saved")

    if "xss" in scanners and engine is None:
        demote_unproven_xss(pairs, "chromium unavailable")

    client.close()
    stats.requests = client.requests_sent
    stats.errors = client.errors + failures
    stats.finished = time.monotonic()
    findings = report.sort_findings(findings)
    save_checkpoint()

    meta = {
        "target": target,
        "crawl": bool(args.crawl),
        "depth": depth,
        "scanners": scanners,
        "time_based": bool(args.time_based),
        "union": not args.no_union,
        "replay": not args.no_verify,
        "browser": engine is not None,
        "stored": bool(args.stored),
        "hidden": bool(args.params),
        "js": bool(args.js),
        "external_js": bool(args.external_js),
        "har": bool(args.har),
        "request": bool(args.request),
        "data": bool(args.data),
        "json": bool(args.json),
        "second_order": bool(args.second_order),
        "hidden_fields": bool(args.hidden_fields),
        "password_fields": bool(args.password_fields),
        "storage_state": bool(args.storage_state),
        "saved_storage_state": os.path.abspath(args.save_storage_state)
        if args.save_storage_state else "",
        "login": bool(args.login),
        "login_ok": login_ok,
        "sitemap": bool(args.sitemap),
        "resume": os.path.abspath(args.resume) if args.resume else "",
        "dump": bool(args.dump),
        "spa": bool(args.spa),
        "openapi": bool(args.openapi),
        "blind": bool(args.blind),
        "ssrf": bool(args.ssrf),
        "oob": callback.base if callback is not None else "",
        "fail_on": args.fail_on,
        "scope": args.scope,
        "db": os.path.abspath(args.db) if args.db else "",
        "sarif": os.path.abspath(args.sarif) if args.sarif else "",
        "retest": False,
    }
    if history is not None:
        save_history(history, args, target, findings, stats, meta, pairs)
        history.close()

    report.print_summary(findings, stats)
    write_code = export_reports(findings, stats, meta, args)
    if write_code:
        return write_code

    return 1 if policy.should_fail(findings, args.fail_on) else 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return run(args)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
