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

if sys.version_info < (3, 8):
    sys.stderr.write("SV1 needs Python 3.8 or newer\n")
    raise SystemExit(2)

from sv1lib import banner, blind, config, crawl, domxss, hidden, jsparse, net, oob, openapi, report, spa, sqli, ssrf
from sv1lib import browser as browser_mod
from sv1lib import history as history_mod
from sv1lib import policy, sarif, scope as scope_mod
from sv1lib import secondorder, stored, verify, xss
from sv1lib.models import ScanStats

TOKEN_RE = re.compile(r"sv1[0-9a-zA-Z]+")


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
""",
    )
    parser.add_argument("--version", action="version",
                        version=f"SV1 {config.TOOL_VERSION} by {config.TOOL_AUTHOR}")
    parser.add_argument("-u", "--url", required=True, help="target url")
    parser.add_argument("--crawl", action="store_true", help="follow links from the target")
    parser.add_argument("--depth", type=int, default=config.DEFAULT_MAX_DEPTH, help="crawl depth (default 2)")
    parser.add_argument("--pages", type=int, default=config.DEFAULT_MAX_PAGES, help="max pages to crawl")
    parser.add_argument("--threads", type=int, default=8, help="worker threads (default 8)")
    parser.add_argument("--timeout", type=float, default=config.DEFAULT_TIMEOUT, help="request timeout seconds")
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
    parser.add_argument("--json", default="", help="json endpoint to test (POST)")
    parser.add_argument("--json-data", default='{"id": "1", "q": "test"}', help="json body template")
    parser.add_argument("--params", action="store_true", help="discover hidden query parameters")
    parser.add_argument("--js", action="store_true", help="mine endpoints from javascript")
    parser.add_argument("--second-order", action="store_true",
                        help="probe second-order sqli (writes to the target)")
    parser.add_argument("--dump", action="store_true",
                        help="extract current user, database and table names via union")
    parser.add_argument("--spa", action="store_true",
                        help="render pages in chromium and capture xhr endpoints")
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


def make_browser(args: argparse.Namespace, target: str):
    return browser_mod.Browser(
        headers=parse_headers(args.header),
        cookies=parse_cookies(args.cookie),
        proxy=args.proxy,
        ignore_https=not args.insecure,
        base_url=target,
        artifacts=args.artifacts,
        timeout_ms=config.BROWSER_TIMEOUT_MS,
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
    """Header, cookie and json points are opt in: they widen the attack surface."""
    extra = []
    if args.headers:
        extra.extend(crawl.header_points(target, deep=args.deep))
    if args.cookies and cookies:
        extra.extend(crawl.cookie_points(target, cookies))
    if args.json:
        try:
            data = json.loads(args.json_data)
        except json.JSONDecodeError:
            data = {}
            report.warn("--json-data is not valid json - json point skipped")
        if isinstance(data, dict) and data:
            extra.extend(crawl.json_points(args.json, data))
    return extra


def token_of(payload: str) -> str:
    match = TOKEN_RE.search(payload or "")
    return match.group(0) if match else ""


def artifact_path(root: str, kind: str, index: int) -> str:
    return f"{root}/{kind}-{index:02d}.png" if root else ""


def prove_xss(engine, pairs: list, args: argparse.Namespace) -> None:
    """Turn 'the payload came back' into 'the payload ran'."""
    targets = [
        (finding, point)
        for finding, point in pairs
        if finding.kind == "XSS"
        and finding.technique != "reflection-encoded"
        and point.source in ("query", "form", "js")
        and token_of(finding.payload)
    ]
    if not targets:
        return
    report.section("execution")
    for index, (finding, point) in enumerate(targets, 1):
        token = token_of(finding.payload)
        if not token:
            continue
        shot = artifact_path(args.artifacts, "xss", index)
        visit = engine.visit_point(point, finding.payload, shot_path=shot)
        label = f"{finding.url} [{finding.param}]"
        if visit.fired(token):
            finding.confidence = "CONFIRMED"
            finding.evidence = f"executed in chromium: {visit.proof(token)}"
            finding.detail = f"{finding.detail} | proof: alert fired".strip(" |")
            finding.artifact = visit.screenshot
            report.good(f"{label}  executed")
        else:
            finding.confidence = "MEDIUM"
            note = "chromium did not execute the payload"
            finding.detail = f"{finding.detail} | {note}".strip(" |")
            suffix = f" ({visit.error})" if visit.error else ""
            report.warn(f"{label}  not executed{suffix}")


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
    stats.verified = len(findings)
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

    client = net.Client(
        timeout=args.timeout,
        rps=args.rps,
        headers=parse_headers(args.header),
        cookies=parse_cookies(args.cookie),
        verify=not args.insecure,
        proxy=args.proxy,
    )

    if args.retest:
        code = retest_run(args, target, client, history, scope_rules, stats)
        client.close()
        history.close()
        return code

    depth = max(0, args.depth) if args.crawl else 0
    pages_limit = max(1, args.pages) if args.crawl else 1

    report.section("recon")
    spinner = report.Spinner("crawling").start()
    start = time.monotonic()
    pages = crawl.crawl(
        client,
        target,
        pages_limit,
        depth,
        allows=scope_rules.allows if scope_rules is not None else None,
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
    spa_points: list = []
    if args.spa:
        if not use_browser:
            report.warn("spa skipped - browser disabled")
        elif not browser_mod.available():
            report.warn("spa skipped - chromium not installed")
        else:
            explorer = make_browser(args, target)
            spinner = report.Spinner("rendering pages").start()
            started = explorer.start()
            spinner.stop()
            if not started:
                report.warn(f"spa skipped - {explorer.reason}")
            else:
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
    points = crawl.collect_points(pages)
    merge_points(points, spa_points)
    extra = extra_points(args, target, parse_cookies(args.cookie))
    merge_points(points, extra)
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

    report.section("scan")
    findings = []
    pairs = []
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
            for point in points
        }
        try:
            for future in as_completed(futures):
                point = futures[future]
                done += 1
                try:
                    found = future.result()
                except Exception as exc:  # a broken page must not kill the run
                    failures += 1
                    if args.verbose:
                        sys.stdout.write("\r\x1b[2K")
                        report.bad(f"{point.label()} - {exc}")
                        traceback.print_exc(limit=1)
                    continue
                for finding in found:
                    sys.stdout.write("\r\x1b[2K")
                    findings.append(finding)
                    pairs.append((finding, point))
                    report.print_finding(finding, len(findings))
                if not sys.stdout.isatty():
                    continue
                sys.stdout.write(
                    f"\r\x1b[2K  {report.DIM}scanning {done}/{len(points)}"
                    f"  ·  {len(findings)} finding(s){report.RESET}"
                )
                sys.stdout.flush()
        except KeyboardInterrupt:
            report.warn("interrupted - reporting what finished")
            for future in futures:
                future.cancel()

    if sys.stdout.isatty():
        sys.stdout.write("\r\x1b[2K")

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
                    stats.verified += 1
                    report.print_finding(finding, len(findings))
                if not ssrf_findings:
                    report.info("no callback from url-like parameters")

        if use_browser and (pairs or pages):
            engine = make_browser(args, target)
            spinner = report.Spinner("launching chromium").start()
            started = engine.start()
            spinner.stop()
            if not started:
                report.warn(f"chromium unavailable: {engine.reason}")
                engine = None
            else:
                report.good("chromium ready - xss must execute to stay high")

        if engine is not None:
            if "xss" in scanners:
                prove_xss(engine, pairs, args)

                report.section("dom")
                dom_findings = domxss.run(engine, pages, args.artifacts)
                for finding in dom_findings:
                    findings.append(finding)
                    stats.verified += 1
                    report.print_finding(finding, len(findings))
                if not dom_findings:
                    report.info("no dom injection path executed")

            if args.stored:
                report.section("stored")
                stored_findings = stored.run(engine, pages, args.artifacts)
                for finding in stored_findings:
                    findings.append(finding)
                    stats.verified += 1
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
                )
                report.info(f"blind   {note}")
                for finding in blind_findings:
                    findings.append(finding)
                    stats.verified += 1
                    report.print_finding(finding, len(findings))
                if not blind_findings:
                    report.info("no blind callback fired")

        if args.second_order and "sqli" in scanners:
            report.section("second-order")
            doubles = secondorder.run(client, pages)
            for finding, point in doubles:
                findings.append(finding)
                pairs.append((finding, point))
                report.print_finding(finding, len(findings))
            if not doubles:
                report.info("no stored value reached a query")

        if pairs and not args.no_verify:
            pending = [(f, p) for f, p in pairs if f.confidence != "CONFIRMED"]
            proven = len(pairs) - len(pending)
            stats.verified += proven
            if pending:
                report.section("replay")
            for index, (finding, point) in enumerate(pending, 1):
                label = f"{finding.kind} {point.url} [{point.param}]"
                if verify.verify(client, point, finding):
                    stats.verified += 1
                    report.good(f"{index}/{len(pending)}  {label}")
                else:
                    stats.unverified += 1
                    verify.demote(finding)
                    report.warn(f"{index}/{len(pending)}  {label}  -  not reproducible")
    finally:
        if engine is not None:
            engine.close()
        if callback is not None:
            callback.close()

    client.close()
    stats.requests = client.requests_sent
    stats.errors = client.errors + failures
    stats.finished = time.monotonic()
    findings = report.sort_findings(findings)

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
        "second_order": bool(args.second_order),
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
