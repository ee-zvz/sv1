"""SV1 - console rendering and file export."""

from __future__ import annotations

import csv
import json
import sys
import threading
import time

from . import config

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RED = "\x1b[38;2;255;85;85m"
ORANGE = "\x1b[38;2;255;165;60m"
YELLOW = "\x1b[38;2;240;220;90m"
GREEN = "\x1b[38;2;110;230;150m"
BLUE = "\x1b[38;2;90;175;255m"
CYAN = "\x1b[38;2;0;229;255m"
MAGENTA = "\x1b[38;2;255;0;170m"
GREY = "\x1b[38;2;120;130;150m"
WHITE = "\x1b[38;2;235;240;250m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH": ORANGE,
    "MEDIUM": YELLOW,
    "LOW": BLUE,
    "INFO": GREY,
}

FRAMES = "⣾⣽⣻⢿⡿⣟⣯⣷"
FRAMES_ASCII = "|/-\\"


def supports_unicode() -> bool:
    encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in encoding


def rule(char: str = "─", width: int = 66) -> str:
    if not supports_unicode():
        char = "-"
    return DIM + GREY + char * width + RESET


class Spinner:
    """One status line. Never fights with printed findings."""

    def __init__(self, message: str) -> None:
        self.message = message
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._frames = FRAMES if supports_unicode() else FRAMES_ASCII

    def start(self) -> "Spinner":
        if not sys.stdout.isatty():
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def _spin(self) -> None:
        index = 0
        while not self._stop.is_set():
            frame = self._frames[index % len(self._frames)]
            sys.stdout.write(f"\r\x1b[2K  {CYAN}{frame}{RESET} {DIM}{self.message}{RESET}")
            sys.stdout.flush()
            index += 1
            time.sleep(config.SPINNER_INTERVAL)

    def stop(self, final: str = "") -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        if sys.stdout.isatty():
            sys.stdout.write("\r\x1b[2K")
            if final:
                sys.stdout.write(final + "\n")
            sys.stdout.flush()


def info(message: str) -> None:
    sys.stdout.write(f"  {GREY}·{RESET} {message}\n")
    sys.stdout.flush()


def good(message: str) -> None:
    sys.stdout.write(f"  {GREEN}✓{RESET} {message}\n")
    sys.stdout.flush()


def warn(message: str) -> None:
    sys.stdout.write(f"  {YELLOW}!{RESET} {message}\n")
    sys.stdout.flush()


def bad(message: str) -> None:
    sys.stdout.write(f"  {RED}✗{RESET} {message}\n")
    sys.stdout.flush()


def section(title: str) -> None:
    sys.stdout.write(f"\n  {BOLD}{MAGENTA}{title}{RESET}\n")
    sys.stdout.write(rule() + "\n")
    sys.stdout.flush()


def print_finding(finding, index: int) -> None:
    color = SEVERITY_COLOR.get(finding.severity, WHITE)
    sys.stdout.write(
        f"\n  {color}{BOLD}[{finding.severity}]{RESET} "
        f"{BOLD}{finding.kind}{RESET} "
        f"{DIM}{finding.confidence} confidence{RESET}\n"
    )
    sys.stdout.write(f"  {GREY}target  {RESET}{WHITE}{finding.method} {finding.url}{RESET}\n")
    sys.stdout.write(f"  {GREY}param   {RESET}{CYAN}{finding.param}{RESET}\n")
    if finding.technique:
        sys.stdout.write(f"  {GREY}vector  {RESET}{BLUE}{finding.technique}{RESET}\n")
    payload = finding.payload if len(finding.payload) <= 96 else finding.payload[:93] + "..."
    sys.stdout.write(f"  {GREY}payload {RESET}{MAGENTA}{payload}{RESET}\n")
    for label, value in getattr(finding, "data", {}).items():
        shown = value if len(value) <= 110 else value[:107] + "..."
        sys.stdout.write(f"  {GREY}data    {RESET}{DIM}{label:<8}{RESET}{shown}\n")
    if finding.detail:
        sys.stdout.write(f"  {GREY}note    {RESET}{finding.detail}\n")
    if finding.evidence:
        evidence = finding.evidence if len(finding.evidence) <= 150 else finding.evidence[:147] + "..."
        sys.stdout.write(f"  {GREY}proof   {RESET}{DIM}{evidence}{RESET}\n")
    sys.stdout.flush()


def print_summary(findings: list, stats) -> None:
    section("summary")
    counts: dict[str, int] = {}
    kinds: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        kinds[finding.kind] = kinds.get(finding.kind, 0) + 1

    if not findings:
        good("no open findings on retest" if getattr(stats, "retest", False)
             else "no findings on the tested inputs")
    else:
        for severity in sorted(counts, key=lambda s: config.SEVERITY_ORDER.get(s, 9)):
            color = SEVERITY_COLOR.get(severity, WHITE)
            sys.stdout.write(f"  {color}{severity:<9}{RESET} {counts[severity]}\n")
        detail = "  ".join(f"{kind}:{count}" for kind, count in sorted(kinds.items()))
        sys.stdout.write(f"  {GREY}by type  {RESET}{detail}\n")

    verified = getattr(stats, "verified", 0)
    unverified = getattr(stats, "unverified", 0)
    fixed = getattr(stats, "fixed", 0)
    if getattr(stats, "retest", False):
        mark = GREEN if not fixed else YELLOW
        sys.stdout.write(
            f"  {GREY}retest   {RESET}{GREEN}{verified} open{RESET}"
            f"{GREY}, {mark}{fixed} fixed{RESET}\n"
        )
    elif verified or unverified:
        mark = GREY if unverified else GREEN
        sys.stdout.write(
            f"  {GREY}replay   {RESET}{mark}{verified} reproduced{RESET}"
            f"{GREY}, {unverified} unstable{RESET}\n"
        )

    sys.stdout.write(
        f"\n  {GREY}pages {RESET}{stats.pages}"
        f"  {GREY}points {RESET}{stats.points}"
        f"  {GREY}requests {RESET}{stats.requests}"
        f"  {GREY}errors {RESET}{stats.errors}"
        f"  {GREY}time {RESET}{stats.duration:.1f}s\n"
    )
    sys.stdout.write("\n")
    sys.stdout.flush()


def export(path: str, findings: list, stats, meta: dict) -> str:
    lowered = path.lower()
    if lowered.endswith(".csv"):
        with open(path, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=config.CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding.to_row())
        return path

    payload = {
        "tool": config.TOOL_NAME,
        "author": config.TOOL_AUTHOR,
        "version": config.TOOL_VERSION,
        "meta": meta,
        "stats": {
            "pages": stats.pages,
            "points": stats.points,
            "requests": stats.requests,
            "errors": stats.errors,
            "verified": stats.verified,
            "unverified": stats.unverified,
            "fixed": getattr(stats, "fixed", 0),
            "retest": bool(getattr(stats, "retest", False)),
            "duration_seconds": round(stats.duration, 2),
        },
        "counts": {
            "total": len(findings),
            "by_severity": _count(findings, "severity"),
            "by_type": _count(findings, "kind"),
        },
        "findings": [finding.to_dict() for finding in findings],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return path


def _count(findings: list, attribute: str) -> dict:
    result: dict[str, int] = {}
    for finding in findings:
        value = getattr(finding, attribute)
        result[value] = result.get(value, 0) + 1
    return result


def export_html(path: str, findings: list, stats, meta: dict) -> str:
    from html import escape

    counts = _count(findings, "severity")
    cards = []
    for finding in sort_findings(findings):
        color = {
            "CRITICAL": "#ff5555",
            "HIGH": "#ffa53c",
            "MEDIUM": "#f0dc5a",
            "LOW": "#5aafff",
            "INFO": "#788296",
        }.get(finding.severity, "#e6ecf5")
        shot = ""
        if finding.artifact:
            from pathlib import Path

            source = escape(Path(finding.artifact).resolve().as_uri())
            shot = f'<img class="shot" src="{source}" alt="proof">'
        data_rows = "".join(
            f'<div class="row"><b>{escape(label)}</b><span>{escape(value)}</span></div>'
            for label, value in getattr(finding, "data", {}).items()
        )
        cards.append(
            f"""
  <article class="card" style="border-left-color:{color}">
    <header>
      <span class="badge" style="background:{color}">{escape(finding.severity)}</span>
      <span class="kind">{escape(finding.kind)}</span>
      <span class="conf">{escape(finding.confidence)}</span>
      <span class="tech">{escape(finding.technique)}</span>
    </header>
    <div class="row"><b>target</b><code>{escape(finding.method)} {escape(finding.url)}</code></div>
    <div class="row"><b>param</b><code>{escape(finding.param)}</code></div>
    <div class="row"><b>payload</b><code class="payload">{escape(finding.payload)}</code></div>
    {f'<div class="row"><b>note</b><span>{escape(finding.detail)}</span></div>' if finding.detail else ''}
    {f'<div class="row"><b>proof</b><span class="proof">{escape(finding.evidence)}</span></div>' if finding.evidence else ''}
    {data_rows}
    {shot}
  </article>"""
        )

    summary = " · ".join(
        f"{name}: {count}" for name, count in sorted(
            counts.items(), key=lambda item: config.SEVERITY_ORDER.get(item[0], 9)
        )
    ) or "no findings"
    target = escape(str(meta.get("target", "")))
    duration = f"{stats.duration:.1f}s"
    started = (
        time.strftime("%Y-%m-%d %H:%M", time.localtime(stats.started))
        if getattr(stats, "started", 0.0)
        else ""
    )

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>SV1 report - {target}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:40px 24px 80px; background:#0b0e14; color:#dbe3f0;
         font:15px/1.55 "Segoe UI", system-ui, sans-serif; }}
  .wrap {{ max-width:1080px; margin:0 auto; }}
  h1 {{ margin:0; font-size:34px; letter-spacing:.14em; color:#00e5ff; }}
  .sub {{ color:#8b97ad; margin:6px 0 28px; letter-spacing:.22em; font-size:12px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:18px; padding:16px 18px; border-radius:12px;
           background:#111725; border:1px solid #1d2739; margin-bottom:26px; }}
  .meta div {{ font-size:13px; color:#8b97ad; }}
  .meta b {{ color:#dbe3f0; display:block; font-weight:600; }}
  .card {{ background:#101725; border:1px solid #1d2739; border-left:4px solid #333;
           border-radius:12px; padding:18px 20px; margin:14px 0; }}
  .card header {{ display:flex; align-items:center; gap:10px; margin-bottom:12px; }}
  .badge {{ color:#0b0e14; font-weight:700; font-size:11px; padding:2px 9px;
            border-radius:99px; letter-spacing:.07em; }}
  .kind {{ font-weight:700; letter-spacing:.1em; }}
  .conf {{ color:#6ee796; font-size:12px; }}
  .tech {{ margin-left:auto; color:#5aafff; font-size:12px; }}
  .row {{ display:flex; gap:12px; margin:6px 0; align-items:baseline; }}
  .row b {{ width:64px; color:#8b97ad; font-weight:500; font-size:12px; text-transform:uppercase; }}
  code {{ background:#0b111c; border:1px solid #1a2434; border-radius:6px;
          padding:2px 7px; color:#9fd4ff; font-size:13px; word-break:break-all; }}
  .payload {{ color:#ff8ad4; }}
  .proof {{ color:#93a2bb; font-size:13px; word-break:break-word; }}
  .shot {{ width:100%; max-width:760px; margin-top:14px; border-radius:8px;
           border:1px solid #1d2739; display:block; }}
  footer {{ margin-top:34px; color:#5d6a80; font-size:12px; letter-spacing:.1em; }}
</style></head>
<body><div class="wrap">
  <h1>SV1</h1>
  <div class="sub">BY ee.zvz · web vulnerability report</div>
  <div class="meta">
    <div><b>{target}</b>target</div>
    <div><b>{started or '—'}</b>started</div>
    <div><b>{stats.pages}</b>pages</div>
    <div><b>{stats.points}</b>points</div>
    <div><b>{stats.requests}</b>requests</div>
    <div><b>{duration}</b>duration</div>
    <div><b>{len(findings)}</b>findings</div>
    <div><b>{summary}</b>severity</div>
  </div>
  {''.join(cards) if cards else '<p style="color:#6ee796">No findings on the tested inputs.</p>'}
  <footer>generated by SV1 {config.TOOL_VERSION}</footer>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(document)
    return path


def sort_findings(findings: list) -> list:
    return sorted(
        findings,
        key=lambda f: (config.SEVERITY_ORDER.get(f.severity, 9), f.kind, f.url, f.param),
    )
