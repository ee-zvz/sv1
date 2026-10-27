**English** · [العربية](README.ar.md)

# SV1 — BY ee.zvz

[![ci](https://github.com/ee-zvz/sv1/actions/workflows/ci.yml/badge.svg)](https://github.com/ee-zvz/sv1/actions/workflows/ci.yml)

**SV1** is a Python XSS / SQL injection / blind XSS / SSRF scanner for Windows 11.
It proves execution inside Chromium, catches out-of-band callbacks, crawls SPAs,
imports OpenAPI, and ships CI output: SARIF, severity gates, scoped scans, and
SQLite session history. Release `1.3.3` keeps the real-application inputs
introduced in `1.3.0`: HAR and raw HTTP request import, nested JSON and raw
bodies, XHR/fetch POST capture, same-origin external JavaScript analysis, and
nested OpenAPI bodies. Reflection alone stays `MEDIUM`; `HIGH` needs execution.
`1.3.1` added exact dependency pins, a `pyproject.toml`, a full-lab CI gate, and
replay-enabled Altoro evidence. `1.3.2` added one version source, ruff/mypy and
coverage gates, a 42.5% branch baseline, and a same-target comparison against
dalfox and sqlmap. `1.3.3` checks every redirect hop, keeps session headers and
cookies on the target origin, and splits confirmed from replayed proof.

A vulnerability scanner for **XSS**, **SQL Injection**, **Blind XSS** and **SSRF**
written in Python, running on Windows 11. On start it prints an animated banner
(the SV1 logo with a colour gradient, plus the author name) and then begins the scan.

---

## Install

Requires **Python 3.10+**.

```powershell
cd sv1
python -m pip install -r requirements.txt
python -m playwright install chromium
```

`requirements.txt` and `pyproject.toml` pin exact versions; `python -m pip install .`
uses the same dependency set. The version comes from `sv1lib/version.py`; the
user agent and package metadata read the same string.

For contributors:

```powershell
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m ruff check .
python -m mypy
python -m coverage run -m unittest discover -s tests
python -m coverage report -m
```

CI runs the same checks in the `quality` job. Details:
[`docs/QUALITY.md`](docs/QUALITY.md).

The browser step is optional, but required for execution proof (real XSS, DOM,
Stored), for visiting the admin page in Blind XSS, and for SPA crawling. Without
it the tool still runs and tests reflection, SQLi, blind callbacks and SSRF normally.

Quick start:

```powershell
.\run.bat -u http://target.tld --crawl
```

`run.bat` creates a `.venv` on first run, installs requirements, and launches the tool.

> Use **Windows Terminal** for the animated banner (24-bit colour and glyph support).

---

## Usage

```powershell
python sv1.py -u <URL> [options]
```

| Option | Meaning |
|---|---|
| `-u, --url` | Target (required). Accepts a value without `http://` and adds it |
| `--crawl` | Follow links from the page |
| `--depth N` | Crawl depth (default 2) |
| `--pages N` | Maximum pages (default 25) |
| `--threads N` | Worker threads (default 8) |
| `--timeout S` | Request timeout in seconds (default 12) |
| `--rps N` | Requests per second (default 8, `0` = unlimited) |
| `--fail-on LEVEL` | When to exit 1: `any` (default), `none`, `low`, `medium`, `high`, `critical` |
| `--scope FILE` | Host/path allowlist; anything outside is refused |
| `--db FILE` | SQLite database for sessions and findings |
| `--diff` | Compare this session with the previous one in `--db` |
| `--retest` | Replay findings from the saved session instead of crawling |
| `--sarif FILE` | SARIF 2.1.0 report for CI |
| `--xss` | XSS checks only |
| `--sqli` | SQLi checks only |
| `--no-xss` / `--no-sqli` | Disable one of the two |
| `--time` | Run time-based injection checks (slow, accurate) |
| `--no-union` | Disable UNION extraction |
| `--headers` | Inject into `X-Forwarded-For`, `Referer`, `User-Agent` |
| `--deep` | Additional headers: `X-Real-IP`, `Client-IP`, `Origin`, … |
| `--cookies` | Inject into cookie values passed with `--cookie` |
| `--json URL` | Test JSON body injection; nested objects and arrays are flattened to leaf points |
| `--json-data JSON` | JSON body template (default `{"id": "1", "q": "test"}`) |
| `--data BODY` | Raw body template; use `*` as the injection marker, or pass JSON to test nested leaves |
| `--method METHOD` | Method for `--data`/`--json` (default `POST`) |
| `--content-type TYPE` | Content type for `--data`/`--json` bodies |
| `--har FILE` | Import cookies, headers and injection points from a HAR file |
| `--request FILE` | Import one raw HTTP request file (method, path, headers, body) |
| `--external-js` | Read same-origin external scripts for DOM source/sink analysis |
| `--params` | Discover hidden GET parameters on the target URL |
| `--js` | Extract injection points from page scripts |
| `--second-order` | Second-order SQLi (writes to the target) |
| `--dump` | Pull database identity and table names after a successful UNION |
| `--spa` | SPA crawl: load pages in Chromium and capture XHR/fetch URLs and POST bodies |
| `--openapi SPEC` | Import injection points from a local or remote OpenAPI JSON file |
| `--blind` | Blind XSS: inject a callback script into POST forms and wait for a hit (writes to the target) |
| `--blind-visit URL` | Open the admin page after injection, repeats (local simulation) |
| `--ssrf` | Test URL-like parameters through a callback |
| `--oob BASE` | Public callback address (default `http://127.0.0.1:8777`) |
| `--oob-bind HOST:PORT` | Callback listen address (default `127.0.0.1:8777`) |
| `--oob-wait S` | Seconds to wait for a callback after the scan (default 8) |
| `--browser` | Force execution proof in Chromium |
| `--no-browser` | Disable the browser entirely |
| `--stored` | Stored XSS checks (writes data to the target) |
| `--artifacts DIR` | Evidence screenshot directory (default `sv1-artifacts`) |
| `--html FILE` | HTML report with screenshots |
| `-H "Key: Value"` | Extra header, repeatable |
| `--cookie "sid=abc"` | Session cookies |
| `--proxy URL` | Proxy |
| `-k, --insecure` | Ignore the TLS certificate |
| `-o FILE` | Export findings to `.json` or `.csv` |
| `--no-verify` | Skip the replay stage |
| `--no-banner` | Skip the banner |
| `--version` | Print the version |
| `-v` | Show network and internal errors |

### Examples

```powershell
# Whole site, full scan + HTML report
python sv1.py -u https://site.tld --crawl --html report.html -o report.json

# Single search page, XSS only
python sv1.py -u "https://site.tld/search?q=test" --xss

# ID endpoint with time-based checks and a saved session
python sv1.py -u "https://site.tld/item?id=1" --sqli --time --cookie "PHPSESSID=abc123"

# Stored scan (writes to the target) with evidence screenshots
python sv1.py -u https://site.tld --crawl --stored --html report.html

# No browser (faster, no execution proof)
python sv1.py -u https://site.tld --crawl --no-browser

# Header and cookie injection (tests the target URL itself)
python sv1.py -u https://site.tld/api/account --headers --deep --cookies --cookie "sid=abc"

# JSON endpoint (PowerShell eats inner quotes, so use backticks)
python sv1.py -u https://site.tld/api/item --json https://site.tld/api/item `
  --json-data "{\`"id\`": 1, \`"q\`": \`"test\`", \`"user\`": {\`"name\`": \`"guest\`"}}"

# Use a captured authenticated session and its requests
python sv1.py -u https://site.tld --har session.har --xss --sqli

# One raw HTTP request, including its body and headers
python sv1.py -u https://site.tld --request request.txt

# Raw body template: only the first * becomes the payload
python sv1.py -u https://site.tld/api/search --method POST `
  --content-type "application/x-www-form-urlencoded" --data "q=*&page=2"

# SPA XHR/fetch POST body capture
python sv1.py -u https://site.tld/app --spa --xss

# External same-origin bundle source/sink analysis, with browser proof
python sv1.py -u https://site.tld/app --external-js --xss

# Hidden parameters on one page
python sv1.py -u https://site.tld/export --params

# Points from JavaScript + second-order SQLi
python sv1.py -u https://site.tld --crawl --js --second-order

# Pull database identity and table names after UNION proof
python sv1.py -u "https://site.tld/item?id=1" --dump

# SPA crawl + OpenAPI import
python sv1.py -u https://site.tld --crawl --spa --openapi https://site.tld/openapi.json

# Blind XSS: inject into forms, then open the admin page (local simulation)
python sv1.py -u https://site.tld/contact --blind `
  --blind-visit https://site.tld/admin/messages --html report.html

# SSRF: a URL parameter requests the callback address
python sv1.py -u "https://site.tld/fetch?url=x" --ssrf

# CI: SARIF + fail only on HIGH or above
python sv1.py -u https://site.tld --crawl --sarif sv1.sarif --fail-on high

# Scoped from a file + history + diff between sessions
python sv1.py -u https://site.tld --crawl --scope scope.txt `
  --db sv1-history.db --diff --fail-on high

# Replay the previous session (no crawling)
python sv1.py -u https://site.tld --db sv1-history.db --retest --fail-on high

# Remote target: the callback must be reachable from it (tunnel / reverse proxy)
python sv1.py -u https://site.tld --blind --oob https://cb.example.tld `
  --oob-bind 0.0.0.0:8777 --oob-wait 30
```

Exit codes: `0` = no findings (or `--fail-on none`), `1` = a finding at or above
the `--fail-on` threshold, `2` = the target did not respond or a file could not be opened.

### Real application inputs (1.3.1)

- **HAR session import.** `--har session.har` reads same-origin cookies, headers
  (including `Authorization` and CSRF headers) and request bodies. Query, JSON,
  form and raw body points are imported, then the normal scanners run. CLI
  `-H`/`--cookie` values override the file.
- **Raw request import.** `--request request.txt` accepts one HTTP request with
  its method, path, headers and body. A relative request path is resolved against
  the `-u` origin. The file is read once; imported session values are not printed.
- **Nested JSON and raw bodies.** `--json`/`--json-data` recursively flattens
  objects and arrays into leaf paths such as `user.name` and `items[0].id`.
  `--har`, `--request`, `--spa` and OpenAPI use the same helper. Every request
  rebuilds the template and replaces only the selected leaf. `--data` accepts a
  JSON document or a raw template whose first `*` is the marker; `--method` and
  `--content-type` control the request. Form points also honour non-POST methods.
- **XHR/fetch POST capture.** `--spa` records the method, body and content type
  of same-origin XHR/fetch calls. JSON and form-urlencoded bodies become points;
  raw bodies with `*` are accepted. Body capture is capped at 200 KB per call and
  40 points per SPA pass.
- **External JavaScript.** `--external-js` reads up to four same-origin
  `<script src>` bundles per page (1.5 MB each), looks for DOM source/sink pairs,
  and proves the candidate in Chromium. Cross-origin bundles are skipped.
- **Nested OpenAPI bodies.** JSON `requestBody` schemas are expanded into nested
  objects and arrays before points are created; form and multipart bodies remain
  top-level.
- **Honest severity.** Reflected XSS starts at `MEDIUM` in the scan output.
  Chromium promotion to `HIGH`/`CONFIRMED` happens only after the marker executes.
  JSON and XHR POST reflections that have no browser execution path stay `MEDIUM`.

### Scope and request identity (1.3.3)

- **Redirects are checked before every hop.** `requests` is asked not to follow
  redirects; SV1 resolves `Location`, rejects non-HTTP(S) schemes, enforces
  `config.MAX_REDIRECTS`, and asks scope before the next request is prepared.
  Without `--scope`, the target origin is the whole allowlist, plus the
  canonical same-host HTTP-to-HTTPS upgrade. A scope file can authorise another
  host, but the hop is still checked first.
- **Session material stays on the scan origin.** Imported `Authorization`,
  `-H` headers and cookies are attached per request. A scoped cross-origin hop
  is reachable and anonymous. The cookie jar is host-scoped, and a cookie point
  replaces the same name instead of sending `sid=abc; sid=payload`.
- **Chromium applies the same rule.** Session headers are not set on the
  browser context; a route guard adds them only for target-origin requests.
  Third-party scripts, images and frames load without the operator's session.
  Top-level navigations outside scope are aborted; subresources are not used as
  a reason to send credentials. Because the browser cookie jar ignores ports,
  any cross-origin request that would carry an imported cookie is cancelled.
- **A refused URL sends no bytes.** Out-of-scope URLs and refused redirect hops
  return `Response(status=0, error=...)` before a socket is opened.
- **Request identity includes the body.** Two raw or JSON templates on the same
  URL and parameter are different points. Form actions keep their query string.
- **Proof counters are honest.** `confirmed` counts browser/OOB proof,
  `replayed` counts HTTP replay, and `verified` is their sum. JSON, history and
  the console summary keep both visible.

### Security and correctness (1.2.1)

- **No inverted TLS flag.** `-k/--insecure` now sets Chromium
  `ignore_https_errors=True`. Before 1.2.1 the value was inverted, so `-k` kept
  certificate errors fatal and the default silently ignored them.
- **Forms stay on the target.** A form action must be same-origin HTTP(S) before
  the crawler turns it into a point, before stored/second-order submission, and
  before the browser submits it. A hostile page cannot redirect scanner headers
  or payloads to a third-party origin through `<form action>`.
- **Parallel requests do not share a `requests.Session`.** Each worker gets its
  own session and adapter pool; all sessions share one thread-safe cookie jar.
  Login cookies still propagate, but adapter state and connection pools are not
  mutated concurrently.
- **SQLi baseline uses the injected occurrence.** When a query or form repeats a
  name (`id=1&id=2`), replay compares against the value at `param_index`, not the
  first value with that name.
- **Published evidence is the finding JSON.** Screenshot files are not release
  assets; the executed marker and `confidence` live in the finding itself.

### Accuracy and reproducibility (1.2.0)

- **Grammar, not payload lists.** A single HTML state machine reads the point:
  tag name, attribute name/value/quote, raw text (`title`, `textarea`, `style`),
  script string/code/regex/comment, or HTML comment. Markup inside a quoted
  attribute (an iframe `data:` URL, for example) is not mistaken for a new tag.
- **Context candidates.** It closes the exact attribute, tag, raw element or
  JavaScript construct that is open. Event-handler reflections use a quote-free
  `alert(/token/)` so servers that escape quotes cannot silently break the proof.
- **Browser proof tries alternatives.** Up to six reflected candidates are tried
  per point. Chromium reads the top page and every child frame, so `iframe srcdoc`
  and injected `srcdoc` are proved rather than guessed. When Chromium is
  available, `HIGH` requires execution; exact reflection without execution stays
  `MEDIUM`. Without a browser the result is reflection-only.
- **Request fidelity.** Duplicate query and form names are preserved, and
  `param_index` means the occurrence of that name. A second parameter such as
  `?id=1&name=test` is actually replaced instead of being left untouched.
- **Reproduce it.** Reflected XSS, SQLi and SSRF findings carry a `curl` command;
  the same string is in the console, HTML, JSON and CSV output. Browser-only
  proofs (DOM, stored, blind) write a local screenshot and record the executed
  marker in the finding; the JSON is the authoritative published evidence.
- **Reports stay safe.** ANSI escapes, control bytes, CSV formula prefixes and
  markup are neutralised before rendering.
- **Non-markup is not XSS.** `text/plain`, JSON and other non-HTML/XML responses are
  not treated as XSS candidates.

Full evidence: [`docs/REALWORLD.md`](docs/REALWORLD.md).

---

## CI and memory (P5)

### SARIF and `--fail-on`

```powershell
python sv1.py -u https://site.tld --crawl `
  --sarif sv1.sarif --fail-on high
```

- `--sarif` writes SARIF 2.1.0: one rule per `kind/technique`, one result per
  finding, a stable fingerprint (`sv1Fingerprint`), a physical location and a
  security severity. Ready for GitHub code scanning or any SARIF consumer.
- `--fail-on` only sets the exit code; it never hides findings:
  - `any` (default): 1 when any finding exists.
  - `none`: always 0, report still written.
  - `low/medium/high/critical`: 1 when a finding is at or above the threshold.
  - 2 stays reserved for an unreachable target or a write failure.
- A `high` threshold does not fail on MEDIUM; a `critical` threshold does not fail on HIGH.
- CI example:

```yaml
- run: python sv1.py -u "$TARGET" --crawl --sarif sv1.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: sv1.sarif
```

### Scope file `--scope`

```text
# scope.txt
example.com
*.example.com
https://api.example.com/v1/*
127.0.0.1:8099
```

- One rule per line, `#` for comments, `*` wildcard in host or path.
- The target itself must match a rule, otherwise the scan stops with code 2.
- Without `--scope`, the target origin is the allowlist (plus a same-host
  HTTP-to-HTTPS upgrade) and cross-origin redirects are refused. With a scope
  file, the crawler, imported points, header/cookie points, every redirect hop
  and top-level browser navigation are checked before use.
- Scope authorises reachability, not secrets: imported headers and cookies are
  still sent only to the target origin. A cross-origin hop inside scope is
  anonymous.
- The file defines what is tested, not a network wall: SPA pages may still load
  external assets while rendering. Those assets do not receive session headers.
  Do not rely on it for network isolation.

### Session database `--db` and `--diff`

```powershell
python sv1.py -u https://site.tld --crawl --db sv1.db --diff
```

- SQLite stores every session and every finding: target, time, version, stats,
  fingerprint, replayable injection point.
- `--diff` compares against the latest session for the same target:
  `+N new · N open · -N fixed`. The fingerprint is kind + HTTP method + URL
  (query sorted) + parameter + detection technique, so a changing payload does
  not create a new finding, while error-based and UNION on the same point stay
  two findings.
- A session is saved even when clean, so a later diff can prove the fix.
- `--retest` reads the latest session and replays the replayable findings only:
  XSS / SQLi error / boolean / time / second-order. It does not crawl and does
  not re-test OOB. Blind/SSRF/Stored/DOM/UNION findings are marked `skipped`
  because they need a browser or a full extraction. Use the same `-u` as the
  original session.
- If the target becomes unreachable, retest marks findings `fixed` (no longer
  provable) and prints the count; this is intended.

### 429 and adaptation

`--rps` is no longer a fixed limit: on `429/503` SV1 doubles the interval up to
8x, honours a numeric `Retry-After` (capped at 30s), and recovers gradually
after 20 healthy responses. `--rps 0` stays unlimited.

> 1.4.0 later: async engine on `httpx` and `--resume`.
> Release 1.3.3 checks redirect scope hop by hop, isolates session headers and
> cookies on the target origin, and keeps HAR/raw request import, nested JSON/raw
> bodies, XHR POST capture, external JavaScript analysis and nested OpenAPI
> bodies. CI runs the Chromium integration tests, the full-lab acceptance test, ruff, mypy
> and a 43.5% coverage floor.

---

## How it scans

**Baseline: measure the page first**

Every point is requested twice unmodified. The two copies are compared at token
level (`difflib`) and the noise is measured: nonce, CSRF token, time, counters.
That noise drives every decision after it:

- `floor = 3 × noise` — the smallest believable difference.
- Stable page: one comparison.
- Volatile page: each branch is re-fetched twice before comparing.

A page whose noise exceeds 10% is treated as unreliable, and every finding on it
loses a confidence grade.

**XSS (reflected)**

1. Sends a random token `sv1xxxxxxxx` in the parameter.
2. If it does not come back in the response → no reflection, skip. Responses whose
   content type is not HTML/XML are not XSS candidates.
3. Reads the **grammar** of the reflection point: element tag name, attribute
   name/value and its quote, raw text (`title`, `textarea`, `style`, `xmp`,
   `noscript`), inside `<script>` (code, string, regex or comment), or inside an
   HTML comment.
4. Builds ordered context payloads that close exactly what is open — e.g. inside
   `<script>var x = "..."` it uses `";alert(tok)//`; inside a block comment it
   closes `*/` first; inside `value='...'` it closes the attribute and tag; inside
   a raw-text attribute it closes the element before injecting markup.
5. Waits for the token to return **verbatim**. Exact reflection proposes a
   finding; encoded or stripped markup is `MEDIUM`.
6. Chromium tries the primary payload and up to five exact alternatives, dispatches
   `mouseover`/`focus`/`click` for handler payloads, and reads every frame. Only
   an executed marker keeps `HIGH` + `CONFIRMED`; exact but non-executing payloads
   drop to `MEDIUM` with the reason.

**SQLi**

1. **Error-based** — breaking payloads + error signatures for 7 databases,
   excluding errors already present on the original page.
2. **Boolean-based** — 6 true/false pairs, accepted only if: both branches
   repeat with the same shape, "true" matches the original, "false" differs from
   it, and the gap between them is above the noise floor.
3. **Time-based** (`--time`) — SLEEP / WAITFOR / pg_sleep / DBMS_PIPE, confirmed
   twice with a margin above the original timing.
4. **UNION + extraction** — only runs on a point that already proved injectable:
   - Column count: `ORDER BY n` fails at the first excess column → binary search.
   - Echoed column: `UNION SELECT NULL,...,'sv1u...',...` until the marker appears.
   - Real extraction: `version()`, `@@version`, `sqlite_version()`, or `v$version`
     for Oracle. The value itself is written to the evidence, and the fingerprint
     identifies the database.
   - `--dump`: reads `current_user()`, `database()` and table names from the
     database catalog through the same echoed column. Every value is wrapped in
     an `sv1[...]sv1` marker so it is cut from the response without guessing;
     capped at 3 requests and 12 tables. Supported on MySQL/PostgreSQL/MSSQL/SQLite.
   - Result is `CRITICAL` and `CONFIRMED` — read from the database, not guessed.

**Filter bypass**

If the target answers a payload with `403/406/429`, the same injection is retried
in other shapes: `/**/` whitespace, `%09` tabs, case swapping, double encoding.
The payload that actually worked is the one stored in the finding, and the replay
stage tries the same shapes before declaring a finding unstable.

**Injection sites**

- `query` and `form` — automatically from the crawl.
- `header` (`--headers`) — the header values listed above on the target URL.
- `cookie` (`--cookies`) — every cookie passed with `--cookie`.
- `json` (`--json`, `--har`, `--request`, `--spa`, `--openapi`) — every scalar
  leaf in a JSON body, including nested objects and arrays. The body template is
  rebuilt for each request.
- `raw` (`--data`, `--request`, `--spa`) — a body template whose first `*` is
  the marker, sent with the declared method and content type.
- `js` (`--js`) — every URL with a query inside an inline `<script>` or a
  same-origin external script. Covers `fetch`, `axios`, `$.ajax` and any URL
  written as text.
- `multipart` — `enctype="multipart/form-data"` forms are actually sent as
  multipart, and their text fields become injection points.

**Replay**

Every finding is replayed after the scan (`--no-verify` disables it). If it does
not reproduce, its severity and confidence drop and the report states it is
unstable. This kills false positives produced by random pages or a WAF.

**Execution proof (Chromium)**

With Playwright installed, SV1 actually opens the page and re-sends the injection
as sent:

- An init script replaces `alert/confirm/prompt` before any page script and
  records every call with a scan-specific marker (`sv1...`).
- The primary payload is tried first. If it reflects but does not execute, up to
  five alternatives are tried before the finding is downgraded.
- The reader walks every frame, so `iframe srcdoc` and injected `srcdoc` prove
  execution in the child document, not just the top page.
- Event-handler payloads are exercised with `mouseover`, `focus` and `click`;
  `javascript:` links are followed.
- A finding is only `CONFIRMED` if the marker fired inside any frame.
- No fire → drops to `MEDIUM` with an explicit note and the candidate count.
- Every confirmed finding gets a screenshot in `sv1-artifacts/`.

**DOM XSS**

Static analysis of every `<script>`: looks for sources
(`location.hash/search/href`, `document.referrer`, `window.name`, `document.cookie`,
`localStorage`, `sessionStorage`, `postMessage`) and sinks (`innerHTML`,
`document.write`, `eval`, `insertAdjacentHTML`, `setTimeout` …). Every
source→sink pair is tested in the browser: `#payload`, common parameters,
referrer, `window.name`, web-storage keys or a `postMessage` event. The finding
is recorded only if the browser executed the marker.

**Stored XSS** (`--stored`)

Sends the payload into POST forms, then visits the pages again and waits for the
marker. Writes data to the target.

**Hidden parameter discovery** (`--params`)

Starts with a random control parameter: if it changes the page, the page reacts
to anything and the result is unreliable. Otherwise it sends common names in
batches (16 names), and when the response changes it splits the batch in half
until the name is isolated, then confirms each name twice on its own. Names
already present in the URL are excluded, and names that only work together are
rejected. It tests the target URL itself (like Arjun), not every crawled page.

**Points from JavaScript** (`--js`)

The crawler follows `<a href>` only. Modern apps call `/api/...` from inside the
script. SV1 reads the inline script and fetches same-origin external scripts
(capped at 6 files per page), extracts every quoted string containing `?` or `&`,
turns it into a normal `InjectionPoint`, and runs XSS + SQLi on it. External links
and static files (`*.js?v=1`) are excluded.

**SPA crawl** (`--spa`)

The normal crawler reads HTML only. SV1 opens up to 6 pages containing `<script>`
in a real Chromium, listens for `xhr` and `fetch` requests, and turns every URL
with a query into a normal injection point. POST/fetch bodies are captured too:
JSON objects become nested leaf points, form-urlencoded bodies become form points,
and a raw body with `*` becomes one raw point. It also captures `<a>` links that
only appear after JavaScript runs: a link with a query becomes injection points,
and a link without one is fetched as a page (capped at 4). This covers interfaces
that build themselves in the browser.

Limits: bodies are kept up to 200 KB; multipart POST bodies are skipped. Requires
Chromium; with `--no-browser` it is skipped with a warning. JSON/XHR POST
reflections are reported as `MEDIUM` unless another executed path proves them.

**OpenAPI import** (`--openapi`)

```powershell
python sv1.py -u https://site.tld --openapi spec.json
python sv1.py -u https://site.tld --openapi https://site.tld/openapi.json
```

Reads JSON (local file or URL), builds URLs from `servers[0]` + `paths`, and
creates a point for every `query` parameter and every property in a JSON, form or
multipart body. Local `$ref` is followed, and `{param}` in the path is replaced
with `1` (the path itself is never injected). Capped at 80 points and 6 fields per
operation. YAML is not supported — export JSON first.

**The callback (OOB)**

With `--blind` or `--ssrf`, SV1 starts a local HTTP server on `127.0.0.1:8777`.
Every injection gets a unique token (16 hex chars). The server records arrival
time, IP, User-Agent, Referer and query — and never records a request without a
registered token. `/t/<token>` returns a script, `/e/<token>` returns a 1×1 image.

- Local target: the default address is enough.
- Remote target: `--oob https://...` + `--oob-bind 0.0.0.0:8777` + a tunnel or
  opened port that reaches the listener. A `127.0.0.1` address is not reachable
  from outside the machine.
- If the target is HTTPS, use an HTTPS callback; the browser blocks mixed content.
- `--oob-wait` sets the maximum wait for callbacks (blind and SSRF) after the
  injection/scan.
- The server reads no files and serves no target content; it records hits only.

**Blind XSS** (`--blind`)

1. Collects POST forms (capped at 6 forms, 2 fields each).
2. Injects two shapes: `<script src="http://cb/t/TOKEN"></script>` and
   `"><script src="..."></script>`, with an independent token per injection.
3. If the page is opened in a browser, it requests `/t` and returns JavaScript
   that loads `/e/TOKEN?p=<sink-url>`.
4. `/t` = the script was fetched. `/e` = the script **executed**, and `p`
   identifies the actual rendering page.
5. `--blind-visit` opens the admin page inside Chromium after injection (local
   simulation) and takes a screenshot. Without it, SV1 waits `--oob-wait` for a
   real admin.
6. Result: `HIGH` + `CONFIRMED` on execution, `HIGH` + `MEDIUM` if the script was
   only fetched (e.g. CSP blocked the image). No hit, no finding.

`--blind` writes data to the target.

**SSRF** (`--ssrf`)

- Picks query/form/JSON/multipart parameters whose name looks like an address
  (`url`, `redirect`, `callback`, `webhook`, `next`, `dest` …) or whose original
  value is a full URL.
- Sends `http://<callback>/t/<token>` in place of it. The server records the connection.
- The test does not follow redirects: a target returning `302` toward the callback
  creates no false finding, because the request has to come from the target itself.
- Result `HIGH` + `CONFIRMED` with arrival time, IP and User-Agent.
- Capped at 15 points, HTTP(S) only. Headers and cookies are excluded.

**Second-order SQLi** (`--second-order`)

The injection is stored now and executed later in a second query. Steps:

1. Stores a clean value (`sv1clean`) in the field → measures the pages (no errors).
2. Stores `sv1'` in the same field.
3. Visits up to 6 pages (including the form pages) looking for a database error
   signature that was **not** in the baseline.
4. Error appears → `CRITICAL` finding with evidence: the field, the storage page,
   the error page.
5. The replay stage opens the error page and confirms the error persists.

Limits: one form per field, one payload, up to 6 forms and 6 pages. Writes data to
the target, like `--stored`.

Every finding shows: target, parameter, **detection technique** (`technique`),
payload, severity, confidence grade, and one line of evidence.

---

## Measured on the lab

The `/account` page changes on every request (random nonce) and contains a real
logical injection. Comparing the old logic (bytes, one request) with the current
engine:

```
real injection on /account   old 0/5   sv1 5/5     ← the old one missed it
false positives on /noisy    old 0/5   sv1 0/5
```

Cause: 2% noise completely breaks byte comparison. SV1 measures the noise and
compares structure.

---

## Real-world validation

Public, intentionally vulnerable demo targets only. Raw evidence and the exact
commands: [`docs/REALWORLD.md`](docs/REALWORLD.md). The same-target comparison
against dalfox and sqlmap is in [`docs/COMPARISON.md`](docs/COMPARISON.md).

Live-site validation: **4 runs, 76 pages, 49 injection points, 560 requests,
59 findings, 59/59 verified, 0 errors**. Automated tests: **110 discovered,
106 pass by default; the Chromium integration tests and the full-lab acceptance test run
in CI**.

| Target | Scope | Result |
|---|---|---|
| Google Firing Range, reflected | 49 pages, 47 points | 42 findings — **40 HIGH** confirmed in Chromium, 2 MEDIUM; replay 42/42, 0 unstable |
| Google Firing Range, DOM | 25 pages crawled, 20 rendered | **15 HIGH** DOM findings, 0 errors |
| Altoro Mutual search | one GET parameter | **1 HIGH** reflected XSS, confirmed; replay 1/1 |
| Firing Range, HAR import | one imported GET point | **1 HIGH** confirmed; replay 1/1 |
| Local lab, 1.3.3 | full coverage incl. HAR/JSON/XHR/external JS | **31/31** findings, 0 unstable; scope and browser guards active |

The reflected Firing Range and DOM runs remain the 1.2.1/1.2.0 evidence; the
detection engine is unchanged. Altoro was re-run with replay enabled for 1.3.1;
that evidence is retained.
The 1.3.1 public HAR run imported one GET request, found the reflected XSS at
`HIGH` + `CONFIRMED`, and replayed it (12 requests, 12.1 s).
Firing Range ended with 512 requests, 0 errors and 247 s.
The two `MEDIUM` cases are `/url/css_import` (a stylesheet `<link>` cannot execute
`javascript:` in current Chromium) and `/url/object_data` (pinned to the removed
Flash plugin type); neither page accepts `<`/`>` in the parameter. They are
reported as reflection-only, not inflated to `HIGH`. Replay re-sent all 42
findings and reproduced all 42.

The 1.3.3 lab acceptance run: 31/31 verified (17 confirmed in the browser or
OOB, 14 replayed over HTTP), 0 unstable — CRITICAL 10 / HIGH 18 / MEDIUM 3,
21 pages, 29 points, 966 requests, 184.8 s, 0 errors. Evidence:
[`docs/evidence/local-lab-1.3.3.json`](docs/evidence/local-lab-1.3.3.json). The
run uses `--scope 127.0.0.1:8099` and therefore exercises the redirect and
browser guards. The new input paths are in that same run: `--external-js`
confirms `/external` (`location.hash → innerHTML` inside `/external.js`) at
`HIGH`; `--spa` captures the `/api/xhr` POST JSON body and reports `user.name`
at `MEDIUM` (reflection only, no JSON browser execution); the nested-JSON and
HAR focused runs each produce the same `user.name` point.

External comparison on a real SQLite target, same day: SV1 confirmed 3 XSS and
2 SQLi, dalfox confirmed 3 XSS, sqlmap confirmed 2 SQLi; all three reported zero
false positives. SV1 added two explicit reflection-only `MEDIUM` notes. The
specialists are faster in their lanes; SV1 costs more because it crawls, covers
both classes and proves execution. See [`docs/COMPARISON.md`](docs/COMPARISON.md).

---

## Project structure

```
sv1/
├── sv1.py              entry point and CLI
├── sv1lib/
│   ├── version.py      the only version string
│   ├── config.py       every number and constant
│   ├── models.py       data types (Finding, InjectionPoint ...)
│   ├── net.py          HTTP client + adaptive 429 rate limit
│   ├── jsonbody.py     nested JSON leaf paths and body rebuilding
│   ├── imports.py      HAR / raw HTTP request import
│   ├── identity.py     stable finding fingerprint (history/SARIF)
│   ├── history.py      SQLite: sessions, findings, diff, retest
│   ├── scope.py        host/path allowlist
│   ├── policy.py       fail-on threshold and exit code
│   ├── sarif.py        SARIF 2.1.0 export
│   ├── crawl.py        crawler + form extractor (stdlib)
│   ├── baseline.py     noise measurement and page identity (difflib)
│   ├── context.py      injection context analysis + payload building
│   ├── payloads.py     payloads and DB error signatures
│   ├── xss.py          reflected XSS detector
│   ├── domxss.py       source→sink analysis + browser proof
│   ├── stored.py       inject into forms, then visit pages
│   ├── hidden.py       hidden parameter discovery (binary search)
│   ├── jsparse.py      extract injection points from JavaScript
│   ├── spa.py          SPA crawl + XHR/fetch capture
│   ├── openapi.py      import injection points from OpenAPI JSON
│   ├── secondorder.py  second-order SQLi (store, then visit)
│   ├── oob.py          callback server + tokens + hit log
│   ├── blind.py        Blind XSS: inject, then wait for execution
│   ├── ssrf.py         SSRF over the same callback
│   ├── sqli.py         SQLi detector (error/boolean/time/union)
│   ├── union.py        column counting + extraction + dump
│   ├── dberrors.py     database error signatures
│   ├── tamper.py       alternate shapes when a filter is present
│   ├── browser.py      Chromium + alert hook + screenshots
│   ├── verify.py       finding replay
│   ├── banner.py       animated banner
│   └── report.py       rendering and export (text/JSON/CSV/HTML)
├── lab/server.py       local vulnerable target for practice
├── tests/test_p5.py    unit tests (scope/history/SARIF/rate/fail-on)
├── tests/test_1_2.py   request fidelity, context grammar, proof policy
├── tests/test_1_3.py   HAR, nested JSON, SPA bodies, external JS
├── tests/test_browser_1_3.py  Chromium integration: XHR, headers, cookies (CI)
├── tests/test_lab_1_3.py      full-lab release gate (CI)
├── docs/REALWORLD.md   real-world validation
├── docs/evidence/      JSON evidence from public and local runs
├── .github/workflows/ci.yml
├── LICENSE             MIT
├── CHANGELOG.md        release log
├── ROADMAP.md          development roadmap
├── requirements.txt    exact runtime dependency pins
├── requirements-dev.txt exact test/lint/type pins
├── pyproject.toml      package metadata and build configuration
└── run.bat
```

---

## Local lab

A ready vulnerable target on `127.0.0.1` only; it never leaves the network:

```powershell
# window 1
python lab\server.py 8099

# window 2
python sv1.py -u http://127.0.0.1:8099/ --crawl --no-banner
```

Full scan with P3 + P3.1 + P4 + P5 coverage:

```powershell
# scope file, once
"127.0.0.1:8099" | Set-Content scope-lab.txt

python sv1.py -u http://127.0.0.1:8099/ --crawl --stored --js --second-order --dump `
  --spa --external-js --openapi http://127.0.0.1:8099/openapi.json `
  --blind --blind-visit http://127.0.0.1:8099/blind-admin --ssrf `
  --scope scope-lab.txt --db lab-history.db --diff --sarif report.sarif `
  --fail-on high --html report.html
```

Result: **31 findings, 31 verified (17 confirmed, 14 replayed), 0 unstable** —
CRITICAL 10, HIGH 18, MEDIUM 3, 21 pages, 29 injection points, 966 requests,
184.8 s (with Chromium).

The lab stores guestbook, blind and profile state in memory. Restart
`lab\server.py` before repeating the full run; otherwise `/profile` already
contains the second-order payload and its form is replaced by the error page.

- **XSS (17):** 15 confirmed by execution inside Chromium (`/search`, `/feedback`
  two fields, `/js`, `/attr`, `/waf`, `/api/fetch`, `/api/spa`, `/dynamic`, plus
  the external bundle at `/external`), DOM in `/dom`, stored in `/guestbook`
  (name + message), and Blind XSS in `/blind-admin`; the encoded reflection in
  `/safe` and the JSON POST reflection at `/api/xhr` stay `MEDIUM`.
- **SQLi (13):** MySQL error in `/search`, `/union`, `/waf`, `/upload`,
  `/api/fetch`, `/api/spa`, `/dynamic`; logical injection in `/item` and
  `/api/item`; `/account` drops to `MEDIUM` because its page is volatile (noise);
  UNION extraction from `/union`: `3 columns, column 1 echoes back; version() -> 8.0.36-lab`;
  second-order injection in `/profile` (`sv1'` is stored, then breaks on render).
- **SSRF (1):** `/fetch?url=` actually requested the callback address, result
  `HIGH` + `CONFIRMED` with arrival time and User-Agent. The test does not follow
  redirects, so the hit comes from the target itself.
- **`--blind`:** 14 payloads across 5 forms (two shapes per field). The
  `/blind-admin` page is not linked from the index — the crawler never sees it.
  After injection `--blind-visit` opened it, so the script was requested from
  `/t`, then executed the `/e` image and sent the rendering page in `p`. The same
  field in `/blind` was discovered once after dedupe.
- **`--ssrf`:** one URL point in `/fetch`; the request reached the listener from
  `urllib` inside the lab, not from the scanner browser.
- **`--dump`:** adds the database values to the finding:
  ```
  data    user    sv1@localhost
  data    db      sv1lab
  data    tables  users,notes,accounts
  ```
- **`--js`:** two points from the `/js-endpoints` script:
  `/api/fetch?id=1&name=test` — XSS confirmed by execution and SQLi error.
- **`--spa`:** captures GET and XHR POST traffic. It catches
  `/api/spa?id=1&name=test` built from variables (`--js` cannot see it) → XSS
  confirmed by execution and SQLi error. It also catches the `<a>` link the script
  built toward `/dynamic?id=1&name=test` → the same two findings. The `/xhr-post`
  page sends a JSON body to `/api/xhr`; `user.name` is captured as a POST point
  and reported at `MEDIUM` (reflection only). `/api/fetch` was already listed so
  it did not repeat (dedupe by key).
- **`--external-js`:** reads `/external.js` and confirms
  `location.hash → innerHTML` in Chromium, recording `/external` at `HIGH` +
  `CONFIRMED`.
- **`--openapi`:** 4 points from `/openapi.json`; `/api/item` JSON added one
  logical injection. `/api/fetch` points matched `--js` points so they did not repeat.
- **`--second-order`:** stores `sv1clean` then `sv1'` in `/profile`, measures the
  pages, and detects the new error on render.
- **`--params`** on `-u http://127.0.0.1:8099/hidden`: discovers `debug` and
  `export` and yields two XSS findings confirmed by execution.
- `--json http://127.0.0.1:8099/api/item`: +1 (JSON logical injection).
- `--headers` on `-u .../header`: +1; `--cookies --cookie sid=abc` on
  `-u .../cookie`: +1.

`--stored`, `--second-order` and `--blind` write data to the target.
`--ssrf` makes the target request the callback address. The lab adds `/blind`
and `/fetch` as normal pages, while `/blind-admin` is intentionally left unlinked.

- **`--scope`:** the file `127.0.0.1:8099` allowed the target; a target outside
  the file returns 2 before any request. The crawl never leaves scope, and
  OpenAPI points are filtered.
- **`--db --diff`:** the first session is `#1` with no predecessor; the next
  scan of the same target is compared against it (`+N new · N open · -N fixed`).
- **`--retest`:** rechecks replayable findings from the session and skips Blind,
  SSRF, Stored, DOM and UNION. It does not crawl and does not open a browser.
- **SARIF:** 31 findings, a stable fingerprint per finding, and a file that passes
  the official SARIF 2.1.0 schema.
- **`--fail-on`:** `none` = 0, `high` = 1, `critical` = 1 on the lab, and a clean
  target with `high` = 0.

`/waf` rejects any request containing a space with 403. SV1 bypasses it with
`/**/` and stores the successful shape in the finding:

```
vector  error
payload '/**/AND/**/1=CONVERT(int,@@version)--/**/-
note    database error surfaced (MySQL) - error based injection
        | filter bypassed with 2 encoded payload(s)
```

---

## Limits

- XSS covers reflected, DOM and stored when Chromium runs. Without it: reflection only.
- Non-HTML responses (`text/plain`, JSON, binary) are not XSS candidates. A
  stylesheet `link` or a removed Flash `object` can reflect a `javascript:` URL
  without executing it; those findings stay `MEDIUM`.
- DOM detection relies on source→sink pairs inside inline `<script>` by default.
  `--external-js` adds up to four same-origin bundles per page (1.5 MB each).
  `--spa` executes pages but does not analyse external bundle text. The browser
  budget renders 20 pages per DOM pass.
- `--js` reads URLs written as text inside scripts (inline script + same-origin
  external files). If the URL is built from variables (`'/api/' + id`) it is not
  found — that is where `--spa` comes in and catches it from the actual request.
- `--spa`: up to 6 pages, 1.8 s wait for late requests, captures XHR/fetch POST
  bodies up to 200 KB. Multipart POST bodies are skipped. Requires Chromium;
  skipped with `--no-browser`.
- `--openapi`: JSON only (export YAML to JSON), reads `servers[0]` and `paths`,
  does not inject `{param}` inside the path, capped at 80 points and 6 fields per
  operation. JSON bodies are flattened to scalar leaves; form/multipart bodies
  remain top-level.
- `--har`/`--request`: same-origin session material only; cookies and headers are
  static from the file. A rotating CSRF token or short-lived session needs a fresh
  capture/proxy. Imported values are not printed to the console.
- Nested JSON is bounded at 24 levels; a leaf path is sent by rebuilding the
  original template. In a raw body, the first `*` is the injection marker.
- `--external-js` reads same-origin scripts only; cross-origin CDN bundles are
  skipped. It is a source/sink scan, not a full JavaScript parser.
- `--params` tests the target URL itself, not every crawled page.
- `--second-order` tries one payload (`sv1'`) and up to 6 forms and 6 pages;
  fields filtered on input will not surface.
- `--blind`: POST forms only, up to 6 forms, 2 fields per form, 2 shapes per field.
  `--blind-visit` needs Chromium; without it SV1 waits for a real admin. A strong
  CSP can block the image (`/e`) so the finding is `MEDIUM` even though the script
  was fetched.
- `--ssrf`: relies on the parameter name or a full URL value; capped at 15 points,
  HTTP(S) only. `file/gopher` is not attempted yet. An allowlist or authentication
  on the target endpoint means a false negative.
- The callback must be reachable from the target. The default `127.0.0.1` is for a
  local target only; for a remote target use a public `--oob` + a tunnel or opened
  port + `--oob-bind`. There is no DNS/SMB OOB, and no OOB SQLi via
  `xp_dirtree`/`UTL_HTTP` yet.
- multipart covers text fields inside the form, not the contents of uploaded files.
- SQLi: error/boolean/time + UNION extraction. UNION needs a text column and
  unblocked `ORDER BY`/`UNION`. `--dump` reads identity and table names only, not
  full rows; Oracle has no dump yet.
- `--headers` and `--cookies` test the target URL itself, not every crawled page.
- WAF/flood protection can flip results. Lower `--rps` when needed.
- Time-based scanning is slow by nature: every payload waits several seconds.
- `--stored`, `--second-order` and `--blind` write data to the target.
- Pages behind a login need `--cookie` or `-H` (the browser uses the same cookies).
- `--scope` defines scan, redirect and top-level navigation targets. SPA pages
  may still load external assets while rendering, but those requests do not get
  the operator's headers or cookies; it is not a network wall.
- `--retest` replays XSS and SQLi error/boolean/time/second-order only. Blind,
  SSRF, Stored, DOM and UNION need a browser or a full extraction, so they are
  skipped. The latest session for the same `-u` is the reference.
- `--db` has no automatic pruning; delete the file or archive old sessions manually.
- `--resume` and the async engine (`httpx`) are deferred to 1.4.0. Curl
  reproduction is included since 1.2.0.

---

## License

MIT — see `LICENSE`.

## Version

`1.3.3` — current public release. Real-application inputs: HAR/raw HTTP request
import, nested JSON and raw bodies, XHR/fetch POST capture, external same-origin
JavaScript analysis, nested OpenAPI bodies, exact dependency pins, a
`pyproject.toml`, and a full-lab Playwright CI gate. `1.3.3` adds redirect-wide
scope enforcement, session-header isolation in HTTP and Chromium, imported-cookie
isolation, split confirmed/replayed counters, and a 43.5% coverage floor. Reflection alone
remains `MEDIUM`. Change details in `CHANGELOG.md`.
