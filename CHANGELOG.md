# Changelog

All notable changes to SV1. Format follows Keep a Changelog.

## 1.3.2 - 2026-10-27

Quality gates and a same-target external comparison. The detection engine and
the vulnerability scope are unchanged: XSS, SQLi and SSRF; reflection-only
stays `MEDIUM`.

### Added

- `sv1lib/version.py` is the only version string. `pyproject.toml` uses a dynamic
  version, `config.TOOL_VERSION` imports it, and the user agent is built from it.
  `tests/test_version.py` guards the package metadata.
- `requirements-dev.txt` pins `coverage==7.17.0`, `mypy==2.4.0` and
  `ruff==0.17.3`. The new `quality` CI job runs ruff, mypy and branch coverage.
- `docs/QUALITY.md` records the 42.5% branch baseline and the modules that need
  the live lab (`sqli`, `verify`, `ssrf`, `browser`).
- `tests/test_quality_1_3_2.py` covers UNION payload/column/marker/extract paths
  and blind form/sink submission without a network.
- `lab/real_sql.py`: a small SQLite-backed comparison target. It exists only for
  `docs/COMPARISON.md`; the 31-case emulator remains the release gate.
- `docs/COMPARISON.md` and `docs/evidence/comparison-2026-10-27.json`: same-day
  runs of SV1 `1.3.2`, dalfox `3.2.4` and sqlmap `1.10.10.27#dev`.

### Changed

- `pyproject.toml` gained ruff, mypy and coverage configuration and a dynamic
  version. Generated `build/`, `dist/`, `.coverage` and egg-info are ignored.
- `config.USER_AGENT` now follows `TOOL_VERSION` instead of duplicating `1.3.1`.

### Fixed

- Mypy findings in `history.py`, `banner.py`, `crawl.py`, `openapi.py`,
  `browser.py`, `stored.py` and the retest guard in `sv1.py`.
- Unused imports in `net.py` and `tests/test_1_2.py`; ruff `E9`/`F` is clean.

### Validation

- Unit tests: 86 discovered, 84 pass and 2 opt-in browser/lab tests are skipped
  by default; `compileall` clean. Both opt-in tests pass.
- `python -m ruff check .`: all checks passed.
- `python -m mypy`: no issues in 36 source files.
- `coverage`: 42.5% branch over `sv1.py` and `sv1lib`; `union.py` 48.9% and
  `blind.py` 46.7% after the focused tests.
- Full lab: 31 findings, 31/31 replayed, 0 unstable, 10 `CRITICAL` / 18 `HIGH` /
  3 `MEDIUM`, 21 pages, 29 points, 966 requests, 0 errors, 186.0 s. Evidence:
  `docs/evidence/local-lab.json`.
- Comparison on one real SQLite target: SV1 confirmed 3 XSS + 2 SQLi plus 2
  reflection-only `MEDIUM`; dalfox confirmed 3 XSS; sqlmap confirmed 2 SQLi. All
  three had 0 confirmed false positives. Evidence:
  `docs/evidence/comparison-2026-10-27.json`.
- Version `1.3.2`.

## 1.3.1 - 2026-10-27

Packaging, evidence and CI hardening for the 1.3.0 feature set. Vulnerability
scope is unchanged: XSS, SQLi and SSRF; reflection-only stays `MEDIUM`.

### Added

- `pyproject.toml` with package metadata, console entry point and exact
  dependency pins. `requirements.txt` pins `requests==2.34.2` and
  `playwright==1.64.1`; the install path is reproducible.
- `tests/test_lab_1_3.py`: full-lab acceptance test. It starts a fresh lab,
  runs the complete crawl/XSS/SQLi/SSRF/SPA/external-JS/OpenAPI command, and
  asserts 31 findings, 31 verified, 0 unverified, 0 errors, the severity split,
  the SARIF result count and the HTML report. CI runs it after the Chromium test.
- CI now installs from the pinned requirements and executes both the Chromium
  XHR integration test and the full-lab acceptance test.

### Fixed

- A GET form and a page query on the same URL and parameter are one injection
  point instead of two. Altoro produced duplicate findings before this fix; the
  replay evidence is now 1 point, 1 finding, 1/1 verified.

### Validation

- Unit tests: 75 discovered, 73 pass and 2 opt-in browser/lab tests are skipped
  by default; `compileall` clean. Both opt-in tests pass with
  `SV1_BROWSER_TESTS=1` / `SV1_LAB_TESTS=1`.
- Full lab: 31 findings, 31/31 replayed, 0 unstable, 10 `CRITICAL` / 18 `HIGH` /
  3 `MEDIUM`, 21 pages, 29 points, 966 requests, 0 errors, 185.4 s. Evidence:
  `docs/evidence/local-lab.json`.
- Live-site totals across the four retained public runs: 4 runs, 76 pages,
  49 injection points, 560 requests, 59 findings, 59/59 verified, 0 errors.
- Altoro rerun with replay enabled: 1 page, 1 point, 11 requests, 0 errors,
  1 `HIGH` + `CONFIRMED`, 8.0 s. Evidence:
  `docs/evidence/altoro-search.json` (`meta.replay: true`).
- Public HAR import on Firing Range: 1 imported GET point, 1 `HIGH` +
  `CONFIRMED`, 1/1 replay, 12 requests, 12.1 s. Evidence:
  `docs/evidence/firing-range-har.json`.
- Version `1.3.1`.

## 1.3.0 - 2026-10-27

Real-application inputs. The vulnerability scope is unchanged: XSS (reflected,
DOM, stored, blind), SQLi and SSRF. Async and `--resume` move to 1.4.0.

### Added

- **HAR import** (`--har FILE`): same-origin cookies, headers and request bodies
  become a session and injection points. Query, form-urlencoded, JSON and raw
  bodies are imported. CLI headers/cookies override the file.
- **Raw HTTP request import** (`--request FILE`): method, path, headers, cookies
  and body from one request; relative paths resolve against the `-u` origin.
- **Nested JSON bodies**: `--json`, `--har`, `--request`, `--spa` and OpenAPI
  flatten objects and arrays into leaf paths (`user.name`, `items[0].id`) and
  rebuild the original template for every request.
- **Raw bodies and explicit methods**: `--data` accepts a JSON document or a raw
  template whose first `*` is the marker; `--method` and `--content-type` control
  both `--data` and `--json`. Form points now honour PUT/PATCH instead of always POST.
- **XHR/fetch POST capture in `--spa`**: method, body and content type are
  recorded in Chromium. JSON and form-urlencoded bodies become points; raw
  bodies with `*` are accepted. Body cap 200 KB, 40 points per pass.
- **External JavaScript analysis** (`--external-js`): up to four same-origin
  `<script src>` bundles per page (1.5 MB each) are scanned for DOM source/sink
  pairs and proved in Chromium.
- **Nested OpenAPI JSON bodies**: requestBody schemas are expanded through nested
  objects and arrays; form/multipart bodies remain top-level.
- **Playwright CI job** with a Chromium XHR POST integration test against the
  local lab.

### Fixed

- Reflected XSS is emitted as `MEDIUM`/`MEDIUM` until Chromium executes it. If
  the browser is unavailable, every reflected finding is explicitly downgraded
  with a `reflection only` note; the console no longer prints `HIGH` before a
  later downgrade.
- `--json` points and imported JSON points preserve sibling fields and array
  order instead of sending only top-level keys.
- Imported session data is filtered to the target origin and is not written to
  the console or report metadata.

### Validation

- Unit tests: 72 discovered, 71 pass and 1 opt-in browser test is skipped by
  default; `compileall` clean. The opt-in Chromium test passes with
  `SV1_BROWSER_TESTS=1`.
- Browser integration: Chromium captures the `/xhr-post` POST JSON body and
  produces `user.name` and `q` points.
- Local lab focused checks:
  - `/external --external-js`: 1 `HIGH` DOM XSS confirmed in Chromium
    (`location.hash -> innerHTML` in `/external.js`), 2 requests.
  - `/xhr-post --spa`: 1 XHR POST call with body, 2 points, 1 `MEDIUM`
    reflection (no JSON browser execution path), 14 requests.
  - `/api/nested --json`: nested `user.name` and `q` points, 1 `MEDIUM`
    reflection, 14 requests.
  - HAR import: same-origin session plus nested JSON points, 1 `MEDIUM`
    reflection, 14 requests.
- Full local lab with `--external-js`: 31 findings, 31/31 replayed, 0 unstable,
  10 `CRITICAL` / 18 `HIGH` / 3 `MEDIUM`, 21 pages, 29 points, 966 requests,
  0 errors, 183.8 s. Evidence: `docs/evidence/local-lab.json`.
- Public HAR import on Firing Range: 1 imported GET point, 1 `HIGH` +
  `CONFIRMED` reflected XSS, replay 1/1, 12 requests, 0 errors, 17.9 s.
  Evidence: `docs/evidence/firing-range-har.json`.
- Version `1.3.0`.

## 1.2.1 - 2026-10-27

Security and correctness hotfix on top of 1.2.0. No new vulnerability categories;
XSS (reflected, DOM, stored, blind), SQLi and SSRF remain the scope.

### Fixed

- **Inverted browser TLS flag.** `-k/--insecure` now maps to Playwright
  `ignore_https_errors=True`. Before this fix `-k` kept certificate errors fatal
  while the default silently ignored them.
- **Cross-origin form actions.** A form action must be same-origin HTTP(S) before
  it becomes an injection point, before stored/second-order submission, and
  before the browser submits it. A hostile page can no longer redirect scanner
  headers or payloads to a third-party origin through `<form action>`.
- **Shared `requests.Session` across workers.** Each thread now gets its own
  session and adapter pool; all sessions share one thread-safe cookie jar. Login
  cookies still propagate, but session/adapter state is not mutated concurrently.
- **Duplicate-name SQLi baseline.** Replay reads the value at the exact
  `param_index` occurrence, not the first value with the same name
  (`id=1&id=2` now uses `2` when position 1 is injected).

### Evidence

- Removed the unpublished screenshot artifacts. Execution evidence is recorded
  in the finding JSON itself (`evidence` plus `confidence`); the Altoro reference
  now points at `docs/evidence/altoro-search.json` and its `confidence:
  CONFIRMED` record.

### Validation

- Unit tests: 49 pass; `compileall` clean.
- **Google Firing Range reflected, replay enabled:** 49 pages, 47 points, 512
  requests, 0 errors, 42 findings — 40 `HIGH` browser-confirmed, 2 `MEDIUM`
  reflection-only. Replay `42/42` reproduced, 0 unstable, 247 s.
  - The two `MEDIUM` cases remain `/url/css_import` (stylesheet link) and
    `/url/object_data` (removed Flash plugin type).
- **Local lab, 1.2.1:** 19 pages, 25 points, 853 requests, 0 errors, 27 findings
  — CRITICAL 9 / HIGH 16 / MEDIUM 2; replay `27/27`, 0 unstable, 163.4 s.
- Raw JSON and commands: `docs/REALWORLD.md`, `docs/evidence/`.
- Version `1.2.1`.

## 1.2.0 - 2026-10-26

Accuracy and reproducibility. No new vulnerability categories: XSS (reflected,
DOM, stored, blind), SQLi and SSRF remain the scope. Async, `--resume` and
auth/session work stay deferred to 1.3.0.

### XSS accuracy

- Replaced the `rfind('<')` guess with an HTML state machine that tracks normal
  tags, quoted attribute values, comments and raw-text elements. Markup inside a
  quoted attribute (an iframe `data:` URL) no longer looks like a new tag.
- Added grammar-specific payloads:
  - element tag-name injection (`TOKEN><svg/onload=...>`);
  - attribute-name and unquoted-value injection via a new event attribute;
  - quote-free `alert(/TOKEN/)` for event-handler reflections, so servers that
    escape double or single quotes cannot silently break the proof;
  - closing `</textarea>` / `</style>` before markup when the reflection is in
    the opening tag of a raw-text element;
  - `iframe srcdoc` markup and a new `srcdoc` attribute for iframe parameters;
  - JavaScript string (assignment and call), code, regex-literal and line/block
    comment payloads;
  - quote-aware `alert` strings so the JS string quote never collides with the
    HTML attribute quote.
- Content-type gate: `text/plain`, JSON and other non-HTML/XML responses are no
  longer XSS candidates. This removed the Firing Range `text/plain` false
  positives.
- Browser proof now tries the primary payload plus up to five exact alternatives
  (`XSS_MAX_PROOFS = 6`), reads every frame, and dispatches `mouseover`, `focus`
  and `click` for handler payloads. `HIGH` still requires the marker to execute;
  exact reflection without execution is `MEDIUM`.
- DOM vectors extended to `document.referrer`, `window.name`, localStorage,
  sessionStorage, `postMessage` and cookies.

### Request and evidence fidelity

- Duplicate query/form names are preserved in `InjectionPoint.params`.
- `param_index` is the occurrence of that name, resolved through
  `InjectionPoint.position()`. Fixed a 1.2.0 development bug where a second,
  differently named parameter (`?id=1&name=test`) was not replaced at all. This
  restored three multi-parameter lab XSS findings.
- Reflected XSS, SQLi and SSRF findings carry a `curl` reproduction string,
  shown in the console and exported to HTML, JSON and CSV. DOM, stored and blind
  findings are browser proofs and carry the executed marker plus a screenshot.
- OpenAPI operations keep their declared method and import query parameters for
  non-GET methods.
- Report output sanitises ANSI escapes, control bytes, CSV formula prefixes and
  HTML text; console glyphs fall back to ASCII on non-UTF-8 streams.

### Validation

- `tests/test_1_2.py`: request fidelity (duplicate query/form names, second named
  parameter, second occurrence), context grammar (tag name, raw text, iframe,
  event handlers, JS comment/regex/eval), content-type gating, DOM vectors,
  OpenAPI methods, report sanitisation. Total unit tests: 42.
- **Google Firing Range reflected:** 49 pages, 47 points, 508 requests, 0 errors,
  42 findings — 40 `HIGH` confirmed in Chromium, 2 `MEDIUM`. The two are
  `/url/css_import` (stylesheet link) and `/url/object_data` (removed Flash
  plugin type); markup is rejected by the target and current Chromium does not
  execute those URL schemes.
- **Google Firing Range DOM:** 25 pages crawled, 20 rendered, 15 confirmed DOM
  findings across referrer, `location.href`, localStorage and `window.name`;
  0 errors.
- **Altoro Mutual:** one reflected query parameter confirmed `HIGH` by Chromium.
- **Local lab:** 27 findings, 27 replayed, 0 unstable — CRITICAL 9 / HIGH 16 /
  MEDIUM 2, 19 pages, 25 points, 853 requests, 164.4 s.
- Evidence and commands: `docs/REALWORLD.md`, raw JSON under `docs/evidence/`.
- Version `1.2.0`.

## 1.1.0 - 2026-10-26

CI contract and session history. The scanner core, execution proof, coverage and
OOB behaviour from 1.0.0 are unchanged.

### CI and reports

- SARIF 2.1.0 export (`--sarif FILE`) with one rule per kind/technique, stable
  partial fingerprints, physical locations, security severity metadata and
  invocation timestamps. Validated against the OASIS 2.1.0 schema.
- `--fail-on any|none|low|medium|high|critical` (default `any`). Exit 1 only
  when a finding at or above the chosen severity exists; exit 2 still means the
  target was unreachable. `--fail-on none` keeps the report but returns 0.
- HTML report now records the scan start time; JSON stats include replay,
  retest and fixed counts.

### Scope and history

- `--scope FILE`: host/path allowlist with `*` wildcards, comments and blank
  lines. The target must match, the crawler does not fetch outside the scope,
  and imported/JS/SPA/header/cookie/JSON points are filtered. Fails closed.
- `--db FILE`: SQLite sessions and findings with stable fingerprints.
  `--diff` compares the current findings with the previous session for the same
  target: new, still open and fixed.
- `--retest`: replays HTTP-replayable findings from the latest `--db` session
  without crawling, marking each one still open or fixed. OOB, stored, DOM and
  UNION extraction findings are skipped because they need more than a single
  replay request.
- `--scope` applies to retest and to simulated admin visits.

### Networking

- Adaptive rate limit: 429/503 responses double the interval up to 8x, honour
  numeric `Retry-After` (capped at 30s), and recover after 20 healthy
  responses. `--rps 0` remains unlimited.

### Tests and packaging

- `tests/test_p5.py`: identity, scope, fail policy, SQLite round-trip/diff,
  SARIF structure, rate limiter penalty/recovery. CI runs them on Windows and
  Linux.
- Version `1.1.0`.

**Acceptance:** full lab run with `--scope --db --diff --sarif --fail-on high`:
27 findings, 27 replayed, 0 unstable, CRITICAL 9 / HIGH 16 / MEDIUM 2,
19 pages, 25 points, 780 requests, 149.2s. Retest: 21 open, 0 fixed,
6 skipped (OOB/stored/DOM/UNION). SARIF schema valid. `--fail-on none` exit 0,
`--fail-on high` exit 1; clean target exit 0.

## 1.0.0 - 2026-10-26

Initial build. Windows 11, Python 3.10+.

### Scanner core

- Double baseline per injection point, token-level diff (`difflib`) and a
  measured noise floor (`3 x noise`); variable pages are re-sampled.
- Context-aware XSS: text, quoted/unquoted attributes, script, comment,
  encoded reflection downgrade.
- SQL injection: error fingerprints for seven DBMS, paired boolean probes,
  opt-in time based confirmation, UNION column count and echoed-column
  discovery, DBMS fingerprint.
- UNION extraction: version banner, plus `--dump` metadata (`current_user`,
  database, table names) inside markers. MySQL, PostgreSQL, MSSQL, SQLite;
  Oracle extraction only.
- Filter response: tamper variants (`/**/`, tab, case, URL/double encoding)
  and replay with the payload that actually worked.
- Injection points: query, forms, multipart body, JSON body, headers, cookies,
  mined JavaScript URLs, hidden GET parameters, OpenAPI imports, SPA XHR.

### Execution proof

- Playwright Chromium with an init script that hooks `alert/confirm/prompt`
  before page code. XSS is `CONFIRMED` only when the marker fires, otherwise
  downgraded; screenshots saved per confirmed finding.
- DOM XSS source-to-sink analysis (`location.*`, referrer, window.name,
  cookie -> innerHTML/write/eval/setTimeout) proven in the browser.
- Stored XSS: submit payload, revisit crawled pages, wait for the marker.
- Second-order SQLi: clean baseline, store `sv1'`, revisit, require a new
  database error line, replay the error page.

### Coverage

- SPA crawl: rendered pages, XHR/fetch GET URLs, dynamic anchors.
- OpenAPI JSON import (local file or URL, local `$ref`), query/body points.
- Multipart forms, hidden parameter discovery, JavaScript endpoint mining.

### Out of band (P4)

- Local callback listener (`127.0.0.1:8777`) with unique 16-hex tokens,
  bounded hit storage, timestamps, remote IP, UA, referer.
- Blind XSS: seed POST forms with callback scripts; `/t` proves fetch,
  `/e` proves browser execution, and `p`/Referer identifies the sink page.
  `--blind-visit` opens a simulated admin page in Chromium and screenshots it.
- SSRF: url-like parameters fetch the callback; redirects are not followed
  during the probe, so a 302 cannot fake a server-side request.
- `--oob`, `--oob-bind`, `--oob-wait` for local and tunneled deployments.
- Findings are correlated by token; blind execution and SSRF are
  `CONFIRMED`, fetch-only blind hits stay `MEDIUM`.

### Output and packaging

- Console, JSON, CSV and HTML reports; `data` rows for extracted values.
- Exit codes: 0 clean, 1 findings, 2 unreachable.
- Animated 24-bit splash, `run.bat` bootstrap, local vulnerable lab.
- MIT license, GitHub Actions CI for compile and CLI on Windows/Linux.
