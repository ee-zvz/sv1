# Changelog

All notable changes to SV1. Format follows Keep a Changelog.

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
