# Changelog

All notable changes to SV1. Format follows Keep a Changelog.

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
