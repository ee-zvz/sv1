# Changelog

All notable changes to SV1. Format follows Keep a Changelog.

## 1.5.0 - 2026-10-28

Operating-layer release. Detection scope is unchanged: XSS, SQLi, blind XSS and
SSRF; reflection-only remains `MEDIUM`. The release closes the gaps that stopped
the proof-first model from reaching real applications: login, discovery, restart
and standard finding metadata. The field audit is in
[`docs/IMPROVEMENTS.md`](docs/IMPROVEMENTS.md).

### Added

- `--login [URL]` bootstraps a scan through a same-origin POST form. It finds
  the password form, preserves hidden CSRF fields, sends the credentials once and
  keeps the resulting cookies in the live HTTP session. Chromium imports that
  session before execution proof. `--login-check TEXT` requires a post-login
  marker; `--login-user-field` / `--login-pass-field` override field detection;
  `--username` / `--password` fall back to `SV1_USERNAME` / `SV1_PASSWORD`.
  A failed login exits `2` instead of silently scanning anonymously.
- The login form's username field is removed from the point set and from the
  stored/blind/second-order form passes unless `--login-attack` is explicit, so
  an authenticated scan does not become a credential-stuffing test.
- `--resume FILE` writes an atomic JSON checkpoint after every completed point.
  A second run validates the target and material scan/point options, skips
  completed point keys and restores prior findings; browser proof is revalidated
  in the new session. The browser, DOM, stored, blind and replay phases still run
  because they depend on the live page and callbacks. Cookies are not stored, and
  an authenticated checkpoint refuses to resume against an anonymous run. This is
  point-level resume, not the deferred async engine.
- `--sitemap` discovers same-origin seeds from `robots.txt` and up to three
  sitemap documents, following one sitemap-index hop. External hosts, binary
  assets and out-of-scope URLs are refused; the normal page cap, depth and form
  parser still apply.
- Every XSS, SQLI and SSRF finding now carries `cwe`, `owasp` and `remediation`.
  XSS maps to CWE-79 / A03:2021, SQLi to CWE-89 / A03:2021 and SSRF to CWE-918 /
  A10:2021. The console, HTML report, JSON, CSV and SARIF expose the metadata.
- `tests/test_1_5.py`: 12 regressions for login form detection and CSRF
  preservation, wrong-password rejection, text-field password rejection, CLI
  login, sitemap filtering, checkpoint round-trip and mismatch refusal, resume
  CLI, and CWE/OWASP/remediation output in CSV and SARIF.

### Security

- Login credentials are never printed and are not written to a finding, history
  row or checkpoint. `SV1_PASSWORD` is the documented form because argv is
  visible in the process list.
- Login actions must be same-origin HTTP(S). The normal Origin/Referer request
  policy applies, and the login form is not attacked unless explicitly requested.
- A checkpoint is sensitive local state: it can contain imported session headers,
  cookies and curl reproduction commands. It does not contain the login password.
- Sitemap discovery is same-origin, size-capped, page-capped and scope-aware;
  it adds seeds, not permissions.

### Limits

- The async `httpx` engine remains deferred. The current engine is a bounded
  thread pool with adaptive rate limiting.
- `--login` covers the single-form case. OAuth, SSO, JavaScript-only login and
  time-based MFA need `--storage-state`, a HAR, or a browser-recorded sequence.
- `--resume` does not checkpoint the browser/DOM, stored, blind or replay phases;
  these rerun after a restart.
- Gzipped sitemap archives are not unpacked.

### Tests

- Default suite: **177 discovered, 166 pass, 11 opt-in skips**.
- Branch coverage: **51.3%** (5,835 statements) against the 47.0% floor;
  `ruff` clean, `mypy` clean on 41 source files.
- Chromium integration: **10/10**.
- Full lab: **38/38 verified**, 22 confirmed, 16 replayed, 0 unverified,
  0 errors, 23 pages, 32 points, 1099 requests, 261.0 s. Severity is
  13 `CRITICAL`, 23 `HIGH`, 2 `MEDIUM`; 21 XSS, 16 SQLI, 1 SSRF.
  Evidence: `docs/evidence/local-lab-1.5.0.json` and
  `local-lab-1.5.0.sarif`.
- Public 1.5.0: Firing Range reflected attribute, 1 `HIGH`/`CONFIRMED` XSS,
  12 requests, 18.0 s; Altoro Mutual search, 1 `HIGH`/`CONFIRMED` XSS,
  11 requests, 13.6 s; both 0 errors. Evidence:
  `docs/evidence/firing-range-1.5.0.json` and `altoro-1.5.0.json`.
- SQLite comparison: same seven findings (3 confirmed XSS, 2 SQLi, 2
  reflection-only `MEDIUM`), 221 requests, 49.1 s, 0 false positives. Evidence:
  `docs/evidence/sv1-real-1.5.0.json`.

## 1.4.0 - 2026-10-28

Feature release that closes the deferred P1 gaps and includes the `1.3.5`
request-boundary security patch. Detection scope is unchanged: XSS, SQLi,
blind XSS and SSRF; reflection-only stays `MEDIUM`.

### Added

- Multipart `multipart/form-data` support end to end. Direct forms, XHR/fetch
  bodies captured by `--spa`, and HAR/raw request imports now become text-field
  injection points. File parts are skipped, not guessed at. Requests and
  browser proof keep the multipart encoding, and curl replay uses `-F`.
- OpenAPI **path** parameters are real injection points. `/users/{id}` keeps
  the placeholder in the finding so the path is visible, while every request,
  browser proof and curl command builds and encodes the selected route value.
- `--hidden-fields` and `--password-fields` opt in to hidden and password form
  inputs. Both values are always preserved in the form mapping (CSRF tokens and
  login forms keep working), but neither is attacked by default.
- `--storage-state FILE` loads target cookies into the HTTP session and target
  cookies + localStorage into Chromium. `--save-storage-state FILE` exports the
  post-scan browser state. Both paths are target-scoped: cookies must match the
  target host, localStorage must match the exact origin, expired and secure
  cookies are filtered, and another host's state is never exported.
- Unsafe same-target HTTP requests now carry browser-like `Origin` and
  `Referer` headers. Browser form proof first navigates to the target origin,
  so a CSRF middleware sees the same origin and the preserved hidden token.
  JSON and multipart form proof use the same origin-preserving path.
- Finding curl commands use the live session: target-scoped cookies and session
  headers are included, path values are concrete, JSON bodies are rebuilt from
  the original document, and multipart points stay multipart.

### Fixed

- Confirmed XSS detail no longer says `execution not yet proven` after Chromium
  has actually fired the marker. The proof line and confidence now agree.
- SARIF invocation times now use wall-clock timestamps instead of passing a
  monotonic counter to `gmtime`, which produced 1970 evidence dates.

### Security

- The `1.3.5` fixes remain in force: cross-origin redirects cannot carry a
  body, Chromium aborts a cross-target request with a body, scope paths and
  IPv6 are canonicalized, SARIF reports real execution status, and build
  dependencies are OSV-clean.
- Storage-state import is a boundary, not a cookie dump. It rejects oversized
  or malformed files, filters every cookie and origin to the target, and never
  writes third-party state. A `Secure` cookie is not copied into a plain-HTTP
  session.
- Preserving hidden and password inputs changes fidelity, not attack surface:
  the default point set is still visible text inputs only. Opting in is explicit
  because injecting into a CSRF token or password field can invalidate a form
  or lock an account.

### Tests

- `tests/test_1_4.py`: 15 unit/CLI regressions for form policy, multipart
  parsing, SPA/HAR capture, OpenAPI path points, Origin/Referer, session curl,
  storage-state filtering and the new CLI surface.
- `tests/test_browser_1_3.py`: 10/10 Chromium integration, adding multipart XHR
  capture, multipart proof with Origin, hidden-token CSRF proof and
  localStorage import/export.
- Default suite: **165 discovered, 154 pass, 11 opt-in skips**.
- Full lab: **38/38 verified**, 22 confirmed, 16 replayed, 0 unverified,
  0 errors, 23 pages, 32 points, 1099 requests, 262.8 s. Severity is 13
  `CRITICAL`, 23 `HIGH`, 2 `MEDIUM`; 21 XSS, 16 SQLI, 1 SSRF. New lab proof:
  `/csrf` (Origin + hidden token), `/upload` and `/api/form` (multipart), and
  `/api/path/{id}` (OpenAPI path).
- Branch coverage: **50.3%** (5,349 statements); the 47.0% floor is unchanged.
- Public 1.4.0 evidence: Firing Range reflected attribute (1 `HIGH` confirmed,
  12 requests, 18.4 s) and Altoro search (1 `HIGH` confirmed, 35 requests,
  35.0 s), both with 0 errors. The SQLite comparison stayed at seven findings
  (3 confirmed XSS, 2 SQLi, 2 reflection-only `MEDIUM`; 221 requests, 49.2 s).

## 1.3.5 - 2026-10-27

Security patch after the 1.3.4 audit. Detection scope is unchanged: XSS, SQLi,
blind XSS and SSRF; reflection-only stays `MEDIUM`.

### Security

- A cross-origin redirect can no longer copy a request body. `307`/`308` keep
  the method and body by design, and `301`/`302` preserve a non-POST body such
  as `PUT`; when the next hop leaves the target origin, SV1 now refuses the hop
  before the body is sent. A bodyless cross-origin `GET`/`HEAD` hop and a
  `301`/`302` POST-to-GET hop remain allowed.
- Chromium applies the same body rule. A cross-target form post or redirect
  that still carries `post_data` is aborted by the route guard. If the body
  cannot be inspected, the guard fails closed.
- Scope matching canonicalizes dot segments, duplicate slashes, backslashes
  and percent encoding before comparing a path. `Rule("*", "host", "/app/*")`
  no longer matches `/app/../admin`, `%2e%2e`, `%252e%252e` or encoded
  backslash variants. URL rules without an explicit port use the scheme
  default; bare hosts keep the documented any-port meaning. Host matching also
  decodes percent-escaped hosts, strips a trailing dot and applies IDNA.
- IPv6 scope rules now parse and match correctly. `[::1]:8099` is a bracketed
  host plus a port, not a hostname containing a colon; malformed brackets,
  ports and authorities fail the scope file closed.
- Cookies acquired by the HTTP client during login or crawling are imported
  into Chromium before proof. The browser previously received only the
  CLI/imported snapshot, so a server-set session produced a `403` during the
  browser replay. Imported cookies are anchored to the target origin and only
  target-host cookies are selected; the existing cross-port guard still runs.
- Build-time `setuptools` pin raised from `78.1.0` to `84.2.1`; the `78.1.0`
  pin had five OSV advisories, including HIGH `CVE-2025-47273`. Development
  `coverage` pin lowered from `7.17.0` to `7.16.2`, the newest release that
  still supports Python 3.10.
- SARIF `executionSuccessful` now reflects the scan error count instead of
  always claiming success, and the run carries `errorCount` for CI consumers.
- CI uses `actions/checkout@v7.0.1`, `actions/setup-python@v7.1.0`, a pip cache
  keyed by both requirement files, and a read-only repository token.

### Tests

- `tests/test_audit_1_3_5.py`: 20 regressions for redirect bodies,
  Chromium body isolation, scope canonicalization, IPv6, host encoding and
  cookie import.
- `tests/test_browser_1_3.py`: 6/6 Chromium integration, including a
  server-set cookie that must reach Chromium and a cross-target form body that
  must never leave it.
- Default suite: 146 discovered, 139 pass, 7 opt-in skips.
- Full lab: 31/31 verified, 17 confirmed, 14 replayed, 0 unverified, 0 errors,
  21 pages, 29 points; severity 10 `CRITICAL`, 18 `HIGH`, 3 `MEDIUM`.
- Branch coverage: 49.0% against the 47.0% floor.

## 1.3.4 - 2026-10-27

Verification hardening after the 1.3.3 audit. Detection scope is unchanged:
XSS, SQLi, blind XSS and SSRF; reflection-only stays `MEDIUM`. The same lab
findings must survive stricter replay, not merely the same payload count.

### Security

- Chromium now rejects every cross-target request that carries a `Cookie`
  header, including a cookie the target set during the scan. Chromium scopes
  cookies by host, not port, so an image on another loopback port could
  otherwise receive a server-set session. The route guard fails closed when
  headers cannot be inspected, and a two-port server-set-cookie regression test
  covers the exact leak.
- Blind XSS script-only callbacks are `MEDIUM`/`MEDIUM` and are not counted as
  confirmed. Only a `/e` execution hit is `HIGH`/`CONFIRMED`; the console's
  `confirmed` counter follows the finding confidence.
- SQLi replay now captures a fresh clean baseline for error, boolean and time
  techniques. An error line present in the baseline, a false branch equal to the
  baseline, or a delay below the baseline-relative threshold no longer
  reproduces. Second-order replay uses two fetches of the sink, rejects the
  clean-baseline error recorded at scan time, and requires a stable new error.
- The scanner never retries `POST` after a transport failure; only
  `GET`/`HEAD`/`OPTIONS` are repeated. This prevents duplicate writes from a
  connection reset.
- `--timeout 0` is rejected by the CLI and `net.Client` with a clean validation
  error instead of a `requests` traceback. Origins used for cookie scope strip
  embedded credentials; IPv6 hosts remain bracketed.

### Changed

- Stored XSS tries three payload shapes per field (`svg`, `script`, `img`) and
  keeps walking revisit pages until one executes. Browser form submission
  preserves `multipart/form-data` and `text/plain` enctypes.
- `--insecure` suppresses the expected urllib3 warning after the operator has
  explicitly disabled certificate validation.

### Tests

- Default suite: 123 discovered, 118 pass, 5 opt-in tests skipped.
- Chromium integration: 4/4.
- Full lab: 31/31 verified (17 confirmed, 14 replayed), 0 unstable, 0 errors;
  10 `CRITICAL` / 18 `HIGH` / 3 `MEDIUM`, 21 pages, 29 points, 1012 requests,
  240.2 s. Evidence: `docs/evidence/local-lab-1.3.4.json`.
- Branch coverage: 47.9% over `sv1.py` and `sv1lib`; the CI floor is raised from
  43.5% to 47.0%.
- Public demos on 2026-10-27: Google Firing Range reflected attribute, 1
  `HIGH`/`CONFIRMED` XSS (12 requests, 18.8 s); Altoro Mutual search, 1
  `HIGH`/`CONFIRMED` XSS (35 requests, 46.5 s). Both 0 errors.
- Real SQLite comparison target: 7 findings (3 XSS confirmed, 2 SQLi, 2
  reflection-only `MEDIUM`), 221 requests, 49.0 s, 0 errors.

## 1.3.3 - 2026-10-27

Scope and identity hardening. The vulnerability scope is unchanged: XSS, SQLi,
blind XSS and SSRF; reflection-only stays `MEDIUM`.

### Security

- `net.Client` now walks redirects itself, one hop at a time. Without
  `--scope`, only the target origin is followed, plus a plain-HTTP to HTTPS
  upgrade on the same host and standard ports. A scope file may authorise
  another host, but the hop is still checked before a request is sent.
  `config.MAX_REDIRECTS` is enforced, and `file:`, `gopher:` and other
  non-HTTP(S) redirect targets are refused.
- Imported session headers (`Authorization`, `-H`, ...) and cookies are sent
  only to the target origin. A cross-origin hop that `--scope` permits carries
  no session material. The cookie jar is host-scoped, and explicit cookie
  points override a jar value instead of producing `sid=abc; sid=payload`.
- Chromium no longer receives session headers through `extra_http_headers`.
  A route guard adds them per request only for the target origin, so a
  third-party script, image or iframe cannot inherit the operator's session.
  Top-level browser navigations obey the same scope as the HTTP client;
  cross-origin subresources may still load without session headers. Chromium's
  cookie jar ignores ports, so a cross-origin request that would carry an
  imported cookie is cancelled instead of leaking it.
- An out-of-scope URL is refused before any bytes are sent, not filtered after
  the response arrives.

### Fixed

- Form actions keep their query string. `/search?lang=en` is now scanned as
  that endpoint instead of `/search`.
- SSRF probes rebuild nested JSON bodies from the original template, so a
  payload in `items[1].id` no longer erases `user.name` or `items[0].id`.
- Stored-XSS markers are unique per run. A token left in the database by an
  earlier scan can no longer be mistaken for a fresh execution.
- `InjectionPoint.key()` includes a hash of the raw/JSON body and its content
  type. Two templates on the same URL and parameter are distinct points.
- `ScanStats` separates `confirmed` (browser/OOB proof) from `replayed` (HTTP
  replay). `verified` remains their sum for compatibility; JSON, history and
  the console summary expose both counters.

### Tests and CI

- `tests/test_1_3_3.py`: 22 tests covering default scope, scoped redirects,
  header/cookie isolation, redirect caps and schemes, cookie override,
  browser origin scoping, form-action queries, body identity, SSRF nested
  bodies, stored tokens and split proof counters.
- Coverage gate: `[tool.coverage.report] fail_under = 43.5`. Default suite
  branch coverage is 44.4% (4,554 statements).
- Default suite: 110 discovered, 106 pass, 4 opt-in tests skipped.

### Validation

- `python -m ruff check .`: all checks passed.
- `python -m mypy`: no issues in 36 source files.
- Chromium integration tests: XHR body capture, origin-scoped session headers,
  and imported-cookie isolation across ports all pass.
- Full lab on Windows 11 / Python 3.14.6: 31/31 verified (17 confirmed,
  14 replayed), 0 unstable, 10 `CRITICAL` / 18 `HIGH` / 3 `MEDIUM`, 21 pages,
  29 points, 966 requests, 184.8 s, 0 errors. The run uses
  `--scope 127.0.0.1:8099` and therefore exercises the new redirect and browser
  guards. Evidence: `docs/evidence/local-lab-1.3.3.json`.

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
