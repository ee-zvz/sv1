# SV1 1.5.0 — field audit and next position

Date: 2026-10-28

This page is the research that led to `1.5.0`. It compares the public feature
surface of the tools SV1 is measured against, separates features that improve
proof from features that only add breadth, and records what was shipped now
versus what stays on the roadmap.

## Verdict

SV1 should not try to out-feature Burp Suite, ZAP or Nuclei. Those products win
on breadth: hundreds of checks, authentication plugins, enterprise integrations
and a large extension ecosystem. A focused scanner cannot honestly claim the
number-one *general* scanner position today.

SV1 can lead a narrower category: **proof-first XSS, SQLi, blind XSS and SSRF**.
The position is built on four properties the current scanner already has:

1. a `HIGH` XSS finding needs a marker executed in Chromium, not a reflected
   string;
2. noisy pages are measured before a boolean or time decision is accepted;
3. every accepted finding is replayed and downgraded when it does not repeat;
4. session material, scope and redirects are enforced as boundaries, not as
   best-effort filters.

`1.5.0` closes the three practical gaps that were stopping that position from
being useful on real applications: login, discovery and restartability. It also
makes the output usable by a security team without a custom mapping layer.

## What the field ships today

The table below is a feature summary from the official public documentation,
not a benchmark and not a claim that any one tool is better at every task.

| Tool | Public capabilities relevant to SV1 |
|---|---|
| Burp Suite Professional / DAST | Crawling and auditing, browser-powered scanning, single-step credentials and recorded login sequences, API/GraphQL/WebSocket support, BChecks, extensions, SARIF/CI workflows |
| OWASP ZAP | Active/passive scanning, authentication and verification strategies, anti-CSRF handling, OAST callbacks, GraphQL/OpenAPI/WebSocket support, scripts, API and automation framework |
| dalfox v3 | Reflected/stored/DOM XSS, parameter analysis and mining, WAF fingerprinting and bypass tracking, custom payloads, JSON/JSONL/Markdown/SARIF, REST and MCP server |
| sqlmap | Very deep DBMS-specific SQLi detection and exploitation, tamper scripts, OOB channels, fingerprinting, dumping, OS/file access |
| Nuclei | Template-driven checks across HTTP and network protocols, a large community template set, CI-friendly output and integrations |

The gap is visible:

- **Authentication.** Burp and ZAP can authenticate before crawling. SV1 had
  storage state and HAR import, but no built-in login.
- **Restartability.** A long scan had no durable progress file. A browser crash
  or a closed terminal meant starting over.
- **Discovery.** The crawler followed links and forms, but ignored the two
  cheapest public maps: `robots.txt` and `sitemap.xml`.
- **Finding integration.** A finding carried severity and proof, but not a
  standard weakness class or a remediation line for a ticket or SARIF consumer.
- **Modern API surfaces.** GraphQL, WebSocket, YAML OpenAPI and browser-recorded
  login sequences remain behind SV1's stated scope or the current release.

## What 1.5.0 adds

### 1. Login before crawl

`--login URL` fetches the login page, finds a same-origin POST form with a
password field, preserves its hidden CSRF token and submits the supplied
credentials once. The resulting cookies stay in the live HTTP session and are
imported into Chromium before proof.

```powershell
$env:SV1_USERNAME = "operator"
$env:SV1_PASSWORD = "correct horse battery staple"
python sv1.py -u https://app.tld/dashboard --login https://app.tld/login `
  --login-check "Sign out" --crawl --xss --sqli
```

Design choices:

- `--login-check TEXT` is the reliable success test. Without it, a changed
  session cookie or a redirect is accepted but the console warns that the login
  is not fully confirmed.
- The login form's username field is not fuzzed by default, including the
  stored, blind and second-order form passes. Testing it would turn an
  authenticated scan into a credential-stuffing test and can lock the account.
  `--login-attack` opts in explicitly.
- The password is never printed and is not written to a checkpoint or history
  row. Prefer `SV1_PASSWORD` over the visible `--password` argument.
- A single POST form covers the common case. OAuth, SSO, JavaScript-only login
  and time-based MFA should use `--storage-state`, a HAR, or a recorded browser
  sequence. That is a documented boundary, not a silent fallback.

### 2. Resumable point scan

`--resume FILE` writes an atomic JSON checkpoint after every completed point.
The file contains the point set, completed keys, findings and scan options. A
second run with the same file skips completed points and restores findings that
already survived verification.

```powershell
python sv1.py -u https://app.tld --crawl --xss --sqli --resume scan.json
# interrupted?
python sv1.py -u https://app.tld --crawl --xss --sqli --resume scan.json
```

The checkpoint validates the target and the material scanner and point-discovery
options. It refuses to mix a checkpoint from another target, a different scanner
set, or an authenticated run with an anonymous one. The browser proof, DOM,
stored, blind and replay phases still run again because they depend on the
rendered page and live callbacks; the expensive point pass is the part that is
skipped. This is point-level resume, not a claim of a fully asynchronous or
distributed session.

The cookie jar is not serialized, but header points and curl commands may carry
cookies, so the checkpoint is session material, not a progress-only file. An
authenticated scan must be resumed with the same `--login` options so the next
run rebuilds the session before it sends pending payloads. It does not contain
the login password.

### 3. Public map discovery

`--sitemap` reads `robots.txt`, follows up to three same-origin sitemap
documents, and seeds the normal crawler with page URLs. Sitemap indexes are
followed one level. External hosts, binary assets and out-of-scope URLs are
never added.

```powershell
python sv1.py -u https://site.tld --crawl --sitemap --xss --sqli
```

The normal crawl depth, page cap, form parser and scope rules still apply. The
sitemap only changes the seed queue.

### 4. Finding class and remediation

Every XSS, SQLI and SSRF finding now carries:

- `cwe` — CWE-79, CWE-89 or CWE-918;
- `owasp` — A03:2021 Injection or A10:2021 SSRF;
- `remediation` — a short fix direction tied to the class.

The console shows one `class` line, the HTML report shows class and fix, CSV has
`cwe`, `owasp` and `remediation` columns, JSON includes all three, and SARIF puts
them in the rule and result properties. This is metadata, not a new finding and
not a new severity.

## What stays on the roadmap

The order is deliberate: a feature moves up only when it improves detection
quality, repeatability or the ability to reach an authenticated surface.

| Priority | Item | Why it matters | Effort |
|---|---|---|---|
| P0 | Recall comparison with dalfox | Measures what we miss, not what we add | Low |
| P1 | Browser-recorded login / OAuth + SSO | The single POST form is the common case; enterprise apps need a real sequence | High |
| P1 | Async HTTP engine | The current thread pool works, but long authenticated scans need better scheduling and cancellation | High |
| P1 | GraphQL and WebSocket points | APIs increasingly expose the same inputs outside HTML forms | Medium |
| P1 | OpenAPI YAML and auto-discovery | More specs, less operator setup | Low/Medium |
| P2 | Custom payload files and templates | Power users need to add a check without editing Python | Medium |
| P2 | OOB SQLi and NoSQL coverage | Extends the proof model to more backends and data models | Medium |
| P2 | Dynamic DOM taint instrumentation | Static source→sink pairing misses values assembled at runtime | High |
| P2 | API/MCP/plugin surface | Integrations matter for a team workflow, not for detection quality | Medium |
| P3 | Broad non-injection checks | This is where Burp/ZAP/Nuclei already win; not the niche SV1 should chase | Very high |

## What not to copy

- **Payload count as a scoreboard.** A longer wordlist is not a better finding.
  Execution proof and replay remain the rule.
- **A finding for every reflection.** Reflection-only stays `MEDIUM`; the
  scanner should not inflate a report to look busy.
- **Exploitation breadth.** SV1 is a scanner and proof tool, not a database
  takeover framework. sqlmap already owns that lane.
- **Breadth-first check count.** Adding hundreds of low-confidence checks would
  weaken the signal that makes SV1 useful.

## Evidence for this release

- `tests/test_1_5.py`: login form detection, CSRF preservation, login success
  and wrong-password rejection, CLI login, sitemap seeds, checkpoint restore and
  option/target mismatch, resume CLI, CWE/OWASP in CSV and SARIF.
- Full regression suite and full lab are recorded in [`QUALITY.md`](QUALITY.md)
  and [`CHANGELOG.md`](../CHANGELOG.md).
- Public evidence remains the prior deliberately vulnerable demos in
  [`REALWORLD.md`](REALWORLD.md); no third-party production target was used.

## Sources consulted

- Burp Scanner, authenticated scanning: https://portswigger.net/burp/documentation/scanner/authenticated-scanning
- OWASP ZAP features: https://www.zaproxy.org/docs/desktop/start/features/
- ZAP authentication helper: https://www.zaproxy.org/docs/desktop/addons/authentication-helper/
- dalfox README: https://github.com/hahwul/dalfox
- sqlmap README: https://github.com/sqlmapproject/sqlmap
- Nuclei README: https://github.com/projectdiscovery/nuclei

Research date: 2026-10-28.
