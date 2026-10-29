# SV1 1.6.1 - quality gates

Date: 2026-10-29

`1.6.1` repairs the proof gate for `1.6.0` Coverage 2.0. The full lab now
exercises `--path`, `--headers` and `--cookies` directly and requires a
`HIGH`/`CONFIRMED` execution finding for a path segment, a reflected custom
header and a reflected cookie. The three routes are `/catalog/42?ref=home`,
`/header-xss` and `/cookie-xss`; they use a 40-page crawl budget so the new
links do not displace the existing DOM proof.

`1.6.0` added Coverage 2.0: `--path` creates a replayable point for every URL
path segment; `--headers` and `--cookies` follow every discovered page; header
and cookie XSS can be proved in Chromium; a scope file can authorize a second
API/SPA origin without sending target credentials there; and one passive GET
names a known WAF. The four scanners remain XSS, SQLi, blind XSS and SSRF;
reflection-only results remain `MEDIUM`. Detection and proof rules are unchanged.

`1.5.1` was the session-material and lab-proof patch: checkpoint temporary files
use mode `0600`, `--resume` warns before a new file is committed,
storage/checkpoint/resume JSON are ignored, and the coverage floor is 51.0%.
The full lab proves login-protected `/private` and sitemap-only `/orphan`.
`1.5.0` added the operating layer around the detection engine: login, resume,
sitemap seeds and standard metadata.

## What changed

| Area | 1.4.0 | 1.5.0 |
|---|---|---|
| Authentication | Storage state / HAR import only | `--login` submits a same-origin POST form once, preserves hidden CSRF, imports the session into Chromium; `--login-check` verifies success |
| Login form fuzzing | No special rule | Username field removed from points and later form passes unless `--login-attack` is explicit |
| Restart | No durable progress | `--resume FILE` writes an atomic checkpoint per point, restores completed keys/findings and revalidates proof |
| Discovery | Links, forms, SPA, OpenAPI | `--sitemap` adds same-origin `robots.txt` / sitemap seeds, capped and scope-aware |
| Finding metadata | Severity, confidence, evidence | Adds CWE, OWASP 2021 and remediation to console, HTML, JSON, CSV (including `remediation`) and SARIF |
| Existing guarantees | Multipart, OpenAPI paths, hidden/password opt-in, storage state, origin-aware proof | All remain in force |

`1.5.1` adds atomic checkpoint temp files with mode `0600`, the `--resume`
session-material warning, session-artifact ignore rules, the 51.0% floor, and
login/sitemap proof for `/private` and `/orphan`. The `1.3.4` verification
changes also remain in force: baseline-aware SQLi replay, server-set cookie
isolation, blind script-only demotion, stored-XSS payload fallback and
safe-method-only retries.

`1.6.x` widens inputs without widening the proof claim:

| Area | 1.5.0 | 1.6.x |
|---|---|---|
| Inputs | target, forms, imports | adds path segments and route-wide headers/cookies |
| Browser proof | target/page XSS | adds header and cookie XSS, with cookie restoration |
| Discovery | same-origin | explicit `--scope` can add an API/SPA origin |
| WAF | none | one passive GET names a known edge |
| Standards | OWASP 2021 | OWASP Top 10:2025 |
| Release gate | 34-point lab | 43-point lab with path/header/cookie assertions |

## Gates

```powershell
python -m ruff check sv1.py sv1lib tests
python -m mypy
python -m unittest discover -s tests
$env:SV1_BROWSER_TESTS='1'; python -m unittest tests.test_browser_1_3
$env:SV1_LAB_TESTS='1'; $env:SV1_LAB_EVIDENCE='docs/evidence/local-lab-1.6.1'; python -m unittest tests.test_lab_1_3
```

Results on Windows 11 / Python 3.14.6:

- `ruff`: pass.
- `mypy`: pass, 43 source files.
- default tests: **203 discovered, 190 pass, 13 opt-in tests skipped**.
- Chromium integration: **12/12**.
- full lab: **43/43 verified**, 27 confirmed, 16 replayed, 0 unverified, 0 errors,
  28 pages, 150 points; 13 `CRITICAL`, 28 `HIGH`, 2 `MEDIUM`;
  26 XSS, 16 SQLI, 1 SSRF; 4201 requests, 655.7 s. The new carriers are
  `/catalog/{sv1_path_2}?ref=home`, `/header-xss` and `/cookie-xss`, all
  `HIGH`/`CONFIRMED`.
- default branch coverage: **52.6%** (6,075 statements); the CI floor is
  **51.0%**.

Coverage of the new and touched paths:

| Module | 1.6.1 |
|---|---:|
| `auth.py` | 73.3% |
| `checkpoint.py` | 77.6% |
| `discovery.py` | 65.8% |
| `models.py` | 95.1% |
| `sarif.py` | 93.1% |
| `formdata.py` | 68.1% |
| `storage.py` | 72.4% |
| `scope.py` | 75.5% |
| `net.py` | 77.4% |
| `browser.py` | 14.9% (integration is separate) |
| `coverage.py` | 85.2% |
| `waf.py` | 100.0% |
| `blind.py` | 85.9% |
| `stored.py` | 90.7% |
| `verify.py` | 46.0% |
| `secondorder.py` | 33.8% |
| `openapi.py` | 63.8% |
| `sqli.py` | 8.7% (full-lab path is separate) |

The default suite still does not launch Chromium; the two opt-in jobs remain
the release gate for browser execution and the 43-case lab.

## Public evidence

Fresh `1.6.1` public runs were collected after the proof-gate repair. All use
intentionally vulnerable demos, never a third-party production site.

| Target | Date | Result | Requests | Time |
|---|---|---|---:|---:|
| Google Firing Range, reflected - 1.6.1 | 2026-10-29 | 44 findings, 42 `HIGH`, 2 `MEDIUM`; 43/43 recall | 515 | 206.3 s |
| Google Firing Range, carriers - 1.6.1 | 2026-10-29 | 123 findings, 42 `HIGH`, 81 `MEDIUM`; no header/cookie reflection | 3088 | 1136.6 s |
| Google Firing Range, reflected attribute | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 12 | 18.0 s |
| Altoro Mutual search | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 11 | 13.6 s |
| Google Firing Range, reflected attribute - 1.4.0 | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 12 | 18.4 s |
| Altoro Mutual search - 1.4.0 | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 35 | 35.0 s |
| Google Firing Range, reflected attribute - dalfox 3.2.4 | 2026-10-27 | 1 high XSS | 26 | 6.2 s |
| Altoro search - dalfox 3.2.4 | 2026-10-27 | 1 high XSS | 23 | 12.0 s |

The SV1 public runs had 0 errors. Altoro uses an expired TLS certificate, so
the deliberate `--insecure` option is required. The same-day SQLite comparison
also stayed at seven findings (3 confirmed XSS, 2 SQLi, 2 reflection-only
`MEDIUM`) in 221 requests and 49.1 s, with zero false positives. Dalfox reports
a parsed reflection / DOM marker; SV1's evidence is an actual Chromium `alert`
marker.
The full comparison is in [`COMPARISON.md`](COMPARISON.md).

The page-level recall baseline is separate from these single-target runs. On
the Firing Range reflected section the index is **47 GET pages plus one POST
form**. Counting unique paths (not findings), SV1 1.5.1 reported 41 of the 43
GET pages in the union (95.3%; 39 execution proofs) and dalfox 3.2.4 reported
43/43 (100%; 39 parsed-DOM `V`). The earlier 42/44 table mixed the POST form
into the GET denominator; the corrected baseline is 41/43. SV1 1.5.2 closes the
two payload gaps (`data:text/javascript` for `<script src>` and a quote-free
bare-attribute handler) and reaches **43/43 GET pages with 41 execution
proofs**; dalfox remains 43/43 seen and 39 `V`.

SV1 1.6.1 was re-measured rather than inferred from unchanged detector code:
**49 pages crawled, 47 points, 515 requests, 0 errors, 206.3 s**;
**44 findings** (42 `HIGH`, 2 `MEDIUM`), **43/43 GET recall**, **41/43 GET
execution proofs**, and the POST form 1/1 `HIGH`. The two `MEDIUM` findings
(`css_import`, `object_data`) replay over HTTP. The one-request increase over
1.5.2 is the passive WAF probe; the proof boundary is unchanged. The form is
reported separately. The four pages neither tool reported are Flash, JSON,
plaintext and JSONP, outside the modern HTML scope. The full table, the single
scope-decision list and the roadmap are in [`RECALL.md`](RECALL.md); the
machine-readable calculation is
[`firing-range-reflected-recall-1.6.1.json`](evidence/firing-range-reflected-recall-1.6.1.json).

A separate 1.6.1 carrier run exercised **323 points** (47 query, 80 path,
147 header, 49 cookie) in **3088 requests, 0 errors, 1136.6 s**. The query set
stayed at 44 findings (42 `HIGH`, 2 `MEDIUM`). The 80 path points added **79
reflection-only `MEDIUM`** findings from the server's 404/500 error template;
all replayed over HTTP and none was promoted to `HIGH`. No header or cookie
reflection was found on this target. Total: **123 findings**, 42 `HIGH`, 81
`MEDIUM`, 0 unverified. Header/cookie execution proof is covered by the lab
gate, not inferred from this public target.

Raw evidence: [`firing-range-carriers-1.6.1.json`](evidence/firing-range-carriers-1.6.1.json),
[`firing-range-reflected-1.6.1.json`](evidence/firing-range-reflected-1.6.1.json),
[`firing-range-reflected-recall-1.6.1.json`](evidence/firing-range-reflected-recall-1.6.1.json),
[`local-lab-1.6.1.json`](evidence/local-lab-1.6.1.json),
[`local-lab-1.6.1.sarif`](evidence/local-lab-1.6.1.sarif),
[`firing-range-1.5.0.json`](evidence/firing-range-1.5.0.json),
[`altoro-1.5.0.json`](evidence/altoro-1.5.0.json),
[`local-lab-1.5.1.json`](evidence/local-lab-1.5.1.json) and
[`local-lab-1.5.1.sarif`](evidence/local-lab-1.5.1.sarif). The 1.5.0 and 1.4.0
JSON stays as history.

## Scope guarantees

- A URL outside the allowlist returns `Response(status=0, error=...)` before a
  socket is opened.
- Every redirect hop is checked; non-HTTP(S) targets are refused.
- A redirect that leaves the target origin cannot carry a body or files.
- Imported headers and cookies are attached only to the target origin.
- Scope paths are canonicalized before matching; IPv6 and explicit ports are
  parsed as host plus port.
- Chromium's route guard removes all cookies from cross-target requests, not
  only the names imported by the operator, and aborts a cross-target POST body.
- A failed guard aborts a cross-target request rather than continuing it.
- Storage state is filtered by target host and exact origin; expired and
  `Secure`-on-HTTP cookies are dropped, and foreign state is not exported.
- `confirmed` means browser/OOB execution proof; `replayed` means HTTP replay;
  `verified` is the sum. A script-only blind callback is not confirmed.

## Notes

- `browser.py` coverage is low in the default suite because Playwright tests are
  opt-in. CI runs those tests separately.
- `sqli.py` is exercised end-to-end by the full lab; the focused unit suite only
  covers its simpler helpers.
- The 43-case lab includes `/private` (login token + `sid` session, root link
  visible only after login), `/orphan` (robots/sitemap only, no HTML link),
  `/catalog/{id}?ref=home` (path segment), `/header-xss` (`X-Forwarded-For`)
  and `/cookie-xss` (`prefs`), plus the earlier `/csrf`, `/upload`, `/api/form`
  and `/api/path/{id}` paths. Restart the lab before repeating it because
  profile, guestbook and blind state live in memory. The crawl budget is
  `--pages 40`: the new links must stay after `/fetch` or `/external` DOM proof
  falls outside `BROWSER_MAX_PAGES=20`.
- With `--login`, the lab uses `127.0.0.2:8777` for OOB. Chromium cookies ignore
  ports, so the route guard would correctly block a same-host callback carrying
  `sid`; the test uses a different loopback host instead of weakening the guard.

## الخلاصة

`1.6.1` يصلح بوابة إثبات Coverage 2.0: المختبر الكامل يشغّل
`--path --headers --cookies` ويثبت XSS لمقطع المسار والهيدر والكوكي في
Chromium. `1.6.0` أضاف `--path` (كل segment نقطة قابلة لإعادة التشغيل)،
و`--headers`/`--cookies` على كل صفحة مكتشفة، و`--scope` لأصل API/SPA إضافي
بلا إرسال جلسة الهدف إليه، وبصمة WAF سلبية. لا تتغير قاعدة الإثبات:
الانعكاس وحده `MEDIUM`.
الاختبارات 203 مكتشفاً (190 ينجح، 13 اختيارياً)، Chromium 12/12، المختبر
الكامل 43/43 في 655.7 ثانية (28 صفحة، 150 نقطة)، والتغطية 52.6% فوق أرضية
51.0%. القياس العام الحالي: Firing Range 1.6.1، 44 نتيجة (42 `HIGH`،
2 `MEDIUM`) في 515 طلباً و206.3 ثانية، 43/43 استرجاع، 0 أخطاء. وفحص
الناقلين العام: 323 نقطة و3088 طلباً في 1136.6 ثانية، 123 نتيجة (42 `HIGH`،
81 `MEDIUM`)؛ 79 انعكاس path في قالب 404/500 بقي `MEDIUM`، ولا انعكاس
header/cookie على الهدف. Altoro يبقى دليل 1.5.0: نتيجة `HIGH` مؤكدة في
11 طلباً و13.6 ثانية.
