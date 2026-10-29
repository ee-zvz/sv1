# SV1 1.5.1 - quality gates

Date: 2026-10-28

`1.5.1` is a session-material and lab-proof patch. Checkpoint temporary files
are created with mode `0600`, `--resume` warns before a new file is committed,
storage/checkpoint/resume JSON are ignored, and the coverage floor is 51.0%.
The full lab now proves login-protected `/private` and sitemap-only `/orphan`.
`1.5.0` added the operating layer around the existing detection engine. The four
scanners remain XSS, SQLi, blind XSS and SSRF; reflection-only results remain
`MEDIUM`. Detection and proof rules are unchanged.

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

## Gates

```powershell
python -m ruff check sv1.py sv1lib tests
python -m mypy
python -m unittest discover -s tests
$env:SV1_BROWSER_TESTS='1'; python -m unittest tests.test_browser_1_3
$env:SV1_LAB_TESTS='1'; python -m unittest tests.test_lab_1_3
```

Results on Windows 11 / Python 3.14.6:

- `ruff`: pass.
- `mypy`: pass, 41 source files.
- default tests: **177 discovered, 166 pass, 11 opt-in tests skipped**.
- Chromium integration: **10/10**.
- full lab: **40/40 verified**, 24 confirmed, 16 replayed, 0 unverified, 0 errors,
  25 pages, 34 points; 13 `CRITICAL`, 25 `HIGH`, 2 `MEDIUM`;
  23 XSS, 16 SQLI, 1 SSRF; 1174 requests, 275.2 s.
- default branch coverage: **51.3%** (5,837 statements); the CI floor is
  **51.0%**.

Coverage of the new and touched paths:

| Module | 1.5.1 |
|---|---:|
| `auth.py` | 73.3% |
| `checkpoint.py` | 77.6% |
| `discovery.py` | 65.8% |
| `models.py` | 95.1% |
| `sarif.py` | 93.1% |
| `formdata.py` | 68.1% |
| `storage.py` | 72.4% |
| `scope.py` | 75.5% |
| `net.py` | 76.5% |
| `browser.py` | 16.1% (integration is separate) |
| `blind.py` | 85.9% |
| `stored.py` | 90.7% |
| `verify.py` | 46.0% |
| `secondorder.py` | 33.8% |
| `openapi.py` | 63.8% |
| `sqli.py` | 8.7% (full-lab path is separate) |

The default suite still does not launch Chromium; the two opt-in jobs remain
the release gate for browser execution and the 40-case lab.

## Public evidence

Fresh `1.5.0` public runs were collected after the release build. Both use
intentionally vulnerable demos, never a third-party production site.

| Target | Date | Result | Requests | Time |
|---|---|---|---:|---:|
| Google Firing Range, reflected attribute | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 12 | 18.0 s |
| Altoro Mutual search | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 11 | 13.6 s |
| Google Firing Range, reflected attribute - 1.4.0 | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 12 | 18.4 s |
| Altoro Mutual search - 1.4.0 | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 35 | 35.0 s |
| Google Firing Range, reflected attribute - dalfox 3.2.4 | 2026-10-27 | 1 high XSS | 26 | 6.2 s |
| Altoro search - dalfox 3.2.4 | 2026-10-27 | 1 high XSS | 23 | 12.0 s |

Both SV1 public runs had 0 errors. Altoro uses an expired TLS certificate, so
the deliberate `--insecure` option is required. The same-day SQLite comparison
also stayed at seven findings (3 confirmed XSS, 2 SQLi, 2 reflection-only
`MEDIUM`) in 221 requests and 49.1 s, with zero false positives. Dalfox reports
a parsed reflection / DOM marker; SV1's evidence is an actual Chromium `alert`
marker.
The full comparison is in [`COMPARISON.md`](COMPARISON.md).

The page-level recall baseline is separate from these single-target runs. On
the 48-page Firing Range reflected section, SV1 reported 42 pages (40 execution
proofs), or 87.5% of the index. Dalfox 3.2.4 reported 44 pages after a two-pass
run (40 parsed-DOM `V`), so the union is 44: SV1 42/44 = 95.5%, dalfox 44/44 =
100%. The four pages neither tool reported are Flash, JSON, plaintext and JSONP,
outside the modern HTML scope. The full table, the missed list and the roadmap
are in [`RECALL.md`](RECALL.md).

Raw evidence: [`firing-range-1.5.0.json`](evidence/firing-range-1.5.0.json),
[`altoro-1.5.0.json`](evidence/altoro-1.5.0.json),
[`local-lab-1.5.1.json`](evidence/local-lab-1.5.1.json),
[`local-lab-1.5.1.sarif`](evidence/local-lab-1.5.1.sarif),
[`local-lab-1.5.0.json`](evidence/local-lab-1.5.0.json) and
[`local-lab-1.5.0.sarif`](evidence/local-lab-1.5.0.sarif). The 1.4.0 public JSON
stays as history.

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
- The 40-case lab includes `/private` (login token + `sid` session, root link
  visible only after login) and `/orphan` (robots/sitemap only, no HTML link),
  plus the earlier `/csrf`, `/upload`, `/api/form` and `/api/path/{id}` paths.
  Restart the lab before repeating it because profile, guestbook and blind state
  live in memory.
- With `--login`, the lab uses `127.0.0.2:8777` for OOB. Chromium cookies ignore
  ports, so the route guard would correctly block a same-host callback carrying
  `sid`; the test uses a different loopback host instead of weakening the guard.

## الخلاصة

`1.5.1` يصلّب ملفات checkpoint بمود `0600`، ويحذر أن ملف `--resume` مادة جلسة،
ويستثني ملفات الجلسة من Git، ويرفع أرضية التغطية إلى 51.0%. يضيف المختبر
الكامل `/private` المحمي بالدخول و`/orphan` القادم من sitemap. لا تتغير قاعدة
الإثبات: الانعكاس وحده `MEDIUM`.
الاختبارات 177 مكتشفاً (166 ينجح، 11 اختيارياً)، Chromium 10/10، المختبر
الكامل 40/40 في 275.2 ثانية، والتغطية 51.3% فوق أرضية 51.0%. الدليل العام من
1.5.0 باقٍ: Firing Range نتيجة `HIGH` مؤكدة في 12 طلباً و18.0 ثانية، وAltoro
نتيجة `HIGH` مؤكدة في 11 طلباً و13.6 ثانية، بلا أخطاء.
