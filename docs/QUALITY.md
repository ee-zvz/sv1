# SV1 1.4.0 - quality gates

Date: 2026-10-28

`1.4.0` is a feature release that includes the `1.3.5` request-boundary security
patch. The four scanners remain XSS, SQLi, blind XSS and SSRF; reflection-only
results remain `MEDIUM`. The new work closes the deferred P1 gaps: multipart
text points, OpenAPI path parameters, hidden/password opt-in, target-scoped
Playwright storage state, origin-aware form proof, and session-aware curl.

## What changed

| Area | 1.3.5 | 1.4.0 |
|---|---|---|
| Multipart | Parsed for a direct form only | Direct forms, XHR/fetch captures and HAR/raw imports; file parts skipped; browser proof and curl replay keep multipart |
| OpenAPI path | Path placeholders stayed fixed strings | `/users/{id}` is an injection point; requests, browser proof and curl build the concrete encoded path |
| Hidden/password fields | Preserved but never attackable | Preserved by default; `--hidden-fields` and `--password-fields` opt in to attacking them |
| Browser proof | Direct POST / fetch injection | Form proof navigates to the target origin first, then submits with target `Origin`, `Referer` and cookies |
| Same-target HTTP | Session material isolated by origin | Unsafe same-target requests also carry browser-like `Origin`/`Referer`; explicit header points win |
| Storage | CLI/imported cookies and live HTTP jar | `--storage-state` loads target-scoped Playwright cookies + localStorage; `--save-storage-state` exports only target state |
| Replay curl | Session cookies/headers | Session cookies/headers, concrete path URL, rebuilt JSON, multipart `-F` |
| 1.3.5 security fixes | Cross-origin body refusal, scope canonicalization, IPv6, SARIF status, build pins | All remain in force |

The `1.3.4` verification changes also remain in force: baseline-aware SQLi
replay, server-set cookie isolation, blind script-only demotion, stored-XSS
payload fallback, safe-method-only retries and the 47.0% coverage floor.

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
- `mypy`: pass, 38 source files.
- default tests: **165 discovered, 154 pass, 11 opt-in tests skipped**.
- Chromium integration: **10/10**.
- full lab: **38/38 verified**, 22 confirmed, 16 replayed, 0 unverified, 0 errors,
  23 pages, 32 points; 13 `CRITICAL`, 23 `HIGH`, 2 `MEDIUM`;
  21 XSS, 16 SQLI, 1 SSRF.
- default branch coverage: **50.3%** (5,349 statements); the CI floor remains
  **47.0%**.

Coverage of the paths touched here:

| Module | 1.4.0 |
|---|---:|
| `formdata.py` | 68.1% |
| `storage.py` | 72.4% |
| `scope.py` | 75.5% |
| `net.py` | 76.2% |
| `browser.py` | 16.1% (integration is separate) |
| `blind.py` | 85.9% |
| `stored.py` | 90.7% |
| `verify.py` | 46.0% |
| `secondorder.py` | 33.8% |
| `openapi.py` | 63.8% |
| `sqli.py` | 8.7% (full-lab path is separate) |

The default suite still does not launch Chromium; the two opt-in jobs remain
the release gate for browser execution and the 38-case lab.

## Public evidence

Fresh `1.4.0` public runs were collected after the release build. Both use
intentionally vulnerable demos, never a third-party production site.

| Target | Date | Result | Requests | Time |
|---|---|---|---:|---:|
| Google Firing Range, reflected attribute | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 12 | 18.4 s |
| Altoro Mutual search | 2026-10-28 | 1 `HIGH`/`CONFIRMED` XSS | 35 | 35.0 s |
| Google Firing Range, reflected attribute - dalfox 3.2.4 | 2026-10-27 | 1 high XSS | 26 | 6.2 s |
| Altoro search - dalfox 3.2.4 | 2026-10-27 | 1 high XSS | 23 | 12.0 s |

Both SV1 public runs had 0 errors. Altoro uses an expired TLS certificate, so
the deliberate `--insecure` option is required. Dalfox reports a parsed
reflection / DOM marker; SV1's evidence is an actual Chromium `alert` marker.
The full comparison is in [`COMPARISON.md`](COMPARISON.md).

Raw evidence: [`firing-range-1.4.0.json`](evidence/firing-range-1.4.0.json),
[`altoro-1.4.0.json`](evidence/altoro-1.4.0.json),
[`local-lab-1.4.0.json`](evidence/local-lab-1.4.0.json) and
[`local-lab-1.4.0.sarif`](evidence/local-lab-1.4.0.sarif).

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
- The 38-case lab includes the new proof paths `/csrf`, `/upload`, `/api/form`
  and `/api/path/{id}`. Restart the lab before repeating it because profile,
  guestbook and blind state live in memory.

## الخلاصة

`1.4.0` يوسّع دقة الطلب بدل توسيع عدد الثغرات: multipart يصير نقاطاً حقيقية،
ومعاملات مسار OpenAPI تُحقن فعلاً، والحقول المخفية وكلمات المرور تُحفظ ولا
تُهاجم إلا بعلم صريح، وحالة Playwright محصورة بالهدف، وcurl يعيد الطلب بجلسة
حية. المختبر الكامل 38/38، واختبارات Chromium 10/10، والتغطية 50.3% فوق أرضية
47.0%. الدليل العام الجديد من 1.4.0 على Firing Range وAltoro.
