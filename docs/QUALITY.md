# SV1 1.3.4 - quality gates

Date: 2026-10-27

`1.3.4` is the verification-hardening patch that follows the `1.3.3` audit. It
does not add a vulnerability class. The four scanners remain XSS, SQLi, blind
XSS and SSRF; reflection-only results remain `MEDIUM`. The change is that a
finding must survive a cleaner replay before it keeps its severity.

## What changed

| Area | 1.3.3 | 1.3.4 |
|---|---|---|
| Browser cookies | Imported cookies blocked cross-target | **Any** cookie blocked cross-target, including a server-set cookie; fail closed if headers cannot be read |
| Blind XSS | Script-only callback could be `HIGH` and counted confirmed | Script-only is `MEDIUM`/`MEDIUM`; only `/e` execution is `HIGH`/`CONFIRMED` |
| SQLi error replay | Payload error accepted | Fresh clean baseline; an error line already in the baseline is rejected |
| SQLi boolean replay | Hot/cold pages differ | Hot must match baseline; cold must differ; noise floor applied |
| SQLi time replay | Fixed delay threshold | Fresh baseline-relative threshold |
| Second-order replay | One fetch, any DB error | Two stable fetches; scan-time clean baseline error is recorded and rejected |
| Stored XSS | First payload shape only | Three shapes per field; retries until one fires |
| Browser forms | URL-encoded only | Preserves `multipart/form-data` and `text/plain` enctypes |
| Transport retry | All methods retried | Only `GET`/`HEAD`/`OPTIONS`; no duplicate `POST` writes |
| `--timeout 0` | Traceback from `requests` | Clean CLI/client validation error |

The browser regression starts two loopback servers on different ports. The
target sets `sid=SERVER-SET`; its page loads an image from the second port. The
second server must receive no request. This is the exact server-set-cookie leak
that the imported-cookie test did not cover.

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
- `mypy`: pass, 36 source files.
- default tests: **123 discovered, 118 pass, 5 opt-in tests skipped**.
- Chromium integration: **4/4**.
- full lab: **31/31 verified**, 17 confirmed, 14 replayed, 0 unverified,
  0 errors, 21 pages, 29 points, 1012 requests, 240.2 s.
- full-lab severity: 10 `CRITICAL`, 18 `HIGH`, 3 `MEDIUM`;
  17 XSS, 13 SQLI, 1 SSRF.
- default branch coverage: **47.9%** (4,632 statements), up from 44.4% in
  `1.3.3`; CI floor raised from 43.5% to **47.0%**.

Coverage of the paths touched here:

| Module | 1.3.4 |
|---|---:|
| `blind.py` | 85.3% |
| `stored.py` | 89.9% |
| `verify.py` | 46.0% |
| `secondorder.py` | 29.5% |
| `browser.py` | 14.5% (integration is separate) |
| `net.py` | 51.0% |
| `sqli.py` | 8.7% (full-lab path is separate) |

The default suite still does not launch Chromium; the two opt-in jobs remain
the release gate for browser execution and the 31-case lab.

## Public evidence

All public tests use intentionally vulnerable demos, never a third-party site
without permission.

| Target | Date | Result | Requests | Time |
|---|---|---|---:|---:|
| Google Firing Range, reflected attribute | 2026-10-27 | 1 `HIGH`/`CONFIRMED` XSS | 12 | 18.8 s |
| Altoro Mutual search | 2026-10-27 | 1 `HIGH`/`CONFIRMED` XSS | 35 | 46.5 s |
| Google Firing Range, reflected attribute - dalfox 3.2.4 | 2026-10-27 | 1 high XSS | 26 | 6.2 s |
| Altoro search - dalfox 3.2.4 | 2026-10-27 | 1 high XSS | 23 | 12.0 s |

Both SV1 public runs had 0 errors. Altoro uses an expired TLS certificate, so
the deliberate `--insecure` option is required. Dalfox reports a parsed
reflection / DOM marker; SV1's evidence is an actual Chromium `alert` marker.
The full comparison is in [`COMPARISON.md`](COMPARISON.md).

## Scope guarantees

- A URL outside the allowlist returns `Response(status=0, error=...)` before a
  socket is opened.
- Every redirect hop is checked; non-HTTP(S) targets are refused.
- Imported headers and cookies are attached only to the target origin.
- Chromium's route guard now removes all cookies from cross-target requests,
  not only the names imported by the operator.
- A failed guard aborts a cross-target request rather than continuing it.
- `confirmed` means browser/OOB execution proof; `replayed` means HTTP replay;
  `verified` is the sum. A script-only blind callback is not confirmed.

## Notes

- `browser.py` coverage is low in the default suite because Playwright tests are
  opt-in. CI runs those tests separately.
- `sqli.py` is exercised end-to-end by the full lab; the focused unit suite only
  covers its simpler helpers.
- `--rps`, proxy, HAR, raw request, external JavaScript and OpenAPI paths are
  unchanged in this patch and keep their existing gates.

## الخلاصة

هذا الإصدار ليس إضافة عدد ثغرات؛ هو تشديد إثبات. أي نتيجة قديمة كانت تعتمد على
خطأ موجود أصلاً، أو اختلاف صفحة عشوائي، أو مجرد تحميل سكربت بلا تنفيذ، صارت
تُرفض أو تُخفض. الدليل العام: Firing Range و Altoro، وكلاهما أعطى XSS مؤكداً
بتنفيذ فعلي داخل Chromium. المختبر الكامل بقي 31/31، والفرق الوحيد في الوقت
والطلبات هو ثمن خط الأساس الإضافي. الفحص اليدوي والاختبارات الآلية في
`docs/evidence/`.
