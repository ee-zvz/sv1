# SV1 - real-world validation

Date: 2026-10-28
Build: `1.5.0`
Platform: Windows 11, Python 3.14.6, Playwright Chromium (headless)

This document records what SV1 actually found and proved outside the local lab.
Only public, intentionally vulnerable demos were used:

- **Google Firing Range** (`public-firing-range.appspot.com`) - reflected and
  DOM XSS test corpus.
- **Altoro Mutual** (`demo.testfire.net`) - a deliberately vulnerable banking
  demo with an expired certificate.

No third-party production application was scanned.

## 1.5.0 public evidence

Same-day, focused validation of the release build:

| Target | Command scope | Result | Requests | Wall time | Errors |
|---|---|---|---:|---:|---:|
| Firing Range, reflected attribute | one GET parameter, `--xss` | 1 `HIGH` / `CONFIRMED` XSS | 12 | 18.0 s | 0 |
| Altoro Mutual search | one GET parameter, `--xss --insecure` | 1 `HIGH` / `CONFIRMED` XSS | 11 | 13.6 s | 0 |

The 1.5.0 proof strings are execution markers, not guesses:

```text
executed in chromium: alert:sv19e86a12d
executed in chromium: alert:sv157c2495f
```

Raw 1.5.0 evidence: [`firing-range-1.5.0.json`](evidence/firing-range-1.5.0.json)
and [`altoro-1.5.0.json`](evidence/altoro-1.5.0.json).

## 1.4.0 public evidence

The prior release pair is retained as history:

| Target | Command scope | Result | Requests | Wall time | Errors |
|---|---|---|---:|---:|---:|
| Firing Range, reflected attribute | one GET parameter, `--xss` | 1 `HIGH` / `CONFIRMED` XSS | 12 | 18.4 s | 0 |
| Altoro Mutual search | one GET parameter, `--xss --insecure` | 1 `HIGH` / `CONFIRMED` XSS | 35 | 35.0 s | 0 |

The 1.4.0 proof strings:

```text
executed in chromium: alert:sv1376d4837
executed in chromium: alert:sv1b6a24f18
```

The detail line now agrees with the confidence field:

```text
execution confirmed in chromium (inside <tag> attribute ? (bare quoted)) | proof: alert fired
execution confirmed in chromium (in HTML text flow) | proof: alert fired
```

The Altoro certificate is expired. Public Altoro testing therefore uses the
explicit `--insecure` option; that is a property of the demo, not a TLS finding.

Raw evidence:

- [Firing Range 1.5.0 JSON](evidence/firing-range-1.5.0.json)
- [Altoro 1.5.0 JSON](evidence/altoro-1.5.0.json)
- [Firing Range 1.4.0 JSON](evidence/firing-range-1.4.0.json)
- [Altoro 1.4.0 JSON](evidence/altoro-1.4.0.json)
- [Firing Range dalfox 3.2.4](evidence/dalfox-firing-1.3.4.json)
- [Altoro dalfox 3.2.4](evidence/dalfox-altoro-1.3.4.json)
- [Full-lab 1.5.0 JSON](evidence/local-lab-1.5.0.json)
- [Full-lab 1.5.0 SARIF](evidence/local-lab-1.5.0.sarif)
- [Full-lab 1.4.0 JSON](evidence/local-lab-1.4.0.json)
- [Full-lab 1.4.0 SARIF](evidence/local-lab-1.4.0.sarif)
- [SQLite 1.5.0 comparison](evidence/sv1-real-1.5.0.json)
- [SQLite 1.4.0 comparison](evidence/sv1-real-1.4.0.json)
- [Before/after and external comparison](COMPARISON.md)
- [Quality gates](QUALITY.md)

## Totals

Between 1.2.0 and 1.5.0, public validation is **8 runs, 80 pages, 53 injection
points, 630 HTTP requests, 63 findings, 63/63 verified, 0 errors**. Those runs
are the retained Firing Range reflected, Firing Range DOM, Altoro, public HAR,
the two 1.4.0 public scans, and the two fresh 1.5.0 public scans. The older runs
are from 1.2.0/1.2.1/1.3.1/1.4.0; their evidence files are kept so the history
is auditable.

The 1.5.0 full lab is separate from the public total: 38/38 verified, 22
confirmed, 16 replayed, 0 unstable, 23 pages, 32 points, 1099 requests, 261.0 s,
0 errors. Severity: 13 `CRITICAL`, 23 `HIGH`, 2 `MEDIUM`; 21 XSS, 16 SQLI,
1 SSRF. The lab was started fresh and used `--scope 127.0.0.1:8099`, so redirect
and browser guards were active.

The separate SQLite target stayed at seven findings in `1.5.0`: 3 confirmed XSS,
2 SQLi, and 2 reflection-only `MEDIUM`; 221 requests, 49.1 s, 0 errors. It uses
the same command as `1.3.3`/`1.3.4`/`1.4.0`, which keeps the detection comparison
honest. Evidence: [`sv1-real-1.5.0.json`](evidence/sv1-real-1.5.0.json).

## Commands

```powershell
python sv1.py -u "https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=test" `
  --xss --browser --timeout 25 --rps 2 --fail-on none --no-banner `
  -o docs/evidence/firing-range-1.5.0.json

python sv1.py -u "https://demo.testfire.net/search.jsp?query=test" `
  --xss --insecure --browser --timeout 25 --rps 2 --fail-on none --no-banner `
  -o docs/evidence/altoro-1.5.0.json
```

The same-target external comparison (Dalfox 3.2.4 and sqlmap 1.10.10.27#dev)
and the exact local-lab command are in [`COMPARISON.md`](COMPARISON.md).

## Notes

- The two `MEDIUM` Firing Range cases in the retained 1.2.1 corpus are
  `/url/css_import` (a stylesheet link cannot execute `javascript:` in current
  Chromium) and `/url/object_data` (removed Flash type). They stay
  reflection-only rather than being inflated.
- The retained Firing Range DOM run was generated with `--no-verify`; its 15
  findings are execution-confirmed but did not go through HTTP replay.
- SV1's `confirmed` and `replayed` counters separate browser/OOB proof from an
  HTTP replay. A reflection alone is never `HIGH`.
- The local lab stores guestbook, blind and profile state in memory. Restart
  `lab/server.py` before repeating a full run; otherwise `/profile` already
  contains the second-order payload.

## الخلاصة

الدليل العام الحالي هو فحصان حديثان على نسخة `1.5.0`: Firing Range وAltoro،
وكلاهما أعطى XSS عالي الخطورة مؤكداً بتنفيذ Chromium فعلي. الإجمالي التراكمي
للعينات العامة 63/63 بلا أخطاء (8 تشغيلات). المختبر الكامل 38/38، وهدف SQLite
بقي سبع نتائج دون تراجع. المقارنة مع dalfox وsqlmap على نفس الهدف موجودة في
`COMPARISON.md`، وتظهر أن SV1 أبطأ لكنه يثبت التنفيذ ويغطي XSS وSQLi معاً.
