# SV1 - real-world validation

Date: 2026-10-27
Build: `1.3.4`
Platform: Windows 11, Python 3.14.6, Playwright Chromium (headless)

This document records what SV1 actually found and proved outside the local lab.
Only public, intentionally vulnerable demos were used:

- **Google Firing Range** (`public-firing-range.appspot.com`) - reflected and
  DOM XSS test corpus.
- **Altoro Mutual** (`demo.testfire.net`) - a deliberately vulnerable banking
  demo with an expired certificate.

No third-party production application was scanned.

## 1.3.4 public evidence

Same-day, focused validation of the hardened build:

| Target | Command scope | Result | Requests | Wall time | Errors |
|---|---|---|---:|---:|---:|
| Firing Range, reflected attribute | one GET parameter, `--xss` | 1 `HIGH` / `CONFIRMED` XSS | 12 | 18.8 s | 0 |
| Altoro Mutual search | one GET parameter, `--xss --insecure` | 1 `HIGH` / `CONFIRMED` XSS | 35 | 46.5 s | 0 |

The proof strings in the JSON are execution markers, not guesses:

```text
executed in chromium: alert:sv10bf9a934
executed in chromium: alert:sv1bcccfe46
```

The Altoro certificate is expired. Public Altoro testing therefore uses the
explicit `--insecure` option; that is a property of the demo, not a TLS finding.

Raw evidence:

- [Firing Range 1.3.4 JSON](evidence/firing-range-1.3.4.json)
- [Altoro 1.3.4 JSON](evidence/altoro-1.3.4.json)
- [Firing Range dalfox 3.2.4](evidence/dalfox-firing-1.3.4.json)
- [Altoro dalfox 3.2.4](evidence/dalfox-altoro-1.3.4.json)
- [Full-lab 1.3.4 JSON](evidence/local-lab-1.3.4.json)
- [Full-lab 1.3.4 SARIF](evidence/local-lab-1.3.4.sarif)
- [Before/after and external comparison](COMPARISON.md)
- [Quality gates](QUALITY.md)

## Totals

Between 1.2.0 and 1.3.4, public validation is **6 runs, 78 pages, 51 injection
points, 607 HTTP requests, 61 findings, 61/61 verified, 0 errors**. Those runs
are the retained Firing Range reflected, Firing Range DOM, Altoro, public HAR,
and the two fresh 1.3.4 public scans. The older runs are from 1.2.0/1.2.1/1.3.1;
their evidence files are kept so the history is auditable.

The 1.3.4 full lab is separate from the public total: 31/31 verified, 17
confirmed, 14 replayed, 0 unstable, 21 pages, 29 points, 1012 requests, 240.2 s,
0 errors. Severity: 10 `CRITICAL`, 18 `HIGH`, 3 `MEDIUM`; 17 XSS, 13 SQLI,
1 SSRF. The lab was started fresh and used `--scope 127.0.0.1:8099`, so redirect
and browser guards were active.

## Commands

```powershell
python sv1.py -u "https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=test" `
  --xss --browser --timeout 25 --rps 2 --fail-on none --no-banner `
  -o docs/evidence/firing-range-1.3.4.json

python sv1.py -u "https://demo.testfire.net/search.jsp?query=test" `
  --insecure --browser --timeout 25 --rps 2 --fail-on none --no-banner `
  -o docs/evidence/altoro-1.3.4.json
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

الدليل العام الحالي هو فحصان حديثان على نسخة `1.3.4`: Firing Range و Altoro،
وكلاهما أعطى XSS عالي الخطورة مؤكداً بتنفيذ Chromium فعلي. الإجمالي التراكمي
للعينات العامة 61/61 بلا أخطاء. المقارنة مع dalfox وsqlmap على نفس الهدف
ونفس اليوم موجودة في `COMPARISON.md`، وتظهر أن SV1 أبطأ لكنه يثبت التنفيذ
ويغطي XSS وSQLi معاً.
