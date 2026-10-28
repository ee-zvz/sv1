# SV1 1.5.0 - before/after and external comparison

This comparison was measured on `1.5.0`. The `1.3.3` / `1.3.4` / `1.4.0` rows
are kept as history; `1.3.5` is included in `1.4.0` and adds request-boundary
hardening. `1.5.0` adds login, resume, sitemap and finding metadata without
changing the detection scope, so the separate SQLite benchmark still stays at
seven findings and the 38-case lab remains the release gate.

Date: 2026-10-28

This page fixes the comparison to one day and one target process. It is not a
scoreboard. Dalfox is an XSS scanner; sqlmap is a SQL injection engine; SV1
crawls, scans both classes, proves browser execution and also records
reflection-only notes. The table keeps those scope differences visible.

The release gate is the 38-case local lab. The external comparison uses a
separate SQLite target because the lab emulates SQL errors and is not a valid
sqlmap benchmark. Public runs use Google Firing Range and Altoro Mutual, both
intentionally vulnerable demos.

## 1. Same target, 1.3.3 vs 1.3.4 vs 1.4.0 vs 1.5.0

Target: [`lab/real_sql.py`](../lab/real_sql.py), `http://127.0.0.1:8100/`,
7 pages, 6 injection points, SQLite in memory. Same command, fresh process for
each version.

| Build | Findings | XSS confirmed | SQLi | Reflection-only `MEDIUM` | False positives | HTTP requests | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|
| SV1 1.3.3 | 7 | **3** | **2** | 2 | 0 | 213 | 47.4 s |
| SV1 1.3.4 | 7 | **3** | **2** | 2 | 0 | 221 | 49.0 s |
| SV1 1.4.0 | 7 | **3** | **2** | 2 | 0 | 221 | 49.2 s |
| SV1 1.5.0 | 7 | **3** | **2** | 2 | 0 | 221 | 49.1 s |

Result: same seven findings, no lost detection and no new false positive. The
1.3.4 pass sent 8 more requests and took 1.6 s longer because it measured a fresh
clean baseline before replaying the SQLi evidence. `1.4.0` and `1.5.0` keep the
stronger proof at the same request count. Raw JSON:
[`sv1-real-1.3.3.json`](evidence/sv1-real-1.3.3.json),
[`sv1-real-1.3.4.json`](evidence/sv1-real-1.3.4.json),
[`sv1-real-1.4.0.json`](evidence/sv1-real-1.4.0.json) and
[`sv1-real-1.5.0.json`](evidence/sv1-real-1.5.0.json).

Full-lab comparison on the same day:

| Build | Verified | Confirmed | Replayed | Requests | Wall time | Errors |
|---|---:|---:|---:|---:|---:|---:|
| SV1 1.3.3 | 31/31 | 17 | 14 | 966 | 184.8 s | 0 |
| SV1 1.3.4 | 31/31 | 17 | 14 | 1012 | 240.2 s | 0 |
| SV1 1.4.0 | 38/38 | 22 | 16 | 1099 | 262.8 s | 0 |
| SV1 1.5.0 | 38/38 | 22 | 16 | 1099 | 261.0 s | 0 |

The 1.5.0 lab run keeps the same 38 findings and proof split; the new login,
resume, sitemap and metadata paths are covered by `tests/test_1_5.py` rather than
new lab endpoints. The 1.4.0 lab run adds seven findings across four new paths: `/csrf`
(hidden-token + Origin; XSS + SQLi), `/upload` (multipart; XSS), `/api/form`
(multipart; XSS + SQLi), and `/api/path/{id}` (OpenAPI path; XSS + SQLi). The
previously reflected `/api/xhr` is promoted to `HIGH` but is not an additional
finding. Severity is now 13 `CRITICAL`, 23 `HIGH`, 2 `MEDIUM`. Evidence:
[`local-lab-1.3.3.json`](evidence/local-lab-1.3.3.json),
[`local-lab-1.3.4.json`](evidence/local-lab-1.3.4.json),
[`local-lab-1.4.0.json`](evidence/local-lab-1.4.0.json) and
[`local-lab-1.5.0.json`](evidence/local-lab-1.5.0.json).

## 2. External tools, same SQLite target

Same target process, same day, fresh session per tool. Dalfox and sqlmap were
downloaded for this run; Dalfox 3.2.4 and sqlmap 1.10.10.27#dev are the exact
versions below.

| Tool | Scope | Confirmed XSS | Confirmed SQLi | Reflection-only | False positives | HTTP requests | Wall time |
|---|---|---:|---:|---:|---:|---:|---:|
| SV1 1.3.4 | crawl 7 pages, 6 points, XSS + SQLi + dump | **3** | **2** | 2 `MEDIUM` | 0 | 221 | 49.0 s |
| SV1 1.4.0 | crawl 7 pages, 6 points, XSS + SQLi + dump | **3** | **2** | 2 `MEDIUM` | 0 | 221 | 49.2 s |
| SV1 1.5.0 | crawl 7 pages, 6 points, XSS + SQLi + dump | **3** | **2** | 2 `MEDIUM` | 0 | 221 | 49.1 s |
| dalfox 3.2.4 | 4 XSS URLs, no mining | **3** | n/a | 0 | 0 | 598 | 29.9 s |
| sqlmap 1.10.10.27#dev | 2 SQLi URLs, level 3 / risk 2 / BEUST | n/a | **2** | 0 | 0 | 107 | 9.4 s |

Dalfox and sqlmap do their narrow jobs with fewer requests and less time. SV1
finds the same five exploitable issues plus two deliberate reflection-only
`MEDIUM` notes, and its XSS proof is an actual Chromium `alert`, not only a
parsed sink. The comparison does not hide that cost.

The Dalfox Windows archive was checked against the published SHA-256
`28100d9355a1c767facd571a180d08b87d4de61167b3db99d56e4d8a6601d69a` before it
was executed. sqlmap was a fresh shallow clone reporting `1.10.10.27#dev`.

Raw evidence: [`dalfox-real-1.3.4.json`](evidence/dalfox-real-1.3.4.json),
[`sqlmap-item-1.3.4.txt`](evidence/sqlmap-item-1.3.4.txt),
[`sqlmap-user-1.3.4.txt`](evidence/sqlmap-user-1.3.4.txt).

## 3. Public intentionally vulnerable demos

The same URL was given to each XSS tool on 2026-10-27. No authenticated or
third-party target was used.

| Target | Tool | Finding | Requests | Wall time | Errors |
|---|---|---|---:|---:|---:|
| Firing Range reflected attribute | SV1 1.5.0 | 1 `HIGH` / `CONFIRMED` XSS | 12 | 18.0 s | 0 |
| Firing Range reflected attribute | SV1 1.4.0 | 1 `HIGH` / `CONFIRMED` XSS | 12 | 18.4 s | 0 |
| Firing Range reflected attribute | dalfox 3.2.4 | 1 high XSS | 26 | 6.2 s | 0 |
| Altoro Mutual search | SV1 1.5.0 | 1 `HIGH` / `CONFIRMED` XSS | 11 | 13.6 s | 0 |
| Altoro Mutual search | SV1 1.4.0 | 1 `HIGH` / `CONFIRMED` XSS | 35 | 35.0 s | 0 |
| Altoro Mutual search | dalfox 3.2.4 | 1 high XSS | 23 | 12.0 s | 0 |

SV1 1.5.0 evidence contains the executed marker:
`executed in chromium: alert:sv19e86a12d` (Firing Range) and
`executed in chromium: alert:sv157c2495f` (Altoro). The 1.4.0 markers
`sv1376d4837` and `sv1b6a24f18` remain in the historical JSON. Dalfox reports a
parsed reflection / DOM marker. Both tools agree the input is exploitable.

Altoro's certificate is expired. The public Altoro run therefore uses the
explicit `--insecure` option; this is a property of the demo, not a TLS finding.
Raw evidence:
[`firing-range-1.5.0.json`](evidence/firing-range-1.5.0.json),
[`altoro-1.5.0.json`](evidence/altoro-1.5.0.json),
[`dalfox-firing-1.3.4.json`](evidence/dalfox-firing-1.3.4.json) and
[`dalfox-altoro-1.3.4.json`](evidence/dalfox-altoro-1.3.4.json). The 1.4.0
public JSON stays as history.

## 4. Exact commands

```powershell
# local SQLite target
python lab/real_sql.py 8100

# SV1 1.3.3, 1.3.4, 1.4.0 and 1.5.0 (run from the matching source tree)
python sv1.py -u http://127.0.0.1:8100/ --crawl --pages 10 `
  --xss --sqli --dump --threads 2 --rps 5 --fail-on none --no-banner `
  -o docs/evidence/sv1-real-1.5.0.json

# dalfox
dalfox scan `
  "http://127.0.0.1:8100/search?q=hello" `
  "http://127.0.0.1:8100/attr?q=hello" `
  "http://127.0.0.1:8100/js?q=hello" `
  "http://127.0.0.1:8100/safe?q=hello" `
  --silence --format json --output dalfox-real.json `
  --skip-mining --workers 4 --rate-limit 20 --timeout 5

# sqlmap
python sqlmap.py -u "http://127.0.0.1:8100/item?id=1" `
  --batch --flush-session --level=3 --risk=2 --threads=4 `
  --technique=BEUST --time-sec=1 --output-dir sqlmap-item

python sqlmap.py -u "http://127.0.0.1:8100/user?name=alice" `
  --batch --flush-session --level=3 --risk=2 --threads=4 `
  --technique=BEUST --time-sec=1 --output-dir sqlmap-user

# public demos
python sv1.py -u "https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=test" `
  --xss --browser --timeout 25 --rps 2 --fail-on none --no-banner `
  -o docs/evidence/firing-range-1.5.0.json

python sv1.py -u "https://demo.testfire.net/search.jsp?query=test" `
  --xss --insecure --browser --timeout 25 --rps 2 --fail-on none --no-banner `
  -o docs/evidence/altoro-1.5.0.json
```

## الخلاصة

على نفس الهدف ونفس اليوم: `1.3.3` و`1.3.4` و`1.4.0` و`1.5.0` أعطوا نفس السبع
نتائج، و`1.5.0` حافظ على 221 طلباً و49.1 ثانية. المختبر الكامل بقي 38/38 لأن
1.5.0 أضاف طبقة تشغيل (دخول/استكمال/اكتشاف/تصنيف) ولم يغيّر نطاق الكشف. هدف
SQLite بقي سبع نتائج فلا تراجع في الفئات الأصلية. dalfox وsqlmap أسرع داخل
تخصصهما، لكن SV1 غطى الصنفين وأثبت تنفيذ XSS داخل Chromium. لا إيجابيات كاذبة
في أي من الجولات. الدليل العام 1.5.0: Firing Range وAltoro، نتيجة `HIGH`
مؤكدة لكل هدف، 12 و11 طلباً، 18.0 و13.6 ثانية، بلا أخطاء.
