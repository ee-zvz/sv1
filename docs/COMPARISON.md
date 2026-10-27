# SV1 1.3.4 - before/after and external comparison

Date: 2026-10-27

This page fixes the comparison to one day and one target process. It is not a
scoreboard. Dalfox is an XSS scanner; sqlmap is a SQL injection engine; SV1
crawls, scans both classes, proves browser execution and also records
reflection-only notes. The table keeps those scope differences visible.

The release gate is the 31-case local lab. The external comparison uses a
separate SQLite target because the lab emulates SQL errors and is not a valid
sqlmap benchmark. Public runs use Google Firing Range and Altoro Mutual, both
intentionally vulnerable demos.

## 1. Same target, 1.3.3 vs 1.3.4

Target: [`lab/real_sql.py`](../lab/real_sql.py), `http://127.0.0.1:8100/`,
7 pages, 6 injection points, SQLite in memory. Same command, fresh process for
each version.

| Build | Findings | XSS confirmed | SQLi | Reflection-only `MEDIUM` | False positives | HTTP requests | Wall time |
|---|---:|---:|---:|---:|---:|---:|---:|
| SV1 1.3.3 | 7 | **3** | **2** | 2 | 0 | 213 | 47.4 s |
| SV1 1.3.4 | 7 | **3** | **2** | 2 | 0 | 221 | 49.0 s |

Result: same seven findings, no lost detection and no new false positive. The
1.3.4 pass sent 8 more requests and took 1.6 s longer because it measured a fresh
clean baseline before replaying the SQLi evidence. That is the intended price of
a stronger proof. Raw JSON:
[`sv1-real-1.3.3.json`](evidence/sv1-real-1.3.3.json) and
[`sv1-real-1.3.4.json`](evidence/sv1-real-1.3.4.json).

Full-lab comparison on the same day:

| Build | Verified | Confirmed | Replayed | Requests | Wall time | Errors |
|---|---:|---:|---:|---:|---:|---:|
| SV1 1.3.3 | 31/31 | 17 | 14 | 966 | 184.8 s | 0 |
| SV1 1.3.4 | 31/31 | 17 | 14 | 1012 | 240.2 s | 0 |

The 1.3.4 lab run adds baseline checks across 31 findings; it does not change
the severity mix (10 `CRITICAL`, 18 `HIGH`, 3 `MEDIUM`). Evidence:
[`local-lab-1.3.3.json`](evidence/local-lab-1.3.3.json) and
[`local-lab-1.3.4.json`](evidence/local-lab-1.3.4.json).

## 2. External tools, same SQLite target

Same target process, same day, fresh session per tool. Dalfox and sqlmap were
downloaded for this run; Dalfox 3.2.4 and sqlmap 1.10.10.27#dev are the exact
versions below.

| Tool | Scope | Confirmed XSS | Confirmed SQLi | Reflection-only | False positives | HTTP requests | Wall time |
|---|---|---:|---:|---:|---:|---:|---:|
| SV1 1.3.4 | crawl 7 pages, 6 points, XSS + SQLi + dump | **3** | **2** | 2 `MEDIUM` | 0 | 221 | 49.0 s |
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
| Firing Range reflected attribute | SV1 1.3.4 | 1 `HIGH` / `CONFIRMED` XSS | 12 | 18.8 s | 0 |
| Firing Range reflected attribute | dalfox 3.2.4 | 1 high XSS | 26 | 6.2 s | 0 |
| Altoro Mutual search | SV1 1.3.4 | 1 `HIGH` / `CONFIRMED` XSS | 35 | 46.5 s | 0 |
| Altoro Mutual search | dalfox 3.2.4 | 1 high XSS | 23 | 12.0 s | 0 |

SV1 evidence contains the executed marker:
`executed in chromium: alert:sv10bf9a934` (Firing Range) and
`executed in chromium: alert:sv1bcccfe46` (Altoro). Dalfox reports a parsed
reflection / DOM marker. Both tools agree the input is exploitable.

Altoro's certificate is expired. The public Altoro run therefore uses the
explicit `--insecure` option; this is a property of the demo, not a TLS finding.
Raw evidence:
[`firing-range-1.3.4.json`](evidence/firing-range-1.3.4.json),
[`altoro-1.3.4.json`](evidence/altoro-1.3.4.json),
[`dalfox-firing-1.3.4.json`](evidence/dalfox-firing-1.3.4.json) and
[`dalfox-altoro-1.3.4.json`](evidence/dalfox-altoro-1.3.4.json).

## 4. Exact commands

```powershell
# local SQLite target
python lab/real_sql.py 8100

# SV1 1.3.3 and 1.3.4 (run from the matching source tree)
python sv1.py -u http://127.0.0.1:8100/ --crawl --pages 10 `
  --xss --sqli --dump --threads 2 --rps 5 --fail-on none --no-banner `
  -o sv1-real.json

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
  --xss --browser --timeout 25 --rps 2 --fail-on none --no-banner -o firing.json

python sv1.py -u "https://demo.testfire.net/search.jsp?query=test" `
  --insecure --browser --timeout 25 --rps 2 --fail-on none --no-banner -o altoro.json
```

## الخلاصة

على نفس الهدف ونفس اليوم: `1.3.3` و`1.3.4` أعطيا نفس السبع نتائج، لكن `1.3.4`
أعاد قياس خط الأساس قبل تثبيت أدلة SQLi، فزاد 8 طلبات فقط. على المختبر الكامل
بقي 31/31، والزيادة في الوقت ثمن التحقق الإضافي. dalfox وsqlmap أسرع داخل
تخصصهما، لكن SV1 غطى الصنفين وأثبت تنفيذ XSS داخل Chromium. لا إيجابيات كاذبة
في أي من الجولات.
