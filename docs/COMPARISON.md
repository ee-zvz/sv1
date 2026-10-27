# SV1 1.3.2 — external comparison

Date: 2026-10-27
Target: [`lab/real_sql.py`](../lab/real_sql.py), a local SQLite-backed target
(`http://127.0.0.1:8100/`, 7 pages, 6 injection points)
SV1: `1.3.2` · dalfox: `3.2.4` · sqlmap: `1.10.10.27#dev`

This is not a scoreboard. Dalfox is an XSS scanner; sqlmap is a SQL injection
engine; SV1 scans both classes and proves browser execution. The table keeps the
scope difference visible instead of hiding it in a single number.

## Results

Same target and same day, with a fresh scan session per tool. Dalfox scanned
the four XSS URLs; sqlmap scanned the two SQLi URLs; SV1 crawled the whole
target and scanned both classes.

| Tool | Scope | Confirmed XSS | Confirmed SQLi | Reflection-only | False positives | HTTP requests | Wall time |
|---|---|---:|---:|---:|---:|---:|---:|
| SV1 1.3.2 | crawl 7 pages, 6 points, XSS + SQLi + dump | **3** | **2** | 2 `MEDIUM` | 0 | 213 | 47.7 s |
| dalfox 3.2.4 | 4 XSS URLs, no mining | **3** | n/a | 0 | 0 | 598 | 29.9 s |
| sqlmap 1.10.10.27#dev | 2 SQLi URLs, level 3 / risk 2 / BEUST | n/a | **2** | 0 | 0 | 119 | 9.7 s |

Confirmed means the tool's own verification passed and the result reproduced.
SV1's two `MEDIUM` rows are `/safe?q=` and `/item?id=` reflection-only notes; they
are deliberately not counted as XSS. Dalfox reported no reflection-only rows on
this target.

### What each tool found

- **SV1:** `/search`, `/attr` and `/js` XSS at `HIGH` + `CONFIRMED` after Chromium
  execution; `/item?id=` and `/user?name=` SQLi at `CRITICAL`; two additional
  reflection-only `MEDIUM` notes. Zero unverified findings, zero request errors.
- **dalfox:** exactly the three executable XSS endpoints, `type: V`; no false
  positive on `/safe`. It returned `incomplete: false` when limited to the XSS
  URLs.
- **sqlmap:** both SQLi parameters, with boolean-based blind, error-based and
  UNION techniques on each; back-end DBMS identified as SQLite.

### Why the 31-case lab is not in this table

The main lab is a deterministic emulator: it answers specific SQL fragments
instead of running a database. It is the right release gate for SV1 because all
31 cases are replayable, but it is not a valid sqlmap benchmark. On that lab,
dalfox finds 7 vulnerable XSS and 1 reflection-only row; sqlmap finds 0 because
the emulator does not implement a real SQL engine. The SQLite target above
removes that bias. SV1's 31/31 lab evidence remains in
[`evidence/local-lab.json`](evidence/local-lab.json).

## Reproduce

```powershell
# target
python lab/real_sql.py 8100 requests.log

# SV1
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
```

Raw evidence: [`realapp-sv1.json`](evidence/realapp-sv1.json),
[`realapp-dalfox.json`](evidence/realapp-dalfox.json),
[`realapp-sqlmap-item.txt`](evidence/realapp-sqlmap-item.txt) and
[`realapp-sqlmap-user.txt`](evidence/realapp-sqlmap-user.txt). The summary is
[`comparison-2026-10-27.json`](evidence/comparison-2026-10-27.json).

## الخلاصة بالعربية

في 27 أكتوبر 2026 شُغّلت الأدوات الثلاث على نفس الهدف المحلي (تطبيق SQLite
حقيقي، 7 صفحات و6 نقاط حقن):

- **SV1 1.3.2:** 5 ثغرات مؤكدة (3 XSS + 2 SQLi)، وملاحظتان انعكاسيتان
  `MEDIUM`، و0 إيجابيات كاذبة، و213 طلبًا في 47.7 ثانية. أضاف إثبات تنفيذ
  Chromium وإعادة التحقق.
- **dalfox 3.2.4:** 3/3 XSS مؤكدة، و0 إيجابيات كاذبة، و598 طلبًا في 29.9 ثانية.
  تخصصه XSS فقط.
- **sqlmap 1.10.10.27#dev:** 2/2 SQLi مؤكدة، و0 إيجابيات كاذبة، و119 طلبًا في
  9.7 ثانية. تخصصه SQLi فقط.

الأدوات المتخصصة أسرع وأرخص داخل تخصصها، وهذا متوقع. SV1 أغلى لأنه يزحف،
يصنّف، يثبت التنفيذ، ويغطي أكثر من فئة. المقارنة لا تقول «أيهما أفضل» بل
توضّح السؤال الذي يجيب عنه كل أداة. مختبر SV1 ذو 31 حالة يبقى بوابة الإصدار،
ولا يُستخدم كرقم لـ sqlmap لأن SQL فيه محاكاة وليس محركًا حقيقيًا.
