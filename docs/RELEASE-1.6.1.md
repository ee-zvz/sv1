# SV1 1.6.1 — proof-gate repair

`1.6.1` repairs the release gate for **Coverage 2.0**. Detection rules are
unchanged: reflection alone stays `MEDIUM`; `HIGH` requires Chromium execution,
HTTP replay or an OOB callback.

## Fixed

- The full lab now runs `--path --headers --cookies` instead of re-running the
  old 34-point set.
- `/catalog/{id}?ref=home` proves path-segment XSS, `/header-xss` proves
  `X-Forwarded-For` XSS and `/cookie-xss` proves `prefs` cookie XSS.
- `SV1_LAB_EVIDENCE=FILE` stores the gate JSON/SARIF outside the temporary run.
- The Firing Range recall is re-measured with `scripts/recall.py`; query
  findings are counted separately from header/cookie findings.

## Evidence

- Full lab: **43/43 verified**, 27 confirmed, 16 replayed, 0 unverified,
  0 errors, 28 pages, 150 points, 4201 requests, 655.7 s; 13 `CRITICAL`,
  28 `HIGH`, 2 `MEDIUM`; 26 XSS, 16 SQLI, 1 SSRF.
- Firing Range reflected: **49 pages, 47 points, 515 requests, 0 errors,
  206.3 s**; 44 findings (42 `HIGH`, 2 `MEDIUM`), **43/43 GET recall**,
  **41/43 GET execution proofs**, POST form 1/1 `HIGH`.
- Carrier coverage: **323 points, 3088 requests, 0 errors, 1136.6 s**;
  123 findings (42 `HIGH`, 81 `MEDIUM`). The 79 new path findings are
  reflection-only 404/500 echoes and stayed `MEDIUM`; the public target
  reflected no header or cookie.
- Default suite: **203 discovered, 190 pass, 13 opt-in skips**; `ruff` and
  `mypy` clean; branch coverage **52.6%** (6,075 statements).

## Scope

WebSocket, GraphQL, interactsh/DNS OOB, ProofBench and first-class fragment
points remain `1.7.0` work; they are not claimed by `1.6.x`.

## Links

- [Full lab JSON](https://github.com/ee-zvz/sv1/blob/main/docs/evidence/local-lab-1.6.1.json)
- [Full lab SARIF](https://github.com/ee-zvz/sv1/blob/main/docs/evidence/local-lab-1.6.1.sarif)
- [Firing Range reflected](https://github.com/ee-zvz/sv1/blob/main/docs/evidence/firing-range-reflected-1.6.1.json)
- [Firing Range carriers](https://github.com/ee-zvz/sv1/blob/main/docs/evidence/firing-range-carriers-1.6.1.json)
- [Recall summary](https://github.com/ee-zvz/sv1/blob/main/docs/evidence/firing-range-reflected-recall-1.6.1.json)
