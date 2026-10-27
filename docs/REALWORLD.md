# SV1 - real-world validation

Date: 2026-10-27
Build: `1.3.3`; public evidence retained from `1.3.1`
Platform: Windows 11, Python 3.14.6, Playwright Chromium (headless)

> `1.3.3` does not change the detection engine. Its full-lab rerun is 31/31 at
> 184.8 s (17 confirmed, 14 replayed) with `--scope 127.0.0.1:8099`, so the new
> redirect and browser guards are exercised. The same-target dalfox/sqlmap
> comparison from 1.3.2 is in [`COMPARISON.md`](COMPARISON.md). This document
> keeps the 1.3.1 public evidence and adds no new public scan.

This document records what SV1 actually found and proved outside the local lab.
The reflected Firing Range and DOM runs remain from 1.2.1/1.2.0; Altoro was
re-run for 1.3.1 with replay enabled. Release 1.3.1 packages the 1.3.0
input-path work and adds exact dependency pins, a `pyproject.toml`, a full-lab
CI acceptance test, and fresh evidence. The public targets are intentionally
vulnerable demo applications:

- **Google Firing Range** (`public-firing-range.appspot.com`) — reflected and DOM
  XSS test corpus.
- **Altoro Mutual** (`demo.testfire.net`) — a deliberately vulnerable banking demo.

No third-party production application was scanned.

Raw evidence:

- [Firing Range reflected JSON](evidence/firing-range-reflected.json)
- [Firing Range DOM JSON](evidence/firing-range-dom.json)
- [Altoro search JSON](evidence/altoro-search.json)
- [Local lab JSON](evidence/local-lab.json) and [SARIF](evidence/local-lab.sarif)
- [Nested JSON evidence](evidence/local-nested-json.json)
- [XHR POST evidence](evidence/local-xhr-post.json)
- [External JS evidence](evidence/local-external-js.json)
- [Local HAR import evidence](evidence/local-har.json) and [HAR fixture](evidence/local-nested.har)
- [Public HAR import evidence](evidence/firing-range-har.json) and [HAR fixture](evidence/firing-range-har.har)
- [Same-target dalfox/sqlmap comparison](COMPARISON.md) and [quality gates](QUALITY.md)

Live-site validation totals: **4 runs, 76 pages, 49 injection points, 560 HTTP
requests, 59 findings, 59/59 verified, 0 errors**. The replay counts are 42/42
for reflected Firing Range, 1/1 for Altoro, 1/1 for the public HAR import, and
15/15 execution-confirmed for DOM (the DOM run was generated with
`--no-verify`).

Automated tests on the current 1.3.3 tree: **110 discovered, 106 pass by default**.
The Chromium integration tests and the full-lab acceptance test are opt-in locally and
run in CI; both pass on a fresh lab process. Quality gates and coverage:
[`QUALITY.md`](QUALITY.md).

---

## 0. 1.3.1 input-path regression (local lab)

The local lab is the controlled target. Each focused run kept replay enabled
unless noted, so a reflection is re-sent and the finding is removed if it does
not reproduce.

### External JavaScript

```powershell
python sv1.py -u http://127.0.0.1:8099/external `
  --external-js --xss --no-banner `
  -o docs/evidence/local-external-js.json
```

`/external.js` contains `location.hash → innerHTML`. Chromium executed the
marker; the result is one `HIGH` + `CONFIRMED` DOM finding. No query/form points
exist on this page, so it is the external source/sink path that supplies the
finding. Stats: 1 page, 0 points, 2 requests, 0 errors, 1.57 s.

### XHR/fetch POST capture

```powershell
python sv1.py -u http://127.0.0.1:8099/xhr-post `
  --spa --xss --no-banner `
  -o docs/evidence/local-xhr-post.json
```

The page sends `{"user":{"name":"hello"},"q":"hello"}` to `/api/xhr` after load.
`--spa` captured the POST method, body and content type; `user.name` and `q`
became points. The server reflects `user.name` into HTML, but there is no
browser execution path for a JSON POST endpoint, so the finding is `MEDIUM`
(reflection only), not inflated. Stats: 1 page, 2 points, 14 requests, 0 errors,
4.27 s.

### Nested JSON and HAR

The HAR fixture (`docs/evidence/local-nested.har`) records a same-origin POST
with a nested JSON body. It is read once; headers/cookies are not printed.

```powershell
python sv1.py -u http://127.0.0.1:8099/api/nested `
  --har docs/evidence/local-nested.har --xss --no-browser --no-banner `
  -o docs/evidence/local-har.json
```

The imported body is flattened to `user.name` and `q`; the nested leaf is sent
by rebuilding the original object, not by flattening the wire body. The
reflection is `MEDIUM` because the run has no browser. Stats: 1 page, 2 points,
14 requests, 0 errors, 1.65 s. The `--json` variant produced the same point and
the same `MEDIUM` result ([evidence](evidence/local-nested-json.json)).

### Public HAR import (Firing Range)

```powershell
python sv1.py -u "https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=test" `
  --har docs/evidence/firing-range-har.har --xss --threads 2 --rps 4 `
  --no-banner -o docs/evidence/firing-range-har.json
```

The HAR supplies the request, query point, `Accept` header and browser session.
The run produced one `HIGH` + `CONFIRMED` reflected XSS finding and replayed it
(`stats.verified: 1`). Stats: 1 page, 1 point, 12 requests, 0 errors, 12.1 s.
This is the public-target check for the import path; the nested-body features
were checked on the controlled local lab because no public demo exposes a
matching authenticated JSON request.

---

## 1. Firing Range — reflected XSS (1.2.1 evidence)

### Command

```powershell
python sv1.py -u https://public-firing-range.appspot.com/reflected/ `
  --crawl --depth 1 --pages 60 --xss --threads 4 --rps 4 `
  --no-banner `
  -o docs/evidence/firing-range-reflected.json `
  --html fr-reflected-1.2.1.html `
  --artifacts fr-artifacts-1.2.1
```

`--rps 4` keeps the request rate polite. Replay is enabled (there is no
`--no-verify`): every reported finding is sent again, and a finding that does
not reproduce is marked unstable. The browser execution stage still runs. A
finding is `HIGH` only after Chromium executes the marker; an exact reflection
that cannot execute stays `MEDIUM`.

### Result

| Metric | Value |
|---|---:|
| Pages crawled | 49 |
| Injection points | 47 |
| HTTP requests | 512 |
| Errors | 0 |
| Findings | 42 |
| `HIGH` (execution-confirmed) | 40 |
| `MEDIUM` (reflection only) | 2 |
| Replay reproduced / verified | 42/42 |
| Replay unstable | 0 |
| Duration | 247 s |

The JSON records `meta.replay: true`, `stats.verified: 42` and
`stats.unverified: 0`; 42 equals the 42 findings. The 40 `HIGH` findings are
execution-confirmed in Chromium; the 2 `MEDIUM` findings are reflection-only and
are still replayed successfully.

The two `MEDIUM` cases are not inflated to `HIGH`:

| Endpoint | Context | Why it stayed `MEDIUM` |
|---|---|---|
| `/reflected/url/css_import` | `<link rel="stylesheet" href="...">` | Current Chromium does not execute `javascript:` in a stylesheet link. The page rejects `<`/`>` in the parameter, so markup injection is not available. |
| `/reflected/url/object_data` | `<object type="application/x-shockwave-flash" data="...">` | The object is pinned to the removed Flash plugin type; a `javascript:` or `data:text/html` value does not render an HTML document. The page also rejects `<`/`>` in the parameter. |

### Context coverage confirmed by execution

| Firing Range case | Payload shape | Proof |
|---|---|---|
| `escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE` | `alert(/TOKEN/)` | quote-free handler survives escaped quotes; click event |
| `escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE` | `alert(/TOKEN/)` | same, single-quoted handler |
| `escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE` | new `onmouseover` attribute | browser event dispatch |
| `parameter/tagname` | `TOKEN><svg/onload=...>` | element created, `svg` load |
| `parameter/attribute_name` | new `onmouseover` attribute | browser event dispatch |
| `parameter/attribute_unquoted` | new `onmouseover` attribute | browser event dispatch |
| `parameter/iframe_srcdoc` | `<svg/onload=...>` | marker read from the child frame |
| `parameter/iframe_attribute_value` | injected `srcdoc` | marker read from the child frame |
| `parameter/textarea_attribute_value` | `'></textarea><svg/onload=...>` | raw-text element closed first |
| `parameter/style_attribute_value` | `'></style><svg/onload=...>` | raw-text element closed first |
| `parameter/js_assignment` | `0;alert(...)//` | expression terminates safely before the alert |
| `parameter/js_eval` | `0");alert(...)//` | benign literal, closes the string and the call |
| `parameter/js_slashquoted_string` | `TOKEN/;alert(...);/` | closes the regex literal |
| `parameter/js_comment` | `TOKEN*/0;alert(...)/*` | closes the block comment |
| `parameter/attribute_script` | closing `</script>` then markup | script element ended |
| `escapedparameter` variants | context-specific, quote-safe | exact reflection plus execution |

Execution evidence is recorded inside the finding itself: proof: executed in chromium. Screenshot artifacts are not published — a captured page without the marker proves nothing.

This is the accuracy gain over 1.1.0 on the same corpus. The 1.1.0 JSON
confirmed 18 payloads but still printed 26 reflections the browser did not
execute as `HIGH`. 1.2.1 confirms 40 and leaves only the two non-executable
cases at `MEDIUM`; the other unproven reflections are no longer inflated. The
replay pass re-sent all 42 findings and reproduced all 42.

---

## 2. Firing Range — DOM XSS (1.2.0 evidence)

### Command

```powershell
python sv1.py -u https://public-firing-range.appspot.com/dom/ `
  --crawl --depth 1 --pages 25 --xss --threads 4 --rps 4 `
  --no-banner --no-verify `
  -o fr-dom-1.2.0.json `
  --html fr-dom-1.2.0.html `
  --artifacts fr-artifacts-dom-1.2.0
```

### Result

| Metric | Value |
|---|---:|
| Pages crawled | 25 |
| Pages rendered in Chromium | 20 (browser page budget) |
| Static source → sink candidates | 21 |
| Confirmed DOM findings | 15 |
| Errors | 0 |
| Duration | ~164 s |

Confirmed source/sink families:

- `document.referrer` → `document.write` and `innerHTML`
- `location.href` → `document.write` and `innerHTML` on the referrer pages
- `localStorage` / `localStorage.getItem` → `eval`, `innerHTML`, `document.write`
- `window.name` → `eval`, `innerHTML`, `document.write`

Every finding is backed by the browser's own `alert` hook, e.g.:

```text
document.referrer -> document.write: alert:sv1dom1bee6dab9
```

The cookie-based Firing Range pages did not produce a confirmed DOM finding in
this run; they are not counted. This is a report of confirmed execution, not a
claim that every page in the corpus is vulnerable.

---

## 3. Altoro Mutual — reflected XSS (1.3.1 evidence)

### Command

```powershell
python sv1.py -u "http://demo.testfire.net/search.jsp?query=test" `
  --xss --threads 2 --rps 2 --no-banner --fail-on none `
  -o docs/evidence/altoro-search.json `
  --html altoro-search-1.3.1.html `
  --artifacts altoro-artifacts-1.3.1
```

Replay is enabled (there is no `--no-verify`). The 1.3.1 run also collapses the
GET form point into the query point when both address the same URL and
parameter, so the same reflection is not reported twice.

### Result

| Metric | Value |
|---|---:|
| Pages | 1 |
| Injection points | 1 |
| Requests | 11 |
| Errors | 0 |
| Findings | 1 |
| Verified / replayed | 1/1 |
| Unstable | 0 |
| Duration | 8.0 s |

One finding, `HIGH` + `CONFIRMED`:

```text
target   http://demo.testfire.net/search.jsp?query=test
param    query
payload  <svg/onload=alert('sv11af4bbc1')>sv11af4bbc1
proof    executed in chromium: alert:sv11af4bbc1
```

The JSON evidence is [`evidence/altoro-search.json`](evidence/altoro-search.json).
It records `meta.replay: true`, `stats.verified: 1`, `stats.unverified: 0`, and
`confidence: CONFIRMED`.

---

## 4. Local lab regression (1.3.2)

The lab is the controlled acceptance target. It contains reflected, stored, DOM,
external-script DOM, blind, second-order, SQLi and SSRF paths, plus a JSON POST
XHR path. The same command is enforced by `tests/test_lab_1_3.py` in CI.

### Command

```powershell
python lab\server.py 8099

"127.0.0.1:8099" | Set-Content scope-lab.txt

python sv1.py -u http://127.0.0.1:8099/ `
  --crawl --stored --js --second-order --dump `
  --spa --external-js --openapi http://127.0.0.1:8099/openapi.json `
  --blind --blind-visit http://127.0.0.1:8099/blind-admin --ssrf `
  --scope scope-lab.txt --db lab-1.3.2.db --diff `
  --sarif docs/evidence/local-lab.sarif --fail-on high `
  --html lab-1.3.2.html --no-banner `
  -o docs/evidence/local-lab.json --artifacts lab-artifacts-1.3.2
```

### Result

| Metric | Value |
|---|---:|
| Findings | 31 |
| Replayed | 31 |
| Unstable | 0 |
| `CRITICAL` | 10 |
| `HIGH` | 18 |
| `MEDIUM` | 3 |
| Pages | 21 |
| Injection points | 29 |
| Requests | 966 |
| Errors | 0 |
| Duration | 186.0 s |

Breakdown: 17 XSS, 13 SQLi, 1 SSRF. The run is `stats.verified: 31`,
`stats.unverified: 0`, so the release gate (`verified == findings`) passes. The
new paths are visible in the same result: `/external` is a `HIGH` external-script
DOM finding, and `/api/xhr` is a `MEDIUM` reflected JSON POST finding captured
from the SPA pass. The multi-parameter behavior is unchanged: `/api/fetch`,
`/api/spa` and `/dynamic` inject the second parameter (`name`), not only the
first.

The CI acceptance test starts a fresh server, runs the same full command with
`--fail-on none`, and asserts 31 findings, 31 verified, 0 unverified, 0 errors,
the severity/type split, `/external` at `HIGH`/`CONFIRMED`, `/api/xhr` at
`MEDIUM`, 31 SARIF results, and an HTML report. It passed locally in 185.0 s and
runs in the `browser-and-lab` CI job after the Chromium XHR test.

The lab keeps its stored state in memory. Restart `lab\server.py` before a full
acceptance run. A second full run without a restart starts with the second-order
payload already in `/profile`; that page then renders the error state and no
longer exposes the form, so the second-order finding is absent (30/31) even
though every finding it did produce replayed. The 31/31 result is from a fresh
server process.

### 1.3.3 rerun

The 1.3.3 acceptance run on the same lab, with a fresh server and a scope file
containing `127.0.0.1:8099`:

| Metric | Value |
|---|---:|
| Findings | 31 |
| Confirmed (browser/OOB) | 17 |
| Replayed (HTTP) | 14 |
| Unstable | 0 |
| `CRITICAL` | 10 |
| `HIGH` | 18 |
| `MEDIUM` | 3 |
| Pages | 21 |
| Injection points | 29 |
| Requests | 966 |
| Errors | 0 |
| Duration | 184.8 s |

`stats.verified` remains 31 (`confirmed + replayed`). Evidence:
[`evidence/local-lab-1.3.3.json`](evidence/local-lab-1.3.3.json). The run is the
release gate: `tests/test_lab_1_3.py` asserts the exact counts after the redirect
and browser guards were added. A dedicated loopback test in
`tests/test_1_3_3.py` proves that a 302 to another port is refused by default,
that a scoped hop carries no session headers or cookies, and that redirects to
non-HTTP schemes are refused.

---

## 5. What this proves, and what it does not

Proved:

- Payloads are generated from the actual HTML/JavaScript grammar at the
  reflection point.
- `HIGH` means Chromium executed the marker; exact reflection alone is not
  enough.
- Child frames are read, so `iframe srcdoc` and injected `srcdoc` are proved,
  not guessed.
- Duplicate and multi-parameter requests keep every value in order.
- A GET form and a page query that address the same URL and parameter are
  collapsed into one point, so Altoro is 1 point / 1 finding instead of a
  duplicate pair.
- The local lab result is reproducible after a fresh server start: 31/31.
- HAR/raw request import, nested JSON rebuilding and XHR POST capture retain the
  actual body and method; the JSON, XHR and HAR focused files record 2 points
  each.
- External same-origin JavaScript is read and its source/sink path is proved by
  Chromium execution, not by string matching alone.

Not proved:

- A hardened production target will behave like these demos.
- Every page in Firing Range was executed; the DOM pass renders 20 pages because
  of the browser budget.
- CSS-only injection or a removed Flash plugin is XSS. Those stay `MEDIUM`.
- JSON/XHR POST reflections have no general browser execution path here; they
  stay `MEDIUM` until a real execution path proves them.
- HAR sessions are static captures; login/CSRF refresh is not automated.
- The Altoro result is a single reflected parameter, not a full assessment.

The public demos can change without notice. The JSON files under `evidence/`
capture the exact responses and findings for this release.
