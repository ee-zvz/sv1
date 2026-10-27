# SV1 1.2.0 — real-world validation

Date: 2026-10-26
Build: `1.2.0`
Platform: Windows 11, Python 3.14.6, Playwright Chromium (headless)

This document records what SV1 1.2.0 actually found and proved outside the local
lab. The targets are public, intentionally vulnerable demo applications:

- **Google Firing Range** (`public-firing-range.appspot.com`) — reflected and DOM
  XSS test corpus.
- **Altoro Mutual** (`demo.testfire.net`) — a deliberately vulnerable banking demo.

No third-party production application was scanned.

Raw evidence:

- [Firing Range reflected JSON](evidence/firing-range-reflected.json)
- [Firing Range DOM JSON](evidence/firing-range-dom.json)
- [Altoro search JSON](evidence/altoro-search.json)
- [Local lab JSON](evidence/local-lab.json) and [SARIF](evidence/local-lab.sarif)

---

## 1. Firing Range — reflected XSS

### Command

```powershell
python sv1.py -u https://public-firing-range.appspot.com/reflected/ `
  --crawl --depth 1 --pages 60 --xss --threads 4 --rps 4 `
  --no-banner --no-verify `
  -o fr-reflected-1.2.0.json `
  --html fr-reflected-1.2.0.html `
  --artifacts fr-artifacts-1.2.0
```

`--rps 4` keeps the request rate polite. `--no-verify` skips the HTTP replay stage;
the browser execution stage still runs. A finding is `HIGH` only after Chromium
executes the marker.

### Result

| Metric | Value |
|---|---:|
| Pages crawled | 49 |
| Injection points | 47 |
| HTTP requests | 508 |
| Errors | 0 |
| Findings | 42 |
| `HIGH` + browser-confirmed | 40 |
| `MEDIUM` (reflection only) | 2 |
| Duration | 220 s |

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

One execution screenshot: [`evidence/firing-range-js-eval.png`](evidence/firing-range-js-eval.png).

This is the accuracy gain over 1.1.0 on the same corpus. The 1.1.0 JSON
confirmed 18 payloads but still printed 26 reflections the browser did not
execute as `HIGH`. 1.2.0 confirms 40 and leaves only the two non-executable
cases at `MEDIUM`; the other unproven reflections are no longer inflated.

---

## 2. Firing Range — DOM XSS

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

## 3. Altoro Mutual — reflected XSS

### Command

```powershell
python sv1.py -u "http://demo.testfire.net/search.jsp?query=test" `
  --xss --threads 2 --rps 2 --no-banner --no-verify `
  -o altoro-search-1.2.0.json `
  --html altoro-search-1.2.0.html `
  --artifacts altoro-artifacts
```

### Result

One finding, `HIGH` + `CONFIRMED`:

```text
target   http://demo.testfire.net/search.jsp?query=test
param    query
payload  <svg/onload=alert('sv1a041d253')>sv1a041d253
proof    executed in chromium: alert:sv1a041d253
```

The HTML artifact is [`evidence/altoro-xss.png`](evidence/altoro-xss.png).

---

## 4. Local lab regression

The lab is the controlled acceptance target. It contains reflected, stored, DOM,
blind, second-order, SQLi and SSRF paths.

### Command

```powershell
python lab\server.py 8099

"127.0.0.1:8099" | Set-Content scope-lab.txt

python sv1.py -u http://127.0.0.1:8099/ `
  --crawl --stored --js --second-order --dump `
  --spa --openapi http://127.0.0.1:8099/openapi.json `
  --blind --blind-visit http://127.0.0.1:8099/blind-admin --ssrf `
  --scope scope-lab.txt --db lab-history.db --diff `
  --sarif lab-1.2.0.sarif --fail-on high `
  --html lab-1.2.0.html --no-banner `
  -o lab-1.2.0.json --artifacts lab-artifacts-1.2.0
```

### Result

| Metric | Value |
|---|---:|
| Findings | 27 |
| Replayed | 27 |
| Unstable | 0 |
| `CRITICAL` | 9 |
| `HIGH` | 16 |
| `MEDIUM` | 2 |
| Pages | 19 |
| Injection points | 25 |
| Requests | 853 |
| Duration | ~165 s |

Breakdown: 14 XSS, 12 SQLi, 1 SSRF. The 1.2.0 request-fidelity fix is visible
in the multi-parameter results: `/api/fetch`, `/api/spa` and `/dynamic` now
inject the second parameter (`name`) instead of leaving it at its original value.
Those three reflected XSS findings were missing from the first 1.2.0 lab run and
returned after the fix.

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
- The local lab result is reproducible after a fresh server start: 27/27.

Not proved:

- A hardened production target will behave like these demos.
- Every page in Firing Range was executed; the DOM pass renders 20 pages because
  of the browser budget.
- CSS-only injection or a removed Flash plugin is XSS. Those stay `MEDIUM`.
- The Altoro result is a single reflected parameter, not a full assessment.

The public demos can change without notice. The JSON files under `evidence/`
capture the exact responses and findings for this release.
