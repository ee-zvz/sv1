# SV1 1.3.3 — quality gates

Date: 2026-10-27
Platform: Windows 11, Python 3.14.6

The 1.3.3 patch hardens scope and request identity. It does not add a new
vulnerability class: XSS, SQLi, blind XSS and SSRF stay the surface, and
reflection-only findings stay `MEDIUM`.

## One version source

`sv1lib/version.py` is the only version string:

```python
__version__ = "1.3.3"
```

- `sv1lib/config.py` imports it and exposes `TOOL_VERSION`.
- the user agent is built from `TOOL_VERSION`.
- `pyproject.toml` uses `dynamic = ["version"]` and reads
  `sv1lib.version.__version__`.
- `tests/test_version.py` fails if the runtime, user agent and package metadata
  drift apart.
- `python -m pip install --dry-run --no-deps .` reports `Would install sv1-1.3.3`.

## Ruff and mypy

`requirements-dev.txt` pins the tools:

```text
coverage==7.17.0
mypy==2.4.0
ruff==0.17.3
```

`[tool.ruff.lint]` selects `E9` (syntax/runtime errors) and `F` (undefined names,
unused imports, redefinitions). `[tool.mypy]` checks `sv1.py` and `sv1lib` with
`check_untyped_defs = true`, `ignore_missing_imports = true` and Python 3.10 as
the target.

```text
python -m ruff check .          all checks passed
python -m mypy                  success: no issues found in 36 source files
```

Both run in the `quality` CI job, together with coverage.

## Coverage

Default suite:

```text
python -m coverage run -m unittest discover -s tests
python -m coverage report -m
```

Result: **44.4% branch coverage** across `sv1.py` and `sv1lib` (4,554
statements). The suite is network-free except for loopback redirect tests, so
integration paths stay low:

| Module | Coverage | Why |
|---|---:|---|
| `sv1lib/net.py` | 74.0% | redirect hops, scope refusal, cookie override and rate paths are unit-tested |
| `sv1lib/browser.py` | 14.5% | route guard helpers are unit-tested; Playwright lifecycle needs Chromium |
| `sv1lib/ssrf.py` | 26.1% | body rebuilding is tested; probes need a live target and listener |
| `sv1lib/sqli.py` | 8.7% | request/response loops; exercised by the full lab |
| `sv1lib/verify.py` | 9.2% | replay needs a live response |
| `sv1lib/union.py` | 48.9% | payload/ordering tests; extraction still needs a server |
| `sv1lib/blind.py` | 46.7% | form/sink tests; callback wait needs a browser and an OOB listener |

`[tool.coverage.report]` now sets `fail_under = 43.5`. The `quality` job fails
when the default suite drops below that floor. The full lab
(`tests/test_lab_1_3.py`, `SV1_LAB_TESTS=1`) remains the integration gate for
the browser and live-response modules.

## Package checks

- `python -m compileall -q sv1.py sv1lib lab tests`
- `python -m pip install --dry-run --no-deps .`
- default tests: **110 discovered, 106 pass, 4 opt-in tests skipped**.
- opt-in Chromium integration tests and full-lab acceptance test: all pass.
- full lab: 31/31 verified (17 confirmed, 14 replayed), 0 unstable, 0 errors,
  21 pages, 29 points, 966 requests, 184.8 s.

## Scope guarantees added in 1.3.3

- The HTTP client follows redirects only inside the target origin unless
  `--scope` explicitly allows the next host. Every hop is checked before the
  request is prepared.
- Session headers and cookies never follow a cross-origin hop. A scoped hop is
  reachable, but it is anonymous.
- The browser route guard applies the same header rule per request and blocks
  out-of-scope top-level navigations. Cross-origin iframes/scripts can still
  load; they do not receive the operator's headers or imported cookies. A
  cross-origin request that would carry an imported cookie is cancelled,
  because Chromium's cookie jar ignores ports.
- Refused URLs return `Response(status=0, error=...)` without a socket.

## الخلاصة بالعربية

- مصدر واحد للإصدار: `sv1lib/version.py`، ويقرأ منه `config.py` و`pyproject.toml`
  و`User-Agent`، مع اختبار يمنع التباعد.
- `ruff` يفحص أخطاء الصياغة والأسماء غير المعرفة، و`mypy` يفحص 36 ملفًا،
  والاثنان يعملان في CI.
- تغطية الاختبارات الافتراضية 44.4% (branch) مع حد أدنى 43.5% في CI.
- في 1.3.3 صار العميل يفحص كل قفزة تحويل قبل إرسالها، ولا ترافق ترويسات
  الجلسة أو الكوكيز أي نطاق آخر. المتصفح يطبّق القاعدة نفسها لكل طلب.
- المختبر الكامل ما زال البوابة: 31/31 (17 مؤكدة + 14 معادة)، صفر نتائج غير
  مستقرة، 966 طلباً، 184.8 ثانية.
