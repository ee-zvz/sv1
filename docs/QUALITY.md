# SV1 1.3.2 — quality gates

Date: 2026-10-27
Platform: Windows 11, Python 3.14.6

The 1.3.2 patch does not change the detection engine. It removes duplicate
version sources, measures the test surface, and puts static checks in CI.

## One version source

`sv1lib/version.py` is the only version string:

```python
__version__ = "1.3.2"
```

- `sv1lib/config.py` imports it and exposes `TOOL_VERSION`.
- the user agent is built from `TOOL_VERSION`.
- `pyproject.toml` uses `dynamic = ["version"]` and reads
  `sv1lib.version.__version__`.
- `tests/test_version.py` fails if the runtime, user agent and package metadata
  drift apart.
- `python -m pip install --dry-run --no-deps .` reports `Would install sv1-1.3.2`.

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

Both run in the new `quality` CI job, together with coverage.

## Coverage

Default suite:

```text
python -m coverage run -m unittest discover -s tests
python -m coverage report -m
```

Result: **42.5% branch coverage** across `sv1.py` and `sv1lib` (4,342
statements). The default suite is fast and network-free, so integration paths
stay low:

| Module | Coverage | Why |
|---|---:|---|
| `sv1lib/union.py` | 48.9% | payload/ordering tests added in 1.3.2; extraction still needs a server |
| `sv1lib/blind.py` | 46.7% | form/sink tests added; callback wait needs a browser and an OOB listener |
| `sv1lib/sqli.py` | 8.7% | request/response loops; exercised by the full lab, not unit tests |
| `sv1lib/verify.py` | 9.2% | replay needs a live response |
| `sv1lib/browser.py` | 12.9% | Playwright lifecycle and page execution |
| `sv1lib/ssrf.py` | 11.9% | probes need a live target and controlled listener |

The full lab (`tests/test_lab_1_3.py`, `SV1_LAB_TESTS=1`) is the integration
gate for those modules; it runs Chromium and the local server in CI. Coverage is
reported, not used as a hard percentage gate, because a network-free unit suite
and a browser lab measure different things.

## Package checks

- `python -m compileall -q sv1.py sv1lib lab tests`
- `python -m pip install --dry-run --no-deps .`
- default tests: **86 discovered, 84 pass, 2 opt-in tests skipped**.
- opt-in Chromium XHR test and full-lab acceptance test: both pass.

## الخلاصة بالعربية

- مصدر واحد للإصدار: `sv1lib/version.py`، ويقرأ منه `config.py` و`pyproject.toml`
  و`User-Agent`، مع اختبار يمنع التباعد.
- `ruff` يفحص أخطاء الصياغة والأسماء غير المعرفة، و`mypy` يفحص 36 ملفًا،
  والاثنان يعملان في CI.
- تغطية الاختبارات الافتراضية 42.5% (branch). وحدات `sqli` و`verify` و`ssrf`
  و`browser` منخفضة لأنها تحتاج هدفًا حيًا؛ المختبر الكامل في CI هو بوابتها.
- `union` و`blind` كانا الأضعف؛ أُضيفت لهما اختبارات مباشرة في 1.3.2.
