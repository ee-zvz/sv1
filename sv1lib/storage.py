"""SV1 - Chromium storage-state import and export.

Playwright's storage state is the portable form of a logged-in browser:
cookies plus per-origin localStorage.  A scan may receive that file to reach
authenticated pages, and may write an updated state after the browser proved a
finding.  Import is deliberately target-scoped: a state file for one host must
not hand another host's cookies to the HTTP client or the browser.

The module uses no browser imports so it can be unit-tested on a machine
without Chromium.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
from typing import Any

from . import config, net

COOKIE_FIELDS = (
    "name", "value", "domain", "path", "expires",
    "httpOnly", "secure", "sameSite",
)
LOCAL_STORAGE_FIELDS = ("name", "value")


class StorageError(Exception):
    """The storage-state file is missing, oversized or not valid JSON."""


def load(path: str) -> dict:
    """Read one storage-state document, bounded by bytes."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise StorageError(f"cannot read storage state: {exc.strerror}") from exc
    if size > config.STORAGE_STATE_MAX_BYTES:
        raise StorageError(
            f"storage state is larger than {config.STORAGE_STATE_MAX_BYTES} bytes"
        )
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise StorageError(f"invalid storage state: {exc}") from exc
    if not isinstance(data, dict):
        raise StorageError("storage state must be a JSON object")
    if not isinstance(data.get("cookies", []), list):
        raise StorageError("storage state cookies must be a list")
    if not isinstance(data.get("origins", []), list):
        raise StorageError("storage state origins must be a list")
    return data


def _target(base_url: str) -> tuple[str, str]:
    try:
        parts = urllib.parse.urlsplit(base_url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return "", ""
    if scheme not in ("http", "https") or not host:
        return "", ""
    if port is None:
        port = 80 if scheme == "http" else 443
    shown_host = f"[{host}]" if ":" in host else host
    default = 80 if scheme == "http" else 443
    authority = shown_host if port == default else f"{shown_host}:{port}"
    return host, f"{scheme}://{authority}"


def _host_matches(domain: str, host: str) -> bool:
    domain = (domain or "").lstrip(".").lower().rstrip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


def _clean_cookie(raw: dict, host: str) -> dict | None:
    name = str(raw.get("name", ""))
    value = str(raw.get("value", ""))
    if not name or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name + value):
        return None
    domain = str(raw.get("domain", "") or "")
    if not _host_matches(domain, host):
        return None
    path = str(raw.get("path", "/") or "/")
    if not path.startswith("/"):
        path = "/" + path
    record: dict[str, Any] = {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
    }
    if "expires" in raw:
        try:
            record["expires"] = float(raw["expires"])
        except (TypeError, ValueError):
            pass
    if raw.get("httpOnly"):
        record["httpOnly"] = True
    if raw.get("secure"):
        record["secure"] = True
    same_site = str(raw.get("sameSite", "") or "")
    if same_site in ("Strict", "Lax", "None"):
        record["sameSite"] = same_site
    return record


def browser_state(raw: dict, base_url: str) -> dict:
    """Filter a state to the target host and exact target origin."""
    host, origin_url = _target(base_url)
    if not host or not origin_url:
        return {"cookies": [], "origins": []}
    cookies: list[dict] = []
    for item in raw.get("cookies", [])[: config.STORAGE_STATE_MAX_COOKIES * 2]:
        if not isinstance(item, dict):
            continue
        cookie = _clean_cookie(item, host)
        if cookie is not None:
            expires = cookie.get("expires")
            if isinstance(expires, (int, float)) and expires > 0 and expires < time.time():
                continue
            if cookie.get("secure") and origin_url.startswith("http://"):
                continue
            cookies.append(cookie)
        if len(cookies) >= config.STORAGE_STATE_MAX_COOKIES:
            break

    origins: list[dict] = []
    for item in raw.get("origins", [])[: config.STORAGE_STATE_MAX_ORIGINS * 2]:
        if not isinstance(item, dict):
            continue
        if str(item.get("origin", "")).rstrip("/") != origin_url:
            continue
        values = item.get("localStorage")
        if not isinstance(values, list):
            continue
        clean = []
        for pair in values[:200]:
            if not isinstance(pair, dict):
                continue
            name = str(pair.get("name", ""))
            value = str(pair.get("value", ""))
            if not name or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name + value):
                continue
            clean.append({"name": name, "value": value})
        origins.append({"origin": origin_url, "localStorage": clean})
        if len(origins) >= config.STORAGE_STATE_MAX_ORIGINS:
            break
    return {"cookies": cookies, "origins": origins}


def cookie_values(raw: dict, base_url: str) -> dict[str, str]:
    """Flatten target-host cookies for the requests session."""
    host, origin_url = _target(base_url)
    if not host:
        return {}
    secure_origin = origin_url.startswith("https://")
    found: dict[str, str] = {}
    for item in raw.get("cookies", []):
        if not isinstance(item, dict):
            continue
        cookie = _clean_cookie(item, host)
        if cookie is None:
            continue
        if cookie.get("secure") and not secure_origin:
            continue
        expires = cookie.get("expires")
        if isinstance(expires, (int, float)) and expires > 0 and expires < time.time():
            continue
        found[cookie["name"]] = cookie["value"]
    return found


def save(path: str, raw: dict, base_url: str) -> str:
    """Write only target-scoped state, never a third-party cookie jar."""
    filtered = browser_state(raw, base_url)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(filtered, handle, ensure_ascii=False, indent=2)
    return path


def playwright_cookies(raw: dict, base_url: str) -> list[dict]:
    """Return Playwright cookie records anchored by URL.

    ``browser_state`` keeps the domain form so a context can also use
    localStorage.  This helper is for callers that want to add cookies to an
    already-running context, where a URL anchor keeps the host-only rule.
    """
    state = browser_state(raw, base_url)
    origin_url = net.origin(base_url) or ""
    records = []
    for cookie in state["cookies"]:
        path = str(cookie.get("path", "/"))
        record = {
            "name": cookie["name"],
            "value": cookie["value"],
            "url": f"{origin_url}{path}",
        }
        for key in ("httpOnly", "secure", "sameSite", "expires"):
            if key in cookie:
                record[key] = cookie[key]
        records.append(record)
    return records
