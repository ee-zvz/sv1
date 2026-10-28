"""SV1 - session and input import.

A real application is usually already captured in a HAR file or a raw HTTP
request. Those files carry the cookies, authorization headers, CSRF tokens and
JSON bodies the crawler cannot invent. This module imports them without making
the rest of the scanner care where a point came from.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from dataclasses import dataclass, field

from . import config, crawl, formdata, jsonbody, net
from .models import InjectionPoint

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
NO_SESSION_HEADERS = {
    "host",
    "content-length",
    "cookie",
    "connection",
    "proxy-connection",
    "transfer-encoding",
    "accept-encoding",
    "content-type",
}
COOKIE_HEADER = "cookie"


@dataclass
class ImportedRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""


def _header(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)
    return ""


def parse_cookie_header(raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for chunk in (raw or "").split(";"):
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        key = key.strip()
        if key:
            cookies[key] = value.strip()
    return cookies


def _headers_from_har(raw) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()
        if not name or name.startswith(":"):
            continue
        headers[name] = str(item.get("value", "") or "")
    return headers


def _cookies_from_har(raw, headers: dict[str, str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()
        if name:
            cookies[name] = str(item.get("value", "") or "")
    cookies.update(parse_cookie_header(_header(headers, COOKIE_HEADER)))
    return cookies


def _content_type(headers: dict[str, str], fallback: str = "") -> str:
    return _header(headers, "content-type") or fallback


def _post_body(post: dict, headers: dict[str, str]) -> tuple[str, str]:
    if not isinstance(post, dict):
        return "", _content_type(headers)
    text = str(post.get("text", "") or "")
    mime = str(post.get("mimeType", "") or "") or _content_type(headers)
    if text:
        return text, mime
    params = post.get("params")
    if not isinstance(params, list):
        return "", mime
    pairs = []
    for item in params:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        if item.get("fileName") is not None:
            continue
        pairs.append((str(item["name"]), str(item.get("value", "") or "")))
    if not pairs:
        return "", mime
    if "json" in mime.lower():
        return jsonbody.dumps({name: value for name, value in pairs}), mime
    return urllib.parse.urlencode(pairs, doseq=True), mime or "application/x-www-form-urlencoded"


def load_har(path: str) -> tuple[list[ImportedRequest], str]:
    """Read a HAR file. Returns (requests, note)."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return [], f"cannot read HAR: {exc.strerror}"
    if size > config.HAR_MAX_BYTES:
        return [], f"HAR is larger than {config.HAR_MAX_BYTES} bytes"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"invalid HAR: {exc}"

    log = data.get("log") if isinstance(data, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        return [], "HAR has no log.entries"

    imported: list[ImportedRequest] = []
    for entry in entries[: config.HAR_MAX_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            continue
        method = str(request.get("method", "GET") or "GET").upper()
        url = str(request.get("url", "") or "")
        if method not in METHODS or not url.startswith(("http://", "https://")):
            continue
        headers = _headers_from_har(request.get("headers"))
        cookies = _cookies_from_har(request.get("cookies"), headers)
        body, content_type = _post_body(request.get("postData") or {}, headers)
        imported.append(
            ImportedRequest(
                method=method,
                url=url,
                headers=headers,
                cookies=cookies,
                body=body,
                content_type=content_type,
            )
        )
    return imported, f"{len(imported)} request(s) from {os.path.basename(path)}"


def load_request(path: str, target: str) -> tuple[list[ImportedRequest], str]:
    """Read one raw HTTP request and resolve its origin against `target`."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return [], f"cannot read request: {exc.strerror}"
    if size > config.REQUEST_MAX_BYTES:
        return [], f"request is larger than {config.REQUEST_MAX_BYTES} bytes"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        return [], f"cannot read request: {exc.strerror}"

    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    if not lines:
        return [], "request is empty"
    first = lines[0].strip().split()
    if len(first) < 2:
        return [], "request line must be METHOD PATH HTTP/1.1"
    method = first[0].upper()
    if method not in METHODS:
        return [], f"unsupported method {method}"
    raw_target = first[1]
    if raw_target.startswith(("http://", "https://")):
        url = raw_target
    else:
        parts = urllib.parse.urlsplit(target)
        if not parts.scheme or not parts.netloc:
            return [], "target must include a scheme and host"
        url = f"{parts.scheme}://{parts.netloc}{raw_target}"

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if name and not name.startswith(":"):
            headers[name] = value.strip()
    cookies = parse_cookie_header(_header(headers, COOKIE_HEADER))
    content_type = _content_type(headers)
    return [
        ImportedRequest(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            body=body,
            content_type=content_type,
        )
    ], "1 raw request"


def session(requests: list[ImportedRequest], target: str) -> tuple[dict[str, str], dict[str, str]]:
    """Merge same-origin request headers and cookies for the scan session."""
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    for request in requests:
        if not net.same_origin(request.url, target):
            continue
        for name, value in request.headers.items():
            if name.lower() in NO_SESSION_HEADERS:
                continue
            headers[name] = value
        cookies.update(request.cookies)
    return headers, cookies


def _query_points(url: str, method: str) -> list[InjectionPoint]:
    parts = urllib.parse.urlsplit(url)
    if not parts.query:
        return []
    pairs = tuple(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    if not pairs:
        return []
    base = urllib.parse.urlunsplit(parts._replace(query="", fragment=""))
    counts: dict[str, int] = {}
    points: list[InjectionPoint] = []
    for name, _value in pairs:
        occurrence = counts.get(name, 0)
        counts[name] = occurrence + 1
        points.append(
            InjectionPoint(
                url=base,
                method=method,
                params=pairs,
                param=name,
                source="query",
                param_index=occurrence,
            )
        )
    return points


def _body_points(request: ImportedRequest) -> list[InjectionPoint]:
    body = request.body or ""
    if not body:
        return []
    content_type = (request.content_type or "").lower()
    stripped = body.lstrip()
    if "json" in content_type or stripped.startswith(("{", "[")):
        try:
            data = json.loads(body)
        except (TypeError, ValueError):
            return []
        return crawl.json_points(
            request.url,
            data,
            method=request.method,
            content_type=request.content_type or "application/json",
        )
    if "multipart/form-data" in content_type:
        return formdata.points(
            request.url,
            request.content_type,
            body,
            method=request.method,
        )
    if "x-www-form-urlencoded" in content_type:
        pairs = tuple(urllib.parse.parse_qsl(body, keep_blank_values=True))
        if not pairs:
            return []
        counts: dict[str, int] = {}
        points: list[InjectionPoint] = []
        for name, _value in pairs:
            occurrence = counts.get(name, 0)
            counts[name] = occurrence + 1
            points.append(
                InjectionPoint(
                    url=request.url,
                    method=request.method,
                    params=pairs,
                    param=name,
                    source="form",
                    param_index=occurrence,
                    content_type=request.content_type,
                )
            )
        return points
    return crawl.raw_point(
        request.url,
        body,
        method=request.method,
        content_type=request.content_type,
    )


def points(requests: list[ImportedRequest], target: str,
           allows=None) -> list[InjectionPoint]:
    """Build injection points from same-origin imported requests."""
    found: list[InjectionPoint] = []
    seen: set[tuple] = set()

    def add(point: InjectionPoint) -> bool:
        key = point.key()
        if key in seen:
            return False
        seen.add(key)
        found.append(point)
        return len(found) >= config.HAR_MAX_POINTS

    for request in requests:
        if not net.same_origin(request.url, target):
            continue
        if allows is not None and not allows(request.url):
            continue
        if net.is_skippable(request.url) and not request.body:
            continue
        for point in _query_points(request.url, request.method):
            if add(point):
                return found
        for point in _body_points(request):
            if add(point):
                return found
    return found
