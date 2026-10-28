"""SV1 - multipart/form-data parsing for captured requests.

Browsers and HAR files send multipart bodies as bytes with a boundary.  The
scanner only needs the text fields: file parts are not injection targets, and
re-encoding a file body without its original bytes would be dishonest.  Keep
the parser small, bounded and tolerant.  A malformed body returns no fields
instead of raising into the scan loop.
"""

from __future__ import annotations

import re
import urllib.parse
from email.message import Message

from . import config

_BOUNDARY_RE = re.compile(r"(?:^|;)\s*boundary\s*=\s*(\"[^\"]+\"|[^;\s]+)", re.I)


def boundary(content_type: str) -> str:
    """Return the multipart boundary, or an empty string."""
    text = str(content_type or "")
    if "multipart/" not in text.lower():
        return ""
    match = _BOUNDARY_RE.search(text)
    if not match:
        return ""
    value = match.group(1).strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value[:200]


def is_multipart(content_type: str) -> bool:
    return bool(boundary(content_type))


def _disposition(value: str) -> tuple[str, str]:
    """Read name/filename from a Content-Disposition header."""
    message = Message()
    message["content-disposition"] = value
    name = message.get_param("name", header="content-disposition") or ""
    filename = message.get_param("filename", header="content-disposition")
    if isinstance(name, tuple):
        name = email_decode(name)
    if isinstance(filename, tuple):
        filename = email_decode(filename)
    return str(name or ""), str(filename or "")


def email_decode(value) -> str:
    """RFC 2231 parameters arrive as (charset, language, text) tuples."""
    if isinstance(value, tuple) and len(value) == 3:
        raw = value[2]
        if isinstance(raw, bytes):
            raw = raw.decode(value[0] or "utf-8", "replace")
        return str(raw)
    return str(value)


def _body_text(raw: bytes, content_type: str) -> str:
    charset = ""
    message = Message()
    message["content-type"] = content_type or "text/plain"
    charset = str(message.get_param("charset") or "").strip()
    candidates = [charset, "utf-8", "cp1256", "cp1252", "latin-1"]
    seen: set[str] = set()
    for candidate in candidates:
        normalized = candidate.lower()
        if not candidate or normalized in seen:
            continue
        seen.add(normalized)
        try:
            return raw.decode(candidate, errors="strict")
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", "replace")


def parse(content_type: str, body: str | bytes) -> list[tuple[str, str]]:
    """Return text field pairs from one multipart body.

    File parts and parts without a form name are skipped.  The returned order
    is the wire order, and duplicate names stay duplicated.
    """
    marker = boundary(content_type)
    if not marker:
        return []
    if isinstance(body, str):
        raw = body.encode("utf-8", errors="replace")
    else:
        raw = bytes(body)
    delimiter = b"--" + marker.encode("latin-1", errors="replace")
    segments = raw.split(delimiter)
    pairs: list[tuple[str, str]] = []
    for segment in segments[1:]:
        if segment in (b"", b"--", b"--\r\n", b"--\n"):
            break
        segment = segment.lstrip(b"\r\n")
        if segment.startswith(b"--"):
            break
        head, separator, payload = segment.partition(b"\r\n\r\n")
        if not separator:
            head, separator, payload = segment.partition(b"\n\n")
            if not separator:
                continue
        headers: dict[str, str] = {}
        for line in head.replace(b"\r\n", b"\n").split(b"\n"):
            if b":" not in line:
                continue
            header_name, header_value = line.split(b":", 1)
            headers[header_name.decode("latin-1", "replace").strip().lower()] = \
                header_value.decode("latin-1", "replace").strip()
        disposition = headers.get("content-disposition", "")
        if "form-data" not in disposition.lower():
            continue
        name, filename = _disposition(disposition)
        if not name or filename:
            continue
        name = name[:200]
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        elif payload.endswith(b"\n"):
            payload = payload[:-1]
        value = _body_text(payload, headers.get("content-type", ""))
        pairs.append((name, value[: config.MULTIPART_MAX_VALUE]))
        if len(pairs) >= config.MULTIPART_MAX_FIELDS:
            break
    return pairs


def points(url: str, content_type: str, body: str | bytes,
           method: str = "POST") -> list:
    """Create one injection point per multipart text field."""
    from .models import InjectionPoint

    pairs = tuple(parse(content_type, body))
    if not pairs:
        return []
    counts: dict[str, int] = {}
    points: list[InjectionPoint] = []
    for name, _value in pairs:
        occurrence = counts.get(name, 0)
        counts[name] = occurrence + 1
        points.append(
            InjectionPoint(
                url=url,
                method=method,
                params=pairs,
                param=name,
                source="multipart",
                param_index=occurrence,
                content_type=content_type,
            )
        )
    return points


def encode_urlencoded(pairs: list[tuple[str, str]]) -> str:
    """A small helper for tests and callers that need a query string."""
    return urllib.parse.urlencode(pairs, doseq=True)
