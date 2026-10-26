"""SV1 - stable finding identity used by history and SARIF."""

from __future__ import annotations

import hashlib
import json
import urllib.parse


def normalize_url(url: str) -> str:
    """Lower the origin, drop the fragment, sort the query, keep the path."""
    try:
        parts = urllib.parse.urlsplit(url or "")
    except ValueError:
        return (url or "").lower()
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path.rstrip("/") or "/"
    query = urllib.parse.urlencode(
        sorted(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    )
    return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))


def fingerprint(finding) -> str:
    """Same endpoint, method, parameter and proof class mean the same finding."""
    raw = json.dumps(
        [
            str(getattr(finding, "kind", "")).lower(),
            str(getattr(finding, "method", "")).upper(),
            normalize_url(str(getattr(finding, "url", ""))),
            str(getattr(finding, "param", "")).lower(),
            str(getattr(finding, "technique", "")).lower(),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
