"""SV1 - database error fingerprints. One place, shared by every technique."""

from __future__ import annotations

from . import payloads


def match_error(text: str) -> tuple[str, str]:
    """Return (dbms, matching_line) or ("", "")."""
    for dbms, pattern in payloads.ERROR_SIGNATURES:
        found = pattern.search(text)
        if not found:
            continue
        start = text.rfind("\n", 0, found.start()) + 1
        end = text.find("\n", found.end())
        if end == -1:
            end = min(len(text), found.end() + 160)
        line = " ".join(text[start:end].split())[:220]
        return dbms, line
    return "", ""
