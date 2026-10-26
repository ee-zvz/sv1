"""SV1 - hidden parameter discovery.

The URL shows one or two inputs. The backend reads more. Send names in
batches, bisect the batch that changes the page, then confirm each candidate
on its own. A control name keeps us honest: if a random string also changes
the page, the page is reacting to noise and we walk away.
"""

from __future__ import annotations

import secrets
import urllib.parse

from . import baseline as baseline_mod
from . import config
from .models import InjectionPoint

NAMES = (
    "id", "page", "p", "q", "s", "search", "query", "name", "user", "username",
    "email", "file", "filename", "path", "url", "uri", "redirect", "next", "return",
    "view", "action", "cmd", "exec", "debug", "test", "admin", "lang", "language",
    "country", "type", "cat", "category", "sort", "order", "limit", "offset", "start",
    "end", "date", "from", "to", "format", "output", "export", "api", "key", "token", "auth",
    "access", "role", "mode", "theme", "template", "include", "load", "download",
    "upload", "img", "image", "doc", "folder", "dir", "config", "option", "data",
    "value", "input", "callback", "jsonp", "ref", "src", "tab", "step",
)


def split_url(url: str) -> tuple[str, list[tuple[str, str]]]:
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    base = urllib.parse.urlunsplit(parts._replace(query=""))
    return base, pairs


def with_params(url: str, names: list[str]) -> str:
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    pairs.extend((name, "1") for name in names)
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(pairs)))


def discover(client, url: str) -> tuple[list[InjectionPoint], str]:
    """Return (points, note). The note says what happened either way."""
    first = client.fetch(url)
    second = client.fetch(url)
    if not first.ok or not second.ok:
        return [], "target unreachable"

    noise = 1.0 - baseline_mod.text_similarity(first.text, second.text)
    if noise > config.PAGE_MAX_FLOOR:
        return [], f"page drifts {noise:.1%}, too noisy to compare"

    floor = min(max(config.PAGE_MIN_DIFF, noise * 3.0), config.PAGE_MAX_FLOOR)
    threshold = 1.0 - floor

    control = "sv1" + secrets.token_hex(3)
    probe = client.fetch(with_params(url, [control]))
    if probe.ok and baseline_mod.text_similarity(first.text, probe.text) < threshold:
        return [], "page reacts to any parameter, cannot isolate names"

    base, existing = split_url(url)
    taken = {name for name, _value in existing}
    names = [name for name in NAMES if name not in taken]

    found: list[str] = []
    for start in range(0, len(names), config.HIDDEN_CHUNK):
        if len(found) >= config.HIDDEN_MAX:
            break
        chunk = names[start:start + config.HIDDEN_CHUNK]
        response = client.fetch(with_params(url, chunk))
        if not response.ok:
            continue
        if baseline_mod.text_similarity(first.text, response.text) >= threshold:
            continue
        found.extend(_bisect(client, url, chunk, first.text, threshold))

    confirmed: list[str] = []
    for name in found:
        hits = 0
        for _ in range(config.HIDDEN_VERIFY):
            response = client.fetch(with_params(url, [name]))
            if response.ok and baseline_mod.text_similarity(first.text, response.text) < threshold:
                hits += 1
        if hits == config.HIDDEN_VERIFY:
            confirmed.append(name)

    if not confirmed:
        return [], "no hidden parameter changed the page"

    points = [
        InjectionPoint(
            url=base,
            method="GET",
            params=tuple(existing + [(name, "1")]),
            param=name,
            source="query",
        )
        for name in confirmed
    ]
    return points, "found " + ", ".join(confirmed)


def _bisect(client, url: str, group: list[str], base_text: str, threshold: float) -> list[str]:
    found: list[str] = []
    stack = [list(group)]
    while stack:
        current = stack.pop()
        response = client.fetch(with_params(url, current))
        if not response.ok:
            continue
        if baseline_mod.text_similarity(base_text, response.text) >= threshold:
            continue
        if len(current) == 1:
            found.append(current[0])
            continue
        middle = len(current) // 2
        stack.append(current[:middle])
        stack.append(current[middle:])
    return found
