"""SV1 - small JSON body helpers.

The scanner works with leaf paths, not only top-level keys. A JSON body is
flattened to ``(path, value)`` pairs; when a payload is sent, the same path is
rebuilt inside a fresh copy of the template. Lists use integer path elements so
``items[0].name`` and ``items[1].name`` are distinct injection points.
"""

from __future__ import annotations

import json
from typing import Any

MAX_DEPTH = 24


def flatten(value: Any, path: tuple = (), depth: int = 0) -> list[tuple[tuple, Any]]:
    """Return every scalar leaf in a JSON value.

    Depth is bounded: a hostile or accidental 500-level document is not worth
    a recursion crash, and no real request body needs that shape.
    """
    if depth > MAX_DEPTH:
        return []
    if isinstance(value, dict):
        leaves: list[tuple[tuple, Any]] = []
        for key, item in value.items():
            leaves.extend(flatten(item, path + (key,), depth + 1))
        return leaves
    if isinstance(value, list):
        leaves = []
        for index, item in enumerate(value):
            leaves.extend(flatten(item, path + (index,), depth + 1))
        return leaves
    return [(path, value)]


def label(path: tuple) -> str:
    """Human-readable path: user.name, items[0].id, or $ for a scalar root."""
    if not path:
        return "$"
    text = ""
    for part in path:
        if isinstance(part, int):
            text += f"[{part}]"
        else:
            text = f"{text}.{part}" if text else str(part)
    return text


def get(root: Any, path: tuple) -> Any:
    node = root
    for part in path:
        node = node[part]
    return node


def set_value(root: Any, path: tuple, value: Any) -> Any:
    """Set one leaf and return the root.

    A scalar root has an empty path; in that case the value itself is returned.
    The caller owns the parsed template, so mutating it is safe.
    """
    if not path:
        return value
    node = root
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    return root


def parse(text: str) -> tuple[Any, str]:
    """Parse JSON text. Returns (value, error)."""
    try:
        return json.loads(text), ""
    except (TypeError, ValueError) as exc:
        return None, str(exc)


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
