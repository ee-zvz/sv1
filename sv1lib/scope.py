"""SV1 - scope file. Fail closed: no rule means no request."""

from __future__ import annotations

import fnmatch
import urllib.parse
from dataclasses import dataclass


class ScopeError(Exception):
    """The scope file is missing, empty or malformed."""


@dataclass(frozen=True)
class Rule:
    scheme: str
    host: str
    path: str

    def matches(self, url: str) -> bool:
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            return False
        if self.scheme != "*" and parts.scheme.lower() != self.scheme:
            return False
        netloc = parts.netloc.lower()
        hostname = (parts.hostname or "").lower()
        candidate = netloc if ":" in self.host else hostname
        if not fnmatch.fnmatchcase(candidate, self.host):
            return False
        path = parts.path or "/"
        return fnmatch.fnmatchcase(path, self.path)


class Scope:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = tuple(rules)

    def __len__(self) -> int:
        return len(self.rules)

    def allows(self, url: str) -> bool:
        return any(rule.matches(url) for rule in self.rules)

    @classmethod
    def load(cls, path: str) -> "Scope":
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                lines = handle.readlines()
        except OSError as exc:
            raise ScopeError(f"cannot read scope file: {exc}") from exc

        rules: list[Rule] = []
        for number, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rules.append(_parse(line))
            except ValueError as exc:
                raise ScopeError(f"{path}:{number}: {exc}") from exc
        if not rules:
            raise ScopeError(f"{path}: no rules")
        return cls(rules)


def _parse(line: str) -> Rule:
    if "://" in line:
        parts = urllib.parse.urlsplit(line)
        host = parts.netloc.lower()
        if not host:
            raise ValueError("rule has no host")
        scheme = parts.scheme.lower() or "*"
        path = parts.path or "*"
    else:
        scheme = "*"
        if "/" in line:
            host, tail = line.split("/", 1)
            path = "/" + tail
        else:
            host, path = line, "*"
        host = host.strip().lower()
        if not host:
            raise ValueError("rule has no host")
        if not path:
            path = "*"
    if any(ch.isspace() for ch in host):
        raise ValueError("rule has whitespace in the host")
    return Rule(scheme=scheme, host=host, path=path or "*")
