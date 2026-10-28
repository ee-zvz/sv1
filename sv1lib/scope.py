"""SV1 - scope file. Fail closed: no rule means no request."""

from __future__ import annotations

import fnmatch
import ipaddress
import posixpath
import urllib.parse
from dataclasses import dataclass

DEFAULT_PORTS = {"http": 80, "https": 443}


class ScopeError(Exception):
    """The scope file is missing, empty or malformed."""


def _canonical_path(value: str) -> str:
    """Normalize a URL path or glob before matching.

    Scope is a security boundary, not a display string. Decoding dot segments
    before a comparison stops ``/app/../admin`` from looking like an ``/app/*``
    request on the wire, and collapsing duplicate slashes and backslashes
    closes the same trick on servers that normalize them. Control characters
    make the path unmatched instead of trying to guess how a server reads it.
    """
    path = value or "/"
    if path == "*":
        return path
    if not path.startswith("/"):
        path = "/" + path
    path = path.replace("\\", "/")
    for _ in range(3):
        decoded = urllib.parse.unquote(path)
        if decoded == path:
            break
        path = decoded
    path = path.replace("\\", "/")
    lowered = path.lower()
    if any(marker in lowered for marker in ("%2e", "%2f", "%5c")):
        # The server may decode once more than we did. Refuse the ambiguity.
        return ""
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        return ""
    normalized = posixpath.normpath(path)
    if normalized in ("", "."):
        return "/"
    return "/" + normalized.lstrip("/")


def _canonical_host(value: str) -> str:
    """Lower-case, decode and IDNA-normalize a host before matching."""
    host = (value or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        host = urllib.parse.unquote(host)
    except Exception:
        return ""
    host = host.rstrip(".")
    if not host or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in host):
        return ""
    if any(ch.isspace() for ch in host):
        return ""
    if any(ch in host for ch in "/\\@?#"):
        return ""
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return host


def _validate_host(value: str) -> str:
    host = _canonical_host(value)
    if not host:
        raise ValueError("rule has no host")
    if any(ch.isspace() for ch in host):
        raise ValueError("rule has whitespace in the host")
    if any(ch in host for ch in "/\\@?#"):
        raise ValueError("rule has an invalid host")
    return host


def _parse_port(value: str) -> int:
    raw = (value or "").strip()
    if not raw.isdigit():
        raise ValueError("port must be a number from 1 to 65535")
    port = int(raw)
    if port < 1 or port > 65535:
        raise ValueError("port must be a number from 1 to 65535")
    return port


def _split_authority(value: str) -> tuple[str, int | None]:
    """Split ``host[:port]`` without confusing an IPv6 address for a port."""
    text = (value or "").strip()
    if not text:
        raise ValueError("rule has no host")
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ValueError("rule has an unterminated IPv6 host")
        host = _validate_host(text[1:end])
        rest = text[end + 1:]
        if not rest:
            return host, None
        if not rest.startswith(":"):
            raise ValueError("rule has invalid text after the IPv6 host")
        return host, _parse_port(rest[1:])
    if text.count(":") > 1:
        try:
            ipaddress.ip_address(text)
        except ValueError as exc:
            raise ValueError("rule has an invalid IPv6 host") from exc
        return _validate_host(text), None
    if ":" in text:
        host, raw_port = text.rsplit(":", 1)
        return _validate_host(host), _parse_port(raw_port)
    return _validate_host(text), None


@dataclass(frozen=True)
class Rule:
    """One scope line.

    ``port`` is ``None`` for a bare host, which keeps the historical "any
    port" rule. A URL rule without an explicit port gets the scheme's default
    port, so ``https://example.com/`` does not silently authorise ``:8443``.
    """

    scheme: str
    host: str
    path: str
    port: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "scheme", (self.scheme or "*").lower())
        host = _canonical_host(self.host)
        if self.port is None and host.count(":") == 1:
            name, raw_port = host.rsplit(":", 1)
            if raw_port.isdigit():
                host = _canonical_host(name)
                object.__setattr__(self, "port", _parse_port(raw_port))
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "path", _canonical_path(self.path))

    def matches(self, url: str) -> bool:
        try:
            parts = urllib.parse.urlsplit(url)
            scheme = parts.scheme.lower()
            if scheme not in ("http", "https"):
                return False
            hostname = _canonical_host(parts.hostname or "")
            if not hostname:
                return False
            port = parts.port
        except ValueError:
            return False
        if self.scheme != "*" and scheme != self.scheme:
            return False
        if self.port is not None:
            effective = port if port is not None else DEFAULT_PORTS[scheme]
            if effective != self.port:
                return False
        if not fnmatch.fnmatchcase(hostname, self.host):
            return False
        path = _canonical_path(parts.path or "/")
        if not path:
            return False
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
        try:
            parts = urllib.parse.urlsplit(line)
        except ValueError as exc:
            raise ValueError("rule is not a valid URL") from exc
        scheme = (parts.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError("rule scheme must be http or https")
        host = _validate_host(parts.hostname or "")
        try:
            port = parts.port
        except ValueError as exc:
            raise ValueError("rule has an invalid port") from exc
        if port is None:
            port = DEFAULT_PORTS[scheme]
        path = _canonical_path(parts.path or "*")
        if not path:
            raise ValueError("rule has an invalid path")
        return Rule(scheme=scheme, host=host, path=path, port=port)

    scheme = "*"
    if "/" in line:
        authority, tail = line.split("/", 1)
        path_text = "/" + tail
    else:
        authority, path_text = line, "*"
    host, port = _split_authority(authority)
    path = _canonical_path(path_text or "*")
    if not path:
        raise ValueError("rule has an invalid path")
    return Rule(scheme=scheme, host=host, path=path, port=port)
