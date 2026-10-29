"""SV1 - data carriers. No behaviour, no I/O."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True)
class FormField:
    name: str
    value: str
    type: str


@dataclass
class Form:
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)
    enctype: str = ""


@dataclass
class Page:
    url: str
    status: int
    html: str
    links: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)


@dataclass(frozen=True)
class InjectionPoint:
    """A single mutable input on a single endpoint.

    param_index keeps duplicate names honest: ?id=1&id=2 is two points, and
    the verifier must replace the same occurrence the scanner did.

    body/path carry a JSON or raw body template. A nested JSON point owns the
    whole document and only one leaf path; rebuilding the document on every
    request keeps sibling fields exactly as the application sent them.
    """

    url: str
    method: str                 # "GET" | "POST" | "PUT" | ...
    params: tuple               # tuple[(name, value), ...] - untouched inputs
    param: str                  # which key gets the payload
    source: str                 # "query" | "form" | "multipart" | "path" | "header" | "cookie" | "json" | "raw"
    param_index: int = 0        # which occurrence of param gets the payload
    body: str = ""              # JSON/raw body template, when source needs it
    content_type: str = ""      # request content type for body-based points
    path: tuple = ()            # nested JSON path, e.g. ("user", "name")

    def key(self) -> tuple:
        # A GET form is sent on the query string. When the page URL already
        # exposes the same parameter, scanning both would send the same
        # request twice and produce duplicate findings.
        source = self.source
        if self.method.upper() == "GET" and source in ("query", "form"):
            source = "query"
        # Two raw/JSON points can share method, URL and parameter name while
        # carrying different templates. The body is the request, so it belongs
        # in the identity. Hash it instead of keeping a 4 MB string in a set.
        body = ""
        content_type = ""
        if self.body:
            body = hashlib.sha1(
                self.body.encode("utf-8", "replace")
            ).hexdigest()
            content_type = self.content_type
        return (
            self.method,
            self.url,
            source,
            self.param,
            self.param_index,
            self.path,
            body,
            content_type,
        )

    def position(self) -> int:
        """Absolute index in params for occurrence param_index of param."""
        wanted = max(0, int(self.param_index))
        seen = 0
        for index, (name, _value) in enumerate(self.params):
            if name != self.param:
                continue
            if seen == wanted:
                return index
            seen += 1
        return -1

    def original(self) -> str:
        """The untouched value at the exact occurrence the scanner injects."""
        position = self.position()
        if 0 <= position < len(self.params):
            return self.params[position][1]
        return ""

    def label(self) -> str:
        return f"{self.method} {self.url} [{self.param}]"


@dataclass
class Response:
    status: int
    text: str
    elapsed: float
    url: str
    headers: dict
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.error == "" and self.status > 0


@dataclass
class CapturedRequest:
    """One xhr/fetch call seen by Chromium, including its wire body."""

    url: str
    method: str = "GET"
    body: str = ""
    content_type: str = ""


@dataclass
class Explore:
    """One rendered page: where it landed, what it fetched, what it links to."""

    url: str
    xhr: list[str] = field(default_factory=list)
    anchors: list[str] = field(default_factory=list)
    error: str = ""
    requests: list[CapturedRequest] = field(default_factory=list)


FINDING_META = {
    "XSS": (
        "CWE-79",
        "A05:2025 Injection",
        "Encode output for the exact HTML, attribute, URL or JavaScript context; "
        "use a framework auto-escaper and a restrictive Content-Security-Policy.",
    ),
    "SQLI": (
        "CWE-89",
        "A05:2025 Injection",
        "Use parameterized queries or prepared statements; never concatenate "
        "request data into SQL, and validate the type before the query.",
    ),
    "SSRF": (
        "CWE-918",
        "A01:2025 Broken Access Control",
        "Allowlist destination schemes, hosts and ports; resolve and re-check "
        "after redirects, and block link-local/cloud metadata ranges.",
    ),
}


@dataclass
class Finding:
    kind: str                   # "XSS" | "SQLI" | "SSRF"
    severity: str               # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url: str
    method: str
    param: str
    payload: str
    confidence: str
    evidence: str
    technique: str = ""         # reflected/attr, error, boolean, time ...
    detail: str = ""
    artifact: str = ""          # screenshot proving execution
    curl: str = ""              # exact reproduction command
    data: dict[str, str] = field(default_factory=dict)  # dumped values (user/db/tables)
    alternatives: list[str] = field(default_factory=list)  # other confirmed payloads
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""

    def __post_init__(self) -> None:
        meta = FINDING_META.get((self.kind or "").upper())
        if meta is None:
            return
        if not self.cwe:
            self.cwe = meta[0]
        if not self.owasp:
            self.owasp = meta[1]
        if not self.remediation:
            self.remediation = meta[2]

    def to_row(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "url": self.url,
            "method": self.method,
            "param": self.param,
            "payload": self.payload,
            "confidence": self.confidence,
            "technique": self.technique,
            "evidence": self.evidence.replace("\n", " ")[:400],
            "curl": self.curl,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "remediation": self.remediation,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if not payload.get("alternatives"):
            payload.pop("alternatives", None)
        return payload


@dataclass
class ScanStats:
    requests: int = 0
    pages: int = 0
    points: int = 0
    errors: int = 0
    confirmed: int = 0              # browser/OOB proof, no HTTP replay needed
    replayed: int = 0               # reproduced by the HTTP replay pass
    unverified: int = 0
    fixed: int = 0
    retest: bool = False
    started: float = 0.0
    finished: float = 0.0

    @property
    def verified(self) -> int:
        """Backwards-compatible total; the two proof paths stay visible."""
        return self.confirmed + self.replayed

    @property
    def duration(self) -> float:
        return max(0.0, self.finished - self.started)
