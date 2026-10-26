"""SV1 - data carriers. No behaviour, no I/O."""

from __future__ import annotations

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
    """A single mutable input on a single endpoint."""

    url: str
    method: str                 # "GET" | "POST"
    params: tuple               # tuple[(name, value), ...] - untouched inputs
    param: str                  # which key gets the payload
    source: str                 # "query" | "form" | "header" | "cookie" | "json"

    def key(self) -> tuple:
        return (self.method, self.url, self.param)

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
class Explore:
    """One rendered page: where it landed, what it fetched, what it links to."""

    url: str
    xhr: list[str] = field(default_factory=list)
    anchors: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class Finding:
    kind: str                   # "XSS" | "SQLI"
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
    data: dict[str, str] = field(default_factory=dict)  # dumped values (user/db/tables)

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
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanStats:
    requests: int = 0
    pages: int = 0
    points: int = 0
    errors: int = 0
    verified: int = 0
    unverified: int = 0
    fixed: int = 0
    retest: bool = False
    started: float = 0.0
    finished: float = 0.0

    @property
    def duration(self) -> float:
        return max(0.0, self.finished - self.started)
