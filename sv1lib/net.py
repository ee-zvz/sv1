"""SV1 - HTTP client. Throttled, thread-safe, never raises at the caller."""

from __future__ import annotations

import json
import shlex
import threading
import time
import urllib.parse

import requests

from . import config
from .models import Response


class RateLimiter:
    """Spaces requests evenly. Adapts to 429/503 without losing the floor."""

    def __init__(self, rps: float) -> None:
        self._base = (1.0 / rps) if rps and rps > 0 else 0.0
        self._interval = self._base
        self._lock = threading.Lock()
        self._next_at = 0.0
        self._healthy = 0

    @property
    def interval(self) -> float:
        with self._lock:
            return self._interval

    @property
    def base_interval(self) -> float:
        return self._base

    def wait(self) -> None:
        with self._lock:
            interval = self._interval
            if interval <= 0.0:
                return
            now = time.monotonic()
            if now < self._next_at:
                delay = self._next_at - now
                self._next_at += interval
            else:
                delay = 0.0
                self._next_at = now + interval
        if delay > 0.0:
            time.sleep(delay)

    def penalize(self) -> None:
        """A server pushed back. Double the spacing, up to the cap."""
        if self._base <= 0.0:
            return
        with self._lock:
            cap = self._base * config.RATE_MAX_MULTIPLIER
            self._interval = min(cap, max(self._base, self._interval * config.RATE_PENALTY_FACTOR))
            self._healthy = 0

    def reward(self) -> None:
        """Healthy responses slowly restore the requested rate."""
        with self._lock:
            if self._base <= 0.0 or self._interval <= self._base:
                return
            self._healthy += 1
            if self._healthy < config.RATE_RECOVERY_AFTER:
                return
            self._healthy = 0
            self._interval = max(self._base, self._interval / config.RATE_RECOVERY_FACTOR)

    def defer(self, seconds: float) -> None:
        """Honor Retry-After without letting it stall the whole scan."""
        if not seconds or seconds <= 0:
            return
        capped = min(float(seconds), config.RATE_MAX_DEFER)
        with self._lock:
            self._next_at = max(self._next_at, time.monotonic() + capped)



class Client:
    """One session, one cookie jar, one rate budget."""

    def __init__(
        self,
        timeout: float = config.DEFAULT_TIMEOUT,
        rps: float = config.DEFAULT_RPS,
        headers: dict | None = None,
        cookies: dict | None = None,
        verify: bool = True,
        proxy: str = "",
    ) -> None:
        self.timeout = timeout
        self.verify = verify
        self.limiter = RateLimiter(rps)
        self.session = requests.Session()
        self.session.headers.update(config.DEFAULT_HEADERS)
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        self._stat_lock = threading.Lock()
        self.requests_sent = 0
        self.errors = 0

    # -- counters ----------------------------------------------------------
    def _tick(self) -> None:
        with self._stat_lock:
            self.requests_sent += 1

    def _fail(self) -> None:
        with self._stat_lock:
            self.errors += 1

    # -- core --------------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        params: dict | list | None = None,
        data: dict | list | str | None = None,
        allow_redirects: bool = True,
        headers: dict | None = None,
        cookies: dict | None = None,
        files: dict | list | None = None,
    ) -> Response:
        method = method.upper()
        started = time.monotonic()
        last_error = ""
        for attempt in range(config.MAX_RETRIES):
            self.limiter.wait()
            self._tick()
            try:
                raw = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    headers=headers,
                    cookies=cookies,
                    files=files,
                    timeout=self.timeout,
                    verify=self.verify,
                    allow_redirects=allow_redirects,
                    stream=True,
                )
                try:
                    body = raw.raw.read(config.MAX_BODY_BYTES, decode_content=True) or b""
                    status = raw.status_code
                    final_url = raw.url
                    response_headers = dict(raw.headers)
                    retry_after = raw.headers.get("Retry-After", "")
                finally:
                    raw.close()
                text = self._decode(body, raw)
                self._adapt(status, retry_after)
                return Response(
                    status=status,
                    text=text,
                    elapsed=time.monotonic() - started,
                    url=final_url,
                    headers=response_headers,
                )
            except requests.RequestException as exc:
                last_error = str(exc)
                if attempt < config.MAX_RETRIES - 1:
                    time.sleep(0.35 * (attempt + 1))
        self._fail()
        return Response(
            status=0,
            text="",
            elapsed=time.monotonic() - started,
            url=url,
            headers={},
            error=last_error,
        )

    def _adapt(self, status: int, retry_after: str) -> None:
        """Rate-limit feedback belongs in one place, not in every scanner."""
        if status in (429, 503):
            self.limiter.penalize()
            try:
                seconds = float(retry_after) if retry_after else 0.0
            except (TypeError, ValueError):
                seconds = 0.0
            self.limiter.defer(seconds)
        elif status > 0:
            self.limiter.reward()

    @staticmethod
    def _decode(body: bytes, raw: requests.Response) -> str:
        declared = (raw.encoding or "").lower()
        candidates = []
        if declared and declared not in ("iso-8859-1", "latin-1"):
            candidates.append(declared)
        try:
            guessed = raw.apparent_encoding
        except Exception:
            guessed = None
        if guessed:
            candidates.append(guessed)
        candidates.extend(["utf-8", "cp1256", "cp1252"])
        for encoding in candidates:
            try:
                return body.decode(encoding, errors="strict")
            except (LookupError, UnicodeDecodeError):
                continue
        return body.decode("utf-8", errors="replace")

    # -- helpers -----------------------------------------------------------
    def send(self, point, value: str) -> Response:
        """Fire one injection point with `value` in place of the real input.

        A list of pairs, not a dict: repeated names are real server inputs and
        collapsing them changes the request the scanner claims to test.
        """
        target_index = point.position()
        mapping = [
            (name, value if index == target_index else original)
            for index, (name, original) in enumerate(point.params)
        ]
        source = getattr(point, "source", "query")
        if source == "header":
            return self.request("GET", point.url, headers=dict(mapping))
        if source == "cookie":
            return self.request("GET", point.url, cookies=dict(mapping))
        if source == "multipart":
            files = [(name, (None, str(item))) for name, item in mapping]
            return self.request(point.method, point.url, files=files)
        if source == "json":
            payload = {}
            for name, item in mapping:
                payload[name] = item
            return self.request(
                point.method,
                point.url,
                data=json.dumps(payload),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
        if source == "query" or point.method == "GET":
            return self.request(point.method, point.url, params=mapping)
        return self.request("POST", point.url, data=mapping)

    def fetch(self, url: str) -> Response:
        return self.request("GET", url)

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass


def with_scheme(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if "://" not in url:
        return "http://" + url
    return url


def same_origin(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def is_skippable(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path.lower()
    return path.endswith(config.SKIP_EXTENSIONS)


def curl(point, value: str) -> str:
    """Build a replay command from the exact point and payload.

    Boolean findings carry two branches separated by `|`; the first branch is
    the request that actually demonstrates the difference.
    """
    if "|" in (value or ""):
        value = value.split("|", 1)[0].strip()
    target_index = point.position()
    mapping = [
        (name, value if index == target_index else original)
        for index, (name, original) in enumerate(point.params)
    ]
    source = getattr(point, "source", "query")
    parts = ["curl", "-sS"]
    if source == "header":
        for name, item in mapping:
            parts.extend(["-H", shlex.quote(f"{name}: {item}")])
        parts.append(shlex.quote(point.url))
        return " ".join(parts)
    if source == "cookie":
        jar = "; ".join(f"{name}={item}" for name, item in mapping)
        parts.extend(["-b", shlex.quote(jar)])
        parts.append(shlex.quote(point.url))
        return " ".join(parts)
    if source == "multipart":
        parts.extend(["-X", point.method])
        for name, item in mapping:
            parts.extend(["-F", shlex.quote(f"{name}={item}")])
        parts.append(shlex.quote(point.url))
        return " ".join(parts)
    if source == "json":
        payload = json.dumps({name: item for name, item in mapping})
        parts.extend(["-X", point.method])
        parts.extend(["-H", shlex.quote("Content-Type: application/json")])
        parts.extend(["--data-raw", shlex.quote(payload)])
        parts.append(shlex.quote(point.url))
        return " ".join(parts)
    if source == "query" or point.method == "GET":
        query = urllib.parse.urlencode(mapping)
        separator = "&" if "?" in point.url else "?"
        if point.method != "GET":
            parts.extend(["-X", point.method])
        parts.append(shlex.quote(f"{point.url}{separator}{query}"))
        return " ".join(parts)
    parts.extend(["-X", "POST"])
    for name, item in mapping:
        parts.extend(["--data-urlencode", shlex.quote(f"{name}={item}")])
    parts.append(shlex.quote(point.url))
    return " ".join(parts)
