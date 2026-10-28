"""SV1 - HTTP client. Throttled, thread-safe, never raises at the caller."""

from __future__ import annotations

import re
import shlex
import threading
import time
import urllib.parse
from typing import Callable

import requests

from . import config, jsonbody
from .models import Response

# A redirect may keep these headers. Everything else came from the operator or
# the imported session and must not follow the scan to another origin.
SAFE_REDIRECT_HEADERS = frozenset({"accept", "content-type"})


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
    """One cookie jar, one rate budget, one requests session per thread.

    ``base_url`` is the scan origin. Session headers and the cookie jar only
    travel there; a redirect to another origin is refused unless a ``scope``
    predicate explicitly allows the hop, and even then the session material is
    stripped. Without a scope predicate the default allowlist is the target
    origin, not the whole internet.
    """

    def __init__(
        self,
        timeout: float = config.DEFAULT_TIMEOUT,
        rps: float = config.DEFAULT_RPS,
        headers: dict | None = None,
        cookies: dict | None = None,
        verify: bool = True,
        proxy: str = "",
        base_url: str = "",
        scope: Callable[[str], bool] | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        self.timeout = timeout
        self.verify = verify
        if not verify:
            try:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        self.limiter = RateLimiter(rps)
        self.base_url = base_url
        self.scope = scope
        self.session_headers = dict(headers or {})
        self.headers = dict(config.DEFAULT_HEADERS)
        self.headers.update(self.session_headers)
        self.cookies = requests.cookies.RequestsCookieJar()
        if cookies:
            host = urllib.parse.urlsplit(base_url).hostname if base_url else ""
            for name, value in cookies.items():
                # A host-only jar entry keeps imported cookies away from
                # third-party redirects; the cookie spec itself ignores ports.
                if host:
                    self.cookies.set(name, value, domain=host, path="/")
                else:
                    self.cookies.set(name, value)
        self.proxies: dict[str, str] = {}
        if proxy:
            self.proxies = {"http": proxy, "https": proxy}
        self._local = threading.local()
        self._session_lock = threading.Lock()
        self._sessions: list[requests.Session] = []
        self.session = self._session()
        self._stat_lock = threading.Lock()
        self.requests_sent = 0
        self.errors = 0

    # -- sessions ----------------------------------------------------------
    def _new_session(self) -> requests.Session:
        session = requests.Session()
        # Operator headers are merged per request, not baked into the session:
        # a redirect to another host must be able to drop them.
        session.headers.update(config.DEFAULT_HEADERS)
        session.cookies = self.cookies
        if self.proxies:
            session.proxies.update(self.proxies)
        return session

    def _session(self) -> requests.Session:
        """A session is an adapter pool, not a shared mutable request object."""
        session = getattr(self._local, "session", None)
        if session is None:
            session = self._new_session()
            self._local.session = session
            with self._session_lock:
                self._sessions.append(session)
        return session

    # -- scope -------------------------------------------------------------
    def _allows(self, url: str) -> bool:
        if self.scope is not None:
            try:
                return bool(self.scope(url))
            except Exception:
                return False
        if self.base_url:
            return same_target(url, self.base_url)
        return True

    def _may_send_session(self, url: str) -> bool:
        """Session headers and cookies belong to the scan origin, not to scope.

        A scope file authorises reachability. It does not turn an imported
        Authorization header into a credential for every host in the file.
        """
        if self.base_url:
            return same_target(url, self.base_url)
        return True

    def _hop_headers(self, url: str, headers: dict | None) -> dict:
        extra = dict(headers or {})
        if not self._may_send_session(url):
            return {
                name: value for name, value in extra.items()
                if name.lower() in SAFE_REDIRECT_HEADERS
            }
        merged = dict(self.session_headers)
        merged.update(extra)
        return merged

    def _context_headers(self, method: str, url: str, headers: dict) -> dict:
        """Add the headers a browser sends with an unsafe same-origin request.

        CSRF middleware often checks ``Origin`` (and sometimes ``Referer``)
        before it looks at the token.  ``requests`` does not add either header,
        so a scan that preserved the hidden token still looked like a
        cross-site request.  Only the target origin is decorated, and an
        explicit header point keeps the value the operator asked us to test.
        """
        if method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
            return headers
        if not self.base_url or not self.same_target_origin(url):
            return headers
        merged = dict(headers)
        merged.setdefault("Origin", origin(url))
        merged.setdefault("Referer", self.base_url)
        return merged

    def same_target_origin(self, url: str) -> bool:
        """Public spelling of the send boundary, used by callers and tests."""
        return self._may_send_session(url)

    def repro_headers(self) -> dict:
        """Headers that belong in a reproduction command, not scanner noise."""
        skip = {
            "cookie", "host", "content-length", "connection",
            "proxy-connection", "transfer-encoding", "accept-encoding",
        }
        return {
            str(name): str(value)
            for name, value in self.session_headers.items()
            if str(name).lower() not in skip
        }

    def repro_cookies(self) -> dict:
        """Target-scoped cookies for ``curl -b``; never another host's jar."""
        if not self.base_url:
            return {}
        try:
            host = (urllib.parse.urlsplit(self.base_url).hostname or "").lower()
        except ValueError:
            return {}
        found: dict[str, str] = {}
        for cookie in self.cookies:
            domain = (cookie.domain or "").lstrip(".").lower()
            if host != domain and not host.endswith("." + domain):
                continue
            found[str(cookie.name)] = str(cookie.value)
        return found

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
        if not self._allows(url):
            return Response(
                status=0,
                text="",
                elapsed=0.0,
                url=url,
                headers={},
                error=f"outside scan scope: {url}",
            )
        last_error = ""
        attempts = config.MAX_RETRIES if method in config.RETRY_METHODS else 1
        for attempt in range(attempts):
            try:
                return self._follow(
                    method, url, params, data, allow_redirects,
                    headers, cookies, files, started,
                )
            except requests.RequestException as exc:
                last_error = str(exc)
                if attempt < attempts - 1:
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

    def _follow(
        self,
        method: str,
        url: str,
        params: dict | list | None,
        data: dict | list | str | None,
        allow_redirects: bool,
        headers: dict | None,
        cookies: dict | None,
        files: dict | list | None,
        started: float,
    ) -> Response:
        """Send the request and walk redirects one hop at a time.

        ``requests`` follows redirects inside the adapter, where the client
        cannot see the next host before the bytes leave. Doing it here keeps
        every hop behind the scope check and makes header stripping explicit.
        """
        current_url = url
        current_method = method
        current_params = params
        current_data = data
        current_files = files
        current_headers = dict(headers or {})
        current_cookies = cookies
        hops = 0

        while True:
            session = self._session()
            hop_headers = self._hop_headers(current_url, current_headers)
            if self._may_send_session(current_url):
                hop_headers = self._context_headers(
                    current_method, current_url, hop_headers
                )
            prepared = session.prepare_request(requests.Request(
                method=current_method,
                url=current_url,
                params=current_params,
                data=current_data,
                headers=hop_headers,
                cookies=current_cookies,
                files=current_files,
            ))
            if not self._may_send_session(current_url):
                # CookieJar ignores ports and can match a host-only entry on a
                # different port. Remove the prepared header for this hop.
                prepared.headers.pop("Cookie", None)
            elif current_cookies is not None:
                self._override_cookies(prepared, current_cookies)

            self.limiter.wait()
            self._tick()
            raw = session.send(
                prepared,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=False,
                stream=True,
            )
            try:
                status = raw.status_code
                response_headers = dict(raw.headers)
                retry_after = raw.headers.get("Retry-After", "")
                location = raw.headers.get("Location", "")
                body = raw.raw.read(config.MAX_BODY_BYTES, decode_content=True) or b""
                landed = raw.url or current_url
            finally:
                raw.close()

            self._adapt(status, retry_after)
            if not (allow_redirects and status in config.REDIRECT_STATUSES and location):
                return Response(
                    status=status,
                    text=self._decode(body, raw),
                    elapsed=time.monotonic() - started,
                    url=landed,
                    headers=response_headers,
                )

            next_url = urllib.parse.urljoin(landed, location.strip())
            next_url = urllib.parse.urldefrag(next_url)[0]
            scheme = urllib.parse.urlsplit(next_url).scheme.lower()
            if scheme not in ("http", "https"):
                return self._blocked(
                    next_url, response_headers, started,
                    f"redirect scheme blocked: {next_url}",
                )
            if hops >= config.MAX_REDIRECTS:
                return self._blocked(
                    next_url, response_headers, started,
                    f"redirect limit reached ({config.MAX_REDIRECTS})",
                )
            if not self._allows(next_url):
                return self._blocked(
                    next_url, response_headers, started,
                    f"redirect outside scan scope: {next_url}",
                )

            cross_origin = not self._may_send_session(next_url)
            next_method, next_data, next_files = self._redirect_method(
                status, current_method, current_data, current_files,
            )
            if cross_origin and (next_data is not None or next_files is not None):
                return self._blocked(
                    next_url, response_headers, started,
                    f"cross-origin redirect would forward request body: {next_url}",
                )
            current_method, current_data, current_files = (
                next_method, next_data, next_files,
            )
            current_params = None
            current_cookies = None
            if cross_origin:
                current_headers = {
                    name: value for name, value in current_headers.items()
                    if name.lower() in SAFE_REDIRECT_HEADERS
                }
            hops += 1
            current_url = next_url

    @staticmethod
    def _blocked(url: str, headers: dict, started: float, error: str) -> Response:
        """A refused hop is not a transport error; the URL is the evidence."""
        return Response(
            status=0,
            text="",
            elapsed=time.monotonic() - started,
            url=url,
            headers=headers,
            error=error,
        )

    @staticmethod
    def _redirect_method(
        status: int,
        method: str,
        data: dict | list | str | None,
        files: dict | list | None,
    ) -> tuple[str, dict | list | str | None, dict | list | None]:
        """Mirror the browser rules: 303 is GET, 301/302 turn POST into GET."""
        if status == 303 or (status in (301, 302) and method == "POST"):
            return "GET", None, None
        return method, data, files

    def _override_cookies(self, prepared: requests.PreparedRequest,
                          overrides: dict) -> None:
        """Apply a cookie point without duplicating a name from the jar.

        ``requests`` merges the explicit dict and the jar, so a host-scoped
        ``sid=abc`` plus an injected ``sid=PAY`` becomes ``sid=abc; sid=PAY``.
        The target should see one value: the one the scanner claims to test.
        """
        jar = requests.cookies.merge_cookies(
            requests.cookies.RequestsCookieJar(), self.cookies
        )
        for cookie in list(jar):
            if cookie.name in overrides:
                try:
                    jar.clear(cookie.domain, cookie.path, cookie.name)
                except KeyError:
                    continue
        for name, value in overrides.items():
            jar.set_cookie(requests.cookies.create_cookie(name=name, value=str(value)))
        prepared.headers.pop("Cookie", None)
        header = requests.cookies.get_cookie_header(jar, prepared)
        if header:
            prepared.headers["Cookie"] = header

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
        if source == "path":
            return self.request(point.method, path_url(point.url, mapping))
        if source == "header":
            return self.request("GET", point.url, headers=dict(mapping))
        if source == "cookie":
            return self.request("GET", point.url, cookies=dict(mapping))
        if source == "multipart":
            files = [(name, (None, str(item))) for name, item in mapping]
            return self.request(point.method, point.url, files=files)
        if source == "json":
            body = getattr(point, "body", "")
            path = tuple(getattr(point, "path", ()) or ())
            payload: object
            if body:
                template, error = jsonbody.parse(body)
                if error:
                    payload = {name: item for name, item in mapping}
                else:
                    try:
                        payload = jsonbody.set_value(template, path, value)
                    except (KeyError, IndexError, TypeError):
                        payload = {name: item for name, item in mapping}
            else:
                payload = {name: item for name, item in mapping}
            return self.request(
                point.method,
                point.url,
                data=jsonbody.dumps(payload),
                headers={
                    "Content-Type": getattr(point, "content_type", "")
                    or "application/json",
                    "Accept": "application/json",
                },
            )
        if source == "raw":
            body = getattr(point, "body", "") or value
            if "*" in body:
                body = body.replace("*", value, 1)
            return self.request(
                point.method,
                point.url,
                data=body,
                headers={
                    "Content-Type": getattr(point, "content_type", "")
                    or "application/octet-stream",
                },
            )
        if source == "query" or point.method == "GET":
            return self.request(point.method, point.url, params=mapping)
        return self.request(point.method, point.url, data=mapping)

    def fetch(self, url: str) -> Response:
        return self.request("GET", url)

    def close(self) -> None:
        with self._session_lock:
            sessions = list(self._sessions)
            self._sessions.clear()
        for session in sessions:
            try:
                session.close()
            except Exception:
                pass
        self._local.session = None


def with_scheme(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if "://" not in url:
        return "http://" + url
    return url


def same_origin(a: str, b: str) -> bool:
    """Compare scheme, host and effective port; ignore path and credentials."""
    first = _origin(a)
    return (
        first is not None
        and first[0] in ("http", "https")
        and bool(first[1])
        and first == _origin(b)
    )


def _origin(url: str) -> tuple[str, str, int | None] | None:
    try:
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return scheme, host, port


def origin(url: str) -> str:
    """Return scheme://host[:port], never credentials embedded in netloc."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if not parts.scheme or not host:
        return ""
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme}://{host}{f':{port}' if port is not None else ''}"


def browser_cookies(
    jar: requests.cookies.RequestsCookieJar,
    base_url: str,
) -> list[dict]:
    """Translate target cookies from the HTTP jar into Playwright records.

    ``requests`` and Chromium keep separate cookie jars. A login performed by
    the HTTP client would otherwise disappear when the browser tries to prove
    the finding. Only cookies that belong to the scan host are imported, and
    every record is anchored to the target origin by URL, so a server-set
    domain cookie cannot widen browser scope.
    """
    if not base_url:
        return []
    try:
        parts = urllib.parse.urlsplit(base_url)
        host = (parts.hostname or "").lower().rstrip(".")
        scheme = parts.scheme.lower()
    except ValueError:
        return []
    if scheme not in ("http", "https") or not host:
        return []
    origin_url = origin(base_url)
    if not origin_url:
        return []

    records: list[dict] = []
    now = time.time()
    for cookie in jar:
        domain = (cookie.domain or "").lstrip(".").lower().rstrip(".")
        if not domain:
            continue
        if host != domain and not host.endswith("." + domain):
            continue
        name = str(cookie.name or "")
        value = str(cookie.value or "")
        if not name or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name + value):
            continue
        expired = False
        if cookie.expires is not None:
            try:
                expired = float(cookie.expires) < now
            except (TypeError, ValueError):
                expired = False
        if expired:
            continue
        if cookie.secure and scheme != "https":
            continue
        path = str(cookie.path or "/")
        if not path.startswith("/"):
            path = "/" + path
        path = urllib.parse.quote(path, safe="/%!$&'()*+,;=:@-._~")
        record: dict = {
            "name": name,
            "value": value,
            "url": f"{origin_url}{path}",
        }
        if cookie.secure:
            record["secure"] = True
        if cookie.has_nonstandard_attr("HttpOnly"):
            record["httpOnly"] = True
        records.append(record)
    return records


def same_target(a: str, b: str) -> bool:
    """Same origin, plus the one canonical hop worth trusting by default.

    Plain HTTP to HTTPS on the same host and standard ports is how most sites
    answer a bare hostname. It changes no host and only adds TLS, so following
    it without a scope file is safe. Any other host or port change is not.
    """
    if same_origin(a, b):
        return True
    first, second = _origin(a), _origin(b)
    if first is None or second is None:
        return False
    return (
        first[0] == "http"
        and second[0] == "https"
        and first[1] == second[1]
        and bool(first[1])
        and first[2] == 80
        and second[2] == 443
    )


def is_skippable(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path.lower()
    return path.endswith(config.SKIP_EXTENSIONS)


def path_url(template: str, mapping: list[tuple[str, str]]) -> str:
    """Replace every OpenAPI-style path placeholder with an encoded value."""
    url = template
    for name, item in mapping:
        url = url.replace("{" + str(name) + "}", urllib.parse.quote(str(item), safe=""))
    # A placeholder the spec did not describe must not leak a literal brace
    # into the request line. It is unknown, so leave it as a harmless value.
    return re.sub(r"\{[^{}/]+\}", "1", url)


def _curl_headers(parts: list[str], headers: dict | None,
                  skip: tuple[str, ...] = ("cookie", "host", "content-length",
                                           "connection", "proxy-connection",
                                           "transfer-encoding", "accept-encoding")) -> None:
    for name, value in (headers or {}).items():
        if str(name).lower() in skip:
            continue
        parts.extend(["-H", shlex.quote(f"{name}: {value}")])


def _curl_cookies(parts: list[str], cookies: dict | None) -> None:
    if not cookies:
        return
    jar = "; ".join(f"{name}={value}" for name, value in cookies.items())
    parts.extend(["-b", shlex.quote(jar)])


def repro_headers(point, headers: dict | None, url: str = "") -> dict:
    """Session headers plus the browser context an unsafe request needs."""
    merged = {str(name): str(value) for name, value in (headers or {}).items()}
    target = url or point.url
    if point.method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        merged.setdefault("Origin", origin(target))
        merged.setdefault("Referer", target)
    return merged


def curl(point, value: str, headers: dict | None = None,
         cookies: dict | None = None) -> str:
    """Build a replay command from the exact point and payload.

    Boolean findings carry two branches separated by `|`; the first branch is
    the request that actually demonstrates the difference.  Optional session
    headers and target cookies are added so a replay of an authenticated form
    is usable, while a cookie point still overrides the jar value.
    """
    if "|" in (value or ""):
        value = value.split("|", 1)[0].strip()
    target_index = point.position()
    mapping = [
        (name, value if index == target_index else original)
        for index, (name, original) in enumerate(point.params)
    ]
    source = getattr(point, "source", "query")
    concrete_url = path_url(point.url, mapping) if source == "path" else point.url
    session_headers = repro_headers(point, headers, concrete_url)
    session_cookies = dict(cookies or {})
    parts = ["curl", "-sS"]
    if source == "path":
        parts.extend(["-X", point.method])
        _curl_headers(parts, session_headers)
        _curl_cookies(parts, session_cookies)
        parts.append(shlex.quote(concrete_url))
        return " ".join(parts)
    if source == "header":
        headers_here = dict(session_headers)
        headers_here.update({name: item for name, item in mapping})
        _curl_headers(parts, headers_here)
        _curl_cookies(parts, session_cookies)
        parts.append(shlex.quote(point.url))
        return " ".join(parts)
    if source == "cookie":
        jar = dict(session_cookies)
        jar.update({name: item for name, item in mapping})
        _curl_cookies(parts, jar)
        _curl_headers(parts, session_headers)
        parts.append(shlex.quote(point.url))
        return " ".join(parts)
    if source == "multipart":
        parts.extend(["-X", point.method])
        _curl_headers(parts, session_headers)
        _curl_cookies(parts, session_cookies)
        for name, item in mapping:
            parts.extend(["-F", shlex.quote(f"{name}={item}")])
        parts.append(shlex.quote(point.url))
        return " ".join(parts)
    if source == "json":
        body = getattr(point, "body", "")
        path = tuple(getattr(point, "path", ()) or ())
        payload: object
        if body:
            template, error = jsonbody.parse(body)
            if error:
                payload = {name: item for name, item in mapping}
            else:
                try:
                    payload = jsonbody.set_value(template, path, value)
                except (KeyError, IndexError, TypeError):
                    payload = {name: item for name, item in mapping}
        else:
            payload = {name: item for name, item in mapping}
        parts.extend(["-X", point.method])
        _curl_headers(parts, session_headers)
        parts.extend(["-H", shlex.quote(
            f"Content-Type: {getattr(point, 'content_type', '') or 'application/json'}"
        )])
        _curl_cookies(parts, session_cookies)
        parts.extend(["--data-raw", shlex.quote(jsonbody.dumps(payload))])
        parts.append(shlex.quote(point.url))
        return " ".join(parts)
    if source == "raw":
        body = getattr(point, "body", "") or value
        if "*" in body:
            body = body.replace("*", value, 1)
        parts.extend(["-X", point.method])
        _curl_headers(parts, session_headers)
        parts.extend(["-H", shlex.quote(
            f"Content-Type: {getattr(point, 'content_type', '') or 'application/octet-stream'}"
        )])
        _curl_cookies(parts, session_cookies)
        parts.extend(["--data-raw", shlex.quote(body)])
        parts.append(shlex.quote(point.url))
        return " ".join(parts)
    if source == "query" or point.method == "GET":
        query = urllib.parse.urlencode(mapping)
        separator = "&" if "?" in point.url else "?"
        if point.method != "GET":
            parts.extend(["-X", point.method])
        _curl_headers(parts, session_headers)
        _curl_cookies(parts, session_cookies)
        parts.append(shlex.quote(f"{point.url}{separator}{query}"))
        return " ".join(parts)
    parts.extend(["-X", point.method])
    _curl_headers(parts, session_headers)
    _curl_cookies(parts, session_cookies)
    for name, item in mapping:
        parts.extend(["--data-urlencode", shlex.quote(f"{name}={item}")])
    parts.append(shlex.quote(point.url))
    return " ".join(parts)


def repro_curl(client, point, value: str) -> str:
    """Use the live session for a command that an operator can actually run."""
    headers = client.repro_headers() if hasattr(client, "repro_headers") else {}
    cookies = client.repro_cookies() if hasattr(client, "repro_cookies") else {}
    return curl(point, value, headers, cookies)
