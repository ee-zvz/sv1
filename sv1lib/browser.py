"""SV1 - real browser. Reflection is a hint; execution is the proof.

One Chromium instance, one context, hooks installed before any page script
runs. Every alert/confirm/prompt is recorded with a per-scan marker, so a hit
proves our payload ran and not the site's own dialog.
"""

from __future__ import annotations

import os
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

from . import config, jsonbody, net
from .models import CapturedRequest, Explore

SUBMIT_SCRIPT = """
(payload) => {
  const form = document.createElement('form');
  form.method = 'post';
  form.action = payload.action;
  if (payload.enctype) { form.enctype = payload.enctype; }
  for (const pair of payload.entries) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = pair[0];
    input.value = pair[1];
    form.appendChild(input);
  }
  document.body.appendChild(form);
  form.submit();
}
"""

FETCH_RENDER_SCRIPT = """
async (payload) => {
  const response = await fetch(payload.url, {
    method: payload.method,
    headers: payload.headers,
    body: payload.body,
    credentials: 'include',
    redirect: 'follow'
  });
  const text = await response.text();
  document.open();
  document.write(text);
  document.close();
}
"""

INIT_SCRIPT = """
(() => {
  if (window.__sv1) { return; }
  window.__sv1 = { calls: [], errors: [] };
  for (const name of ['alert', 'confirm', 'prompt']) {
    const original = window[name];
    window[name] = function () {
      let text = '';
      try {
        text = Array.from(arguments).map(String).join(' ');
      } catch (e) {
        text = '';
      }
      window.__sv1.calls.push(name + ':' + text);
      return name === 'confirm' ? false : undefined;
    };
    window[name].__sv1 = original;
  }
  window.addEventListener('error', (event) => {
    window.__sv1.errors.push(String(event.message));
  });
})();
"""


@dataclass
class Visit:
    url: str
    calls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    console: list[str] = field(default_factory=list)
    screenshot: str = ""
    error: str = ""

    def fired(self, marker: str) -> bool:
        if not marker:
            return False
        for call in self.calls:
            if marker in call:
                return True
        return False

    def proof(self, marker: str) -> str:
        for call in self.calls:
            if marker in call:
                return call
        return ""


def available() -> bool:
    """True only when the package AND a chromium build are on disk."""
    try:
        import playwright  # noqa: F401
    except Exception:
        return False

    roots = []
    override = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")
    if override:
        roots.append(override)
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        if local:
            roots.append(os.path.join(local, "ms-playwright"))
    roots.append(os.path.join(os.path.expanduser("~"), ".cache", "ms-playwright"))

    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            names = os.listdir(root)
        except OSError:
            continue
        if any(name.startswith("chromium") for name in names):
            return True
    return False


class Browser:
    """Wraps Playwright so the scanner can ask one question: did it run?"""

    def __init__(
        self,
        headers: dict | None = None,
        cookies: dict | None = None,
        proxy: str = "",
        ignore_https: bool = True,
        base_url: str = "",
        artifacts: str = "",
        timeout_ms: int = config.BROWSER_TIMEOUT_MS,
        allows: Callable[[str], bool] | None = None,
        storage_state: dict | None = None,
    ) -> None:
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.ignore_https = ignore_https
        self.base_url = base_url
        self.artifacts = artifacts
        self.timeout_ms = timeout_ms
        self.allows = allows
        self.storage_state = storage_state
        self.enabled = False
        self.reason = ""
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._extra_headers: dict[str, str] = {}
        self._extra_origin = ""

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> bool:
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            self.reason = "playwright is not installed"
            return False
        try:
            self._pw = sync_playwright().start()
            launch: dict = {"headless": True}
            if self.proxy:
                launch["proxy"] = {"server": self.proxy}
            self._browser = self._pw.chromium.launch(**launch)
            # Session headers are applied per request by the route guard, not
            # on the context. Context-level headers also reach third-party
            # scripts, styles and images, which is exactly the leak we remove.
            context_options: dict = {
                "ignore_https_errors": self.ignore_https,
                "viewport": {
                    "width": config.BROWSER_VIEWPORT[0],
                    "height": config.BROWSER_VIEWPORT[1],
                },
            }
            if self.storage_state:
                context_options["storage_state"] = self.storage_state
            self._context = self._browser.new_context(**context_options)
            self._context.add_init_script(INIT_SCRIPT)
            self._context.route("**/*", self._guard)
            if self.cookies:
                scope_url = (net.origin(self.base_url) or "http://localhost") + "/"
                self._context.add_cookies([
                    {"name": name, "value": str(value), "url": scope_url}
                    for name, value in self.cookies.items()
                ])
            self.enabled = True
            return True
        except Exception as exc:
            self.reason = str(exc).strip().splitlines()[0] if str(exc).strip() else "launch failed"
            self.close()
            return False

    def close(self) -> None:
        for closable in (self._context, self._browser):
            try:
                if closable is not None:
                    closable.close()
            except Exception:
                pass
        try:
            if self._pw is not None:
                self._pw.stop()
        except Exception:
            pass
        self._context = None
        self._browser = None
        self._pw = None
        self.enabled = False

    def import_cookies(self, cookies) -> bool:
        """Copy cookies acquired by the HTTP client into Chromium.

        A login or redirect can set a session cookie while the crawler runs.
        The browser context was created later and does not share the requests
        jar, so replaying only the CLI/imported cookie snapshot would lose the
        live session. Cookies are anchored to the target origin by
        ``net.browser_cookies``; the route guard still enforces port isolation.
        """
        if self._context is None:
            return False
        try:
            records = net.browser_cookies(cookies, self.base_url)
            if records:
                self._context.add_cookies(records)
            return True
        except Exception:
            return False

    def export_state(self) -> dict:
        """Return the live browser state for a caller that wants to save it."""
        if self._context is None:
            return {}
        try:
            state = self._context.storage_state()
        except Exception:
            return {}
        return state if isinstance(state, dict) else {}

    # -- per-visit carriers -------------------------------------------------
    def _override_cookie(self, name: str, value: str, url: str = "") -> list[dict]:
        """Temporarily replace one cookie for a single navigation.

        Cookie XSS is only proven when the browser actually sends the payload.
        The live session must survive the proof, so the old cookie records are
        captured and restored after the visit. The temporary value is scoped to
        the page origin being proved; a server-set domain cookie is not widened.
        """
        if self._context is None:
            return []
        origin = net.origin(url) or net.origin(self.base_url) or ""
        if not origin:
            return []
        scope_url = origin.rstrip("/") + "/"
        if not scope_url:
            return []
        saved: list[dict] = []
        try:
            # Save every same-name cookie, not just this origin's record. The
            # restore path clears by name and must not drop a neighbour origin.
            existing = self._context.cookies()
        except Exception:
            existing = []
        for cookie in existing:
            if str(cookie.get("name", "")) != name:
                continue
            saved.append(dict(cookie))
            try:
                self._context.clear_cookies(
                    name=name,
                    domain=cookie.get("domain"),
                    path=cookie.get("path"),
                )
            except Exception:
                pass
        try:
            self._context.add_cookies([{
                "name": name,
                "value": str(value),
                "url": scope_url,
            }])
        except Exception:
            self._restore_cookie(name, saved)
            return []
        return saved

    def _restore_cookie(self, name: str, saved: list[dict]) -> None:
        if self._context is None:
            return
        try:
            self._context.clear_cookies(name=name)
        except Exception:
            pass
        if not saved:
            return
        try:
            self._context.add_cookies(saved)
        except Exception:
            pass

    # -- scope and headers -------------------------------------------------
    def session_headers_for(self, url: str) -> dict:
        """Operator/imported headers only go to the scan origin."""
        if not self.headers:
            return {}
        if self.base_url and not net.same_target(url, self.base_url):
            return {}
        return dict(self.headers)

    def _blocks_navigation(self, url: str) -> bool:
        """Top-level navigations obey scope; subresources may load normally."""
        if self.allows is not None:
            try:
                return not self.allows(url)
            except Exception:
                return True
        if self.base_url:
            return not net.same_target(url, self.base_url)
        return False

    def _guard(self, route) -> None:
        """Per-request route guard: scope, headers and cookie isolation."""
        try:
            request = route.request
            frame = getattr(request, "frame", None)
            main_frame = frame is not None and getattr(frame, "parent_frame", None) is None
            navigation = False
            try:
                navigation = bool(request.is_navigation_request())
            except Exception:
                navigation = str(getattr(request, "resource_type", "")) == "document"
            if navigation and main_frame and self._blocks_navigation(request.url):
                route.abort("blockedbyclient")
                return
            if self._would_leak_body(request):
                route.abort("blockedbyclient")
                return
            if self._would_leak_cookie(request):
                route.abort("blockedbyclient")
                return
            headers = self.session_headers_for(request.url)
            proof_origin = self._extra_origin or self.base_url
            if self._extra_headers and proof_origin and net.same_target(
                request.url, proof_origin
            ):
                headers.update(self._extra_headers)
            if headers:
                # playwright replaces the header set when the option is used;
                # keep the browser's own headers (cookie, UA, accept) intact.
                try:
                    merged = dict(request.all_headers())
                except Exception:
                    merged = dict(request.headers)
                merged.update({str(name).lower(): str(value) for name, value in headers.items()})
                route.continue_(headers=merged)
            else:
                route.continue_()
        except Exception:
            # A failed guard must not become a cookie leak. Allow the target
            # origin to recover; abort anything that would cross it.
            self._abort_cross_target(route)

    def _abort_cross_target(self, route) -> None:
        try:
            if self.base_url and not net.same_target(route.request.url, self.base_url):
                route.abort("blockedbyclient")
                return
            route.continue_()
        except Exception:
            try:
                route.abort("failed")
            except Exception:
                pass

    def _would_leak_cookie(self, request) -> bool:
        """Any cookie is session material, including one the target just set.

        Chromium scopes cookies by host, not port, so an image on another
        loopback port receives a cookie set by the target page. Imported
        cookies are not special: the browser jar can also hold a server-set
        session. Allow cookies only on the target origin; abort every other
        request that would carry a Cookie header. If headers cannot be read,
        fail closed for the cross-target request.
        """
        if not self.base_url:
            return False
        if net.same_target(request.url, self.base_url):
            return False
        try:
            headers = dict(request.all_headers())
        except Exception:
            return True
        raw = headers.get("cookie") or headers.get("Cookie") or ""
        return bool(raw)

    def _would_leak_body(self, request) -> bool:
        """A cross-target request must not carry a submitted body.

        A page can submit a form to another host, and a 307/308 redirect can
        preserve a POST body. Cookies and Authorization are not the only
        secret in the request: the payload itself may be privileged. Scope can
        authorise the destination, but it does not authorise copying the body
        there. If the body cannot be inspected, fail closed.
        """
        if not self.base_url:
            return False
        if net.same_target(request.url, self.base_url):
            return False
        method = str(getattr(request, "method", "")).upper()
        if method in ("GET", "HEAD", "OPTIONS"):
            return False
        try:
            body = request.post_data
        except Exception:
            return True
        return body is not None and bool(body)

    # -- internals ---------------------------------------------------------
    def _read(self, page) -> tuple[list[str], list[str]]:
        calls: list[str] = []
        errors: list[str] = []
        try:
            frames = list(page.frames)
        except Exception:
            frames = [page]
        for frame in frames:
            try:
                data = frame.evaluate("() => (window.__sv1 ? window.__sv1 : null)")
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            for item in data.get("calls") or []:
                text = str(item)
                if text not in calls:
                    calls.append(text)
            for item in data.get("errors") or []:
                text = str(item)
                if text not in errors:
                    errors.append(text)
        return calls, errors

    def _settle(self, page, wait_ms: int | None) -> None:
        try:
            page.wait_for_timeout(wait_ms if wait_ms is not None else config.BROWSER_SETTLE_MS)
        except Exception:
            pass

    def _shot(self, page, path: str) -> str:
        if not path:
            return ""
        try:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            page.screenshot(path=path, full_page=True)
            return path
        except Exception:
            return ""

    # -- public ------------------------------------------------------------
    def _interact(self, page, marker: str) -> None:
        """Trigger the event an injected handler waits for.

        A payload in href/onmouseover/onfocus is real only when the browser
        runs it. Dispatching the event is the difference between a reflection
        and a proof; it is deliberately limited to elements that contain the
        marker the scanner inserted.
        """
        if not marker:
            return
        script = """
        (marker) => {
          const nodes = Array.from(document.querySelectorAll('*'));
          for (const el of nodes) {
            if (el === document.documentElement || el === document.body) continue;
            const tag = (el.tagName || '').toUpperCase();
            if (['SCRIPT', 'STYLE', 'TITLE', 'META', 'LINK'].includes(tag)) continue;
            let html = '';
            try { html = el.outerHTML || ''; } catch (e) { continue; }
            if (!html.includes(marker)) continue;
            for (const name of ['mouseover', 'mouseenter', 'mousemove']) {
              try {
                el.dispatchEvent(new MouseEvent(name, {
                  bubbles: true, cancelable: true, view: window
                }));
              } catch (e) {}
            }
            try { el.focus(); } catch (e) {}
            for (const name of ['focus', 'focusin']) {
              try {
                el.dispatchEvent(new FocusEvent(name, {bubbles: true}));
              } catch (e) {}
            }
            const href = String(el.href || '');
            if (tag === 'A' && href.startsWith('javascript:')) {
              try { el.click(); } catch (e) {}
            } else if (el.hasAttribute && (
              el.hasAttribute('onclick') ||
              el.hasAttribute('onmousedown') ||
              el.hasAttribute('onmouseup')
            )) {
              try { el.click(); } catch (e) {}
            }
          }
        }
        """
        try:
            frames = list(page.frames)
        except Exception:
            frames = [page]
        for frame in frames:
            try:
                frame.evaluate(script, marker)
            except Exception:
                continue
        page.wait_for_timeout(config.BROWSER_INTERACT_MS)

    def visit(
        self,
        url: str,
        wait_ms: int | None = None,
        shot_path: str = "",
        timeout_ms: int | None = None,
        referer: str = "",
        init_script: str = "",
        messages: list[str] | tuple[str, ...] | None = None,
        interact_marker: str = "",
    ) -> Visit:
        if not self.enabled or self._context is None:
            return Visit(url=url, error=self.reason or "browser disabled")
        if self._blocks_navigation(url):
            return Visit(url=url, error=f"outside scan scope: {url}")
        page = self._context.new_page()
        console: list[str] = []
        page.on("console", lambda message: console.append(f"{message.type}: {message.text}"))
        if init_script:
            try:
                page.add_init_script(init_script)
            except Exception:
                pass
        try:
            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=timeout_ms or self.timeout_ms,
                referer=referer or None,
            )
        except Exception as exc:
            message = str(exc).splitlines()[0] if str(exc) else "navigation failed"
            self._settle(page, 250)
            calls, errors = self._read(page)
            shot = self._shot(page, shot_path)
            visit = Visit(url=url, calls=calls, errors=errors, console=console, screenshot=shot, error=message)
            page.close()
            return visit
        for message in messages or ():
            try:
                page.evaluate("(msg) => window.postMessage(msg, '*')", message)
            except Exception:
                pass
        if interact_marker:
            self._interact(page, interact_marker)
        self._settle(page, wait_ms)
        calls, errors = self._read(page)
        shot = self._shot(page, shot_path)
        final_url = url
        try:
            final_url = page.url
        except Exception:
            pass
        visit = Visit(
            url=final_url,
            calls=calls,
            errors=errors,
            console=console,
            screenshot=shot,
        )
        page.close()
        return visit

    def explore(self, url: str, wait_ms: int | None = None) -> Explore:
        """Render a page like a user, keep the xhr calls and the links it builds."""
        if not self.enabled or self._context is None:
            return Explore(url=url, error=self.reason or "browser disabled")
        if self._blocks_navigation(url):
            return Explore(url=url, error=f"outside scan scope: {url}")
        page = self._context.new_page()
        xhr: list[str] = []
        captured: list[CapturedRequest] = []

        def note(request) -> None:
            try:
                if request.resource_type not in ("xhr", "fetch"):
                    return
                url = request.url
                xhr.append(url)
                method = str(getattr(request, "method", "GET") or "GET").upper()
                try:
                    body = str(getattr(request, "post_data", "") or "")
                except Exception:
                    body = ""
                if not body:
                    try:
                        buffer = request.post_data_buffer
                        if buffer:
                            body = bytes(buffer).decode("utf-8", "replace")
                    except Exception:
                        pass
                headers = getattr(request, "headers", {}) or {}
                content_type = ""
                for key, value in headers.items():
                    if str(key).lower() == "content-type":
                        content_type = str(value)
                        break
                captured.append(
                    CapturedRequest(
                        url=url,
                        method=method,
                        body=body if len(body) <= config.SPA_MAX_BODY_BYTES else "",
                        content_type=content_type,
                    )
                )
            except Exception:
                pass

        page.on("request", note)
        error = ""
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        except Exception as exc:
            error = str(exc).splitlines()[0] if str(exc) else "navigation failed"
        self._settle(page, wait_ms)
        anchors: list[str] = []
        try:
            found = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            anchors = [str(item) for item in found if item]
        except Exception:
            pass
        final_url = url
        try:
            final_url = page.url
        except Exception:
            pass
        try:
            page.close()
        except Exception:
            pass
        return Explore(
            url=final_url,
            xhr=xhr,
            anchors=anchors,
            error=error,
            requests=captured,
        )

    def _open_target(self, page, url: str) -> str:
        """Put the page on the target origin before submitting a form.

        A form injected into ``about:blank`` is cross-site from the target's
        point of view: Chromium sends ``Origin: null`` and omits cookies in
        some policies.  Navigating to the endpoint first gives the replay the
        Origin, Referer and cookie context a real browser would have.  If the
        endpoint only accepts POST, the origin root is a safe second choice.
        """
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            return ""
        except Exception as exc:
            first = str(exc).splitlines()[0] if str(exc) else "navigation failed"
        root = (net.origin(url) or "").rstrip("/") + "/"
        if root and root != url:
            try:
                page.goto(root, wait_until="domcontentloaded", timeout=self.timeout_ms)
                return ""
            except Exception:
                pass
        return first

    def _form_entries(self, point, mapping: list[tuple[str, str]]) -> list[list[str]]:
        return [[str(name), str(value)] for name, value in mapping]

    def visit_point(
        self,
        point,
        payload: str,
        wait_ms: int | None = None,
        shot_path: str = "",
        interact_marker: str = "",
    ) -> Visit:
        """Navigate exactly as the scanner injected, so the browser sees the same bytes."""
        target_index = point.position()
        mapping = [
            (name, payload if index == target_index else value)
            for index, (name, value) in enumerate(point.params)
        ]
        source = getattr(point, "source", "query")
        guard_url = net.path_url(point.url, mapping) if source == "path" else point.url
        if self._blocks_navigation(guard_url):
            return Visit(url=point.url, error=f"outside scan scope: {guard_url}")

        if source == "header":
            header_name = str(point.param)
            self._extra_headers = {header_name: str(payload)}
            self._extra_origin = net.origin(point.url) or self.base_url
            try:
                return self.visit(
                    point.url,
                    wait_ms,
                    shot_path,
                    interact_marker=interact_marker,
                )
            finally:
                self._extra_headers = {}
                self._extra_origin = ""

        if source == "cookie":
            cookie_name = str(point.param)
            saved = self._override_cookie(
                cookie_name, str(payload), url=point.url,
            )
            try:
                return self.visit(
                    point.url,
                    wait_ms,
                    shot_path,
                    interact_marker=interact_marker,
                )
            finally:
                self._restore_cookie(cookie_name, saved)

        if point.method == "GET":
            if source == "path":
                url = net.path_url(point.url, mapping)
            else:
                query = urllib.parse.urlencode(mapping)
                separator = "&" if "?" in point.url else "?"
                url = f"{point.url}{separator}{query}"
            return self.visit(
                url,
                wait_ms,
                shot_path,
                interact_marker=interact_marker,
            )

        if not self.enabled or self._context is None:
            return Visit(url=point.url, error=self.reason or "browser disabled")

        page = self._context.new_page()
        console: list[str] = []
        page.on("console", lambda message: console.append(f"{message.type}: {message.text}"))
        target_url = net.path_url(point.url, mapping) if source == "path" else point.url
        error = self._open_target(page, target_url)
        if error:
            page.close()
            return Visit(url=point.url, error=error)

        if source in ("query", "form", "multipart"):
            action = point.url
            entries = [] if source == "query" else self._form_entries(point, mapping)
            if source == "query":
                query = urllib.parse.urlencode(mapping)
                separator = "&" if "?" in action else "?"
                action = f"{action}{separator}{query}"
            enctype = ""
            if source == "multipart":
                enctype = "multipart/form-data"
            elif source == "form" and "multipart" in (point.content_type or "").lower():
                enctype = "multipart/form-data"
            elif source == "form" and "text/plain" in (point.content_type or "").lower():
                enctype = "text/plain"
            try:
                if point.method == "POST":
                    page.evaluate(SUBMIT_SCRIPT, {
                        "action": action,
                        "enctype": enctype,
                        "entries": entries,
                    })
                else:
                    page.evaluate("""
                    async (payload) => {
                      let body;
                      if (payload.enctype === 'multipart/form-data' && payload.entries.length) {
                        body = new FormData();
                        for (const pair of payload.entries) { body.append(pair[0], pair[1]); }
                      } else {
                        body = new URLSearchParams(payload.entries).toString();
                      }
                      const response = await fetch(payload.action, {
                        method: payload.method,
                        headers: payload.enctype === 'text/plain'
                          ? {'Content-Type': 'text/plain'} : {},
                        body: body,
                        credentials: 'include',
                        redirect: 'follow'
                      });
                      const text = await response.text();
                      document.open(); document.write(text); document.close();
                    }
                    """, {
                        "action": action,
                        "method": point.method,
                        "enctype": enctype,
                        "entries": entries,
                    })
                page.wait_for_load_state("domcontentloaded", timeout=self.timeout_ms)
            except Exception as exc:
                error = str(exc).splitlines()[0] if str(exc) else "submit failed"
        elif source in ("json", "raw"):
            headers = {
                "Content-Type": point.content_type or (
                    "application/json" if source == "json" else "application/octet-stream"
                ),
                "Accept": "application/json",
            }
            body = ""
            if source == "json":
                template, parse_error = jsonbody.parse(getattr(point, "body", ""))
                if parse_error:
                    document = {name: value for name, value in mapping}
                else:
                    try:
                        document = jsonbody.set_value(
                            template, tuple(getattr(point, "path", ()) or ()), payload
                        )
                    except (KeyError, IndexError, TypeError):
                        document = {name: value for name, value in mapping}
                body = jsonbody.dumps(document)
            else:
                body = getattr(point, "body", "") or payload
                if "*" in body:
                    body = body.replace("*", payload, 1)
            try:
                page.evaluate(FETCH_RENDER_SCRIPT, {
                    "url": point.url,
                    "method": point.method,
                    "headers": headers,
                    "body": body,
                })
                page.wait_for_load_state("domcontentloaded", timeout=self.timeout_ms)
            except Exception as exc:
                error = str(exc).splitlines()[0] if str(exc) else "fetch failed"
        elif source == "path":
            try:
                url = net.path_url(point.url, mapping)
                page.evaluate(FETCH_RENDER_SCRIPT, {
                    "url": url,
                    "method": point.method,
                    "headers": {},
                    "body": None,
                })
                page.wait_for_load_state("domcontentloaded", timeout=self.timeout_ms)
            except Exception as exc:
                error = str(exc).splitlines()[0] if str(exc) else "fetch failed"
        else:
            error = f"browser proof unavailable for {source} inputs"

        if interact_marker:
            self._interact(page, interact_marker)
        self._settle(page, wait_ms)
        calls, errors = self._read(page)
        shot = self._shot(page, shot_path)
        final_url = point.url
        try:
            final_url = page.url
        except Exception:
            pass
        visit = Visit(url=final_url, calls=calls, errors=errors, console=console,
                      screenshot=shot, error=error)
        page.close()
        return visit

    def submit_form(self, page_url: str, form, payload: str, field: str,
                    shot_path: str = "") -> Visit:
        """Fill one field with the payload, leave the rest at their defaults.

        The form is injected into the real page instead of an ``about:blank``
        document, so Chromium sends the target Origin/Referer and any CSRF
        cookie the page already holds.  Hidden fields, including the token,
        are preserved with the values the application rendered.
        """
        if not self.enabled or self._context is None:
            return Visit(url=page_url, error=self.reason or "browser disabled")
        action = urllib.parse.urljoin(page_url, form.action or page_url)
        parts = urllib.parse.urlsplit(action)
        if parts.scheme not in ("http", "https") or not net.same_origin(action, page_url):
            return Visit(url=page_url, error="cross-origin form action blocked")
        entries = []
        for item in form.fields[: config.STORED_MAX_FIELDS]:
            value = payload if item.name == field else (item.value or "test")
            entries.append([str(item.name), str(value)])
        enctype = (getattr(form, "enctype", "") or "").strip().lower()
        if enctype not in ("multipart/form-data", "text/plain"):
            enctype = ""
        page = self._context.new_page()
        console: list[str] = []
        page.on("console", lambda message: console.append(f"{message.type}: {message.text}"))
        error = self._open_target(page, page_url)
        if not error:
            try:
                page.evaluate(SUBMIT_SCRIPT, {
                    "action": action,
                    "enctype": enctype,
                    "entries": entries,
                })
                page.wait_for_load_state("domcontentloaded", timeout=self.timeout_ms)
            except Exception as exc:
                error = str(exc).splitlines()[0] if str(exc) else "submit failed"
        self._settle(page, 400)
        calls, errors = self._read(page)
        shot = self._shot(page, shot_path)
        final_url = page.url
        page.close()
        return Visit(url=final_url, calls=calls, errors=errors, console=console,
                     screenshot=shot, error=error)
