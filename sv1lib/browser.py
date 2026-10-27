"""SV1 - real browser. Reflection is a hint; execution is the proof.

One Chromium instance, one context, hooks installed before any page script
runs. Every alert/confirm/prompt is recorded with a per-scan marker, so a hit
proves our payload ran and not the site's own dialog.
"""

from __future__ import annotations

import os
import urllib.parse
from dataclasses import dataclass, field
from html import escape
from typing import Any, Callable

from . import config, net
from .models import CapturedRequest, Explore

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
    ) -> None:
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.ignore_https = ignore_https
        self.base_url = base_url
        self.artifacts = artifacts
        self.timeout_ms = timeout_ms
        self.allows = allows
        self.enabled = False
        self.reason = ""
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None

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
            self._context = self._browser.new_context(
                ignore_https_errors=self.ignore_https,
                viewport={
                    "width": config.BROWSER_VIEWPORT[0],
                    "height": config.BROWSER_VIEWPORT[1],
                },
            )
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
            if self._would_leak_cookie(request):
                route.abort("blockedbyclient")
                return
            headers = self.session_headers_for(request.url)
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
            try:
                route.continue_()
            except Exception:
                pass

    def _would_leak_cookie(self, request) -> bool:
        """A browser cookie ignores ports; do not let it cross the target.

        The limit is specific: cookies imported with --cookie/-H. Cookies the
        target sets during the scan stay in Chromium's jar by design, but an
        imported session cookie must never follow a subresource to another
        port or host. Cancelling the request is the only reliable way to
        remove a Cookie header Chromium adds after route interception.
        """
        if not self.cookies or not self.base_url:
            return False
        if net.same_target(request.url, self.base_url):
            return False
        try:
            headers = dict(request.all_headers())
        except Exception:
            headers = dict(request.headers)
        raw = headers.get("cookie") or headers.get("Cookie") or ""
        if not raw:
            return False
        sent = {
            item.split("=", 1)[0].strip()
            for item in raw.split(";")
            if item.strip()
        }
        return any(str(name) in sent for name in self.cookies)

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

    def visit_point(
        self,
        point,
        payload: str,
        wait_ms: int | None = None,
        shot_path: str = "",
        interact_marker: str = "",
    ) -> Visit:
        """Navigate exactly as the scanner injected, so the browser sees the same bytes."""
        if self._blocks_navigation(point.url):
            return Visit(url=point.url, error=f"outside scan scope: {point.url}")
        target_index = point.position()
        mapping = [
            (name, payload if index == target_index else value)
            for index, (name, value) in enumerate(point.params)
        ]
        if point.method == "GET":
            query = urllib.parse.urlencode(mapping)
            separator = "&" if "?" in point.url else "?"
            return self.visit(
                f"{point.url}{separator}{query}",
                wait_ms,
                shot_path,
                interact_marker=interact_marker,
            )

        if not self.enabled or self._context is None:
            return Visit(url=point.url, error=self.reason or "browser disabled")

        page = self._context.new_page()
        console: list[str] = []
        page.on("console", lambda message: console.append(f"{message.type}: {message.text}"))
        source = getattr(point, "source", "query")
        if source == "query":
            query = urllib.parse.urlencode(mapping)
            separator = "&" if "?" in point.url else "?"
            action = f"{point.url}{separator}{query}"
            form = (
                f'<form method="POST" action="{escape(action)}"></form>'
                "<script>document.forms[0].submit();</script>"
            )
        else:
            inputs = "".join(
                f'<input type="hidden" name="{escape(name)}" value="{escape(str(value))}">'
                for name, value in mapping
            )
            form = (
                f'<form method="POST" action="{escape(point.url)}">{inputs}</form>'
                "<script>document.forms[0].submit();</script>"
            )
        error = ""
        try:
            page.set_content(form)
            page.wait_for_load_state("domcontentloaded", timeout=self.timeout_ms)
        except Exception as exc:
            error = str(exc).splitlines()[0] if str(exc) else "submit failed"
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
        visit = Visit(url=final_url, calls=calls, errors=errors, console=console, screenshot=shot, error=error)
        page.close()
        return visit

    def submit_form(self, page_url: str, form, payload: str, field: str, shot_path: str = "") -> Visit:
        """Fill one field with the payload, leave the rest at their defaults."""
        if not self.enabled or self._context is None:
            return Visit(url=page_url, error=self.reason or "browser disabled")
        action = urllib.parse.urljoin(page_url, form.action or page_url)
        parts = urllib.parse.urlsplit(action)
        if parts.scheme not in ("http", "https") or not net.same_origin(action, page_url):
            return Visit(url=page_url, error="cross-origin form action blocked")
        inputs = []
        for item in form.fields[: config.STORED_MAX_FIELDS]:
            value = payload if item.name == field else (item.value or "test")
            inputs.append(
                f'<input type="hidden" name="{escape(item.name)}" value="{escape(str(value))}">'
            )
        markup = (
            f'<form method="POST" action="{escape(action)}">{"".join(inputs)}</form>'
            "<script>document.forms[0].submit();</script>"
        )
        page = self._context.new_page()
        console: list[str] = []
        page.on("console", lambda message: console.append(f"{message.type}: {message.text}"))
        error = ""
        try:
            page.set_content(markup)
            page.wait_for_load_state("domcontentloaded", timeout=self.timeout_ms)
        except Exception as exc:
            error = str(exc).splitlines()[0] if str(exc) else "submit failed"
        self._settle(page, 400)
        calls, errors = self._read(page)
        shot = self._shot(page, shot_path)
        final_url = page.url
        page.close()
        return Visit(url=final_url, calls=calls, errors=errors, console=console, screenshot=shot, error=error)
