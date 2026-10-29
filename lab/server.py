"""SV1 test lab - deliberately vulnerable local target. Localhost only."""

from __future__ import annotations

import html
import json
import random
import re
import secrets
import string
import sys
import time
import urllib.request
from email.parser import BytesParser
from email.policy import default as email_default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, unquote_plus, urlsplit

PORT = 8099

INDEX = """<!doctype html>
<html><head><title>lab</title></head>
<body>
  <h1>lab index</h1>
  <p><a href="/search?q=hello">search</a></p>
  <p><a href="/item?id=1">item</a></p>
  <p><a href="/account?id=1">account</a></p>
  <p><a href="/safe?q=hello">safe</a></p>
  <p><a href="/noisy?q=hello">noisy</a></p>
  <p><a href="/js?q=hello">js</a></p>
  <p><a href="/attr?q=hello">attr</a></p>
  <p><a href="/dom">dom</a></p>
  <p><a href="/guestbook">guestbook</a></p>
  <p><a href="/union?q=1">union</a></p>
  <p><a href="/waf?q=1">waf</a></p>
  <p><a href="/hidden">hidden</a></p>
  <p><a href="/js-endpoints">js api</a></p>
  <p><a href="/spa">spa</a></p>
  <p><a href="/xhr-post">xhr post</a></p>
  <p><a href="/xhr-form">xhr form</a></p>
  <p><a href="/csrf">csrf form</a></p>
  <p><a href="/external">external js</a></p>
  <p><a href="/upload">upload</a></p>
  <p><a href="/profile">profile</a></p>
  <p><a href="/blind">blind</a></p>
  <p><a href="/fetch?url=http://127.0.0.1:8099/">fetch</a></p>
  <p><a href="/catalog/42?ref=home">catalog path</a></p>
  <p><a href="/header-xss">header xss</a></p>
  <p><a href="/cookie-xss">cookie xss</a></p>
  <form action="/feedback" method="post">
    <input type="text" name="name" value="">
    <input type="text" name="message" value="">
    <input type="submit" value="send">
  </form>
</body></html>"""

GUESTBOOK: list[tuple[str, str]] = []
BLIND: list[str] = []
PROFILE: dict[str, str] = {"name": "guest"}
CSRF_TOKEN = "sv1-csrf-token"
LOGIN_TOKEN = "sv1-login-token"
LOGIN_USER = "sv1operator"
LOGIN_PASSWORD = "sv1-lab-password"
SESSIONS: set[str] = set()


def _session_id(cookie_header: str) -> str:
    """Return a valid sid from a Cookie header, or an empty string."""
    for part in (cookie_header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == "sid" and value in SESSIONS:
            return value
    return ""


def _looks_sql(value: str) -> bool:
    """A single quote is the error probe; XSS payloads also contain quotes."""
    text = (value or "").strip()
    if text in ("'", '"'):
        return True
    return bool(re.search(r"(?i)\b(union\s+select|sleep\s*\(|extractvalue\s*\()", text))


def _multipart_fields(content_type: str, raw: bytes) -> dict[str, list[str]]:
    """Small test-only multipart reader; file parts are deliberately ignored."""
    message = BytesParser(policy=email_default).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1", "replace")
        + b"\r\nMIME-Version: 1.0\r\n\r\n" + raw
    )
    fields: dict[str, list[str]] = {}
    for part in message.iter_parts():
        if part.get_content_disposition() != "form-data":
            continue
        name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        if isinstance(name, tuple):
            name = name[2]
        if not name or filename:
            continue
        value = part.get_content()
        fields.setdefault(str(name), []).append(str(value))
        if len(fields) >= 40:
            break
    return fields

MYSQL_ERROR = (
    "<br />You have an error in your SQL syntax; check the manual that "
    "corresponds to your MySQL server version for the right syntax to use "
    "near '&#039;' at line 1"
)

CHROME = (
    "<nav><a href='/'>home</a> <a href='/search?q=hello'>search</a> "
    "<a href='/account?id=1'>account</a> <a href='/noisy?q=hello'>dash</a></nav>"
    "<main><h1>acme portal</h1>"
    "<p>this portal tracks orders, invoices and support tickets for every "
    "customer in the region. the layout is stable, the content is not: "
    "session tokens, csrf values and counters rotate on every single request "
    "because the frontend renders them server side without caching.</p>"
    "<p>orders placed before friday ship the same week. invoices older than "
    "ninety days are archived automatically. support tickets are answered in "
    "the order they arrive, unless the customer is on the priority list.</p>"
    "<p>if a page looks different on every refresh that is expected, not a bug. "
    "compare the structure, never the bytes.</p></main>"
)


def _noise() -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(24))


def _is_false(value: str) -> bool:
    """The lab plays database: a false logical branch returns no rows."""
    squeezed = value.replace(" ", "")
    return (
        "1=2" in squeezed
        or "'1'='2" in squeezed
        or '"1"="2' in squeezed
        or "'2'" in squeezed
    )


UNION_PAGE = (
    "<html><body><h1>item</h1>"
    "<p>name: widget</p><p>price: 42</p><p>stock: yes</p></body></html>"
)

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "sv1 lab", "version": "1.0"},
    "servers": [{"url": "/"}],
    "paths": {
        "/api/fetch": {
            "get": {
                "summary": "fetch one item",
                "parameters": [
                    {"name": "id", "in": "query",
                     "schema": {"type": "integer", "default": 1}},
                    {"name": "name", "in": "query",
                     "schema": {"type": "string", "default": "test"}},
                ],
            }
        },
        "/api/item": {
            "post": {
                "summary": "create one item",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "id": {"type": "integer", "default": 1},
                                    "q": {"type": "string", "default": "test"},
                                },
                            }
                        }
                    }
                },
            }
        },
        "/api/path/{id}": {
            "get": {
                "summary": "path parameter injection",
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "string", "default": "1"}},
                ],
            }
        },
    },
}


def _split_exprs(text: str) -> list[str]:
    """Split a select list on top level commas only. Quotes and parens hide commas."""
    pieces: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in ("'", '"'):
            quote = char
            current.append(char)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            pieces.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        pieces.append("".join(current).strip())
    return pieces


def _eval_sql(expr: str) -> str:
    """Fake a few functions so union extraction reads something instead of NULL."""
    low = expr.lower()
    if re.fullmatch(r"\d+", expr.strip()):
        return expr.strip()
    if "group_concat" in low and "information_schema.tables" in low:
        value = "users,notes,accounts"
    elif "current_user()" in low:
        value = "sv1@localhost"
    elif "database()" in low:
        value = "sv1lab"
    elif "version()" in low:
        value = "8.0.36-lab"
    else:
        found = re.search(r"'([^']*)'", expr)
        value = found.group(1) if found else ""
    if "sv1[" in low:
        return "sv1[" + value + "]sv1"
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "LabServer/1.0"

    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def _send(self, body: str, status: int = 200,
              content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8", errors="replace")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)

        if parts.path == "/":
            body = INDEX
            if _session_id(self.headers.get("Cookie", "")):
                body = body.replace(
                    '  <p><a href="/blind">blind</a></p>',
                    '  <p><a href="/private?q=hello">private</a></p>\n'
                    '  <p><a href="/blind">blind</a></p>',
                )
            self._send(body)
            return

        if parts.path == "/login":
            self._send(
                "<html><body><h1>login</h1>"
                "<form method='post' action='/login'>"
                f"<input type='hidden' name='csrf' value='{LOGIN_TOKEN}'>"
                "<input type='text' name='username' value=''>"
                "<input type='password' name='password' value=''>"
                "<button type='submit'>sign in</button>"
                "</form></body></html>"
            )
            return

        if parts.path == "/private":
            if not _session_id(self.headers.get("Cookie", "")):
                self._send(
                    "<html><body><h1>login required</h1></body></html>",
                    403,
                )
                return
            term = query.get("q", [""])[0]
            self._send(
                "<html><body><h1>private</h1>"
                f"<div>{term}</div></body></html>"
            )
            return

        if parts.path == "/robots.txt":
            host = self.headers.get("Host") or f"127.0.0.1:{PORT}"
            self._send(
                "User-agent: *\nDisallow:\n"
                f"Sitemap: http://{host}/sitemap.xml\n",
                content_type="text/plain; charset=utf-8",
            )
            return

        if parts.path == "/sitemap.xml":
            host = self.headers.get("Host") or f"127.0.0.1:{PORT}"
            self._send(
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f"<url><loc>http://{host}/orphan?q=hello</loc></url>"
                "</urlset>",
                content_type="application/xml; charset=utf-8",
            )
            return

        if parts.path == "/orphan":
            term = query.get("q", [""])[0]
            self._send(
                "<html><body><h1>orphan</h1>"
                f"<div>{term}</div></body></html>"
            )
            return

        if parts.path == "/search":                       # reflective xss + sqli error
            term = query.get("q", [""])[0]
            if "'" in term and "<" not in term:
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(f"<html><body><h1>results</h1><div>{term}</div></body></html>")
            return

        if parts.path.startswith("/catalog/"):            # path segment xss
            ident = unquote(parts.path[len("/catalog/"):])
            self._send(
                "<html><body><h1>catalog</h1>"
                f"<div>item: {ident}</div></body></html>"
            )
            return

        if parts.path == "/item":                         # boolean based sqli
            ident = query.get("id", ["1"])[0]
            if _is_false(ident):
                self._send("<html><body><h1>item</h1><p>not found</p></body></html>")
                return
            self._send(
                "<html><body><h1>item</h1>"
                "<p>name: widget</p><p>price: 42</p><p>stock: yes</p>"
                "<p>description: a fine widget for fine people</p></body></html>"
            )
            return

        if parts.path == "/safe":                         # encoded reflection only
            term = query.get("q", [""])[0]
            escaped = (
                term.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;")
            )
            self._send(f"<html><body><h1>safe</h1><div>{escaped}</div></body></html>")
            return

        if parts.path == "/noisy":                        # volatile page, no reflection
            self._send(
                "<html><body>" + CHROME +
                f"<div id='nonce'>{_noise()}</div>"
                f"<div id='clock'>{time.time()}</div>"
                "</body></html>"
            )
            return

        if parts.path == "/account":                      # volatile page + boolean sqli
            ident = query.get("id", ["1"])[0]
            body = "<html><body>" + CHROME + f"<div id='nonce'>{_noise()}</div>"
            if _is_false(ident):
                body += "<h2>account</h2><p>no records found for this account</p>"
            else:
                body += (
                    "<h2>account</h2><p>name: widget</p>"
                    "<p>balance: 42.00 USD</p><p>status: active since 2019</p>"
                )
            self._send(body + "</body></html>")
            return

        if parts.path == "/js":                           # reflection inside a JS string
            term = query.get("q", [""])[0]
            self._send(
                "<html><body><h1>js</h1>"
                f'<script>var name = "{term}"; document.title = name;</script>'
                "</body></html>"
            )
            return

        if parts.path == "/attr":                         # reflection inside a quoted attribute
            term = query.get("q", [""])[0]
            self._send(
                "<html><body><h1>attr</h1>"
                f"<input type='text' value='{term}' name='v'>"
                "</body></html>"
            )
            return

        if parts.path == "/dom":                          # dom xss: hash -> innerHTML
            self._send(
                "<html><body><h1>dom</h1><div id='out'></div>"
                "<script>"
                "var raw = decodeURIComponent(location.hash.slice(1));"
                "if (raw) { document.getElementById('out').innerHTML = raw; }"
                "</script></body></html>"
            )
            return

        if parts.path == "/guestbook":                    # stored xss
            rows = "".join(f"<li><b>{name}</b>: {text}</li>" for name, text in GUESTBOOK[-20:])
            self._send(
                "<html><body><h1>guestbook</h1>"
                f"<ul>{rows}</ul>"
                "<form method='post' action='/guestbook'>"
                "<input type='text' name='name' value=''>"
                "<input type='text' name='message' value=''>"
                "<input type='submit' value='sign'>"
                "</form></body></html>"
            )
            return

        if parts.path == "/union":                        # union based sqli
            term = query.get("q", ["1"])[0]
            upper = term.upper()
            if "ORDER BY" in upper:
                match = re.search(r"ORDER BY\s+(\d+)", upper)
                columns = int(match.group(1)) if match else 0
                if 1 <= columns <= 3:
                    self._send(UNION_PAGE)
                else:
                    self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            cut = upper.find("UNION SELECT")
            if cut >= 0:
                tail = term[cut + len("UNION SELECT"):]
                tail = re.split(r"--|#", tail)[0]
                exprs = _split_exprs(tail)
                if len(exprs) != 3:
                    self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                    return
                literal = ""
                for piece in exprs:
                    value = _eval_sql(piece)
                    if value:
                        literal = value
                        break
                self._send(
                    "<html><body><h1>item</h1>"
                    f"<p>name: {literal}</p><p>price: 42</p><p>stock: yes</p>"
                    "</body></html>"
                )
                return
            if "'" in term or '"' in term:
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(UNION_PAGE)
            return

        if parts.path == "/header-xss":                   # header reflected into html
            forwarded = self.headers.get("X-Forwarded-For", "")
            self._send(
                "<html><body><h1>header xss</h1>"
                f"<div>{forwarded}</div></body></html>"
            )
            return

        if parts.path == "/header":                       # header based sqli
            forwarded = self.headers.get("X-Forwarded-For", "")
            if "'" in forwarded or '"' in forwarded:
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(
                "<html><body><h1>header</h1>"
                f"<p>client: {forwarded}</p><p>name: widget</p></body></html>"
            )
            return

        if parts.path == "/cookie-xss":                   # cookie reflected into html
            raw_cookie = self.headers.get("Cookie", "")
            prefs = ""
            for part in raw_cookie.split(";"):
                name, _, value = part.strip().partition("=")
                if name == "prefs":
                    prefs = unquote(value)
                    break
            self._send(
                "<html><body><h1>cookie xss</h1>"
                f"<div>{prefs}</div></body></html>"
            )
            return

        if parts.path == "/cookie":                       # cookie based sqli
            raw_cookie = self.headers.get("Cookie", "")
            if "'" in raw_cookie or '"' in raw_cookie:
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send("<html><body><h1>cookie</h1><p>welcome back</p></body></html>")
            return

        if parts.path == "/waf":                          # stupid filter: blocks spaces
            term = query.get("q", [""])[0]
            if " " in unquote_plus(parts.query):
                self._send("<html><body><h1>blocked</h1><p>request rejected</p></body></html>", 403)
                return
            lowered = term.lower()
            if "'" in term and any(word in lowered for word in ("and", "union", "extractvalue")):
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(f"<html><body><h1>search</h1><div>{term}</div></body></html>")
            return

        if parts.path == "/spa":                           # xhr only visible after render
            self._send(
                "<html><body><h1>spa</h1><div id='out'></div>"
                "<script>"
                "const params = new URLSearchParams({ id: '1', name: 'test' });"
                "fetch('/api/spa?' + params.toString())"
                ".then(r => r.text())"
                ".then(t => { document.getElementById('out').innerHTML = t; });"
                "const link = new URL('/dynamic', location.origin);"
                "link.searchParams.set('id', '1');"
                "link.searchParams.set('name', 'test');"
                "const a = document.createElement('a');"
                "a.href = link.toString(); a.textContent = 'dynamic';"
                "document.body.appendChild(a);"
                "</script></body></html>"
            )
            return

        if parts.path == "/api/spa":                       # target of the rendered call
            ident = query.get("id", ["1"])[0]
            name = query.get("name", [""])[0]
            if "'" in ident or '"' in ident:
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(f"<html><body><h1>spa api</h1><div>{name}</div></body></html>")
            return

        if parts.path == "/dynamic":                       # rendered anchor target
            ident = query.get("id", ["1"])[0]
            name = query.get("name", [""])[0]
            if "'" in ident or '"' in ident:
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(f"<html><body><h1>dynamic</h1><div>{name}</div></body></html>")
            return

        if parts.path == "/openapi.json":
            self._send(json.dumps(OPENAPI_SPEC))
            return

        if parts.path == "/hidden":                       # hidden parameter discovery
            debug = query.get("debug", [""])[0]
            export = query.get("export", [""])[0]
            block = ""
            if debug:
                block += (
                    "<section id='debug'><h2>debug panel</h2>" + CHROME +
                    f"<p>debug value: {debug}</p></section>"
                )
            if export:
                block += (
                    "<section id='export'><h2>export</h2>" + CHROME +
                    f"<p>export value: {export}</p></section>"
                )
            self._send("<html><body><h1>hidden</h1><p>a quiet page</p>" + block + "</body></html>")
            return

        if parts.path == "/js-endpoints":                 # endpoints only visible in js
            self._send(
                "<html><body><h1>js api</h1><div id='out'></div>"
                "<script>"
                "fetch('/api/fetch?id=1&name=test')"
                ".then(r => r.text())"
                ".then(t => { document.getElementById('out').textContent = t; });"
                "</script></body></html>"
            )
            return

        if parts.path == "/api/fetch":                    # target of the js call
            ident = query.get("id", ["1"])[0]
            name = query.get("name", [""])[0]
            if "'" in ident or '"' in ident:
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(f"<html><body><h1>api</h1><div>{name}</div></body></html>")
            return

        if parts.path == "/upload":                       # multipart form
            self._send(
                "<html><body><h1>upload</h1>"
                "<form action='/upload' method='post' enctype='multipart/form-data'>"
                "<input type='text' name='comment' value=''>"
                "<input type='file' name='doc'>"
                "<input type='submit' value='send'>"
                "</form></body></html>"
            )
            return

        if parts.path == "/xhr-form":                      # multipart created by fetch
            self._send(
                "<html><body><h1>xhr form</h1><div id='out'></div>"
                "<script>"
                "const fd = new FormData(); fd.append('comment', 'hello');"
                "fetch('/api/form', {method: 'POST', body: fd})"
                ".then(r => r.text())"
                ".then(t => { document.getElementById('out').innerHTML = t; });"
                "</script></body></html>"
            )
            return

        if parts.path == "/csrf":                          # origin + hidden token form
            self._send(
                "<html><body><h1>csrf</h1>"
                "<form method='post' action='/csrf'>"
                f"<input type='hidden' name='csrf' value='{CSRF_TOKEN}'>"
                "<input type='text' name='message' value=''>"
                "<input type='submit' value='send'>"
                "</form></body></html>"
            )
            return

        if parts.path.startswith("/api/path/"):            # openapi path parameter
            ident = unquote(parts.path[len("/api/path/"):])
            if _looks_sql(ident):
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(
                "<html><body><h1>path api</h1>"
                f"<div>{ident}</div></body></html>"
            )
            return

        if parts.path == "/profile":                      # second-order sqli
            name = PROFILE["name"]
            if "'" in name:
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(
                "<html><body><h1>profile</h1>"
                f"<p>name: {name}</p>"
                "<form method='post' action='/profile'>"
                "<input type='text' name='name' value=''>"
                "<input type='submit' value='save'>"
                "</form></body></html>"
            )
            return

        if parts.path == "/blind":                        # blind xss entry form
            self._send(
                "<html><body><h1>contact moderation</h1>"
                "<form method='post' action='/blind'>"
                "<textarea name='message' rows='4' cols='40'></textarea>"
                "<input type='submit' value='send'>"
                "</form></body></html>"
            )
            return

        if parts.path == "/blind-admin":                  # not linked from anywhere
            tickets = "".join(
                f"<div class='ticket'>{message}</div>" for message in BLIND[-20:]
            )
            self._send(
                "<html><body><h1>moderation queue</h1>"
                + (tickets or "<p>empty</p>")
                + "</body></html>"
            )
            return

        if parts.path == "/fetch":                        # ssrf sink
            target_url = query.get("url", [""])[0]
            if not target_url.lower().startswith(("http://", "https://")):
                self._send("<html><body><h1>fetch</h1><p>url required</p></body></html>")
                return
            try:
                with urllib.request.urlopen(target_url, timeout=4) as response:
                    status = response.status
                    body = response.read(2048).decode("utf-8", errors="replace")
            except Exception as exc:
                self._send(
                    "<html><body><h1>fetch</h1>"
                    f"<p>error: {html.escape(str(exc))}</p></body></html>"
                )
                return
            self._send(
                "<html><body><h1>fetch</h1>"
                f"<p>status: {status}</p><pre>{html.escape(body)}</pre>"
                "</body></html>"
            )
            return

        if parts.path == "/slow":                         # time based sqli
            term = query.get("q", [""])[0]
            if "SLEEP" in term.upper() or "PG_SLEEP" in term.upper():
                time.sleep(4.0)
            self._send(f"<html><body><h1>slow</h1><div>{term}</div></body></html>")
            return

        if parts.path == "/xhr-post":                     # POST body only after render
            self._send(
                "<html><body><h1>xhr post</h1><div id='out'></div>"
                "<script>"
                "fetch('/api/xhr', {"
                "method: 'POST',"
                "headers: {'Content-Type': 'application/json'},"
                "body: JSON.stringify({user: {name: 'hello'}, q: 'hello'})"
                "}).then(r => r.text())"
                ".then(t => { document.getElementById('out').innerHTML = t; });"
                "</script></body></html>"
            )
            return

        if parts.path == "/external":                     # external bundle source/sink
            self._send(
                "<html><body><h1>external</h1><div id='out'></div>"
                "<script src='/external.js'></script></body></html>"
            )
            return

        if parts.path == "/external.js":
            self._send(
                "const raw = decodeURIComponent(location.hash.slice(1));"
                "if (raw) { document.getElementById('out').innerHTML = raw; }",
                content_type="application/javascript; charset=utf-8",
            )
            return

        self._send("<html><body>404</body></html>", 404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)
        body = raw_body.decode("utf-8", errors="replace")
        path = urlsplit(self.path).path
        content_type = (self.headers.get("Content-Type") or "").lower()

        if "json" in content_type or body.strip().startswith("{"):
            try:
                payload = json.loads(body or "{}")
            except json.JSONDecodeError:
                payload = {}
            if path == "/api/item":
                ident = str(payload.get("id", "1"))
                if _is_false(ident):
                    self._send("<html><body><h1>item</h1><p>not found</p></body></html>")
                else:
                    self._send(UNION_PAGE)
                return
            if path in ("/api/xhr", "/api/nested"):
                value = payload.get("q", "")
                user = payload.get("user")
                if isinstance(user, dict):
                    value = str(user.get("name", value))
                self._send(
                    "<html><body><h1>api body</h1>"
                    f"<div>{value}</div></body></html>"
                )
                return
            self._send(f"<html><body><pre>{json.dumps(payload)}</pre></body></html>")
            return

        if "multipart/form-data" in content_type:
            data = _multipart_fields(self.headers.get("Content-Type", ""), raw_body)
        else:
            data = parse_qs(body, keep_blank_values=True)
        name = data.get("name", [""])[0]
        message = data.get("message", [""])[0]

        if path == "/login":
            token = data.get("csrf", [""])[0]
            username = data.get("username", [""])[0]
            password = data.get("password", [""])[0]
            if (
                token != LOGIN_TOKEN
                or username != LOGIN_USER
                or password != LOGIN_PASSWORD
            ):
                self._send(
                    "<html><body><h1>denied</h1><p>login refused</p></body></html>",
                    403,
                )
                return
            session = secrets.token_urlsafe(24)
            SESSIONS.add(session)
            self.send_response(302)
            self.send_header("Location", "/private")
            self.send_header("Set-Cookie", f"sid={session}; Path=/; HttpOnly")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/csrf":
            token = data.get("csrf", [""])[0]
            origin = self.headers.get("Origin", "")
            expected = f"http://{self.headers.get('Host', '')}"
            if token != CSRF_TOKEN or origin.rstrip("/") != expected:
                self._send(
                    "<html><body><h1>blocked</h1><p>csrf check failed</p></body></html>",
                    403,
                )
                return
            if _looks_sql(message):
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(
                "<html><body><h1>csrf</h1>"
                f"<div>{message}</div></body></html>"
            )
            return

        if path in ("/upload", "/api/form"):
            comment = data.get("comment", [""])[0]
            if _looks_sql(comment):
                self._send(f"<html><body><h1>error</h1>{MYSQL_ERROR}</body></html>")
                return
            self._send(
                "<html><body><h1>uploaded</h1>"
                f"<p>saved: {comment}</p></body></html>"
            )
            return

        if path == "/guestbook":
            GUESTBOOK.append((name, message))
            self._send("<html><body><h1>signed</h1><p>saved</p></body></html>")
            return

        if path == "/profile":
            PROFILE["name"] = data.get("name", ["guest"])[0]
            self._send("<html><body><h1>saved</h1><p>profile updated</p></body></html>")
            return

        if path == "/blind":
            BLIND.append(message)
            del BLIND[:-20]
            self._send("<html><body><h1>queued</h1><p>awaiting moderation</p></body></html>")
            return

        self._send(
            "<html><body><h1>thanks</h1>"
            f"<div>from {name}</div><div>{message}</div></body></html>"
        )


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"lab up on http://127.0.0.1:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("lab down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
