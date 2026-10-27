"""Comparison-only real SQLite target. Localhost only; deliberately injectable.

The main 31-case lab emulates SQL errors and boolean branches so every
technique can be proved deterministically. sqlmap needs a real database engine,
so this second target backs the same ideas with sqlite3. It is used by
docs/COMPARISON.md, not by the release acceptance test.

    python lab/real_sql.py 8100 [requests.log]
"""

from __future__ import annotations

import html
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript(
    """
    CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price REAL);
    CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);
    INSERT INTO items VALUES (1, 'widget', 42.0), (2, 'gadget', 7.5);
    INSERT INTO users VALUES (1, 'alice', 'admin'), (2, 'bob', 'user');
    """
)

INDEX = """<!doctype html><html><body>
<h1>real sqlite target</h1>
<a href="/search?q=hello">search xss</a>
<a href="/attr?q=hello">attribute xss</a>
<a href="/js?q=hello">js xss</a>
<a href="/safe?q=hello">safe</a>
<a href="/item?id=1">item sqli</a>
<a href="/user?name=alice">user sqli</a>
</body></html>"""


def _rows(sql: str) -> tuple[int, str]:
    try:
        rows = DB.execute(sql).fetchall()
    except Exception as exc:
        return 500, (
            "<html><body><h1>SQL error</h1><pre>"
            f"{html.escape(str(exc))}</pre></body></html>"
        )
    if not rows:
        return 200, "<html><body><h1>not found</h1></body></html>"
    cells = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return 200, f"<html><body><h1>rows</h1><table>{cells}</table></body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        line = (fmt % args) + "\n"
        sys.stderr.write(line)
        sys.stderr.flush()
        if len(sys.argv) > 2:
            with open(sys.argv[2], "a", encoding="utf-8") as log:
                log.write(line)
                log.flush()

    def _send(
        self,
        body: str,
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        if parts.path == "/":
            self._send(INDEX)
            return
        if parts.path == "/search":
            term = query.get("q", [""])[0]
            self._send(f"<html><body><h1>search</h1><div>{term}</div></body></html>")
            return
        if parts.path == "/attr":
            term = query.get("q", [""])[0]
            self._send(f"<html><body><h1>attr</h1><input value='{term}' name='v'></body></html>")
            return
        if parts.path == "/js":
            term = query.get("q", [""])[0]
            self._send(
                "<html><body><h1>js</h1><script>var q = \""
                + term
                + "\"; document.title = q;</script></body></html>"
            )
            return
        if parts.path == "/safe":
            term = query.get("q", [""])[0]
            escaped = html.escape(term).replace('"', "&quot;")
            self._send(f"<html><body><h1>safe</h1><div>{escaped}</div></body></html>")
            return
        if parts.path == "/item":
            ident = query.get("id", ["1"])[0]
            status, body = _rows(f"SELECT id, name, price FROM items WHERE id = {ident}")
            self._send(body, status)
            return
        if parts.path == "/user":
            name = query.get("name", ["alice"])[0]
            status, body = _rows(f"SELECT id, name, role FROM users WHERE name = '{name}'")
            self._send(body, status)
            return
        self._send("<html><body>404</body></html>", 404)


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8100
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"real target on http://127.0.0.1:{port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
