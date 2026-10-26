"""SV1 - crawler. Stdlib HTMLParser, same-origin, bounded."""

from __future__ import annotations

import urllib.parse

from html.parser import HTMLParser

from . import config, net
from .models import Form, FormField, InjectionPoint, Page

SKIP_PAGE_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "file:", "ftp:")

HEADER_CANDIDATES = (
    ("X-Forwarded-For", "127.0.0.1"),
    ("Referer", ""),
    ("User-Agent", "SV1-probe/1.0"),
)

DEEP_HEADERS = (
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("Client-IP", "127.0.0.1"),
    ("Origin", ""),
)


class PageParser(HTMLParser):
    """Collects anchors and forms. Tolerant of broken markup by design."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._form: Form | None = None
        self._field: FormField | None = None
        self._buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        props = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag in ("a", "area") and props.get("href"):
            self.links.append(props["href"])
        elif tag == "form":
            self._form = Form(
                action=props.get("action", ""),
                method=(props.get("method") or "get").lower(),
                enctype=(props.get("enctype") or "").lower(),
            )
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select", "button") and self._form is not None:
            name = props.get("name", "").strip()
            if not name:
                return
            kind = (props.get("type") or "text").lower()
            if kind in ("submit", "button", "image", "reset", "file"):
                return
            self._field = FormField(name=name, value=props.get("value", ""), type=kind)
            self._buffer = []
            self._form.fields.append(self._field)
        elif tag == "option" and self._field is not None and self._field.type == "select":
            self._buffer = []

    def handle_data(self, data: str) -> None:
        if self._field is not None:
            self._buffer.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
            self._field = None
        elif tag in ("textarea", "select") and self._field is not None:
            text = "".join(self._buffer).strip()
            if text:
                self._field = FormField(
                    name=self._field.name, value=text[:200], type=self._field.type
                )
                self._form.fields[-1] = self._field
            self._field = None
            self._buffer = []


def parse_page(url: str, status: int, html: str) -> Page:
    parser = PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    return Page(url=url, status=status, html=html, links=parser.links, forms=parser.forms)


def normalize(url: str, base: str) -> str:
    absolute = urllib.parse.urljoin(base, url.strip())
    parts = urllib.parse.urlsplit(absolute)
    cleaned = parts._replace(fragment="", scheme=parts.scheme.lower(), netloc=parts.netloc.lower())
    return urllib.parse.urlunsplit(cleaned)


def crawl(client: net.Client, start_url: str, max_pages: int, max_depth: int,
          allows=None) -> list[Page]:
    seen: set[str] = set()
    pages: list[Page] = []
    queue: list[tuple[str, int]] = [(start_url, 0)]
    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        if allows is not None and not allows(url):
            continue
        seen.add(url)
        response = client.fetch(url)
        if not response.ok:
            continue
        ctype = response.headers.get("Content-Type", "").lower()
        if ctype and "html" not in ctype and "xml" not in ctype:
            continue
        page = parse_page(response.url or url, response.status, response.text)
        pages.append(page)
        if depth >= max_depth:
            continue
        for raw in page.links:
            if raw.lower().startswith(SKIP_PAGE_SCHEMES):
                continue
            candidate = normalize(raw, page.url)
            if not net.same_origin(candidate, start_url):
                continue
            if allows is not None and not allows(candidate):
                continue
            if net.is_skippable(candidate) or candidate in seen:
                continue
            queue.append((candidate, depth + 1))
    return pages


def points_from_page(page: Page) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    parts = urllib.parse.urlsplit(page.url)

    if parts.query:
        base = urllib.parse.urlunsplit(parts._replace(query=""))
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        for name, _value in pairs:
            points.append(
                InjectionPoint(
                    url=base,
                    method="GET",
                    params=tuple(pairs),
                    param=name,
                    source="query",
                )
            )

    for form in page.forms:
        action = normalize(form.action or page.url, page.url)
        action_parts = urllib.parse.urlsplit(action)
        action = urllib.parse.urlunsplit(action_parts._replace(query=""))
        method = "POST" if form.method == "post" else "GET"
        source = "multipart" if "multipart" in form.enctype else "form"
        fields = form.fields[: config.MAX_FORM_FIELDS]
        if not fields:
            continue
        pairs = tuple((f.name, f.value) for f in fields)
        names = {f.name for f in fields}
        for name in names:
            points.append(
                InjectionPoint(
                    url=action,
                    method=method,
                    params=pairs,
                    param=name,
                    source=source,
                )
            )
    return points


def collect_points(pages: list[Page]) -> list[InjectionPoint]:
    seen: set[tuple] = set()
    collected: list[InjectionPoint] = []
    for page in pages:
        for point in points_from_page(page):
            if point.key() in seen:
                continue
            seen.add(point.key())
            collected.append(point)
            if len(collected) >= config.MAX_POINTS:
                return collected
    return collected


def header_points(url: str, deep: bool = False) -> list[InjectionPoint]:
    """Header values are trusted more often than query strings. Test the usual suspects."""
    parts = urllib.parse.urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    candidates = HEADER_CANDIDATES + (DEEP_HEADERS if deep else ())
    points: list[InjectionPoint] = []
    for name, default in candidates:
        if not default:
            default = origin if name == "Origin" else url
        points.append(
            InjectionPoint(
                url=url,
                method="GET",
                params=((name, default),),
                param=name,
                source="header",
            )
        )
    return points


def cookie_points(url: str, cookies: dict) -> list[InjectionPoint]:
    return [
        InjectionPoint(
            url=url,
            method="GET",
            params=((name, value),),
            param=name,
            source="cookie",
        )
        for name, value in cookies.items()
    ]


def json_points(url: str, data: dict, method: str = "POST") -> list[InjectionPoint]:
    pairs = tuple((name, value) for name, value in data.items())
    return [
        InjectionPoint(
            url=url,
            method=method,
            params=pairs,
            param=name,
            source="json",
        )
        for name, _value in pairs
    ]
