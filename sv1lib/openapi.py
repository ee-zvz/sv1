"""SV1 - OpenAPI import.

A spec is a list of inputs without the crawling. Read the json document, turn
every query parameter and every body property into an injection point, and let
the normal scanner do the rest. Local files work too.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from typing import Any

from . import config, crawl
from .models import InjectionPoint

METHODS = ("get", "post", "put", "patch", "delete")
BODY_TYPES = (
    ("application/json", "json"),
    ("application/x-www-form-urlencoded", "form"),
    ("multipart/form-data", "multipart"),
)


def load(client, ref: str) -> tuple[dict | None, str]:
    """Return (spec, note). Only the loaded path is spoken about."""
    ref = (ref or "").strip()
    if not ref:
        return None, "no spec given"
    if ref.startswith(("http://", "https://")):
        response = client.fetch(ref)
        if not response.ok:
            return None, f"spec unreachable ({response.status or response.error})"
        text = response.text
    else:
        path = os.path.abspath(os.path.expanduser(ref))
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read(config.OPENAPI_MAX_BYTES)
        except OSError as exc:
            return None, f"cannot read spec: {exc.strerror}"

    if not text.lstrip().startswith("{"):
        return None, "spec must be json (export yaml as json first)"
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"invalid json at line {exc.lineno}"
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return None, "spec has no paths object"
    return spec, ""


def _deref(spec: dict, node):
    hops = 0
    while isinstance(node, dict) and "$ref" in node and hops < 4:
        ref = str(node["$ref"])
        if not ref.startswith("#/"):
            return node
        target: Any = spec
        for part in ref[2:].split("/"):
            if not isinstance(target, dict):
                return node
            target = target.get(part)
        if target is None:
            return node
        node = target
        hops += 1
    return node


def _value(node: dict) -> str:
    for key in ("example", "default"):
        if key in node:
            return str(node[key])
    schema = node.get("schema")
    if isinstance(schema, dict):
        for key in ("example", "default"):
            if key in schema:
                return str(schema[key])
        kind = str(schema.get("type", "string")).lower()
    else:
        kind = str(node.get("type", "string")).lower()
    return "1" if kind in ("integer", "number", "boolean") else "test"


def _query_parameters(common: list, operation: list) -> list[dict]:
    merged: dict[str, dict] = {}
    for item in list(common) + list(operation):
        if not isinstance(item, dict):
            continue
        if item.get("in") != "query" or not item.get("name"):
            continue
        merged[str(item["name"])] = item
    return list(merged.values())


def _example(spec: dict, schema, depth: int = 0):
    """Build a small example body, including nested objects and arrays."""
    if depth > 6:
        return "test"
    schema = _deref(spec, schema if isinstance(schema, dict) else {})
    if not isinstance(schema, dict):
        return "test"
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    kind = str(schema.get("type", "")).lower()
    properties = schema.get("properties")
    if isinstance(properties, dict) or kind == "object":
        if not isinstance(properties, dict):
            return {}
        value = {}
        for name, prop in list(properties.items())[: config.OPENAPI_MAX_FIELDS]:
            value[str(name)] = _example(spec, prop, depth + 1)
        return value
    if kind == "array" or "items" in schema:
        item = _example(spec, schema.get("items") or {}, depth + 1)
        return [item]
    if kind in ("integer", "number"):
        return 1
    if kind == "boolean":
        return True
    if kind == "null":
        return None
    return "test"


def _media_entry(content: dict, media: str) -> dict | None:
    entry = content.get(media)
    if isinstance(entry, dict):
        return entry
    for key, value in content.items():
        if (str(key).split(";", 1)[0].strip().lower() == media
                and isinstance(value, dict)):
            return value
    return None


def _body_fields(spec: dict, operation: dict) -> tuple[str, object]:
    body = operation.get("requestBody")
    if not isinstance(body, dict):
        return "", {}
    content = body.get("content")
    if not isinstance(content, dict):
        return "", {}
    for media, source in BODY_TYPES:
        entry = _media_entry(content, media)
        if entry is None:
            continue
        schema = _deref(spec, entry.get("schema") or {})
        if source == "json":
            value = _example(spec, schema)
            if isinstance(value, (dict, list)) and value:
                return source, value
            continue
        properties = schema.get("properties") if isinstance(schema, dict) else None
        if not isinstance(properties, dict):
            continue
        fields: dict[str, str] = {}
        for name, prop in list(properties.items())[: config.OPENAPI_MAX_FIELDS]:
            prop = _deref(spec, prop if isinstance(prop, dict) else {})
            fields[str(name)] = _value(prop if isinstance(prop, dict) else {})
        if fields:
            return source, fields
    return "", {}


def _base(spec: dict, target: str) -> str:
    parts = urllib.parse.urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}"
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        raw = str(servers[0].get("url", "") or "")
        if raw:
            raw = re.sub(r"\{[^}]+\}", "1", raw)
            return urllib.parse.urljoin(origin + "/", raw.lstrip("/"))
    return origin


def points(spec: dict, target: str) -> list[InjectionPoint]:
    base = _base(spec, target)
    out: list[InjectionPoint] = []
    seen: set[tuple] = set()

    for raw_path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        common = item.get("parameters")
        if not isinstance(common, list):
            common = []
        path = re.sub(r"\{[^}]+\}", "1", str(raw_path))
        url = base.rstrip("/") + "/" + path.lstrip("/")
        for method in METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue

            parameters = operation.get("parameters")
            if not isinstance(parameters, list):
                parameters = []
            query = _query_parameters(common, parameters)
            if query:
                pairs = tuple((str(item["name"]), _value(item)) for item in query)
                for name, _value_ in pairs:
                    _add(out, seen, InjectionPoint(
                        url=url,
                        method=method.upper(),
                        params=pairs,
                        param=name,
                        source="query",
                    ))

            source, body_value = _body_fields(spec, operation)
            if source == "json" and isinstance(body_value, (dict, list)):
                for point in crawl.json_points(
                    url,
                    body_value,
                    method=method.upper(),
                    content_type="application/json",
                ):
                    _add(out, seen, point)
            elif source and isinstance(body_value, dict) and body_value:
                pairs = tuple(
                    (str(name), str(value))
                    for name, value in body_value.items()
                )
                for name, _value_ in pairs:
                    _add(out, seen, InjectionPoint(
                        url=url,
                        method=method.upper(),
                        params=pairs,
                        param=name,
                        source=source,
                    ))
            if len(out) >= config.OPENAPI_MAX_POINTS:
                return out
    return out


def _add(out: list, seen: set, point: InjectionPoint) -> None:
    if len(out) >= config.OPENAPI_MAX_POINTS:
        return
    key = point.key()
    if key in seen:
        return
    seen.add(key)
    out.append(point)
