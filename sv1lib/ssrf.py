"""SV1 - server side request forgery.

URL-like inputs are asked to fetch a callback address that carries a unique
token. A hit means the server (or something behind it) made the request. The
scanner never follows redirects while testing, so a redirect to the callback
cannot fake a result.
"""

from __future__ import annotations

import time

from . import config, jsonbody, net
from .models import Finding, InjectionPoint
from .oob import Callback

URL_NAMES = {
    "url", "uri", "link", "href", "src", "source", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "return_url", "next", "continue", "callback", "callback_url", "cb",
    "webhook", "webhook_url", "hook", "fetch", "load", "loader", "proxy",
    "proxy_url", "image", "image_url", "img", "avatar", "avatar_url",
    "file", "file_url", "path", "target", "target_url", "host", "domain",
    "feed", "rss", "endpoint", "api", "api_url", "request", "open", "view",
}
URL_HINTS = ("redirect", "callback", "webhook", "destination")


def _original(point: InjectionPoint) -> str:
    getter = getattr(point, "original", None)
    if callable(getter):
        return getter()
    for name, value in point.params:
        if name == point.param:
            return value
    return ""


def _candidate(point: InjectionPoint) -> bool:
    if getattr(point, "source", "query") not in ("query", "form", "json", "multipart"):
        return False
    leaf = point.param.lower().replace("[]", "")
    leaf = leaf.split("[")[-1].split(".")[-1].strip("]")
    if leaf in URL_NAMES or leaf.endswith(("url", "uri", "link", "href")):
        return True
    if any(hint in leaf for hint in URL_HINTS):
        return True
    value = _original(point).strip().lower()
    return value.startswith(("http://", "https://"))


def _send(client, point: InjectionPoint, payload: str):
    target_index = point.position()
    mapping = [
        (name, payload if index == target_index else value)
        for index, (name, value) in enumerate(point.params)
    ]
    source = getattr(point, "source", "query")
    if source == "query" or (source == "form" and point.method == "GET"):
        return client.request(point.method, point.url, params=mapping, allow_redirects=False)
    if source == "form":
        return client.request("POST", point.url, data=mapping, allow_redirects=False)
    if source == "json":
        body = getattr(point, "body", "")
        path = tuple(getattr(point, "path", ()) or ())
        document: object
        if body:
            template, error = jsonbody.parse(body)
            if error:
                document = {name: value for name, value in mapping}
            else:
                try:
                    document = jsonbody.set_value(template, path, payload)
                except (KeyError, IndexError, TypeError):
                    document = {name: value for name, value in mapping}
        else:
            document = {name: value for name, value in mapping}
        return client.request(
            point.method,
            point.url,
            data=jsonbody.dumps(document),
            headers={
                "Content-Type": getattr(point, "content_type", "")
                or "application/json",
            },
            allow_redirects=False,
        )
    if source == "multipart":
        files = [(name, (None, str(value))) for name, value in mapping]
        return client.request(point.method, point.url, files=files, allow_redirects=False)
    return None


def run(client, points: list[InjectionPoint], callback: Callback,
        wait: float) -> tuple[list[Finding], str]:
    candidates = [point for point in points if _candidate(point)]
    candidates = candidates[: config.SSRF_MAX_POINTS]
    if not candidates:
        return [], "no url-like parameters found"

    probes = []
    for point in candidates:
        token = callback.register(f"ssrf {point.label()}", "ssrf")
        payload = callback.url_for(token)
        response = _send(client, point, payload)
        if response is None:
            continue
        probes.append((point, token, payload, response))
    if not probes:
        return [], "no sendable url-like parameters"

    timeout = max(1.0, wait)
    callback.settle([probe[1] for probe in probes], timeout)

    findings: list[Finding] = []
    for point, token, payload, response in probes:
        hits = callback.hits_for(token)
        if not hits:
            continue
        hit = hits[0]
        when = time.strftime("%H:%M:%S", time.localtime(hit.at))
        agent = hit.user_agent or "unknown agent"
        findings.append(Finding(
            kind="SSRF",
            severity="HIGH",
            url=point.url,
            method=point.method,
            param=point.param,
            payload=payload,
            confidence="CONFIRMED",
            evidence=(f"target fetched {payload} at {when} from {hit.remote} "
                      f"({agent}); response status {response.status}"),
            technique="ssrf-oob",
            detail="url-like parameter made a server side request to the callback host",
            data={
                "oob": "fetched",
                "from": hit.remote,
                "agent": agent[:80],
                "time": when,
            },
            curl=net.repro_curl(client, point, payload),
        ))

    note = f"{len(probes)} url-like point(s) probed, {len(findings)} callback(s)"
    return findings, note
