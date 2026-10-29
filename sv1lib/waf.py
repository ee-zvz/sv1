"""SV1 - passive WAF fingerprint.

The scanner already reacts to a WAF when a payload is refused. This module
names the edge in front of the target so the operator knows why a request was
rewritten or blocked. It is passive: one ordinary GET, no probe strings, no
extra attack traffic.

Only named products are reported. A generic 403 is not a fingerprint.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Response

BODY_BYTES = 128_000


@dataclass(frozen=True)
class Waf:
    name: str
    evidence: str


def _header_map(response: Response) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in (response.headers or {}).items():
        result[str(key).lower()] = str(value)
    return result


def _body(response: Response) -> str:
    text = response.text or ""
    return text[:BODY_BYTES].lower()


def _has_header(headers: dict[str, str], name: str, needle: str | None = None) -> bool:
    value = headers.get(name.lower())
    if value is None:
        return False
    return needle is None or needle.lower() in value.lower()


def _header_rules(headers: dict[str, str]) -> list[tuple[str, str]]:
    rules = [
        ("Cloudflare", "cf-ray", None),
        ("Cloudflare", "server", "cloudflare"),
        ("Cloudflare", "cf-cache-status", None),
        ("Akamai", "akamai-grn", None),
        ("Akamai", "server", "akamaighost"),
        ("Imperva", "x-iinfo", None),
        ("Imperva", "server", "imperva"),
        ("F5 BIG-IP", "x-wa-info", None),
        ("F5 BIG-IP", "server", "big-ip"),
        ("Sucuri", "x-sucuri-id", None),
        ("Sucuri", "server", "sucuri"),
        ("AWS WAF", "x-amzn-waf-action", None),
        ("Azure Front Door", "x-azure-ref", None),
        ("Fastly", "x-fastly-request-id", None),
        ("Vercel", "x-vercel-id", None),
        ("Barracuda", "barra_counter_session", None),
        ("Citrix NetScaler", "ns_af", None),
        ("Wallarm", "x-wallarm-waf", None),
        ("SafeLine", "x-safeline-waf", None),
        ("ModSecurity", "server", "modsecurity"),
        ("NAXSI", "server", "naxsi"),
    ]
    found: list[tuple[str, str]] = []
    for name, header, needle in rules:
        if _has_header(headers, header, needle):
            value = headers.get(header, "")
            label = header if not needle else f"{header}: {value}"
            found.append((name, label))
    return found


def _cookie_rules(headers: dict[str, str]) -> list[tuple[str, str]]:
    cookies = (headers.get("set-cookie", "") + " " + headers.get("cookie", "")).lower()
    rules = (
        ("Imperva", "incap_ses"),
        ("Imperva", "visid_incap"),
        ("F5 BIG-IP", "bigipserver"),
        ("Barracuda", "barra_counter_session"),
        ("Citrix NetScaler", "citrix_ns_id"),
        ("Cloudflare", "__cf_bm"),
        ("Wordfence", "wfvt_"),
    )
    return [(name, marker) for name, marker in rules if marker in cookies]


def _body_rules(body: str) -> list[tuple[str, str]]:
    rules = (
        ("ModSecurity", "modsecurity"),
        ("NAXSI", "naxsi"),
        ("Wordfence", "wordfence"),
        ("Sucuri", "sucuri website firewall"),
        ("Cloudflare", "cloudflare ray id"),
        ("Imperva", "incapsula incident id"),
        ("AWS WAF", "request blocked by aws waf"),
        ("Azure Front Door", "azure front door"),
        ("SafeLine", "safeline"),
        ("Wallarm", "wallarm"),
    )
    return [(name, marker) for name, marker in rules if marker in body]


def detect(response: Response | None) -> Waf | None:
    """Return the first named edge signature, or None.

    Header evidence outranks body evidence because a block page can be copied
    by a reverse proxy that is not itself a WAF. A plain 403 with no named
    marker is deliberately not reported.
    """
    if response is None:
        return None
    headers = _header_map(response)
    for name, evidence in _header_rules(headers):
        return Waf(name=name, evidence=evidence)
    for name, evidence in _cookie_rules(headers):
        return Waf(name=name, evidence=f"cookie {evidence}")
    for name, evidence in _body_rules(_body(response)):
        return Waf(name=name, evidence=f"body marker {evidence}")
    return None


def probe(client, url: str) -> Waf | None:
    """Fetch one page and fingerprint its response. Never raises."""
    try:
        response = client.fetch(url)
    except Exception:
        return None
    return detect(response)
