"""RDAP endpoint discovery (IANA bootstrap via ``whoisit``) and RFC 9083 response parsing.

``whoisit`` (BSD-3) is used for what it does well — bootstrap data handling and mapping a domain,
IP or ASN to the right registry RDAP server. Requests themselves go through :class:`HttpClient`
(limits, timeouts, size caps), and responses are parsed here so that *absent* fields stay absent
(e.g. no ``secureDNS`` member means "unknown", not "DNSSEC off").
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import whoisit
from whoisit.errors import QueryError, UnsupportedError, WhoisItError

from osint_toolkit.config import ensure_private_dir
from osint_toolkit.net.errors import NetworkError
from osint_toolkit.net.http import HttpClient

BOOTSTRAP_URLS = {
    "asn": "https://data.iana.org/rdap/asn.json",
    "dns": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
    "object": "https://data.iana.org/rdap/object-tags.json",
}
BOOTSTRAP_MAX_AGE_DAYS = 7
_lock = asyncio.Lock()


class RdapUnsupportedError(Exception):
    """No RDAP service is registered for this object (e.g. a ccTLD without RDAP)."""


async def ensure_bootstrap(http: HttpClient, cache_dir: Path) -> str:
    """Load IANA bootstrap data (cached for 7 days). Returns where it came from."""
    async with _lock:
        if whoisit.is_bootstrapped() and not whoisit.bootstrap_is_older_than(
            BOOTSTRAP_MAX_AGE_DAYS
        ):
            return "память"
        if whoisit.is_bootstrapped():
            whoisit.clear_bootstrapping()
        cache = cache_dir / "rdap-bootstrap.json"
        if cache.exists():
            try:
                whoisit.load_bootstrap_data(cache.read_text(encoding="utf-8"))
                if not whoisit.bootstrap_is_older_than(BOOTSTRAP_MAX_AGE_DAYS):
                    return "кэш"
                whoisit.clear_bootstrapping()
            except (WhoisItError, OSError, ValueError):
                whoisit.clear_bootstrapping()
        data: dict[str, Any] = {"timestamp": int(time.time())}
        for name, url in BOOTSTRAP_URLS.items():
            data[name] = await http.get_json(url, max_bytes=5 * 1024 * 1024)
        try:
            whoisit.load_bootstrap_data(data, from_json=False)
        except WhoisItError as exc:
            whoisit.clear_bootstrapping()
            raise NetworkError(f"Некорректные bootstrap-данные IANA: {exc}") from exc
        ensure_private_dir(cache_dir)
        fd = os.open(cache, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        return "data.iana.org"


def endpoint_for(query_type: str, value: str) -> str:
    """RDAP URL for a domain / ip / autnum. Raises RdapUnsupportedError."""
    try:
        _, url, _ = whoisit.build_query(query_type=query_type, query_value=value)
    except UnsupportedError as exc:
        raise RdapUnsupportedError(str(exc)) from exc
    except QueryError as exc:
        raise RdapUnsupportedError(str(exc)) from exc
    return str(url)


# --------------------------------------------------------------------------- parsing (RFC 9083)
def _vcard(entity: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    array = entity.get("vcardArray")
    if not (isinstance(array, list) and len(array) == 2 and isinstance(array[1], list)):
        return out
    for item in array[1]:
        if isinstance(item, list) and len(item) >= 4:
            name, value = str(item[0]).lower(), item[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            if isinstance(value, str) and value.strip():
                out.setdefault(name, []).append(value.strip())
    return out


def _first(card: dict[str, list[str]], key: str) -> str | None:
    values = card.get(key)
    return values[0] if values else None


def _entities(data: dict[str, Any]) -> list[dict[str, Any]]:
    """All entities, depth-first (abuse contacts are often nested in the registrar entity)."""
    found: list[dict[str, Any]] = []
    stack = list(data.get("entities") or [])
    while stack:
        entity = stack.pop(0)
        if isinstance(entity, dict):
            found.append(entity)
            stack.extend(entity.get("entities") or [])
    return found


def _date(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


@dataclass(slots=True)
class RdapRecord:
    url: str
    server: str
    handle: str | None = None
    name: str | None = None
    status: list[str] = field(default_factory=list)
    events: dict[str, str] = field(default_factory=dict)
    nameservers: list[str] = field(default_factory=list)
    dnssec: bool | None = None
    registrar: str | None = None
    registrar_iana_id: str | None = None
    abuse_emails: list[str] = field(default_factory=list)
    port43: str | None = None
    related: str | None = None
    # IP network fields
    start_address: str | None = None
    end_address: str | None = None
    cidrs: list[str] = field(default_factory=list)
    network_type: str | None = None
    country: str | None = None
    parent_handle: str | None = None
    org_name: str | None = None


def parse_rdap(data: dict[str, Any], url: str) -> RdapRecord:
    record = RdapRecord(url=url, server=urlsplit(url).hostname or url)
    record.handle = data.get("handle") if isinstance(data.get("handle"), str) else None
    record.name = data.get("ldhName") or data.get("name")
    record.status = [str(s) for s in data.get("status") or [] if s]
    for event in data.get("events") or []:
        if isinstance(event, dict):
            action, date = str(event.get("eventAction", "")).lower(), _date(event.get("eventDate"))
            if action and date and action not in record.events:
                record.events[action] = date
    record.nameservers = sorted(
        {
            str(ns.get("ldhName")).lower().rstrip(".")
            for ns in data.get("nameservers") or []
            if isinstance(ns, dict) and ns.get("ldhName")
        }
    )
    secure = data.get("secureDNS")
    if isinstance(secure, dict) and isinstance(secure.get("delegationSigned"), bool):
        record.dnssec = secure["delegationSigned"]
    for entity in _entities(data):
        roles = {str(r).lower() for r in entity.get("roles") or []}
        card = _vcard(entity)
        if "registrar" in roles and record.registrar is None:
            record.registrar = _first(card, "fn")
            for public in entity.get("publicIds") or []:
                if isinstance(public, dict) and "iana" in str(public.get("type", "")).lower():
                    record.registrar_iana_id = str(public.get("identifier"))
        if "abuse" in roles:
            record.abuse_emails.extend(
                e for e in card.get("email", []) if e not in record.abuse_emails
            )
        if "registrant" in roles and record.org_name is None:
            kind = (_first(card, "kind") or "").lower()
            if kind == "org":  # organisations only; personal registrant data is not collected
                record.org_name = _first(card, "fn") or _first(card, "org")
    record.port43 = data.get("port43") if isinstance(data.get("port43"), str) else None
    for link in data.get("links") or []:
        if (
            isinstance(link, dict)
            and link.get("rel") in ("related", "registration")
            and "rdap" in str(link.get("type", "application/rdap+json"))
            and str(link.get("href", "")).startswith("https://")
            and link.get("href") != url
        ):
            record.related = str(link["href"])
            break
    record.start_address = data.get("startAddress")
    record.end_address = data.get("endAddress")
    for cidr in data.get("cidr0_cidrs") or []:
        if isinstance(cidr, dict):
            prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
            if prefix and cidr.get("length") is not None:
                record.cidrs.append(f"{prefix}/{cidr['length']}")
    record.network_type = data.get("type") if isinstance(data.get("type"), str) else None
    record.country = data.get("country") if isinstance(data.get("country"), str) else None
    record.parent_handle = data.get("parentHandle")
    return record
