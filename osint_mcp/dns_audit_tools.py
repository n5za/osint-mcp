"""Passive DNS delegation and public resolver comparison tools."""

from __future__ import annotations

import asyncio
import ipaddress
import re

import dns.asyncresolver
import dns.resolver

from .common import guarded, normalize_target, request, utcnow


def _domain(value: str) -> str:
    host = normalize_target(value).lower()
    if not host or len(host) > 253 or any(not label or len(label) > 63 for label in host.split(".")):
        raise ValueError("provide a valid domain name")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("provide a domain name, not an IP address")
    ascii_host = host.encode("idna").decode("ascii")
    if "." not in ascii_host or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in ascii_host.split(".")
    ):
        raise ValueError("provide a valid domain name")
    return ascii_host


async def _records(name: str, kind: str) -> tuple[list[str], str | None]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8
    try:
        answer = await resolver.resolve(name, kind, raise_on_no_answer=False)
        return sorted(item.to_text() for item in answer), None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"


@guarded
async def dnssec_status(domain: str) -> dict:
    """Inspect DNSSEC DS and DNSKEY publication for a domain.

    Reports delegation/key presence and algorithms. This is a publication check,
    not cryptographic DNSSEC validation.
    """
    target = _domain(domain)
    (ds, ds_error), (keys, key_error) = await asyncio.gather(
        _records(target, "DS"), _records(target, "DNSKEY")
    )
    errors = {k: v for k, v in (("DS", ds_error), ("DNSKEY", key_error)) if v}
    return {
        "ok": not bool(errors),
        "domain": target,
        "delegation_signed": bool(ds),
        "dnskey_published": bool(keys),
        "ds_records": ds,
        "dnskey_count": len(keys),
        "status": "unknown" if errors else "signed" if ds and keys else "incomplete" if ds or keys else "unsigned",
        "validation_performed": False,
        "errors": errors or None,
        "queried_at": utcnow().isoformat(timespec="seconds"),
    }


async def _doh(provider: str, endpoint: str, domain: str, kind: str) -> dict:
    try:
        response = await request(
            endpoint,
            params={"name": domain, "type": kind},
            headers={"Accept": "application/dns-json"},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("Status"), int):
            raise ValueError("invalid DNS response")
        answers = sorted({str(item.get("data", "")).strip('"').rstrip(".")
                          for item in data.get("Answer", []) if item.get("data")})
        return {"provider": provider, "status": data["Status"], "answers": answers}
    except Exception as exc:
        return {"provider": provider, "error": f"{type(exc).__name__}: {exc}"}


@guarded
async def dns_resolver_compare(domain: str, record_type: str = "A") -> dict:
    """Compare public DNS answers from Cloudflare and Google over DNS-over-HTTPS.

    Supports A, AAAA, MX, NS, TXT, CAA, and CNAME. A mismatch can reflect
    propagation, geo DNS, load balancing, or resolver policy.
    """
    target = _domain(domain)
    kind = record_type.upper().strip()
    if kind not in {"A", "AAAA", "MX", "NS", "TXT", "CAA", "CNAME"}:
        return {"ok": False, "error": "unsupported record type"}
    results = await asyncio.gather(
        _doh("cloudflare", "https://cloudflare-dns.com/dns-query", target, kind),
        _doh("google", "https://dns.google/resolve", target, kind),
    )
    good = [result for result in results if "error" not in result]
    return {
        "ok": bool(good),
        "domain": target,
        "record_type": kind,
        "resolvers": results,
        "same_answers": (good[0]["status"], good[0]["answers"]) ==
                        (good[1]["status"], good[1]["answers"]) if len(good) == 2 else None,
        "note": "Differences can be normal for geo DNS, load balancing, or resolver policy.",
        "queried_at": utcnow().isoformat(timespec="seconds"),
    }
