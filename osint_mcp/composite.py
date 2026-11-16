"""Composite one-shot recon tools that run many checks in parallel."""

from __future__ import annotations

import asyncio

from .common import guarded, normalize_target, utcnow
from .discovery_tools import (
    api_discovery,
    commoncrawl_urls,
    favicon_hash,
    passive_subdomains,
    urlscan_search,
    well_known,
)
from .dns_tools import crtsh_subdomains, dns_lookup, reverse_dns
from .domain_tools import domain_whois, robots_txt, security_txt, ssl_certificate
from .intel_tools import threat_reputation
from .ip_tools import asn_lookup, ip_intel, port_scan, reverse_ip
from .mail_tools import email_security
from .web_tools import http_headers_audit, tech_fingerprint


def _registrar(whois: dict) -> str | None:
    for contact in whois.get("contacts", []):
        roles = [str(role).lower() for role in contact.get("roles", [])]
        if "registrar" in roles:
            return contact.get("org") or contact.get("name")
    return None


@guarded
async def recon_domain(domain: str) -> dict:
    """One-shot domain recon: DNS, RDAP whois, TLS cert, crt.sh subdomains, headers, tech, robots.

    Runs 8 passive checks in parallel and returns a compact summary plus the full
    results. Start here for a new domain, then drill down with the specific tools.
    """
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}
    base = f"https://{target}"

    keys = ["dns", "whois", "tls", "subdomains", "headers", "tech", "robots", "security_txt"]
    coros = [
        dns_lookup(target, "ANY"),
        domain_whois(target),
        ssl_certificate(target),
        crtsh_subdomains(target),
        http_headers_audit(base),
        tech_fingerprint(base),
        robots_txt(target),
        security_txt(target),
    ]
    raw = await asyncio.gather(*coros, return_exceptions=True)
    results = {}
    for key, value in zip(keys, raw, strict=False):
        results[key] = value if not isinstance(value, BaseException) else {"ok": False, "error": str(value)}

    dns_result = results["dns"] if isinstance(results["dns"], dict) else {}
    records = dns_result.get("records", {}) if dns_result.get("ok") else {}
    whois = results["whois"] if isinstance(results["whois"], dict) else {}
    tls = results["tls"] if isinstance(results["tls"], dict) else {}
    crt = results["subdomains"] if isinstance(results["subdomains"], dict) else {}
    headers = results["headers"] if isinstance(results["headers"], dict) else {}
    tech = results["tech"] if isinstance(results["tech"], dict) else {}
    robots = results["robots"] if isinstance(results["robots"], dict) else {}

    summary = {
        "ipv4": records.get("A", []),
        "ipv6": records.get("AAAA", []),
        "nameservers": records.get("NS", []),
        "mx": records.get("MX", []),
        "spf": next((row for row in records.get("TXT", []) if isinstance(row, str) and row.lower().startswith("v=spf1")), None),
        "registrar": _registrar(whois) if whois.get("ok") else None,
        "created": whois.get("registered"),
        "expires": whois.get("expires"),
        "tls_issuer": tls.get("issuer"),
        "tls_expires": tls.get("not_after"),
        "tls_days_remaining": tls.get("days_remaining"),
        "subdomains_found": crt.get("count"),
        "technologies": [item.get("name") for item in tech.get("technologies", [])],
        "security_grade": headers.get("grade"),
        "security_score": headers.get("score"),
        "missing_headers": headers.get("missing", []),
        "sitemaps": robots.get("sitemaps", []),
    }

    return {"ok": True, "target": target, "summary": summary, "results": results}


@guarded
async def recon_ip(ip: str) -> dict:
    """One-shot IP recon: geo/ASN, Shodan InternetDB, PTR, reverse-IP domains, top-20 ports.

    Combines 5 keyless sources in parallel. Follow up with a wider port_scan or
    certificate lookups on discovered hostnames.
    """
    target = (ip or "").strip()
    keys = ["intel", "ptr", "asn", "ports", "reverse_ip"]
    raw = await asyncio.gather(
        ip_intel(target),
        reverse_dns(target),
        asn_lookup(target),
        port_scan(target, "top20"),
        reverse_ip(target),
        return_exceptions=True,
    )
    results = {}
    for key, value in zip(keys, raw, strict=False):
        results[key] = value if not isinstance(value, BaseException) else {"ok": False, "error": str(value)}

    intel = results["intel"] if isinstance(results["intel"], dict) else {}
    geo = intel.get("geo", {}) if intel.get("ok") else {}
    shodan = intel.get("shodan_internetdb") or {}
    tls = results["ports"] if isinstance(results["ports"], dict) else {}
    rev = results["reverse_ip"] if isinstance(results["reverse_ip"], dict) else {}

    summary = {
        "country": geo.get("country"),
        "city": geo.get("city"),
        "org": geo.get("org"),
        "asn": geo.get("as"),
        "ptr": (results["ptr"] or {}).get("ptr") if isinstance(results["ptr"], dict) else None,
        "open_ports": [item.get("port") for item in tls.get("open_ports", [])] if tls.get("ok") else None,
        "shodan_ports": shodan.get("ports"),
        "hostnames": shodan.get("hostnames"),
        "vulnerabilities": shodan.get("vulns"),
        "reverse_ip_domains": rev.get("count"),
    }
    return {"ok": True, "target": target, "summary": summary, "results": results}


async def _safe(coro, timeout: float, label: str):
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except Exception as exc:
        return {"ok": False, "error": f"{label}: {type(exc).__name__}: {exc}"}


@guarded
async def recon_deep(domain: str, limit: int = 100) -> dict:
    """Deep passive recon: subdomains + archives + API surface + email + threat intel.

    Runs passive_subdomains, urlscan, Common Crawl, api_discovery, well_known,
    email_security, threat_reputation and favicon_hash in parallel. Slower than
    recon_domain but aimed at forgotten endpoints, dangling hosts and exposure.
    """
    target = normalize_target(domain)
    if not target or "." not in target:
        return {"ok": False, "error": "provide a domain like example.com"}
    limit = max(10, min(int(limit), 1000))
    base = f"https://{target}"

    keys = [
        "subdomains",
        "urlscan",
        "commoncrawl",
        "api",
        "well_known",
        "email",
        "threat",
        "favicon",
    ]
    coros = [
        _safe(passive_subdomains(target, limit=limit, deep=True), 120, "subdomains"),
        _safe(urlscan_search(target, limit=20), 60, "urlscan"),
        _safe(commoncrawl_urls(target, limit=min(limit * 2, 500)), 120, "commoncrawl"),
        _safe(api_discovery(target, limit=60), 90, "api"),
        _safe(well_known(target), 60, "well_known"),
        _safe(email_security(target), 90, "email"),
        _safe(threat_reputation(target), 120, "threat"),
        _safe(favicon_hash(base), 60, "favicon"),
    ]
    raw = await asyncio.gather(*coros, return_exceptions=True)
    results = {}
    for key, value in zip(keys, raw, strict=False):
        results[key] = value if not isinstance(value, BaseException) else {"ok": False, "error": str(value)}

    subdomains = results["subdomains"] if isinstance(results["subdomains"], dict) else {}
    urlscan = results["urlscan"] if isinstance(results["urlscan"], dict) else {}
    crawl = results["commoncrawl"] if isinstance(results["commoncrawl"], dict) else {}
    api = results["api"] if isinstance(results["api"], dict) else {}
    wk = results["well_known"] if isinstance(results["well_known"], dict) else {}
    email = results["email"] if isinstance(results["email"], dict) else {}
    threat = results["threat"] if isinstance(results["threat"], dict) else {}
    favicon = results["favicon"] if isinstance(results["favicon"], dict) else {}

    summary = {
        "subdomains": subdomains.get("count"),
        "subdomain_sources": subdomains.get("sources"),
        "urlscan_results": urlscan.get("count"),
        "commoncrawl_urls": crawl.get("count"),
        "api_paths_found": api.get("found_count"),
        "sensitive_paths_exposed": [item.get("path") for item in api.get("exposed_sensitive", [])],
        "well_known_documents": wk.get("found_count"),
        "email_grade": email.get("grade"),
        "email_score": email.get("score"),
        "threat_verdict": threat.get("verdict"),
        "threat_signals": threat.get("signal_count"),
        "favicon_shodan_query": favicon.get("shodan_query"),
    }
    return {
        "ok": True,
        "target": target,
        "summary": summary,
        "results": results,
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }
