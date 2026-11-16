"""Threat-intelligence tools: OTX, VirusTotal, CVE, DNSBL, Tor, GreyNoise, RDAP."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import re
import socket
import time
from typing import Any

import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

from .common import (
    api_key,
    cache_get,
    cache_set,
    clip,
    get_json,
    guarded,
    normalize_target,
    request,
    utcnow,
)

VT_BASE = "https://www.virustotal.com/api/v3"
CIRCL_CVE = "https://cve.circl.lu/api/cve"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
OPENPHISH_FEED = "https://openphish.com/feed.txt"

_NS_CACHE: dict[str, tuple[float, list[str]]] = {}


def _json_or_none(response) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def _dt(value: Any) -> str | None:
    """VirusTotal/OTX timestamps are unix seconds; return ISO for readability."""
    if value in (None, "", 0):
        return None
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(value)))
    except Exception:
        return str(value)


def _stats(attributes: dict) -> dict:
    stats = attributes.get("last_analysis_stats") or {}
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout": stats.get("timeout", 0),
    }


def _engine_hits(attributes: dict, limit: int = 15) -> list[dict]:
    results = attributes.get("last_analysis_results") or {}
    hits = []
    for engine, result in results.items():
        category = (result or {}).get("category")
        if category in ("malicious", "suspicious"):
            hits.append(
                {
                    "engine": engine,
                    "category": category,
                    "result": (result or {}).get("result"),
                    "method": (result or {}).get("method"),
                }
            )
    hits.sort(key=lambda item: (item["category"] != "malicious", item["engine"]))
    return hits[:limit]


def _mask(secret: str) -> str:
    if len(secret) <= 8:
        return "***"
    return secret[:4] + "..." + secret[-4:]


# --------------------------------------------------------------------------- OTX
def _otx_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    key = api_key("otx")
    if key:
        headers["X-OTX-API-KEY"] = key
    return headers


def _otx_pulse(pulse: dict) -> dict:
    return {
        "name": pulse.get("name"),
        "author": (pulse.get("author") or {}).get("username"),
        "created": pulse.get("created"),
        "modified": pulse.get("modified"),
        "tags": (pulse.get("tags") or [])[:10],
        "adversary": pulse.get("adversary"),
        "malware_families": (pulse.get("malware_families") or [])[:10],
        "attack_ids": [
            {"id": item.get("id"), "name": item.get("name")}
            for item in (pulse.get("attack_ids") or [])[:10]
        ],
        "targeted_countries": (pulse.get("targeted_countries") or [])[:10],
        "references": (pulse.get("references") or [])[:5],
    }


@guarded
async def otx_domain(domain: str, limit: int = 50) -> dict:
    """AlienVault OTX threat profile for a domain: pulses, malware, hosted URLs, validation.

    Uses the OTX DirectConnect API. A key (OTX_API_KEY or keys.json) raises limits;
    without one, OTX may return 403/429. Passive-DNS is intentionally skipped because
    OTX frequently returns 504 for it.
    """
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}
    limit = max(1, min(int(limit), 200))
    headers = _otx_headers()

    sections = {
        "general": f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general",
        "url_list": f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/url_list",
        "malware": f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/malware",
    }

    async def fetch(name: str, url: str):
        try:
            response = await request(url, headers=headers, timeout=45.0)
            return name, response.status_code, _json_or_none(response), clip(response.text, 300)
        except Exception as exc:
            return name, 0, None, f"{type(exc).__name__}: {exc}"

    results = await asyncio.gather(*(fetch(name, url) for name, url in sections.items()))
    by_name = {name: (status, data, err) for name, status, data, err in results}

    general_status, general, general_err = by_name["general"]
    if general_status in (401, 403):
        return {
            "ok": False,
            "domain": target,
            "error": f"OTX returned HTTP {general_status}",
            "hint": "Set OTX_API_KEY (free key at otx.alienvault.com/api) or add it to ~/.config/osint-mcp/keys.json.",
        }
    if general_status == 429:
        return {
            "ok": False,
            "domain": target,
            "error": "OTX rate limit exceeded",
            "hint": "Retry later or add OTX_API_KEY for a higher quota.",
        }
    if not isinstance(general, dict):
        return {
            "ok": False,
            "domain": target,
            "error": f"OTX general lookup failed (HTTP {general_status})",
            "detail": general_err,
        }

    pulse_info = general.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    url_status, url_data, url_err = by_name["url_list"]
    mal_status, mal_data, mal_err = by_name["malware"]

    urls = []
    if isinstance(url_data, dict):
        for item in (url_data.get("url_list") or [])[:limit]:
            urls.append(
                {
                    "url": item.get("url"),
                    "hostname": item.get("hostname"),
                    "date": item.get("date"),
                    "http_code": item.get("httpcode"),
                    "gsb": item.get("gsb") or [],
                }
            )

    malware = []
    if isinstance(mal_data, dict):
        for item in (mal_data.get("malware") or [])[:limit]:
            if isinstance(item, dict):
                malware.append(
                    {
                        "hash": item.get("hash"),
                        "detections": item.get("detections"),
                        "date": item.get("date"),
                        "name": item.get("name"),
                    }
                )

    validation = []
    for item in general.get("validation") or []:
        if isinstance(item, dict):
            validation.append(
                {
                    "source": item.get("source"),
                    "name": item.get("name"),
                    "message": item.get("message"),
                }
            )

    return {
        "ok": True,
        "domain": target,
        "pulse_count": pulse_info.get("count", len(pulses)),
        "pulses": [_otx_pulse(pulse) for pulse in pulses[:10]],
        "validation": validation[:20],
        "false_positive": general.get("false_positive"),
        "alexa": general.get("alexa"),
        "whois": general.get("whois"),
        "url_count": len(urls),
        "urls": urls,
        "malware_count": len(malware),
        "malware": malware,
        "section_errors": {
            "url_list": url_err if url_status not in (200,) else None,
            "malware": mal_err if mal_status not in (200,) else None,
        },
        "key_used": bool(api_key("otx")),
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# ------------------------------------------------------------------- VirusTotal
def _vt_kind(target: str, kind: str) -> tuple[str, str]:
    value = (target or "").strip()
    requested = (kind or "auto").strip().lower()
    if requested in ("ip", "domain", "url", "file", "hash"):
        return ("file" if requested == "hash" else requested), value
    if value.startswith(("http://", "https://")):
        return "url", value
    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        return "file", value.lower()
    return "domain", normalize_target(value)


def _vt_endpoint(kind: str, value: str) -> str:
    if kind == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"{VT_BASE}/urls/{url_id}"
    if kind == "file":
        return f"{VT_BASE}/files/{value}"
    if kind == "ip":
        return f"{VT_BASE}/ip_addresses/{value}"
    return f"{VT_BASE}/domains/{value}"


def _vt_dns_records(attributes: dict, limit: int = 40) -> list[dict]:
    records = attributes.get("last_dns_records") or []
    out = []
    for record in records[:limit]:
        if isinstance(record, dict):
            out.append(
                {
                    "type": record.get("type"),
                    "value": record.get("value"),
                    "ttl": record.get("ttl"),
                }
            )
    return out


@guarded
async def virustotal_report(target: str, kind: str = "auto") -> dict:
    """VirusTotal v3 report for an IP, domain, URL or file hash.

    `kind` is auto|ip|domain|url|file. Requires VIRUSTOTAL_API_KEY (or
    VT_API_KEY, or a "virustotal" entry in ~/.config/osint-mcp/keys.json).
    Free keys allow about 4 requests/minute.
    """
    key = api_key("virustotal", "vt")
    if not key:
        return {
            "ok": False,
            "error": "VirusTotal API key not configured",
            "hint": "Set VIRUSTOTAL_API_KEY or add {\"virustotal\": \"...\"} to ~/.config/osint-mcp/keys.json.",
        }
    resolved_kind, value = _vt_kind(target, kind)
    if not value:
        return {"ok": False, "error": "empty target"}

    response = await request(
        _vt_endpoint(resolved_kind, value),
        headers={"x-apikey": key, "Accept": "application/json"},
        timeout=40.0,
    )
    if response.status_code == 404:
        return {
            "ok": True,
            "found": False,
            "kind": resolved_kind,
            "target": value,
            "note": "VirusTotal has no record for this object yet.",
        }
    if response.status_code in (401, 403):
        return {
            "ok": False,
            "error": f"VirusTotal rejected the API key (HTTP {response.status_code})",
            "hint": "Check VIRUSTOTAL_API_KEY or regenerate the key at virustotal.com/gui/my-apikey.",
        }
    if response.status_code == 429:
        return {
            "ok": False,
            "error": "VirusTotal API quota exceeded",
            "hint": "Free keys allow about 4 requests/minute; retry shortly.",
        }
    if response.status_code != 200:
        return {
            "ok": False,
            "error": f"VirusTotal HTTP {response.status_code}",
            "body": clip(response.text, 400),
        }

    payload = response.json()
    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}
    result = {
        "ok": True,
        "found": True,
        "kind": resolved_kind,
        "target": value,
        "id": data.get("id"),
        "stats": _stats(attributes),
        "reputation": attributes.get("reputation"),
        "tags": attributes.get("tags") or [],
        "categories": attributes.get("categories") or {},
        "total_votes": attributes.get("total_votes") or {},
        "times_submitted": attributes.get("times_submitted"),
        "first_submission": _dt(attributes.get("first_submission_date")),
        "last_submission": _dt(attributes.get("last_submission_date")),
        "last_analysis": _dt(attributes.get("last_analysis_date")),
        "engine_hits": _engine_hits(attributes),
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }

    if resolved_kind == "ip":
        result.update(
            {
                "as_owner": attributes.get("as_owner"),
                "asn": attributes.get("asn"),
                "network": attributes.get("network"),
                "country": attributes.get("country"),
                "continent": attributes.get("continent"),
                "rir": attributes.get("regional_internet_registry"),
                "whois": clip(attributes.get("whois"), 4000),
            }
        )
    elif resolved_kind == "domain":
        cert = attributes.get("last_https_certificate") or {}
        result.update(
            {
                "registrar": attributes.get("registrar"),
                "created": _dt(attributes.get("creation_date")),
                "updated": _dt(attributes.get("last_update_date")),
                "expires": _dt(attributes.get("expiration_date")),
                "dns_records": _vt_dns_records(attributes),
                "whois": clip(attributes.get("whois"), 4000),
                "popularity": attributes.get("popularity_ranks") or {},
                "certificate": {
                    "issuer": ((cert.get("issuer") or {}).get("CN") if isinstance(cert, dict) else None),
                    "subject": ((cert.get("subject") or {}).get("CN") if isinstance(cert, dict) else None),
                    "valid_from": (cert.get("validity") or {}).get("not_before") if isinstance(cert, dict) else None,
                    "valid_to": (cert.get("validity") or {}).get("not_after") if isinstance(cert, dict) else None,
                }
                if cert
                else None,
            }
        )
    elif resolved_kind == "url":
        result.update(
            {
                "url": attributes.get("url"),
                "final_url": attributes.get("last_final_url"),
                "title": attributes.get("title"),
                "http_code": attributes.get("last_http_response_code"),
                "content_length": attributes.get("last_http_response_content_length"),
                "first_seen": _dt(attributes.get("first_submission_date")),
            }
        )
    else:
        signature = attributes.get("signature_info") or {}
        result.update(
            {
                "names": (attributes.get("names") or [])[:10],
                "meaningful_name": attributes.get("meaningful_name"),
                "type_description": attributes.get("type_description"),
                "size": attributes.get("size"),
                "magic": attributes.get("magic"),
                "sha256": attributes.get("sha256"),
                "sha1": attributes.get("sha1"),
                "md5": attributes.get("md5"),
                "ssdeep": attributes.get("ssdeep"),
                "vhash": attributes.get("vhash"),
                "signature": {
                    "product": signature.get("product"),
                    "description": signature.get("description"),
                    "signers": signature.get("signers"),
                }
                if signature
                else None,
            }
        )

    return result


# -------------------------------------------------------------------------- CVE
def _cvss_from_circl(data: dict) -> dict | None:
    for key in ("cvss4", "cvss3", "cvss"):
        value = data.get(key)
        if isinstance(value, (int, float)):
            return {"version": key, "score": value}
        if isinstance(value, dict) and value:
            return {
                "version": key,
                "score": value.get("score") or value.get("baseScore") or value.get("cvssV3"),
                "vector": value.get("vector") or value.get("vectorString"),
                "severity": value.get("severity") or value.get("baseSeverity"),
            }
    return None


def _cvss_from_nvd(cve: dict) -> dict | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            entry = entries[0]
            data = entry.get("cvssData") or {}
            return {
                "version": key,
                "score": data.get("baseScore"),
                "vector": data.get("vectorString"),
                "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
            }
    return None


def _kev_entry(cve_id: str) -> dict | None:
    cached = cache_get("cisa_kev", ttl=6 * 3600)
    if cached is None:
        try:
            response = request_sync_kev()
            cached = response
            cache_set("cisa_kev", cached)
        except Exception:
            return None
    for item in cached.get("vulnerabilities", []):
        if (item.get("cveID") or "").upper() == cve_id.upper():
            return {
                "listed": True,
                "vendor": item.get("vendorProject"),
                "product": item.get("product"),
                "name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "required_action": item.get("requiredAction"),
                "ransomware": item.get("knownRansomwareCampaignUse"),
                "notes": item.get("notes"),
            }
    return {"listed": False}


def request_sync_kev() -> dict:
    """Fetch the CISA KEV catalogue synchronously (called via to_thread)."""
    import httpx

    response = httpx.get(KEV_URL, timeout=60.0, follow_redirects=True)
    response.raise_for_status()
    return response.json()


async def _kev_entry_async(cve_id: str) -> dict | None:
    return await asyncio.to_thread(_kev_entry, cve_id)


@guarded
async def cve_intel(cve_id: str) -> dict:
    """CVE intelligence: description, CVSS, CWE, EPSS score and CISA KEV status.

    Combines CIRCL CVE, FIRST EPSS and the CISA Known Exploited Vulnerabilities
    catalogue, with NVD as a fallback. Keyless.
    """
    cve = (cve_id or "").strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
        return {"ok": False, "error": "CVE must look like CVE-2021-44228"}

    async def circl():
        try:
            return await get_json(f"{CIRCL_CVE}/{cve}", timeout=45.0)
        except Exception:
            return None

    async def epss():
        try:
            data = await get_json(f"{EPSS_API}?cve={cve}", timeout=30.0)
            entries = (data or {}).get("data") or []
            return entries[0] if entries else None
        except Exception:
            return None

    async def nvd():
        try:
            data = await get_json(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
                timeout=45.0,
                headers={"Accept": "application/json"},
            )
            items = (data or {}).get("vulnerabilities") or []
            return items[0].get("cve") if items else None
        except Exception:
            return None

    circl_data, epss_data, kev_data, nvd_data = await asyncio.gather(
        circl(), epss(), _kev_entry_async(cve), nvd()
    )

    description = None
    cvss = None
    cwe = []
    references = []
    published = modified = None
    affected = []

    if isinstance(circl_data, dict) and circl_data.get("summary"):
        description = circl_data.get("summary")
        cvss = _cvss_from_circl(circl_data)
        cwe = circl_data.get("cwe") or circl_data.get("cwe_list") or []
        references = circl_data.get("references") or []
        published = circl_data.get("Published")
        modified = circl_data.get("Modified")
        affected = [
            item for item in (circl_data.get("vulnerable_product") or circl_data.get("vulnerable_configuration") or [])
            if isinstance(item, str)
        ][:30]

    if isinstance(nvd_data, dict):
        if not description:
            for item in nvd_data.get("descriptions") or []:
                if item.get("lang") == "en":
                    description = item.get("value")
                    break
        if not cvss:
            cvss = _cvss_from_nvd(nvd_data)
        published = published or nvd_data.get("published")
        modified = modified or nvd_data.get("lastModified")
        for weakness in nvd_data.get("weaknesses") or []:
            for item in weakness.get("description") or []:
                if item.get("value") and item["value"] not in cwe:
                    cwe.append(item["value"])
        for reference in nvd_data.get("references") or []:
            url = reference.get("url")
            if url and url not in references:
                references.append(url)

    if not description and not cvss and not (epss_data or {}).get("epss"):
        return {
            "ok": False,
            "cve": cve,
            "error": "No data found (CIRCL and NVD both failed or returned nothing)",
        }

    if isinstance(cwe, list):
        cleaned_cwe = []
        for item in cwe:
            if isinstance(item, dict):
                cleaned_cwe.append(item.get("id") or item.get("value") or item.get("name"))
            elif item:
                cleaned_cwe.append(str(item))
        cwe = cleaned_cwe

    epss = None
    if isinstance(epss_data, dict):
        try:
            epss = {
                "score": float(epss_data.get("epss")),
                "percentile": float(epss_data.get("percentile")),
                "date": epss_data.get("date"),
            }
        except (TypeError, ValueError):
            epss = epss_data

    return {
        "ok": True,
        "cve": cve,
        "description": clip(description, 4000),
        "cvss": cvss,
        "cwe": cwe[:20],
        "published": published,
        "modified": modified,
        "epss": epss,
        "kev": kev_data or {"listed": None, "error": "KEV catalogue unavailable"},
        "exploited": bool((kev_data or {}).get("listed")),
        "affected_products": affected,
        "references": references[:30],
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# ------------------------------------------------------------------------ DNSBL
DNSBL_ZONES = [
    ("spamhaus_zen", "zen.spamhaus.org", "Spamhaus ZEN (SBL/XBL/PBL/DROP)"),
    ("barracuda", "b.barracudacentral.org", "Barracuda BRBL"),
    ("spamcop", "bl.spamcop.net", "SpamCop"),
    ("sorbs", "dnsbl.sorbs.net", "SORBS"),
    ("psbl", "psbl.surriel.com", "Passive Spam Block List"),
    ("uceprotect1", "dnsbl-1.uceprotect.net", "UCEPROTECT Level 1"),
]

SPAMHAUS_CODES = {
    "127.0.0.2": "SBL - spam source",
    "127.0.0.3": "SBL CSS - snowshoe spam",
    "127.0.0.4": "XBL - exploited machine",
    "127.0.0.5": "XBL - exploited machine",
    "127.0.0.6": "XBL - exploited machine",
    "127.0.0.7": "XBL - exploited machine",
    "127.0.0.9": "DROP - hijacked netblock",
    "127.0.0.10": "PBL - dynamic/residential IP",
    "127.0.0.11": "PBL - dynamic/residential IP",
    "127.255.255.252": "error: typo in queried domain",
    "127.255.255.253": "error: query blocked (MBU)",
    "127.255.255.254": "error: query via open resolver",
    "127.255.255.255": "error: too many queries",
}

DBL_CODES = {
    "127.0.1.2": "spam domain",
    "127.0.1.4": "phishing domain",
    "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet C&C domain",
    "127.0.1.102": "abused legitimate domain",
}


def _zone_nameservers(zone: str) -> list[str]:
    cached = _NS_CACHE.get(zone)
    if cached and time.time() - cached[0] < 3600:
        return cached[1]
    ips: list[str] = []
    try:
        answers = dns.resolver.resolve(zone, "NS", lifetime=6)
        for name in [str(item).rstrip(".") for item in answers][:4]:
            try:
                for address in dns.resolver.resolve(name, "A", lifetime=5):
                    ips.append(str(address))
            except Exception:
                continue
    except Exception:
        ips = []
    if ips:
        _NS_CACHE[zone] = (time.time(), ips)
    return ips


def _query_zone(zone: str, qname: str) -> dict:
    servers = _zone_nameservers(zone)
    if not servers:
        return {"status": "error", "error": "could not resolve zone nameservers"}
    last_error = ""
    for server in servers[:3]:
        try:
            query = dns.message.make_query(qname, "A")
            reply = dns.query.udp(query, server, timeout=4.0)
            if reply.rcode() == 3:  # NXDOMAIN
                return {"status": "not_listed", "server": server}
            if reply.rcode() != 0:
                last_error = f"rcode {reply.rcode()} from {server}"
                continue
            codes = []
            for rrset in reply.answer:
                for item in rrset:
                    if item.rdtype == dns.rdatatype.A:
                        codes.append(item.address)
            if codes:
                return {"status": "listed", "codes": codes, "server": server}
            return {"status": "not_listed", "server": server}
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
    return {"status": "error", "error": last_error or "all nameservers timed out"}


def _reverse_ip_name(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.version == 4:
        return ".".join(reversed(str(ip).split(".")))
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles))


async def _check_zone(zone: str, qname: str, label: str, codes_map: dict[str, str] | None = None) -> dict:
    raw = await asyncio.to_thread(_query_zone, zone, qname)
    entry = {"zone": zone, "label": label, "listed": raw.get("status") == "listed"}
    codes = raw.get("codes") or []
    if codes:
        entry["codes"] = codes
        if codes_map:
            entry["meaning"] = [codes_map.get(code, f"listed ({code})") for code in codes]
        else:
            entry["meaning"] = ["listed"]
        if any(code.startswith("127.255.255.") for code in codes):
            entry["listed"] = False
            entry["error"] = codes_map.get(codes[0], "query error") if codes_map else "query error"
    if raw.get("status") == "error":
        entry["error"] = raw.get("error")
    return entry


@guarded
async def dnsbl_check(target: str, include_errors: bool = False) -> dict:
    """Check an IP (or domain) against major DNS blocklists via direct DNS queries.

    Queries Spamhaus ZEN, Barracuda, SpamCop, SORBS, PSBL and UCEPROTECT, bypassing
    open-resolver blocks by talking to each zone's authoritative nameservers.
    Domains are checked against Spamhaus DBL. Some zones may be unreachable.
    """
    value = (target or "").strip()
    if not value:
        return {"ok": False, "error": "empty target"}

    is_ip = False
    try:
        ipaddress.ip_address(value)
        is_ip = True
    except ValueError:
        value = normalize_target(value)
        if not value or "." not in value:
            return {"ok": False, "error": "provide an IPv4/IPv6 address or a domain"}

    if is_ip:
        reversed_ip = _reverse_ip_name(value)
        tasks = [
            _check_zone(zone, f"{reversed_ip}.{zone}", label, SPAMHAUS_CODES if zone == "zen.spamhaus.org" else None)
            for _key, zone, label in DNSBL_ZONES
        ]
        results = await asyncio.gather(*tasks)
        listed = [item for item in results if item.get("listed")]
        errors = [item for item in results if item.get("error")]
        if not include_errors:
            results = [item for item in results if not item.get("error")]
        return {
            "ok": True,
            "target": value,
            "type": "ip",
            "listed": bool(listed),
            "listed_count": len(listed),
            "listed_in": [item["zone"] for item in listed],
            "results": results,
            "errors": len(errors),
            "note": "Some blocklists may be offline or refuse queries; treat errors as unknown, not clean."
            if errors
            else None,
        }

    results = await asyncio.gather(
        _check_zone("dbl.spamhaus.org", f"{value}.dbl.spamhaus.org", "Spamhaus DBL", DBL_CODES),
    )
    listed = [item for item in results if item.get("listed")]
    return {
        "ok": True,
        "target": value,
        "type": "domain",
        "listed": bool(listed),
        "listed_count": len(listed),
        "listed_in": [item["zone"] for item in listed],
        "results": results,
        "note": "Domain checks use Spamhaus DBL only.",
    }


# -------------------------------------------------------------------------- Tor
@guarded
async def tor_exit_check(target: str) -> dict:
    """Check whether an IP (or a domain's IPs) is a Tor exit node.

    Uses the Tor Project's public bulk exit list, cached for 30 minutes.
    """
    value = (target or "").strip()
    if not value:
        return {"ok": False, "error": "empty target"}

    ips: list[str] = []
    try:
        ipaddress.ip_address(value)
        ips = [value]
    except ValueError:
        host = normalize_target(value)
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, host, None, socket.AF_INET)
            ips = sorted({info[4][0] for info in infos})
        except Exception as exc:
            return {"ok": False, "error": f"cannot resolve {host}: {exc}"}

    exit_list = cache_get("tor_exit_list", ttl=1800)
    if exit_list is None:
        response = await request(TOR_EXIT_URL, timeout=45.0)
        if response.status_code != 200:
            return {"ok": False, "error": f"Tor exit list HTTP {response.status_code}"}
        exit_list = {line.strip() for line in response.text.splitlines() if line.strip()}
        cache_set("tor_exit_list", exit_list)

    matched = [ip for ip in ips if ip in exit_list]
    return {
        "ok": True,
        "target": value,
        "ips": ips,
        "is_tor_exit": bool(matched),
        "matched_ips": matched,
        "exit_node_count": len(exit_list),
        "note": None if ips else "Target did not resolve to an IPv4 address.",
    }


# -------------------------------------------------------------------- GreyNoise
@guarded
async def greynoise_ip(ip: str) -> dict:
    """GreyNoise community lookup: is this IP mass-scanning the internet (noise/RIOT)?

    Keyless for the community endpoint; GREYNOISE_API_KEY is optional.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "invalid IP address"}

    headers = {"Accept": "application/json"}
    key = api_key("greynoise")
    if key:
        headers["key"] = key
    response = await request(f"https://api.greynoise.io/v3/community/{ip}", headers=headers, timeout=25.0)
    data = _json_or_none(response) or {}
    if response.status_code not in (200, 404):
        return {
            "ok": False,
            "ip": ip,
            "error": f"GreyNoise HTTP {response.status_code}",
            "body": clip(response.text, 300),
        }
    return {
        "ok": True,
        "ip": ip,
        "noise": bool(data.get("noise")),
        "riot": bool(data.get("riot")),
        "classification": data.get("classification"),
        "name": data.get("name"),
        "link": data.get("link"),
        "last_seen": data.get("last_seen"),
        "message": data.get("message"),
        "observed": response.status_code == 200,
    }


# ----------------------------------------------------------------------- RDAP IP
def _vcard(entity: dict) -> dict:
    props: dict[str, str] = {}
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[3]:
                value = item[3]
                if isinstance(value, list):
                    value = ", ".join(str(part) for part in value)
                props[str(item[0])] = str(value)
    return props


@guarded
async def ip_whois(ip: str) -> dict:
    """RDAP registration data for an IP: network range, holder, ASN, contacts, events."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "invalid IP address"}

    response = await request(f"https://rdap.org/ip/{ip}", timeout=40.0)
    if response.status_code != 200:
        return {"ok": False, "ip": ip, "error": f"RDAP HTTP {response.status_code}"}
    data = response.json()

    events = {}
    for event in data.get("events") or []:
        if event.get("eventAction") and event.get("eventDate"):
            events[event["eventAction"]] = event["eventDate"]

    contacts = []
    for entity in data.get("entities") or []:
        props = _vcard(entity)
        contacts.append(
            {
                "roles": entity.get("roles") or [],
                "handle": entity.get("handle"),
                "name": props.get("fn"),
                "org": props.get("org"),
                "email": props.get("email"),
                "phone": props.get("tel"),
                "url": props.get("url"),
            }
        )

    remarks = []
    for remark in data.get("remarks") or []:
        if remark.get("description"):
            remarks.append(" ".join(str(item) for item in remark["description"]))

    return {
        "ok": True,
        "ip": ip,
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "country": data.get("country"),
        "ip_version": data.get("ipVersion"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "parent_handle": data.get("parentHandle"),
        "status": data.get("status") or [],
        "registered": events.get("registration"),
        "last_changed": events.get("last changed"),
        "contacts": contacts[:15],
        "remarks": remarks[:5],
    }


# ---------------------------------------------------------------------- URLhaus
@guarded
async def urlhaus_lookup(target: str) -> dict:
    """Look up a host/domain/URL in abuse.ch URLhaus (requires URLHAUS_AUTH_KEY).

    abuse.ch now requires a free Auth-Key from auth.abuse.ch; without it this tool
    returns a clear needs_key result instead of a cryptic 401.
    """
    key = os.environ.get("URLHAUS_AUTH_KEY") or api_key("urlhaus")
    if not key:
        return {
            "ok": False,
            "needs_key": True,
            "target": target,
            "error": "URLhaus requires an abuse.ch Auth-Key",
            "hint": "Create one at https://auth.abuse.ch/ then set URLHAUS_AUTH_KEY or add {\"urlhaus\": \"...\"} to keys.json.",
        }
    value = (target or "").strip()
    if not value:
        return {"ok": False, "error": "empty target"}
    is_url = value.startswith(("http://", "https://"))
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/" if is_url else "https://urlhaus-api.abuse.ch/v1/host/"
    payload = {"url": value} if is_url else {"host": normalize_target(value)}
    response = await request(
        endpoint,
        method="POST",
        data=payload,
        headers={"Auth-Key": key, "Accept": "application/json"},
        timeout=30.0,
    )
    if response.status_code == 401:
        return {"ok": False, "error": "URLhaus rejected the Auth-Key (HTTP 401)"}
    data = _json_or_none(response) or {}
    status = data.get("query_status")
    if status == "no_results":
        return {"ok": True, "found": False, "target": value, "status": status}
    if response.status_code != 200:
        return {"ok": False, "error": f"URLhaus HTTP {response.status_code}", "body": clip(response.text, 300)}

    urls = []
    for item in (data.get("urls") or [])[:50]:
        urls.append(
            {
                "url": item.get("url"),
                "status": item.get("url_status"),
                "threat": item.get("threat"),
                "tags": item.get("tags"),
                "date_added": item.get("date_added"),
                "reporter": item.get("reporter"),
            }
        )
    payloads = []
    for item in (data.get("payloads") or [])[:20]:
        payloads.append(
            {
                "sha256": item.get("sha256_hash"),
                "file_type": item.get("file_type"),
                "signature": item.get("signature"),
                "first_seen": item.get("firstseen"),
            }
        )
    return {
        "ok": True,
        "found": status == "ok",
        "target": value,
        "status": status,
        "urls": urls,
        "payloads": payloads,
        "blacklists": data.get("blacklists") or {},
    }


# -------------------------------------------------------------------- PeeringDB
@guarded
async def peeringdb_network(query: str) -> dict:
    """PeeringDB network profile by ASN (AS15169) or name: policy, IX and facility presence."""
    value = (query or "").strip()
    if not value:
        return {"ok": False, "error": "empty query"}
    params: dict[str, Any]
    if re.fullmatch(r"(?i)as\d+", value):
        params = {"asn": int(value[2:])}
    elif re.fullmatch(r"\d+", value):
        params = {"asn": int(value)}
    else:
        params = {"name__contains": value, "limit": 5}
    response = await request("https://www.peeringdb.com/api/net", params=params, timeout=30.0)
    if response.status_code != 200:
        return {"ok": False, "error": f"PeeringDB HTTP {response.status_code}"}
    networks = (response.json() or {}).get("data") or []
    if not networks:
        return {"ok": True, "query": value, "found": False, "networks": []}
    out = []
    for net in networks[:5]:
        out.append(
            {
                "asn": net.get("asn"),
                "name": net.get("name"),
                "aka": net.get("aka"),
                "website": net.get("website"),
                "looking_glass": net.get("looking_glass"),
                "irr_as_set": net.get("irr_as_set"),
                "info_type": net.get("info_type"),
                "policy": net.get("policy_general"),
                "traffic": net.get("traffic"),
                "ratio": net.get("ratio"),
                "scope": net.get("scope"),
                "ix_count": len(net.get("netixlan_set") or []),
                "facility_count": len(net.get("netfac_set") or []),
                "ix": [
                    {"name": item.get("name"), "ix_id": item.get("ix_id"), "speed": item.get("speed")}
                    for item in (net.get("netixlan_set") or [])[:20]
                ],
                "facilities": [
                    {"name": item.get("name"), "city": item.get("city"), "country": item.get("country")}
                    for item in (net.get("netfac_set") or [])[:20]
                ],
            }
        )
    return {"ok": True, "query": value, "found": True, "count": len(out), "networks": out}


# -------------------------------------------------------------------- OpenPhish
@guarded
async def openphish_check(url: str) -> dict:
    """Check a URL or domain against the OpenPhish public phishing feed (keyless)."""
    from urllib.parse import urlparse

    value = (url or "").strip()
    if not value:
        return {"ok": False, "error": "empty target"}
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or "").lower()
    if not host:
        return {"ok": False, "error": "could not parse host"}

    feed = cache_get("openphish_feed", ttl=600)
    if feed is None:
        response = await request(OPENPHISH_FEED, timeout=30.0)
        if response.status_code != 200:
            return {"ok": False, "error": f"OpenPhish feed HTTP {response.status_code}"}
        feed = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
        cache_set("openphish_feed", feed)

    normalized = value.rstrip("/")
    exact = []
    host_hits = []
    for item in feed:
        if item.rstrip("/") == normalized:
            exact.append(item)
        else:
            item_host = (urlparse(item).hostname or "").lower()
            if item_host == host:
                host_hits.append(item)

    return {
        "ok": True,
        "target": value,
        "host": host,
        "listed": bool(exact or host_hits),
        "exact_match": bool(exact),
        "host_match_count": len(host_hits),
        "matches": (exact + host_hits)[:20],
        "feed_size": len(feed),
        "checked_at": utcnow().isoformat(timespec="seconds"),
        "note": None if exact else ("Host appears in the feed but this exact URL does not." if host_hits else None),
    }


# ------------------------------------------------------------------- Composite
async def _internetdb(ip: str) -> dict | None:
    try:
        response = await request(f"https://internetdb.shodan.io/{ip}", timeout=20.0)
        if response.status_code != 200:
            return None
        data = response.json()
        return {
            "ports": sorted(data.get("ports") or []),
            "hostnames": (data.get("hostnames") or [])[:20],
            "tags": (data.get("tags") or [])[:20],
            "vulns": (data.get("vulns") or [])[:30],
        }
    except Exception:
        return None


def _verdict(signals: list[dict]) -> str:
    high = any(item.get("severity") == "high" for item in signals)
    medium = any(item.get("severity") == "medium" for item in signals)
    if high:
        return "high_risk"
    if medium:
        return "suspicious"
    return "low_risk"


@guarded
async def threat_reputation(target: str) -> dict:
    """One-shot reputation verdict for an IP, domain, URL or file hash.

    Aggregates VirusTotal, OTX, GreyNoise, Tor exit status, DNS blocklists,
    Shodan InternetDB and OpenPhish where applicable. Requires VIRUSTOTAL_API_KEY;
    the other sources are keyless or optional.
    """
    value = (target or "").strip()
    if not value:
        return {"ok": False, "error": "empty target"}
    kind, normalized = _vt_kind(value, "auto")
    signals: list[dict] = []
    details: dict[str, Any] = {}
    tasks: dict[str, Any] = {}

    if kind == "ip":
        tasks = {
            "virustotal": virustotal_report(normalized),
            "greynoise": greynoise_ip(normalized),
            "tor": tor_exit_check(normalized),
            "dnsbl": dnsbl_check(normalized),
            "internetdb": _internetdb(normalized),
        }
    elif kind == "domain":
        tasks = {
            "virustotal": virustotal_report(normalized),
            "otx": otx_domain(normalized, limit=20),
            "openphish": openphish_check(f"https://{normalized}"),
        }
    elif kind == "url":
        tasks = {
            "virustotal": virustotal_report(value),
            "openphish": openphish_check(value),
        }
    else:
        tasks = {"virustotal": virustotal_report(normalized)}

    keys = list(tasks)
    results = await asyncio.gather(*(tasks[key] for key in keys))
    for key, result in zip(keys, results, strict=False):
        details[key] = result

    vt = details.get("virustotal") or {}
    if vt.get("ok") and vt.get("found"):
        stats = vt.get("stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        if malicious >= 3:
            signals.append({"source": "virustotal", "severity": "high", "detail": f"{malicious} engines flag malicious"})
        elif malicious or suspicious:
            signals.append(
                {
                    "source": "virustotal",
                    "severity": "medium",
                    "detail": f"{malicious} malicious / {suspicious} suspicious engine verdicts",
                }
            )
        if (vt.get("reputation") or 0) < -20:
            signals.append({"source": "virustotal", "severity": "medium", "detail": f"reputation {vt['reputation']}"})

    if kind == "ip":
        gn = details.get("greynoise") or {}
        if gn.get("ok"):
            if gn.get("classification") == "malicious":
                signals.append({"source": "greynoise", "severity": "high", "detail": "classified malicious"})
            elif gn.get("noise"):
                signals.append({"source": "greynoise", "severity": "medium", "detail": "observed mass-scanning (noise)"})
        tor = details.get("tor") or {}
        if tor.get("is_tor_exit"):
            signals.append({"source": "tor", "severity": "medium", "detail": "Tor exit node"})
        bl = details.get("dnsbl") or {}
        for zone in bl.get("listed_in") or []:
            signals.append({"source": f"dnsbl:{zone}", "severity": "high", "detail": "listed on blocklist"})
        idb = details.get("internetdb") or {}
        if idb.get("vulns"):
            signals.append(
                {
                    "source": "shodan_internetdb",
                    "severity": "medium",
                    "detail": f"{len(idb['vulns'])} known vulnerabilities on exposed services",
                }
            )
    elif kind == "domain":
        otx = details.get("otx") or {}
        if otx.get("ok") and int(otx.get("pulse_count") or 0) > 0:
            severity = "high" if int(otx.get("pulse_count") or 0) >= 10 else "medium"
            signals.append(
                {
                    "source": "otx",
                    "severity": severity,
                    "detail": f"{otx.get('pulse_count')} threat pulses reference the domain",
                }
            )
        op = details.get("openphish") or {}
        if op.get("listed"):
            signals.append({"source": "openphish", "severity": "high", "detail": "listed in phishing feed"})
    elif kind == "url":
        op = details.get("openphish") or {}
        if op.get("listed"):
            signals.append({"source": "openphish", "severity": "high", "detail": "listed in phishing feed"})

    return {
        "ok": True,
        "target": value,
        "kind": kind,
        "verdict": _verdict(signals),
        "signals": signals,
        "signal_count": len(signals),
        "details": details,
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }
