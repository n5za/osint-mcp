"""Email security posture: SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT, CAA."""

from __future__ import annotations

import asyncio
import base64
import re

import dns.resolver

from .common import clip, guarded, normalize_target, request, utcnow

DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "mail",
    "s1",
    "s2",
    "dkim",
    "smtp",
    "mandrill",
    "everlytickey1",
    "cm",
]


def _resolve(name: str, rtype: str) -> list:
    try:
        answer = dns.resolver.resolve(name, rtype, lifetime=7)
        return list(answer)
    except Exception:
        return []


def _txt(name: str) -> list[str]:
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=7)
    except Exception:
        return []
    records: list[str] = []
    for rdata in answer:
        try:
            chunks = [chunk.decode("utf-8", "replace") for chunk in rdata.strings]
            records.append("".join(chunks))
        except Exception:
            records.append(str(rdata).strip('"'))
    return records


def _tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in (record or "").split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def _rsa_bits(p_value: str) -> int | None:
    try:
        der = base64.b64decode(p_value, validate=False)
    except Exception:
        return None
    match = re.search(rb"\x02\x82(..)", der, re.S)
    if match:
        length = int.from_bytes(match.group(1), "big")
        modulus = der[match.end() : match.end() + length]
        if modulus.startswith(b"\x00"):
            modulus = modulus[1:]
        return len(modulus) * 8 if modulus else None
    match = re.search(rb"\x02\x81(.)", der, re.S)
    if match:
        length = match.group(1)[0]
        modulus = der[match.end() : match.end() + length]
        if modulus.startswith(b"\x00"):
            modulus = modulus[1:]
        return len(modulus) * 8 if modulus else None
    return None


def _spf_summary(records: list[str]) -> dict:
    record = next((item for item in records if item.lower().startswith("v=spf1")), None)
    if not record:
        return {
            "present": False,
            "record": None,
            "mechanisms": [],
            "includes": [],
            "all_qualifier": None,
            "lookup_estimate": 0,
        }
    mechanisms = record.split()[1:]
    all_mechanism = next((item for item in mechanisms if item.lower().endswith("all")), None)
    qualifier = "+"
    if all_mechanism and all_mechanism[0] in "+-~?":
        qualifier = all_mechanism[0]
    includes = [
        item.split(":", 1)[1]
        for item in mechanisms
        if item.lower().startswith("include:") and ":" in item
    ]
    lookup_mechanisms = [
        item
        for item in mechanisms
        if re.match(r"^(include:|a(?:[:/]|$)|mx(?:[:/]|$)|ptr(?:[:/]|$)|exists:|redirect=)", item, re.I)
    ]
    return {
        "present": True,
        "record": record,
        "mechanisms": mechanisms,
        "includes": includes,
        "all_qualifier": qualifier,
        "all_mechanism": all_mechanism,
        "lookup_estimate": len(lookup_mechanisms),
        "ip4_count": sum(1 for item in mechanisms if item.lower().startswith("ip4:")),
        "ip6_count": sum(1 for item in mechanisms if item.lower().startswith("ip6:")),
    }


def _dmarc_summary(records: list[str]) -> dict:
    record = next((item for item in records if item.lower().startswith("v=dmarc1")), None)
    if not record:
        return {"present": False, "record": None, "tags": {}}
    tags = _tags(record)
    return {
        "present": True,
        "record": record,
        "tags": tags,
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "percentage": tags.get("pct"),
        "aggregate_reports": tags.get("rua"),
        "forensic_reports": tags.get("ruf"),
        "alignment_dkim": tags.get("adkim", "r"),
        "alignment_spf": tags.get("aspf", "r"),
        "failure_options": tags.get("fo"),
    }


def _dkim_summary(selector: str, records: list[str]) -> dict | None:
    for record in records:
        tags = _tags(record)
        if "p" not in tags and not record.lower().startswith("v=dkim1"):
            continue
        p_value = tags.get("p", "")
        return {
            "selector": selector,
            "name": f"{selector}._domainkey",
            "record": clip(record, 500),
            "version": tags.get("v"),
            "key_type": tags.get("k", "rsa"),
            "key_present": bool(p_value),
            "key_bits": _rsa_bits(p_value) if p_value else None,
            "flags": tags.get("t"),
            "notes": tags.get("n"),
            "revoked": "p" in tags and not p_value,
        }
    return None


async def _dkim_lookup(domain: str, selector: str) -> dict | None:
    records = await asyncio.to_thread(_txt, f"{selector}._domainkey.{domain}")
    if not records:
        return None
    return _dkim_summary(selector, records)


def _caa_summary(domain: str) -> dict:
    records = _resolve(domain, "CAA")
    entries = []
    for record in records:
        try:
            entries.append(
                {
                    "flags": record.flags,
                    "tag": record.tag.decode("utf-8", "replace") if isinstance(record.tag, bytes) else str(record.tag),
                    "value": record.value.decode("utf-8", "replace") if isinstance(record.value, bytes) else str(record.value),
                }
            )
        except Exception:
            entries.append({"raw": str(record)})
    return {"present": bool(entries), "records": entries}


def _mta_sts_dns(records: list[str]) -> dict:
    record = next((item for item in records if item.lower().startswith("v=stsv1")), None)
    if not record:
        return {"present": False, "record": None, "id": None}
    tags = _tags(record)
    return {"present": True, "record": record, "id": tags.get("id")}


def _tls_rpt(records: list[str]) -> dict:
    record = next((item for item in records if item.lower().startswith("v=tlsrptv1")), None)
    if not record:
        return {"present": False, "record": None, "rua": []}
    tags = _tags(record)
    rua = [item.strip() for item in (tags.get("rua") or "").split(",") if item.strip()]
    return {"present": True, "record": record, "rua": rua}


def _bimi(records: list[str]) -> dict:
    record = next((item for item in records if item.lower().startswith("v=bimi1")), None)
    if not record:
        return {"present": False, "record": None, "logo_url": None, "authority_url": None}
    tags = _tags(record)
    return {
        "present": True,
        "record": record,
        "logo_url": tags.get("l"),
        "authority_url": tags.get("a"),
    }


async def _mta_sts_policy(domain: str) -> dict:
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        response = await request(url, timeout=15.0)
        if response.status_code != 200:
            return {"url": url, "status": response.status_code, "present": False}
        policy = {"mode": None, "mx": [], "max_age": None}
        for line in response.text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key == "mx":
                policy["mx"].append(value)
            else:
                policy[key] = value
        return {
            "url": url,
            "status": response.status_code,
            "present": True,
            **policy,
            "enforced": policy.get("mode") == "enforce",
            "raw": clip(response.text, 800),
        }
    except Exception as exc:
        return {"url": url, "present": False, "error": f"{type(exc).__name__}: {exc}"}


@guarded
async def email_security(domain: str) -> dict:
    """Audit a domain's email security: SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT and CAA.

    Accepts a domain or an email address. Queries DNS TXT/MX/CAA records, checks
    common DKIM selectors, fetches the MTA-STS policy, and returns a score, grade,
    issues and concrete recommendations.
    """
    raw = (domain or "").strip()
    if "@" in raw:
        raw = raw.rsplit("@", 1)[-1]
    target = normalize_target(raw)
    if not target or "." not in target:
        return {"ok": False, "error": "provide a domain like example.com or an email address"}

    (
        mx_records,
        domain_txt,
        dmarc_txt,
        mta_sts_txt,
        tls_rpt_txt,
        bimi_txt,
    ) = await asyncio.gather(
        asyncio.to_thread(_resolve, target, "MX"),
        asyncio.to_thread(_txt, target),
        asyncio.to_thread(_txt, f"_dmarc.{target}"),
        asyncio.to_thread(_txt, f"_mta-sts.{target}"),
        asyncio.to_thread(_txt, f"_smtp._tls.{target}"),
        asyncio.to_thread(_txt, f"default._bimi.{target}"),
    )

    mx = []
    for record in mx_records:
        try:
            mx.append(
                {
                    "priority": record.preference,
                    "host": str(record.exchange).rstrip("."),
                }
            )
        except Exception:
            mx.append({"raw": str(record)})
    mx.sort(key=lambda item: item.get("priority", 9999))

    dkim_results = await asyncio.gather(
        *(_dkim_lookup(target, selector) for selector in DKIM_SELECTORS)
    )
    dkim = [item for item in dkim_results if item]

    spf = _spf_summary(domain_txt)
    dmarc = _dmarc_summary(dmarc_txt)
    caa = await asyncio.to_thread(_caa_summary, target)
    mta_sts = _mta_sts_dns(mta_sts_txt)
    tls_rpt = _tls_rpt(tls_rpt_txt)
    bimi = _bimi(bimi_txt)
    mta_sts["policy"] = await _mta_sts_policy(target)

    issues: list[str] = []
    recommendations: list[str] = []
    score = 100

    if not mx:
        score -= 10
        issues.append("No MX records found; the domain may not receive email.")
        recommendations.append("Publish MX records if this domain should receive mail.")

    if not spf["present"]:
        score -= 25
        issues.append("SPF record is missing.")
        recommendations.append("Publish a single SPF TXT record ending in -all (after validating senders).")
    else:
        if spf["all_qualifier"] in ("+", "?"):
            score -= 20
            issues.append(f"SPF uses '{spf['all_qualifier']}all', which does not block unauthorized senders.")
            recommendations.append("Change the SPF all mechanism to -all after inventorying legitimate senders.")
        if spf["lookup_estimate"] > 10:
            score -= 5
            issues.append(f"SPF has about {spf['lookup_estimate']} DNS-lookup mechanisms (limit is 10).")
            recommendations.append("Flatten or reduce SPF include/redirect mechanisms to stay under 10 lookups.")

    if not dmarc["present"]:
        score -= 30
        issues.append("DMARC record is missing.")
        recommendations.append("Publish a DMARC record at _dmarc with p=none first, then move to quarantine/reject.")
    else:
        policy = (dmarc.get("policy") or "none").lower()
        if policy == "none":
            score -= 15
            issues.append("DMARC policy is p=none (monitoring only).")
            recommendations.append("Move DMARC to p=quarantine and then p=reject once reports are clean.")
        try:
            pct = int(dmarc.get("percentage") or "100")
        except ValueError:
            pct = 100
        if pct < 100:
            score -= 5
            issues.append(f"DMARC applies to only {pct}% of messages.")
            recommendations.append("Raise DMARC pct to 100 once alignment is confirmed.")
        if not dmarc.get("aggregate_reports"):
            score -= 5
            issues.append("DMARC has no rua aggregate-report address.")
            recommendations.append("Add a rua=mailto: address to receive DMARC aggregate reports.")

    active_dkim = [item for item in dkim if item["key_present"] and not item["revoked"]]
    if not active_dkim:
        score -= 10
        issues.append("No active DKIM key found on common selectors.")
        recommendations.append("Enable DKIM signing and publish the public key for your mail provider's selector.")
    for item in dkim:
        if item.get("revoked"):
            score -= 10
            issues.append(f"DKIM selector '{item['selector']}' is revoked (empty p=).")
            recommendations.append(f"Remove or rotate the revoked DKIM selector '{item['selector']}'.")

    if not mta_sts["present"]:
        score -= 5
        issues.append("MTA-STS DNS record is missing.")
        recommendations.append("Publish _mta-sts TXT and an HTTPS MTA-STS policy in enforce mode.")
    elif not (mta_sts.get("policy") or {}).get("enforced"):
        score -= 5
        issues.append("MTA-STS policy is not in enforce mode.")
        recommendations.append("Set the MTA-STS policy mode to enforce after testing.")
    if not tls_rpt["present"]:
        score -= 5
        issues.append("TLS-RPT record is missing.")
        recommendations.append("Publish a _smtp._tls TLS-RPT record to receive TLS failure reports.")

    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return {
        "ok": True,
        "domain": target,
        "score": score,
        "grade": grade,
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "bimi": bimi,
        "mta_sts": mta_sts,
        "tls_rpt": tls_rpt,
        "caa": caa,
        "issues": issues,
        "recommendations": recommendations,
        "note": "DKIM selectors are discovered from a common list, not from provider metadata.",
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }
