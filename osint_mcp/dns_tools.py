"""DNS, subdomain and certificate-transparency tools."""

from __future__ import annotations

import asyncio
import os
import random
import string
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone

from .common import clip, guarded, normalize_target, request, utcnow

DATA_DIR = Path(__file__).with_name("data")
WORDLIST_PATH = DATA_DIR / "subdomains.txt"

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]


def _resolver(timeout: float = 5.0) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = max(timeout, 6.0)
    return resolver


def _rdata(record_type: str, rdata) -> dict | str:
    try:
        if record_type == "MX":
            return {
                "preference": rdata.preference,
                "exchange": rdata.exchange.to_text(omit_final_dot=True),
            }
        if record_type == "TXT":
            parts = []
            for part in rdata.strings:
                parts.append(part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part))
            return "".join(parts)
        if record_type == "SOA":
            return {
                "mname": rdata.mname.to_text(omit_final_dot=True),
                "rname": rdata.rname.to_text(omit_final_dot=True),
                "serial": rdata.serial,
                "refresh": rdata.refresh,
                "retry": rdata.retry,
                "expire": rdata.expire,
                "minimum": rdata.minimum,
            }
        if record_type == "SRV":
            return {
                "priority": rdata.priority,
                "weight": rdata.weight,
                "port": rdata.port,
                "target": rdata.target.to_text(omit_final_dot=True),
            }
        if record_type == "CAA":
            return {"flags": rdata.flags, "tag": rdata.tag, "value": rdata.value}
        text = rdata.to_text()
        return text[:-1] if text.endswith(".") else text
    except Exception:
        return rdata.to_text()


@guarded
async def dns_lookup(domain: str, record_type: str = "A") -> dict:
    """Resolve DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV or ANY).

    Returns structured answers plus the raw text form. Handles NXDOMAIN and
    missing records without failing. Use ANY for a full passive DNS profile.
    """
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}

    requested = (record_type or "A").upper().strip()
    types = RECORD_TYPES if requested in ("ANY", "*", "") else [requested]
    resolver = _resolver()
    records: dict[str, list] = {}
    errors: dict[str, str] = {}
    nxdomain = False

    async def one(rtype: str) -> None:
        nonlocal nxdomain
        try:
            answer = await resolver.resolve(target, rtype, raise_on_no_answer=False)
            if answer.rrset is None:
                return
            records[rtype] = [_rdata(rtype, item) for item in answer]
        except dns.resolver.NXDOMAIN:
            nxdomain = True
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return
        except Exception as exc:
            errors[rtype] = f"{type(exc).__name__}: {exc}"

    await asyncio.gather(*(one(rtype) for rtype in types))

    if nxdomain and not records:
        return {
            "ok": True,
            "domain": target,
            "record_type": requested,
            "exists": False,
            "note": "NXDOMAIN - domain does not resolve",
        }

    return {
        "ok": True,
        "domain": target,
        "record_type": requested,
        "exists": True,
        "count": sum(len(v) for v in records.values()),
        "records": records,
        "errors": errors or None,
        "queried_at": utcnow().isoformat(timespec="seconds"),
    }


@guarded
async def reverse_dns(ip: str) -> dict:
    """PTR lookup for an IPv4/IPv6 address (returns hostnames pointing back at the IP)."""
    from ipaddress import ip_address

    ip_address(ip)
    resolver = _resolver()
    try:
        answer = await resolver.resolve(dns.reversename.from_address(ip), "PTR")
        names = [item.to_text().rstrip(".") for item in answer]
    except dns.resolver.NXDOMAIN:
        names = []
    except dns.resolver.NoAnswer:
        names = []
    return {"ok": True, "ip": ip, "ptr": names, "count": len(names)}


def _axfr(nameserver: str, domain: str) -> tuple[list[str], bool]:
    xfr = dns.query.xfr(nameserver, domain, lifetime=12.0, timeout=6.0)
    zone = dns.zone.from_xfr(xfr, relativize=False)
    rows: list[str] = []
    truncated = False
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            for rdata in rdataset:
                rows.append(
                    f"{name} {rdataset.ttl} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata.to_text()}"
                )
                if len(rows) >= 300:
                    truncated = True
                    return rows, truncated
    return rows, truncated


@guarded
async def dns_zone_transfer(domain: str) -> dict:
    """Attempt an AXFR zone transfer against every authoritative nameserver.

    A successful transfer is a serious DNS misconfiguration and dumps the whole
    zone. Returns per-nameserver status plus up to 300 records on success.
    """
    target = normalize_target(domain)
    lookup = await dns_lookup(target, "NS")
    if not lookup.get("ok"):
        return lookup
    nameservers = lookup.get("records", {}).get("NS", [])
    if not nameservers:
        return {"ok": True, "domain": target, "vulnerable": False, "note": "no NS records found"}

    results = []
    any_success = False

    async def attempt(ns: str) -> None:
        nonlocal any_success
        try:
            rows, truncated = await asyncio.to_thread(_axfr, ns, target)
            any_success = True
            results.append(
                {
                    "nameserver": ns,
                    "success": True,
                    "records": rows,
                    "truncated": truncated,
                    "count": len(rows),
                }
            )
        except Exception as exc:
            message = str(exc) or "transfer refused"
            results.append({"nameserver": ns, "success": False, "error": f"{type(exc).__name__}: {message}"})

    await asyncio.gather(*(attempt(ns) for ns in nameservers))
    return {
        "ok": True,
        "domain": target,
        "vulnerable": any_success,
        "nameservers": nameservers,
        "attempts": results,
    }


def _load_wordlist(custom: str) -> list[str]:
    if custom:
        maybe_path = Path(os.path.expanduser(custom))
        if maybe_path.is_file():
            words = maybe_path.read_text(encoding="utf-8", errors="ignore").split()
        else:
            words = [w for w in custom.replace(",", " ").split() if w]
    else:
        words = WORDLIST_PATH.read_text(encoding="utf-8", errors="ignore").split() if WORDLIST_PATH.is_file() else []
    cleaned = []
    for word in words:
        word = word.strip().strip(".")
        if word and not word.startswith("#"):
            cleaned.append(word)
    return cleaned


def _expand_permutations(words: list[str], limit: int = 3000) -> list[str]:
    """Derive common label variants: api-dev / dev-api, api2, api-old, api-v2."""
    env_words = ("dev", "test", "stage", "staging", "qa", "uat", "prod", "demo", "old", "new", "beta")
    derived: set[str] = set()
    # only permute the most common service words to keep the probe count sane
    hot = {w for w in words if w in ("api", "app", "web", "www", "mail", "vpn", "admin", "dev", "test", "portal", "auth", "sso", "jenkins", "gitlab", "jira", "docs", "blog", "shop", "cdn", "db", "mysql", "postgres", "redis", "kibana", "grafana")}
    for word in hot:
        derived.add(f"{word}2")
        derived.add(f"{word}-old")
        derived.add(f"old-{word}")
        derived.add(f"{word}-v2")
        derived.add(f"{word}-internal")
        derived.add(f"internal-{word}")
        derived.add(f"{word}-private")
        for env in env_words:
            derived.add(f"{word}-{env}")
            if env != word:
                derived.add(f"{env}-{word}")
    combined = words + sorted(derived)
    return combined[:limit]


@guarded
async def subdomain_enum(
    domain: str,
    wordlist: str = "",
    permutations: bool = False,
    concurrency: int = 80,
    timeout: float = 3.0,
) -> dict:
    """Brute-force subdomains of a domain using a built-in wordlist (or a custom one).

    `wordlist` may be a file path, a comma/space separated list, or empty for the
    built-in 1280+ entry list. `permutations=True` also probes common derived
    labels (e.g. `api-dev`, `api2`, `dev-api`). Performs wildcard-DNS detection
    and filters wildcard matches so results are not polluted. Passive
    alternative: crtsh_subdomains.
    """
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}
    words = _load_wordlist(wordlist)
    if not words:
        return {"ok": False, "error": "no wordlist entries"}
    if permutations:
        words = _expand_permutations(words, limit=3000)

    resolver = _resolver(timeout)
    sem = asyncio.Semaphore(max(1, min(int(concurrency), 250)))
    wildcard_ips: set[str] = set()
    wildcard_checked = False

    random_label = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(14))

    async def resolve_ips(name: str) -> list[str]:
        answer = await resolver.resolve(name, "A", raise_on_no_answer=False)
        if answer.rrset is None:
            return []
        return [item.address for item in answer]

    try:
        wildcard_ips = set(await resolve_ips(f"{random_label}.{target}"))
        wildcard_checked = True
    except Exception:
        wildcard_ips = set()

    found: list[dict] = []
    tested = 0

    async def check(label: str) -> None:
        nonlocal tested
        full = f"{label}.{target}"
        async with sem:
            tested += 1
            try:
                ips = await resolve_ips(full)
                if not ips:
                    return
                if wildcard_ips and set(ips).issubset(wildcard_ips):
                    return
                found.append({"subdomain": full, "ip": ips})
            except Exception:
                return

    await asyncio.gather(*(check(word) for word in words))
    found.sort(key=lambda item: item["subdomain"])
    return {
        "ok": True,
        "domain": target,
        "found": found[:1000],
        "count": len(found),
        "tested": tested,
        "wordlist_size": len(words),
        "wildcard_dns": bool(wildcard_ips),
        "wildcard_ips": sorted(wildcard_ips) if wildcard_checked else [],
    }


async def _certspotter(domain: str) -> set[str] | None:
    """Keyless fallback when crt.sh is down."""
    try:
        response = await request(
            "https://api.certspotter.com/v1/issuances",
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=45.0,
        )
        if response.status_code != 200:
            return None
        names: set[str] = set()
        for entry in response.json():
            for raw_name in entry.get("dns_names", []):
                name = str(raw_name).strip().lower().lstrip("*.").rstrip(".")
                if name and (name == domain or name.endswith("." + domain)):
                    names.add(name)
        return names
    except Exception:
        return None


@guarded
async def crtsh_subdomains(domain: str, limit: int = 2000) -> dict:
    """Enumerate subdomains from certificate transparency logs (crt.sh), passive.

    Free, no API key. Falls back to Cert Spotter when crt.sh is overloaded. Can be
    slow for large domains; subdomain_enum is the active alternative.
    """
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}

    url = "https://crt.sh/"
    params = {"q": f"%.{target}", "output": "json", "exclude": "expired"}
    last_error = ""
    data = None
    for attempt in range(2):
        try:
            response = await request(url, params=params, timeout=60.0)
            if response.status_code == 200:
                data = response.json()
                break
            last_error = f"HTTP {response.status_code}: {clip(response.text, 200)}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        await asyncio.sleep(1.5 * (attempt + 1))

    if data is None:
        fallback = await _certspotter(target)
        if fallback is not None:
            ordered = sorted(fallback)
            return {
                "ok": True,
                "domain": target,
                "source": "certspotter (crt.sh unavailable)",
                "count": len(ordered),
                "subdomains": ordered[: max(1, int(limit))],
                "truncated": len(ordered) > limit,
                "note": f"crt.sh failed: {clip(last_error, 200)}",
            }
        return {"ok": False, "error": f"crt.sh failed: {last_error}", "domain": target}

    names: set[str] = set()
    issuer_names: set[str] = set()
    for entry in data:
        for field in ("name_value", "common_name"):
            value = entry.get(field) or ""
            for line in str(value).splitlines():
                name = line.strip().lower().lstrip("*.").rstrip(".")
                if not name or " " in name:
                    continue
                if name == target or name.endswith("." + target):
                    names.add(name)
                    if entry.get("issuer_name"):
                        issuer_names.add(entry["issuer_name"])

    ordered = sorted(names)
    return {
        "ok": True,
        "domain": target,
        "source": "crt.sh",
        "count": len(ordered),
        "subdomains": ordered[: max(1, int(limit))],
        "truncated": len(ordered) > limit,
        "certificate_entries": len(data),
        "sample_issuers": sorted(issuer_names)[:10],
    }
