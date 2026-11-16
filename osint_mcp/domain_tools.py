"""Domain-level tools: RDAP whois, TLS certificates, robots/security.txt, wayback."""

from __future__ import annotations

import asyncio
import gzip
import socket
import ssl
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from .common import (
    clip,
    ensure_url,
    guarded,
    normalize_target,
    request,
    utcnow,
)


def _vcard_props(entity: dict) -> dict:
    props: dict[str, str] = {}
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return props
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key, value = item[0], item[3]
        if isinstance(value, list):
            value = ", ".join(str(part) for part in value)
        props[str(key)] = str(value)
    return props


@guarded
async def domain_whois(domain: str) -> dict:
    """Registration data for a domain via RDAP (the modern WHOIS replacement).

    Returns registrar, creation/expiry/update dates, status flags, nameservers,
    DNSSEC state and public contacts. No API key needed.
    """
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}

    response = await request(f"https://rdap.org/domain/{target}", timeout=30.0)
    if response.status_code != 200:
        return {
            "ok": False,
            "domain": target,
            "error": f"RDAP returned HTTP {response.status_code}",
            "hint": "TLD may not publish RDAP; try the registry whois manually.",
        }
    data = response.json()

    events = {}
    for event in data.get("events", []):
        if event.get("eventAction") and event.get("eventDate"):
            events[event["eventAction"]] = event["eventDate"]

    contacts = []
    for entity in data.get("entities", []):
        props = _vcard_props(entity)
        contacts.append(
            {
                "roles": entity.get("roles", []),
                "handle": entity.get("handle"),
                "name": props.get("fn"),
                "org": props.get("org"),
                "email": props.get("email"),
                "phone": props.get("tel"),
                "url": props.get("url"),
            }
        )

    nameservers = []
    for ns in data.get("nameservers", []):
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            nameservers.append(name.rstrip(".").lower())

    secure_dns = data.get("secureDNS") or {}
    return {
        "ok": True,
        "domain": target,
        "handle": data.get("handle"),
        "status": data.get("status", []),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": sorted(set(nameservers)),
        "dnssec_signed": secure_dns.get("delegationSigned"),
        "contacts": contacts[:20],
    }


def _grab_certificate(host: str, port: int, timeout: float) -> tuple[bytes, list[bytes], tuple, str]:
    """TLS handshake returning (leaf DER, chain DERs, cipher, version).

    Chain collection uses the public get_verified_chain() API when available
    (Python 3.13+) and degrades to leaf-only on older interpreters.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            cipher = tls.cipher()
            version = tls.version() or "unknown"
            if not der:
                raise RuntimeError("server returned no certificate")
            chain: list[bytes] = []
            try:
                verified = tls.get_verified_chain()  # Python 3.13+
            except AttributeError:
                verified = None
            if not verified:
                sslobj = getattr(tls, "_sslobj", None)  # older interpreters, private API
                if sslobj is not None:
                    try:
                        verified = sslobj.get_verified_chain()
                    except Exception:
                        verified = None
            if verified:
                for link_cert in verified:
                    try:
                        chain.append(link_cert.public_bytes())
                    except TypeError:
                        try:
                            chain.append(link_cert.public_bytes(x509.Certificate))
                        except Exception:
                            continue
                    except Exception:
                        continue
            return der, chain, cipher or (None, None, None), version


def _public_key_info(cert: x509.Certificate) -> dict:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"type": "EC", "curve": key.curve.name, "bits": key.key_size}
    if isinstance(key, dsa.DSAPublicKey):
        return {"type": "DSA", "bits": key.key_size}
    if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return {"type": type(key).__name__}
    return {"type": type(key).__name__}


def _expiry_alerts(cert: x509.Certificate, days_left: int, self_signed: bool, public_key: dict) -> list[str]:
    """Human-readable certificate health alerts."""
    alerts: list[str] = []
    if days_left < 0:
        alerts.append(f"EXPIRED: certificate expired {-days_left} days ago")
    elif days_left <= 7:
        alerts.append(f"CRITICAL: certificate expires in {days_left} days")
    elif days_left <= 30:
        alerts.append(f"WARNING: certificate expires in {days_left} days")
    if self_signed:
        alerts.append("WARNING: self-signed certificate (no trusted CA)")
    algo = cert.signature_algorithm_oid._name.lower()
    if "sha1" in algo or "md5" in algo:
        alerts.append(f"CRITICAL: weak signature algorithm ({cert.signature_algorithm_oid._name})")
    if public_key.get("type") == "RSA" and isinstance(public_key.get("bits"), int) and public_key["bits"] < 2048:
        alerts.append(f"CRITICAL: weak RSA key ({public_key['bits']} bits)")
    return alerts


@guarded
async def ssl_certificate(host: str, port: int = 443) -> dict:
    """Inspect the live TLS certificate of a host: subject, issuer, SANs, validity.

    Returns days until expiry, whether it is currently valid and self-signed,
    signature algorithm, public-key info and negotiated TLS version/cipher.
    Includes the served chain (when the Python build exposes it) and health alerts.
    """
    target = normalize_target(host)
    der, chain_ders, cipher, tls_version = await asyncio.to_thread(_grab_certificate, target, int(port), 12.0)
    cert = x509.load_der_x509_certificate(der)

    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        not_before = cert.not_valid_before.replace(tzinfo=utcnow().tzinfo)
        not_after = cert.not_valid_after.replace(tzinfo=utcnow().tzinfo)

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san_ext.get_values_for_type(x509.DNSName)
        ip_names = [str(item) for item in san_ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names, ip_names = [], []

    now = utcnow()
    days_left = (not_after - now).days
    self_signed = cert.subject == cert.issuer
    public_key = _public_key_info(cert)

    chain: list[dict] = []
    for index, link_der in enumerate(chain_ders):
        try:
            link = x509.load_der_x509_certificate(link_der)
            try:
                link_after = link.not_valid_after_utc
            except AttributeError:
                link_after = link.not_valid_after.replace(tzinfo=utcnow().tzinfo)
            chain.append(
                {
                    "position": index,
                    "subject": link.subject.rfc4514_string(),
                    "issuer": link.issuer.rfc4514_string(),
                    "not_after": link_after.isoformat(timespec="seconds"),
                    "self_signed": link.subject == link.issuer,
                }
            )
        except Exception:
            continue

    return {
        "ok": True,
        "host": target,
        "port": int(port),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(timespec="seconds"),
        "not_after": not_after.isoformat(timespec="seconds"),
        "days_remaining": days_left,
        "valid": not_before <= now <= not_after,
        "expired": days_left < 0,
        "self_signed": self_signed,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key": public_key,
        "san_dns": dns_names,
        "san_ip": ip_names,
        "tls_version": tls_version,
        "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]},
        "chain_length": len(chain_ders),
        "chain": chain,
        "chain_note": None if chain_ders else "chain unavailable on this Python build; leaf only",
        "alerts": _expiry_alerts(cert, days_left, self_signed, public_key),
    }


async def _first_ok(urls: list[str], timeout: float = 15.0):
    last_error = None
    for url in urls:
        try:
            response = await request(url, timeout=timeout)
            if response.status_code < 400:
                return url, response
            last_error = f"{url} -> HTTP {response.status_code}"
        except Exception as exc:
            last_error = f"{url} -> {type(exc).__name__}: {exc}"
    raise RuntimeError(last_error or "all URLs failed")


@guarded
async def robots_txt(domain: str) -> dict:
    """Fetch and parse robots.txt: user-agent groups, disallow/allow rules, sitemaps.

    Flags sensitive-looking paths (admin, api, backup, private, .git, config).
    """
    target = normalize_target(domain)
    base = ensure_url(target).rstrip("/")
    try:
        url, response = await _first_ok([f"{base}/robots.txt", f"http://{target}/robots.txt"])
    except Exception as exc:
        return {"ok": True, "found": False, "domain": target, "url": None, "note": str(exc)}
    text = response.text

    groups: list[dict] = []
    sitemaps: list[str] = []
    current: dict | None = None
    sensitive_hits: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "sitemap":
            sitemaps.append(value)
        elif key == "user-agent":
            current = {"user_agent": value, "allow": [], "disallow": []}
            groups.append(current)
        elif key in ("allow", "disallow") and current is not None:
            current[key].append(value)
            low = value.lower()
            if any(word in low for word in ("admin", "api", "backup", "private", "secret", ".git", "config", "db", "internal")):
                sensitive_hits.append(value)

    return {
        "ok": True,
        "found": True,
        "domain": target,
        "url": url,
        "status": response.status_code,
        "groups": groups[:30],
        "sitemaps": sitemaps,
        "sensitive_paths": sorted(set(sensitive_hits))[:50],
        "raw": clip(text, 8000),
    }


@guarded
async def security_txt(domain: str) -> dict:
    """Look for RFC 9116 security.txt at /.well-known/ and root, parse its fields."""
    target = normalize_target(domain)
    base = ensure_url(target).rstrip("/")
    try:
        url, response = await _first_ok(
            [f"{base}/.well-known/security.txt", f"{base}/security.txt", f"http://{target}/.well-known/security.txt"]
        )
    except Exception as exc:
        return {"ok": True, "found": False, "domain": target, "url": None, "note": str(exc)}
    fields: dict[str, list[str]] = {}
    for raw_line in response.text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields.setdefault(key.strip().lower(), []).append(value.strip())

    expires = (fields.get("expires") or [None])[0]
    expired = None
    if expires:
        try:
            from datetime import datetime

            expired = datetime.fromisoformat(expires.replace("Z", "+00:00")) < utcnow()
        except Exception:
            expired = None

    return {
        "ok": True,
        "found": True,
        "domain": target,
        "url": url,
        "fields": fields,
        "expired": expired,
        "raw": clip(response.text, 6000),
    }


def _xml_locs(text: str) -> list[str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    return [element.text.strip() for element in root.iter() if element.tag.lower().endswith("loc") and element.text]


@guarded
async def sitemap_urls(domain: str, limit: int = 500) -> dict:
    """Discover and parse sitemap.xml (including sitemap indexes) to list URLs."""
    target = normalize_target(domain)
    base = ensure_url(target).rstrip("/")
    candidates = [
        f"{base}/sitemap.xml",
        f"{base}/sitemap_index.xml",
        f"{base}/sitemap-index.xml",
        f"{base}/sitemap.xml.gz",
    ]
    found_url = None
    locs: list[str] = []
    errors: list[str] = []

    for candidate in candidates:
        try:
            response = await request(candidate, timeout=20.0)
            if response.status_code >= 400:
                continue
            body = response.content
            if body[:2] == b"\x1f\x8b":
                body = await asyncio.to_thread(gzip.decompress, body)
            text = body.decode("utf-8", "replace")
            current = _xml_locs(text)
            if not current:
                continue
            found_url = candidate
            if any("sitemapindex" in element.tag.lower() for element in ET.fromstring(text).iter()):
                for child in current[:5]:
                    try:
                        child_response = await request(child, timeout=20.0)
                        locs.extend(_xml_locs(child_response.text))
                    except Exception as exc:
                        errors.append(f"{child}: {type(exc).__name__}")
            else:
                locs.extend(current)
            break
        except Exception as exc:
            errors.append(f"{candidate}: {type(exc).__name__}")

    if not found_url:
        return {"ok": True, "found": False, "domain": target, "error": "no sitemap found", "errors": errors}

    unique = list(dict.fromkeys(locs))
    return {
        "ok": True,
        "domain": target,
        "sitemap": found_url,
        "count": len(unique),
        "urls": unique[: max(1, int(limit))],
        "truncated": len(unique) > limit,
        "errors": errors or None,
    }


@guarded
async def wayback_urls(
    domain: str,
    limit: int = 500,
    include_subdomains: bool = True,
    only_ok: bool = False,
) -> dict:
    """List archived URLs from the Wayback Machine CDX API (historical endpoints/files).

    Great for finding forgotten paths, old API versions, backups and parameters.
    """
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}

    params = {
        "url": target,
        "matchType": "domain" if include_subdomains else "exact",
        "output": "json",
        "fl": "original,timestamp,statuscode,mimetype",
        "collapse": "urlkey",
        "limit": str(max(1, min(int(limit), 5000))),
    }
    if only_ok:
        params["filter"] = "statuscode:200"

    last_error = ""
    response = None
    for _attempt in range(2):
        try:
            response = await request(
                "https://web.archive.org/cdx/search/cdx", params=params, timeout=90.0
            )
            if response.status_code == 200:
                break
            last_error = f"CDX HTTP {response.status_code}: {clip(response.text, 200)}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        await asyncio.sleep(2.0)
    if response is None or response.status_code != 200:
        return {
            "ok": False,
            "domain": target,
            "error": last_error or "CDX request failed",
            "hint": "The Wayback CDX API is often slow; retry with a smaller limit.",
        }

    try:
        rows = response.json()
    except Exception:
        return {"ok": True, "domain": target, "count": 0, "urls": [], "note": clip(response.text, 300)}

    if not rows:
        return {"ok": True, "domain": target, "count": 0, "urls": []}

    header, data = rows[0], rows[1:]
    records = []
    for row in data:
        item = dict(zip(header, row, strict=False))
        records.append(
            {
                "url": item.get("original"),
                "timestamp": item.get("timestamp"),
                "status": item.get("statuscode"),
                "mime": item.get("mimetype"),
            }
        )
    return {
        "ok": True,
        "domain": target,
        "count": len(records),
        "urls": records,
        "truncated": len(records) >= int(limit),
    }
