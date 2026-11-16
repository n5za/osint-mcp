"""IP intelligence, ASN and port-scanning tools."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time

from .common import clip, guarded, port_service, request

TOP_20 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080]
TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554,
    587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723,
    1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000,
    8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155,
    49156, 49157,
]
WEB_PORTS = [80, 81, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9443, 3000, 5000, 9000]
DB_PORTS = [1433, 1521, 3306, 5432, 6379, 27017, 27018, 9200, 9300, 11211, 5672, 9092, 2181, 9042, 5984]

PRESETS = {
    "top20": TOP_20,
    "top100": TOP_100,
    "web": WEB_PORTS,
    "db": DB_PORTS,
    "common": sorted(set(TOP_20 + WEB_PORTS + DB_PORTS + [389, 636, 873, 1080, 2049, 2375, 2376, 5900])),
}

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443, 2376}


def _grab_tls_cert_sync(host: str, port: int, timeout: float) -> dict | None:
    """Best-effort TLS handshake for the port-scan probe: leaf CN, issuer, expiry."""
    import ssl as _ssl
    from datetime import datetime, timezone

    try:
        context = _ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = _ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=max(0.5, timeout)) as sock:
            sock.settimeout(max(0.5, timeout))
            with context.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return None
                # cryptography is a hard dependency; import lazily to keep the scan loop light
                from cryptography import x509

                cert = x509.load_der_x509_certificate(der)
                try:
                    not_after = cert.not_valid_after_utc
                except AttributeError:
                    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                return {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_after": not_after.isoformat(timespec="seconds"),
                    "days_remaining": days_left,
                    "expired": days_left < 0,
                    "self_signed": cert.subject == cert.issuer,
                }
    except Exception:
        return None


def _parse_ports(spec: str) -> list[int]:
    value = (spec or "top20").strip().lower()
    if value in PRESETS:
        return list(PRESETS[value])
    ports: set[int] = set()
    for chunk in value.replace(" ", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            if "-" in chunk:
                start, end = chunk.split("-", 1)
                low, high = int(start), int(end)
                if low > high:
                    low, high = high, low
                ports.update(range(low, high + 1))
            else:
                ports.add(int(chunk))
        except ValueError:
            continue  # skip malformed tokens instead of failing the whole scan
    return sorted(port for port in ports if 0 < port <= 65535)


async def _http_get_json(url: str, timeout: float = 15.0):
    response = await request(url, timeout=timeout)
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except Exception:
        return None


@guarded
async def ip_intel(ip: str) -> dict:
    """Full IP profile: geolocation/ASN/org + Shodan InternetDB open ports, hostnames, CVEs.

    Uses keyless APIs (ip-api.com + internetdb.shodan.io) with an ipinfo.io fallback.
    """
    ipaddress.ip_address(ip)
    geo = await _http_get_json(
        f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    )
    if not geo or geo.get("status") != "success":
        fallback = await _http_get_json(f"https://ipinfo.io/{ip}/json")
        if fallback and not fallback.get("bogon"):
            geo = {
                "status": "success",
                "query": ip,
                "country": fallback.get("country"),
                "regionName": fallback.get("region"),
                "city": fallback.get("city"),
                "zip": fallback.get("postal"),
                "lat": (fallback.get("loc") or ",").split(",")[0],
                "lon": (fallback.get("loc") or ",").split(",")[-1],
                "timezone": fallback.get("timezone"),
                "org": fallback.get("org"),
                "as": fallback.get("org"),
                "reverse": fallback.get("hostname"),
                "source": "ipinfo.io",
            }
        else:
            geo = {"status": "error", "message": (geo or {}).get("message", "geo lookup failed")}

    internetdb = await _http_get_json(f"https://internetdb.shodan.io/{ip}", timeout=20.0)
    shodan = None
    if internetdb:
        shodan = {
            "ports": sorted(internetdb.get("ports", [])),
            "hostnames": internetdb.get("hostnames", []),
            "cpes": internetdb.get("cpes", []),
            "tags": internetdb.get("tags", []),
            "vulns": internetdb.get("vulns", []),
        }

    return {
        "ok": True,
        "ip": ip,
        "geo": geo,
        "shodan_internetdb": shodan,
        "note": None if shodan else "No InternetDB record (not a known internet-facing host).",
    }


@guarded
async def asn_lookup(target: str) -> dict:
    """Look up an ASN (e.g. AS15169), an IP, or a domain: holder, country, announced prefixes."""
    import re

    value = (target or "").strip()
    asn = None
    if re.fullmatch(r"(?i)as\d+", value):
        asn = int(value[2:])
    elif re.fullmatch(r"\d{1,10}", value):
        asn = int(value)
    else:
        host = value
        try:
            ipaddress.ip_address(value)
        except ValueError:
            try:
                host = socket.gethostbyname(value)
            except Exception as exc:
                return {"ok": False, "error": f"cannot resolve {value}: {exc}"}
        geo = await _http_get_json(f"http://ip-api.com/json/{host}?fields=status,as,asname,isp,org,query,country")
        if not geo or geo.get("status") != "success":
            return {"ok": False, "error": "ASN lookup failed", "ip": host}
        match = re.match(r"AS(\d+)", geo.get("as") or "")
        if not match:
            return {"ok": True, "ip": host, "asn": None, "org": geo.get("org"), "isp": geo.get("isp")}
        asn = int(match.group(1))
        return {
            "ok": True,
            "query": value,
            "ip": host,
            "asn": f"AS{asn}",
            "as_name": geo.get("asname"),
            "org": geo.get("org"),
            "isp": geo.get("isp"),
            "country": geo.get("country"),
        }

    overview = await _http_get_json(f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}")
    prefixes = await _http_get_json(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}")
    data = (overview or {}).get("data", {}) if overview else {}
    prefix_list = []
    if prefixes:
        prefix_list = sorted(
            {entry.get("prefix") for entry in prefixes.get("data", {}).get("prefixes", []) if entry.get("prefix")}
        )
    return {
        "ok": bool(data),
        "asn": f"AS{asn}",
        "holder": data.get("holder"),
        "announced": data.get("announced"),
        "block": data.get("block"),
        "country": None,
        "prefix_count": len(prefix_list),
        "prefixes": prefix_list[:200],
        "truncated": len(prefix_list) > 200,
    }


@guarded
async def reverse_ip(ip: str) -> dict:
    """Reverse-IP lookup: other domains hosted on the same IP (Hackertarget, keyless).

    Rate limited upstream (a few dozen/day); a failure usually means quota, not
    that the IP hosts nothing.
    """
    ipaddress.ip_address(ip)
    response = await request(
        "https://api.hackertarget.com/reverseiplookup/",
        params={"q": ip},
        timeout=30.0,
    )
    text = (response.text or "").strip()
    lowered = text.lower()
    if response.status_code != 200 or lowered.startswith("error") or "api count exceeded" in lowered:
        return {"ok": False, "ip": ip, "error": clip(text, 300), "hint": "upstream quota/error"}
    domains = [line.strip() for line in text.splitlines() if line.strip() and " " not in line.strip()]
    return {"ok": True, "ip": ip, "count": len(domains), "domains": domains[:500]}


@guarded
async def port_scan(
    host: str,
    ports: str = "top20",
    timeout: float = 1.0,
    concurrency: int = 200,
) -> dict:
    """TCP connect scan. Presets: top20, top100, web, db, common - or "80,443,8000-8100".

    Only scan hosts you are authorized to test. Grabs a small plaintext banner
    where possible. Uses asyncio so it is fast but still a real connect scan.
    """
    target = host.strip()
    try:
        ipaddress.ip_address(target)
        ip = target
    except ValueError:
        infos = await asyncio.to_thread(socket.getaddrinfo, target, None)
        ip = infos[0][4][0]

    port_list = _parse_ports(ports)
    if not port_list:
        return {"ok": False, "error": "no valid ports"}
    if len(port_list) > 2000:
        return {"ok": False, "error": "too many ports (max 2000)"}

    sem = asyncio.Semaphore(max(1, min(int(concurrency), 500)))
    open_ports: list[dict] = []
    started = time.perf_counter()

    async def probe(port: int) -> None:
        async with sem:
            writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=max(0.2, float(timeout))
                )
                banner = ""
                if port not in TLS_PORTS:
                    try:
                        chunk = await asyncio.wait_for(reader.read(256), timeout=0.8)
                        banner = chunk.decode("utf-8", "replace").strip()
                    except Exception:
                        banner = ""
                entry = {
                    "port": port,
                    "service": port_service(port),
                    "banner": clip(banner, 200),
                }
                if port in TLS_PORTS:
                    writer.close()  # release the plain socket; TLS grabs its own connection
                    await writer.wait_closed()
                    writer = None
                    loop = asyncio.get_running_loop()
                    cert = await asyncio.wait_for(
                        loop.run_in_executor(None, _grab_tls_cert_sync, target, port, max(1.0, float(timeout))),
                        timeout=max(2.0, float(timeout) + 1.0),
                    )
                    if cert:
                        entry["tls_cert"] = cert
                open_ports.append(entry)
            except Exception:
                return
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

    await asyncio.gather(*(probe(port) for port in port_list))
    open_ports.sort(key=lambda item: item["port"])
    return {
        "ok": True,
        "host": target,
        "ip": ip,
        "scanned": len(port_list),
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "duration_seconds": round(time.perf_counter() - started, 2),
    }
