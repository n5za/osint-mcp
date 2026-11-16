"""Discovery tools: urlscan, Common Crawl, subdomains, JS recon, API discovery, takeover, favicon, buckets."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

import dns.resolver
from bs4 import BeautifulSoup

from .common import (
    api_key,
    clip,
    ensure_url,
    get_json,
    guarded,
    normalize_target,
    request,
    utcnow,
)

# ---------------------------------------------------------------- helpers


def _json_or_none(response):
    try:
        return response.json()
    except Exception:
        return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _dedupe_sorted(values) -> list[str]:
    return sorted({str(value).strip().lower().rstrip(".") for value in values if str(value).strip()})


# ------------------------------------------------------------------ urlscan
@guarded
async def urlscan_search(query: str, limit: int = 20) -> dict:
    """Search urlscan.io scans for a domain, IP, URL or filename (keyless).

    Auto-prefixes plain domains with domain:, IPs with ip: and URLs with page.url:.
    Returns scan time, page metadata, server, ASN and result links.
    """
    value = (query or "").strip()
    if not value:
        return {"ok": False, "error": "empty query"}
    limit = max(1, min(int(limit), 100))
    has_operator = bool(
        re.search(r"\b(domain|ip|page\.url|filename|hash|asn|server|country|task\.url):", value, re.I)
    )
    if not has_operator:
        if value.startswith(("http://", "https://")):
            value = f'page.url:"{value}"'
        elif _is_ip(value):
            value = f"ip:{value}"
        elif "." in value:
            value = f"domain:{normalize_target(value)}"

    response = await request(
        "https://urlscan.io/api/v1/search/",
        params={"q": value, "size": limit},
        headers={"Accept": "application/json"},
        timeout=35.0,
    )
    if response.status_code != 200:
        return {
            "ok": False,
            "query": value,
            "error": f"urlscan HTTP {response.status_code}",
            "body": clip(response.text, 300),
        }
    data = _json_or_none(response) or {}
    results = []
    for item in (data.get("results") or [])[:limit]:
        page = item.get("page") or {}
        task = item.get("task") or {}
        stats = item.get("stats") or {}
        results.append(
            {
                "url": page.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "asn": page.get("asn"),
                "asnname": page.get("asnname"),
                "server": page.get("server"),
                "title": page.get("title"),
                "country": page.get("country"),
                "scan_time": task.get("time"),
                "scan_url": task.get("url"),
                "result": item.get("result"),
                "screenshot": item.get("screenshot"),
                "malicious": stats.get("malicious"),
            }
        )
    return {
        "ok": True,
        "query": value,
        "total": data.get("total"),
        "count": len(results),
        "results": results,
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# -------------------------------------------------------------- Common Crawl
@guarded
async def commoncrawl_urls(domain: str, limit: int = 500, index: str | None = None) -> dict:
    """Find archived URLs for a domain in the Common Crawl index (keyless).

    Great for forgotten endpoints, old JS bundles and parameters. Uses the latest
    crawl index unless `index` is supplied (e.g. CC-MAIN-2026-43-index).
    """
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}
    limit = max(1, min(int(limit), 5000))
    crawl_index = (index or "").strip()
    if not crawl_index:
        try:
            data = await get_json("https://index.commoncrawl.org/collinfo.json", timeout=45.0)
        except Exception as exc:
            return {"ok": False, "error": f"could not fetch crawl index list: {exc}"}
        if not isinstance(data, list) or not data:
            return {"ok": False, "error": "Common Crawl returned no indexes"}
        crawl_index = data[0].get("id") or ""
    if crawl_index and not crawl_index.endswith("-index"):
        crawl_index += "-index"

    response = None
    for attempt in range(3):
        response = await request(
            f"https://index.commoncrawl.org/{crawl_index}",
            params={"url": f"{target}/*", "output": "json", "limit": limit},
            timeout=90.0,
        )
        if response.status_code in (200, 404):
            break
        await asyncio.sleep(2.0 * (attempt + 1))
    if response is None:
        return {"ok": False, "domain": target, "index": crawl_index, "error": "no response"}
    if response.status_code == 404:
        return {
            "ok": True,
            "domain": target,
            "index": crawl_index,
            "count": 0,
            "urls": [],
            "note": "No captures for this domain in the selected index.",
        }
    if response.status_code != 200:
        return {
            "ok": False,
            "domain": target,
            "index": crawl_index,
            "error": f"Common Crawl HTTP {response.status_code}",
            "body": clip(response.text, 300),
        }

    rows: dict[str, dict] = {}
    for line in response.text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        url = item.get("url")
        if not url:
            continue
        row = {
            "url": url,
            "timestamp": item.get("timestamp"),
            "status": item.get("status"),
            "mime": item.get("mime"),
            "length": item.get("length"),
        }
        previous = rows.get(url)
        if previous is None or str(row.get("timestamp")) > str(previous.get("timestamp")):
            rows[url] = row

    ordered = sorted(rows.values(), key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return {
        "ok": True,
        "domain": target,
        "index": crawl_index,
        "count": len(ordered),
        "urls": ordered[:limit],
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# ----------------------------------------------------------- passive subdomains
async def _hackertarget_hosts(domain: str) -> tuple[set[str], str | None]:
    try:
        response = await request(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=35.0,
        )
        if response.status_code != 200:
            return set(), f"HTTP {response.status_code}"
        text = response.text.strip()
        lowered = text.lower()
        if "error" in lowered or "api count exceeded" in lowered or "no records found" in lowered:
            return set(), clip(text, 200)
        hosts = set()
        for line in text.splitlines():
            host = line.split(",")[0].strip().lower()
            if host and "." in host:
                hosts.add(host)
        return hosts, None
    except Exception as exc:
        return set(), f"{type(exc).__name__}: {exc}"


async def _rapiddns_hosts(domain: str) -> tuple[set[str], str | None]:
    try:
        response = await request(
            f"https://rapiddns.io/subdomain/{domain}",
            params={"full": "1"},
            timeout=40.0,
        )
        if response.status_code != 200:
            return set(), f"HTTP {response.status_code}"
        soup = BeautifulSoup(response.text, "html.parser")
        hosts = set()
        for row in soup.select("table tbody tr"):
            cells = [cell.get_text(" ", strip=True) for cell in row.find_all("td")]
            if len(cells) >= 2:
                host = cells[1].lower()
                if host and "." in host and " " not in host:
                    hosts.add(host)
        return hosts, None
    except Exception as exc:
        return set(), f"{type(exc).__name__}: {exc}"


async def _otx_url_hosts(domain: str) -> tuple[set[str], str | None]:
    key = api_key("otx")
    if not key:
        return set(), "no OTX key"
    try:
        response = await request(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
            headers={"X-OTX-API-KEY": key, "Accept": "application/json"},
            timeout=45.0,
        )
        if response.status_code != 200:
            return set(), f"HTTP {response.status_code}"
        data = _json_or_none(response) or {}
        hosts = set()
        for item in data.get("url_list") or []:
            host = (item.get("hostname") or "").strip().lower()
            if host and "." in host:
                hosts.add(host)
        return hosts, None
    except Exception as exc:
        return set(), f"{type(exc).__name__}: {exc}"


@guarded
async def passive_subdomains(domain: str, limit: int = 1000, deep: bool = True) -> dict:
    """Aggregate passive subdomains from crt.sh, HackerTarget, RapidDNS and OTX.

    `deep=False` skips crt.sh for a fast result. Deduplicates and filters to the
    target domain, returning per-source counts and errors.
    """
    target = normalize_target(domain)
    if not target or "." not in target:
        return {"ok": False, "error": "provide a domain like example.com"}
    limit = max(1, min(int(limit), 5000))

    sources: dict[str, set[str]] = {}
    errors: dict[str, str] = {}

    jobs = {
        "hackertarget": _hackertarget_hosts(target),
        "rapiddns": _rapiddns_hosts(target),
        "otx": _otx_url_hosts(target),
    }
    if deep:
        from .dns_tools import crtsh_subdomains

        async def crtsh():
            result = await crtsh_subdomains(target, limit=limit)
            if result.get("ok"):
                return set(result.get("subdomains") or []), None
            return set(), result.get("error") or "crt.sh failed"

        jobs["crtsh"] = crtsh()

    names = list(jobs)
    results = await asyncio.gather(*(jobs[name] for name in names))
    for name, (hosts, error) in zip(names, results, strict=False):
        if hosts:
            sources[name] = hosts
        if error:
            errors[name] = error

    combined = set()
    for hosts in sources.values():
        for host in hosts:
            host = host.lower().lstrip("*.").rstrip(".")
            if host == target or host.endswith("." + target):
                combined.add(host)

    ordered = sorted(combined)
    return {
        "ok": True,
        "domain": target,
        "count": len(ordered),
        "subdomains": ordered[:limit],
        "truncated": len(ordered) > limit,
        "sources": {name: len(hosts) for name, hosts in sources.items()},
        "source_errors": errors or None,
        "deep": deep,
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# ------------------------------------------------------------------- JS recon
ENDPOINT_RE = re.compile(
    r"""["'`](\/(?:api|rest|graphql|gql|v\d+|internal|admin|auth|oauth|upload|download|webhook|socket)[^"'`\s]{0,160})["'`]""",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s\"'<>()]+")
SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_key_assignment": re.compile(
        r"""aws[_-]?(?:secret[_-]?)?access[_-]?key[_-]?secret\s*[:=]\s*["'`]([A-Za-z0-9/+=]{40})["'`]""", re.I
    ),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "google_oauth_client_secret": re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28,}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "gitlab_token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    "npm_token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "slack_webhook": re.compile(r"\bhttps://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9]{24}\b"),
    "stripe_live_key": re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"),
    "stripe_webhook_secret": re.compile(r"\bwhsec_[0-9a-zA-Z]{24,}\b"),
    "twilio_key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "sendgrid_key": re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    "mailgun_key": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
    "telegram_bot_token": re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    "discord_bot_token": re.compile(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b"),
    "openai_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    "supabase_service_key": re.compile(r"\bservice_role\b.*\beyJ[A-Za-z0-9_-]{20,}\.ey", re.I),
    "azure_connection_string": re.compile(
        r"""(?:AccountName|AccountKey)=[^;]{4,};(?:AccountName|AccountKey)=[^;]{4,};""", re.I
    ),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----"),
    "mongodb_uri": re.compile(r"\bmongodb(?:\+srv)?://[^\s\"'<>]{6,}\b"),
    "postgres_uri": re.compile(r"\bpostgres(?:ql)?://[^\s\"'<>]{6,}\b"),
    "mysql_uri": re.compile(r"\bmysql://[^\s\"'<>]{6,}\b"),
    "amqp_uri": re.compile(r"\bamqps?://[^\s\"'<>]{6,}\b"),
    "bearer_token": re.compile(r"""[Bb]earer\s+[A-Za-z0-9._~+/-]{20,}"""),
    "basic_auth_url": re.compile(r"\bhttps?://[A-Za-z0-9._%-]+:[A-Za-z0-9._%-]+@[^\s\"'<>]+\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "generic_assignment": re.compile(
        r"""(?:api[_-]?key|apikey|secret|token|password|passwd|client[_-]?secret)\s*[:=]\s*["'`]([^"'`\s]{8,100})["'`]""",
        re.I,
    ),
}


def _mask(secret: str) -> str:
    if len(secret) <= 8:
        return "***"
    return secret[:4] + "..." + secret[-4:]


def _scan_js(text: str) -> dict:
    endpoints = set()
    urls = set()
    secrets: list[dict] = []
    source_maps = set()

    for match in ENDPOINT_RE.finditer(text):
        endpoints.add(match.group(1))
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:)'\"")
        if len(url) < 200:
            urls.add(url)
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if name == "jwt" and value.count(".") != 2:
                continue
            if name == "generic_assignment" and value.lower() in {
                "true",
                "false",
                "null",
                "undefined",
                "string",
                "number",
                "boolean",
            }:
                continue
            secrets.append({"type": name, "value": _mask(value)})
    for match in SOURCE_MAP_RE.finditer(text):
        source_maps.add(match.group(1))
    return {
        "endpoints": sorted(endpoints),
        "urls": sorted(urls),
        "secrets": secrets[:50],
        "source_maps": sorted(source_maps),
    }


@guarded
async def js_recon(url: str, max_scripts: int = 8, max_bytes: int = 2_000_000) -> dict:
    """Extract API endpoints, URLs, source maps and potential secrets from a page's JavaScript.

    Fetches the page, its script bundles (capped; tracker hosts skipped) and inline
    scripts, then applies endpoint and secret-pattern regexes. Secret values are masked.
    """
    target = ensure_url(url)
    if not target:
        return {"ok": False, "error": "empty URL"}
    max_scripts = max(1, min(int(max_scripts), 20))
    max_bytes = max(50_000, min(int(max_bytes), 8_000_000))

    page = await request(target, timeout=35.0)
    if page.status_code != 200:
        return {"ok": False, "url": target, "error": f"page HTTP {page.status_code}"}
    soup = BeautifulSoup(page.text, "html.parser")

    scripts: list[dict] = []
    inline_texts: list[str] = []
    script_urls: list[str] = []

    for tag in soup.find_all("script"):
        src = (tag.get("src") or "").strip()
        if src:
            absolute = urljoin(target, src)
            script_urls.append(absolute)
        elif tag.string:
            inline_texts.append(tag.string)

    deduped = []
    seen = set()
    for script_url in script_urls:
        if script_url in seen:
            continue
        seen.add(script_url)
        deduped.append(script_url)

    sem = asyncio.Semaphore(4)
    tracker_hosts = (
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
        "facebook.net",
        "hotjar.com",
        "segment.com",
        "segment.io",
        "mixpanel.com",
        "clarity.ms",
        "sentry.io",
        "newrelic.com",
        "nr-data.net",
    )

    async def fetch_script(script_url: str):
        async with sem:
            host = (urlparse(script_url).hostname or "").lower()
            if any(host == tracker or host.endswith("." + tracker) for tracker in tracker_hosts):
                return {
                    "url": script_url,
                    "skipped": "tracker host",
                }
            try:
                response = await request(script_url, timeout=30.0)
                body = response.text[:max_bytes]
                return {
                    "url": script_url,
                    "status": response.status_code,
                    "bytes": len(response.content),
                    "truncated": len(response.content) > max_bytes,
                    "content_type": response.headers.get("content-type"),
                    "_body": body,
                }
            except Exception as exc:
                return {"url": script_url, "error": f"{type(exc).__name__}: {exc}"}

    fetched = await asyncio.gather(*(fetch_script(script_url) for script_url in deduped[:max_scripts]))
    combined = "\n".join(inline_texts)
    for item in fetched:
        body = item.pop("_body", "") or ""
        if body:
            combined += "\n" + body
        scripts.append(item)

    scan = _scan_js(combined)
    return {
        "ok": True,
        "url": target,
        "script_count": len(deduped),
        "scripts": scripts,
        "inline_scripts": len(inline_texts),
        "endpoint_count": len(scan["endpoints"]),
        "endpoints": scan["endpoints"][:200],
        "url_count": len(scan["urls"]),
        "urls": scan["urls"][:100],
        "secret_count": len(scan["secrets"]),
        "potential_secrets": scan["secrets"],
        "source_maps": scan["source_maps"][:50],
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# -------------------------------------------------------------- API discovery
DISCOVERY_PATHS = [
    ("/openapi.json", "api_spec"),
    ("/swagger.json", "api_spec"),
    ("/swagger/v1/swagger.json", "api_spec"),
    ("/api-docs", "api_spec"),
    ("/v2/api-docs", "api_spec"),
    ("/v3/api-docs", "api_spec"),
    ("/graphql", "graphql"),
    ("/graphiql", "graphql"),
    ("/api/graphql", "graphql"),
    ("/.well-known/openid-configuration", "oidc"),
    ("/.well-known/oauth-authorization-server", "oidc"),
    ("/.well-known/jwks.json", "jwks"),
    ("/.well-known/security.txt", "security_txt"),
    ("/robots.txt", "robots"),
    ("/sitemap.xml", "sitemap"),
    ("/api", "api_root"),
    ("/api/v1", "api_root"),
    ("/health", "health"),
    ("/actuator", "actuator"),
    ("/actuator/health", "actuator"),
    ("/server-status", "sensitive"),
    ("/.env", "sensitive"),
    ("/.git/HEAD", "sensitive"),
    ("/phpinfo.php", "sensitive"),
    ("/debug", "sensitive"),
    ("/console", "sensitive"),
]


def _spec_summary(data: dict) -> dict:
    info = data.get("info") or {}
    paths = data.get("paths") or {}
    sample = []
    methods: set[str] = set()
    if isinstance(paths, dict):
        sample = list(paths.keys())[:12]
        for operations in list(paths.values())[:40]:
            if isinstance(operations, dict):
                for key in operations:
                    if key.lower() in ("get", "post", "put", "patch", "delete", "head", "options", "trace"):
                        methods.add(key.lower())
    servers = []
    raw_servers = data.get("servers")
    if isinstance(raw_servers, list):
        servers = [item.get("url") for item in raw_servers if isinstance(item, dict) and item.get("url")][:6]
    security = []
    raw_security = data.get("components", {}).get("securitySchemes") if isinstance(data.get("components"), dict) else None
    if isinstance(raw_security, dict):
        for name, scheme in list(raw_security.items())[:10]:
            scheme_type = scheme.get("type") if isinstance(scheme, dict) else None
            security.append({"name": name, "type": scheme_type})
    openapi_version = data.get("openapi") or data.get("swagger")
    return {
        "title": info.get("title"),
        "version": info.get("version"),
        "spec_version": openapi_version,
        "path_count": len(paths) if isinstance(paths, dict) else None,
        "sample_paths": sample,
        "http_methods": sorted(methods),
        "servers": servers,
        "security_schemes": security,
        "has_auth": bool(security) or bool(data.get("security")),
    }


def _oidc_summary(data: dict) -> dict:
    keys = [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "registration_endpoint",
        "scopes_supported",
        "response_types_supported",
        "grant_types_supported",
    ]
    return {key: data.get(key) for key in keys if data.get(key) is not None}


def _path_summary(category: str, response) -> dict | None:
    content_type = (response.headers.get("content-type") or "").lower()
    if category == "api_spec" and ("json" in content_type or response.text.lstrip().startswith("{")):
        data = _json_or_none(response)
        if isinstance(data, dict):
            return _spec_summary(data)
    if category == "oidc" and isinstance(_json_or_none(response), dict):
        return _oidc_summary(_json_or_none(response))
    if category == "jwks":
        data = _json_or_none(response)
        if isinstance(data, dict) and isinstance(data.get("keys"), list):
            return {"key_count": len(data["keys"])}
    if category == "security_txt":
        fields = {}
        for line in response.text.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                fields[key.strip().lower()] = val.strip()
        return {
            "contacts": [fields.get("contact")] if fields.get("contact") else [],
            "expires": fields.get("expires"),
            "policy": fields.get("policy"),
            "canonical": fields.get("canonical"),
        }
    if category == "robots":
        return {
            "lines": len(response.text.splitlines()),
            "sitemaps": [line.split(":", 1)[1].strip() for line in response.text.splitlines() if line.lower().startswith("sitemap:")][:10],
        }
    if category == "sitemap":
        return {"length": len(response.text), "urls": response.text.count("<loc>")}
    if category == "graphql":
        return {"introspection_hint": "GraphQL endpoint responded; verify auth and introspection manually."}
    return None


@guarded
async def api_discovery(domain: str, limit: int = 60) -> dict:
    """Probe common API/spec/debug paths on a domain (light, non-intrusive).

    Checks OpenAPI/Swagger, GraphQL, OIDC, JWKS, security.txt, robots, actuator
    and a few known-sensitive paths. Sensitive bodies are never returned, only status.
    """
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}
    limit = max(1, min(int(limit), 200))
    paths = DISCOVERY_PATHS[:limit]

    sem = asyncio.Semaphore(6)

    async def probe(path: str, category: str):
        async with sem:
            url = f"https://{target}{path}"
            try:
                response = await request(url, timeout=10.0, follow_redirects=False)
                found = response.status_code in (200, 201, 204, 301, 302, 401, 403)
                entry = {
                    "path": path,
                    "category": category,
                    "status": response.status_code,
                    "content_type": response.headers.get("content-type"),
                    "length": len(response.content),
                    "found": found,
                }
                if category == "sensitive":
                    entry["exposed"] = response.status_code == 200
                    entry["note"] = "Body intentionally not returned."
                else:
                    summary = _path_summary(category, response)
                    if summary:
                        entry["summary"] = summary
                return entry
            except Exception as exc:
                return {
                    "path": path,
                    "category": category,
                    "status": None,
                    "error": f"{type(exc).__name__}: {exc}",
                    "found": False,
                }

    results = await asyncio.gather(*(probe(path, category) for path, category in paths))
    found = [item for item in results if item.get("found")]
    exposed = [item for item in results if item.get("exposed")]
    return {
        "ok": True,
        "domain": target,
        "checked": len(results),
        "found_count": len(found),
        "found": sorted(found, key=lambda item: item["path"]),
        "exposed_sensitive": exposed,
        "errors": len([item for item in results if item.get("error")]),
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# ---------------------------------------------------------------- well-known
WELL_KNOWN_PATHS = [
    ".well-known/security.txt",
    ".well-known/openid-configuration",
    ".well-known/oauth-authorization-server",
    ".well-known/jwks.json",
    ".well-known/change-password",
    ".well-known/dnssec",
    ".well-known/apple-app-site-association",
    ".well-known/assetlinks.json",
    ".well-known/mta-sts.txt",
]


@guarded
async def well_known(domain: str) -> dict:
    """Fetch standard /.well-known documents and summarize OIDC, JWKS, security.txt and app links."""
    target = normalize_target(domain)
    if not target:
        return {"ok": False, "error": "empty domain"}

    async def fetch(path: str):
        try:
            response = await request(f"https://{target}/{path}", timeout=15.0)
            entry = {
                "path": path,
                "status": response.status_code,
                "content_type": response.headers.get("content-type"),
                "length": len(response.content),
                "found": response.status_code == 200,
            }
            if response.status_code == 200:
                text = response.text
                data = _json_or_none(response)
                if isinstance(data, list):
                    entry["summary"] = {"entries": len(data)}
                elif isinstance(data, dict):
                    if "openid-configuration" in path or "oauth-authorization-server" in path:
                        entry["summary"] = _oidc_summary(data)
                    elif path.endswith("jwks.json"):
                        entry["summary"] = {"key_count": len(data.get("keys") or [])}
                    elif path.endswith("apple-app-site-association"):
                        entry["summary"] = {"applinks": bool(data.get("applinks"))}
                    else:
                        entry["summary"] = {"keys": list(data.keys())[:15]}
                elif "security.txt" in path:
                    fields = {}
                    for line in text.splitlines():
                        if ":" in line:
                            key, value = line.split(":", 1)
                            fields[key.strip().lower()] = value.strip()
                    entry["summary"] = {
                        "contacts": fields.get("contact"),
                        "expires": fields.get("expires"),
                        "policy": fields.get("policy"),
                        "canonical": fields.get("canonical"),
                    }
                elif path.endswith("mta-sts.txt"):
                    fields = {}
                    for line in text.splitlines():
                        if ":" in line:
                            key, value = line.split(":", 1)
                            fields[key.strip().lower()] = value.strip()
                    entry["summary"] = fields
            return entry
        except Exception as exc:
            return {"path": path, "status": None, "error": f"{type(exc).__name__}: {exc}", "found": False}

    results = await asyncio.gather(*(fetch(path) for path in WELL_KNOWN_PATHS))
    return {
        "ok": True,
        "domain": target,
        "found_count": len([item for item in results if item.get("found")]),
        "results": results,
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# --------------------------------------------------------- subdomain takeover
TAKEOVER_PROVIDERS = [
    ("github.io", "GitHub Pages", ["There isn't a GitHub Pages site here"]),
    ("s3.amazonaws.com", "AWS S3", ["NoSuchBucket", "The specified bucket does not exist"]),
    ("s3-website", "AWS S3 website", ["NoSuchBucket", "The specified bucket does not exist"]),
    ("cloudfront.net", "AWS CloudFront", ["ERROR: The request could not be satisfied"]),
    ("herokuapp.com", "Heroku", ["No such app"]),
    ("azurewebsites.net", "Azure App Service", ["404 Web Site not found", "This web app is stopped"]),
    ("cloudapp.azure.com", "Azure VM", ["404 Not Found"]),
    ("blob.core.windows.net", "Azure Blob", ["BlobNotFound"]),
    ("trafficmanager.net", "Azure Traffic Manager", ["not found"]),
    ("netlify.app", "Netlify", ["Not found - Request ID"]),
    ("netlify.com", "Netlify", ["Not found - Request ID"]),
    ("vercel.app", "Vercel", ["DEPLOYMENT_NOT_FOUND", "The deployment could not be found"]),
    ("vercel-dns.com", "Vercel", ["DEPLOYMENT_NOT_FOUND", "The deployment could not be found"]),
    ("now.sh", "Vercel", ["DEPLOYMENT_NOT_FOUND"]),
    ("surge.sh", "Surge", ["project not found"]),
    ("bitbucket.io", "Bitbucket", ["Repository not found"]),
    ("ghost.io", "Ghost", ["Domain error"]),
    ("shopify.com", "Shopify", ["Sorry, this shop is currently unavailable"]),
    ("myshopify.com", "Shopify", ["Sorry, this shop is currently unavailable"]),
    ("pantheonsite.io", "Pantheon", ["The gods are wise"]),
    ("wpengine.com", "WP Engine", ["No site configured at this address"]),
    ("fastly.net", "Fastly", ["Fastly error: unknown domain"]),
    ("zendesk.com", "Zendesk", ["Help Center Closed"]),
    ("statuspage.io", "Statuspage", ["Page not found"]),
    ("readme.io", "ReadMe", ["Project not found"]),
    ("teamwork.com", "Teamwork", ["Oops"]),
    ("uservoice.com", "UserVoice", ["This UserVoice subdomain is currently available"]),
    ("unbounce.com", "Unbounce", ["The requested URL was not found"]),
    ("tumblr.com", "Tumblr", ["There's nothing here"]),
    ("desk.com", "Desk", ["This help center no longer exists"]),
    ("helpscout.net", "Help Scout", ["No such site"]),
    ("freshdesk.com", "Freshdesk", ["There is no helpdesk here"]),
    ("smugmug.com", "SmugMug", ["Page Not Found"]),
    ("kinsta.com", "Kinsta", ["No site configured at this address"]),
    ("readthedocs.io", "Read the Docs", ["404 - Not Found"]),
]


def _provider_for(cname: str) -> tuple[str, str, list[str]] | None:
    lowered = cname.lower().rstrip(".")
    for suffix, provider, fingerprints in TAKEOVER_PROVIDERS:
        if suffix == "s3-website":
            if "s3-website" in lowered and lowered.endswith(".amazonaws.com"):
                return suffix, provider, fingerprints
            continue
        if lowered.endswith("." + suffix) or lowered == suffix:
            return suffix, provider, fingerprints
    return None


def _cname_sync(host: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(host, "CNAME", lifetime=6)
        return [str(item.target).rstrip(".").lower() for item in answers]
    except Exception:
        return []


@guarded
async def subdomain_takeover_check(domain: str, limit: int = 100, deep: bool = False) -> dict:
    """Check subdomains for dangling CNAMEs to known takeover-prone providers.

    Enumerates subdomains (or accepts a comma/newline-separated host list), resolves
    CNAMEs, and fetches each host to match provider-specific unclaimed fingerprints.
    High confidence requires a matching fingerprint; a matching CNAME alone is potential.
    """
    raw = (domain or "").strip()
    if not raw:
        return {"ok": False, "error": "empty target"}
    limit = max(1, min(int(limit), 500))

    hosts: list[str] = []
    enumeration: dict = {}
    if any(sep in raw for sep in (",", "\n", " ")):
        hosts = _dedupe_sorted(re.split(r"[\s,]+", raw))
    else:
        target = normalize_target(raw)
        if not target or "." not in target:
            return {"ok": False, "error": "provide a domain or a comma-separated host list"}
        try:
            enumeration = await asyncio.wait_for(
                passive_subdomains(target, limit=limit, deep=deep), timeout=100.0
            )
        except asyncio.TimeoutError:
            enumeration = {"ok": False, "error": "subdomain enumeration timed out", "subdomains": []}
        if enumeration.get("ok"):
            hosts = list(enumeration.get("subdomains") or [])
        else:
            hosts_, error = await _hackertarget_hosts(target)
            hosts = sorted(hosts_)
            enumeration = {"ok": False, "error": error, "subdomains": hosts}

    hosts = _dedupe_sorted(hosts)[:limit]
    if not hosts:
        return {"ok": True, "target": raw, "checked": 0, "findings": [], "note": "No subdomains found."}

    sem = asyncio.Semaphore(8)

    async def check_host(host: str):
        async with sem:
            cnames = await asyncio.to_thread(_cname_sync, host)
            if not cnames:
                return {"host": host, "cname": None, "provider": None, "risk": "none"}
            cname = cnames[0]
            provider_info = _provider_for(cname)
            if not provider_info:
                return {"host": host, "cname": cname, "provider": None, "risk": "none"}
            _suffix, provider, fingerprints = provider_info
            http_status = None
            matched = None
            body_snippet = ""
            for scheme in ("https", "http"):
                try:
                    response = await request(f"{scheme}://{host}", timeout=12.0, follow_redirects=True)
                    http_status = response.status_code
                    text = response.text[:200_000]
                    lowered = text.lower()
                    for fingerprint in fingerprints:
                        if fingerprint.lower() in lowered:
                            matched = fingerprint
                            body_snippet = clip(text, 300)
                            break
                    if matched:
                        break
                    if response.status_code == 200:
                        break
                except Exception:
                    continue
            if matched:
                risk = "high"
            elif http_status is None or http_status >= 500 or http_status in (404, 410):
                risk = "potential"
            else:
                risk = "claimed"
            return {
                "host": host,
                "cname": cname,
                "provider": provider,
                "http_status": http_status,
                "fingerprint": matched,
                "risk": risk,
                "evidence": body_snippet or None,
            }

    results = await asyncio.gather(*(check_host(host) for host in hosts))
    interesting = [item for item in results if item.get("provider")]
    findings = [item for item in interesting if item.get("risk") in ("high", "potential")]
    findings.sort(key=lambda item: (item.get("risk") != "high", item["host"]))
    return {
        "ok": True,
        "target": raw,
        "checked": len(hosts),
        "with_cname_to_provider": len(interesting),
        "finding_count": len(findings),
        "findings": findings,
        "claimed": [item for item in interesting if item.get("risk") == "claimed"][:30],
        "enumeration": {
            "ok": enumeration.get("ok"),
            "count": enumeration.get("count"),
            "sources": enumeration.get("sources"),
            "error": enumeration.get("error"),
        },
        "note": "Only high-confidence fingerprint matches should be treated as takeovers; potential needs manual review.",
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# --------------------------------------------------------------- favicon hash
def _murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86 32-bit (Shodan-compatible favicon hashing)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h1 = seed & 0xFFFFFFFF
    length = len(data)
    rounded_end = length & ~3

    for index in range(0, rounded_end, 4):
        k1 = int.from_bytes(data[index : index + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[rounded_end:]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def _shodan_favicon_hash(data: bytes) -> int:
    encoded = base64.encodebytes(data)
    return _murmur3_x86_32(encoded)


@guarded
async def favicon_hash(url: str) -> dict:
    """Fetch a site's favicon and compute the Shodan mmh3 hash (plus MD5/SHA256).

    Tries the page's <link rel=icon>, apple-touch-icon, then /favicon.ico. Returns
    the ready-to-use Shodan query http.favicon.hash:<hash>.
    """
    target = ensure_url(url)
    if not target:
        return {"ok": False, "error": "empty URL"}

    candidates: list[str] = []
    page_status = None
    content_type = ""
    try:
        page = await request(target, timeout=25.0)
        page_status = page.status_code
        content_type = (page.headers.get("content-type") or "").lower()
        if page.status_code == 200 and "image" not in content_type:
            soup = BeautifulSoup(page.text, "html.parser")
            for tag in soup.find_all("link"):
                rel = " ".join(tag.get("rel") or []).lower()
                href = (tag.get("href") or "").strip()
                if href and ("icon" in rel or "apple-touch" in rel):
                    candidates.append(urljoin(target, href))
    except Exception:
        pass

    parsed = urlparse(target)
    candidates.extend(
        [
            f"{parsed.scheme}://{parsed.netloc}/favicon.ico",
            f"{parsed.scheme}://{parsed.netloc}/favicon.png",
        ]
    )
    if "image" in content_type and page_status == 200:
        candidates.insert(0, target)

    seen = set()
    errors = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            response = await request(candidate, timeout=20.0)
            if response.status_code != 200 or not response.content:
                continue
            if len(response.content) > 3_000_000:
                continue
            body = response.content
            mmh3 = _shodan_favicon_hash(body)
            return {
                "ok": True,
                "page": target,
                "page_status": page_status,
                "favicon_url": candidate,
                "content_type": response.headers.get("content-type"),
                "size": len(body),
                "md5": hashlib.md5(body).hexdigest(),
                "sha256": hashlib.sha256(body).hexdigest(),
                "shodan_mmh3": mmh3,
                "shodan_mmh3_unsigned": mmh3 & 0xFFFFFFFF,
                "shodan_query": f"http.favicon.hash:{mmh3}",
            }
        except Exception as exc:
            errors.append(f"{candidate}: {type(exc).__name__}")
            continue

    return {
        "ok": False,
        "url": target,
        "error": "no favicon found",
        "tried": list(seen),
        "errors": errors[:5],
    }


# -------------------------------------------------------------- cloud buckets
def _xml_text(root, path: str) -> str | None:
    node = root.find(path)
    return node.text if node is not None and node.text else None


@guarded
async def cloud_bucket_check(bucket: str, provider: str = "auto") -> dict:
    """Check whether an S3/GCS/Azure bucket exists and allows public object listing.

    Accepts a bucket name (tries S3 and GCS) or account/container for Azure. Returns
    existence, public-listing state and a sample of object names. Read-only.
    """
    value = (bucket or "").strip()
    if not value:
        return {"ok": False, "error": "empty bucket"}
    value = re.sub(r"^(?:s3|gs|gcs)://", "", value).strip("/")
    provider = (provider or "auto").strip().lower()
    results: list[dict] = []

    if "/" in value:
        account, container = value.split("/", 1)
        azure_value = (account, container)
    else:
        azure_value = None

    if provider in ("auto", "s3"):
        name = value.split("/")[0]
        try:
            response = await request(
                f"https://{name}.s3.amazonaws.com/",
                params={"list-type": "2", "max-keys": "10"},
                timeout=25.0,
            )
            text = response.text
            entry = {
                "provider": "aws_s3",
                "bucket": name,
                "status": response.status_code,
                "exists": False,
                "public_listing": False,
                "objects": [],
            }
            if response.status_code == 200 and "<ListBucketResult" in text:
                root = ET.fromstring(text)
                entry.update(
                    {
                        "exists": True,
                        "public_listing": True,
                        "object_count": _xml_text(root, ".//KeyCount"),
                        "truncated": _xml_text(root, ".//IsTruncated"),
                        "objects": [
                            _xml_text(item, "Key")
                            for item in root.findall(".//Contents")[:10]
                        ],
                    }
                )
            elif "NoSuchBucket" in text or "The specified bucket does not exist" in text:
                entry["exists"] = False
            elif response.status_code in (401, 403):
                entry["exists"] = True
                entry["public_listing"] = False
                entry["note"] = "Bucket exists but listing is denied."
            results.append(entry)
        except Exception as exc:
            results.append({"provider": "aws_s3", "bucket": name, "error": f"{type(exc).__name__}: {exc}"})

    if provider in ("auto", "gcs", "google"):
        name = value.split("/")[0]
        try:
            response = await request(
                f"https://storage.googleapis.com/storage/v1/b/{name}/o",
                params={"maxResults": "10"},
                timeout=25.0,
            )
            data = _json_or_none(response) or {}
            entry = {
                "provider": "google_cloud_storage",
                "bucket": name,
                "status": response.status_code,
                "exists": response.status_code in (200, 401, 403),
                "public_listing": response.status_code == 200,
                "objects": [item.get("name") for item in (data.get("items") or [])[:10]],
            }
            if response.status_code == 404:
                entry["exists"] = False
            results.append(entry)
        except Exception as exc:
            results.append({"provider": "google_cloud_storage", "bucket": name, "error": f"{type(exc).__name__}: {exc}"})

    if provider in ("auto", "azure") and azure_value:
        account, container = azure_value
        try:
            response = await request(
                f"https://{account}.blob.core.windows.net/{container}",
                params={"restype": "container", "comp": "list", "maxresults": "10"},
                timeout=25.0,
            )
            text = response.text
            entry = {
                "provider": "azure_blob",
                "account": account,
                "container": container,
                "status": response.status_code,
                "exists": response.status_code in (200, 401, 403),
                "public_listing": False,
                "objects": [],
            }
            if response.status_code == 200 and "<EnumerationResults" in text:
                root = ET.fromstring(text)
                entry["public_listing"] = True
                entry["objects"] = [
                    _xml_text(item, "Name") for item in root.findall(".//Blob")[:10]
                ]
            results.append(entry)
        except Exception as exc:
            results.append({"provider": "azure_blob", "account": account, "container": container, "error": f"{type(exc).__name__}: {exc}"})

    public = [item for item in results if item.get("public_listing")]
    return {
        "ok": True,
        "input": bucket,
        "publicly_listable": bool(public),
        "results": results,
        "note": "Public listing does not imply write access; this tool is read-only.",
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }
