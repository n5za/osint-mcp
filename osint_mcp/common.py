"""Shared helpers for the OSINT MCP server.

v2 reliability core:
- shared pooled httpx clients (connection reuse, no TLS handshake per request)
- automatic retry with backoff for idempotent requests
- bounded LRU cache (no unbounded memory growth)
- per-host concurrency cap
- SSRF guard against private/loopback address ranges (OSINT_ALLOW_PRIVATE=1 opts out)
- structured errors with error_code / retryable
- stderr logging for client-side debugging
"""

from __future__ import annotations

import asyncio
import datetime as dt
import functools
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import urlsplit

import httpx

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 20.0
MAX_TEXT = 20000
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS_DIR = os.environ.get("OSINT_SHOTS_DIR", os.path.join(BASE_DIR, "shots"))
KEYS_PATH = os.path.expanduser(os.environ.get("OSINT_KEYS_FILE", "~/.config/osint-mcp/keys.json"))

# ---------------------------------------------------------------------------
# Logging (stderr only — stdout carries the MCP protocol)
# ---------------------------------------------------------------------------
LOG_LEVEL = os.environ.get("OSINT_LOG_LEVEL", "WARNING").upper()
logging.basicConfig(
    stream=sys.stderr,
    level=LOG_LEVEL if LOG_LEVEL in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "WARNING",
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("osint")

# ---------------------------------------------------------------------------
# Bounded LRU cache with TTL
# ---------------------------------------------------------------------------
CACHE_MAX_ENTRIES = int(os.environ.get("OSINT_CACHE_MAX", "512"))


class _BoundedCache:
    """LRU cache with a hard cap so long sessions cannot leak memory."""

    def __init__(self, max_entries: int = CACHE_MAX_ENTRIES) -> None:
        self.max_entries = max(8, max_entries)
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()

    def get(self, key: str, ttl: float = 300.0) -> Any | None:
        item = self._data.get(key)
        if not item:
            return None
        saved_at, value = item
        if time.time() - saved_at > ttl:
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: str, value: Any) -> Any:
        self._data[key] = (time.time(), value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)
        return value

    def clear(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


_CACHE = _BoundedCache()


def cache_get(key: str, ttl: float = 300.0) -> Any | None:
    """Return a cached value if it is younger than ttl seconds."""
    return _CACHE.get(key, ttl)


def cache_set(key: str, value: Any) -> Any:
    return _CACHE.set(key, value)


def cache_clear() -> None:
    _CACHE.clear()


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
def api_key(*names: str) -> str | None:
    """Find an API key from the environment or the local key store.

    Looks for NAME_API_KEY, NAME_KEY and NAME (upper-case) first, then checks
    ~/.config/osint-mcp/keys.json using the same lower-case names.
    """
    for name in names:
        for env_name in (f"{name.upper()}_API_KEY", f"{name.upper()}_KEY", name.upper()):
            value = os.environ.get(env_name)
            if value and value.strip():
                return value.strip()
    try:
        with open(KEYS_PATH, encoding="utf-8") as fh:
            stored = json.load(fh)
    except Exception:
        return None
    if not isinstance(stored, dict):
        return None
    for name in names:
        value = stored.get(name.lower())
        if value and str(value).strip():
            return str(value).strip()
    return None


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------
def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def jsonable(value: Any) -> Any:
    """Best-effort conversion to JSON-serialisable types."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v) for v in value]
    return str(value)


def clip(text: str | None, limit: int = MAX_TEXT) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"


def normalize_target(target: str) -> str:
    """Turn a URL / host:port / user@host into a bare hostname."""
    value = (target or "").strip()
    value = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", value)
    value = value.split("/")[0].split("?")[0]
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if value.startswith("["):
        value = value.split("]")[0].lstrip("[")
    elif value.count(":") == 1:
        value = value.split(":")[0]
    return value.rstrip(".").strip()


def ensure_url(target: str) -> str:
    value = (target or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    return value


def url_host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def headers_dict(response: httpx.Response) -> dict[str, Any]:
    """Headers with duplicates grouped (Set-Cookie etc.)."""
    grouped: dict[str, list[str]] = {}
    for key, value in response.headers.multi_items():
        grouped.setdefault(key.lower(), []).append(value)
    return {k: (v[0] if len(v) == 1 else v) for k, v in grouped.items()}


# ---------------------------------------------------------------------------
# Structured errors
# ---------------------------------------------------------------------------
_RETRYABLE_EXCEPTIONS = (
    httpx.TimeoutException,
    httpx.TransportError,
    ConnectionError,
    TimeoutError,
)


def _is_retryable(exc: BaseException) -> bool:
    return isinstance(exc, _RETRYABLE_EXCEPTIONS)


def error_result(exc: BaseException) -> dict:
    """Structured failure result: human message + machine-readable hints."""
    return {
        "ok": False,
        "error": f"{type(exc).__name__}: {exc}",
        "error_code": type(exc).__name__,
        "retryable": _is_retryable(exc),
    }


def fail(message: str, *, code: str = "error", retryable: bool = False, **extra: Any) -> dict:
    """Build a structured failure result without raising."""
    return {"ok": False, "error": message, "error_code": code, "retryable": retryable, **extra}


def guarded(fn):
    """Catch exceptions so the model gets a structured error instead of a crash."""

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except Exception as exc:
            log.debug("tool %s failed: %s", getattr(fn, "__name__", "?"), exc)
            return error_result(exc)

    return wrapper


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------
class PrivateAddressError(ValueError):
    """Raised when a request targets a private/loopback network address."""


def allow_private() -> bool:
    return os.environ.get("OSINT_ALLOW_PRIVATE", "0").strip().lower() in ("1", "true", "yes", "on")


def _address_is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


_DNS_CACHE: dict[str, tuple[float, list[str]]] = {}
_DNS_CACHE_TTL = 120.0


async def resolve_hosts(host: str) -> list[str]:
    """Resolve a hostname to IP addresses with a short cache (guard helper)."""
    cached = _DNS_CACHE.get(host)
    now = time.time()
    if cached and now - cached[0] < _DNS_CACHE_TTL:
        return cached[1]
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
        addresses = sorted({info[4][0] for info in infos})
    except OSError:
        addresses = []
    if addresses:
        _DNS_CACHE[host] = (now, addresses)
        if len(_DNS_CACHE) > 1024:  # bound the resolver cache too
            _DNS_CACHE.clear()
    return addresses


async def assert_public_url(url: str) -> None:
    """Guard helper: raise PrivateAddressError when url points at a private range.

    Disabled entirely when OSINT_ALLOW_PRIVATE=1 (authorized lab use).
    Note: this is accident prevention, not a sandbox — DNS rebinding between
    check and connect is out of scope; run hostile targets in an isolated network.
    """
    if allow_private():
        return
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise PrivateAddressError(f"unparsable URL: {exc}") from exc
    if parts.scheme.lower() not in ("http", "https"):
        raise PrivateAddressError(f"blocked non-HTTP scheme: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise PrivateAddressError("URL has no hostname")
    if host.strip("[]").endswith(".local") or host == "localhost":
        raise PrivateAddressError(f"blocked internal host: {host}")
    try:
        ipaddress.ip_address(host.strip("[]"))
        addresses = [host.strip("[]")]
    except ValueError:
        addresses = await resolve_hosts(host)
    for address in addresses:
        if _address_is_private(address):
            raise PrivateAddressError(
                f"blocked private/internal address {address} (host {host}); "
                "set OSINT_ALLOW_PRIVATE=1 for authorized lab use"
            )


# ---------------------------------------------------------------------------
# Shared pooled HTTP clients
# ---------------------------------------------------------------------------
_CLIENTS: dict[bool, httpx.AsyncClient] = {}
_CLIENT_LOCK: asyncio.Lock | None = None
_BASE_HEADERS = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}

# per-host concurrency cap so a fragile source is never burst-pounded
_HOST_LOCKS: dict[str, asyncio.Semaphore] = {}
_HOST_LOCK_LIMIT = 4
_HOST_LOCKS_MAX = 256

RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_RETRIES = 2
MAX_REDIRECTS = 10


async def get_client(verify: bool = True) -> httpx.AsyncClient:
    """Return the shared pooled client (one per verify mode)."""
    global _CLIENT_LOCK
    client = _CLIENTS.get(verify)
    if client is not None and not client.is_closed:
        return client
    if _CLIENT_LOCK is None:
        _CLIENT_LOCK = asyncio.Lock()
    async with _CLIENT_LOCK:
        client = _CLIENTS.get(verify)
        if client is None or client.is_closed:
            client = httpx.AsyncClient(
                headers=_BASE_HEADERS,
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=False,  # redirects are handled per-hop in request()
                limits=httpx.Limits(max_connections=64, max_keepalive_connections=16),
                verify=verify,
            )
            _CLIENTS[verify] = client
        return client


async def aclose_clients() -> None:
    """Close pooled clients (used by tests and shutdown)."""
    for client in _CLIENTS.values():
        try:
            await client.aclose()
        except Exception:
            pass
    _CLIENTS.clear()


def _host_lock(host: str) -> asyncio.Semaphore:
    sem = _HOST_LOCKS.get(host)
    if sem is None:
        if len(_HOST_LOCKS) > _HOST_LOCKS_MAX:
            _HOST_LOCKS.clear()
        sem = asyncio.Semaphore(_HOST_LOCK_LIMIT)
        _HOST_LOCKS[host] = sem
    return sem


def _merge_headers(headers: dict[str, str] | None) -> dict[str, str]:
    return {**_BASE_HEADERS, **(headers or {})}


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return min(float(value), 10.0)
    try:
        import email.utils

        parsed = email.utils.parsedate_to_datetime(value)
        delta = parsed.timestamp() - time.time()
        return min(max(delta, 0.0), 10.0) if delta > 0 else None
    except Exception:
        return None


def _redirect_hop(
    response: httpx.Response,
    current_url: str,
    current_method: str,
    body_kwargs: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    """Return (next_url, next_method, next_body) for a redirect response."""
    location = response.headers.get("location") or ""
    next_url = str(httpx.URL(current_url).join(location))
    next_method = current_method
    next_body = body_kwargs
    # RFC semantics: 303 always becomes GET; 301/302 downgrade mutating methods
    if response.status_code == 303 or (
        response.status_code in (301, 302) and current_method in ("POST", "PUT", "PATCH")
    ):
        next_method = "GET"
        next_body = {"content": None, "data": None}
    return next_url, next_method, next_body


async def _send_chain(
    url: str,
    *,
    method: str,
    headers: dict[str, str] | None,
    params: dict[str, Any] | None,
    content: str | bytes | None,
    data: dict[str, Any] | None,
    timeout: float | None,
    verify: bool,
) -> httpx.Response:
    """Send one request, following redirects manually so every hop passes the SSRF guard."""
    current_url = url
    current_method = method.upper()
    history: list[httpx.Response] = []
    body_kwargs: dict[str, Any] = {"content": content, "data": data}

    for _hop in range(MAX_REDIRECTS + 1):
        await assert_public_url(current_url)
        host = url_host(current_url) or "unknown"
        client = await get_client(verify)
        async with _host_lock(host):
            response = await client.request(
                current_method,
                current_url,
                headers=_merge_headers(headers),
                params=params if not history else None,
                timeout=timeout,
                **body_kwargs,
            )
        if response.status_code not in (301, 302, 303, 307, 308):
            break
        location = response.headers.get("location")
        if not location:
            break
        history.append(response)
        await response.aread()
        current_url, current_method, body_kwargs = _redirect_hop(response, current_url, current_method, body_kwargs)
    else:
        raise httpx.TooManyRedirects(f"more than {MAX_REDIRECTS} redirects")

    response.history = history
    return response


async def request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    content: str | bytes | None = None,
    data: dict[str, Any] | None = None,
    timeout: float | None = None,
    verify: bool = True,
    follow_redirects: bool = True,
    retries: int | None = None,
) -> httpx.Response:
    """HTTP request through the pooled client with SSRF guard and retries.

    GET/HEAD requests are retried up to MAX_RETRIES times on 429/5xx and
    transport errors, honouring Retry-After. Non-idempotent methods are sent once.
    """
    method_upper = method.upper()
    idempotent = method_upper in ("GET", "HEAD")
    attempts = MAX_RETRIES if retries is None else max(0, int(retries))
    total_attempts = attempts + 1

    for attempt in range(total_attempts):
        try:
            if follow_redirects:
                response = await _send_chain(
                    url,
                    method=method_upper,
                    headers=headers,
                    params=params,
                    content=content,
                    data=data,
                    timeout=timeout,
                    verify=verify,
                )
            else:
                response = await _send_no_redirect(
                    url,
                    method=method_upper,
                    headers=headers,
                    params=params,
                    content=content,
                    data=data,
                    timeout=timeout,
                    verify=verify,
                )
            if response.status_code not in RETRYABLE_STATUSES or not idempotent:
                return response
            if attempt < total_attempts - 1:
                retry_after = _parse_retry_after(response.headers.get("retry-after"))
                delay = retry_after if retry_after is not None else 0.5 * (2**attempt)
                log.info("retrying %s %s after %.1fs (status %s)", method_upper, url, delay, response.status_code)
                await asyncio.sleep(delay)
                continue
            return response
        except _RETRYABLE_EXCEPTIONS:
            if attempt < total_attempts - 1 and idempotent:
                delay = 0.5 * (2**attempt)
                log.info("retrying %s %s after %.1fs", method_upper, url, delay)
                await asyncio.sleep(delay)
                continue
            raise
    raise RuntimeError("unreachable request state")


async def _send_no_redirect(
    url: str,
    *,
    method: str,
    headers: dict[str, str] | None,
    params: dict[str, Any] | None,
    content: str | bytes | None,
    data: dict[str, Any] | None,
    timeout: float | None,
    verify: bool,
) -> httpx.Response:
    """Single hop without redirect following (follow_redirects=False callers)."""
    await assert_public_url(url)
    host = url_host(url) or "unknown"
    client = await get_client(verify)
    async with _host_lock(host):
        return await client.request(
            method,
            url,
            headers=_merge_headers(headers),
            params=params,
            timeout=timeout,
            content=content,
            data=data,
        )


async def get_json(url: str, *, timeout: float | None = None, headers: dict[str, str] | None = None) -> Any:
    response = await request(url, timeout=timeout, headers=headers)
    response.raise_for_status()
    return response.json()


def port_service(port: int) -> str:
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
        143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
        465: "smtps", 587: "submission", 636: "ldaps", 873: "rsync", 993: "imaps",
        995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 2049: "nfs",
        2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql",
        3389: "rdp", 4443: "https-alt", 5000: "http-alt", 5432: "postgresql",
        5601: "kibana", 5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "k8s-api",
        8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
        9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch",
        11211: "memcached", 27017: "mongodb", 27018: "mongodb",
    }
    return services.get(port, "unknown")
