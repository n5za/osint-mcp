"""Shared helpers for the OSINT MCP server."""

from __future__ import annotations

import datetime as dt
import functools
import json
import os
import re
import time
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

_CACHE: dict[str, tuple[float, Any]] = {}


def cache_get(key: str, ttl: float = 300.0) -> Any | None:
    """Return a cached value if it is younger than ttl seconds."""
    item = _CACHE.get(key)
    if not item:
        return None
    saved_at, value = item
    if time.time() - saved_at > ttl:
        _CACHE.pop(key, None)
        return None
    return value


def cache_set(key: str, value: Any) -> Any:
    _CACHE[key] = (time.time(), value)
    return value


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
        with open(KEYS_PATH, "r", encoding="utf-8") as fh:
            stored = json.load(fh)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(stored, dict):
        return None
    for name in names:
        value = stored.get(name.lower())
        if value and str(value).strip():
            return str(value).strip()
    return None



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


def error_result(exc: BaseException) -> dict:
    return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def guarded(fn):
    """Catch exceptions so the model gets a structured error instead of a crash."""

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            return error_result(exc)

    return wrapper


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
) -> httpx.Response:
    merged = {
        "User-Agent": USER_AGENT,
        "Accept-Language": "en-US,en;q=0.9",
        **(headers or {}),
    }
    async with httpx.AsyncClient(
        headers=merged,
        timeout=timeout or DEFAULT_TIMEOUT,
        follow_redirects=follow_redirects,
        verify=verify,
    ) as client:
        return await client.request(method, url, params=params, content=content, data=data)


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
