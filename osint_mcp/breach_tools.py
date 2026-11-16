"""Breach / leaked-data exposure tools.

These tools return breach and infostealer *metadata* only. They never download,
return, or display raw leaked records, passwords, hashes, cookies, or logs.
Personal lookups require the caller to attest authorization with authorized=True.
"""

from __future__ import annotations

import asyncio
import html
import os
import re
from typing import Any
from urllib.parse import quote

from .common import api_key, cache_get, cache_set, clip, guarded, normalize_target, request

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
LEAKCHECK_PUBLIC = "https://leakcheck.io/api/public"
HUDSON_ROCK = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

BREACH_TTL = 21_600  # 6 hours
CATALOG_TTL = 86_400  # 24 hours

FIELD_LABELS = {
    "password": "Passwords",
    "passwords": "Passwords",
    "passhash": "Password hashes",
    "hash": "Password hashes",
    "email": "Email addresses",
    "emails": "Email addresses",
    "username": "Usernames",
    "usernames": "Usernames",
    "name": "Names",
    "first_name": "Names",
    "last_name": "Names",
    "middle_name": "Names",
    "profile_name": "Profile names",
    "phone": "Phone numbers",
    "address": "Physical addresses",
    "city": "Physical addresses",
    "state": "Physical addresses",
    "zip": "Physical addresses",
    "country": "Physical addresses",
    "dob": "Dates of birth",
    "ssn": "Social security numbers",
    "ip": "IP addresses",
    "ip1": "IP addresses",
    "ip2": "IP addresses",
    "company_name": "Employers",
    "gender": "Genders",
    "id": "Account identifiers",
    "origin": "Account identifiers",
    "bank": "Financial data",
    "bank_account": "Financial data",
    "credit_card": "Financial data",
    "cc": "Financial data",
    "iban": "Financial data",
    "account": "Financial data",
    "balance": "Financial data",
}

SENSITIVE_FIELDS = {
    "password",
    "passwords",
    "passhash",
    "hash",
    "ssn",
    "bank",
    "bank_account",
    "credit_card",
    "cc",
    "iban",
    "account",
    "balance",
}


def _safe_error(exc: BaseException) -> str:
    """Provider errors without leaking URLs (which may contain the identifier)."""
    return f"{type(exc).__name__}: provider request failed"


def _mask_email(email: str) -> str:
    local, domain = email.rsplit("@", 1)
    masked = local[0] + "***" if len(local) <= 2 else local[0] + "***" + local[-1]
    return f"{masked}@{domain}"


def _mask_handle(handle: str) -> str:
    if len(handle) <= 2:
        return handle[0] + "***"
    return handle[0] + "***" + handle[-1]


def _parse_identifier(identifier: str, kind: str) -> tuple[str, str] | tuple[None, dict]:
    raw = (identifier or "").strip()
    if not raw:
        return None, {"ok": False, "error": "identifier is required"}

    if len(raw) > 320:
        return None, {"ok": False, "error": "identifier is too long"}

    selected = (kind or "auto").strip().lower()
    allowed = {"auto", "email", "domain", "username"}
    if selected not in allowed:
        return None, {"ok": False, "error": f"invalid kind; use one of {sorted(allowed)}"}

    if selected == "auto":
        if "@" in raw:
            selected = "email"
        elif "." in raw:
            selected = "domain"
        else:
            selected = "username"

    if selected == "email":
        value = raw.lower()
        if not EMAIL_RE.fullmatch(value):
            return None, {"ok": False, "error": "invalid email address"}
        return "email", value

    if selected == "domain":
        value = normalize_target(raw).lower()
        if not value or not DOMAIN_RE.fullmatch(value):
            return None, {"ok": False, "error": "invalid domain name"}
        return "domain", value

    value = raw.lstrip("@").strip()
    if not USERNAME_RE.fullmatch(value):
        return None, {
            "ok": False,
            "error": "invalid username (allowed: letters, digits, dot, underscore, hyphen)",
        }
    return "username", value


def _hibp_key() -> str | None:
    return api_key("hibp", "haveibeenpwned")


def _hibp_key_source() -> str | None:
    for env_name in ("HIBP_API_KEY", "HIBP_KEY", "HIBP", "HAVEIBEENPWNED_API_KEY"):
        if os.environ.get(env_name):
            return "environment"
    if _hibp_key():
        return "key_store"
    return None


def _hibp_headers() -> dict[str, str]:
    key = _hibp_key()
    if not key:
        return {}
    return {
        "hibp-api-key": key,
        "User-Agent": "osint-mcp/1.0",
        "Accept": "application/json",
    }


def _http_status_result(provider: str, status: int) -> dict:
    if status == 401:
        return {
            "provider": provider,
            "status": "error",
            "http_status": status,
            "error": "invalid or missing API key",
            "configured": bool(_hibp_key()),
        }
    if status == 403:
        return {
            "provider": provider,
            "status": "domain_not_verified",
            "http_status": status,
            "error": "HIBP requires the domain to be verified in the dashboard",
        }
    if status == 429:
        return {
            "provider": provider,
            "status": "rate_limited",
            "http_status": status,
            "error": "provider rate limit reached; retry later",
        }
    return {
        "provider": provider,
        "status": "error",
        "http_status": status,
        "error": f"provider returned HTTP {status}",
    }


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _field_label(field: str) -> str:
    key = field.strip().lower()
    if key in FIELD_LABELS:
        return FIELD_LABELS[key]
    return key.replace("_", " ").strip().title() or "Other"


def _count_points(count: int, maximum: int = 20) -> int:
    if count <= 0:
        return 0
    if count < 10:
        return min(5, maximum)
    if count < 100:
        return min(10, maximum)
    if count < 1000:
        return min(15, maximum)
    return maximum


def _level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _usable(provider: dict) -> bool:
    return provider.get("status") in {"found", "not_found"}


def _provider(providers: list[dict], name: str) -> dict:
    return next((item for item in providers if item.get("provider") == name), {})


async def _leakcheck_public(identifier: str, refresh: bool = False) -> dict:
    """LeakCheck public API: aggregate counts, source names and field names only."""
    cache_key = f"leakcheck:public:{identifier.lower()}"
    if not refresh:
        cached = cache_get(cache_key, BREACH_TTL)
        if cached is not None:
            return {**cached, "cached": True}

    try:
        response = await request(
            LEAKCHECK_PUBLIC,
            params={"check": identifier},
            headers={"Accept": "application/json"},
            timeout=30.0,
        )
    except Exception as exc:
        return {
            "provider": "leakcheck_public",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if response.status_code != 200:
        return _http_status_result("leakcheck_public", response.status_code)

    try:
        data = response.json()
    except Exception as exc:
        return {
            "provider": "leakcheck_public",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if not isinstance(data, dict):
        return {
            "provider": "leakcheck_public",
            "status": "error",
            "error": "unexpected provider response",
            "configured": True,
        }

    if not data.get("success"):
        message = str(data.get("error") or "").strip()
        if "not found" in message.lower():
            result = {
                "provider": "leakcheck_public",
                "status": "not_found",
                "records_found": 0,
                "sources": [],
                "source_count": 0,
                "data_classes": [],
                "has_password": False,
                "has_ssn": False,
                "has_financial": False,
                "configured": True,
                "note": "LeakCheck public API returned no aggregate matches.",
            }
            cache_set(cache_key, result)
            return result
        result = {
            "provider": "leakcheck_public",
            "status": "error",
            "error": clip(message, 200) or "provider did not return success",
            "configured": True,
        }
        return result

    found = max(0, _as_int(data.get("found")))
    raw_sources = data.get("sources") if isinstance(data.get("sources"), list) else []
    raw_fields = data.get("fields") if isinstance(data.get("fields"), list) else []

    sources: list[dict] = []
    seen_sources: set[tuple[str, str]] = set()
    for item in raw_sources:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            date = str(item.get("date") or "").strip()
        elif isinstance(item, str):
            name, date = item.strip(), ""
        else:
            continue
        if not name:
            continue
        marker = (name.lower(), date)
        if marker in seen_sources:
            continue
        seen_sources.add(marker)
        sources.append({"name": clip(name, 160), "date": date[:32]})

    sources.sort(key=lambda item: (item.get("date") or "", item.get("name") or ""), reverse=True)
    source_count = len(sources)
    sources = sources[:50]

    fields = []
    for field in raw_fields:
        if isinstance(field, str) and field.strip():
            fields.append(field.strip().lower()[:80])
    fields = sorted(set(fields))

    data_classes = sorted({_field_label(field) for field in fields})
    has_password = any(field in {"password", "passwords", "passhash", "hash"} for field in fields)
    has_ssn = "ssn" in fields
    has_financial = any(
        field in {"bank", "bank_account", "credit_card", "cc", "iban", "account", "balance"}
        or "card" in field
        for field in fields
    )

    result = {
        "provider": "leakcheck_public",
        "status": "found" if found else "not_found",
        "records_found": found,
        "records_found_at_least_1000": found >= 1000,
        "source_count": source_count,
        "sources_returned": len(sources),
        "sources_truncated": source_count > len(sources),
        "sources": sources,
        "field_count": len(fields),
        "fields": fields[:40],
        "data_classes": data_classes[:40],
        "has_password": has_password,
        "has_ssn": has_ssn,
        "has_financial": has_financial,
        "configured": True,
        "note": (
            "LeakCheck public API returns aggregate metadata only (count, source names, "
            "field categories). It does not return the matching records or credentials."
        ),
    }
    cache_set(cache_key, result)
    return result


def _sanitize_path(path: Any) -> str:
    text = clip(str(path or ""), 300)
    text = re.sub(r"(?i)([A-Z]:\\Users\\)[^\\]+", r"\1<redacted>", text)
    text = re.sub(r"(?i)(/home/)[^/]+", r"\1<redacted>", text)
    text = re.sub(r"(?i)(/Users/)[^/]+", r"\1<redacted>", text)
    text = re.sub(r"(?i)([A-Z]:\\Documents and Settings\\)[^\\]+", r"\1<redacted>", text)
    return text


async def _hudson_rock(kind: str, identifier: str, refresh: bool = False) -> dict:
    """Hudson Rock Cavalier: infostealer infection metadata, no credentials/IPs."""
    if kind not in {"email", "username"}:
        return {
            "provider": "hudsonrock",
            "status": "skipped",
            "reason": "Hudson Rock lookup supports email or username only",
            "configured": True,
        }

    cache_key = f"hudsonrock:{kind}:{identifier.lower()}"
    if not refresh:
        cached = cache_get(cache_key, BREACH_TTL)
        if cached is not None:
            return {**cached, "cached": True}

    try:
        response = await request(
            f"{HUDSON_ROCK}/search-by-{kind}",
            params={kind: identifier},
            headers={"Accept": "application/json"},
            timeout=35.0,
        )
    except Exception as exc:
        return {
            "provider": "hudsonrock",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if response.status_code != 200:
        return _http_status_result("hudsonrock", response.status_code)

    try:
        data = response.json()
    except Exception as exc:
        return {
            "provider": "hudsonrock",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if not isinstance(data, dict):
        return {
            "provider": "hudsonrock",
            "status": "error",
            "error": "unexpected provider response",
            "configured": True,
        }

    raw_stealers = data.get("stealers") if isinstance(data.get("stealers"), list) else []
    stealers: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for item in raw_stealers:
        if not isinstance(item, dict):
            continue
        date = str(item.get("date_compromised") or "").strip()[:40]
        os_name = clip(str(item.get("operating_system") or ""), 120)
        malware_path = _sanitize_path(item.get("malware_path"))
        marker = (date, os_name.lower(), malware_path.lower())
        if marker in seen:
            continue
        seen.add(marker)

        passwords = item.get("top_passwords") if isinstance(item.get("top_passwords"), list) else []
        logins = item.get("top_logins") if isinstance(item.get("top_logins"), list) else []
        antiviruses = item.get("antiviruses") if isinstance(item.get("antiviruses"), list) else []
        antiviruses = [clip(str(value), 80) for value in antiviruses if str(value).strip()][:10]

        stealers.append(
            {
                "date_compromised": date,
                "operating_system": os_name,
                "malware_path": malware_path,
                "antiviruses": antiviruses,
                "credentials_present": bool(passwords or logins),
                "password_count": len(passwords),
                "login_count": len(logins),
            }
        )

    stealers.sort(key=lambda item: item.get("date_compromised") or "", reverse=True)
    infection_count = len(stealers)
    dates = [item.get("date_compromised") for item in stealers if item.get("date_compromised")]
    result = {
        "provider": "hudsonrock",
        "status": "found" if infection_count else "not_found",
        "infected": bool(infection_count),
        "infection_count": infection_count,
        "first_seen": min(dates) if dates else None,
        "last_seen": max(dates) if dates else None,
        "total_user_services": _as_int(data.get("total_user_services")),
        "total_corporate_services": _as_int(data.get("total_corporate_services")),
        "stealers_returned": min(len(stealers), 20),
        "stealers": stealers[:20],
        "configured": True,
        "note": (
            "Hudson Rock infostealer telemetry. Passwords, logins, IP addresses and "
            "device names are intentionally omitted. Test/shared addresses can produce "
            "false positives; verify before acting."
        ),
    }
    cache_set(cache_key, result)
    return result


async def _hibp_account(email: str) -> dict:
    key = _hibp_key()
    if not key:
        return {
            "provider": "hibp",
            "status": "skipped",
            "reason": "HIBP API key not configured",
            "configured": False,
        }

    try:
        response = await request(
            f"{HIBP_BASE}/breachedaccount/{quote(email, safe='')}",
            params={"truncateResponse": "false"},
            headers=_hibp_headers(),
            timeout=30.0,
        )
    except Exception as exc:
        return {
            "provider": "hibp",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if response.status_code == 404:
        return {
            "provider": "hibp",
            "status": "not_found",
            "breach_count": 0,
            "breaches": [],
            "has_password": False,
            "configured": True,
        }
    if response.status_code != 200:
        return _http_status_result("hibp", response.status_code)

    try:
        data = response.json()
    except Exception as exc:
        return {
            "provider": "hibp",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if not isinstance(data, list):
        return {
            "provider": "hibp",
            "status": "error",
            "error": "unexpected provider response",
            "configured": True,
        }

    breaches: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        data_classes = item.get("DataClasses") if isinstance(item.get("DataClasses"), list) else []
        data_classes = [clip(str(value), 100) for value in data_classes if str(value).strip()]
        breaches.append(
            {
                "name": clip(str(item.get("Name") or ""), 120),
                "title": clip(str(item.get("Title") or ""), 200),
                "domain": clip(str(item.get("Domain") or ""), 200),
                "breach_date": clip(str(item.get("BreachDate") or ""), 40),
                "added_date": clip(str(item.get("AddedDate") or ""), 60),
                "pwn_count": _as_int(item.get("PwnCount")),
                "data_classes": data_classes[:30],
                "is_verified": bool(item.get("IsVerified")),
                "is_sensitive": bool(item.get("IsSensitive")),
                "is_spam_list": bool(item.get("IsSpamList")),
                "is_stealer_log": bool(item.get("IsStealerLog")),
            }
        )

    breaches.sort(key=lambda item: (item.get("breach_date") or "", item.get("pwn_count") or 0), reverse=True)
    has_password = any(
        "password" in value.lower()
        for breach in breaches
        for value in breach.get("data_classes", [])
    )
    result = {
        "provider": "hibp",
        "status": "found" if breaches else "not_found",
        "breach_count": len(breaches),
        "breaches_returned": min(len(breaches), 100),
        "breaches_truncated": len(breaches) > 100,
        "breaches": breaches[:100],
        "has_password": has_password,
        "configured": True,
    }
    return result


async def _hibp_catalog(refresh: bool = False) -> tuple[list[dict] | None, dict | None]:
    cache_key = "hibp:breaches:catalog"
    if not refresh:
        cached = cache_get(cache_key, CATALOG_TTL)
        if cached is not None:
            return cached, None

    try:
        response = await request(
            f"{HIBP_BASE}/breaches",
            headers={"Accept": "application/json", "User-Agent": "osint-mcp/1.0"},
            timeout=45.0,
        )
    except Exception as exc:
        return None, {
            "status": "error",
            "error": _safe_error(exc),
        }

    if response.status_code != 200:
        return None, _http_status_result("hibp_catalog", response.status_code)

    try:
        data = response.json()
    except Exception as exc:
        return None, {
            "status": "error",
            "error": _safe_error(exc),
        }

    if not isinstance(data, list):
        return None, {"status": "error", "error": "unexpected catalogue response"}

    cache_set(cache_key, data)
    return data, None


def _catalog_item(item: dict) -> dict:
    description = str(item.get("Description") or "")
    description = re.sub(r"<[^>]+>", " ", description)
    description = html.unescape(re.sub(r"\s+", " ", description)).strip()
    data_classes = item.get("DataClasses") if isinstance(item.get("DataClasses"), list) else []
    return {
        "name": clip(str(item.get("Name") or ""), 120),
        "title": clip(str(item.get("Title") or ""), 200),
        "domain": clip(str(item.get("Domain") or ""), 200),
        "breach_date": clip(str(item.get("BreachDate") or ""), 40),
        "added_date": clip(str(item.get("AddedDate") or ""), 60),
        "pwn_count": _as_int(item.get("PwnCount")),
        "data_classes": [clip(str(value), 100) for value in data_classes if str(value).strip()][:30],
        "is_verified": bool(item.get("IsVerified")),
        "is_fabricated": bool(item.get("IsFabricated")),
        "is_sensitive": bool(item.get("IsSensitive")),
        "is_spam_list": bool(item.get("IsSpamList")),
        "is_stealer_log": bool(item.get("IsStealerLog")),
        "description": clip(description, 500),
    }


def _domain_matches(breach_domain: str, domain: str) -> bool:
    value = (breach_domain or "").strip().lower().rstrip(".")
    target = (domain or "").strip().lower().rstrip(".")
    return bool(value and target and (value == target or value.endswith("." + target)))


@guarded
async def breach_catalog(query: str = "", limit: int = 25, domain_only: bool = False) -> dict:
    """Search the public Have I Been Pwned breach catalogue by company, domain or keyword.

    Keyless and safe for general research: returns breach names, dates, record counts,
    data classes and descriptions. It does not look up an individual email address.
    Use `domain_only=True` to match only the breached site's domain. `limit` is capped
    at 100. Results are cached for 24 hours.
    """
    requested_limit = max(1, min(_as_int(limit, 25), 100))
    terms = [part for part in (query or "").strip().lower().split() if part]
    catalog, error = await _hibp_catalog()
    if error:
        return {
            "ok": False,
            "error": error.get("error", "could not load HIBP breach catalogue"),
            "http_status": error.get("http_status"),
            "source": "HIBP",
        }

    matches: list[dict] = []
    for raw in catalog or []:
        if not isinstance(raw, dict):
            continue
        item = _catalog_item(raw)
        if domain_only:
            haystack = item.get("domain", "").lower()
        else:
            haystack = " ".join(
                [
                    item.get("name", ""),
                    item.get("title", ""),
                    item.get("domain", ""),
                    " ".join(item.get("data_classes", [])),
                    item.get("description", ""),
                ]
            ).lower()
        if terms and not all(term in haystack for term in terms):
            continue
        matches.append(item)

    matches.sort(
        key=lambda item: (item.get("breach_date") or "", item.get("pwn_count") or 0),
        reverse=True,
    )
    total = len(matches)
    selected = matches[:requested_limit]
    return {
        "ok": True,
        "query": query or "",
        "domain_only": bool(domain_only),
        "catalog_total": len(catalog or []),
        "matches_total": total,
        "matches_returned": len(selected),
        "matches_truncated": total > len(selected),
        "sum_pwn_count": sum(item.get("pwn_count") or 0 for item in selected),
        "matches": selected,
        "source": "HIBP public breach catalogue",
        "source_url": "https://haveibeenpwned.com/PwnedWebsites",
        "cache_ttl_seconds": CATALOG_TTL,
        "note": "Public breach metadata only; no individual account lookup and no raw records.",
    }


@guarded
async def breach_check(
    identifier: str,
    kind: str = "auto",
    authorized: bool = False,
    refresh: bool = False,
) -> dict:
    """Check one email, domain or username for breach exposure across several providers.

    Aggregates LeakCheck public metadata, HIBP account breaches (only if an HIBP key
    is configured), Hudson Rock infostealer telemetry for email/username, and HIBP
    catalogue matches for domains. Returns counts, source names, dates, data classes
    and recommendations only. It never returns passwords, hashes, cookies or raw
    leaked records.

    `kind` is auto/email/domain/username. Auto treats an @ value as email, a dotted
    value as a domain, and everything else as a username. Personal identifiers require
    `authorized=True`: the caller attests they own the identifier or have permission
    to assess it. LeakCheck/Hudson Rock are keyless; HIBP account search needs a key.
    """
    if not authorized:
        return {
            "ok": False,
            "error": "authorization required",
            "authorized": False,
            "hint": (
                "Only check an email, username or domain that you own or are explicitly "
                "authorized to assess. Re-run with authorized=True after confirming."
            ),
            "policy": "Defensive exposure assessment only; no raw leaked records are accessed.",
        }

    parsed_kind, parsed = _parse_identifier(identifier, kind)
    if parsed_kind is None:
        return parsed  # type: ignore[return-value]

    cache_key = f"breach:check:{parsed_kind}:{parsed.lower()}"
    if not refresh:
        cached = cache_get(cache_key, BREACH_TTL)
        if cached is not None:
            return {**cached, "cached": True}

    tasks: list[Any] = [_leakcheck_public(parsed, refresh)]
    if parsed_kind == "email":
        tasks.append(_hibp_account(parsed))
        tasks.append(_hudson_rock("email", parsed, refresh))
    elif parsed_kind == "username":
        tasks.append(_hudson_rock("username", parsed, refresh))
    else:
        tasks.append(_hibp_catalog(refresh))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    providers: list[dict] = []
    catalog_error: dict | None = None

    for item in gathered:
        if isinstance(item, BaseException):
            providers.append(
                {
                    "provider": "unknown",
                    "status": "error",
                    "error": _safe_error(item),
                }
            )
            continue
        if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], (list, type(None))):
            catalog, catalog_error = item
            if catalog_error:
                providers.append(
                    {
                        "provider": "hibp_catalog",
                        "status": catalog_error.get("status", "error"),
                        "http_status": catalog_error.get("http_status"),
                        "error": catalog_error.get("error", "catalogue unavailable"),
                    }
                )
            else:
                matches = [
                    _catalog_item(breach)
                    for breach in (catalog or [])
                    if isinstance(breach, dict)
                    and _domain_matches(str(breach.get("Domain") or ""), parsed)
                ]
                providers.append(
                    {
                        "provider": "hibp_catalog",
                        "status": "found" if matches else "not_found",
                        "match_count": len(matches),
                        "sum_pwn_count": sum(_as_int(item.get("pwn_count")) for item in matches),
                        "matches": matches[:20],
                        "matches_truncated": len(matches) > 20,
                        "configured": True,
                        "note": "Exact domain matches in the public HIBP catalogue.",
                    }
                )
        elif isinstance(item, dict):
            providers.append(item)

    if parsed_kind == "domain":
        key = _hibp_key()
        if key:
            providers.append(await _hibp_domain_aggregate(parsed))
        else:
            providers.append(
                {
                    "provider": "hibp_domain",
                    "status": "skipped",
                    "reason": "HIBP API key not configured",
                    "configured": False,
                }
            )

    leakcheck = _provider(providers, "leakcheck_public")
    hibp = _provider(providers, "hibp")
    hudson = _provider(providers, "hudsonrock")
    catalog_match = _provider(providers, "hibp_catalog")
    hibp_domain = _provider(providers, "hibp_domain")

    score = 0
    signals: list[str] = []

    if leakcheck.get("status") == "found":
        found = _as_int(leakcheck.get("records_found"))
        score += 10 + _count_points(found)
        signals.append(f"LeakCheck: {found} aggregate record(s) matched")
        if leakcheck.get("has_password"):
            score += 15
            signals.append("LeakCheck: password-field exposure indicated")
        if leakcheck.get("has_ssn"):
            score += 10
            signals.append("LeakCheck: SSN-field exposure indicated")
        if leakcheck.get("has_financial"):
            score += 5
            signals.append("LeakCheck: financial-field exposure indicated")

    if hibp.get("status") == "found":
        count = _as_int(hibp.get("breach_count"))
        score += 15 + _count_points(count)
        signals.append(f"HIBP: {count} breach(es) for this email")
        if hibp.get("has_password"):
            score += 15
            signals.append("HIBP: at least one breach exposed passwords")

    if hudson.get("status") == "found":
        count = _as_int(hudson.get("infection_count"))
        score += 40 + min(20, count * 5)
        signals.append(f"Hudson Rock: {count} infostealer infection(s)")
        if hudson.get("first_seen"):
            signals.append(f"Infostealer first seen: {hudson.get('first_seen')}")

    if catalog_match.get("status") == "found":
        count = _as_int(catalog_match.get("match_count"))
        catalog_pwn = _as_int(catalog_match.get("sum_pwn_count"))
        score += min(25, 5 + count * 3 + (10 if catalog_pwn >= 1_000_000 else 0))
        signals.append(f"HIBP catalogue: {count} breach(es) against this domain")

    if hibp_domain.get("status") == "found":
        aliases = _as_int(hibp_domain.get("breached_aliases"))
        score += 20 + _count_points(aliases)
        signals.append(f"HIBP domain: {aliases} breached email alias(es)")

    score = min(100, score)
    usable = sum(1 for provider in providers if _usable(provider))
    skipped = sum(1 for provider in providers if provider.get("status") == "skipped")
    unverified = sum(1 for provider in providers if provider.get("status") == "domain_not_verified")
    errors = sum(1 for provider in providers if provider.get("status") in {"error", "rate_limited"})
    found_any = any(provider.get("status") == "found" for provider in providers)

    if usable == 0:
        exposure_level = "unknown"
        exposure_score: int | None = None
        signals = ["No provider returned usable data."]
    elif not found_any:
        exposure_level = "none"
        exposure_score = 0
        signals = ["No exposure found in the providers that answered."]
    else:
        exposure_level = _level(score)
        exposure_score = score

    if parsed_kind == "email":
        masked = _mask_email(parsed)
    elif parsed_kind == "username":
        masked = _mask_handle(parsed)
    else:
        masked = parsed

    coverage_note = None
    if skipped:
        coverage_note = (
            f"{skipped} provider(s) skipped. Configure an HIBP key for email breach and "
            "verified-domain coverage; LeakCheck and Hudson Rock are keyless."
        )
    if unverified:
        coverage_note = (
            (coverage_note + " ") if coverage_note else ""
        ) + (
            f"{unverified} HIBP domain provider(s) need the domain verified in the HIBP "
            "dashboard before they can return alias-level data."
        )
    if errors:
        coverage_note = (
            (coverage_note + " ") if coverage_note else ""
        ) + f"{errors} provider(s) failed or were rate-limited; treat the result as partial."

    recommendations = [
        "Change any reused password from a clean device and use a password manager.",
        "Enable MFA on the affected account(s), especially email and financial services.",
        "Review active sessions and revoke unknown devices.",
        "Verify every finding against the original source; aggregates can be stale or wrong.",
    ]
    if hudson.get("status") == "found":
        recommendations.insert(
            0,
            "Treat browser-saved credentials on the infected device as compromised; "
            "rotate them from a clean device and run a malware scan.",
        )
    if parsed_kind == "domain":
        recommendations.insert(
            0,
            "Prioritize accounts with password/stealer exposure, force resets, and "
            "review MFA coverage for the domain.",
        )

    result = {
        "ok": True,
        "identifier_masked": masked,
        "identifier_type": parsed_kind,
        "authorized": True,
        "authorization_note": "Caller attested ownership or explicit authorization.",
        "exposure_level": exposure_level,
        "exposure_score": exposure_score,
        "signals": signals,
        "providers": providers,
        "coverage": {
            "usable": usable,
            "skipped": skipped,
            "unverified": unverified,
            "errors": errors,
            "note": coverage_note,
        },
        "recommendations": recommendations,
        "metadata_only": True,
        "raw_records_returned": False,
        "disclaimer": (
            "Only breach/infection metadata is returned. No passwords, hashes, cookies, "
            "or raw leaked records are downloaded or displayed. Third-party aggregates "
            "may be stale or produce false positives; verify against the source."
        ),
        "source_links": [
            "https://haveibeenpwned.com/PwnedWebsites",
            "https://leakcheck.io/",
            "https://www.hudsonrock.com/free-tools",
        ],
        "cache_ttl_seconds": BREACH_TTL,
        "cached": False,
    }
    if usable:
        cache_set(cache_key, result)
    return result


async def _hibp_domain_aggregate(domain: str) -> dict:
    key = _hibp_key()
    if not key:
        return {
            "provider": "hibp_domain",
            "status": "skipped",
            "reason": "HIBP API key not configured",
            "configured": False,
        }
    try:
        response = await request(
            f"{HIBP_BASE}/breacheddomain/{quote(domain, safe='')}",
            headers=_hibp_headers(),
            timeout=35.0,
        )
    except Exception as exc:
        return {
            "provider": "hibp_domain",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if response.status_code == 404:
        return {
            "provider": "hibp_domain",
            "status": "not_found",
            "breached_aliases": 0,
            "breaches": [],
            "configured": True,
        }
    if response.status_code != 200:
        result = _http_status_result("hibp_domain", response.status_code)
        result["configured"] = True
        return result

    try:
        data = response.json()
    except Exception as exc:
        return {
            "provider": "hibp_domain",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if not isinstance(data, dict):
        return {
            "provider": "hibp_domain",
            "status": "error",
            "error": "unexpected provider response",
            "configured": True,
        }

    breach_names: set[str] = set()
    for value in data.values():
        if isinstance(value, list):
            for name in value:
                if str(name).strip():
                    breach_names.add(clip(str(name), 120))
    return {
        "provider": "hibp_domain",
        "status": "found" if data else "not_found",
        "breached_aliases": len(data),
        "breach_count": len(breach_names),
        "breaches": sorted(breach_names)[:100],
        "configured": True,
        "note": "Aliases are counted but not returned; HIBP requires a verified domain.",
    }


async def _hibp_stealer_by_email(email: str) -> dict:
    key = _hibp_key()
    if not key:
        return {
            "provider": "hibp_stealer_logs",
            "status": "skipped",
            "reason": "HIBP API key not configured",
            "configured": False,
        }
    try:
        response = await request(
            f"{HIBP_BASE}/stealerLogsByEmail/{quote(email, safe='')}",
            headers=_hibp_headers(),
            timeout=35.0,
        )
    except Exception as exc:
        return {
            "provider": "hibp_stealer_logs",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if response.status_code == 404:
        return {
            "provider": "hibp_stealer_logs",
            "status": "not_found",
            "website_domains": [],
            "domain_count": 0,
            "configured": True,
        }
    if response.status_code != 200:
        result = _http_status_result("hibp_stealer_logs", response.status_code)
        result["configured"] = True
        return result

    try:
        data = response.json()
    except Exception as exc:
        return {
            "provider": "hibp_stealer_logs",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    domains = []
    if isinstance(data, list):
        domains = [clip(str(value), 200) for value in data if str(value).strip()]
    return {
        "provider": "hibp_stealer_logs",
        "status": "found" if domains else "not_found",
        "domain_count": len(domains),
        "website_domains": sorted(set(domains))[:100],
        "configured": True,
        "note": (
            "HIBP returns the website domains where the email appeared in stealer logs, "
            "not the passwords. The email domain must be verified in HIBP."
        ),
    }


async def _hibp_stealer_domain_aggregate(domain: str) -> dict:
    key = _hibp_key()
    if not key:
        return {
            "provider": "hibp_stealer_domain",
            "status": "skipped",
            "reason": "HIBP API key not configured",
            "configured": False,
        }
    try:
        response = await request(
            f"{HIBP_BASE}/stealerLogsByEmailDomain/{quote(domain, safe='')}",
            headers=_hibp_headers(),
            timeout=40.0,
        )
    except Exception as exc:
        return {
            "provider": "hibp_stealer_domain",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if response.status_code == 404:
        return {
            "provider": "hibp_stealer_domain",
            "status": "not_found",
            "exposed_aliases": 0,
            "website_domains": [],
            "configured": True,
        }
    if response.status_code != 200:
        result = _http_status_result("hibp_stealer_domain", response.status_code)
        result["configured"] = True
        return result

    try:
        data = response.json()
    except Exception as exc:
        return {
            "provider": "hibp_stealer_domain",
            "status": "error",
            "error": _safe_error(exc),
            "configured": True,
        }

    if not isinstance(data, dict):
        return {
            "provider": "hibp_stealer_domain",
            "status": "error",
            "error": "unexpected provider response",
            "configured": True,
        }

    website_counts: dict[str, int] = {}
    for websites in data.values():
        if isinstance(websites, list):
            for website in websites:
                value = str(website).strip()
                if value:
                    website_counts[value] = website_counts.get(value, 0) + 1
    ordered = sorted(website_counts.items(), key=lambda item: item[1], reverse=True)
    return {
        "provider": "hibp_stealer_domain",
        "status": "found" if data else "not_found",
        "exposed_aliases": len(data),
        "website_domain_count": len(website_counts),
        "website_domains": [
            {"domain": clip(name, 200), "aliases": count} for name, count in ordered[:100]
        ],
        "configured": True,
        "note": "Aliases are counted but not returned; HIBP requires a verified domain.",
    }


@guarded
async def stealer_log_check(
    identifier: str,
    kind: str = "auto",
    authorized: bool = False,
    refresh: bool = False,
) -> dict:
    """Focused infostealer check for one email or username.

    Uses Hudson Rock Cavalier and, when an HIBP key is configured, HIBP stealer logs
    (email only). Returns infection dates, operating system, sanitized malware path,
    website-domain exposure and counts. Passwords, logins, IPs and device names are
    never returned. Use `domain_breach_exposure` for a whole domain. Requires
    `authorized=True`.
    """
    if not authorized:
        return {
            "ok": False,
            "error": "authorization required",
            "authorized": False,
            "hint": "Only check an email or username you own or are authorized to assess.",
            "policy": "Defensive exposure assessment only; no raw stealer logs are accessed.",
        }

    parsed_kind, parsed = _parse_identifier(identifier, kind)
    if parsed_kind is None:
        return parsed  # type: ignore[return-value]
    if parsed_kind == "domain":
        return {
            "ok": False,
            "error": "stealer_log_check is for an email or username; use domain_breach_exposure for a domain",
        }

    cache_key = f"breach:stealer:{parsed_kind}:{parsed.lower()}"
    if not refresh:
        cached = cache_get(cache_key, BREACH_TTL)
        if cached is not None:
            return {**cached, "cached": True}

    if parsed_kind == "email":
        providers = list(
            await asyncio.gather(
                _hudson_rock(parsed_kind, parsed, refresh),
                _hibp_stealer_by_email(parsed),
            )
        )
    else:
        providers = [
            await _hudson_rock(parsed_kind, parsed, refresh),
            {
                "provider": "hibp_stealer_logs",
                "status": "skipped",
                "reason": "HIBP stealer-log API supports email addresses, not usernames",
                "configured": bool(_hibp_key()),
            },
        ]

    hudson = _provider(providers, "hudsonrock")
    hibp = _provider(providers, "hibp_stealer_logs")

    infected = hudson.get("status") == "found" or hibp.get("status") == "found"
    website_domains = hibp.get("website_domains") if hibp.get("status") == "found" else []
    exposure_level = "critical" if infected else "none"
    errors = sum(1 for provider in providers if provider.get("status") in {"error", "rate_limited"})
    skipped = sum(1 for provider in providers if provider.get("status") == "skipped")
    unverified = sum(1 for provider in providers if provider.get("status") == "domain_not_verified")
    if not infected and errors:
        exposure_level = "unknown"

    coverage_note = None
    if skipped:
        coverage_note = (
            "HIBP stealer-log coverage is partial without a Pro+ HIBP key and a verified "
            "email domain; Hudson Rock still answered."
        )
    if unverified:
        coverage_note = (
            (coverage_note + " ") if coverage_note else ""
        ) + "HIBP needs the email domain verified before returning stealer-log websites."
    if errors:
        coverage_note = (
            (coverage_note + " ") if coverage_note else ""
        ) + f"{errors} provider(s) failed or were rate-limited."

    masked = _mask_email(parsed) if parsed_kind == "email" else _mask_handle(parsed)
    result = {
        "ok": True,
        "identifier_masked": masked,
        "identifier_type": parsed_kind,
        "authorized": True,
        "infected": infected,
        "exposure_level": exposure_level,
        "hudsonrock": hudson,
        "hibp_stealer_logs": hibp,
        "exposed_website_domains": website_domains,
        "providers": providers,
        "coverage": {
            "skipped": skipped,
            "unverified": unverified,
            "errors": errors,
            "note": coverage_note,
        },
        "recommendations": [
            "Rotate credentials for every account used on the affected device from a clean device.",
            "Enable MFA, revoke active sessions, and check email/cloud/bank accounts first.",
            "Run a full malware scan and rebuild the device if the infection is confirmed.",
            "Verify the finding against the provider; shared/test addresses can produce false positives.",
        ],
        "metadata_only": True,
        "raw_records_returned": False,
        "disclaimer": (
            "Infostealer metadata only. No passwords, logins, cookies, IP addresses or "
            "raw stealer logs are returned. Verify before acting."
        ),
        "source_links": [
            "https://www.hudsonrock.com/free-tools",
            "https://haveibeenpwned.com/StealerLogs",
        ],
        "cache_ttl_seconds": BREACH_TTL,
        "cached": False,
    }
    if hudson.get("status") in {"found", "not_found"} or hibp.get("status") in {"found", "not_found"}:
        cache_set(cache_key, result)
    return result


@guarded
async def domain_breach_exposure(
    domain: str,
    authorized: bool = False,
    refresh: bool = False,
) -> dict:
    """Assess a whole domain's breach exposure without returning employee emails.

    Combines LeakCheck public aggregate metadata, exact matches in the public HIBP
    breach catalogue, and (when an HIBP key is configured and the domain is verified)
    HIBP's breached-domain and stealer-log-by-email-domain aggregates. Returns counts,
    breach names, data classes and affected website domains only; aliases/addresses
    are never returned. Requires `authorized=True`.
    """
    if not authorized:
        return {
            "ok": False,
            "error": "authorization required",
            "authorized": False,
            "hint": "Only assess a domain you own or are explicitly authorized to test.",
            "policy": "Defensive exposure assessment only; no raw leaked records are accessed.",
        }

    parsed_kind, parsed = _parse_identifier(domain, "domain")
    if parsed_kind is None:
        return parsed  # type: ignore[return-value]

    cache_key = f"breach:domain:{parsed}"
    if not refresh:
        cached = cache_get(cache_key, BREACH_TTL)
        if cached is not None:
            return {**cached, "cached": True}

    providers: list[dict] = []
    leakcheck, catalog_result = await asyncio.gather(
        _leakcheck_public(parsed, refresh),
        _hibp_catalog(refresh),
    )
    providers.append(leakcheck)

    catalog, catalog_error = catalog_result
    if catalog_error:
        providers.append(
            {
                "provider": "hibp_catalog",
                "status": catalog_error.get("status", "error"),
                "http_status": catalog_error.get("http_status"),
                "error": catalog_error.get("error", "catalogue unavailable"),
            }
        )
    else:
        matches = [
            _catalog_item(breach)
            for breach in (catalog or [])
            if isinstance(breach, dict)
            and _domain_matches(str(breach.get("Domain") or ""), parsed)
        ]
        providers.append(
            {
                "provider": "hibp_catalog",
                "status": "found" if matches else "not_found",
                "match_count": len(matches),
                "sum_pwn_count": sum(_as_int(item.get("pwn_count")) for item in matches),
                "matches_returned": min(len(matches), 25),
                "matches_truncated": len(matches) > 25,
                "matches": matches[:25],
                "configured": True,
                "note": "Exact domain matches in the public HIBP catalogue.",
            }
        )

    if _hibp_key():
        hibp_domain, hibp_stealer = await asyncio.gather(
            _hibp_domain_aggregate(parsed),
            _hibp_stealer_domain_aggregate(parsed),
        )
        providers.extend([hibp_domain, hibp_stealer])
    else:
        providers.extend(
            [
                {
                    "provider": "hibp_domain",
                    "status": "skipped",
                    "reason": "HIBP API key not configured",
                    "configured": False,
                },
                {
                    "provider": "hibp_stealer_domain",
                    "status": "skipped",
                    "reason": "HIBP API key not configured",
                    "configured": False,
                },
            ]
        )

    leakcheck_p = _provider(providers, "leakcheck_public")
    catalog_p = _provider(providers, "hibp_catalog")
    hibp_domain = _provider(providers, "hibp_domain")
    hibp_stealer = _provider(providers, "hibp_stealer_domain")

    score = 0
    signals: list[str] = []
    if leakcheck_p.get("status") == "found":
        found = _as_int(leakcheck_p.get("records_found"))
        score += 10 + _count_points(found)
        signals.append(f"LeakCheck: {found} aggregate record(s) matched")
        if leakcheck_p.get("has_password"):
            score += 15
            signals.append("LeakCheck: password-field exposure indicated")
        if leakcheck_p.get("has_ssn"):
            score += 10
            signals.append("LeakCheck: SSN-field exposure indicated")
    if catalog_p.get("status") == "found":
        count = _as_int(catalog_p.get("match_count"))
        catalog_pwn = _as_int(catalog_p.get("sum_pwn_count"))
        score += min(30, 5 + count * 3 + (10 if catalog_pwn >= 1_000_000 else 0))
        signals.append(f"HIBP catalogue: {count} breach(es) against the domain")
    if hibp_domain.get("status") == "found":
        aliases = _as_int(hibp_domain.get("breached_aliases"))
        score += 20 + _count_points(aliases)
        signals.append(f"HIBP domain: {aliases} breached alias(es)")
    if hibp_stealer.get("status") == "found":
        aliases = _as_int(hibp_stealer.get("exposed_aliases"))
        score += 35 + min(20, aliases)
        signals.append(f"HIBP stealer logs: {aliases} exposed alias(es)")
    score = min(100, score)

    found_any = any(provider.get("status") == "found" for provider in providers)
    usable = sum(1 for provider in providers if _usable(provider))
    skipped = sum(1 for provider in providers if provider.get("status") == "skipped")
    unverified = sum(1 for provider in providers if provider.get("status") == "domain_not_verified")
    errors = sum(1 for provider in providers if provider.get("status") in {"error", "rate_limited"})
    if usable == 0:
        exposure_level = "unknown"
        exposure_score: int | None = None
        signals = ["No provider returned usable data."]
    elif not found_any:
        exposure_level = "none"
        exposure_score = 0
        signals = ["No domain exposure found in the providers that answered."]
    else:
        exposure_level = _level(score)
        exposure_score = score

    coverage_note = None
    if skipped:
        coverage_note = (
            "HIBP verified-domain/stealer coverage is skipped; configure an HIBP key "
            "and verify the domain for alias-level aggregates."
        )
    if unverified:
        coverage_note = (
            (coverage_note + " ") if coverage_note else ""
        ) + "The domain is not verified in the HIBP dashboard, so HIBP domain data is unavailable."
    if errors:
        coverage_note = (
            (coverage_note + " ") if coverage_note else ""
        ) + f"{errors} provider(s) failed or were rate-limited; treat the result as partial."

    result = {
        "ok": True,
        "domain": parsed,
        "authorized": True,
        "authorization_note": "Caller attested ownership or explicit authorization.",
        "exposure_level": exposure_level,
        "exposure_score": exposure_score,
        "signals": signals,
        "providers": providers,
        "coverage": {
            "usable": usable,
            "skipped": skipped,
            "unverified": unverified,
            "errors": errors,
            "note": coverage_note,
        },
        "recommendations": [
            "Prioritize aliases with password/stealer exposure and force resets.",
            "Review MFA coverage for the domain and enforce it on email/cloud/finance.",
            "Check HIBP verified-domain and stealer-log access for per-alias detail.",
            "Notify affected users according to your incident-response policy.",
            "Verify findings against the source; aggregates can be stale or incomplete.",
        ],
        "metadata_only": True,
        "raw_records_returned": False,
        "aliases_returned": False,
        "disclaimer": (
            "Aggregate domain exposure only. No employee email addresses, passwords, "
            "hashes or raw leaked records are returned. HIBP domain/stealer endpoints "
            "require a paid key and a verified domain."
        ),
        "source_links": [
            "https://haveibeenpwned.com/PwnedWebsites",
            "https://leakcheck.io/",
            "https://www.hudsonrock.com/free-tools",
        ],
        "cache_ttl_seconds": BREACH_TTL,
        "cached": False,
    }
    if usable:
        cache_set(cache_key, result)
    return result


@guarded
async def breach_providers() -> dict:
    """Show which breach/leaked-data providers are available, without exposing keys.

    Reports booleans only: HIBP key present/format-valid, LeakCheck public keyless
    availability, Hudson Rock keyless availability, and what each provider can search.
    Never returns a key or any part of a key.
    """
    key = _hibp_key()
    key_source = _hibp_key_source()
    key_format_ok = bool(re.fullmatch(r"[0-9a-fA-F]{32}", key or ""))
    return {
        "ok": True,
        "providers": [
            {
                "name": "hibp_catalog",
                "capabilities": ["breach catalogue", "breach metadata"],
                "requires_key": False,
                "configured": True,
                "status": "ready",
                "note": "Keyless public catalogue; cached for 24 hours.",
            },
            {
                "name": "leakcheck_public",
                "capabilities": ["email", "username", "domain", "aggregate metadata"],
                "requires_key": False,
                "configured": True,
                "status": "ready",
                "note": "Keyless aggregate counts/sources/field names only; no raw records.",
            },
            {
                "name": "hudsonrock",
                "capabilities": ["email", "username", "infostealer infections"],
                "requires_key": False,
                "configured": True,
                "status": "ready",
                "note": "Keyless infostealer telemetry; no passwords/logins/IPs returned.",
            },
            {
                "name": "hibp_account",
                "capabilities": ["email breach list"],
                "requires_key": True,
                "configured": bool(key),
                "key_format_valid": key_format_ok,
                "key_source": key_source,
                "status": "ready" if key else "key_missing",
                "note": "Needs a 32-hex HIBP API key in HIBP_API_KEY or keys.json as hibp.",
            },
            {
                "name": "hibp_domain",
                "capabilities": ["breached aliases", "domain aggregate"],
                "requires_key": True,
                "configured": bool(key),
                "key_format_valid": key_format_ok,
                "key_source": key_source,
                "status": "ready" if key else "key_missing",
                "note": "Also requires the domain to be verified in the HIBP dashboard.",
            },
            {
                "name": "hibp_stealer_logs",
                "capabilities": ["email stealer logs", "domain stealer aggregates"],
                "requires_key": True,
                "configured": bool(key),
                "key_format_valid": key_format_ok,
                "key_source": key_source,
                "status": "ready" if key else "key_missing",
                "note": "Pro+ HIBP plan and verified domain required.",
            },
        ],
        "authorization_required_for_personal_lookup": True,
        "raw_records_returned": False,
        "policy": (
            "Defensive exposure assessment only. Tools return counts, source names, "
            "dates and data classes; they never return passwords, hashes, cookies or "
            "raw leaked records."
        ),
        "key_exposure": "Only booleans and source labels are returned; no key material is shown.",
    }
