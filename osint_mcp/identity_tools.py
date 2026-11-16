"""Identity tools: username enumeration across platforms and email intelligence."""

from __future__ import annotations

import asyncio
import hashlib
import re

from .common import api_key, guarded, request
from .dns_tools import dns_lookup

SITES: dict[str, dict] = {
    "github": {"url": "https://github.com/{u}", "type": "status"},
    "gitlab": {"url": "https://gitlab.com/{u}", "type": "status"},
    "bitbucket": {"url": "https://bitbucket.org/{u}/", "type": "status"},
    "codeberg": {"url": "https://codeberg.org/{u}", "type": "status"},
    "pypi": {"url": "https://pypi.org/user/{u}/", "type": "status"},
    "npm": {"url": "https://www.npmjs.com/~{u}", "type": "status"},
    "dockerhub": {"url": "https://hub.docker.com/u/{u}", "type": "status"},
    "hackerone": {"url": "https://hackerone.com/{u}", "type": "status"},
    "bugcrowd": {"url": "https://bugcrowd.com/{u}", "type": "status"},
    "keybase": {"url": "https://keybase.io/{u}", "type": "status"},
    "reddit": {"url": "https://www.reddit.com/user/{u}/about.json", "type": "status"},
    "medium": {"url": "https://medium.com/@{u}", "type": "status"},
    "devto": {"url": "https://dev.to/{u}", "type": "status"},
    "kaggle": {"url": "https://www.kaggle.com/{u}", "type": "status"},
    "soundcloud": {"url": "https://soundcloud.com/{u}", "type": "status"},
    "behance": {"url": "https://www.behance.net/{u}", "type": "status"},
    "dribbble": {"url": "https://dribbble.com/{u}", "type": "status"},
    "letterboxd": {"url": "https://letterboxd.com/{u}/", "type": "status"},
    "aboutme": {"url": "https://about.me/{u}", "type": "status"},
    "linktree": {"url": "https://linktr.ee/{u}", "type": "status"},
    "pastebin": {"url": "https://pastebin.com/u/{u}", "type": "status"},
    "hackerrank": {"url": "https://www.hackerrank.com/{u}", "type": "status"},
    "tryhackme": {"url": "https://tryhackme.com/p/{u}", "type": "status"},
    "hackernews": {"url": "https://news.ycombinator.com/user?id={u}", "type": "absent", "marker": "No such user."},
    "telegram": {"url": "https://t.me/{u}", "type": "present", "marker": "tgme_page_title"},
    "steam": {
        "url": "https://steamcommunity.com/id/{u}",
        "type": "absent",
        "marker": "The specified profile could not be found",
    },
}


@guarded
async def username_search(username: str, sites: str = "", timeout: float = 12.0) -> dict:
    """Check whether a username exists on ~25 platforms (GitHub, GitLab, Reddit, Telegram...).

    `sites` optionally limits checks to comma-separated keys. Results distinguish
    found / not found / blocked, so Cloudflare 403s are not reported as absence.
    """
    handle = (username or "").strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", handle):
        return {"ok": False, "error": "invalid username (allowed: letters, digits, . _ -)"}

    selected = SITES
    if sites:
        keys = [item.strip().lower() for item in sites.split(",") if item.strip()]
        unknown = [key for key in keys if key not in SITES]
        if unknown:
            return {"ok": False, "error": f"unknown sites: {unknown}", "available": sorted(SITES)}
        selected = {key: SITES[key] for key in keys}

    sem = asyncio.Semaphore(12)
    found: list[dict] = []
    not_found: list[str] = []
    blocked: list[dict] = []

    async def check(name: str, config: dict) -> None:
        url = config["url"].format(u=handle)
        async with sem:
            try:
                response = await request(
                    url,
                    timeout=timeout,
                    headers={"Accept": "text/html,application/json;q=0.9,*/*;q=0.8"},
                    follow_redirects=True,
                )
            except Exception as exc:
                blocked.append({"site": name, "reason": f"{type(exc).__name__}"})
                return

        status = response.status_code
        body = response.text or ""
        if status in (403, 429, 503) or ("cloudflare" in body.lower()[:2000] and status != 200):
            blocked.append({"site": name, "status": status, "reason": "blocked/challenge"})
            return

        kind = config["type"]
        marker = config.get("marker", "")
        if kind == "status":
            if status == 200:
                found.append({"site": name, "url": url, "status": status})
            elif status == 404:
                not_found.append(name)
            else:
                blocked.append({"site": name, "status": status, "reason": "ambiguous"})
        elif kind == "absent":
            if status == 200 and marker.lower() not in body.lower():
                found.append({"site": name, "url": url, "status": status})
            elif status == 200 or status == 404:
                not_found.append(name)
            else:
                blocked.append({"site": name, "status": status, "reason": "ambiguous"})
        elif kind == "present":
            if status == 200 and marker.lower() in body.lower():
                found.append({"site": name, "url": url, "status": status})
            elif status == 200:
                not_found.append(name)
            else:
                blocked.append({"site": name, "status": status, "reason": "ambiguous"})

    await asyncio.gather(*(check(name, config) for name, config in selected.items()))
    found.sort(key=lambda item: item["site"])
    return {
        "ok": True,
        "username": handle,
        "checked": len(selected),
        "found_count": len(found),
        "found": found,
        "not_found": sorted(not_found),
        "blocked": blocked,
        "note": "A 200 does not always prove ownership; verify profile content.",
    }


DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
    "yopmail.com", "sharklasers.com", "trashmail.com", "dispostable.com", "maildrop.cc",
    "getnada.com", "mailnesia.com", "spamgourmet.com", "throwawaymail.com", "fakeinbox.com",
    "mytemp.email", "burnermail.io", "mohmal.com", "emailondeck.com", "mailcatch.com",
    "tempr.email", "discard.email", "spam4.me", "grr.la", "guerrillamailblock.com",
    "guerrillamail.net", "guerrillamail.org", "pokemail.net", "spam.la", "tempail.com",
}

ROLE_PREFIXES = {
    "admin", "administrator", "info", "support", "sales", "contact", "hello", "team",
    "billing", "security", "abuse", "postmaster", "webmaster", "noreply", "no-reply",
    "hr", "jobs", "careers", "marketing", "press", "legal", "privacy", "help",
}

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


async def _txt(domain: str, record_type: str = "TXT") -> list[str]:
    result = await dns_lookup(domain, record_type)
    if not result.get("ok"):
        return []
    values = result.get("records", {}).get("TXT", [])
    return [value for value in values if isinstance(value, str)]


@guarded
async def email_intel(email: str) -> dict:
    """Profile an email: syntax, MX/SPF/DMARC, disposable check, Gravatar, breaches.

    Breach data appears only if an HIBP key is set in HIBP_API_KEY or the local key
    store as `hibp`. Gravatar existence is checked with the privacy-preserving 404
    endpoint. For a richer leaked-data exposure report use breach_check.
    """
    address = (email or "").strip().lower()
    if not EMAIL_RE.fullmatch(address):
        return {"ok": False, "error": "invalid email address"}

    local, domain = address.rsplit("@", 1)
    gravatar_hash = hashlib.md5(address.encode()).hexdigest()

    mx_task = dns_lookup(domain, "MX")
    spf_task = _txt(domain, "TXT")
    dmarc_task = _txt(f"_dmarc.{domain}", "TXT")
    mx, spf_records, dmarc_records = await asyncio.gather(mx_task, spf_task, dmarc_task)

    mx_hosts = []
    for item in (mx.get("records", {}).get("MX", []) if isinstance(mx, dict) else []):
        if isinstance(item, dict):
            mx_hosts.append(item.get("exchange"))
        elif isinstance(item, str):
            mx_hosts.append(item)

    spf = next((record for record in spf_records if record.lower().startswith("v=spf1")), None)
    dmarc = next((record for record in dmarc_records if record.lower().startswith("v=dmarc1")), None)

    gravatar = False
    try:
        gravatar_response = await request(
            f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404&s=1", timeout=15.0
        )
        gravatar = gravatar_response.status_code == 200
    except Exception:
        gravatar = False

    breaches = None
    hibp_key = api_key("hibp", "haveibeenpwned")
    if hibp_key:
        try:
            breach_response = await request(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{address}?truncateResponse=false",
                headers={"hibp-api-key": hibp_key, "User-Agent": "osint-mcp"},
                timeout=25.0,
            )
            if breach_response.status_code == 200:
                breaches = [
                    {
                        "name": item.get("Name"),
                        "title": item.get("Title"),
                        "date": item.get("BreachDate"),
                        "data_classes": item.get("DataClasses"),
                    }
                    for item in breach_response.json()
                ]
            elif breach_response.status_code == 404:
                breaches = []
        except Exception:
            breaches = None

    return {
        "ok": True,
        "email": address,
        "local_part": local,
        "domain": domain,
        "role_account": local.split("+")[0] in ROLE_PREFIXES,
        "plus_addressing": "+" in local,
        "disposable": domain in DISPOSABLE_DOMAINS,
        "mx": mx_hosts,
        "null_mx": mx_hosts == ["."],
        "accepts_email": bool(mx_hosts) and mx_hosts != ["."],
        "spf": spf,
        "dmarc": dmarc,
        "gravatar": gravatar,
        "gravatar_hash": gravatar_hash,
        "breaches": breaches,
        "breach_check": "performed" if hibp_key else "skipped (no HIBP key configured)",
        "dork_google": f"https://www.google.com/search?q=%22{address}%22",
        "dork_github": f"https://github.com/search?q=%22{address}%22&type=code",
        "dork_linkedin": f"https://www.google.com/search?q=site%3Alinkedin.com+%22{address}%22",
    }
