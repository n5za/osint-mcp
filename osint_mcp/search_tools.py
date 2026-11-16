"""Search tools: DuckDuckGo, dork generator, GitHub search."""

from __future__ import annotations

import os
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

from bs4 import BeautifulSoup

from .common import clip, guarded, request

DORK_CATEGORIES: dict[str, list[str]] = {
    "exposed_files": [
        'site:{t} (ext:env OR ext:sql OR ext:log OR ext:bak OR ext:old OR ext:conf)',
        'site:{t} intitle:"index of" (backup OR backup.zip OR db.sql)',
        'site:{t} ext:json ("api_key" OR "apikey" OR "access_token")',
        'site:{t} ext:yml OR ext:yaml ("password" OR "secret" OR "token")',
    ],
    "login_panels": [
        'site:{t} inurl:(admin OR login OR signin OR dashboard)',
        'site:{t} intitle:("admin panel" OR "login" OR "sign in")',
        'site:{t} inurl:(wp-admin OR administrator OR phpmyadmin)',
        'site:{t} ("staff login" OR "employee login" OR "partner portal")',
    ],
    "directory_listing": [
        'site:{t} intitle:"index of /"',
        'site:{t} intitle:"index of" "parent directory"',
        'site:{t} intitle:"index of" (backup OR uploads OR private)',
        'site:{t} "directory listing for"',
    ],
    "git_exposure": [
        'site:{t} inurl:".git"',
        'site:{t} inurl:".env"',
        'site:{t} inurl:(".svn" OR ".hg" OR "CVS")',
        'site:{t} inurl:("docker-compose.yml" OR "Dockerfile")',
    ],
    "subdomains": [
        'site:*.{t} -site:www.{t}',
        'site:*.{t} inurl:(dev OR staging OR test OR beta)',
        'site:*.{t} inurl:(api OR admin OR internal)',
        'site:*.{t} ext:(env OR sql OR log)',
    ],
    "api_keys": [
        'site:{t} ("AIza" OR "AKIA" OR "ghp_" OR "sk_live_")',
        'site:{t} ("Authorization: Bearer" OR "client_secret")',
        'site:{t} ("firebase" OR "supabase") ("anon key" OR "service_role")',
        'site:{t} ext:js ("apiKey" OR "api_key" OR "token")',
    ],
    "documents": [
        'site:{t} (ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx)',
        'site:{t} ext:pdf ("confidential" OR "internal use only")',
        'site:{t} (ext:ppt OR ext:pptx) ("roadmap" OR "strategy")',
        'site:{t} ext:csv',
    ],
    "emails": [
        'site:{t} "@{t}"',
        'site:{t} ("@{t}" AND (email OR contact))',
        'site:{t} intext:"@{t}" filetype:pdf',
        '"{t}" ("email" OR "contact") -site:{t}',
    ],
    "parameters": [
        'site:{t} inurl:("?id=" OR "?page=" OR "?file=" OR "?url=")',
        'site:{t} inurl:("redirect=" OR "next=" OR "return=" OR "callback=")',
        'site:{t} inurl:("debug=" OR "test=" OR "admin=")',
        'site:{t} inurl:(".php?id=" OR ".asp?id=" OR ".jsp?id=")',
    ],
    "cloud_storage": [
        'site:{t} (s3.amazonaws.com OR storage.googleapis.com OR blob.core.windows.net)',
        'site:{t} ("s3://" OR "gs://" OR "azureedge.net")',
        'site:{t} ("bucket" AND ("public" OR "list"))',
        '"{t}" (site:pastebin.com OR site:gist.github.com OR site:trello.com)',
    ],
    "errors": [
        'site:{t} ("sql syntax" OR "mysql_fetch" OR "ORA-" OR "PostgreSQL")',
        'site:{t} ("stack trace" OR "exception" OR "debug mode")',
        'site:{t} ("fatal error" OR "warning:" OR "undefined index")',
        'site:{t} intitle:("404" OR "500" OR "error")',
    ],
}

ENGINES = {
    "google": "https://www.google.com/search?q=",
    "bing": "https://www.bing.com/search?q=",
    "duckduckgo": "https://duckduckgo.com/?q=",
}


def _parse_ddg_html(html: str) -> list[dict]:
    """Parse DuckDuckGo HTML results with layered selectors (markup-resilient)."""
    soup = BeautifulSoup(html, "html.parser")
    results: list[dict] = []
    # layered selectors across DDG markup variants (combined query is resilient)
    blocks = soup.select("div.result, div.web-result, article.result")
    for block in blocks:
        link = block.select_one("a.result__a") or block.select_one("a.result-link") or block.select_one("h2 a")
        if not link:
            continue
        href = link.get("href", "")
        if isinstance(href, list):
            href = href[0] if href else ""
        if "uddg=" in href:
            parsed = parse_qs(urlparse(href).query)
            href = unquote(parsed.get("uddg", [href])[0])
        snippet_tag = block.select_one(".result__snippet") or block.select_one(".result-snippet")
        results.append(
            {
                "title": link.get_text(" ", strip=True),
                "url": href,
                "snippet": snippet_tag.get_text(" ", strip=True) if snippet_tag else "",
            }
        )
    return results


def _parse_ddg_lite(html: str) -> list[dict]:
    """Parse the DuckDuckGo Lite fallback page (simpler table markup)."""
    soup = BeautifulSoup(html, "html.parser")
    results: list[dict] = []
    for link in soup.select("a.result-link"):
        href = link.get("href", "")
        if isinstance(href, list):
            href = href[0] if href else ""
        if "uddg=" in href:
            parsed = parse_qs(urlparse(href).query)
            href = unquote(parsed.get("uddg", [href])[0])
        results.append({"title": link.get_text(" ", strip=True), "url": href, "snippet": ""})
    if not results:
        # last-ditch: any anchor under the results table
        for link in soup.select("table tr a"):
            href = link.get("href", "")
            if href.startswith("http") and "duckduckgo.com" not in href:
                results.append({"title": link.get_text(" ", strip=True), "url": href, "snippet": ""})
    return results


def _blocked_page(text: str) -> bool:
    lowered = text.lower()
    return "anomaly" in lowered or "unusual traffic" in lowered or "challenge" in lowered


@guarded
async def web_search(query: str, max_results: int = 10) -> dict:
    """Search the web (keyless) with automatic engine fallback.

    Tries DuckDuckGo HTML first, then the Lite endpoint. Returns titles, URLs
    and snippets; failures report which engines were tried.
    """
    limit = max(1, min(int(max_results), 30))
    engines_tried: list[str] = []
    errors: list[str] = []

    for engine, endpoint, parser in (
        ("duckduckgo-html", "https://html.duckduckgo.com/html/", _parse_ddg_html),
        ("duckduckgo-lite", "https://lite.duckduckgo.com/lite/", _parse_ddg_lite),
    ):
        engines_tried.append(engine)
        try:
            response = await request(endpoint, params={"q": query}, timeout=25.0)
        except Exception as exc:
            errors.append(f"{engine}: {type(exc).__name__}: {exc}")
            continue
        if response.status_code != 200:
            errors.append(f"{engine}: HTTP {response.status_code}")
            continue
        if _blocked_page(response.text):
            errors.append(f"{engine}: bot challenge")
            continue
        results = parser(response.text)
        if results:
            return {
                "ok": True,
                "query": query,
                "count": len(results[:limit]),
                "engine": engine,
                "results": results[:limit],
                "note": None,
            }
        errors.append(f"{engine}: no results parsed")

    return {
        "ok": False,
        "query": query,
        "error": "no search engine responded with results",
        "error_code": "search_unavailable",
        "retryable": True,
        "engines_tried": engines_tried,
        "details": errors,
        "hint": "Retry later, or use browser_open on a search URL (browser_search tool).",
    }


@guarded
async def google_dorks(target: str, category: str = "all") -> dict:
    """Generate ready-to-click Google/Bing/DDG dork URLs for a domain or brand.

    Categories: exposed_files, login_panels, directory_listing, git_exposure,
    subdomains, api_keys, documents, emails, parameters, cloud_storage, errors, all.
    Google blocks automated queries - open these URLs in a browser.
    """
    clean = (target or "").strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if clean.lower().startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0]
    if not clean:
        return {"ok": False, "error": "empty target"}

    if category != "all" and category not in DORK_CATEGORIES:
        return {
            "ok": False,
            "error": f"unknown category '{category}'",
            "available": [*sorted(DORK_CATEGORIES), "all"],
        }

    selected = DORK_CATEGORIES if category == "all" else {category: DORK_CATEGORIES[category]}
    dorks = []
    for name, templates in selected.items():
        for template in templates:
            dork = template.format(t=clean)
            encoded = quote_plus(dork)
            dorks.append(
                {
                    "category": name,
                    "dork": dork,
                    "google": ENGINES["google"] + encoded,
                    "bing": ENGINES["bing"] + encoded,
                    "duckduckgo": ENGINES["duckduckgo"] + encoded,
                }
            )

    return {"ok": True, "target": clean, "count": len(dorks), "dorks": dorks}


@guarded
async def github_search(query: str, kind: str = "repositories", max_results: int = 10) -> dict:
    """Search GitHub repositories, users, issues or (authenticated) code.

    `kind`: repositories | users | issues | commits | code. Code search requires a
    GITHUB_TOKEN env var. Keyless requests are rate-limited to ~10/min.
    """
    kind = (kind or "repositories").lower().strip()
    allowed = {"repositories", "users", "issues", "commits", "code"}
    if kind not in allowed:
        return {"ok": False, "error": f"kind must be one of {sorted(allowed)}"}

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if kind == "code" and not token:
        return {
            "ok": False,
            "error": "GitHub code search requires authentication",
            "hint": "export GITHUB_TOKEN=... before starting the MCP server",
        }

    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = await request(
        f"https://api.github.com/search/{kind}",
        params={"q": query, "per_page": max(1, min(int(max_results), 100))},
        headers=headers,
        timeout=30.0,
    )
    if response.status_code == 401:
        return {"ok": False, "error": "GitHub authentication failed (bad token?)"}
    if response.status_code == 403:
        return {
            "ok": False,
            "error": "GitHub rate limit or forbidden",
            "hint": "set GITHUB_TOKEN for a 30/min quota",
            "body": clip(response.text, 300),
        }
    if response.status_code != 200:
        return {"ok": False, "error": f"GitHub HTTP {response.status_code}", "body": clip(response.text, 300)}

    data = response.json()
    items = []
    for item in data.get("items", [])[: max_results]:
        if kind == "repositories":
            items.append(
                {
                    "name": item.get("full_name"),
                    "url": item.get("html_url"),
                    "description": item.get("description"),
                    "stars": item.get("stargazers_count"),
                    "language": item.get("language"),
                    "updated": item.get("updated_at"),
                }
            )
        elif kind == "users":
            items.append(
                {
                    "login": item.get("login"),
                    "url": item.get("html_url"),
                    "type": item.get("type"),
                    "score": item.get("score"),
                }
            )
        elif kind == "code":
            items.append(
                {
                    "repo": (item.get("repository") or {}).get("full_name"),
                    "path": item.get("path"),
                    "url": item.get("html_url"),
                }
            )
        else:
            items.append(
                {
                    "title": item.get("title"),
                    "url": item.get("html_url"),
                    "state": item.get("state"),
                    "created": item.get("created_at"),
                }
            )

    rate = {
        "limit": response.headers.get("x-ratelimit-limit"),
        "remaining": response.headers.get("x-ratelimit-remaining"),
        "reset": response.headers.get("x-ratelimit-reset"),
        "authenticated": bool(token),
    }
    return {
        "ok": True,
        "kind": kind,
        "query": query,
        "total": data.get("total_count"),
        "count": len(items),
        "items": items,
        "rate_limit": rate,
    }
