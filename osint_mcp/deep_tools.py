"""Browser-driven deep OSINT: search, crawl sources, cross-check, image analysis."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, quote, quote_plus, urlparse

from bs4 import BeautifulSoup
from PIL import ExifTags, Image
from playwright.async_api import async_playwright

from .browser_tools import _launch, _shots_dir
from .common import USER_AGENT, clip, ensure_url, guarded, request, utcnow

try:
    import numpy as np
except Exception:
    np = None

try:
    import cv2
except Exception:
    cv2 = None


# --------------------------------------------------------------------- browser
@asynccontextmanager
async def _browser_context():
    async with async_playwright() as playwright:
        browser = await _launch(playwright)
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            user_agent=USER_AGENT,
            locale="en-US",
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        try:
            yield context
        finally:
            await browser.close()


SEARCH_ENGINES = ("duckduckgo", "bing", "brave")


def _decode_ddg(url: str) -> str:
    if "duckduckgo.com/l/" in url:
        query = parse_qs(urlparse(url).query)
        if query.get("uddg"):
            return query["uddg"][0]
    return url


def _decode_bing(url: str) -> str:
    if "bing.com/ck/a" in url:
        query = parse_qs(urlparse(url).query)
        encoded = (query.get("u") or [""])[0]
        if encoded.startswith("a1"):
            payload = encoded[2:]
            payload += "=" * (-len(payload) % 4)
            try:
                decoded = base64.urlsafe_b64decode(payload).decode("utf-8")
                if decoded.startswith(("http://", "https://")):
                    return decoded
            except Exception:
                pass
    return url


def _clean_result(item: dict) -> dict | None:
    url = _decode_bing((item.get("url") or "").strip())
    title = (item.get("title") or "").strip()
    if not url.startswith(("http://", "https://")):
        return None
    if not title:
        return None
    if any(token in url for token in ("duckduckgo.com/y.js", "bing.com/aclick", "googleadservices.com")):
        return None
    return {
        "title": clip(title, 200),
        "url": url,
        "snippet": clip((item.get("snippet") or "").strip(), 500),
        "display_url": (item.get("display_url") or urlparse(url).netloc).strip(),
    }


async def _search_duckduckgo(page, query: str) -> list[dict]:
    await page.goto(
        f"https://html.duckduckgo.com/html/?q={quote_plus(query)}",
        wait_until="domcontentloaded",
        timeout=35_000,
    )
    await page.wait_for_timeout(1200)
    raw = await page.evaluate(
        """() => Array.from(document.querySelectorAll('.result')).map((r) => {
            const a = r.querySelector('.result__a');
            const s = r.querySelector('.result__snippet');
            const u = r.querySelector('.result__url');
            return {title: a ? a.innerText : '', url: a ? a.href : '', snippet: s ? s.innerText : '', display_url: u ? u.innerText : ''};
        })"""
    )
    results = []
    for item in raw or []:
        cleaned = _clean_result({**item, "url": _decode_ddg(item.get("url") or "")})
        if cleaned:
            results.append(cleaned)
    return results


async def _search_bing(page, query: str) -> list[dict]:
    await page.goto(
        f"https://www.bing.com/search?q={quote_plus(query)}&setlang=en",
        wait_until="domcontentloaded",
        timeout=35_000,
    )
    await page.wait_for_timeout(1500)
    raw = await page.evaluate(
        """() => Array.from(document.querySelectorAll('li.b_algo')).map((li) => {
            const a = li.querySelector('h2 a');
            const p = li.querySelector('.b_caption p');
            return {title: a ? a.innerText : '', url: a ? a.href : '', snippet: p ? p.innerText : '', display_url: ''};
        })"""
    )
    return [item for item in (_clean_result(row) for row in (raw or [])) if item]


async def _search_brave(page, query: str) -> list[dict]:
    await page.goto(
        f"https://search.brave.com/search?q={quote_plus(query)}",
        wait_until="domcontentloaded",
        timeout=35_000,
    )
    await page.wait_for_timeout(1800)
    raw = await page.evaluate(
        """() => Array.from(document.querySelectorAll('div.snippet')).map((s) => {
            const a = s.querySelector('a');
            const p = s.querySelector('.snippet-description, .snippet-content');
            return {title: a ? a.innerText : '', url: a ? a.href : '', snippet: p ? p.innerText : '', display_url: ''};
        })"""
    )
    return [item for item in (_clean_result(row) for row in (raw or [])) if item]


async def _search_in_context(context, query: str, engine: str, limit: int) -> dict:
    engines = SEARCH_ENGINES if engine == "auto" else (engine,)
    errors = {}
    for name in engines:
        page = await context.new_page()
        try:
            if name == "duckduckgo":
                results = await _search_duckduckgo(page, query)
            elif name == "bing":
                results = await _search_bing(page, query)
            elif name == "brave":
                results = await _search_brave(page, query)
            else:
                results = []
            if results:
                return {
                    "ok": True,
                    "engine": name,
                    "query": query,
                    "count": len(results[:limit]),
                    "results": results[:limit],
                    "errors": errors or None,
                }
            body = (await page.inner_text("body"))[:500].lower()
            errors[name] = "no results" + (" (possible captcha)" if "captcha" in body else "")
        except Exception as exc:
            errors[name] = f"{type(exc).__name__}: {exc}"
        finally:
            await page.close()
    return {"ok": False, "query": query, "error": "all search engines failed", "errors": errors}


@guarded
async def browser_search(query: str, engine: str = "auto", limit: int = 10) -> dict:
    """Search the web in a real Chromium browser and return result links.

    Engines: auto (DuckDuckGo -> Bing -> Brave), duckduckgo, bing, brave.
    Handles JS, decodes DuckDuckGo redirect links, filters ads. Use this as the
    first step of a browser-driven OSINT investigation.
    """
    value = (query or "").strip()
    if not value:
        return {"ok": False, "error": "empty query"}
    limit = max(1, min(int(limit), 30))
    engine = (engine or "auto").strip().lower()
    if engine not in ("auto", *SEARCH_ENGINES):
        return {"ok": False, "error": f"engine must be one of auto, {', '.join(SEARCH_ENGINES)}"}
    async with _browser_context() as context:
        result = await _search_in_context(context, value, engine, limit)
    result["checked_at"] = utcnow().isoformat(timespec="seconds")
    return result


# ----------------------------------------------------------------- page crawl
BLOCK_MARKERS = (
    "captcha",
    "unusual traffic",
    "checking your browser",
    "just a moment",
    "cf-chl",
    "are you a robot",
    "verify you are human",
)


def _is_blocked(text: str) -> bool:
    lowered = (text or "").lower()[:5000]
    if any(marker in lowered for marker in BLOCK_MARKERS):
        return True
    # These phrases also occur in normal articles; only treat them as a block
    # when the rendered page is too short to be real content.
    return len(lowered) < 1200 and any(
        marker in lowered for marker in ("access denied", "enable javascript", "cloudflare")
    )

SKIP_EXTENSIONS = (
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".exe",
    ".dmg",
    ".iso",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".css",
    ".js",
)

# Text domains are noisy in documentation/code pages. Accept all two-letter
# country TLDs, plus common generic TLDs; reject code-looking suffixes.
KNOWN_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "mobi", "asia", "app", "dev", "cloud", "tech", "online", "site",
    "store", "shop", "blog", "news", "media", "agency", "digital", "solutions",
    "systems", "network", "security", "email", "social", "link", "live", "life",
    "world", "today", "space", "website", "xyz", "top", "icu", "vip", "club",
    "work", "art", "fun", "wiki", "zone", "city", "land", "moe", "page",
    "travel", "museum", "aero", "coop", "jobs", "tel", "cat", "post", "xxx",
    "recipes", "photography", "international", "technology", "consulting",
    "ventures", "capital", "finance", "financial", "bank", "insurance", "law",
    "legal", "health", "care", "clinic", "hospital", "pharmacy", "school",
    "university", "academy", "education", "training", "courses", "science",
    "engineering", "software", "codes", "computer", "hosting", "domains",
    "market", "sale", "deals", "free", "download", "video", "audio", "music",
    "movie", "film", "photo", "pics", "gallery", "design", "studio", "events",
    "holiday", "hotel", "restaurant", "cafe", "bar", "food", "menu", "coffee",
    "beer", "wine", "farm", "garden", "flowers", "pets", "vet", "fashion",
    "shoes", "jewelry", "watches", "toys", "games", "gaming", "bet", "poker",
    "casino", "money", "cash", "credit", "loan", "mortgage", "realestate",
    "properties", "rentals", "apartments", "house", "construction", "builders",
    "plumbing", "electrician", "cleaning", "repair", "auto", "cars", "bikes",
    "boats", "yachts", "flights", "tours", "taxi", "transport", "logistics",
    "shipping", "courier", "delivery", "storage", "moving", "relocation",
    "attorney", "lawyer", "accountant", "tax", "coach", "fitness", "gym",
    "yoga", "spa", "beauty", "hair", "nails", "tattoo", "wedding", "party",
    "catering", "videography", "marketing", "advertising", "seo", "web",
    "chat", "dating", "community", "forum", "review", "reviews", "guide",
    "tips", "help", "support", "service", "services", "tools",
}

# Common code identifiers that look like a TLD in `object.method` snippets.
CODE_TLDS = {
    "run", "build", "skip", "ctrl", "get", "set", "map", "filter", "read",
    "write", "open", "close", "main", "test", "call", "json", "text", "data",
    "value", "items", "keys", "dict", "list", "str", "int", "float", "bool",
    "none", "true", "false", "js", "ts", "py", "html", "css", "sh", "exe",
    "dll", "so", "dylib", "lock", "log", "tmp", "temp", "old", "new",
    "backup", "min", "prod", "local", "localhost", "example", "invalid",
    "clientsconnect", "tool", "md", "yml", "yaml", "toml", "ini", "cfg",
    "conf", "env", "sql", "tsx", "jsx", "vue", "svelte", "rb", "php",
}


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9][a-z0-9_-]{2,}", (value or "").lower()))


def _relevance(query: str, title: str, text: str) -> int:
    tokens = _tokens(query)
    if not tokens:
        return 0
    haystack = f"{title} {text}".lower()
    overlap = sum(1 for token in tokens if token in haystack)
    phrase = 1 if query.lower().strip() in haystack else 0
    return min(100, overlap * 9 + phrase * 25)


def _rank_links(links: list[dict], query: str, base_url: str) -> list[str]:
    base_host = (urlparse(base_url).hostname or "").lower()
    tokens = _tokens(query)
    scored = []
    seen = set()
    for link in links:
        href = (link.get("href") or "").strip()
        if not href.startswith(("http://", "https://")):
            continue
        parsed = urlparse(href)
        if not parsed.hostname:
            continue
        if parsed.path.lower().endswith(SKIP_EXTENSIONS):
            continue
        if any(part in href.lower() for part in ("/login", "/logout", "/signin", "/signup", "/cart", "/checkout")):
            continue
        if any(host in parsed.hostname for host in ("google.com", "bing.com", "duckduckgo.com")) and "search" in parsed.path:
            continue
        if any(part in href.lower() for part in ("/sharer", "/share?", "/intent/tweet", "/submit?url=")):
            continue
        normalized = href.split("#")[0]
        if normalized in seen:
            continue
        seen.add(normalized)
        anchor = (link.get("text") or "").lower()
        score = sum(2 for token in tokens if token in anchor or token in href.lower())
        score += 1 if parsed.hostname == base_host else 2
        if score:
            scored.append((score, normalized))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [url for _, url in scored[:4]]


def _extract_entities(text: str) -> list[dict]:
    value = text or ""
    found: dict[tuple[str, str], dict] = {}

    def add(kind: str, raw: str) -> None:
        raw = (raw or "").strip().strip(".,;:()[]<>\"'")
        if not raw:
            return
        key = (kind, raw.lower())
        if key not in found:
            found[key] = {"type": kind, "value": raw}

    for match in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", value):
        add("email", match.group(0))

    for match in re.finditer(r"\bCVE-\d{4}-\d{4,7}\b", value, re.I):
        add("cve", match.group(0).upper())

    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
        try:
            ipaddress.ip_address(match.group(0))
            add("ipv4", match.group(0))
        except ValueError:
            pass

    for match in re.finditer(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", value):
        add("bitcoin", match.group(0))

    for match in re.finditer(r"\b0x[a-fA-F0-9]{40}\b", value):
        add("ethereum", match.group(0))

    for match in re.finditer(r"\b[A-Fa-f0-9]{64}\b", value):
        add("sha256", match.group(0).lower())
    for match in re.finditer(r"\b[A-Fa-f0-9]{40}\b", value):
        add("sha1", match.group(0).lower())
    for match in re.finditer(r"\b[A-Fa-f0-9]{32}\b", value):
        add("md5", match.group(0).lower())

    for match in re.finditer(r"(?<![\w@])@[A-Za-z0-9_]{2,30}\b", value):
        add("handle", match.group(0))

    for match in re.finditer(r"\+\d[\d\s().-]{7,}\d", value):
        digits = re.sub(r"\D", "", match.group(0))
        if 8 <= len(digits) <= 15:
            add("phone", match.group(0))

    # Domains that appear inside URLs are high-confidence, even for rare TLDs.
    for match in re.finditer(r"https?://[^\s<>\"')]+", value, re.I):
        try:
            host = urlparse(match.group(0).rstrip(".,;:")).hostname
        except ValueError:
            host = None
        if host:
            add("domain", host.lower())

    email_values = {item["value"].lower() for item in found.values() if item["type"] == "email"}
    host_values = {item["value"].lower() for item in found.values() if item["type"] == "domain"}
    for match in re.finditer(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", value, re.I):
        host = match.group(0).lower().strip(".")
        if host in email_values or host in host_values:
            continue
        if any(part in host for part in ("..", "_")):
            continue
        labels = host.split(".")
        if len(labels[0]) < 2:
            continue
        tld = labels[-1]
        if tld in CODE_TLDS:
            continue
        if tld in {
            "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "css", "js", "json",
            "xml", "pdf", "zip", "gz", "mp4", "mp3", "woff", "woff2", "ttf",
        }:
            continue
        if len(tld) == 2:
            pass
        elif tld not in KNOWN_TLDS:
            continue
        if host.endswith((".local", ".localhost", ".example", ".invalid", ".test")):
            continue
        add("domain", host)

    return sorted(found.values(), key=lambda item: (item["type"], item["value"].lower()))


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text or "")
    return [part.strip() for part in parts if part.strip()]


def _key_sentences(text: str, query: str, entities: list[dict], limit: int = 6) -> list[str]:
    tokens = _tokens(query)
    entity_values = {item["value"].lower() for item in entities}
    scored: list[tuple[int, str]] = []
    seen = set()
    for sentence in _sentences(text):
        if not (50 <= len(sentence) <= 500):
            continue
        lowered = sentence.lower()
        score = sum(1 for token in tokens if token in lowered)
        score += sum(2 for entity in entity_values if entity in lowered)
        if score <= 0:
            continue
        fingerprint = re.sub(r"\W+", "", lowered)[:120]
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        scored.append((score, sentence))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [sentence for _, sentence in scored[:limit]]


async def _analyze_page(page, url: str, query: str, screenshot: bool = False) -> dict:
    result = {
        "url": url,
        "final_url": None,
        "status": None,
        "title": None,
        "description": None,
        "relevance": 0,
        "blocked": False,
        "text_chars": 0,
        "text_excerpt": "",
        "key_sentences": [],
        "entities": [],
        "links": [],
        "images": [],
        "screenshot": None,
        "error": None,
    }
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        result["status"] = response.status if response else None
        await page.wait_for_timeout(1200)
        result["final_url"] = page.url
        result["title"] = (await page.title()) or None
        result["description"] = await page.evaluate(
            """() => {
                const m = (sel) => document.querySelector(sel)?.content || null;
                return m('meta[name="description"]') || m('meta[property="og:description"]') || null;
            }"""
        )
        text = await page.evaluate(
            """() => {
                const root = document.querySelector('article, main, [role="main"]') || document.body;
                const clone = root.cloneNode(true);
                clone.querySelectorAll('script,style,noscript,svg,header,footer,nav,aside,form,iframe,button,select,textarea').forEach((el) => el.remove());
                return clone.innerText || '';
            }"""
        )
        text = re.sub(r"\n{3,}", "\n\n", (text or "").strip())
        result["text_chars"] = len(text)
        result["text_excerpt"] = clip(text, 1200)
        result["blocked"] = _is_blocked(text)
        result["relevance"] = _relevance(query, result["title"] or "", text)
        result["entities"] = _extract_entities(f"{result['title'] or ''}\n{text}")
        result["key_sentences"] = _key_sentences(text, query, result["entities"])
        result["links"] = await page.evaluate(
            """() => Array.from(document.querySelectorAll('a[href]')).map((a) => ({
                href: a.href,
                text: (a.innerText || '').trim().slice(0, 120)
            })).filter((x) => x.href.startsWith('http')).slice(0, 400)"""
        )
        # Trigger lazy-loaded images without moving the final screenshot viewport.
        try:
            await page.evaluate("() => window.scrollTo(0, Math.min(document.body.scrollHeight, 1800))")
            await page.wait_for_timeout(700)
            await page.evaluate("() => window.scrollTo(0, 0)")
        except Exception:
            pass
        raw_images = await page.evaluate(
            """() => Array.from(document.images).map((img) => ({
                src: img.currentSrc || img.src || img.getAttribute('data-src') || '',
                alt: img.alt || '',
                width: img.naturalWidth || img.width || 0,
                height: img.naturalHeight || img.height || 0
            })).filter((x) => x.src.startsWith('http') && x.width >= 100 && x.height >= 100)"""
        )
        raw_images.sort(key=lambda item: item.get("width", 0) * item.get("height", 0), reverse=True)
        result["images"] = raw_images[:6]
        if screenshot:
            host = re.sub(r"[^A-Za-z0-9._-]+", "_", urlparse(page.url).hostname or "page")[:60]
            path = _shots_dir() / f"{time.strftime('%Y%m%d-%H%M%S')}-{host}.png"
            try:
                await page.screenshot(path=str(path), full_page=False)
                result["screenshot"] = str(path)
            except Exception:
                pass
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


async def _crawl(context, start_urls: list[str], query: str, max_pages: int, max_depth: int, screenshots: bool) -> list[dict]:
    queue: list[tuple[str, int]] = [(url, 0) for url in start_urls]
    visited: set[str] = set()
    pages: list[dict] = []
    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        if depth > max_depth:
            continue
        page = await context.new_page()
        try:
            result = await _analyze_page(page, url, query, screenshot=screenshots and len(pages) < 3)
        finally:
            await page.close()
        pages.append(result)
        if depth < max_depth and not result.get("blocked") and result.get("links"):
            for link in _rank_links(result["links"], query, result.get("final_url") or url)[:2]:
                if link not in visited:
                    queue.append((link, depth + 1))
    return pages


@guarded
async def browser_crawl(
    start_url: str,
    query: str = "",
    max_pages: int = 6,
    max_depth: int = 1,
    screenshots: bool = True,
) -> dict:
    """Open a real browser, analyze a page, then follow relevant links.

    Extracts readable text, meta, links, images, entities and key sentences; follows
    up to 2 relevant links per page. Optional screenshots of the first pages.
    Use `start_url` as a URL or a comma-separated list of seed URLs.
    """
    raw = (start_url or "").strip()
    if not raw:
        return {"ok": False, "error": "empty start URL"}
    seeds = [item.strip() for item in re.split(r"[\s,]+", raw) if item.strip()]
    seeds = [ensure_url(item) for item in seeds if item.startswith(("http://", "https://")) or "." in item]
    seeds = list(dict.fromkeys(seeds))[:10]
    if not seeds:
        return {"ok": False, "error": "no valid http(s) URLs"}
    max_pages = max(1, min(int(max_pages), 20))
    max_depth = max(0, min(int(max_depth), 2))
    async with _browser_context() as context:
        pages = await _crawl(context, seeds, query, max_pages, max_depth, bool(screenshots))
    return {
        "ok": True,
        "query": query,
        "seeds": seeds,
        "pages_visited": len(pages),
        "useful_pages": len([page for page in pages if page.get("relevance", 0) >= 15 and not page.get("blocked")]),
        "pages": pages,
        "cross_source": _cross_source(pages),
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# ------------------------------------------------------------- cross-source
def _cross_source(pages: list[dict]) -> dict:
    mapping: dict[tuple[str, str], dict] = {}
    for page in pages:
        for entity in page.get("entities") or []:
            key = (entity["type"], entity["value"].lower())
            entry = mapping.setdefault(
                key,
                {"type": entity["type"], "value": entity["value"], "sources": []},
            )
            if page.get("final_url") or page.get("url"):
                entry["sources"].append(page.get("final_url") or page.get("url"))
    corroborated = []
    single = []
    by_type: dict[str, int] = {}
    for entry in mapping.values():
        entry["sources"] = sorted(set(entry["sources"]))
        entry["source_count"] = len(entry["sources"])
        by_type[entry["type"]] = by_type.get(entry["type"], 0) + 1
        if entry["source_count"] >= 2:
            corroborated.append(entry)
        else:
            single.append(entry)
    corroborated.sort(key=lambda item: (-item["source_count"], item["type"], item["value"]))
    single.sort(key=lambda item: (item["type"], item["value"]))
    return {
        "corroborated": corroborated[:80],
        "single_source": single[:80],
        "counts_by_type": by_type,
        "total_entities": len(mapping),
    }


async def _fetch_text(url: str, query: str = "") -> dict:
    try:
        response = await request(url, timeout=30.0)
        content_type = (response.headers.get("content-type") or "").lower()
        if "html" not in content_type and "text" not in content_type:
            return {"url": url, "ok": False, "error": f"non-text content: {content_type}", "status": response.status_code}
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.get_text(" ", strip=True) if soup.title else None
        description_tag = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
        description = description_tag.get("content") if description_tag else None
        for tag in soup(["script", "style", "noscript", "header", "footer", "nav", "aside", "form"]):
            tag.decompose()
        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
        return {
            "url": url,
            "ok": response.status_code == 200 and len(text) > 100,
            "status": response.status_code,
            "title": title,
            "description": description,
            "text_chars": len(text),
            "text_excerpt": clip(text, 1200),
            "key_sentences": _key_sentences(text, query, _extract_entities(text)),
            "entities": _extract_entities(f"{title or ''}\n{text}"),
        }
    except Exception as exc:
        return {"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


@guarded
async def source_crosscheck(sources: str, query: str = "") -> dict:
    """Fetch several source URLs and cross-check entities across them.

    Accepts a comma/newline-separated list (or a JSON list). Extracts emails,
    domains, IPs, CVEs, wallets, handles, phones and hashes, then separates
    corroborated entities (2+ sources) from single-source claims. Fast HTTP mode.
    """
    raw = (sources or "").strip()
    if not raw:
        return {"ok": False, "error": "empty sources"}
    items: list[str] = []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            items = [str(item) for item in parsed]
    except Exception:
        pass
    if not items:
        items = [item.strip() for item in re.split(r"[\s,]+", raw) if item.strip()]
    urls = list(dict.fromkeys(ensure_url(item) for item in items if item))[:20]
    pages = await asyncio.gather(*(_fetch_text(url, query) for url in urls))
    return {
        "ok": True,
        "query": query,
        "source_count": len(urls),
        "successful": len([page for page in pages if page.get("ok")]),
        "sources": pages,
        "cross_source": _cross_source([page for page in pages if page.get("ok")]),
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# --------------------------------------------------------------- image tools
def _jsonable(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")[:200]
    return str(value)


def _gps_decimal(values) -> float | None:
    try:
        degrees, minutes, seconds = (float(part) for part in values)
        return degrees + minutes / 60 + seconds / 3600
    except Exception:
        return None


def _extract_exif(image: Image.Image) -> tuple[dict, dict | None]:
    try:
        exif = image.getexif()
    except Exception:
        return {}, None
    data = {}
    for tag_id, value in exif.items():
        tag = ExifTags.TAGS.get(tag_id, str(tag_id))
        if tag in ("GPSInfo", "ExifOffset"):
            continue
        data[tag] = _jsonable(value)
    gps = None
    try:
        gps_ifd = exif.get_ifd(0x8825)
        if gps_ifd:
            lat = _gps_decimal(gps_ifd.get(2))
            lon = _gps_decimal(gps_ifd.get(4))
            if lat is not None and lon is not None:
                if str(gps_ifd.get(1, "N")).upper().startswith("S"):
                    lat = -lat
                if str(gps_ifd.get(3, "E")).upper().startswith("W"):
                    lon = -lon
                gps = {
                    "lat": round(lat, 7),
                    "lon": round(lon, 7),
                    "maps_url": f"https://www.google.com/maps?q={lat:.7f},{lon:.7f}",
                }
    except Exception:
        pass
    return data, gps


def _dhash(image: Image.Image) -> str:
    gray = image.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
    pixels = list(gray.get_flattened_data() if hasattr(gray, "get_flattened_data") else gray.getdata())
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (pixels[row * 9 + col] > pixels[row * 9 + col + 1])
    return f"{bits:016x}"


def _ahash(image: Image.Image) -> str:
    gray = image.convert("L").resize((8, 8), Image.Resampling.LANCZOS)
    pixels = list(gray.get_flattened_data() if hasattr(gray, "get_flattened_data") else gray.getdata())
    average = sum(pixels) / len(pixels)
    bits = 0
    for pixel in pixels:
        bits = (bits << 1) | (pixel > average)
    return f"{bits:016x}"


def _dominant_colors(image: Image.Image, count: int = 5) -> list[dict]:
    small = image.convert("RGB").resize((100, 100))
    quantized = small.quantize(colors=max(2, count)).convert("RGB")
    colors = quantized.getcolors(maxcolors=100000) or []
    colors.sort(key=lambda item: item[0], reverse=True)
    return [
        {"hex": "#{:02x}{:02x}{:02x}".format(*color), "share": round(amount / 10000, 4)}
        for amount, color in colors[:count]
    ]


def _ocr_image(data: bytes) -> str | None:
    if not shutil.which("tesseract"):
        return None
    path = None
    try:
        with tempfile.NamedTemporaryFile(dir="/tmp/opencode", suffix=".png", delete=False) as handle:
            path = handle.name
            handle.write(data)
        completed = subprocess.run(
            ["tesseract", path, "stdout", "-l", "eng", "--psm", "6"],
            capture_output=True,
            text=True,
            timeout=25,
        )
        text = (completed.stdout or "").strip()
        return clip(text, 4000) if text else None
    except Exception:
        return None
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _decode_qr(data: bytes) -> list[str]:
    if cv2 is None:
        return []
    try:
        array = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        if array is None:
            return []
        # Small QR images and missing quiet zones are common in the wild.
        height, width = array.shape[:2]
        if min(height, width) < 300:
            scale = max(2, 300 // max(1, min(height, width)))
            array = cv2.resize(array, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
        array = cv2.copyMakeBorder(array, 24, 24, 24, 24, cv2.BORDER_CONSTANT, value=(255, 255, 255))
        detector = cv2.QRCodeDetector()
        decoded: list[str] = []
        try:
            ok, values, _, _ = detector.detectAndDecodeMulti(array)
            if ok:
                decoded.extend(value for value in values if value)
        except Exception:
            pass
        if not decoded:
            value, _, _ = detector.detectAndDecode(array)
            if value:
                decoded.append(value)
        return list(dict.fromkeys(decoded))
    except Exception:
        return []


def _reverse_search_links(url: str) -> dict:
    encoded = quote(url, safe="")
    return {
        "google_lens": f"https://lens.google.com/uploadbyurl?url={encoded}",
        "yandex": f"https://yandex.com/images/search?rpt=imageview&url={encoded}",
        "tineye": f"https://tineye.com/search?url={encoded}",
        "bing_visual": f"https://www.bing.com/images/searchbyimage/upload?cbir=sbi&imgurl={encoded}",
    }


async def _load_image(target: str) -> tuple[bytes, str, str]:
    value = (target or "").strip()
    if not value:
        raise ValueError("empty image target")
    if value.startswith(("http://", "https://")):
        response = await request(value, timeout=35.0)
        if response.status_code != 200:
            raise ValueError(f"image HTTP {response.status_code}")
        content_type = (response.headers.get("content-type") or "").lower()
        if "image" not in content_type and not value.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")):
            raise ValueError(f"not an image content-type: {content_type}")
        return response.content, value, content_type
    path = os.path.expanduser(value)
    with open(path, "rb") as handle:
        return handle.read(), path, "local"


async def _analyze_image(target: str, ocr: bool, qr: bool, reverse: bool) -> dict:
    data, source, content_type = await _load_image(target)
    if len(data) > 20_000_000:
        return {"ok": False, "source": source, "error": "image larger than 20 MB"}
    image = Image.open(io.BytesIO(data))
    image.load()
    exif, gps = _extract_exif(image)
    result = {
        "ok": True,
        "source": source,
        "content_type": content_type,
        "format": image.format,
        "mode": image.mode,
        "width": image.width,
        "height": image.height,
        "megapixels": round(image.width * image.height / 1_000_000, 2),
        "bytes": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "dhash": _dhash(image),
        "ahash": _ahash(image),
        "average_color": "#{:02x}{:02x}{:02x}".format(*image.convert("RGB").resize((1, 1)).getpixel((0, 0))),
        "dominant_colors": _dominant_colors(image),
        "exif": exif,
        "gps": gps,
        "ocr_text": None,
        "qr_codes": [],
        "reverse_search": None,
    }
    if ocr:
        result["ocr_text"] = _ocr_image(data)
    if qr:
        result["qr_codes"] = _decode_qr(data)
    if reverse and source.startswith(("http://", "https://")):
        result["reverse_search"] = _reverse_search_links(source)
    return result


@guarded
async def image_analyze(
    target: str,
    ocr: bool = True,
    qr: bool = True,
    reverse_search: bool = True,
) -> dict:
    """Analyze an image from a URL or local path.

    Returns dimensions/format, hashes (MD5/SHA256/dHash/aHash), EXIF and GPS,
    dominant colors, OCR text (Tesseract), QR codes (OpenCV) and reverse-image
    search links for remote images. No upload; everything runs locally.
    """
    try:
        result = await _analyze_image(target, bool(ocr), bool(qr), bool(reverse_search))
    except Exception as exc:
        return {"ok": False, "target": target, "error": f"{type(exc).__name__}: {exc}"}
    result["checked_at"] = utcnow().isoformat(timespec="seconds")
    return result


# ---------------------------------------------------------------- deep OSINT
def _leads(query: str, pages: list[dict], cross: dict, images: list[dict]) -> list[str]:
    leads: list[str] = []
    for entity in (cross.get("corroborated") or [])[:10]:
        leads.append(f'"{entity["value"]}"')
    for entity in (cross.get("single_source") or [])[:8]:
        if entity["type"] in ("domain", "email", "handle", "cve"):
            leads.append(f'"{entity["value"]}"')
    for page in pages[:4]:
        host = urlparse(page.get("final_url") or page.get("url") or "").hostname
        if host:
            leads.append(f"site:{host} {query}")
    for item in images[:2]:
        if item.get("reverse_search", {}).get("google_lens"):
            leads.append(f"reverse image: {item['reverse_search']['google_lens']}")
    return list(dict.fromkeys(lead for lead in leads if lead))[:20]


@guarded
async def deep_osint(
    query: str,
    max_results: int = 8,
    max_pages: int = 6,
    max_depth: int = 1,
    analyze_images: bool = True,
    ocr_images: bool = True,
    screenshots: bool = True,
) -> dict:
    """Full browser-driven OSINT run: search, crawl sources, cross-check, image analysis.

    1) Searches in Chromium (DDG/Bing/Brave), 2) opens the top results and follows
    relevant links, 3) extracts text/entities/key sentences, 4) cross-checks entities
    across sources, 5) analyzes page images (EXIF/OCR/QR/hashes), 6) returns leads.
    Caps keep it bounded; use narrower tools for a single page or image.
    """
    value = (query or "").strip()
    if not value:
        return {"ok": False, "error": "empty query"}
    max_results = max(1, min(int(max_results), 20))
    max_pages = max(1, min(int(max_pages), 20))
    max_depth = max(0, min(int(max_depth), 2))

    async with _browser_context() as context:
        search = await _search_in_context(context, value, "auto", max_results)
        if not search.get("ok"):
            return {
                "ok": False,
                "query": value,
                "error": search.get("error") or "search failed",
                "search": search,
            }
        start_urls = [item["url"] for item in search.get("results", [])][:max_results]
        pages = await _crawl(context, start_urls, value, max_pages, max_depth, bool(screenshots))

    cross = _cross_source(pages)
    image_candidates = []
    for page in pages:
        for image in page.get("images") or []:
            image_candidates.append(
                {
                    "src": image.get("src"),
                    "alt": image.get("alt"),
                    "width": image.get("width"),
                    "height": image.get("height"),
                    "page": page.get("final_url") or page.get("url"),
                    "area": (image.get("width") or 0) * (image.get("height") or 0),
                }
            )
    image_candidates.sort(key=lambda item: item["area"], reverse=True)
    unique_images = []
    seen_src = set()
    for item in image_candidates:
        src = item.get("src") or ""
        if not src.startswith("http") or src.lower().endswith((".svg", ".gif")):
            continue
        if src in seen_src:
            continue
        seen_src.add(src)
        unique_images.append(item)
    image_candidates = unique_images[:4 if analyze_images else 0]

    analyzed_images = []
    if analyze_images and image_candidates:
        sem = asyncio.Semaphore(2)

        async def run_image(item):
            async with sem:
                try:
                    analysis = await _analyze_image(item["src"], ocr=bool(ocr_images), qr=True, reverse=True)
                except Exception as exc:
                    return {
                        "src": item["src"],
                        "alt": item.get("alt"),
                        "page": item.get("page"),
                        "width": item.get("width"),
                        "height": item.get("height"),
                        "ok": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                return {
                    "src": item["src"],
                    "alt": item.get("alt"),
                    "page": item.get("page"),
                    "width": item.get("width"),
                    "height": item.get("height"),
                    "ok": analysis.get("ok"),
                    "error": analysis.get("error"),
                    "dhash": analysis.get("dhash"),
                    "ocr_text": analysis.get("ocr_text"),
                    "exif": {
                        key: analysis.get("exif", {}).get(key)
                        for key in ("Make", "Model", "DateTimeOriginal", "Software")
                        if analysis.get("exif", {}).get(key)
                    },
                    "gps": analysis.get("gps"),
                    "qr_codes": analysis.get("qr_codes"),
                    "reverse_search": analysis.get("reverse_search"),
                }

        analyzed_images = list(await asyncio.gather(*(run_image(item) for item in image_candidates)))

    useful_pages = [
        page for page in pages
        if page.get("relevance", 0) >= 15 and not page.get("blocked")
    ]
    return {
        "ok": True,
        "query": value,
        "search": {
            "engine": search.get("engine"),
            "result_count": search.get("count"),
            "results": search.get("results"),
        },
        "stats": {
            "pages_visited": len(pages),
            "useful_pages": len(useful_pages),
            "blocked_pages": len([page for page in pages if page.get("blocked")]),
            "entities": cross.get("total_entities"),
            "corroborated": len(cross.get("corroborated") or []),
            "images_analyzed": len([item for item in analyzed_images if item.get("ok")]),
        },
        "pages": pages,
        "cross_source": cross,
        "images": analyzed_images,
        "leads": _leads(value, pages, cross, analyzed_images),
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }
