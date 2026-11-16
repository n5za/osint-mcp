"""Social / code search tools: Hacker News, grep.app, Bluesky, npm."""

from __future__ import annotations

import asyncio
import json
import re
import time
from urllib.parse import urlencode

from bs4 import BeautifulSoup

from .common import USER_AGENT, clip, guarded, request, utcnow


def _json_or_none(response):
    try:
        return response.json()
    except Exception:
        return None


# ------------------------------------------------------------- Hacker News
@guarded
async def hackernews_search(
    query: str,
    limit: int = 20,
    sort: str = "relevance",
    tags: str = "story",
) -> dict:
    """Search Hacker News stories/comments via the keyless Algolia API.

    `sort` is relevance or date. `tags` accepts story, comment, show_hn, ask_hn,
    front_page, poll or a comma-separated combination.
    """
    value = (query or "").strip()
    if not value:
        return {"ok": False, "error": "empty query"}
    limit = max(1, min(int(limit), 100))
    mode = (sort or "relevance").strip().lower()
    endpoint = "search_by_date" if mode in ("date", "new", "recent") else "search"
    tag_value = (tags or "story").strip()

    params = {
        "query": value,
        "tags": tag_value,
        "hitsPerPage": limit,
    }
    response = await request(
        f"https://hn.algolia.com/api/v1/{endpoint}",
        params=params,
        headers={"Accept": "application/json"},
        timeout=30.0,
    )
    if response.status_code != 200:
        return {
            "ok": False,
            "query": value,
            "error": f"HN Algolia HTTP {response.status_code}",
            "body": clip(response.text, 300),
        }
    data = _json_or_none(response) or {}
    hits = []
    for item in (data.get("hits") or [])[:limit]:
        object_id = item.get("objectID")
        hits.append(
            {
                "id": object_id,
                "title": item.get("title") or item.get("story_title"),
                "url": item.get("url") or item.get("story_url"),
                "author": item.get("author"),
                "points": item.get("points"),
                "comments": item.get("num_comments"),
                "created_at": item.get("created_at"),
                "story_text": clip(
                    re.sub(r"<[^>]+>", " ", item.get("story_text") or ""), 400
                ),
                "comment_text": clip(
                    re.sub(r"<[^>]+>", " ", item.get("comment_text") or ""), 400
                ),
                "hn_url": f"https://news.ycombinator.com/item?id={object_id}" if object_id else None,
            }
        )
    return {
        "ok": True,
        "query": value,
        "sort": endpoint,
        "tags": tag_value,
        "total": data.get("nbHits"),
        "count": len(hits),
        "hits": hits,
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# ----------------------------------------------------------------- grep.app
_GREP_BROWSER_LOCK = asyncio.Lock()


async def _grep_json_via_browser(url: str) -> dict | None:
    """Render grep.app through Chromium when the keyless JSON endpoint is challenged."""
    from playwright.async_api import async_playwright

    from .browser_tools import _launch

    async with _GREP_BROWSER_LOCK:
        async with async_playwright() as playwright:
            browser = await _launch(playwright)
            try:
                context = await browser.new_context(
                    user_agent=USER_AGENT,
                    locale="en-US",
                    viewport={"width": 1280, "height": 900},
                    ignore_https_errors=True,
                )
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=60_000)
                deadline = time.monotonic() + 35
                text = ""
                while time.monotonic() < deadline:
                    text = await page.evaluate("() => document.body.innerText")
                    stripped = text.strip()
                    if stripped.startswith(("{", "[")):
                        try:
                            return json.loads(stripped)
                        except Exception:
                            pass
                    await asyncio.sleep(0.6)
                return None
            finally:
                await browser.close()


def _clean_grep_snippet(snippet_html: str) -> tuple[str, list[dict]]:
    soup = BeautifulSoup(snippet_html or "", "html.parser")
    lines: list[dict] = []
    for row in soup.select("tr"):
        number_tag = row.select_one(".lineno")
        pre = row.select_one("pre")
        code = pre.get_text("", strip=False) if pre else ""
        number_text = number_tag.get_text(strip=True) if number_tag else ""
        lines.append(
            {
                "line": int(number_text) if number_text.isdigit() else None,
                "code": code.rstrip(),
            }
        )
    if lines:
        rendered = "\n".join(
            f"{item['line']}: {item['code']}" if item["line"] is not None else item["code"]
            for item in lines
        )
        return rendered, lines
    return clip(soup.get_text("\n", strip=True), 1500), []


@guarded
async def grep_app_search(
    query: str,
    limit: int = 10,
    language: str | None = None,
    repo: str | None = None,
) -> dict:
    """Search public code on grep.app (keyless; browser fallback for bot checks).

    Accepts a literal string or regex, optional language and repository filters.
    Returns repo, path, matched line numbers and a cleaned code snippet.
    """
    value = (query or "").strip()
    if not value:
        return {"ok": False, "error": "empty query"}
    limit = max(1, min(int(limit), 50))
    params = {"q": value}
    if language:
        params["filter[lang][0]"] = language
    if repo:
        params["filter[repo][0]"] = repo
    url = "https://grep.app/api/search?" + urlencode(params)

    data = None
    used_browser = False
    try:
        response = await request(url, headers={"Accept": "application/json"}, timeout=35.0)
        if response.status_code == 200:
            data = _json_or_none(response)
        if not isinstance(data, dict):
            data = await _grep_json_via_browser(url)
            used_browser = True
    except Exception:
        data = await _grep_json_via_browser(url)
        used_browser = True

    if not isinstance(data, dict) or "hits" not in data:
        return {
            "ok": False,
            "query": value,
            "error": "grep.app returned no JSON (bot challenge or service change)",
            "used_browser": used_browser,
        }

    raw_hits = ((data.get("hits") or {}).get("hits")) or []
    total = (data.get("hits") or {}).get("total")
    results = []
    for item in raw_hits[:limit]:
        snippet_html = ((item.get("content") or {}).get("snippet")) or ""
        rendered, lines = _clean_grep_snippet(snippet_html)
        results.append(
            {
                "repo": item.get("repo"),
                "path": item.get("path"),
                "branch": item.get("branch"),
                "line_numbers": [line["line"] for line in lines if line["line"] is not None][:20],
                "snippet": rendered,
                "github_url": (
                    f"https://github.com/{item.get('repo')}/blob/{item.get('branch')}/{item.get('path')}"
                    if item.get("repo") and item.get("path")
                    else None
                ),
            }
        )
    return {
        "ok": True,
        "query": value,
        "language": language,
        "repo": repo,
        "total": int(total) if str(total or "").isdigit() else total,
        "count": len(results),
        "results": results,
        "used_browser": used_browser,
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }


# ----------------------------------------------------------------- Bluesky
@guarded
async def bluesky_profile(actor: str, posts: int = 10) -> dict:
    """Look up a public Bluesky profile and recent posts (keyless AT Protocol API).

    `actor` accepts a handle (bsky.app) or a DID. Returns bio, counts, labels and
    recent original posts/reposts with engagement counts.
    """
    value = (actor or "").strip().lstrip("@")
    if not value:
        return {"ok": False, "error": "empty actor"}
    posts = max(0, min(int(posts), 50))
    base = "https://public.api.bsky.app/xrpc"
    response = await request(
        f"{base}/app.bsky.actor.getProfile",
        params={"actor": value},
        headers={"Accept": "application/json"},
        timeout=30.0,
    )
    if response.status_code == 400:
        return {"ok": False, "actor": value, "error": "profile not found"}
    if response.status_code != 200:
        return {
            "ok": False,
            "actor": value,
            "error": f"Bluesky HTTP {response.status_code}",
            "body": clip(response.text, 300),
        }
    profile = _json_or_none(response) or {}
    result = {
        "ok": True,
        "did": profile.get("did"),
        "handle": profile.get("handle"),
        "display_name": profile.get("displayName"),
        "description": profile.get("description"),
        "avatar": profile.get("avatar"),
        "banner": profile.get("banner"),
        "followers": profile.get("followersCount"),
        "follows": profile.get("followsCount"),
        "posts": profile.get("postsCount"),
        "created_at": profile.get("createdAt"),
        "labels": [label.get("val") for label in (profile.get("labels") or [])],
        "profile_url": f"https://bsky.app/profile/{profile.get('handle') or value}",
        "recent_posts": [],
    }
    if posts:
        feed_response = await request(
            f"{base}/app.bsky.feed.getAuthorFeed",
            params={"actor": value, "limit": posts, "filter": "posts_no_replies"},
            headers={"Accept": "application/json"},
            timeout=30.0,
        )
        if feed_response.status_code == 200:
            feed = (_json_or_none(feed_response) or {}).get("feed") or []
            recent = []
            for entry in feed[:posts]:
                post = entry.get("post") or {}
                record = post.get("record") or {}
                recent.append(
                    {
                        "uri": post.get("uri"),
                        "text": record.get("text"),
                        "created_at": record.get("createdAt"),
                        "likes": post.get("likeCount"),
                        "reposts": post.get("repostCount"),
                        "replies": post.get("replyCount"),
                        "url": (
                            f"https://bsky.app/profile/{profile.get('handle') or value}/post/"
                            f"{(post.get('uri') or '').rsplit('/', 1)[-1]}"
                            if post.get("uri")
                            else None
                        ),
                    }
                )
            result["recent_posts"] = recent
    result["checked_at"] = utcnow().isoformat(timespec="seconds")
    return result


# --------------------------------------------------------------------- npm
@guarded
async def npm_search(query: str, limit: int = 10) -> dict:
    """Search the public npm registry for packages (keyless).

    Returns name, latest version, description, publisher, date, keywords, links
    and the registry score. Useful for supply-chain and dependency research.
    """
    value = (query or "").strip()
    if not value:
        return {"ok": False, "error": "empty query"}
    limit = max(1, min(int(limit), 50))
    response = await request(
        "https://registry.npmjs.org/-/v1/search",
        params={"text": value, "size": limit},
        headers={"Accept": "application/json"},
        timeout=30.0,
    )
    if response.status_code != 200:
        return {
            "ok": False,
            "query": value,
            "error": f"npm HTTP {response.status_code}",
            "body": clip(response.text, 300),
        }
    data = _json_or_none(response) or {}
    packages = []
    for item in (data.get("objects") or [])[:limit]:
        package = item.get("package") or {}
        score = item.get("score") or {}
        packages.append(
            {
                "name": package.get("name"),
                "version": package.get("version"),
                "description": package.get("description"),
                "keywords": (package.get("keywords") or [])[:10],
                "date": package.get("date"),
                "publisher": (package.get("publisher") or {}).get("username"),
                "links": package.get("links"),
                "score": {
                    "final": score.get("final"),
                    "quality": score.get("detail", {}).get("quality"),
                    "popularity": score.get("detail", {}).get("popularity"),
                    "maintenance": score.get("detail", {}).get("maintenance"),
                },
            }
        )
    return {
        "ok": True,
        "query": value,
        "total": data.get("total"),
        "count": len(packages),
        "packages": packages,
        "checked_at": utcnow().isoformat(timespec="seconds"),
    }
