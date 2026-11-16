"""Real-browser tools backed by Playwright + Chromium/Chrome."""

from __future__ import annotations

import json
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

from mcp.server.fastmcp import Image
from playwright.async_api import async_playwright

from .common import SHOTS_DIR, USER_AGENT, assert_public_url, clip, ensure_url, guarded, jsonable, url_host, utcnow

CHROME_CANDIDATES = [
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    "/usr/bin/brave-browser",
    "/usr/bin/microsoft-edge",
]


def _chrome_path() -> str | None:
    configured = os.environ.get("OSINT_BROWSER_PATH")
    if configured and Path(configured).is_file():
        return configured
    for candidate in CHROME_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def _headless() -> bool:
    return os.environ.get("OSINT_HEADLESS", "1").strip().lower() not in ("0", "false", "no", "headed")


def _shots_dir() -> Path:
    path = Path(SHOTS_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _screenshot_path(url: str) -> Path:
    host = re.sub(r"[^A-Za-z0-9._-]+", "_", url_host(url) or "page")[:60]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return _shots_dir() / f"{stamp}-{host}.png"


async def _launch(playwright):
    kwargs = {
        "headless": _headless(),
        "args": [
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--hide-scrollbars",
        ],
    }
    executable = _chrome_path()
    if executable:
        kwargs["executable_path"] = executable
    try:
        return await playwright.chromium.launch(**kwargs)
    except Exception:
        if not kwargs["headless"]:
            kwargs["headless"] = True
            return await playwright.chromium.launch(**kwargs)
        raise


@asynccontextmanager
async def _session(url: str, wait_ms: int = 1500):
    target = ensure_url(url)
    await assert_public_url(target)
    async with async_playwright() as playwright:
        browser = await _launch(playwright)
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            user_agent=USER_AGENT,
            locale="en-US",
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        page = await context.new_page()
        console: list[str] = []

        def _on_console(message) -> None:
            if message.type == "error":
                console.append(message.text[:500])

        def _on_page_error(error) -> None:
            console.append(f"pageerror: {error}")

        page.on("console", _on_console)
        page.on("pageerror", _on_page_error)
        try:
            response = await page.goto(target, wait_until="domcontentloaded", timeout=45000)
            if wait_ms > 0:
                await page.wait_for_timeout(min(int(wait_ms), 15000))
            yield page, response, console
        finally:
            try:
                await context.close()
            finally:
                await browser.close()


@guarded
async def browser_open(url: str, wait_ms: int = 1500, screenshot: bool = True) -> dict:
    """Open a URL in a real headless Chrome tab, wait for JS, and report what is there.

    Returns final URL, HTTP status, title, meta description, rendered text excerpt,
    link/form counts, console errors and (by default) a screenshot path. Use this
    for JS-heavy sites, SPAs, Cloudflare-protected pages and anything http_fetch
    cannot render.
    """
    async with _session(url, wait_ms) as (page, response, console):
        title = await page.title()
        meta_description = await page.evaluate(
            "() => { const m = document.querySelector('meta[name=\"description\"]'); return m ? m.content : null; }"
        )
        text = await page.evaluate("() => document.body ? document.body.innerText : ''")
        counts = await page.evaluate(
            "() => ({links: document.querySelectorAll('a[href]').length, "
            "forms: document.querySelectorAll('form').length, "
            "scripts: document.querySelectorAll('script[src]').length, "
            "iframes: document.querySelectorAll('iframe').length})"
        )
        shot_path = None
        if screenshot:
            shot_path = _screenshot_path(str(page.url))
            await page.screenshot(path=str(shot_path), full_page=False)

        return {
            "ok": True,
            "requested_url": ensure_url(url),
            "final_url": page.url,
            "status": response.status if response else None,
            "title": title,
            "description": meta_description,
            "text": clip(text, 15000),
            "counts": counts,
            "console_errors": console[:20],
            "screenshot": str(shot_path) if shot_path else None,
            "fetched_at": utcnow().isoformat(timespec="seconds"),
        }


@guarded
async def browser_extract(url: str, selector: str = "", wait_ms: int = 1500) -> dict:
    """Render a page in Chrome and extract text + links (optionally a CSS selector only).

    Use for content hidden behind JavaScript. `selector` example: "main", "#app",
    "table.results". Without a selector the whole body text is returned.
    """
    async with _session(url, wait_ms) as (page, response, console):
        selected_count = None
        selected_html = None
        if selector:
            locator = page.locator(selector)
            selected_count = await locator.count()
            if selected_count:
                text = await locator.first.inner_text(timeout=8000)
                selected_html = clip(await locator.first.inner_html(timeout=8000), 8000)
            else:
                text = ""
        else:
            text = await page.evaluate("() => document.body ? document.body.innerText : ''")

        links = await page.evaluate(
            "() => Array.from(document.querySelectorAll('a[href]')).map(a => ({href: a.href, text: (a.innerText||'').trim().slice(0,120)}))"
        )
        images = await page.evaluate(
            "() => Array.from(document.querySelectorAll('img[src]')).map(i => ({src: i.src, alt: i.alt})).slice(0,100)"
        )
        return {
            "ok": True,
            "final_url": page.url,
            "status": response.status if response else None,
            "title": await page.title(),
            "selector": selector or None,
            "selector_matches": selected_count,
            "text": clip(text, 20000),
            "html": selected_html,
            "links": links[:300],
            "images": images,
            "console_errors": console[:20],
        }


@guarded
async def browser_screenshot(url: str, full_page: bool = True, wait_ms: int = 1500) -> Image:
    """Open a URL in Chrome and return an actual screenshot image (PNG).

    Set full_page=False for just the viewport. The image is returned inline so
    the model can look at the page; the file also stays in the shots directory.
    """
    async with _session(url, wait_ms) as (page, _response, _console):
        path = _screenshot_path(str(page.url))
        await page.screenshot(path=str(path), full_page=bool(full_page))
        return Image(path=str(path))


@guarded
async def browser_eval(url: str, expression: str, wait_ms: int = 1200) -> dict:
    """Run a JavaScript expression inside a rendered page and return the JSON result.

    Example: "JSON.stringify(Object.keys(localStorage))" or
    "document.querySelectorAll('script').length". Only evaluate expressions you
    trust; this executes arbitrary JS in the page context.
    """
    async with _session(url, wait_ms) as (page, response, console):
        value = await page.evaluate(expression)
        serialized = jsonable(value)
        try:
            text = json.dumps(serialized, ensure_ascii=False, indent=2)
        except Exception:
            text = str(serialized)
        return {
            "ok": True,
            "final_url": page.url,
            "status": response.status if response else None,
            "expression": expression,
            "result": clip(text, 20000),
            "console_errors": console[:20],
        }
