"""Web recon tools: fetch, security headers, tech fingerprint, links, metadata."""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from .common import (
    clip,
    ensure_url,
    guarded,
    headers_dict,
    request,
    url_host,
    utcnow,
)

TEXTUAL_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-javascript",
    "application/x-httpd-php",
    "application/graphql",
    "image/svg+xml",
)


def _decode_body(response) -> tuple[str, bool]:
    content_type = (response.headers.get("content-type") or "").lower()
    if any(kind in content_type for kind in TEXTUAL_TYPES) or content_type == "":
        return response.text, True
    if content_type.startswith("application/") and "charset" in content_type:
        return response.text, True
    return "", False


@guarded
async def http_fetch(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    verify_ssl: bool = True,
    follow_redirects: bool = True,
    include_body: bool = True,
    max_chars: int = 20000,
) -> dict:
    """Fetch a URL with custom method/headers/body and return status, headers and body.

    `headers` is a JSON object string, e.g. '{"Authorization": "Bearer x"}'.
    Binary responses are reported with size instead of content. TLS verification
    can be disabled for targets with broken certificates.
    """
    import json

    target = ensure_url(url)
    parsed_headers = {}
    if headers:
        try:
            parsed_headers = json.loads(headers)
        except Exception:
            return {"ok": False, "error": "headers must be a JSON object string"}

    response = await request(
        target,
        method=method.upper(),
        headers=parsed_headers,
        content=body.encode() if body else None,
        verify=verify_ssl,
        follow_redirects=follow_redirects,
        timeout=30.0,
    )
    text, textual = _decode_body(response)
    title = ""
    if textual and "html" in (response.headers.get("content-type") or "").lower():
        soup = BeautifulSoup(text, "html.parser")
        title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""

    return {
        "ok": True,
        "url": str(response.url),
        "status": response.status_code,
        "reason": response.reason_phrase,
        "content_type": response.headers.get("content-type"),
        "content_length": len(response.content),
        "redirects": [str(item.url) for item in response.history],
        "title": title,
        "headers": headers_dict(response),
        "body": clip(text, max(1000, int(max_chars))) if include_body and textual else None,
        "binary": not textual,
        "elapsed_ms": round(response.elapsed.total_seconds() * 1000, 1) if response.elapsed else None,
    }


SECURITY_HEADERS = {
    "strict-transport-security": 20,
    "content-security-policy": 20,
    "x-frame-options": 12,
    "x-content-type-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 10,
    "cross-origin-opener-policy": 9,
    "cross-origin-resource-policy": 9,
}


def _parse_cookies(response) -> list[dict]:
    cookies = []
    for raw in response.headers.get_list("set-cookie"):
        parts = [part.strip() for part in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        flags = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}
        cookies.append(
            {
                "name": name,
                "secure": "secure" in flags,
                "httponly": "httponly" in flags,
                "samesite": next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), None),
            }
        )
    return cookies


@guarded
async def http_headers_audit(url: str) -> dict:
    """Audit HTTP security headers and cookie flags; returns a score (0-100) and grade.

    Checks HSTS, CSP, X-Frame-Options/CSP frame-ancestors, nosniff, Referrer-Policy,
    Permissions-Policy and COOP/CORP. Also flags version/tech disclosure.
    """
    target = ensure_url(url)
    response = await request(target, method="HEAD", timeout=20.0)
    if response.status_code in (405, 501, 403):
        response = await request(target, method="GET", timeout=20.0)

    headers = {key.lower(): value for key, value in response.headers.items()}
    csp = headers.get("content-security-policy", "")
    present = []
    missing = []
    score = 0
    for name, weight in SECURITY_HEADERS.items():
        found = name in headers
        if name == "x-frame-options" and "frame-ancestors" in csp.lower():
            found = True
        if found:
            score += weight
            present.append(name)
        else:
            missing.append(name)

    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    leaks = {
        key: headers[key]
        for key in (
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "x-generator",
            "x-drupal-cache",
            "x-debug-token",
            "x-runtime",
            "x-version",
        )
        if key in headers
    }
    weak_cookies = [cookie for cookie in _parse_cookies(response) if not cookie["secure"] or not cookie["httponly"]]

    return {
        "ok": True,
        "url": str(response.url),
        "status": response.status_code,
        "score": score,
        "grade": grade,
        "present": present,
        "missing": missing,
        "info_leaks": leaks,
        "cookies": _parse_cookies(response),
        "weak_cookies": weak_cookies,
        "server": headers.get("server"),
        "csp": clip(csp, 2000) if csp else None,
        "headers": headers_dict(response),
    }


TECH_HEADERS = {
    "cloudflare": [("header", "cf-ray"), ("header", "server", "cloudflare")],
    "akamai": [("header", "x-akamai-transformed"), ("header", "akamai-grn")],
    "fastly": [("header", "x-served-by", "cache-"), ("header", "x-fastly-request-id")],
    "amazon cloudfront": [("header", "x-amz-cf-id"), ("header", "via", "cloudfront")],
    "vercel": [("header", "x-vercel-id"), ("header", "server", "vercel")],
    "netlify": [("header", "x-nf-request-id"), ("header", "server", "netlify")],
    "github pages": [("header", "x-github-request-id")],
    "nginx": [("header", "server", "nginx")],
    "apache": [("header", "server", "apache")],
    "microsoft iis": [("header", "server", "microsoft-iis")],
    "litespeed": [("header", "server", "litespeed"), ("header", "x-litespeed-cache")],
    "openresty": [("header", "server", "openresty")],
    "express.js": [("header", "x-powered-by", "express")],
    "php": [("header", "x-powered-by", "php")],
    "asp.net": [("header", "x-powered-by", "asp.net"), ("header", "x-aspnet-version")],
    "rails": [("header", "x-runtime"), ("header", "server", "webrick")],
    "django": [("header", "server", "wsgiserver")],
    "shopify": [("header", "x-shopify-stage"), ("header", "powered-by", "shopify")],
    "drupal": [("header", "x-drupal-cache"), ("header", "x-generator", "drupal")],
    "wordpress": [("header", "x-pingback", "xmlrpc.php"), ("html", "wp-content"), ("html", "wp-includes")],
    "joomla": [("html", "/media/jui/"), ("html", "com_content")],
    "magento": [("html", "mage/cookies"), ("html", "magento")],
    "next.js": [("html", "__next_data__"), ("html", "/_next/")],
    "nuxt": [("html", "__nuxt__"), ("html", "/_nuxt/")],
    "react": [("html", "data-reactroot"), ("html", "react-dom")],
    "vue.js": [("html", "vue.js"), ("html", "data-v-")],
    "angular": [("html", "ng-version"), ("html", "ng-app")],
    "jquery": [("html", "jquery")],
    "bootstrap": [("html", "bootstrap.min.css"), ("html", "bootstrap.min.js")],
    "google analytics": [("html", "googletagmanager.com/gtag"), ("html", "google-analytics.com")],
    "google tag manager": [("html", "googletagmanager.com/gtm")],
    "facebook pixel": [("html", "connect.facebook.net"), ("html", "fbq(")],
    "hotjar": [("html", "static.hotjar.com")],
    "segment": [("html", "cdn.segment.com")],
    "mixpanel": [("html", "cdn.mxpnl.com")],
    "sentry": [("html", "sentry.io"), ("html", "sentry-cdn")],
    "stripe": [("html", "js.stripe.com")],
    "recaptcha": [("html", "google.com/recaptcha")],
    "cloudflare turnstile": [("html", "challenges.cloudflare.com")],
    "firebase": [("html", "firebase")],
    "supabase": [("html", "supabase")],
    "graphql": [("html", "/graphql")],
    "swagger/openapi": [("html", "swagger-ui"), ("html", "openapi")],
}

COOKIE_TECHS = {
    "phpsessid": "php",
    "jsessionid": "java",
    "laravel_session": "laravel",
    "xsrf-token": "laravel/angular",
    "csrftoken": "django",
    "wordpress_logged_in": "wordpress",
    "wp-settings": "wordpress",
    "_shopify_s": "shopify",
    "__cf_bm": "cloudflare",
    "_ga": "google analytics",
    "connect.sid": "express.js",
}


@guarded
async def tech_fingerprint(url: str) -> dict:
    """Fingerprint the web stack from headers, cookies and HTML patterns.

    Detects servers, CDNs/WAFs, frameworks, CMS, JS libraries and analytics.
    Returns each technology with the evidence that matched.
    """
    target = ensure_url(url)
    response = await request(target, timeout=25.0)
    body = response.text if "text" in (response.headers.get("content-type") or "text") else ""
    lowered_body = body.lower()
    headers = {key.lower(): value.lower() for key, value in response.headers.items()}
    cookie_names = {cookie["name"].lower() for cookie in _parse_cookies(response)}
    hits: dict[str, list[str]] = {}

    def add(name: str, evidence: str) -> None:
        hits.setdefault(name, [])
        if evidence not in hits[name]:
            hits[name].append(evidence)

    for name, signals in TECH_HEADERS.items():
        for signal in signals:
            if (signal[0] == "header" and len(signal) == 2 and signal[1] in headers) or (signal[0] == "header" and len(signal) == 3 and signal[2] in headers.get(signal[1], "")):
                add(name, f"header: {signal[1]}")
            elif signal[0] == "html" and signal[1] in lowered_body:
                add(name, f"html: {signal[1]}")

    for cookie_name, tech in COOKIE_TECHS.items():
        if cookie_name in cookie_names:
            add(tech, f"cookie: {cookie_name}")

    meta = {}
    if body:
        soup = BeautifulSoup(body, "html.parser")
        generator = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if generator and generator.get("content"):
            meta["generator"] = generator["content"]
            add(generator["content"].split()[0].lower(), "meta generator")
        title = soup.title.get_text(strip=True) if soup.title else ""
        meta["title"] = title

    return {
        "ok": True,
        "url": str(response.url),
        "status": response.status_code,
        "technologies": [
            {"name": name, "evidence": evidence} for name, evidence in sorted(hits.items())
        ],
        "meta": meta,
        "server": response.headers.get("server"),
        "powered_by": response.headers.get("x-powered-by"),
    }


@guarded
async def extract_links(url: str, external_only: bool = False, limit: int = 500) -> dict:
    """Extract and categorize links from a page: internal, external, emails, scripts, forms.

    Also lists query-parameter names seen, useful for mapping attack surface.
    """
    target = ensure_url(url)
    response = await request(target, timeout=25.0)
    soup = BeautifulSoup(response.text, "html.parser")
    base_host = url_host(str(response.url))

    internal: set[str] = set()
    external: set[str] = set()
    emails: set[str] = set()
    phones: set[str] = set()
    scripts: set[str] = set()
    forms: list[dict] = []
    params: dict[str, int] = {}

    def record(href: str) -> None:
        from urllib.parse import parse_qs, urljoin, urlparse

        absolute = urljoin(str(response.url), href.strip())
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            return
        if parsed.hostname == base_host:
            internal.add(absolute)
        else:
            external.add(absolute)
        for key in parse_qs(parsed.query):
            params[key] = params.get(key, 0) + 1

    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if href.lower().startswith("mailto:"):
            emails.add(href.split(":", 1)[1].split("?")[0])
        elif href.lower().startswith("tel:"):
            phones.add(href.split(":", 1)[1])
        elif not href.startswith(("#", "javascript:", "data:")):
            record(href)

    for tag in soup.find_all("script", src=True):
        from urllib.parse import urljoin

        scripts.add(urljoin(str(response.url), tag["src"]))
    for form in soup.find_all("form"):
        forms.append(
            {
                "action": form.get("action") or str(response.url),
                "method": (form.get("method") or "get").upper(),
                "inputs": [
                    {"name": field.get("name"), "type": field.get("type") or "text"}
                    for field in form.find_all(["input", "textarea", "select"])
                    if field.get("name")
                ],
            }
        )

    internal_list = sorted(internal)
    external_list = sorted(external)
    if external_only:
        internal_list = []
    return {
        "ok": True,
        "url": str(response.url),
        "internal": internal_list[: max(1, int(limit))],
        "external": external_list[: max(1, int(limit))],
        "emails": sorted(emails),
        "phones": sorted(phones),
        "scripts": sorted(scripts)[:200],
        "forms": forms[:50],
        "query_parameters": dict(sorted(params.items(), key=lambda item: -item[1])),
        "counts": {
            "internal": len(internal),
            "external": len(external),
            "scripts": len(scripts),
            "forms": len(forms),
        },
    }


@guarded
async def page_metadata(url: str) -> dict:
    """Extract page metadata: title, meta/OG/Twitter tags, headings, forms, scripts, IDs.

    Useful for profiling a target and spotting analytics IDs, frameworks and
    hidden endpoints referenced in the page.
    """
    target = ensure_url(url)
    response = await request(target, timeout=25.0)
    soup = BeautifulSoup(response.text, "html.parser")

    meta: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        name = tag.get("name") or tag.get("property") or tag.get("http-equiv")
        content = tag.get("content")
        if name and content:
            meta[name.strip().lower()] = content.strip()

    og = {key: value for key, value in meta.items() if key.startswith("og:")}
    twitter = {key: value for key, value in meta.items() if key.startswith("twitter:")}
    canonical = soup.find("link", rel="canonical")
    favicon = soup.find("link", rel=lambda value: value and "icon" in value.lower())
    analytics_ids = sorted(
        set(re.findall(r"\b(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,10}|GT-[A-Z0-9]{4,10})\b", response.text))
    )

    return {
        "ok": True,
        "url": str(response.url),
        "status": response.status_code,
        "title": soup.title.get_text(strip=True) if soup.title else "",
        "description": meta.get("description"),
        "canonical": canonical.get("href") if canonical else None,
        "favicon": favicon.get("href") if favicon else None,
        "robots": meta.get("robots"),
        "generator": meta.get("generator"),
        "og": og,
        "twitter": twitter,
        "headings": {
            f"h{level}": [tag.get_text(" ", strip=True) for tag in soup.find_all(f"h{level}")][:20]
            for level in range(1, 4)
        },
        "scripts": [tag.get("src") for tag in soup.find_all("script", src=True)][:100],
        "iframes": [tag.get("src") for tag in soup.find_all("iframe", src=True)][:50],
        "forms": [
            {
                "action": form.get("action"),
                "method": (form.get("method") or "get").upper(),
                "input_count": len(form.find_all(["input", "textarea", "select"])),
            }
            for form in soup.find_all("form")
        ][:30],
        "analytics_ids": analytics_ids,
        "meta": meta,
        "fetched_at": utcnow().isoformat(timespec="seconds"),
    }
