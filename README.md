# OSINT MCP

![A large black and white eye, the OSINT MCP project banner](docs/eye-banner.png)

**88 tools for open-source intelligence and authorized reconnaissance, exposed through the Model Context Protocol (MCP).** Investigate domains, IPs, websites, public accounts, breach metadata, threat feeds, and images from one stdio server. Keep a private evidence graph for investigations you revisit.

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-111111?logo=python&logoColor=white) ![88 tools](https://img.shields.io/badge/Tools-88-111111) ![License MIT](https://img.shields.io/badge/License-MIT-111111) ![CI](https://github.com/n5za/osint-mcp/actions/workflows/ci.yml/badge.svg)

Most tools work without an API key. Optional keys add coverage from services such as HIBP, VirusTotal, and OTX. Browser tools use Playwright; the rest can run without a browser.

## Install in one command

```bash
# Run without installing (any MCP client that supports uvx/pipx):
uvx osint-mcp            # or: pipx run osint-mcp

# Or install for real:
pipx install osint-mcp
```

Point your MCP client's stdio command at `uvx osint-mcp` (or the installed `osint-mcp` binary). Docker alternative:

```bash
docker build -t osint-mcp .
docker run -i --rm -v osint-cases:/home/osint/.local/share/osint-mcp osint-mcp
```

Verify your environment (keys, Chromium, database, guards):

```bash
osint-mcp doctor
```

## Easy install with your AI agent

Open your coding agent in the environment where you want to use the MCP server. Give it the [OSINT MCP repository](https://github.com/n5za/osint-mcp) and paste this prompt:

```text
Install and configure this MCP server for the agent/client I am using right now:
https://github.com/n5za/osint-mcp

Read the repository README first. Clone the repository to a suitable local directory,
create a Python 3.10+ virtual environment, and install the project in that environment.
Find this client's MCP configuration and add OSINT MCP as a stdio server named "osint".
Use absolute paths to the virtual environment's Python executable and the repository's
server.py. Preserve my existing MCP servers and settings.

Install Playwright Chromium for the browser and deep-research tools. Verify that the
server starts, that the client can discover its tools, and that the expected tool
count is 88. If this client needs a restart or reload, tell me exactly what to do.
Do not put API keys in the repository or in the MCP configuration. Report the install
path, the config file you changed, and the verification result.
```

Your agent needs local shell and file access to do the installation. The steps below are the manual alternative.

## Start here

**Requirements:** Python 3.10 or newer. Chromium is needed only for browser and deep research tools; Tesseract is optional for OCR.

```bash
git clone https://github.com/n5za/osint-mcp.git
cd osint-mcp
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Install Chromium if you plan to use `browser_*`, `browser_search`, `browser_crawl`, or `deep_osint`:

```bash
playwright install chromium
```

The server speaks **MCP over stdio**. Connect it to a client; running `python server.py` directly waits for MCP messages on stdin.

### Connect an MCP client

Use the absolute path to the virtual environment's Python binary. This lets the client start the server without shell activation. If you installed from PyPI, replace both values with a single command: `"command": "uvx", "args": ["osint-mcp"]`.

<details>
<summary>Claude Desktop / Cursor</summary>

Put this in Claude Desktop's `claude_desktop_config.json` or Cursor's `.cursor/mcp.json`, changing the two absolute paths:

```json
{
  "mcpServers": {
    "osint": {
      "command": "/absolute/path/to/osint-mcp/.venv/bin/python",
      "args": ["/absolute/path/to/osint-mcp/server.py"]
    }
  }
}
```

Restart the client after saving.
</details>

<details>
<summary>OpenCode</summary>

Add this to `opencode.jsonc` (or `~/.config/opencode/opencode.jsonc`):

```jsonc
{
  "mcp": {
    "osint": {
      "type": "local",
      "command": [
        "/absolute/path/to/osint-mcp/.venv/bin/python",
        "/absolute/path/to/osint-mcp/server.py"
      ],
      "enabled": true
    }
  }
}
```

Reload OpenCode, then run `opencode mcp list`.
</details>

<details>
<summary>VS Code / Copilot</summary>

Put this in `.vscode/mcp.json`:

```json
{
  "servers": {
    "osint": {
      "type": "stdio",
      "command": "/absolute/path/to/osint-mcp/.venv/bin/python",
      "args": ["/absolute/path/to/osint-mcp/server.py"]
    }
  }
}
```
</details>

<details>
<summary>Claude Code</summary>

```bash
claude mcp add osint -- /absolute/path/to/osint-mcp/.venv/bin/python /absolute/path/to/osint-mcp/server.py
```
</details>

### Check the installation

```bash
python - <<'PY'
import asyncio
from osint_mcp.app import mcp
print(len(asyncio.run(mcp.list_tools())))
PY
```

Expected output: `88`. To try a keyless tool without an MCP client:

```bash
python - <<'PY'
import asyncio
from osint_mcp.dns_tools import dns_lookup
print(asyncio.run(dns_lookup("example.com", "A")))
PY
```

## Choose a workflow

The full generated reference lives in [`docs/TOOL_CATALOG.md`](docs/TOOL_CATALOG.md). Highlights:

| Goal | Start with | Continue with |
|---|---|---|
| Domain overview | `recon_domain` | `recon_deep`, `dns_lookup`, `domain_whois` |
| DNS posture | `dnssec_status` | `dns_resolver_compare`, `email_security` |
| IP context | `recon_ip` | `ip_intel`, `asn_lookup`, `ip_whois` |
| Public web surface | `http_headers_audit` | `tech_fingerprint`, `wayback_urls`, `js_recon` |
| Threat triage | `threat_reputation` | `virustotal_report`, `otx_domain`, `cve_intel` |
| Rendered or dynamic page | `browser_open` | `browser_extract`, `browser_screenshot` |
| Multi-source research | `deep_osint` | `source_crosscheck`, `image_analyze` |
| Ongoing investigation | `case_create` | `case_research`, `case_graph`, `case_add_fact` |
| Image investigation | `case_image_add` | `case_image_view`, `case_image_crop`, `case_image_reverse`, `person_dossier` |

`recon_ip` includes a TCP port check. Other tools that actively contact target systems include `port_scan`, `subdomain_enum`, `api_discovery`, `dns_zone_transfer`, and browser tools. Use them only on targets you are authorized to assess.

## Persistent investigation graph

The case tools let you keep a separate local knowledge graph for each investigation. A case has sources, entities, short observations, and explicit relationships. `case_research` runs browser research and **automatically saves** source URLs, detected entity mentions, and key sentences. `case_capture` saves the same fields from an existing `deep_osint` or `browser_crawl` JSON result. Repeated captures deduplicate mentions and observations. Other OSINT tools do not save data automatically; pass their useful findings to `case_note` or `case_add_fact`.

| Tool | Use it for |
|---|---|
| `case_create(name, description)` | Start or reopen a case. |
| `case_list()` | See saved cases and their counts. |
| `case_research(case, query, max_pages)` | Research and save source/entity mentions in one call. |
| `case_capture(case, result_json)` | Import the `pages` from a prior research result. |
| `case_note(case, entity, kind, observation, source_url)` | Save a person, place, event, or organization with a short observation. |
| `case_add_fact(case, subject, predicate, object_name, ...)` | Add a relationship, ideally with `source_url` and an evidence excerpt. |
| `case_search(case, query)` | Find entities, source titles/URLs, observations, and facts (FTS5 full-text). |
| `case_graph(case, entity)` | Resume the whole case or inspect one entity's connections. |
| `case_export(case, out_path)` | Export the whole case as portable JSON (inline or file). |

For example: create a case named `Missing painting`; run `case_research` for the incident; save a note about Amina, then add the relationship `Amina — visited — Rabat` with the page URL and supporting excerpt; later use `case_graph("Missing painting", "Amina")` to resume. Its `nodes` and `edges` fields are ready for a graph viewer. A page mentioning Amina and Rabat stores two mentions, **not** an invented visit. Facts without both a source and evidence stay marked `lead`; even sourced facts are claims to verify, not ground truth. This is especially important for questions about who acted and why.

The database defaults to `~/.local/share/osint-mcp/cases.sqlite3`. It is local, is not sent to GitHub, and is ignored if placed in the repository. The tool creates the database file with private permissions on POSIX systems. Set `OSINT_CASES_DB` to choose another path. Back up that file if you need to preserve a long-running case. Case storage contains source URLs and brief excerpts, so protect the file like other investigation notes.

## Investigate images and keep person folders

1. Create a case with `case_create`.
2. Add a local file or image URL with `case_image_add(case, image, person="...", source_url="...")`. The image is copied into the private case directory. If you provide a person label, a separate folder and `profile.json` are created for that person. The label is for organization; it does **not** identify anyone in the picture.
3. Use `case_image_view(case, image_id)` in a vision-capable MCP client so the agent can inspect the image. `case_image_crop` isolates a region (for example, one person in a group photo) for closer inspection; it never verifies identity. The agent can describe visible details and record observations with `case_note`. `case_image_add` also returns local EXIF/GPS, hashes, OCR and QR analysis.
4. Use `case_image_similar` to find near-duplicate images already in this case. Similarity compares whole images, not faces or identities.
5. Use `case_image_reverse` to look for web pages carrying a matching image. With a paid `TINEYE_API_KEY`, it calls TinEye and saves page backlinks as image-to-source edges in `case_graph`. Without a key, it returns Google Lens/TinEye pages to open manually. A local image is sent to TinEye **only when you invoke reverse search with a key and `use_tineye=True`**. Recognized social profile paths may produce unverified account candidates; no account ownership is asserted.
6. Run `person_dossier(case, person)` after adding notes or facts to refresh that person's `profile.json`. It contains their case notes, relationships, associated image files and discovered web pages.

The local files live next to the case database, under `cases/<case-id>/people/<person-id>-<name>/`. Case images and profiles are ignored by Git. Search backlinks show where a copy appeared; they do not establish who owns an account or who is depicted. Check each page and record any identity claim with a source and an evidence excerpt.

The reverse-search workflow uses TinEye's [official API](https://help.tineye.com/article/182-using-the-tineye-api-to-determine-if-an-image-is-a-stock-photo) for structured backlinks. Google [documents visual search](https://support.google.com/websearch/answer/1325808?hl=en) in the browser. The [Search by Image](https://github.com/dessant/search-by-image) and [ImageHash](https://github.com/JohannesBuchner/imagehash) repositories informed the multi-engine and local similarity workflow; their code was not copied. Microsoft's [Bing Search APIs retired in 2025](https://learn.microsoft.com/en-us/lifecycle/announcements/bing-search-api-retirement), so this project does not promise a Bing image API.

## Tool catalog

The names below are the registered MCP tool names. Arguments and result schemas are available through MCP tool discovery.

### Overview and DNS

| Tools | Purpose |
|---|---|
| `recon_domain`, `recon_ip`, `recon_deep` | Parallel overviews for a domain or IP. |
| `dns_lookup`, `reverse_dns` | DNS records and reverse PTR lookups. |
| `dnssec_status` | Check DS and DNSKEY publication. This does **not** validate signatures. |
| `dns_resolver_compare` | Compare Cloudflare and Google DNS-over-HTTPS answers. Differences can be normal for geo DNS or load balancing. |
| `crtsh_subdomains`, `passive_subdomains` | Find names from public certificate and passive sources. |
| `subdomain_enum`, `dns_zone_transfer` | Active subdomain guessing and AXFR checks. |

### Case memory

| Tools | Purpose |
|---|---|
| `case_create`, `case_list` | Start and resume separate local investigations. |
| `case_research`, `case_capture` | Save sources, entity mentions, and short observations. |
| `case_note`, `case_add_fact` | Add an entity observation or a sourced relationship. |
| `case_search`, `case_graph` | Retrieve case evidence and connections. |
| `case_image_add`, `case_image_view`, `case_image_crop`, `case_image_similar` | Save, inspect, crop and compare images in a case. |
| `case_image_reverse`, `person_dossier` | Find image appearances and build per-person profiles. |

### Domains, IPs, and websites

| Tools | Purpose |
|---|---|
| `domain_whois`, `ssl_certificate` | RDAP registration and live TLS certificate details. |
| `robots_txt`, `security_txt`, `sitemap_urls`, `wayback_urls` | Site policy files, sitemaps, and archived URLs. |
| `ip_intel`, `asn_lookup`, `reverse_ip`, `ip_whois` | Address, network, ASN, and registration context. |
| `port_scan` | Active TCP connection scan with configurable ports. |
| `http_fetch`, `http_headers_audit`, `tech_fingerprint` | HTTP response, security headers, and technology clues. |
| `extract_links`, `page_metadata` | Links, forms, metadata, and page structure. |

### Discovery and search

| Tools | Purpose |
|---|---|
| `web_search`, `google_dorks`, `github_search` | Web search, prepared search queries, and public GitHub search. |
| `urlscan_search`, `commoncrawl_urls` | Public scan and archive indexes. |
| `js_recon`, `api_discovery`, `well_known` | JavaScript clues, API paths, and well-known endpoints. |
| `subdomain_takeover_check`, `favicon_hash`, `cloud_bucket_check` | Dangling DNS signals, favicon pivot, and public bucket checks. |
| `hackernews_search`, `grep_app_search`, `bluesky_profile`, `npm_search` | Public discussion, code, profile, and package sources. |

### Identity, exposure, and threat intelligence

| Tools | Purpose |
|---|---|
| `username_search`, `email_intel` | Public handle and email context. |
| `breach_check`, `stealer_log_check`, `domain_breach_exposure` | Exposure **metadata only**; personal lookups require `authorized=True`. |
| `breach_catalog`, `breach_providers` | Public breach catalog and provider availability. |
| `email_security` | SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT, and CAA posture. |
| `otx_domain`, `virustotal_report`, `cve_intel`, `threat_reputation` | Threat feeds, detections, vulnerability details, and combined signals. |
| `dnsbl_check`, `tor_exit_check`, `greynoise_ip` | DNS blocklists, Tor exit list, and GreyNoise context. |
| `urlhaus_lookup`, `peeringdb_network`, `openphish_check` | Malware URL, network, and phishing feeds. |

### Browser, deep research, and local utilities

| Tools | Purpose |
|---|---|
| `browser_open`, `browser_extract`, `browser_screenshot`, `browser_eval` | Render a page, extract content, capture a PNG, or evaluate JavaScript. |
| `deep_osint`, `browser_search`, `browser_crawl`, `source_crosscheck` | Bounded browser research and source comparison. |
| `image_analyze`, `image_exif` | Image hashes, metadata, optional OCR/QR, and EXIF. |
| `jwt_decode`, `hash_text`, `doctor` | Decode JWT fields, hash text locally, and self-diagnose the installation. |

`browser_screenshot` returns image content; most other tools return structured data. A source error or missing key is reported in the result, so a failed lookup is not treated as a negative finding.

## Optional API keys

No key is required to start. Set environment variables for extra provider coverage, or copy [`keys.example.json`](keys.example.json) to `~/.config/osint-mcp/keys.json` and set file permissions to `600`.

| Environment variable | Used for |
|---|---|
| `GITHUB_TOKEN` | GitHub code search and higher API limits. |
| `HIBP_API_KEY` | Have I Been Pwned account, domain, and stealer endpoints. |
| `OTX_API_KEY` | AlienVault OTX coverage. |
| `VIRUSTOTAL_API_KEY` | VirusTotal reports. |
| `GREYNOISE_API_KEY` | Optional GreyNoise access. |
| `URLHAUS_API_KEY` | URLhaus API access. |
| `TINEYE_API_KEY` | Paid TinEye reverse-image API; returns matching-image page backlinks. |

```bash
mkdir -p ~/.config/osint-mcp
chmod 700 ~/.config/osint-mcp
cp keys.example.json ~/.config/osint-mcp/keys.json
chmod 600 ~/.config/osint-mcp/keys.json
```

Never commit real keys. See the provider's own documentation for access requirements and quotas.

## Configuration and limits

| Setting | Default | Effect |
|---|---|---|
| `OSINT_BROWSER_PATH` | auto-detected | Override the Chrome/Chromium executable. |
| `OSINT_HEADLESS` | `1` | Set `0` to show a browser window. |
| `OSINT_SHOTS_DIR` | `./shots` | Screenshot output directory. |
| `OSINT_KEYS_FILE` | `~/.config/osint-mcp/keys.json` | Alternate local key file. |
| `OSINT_CASES_DB` | `~/.local/share/osint-mcp/cases.sqlite3` | Local case graph database (WAL mode) and nearby person/image folders. |
| `OSINT_LOG_LEVEL` | `WARNING` | stderr log verbosity (`DEBUG`, `INFO`, ...) for client-side debugging. |
| `OSINT_CACHE_MAX` | `512` | Max entries in the bounded response cache. |
| `OSINT_ALLOW_PRIVATE` | `0` | Set `1` to allow requests to private/loopback ranges (authorized lab use only). |

### Reliability behaviour (v2)

- HTTP requests reuse a pooled connection client, retry idempotent GETs on 429/5xx with backoff, and honour `Retry-After`.
- Failed tools return structured errors: `error` (human message), `error_code`, and `retryable`.
- Outbound HTTP and browser navigation pass an SSRF guard that resolves the host and blocks private/loopback/link-local addresses, including across redirects. This is accident prevention, not a sandbox.
- The case database runs in WAL mode with an FTS5 full-text index (automatic LIKE fallback on SQLite builds without FTS5).

### Optional image extra

`image_analyze` hashes and EXIF work out of the box. QR decoding and image preprocessing need OpenCV:

```bash
pip install "osint-mcp[image]"     # or: pipx install "osint-mcp[image]"
```

Public sources can rate-limit, block, or return incomplete data. A DNS resolver mismatch is not automatically a misconfiguration. Breach results may be stale or contain false positives. Browser crawling and some composite tools make multiple requests, so set their limits to fit your scope. `image_analyze` processes images locally for hashes, EXIF, OCR, and QR; reverse-image search links are generated for remote URLs.

## Project structure

```text
osint_mcp/
├── app.py              # MCP registration and tool instructions
├── common.py           # HTTP, cache, keys, and shared helpers
├── composite.py        # overview workflows
├── case_tools.py       # private investigation graph
├── case_media_tools.py # case images, reverse search, person dossiers
├── dns_tools.py        # DNS, CT, AXFR, subdomain enumeration
├── dns_audit_tools.py  # DNSSEC and resolver comparison
├── domain_tools.py     # RDAP, TLS, site policy files, archives
├── ip_tools.py         # IP and port tools
├── web_tools.py        # HTTP and page analysis
├── discovery_tools.py  # API, JS, archive, and takeover discovery
├── intel_tools.py      # threat intelligence
├── breach_tools.py     # exposure metadata
├── mail_tools.py       # email security
├── search_tools.py     # web and GitHub search
├── social_tools.py     # social, code, and package search
├── identity_tools.py   # username and email context
├── browser_tools.py    # Playwright browser tools
├── deep_tools.py       # deep research and image analysis
└── util_tools.py       # local utilities
```

## Responsible use

Use this project only for your own assets, authorized engagements, bug bounty scopes, or labs. Breach tools return aggregate metadata and do not expose passwords, hashes, cookies, or raw leaked records. Confirm findings with primary evidence before reporting them.

MIT licensed. See [LICENSE](LICENSE)
