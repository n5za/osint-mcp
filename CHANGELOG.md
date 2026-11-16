# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-16

### Added

- **Reliability core**
  - Shared pooled `httpx.AsyncClient` (connection reuse, no TLS handshake per request).
  - Automatic retry with exponential backoff for GET requests on 429/5xx and transport errors, honouring `Retry-After`.
  - Per-host concurrency cap to stop bursts against fragile sources.
  - Bounded LRU response cache with TTL — no more unbounded memory growth.
  - Structured errors: `error_code` and `retryable` fields alongside the human message.
  - Structured stderr logging (`OSINT_LOG_LEVEL`) for client-side debugging.
- **Accuracy**
  - `web_search`: multi-engine fallback (DuckDuckGo HTML → DuckDuckGo Lite) with resilient parsing.
  - `ssl_certificate`: full chain details and expiry days-remaining alerts.
  - `port_scan`: TLS certificate grab on TLS ports (previously empty banners).
  - `subdomain_enum`: wordlist expanded from ~50 to 1000+ entries plus permutation mode.
  - `js_recon`: secret/API-key pattern scanning in fetched JavaScript.
  - `api_discovery`: parses OpenAPI/Swagger specs found on the target.
  - Case graph: SQLite WAL mode, schema migrations, FTS5 full-text search, and a new `case_export` tool for portable case backups.
- **Safety**
  - SSRF guard: outbound requests to private/loopback/link-local ranges are blocked by default; `OSINT_ALLOW_PRIVATE=1` restores old behaviour for authorized lab use (applied to HTTP tools and browser navigation).
- **Distribution**
  - Published to PyPI: `uvx osint-mcp` / `pipx install osint-mcp`.
  - Docker image with Chromium bundled.
  - `doctor` tool and `osint-mcp doctor` CLI: checks keys, browser, database, and dependencies.
  - Optional `[image]` extra: OpenCV/NumPy are no longer required for the base install.
- **Project health**
  - GitHub Actions CI: ruff lint, import + tool-count smoke checks on Python 3.10–3.13, generated-catalog staleness check, and a build/twine job.
  - `SECURITY.md`, `CONTRIBUTING.md`, and this changelog.
  - `keys.example.json` now includes `greynoise` (previously documented but missing).

### Changed

- `image_analyze` / QR decoding require the `[image]` extra (`pip install osint-mcp[image]`); a structured error is returned when OpenCV is missing.
- Error results keep `error` as a human-readable string for backwards compatibility; new consumers should also read `error_code` and `retryable`.

## [1.3.0] - 2025-10-27

### Added

- Image evidence in the case graph: `case_image_add`, `case_image_view`, `case_image_crop`, `case_image_similar`, `case_image_reverse`, and `person_dossier`.
- Copy-paste AI-agent install prompt in the README.

## [1.2.0] - 2025-10-25

### Added

- Persistent case evidence graph: `case_create`, `case_list`, `case_research`, `case_capture`, `case_note`, `case_add_fact`, `case_search`, `case_graph`.
- Passive DNS audit tools: `dnssec_status`, `dns_resolver_compare`.

## [1.0.0] - 2025-10-24

### Added

- Initial release: 70-tool OSINT recon MCP server (DNS, RDAP/TLS, IP, web, discovery, threat intel, breach metadata, email security, browser tools, deep research, image analysis, local utilities).

[2.0.0]: https://github.com/n5za/osint-mcp/compare/v1.3.0...v2.0.0
[1.3.0]: https://github.com/n5za/osint-mcp/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/n5za/osint-mcp/compare/v1.0.0...v1.2.0
[1.0.0]: https://github.com/n5za/osint-mcp/tag/v1.0.0
