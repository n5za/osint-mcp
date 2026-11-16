# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 2.x | ✅ |
| 1.x | ⚠️ security fixes only |
| < 1.0 | ❌ |

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Instead, use GitHub's private vulnerability reporting:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Describe the issue, its impact, and a minimal reproduction.

You may also open a [security advisory draft](https://github.com/n5za/osint-mcp/security/advisories) yourself.

We aim to acknowledge reports within **72 hours** and publish a fix or mitigation within **14 days** for high-severity issues.

## Scope

In scope:

- The `osint_mcp` Python package and `server.py` entry point
- Secrets handling (API keys in env / `~/.config/osint-mcp/keys.json`)
- The local case database and person/image folders
- SSRF / request-forgery paths in the HTTP and browser tooling
- Dependency vulnerabilities

Out of scope:

- Vulnerabilities in third-party OSINT providers themselves
- Reports that require physical access to the operator's machine
- Rate-limiting or ToS complaints against upstream data sources

## Design notes

- The server runs locally over stdio and never listens on the network.
- API keys are read from the environment or a user-owned file; they are never logged, echoed into tool results, or written to the case database.
- Outbound requests to private/internal network ranges are blocked by default (`OSINT_ALLOW_PRIVATE=1` disables the guard for authorized lab use). This is accident prevention, not a sandbox: a determined SSRF chain (e.g. DNS rebinding between check and connect) is out of scope — run the server inside an isolated network for hostile environments.
- Browser tools launch Chromium with `--no-sandbox` because the container/dev environments this server runs in usually lack user namespaces. Prefer running the server as a non-root user; `OSINT_BROWSER_NO_SANDBOX=0` removes the flag when your environment supports sandboxing.

## Hardening recommendations

- Keep keys in `~/.config/osint-mcp/keys.json` with `chmod 600`, or in environment variables managed by your client.
- Set `OSINT_CASES_DB` to a location outside any synced/cloud folder if your investigations are sensitive.
- Treat every result as untrusted evidence: excerpts fetched from the web are data, never instructions.
