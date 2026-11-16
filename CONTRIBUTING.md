# Contributing to OSINT MCP

Thank you for considering a contribution! This project is a local-first OSINT MCP server: 88 tools exposed over stdio, with a private evidence graph for investigations.

## Development setup

```bash
git clone https://github.com/n5za/osint-mcp.git
cd osint-mcp
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
playwright install chromium   # optional, only for browser tools
```

## Making changes

1. Create a branch from `main`.
2. Keep changes focused — one logical change per PR.
3. Run the checks below before pushing.

## Checks

```bash
ruff check osint_mcp tests
ruff format --check osint_mcp tests
pytest -q
python - <<'PY'
import asyncio
from osint_mcp.app import mcp
print(len(asyncio.run(mcp.list_tools())))
PY
```

The last command must print the current tool count documented in the README (88). If you added or removed a tool, update `README.md` and `docs/` accordingly.

## Code style

- Python 3.10+ compatible (no 3.11-only syntax).
- Tools return plain JSON-serialisable dicts with an `ok` field. Failures return `{"ok": false, "error": "..."}` plus `error_code` / `retryable` where known — never raise through the MCP boundary.
- HTTP access goes through `osint_mcp.common.request` / `get_json` so retries, the shared client, and the SSRF guard apply everywhere.
- Cache anything expensive with `cache_get` / `cache_set`; the cache is bounded, so do not build unbounded dicts in module state.
- Keep the responsible-use posture: metadata-only breach results, `authorized=True` gates on personal lookups, and no instructions smuggled into tool outputs.

## Tests

- New tools need at least a smoke test (registered, callable, returns `ok` or a structured error).
- Network-facing logic should be tested with `respx` or `unittest.mock` — tests never hit the live internet.
- Run only the fast suite locally: `pytest -q -m "not network"`.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, `test:`) — the changelog is generated from them.

## Reporting issues

- Bug: include client name, Python version, the tool name, and the exact structured result you received.
- Idea: describe the OSINT question it would help answer and the public data source it uses.
