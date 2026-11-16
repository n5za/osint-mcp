"""``python -m osint_mcp`` / ``osint-mcp`` entrypoint (stdio transport + doctor CLI)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys


def _run_doctor() -> int:
    from .util_tools import doctor

    result = asyncio.run(doctor())
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("ok") else 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="osint-mcp", description="OSINT MCP server (stdio)")
    parser.add_argument("--doctor", action="store_true", help="run self-diagnostics and exit")
    args, _unknown = parser.parse_known_args()
    if args.doctor or (len(sys.argv) > 1 and sys.argv[1] == "doctor"):
        sys.exit(_run_doctor())

    from .app import mcp

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
