"""Runs holehe's site checks inside the sandbox, without holehe's CLI.

Executed by the tool venv's interpreter (mounted read-only at /opt/osint/holehe_runner.py).
Compared with ``holehe`` CLI it:

* never calls ``check_update()`` (which would run ``pip install --upgrade holehe``);
* always excludes password-recovery checks (like ``--no-password-recovery``);
* limits concurrency (``--max-connections``) and per-request timeout;
* records a failing site check as ``error`` — holehe's own ``launch_module`` reports any
  exception (no network, outdated check) as ``rateLimit``, which would be misleading;
* prints one JSON document to stdout instead of writing files or coloured text.

Usage: python -I holehe_runner.py --timeout 10 --max-connections 8 -- EMAIL
This file must not import anything from osint_toolkit (it runs in the tool environment).
"""

import argparse
import json
import sys
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--max-connections", type=int, default=8)
    parser.add_argument("email")
    args = parser.parse_args()

    import httpx
    import trio
    from holehe.core import get_functions, import_submodules

    class Options:
        nopasswordrecovery = True

    modules = import_submodules("holehe.modules")
    websites = get_functions(modules, Options())
    out: list[dict[str, Any]] = []

    async def run() -> None:
        limiter = trio.CapacityLimiter(max(1, args.max_connections))
        client = httpx.AsyncClient(timeout=args.timeout)

        async def guarded(website: Any) -> None:
            async with limiter:
                try:
                    await website(args.email, client, out)
                except Exception as exc:  # noqa: BLE001 - one broken check must not stop others
                    name = getattr(website, "__name__", "?")
                    out.append({"name": name, "domain": name, "error": type(exc).__name__})

        try:
            async with trio.open_nursery() as nursery:
                for website in websites:
                    nursery.start_soon(guarded, website)
        finally:
            await client.aclose()

    trio.run(run)
    keep = (
        "name",
        "domain",
        "method",
        "rateLimit",
        "exists",
        "emailrecovery",
        "phoneNumber",
        "error",
    )
    results = [{k: item.get(k) for k in keep} for item in out if isinstance(item, dict)]
    json.dump({"checked": len(websites), "results": results}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
