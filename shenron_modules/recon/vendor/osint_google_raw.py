#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    # pip install googlesearch-python
    from googlesearch import search  # type: ignore
except Exception as e:
    print(
        f"[vendor] Missing dependency: {e}. Try: pip install googlesearch-python", file=sys.stderr
    )
    sys.exit(1)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OSINT Google vendor (non-interactive).")
    p.add_argument("--query", default=os.getenv("SHENRON_QUERY", "site:example.com"))
    p.add_argument("--depth", type=int, default=_env_int("SHENRON_DEPTH", 1))  # kept for parity
    p.add_argument(
        "--max-pages", type=int, dest="max_pages", default=_env_int("SHENRON_MAX_PAGES", 10)
    )
    p.add_argument("--out", default=os.getenv("SHENRON_OUTDIR", str(Path.cwd() / "out")))
    p.add_argument("--user-agent", default=os.getenv("SHENRON_UA", "shenron-research/0.1"))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    urls_path = out_dir / "urls.txt"

    # NOTE: This lists result URLs only — no page scraping. Use responsibly.
    results = list(search(args.query, num_results=args.max_pages))

    urls_path.write_text("\n".join(results) + ("\n" if results else ""))
    print(f"[vendor] Query: {args.query}")
    print(f"[vendor] Wrote {len(results)} URLs -> {urls_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
