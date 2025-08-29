#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
import zipfile
from pathlib import Path
from pprint import pprint

from shenron_modules.recon.osint_google_adapter import run_adapter as google_run
from shenron_modules.recon.osint_deep_adapter import run_adapter as deep_run


def _zip_dir(src: Path, dest_zip: Path) -> None:
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in src.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(src))


def parse_args():
    p = argparse.ArgumentParser(description="Run OSINT chain: Google -> Deep (titles only).")
    p.add_argument("--query", default="site:example.com")
    p.add_argument("--max-pages", type=int, default=5)
    p.add_argument("--limit", type=int, default=50, help="Limit URLs processed by deep step")
    p.add_argument("--delay-sec", type=float, default=1.0)
    return p.parse_args()


def main() -> int:
    a = parse_args()
    print(f"[+] Google OSINT: {a.query}")
    g = google_run({"query": a.query, "max_pages": a.max_pages})
    pprint(g)

    urls_file = Path(g["out_dir"]) / "urls.txt"
    ts = time.strftime("%Y%m%d_%H%M%S")
    deep_out = Path.home() / "SHENRON" / "output" / f"osint_chain_{ts}"
    deep_out.mkdir(parents=True, exist_ok=True)

    print(f"\n[+] Deep (titles) over URLs in: {urls_file}")
    d = deep_run(
        {
            "urls_file": str(urls_file),
            "out_dir": str(deep_out),
            "delay_sec": a.delay_sec,
            "limit": a.limit,
        }
    )
    pprint(d)

    # Markdown bundle
    md = deep_out / "osint_report.md"
    with md.open("w", encoding="utf-8") as f:
        f.write("# OSINT Report\n\n")
        f.write("## Query\n\n```\n" + a.query + "\n```\n\n")
        f.write("## Google URLs\n\n")
        if urls_file.exists():
            for line in urls_file.read_text().splitlines():
                if line.strip():
                    f.write("- " + line.strip() + "\n")
        else:
            f.write("_No URLs produced._\n")
        f.write("\n## Deep Titles (robots-aware)\n\n")
        titles_csv = Path(d["artifacts"]["titles_csv"])
        if titles_csv.exists():
            f.write("- Titles CSV: `" + str(titles_csv) + "`\n")
        ok_urls = Path(d["artifacts"]["ok_urls"])
        if ok_urls.exists():
            ok = [u for u in ok_urls.read_text().splitlines() if u.strip()]
            f.write("- OK URLs (" + str(len(ok)) + "):\n")
            for u in ok:
                f.write("  - " + u + "\n")

    # Zip the chain-out directory
    zip_path = deep_out.with_suffix(".zip")
    _zip_dir(deep_out, zip_path)
    print(f"\n[+] Markdown: {md}")
    print(f"[+] ZIP:       {zip_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
