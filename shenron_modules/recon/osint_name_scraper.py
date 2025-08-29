#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

from .osint_google_adapter import run_adapter as google_run
from .osint_deep_adapter import run_adapter as deep_run

DEFAULT_UA = "shenron-name/0.1"

_PLATFORMS = [
    ("linkedin", ["linkedin.com/in/", "linkedin.com/company/"]),
    ("github", ["github.com/"]),
    ("twitter", ["x.com/", "twitter.com/"]),
    ("facebook", ["facebook.com/"]),
    ("instagram", ["instagram.com/"]),
    ("youtube", ["youtube.com/", "youtu.be/"]),
    ("medium", ["medium.com/"]),
    ("tiktok", ["tiktok.com/@"]),
]


def _read_lines(p: Path) -> List[str]:
    if not p.exists():
        return []
    return [
        ln.strip()
        for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines()
        if ln.strip()
    ]


def _platform_for_url(url: str) -> str | None:
    u = url.lower()
    for name, needles in _PLATFORMS:
        if any(n in u for n in needles):
            return name
    return None


def _domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


@dataclass
class NameScrapeResult:
    ok: bool
    out_dir: str
    google_out_dir: str
    deep_out_dir: str
    artifacts: Dict[str, str]
    counts: Dict[str, int]


def run_name_scraper(
    name: str,
    max_pages: int = 10,
    deep_limit: int = 50,
    delay_sec: float = 1.0,
    user_agent: str = DEFAULT_UA,
) -> NameScrapeResult:
    # 1) Google for quoted name (URLs only)
    query = f'"{name}"'
    g = google_run({"query": query, "max_pages": max_pages, "user_agent": user_agent})
    google_out = Path(g["out_dir"])
    urls_file = google_out / "urls.txt"

    # 2) Deep: polite titles (robots-aware)
    deep_out = Path.home() / "SHENRON" / "output" / f"osint_name_{name.replace(' ', '_')}"
    deep_out.mkdir(parents=True, exist_ok=True)
    d = deep_run(
        {
            "urls_file": str(urls_file),
            "out_dir": str(deep_out),
            "delay_sec": delay_sec,
            "limit": deep_limit,
            "user_agent": user_agent,
        }
    )

    titles_csv = Path(d["artifacts"]["titles_csv"])
    ok_urls_txt = Path(d["artifacts"]["ok_urls"])

    # 3) Aggregate: profiles + domains
    rows: List[Dict[str, str]] = []
    if titles_csv.exists():
        with titles_csv.open("r", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                url = (r.get("url") or "").strip()
                title = (r.get("title") or "").strip()
                platform = _platform_for_url(url) or ""
                rows.append(
                    {
                        "platform": platform,
                        "url": url,
                        "title": title,
                        "robots_allowed": str(r.get("robots_allowed")),
                        "status": str(r.get("status")),
                    }
                )

    profiles_csv = deep_out / "profiles.csv"
    with profiles_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["platform", "url", "title", "robots_allowed", "status"])
        w.writeheader()
        w.writerows(rows)

    ok_urls = _read_lines(ok_urls_txt)
    domains = sorted({_domain(u) for u in ok_urls if u})
    domains_txt = deep_out / "domains.txt"
    domains_txt.write_text("\n".join(domains) + ("\n" if domains else ""), encoding="utf-8")

    # 4) Markdown mini-report
    report_md = deep_out / "name_report.md"
    with report_md.open("w", encoding="utf-8") as f:
        f.write("# OSINT Name Report\n\n")
        f.write("## Target\n\n```\n" + name + "\n```\n\n")
        f.write("## Google query\n\n```\n" + query + "\n```\n\n")
        f.write("## Artifacts\n\n")
        f.write("- Google URLs: `" + str(urls_file) + "`\n")
        f.write("- Titles CSV:  `" + str(titles_csv) + "`\n")
        f.write("- OK URLs:     `" + str(ok_urls_txt) + "`\n")
        f.write("- Profiles CSV:`" + str(profiles_csv) + "`\n")
        f.write("- Domains:     `" + str(domains_txt) + "`\n")
        f.write("\n## Quick Domains\n\n")
        if domains:
            for dmn in domains:
                f.write("- " + dmn + "\n")
        else:
            f.write("_None_\n")

    return NameScrapeResult(
        ok=True,
        out_dir=str(deep_out),
        google_out_dir=str(google_out),
        deep_out_dir=str(deep_out),
        artifacts={
            "urls_file": str(urls_file),
            "titles_csv": str(titles_csv),
            "ok_urls": str(ok_urls_txt),
            "profiles_csv": str(profiles_csv),
            "domains_txt": str(domains_txt),
            "report_md": str(report_md),
        },
        counts={
            "google_urls": len(_read_lines(urls_file)),
            "ok_urls": len(ok_urls),
            "profiles_rows": len(rows),
            "domains": len(domains),
        },
    )


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="OSINT Name Scraper (polite, robots-aware; profiles via heuristics)."
    )
    p.add_argument("--name", required=True, help='Person or org name, e.g. "Ada Lovelace"')
    p.add_argument("--max-pages", type=int, default=10)
    p.add_argument("--deep-limit", type=int, default=50)
    p.add_argument("--delay-sec", type=float, default=1.0)
    p.add_argument("--user-agent", default=os.getenv("SHENRON_UA", DEFAULT_UA))
    return p.parse_args()


def main() -> int:
    a = _parse_args()
    res = run_name_scraper(a.name, a.max_pages, a.deep_limit, a.delay_sec, a.user_agent)
    print(
        json.dumps(
            {
                "ok": res.ok,
                "out_dir": res.out_dir,
                "artifacts": res.artifacts,
                "counts": res.counts,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
