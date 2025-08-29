#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

DEFAULT_UA = "shenron-deep/0.1"


def load_urls(urls_file: Path, limit: int | None = None) -> List[str]:
    if not urls_file.exists():
        return []
    urls = [line.strip() for line in urls_file.read_text().splitlines() if line.strip()]
    return urls[:limit] if limit else urls


def robots_ok(url: str, ua: str, cache: Dict[str, RobotFileParser]) -> bool:
    try:
        parsed = urlparse(url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        if root not in cache:
            rp = RobotFileParser()
            rp.set_url(urljoin(root, "/robots.txt"))
            try:
                rp.read()
            except Exception:
                pass
            cache[root] = rp
        return cache[root].can_fetch(ua, url)
    except Exception:
        return False


def fetch_title(url: str, ua: str, timeout: float = 7.0) -> Tuple[int | None, str | None]:
    try:
        r = requests.get(url, headers={"User-Agent": ua}, timeout=timeout)
        status = r.status_code
        title = None
        if r.ok:
            soup = BeautifulSoup(r.text, "html.parser")
            t = soup.find("title")
            title = t.get_text(strip=True) if t else None
        return status, title
    except Exception:
        return None, None


def run_deep(
    urls_file: str,
    out_dir: str,
    user_agent: str = DEFAULT_UA,
    delay_sec: float = 1.0,
    limit: int | None = 50,
    timeout: float = 7.0,
) -> Dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    urls = load_urls(Path(urls_file), limit=limit)
    rp_cache: Dict[str, RobotFileParser] = {}

    rows: List[Dict] = []
    ok_urls: List[str] = []

    for _, url in enumerate(urls, 1):
        allowed = robots_ok(url, user_agent, rp_cache)
        status, title = (None, None)
        if allowed:
            status, title = fetch_title(url, user_agent, timeout=timeout)
            if status and 200 <= status < 400:
                ok_urls.append(url)
        rows.append({"url": url, "robots_allowed": allowed, "status": status, "title": title})
        time.sleep(delay_sec)

    (out / "ok_urls.txt").write_text("\n".join(ok_urls) + ("\n" if ok_urls else ""))

    with (out / "titles.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["url", "robots_allowed", "status", "title"])
        w.writeheader()
        w.writerows(rows)

    with (out / "titles.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    return {
        "ok": True,
        "count_total": len(urls),
        "count_ok": len(ok_urls),
        "out_dir": str(out),
        "urls_file": urls_file,
        "artifacts": {
            "ok_urls": str(out / "ok_urls.txt"),
            "titles_csv": str(out / "titles.csv"),
            "titles_jsonl": str(out / "titles.jsonl"),
        },
    }


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Polite deep scraper (titles only, robots-aware).")
    p.add_argument("--urls-file", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--user-agent", default=os.getenv("SHENRON_UA", DEFAULT_UA))
    p.add_argument("--delay-sec", type=float, default=1.0)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--timeout", type=float, default=7.0)
    return p.parse_args()


def main() -> int:
    a = _parse_args()
    res = run_deep(a.urls_file, a.out_dir, a.user_agent, a.delay_sec, a.limit, a.timeout)
    print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
