from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
import time
import zipfile

try:
    from shenron_core import payload_registry  # type: ignore[attr-defined]
except Exception:
    payload_registry = None  # type: ignore[assignment]

from .osint_deep_scraper import run_deep


def _zip_dir(src: Path, dest_zip: Path) -> None:
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in src.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(src))


def run_adapter(params: Dict[str, Any]) -> Dict[str, Any]:
    ts = time.strftime("%Y%m%d_%H%M%S")
    urls_file = str(params.get("urls_file"))
    out_dir = params.get("out_dir") or (Path.home() / "SHENRON" / "output" / f"osint_deep_{ts}")
    ua = str(params.get("user_agent", "shenron-deep/0.1"))
    delay = float(params.get("delay_sec", 1.0))
    limit = params.get("limit", 50)
    timeout = float(params.get("timeout", 7.0))

    res = run_deep(urls_file, str(out_dir), ua, delay, limit, timeout)

    zip_path = Path(str(out_dir)).with_suffix(".zip")
    _zip_dir(Path(str(out_dir)), zip_path)

    res.update({"zip_path": str(zip_path)})
    return res


def _register() -> None:
    if payload_registry and hasattr(payload_registry, "register_payload"):

        @payload_registry.register_payload(
            name="recon.osint_deep",
            version="0.1.0",
            description="Polite deep scraper (titles only, robots-aware).",
            tags=["recon", "web", "osint", "non-invasive"],
        )
        def entrypoint(context: dict[str, Any] | None = None, **kwargs: Any) -> Dict[str, Any]:
            return run_adapter(kwargs)


_register()
