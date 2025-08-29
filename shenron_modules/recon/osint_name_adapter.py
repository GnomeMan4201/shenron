from __future__ import annotations

from typing import Any, Dict

try:
    from shenron_core import payload_registry  # type: ignore[attr-defined]
except Exception:
    payload_registry = None  # type: ignore[assignment]

from .osint_name_scraper import run_name_scraper


def run_adapter(params: Dict[str, Any]) -> Dict[str, Any]:
    name = str(params.get("name") or "").strip()
    if not name:
        return {"ok": False, "error": "Missing required parameter: name"}

    max_pages = int(params.get("max_pages", 10))
    deep_limit = int(params.get("deep_limit", 50))
    delay_sec = float(params.get("delay_sec", 1.0))
    user_agent = str(params.get("user_agent", "shenron-name/0.1"))

    res = run_name_scraper(name, max_pages, deep_limit, delay_sec, user_agent)
    return {
        "ok": res.ok,
        "out_dir": res.out_dir,
        "artifacts": res.artifacts,
        "counts": res.counts,
    }


def _register() -> None:
    if payload_registry and hasattr(payload_registry, "register_payload"):

        @payload_registry.register_payload(
            name="recon.osint_name",
            version="0.1.0",
            description="OSINT name scraper: Google -> polite titles -> profile/domain heuristics.",
            tags=["recon", "web", "osint", "non-invasive"],
        )
        def entrypoint(context: dict[str, Any] | None = None, **kwargs: Any) -> Dict[str, Any]:
            return run_adapter(kwargs)


_register()
