from __future__ import annotations

from typing import Any, Dict

# Re-export the new adapter so existing code/tests keep working
from .osint_google_adapter import run_adapter as run_adapter  # noqa: F401

# Optional: also register the old payload name ("recon.google") if the registry exists
try:
    from shenron_core import payload_registry  # type: ignore[attr-defined]
except Exception:
    payload_registry = None  # type: ignore[assignment]

if payload_registry and hasattr(payload_registry, "register_payload"):

    @payload_registry.register_payload(
        name="recon.google",  # legacy name
        version="0.1.0",
        description="Compatibility alias → uses osint_google_adapter.run_adapter.",
        tags=["recon", "web", "adapter", "research-only", "compat"],
    )
    def entrypoint(context: dict[str, Any] | None = None, **kwargs: Any) -> Dict[str, Any]:
        return run_adapter(kwargs)
