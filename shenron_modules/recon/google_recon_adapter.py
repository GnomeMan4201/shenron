from __future__ import annotations

import os
import sys
import time
import zipfile
import subprocess
from pathlib import Path
from typing import Dict, Any

# NOTE: this decorator is assumed to exist in your core.
# If your project uses a different import path, update it here.
try:
    from shenron_core import payload_registry  # type: ignore
except Exception:  # pragma: no cover
    payload_registry = None

VENDOR_REL = Path("shenron_modules/recon/vendor/google_recon_raw.py")
LOG_DIR = Path.home() / "SHENRON" / "logs"
OUT_DIR = Path.home() / "SHENRON" / "output"
LOG_DIR.mkdir(parents=True, exist_ok=True)
OUT_DIR.mkdir(parents=True, exist_ok=True)


def _timestamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def _zip_dir(src: Path, dest_zip: Path) -> None:
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in src.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(src))


def run_adapter(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adapter that executes the vendor recon script as a subprocess.

    Expected params (all optional with sensible defaults):
      - query: str           (default: "site:example.com")
      - depth: int           (default: 1)
      - max_pages: int       (default: 10)
      - user_agent: str      (default: "shenron-research/0.1")
    """
    vendor_path = (Path.cwd() / VENDOR_REL).resolve()
    if not vendor_path.exists():
        raise FileNotFoundError(f"Vendor script not found: {vendor_path}")

    query = str(params.get("query", "site:example.com"))
    depth = int(params.get("depth", 1))
    max_pages = int(params.get("max_pages", 10))
    ua = str(params.get("user_agent", "shenron-research/0.1"))

    ts = _timestamp()
    run_dir = OUT_DIR / f"google_recon_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"google_recon_{ts}.log"

    # Environment passthrough for the vendor script (if it reads env instead of args)
    env = os.environ.copy()
    env["SHENRON_UA"] = ua
    env["SHENRON_OUTDIR"] = str(run_dir)

    # Build a conservative argv; if the vendor script expects stdin/input(),
    # we still run it—if it supports CLI args, it can read these.
    argv = [
        sys.executable,
        str(vendor_path),
        "--query",
        query,
        "--depth",
        str(depth),
        "--max-pages",
        str(max_pages),
        "--out",
        str(run_dir),
        "--user-agent",
        ua,
    ]

    # If the raw script doesn't support those flags, it should ignore them or we’ll
    # fall back to input() prompts; either way, we capture stdout/err to the log.
    with open(log_file, "wb") as lf:
        proc = subprocess.run(
            argv,
            env=env,
            cwd=str(Path.cwd()),
            stdout=lf,
            stderr=subprocess.STDOUT,
            check=False,
        )
        rc = proc.returncode

    # Zip artifacts even if rc != 0 to keep parity/logs
    zip_path = OUT_DIR / f"google_recon_{ts}.zip"
    _zip_dir(run_dir, zip_path)

    return {
        "ok": rc == 0,
        "returncode": rc,
        "log_file": str(log_file),
        "out_dir": str(run_dir),
        "zip_path": str(zip_path),
        "params": {"query": query, "depth": depth, "max_pages": max_pages, "user_agent": ua},
    }


# ---- SHENRON registration (no-op if registry unavailable during tests) ----
def _register():
    if payload_registry and hasattr(payload_registry, "register_payload"):

        @payload_registry.register_payload(
            name="recon.google",
            version="0.1.0",
            description="Google/web recon adapter (executes vendor script in a sandboxed subprocess). "
            "Use only in authorized lab environments.",
            tags=["recon", "web", "adapter", "research-only"],
        )
        def entrypoint(context: dict[str, Any] | None = None, **kwargs: Any) -> Dict[str, Any]:
            # You can plumb SHENRON context into params if needed:
            # e.g., org_id = context.get("org_id") if context else None
            return run_adapter(kwargs)
    else:
        # Allow import/use in isolation (e.g., tests) without registry.
        pass


_register()
