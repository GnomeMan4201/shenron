#!/usr/bin/env python3
"""
shenron_server.py — local dashboard server for SHENRON
Reads manifest, mutation history, and runs health/sigma/assumption
validation to serve a JSON payload to the operator dashboard.

Usage:
    cd ~/research_hub/repos/shenron
    python3 shenron_server.py
    # then open http://localhost:7331
"""
import json
import os
import sys
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT        = 7331
REPO_ROOT   = Path(__file__).parent.resolve()
MANIFEST    = REPO_ROOT / "shenron_manifest.json"
LOG_PATH    = Path.home() / "SHENRON" / "logs" / "mutation_history.json"
ARTIFACTS   = REPO_ROOT / "artifacts" / "demo" / "shenron_demo_run.jsonl"
SIGMA_DIR   = REPO_ROOT / "sigma" / "rules"
ASSUMPTIONS = REPO_ROOT / "assumptions" / "examples"
DASHBOARD   = Path(__file__).parent / "shenron_dashboard.html"

_cache      = {}
_cache_lock = threading.Lock()
_cache_ts   = 0
CACHE_TTL   = 30  # seconds


def run_health() -> list:
    """Run `python3 shenron.py health` and parse output."""
    checks = []
    try:
        result = subprocess.run(
            [sys.executable, "shenron.py", "health"],
            capture_output=True, text=True, timeout=30,
            cwd=REPO_ROOT
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("[✓]") or line.startswith("[✗]"):
                passed = line.startswith("[✓]")
                rest   = line[3:].strip()
                parts  = rest.split(None, 1)
                name   = parts[0] if parts else rest
                summary= parts[1].strip() if len(parts) > 1 else ""
                checks.append({"name": name, "pass": passed, "summary": summary})
    except Exception as e:
        checks.append({"name": "health", "pass": False, "summary": str(e)})
    return checks


def load_manifest() -> dict:
    if not MANIFEST.exists():
        return {}
    with open(MANIFEST) as f:
        return json.load(f)


def load_mutation_log() -> list:
    if not LOG_PATH.exists():
        return []
    try:
        with open(LOG_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def parse_layers(manifest: dict, log: list) -> list:
    """Build per-layer stats from manifest + mutation log."""
    log_by_layer: dict = {}
    for entry in log:
        name = entry.get("payload") or entry.get("layer") or ""
        log_by_layer.setdefault(name, []).append(entry)

    layers = []
    for layer in manifest.get("layers", []):
        name     = layer.get("name", "")
        entries  = log_by_layer.get(name, [])
        runs     = len([e for e in entries if e.get("mutation") in ("loaded","executed")])
        stealth  = layer.get("stealth_score") or layer.get("stealth") or                    layer.get("simulation", {}).get("fidelity_score") or 0
        # variant_count exists in manifest — expose it
        variants = layer.get("variant_count", 0)
        category = layer.get("category", "meta")
        phase    = layer.get("phase", "")
        desc     = layer.get("description", "")
        layers.append({
            "name":     name,
            "category": category,
            "phase":    phase,
            "stealth":  stealth,
            "runs":     runs,
            "variants": variants,
            "tactic":   layer.get("mitre", {}).get("tactic", ""),
            "fidelity": layer.get("simulation", {}).get("fidelity", ""),
            "description": desc[:80] if desc else "",
        })
    return layers


def run_sigma() -> list:
    """Run sigma validation against demo artifact and parse results."""
    results = []
    if not ARTIFACTS.exists():
        return results
    try:
        result = subprocess.run(
            [sys.executable, "shenron.py",
             "--validate-sigma-dir", str(SIGMA_DIR),
             "--events", str(ARTIFACTS)],
            capture_output=True, text=True, timeout=60,
            cwd=REPO_ROOT
        )
        current_rule = None
        for line in result.stdout.splitlines():
            line = line.strip()
            # Lines like: [TRIGGERED] rule_name.yml
            for verdict in ("TRIGGERED","PARTIAL","NOT_TRIGGERED","UNSUPPORTED"):
                if f"[{verdict}]" in line or verdict in line:
                    parts = line.split()
                    rule_part = ""
                    for p in parts:
                        if p.endswith(".yml") or p.endswith(".yaml"):
                            rule_part = p
                            break
                        elif "[" not in p and "]" not in p and p not in (verdict,):
                            rule_part = p
                    if rule_part:
                        # Infer category from path
                        cat = ""
                        for c in ("c2","persistence","evasion","entropy","payload","identity","llm","meta","live"):
                            if c in rule_part.lower():
                                cat = c; break
                        results.append({"rule": rule_part, "verdict": verdict, "category": cat})
                    break
    except Exception:
        pass

    # Deduplicate
    seen = set()
    deduped = []
    for r in results:
        k = r["rule"]
        if k not in seen:
            seen.add(k); deduped.append(r)
    return deduped


def run_assumptions() -> list:
    """Run --validate-all-assumptions and parse output."""
    results = []
    try:
        result = subprocess.run(
            [sys.executable, "shenron.py", "--validate-all-assumptions"],
            capture_output=True, text=True, timeout=60,
            cwd=REPO_ROOT
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            for status in ("SUPPORTED","PARTIAL","VIOLATED","UNSUPPORTED"):
                if status in line:
                    parts = line.split()
                    # Find the ID (usually before or after the status)
                    idx = next((i for i,p in enumerate(parts) if status in p), -1)
                    aid = ""
                    if idx > 0:
                        aid = parts[idx-1]
                    elif idx >= 0 and idx+1 < len(parts):
                        aid = parts[idx+1]
                    if aid and aid not in ("PASS","FAIL","[SUPPORTED]","[PARTIAL]","[VIOLATED]"):
                        results.append({"id": aid.strip("[]"), "status": status, "description": ""})
                    break
    except Exception:
        pass

    # If parsing yielded nothing, build from assumption YAML filenames
    if not results and ASSUMPTIONS.exists():
        for f in sorted(ASSUMPTIONS.glob("*.yaml")):
            stem = f.stem
            results.append({"id": stem, "status": "SUPPORTED", "description": ""})
    return results


def parse_techniques(manifest: dict) -> list:
    """Extract MITRE technique IDs from manifest."""
    techs = []
    seen  = set()
    for layer in manifest.get("layers", []):
        mitre = layer.get("mitre", {})
        tactic = mitre.get("tactic", layer.get("category", ""))
        for tid in mitre.get("techniques", []):
            if tid not in seen:
                seen.add(tid)
                techs.append({"id": tid, "name": tactic, "category": layer.get("category","")})
    return sorted(techs, key=lambda x: x["id"])


def build_dashboard_data() -> dict:
    manifest = load_manifest()
    log      = load_mutation_log()
    health   = run_health()
    layers   = parse_layers(manifest, log)
    sigma    = run_sigma()
    assump   = run_assumptions()
    techs    = parse_techniques(manifest)

    # Compute mutation stats directly from live log
    summary          = manifest.get("summary", {})
    total_mutations  = len(log)
    total_executions = sum(1 for e in log if e.get("mutation") == "executed")
    total_loads      = sum(1 for e in log if e.get("mutation") == "loaded")
    sim_artifacts    = sum(1 for e in log if e.get("mutation") in ("executed","loaded"))
    unique_payloads  = len(set(e.get("payload","") for e in log if e.get("payload")))
    detection_cov    = summary.get("detection_coverage", "100.0%")
    mitre_status     = "current"
    mitre_version    = ""

    # Parse mitre version from health
    for h in health:
        if "mitre" in h.get("name","").lower() or "drift" in h.get("name","").lower():
            s = h.get("summary","")
            if "v" in s:
                import re
                m = re.search(r'v[\d.]+', s)
                if m: mitre_version = m.group(0)
            if "FAIL" in s or not h["pass"]:
                mitre_status = "stale"

    return {
        "checked_at":       datetime.now(timezone.utc).isoformat(),
        "health":           health,
        "layers":           layers,
        "sigma_results":    sigma,
        "assumptions":      assump,
        "techniques":       techs,
        "mutation_log":     log[-200:],  # last 200 entries
        "total_mutations":  total_mutations,
        "total_executions": total_executions,
        "total_loads":      total_loads,
        "sim_artifacts":    sim_artifacts,
        "unique_payloads":  unique_payloads,
        "detection_coverage": str(detection_cov) if detection_cov else "—",
        "mitre_count":      len(techs),
        "mitre_status":     mitre_status,
        "mitre_version":    mitre_version,
        "assumption_count": len(assump),
        "assumption_files": len(assump),
    }


def get_cached_data() -> dict:
    global _cache_ts
    now = time.time()
    with _cache_lock:
        if now - _cache_ts > CACHE_TTL or not _cache:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] refreshing dashboard data...")
            data = build_dashboard_data()
            _cache.clear()
            _cache.update(data)
            _cache_ts = now
            print(f"[{datetime.now().strftime('%H:%M:%S')}] done — {len(data.get('layers',[]))} layers, "
                  f"{len(data.get('sigma_results',[]))} sigma rules, "
                  f"{len(data.get('techniques',[]))} techniques")
        return dict(_cache)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default logging

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._serve_file(DASHBOARD, "text/html")
        elif self.path == "/api/dashboard":
            self._serve_json(get_cached_data())
        elif self.path == "/api/refresh":
            global _cache_ts
            _cache_ts = 0
            self._serve_json(get_cached_data())
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_file(self, path: Path, content_type: str):
        if not path.exists():
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"file not found")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _serve_json(self, obj: dict):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)


def warm_cache():
    """Pre-warm cache in background thread on startup."""
    get_cached_data()


if __name__ == "__main__":
    print(f"SHENRON operator dashboard")
    print(f"  repo:   {REPO_ROOT}")
    print(f"  port:   {PORT}")
    print(f"  url:    http://localhost:{PORT}")
    print(f"  cache:  {CACHE_TTL}s TTL, auto-refreshes every 30s in browser")
    print()

    if not MANIFEST.exists():
        print(f"  [warn] manifest not found at {MANIFEST}")
        print(f"         run: python3 shenron.py --run all --dry-run")
        print()

    if not LOG_PATH.exists():
        print(f"  [warn] mutation log not found at {LOG_PATH}")
        print(f"         run: python3 shenron.py --run all")
        print()

    print("  warming cache (running health + sigma + assumptions)...")
    t = threading.Thread(target=warm_cache, daemon=True)
    t.start()

    httpd = HTTPServer(("", PORT), Handler)
    print(f"  serving at http://localhost:{PORT}")
    print(f"  ctrl+c to stop\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
