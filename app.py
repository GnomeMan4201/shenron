#!/usr/bin/env python3
"""
SHENRON Dashboard — Flask backend.

Serves the React frontend (frontend/dist) and exposes JSON/SSE APIs that
wrap the REAL SHENRON Python modules.

Run from the SHENRON repo root:  python3 app.py  ->  http://localhost:5000
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Flask, Response, jsonify, request, send_from_directory,
    stream_with_context,
)

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

FRONTEND_DIST = REPO_ROOT / "frontend" / "dist"

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIST) if FRONTEND_DIST.exists() else None,
    static_url_path="",
)
app.config["JSON_SORT_KEYS"] = False


def _try_import_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        return None


def _repo_rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _run_cli(args: List[str], timeout: int = 180) -> Dict[str, Any]:
    proc = subprocess.run(
        args, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=timeout,
    )
    return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def _parse_sigma_rule(path: Path) -> Dict[str, Any]:
    yaml = _try_import_yaml()
    raw = path.read_text(encoding="utf-8", errors="replace")
    data: Dict[str, Any] = {}
    if yaml is not None:
        try:
            data = yaml.safe_load(raw) or {}
        except Exception as e:
            data = {"_parse_error": str(e)}
    else:
        def grab(key):
            m = re.search(rf"^{key}:\s*(.+)$", raw, re.MULTILINE)
            return m.group(1).strip().strip('"').strip("'") if m else None
        data = {"title": grab("title"), "id": grab("id"), "description": grab("description"),
                "level": grab("level"), "status": grab("status")}
    tags = data.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    return {
        "name": data.get("title") or path.stem,
        "id": data.get("id", ""),
        "path": _repo_rel(path),
        "category": path.parent.name,
        "description": data.get("description", "") or "",
        "level": data.get("level", "") or "",
        "status": data.get("status", "") or "",
        "tags": tags,
        "logsource": data.get("logsource", {}) or {},
        "detection": data.get("detection", {}) or {},
        "raw": raw,
    }


def list_sigma_rules() -> List[Dict[str, Any]]:
    rules_dir = REPO_ROOT / "sigma" / "rules"
    if not rules_dir.exists():
        return []
    out = []
    for p in sorted(rules_dir.rglob("*.yml")):
        try:
            out.append(_parse_sigma_rule(p))
        except Exception as e:
            out.append({"name": p.stem, "path": _repo_rel(p), "category": p.parent.name, "error": str(e)})
    return out


def _score_rule_direct(rule_path: str) -> Optional[Dict[str, Any]]:
    try:
        from core.sigma.evaluator import evaluate_sigma_rule
    except Exception:
        return None

    full = REPO_ROOT / rule_path
    artifact = REPO_ROOT / "artifacts" / "demo" / "shenron_demo_run.jsonl"
    if not artifact.exists():
        return None

    try:
        eval_result = evaluate_sigma_rule(str(full), str(artifact), match_mode="tolerant")
    except Exception as e:
        return {"rule_path": rule_path, "error": f"evaluate_sigma_rule raised: {e}", "traceback": traceback.format_exc()}

    score = None
    try:
        from core.cli.commands.validate import _score_brittleness
        score = _score_brittleness(str(full), str(artifact))
    except Exception:
        pass

    triggered = False
    try:
        from core.sigma.model import RuleVerdict
        triggered = eval_result.verdict == RuleVerdict.TRIGGERED
    except Exception:
        pass

    return {
        "rule_path": rule_path,
        "triggered": triggered,
        "triggered_count": getattr(eval_result, "triggered_count", 0),
        "verdict": getattr(eval_result, "verdict", None),
        "brittleness": score,
        "_source": "direct_evaluator",
    }


def _score_rule_via_cli(rule_path: str) -> Dict[str, Any]:
    rule_full = REPO_ROOT / rule_path
    res = _run_cli(
        ["python3", "shenron.py", "validate", "--rules", str(rule_full.parent), "--format", "json"],
        timeout=120,
    )
    if res["returncode"] in (0, 2) and res["stdout"].strip():
        try:
            payload = json.loads(res["stdout"])
            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict) and rule_path in (item.get("rule_path", ""), item.get("path", "")):
                        return {"rule_path": rule_path, **item, "_source": "cli_fallback"}
                if payload:
                    return {"rule_path": rule_path, **payload[0], "_source": "cli_fallback"}
        except json.JSONDecodeError:
            pass
    return {"rule_path": rule_path, "error": "CLI fallback failed", "stdout": res["stdout"][:2000], "stderr": res["stderr"][:2000], "returncode": res["returncode"]}


def score_rule(rule_path: str) -> Dict[str, Any]:
    direct = _score_rule_direct(rule_path)
    if direct is not None:
        return direct
    return _score_rule_via_cli(rule_path)


@app.route("/api/health")
def api_health():
    return jsonify({
        "ok": True,
        "repo_root": str(REPO_ROOT),
        "rules_count": len(list_sigma_rules()),
        "shenron_py": (REPO_ROOT / "shenron.py").exists(),
        "core_dir": (REPO_ROOT / "core").exists(),
        "taxonomy": (REPO_ROOT / "taxonomy" / "mitre_mappings.json").exists(),
        "demo_artifact": (REPO_ROOT / "artifacts" / "demo" / "shenron_demo_run.jsonl").exists(),
        "frontend_dist": FRONTEND_DIST.exists(),
        "python": sys.version.split()[0],
    })


@app.route("/api/rules")
def api_rules():
    return jsonify({"rules": list_sigma_rules()})


@app.route("/api/validate", methods=["POST", "GET"])
def api_validate():
    if request.method == "GET":
        return jsonify({"method": "POST", "description": "Stream brittleness scoring via SSE."})

    body = request.get_json(silent=True) or {}
    rule_paths = body.get("rule_paths")
    all_rules = list_sigma_rules()
    targets = [r for r in all_rules if r["path"] in rule_paths] if rule_paths else all_rules

    def stream():
        total = len(targets)
        yield f"event: start\ndata: {json.dumps({'total': total})}\n\n"
        for i, rule in enumerate(targets):
            yield f"event: progress\ndata: {json.dumps({'index': i, 'total': total, 'rule_path': rule['path'], 'rule_name': rule['name']})}\n\n"
            t0 = time.time()
            try:
                result = score_rule(rule["path"])
                result["rule_name"] = rule["name"]
                result["rule_id"] = rule.get("id", "")
                result["duration_ms"] = int((time.time() - t0) * 1000)
                yield f"event: result\ndata: {json.dumps(result, default=str)}\n\n"
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'rule_path': rule['path'], 'rule_name': rule['name'], 'error': str(e), 'traceback': traceback.format_exc()}, default=str)}\n\n"
        yield "event: done\ndata: {}\n\n"

    return Response(
        stream_with_context(stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.route("/api/artifact")
def api_artifact():
    rel = request.args.get("path", "artifacts/demo/shenron_demo_run.jsonl")
    p = (REPO_ROOT / rel).resolve()
    try:
        p.relative_to(REPO_ROOT)
    except ValueError:
        return jsonify({"error": "path must be inside repo"}), 400
    if not p.exists():
        return jsonify({"error": f"file not found: {rel}"}), 404

    events = []
    errors = []
    for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            errors.append({"line": i, "error": str(e), "snippet": line[:200]})

    rules = list_sigma_rules()
    technique_rules: Dict[str, List[str]] = {}
    for r in rules:
        for tag in r.get("tags", []) or []:
            if isinstance(tag, str) and re.match(r"^attack\.t\d+", tag, re.I):
                tid = tag.split(".")[-1].upper()
                technique_rules.setdefault(tid, []).append(r["name"])

    for ev in events:
        techs = ev.get("mitre_techniques") or []
        matched = []
        for t in techs:
            for rname in technique_rules.get(str(t).upper(), []):
                if rname not in matched:
                    matched.append(rname)
        ev["_matched_rules"] = matched

    return jsonify({"path": rel, "count": len(events), "events": events, "errors": errors, "technique_rules": technique_rules})


@app.route("/api/scenarios")
def api_scenarios():
    res = _run_cli(["python3", "shenron.py", "compare-scenarios", "--format", "json"], timeout=300)
    if res["returncode"] not in (0, 1, 2):
        return jsonify({"error": "compare-scenarios failed", "returncode": res["returncode"], "stdout": res["stdout"][:4000], "stderr": res["stderr"][:4000]}), 500
    try:
        payload = json.loads(res["stdout"])
        return jsonify(payload)
    except json.JSONDecodeError:
        return jsonify({"error": "invalid JSON from compare-scenarios", "stdout": res["stdout"][:4000]}), 500


@app.route("/api/drift")
def api_drift():
    res = _run_cli(["python3", "-m", "core.ci.drift_gate", "--quiet"], timeout=120)
    verdict_map = {0: "pass", 1: "warn", 2: "fail"}
    return jsonify({
        "verdict": verdict_map.get(res["returncode"], f"unknown({res['returncode']})"),
        "returncode": res["returncode"],
        "stdout": res["stdout"],
        "stderr": res["stderr"],
    })


@app.route("/api/mitre")
def api_mitre():
    tax_path = REPO_ROOT / "taxonomy" / "mitre_mappings.json"
    taxonomy = {}
    if tax_path.exists():
        try:
            taxonomy = json.loads(tax_path.read_text(encoding="utf-8"))
        except Exception as e:
            taxonomy = {"_parse_error": str(e)}

    rules = list_sigma_rules()
    technique_rules: Dict[str, List[str]] = {}
    technique_tactics: Dict[str, str] = {}
    for r in rules:
        tac = None
        for tag in r.get("tags", []) or []:
            if isinstance(tag, str) and tag.startswith("attack.") and not re.match(r"^attack\.t\d", tag, re.I):
                tac = tag.replace("attack.", "").replace("_", "-")
        for tag in r.get("tags", []) or []:
            if isinstance(tag, str) and re.match(r"^attack\.t\d", tag, re.I):
                tid = tag.split(".")[-1].upper()
                technique_rules.setdefault(tid, []).append(r["path"])
                if tac and tid not in technique_tactics:
                    technique_tactics[tid] = tac

    return jsonify({
        "taxonomy": taxonomy,
        "technique_rules": technique_rules,
        "technique_tactics": technique_tactics,
        "rules": [{"name": r["name"], "path": r["path"], "tags": r.get("tags", [])} for r in rules],
    })


@app.route("/api/adaptation", methods=["POST", "GET"])
def api_adaptation():
    if request.method == "GET":
        return jsonify({"method": "POST", "description": "Run adversary adaptation loop via SSE."})

    body = request.get_json(silent=True) or {}
    max_iterations = body.get("max_iterations", 8)
    q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

    def worker():
        try:
            from core.campaign.adaptation import run_adaptation, AdaptationReport
            import inspect
            sig = inspect.signature(run_adaptation)
            params = sig.parameters

            artifact = str(REPO_ROOT / "artifacts" / "demo" / "shenron_demo_run.jsonl")
            rules_dirs = [str(REPO_ROOT / "sigma" / "rules")]

            kwargs: Dict[str, Any] = {}
            if "artifact_path" in params:
                kwargs["artifact_path"] = artifact
            if "rules_dirs" in params:
                kwargs["rules_dirs"] = rules_dirs
            if "max_iterations" in params:
                kwargs["max_iterations"] = int(max_iterations)
            if "verbose" in params:
                kwargs["verbose"] = False

            result = run_adaptation(**kwargs)

            if isinstance(result, AdaptationReport):
                for it in result.iterations:
                    q.put(("iteration", {
                        "iteration": it.iteration,
                        "strategy": it.mutation_applied,
                        "rules_firing_count": it.rules_fired_count,
                        "evasion_rate": it.evasion_rate,
                        "artifact_event_count": it.artifact_event_count,
                    }))
                q.put(("done", {
                    "evasion_achieved": result.evasion_achieved,
                    "iterations_to_evasion": result.iterations_to_evasion,
                    "surviving_rules": result.surviving_rules,
                    "evaded_rules": result.evaded_rules,
                    "adaptation_path": result.adaptation_path,
                }))
            else:
                q.put(("done", {"result": str(result)[:500]}))
        except Exception as e:
            q.put(("error", {"error": str(e), "traceback": traceback.format_exc()}))

    threading.Thread(target=worker, daemon=True).start()

    def stream():
        start = time.time()
        while True:
            try:
                event_type, data = q.get(timeout=5)
                yield f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"
                if event_type in ("done", "error"):
                    break
            except queue.Empty:
                yield f"event: ping\ndata: {json.dumps({'elapsed_s': int(time.time() - start)})}\n\n"

    return Response(
        stream_with_context(stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.route("/")
def index():
    if not FRONTEND_DIST.exists():
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>SHENRON</title>"
            "<style>body{background:#0b0f17;color:#e8ecf3;font-family:system-ui;padding:40px;}"
            "code{background:#1a2235;padding:2px 6px;border-radius:3px;}</style></head>"
            "<body><h1>SHENRON dashboard — frontend not built yet</h1>"
            "<p>API is live. To build the UI:</p>"
            "<pre><code>cd frontend\nnpm install\nnpm run build</code></pre>"
            "<p>API endpoints: <code>/api/health</code> <code>/api/rules</code> "
            "<code>/api/artifact</code> <code>/api/scenarios</code> "
            "<code>/api/drift</code> <code>/api/mitre</code></p>"
            "</body></html>",
            200, {"Content-Type": "text/html; charset=utf-8"},
        )
    return send_from_directory(str(FRONTEND_DIST), "index.html")


@app.route("/<path:path>")
def static_proxy(path: str):
    if FRONTEND_DIST.exists():
        full = FRONTEND_DIST / path
        if full.exists() and full.is_file():
            return send_from_directory(str(FRONTEND_DIST), path)
        return send_from_directory(str(FRONTEND_DIST), "index.html")
    return jsonify({"error": "frontend not built"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  SHENRON dashboard -> http://localhost:{port}")
    print(f"  repo_root = {REPO_ROOT}")
    print(f"  frontend  = {'built' if FRONTEND_DIST.exists() else 'NOT built (cd frontend && npm install && npm run build)'}\n")
    app.run(host="0.0.0.0", port=port, threaded=True, debug=False)
