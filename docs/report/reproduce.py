"""Reproduce the numbers in docs/report/index.html.

Run from the root of a SHENRON checkout at the commit you want to test:

    PYTHONHASHSEED=1 python3 docs/report/reproduce.py

It prints, in a stable order:
  1. which rules fire on artifacts/demo/shenron_demo_run.jsonl, with hit
     counts and the per-rule mutation score (POST /api/validate);
  2. the eight adaptive mutation rounds (POST /api/adaptation);
  3. overall brittleness per scenario (ScenarioComparator, as used by
     `shenron.py compare-scenarios`).

Nothing is written outside the checkout's own log directories. Expected
output for each commit is listed in docs/report/VERIFICATION.md.
"""
import contextlib
import io
import json
import os
import sys

sys.path.insert(0, os.getcwd())


def sse(resp):
    events = []
    for raw in resp.get_data(as_text=True).split("\n\n"):
        name, data = "message", ""
        for line in raw.split("\n"):
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data += line[5:].strip()
        if data:
            events.append((name, json.loads(data)))
    return events


def main():
    with contextlib.redirect_stdout(io.StringIO()):
        import app as dashboard
    client = dashboard.app.test_client()

    print("== Rules that fire on the demo events")
    with contextlib.redirect_stdout(io.StringIO()):
        results = [d for n, d in sse(client.post("/api/validate", json={})) if n == "result"]
    fired = [r for r in results if r["verdict"] == "TRIGGERED"]
    print(f"{len(fired)} of {len(results)} rules fired")
    for r in sorted(fired, key=lambda r: r["rule_path"]):
        print(f"  {r['rule_path']}  hits={r.get('triggered_count')}  mutation_score={r.get('brittleness')}")

    print("== Adaptive mutation rounds")
    with contextlib.redirect_stdout(io.StringIO()):
        adapt = sse(client.post("/api/adaptation", json={"max_iterations": 8}))
    for name, d in adapt:
        if name == "iteration":
            print(f"  round {d['iteration']}: {d['strategy']}  firing={d['rules_firing_count']}  evasion_rate={d['evasion_rate']}")
    done = [d for n, d in adapt if n == "done"][0]
    print("  still firing:", sorted(done["surviving_rules"]))
    print("  evaded:", sorted(done["evaded_rules"]))

    print("== Scenario brittleness")
    from core.campaign.comparator import ScenarioComparator
    with contextlib.redirect_stdout(io.StringIO()):
        report = ScenarioComparator("sigma/rules").run_all(persist=False)
    for s in sorted(report.scenarios, key=lambda s: s.scenario_name):
        print(f"  {s.scenario_name}: {s.overall_brittleness:.2f}")


if __name__ == "__main__":
    main()
