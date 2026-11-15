"""Exfiltration upload vs routine upload: which context separates them?

Experiment (see docs/EXFIL_CONTEXT_EXPERIMENT.md):

* Positives are the transient_exfil_sim generator's own data-transfer
  events, with labels stripped.
* Negatives are routine uploads with the same existing fields, chosen to be
  hard: short-lived tools, new destinations, non-standard ports.
* Each candidate context field is added to every event, with the value the
  simulated activity would show, and tested alone as a Sigma predicate, then
  in pairs.
* Kill criterion: a candidate that cannot separate the two without
  simulator-assigned attack labels is rejected.

Run: python3 research/exfil_context.py
"""
import json
import os
import random
import sys
import tempfile
from itertools import combinations
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from core.sigma.fields import LABEL_FIELDS  # noqa: E402

# The existing transfer selection from sigma/rules/exfiltration (presence only).
BASE_SELECTION = """\
    transfer:
        remote_addr_sim|exists: true
        data_size_bytes_sim|exists: true
        socket_closed_after_sim|exists: true
"""

# One block per candidate. Each is a single context field compared by value.
CANDIDATES = {
    "remote_port_sim (existing field)": (
        "port_standard",
        """\
    port_standard:
        remote_port_sim: [21, 22, 80, 443, 990, 8443]
""",
        "not port_standard",
    ),
    "process_image_sim": (
        "shell_or_interpreter",
        """\
    shell_or_interpreter:
        process_image_sim: ['/bin/sh', '/bin/bash', '/usr/bin/python3', '/usr/bin/perl']
""",
        "shell_or_interpreter",
    ),
    "process_uptime_sec_sim < 10": (
        "just_started",
        """\
    just_started:
        process_uptime_sec_sim|re: '^[0-9](\\.[0-9]+)?$'
""",
        "just_started",
    ),
    "dest_first_seen_sim": (
        "new_destination",
        """\
    new_destination:
        dest_first_seen_sim: 'true'
""",
        "new_destination",
    ),
}

# Context the simulated transient exfil shell would show. The generator's own
# header names the behavior: an outbound connection to a non-standard port
# from a non-network process, closed right after the transfer.
POSITIVE_CONTEXT = {
    "process_image_sim": "/bin/sh",
    "process_uptime_sec_sim": 3.2,
    "dest_first_seen_sim": "true",
}

# Routine uploads. Every one has the same existing fields as the positives.
NEGATIVES = [
    ("nightly backup agent run by a timer", {"remote_port_sim": 443, "process_image_sim": "/usr/bin/restic", "process_uptime_sec_sim": 3.0, "dest_first_seen_sim": "false"}),
    ("browser form upload to a new site", {"remote_port_sim": 443, "process_image_sim": "/usr/lib/firefox/firefox", "process_uptime_sec_sim": 7200.0, "dest_first_seen_sim": "true"}),
    ("cron curl shipping logs", {"remote_port_sim": 443, "process_image_sim": "/usr/bin/curl", "process_uptime_sec_sim": 1.0, "dest_first_seen_sim": "false"}),
    ("python backup script to MinIO", {"remote_port_sim": 9000, "process_image_sim": "/usr/bin/python3", "process_uptime_sec_sim": 40.0, "dest_first_seen_sim": "false"}),
    ("developer scp to a new host", {"remote_port_sim": 22, "process_image_sim": "/usr/bin/scp", "process_uptime_sec_sim": 5.0, "dest_first_seen_sim": "true"}),
    ("CI job uploading build artifacts", {"remote_port_sim": 443, "process_image_sim": "/usr/bin/node", "process_uptime_sec_sim": 90.0, "dest_first_seen_sim": "false"}),
]


# Round 2: for each pair that separates round 1, one more plausible routine
# upload aimed at that pair. A pair that only survives hand-picked negatives
# is not evidence of a usable signal.
ADVERSARIAL = [
    ("short python job pushing to MinIO", {"remote_port_sim": 9000, "process_image_sim": "/usr/bin/python3", "process_uptime_sec_sim": 2.0, "dest_first_seen_sim": "false"}),
    ("first sync to a new MinIO bucket host", {"remote_port_sim": 9000, "process_image_sim": "/usr/bin/rclone", "process_uptime_sec_sim": 600.0, "dest_first_seen_sim": "true"}),
    ("python script posting to a new SaaS API", {"remote_port_sim": 443, "process_image_sim": "/usr/bin/python3", "process_uptime_sec_sim": 30.0, "dest_first_seen_sim": "true"}),
]


def generator_transfers(n=8, seed=7):
    """The exfil generator's own data-transfer events, labels stripped."""
    from core.layers import transient_exfil_sim as gen

    random.seed(seed)
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SHENRON_SCOPED_LOG"] = str(Path(tmp) / "x.jsonl")
        import contextlib
        import io
        while len(out) < n:
            with contextlib.redirect_stdout(io.StringIO()):
                events = gen.simulate_exfil_shell()[3]
            out += [e for e in events if e.get("phase") == "data_transfer_sim"]
        os.environ.pop("SHENRON_SCOPED_LOG", None)
    return [{k: v for k, v in e.items() if k not in LABEL_FIELDS} for e in out[:n]]


def negative_events(template):
    """Routine uploads: the template's existing fields, ordinary values."""
    events = []
    for desc, ctx in NEGATIVES:
        e = {k: v for k, v in template.items()}
        e.update(remote_addr_sim="198.51.100.20", data_shape_sim="multipart_form_sim",
                 outcome_sim="http_200_sim", socket_closed_after_sim=True)
        e.update(ctx)
        events.append((desc, e))
    return events


def rule_text(names):
    blocks = BASE_SELECTION + "".join(CANDIDATES[n][1] for n in names)
    cond = " and ".join(["transfer"] + [CANDIDATES[n][2] for n in names])
    return (
        "title: exfil context candidate\nid: exfil-context-candidate\nstatus: experimental\n"
        "logsource:\n    product: shenron\n    category: simulation\n"
        f"detection:\n{blocks}    condition: {cond}\nlevel: low\n"
    )


def fires(names, event):
    from core.sigma.evaluator import evaluate_sigma_rule

    with tempfile.TemporaryDirectory() as tmp:
        rule = Path(tmp) / "r.yml"
        rule.write_text(rule_text(names))
        art = Path(tmp) / "a.jsonl"
        art.write_text(json.dumps(event) + "\n")
        return evaluate_sigma_rule(str(rule), str(art), match_mode="strict").triggered_count > 0


def evaluate(names, positives, negatives):
    tp = sum(fires(names, e) for e in positives)
    fps = [d for d, e in negatives if fires(names, e)]
    return tp, fps


def run():
    positives = [dict(e, **POSITIVE_CONTEXT) for e in generator_transfers()]
    negatives = negative_events(positives[0])
    rows = [("existing transfer selection only", ()), *[(n, (n,)) for n in CANDIDATES]]
    rows += [(" + ".join(pair), pair) for pair in combinations(CANDIDATES, 2)]
    results = []
    for label, names in rows:
        tp, fps = evaluate(names, positives, negatives)
        results.append((label, names, tp, len(positives), fps))
    return results, positives, negatives


def run_round2(results, positives):
    adversarial = [(d, dict(positives[0], **{"remote_addr_sim": "198.51.100.20", "data_shape_sim": "multipart_form_sim", "outcome_sim": "http_200_sim"}, **ctx)) for d, ctx in ADVERSARIAL]
    survivors = [(label, names) for label, names, tp, n, fps in results if tp == n and not fps]
    return [(label, [d for d, e in adversarial if fires(names, e)]) for label, names in survivors]


if __name__ == "__main__":
    results, positives, negatives = run()
    print(f"Round 1. positives: {len(positives)} generator transfers; negatives: {len(negatives)} routine uploads\n")
    for label, names, tp, n, fps in results:
        verdict = "SEPARATES" if tp == n and not fps else "rejected"
        print(f"{verdict:9s} {label:60s} detects {tp}/{n}  false positives {len(fps)}/{len(negatives)}  {', '.join(fps)}")
    print(f"\nRound 2. {len(ADVERSARIAL)} more routine uploads against each round-1 survivor\n")
    for label, fps in run_round2(results, positives):
        print(f"{'holds' if not fps else 'BROKEN':9s} {label:60s} {', '.join(fps)}")
