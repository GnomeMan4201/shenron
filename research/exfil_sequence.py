"""Does the cross-event exfil pattern separate exfiltration from routine activity?

Follows docs/EXFIL_CONTEXT_EXPERIMENT.md, which found that no context on the
upload event alone separates the two. The generator's behavior spans three
events sharing one port:

    one-shot listener binds port X  ->  data goes out to remote port X  ->  X released

This tests that pattern as a correlation over events, before building
correlation support into the evaluator. Same rules as before: no simulator
attack labels, matched negatives, then one more round of negatives aimed at
whatever survives. Write-up: docs/EXFIL_SEQUENCE_EXPERIMENT.md.

Correlation key: session_id, standing in for "same process on the same host".
Real telemetry would correlate on host and process ID.

Run: python3 research/exfil_sequence.py
"""
import contextlib
import io
import os
import random
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from core.sigma.fields import LABEL_FIELDS  # noqa: E402

WINDOW_SEC = 60
LOOPBACK = ("127.", "localhost", "::1")


def _ts(e):
    return datetime.fromisoformat(e["timestamp"])


def _loopback(addr):
    return str(addr).startswith(LOOPBACK)


# Pattern elements. Each variant drops one, to see which ones carry the signal.
FULL = {"one_shot", "same_port", "non_loopback", "release"}
VARIANTS = {
    "full pattern": FULL,
    "without one-shot listener check": FULL - {"one_shot"},
    "without same-port link": FULL - {"same_port"},
    "without loopback exclusion": FULL - {"non_loopback"},
    "without port release": FULL - {"release"},
}


def matches(events, require):
    """True if one session shows listener -> outbound transfer -> release."""
    sessions = {}
    for e in events:
        sessions.setdefault(e.get("session_id"), []).append(e)
    for evs in sessions.values():
        evs = sorted(evs, key=_ts)
        listeners = [e for e in evs if "port_sim" in e and "lifecycle_sim" in e]
        transfers = [e for e in evs if "remote_port_sim" in e]
        releases = [e for e in evs if "port_released_sim" in e]
        for lst in listeners:
            if "one_shot" in require and not (lst.get("lifecycle_sim") == "one_shot" and lst.get("listen_backlog_sim") == 1):
                continue
            port, t0 = lst["port_sim"], _ts(lst)
            for tr in transfers:
                dt = (_ts(tr) - t0).total_seconds()
                if not 0 <= dt <= WINDOW_SEC:
                    continue
                if "same_port" in require and tr["remote_port_sim"] != port:
                    continue
                if "non_loopback" in require and _loopback(tr.get("remote_addr_sim", "")):
                    continue
                if "release" not in require:
                    return True
                if any(r["port_released_sim"] == port and 0 <= (_ts(r) - _ts(tr)).total_seconds() <= WINDOW_SEC
                       for r in releases):
                    return True
    return False


def generator_sequences(n=8, seed=11):
    """The exfil generator's own 3-event sequences, labels stripped."""
    from core.layers import transient_exfil_sim as gen

    random.seed(seed)
    seqs = []
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SHENRON_SCOPED_LOG"] = str(Path(tmp) / "x.jsonl")
        for _ in range(n):
            with contextlib.redirect_stdout(io.StringIO()):
                events = gen.simulate_exfil_shell()[3]
            seqs.append([{k: v for k, v in e.items() if k not in LABEL_FIELDS} for e in events])
        os.environ.pop("SHENRON_SCOPED_LOG", None)
    return seqs


_T0 = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)


def _ev(session, sec, **fields):
    return dict(session_id=session, timestamp=(_T0 + timedelta(seconds=sec)).isoformat(), **fields)


def _listener(s, sec, port, bind="0.0.0.0", lifecycle="one_shot", backlog=1):
    return _ev(s, sec, port_sim=port, bind_addr_sim=bind, lifecycle_sim=lifecycle, listen_backlog_sim=backlog)


def _transfer(s, sec, addr, port):
    return _ev(s, sec, remote_addr_sim=addr, remote_port_sim=port, data_size_bytes_sim=2048, socket_closed_after_sim=True)


def _release(s, sec, port):
    return _ev(s, sec, port_released_sim=port, cleanup_delay_sim=0.5)


# Routine activity that shares parts of the pattern.
NEGATIVES = [
    ("CI test server on loopback", [_listener("ci", 0, 51001, bind="127.0.0.1"), _transfer("ci", 1, "127.0.0.1", 51001), _release("ci", 2, 51001)]),
    ("Syncthing: persistent listener, peers on the same port", [_listener("sync", 0, 22000, lifecycle="persistent", backlog=128), _transfer("sync", 5, "198.51.100.7", 22000)]),
    ("FTP active-mode client data channel", [_listener("ftp", 0, 52010), _transfer("ftp", 1, "198.51.100.9", 21), _release("ftp", 3, 52010)]),
    ("CLI login: one-shot OAuth callback listener", [_listener("oauth", 0, 53111, bind="127.0.0.1"), _transfer("oauth", 4, "203.0.113.30", 443), _release("oauth", 6, 53111)]),
    ("coincidental port match across two processes", [_listener("ftpA", 0, 54321), _transfer("uploadB", 2, "198.51.100.40", 54321), _release("ftpA", 3, 54321)]),
    ("routine HTTPS upload, no listener", [_transfer("up", 0, "203.0.113.10", 443)]),
]

# Round 2: aimed at the full pattern.
ADVERSARIAL = [
    ("UDP hole punch: one-shot socket, peer on the same port", [_listener("p2p", 0, 41641), _transfer("p2p", 1, "198.51.100.77", 41641), _release("p2p", 2, 41641)]),
]


def attacker_variants(seq):
    """Exfiltration the pattern should still catch, varied the way an attacker could."""
    lst, tr, rel = (dict(e) for e in seq)
    out = {}
    tr2 = dict(tr, remote_port_sim=443)
    out["sends to 443 instead of the listener port"] = [lst, tr2, rel]
    out["keeps the port open (no release)"] = [lst, tr]
    lst3 = dict(lst, listen_backlog_sim=5)
    out["listener backlog 5 instead of 1"] = [lst3, tr, rel]
    late = dict(tr, timestamp=(_ts(lst) + timedelta(seconds=WINDOW_SEC + 30)).isoformat())
    late_rel = dict(rel, timestamp=(_ts(late) + timedelta(seconds=1)).isoformat())
    out[f"waits {WINDOW_SEC + 30}s before sending"] = [lst, late, late_rel]
    return out


def run():
    positives = generator_sequences()
    table = []
    for name, require in VARIANTS.items():
        tp = sum(matches(s, require) for s in positives)
        fps = [d for d, s in NEGATIVES if matches(s, require)]
        table.append((name, tp, len(positives), fps))
    round2 = [d for d, s in ADVERSARIAL if matches(s, FULL)]
    # Evasion is measured for the full pattern and for the minimal one
    # (only the elements round 1 showed carry signal).
    patterns = {"full pattern": FULL, "minimal: same port + non-loopback": {"same_port", "non_loopback"}}
    evasions = {}
    for pname, require in patterns.items():
        for seq in positives:
            for desc, varied in attacker_variants(seq).items():
                evasions.setdefault(pname, {}).setdefault(desc, 0)
                evasions[pname][desc] += not matches(varied, require)
    minimal_fps = [d for d, s in NEGATIVES + ADVERSARIAL if matches(s, patterns["minimal: same port + non-loopback"])]
    return positives, table, round2, evasions, minimal_fps


if __name__ == "__main__":
    positives, table, round2, evasions, minimal_fps = run()
    print(f"Round 1. positives: {len(positives)} generator sequences; negatives: {len(NEGATIVES)} routine sequences\n")
    for name, tp, n, fps in table:
        print(f"{name:34s} detects {tp}/{n}  false positives {len(fps)}/{len(NEGATIVES)}  {', '.join(fps)}")
    print(f"\nRound 2 against the full pattern: {', '.join(round2) or 'no false positives'}")
    print(f"\nMinimal pattern false positives (all {len(NEGATIVES) + len(ADVERSARIAL)} negatives): {', '.join(minimal_fps) or 'none'}")
    print(f"\nAttacker variation: of {len(positives)} sequences, how many each pattern misses")
    for pname, rows in evasions.items():
        print(f"  {pname}")
        for desc, missed in rows.items():
            print(f"    {desc:45s} missed {missed}/{len(positives)}")
