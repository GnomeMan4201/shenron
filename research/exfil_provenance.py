"""Can process lineage and data provenance tell exfiltration from a routine upload?

Follows docs/EXFIL_CONTEXT_EXPERIMENT.md and docs/EXFIL_SEQUENCE_EXPERIMENT.md,
which found that network events alone can't. This adds two kinds of
label-free evidence to otherwise identical sequences:

* lineage: which process started the sender, and its ancestors;
* provenance: which file the sender read before sending.

Every case has the same network transfer (same addresses, port, size,
timing). Only the process tree and the file read differ.

Rounds:
 1. one exfiltration sequence vs its routine twin;
 2. routine twins that preserve the suspicious relationship;
 3. attacker variations that change what the predicates read.

Kill criterion: if lineage and provenance can't separate the matched cases
without attack labels or arbitrary generator conventions, reject this
evidence model before building it into SHENRON.

Run: python3 research/exfil_provenance.py
Write-up: docs/EXFIL_PROVENANCE_EXPERIMENT.md
"""
from dataclasses import dataclass, field
from typing import Dict, List

# Values are what real telemetry shows (image paths, file paths), not
# SHENRON-specific names, so a predicate can't key on a generator convention.
NETWORK_FACING = {"/usr/sbin/nginx", "/usr/sbin/apache2", "/usr/sbin/php-fpm8.2", "/usr/sbin/sshd", "/usr/bin/node"}
SHELLS = {"/bin/sh", "/bin/bash", "/usr/bin/python3", "/usr/bin/perl"}
CREDENTIAL_PATHS = ("/etc/shadow", "/.ssh/id_", "/.aws/credentials", "/etc/ssl/private/", "wp-config.php", "/.env")

# Identical network transfer for every case.
TRANSFER = {"remote_addr_sim": "203.0.113.25", "remote_port_sim": 443, "data_size_bytes_sim": 4096, "socket_closed_after_sim": True}


@dataclass
class Case:
    name: str
    tree: List[str]                 # process images, root first; the last one sends
    reads: List[str] = field(default_factory=list)   # files the sender reads before sending
    reader_is_sender: bool = True   # False: an earlier process reads and stages the data

    def events(self) -> List[Dict]:
        """Label-free event stream: process starts, file reads, the transfer."""
        evs, parent = [], None
        for pid, image in enumerate(self.tree, start=100):
            evs.append({"event_sim": "process_start", "process_id_sim": pid, "parent_process_id_sim": parent, "process_image_sim": image})
            parent = pid
        sender = parent
        reader = sender if self.reader_is_sender else sender - 1
        for path in self.reads:
            evs.append({"event_sim": "file_read", "process_id_sim": reader, "file_path_sim": path})
        evs.append({"event_sim": "network_send", "process_id_sim": sender, **TRANSFER})
        return evs


def _ancestry(evs, pid):
    images, parents = {}, {}
    for e in evs:
        if e["event_sim"] == "process_start":
            images[e["process_id_sim"]] = e["process_image_sim"]
            parents[e["process_id_sim"]] = e["parent_process_id_sim"]
    chain = []
    while pid is not None:
        chain.append(images[pid])
        pid = parents[pid]
    return chain  # sender first


def lineage(evs) -> bool:
    """Sender is a shell/interpreter descended from a network-facing service."""
    send = next(e for e in evs if e["event_sim"] == "network_send")
    chain = _ancestry(evs, send["process_id_sim"])
    return any(c in SHELLS for c in chain) and any(c in NETWORK_FACING for c in chain[1:])


def provenance(evs) -> bool:
    """The sending process read a credential-class file before sending."""
    send = next(e for e in evs if e["event_sim"] == "network_send")
    return any(e["event_sim"] == "file_read" and e["process_id_sim"] == send["process_id_sim"]
               and any(p in e["file_path_sim"] for p in CREDENTIAL_PATHS) for e in evs)


PREDICATES = {
    "lineage": lineage,
    "provenance": provenance,
    "lineage + provenance": lambda evs: lineage(evs) and provenance(evs),
}

# Round 1: the exfiltration sequence and its routine twin.
EXFIL = Case("exfiltration from a compromised web server",
             ["/sbin/init", "/usr/sbin/nginx", "/bin/sh", "/usr/bin/python3"],
             ["/root/.aws/credentials", "/etc/shadow"])
TWIN = Case("nightly backup agent upload",
            ["/sbin/init", "/usr/lib/systemd/systemd", "/usr/bin/restic"],
            ["/var/backups/app-db.sql"])

# Round 2: routine activity that keeps the suspicious relationship.
PRESERVING = [
    Case("admin over SSH copies a server key to a new host",
         ["/sbin/init", "/usr/sbin/sshd", "/bin/bash", "/usr/bin/python3"], ["/etc/ssl/private/server.key"]),
    Case("WordPress backup plugin uploads site config",
         ["/sbin/init", "/usr/sbin/php-fpm8.2", "/bin/sh", "/usr/bin/python3"], ["/var/www/html/wp-config.php"]),
    Case("full-system backup includes /etc/shadow",
         ["/sbin/init", "/usr/lib/systemd/systemd", "/usr/bin/restic"], ["/etc/shadow"]),
    Case("Node app shells out to upload its .env to a secrets manager",
         ["/sbin/init", "/usr/bin/node", "/bin/sh", "/usr/bin/python3"], ["/srv/app/.env"]),
]

# Round 3: the attacker changes what the predicates read.
ATTACKER = [
    Case("persists via cron, so no network-facing ancestor",
         ["/sbin/init", "/usr/sbin/cron", "/bin/sh", "/usr/bin/python3"], ["/root/.aws/credentials"]),
    Case("stages: one process copies the secrets, another sends them",
         ["/sbin/init", "/usr/sbin/nginx", "/bin/sh", "/usr/bin/python3"], ["/root/.aws/credentials"], reader_is_sender=False),
    Case("renames the interpreter to look like a service",
         ["/sbin/init", "/usr/sbin/nginx", "/usr/sbin/nginx-worker", "/usr/lib/systemd/systemd-resolved"], ["/root/.aws/credentials"]),
]


def run():
    r1 = {p: (f(EXFIL.events()), f(TWIN.events())) for p, f in PREDICATES.items()}
    r2 = {p: [c.name for c in PRESERVING if f(c.events())] for p, f in PREDICATES.items()}
    r3 = {p: [c.name for c in ATTACKER if not f(c.events())] for p, f in PREDICATES.items()}
    return r1, r2, r3


# Information limit (the cheapest test that could invalidate "this is a
# heuristic failure, not a missing-information problem"): two event
# histories that are identical as inputs, with different authorization
# outcomes held outside the input. Any detector that only sees the events
# must return the same verdict for both, so it is wrong on at least one.
SAME_HISTORY = Case("SSH session copies a server key to a new host",
                    ["/sbin/init", "/usr/sbin/sshd", "/bin/bash", "/usr/bin/python3"],
                    ["/etc/ssl/private/server.key"])
AUTHORIZATION_OUTCOMES = {
    "authorized: on-call admin migrating the service": False,   # should not alert
    "unauthorized: attacker with a stolen SSH key": True,       # should alert
}


def information_limit(detectors=None):
    """Verdicts each detector gives the two outcomes, and whether it can be right on both."""
    detectors = detectors or PREDICATES
    histories = {outcome: SAME_HISTORY.events() for outcome in AUTHORIZATION_OUTCOMES}
    identical = len({repr(h) for h in histories.values()}) == 1
    rows = {}
    for name, f in detectors.items():
        verdicts = {o: f(h) for o, h in histories.items()}
        correct = sum(verdicts[o] == should for o, should in AUTHORIZATION_OUTCOMES.items())
        rows[name] = (verdicts, correct)
    return identical, rows


if __name__ == "__main__":
    r1, r2, r3 = run()
    print("Round 1: exfiltration vs its routine twin (identical network transfer)")
    for p, (e, t) in r1.items():
        print(f"  {p:22s} exfil={'fires' if e else 'quiet'}  twin={'fires' if t else 'quiet'}  {'SEPARATES' if e and not t else ''}")
    print(f"\nRound 2: {len(PRESERVING)} routine cases that keep the suspicious relationship")
    for p, fps in r2.items():
        print(f"  {p:22s} false positives {len(fps)}/{len(PRESERVING)}: {', '.join(fps)}")
    print(f"\nRound 3: {len(ATTACKER)} attacker variations (missed)")
    for p, missed in r3.items():
        print(f"  {p:22s} missed {len(missed)}/{len(ATTACKER)}: {', '.join(missed)}")
    identical, rows = information_limit()
    print(f"\nInformation limit: identical event histories as input: {identical}")
    for p, (verdicts, correct) in rows.items():
        print(f"  {p:22s} same verdict for both: {len(set(verdicts.values())) == 1}  correct on {correct}/2")
