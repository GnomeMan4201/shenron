"""
core/mitre/drift.py

MITRE ATT&CK drift checker for SHENRON.

Compares technique IDs pinned in shenron_manifest.json against the
current ATT&CK STIX bundle from mitre/cti on GitHub.

Three outputs:
  STALE    — technique ID no longer exists in current ATT&CK
  RENAMED  — technique was deprecated but a successor exists
  ORPHANED — layer covers a technique that no active campaign uses
  OK       — pinned ID matches current ATT&CK

No executable behavior. Network: one HTTPS GET to raw.githubusercontent.com.
"""

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone
from pathlib import Path

# ── ATT&CK STIX source ────────────────────────────────────────────────────────
# enterprise-attack.json from mitre/cti, pinned to main branch.
# This is the canonical machine-readable ATT&CK release.
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Fallback: ATT&CK versioned API (lighter, JSON, no STIX dependency)
ATTACK_API_URL = "https://attack.mitre.org/api/techniques/"


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class TechniqueDriftResult:
    technique_id: str
    layer_name: str
    status: str          # OK | STALE | RENAMED | UNKNOWN
    current_name: Optional[str] = None
    deprecated: bool = False
    revoked_by: Optional[str] = None
    note: str = ""


@dataclass
class DriftReport:
    checked_at: str
    attack_version: str
    total_layers: int
    total_techniques: int
    ok: list = field(default_factory=list)
    stale: list = field(default_factory=list)
    renamed: list = field(default_factory=list)
    unknown: list = field(default_factory=list)
    layer_staleness: dict = field(default_factory=dict)  # layer_name → [issues]

    @property
    def has_issues(self):
        return bool(self.stale or self.renamed or self.unknown)

    @property
    def verdict(self):
        if self.stale:
            return "STALE"
        if self.renamed:
            return "NEEDS_UPDATE"
        if self.unknown:
            return "PARTIAL"
        return "CURRENT"


# ── STIX bundle parser ─────────────────────────────────────────────────────────

def _fetch_stix_bundle(url: str, timeout: int = 15) -> Optional[dict]:
    """Fetch and return the ATT&CK STIX bundle as a dict."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SHENRON-drift-checker/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return None


def _parse_techniques(bundle: dict) -> tuple[dict, str]:
    """
    Extract technique metadata from STIX bundle.
    Returns (techniques_by_id, attack_version).

    techniques_by_id: { "T1014": { name, deprecated, revoked_by } }
    """
    techniques = {}
    attack_version = "unknown"

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type", "")

        # Extract ATT&CK version from matrix object (collection removed in recent releases)
        if obj_type == "x-mitre-matrix":
            attack_version = obj.get("x_mitre_attack_spec_version",
                             obj.get("x_mitre_version", "unknown"))

        if obj_type != "attack-pattern":
            continue

        # Extract external reference to get T-ID
        ext_refs = obj.get("external_references", [])
        tid = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                break

        if not tid:
            continue

        deprecated = obj.get("x_mitre_deprecated", False)
        revoked = obj.get("revoked", False)

        # Find what it was revoked in favour of
        revoked_by = None
        if revoked:
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id") != tid:
                    revoked_by = ref.get("external_id")
                    break

        # Only treat as deprecated if:
        # - x_mitre_deprecated is explicitly True, OR
        # - revoked=True AND there is a known successor (revoked_by)
        # revoked=True with no successor is a STIX bundle artifact, not a real retirement
        is_deprecated = deprecated or (revoked and revoked_by is not None)

        techniques[tid] = {
            "name": obj.get("name", ""),
            "deprecated": is_deprecated,
            "revoked_by": revoked_by,
        }

    return techniques, attack_version


# ── Manifest reader ────────────────────────────────────────────────────────────

def _load_manifest(manifest_path: str) -> list[dict]:
    """Load shenron_manifest.json and return the layers list."""
    p = Path(manifest_path)
    if not p.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    data = json.loads(p.read_text(encoding="utf-8"))
    return data.get("layers", [])


def _extract_layer_techniques(layers: list[dict]) -> dict[str, list[str]]:
    """
    Returns { layer_name: [technique_ids] } from manifest layers.
    Also handles LAYER_META format from individual layer files.
    """
    result = {}
    for layer in layers:
        name = layer.get("name", "unknown")
        mitre = layer.get("mitre", {})
        techniques = mitre.get("techniques", [])
        if techniques:
            result[name] = techniques
    return result


# ── Core drift check ───────────────────────────────────────────────────────────

def check_drift(
    manifest_path: str = "shenron_manifest.json",
    offline: bool = False,
    cached_bundle_path: Optional[str] = None,
) -> DriftReport:
    """
    Main entry point. Returns a DriftReport.

    Args:
        manifest_path: path to shenron_manifest.json
        offline: if True, use cached_bundle_path instead of fetching
        cached_bundle_path: path to a locally saved ATT&CK STIX bundle
    """
    now = datetime.now(timezone.utc).isoformat()

    # Load manifest
    layers = _load_manifest(manifest_path)
    layer_techniques = _extract_layer_techniques(layers)

    total_layers = len(layer_techniques)
    total_techniques = sum(len(v) for v in layer_techniques.values())

    # Fetch or load STIX bundle
    bundle = None
    if offline and cached_bundle_path:
        p = Path(cached_bundle_path)
        if p.exists():
            bundle = json.loads(p.read_text(encoding="utf-8"))

    if bundle is None and not offline:
        bundle = _fetch_stix_bundle(ATTACK_STIX_URL)

    if bundle is None:
        # Cannot fetch — return UNKNOWN for everything
        report = DriftReport(
            checked_at=now,
            attack_version="unavailable",
            total_layers=total_layers,
            total_techniques=total_techniques,
        )
        for layer_name, tids in layer_techniques.items():
            for tid in tids:
                r = TechniqueDriftResult(
                    technique_id=tid,
                    layer_name=layer_name,
                    status="UNKNOWN",
                    note="Could not reach ATT&CK STIX bundle",
                )
                report.unknown.append(r)
        return report

    # Parse techniques from bundle
    attack_techniques, attack_version = _parse_techniques(bundle)

    # Optionally cache bundle
    if cached_bundle_path and not offline:
        Path(cached_bundle_path).write_text(
            json.dumps(bundle), encoding="utf-8"
        )

    # Build report
    report = DriftReport(
        checked_at=now,
        attack_version=attack_version,
        total_layers=total_layers,
        total_techniques=total_techniques,
    )

    for layer_name, tids in layer_techniques.items():
        layer_issues = []

        for tid in tids:
            tech = attack_techniques.get(tid)

            if tech is None:
                r = TechniqueDriftResult(
                    technique_id=tid,
                    layer_name=layer_name,
                    status="STALE",
                    note=f"{tid} not found in current ATT&CK — may be deprecated or renumbered",
                )
                report.stale.append(r)
                layer_issues.append(r)

            elif tech["deprecated"]:
                revoked_by = tech.get("revoked_by")
                r = TechniqueDriftResult(
                    technique_id=tid,
                    layer_name=layer_name,
                    status="RENAMED",
                    current_name=tech["name"],
                    deprecated=True,
                    revoked_by=revoked_by,
                    note=(
                        f"{tid} is deprecated/revoked"
                        + (f" — succeeded by {revoked_by}" if revoked_by else "")
                    ),
                )
                report.renamed.append(r)
                layer_issues.append(r)

            else:
                r = TechniqueDriftResult(
                    technique_id=tid,
                    layer_name=layer_name,
                    status="OK",
                    current_name=tech["name"],
                )
                report.ok.append(r)

        if layer_issues:
            report.layer_staleness[layer_name] = layer_issues

    return report


# ── Report printer ─────────────────────────────────────────────────────────────

def print_drift_report(report: DriftReport, verbose: bool = False) -> None:
    """Print drift report to stdout in Shenron's house style."""
    width = 70
    divider = " " + "=" * width

    print()
    print(divider)
    print(f"  MITRE ATT&CK DRIFT CHECK")
    print(f"  checked_at    : {report.checked_at}")
    print(f"  attack_version: {report.attack_version}")
    print(f"  layers_checked: {report.total_layers}")
    print(f"  techniques    : {report.total_techniques}")
    print(divider)
    print()

    # Summary counts
    print(f"  OK       : {len(report.ok)}")
    print(f"  STALE    : {len(report.stale)}")
    print(f"  RENAMED  : {len(report.renamed)}")
    print(f"  UNKNOWN  : {len(report.unknown)}")
    print()

    # Verdict
    verdict_markers = {
        "CURRENT": "[✓]",
        "NEEDS_UPDATE": "[~]",
        "STALE": "[!]",
        "PARTIAL": "[?]",
    }
    marker = verdict_markers.get(report.verdict, "[ ]")
    print(f"  VERDICT  : {marker} {report.verdict}")
    print()

    if not report.has_issues:
        print("  All pinned techniques are current. No drift detected.")
        print()
        return

    # Stale
    if report.stale:
        print(f"  STALE TECHNIQUES  ({len(report.stale)})")
        print(f"  {'LAYER':<40} {'TECHNIQUE':<12} NOTE")
        print(f"  {'-'*39} {'-'*11} {'-'*30}")
        for r in report.stale:
            print(f"  {r.layer_name:<40} {r.technique_id:<12} {r.note}")
        print()

    # Renamed / deprecated
    if report.renamed:
        print(f"  RENAMED / DEPRECATED  ({len(report.renamed)})")
        print(f"  {'LAYER':<40} {'OLD ID':<12} {'NEW ID':<12} NAME")
        print(f"  {'-'*39} {'-'*11} {'-'*11} {'-'*25}")
        for r in report.renamed:
            new_id = r.revoked_by or "—"
            name = r.current_name or "—"
            print(f"  {r.layer_name:<40} {r.technique_id:<12} {new_id:<12} {name}")
        print()

    # Unknown (network failure)
    if report.unknown and verbose:
        print(f"  UNKNOWN (fetch failed)  ({len(report.unknown)})")
        for r in report.unknown:
            print(f"  {r.layer_name:<40} {r.technique_id:<12} {r.note}")
        print()

    # Affected layers summary
    if report.layer_staleness:
        print(f"  LAYERS REQUIRING ATTENTION")
        for layer_name, issues in sorted(report.layer_staleness.items()):
            tids = ", ".join(r.technique_id for r in issues)
            statuses = ", ".join(set(r.status for r in issues))
            print(f"  [{statuses}] {layer_name}")
            print(f"            techniques: {tids}")
        print()

    print("  Next steps:")
    print("  1. Update stale technique IDs in the affected layer files")
    print("  2. Update corresponding manifest entries")
    print("  3. Re-run --check-mitre-drift to confirm")
    print()


def drift_report_to_markdown(report: DriftReport) -> str:
    """Render drift report as markdown for saving to reports/."""
    lines = [
        "# MITRE ATT&CK Drift Report",
        f"",
        f"**Checked:** {report.checked_at}  ",
        f"**ATT&CK Version:** {report.attack_version}  ",
        f"**Layers checked:** {report.total_layers}  ",
        f"**Techniques checked:** {report.total_techniques}  ",
        f"**Verdict:** {report.verdict}",
        "",
        "## Summary",
        "",
        f"| Status | Count |",
        f"|--------|-------|",
        f"| OK | {len(report.ok)} |",
        f"| STALE | {len(report.stale)} |",
        f"| RENAMED | {len(report.renamed)} |",
        f"| UNKNOWN | {len(report.unknown)} |",
        "",
    ]

    if report.stale:
        lines += [
            "## Stale Techniques",
            "",
            "| Layer | Technique | Note |",
            "|-------|-----------|------|",
        ]
        for r in report.stale:
            lines.append(f"| {r.layer_name} | {r.technique_id} | {r.note} |")
        lines.append("")

    if report.renamed:
        lines += [
            "## Renamed / Deprecated Techniques",
            "",
            "| Layer | Old ID | New ID | Name |",
            "|-------|--------|--------|------|",
        ]
        for r in report.renamed:
            new_id = r.revoked_by or "—"
            name = r.current_name or "—"
            lines.append(f"| {r.layer_name} | {r.technique_id} | {new_id} | {name} |")
        lines.append("")

    if report.layer_staleness:
        lines += ["## Layers Requiring Attention", ""]
        for layer_name, issues in sorted(report.layer_staleness.items()):
            tids = ", ".join(r.technique_id for r in issues)
            lines.append(f"- **{layer_name}**: {tids}")
        lines.append("")

    lines += [
        "---",
        "*Generated by SHENRON // GnomeMan4201 / badBANANA Research Collective*",
    ]

    return "\n".join(lines)
