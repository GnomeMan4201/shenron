# SHENRON Campaign Diff Report

**Run A:** `artifacts/diffs/apt29-style_seed42.jsonl`  
**Run B:** `artifacts/diffs/apt29-style_seed99.jsonl`  
**Generated:** 2026-06-25T23:55:13.344628+00:00  
**Events A:** 7 | **Events B:** 7  

## Stability Summary

| Metric | Score | Verdict |
|--------|-------|---------|
| Technique Stability | 1.000 | STABLE |
| Signal Stability | 1.000 | STABLE |
| Overall Stability | 1.000 | STABLE |
| Seed-Dependent Coverage | — | NO — coverage is seed-stable |
| Coverage Delta | +0 signals | — |

## Technique Diff

**Common (14):** T1003, T1003.001, T1021.002, T1036, T1041, T1059, T1059.004, T1059.006, T1543, T1543.003, T1570, T1589, T1589.002, T1589.003
*Technique coverage identical across both runs.*

## Signal Diff

*Signal coverage identical across both runs.*

## Phase Density

| Phase | Count A | Count B | Delta | Delta % |
|-------|---------|---------|-------|---------|
| identity_harvest | 1 | 1 | +0 | +0.0% |
| inline_execution | 1 | 1 | +0 | +0.0% |
| lsass_dump | 1 | 1 | +0 | +0.0% |
| shell_spawn_sim | 1 | 1 | +0 | +0.0% |
| smb_admin_share | 1 | 1 | +0 | +0.0% |
| source_enumeration | 1 | 1 | +0 | +0.0% |
| windows_service | 1 | 1 | +0 | +0.0% |

## Detection Engineering Recommendation

✓ **Coverage is seed-stable.** Technique and signal coverage is consistent across both runs. Detection rules validated against one run should generalize.