# SHENRON Assumption Fuzz Report

**Assumption:** c2_coverage  
**Artifact:** artifacts/demo/shenron_demo_run.jsonl  
**Generated:** 2026-06-25T23:25:31.985013+00:00  
**Original Status:** OUT_OF_SCOPE_VIOLATION  
**Total Mutations:** 18  
**Verdict-Changing Mutations:** 2  

## Claim Sensitivity

| Claim | Sensitivity | Load-Bearing |
|-------|------------|-------------|
| no_persistence_overclaim | 0.40 | no |
| beacon_evidence | 0.00 | no |
| covert_channel_evidence | 0.00 | no |

## Load-Bearing Claims
*(Removing or corrupting these changes the validation verdict)*

*(none — assumption may be over-specified or artifact is comprehensive)*

## Redundant Claims
*(These claims can be removed without changing the verdict)*

- beacon_evidence
- covert_channel_evidence

## Full Mutation Results

| Claim | Strategy | Original | Mutated | Changed |
|-------|----------|----------|---------|---------|
| beacon_evidence | claim_drop | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| beacon_evidence | technique_swap | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| beacon_evidence | technique_add | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| beacon_evidence | signal_corrupt | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| beacon_evidence | signal_add | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| covert_channel_evidence | claim_drop | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| covert_channel_evidence | technique_swap | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| covert_channel_evidence | technique_add | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| covert_channel_evidence | signal_corrupt | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| covert_channel_evidence | signal_add | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| no_persistence_overclaim | claim_drop | OUT_OF_SCOPE_VIOLATION | SUPPORTED | YES |
| no_persistence_overclaim | technique_swap | OUT_OF_SCOPE_VIOLATION | SUPPORTED | YES |
| no_persistence_overclaim | technique_add | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| no_persistence_overclaim | signal_corrupt | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| no_persistence_overclaim | signal_add | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| (global) | oos_inject_0 | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| (global) | oos_inject_1 | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |
| (global) | oos_inject_2 | OUT_OF_SCOPE_VIOLATION | OUT_OF_SCOPE_VIOLATION | no |