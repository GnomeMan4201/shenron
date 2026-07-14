# SHENRON Assumption Fuzz Report

**Assumption:** full_kill_chain_coverage  
**Artifact:** artifacts/demo/shenron_demo_run.jsonl  
**Generated:** 2026-06-25T23:25:59.646020+00:00  
**Original Status:** PARTIALLY_SUPPORTED  
**Total Mutations:** 23  
**Verdict-Changing Mutations:** 1  

## Claim Sensitivity

| Claim | Sensitivity | Load-Bearing |
|-------|------------|-------------|
| persistence_present | 0.20 | no |
| c2_present | 0.00 | no |
| evasion_present | 0.00 | no |
| lateral_present | 0.00 | no |

## Load-Bearing Claims
*(Removing or corrupting these changes the validation verdict)*

*(none — assumption may be over-specified or artifact is comprehensive)*

## Redundant Claims
*(These claims can be removed without changing the verdict)*

- c2_present
- evasion_present
- lateral_present

## Full Mutation Results

| Claim | Strategy | Original | Mutated | Changed |
|-------|----------|----------|---------|---------|
| persistence_present | claim_drop | PARTIALLY_SUPPORTED | SUPPORTED | YES |
| persistence_present | technique_swap | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| persistence_present | technique_add | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| persistence_present | signal_corrupt | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| persistence_present | signal_add | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| c2_present | claim_drop | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| c2_present | technique_swap | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| c2_present | technique_add | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| c2_present | signal_corrupt | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| c2_present | signal_add | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| evasion_present | claim_drop | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| evasion_present | technique_swap | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| evasion_present | technique_add | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| evasion_present | signal_corrupt | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| evasion_present | signal_add | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| lateral_present | claim_drop | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| lateral_present | technique_swap | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| lateral_present | technique_add | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| lateral_present | signal_corrupt | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| lateral_present | signal_add | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| (global) | oos_inject_0 | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| (global) | oos_inject_1 | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |
| (global) | oos_inject_2 | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED | no |