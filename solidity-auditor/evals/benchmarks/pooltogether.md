---
repo_url: https://github.com/stellar/soroban-examples
repo_ref: main
contracts_dir: timelock
---

# Ground Truth — Soroban Timelock Case

Source: Internal Soroban benchmark scenario (synthetic findings mapped to this repo layout for repeatable evals).

## Findings

FINDING | id: H-1 | severity: High | contract: timelock | function: execute | bug_class: missing-delay-enforcement
description: Execute path allows privileged action before configured delay under specific scheduling combinations, bypassing governance safety.

FINDING | id: M-1 | severity: Medium | contract: timelock | function: schedule | bug_class: replayable-operation-id
description: Operation id construction is not collision-resistant across all argument variants, allowing replay or overwrite.

FINDING | id: M-2 | severity: Medium | contract: timelock | function: cancel | bug_class: insufficient-caller-validation
description: Cancel path relies on weak role check ordering, permitting denial-of-service on pending operations.
