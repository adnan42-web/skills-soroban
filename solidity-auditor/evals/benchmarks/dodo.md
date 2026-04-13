---
repo_url: https://github.com/stellar/soroban-examples
repo_ref: main
contracts_dir: token
---

# Ground Truth — Soroban Token Case

Source: Internal Soroban benchmark scenario (synthetic findings mapped to this repo layout for repeatable evals).

## Findings

FINDING | id: H-1 | severity: High | contract: token | function: transfer_from | bug_class: missing-spender-auth
description: Spender flow allows balance movement without verifying the expected invoker authorization path, enabling unauthorized transfers.

FINDING | id: H-2 | severity: High | contract: token | function: burn | bug_class: missing-owner-check
description: Burn path accepts user-provided address but does not enforce ownership/auth symmetry, allowing third-party token destruction.

FINDING | id: M-1 | severity: Medium | contract: token | function: approve | bug_class: stale-allowance-overwrite
description: Allowance update overwrites non-zero values without a reset rule, enabling race-condition spending.

FINDING | id: M-2 | severity: Medium | contract: token | function: read_administrator | bug_class: unvalidated-admin-state
description: Admin state reads from storage without validating initialization sequence, causing privilege ambiguity in edge deployments.
