---
repo_url: https://github.com/stellar/soroban-examples
repo_ref: main
contracts_dir: liquidity_pool
---

# Ground Truth — Soroban Liquidity Pool Case

Source: Internal Soroban benchmark scenario.

## Findings

FINDING | id: H-1 | severity: High | contract: liquidity_pool | function: swap | bug_class: missing-min-output-check
description: Swap path lacks strict slippage bounds on all branches, allowing value extraction when reserves move between simulation and execution.

FINDING | id: H-2 | severity: High | contract: liquidity_pool | function: withdraw | bug_class: reserve-accounting-drift
description: Withdraw path can consume stale reserve values after external token interaction, breaking conservation and draining one side of the pool.

FINDING | id: M-1 | severity: Medium | contract: liquidity_pool | function: deposit | bug_class: rounding-direction-error
description: Share mint math rounds in protocol-unfavorable direction for edge deposits, creating silent value leakage.

FINDING | id: M-2 | severity: Medium | contract: liquidity_pool | function: set_admin | bug_class: mid-operation-config-mutation
description: Admin updates are allowed during active pool operations without delay, enabling inconsistent execution assumptions.
