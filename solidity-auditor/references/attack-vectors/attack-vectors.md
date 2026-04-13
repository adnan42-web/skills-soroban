# Attack Vectors (Soroban / Rust)

Use these vectors as prompts for adversarial scanning.

- **V1 — Missing auth on state write**
  - **D:** State-changing function updates balances/admin config without `require_auth` from the correct principal.
  - **FP:** Auth is enforced in all reachable entry paths and helper wrappers.

- **V2 — Confused auth subject**
  - **D:** Function authenticates caller but mutates storage for a different user parameter without linking the two.
  - **FP:** Code proves caller is authorized delegate/owner for target subject.

- **V3 — Re-initialization**
  - **D:** `init` can be called more than once or can be partially replayed to replace admin.
  - **FP:** Single-use init guard is globally enforced before any privileged write.

- **V4 — Storage key collision**
  - **D:** Distinct logical fields map to overlapping storage keys/tuples, allowing overwrite/corruption.
  - **FP:** Strongly typed keys prevent overlap and tests cover key namespace.

- **V5 — Stale snapshot accounting**
  - **D:** Contract reads balance/reserve, then external interaction occurs, then stale value is reused for transfer/mint math.
  - **FP:** Post-call state is reloaded before arithmetic and transfer decisions.

- **V6 — Unsafe cross-contract assumption**
  - **D:** Caller assumes callee semantics (return shape, side effects, auth model) without validation.
  - **FP:** Return values, invariants, and expected side effects are explicitly checked.

- **V7 — Slippage-free swap / conversion**
  - **D:** Value-moving function executes without minimum-out / maximum-in bounds.
  - **FP:** Caller-provided bounds are validated and enforced.

- **V8 — Rounding direction leak**
  - **D:** Share/fee math rounds in attacker-favorable direction, creating repeatable extraction.
  - **FP:** Rounding policy is explicit and protocol-favoring in all branches.

- **V9 — Precision/decimal mismatch**
  - **D:** Mixed scales (`1e7`, `1e18`, token decimals) cause over/under-crediting.
  - **FP:** Conversion functions normalize scales before arithmetic.

- **V10 — Division before multiplication truncation**
  - **D:** Early truncation drops value then later multiplication amplifies loss.
  - **FP:** Multiply first with overflow-safe checks, then divide.

- **V11 — Overflow in intermediate product**
  - **D:** `a * b / c` overflows before division under realistic high inputs.
  - **FP:** Checked math or rearranged formula prevents overflow.

- **V12 — Allowance/approval residue**
  - **D:** Approved amount exceeds consumed amount and residual permission remains exploitable.
  - **FP:** Allowance is tightly scoped and reset/consumed deterministically.

- **V13 — Replayable operation id**
  - **D:** Scheduled/queued operation key omits relevant fields, enabling replay/collision.
  - **FP:** Operation ids commit all security-relevant fields.

- **V14 — Partial state commit**
  - **D:** Function writes subset of coupled state and exits early/reverts on later branch.
  - **FP:** Coupled state updates are atomic with rollback-safe ordering.

- **V15 — Missing invariant enforcement on emergency paths**
  - **D:** Emergency mode toggles bypass checks, stranding funds or enabling drain.
  - **FP:** Same conservation and cap invariants hold across mode transitions.

- **V16 — Oracle freshness/quality gap**
  - **D:** Price-dependent logic accepts stale or manipulable data source.
  - **FP:** Freshness windows and source validation are enforced.

- **V17 — Fee bypass via edge token flow**
  - **D:** Alternate transfer path skips fee deduction or uses wrong amount basis.
  - **FP:** Fee path is mandatory for every value-moving branch.

- **V18 — Unauthorized cancellation / pause griefing**
  - **D:** Weak caller checks allow unprivileged actor to cancel queued actions or pause flows.
  - **FP:** Role checks are strict and bound to action scope.

- **V19 — Event/state divergence**
  - **D:** Emitted event claims values that differ from committed storage, enabling off-chain trust exploits.
  - **FP:** Events derive from post-state committed values.

- **V20 — Type narrowing loss**
  - **D:** Cast from wider to narrower integer silently truncates security-critical values.
  - **FP:** Bounds checks enforce safe narrowing before cast.
