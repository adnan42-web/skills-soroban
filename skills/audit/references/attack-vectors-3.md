# Attack Vectors Reference (3/3 — Vectors 90–133)

133 total attack vectors. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

**90. ERC20 Non-Compliant: Return Values / Events**

- **Detect:** Custom `transfer()`/`transferFrom()` doesn't return `bool`, or always returns `true` on failure. `mint()` missing `Transfer(address(0), to, amount)` event. `burn()` missing `Transfer(from, address(0), amount)`. `approve()` missing `Approval` event. Breaks DEX and wallet composability.
- **FP:** OpenZeppelin `ERC20.sol` used as base with no custom overrides of the transfer/approve/event logic.

**91. Fee-on-Transfer Token Accounting**

- **Detect:** Deposit recorded as `deposits[user] += amount` then `transferFrom(..., amount)`. Fee-on-transfer tokens (SAFEMOON, STA) cause the contract to receive `amount - fee` but record `amount`. Subsequent withdrawals drain other users.
- **FP:** Balance measured before/after transfer: `uint256 before = token.balanceOf(this); token.transferFrom(...); uint256 received = token.balanceOf(this) - before;` and `received` used for accounting.

**92. Arbitrary `delegatecall` in Implementation**

- **Detect:** Implementation exposes a function that performs `delegatecall` to a user-supplied address, allowing arbitrary bytecode execution in the proxy's storage context -- overwriting owner, balances, or bricking the contract. Pattern: `function execute(address target, bytes calldata data) external { target.delegatecall(data); }` where `target` is not restricted. Real-world: Furucombo (2021, $14M stolen via unrestricted delegatecall to user-supplied handler addresses).
- **FP:** `target` is a hardcoded immutable verified library address that cannot be changed after deployment. Whitelist of approved delegatecall targets enforced. `call` used instead of `delegatecall` for external integrations.

**93. ERC721 transferFrom with Unvalidated `from` Parameter**

- **Detect:** Custom ERC721 overrides `transferFrom(from, to, tokenId)` and verifies that `msg.sender` is the owner or approved, but does not verify that `from == ownerOf(tokenId)`. An attacker who is an approved operator for `tokenId` can call `transferFrom(victim, attacker, tokenId)` with a fabricated `from` address — the approval check passes for the operator, the token moves, but `from` was not the actual owner and may not be the intended origin for accounting, event logging, or protocol-level state. Pattern: `require(isApprovedOrOwner(msg.sender, tokenId))` without a subsequent `require(from == ownerOf(tokenId))`.
- **FP:** `super.transferFrom()` or OZ's `_transfer(from, to, tokenId)` called internally — OZ's `_transfer` explicitly checks `from == ownerOf(tokenId)` and reverts with `ERC721IncorrectOwner` if not. Custom override includes an explicit `require(ownerOf(tokenId) == from)` before transfer logic.

**94. CREATE2 Address Reuse After selfdestruct**

- **Detect:** Protocol whitelists, approves, or trusts a contract at an address derived from CREATE2. Attacker controls the salt or factory. Pre-EIP-6780: attacker deploys a benign contract, earns trust (e.g., token approval, whitelist entry, governance power), calls `selfdestruct`, then redeploys a malicious contract to the identical address. The stored approval/whitelist entry now points to the malicious code. Pattern: `create2Factory.deploy(salt, initcode)` where `salt` is user-supplied or predictable, combined with no bytecode-hash verification at trust-grant time.
- **FP:** Post-Dencun (EIP-6780): `selfdestruct` no longer destroys code unless it occurs in the same transaction as contract creation, effectively eliminating the redeploy path on mainnet. Bytecode hash of the approved contract recorded at approval time and re-verified before each privileged call. No user-controlled CREATE2 salt accepted by the factory.

**95. Chainlink Staleness / No Validity Checks**

- **Detect:** `latestRoundData()` called but any of these checks are missing: `answer > 0`, `updatedAt > block.timestamp - MAX_STALENESS`, `answeredInRound >= roundId`, fallback on failure.
- **FP:** All four checks present. Circuit breaker or fallback oracle used when any check fails.

**96. Transient Storage Low-Gas Reentrancy (EIP-1153)**

- **Detect:** Contract uses `transfer()` or `send()` (2300-gas stipend) as its reentrancy protection, AND either the contract or a called external contract uses `transient` variables or `TSTORE`/`TLOAD` in assembly. Post-Cancun (Solidity ≥0.8.24), `TSTORE` succeeds with fewer than 2300 gas — unlike `SSTORE`, which is blocked by EIP-2200. The 2300-gas-as-reentrancy-guard assumption is broken. Second pattern: transient reentrancy lock that is not explicitly cleared at the end of the call frame. Because transient storage persists for the entire transaction (not just the call), if the contract is invoked again in the same tx (e.g., via multicall or flash loan callback), the transient lock from the first invocation is still set, causing a permanent DoS for the remainder of the tx.
- **FP:** Reentrancy protection uses an explicit `nonReentrant` modifier backed by a regular storage slot (or a correctly implemented transient mutex cleared at call end). CEI pattern followed unconditionally regardless of gas stipend. Contract does not use transient storage at all.

**97. Missing Slippage Protection (Sandwich Attack)**

- **Detect:** Swap/deposit/withdrawal with `minAmountOut = 0`, or `minAmountOut` computed on-chain from current pool state (always passes). Pattern: `router.swap(..., 0, deadline)`.
- **FP:** `minAmountOut` set off-chain by the user and validated on-chain.

**98. Missing Input Validation on Critical Setters**

- **Detect:** Admin functions set numeric parameters with no validation: `setFee(uint256 fee)` with no `require(fee <= MAX_FEE)`; `setOracle(address o)` with no interface check. A misconfigured call — wrong argument, value exceeding 100% — silently bricks fee collection, enables 100% fee extraction, or points the oracle to a dead address.
- **FP:** Every setter has explicit `require` bounds on all parameters. Numeric parameters validated against documented protocol constants.

**99. abi.encodePacked Hash Collision with Dynamic Types**

- **Detect:** `keccak256(abi.encodePacked(a, b, ...))` where two or more arguments are dynamic types (`string`, `bytes`, or dynamic arrays such as `uint[]`, `address[]`). `abi.encodePacked` concatenates raw bytes without length prefixes, so `("AB","CD")`, `("A","BCD")`, and `("ABC","D")` all produce the same byte sequence `0x41424344` and thus the same hash. If the hash is used for permit/signature verification, access control key derivation, or uniqueness enforcement (mapping keys, nullifiers), an attacker crafts an alternative input that collides with a legitimate hash and gains the same privileges.
- **FP:** `abi.encode()` used instead — each argument is ABI-padded and length-prefixed, eliminating ambiguity. Only one argument is a dynamic type (no two dynamic types to collide between). All arguments are fixed-size types (`uint256`, `address`, `bytes32`).

**100. ERC1155 ID-Based Role Access Control With Publicly Mintable Role Tokens**

- **Detect:** Protocol implements access control by checking ERC1155 token balance: `require(balanceOf(msg.sender, ADMIN_ROLE_ID) > 0)` or `require(balanceOf(msg.sender, MINTER_ROLE_ID) >= 1)`. The role token IDs (`ADMIN_ROLE_ID`, `MINTER_ROLE_ID`) are public constants. If the ERC1155 `mint` function for those IDs is not separately access-controlled — e.g., it's callable by any holder of a lower-tier token, or via a public presale — any attacker can acquire the role token and gain elevated privileges. Role tokens are also transferable by default, creating a secondary market for protocol permissions.
- **FP:** Minting of all role-designated token IDs is gated behind a separate access control system (e.g., OZ `AccessControl` with `MINTER_ROLE` on the ERC1155 contract itself). Role tokens for privileged IDs are non-transferable: `_beforeTokenTransfer` reverts for those IDs when `from != address(0) && to != address(0)`. Protocol uses a dedicated non-token access control system rather than ERC1155 balances for privilege gating.

**101. ERC721 Approval Not Cleared in Custom Transfer Override**

- **Detect:** Contract overrides `transferFrom` or `safeTransferFrom` with custom logic — fee collection, royalty payment, access checks — but does not call `super._transfer()` or `super.transferFrom()` internally. OpenZeppelin's `_transfer` is the function that executes `delete _tokenApprovals[tokenId]`. Skipping it leaves the previous approved address permanently approved on the token under the new owner. Pattern: custom `transferFrom` that calls a bespoke `_transferWithFee(from, to, tokenId)` without the approval-clear step.
- **FP:** Custom override calls `super.transferFrom(from, to, tokenId)` or `super._transfer(from, to, tokenId)` internally, preserving OZ's approval clearing. Or explicitly calls `delete _tokenApprovals[tokenId]` / `_approve(address(0), tokenId, owner)` before returning.

**102. Off-By-One in Bounds or Range Checks**

- **Detect:** (1) Loop upper bound uses `<=` instead of `<` on an array index: `for (uint i = 0; i <= arr.length; i++)` — accesses `arr[arr.length]` on the final iteration, reverting or reading uninitialized memory. (2) `arr[arr.length - 1]` or `arr[index - 1]` without a preceding `require(arr.length > 0)` / `require(index > 0)` — in `unchecked` blocks the underflow silently wraps to a huge index. (3) Inclusive/exclusive boundary confusion in financial logic: `require(block.timestamp >= vestingEnd)` vs. `> vestingEnd`, or `require(amount <= MAX)` where MAX was intended as exclusive — one unit of difference causes early unlock or allows a boundary-exceeding deposit. (4) Cumulative distribution: allocating a total across N recipients using integer division, where rounding errors accumulate and the final recipient receives more or less than intended.
- **FP:** Loop uses `<` not `<=` and the upper bound is a fixed-length array or a compile-time constant — overflow into out-of-bounds is structurally impossible. Last-element access is always preceded by a `require(arr.length > 0)` or equivalent in the same scope. Financial boundary comparisons (`>=` vs `>`) are demonstrably correct for the invariant being enforced (e.g., `>= vestingEnd` for an inclusive deadline, `< MAX` for an exclusive cap).

**103. Minimal Proxy (EIP-1167) Implementation Destruction**

- **Detect:** EIP-1167 minimal proxies (clones) permanently `delegatecall` to a fixed implementation address with no upgrade mechanism. If the implementation is destroyed (`selfdestruct` pre-Dencun) or becomes non-functional, every clone is permanently bricked -- calls return success with no effect (empty code = no-op), funds are permanently locked. Pattern: `Clones.clone(implementation)` or `Clones.cloneDeterministic(...)` where the implementation contract has no protection against `selfdestruct` or is not initialized.
- **FP:** Implementation contract has no `selfdestruct` opcode and no path to one via delegatecall. `_disableInitializers()` called in implementation constructor. Post-Dencun (EIP-6780): `selfdestruct` no longer destroys pre-existing code. Beacon proxies used instead when future upgradeability is needed.

**104. Immutable / Constructor Argument Misconfiguration**

- **Detect:** Constructor sets `immutable` variables or critical storage values (admin address, fee basis points, token address, oracle address) that cannot be changed after deployment. If the deployment script passes wrong values — swapped argument order, wrong decimal precision, zero address, test values — the contract is permanently misconfigured with no recourse except redeployment. Pattern: constructor accepts multiple `address` parameters of the same type where argument order can be silently swapped. `immutable` variables set from constructor args without post-deployment validation. Fee parameters in basis points vs. percentage (100 vs. 10000) with no bounds checking. No deployment verification script that reads back on-chain state to confirm correct configuration.
- **FP:** Deployment script includes post-deploy assertions that read back every immutable/constructor-configured value and compare against expected values. Constructor validates arguments: `require(admin != address(0))`, `require(feeBps <= 10000)`. Integration test suite deploys and verifies the full configuration before mainnet deployment.

**105. Missing Storage Gap in Upgradeable Base Contract**

- **Detect:** Upgradeable base contract has no `uint256[N] private __gap;` at the end. A future version adding state variables to the base shifts the derived contract's storage layout, overwriting existing variables.
- **FP:** EIP-1967 namespaced storage slots used for all variables in the base contract. Single-contract (non-inherited) implementation where new variables can only be appended safely.

**106. Non-Atomic Multi-Contract Deployment (Partial System Bootstrap)**

- **Detect:** Deployment script deploys multiple interdependent contracts across separate transactions without atomic guarantees. If the script fails midway (gas exhaustion, RPC error, nonce conflict, reverted transaction), the system is left in a half-deployed state: some contracts reference addresses that don't exist yet, or contracts are deployed but not wired together. A partially deployed lending protocol might have a vault deployed but no oracle configured, allowing deposits at a zero price. Pattern: Foundry script with multiple `vm.broadcast()` blocks or Hardhat deploy script with sequential `await deploy()` calls where later deployments depend on earlier ones. No idempotency checks (does the contract already exist?) or rollback mechanism. No deployment state file tracking which steps completed.
- **FP:** Script uses a single `vm.startBroadcast()` / `vm.stopBroadcast()` block that batches all transactions atomically (note: Foundry still sends individual txs, but script halts on first failure). Deployment uses a factory contract that deploys and wires all contracts in a single transaction. Script is idempotent — checks for existing deployments before each step. Hardhat-deploy module with tagged, resumable migrations.

**107. Stale Cached ERC20 Balance from Direct Token Transfers**

- **Detect:** Contract tracks token holdings in a state variable (`totalDeposited`, `_reserves`, `cachedBalance`) that is only updated through the protocol's own deposit/receive functions. The actual `token.balanceOf(address(this))` can exceed the cached value via direct `token.transfer(contractAddress, amount)` calls made outside the protocol's accounting flow. When protocol logic uses the cached variable — not `balanceOf` live — for share pricing, collateral ratios, or withdrawal limits, an attacker donates tokens directly to inflate actual holdings, then exploits the gap between cached and real state (inflated share price, under-collateralized accounting). Distinct from ERC4626 first-depositor inflation attack (see Vector 86): applies to any contract with split accounting, not just vaults.
- **FP:** All accounting reads `token.balanceOf(address(this))` live — no cached balance variable used in financial math. Cached value is reconciled against `balanceOf` at the start of every state-changing function. Direct token transfers are explicitly considered in the accounting model (e.g., treated as protocol revenue, not phantom deposits).

**108. Merkle Proof Reuse — Leaf Not Bound to Caller**

- **Detect:** Merkle proof accepted without tying the leaf to `msg.sender`. Pattern: `require(MerkleProof.verify(proof, root, keccak256(abi.encodePacked(amount))))` or leaf contains only an address that is not checked against `msg.sender`. Anyone who observes the proof in the mempool can front-run and claim the same entitlement by submitting it from a different address.
- **FP:** Leaf explicitly encodes the caller: `keccak256(abi.encodePacked(msg.sender, amount))`. Function validates that the leaf's embedded address equals `msg.sender` before acting. Proof is single-use and recorded as consumed after the first successful call.

**109. L2 Sequencer Uptime Not Checked**

- **Detect:** Contract on Arbitrum/Optimism/Base/etc. uses Chainlink feeds but does not query the L2 Sequencer Uptime Feed before consuming prices. Stale data during sequencer downtime can trigger wrong liquidations.
- **FP:** Sequencer uptime feed queried explicitly (`answer == 0` = up), with a grace period enforced after restart.

**110. CREATE2 Address Squatting (Counterfactual Front-Running)**

- **Detect:** A CREATE2-based deployment uses a salt that is not bound to the deployer's address (`msg.sender`). An attacker who knows the factory address, salt, and init code can precompute the deployment address and deploy there first (either via the same factory or a different one with matching parameters). For account abstraction wallets, this is especially dangerous: an attacker deploys a wallet to the user's counterfactual address with themselves as the owner, then receives funds intended for the legitimate user. Pattern: `CREATE2` salt is a user-supplied value, sequential counter, or derived from public data (e.g., `keccak256(username)`) without incorporating `msg.sender`. Factory's `deploy()` function is permissionless and does not bind salt to caller.
- **FP:** Salt incorporates `msg.sender`: `salt = keccak256(abi.encodePacked(msg.sender, userSalt))`. Factory restricts who can deploy: `require(msg.sender == authorizedDeployer)`. Init code includes owner address in constructor arguments, so different owners produce different init code hashes and thus different CREATE2 addresses.

**111. Rebasing / Elastic Supply Token Accounting**

- **Detect:** Contract holds rebasing tokens (stETH, AMPL, aTokens) and caches `token.balanceOf(this)` in a state variable used for future accounting. After a rebase, cached value diverges from actual balance.
- **FP:** Protocol enforces at the code level that rebasing tokens cannot be deposited (explicit revert or whitelist). Accounting always reads `balanceOf` live. Wrapper tokens (wstETH) used instead.

---

**112. Banned Opcode in Validation Phase (Simulation-Execution Divergence)**

- **Detect:** `validateUserOp` or `validatePaymasterUserOp` references `block.timestamp`, `block.number`, `block.coinbase`, `block.prevrandao`, or `block.basefee`. Per ERC-7562, these opcodes are banned in the validation phase because their values can differ between bundler simulation (off-chain) and on-chain execution, causing ops that pass simulation to revert on-chain. The bundler pays gas for the failed inclusion.
- **FP:** Banned opcodes appear only in the execution phase (inside `execute`/`executeBatch` logic, not in validation). The entity using the banned opcode is staked and tracked under the ERC-7562 reputation system (reduces but does not eliminate risk).

**113. Missing `__gap` in Upgradeable Base Contracts**

- **Detect:** Upgradeable base contract inherited by other contracts has no `uint256[N] private __gap;` at the end. A future version adding state variables to the base shifts every derived contract's storage layout. Pattern: `contract GovernableV1 { address public governor; }` with no gap -- adding `pendingGov` in V2 shifts all child-contract slots.
- **FP:** EIP-7201 namespaced storage used for all variables in the base contract. `__gap` array present and sized correctly (reduced by 1 for each new variable). Single-contract (non-inherited) implementation where new variables can only be appended safely.

**114. Paymaster ERC-20 Payment Deferred to postOp Without Pre-Validation**

- **Detect:** `validatePaymasterUserOp` does not transfer tokens or lock funds — payment is deferred entirely to `postOp` via `safeTransferFrom`. Between validation and execution the user can revoke the ERC-20 allowance (or drain their balance), causing `postOp` to revert. The paymaster still owes the bundler its gas costs, losing deposit without collecting payment. Pattern: `postOp` contains `token.safeTransferFrom(user, address(this), cost)` with no corresponding lock in the validation phase.
- **FP:** Tokens are transferred or locked (e.g., via `transferFrom` into the paymaster) during `validatePaymasterUserOp` itself. `postOp` is used only to refund excess, never to collect initial payment.

**115. Integer Overflow / Underflow**

- **Detect:** Arithmetic inside `unchecked {}` blocks (Solidity ≥0.8) that could over/underflow: subtraction without a prior `require(amount <= balance)`, multiplication of two large values. Any arithmetic in Solidity <0.8 without SafeMath. (SWC-101)
- **FP:** Value range is provably bounded by earlier checks that appear in the same function before the unchecked block. `unchecked` used exclusively for loop counter increments of the form `++i` where `i < arr.length`, making overflow structurally impossible.

**116. Token Decimal Mismatch in Cross-Token Arithmetic**

- **Detect:** Protocol multiplies or divides token amounts using a hardcoded `1e18` denominator or assumes all tokens share the same decimals. USDC has 6 decimals, WETH has 18 — a formula like `price = usdcAmount * 1e18 / wethAmount` is off by 1e12. Pattern: collateral ratio, LTV, interest rate, or exchange rate calculations that combine two tokens' amounts with no per-token decimal normalization. `token.decimals()` is never called, or is called but its result is not used in scaling factors.
- **FP:** All amounts normalized to a canonical precision (WAD/RAY) immediately after transfer, using each token's actual `decimals()`. Explicit normalization factor `10 ** (18 - token.decimals())` applied per token before any cross-token arithmetic. Protocol only supports tokens with identical, verified decimals.

**117. UUPS Upgrade Logic Removed in New Implementation**

- **Detect:** New UUPS implementation version does not inherit `UUPSUpgradeable` or removes `upgradeTo()`/`upgradeToAndCall()`. After upgrading, the proxy permanently loses upgrade capability -- no further upgrades possible, contract is bricked at current version. Pattern: V2 inherits `OwnableUpgradeable` but not `UUPSUpgradeable`; no `_authorizeUpgrade` override; `upgradeTo` function absent from V2 ABI.
- **FP:** Every implementation version inherits `UUPSUpgradeable`. Integration tests verify `upgradeTo` works after each upgrade. `@openzeppelin/upgrades` plugin upgrade safety checks used in CI.

**118. ERC1155 Batch Transfer Partial-State Callback Window**

- **Detect:** Custom ERC1155 batch mint or transfer processes IDs in a loop — updating `_balances[id][to]` one ID at a time and calling `onERC1155Received` per iteration, rather than committing all balance updates first and then calling the single `onERC1155BatchReceived` hook once. During the per-ID callback, later IDs in the batch have not yet been credited. A re-entrant call from the callback can read stale balances for uncredited IDs, enabling double-counting or theft of not-yet-transferred amounts. Pattern: `for (uint i; i < ids.length; i++) { _balances[ids[i]][to] += amounts[i]; _doSafeTransferAcceptanceCheck(...); }`.
- **FP:** All balance updates for the entire batch are committed before any callback fires — mirroring OZ's approach: update all balances in one loop, then call `_doSafeBatchTransferAcceptanceCheck` once. `nonReentrant` applied to all transfer and mint entry points.

**119. ERC1155 totalSupply Inflation via Reentrancy Before Supply Update**

- **Detect:** Contract extends `ERC1155Supply` (or custom supply tracking) and increments `totalSupply[id]` AFTER calling `_mint`, which triggers the `onERC1155Received` callback on the recipient. During the callback, `totalSupply[id]` has not yet been updated. Any governance, reward, or share-price formula that reads `totalSupply[id]` inside the callback (directly or via a re-entrant call to the same contract) observes an artificially low total, inflating the caller's computed share. OZ pre-4.3.2 `ERC1155Supply` had exactly this ordering — supply updated post-callback. Real finding: ChainSecurity disclosure, OZ advisory GHSA-9c22-pwxw-p6hx (2021).
- **FP:** OZ ≥ 4.3.2 used — supply incremented before the mint callback in patched versions. `nonReentrant` on all mint functions. No totalSupply-dependent logic is callable from within a mint callback path.

**120. ERC721/ERC1155 Callback Reentrancy**

- **Detect:** `safeTransferFrom` (ERC721) or `safeMint`/`safeTransferFrom` (ERC1155) called before state updates. These invoke `onERC721Received`/`onERC1155Received` on recipient contracts.
- **FP:** All state committed before the safe transfer. Function is `nonReentrant`.

**121. ERC4626 Mint/Redeem Asset-Cost Asymmetry**

- **Detect:** For the same share count `s`, `redeem(s)` returns more assets than `mint(s)` costs — so cycling redeem → remint yields a net profit on every loop. Equivalently, `mint(redeem(s).shares)` costs fewer assets than `redeem(s)` returned. Root cause: `_convertToAssets` rounds up in `redeem` (user receives more) and rounds down in `mint` (user pays less), the opposite of what EIP-4626 requires. The spec mandates that `redeem` rounds down (vault keeps the rounding error) and `mint` rounds up (user pays the rounding error). Pattern: `previewRedeem` and `redeem` call `_convertToAssets(shares, Rounding.Ceil)` while `previewMint` and `mint` call `_convertToAssets(shares, Rounding.Floor)`. The delta between the two is extractable per cycle. (Covers `prop_RT_mint_redeem` and `prop_RT_redeem_mint` from the a16z ERC4626 property test suite.)
- **FP:** `redeem`/`previewRedeem` call `_convertToAssets(shares, Math.Rounding.Floor)` and `mint`/`previewMint` call `_convertToAssets(shares, Math.Rounding.Ceil)`. OpenZeppelin ERC4626 used without custom conversion overrides.

---

**122. setApprovalForAll Grants Permanent Unlimited Operator Access**

- **Detect:** Protocol requires users to call `nft.setApprovalForAll(protocol, true)` to enable staking, escrow, or any protocol-managed transfer. This grants the operator irrevocable, time-unlimited control over every current and future token the user holds in that collection. No expiry, no per-token scoping, and no per-amount limit. If the approved operator contract is exploited, upgraded maliciously, or its admin key is compromised, an attacker can drain all tokens from all users who granted approval in a single sweep. Pattern: `require(nft.isApprovedForAll(msg.sender, address(this)), "must approve")` at the entry point of a staking or escrow function.
- **FP:** Protocol uses individual `approve(address(this), tokenId)` before each transfer, requiring per-token user action. Operator is an immutable non-upgradeable contract with a formally verified transfer function. Protocol provides an on-chain `revokeAll()` helper users are trained to call after each interaction.

**123. Griefing via Dust Deposits Resetting Timelocks or Cooldowns**

- **Detect:** Time-based lock, cooldown, or delay is reset on any deposit or interaction with no minimum-amount guard: `lastActionTime[user] = block.timestamp` inside a `deposit(uint256 amount)` with no `require(amount >= MIN_AMOUNT)`. Attacker calls `deposit(1)` repeatedly, just before the victim's lock expires, resetting the cooldown indefinitely at negligible cost. Variant: vault that checks `totalSupply > 0` before first depositor can join — attacker donates 1 wei to permanently inflate the share price and trap subsequent depositors; or a contract guarded by `require(address(this).balance > threshold)` that the attacker manipulates by sending dust.
- **FP:** Minimum deposit enforced unconditionally: `require(amount >= MIN_DEPOSIT)`. Cooldown reset only for the depositing user, not system-wide. Time lock assessed independently of deposit amounts on a per-user basis.

**124. Block Timestamp Dependence**

- **Detect:** `block.timestamp` used for game outcomes, randomness (`block.timestamp % N`), or auction timing where a 15-second manipulation changes the outcome. (SWC-116)
- **FP:** Timestamp used only for periods spanning hours or days, where 15-second validator manipulation has no meaningful impact on the outcome. Timestamp used only for event logging with no effect on state or logic.

**125. Function Selector Clash in Proxy**

- **Detect:** Proxy and implementation share a 4-byte function selector collision. A call intended for the implementation gets routed to the proxy's own function (or vice versa), silently executing the wrong logic.
- **FP:** Transparent proxy pattern used — admin calls always route to the proxy admin and user calls always delegate, so the implementation selector space is the only relevant one for users. UUPS proxy with no custom functions in the proxy shell — all calls delegate unconditionally, making selector clashes between proxy and implementation impossible.

**126. ERC4626 Missing Allowance Check in withdraw() / redeem()**

- **Detect:** `withdraw(assets, receiver, owner)` or `redeem(shares, receiver, owner)` where `msg.sender != owner` but no allowance validation or decrement is performed before burning shares. EIP-4626 requires that if `caller != owner`, the caller must hold sufficient share approval; the allowance must be consumed atomically. Missing this check lets any address burn shares from an arbitrary owner and redirect the assets to any receiver — equivalent to an unchecked `transferFrom`.
- **FP:** `_spendAllowance(owner, caller, shares)` called unconditionally before the share burn when `caller != owner`. OpenZeppelin ERC4626 used without custom overrides of `withdraw`/`redeem`.

**127. Missing `_disableInitializers()` on Implementation Contract**

- **Detect:** The implementation contract behind a proxy does not call `_disableInitializers()` in its constructor. Even when the proxy is properly initialized, the implementation contract itself remains directly callable. An attacker calls `initialize()` on the implementation address (not the proxy), becomes its owner, then calls `upgradeTo()` to point it at a malicious contract containing `selfdestruct`. If the proxy delegates to this now-destroyed implementation, all calls to the proxy revert — bricking the system. This is exactly how the Wormhole whitehat exploit worked: the attacker initialized the implementation, became guardian, upgraded to a `selfdestruct` contract, and destroyed the bridge's implementation. Pattern: implementation contract inherits `Initializable` but its constructor is empty or missing. No `/// @custom:oz-upgrades-unsafe-allow constructor` + `_disableInitializers()` pair.
- **FP:** Constructor contains `_disableInitializers()`: `constructor() { _disableInitializers(); }`. Implementation uses the `@custom:oz-upgrades-unsafe-allow constructor` annotation with an explicit disable call. Contract is not behind a proxy (standalone deployment).

**128. validateUserOp Missing EntryPoint Caller Restriction**

- **Detect:** `validateUserOp(UserOperation calldata, bytes32, uint256)` is `public` or `external` without a guard that enforces `msg.sender == address(entryPoint)`. Anyone can call the validation function directly, bypassing the EntryPoint's replay and gas-accounting protections. Also check `execute` and `executeBatch` — they should be similarly restricted to the EntryPoint or the wallet owner.
- **FP:** Function starts with `require(msg.sender == address(_entryPoint), ...)` or uses an `onlyEntryPoint` modifier. Internal visibility used.

**129. Deployment Transaction Front-Running (Ownership Hijack)**

- **Detect:** Deployment script broadcasts a contract creation transaction to the public mempool without using a private/protected transaction relay. An attacker sees the pending deployment, extracts the bytecode, and deploys an identical contract first with themselves as the owner — or front-runs the initialization with different parameters. For token contracts, the attacker can deploy to a predictable address and pre-seed liquidity pairs to manipulate trading. Pattern: deployment transactions sent via public RPC (`eth_sendRawTransaction`) without Flashbots Protect, MEV Blocker, or a private mempool relay. Constructor sets `owner = msg.sender` or `admin = tx.origin` without additional verification.
- **FP:** Deployment uses a private transaction relay (Flashbots Protect, MEV Blocker, private mempool). Owner address is passed as a constructor argument rather than derived from `msg.sender`. Deployment is on a chain without a public mempool (e.g., Arbitrum sequencer, private L2). Contract uses CREATE2 with a salt tied to the deployer's address.

**130. Diamond Proxy Facet Selector Collision**

- **Detect:** EIP-2535 Diamond proxy where two facets register functions with the same 4-byte selector. One facet silently shadows the other. A malicious facet added via `diamondCut` can hijack calls intended for critical functions like `withdraw()` or `transfer()`. Pattern: `diamondCut` adds a new facet whose function selectors overlap with existing facets without on-chain collision validation.
- **FP:** `diamondCut` implementation validates no selector collisions before adding/replacing facets. `DiamondLoupeFacet` used to enumerate and verify all selectors post-cut. Multisig + timelock required for `diamondCut` operations.

**131. ERC777 tokensToSend / tokensReceived Reentrancy**

- **Detect:** Contract calls `transfer()` or `transferFrom()` on a token that may implement ERC777 (registered via ERC1820 registry) before completing state updates. ERC777 fires a `tokensToSend` hook on the sender's registered hook contract and a `tokensReceived` hook on the recipient's — these callbacks trigger on plain ERC20-style `transfer()` calls, not just ETH. A recipient's `tokensReceived` or sender's `tokensToSend` can re-enter the calling contract before balances are updated. Pattern: `token.transferFrom(msg.sender, address(this), amount)` followed by state updates, or `token.transfer(user, amount)` before clearing user balance, with no `nonReentrant` guard and no ERC777 exclusion.
- **FP:** Strict CEI — all state committed before any token transfer. `nonReentrant` applied to all public entry points. Protocol enforces a token whitelist that explicitly excludes ERC777-compatible tokens.

**132. Deployer Privilege Retention Post-Deployment**

- **Detect:** The deployer EOA retains elevated permissions (owner, admin, minter, pauser, upgrader) after the deployment script completes. The deployer's private key — which was necessarily hot during deployment — remains a single point of failure for the entire system. If the key is compromised later, the attacker inherits all admin capabilities. Pattern: deployment script calls `new Contract()` or `initialize()` but never transfers ownership to a multisig, timelock, or governance contract. `Ownable` constructor sets `owner = msg.sender` (the deployer) and no subsequent `transferOwnership()` call exists in the script. `AccessControl` grants `DEFAULT_ADMIN_ROLE` to the deployer without a later `renounceRole()`.
- **FP:** Deployment script includes explicit ownership transfer: `contract.transferOwnership(multisig)`. Admin role is granted to a timelock or governance contract, and deployer renounces its role in the same script. Two-step ownership transfer (`Ownable2Step`) used with pending owner set to the target multisig.

**133. Counterfactual Wallet Initialization Parameters Not Bound to Deployed Address**

- **Detect:** Factory's `createAccount` uses `CREATE2` but the salt does not incorporate all initialization parameters (especially the owner address). An attacker can call `createAccount` with a different owner before the legitimate user, deploying a wallet they control to the same counterfactual address. Pattern: `salt` is a plain user-supplied value or only includes a partial subset of init data; `CREATE2` address can be predicted and front-run with different constructor args.
- **FP:** Salt is derived from all initialization parameters: `salt = keccak256(abi.encodePacked(owner, ...))`. Factory reverts if the account already exists. Initializer is called atomically in the same transaction as deployment.
