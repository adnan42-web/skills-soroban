# Attack Vectors Reference (2/3 — Vectors 46–89)

133 total attack vectors. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

**46. Missing Chain ID Validation in Deployment Configuration**

- **Detect:** Deployment script reads RPC endpoint and chain parameters from environment variables or config files without validating that the connected chain matches the intended target. A misconfigured `RPC_URL` (e.g., mainnet URL in a staging config, or a compromised/rogue RPC endpoint) causes the script to deploy to the wrong chain with real funds, or to a chain where the deployment has different security assumptions. Pattern: script reads `$RPC_URL` from `.env` without calling `eth_chainId` and asserting it matches the expected value. Foundry script without `--chain-id` flag or `block.chainid` assertion. No dry-run or simulation step before broadcast.
- **FP:** Script asserts `require(block.chainid == expectedChainId)` at the start. Foundry `--verify` flag combined with explicit `--chain` parameter. CI/CD pipeline validates chain ID before executing deployment. Multi-chain deployment framework (e.g., Foundry multi-fork) with per-chain config validated against RPC responses.

**47. Missing or Incorrect Access Modifier**

- **Detect:** State-changing function (`setOwner`, `withdrawFunds`, `mint`, `pause`, `setOracle`, `updateFees`) has no access guard, or modifier references an uninitialized variable. `public`/`external` visibility on privileged operations with no restriction.
- **FP:** Function is genuinely permissionless by design — any caller can legitimately invoke it and the worst-case outcome is a non-critical state transition (e.g., triggering a public distribution, settling an open auction, or advancing a time-locked process that anyone can advance).

**48. Blacklistable or Pausable Token in Critical Payment Path**

- **Detect:** Protocol hard-codes or accepts USDC, USDT, or another token with admin-controlled blacklisting or global pause, and routes payments through a push model: `token.transfer(recipient, amount)`. If `recipient` is blacklisted by the token issuer, or the token is globally paused, every push to that address reverts — permanently bricking withdrawals, liquidations, fee collection, or reward claims. Attacker can weaponize this by ensuring a critical address (vault, fee receiver, required counterparty) is blacklisted. Also relevant: protocol sends fee to a fixed `feeRecipient` inside a state-changing function — if `feeRecipient` is blacklisted, the entire function is permanently DOSed.
- **FP:** Pull-over-push: recipients withdraw their own funds; a blacklisted recipient only blocks themselves. Skip-on-failure logic (`try/catch`) used for fee or reward distribution. Supported token whitelist explicitly excludes blacklistable/pausable tokens.

**49. Missing chainId (Cross-Chain Replay)**

- **Detect:** Signed payload doesn't include `chainId`. Valid signature on mainnet replayable on forks or other EVM chains where the contract is deployed. Or `chainId` hardcoded at deployment rather than read via `block.chainid`.
- **FP:** EIP-712 domain separator includes `chainId: block.chainid` (dynamic) and `verifyingContract`. Domain separator re-checked or invalidated if `block.chainid` changes.

**50. Merkle Tree Second Preimage Attack**

- **Detect:** `MerkleProof.verify(proof, root, leaf)` where the leaf is derived from variable-length or 32-byte user-supplied input without double-hashing or type-prefixing. An attacker can pass a 64-byte value (concatenation of two sibling hashes at an intermediate node) as if it were a leaf — the standard hash tree produces the same root, so verification passes with a shorter proof. Pattern: `leaf = keccak256(abi.encodePacked(account, amount))` without an outer hash or prefix; no length restriction enforced on leaf inputs.
- **FP:** Leaves are double-hashed (`keccak256(keccak256(data))`). Leaf includes a type prefix or domain tag that intermediate nodes cannot satisfy. Input length enforced to be ≠ 64 bytes. OpenZeppelin MerkleProof ≥ v4.9.2 with `processProofCalldata` or sorted-pair variant used correctly.

**51. Missing onERC1155BatchReceived Causes Token Lock on Batch Transfer**

- **Detect:** Receiving contract implements `IERC1155Receiver.onERC1155Received` (for single transfers) but not `IERC1155Receiver.onERC1155BatchReceived` (for batch transfers), or implements the latter returning a wrong selector. `safeBatchTransferFrom` to such a contract reverts on the callback check, permanently preventing batch delivery. Protocol that accepts individual deposits from users but attempts batch settlement or batch reward distribution internally will be permanently stuck if the recipient is one of these incomplete receivers. Pattern: `onERC1155BatchReceived` is absent, `returns (bytes4(0))`, or reverts unconditionally.
- **FP:** Contract implements both `onERC1155Received` and `onERC1155BatchReceived` returning the correct selectors, or inherits from OZ `ERC1155Holder` which provides both. Protocol's internal settlement exclusively uses single-item `safeTransferFrom` and is documented to never issue batch calls to contract recipients.

**52. ERC4626 Preview Rounding Direction Violation**

- **Detect:** `previewDeposit(a)` returns more shares than `deposit(a)` actually mints; `previewRedeem(s)` returns more assets than `redeem(s)` actually transfers; `previewMint(s)` returns fewer assets than `mint(s)` actually charges; `previewWithdraw(a)` returns fewer shares than `withdraw(a)` actually burns. EIP-4626 mandates that preview functions round in the vault's favor — they must never overstate what the user receives or understate what the user pays. Custom `_convertToShares`/`_convertToAssets` implementations that apply the wrong `Math.mulDiv` rounding direction (e.g., `Rounding.Ceil` when `Rounding.Floor` is required) violate this. Integrators that use preview return values for slippage checks will pass with an incorrect expectation and receive less than they planned for.
- **FP:** OpenZeppelin ERC4626 base used without overriding `_convertToShares`/`_convertToAssets`. Custom implementation explicitly passes `Math.Rounding.Floor` for share issuance (deposit/previewDeposit) and `Math.Rounding.Ceil` for share burning (withdraw/previewWithdraw).

**53. ERC721 Unsafe Transfer to Non-Receiver**

- **Detect:** `_transfer()` (unsafe) used instead of `_safeTransfer()`, or `_mint()` instead of `_safeMint()`, sending NFTs to contracts that may not implement `IERC721Receiver`. Tokens permanently locked in the recipient contract.
- **FP:** All transfer and mint paths use `safeTransferFrom` or `_safeMint`, which perform the `onERC721Received` callback check. Function is `nonReentrant` to prevent callback abuse.

**54. Multi-Block TWAP Oracle Manipulation**

- **Detect:** Protocol uses a Uniswap V2 or V3 TWAP with an observation window shorter than 30 minutes (~150 blocks). Post-Merge PoS validators who are elected to propose consecutive blocks can hold an AMM pool in a manipulated state across multiple blocks with no flash-loan repayment pressure. Each held block contributes a manipulated price sample to the TWAP accumulator. With short windows (e.g., 5–10 minutes), controlling 2–3 consecutive blocks shifts the TWAP enough to trigger profitable liquidations or over-collateralized borrows. Cost: only the capital to move the pool, held for a few blocks — far cheaper than equivalent single-block manipulation.
- **FP:** TWAP window ≥ 30 minutes. Chainlink or Pyth used as the price source instead of AMM TWAP. Protocol uses max-deviation circuit breaker that rejects price updates deviating more than X% from a secondary source.

**55. Spot Price Oracle from AMM**

- **Detect:** Price computed from AMM reserves directly: `price = reserve0 / reserve1`, `getAmountsOut()`, `getReserves()`. Any lending, liquidation, or collateral logic built on spot price is flash-loan exploitable atomically.
- **FP:** TWAP oracle with a 30-minute or longer observation window. Chainlink or Pyth as primary source.

**56. Delegatecall to Untrusted / User-Supplied Callee**

- **Detect:** `address(target).delegatecall(data)` where `target` is user-provided or unconstrained. Callee executes in the caller's storage context - can overwrite owner, balances, call `selfdestruct`. (SWC-112)
- **FP:** `target` is a hardcoded immutable verified library address that cannot be changed after deployment.

**57. ERC1155 setApprovalForAll Grants All-Token-All-ID Operator Access**

- **Detect:** Protocol requires `setApprovalForAll(protocol, true)` to enable deposits, staking, or settlement across a user's ERC1155 holdings. Unlike ERC20 allowances (per token, per amount) or ERC721 single-token approve, ERC1155 has no per-ID or per-amount approval granularity — `setApprovalForAll` is an all-or-nothing grant covering every token ID the user holds and any they acquire in the future. A single compromised or malicious operator can call `safeTransferFrom(victim, attacker, anyId, fullBalance, "")` for every ID in one or more transactions, draining everything. Pattern: protocol documents "approve all tokens to use our platform" as a required first step.
- **FP:** Protocol uses individual `safeTransferFrom(from, to, id, amount, data)` calls that each require the user as `msg.sender` directly. Operator is a formally verified immutable contract whose only transfer logic routes tokens to the protocol's own escrow. Users are prompted to revoke approval via `setApprovalForAll(protocol, false)` after each session.

**58. ERC-1271 isValidSignature Delegated to Untrusted or Arbitrary Module**

- **Detect:** `validateUserOp` or the wallet's `isValidSignature` implementation calls `isValidSignature(hash, sig)` on an externally-supplied or user-registered contract address without verifying that the contract is an explicitly whitelisted module or owner-registered guardian. A malicious module that always returns `0x1626ba7e` (ERC-1271 magic value) passes all signature checks. Pattern: `ISignatureValidator(module).isValidSignature(...)` where `module` comes from user input or an unguarded registry.
- **FP:** `isValidSignature` is only delegated to contracts in an owner-controlled whitelist or to the wallet owner's EOA address directly. Module registry has a timelock or guardian approval before a new module can validate signatures.

---

**59. Uninitialized Implementation Takeover**

- **Detect:** Implementation contract has an `initialize()` function but the constructor does not call `_disableInitializers()`. Anyone can call `initialize()` directly on the implementation (not the proxy), claim ownership, then call `upgradeTo()` to replace the implementation or `selfdestruct` via delegatecall. Pattern: UUPS/Transparent/Beacon implementation with `initializer` modifier but no `_disableInitializers()` in constructor. Real-world: Wormhole Bridge (2022), Parity Multisig Library (2017, ~$150M frozen).
- **FP:** Constructor calls `_disableInitializers()`. `initializer` modifier from OpenZeppelin `Initializable` is present and correctly gates the function. Implementation verifies it is being called through a proxy before executing any logic.

**60. Cross-Function Reentrancy**

- **Detect:** Two functions share a state variable. Function A makes an external call before updating shared state; Function B reads or modifies that same state. `nonReentrant` on A but not B.
- **FP:** Both functions are guarded by the same contract-level mutex. Shared state fully updated before any external call in A.

**61. Flash Loan Governance Attack**

- **Detect:** Governance voting uses `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` (current block). Attacker borrows governance tokens, votes, repays in one tx.
- **FP:** Uses `getPastVotes(account, block.number - 1)` (prior block, un-manipulable in current tx). Timelock between snapshot and vote. Staking required before voting.

**62. Paymaster Gas Penalty Undercalculation**

- **Detect:** Paymaster computes the prefund amount as `requiredPreFund + (refundPostopCost * maxFeePerGas)` without including the 10% penalty the EntryPoint applies to unused execution gas (`postOpUnusedGasPenalty`). When a UserOperation specifies a large `executionGasLimit` and uses little of it, the EntryPoint deducts a penalty the paymaster did not budget for, draining its deposit. Pattern: prefund formula lacks any reference to unused-gas penalty or `_getUnusedGasPenalty`.
- **FP:** Prefund calculation explicitly adds the unused-gas penalty: `requiredPreFund + penalty + (refundCost * price)`. Paymaster uses conservative overestimation that covers worst-case penalty.

**63. Nested Mapping Inside Struct Not Cleared on `delete`**

- **Detect:** `delete myMapping[key]` or `delete myArray[i]` where the deleted item is a struct containing a `mapping` or a dynamic array. Solidity's `delete` zeroes primitive fields but does not recursively clear mappings — the nested mapping's entries persist in storage. If the same key is later reused (e.g., a re-deposited user, re-created proposal), old mapping values are unexpectedly visible. Pattern: struct with `mapping(address => uint256)` or `uint256[]` field; `delete` called on the struct without manually iterating and clearing the nested mapping.
- **FP:** Nested mapping manually cleared before `delete` (iterate and zero every entry). Struct key is never reused after deletion. Codebase explicitly accounts for residual mapping values in subsequent reads (always initialises before use).

**64. Block Number as Timestamp Approximation**

- **Detect:** Time computed as `(block.number - startBlock) * 13` assuming fixed block times. Post-Merge Ethereum has variable block times; Polygon/Arbitrum/BSC have very different averages. Causes wrong interest accrual, vesting, or reward calculations.
- **FP:** `block.timestamp` used instead of `block.number` for all time-sensitive calculations.

**65. Non-Standard ERC20 Return Values (USDT-style)**

- **Detect:** `require(token.transfer(to, amount))` reverts on tokens that return nothing (USDT, BNB). Or return value ignored entirely (silent failure on failed transfer). (SWC-104)
- **FP:** OpenZeppelin `SafeERC20.safeTransfer()`/`safeTransferFrom()` used throughout.

**66. Force-Feeding ETH via selfdestruct or coinbase**

- **Detect:** Business logic relies on `address(this).balance` for invariant checks, share/deposit accounting, or as a denominator: `require(address(this).balance == trackingVar)`, `shares = msg.value * totalSupply / address(this).balance`. ETH can be force-sent without triggering `receive()`/`fallback()` via: (1) `selfdestruct(payable(target))` — even if target has no payable functions; (2) pre-deployment: computing a contract's deterministic address and sending ETH before it is deployed; (3) being set as the `coinbase` address for a mined block. Forced ETH inflates the balance above expected values, breaking any invariant or ratio built on it.
- **FP:** All accounting uses a private `uint256 _deposited` variable incremented only inside payable functions — never `address(this).balance`. `address(this).balance` appears only in informational view functions, not in guards or financial math.

**67. `selfdestruct` via Delegatecall Bricking**

- **Detect:** Implementation contract contains `selfdestruct`, or allows `delegatecall` to an arbitrary address that may contain `selfdestruct`. If an attacker gains execution in the implementation context (e.g. via uninitialized takeover), they can call `selfdestruct` which executes in the proxy's context, permanently bricking it. For UUPS, the upgrade logic is destroyed with the implementation -- no recovery. Pattern: `selfdestruct(...)` anywhere in implementation code, or `target.delegatecall(data)` where `target` is user-supplied. Real-world: Parity (2017), Wormhole (2022). Post-Dencun (EIP-6780): `selfdestruct` only fully deletes contracts created in the same transaction -- mitigates but does not fully eliminate this vector.
- **FP:** No `selfdestruct` opcode in implementation or any contract it delegatecalls to. No arbitrary delegatecall targets. `_disableInitializers()` called in constructor.

---

**68. ecrecover Returns address(0) on Invalid Signature**

- **Detect:** Raw `ecrecover(hash, v, r, s)` used without checking that the returned address is not `address(0)`. An invalid or malformed signature does not revert — `ecrecover` silently returns `address(0)`. If the code then checks `recovered == authorizedSigner` and `authorizedSigner` is uninitialized (defaults to `address(0)`), or if `permissions[recovered]` is read from a mapping that has a non-zero default for `address(0)` (e.g., from a prior `grantRole(ROLE, address(0))`), an attacker passes any garbage signature to gain privileges.
- **FP:** OpenZeppelin `ECDSA.recover()` used — it explicitly reverts when `ecrecover` returns `address(0)`. Explicit `require(recovered != address(0))` check present before any comparison or lookup.

**69. ERC1155 Custom Burn Without Caller Authorization Check**

- **Detect:** Custom `burn(address from, uint256 id, uint256 amount)` or `burnBatch(address from, ...)` function is callable by any address without verifying that `msg.sender == from` or that `msg.sender` is an approved operator for `from`. Any caller can burn another user's tokens by passing their address as `from`. Pattern: `function burn(address from, uint256 id, uint256 amount) external { _burn(from, id, amount); }` with no authorization guard. Distinct from OZ's `_burn` (which is internal) — the risk is in public wrappers that expose it without access control.
- **FP:** Burn function requires `require(from == msg.sender || isApprovedForAll(from, msg.sender), "not authorized")` before calling `_burn`. OZ's `ERC1155Burnable` extension used — it includes the owner/operator check. Burn is restricted to a privileged role (admin/governance) and the `from` address is not user-supplied.

**70. Re-initialization Attack**

- **Detect:** Initialization guard is improperly implemented or reset during an upgrade, allowing `initialize()` to be called again to overwrite critical state (owner, token addresses, rates). Pattern: V2 uses `initializer` modifier instead of `reinitializer(2)` on its new init function; upgrade resets the initialized version counter; custom initialization flag uses a `bool` that gets storage-collided to `false`. Real-world: AllianceBlock (2024) -- upgrade reset `initialized` to false, attacker re-invoked initializer.
- **FP:** OpenZeppelin's `reinitializer(version)` used for V2+ initialization with correctly incrementing version numbers. `initializer` modifier on original init, `reinitializer(N)` on subsequent versions. Integration tests verify `initialize()` reverts after first call.

**71. UUPS `_authorizeUpgrade` Missing Access Control**

- **Detect:** UUPS implementation overrides `_authorizeUpgrade()` but the override body is empty or has no access-control modifier (`onlyOwner`, `onlyRole`, etc.). Anyone can call `upgradeTo()` on the proxy and replace the implementation with arbitrary code. Pattern: `function _authorizeUpgrade(address) internal override {}` with no restriction. Real-world: CVE-2021-41264 -- >$50M at risk across KeeperDAO, Rivermen NFT, and others.
- **FP:** `_authorizeUpgrade()` has `onlyOwner` or equivalent modifier. OpenZeppelin `UUPSUpgradeable` base used, which forces the override. Multi-sig or governance controls the owner role.

**72. Small-Type Arithmetic Overflow Before Upcast**

- **Detect:** Arithmetic expression operates on `uint8`, `uint16`, `uint32`, `int8`, or other sub-256-bit types before the result is assigned to a wider type. Pattern: `uint256 result = a * b` where `a` and `b` are `uint8` — multiplication executes in `uint8` and overflows silently (wraps mod 256) before widening. Also: ternary returning a small literal `(condition ? 1 : 0)` inferred as `uint8`; addition `uint16(x) + uint16(y)` assigned to `uint32`. Underflow possible for signed sub-types.
- **FP:** Each operand is explicitly upcast before the operation: `uint256(a) * uint256(b)`. SafeCast used. Solidity 0.8+ overflow protection applies only within the type of the expression — if both operands are `uint8`, the check is still on `uint8` range, not `uint256`.

**73. ERC1155 uri() Missing {id} Substitution Causes Metadata Collapse**

- **Detect:** `uri(uint256 id)` returns a fully resolved URL (e.g., `"https://api.example.com/token/42"`) instead of a template containing the literal `{id}` placeholder as required by EIP-1155. Clients and marketplaces that follow the standard substitute the zero-padded 64-character hex token ID for `{id}` client-side — returning a fully resolved URL breaks this substitution, pointing all IDs to the same metadata endpoint or creating malformed double-substituted URLs. Additionally, if `uri(id)` returns an empty string or a hardcoded static value identical for all IDs, off-chain systems treat all tokens as identical, destroying per-token metadata and market value.
- **FP:** `uri(id)` returns a string containing the literal `{id}` substring per EIP-1155 spec, and clients substitute the hex-encoded token ID. Protocol overrides `uri(id)` to return a fully unique per-ID on-chain URI (e.g., full base64-encoded JSON) and explicitly documents deviation from the `{id}` substitution requirement.

**74. EIP-2612 Permit Front-Run Causing DoS**

- **Detect:** Contract calls `token.permit(owner, spender, value, deadline, v, r, s)` inline as part of a combined permit-and-action function, with no `try/catch` around the permit call. The same permit signature can be submitted by anyone — if an attacker (or MEV bot) front-runs by submitting the permit signature first, the nonce is incremented; the subsequent victim transaction's inline `permit()` call then reverts (wrong nonce), causing the entire action to fail. Because the user only has the one signature, they may be permanently blocked from that code path.
- **FP:** Permit wrapped in `try { token.permit(...); } catch {}` — falls through and relies on pre-existing allowance if permit already consumed. Permit is a standalone user call; the main action function only calls `transferFrom` (not combined).

**75. ERC4626 Caller-Dependent Conversion Functions**

- **Detect:** `convertToShares()` or `convertToAssets()` branches on `msg.sender`-specific state — per-user fee tiers, whitelist status, individual balances, or allowances — causing identical inputs to return different outputs for different callers. EIP-4626 requires these functions to be caller-independent. Downstream aggregators, routers, and on-chain interfaces call these functions to size positions before routing; a caller-dependent result silently produces wrong sizing for some users.
- **FP:** Implementation reads only global vault state (`totalSupply()`, `totalAssets()`, protocol-wide fee constants) with no `msg.sender`-dependent branching.

**76. Non-Atomic Proxy Initialization (Front-Running `initialize()`)**

- **Detect:** Deployment script deploys a proxy contract in one transaction and calls `initialize()` in a separate, subsequent transaction. Between these two transactions the proxy sits on-chain in an uninitialized state. An attacker monitoring the mempool sees the deployment, front-runs the `initialize()` call, and becomes the owner/admin of the proxy. This is the root cause of the Wormhole bridge vulnerability ($10M bounty) and the broader CPIMP (Clandestine Proxy In the Middle of Proxy) attack class. Pattern: `deploy(proxy)` followed by a separate `proxy.initialize(...)` call in the script rather than passing initialization calldata to the proxy constructor. In Foundry scripts, look for `new TransparentUpgradeableProxy(impl, admin, "")` with empty `data` bytes followed by a later `initialize()` call. In Hardhat, look for two separate `await` calls — one for deploy, one for initialize.
- **FP:** Proxy constructor receives initialization calldata as the third argument: `new TransparentUpgradeableProxy(impl, admin, abi.encodeCall(Contract.initialize, (...)))`. OpenZeppelin `deployProxy()` helper used, which atomically deploys and initializes. Script uses a deployer factory contract that performs deploy+init in a single on-chain transaction.

**77. Non-Atomic Proxy Deployment Enabling CPIMP Takeover**

- **Detect:** Deployment script deploys a proxy in one transaction and calls `initialize()` in a separate one, creating a window where an attacker front-runs initialization and inserts a malicious middleman implementation (CPIMP) that persists across upgrades by restoring itself in the ERC-1967 slot after each delegatecall. Pattern: `new TransparentUpgradeableProxy(impl, admin, "")` with empty `data` followed by a separate `proxy.initialize(...)`. In Foundry: `new ERC1967Proxy(address(impl), "")` then a later `initialize()`. In Hardhat: two separate `await` calls for deploy and initialize.
- **FP:** Proxy constructor receives initialization calldata atomically: `new TransparentUpgradeableProxy(impl, admin, abi.encodeCall(Contract.initialize, (...)))`. OpenZeppelin `deployProxy()` helper used. `_disableInitializers()` called in implementation constructor.

**78. Unsafe Downcast / Integer Truncation**

- **Detect:** Explicit cast to smaller type without bounds check: `uint128(largeUint256)`. Solidity ≥0.8 silently truncates on downcast (does NOT revert). Especially dangerous in price feeds, share calculations, timestamps.
- **FP:** Value validated against the target type's maximum before cast (e.g., `require(x <= type(uint128).max)`). OpenZeppelin `SafeCast` library used.

**79. ERC721 onERC721Received Arbitrary Caller Spoofing**

- **Detect:** Contract implements `onERC721Received` and uses its parameters (`operator`, `from`, `tokenId`) to update state — recording ownership, incrementing counters, or crediting balances — without verifying that `msg.sender` is the expected NFT contract address. Anyone can call `onERC721Received(attacker, victim, fakeTokenId, "")` directly with fabricated parameters, fooling the contract into believing it received an NFT it never got. Pattern: `function onERC721Received(...) { credited[from][tokenId] = true; }` with no `require(msg.sender == nftContract)`.
- **FP:** `msg.sender` is validated against a known NFT contract address before any state update: `require(msg.sender == address(nft))`. The function is `view` or reverts unconditionally (acts as a sink only). State changes are gated on verifiable on-chain ownership (`IERC721(msg.sender).ownerOf(tokenId) == from`) before committing.

**80. Storage Layout Shift on Upgrade**

- **Detect:** V2 implementation inserts a new state variable in the middle of the contract rather than appending it at the end. All subsequent variables shift to different storage slots, silently corrupting state. Pattern: V1 has `(owner, totalSupply, balances)` at slots (0, 1, 2); V2 inserts `pauser` at slot 1, pushing `totalSupply` to read from the `balances` mapping slot. Also: changing a variable's type between versions (e.g. `uint128` to `uint256`) shifts slot boundaries.
- **FP:** New variables are only appended after all existing ones. `@openzeppelin/upgrades` storage layout validation is used in CI and confirms no slot shifts. Variable types are unchanged between versions.

**81. Return Bomb (Returndata Copy DoS)**

- **Detect:** `(bool success, bytes memory data) = target.call(payload)` where `target` is user-supplied or unconstrained. Malicious target returns huge returndata; copying it costs enormous gas.
- **FP:** Returndata not copied (`assembly { success := call(...) }` without copy, or gas-limited call). Callee is a hardcoded immutable trusted contract.

**82. Proxy Admin Key Compromise**

- **Detect:** Proxy admin (the address authorized to call `upgradeTo`) is a single EOA rather than a multisig or governance contract. A compromised private key allows instant upgrade to a malicious implementation that drains all funds. Pattern: `ProxyAdmin.owner()` returns an EOA; no timelock between upgrade proposal and execution. Real-world: PAID Network (2021) -- attacker obtained admin key, upgraded token proxy to mint unlimited tokens; Ankr (2022) -- compromised deployer key, minted 6 quadrillion aBNBc (~$5M loss).
- **FP:** Admin is a multisig (Gnosis Safe) with threshold >= 2. Timelock enforced (24-72h delay). Proxy admin role is separate from operational roles. Admin key rotation and monitoring in place.

**83. Improper Flash Loan Callback Validation**

- **Detect:** `onFlashLoan` callback does not verify `msg.sender == lendingPool`, or does not verify `initiator`, or does not check `token`/`amount` match. Attacker can call the callback directly without a real flash loan.
- **FP:** Both `msg.sender == address(lendingPool)` and `initiator == address(this)` are validated. Token and amount checked against pre-stored values.

**84. ERC721 / ERC1155 Type Confusion in Dual-Standard Marketplace**

- **Detect:** Marketplace or aggregator handles both ERC721 and ERC1155 in a shared `buy` or `fill` function using a type flag, but the `quantity` parameter required for ERC1155 amount is also accepted for ERC721 without validation that it equals 1. Price is computed as `price * quantity`. An attacker passes `quantity = 0` for an ERC721 listing — price calculation yields zero, NFT transfers successfully, payment is zero. Root cause of the TreasureDAO exploit (March 2022, $1.4M): `buyItem(listingId, 0)` for an ERC721 listing passed all checks and transferred the NFT for free.
- **FP:** ERC721 branch explicitly `require(quantity == 1)` before any price arithmetic. Separate code paths for ERC721 and ERC1155 with no shared quantity parameter. Price computed independently of quantity for ERC721 listings.

---

**85. Governance Flash-Loan Upgrade Hijack**

- **Detect:** Proxy upgrades controlled by on-chain governance that uses `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` (current block) for vote weight. Attacker flash-borrows governance tokens, self-delegates, votes to approve a malicious upgrade, and executes -- all within one transaction or block if no timelock. Pattern: Governor with no voting delay, no timelock, or snapshot at current block.
- **FP:** Uses `getPastVotes(account, block.number - 1)` (prior block, un-manipulable in current tx). Timelock of 24-72h between proposal and execution. Quorum thresholds high enough to resist flash loan manipulation. Staking lockup required before voting power is active.

**86. DoS via Unbounded Loop**

- **Detect:** Loop iterates over an array that grows with user interaction and is unbounded: `for (uint i = 0; i < users.length; i++) { ... }`. If anyone can push to `users`, the function will eventually hit the block gas limit. (SWC-128)
- **FP:** Array length capped at insertion time with a `require(arr.length < MAX)` check. Loop iterates a fixed small constant count.

**87. ERC4626 Deposit/Withdraw Share-Count Asymmetry**

- **Detect:** For the same asset amount `a`, `withdraw(a)` burns fewer shares than `deposit(a)` minted — meaning a user can deposit, immediately withdraw the same assets, and retain surplus shares for free. Equivalently, `deposit(withdraw(a).assets)` returns more shares than `withdraw(a)` burned, manufacturing shares from nothing. Root cause: `_convertToShares` applies `Rounding.Floor` (rounds down) for both the deposit path (shares issued) and the withdraw path (shares required to burn), when EIP-4626 requires deposit to round down and withdraw to round up. The gap between the two floors is the free share. Pattern: a single `_convertToShares(assets, Rounding.Floor)` helper called on both code paths without distinct rounding arguments. (Covers `prop_RT_deposit_withdraw` and `prop_RT_withdraw_deposit` from the a16z ERC4626 property test suite.)
- **FP:** `deposit`/`previewDeposit` call `_convertToShares(assets, Math.Rounding.Floor)` and `withdraw`/`previewWithdraw` call `_convertToShares(assets, Math.Rounding.Ceil)` — opposite directions, vault-favorable in each case. OpenZeppelin ERC4626 used without custom conversion overrides.

**88. Diamond Proxy Cross-Facet Storage Collision**

- **Detect:** EIP-2535 Diamond proxy where two or more facets declare storage variables without EIP-7201 namespaced storage structs — each facet using plain `uint256 foo` or `mapping(...)` declarations that Solidity places at sequential storage slots 0, 1, 2, …. Different facets independently start at slot 0, so both write to the same slot. Also flag: facet uses a library that writes to storage without EIP-7201 namespacing.
- **FP:** All facets store state exclusively in a single `DiamondStorage` struct retrieved via `assembly { ds.slot := DIAMOND_STORAGE_POSITION }` using a namespaced position (EIP-7201 formula). No facet declares top-level state variables. OpenZeppelin's ERC-7201 `@custom:storage-location` pattern used correctly.

**89. Cross-Contract Reentrancy**

- **Detect:** Two separate contracts share logical state (e.g., balances in A, collateral check in B). A makes an external call before syncing the state B reads. A's `ReentrancyGuard` does not protect B.
- **FP:** The state B reads is synchronized before A's external call. No re-entry path exists from A's external callee back into B — verified by tracing the full call graph.
