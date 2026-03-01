# Attack Vectors Reference (1/3 — Vectors 1–45)

133 total attack vectors. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

**1. Staking Reward Front-Run by New Depositor**

- **Detect:** Reward checkpoint (`rewardPerTokenStored`, `lastUpdateTime`) is updated lazily — only when a user action triggers it — and the update happens AFTER the new stake is recorded in `_balances` or `totalSupply`. A new staker can join immediately before `notifyRewardAmount()` is called (or immediately before a large pending reward accrues), and the checkpoint then distributes the new rewards pro-rata over a supply that includes the attacker's stake. The attacker earns rewards for a period they were not staked. Pattern: `_balances[user] += amount; totalSupply += amount;` executed before `updateReward()`.
- **FP:** `updateReward(account)` is the very first step of `stake()` — executed before any balance update — so new stakers start from the current `rewardPerTokenStored` and earn nothing retroactively. `rewardPerTokenPaid[user]` correctly tracks per-user checkpoint.

**2. ERC1155 safeBatchTransferFrom with Unchecked Mismatched Array Lengths**

- **Detect:** Custom ERC1155 overrides `_safeBatchTransferFrom` or iterates `ids` and `amounts` arrays in a loop without first asserting `require(ids.length == amounts.length)`. A caller passes `ids = [1, 2, 3]` and `amounts = [100]` — the loop processes only as many iterations as the shorter array (Solidity reverts on OOB access in 0.8+, but a `for (uint i = 0; i < ids.length; i++)` loop that reads `amounts[i]` will revert mid-batch rather than rejecting cleanly). In assembly-optimized or unchecked implementations, the shorter array access silently reads uninitialized memory or produces wrong transfers.
- **FP:** OZ ERC1155 base used without overriding batch transfer — OZ checks `ids.length == amounts.length` at the start and reverts with `ERC1155InvalidArrayLength`. Custom override explicitly asserts equal lengths as its first statement before any transfer logic.

**3. DoS via Push Payment to Rejecting Contract**

- **Detect:** ETH/token distribution in a single loop using push model (`recipient.call{value:}("")`). If any recipient reverts on receive, the entire loop reverts. Also: `transfer()`/`send()` to contracts with expensive `fallback()`. (SWC-113)
- **FP:** Pull-over-push pattern used — recipients withdraw their own funds. Loop uses `try/catch` and continues on failure.

**4. tx.origin Authentication**

- **Detect:** `require(tx.origin == owner)` or `require(tx.origin == authorized)` used for authentication. Vulnerable to phishing via malicious intermediary contract.
- **FP:** `tx.origin == msg.sender` used only to assert caller is not a contract (anti-bot pattern, not auth).

**5. Function Selector Clashing (Proxy Backdoor)**

- **Detect:** Proxy contract contains a function whose 4-byte selector collides with a function in the implementation. Two different function signatures can produce the same selector (e.g. `burn(uint256)` and `collate_propagate_storage(bytes16)` both = `0x42966c68`). When a user calls the implementation function, the proxy's function executes instead, silently running different logic. Pattern: proxy with any non-admin functions beyond `fallback()`/`receive()` -- check all selectors against implementation selectors for collisions.
- **FP:** Transparent proxy pattern used -- admin calls always route to the proxy admin and user calls always delegate, making selector clashes between proxy and implementation impossible. UUPS proxy with no custom functions in the proxy shell -- all calls delegate unconditionally.

**6. validateUserOp Signature Not Bound to nonce or chainId**

- **Detect:** `validateUserOp` reconstructs the signed digest manually (not via `entryPoint.getUserOpHash(userOp)`) and omits `userOp.nonce` or `block.chainid` from the signed payload. Enables cross-chain replay (same signature valid on other chains sharing the contract address) or in-chain replay after the wallet state is reset. Pattern: `keccak256(abi.encode(userOp.sender, userOp.callData, ...))` without nonce/chainId.
- **FP:** Signed digest is computed via `entryPoint.getUserOpHash(userOp)` — EntryPoint includes sender, nonce, chainId, and entryPoint address. Custom digest explicitly includes `block.chainid` and `userOp.nonce`.

**7. Proxy Storage Slot Collision**

- **Detect:** Proxy stores `implementation`/`admin` at sequential slots (0, 1) and implementation contract also declares variables from slot 0. Implementation's slot 0 write overwrites the proxy's `implementation` pointer.
- **FP:** Proxy uses EIP-1967 slots (`keccak256("eip1967.proxy.implementation") - 1`). OpenZeppelin Transparent or UUPS proxy pattern used correctly.

**8. ERC721Consecutive (EIP-2309) Balance Corruption with Single-Token Batch**

- **Detect:** Contract uses OpenZeppelin's `ERC721Consecutive` extension (OZ < 4.8.2) and mints a batch of exactly one token via `_mintConsecutive(to, 1)`. A bug in that version fails to increment the recipient's balance for size-1 batches. `balanceOf(to)` returns 0 despite ownership being assigned. When the owner later calls `transferFrom`, the internal balance decrement underflows (reverts in checked math, or wraps in unchecked), leaving the token in a frozen state or causing downstream accounting errors in any contract that relies on `balanceOf` for reward distribution or collateral checks.
- **FP:** OZ version ≥ 4.8.2 used (patched via GHSA-878m-3g6q-594q). Batch size is always ≥ 2. Contract uses standard `ERC721._mint` (non-consecutive) where every mint writes the balance mapping directly.

**9. ERC1155 Fungible / Non-Fungible Token ID Collision**

- **Detect:** Protocol uses ERC1155 to represent both fungible tokens (specific IDs with `supply > 1`) and unique items (other IDs with intended `supply == 1`), relying only on convention rather than enforcement. No `require(totalSupply(id) == 0)` before minting an "NFT" ID, or no check that prevents minting additional copies of an ID already at supply 1. An attacker who can call the public mint function mints a second copy of an "NFT" ID, breaking uniqueness. Or role tokens (e.g., `ROLE_ID = 1`) are fungible and freely tradeable, undermining access control that is gated on `balanceOf(user, ROLE_ID) > 0`.
- **FP:** Contract explicitly enforces `require(totalSupply(id) + amount <= maxSupply(id))` with `maxSupply` set to 1 for NFT IDs at creation time. Fungible and non-fungible ranges are disjoint and enforced with `require(id < FUNGIBLE_CUTOFF || id >= NFT_START)`. Role tokens are non-transferable (transfer overrides revert for role IDs).

**10. Storage Layout Collision Between Proxy and Implementation**

- **Detect:** Proxy contract declares state variables (e.g. `address admin`, `address implementation`) at standard sequential slots (0, 1, ...) instead of EIP-1967 randomized slots. Implementation also declares variables starting at slot 0. Proxy's admin address is non-zero so implementation reads it as `initialized = true` (or vice versa), enabling re-initialization or corrupting owner. Pattern: custom proxy with `address public admin` at slot 0; no EIP-1967 compliance. Real-world: Audius Governance (2022, ~$6M stolen -- `proxyAdmin` added to proxy storage, shadowing `initialized` flag).
- **FP:** Proxy uses EIP-1967 slots (`keccak256("eip1967.proxy.implementation") - 1`). OpenZeppelin Transparent or UUPS proxy pattern used correctly. No state variables declared in the proxy contract itself.

**11. Metamorphic Contract via CREATE2 + SELFDESTRUCT**

- **Detect:** Contract deployed via `CREATE2` from a factory where the deployer can `selfdestruct` the contract and redeploy different bytecode to the same address. Governance voters verify code at proposal time, but the code can be swapped before execution. Pattern: `create2(0, ..., salt)` deployment + `selfdestruct` in the deployed contract or an intermediate deployer that resets its nonce. Real-world: Tornado Cash Governance (May 2023) -- attacker proposed legitimate contract, `selfdestruct`-ed it, redeployed malicious code at same address, gained 1.2M governance votes, drained ~$2.17M. Post-Dencun (EIP-6780): largely killed for pre-existing contracts, but same-transaction create-destroy-recreate may still work.
- **FP:** Post-Dencun (EIP-6780): `selfdestruct` no longer destroys code unless same transaction as creation. `EXTCODEHASH` verified at execution time, not just proposal time. Contract was not deployed via `CREATE2` from a mutable deployer.

**12. Missing Nonce (Signature Replay)**

- **Detect:** Signed message has no per-user nonce, or nonce is present in the struct but never stored/incremented after use. Same valid signature can be submitted multiple times. (SWC-121)
- **FP:** Monotonic per-signer nonce included in signed payload, stored, checked for reuse, incremented atomically. `usedSignatures[hash]` mapping invalidates after first use.

**13. Front-Running Exact-Zero Balance Check with Dust Transfer**

- **Detect:** An `external` or `public` function contains `require(token.balanceOf(address(this)) == 0)`, `require(address(this).balance == 0)`, or any strict equality check against a zero balance that gates a state transition (e.g., starting an auction, initializing a pool, opening a deposit round). An attacker front-runs the legitimate caller's transaction by sending a dust amount of the token or ETH to the contract, making the balance non-zero and causing the victim's transaction to revert. The attack is repeatable at negligible cost, creating a permanent DoS on the guarded function. Distinct from Vector 39 (force-feeding ETH to break invariants) — this targets the zero-check gate itself as a griefing/DoS vector rather than inflating a balance used in financial math.
- **FP:** Check uses `<=` threshold instead of `== 0` (e.g., `require(balance <= DUST_THRESHOLD)`). Function is access-controlled so only a trusted caller can trigger it. Balance is tracked via an internal accounting variable that ignores direct transfers, not via `balanceOf` or `address(this).balance`.

---

**14. Cross-Chain Deployment Replay**

- **Detect:** A deployment transaction from one EVM chain is replayed on another chain. If the deployer EOA has the same nonce on both chains, the CREATE opcode produces the same contract address on the second chain — but now controlled by whoever replayed the transaction. The Wintermute incident demonstrated this: an attacker replayed a deployment transaction across EVM-compatible chains to gain control of the same address on multiple networks. Pattern: deployer EOA reused across chains without nonce management. Deployment transactions lack EIP-155 chain ID protection. Script deploys to multiple chains from the same EOA without verifying per-chain nonce state.
- **FP:** Deployment transactions use EIP-155 (chain ID in v value of signature). Script uses `CREATE2` with a factory already deployed at the same address on all target chains (e.g., deterministic deployment proxies). Per-chain deployer EOAs or hardware wallets with chain-specific derivation paths.

**15. msg.value Reuse in Loop / Multicall**

- **Detect:** `msg.value` read inside a loop body, or inside a `delegatecall`-based multicall where each sub-call is dispatched via `address(this).delegatecall(data[i])`. `msg.value` is a transaction-level constant — it does not decrease as ETH is "spent" within the call. Direct loop: `for (uint i = 0; i < n; i++) { deposit(msg.value); }` credits `n × msg.value` while only `msg.value` was sent. Delegatecall multicall: each sub-call inherits the original `msg.value`, so including the same payable function `n` times receives credit for `n × msg.value` with one payment.
- **FP:** `msg.value` captured into a local variable before the loop; that local is decremented per iteration and the contract enforces that total allocated equals the captured value. Function is non-payable. Multicall dispatches via `call` (not `delegatecall`), so each sub-call only receives ETH explicitly forwarded to it.

**16. Missing or Expired Deadline on Swaps**

- **Detect:** `deadline = block.timestamp` (computed inside the tx, always valid), `deadline = type(uint256).max`, or no deadline at all. Transaction can be held in mempool and executed at any future price.
- **FP:** Deadline is a calldata parameter validated on-chain as `require(deadline >= block.timestamp)` and is not derived from `block.timestamp` or set to `type(uint256).max` within the function itself.

**17. Signature Malleability**

- **Detect:** Raw `ecrecover(hash, v, r, s)` used without validating `s <= 0x7FFF...20A0`. Both `(v,r,s)` and `(v',r,s')` recover the same address. If signatures are used as unique identifiers (stored to prevent replay), a malleable variant bypasses the uniqueness check. (SWC-117)
- **FP:** OpenZeppelin `ECDSA.recover()` used (validates `s` range and `v`). Full message hash used as dedup key, not the signature bytes.

**18. Write to Arbitrary Storage Location**

- **Detect:** (1) Assembly block with `sstore(slot, value)` where `slot` is derived from user-supplied calldata, function parameters, or arithmetic over user-controlled values without bounds validation — allows overwriting any slot including `owner`, `implementation`, or balance mappings. (2) (Solidity <0.6) Direct assignment to a storage array's `.length` field (`arr.length = userValue`) followed by an indexed write `arr[largeIndex] = x`. The storage slot for `arr[i]` is `keccak256(arraySlot) + i`; with a crafted large index, slot arithmetic wraps around and overwrites arbitrary slots. (SWC-124)
- **FP:** Assembly is read-only (`sload` only, no `sstore`). Slot value is a compile-time constant or derived exclusively from non-user-controlled data (e.g., `keccak256("protocol.slot")` pattern). Solidity ≥0.6 used throughout (compiler disallows direct array length assignment). Slot arithmetic validated against a fixed known-safe range before use.

**19. Hardcoded Network-Specific Addresses**

- **Detect:** Deployment script or constructor contains hardcoded addresses for external dependencies (oracles, routers, tokens, registries) that differ across networks. When the script is reused on a different chain or testnet, these addresses point to wrong contracts, EOAs, or undeployed addresses — silently misconfiguring the system. A USDC address hardcoded for Ethereum mainnet resolves to an unrelated contract (or an EOA) on Arbitrum or Polygon. Pattern: literal `address(0x...)` constants in deployment scripts or constructor arguments that represent external protocol addresses. No per-chain configuration mapping or environment variable lookup.
- **FP:** Addresses are loaded from a per-chain configuration file (JSON, TOML) keyed by chain ID. Script asserts `block.chainid` matches expected chain before using hardcoded addresses. Addresses are passed as constructor arguments from the deployment environment, not embedded in source. Deterministic addresses that are guaranteed identical across chains (e.g., CREATE2-deployed singletons like Permit2).

**20. Weak On-Chain Randomness / Randomness Frontrunning**

- **Detect:** Randomness from `block.prevrandao` (RANDAO, validator-influenceable), `blockhash(block.number - 1)` (known before inclusion), `block.timestamp`, `block.coinbase`, or combinations. Validators can influence RANDAO; all block values are visible before tx inclusion, enabling front-running of randomness-dependent outcomes. (SWC-120)
- **FP:** Chainlink VRF v2+ used. Commit-reveal scheme with future-block reveal and a meaningful economic penalty (slashing or bond forfeiture) enforced in code for non-reveal.

**21. ERC4626 Inflation Attack (First Depositor)**

- **Detect:** Vault shares math: `shares = assets * totalSupply / totalAssets`. When `totalSupply == 0`, attacker deposits 1 wei, donates large amount to vault, victim's deposit rounds to 0 shares. No virtual offset or dead shares protection.
- **FP:** OpenZeppelin ERC4626 with `_decimalsOffset()` override. Dead shares minted to `address(0)` at init.

**22. ERC1155 onERC1155Received Return Value Not Validated**

- **Detect:** Custom ERC1155 implementation calls `IERC1155Receiver(to).onERC1155Received(operator, from, id, value, data)` when transferring to a contract address, but does not check that the returned `bytes4` equals `IERC1155Receiver.onERC1155Received.selector` (`0xf23a6e61`). A recipient contract that returns any other value (including `bytes4(0)` or nothing) should cause the transfer to revert per EIP-1155, but without the check the transfer silently succeeds. Tokens are permanently locked in a contract that cannot handle them.
- **FP:** OZ ERC1155 used as base — it validates the selector and reverts with `ERC1155InvalidReceiver` on mismatch. Custom implementation explicitly checks: `require(retval == IERC1155Receiver.onERC1155Received.selector, "ERC1155: rejected")`.

---

**23. Rounding in Favor of the Attacker**

- **Detect:** `shares = assets / pricePerShare` rounds down for the user but up for shares redeemed. First-depositor vault manipulation: when `totalSupply == 0`, attacker donates to inflate `totalAssets`, subsequent deposits round to 0 shares. Division without explicit rounding direction.
- **FP:** `Math.mulDiv(a, b, c, Rounding.Up)` used with explicit rounding direction appropriate for the operation. Virtual offset (OpenZeppelin ERC4626 `_decimalsOffset()`) prevents first-depositor attack. Dead shares minted to `address(0)` at init.

**24. NFT Staking / Escrow Records msg.sender Instead of ownerOf**

- **Detect:** Staking or escrow contract accepts an ERC721 via `nft.transferFrom(msg.sender, address(this), tokenId)` and records `depositor[tokenId] = msg.sender`. An operator (approved but not the owner) can call `stake(tokenId)` — the transfer succeeds because the operator holds approval, but `msg.sender` is the operator, not the real owner. The real owner loses their NFT; the operator is credited as depositor and receives all staking rewards and the right to unstake. Pattern: `depositor[tokenId] = msg.sender` without cross-checking against `nft.ownerOf(tokenId)` before the transfer.
- **FP:** Contract reads `address realOwner = nft.ownerOf(tokenId)` before accepting the transfer and records `depositor[tokenId] = realOwner`. Or requires `require(nft.ownerOf(tokenId) == msg.sender, "not owner")` so operators cannot stake on others' behalf.

**25. Immutable Variable Context Mismatch**

- **Detect:** Implementation contract uses `immutable` variables set in its constructor. These are embedded in bytecode, not storage -- so when a proxy `delegatecall`s, it gets the implementation's hardcoded values regardless of per-proxy configuration needs. If the implementation is shared across multiple proxies or chains, all proxies see the same immutable values. Pattern: `address public immutable WETH` in implementation constructor -- every proxy gets the same WETH address regardless of chain.
- **FP:** Immutable values are intentionally identical across all proxies (e.g. a protocol-wide constant). Per-proxy configuration uses storage variables set in `initialize()`. Implementation is purpose-deployed per proxy with correct constructor args.

**26. extcodesize Zero / isContract Bypass in Constructor**

- **Detect:** Access control or anti-bot check uses `require(msg.sender.code.length == 0)` or assembly `extcodesize(caller())` to assert the caller is an EOA. During a contract's constructor execution, `extcodesize` of that contract's own address returns zero — no code is stored until construction finishes. An attacker deploys a contract whose constructor calls the protected function, bypassing the check. Common targets: minting limits, presale allocation caps, "no smart contracts" whitelist enforcement.
- **FP:** The check is informational only and not security-critical. The function is independently protected by a merkle-proof allowlist, signed permit, or other mechanism that cannot be satisfied inside a constructor. Protocol explicitly states and accepts on-chain contract interaction.

**27. ERC721Enumerable Index Corruption on Burn or Transfer**

- **Detect:** Contract extends `ERC721Enumerable` and overrides `_beforeTokenTransfer` (OZ v4) or `_update` (OZ v5) without calling the corresponding `super` function. `ERC721Enumerable` maintains four interdependent index structures (`_ownedTokens`, `_ownedTokensIndex`, `_allTokens`, `_allTokensIndex`) that must be updated atomically on every mint, burn, and transfer. Skipping the super call leaves stale entries — `tokenOfOwnerByIndex` returns wrong token IDs, `ownerOf` for enumerable lookups resolves incorrectly, and `totalSupply` diverges from actual supply.
- **FP:** Override always calls `super._beforeTokenTransfer(from, to, tokenId, batchSize)` or `super._update(to, tokenId, auth)` as its first statement. Contract does not inherit `ERC721Enumerable` and tracks supply independently.

**28. Block Stuffing / Gas Griefing on Subcalls**

- **Detect:** Time-sensitive function can be blocked by filling blocks (SWC-126). For relayer gas-forwarding griefing via the 63/64 rule, see Vector 47.
- **FP:** Function is not time-sensitive or has a sufficiently long window that block stuffing is economically infeasible.

**29. Chainlink Feed Deprecation / Wrong Decimal Assumption**

- **Detect:** (a) Chainlink aggregator address is hardcoded in the constructor or an immutable with no admin path to update it. When Chainlink deprecates the feed and migrates to a new aggregator contract, the protocol continues reading from the frozen old feed, which may return a stale or zeroed price indefinitely. (b) Price normalization assumes `feed.decimals() == 8` (common for USD feeds) without calling `feed.decimals()` at runtime. Some feeds (e.g., ETH/ETH) return 18 decimals — the 10^10 scaling discrepancy produces wildly wrong collateral values, enabling instant over-borrowing or mass liquidations.
- **FP:** Feed address is updatable via a governance-gated setter. `feed.decimals()` called and stored; used to normalize `latestRoundData().answer` before any arithmetic. Deviation check against a secondary oracle rejects anomalous values.

**30. Zero-Amount Transfer Revert Breaking Distribution Logic**

- **Detect:** Contract calls `token.transfer(recipient, amount)` or `token.transferFrom(from, to, amount)` where `amount` can be zero — e.g., when fees round to 0, a user claims before any yield accrues, or a distribution loop pays out a zero share. Some non-standard ERC20 tokens (LEND, early BNB, certain stablecoins) include `require(amount > 0)` in their transfer logic and revert on zero-amount calls. Any fee distribution loop, reward claim, or conditional-payout path that omits a `if (amount > 0)` guard will permanently DoS on these tokens.
- **FP:** All transfer calls are preceded by `if (amount > 0)` or `require(amount > 0)`. Protocol enforces a minimum claim/distribution amount upstream. Supported token whitelist only includes tokens verified to accept zero-amount transfers (OZ ERC20 base allows them).

**31. Flash Loan-Assisted Price Manipulation**

- **Detect:** A function reads price/ratio from an on-chain source (AMM reserves, vault `totalAssets()`), and that source can be manipulated atomically in the same tx via flash loan + swap. Attacker sequence: borrow → move price → call function → restore → repay.
- **FP:** Price source is TWAP with a 30-minute or longer observation window. Multi-block cooldown enforced between price reads. Function can only be called in a separate block from any state that could be manipulated.

**32. ERC721A / Lazy Ownership — ownerOf Uninitialized in Batch Range**

- **Detect:** Contract uses ERC721A (or OpenZeppelin `ERC721Consecutive`) for gas-efficient batch minting. Ownership is stored lazily: only the first token of a consecutive run has its ownership struct written; all subsequent IDs in the range inherit it by binary search. Before any transfer occurs, `ownerOf(id)` for IDs in the middle of a batch may return `address(0)` or the batch-start owner depending on implementation version. Access control that calls `ownerOf(tokenId) == msg.sender` on freshly minted tokens without an explicit transfer may fail or return incorrect results. Pattern: `require(ownerOf(tokenId) == msg.sender)` in a staking or approval function called immediately after a batch mint.
- **FP:** Protocol always waits for an explicit `transferFrom` or `safeTransferFrom` before checking ownership (each transfer initializes the packed slot). Contract uses standard OZ `ERC721` where every mint writes `_owners[tokenId]` directly.

**33. Bytecode Verification Mismatch (Source-to-Deployment Discrepancy)**

- **Detect:** The source code verified on a block explorer (Etherscan, Sourcify) does not faithfully represent the deployed bytecode's behavior. This can happen through: (a) different compiler settings (optimizer runs, EVM version) producing semantically different bytecode from the same source; (b) constructor arguments that alter behavior but are not visible in the verified source; (c) deliberately crafted source that passes verification but contains obfuscated malicious logic (e.g., a second contract in the same file with phishing/scam code verified under the victim's address). Research has shown that verification services can be abused to associate misleading source code with deployed contracts. Pattern: deployment script uses different `solc` version or optimizer settings than the verification step. Constructor arguments encode addresses or parameters not visible in source. Verification submitted with `--via-ir` but compilation used legacy pipeline (or vice versa). No reproducible build (no committed `foundry.toml` / `hardhat.config.ts` with pinned compiler settings).
- **FP:** Deterministic build: `foundry.toml` or `hardhat.config.ts` committed with pinned compiler version and optimizer settings. Verification is part of the deployment script (Foundry `--verify`, Hardhat `verify` task) using identical settings. Sourcify full match (metadata hash matches). Constructor arguments are ABI-encoded and published alongside verification.

---

**34. Insufficient Gas Forwarding / 63/64 Rule Exploitation**

- **Detect:** Contract forwards an external call without enforcing a minimum gas budget: `target.call(data)` (no explicit gas) or `target.call{gas: userProvidedGas}(data)`. The EVM's 63/64 rule means the callee receives at most 63/64 of the remaining gas. In meta-transaction and relayer patterns, a malicious relayer provides just enough gas for the outer function to complete but not enough for the subcall to succeed. The subcall returns `(false, "")` — which the outer function may misread as a business-logic rejection, marking the user's transaction as "processed" while the actual effect never happened. Silently censors user intent while consuming their allocated gas/fee.
- **FP:** `gasleft()` validated against a minimum threshold before the subcall: `require(gasleft() >= minGas)`. Return value and return data both checked after the call. Relayer pattern uses EIP-2771 with a verified gas parameter that the recipient contract re-validates.

**35. Read-Only Reentrancy**

- **Detect:** Protocol calls a `view` function (e.g., `get_virtual_price()`, `totalAssets()`, `convertToAssets()`) on an external contract from within a callback (`receive`, `onERC721Received`, flash loan hook). The external contract has no reentrancy guard on its view functions - a mid-execution call can return a transitional/manipulated value.
- **FP:** External contract's view functions are themselves `nonReentrant`. Protocol uses Chainlink or another oracle instead of the external view. External contract's reentrancy lock is public and the protocol reads and enforces it before calling any view function.

**36. ERC4626 Round-Trip Profit Extraction**

- **Detect:** A full operation cycle yields strictly more than the starting amount: `redeem(deposit(a)) > a`, `deposit(redeem(s)) > s`, `mint(withdraw(a)) > a`, or `withdraw(mint(s)) > s`. Possible when rounding errors in `_convertToShares` and `_convertToAssets` both truncate in the user's favor, so no value is lost in either direction and a net gain emerges with large inputs or a manipulated share price. Combined with the first-depositor inflation attack (Vector 86), the share price can be engineered so that round-trip profit scales with the amount — enabling systematic value extraction.
- **FP:** Rounding directions satisfy EIP-4626: shares issued on deposit/mint round down (vault-favorable), shares burned on withdraw/redeem round up (vault-favorable). OpenZeppelin ERC4626 with `_decimalsOffset()` used.

**37. Missing chainId / Message Uniqueness in Bridge**

- **Detect:** Bridge/messaging contract processes incoming messages but lacks: `processedMessages[messageHash]` check (replay), `destinationChainId == block.chainid` validation, or source chain ID in the message hash. A message from Chain A to Chain B can be replayed on Chain C, or submitted twice on the destination.
- **FP:** Each message has a unique nonce per sender. Hash of `(sourceChain, destinationChain, nonce, payload)` stored in `processedMessages` and checked before execution. Contract address included in message hash.

**38. Diamond Shared-Storage Cross-Facet Corruption**

- **Detect:** EIP-2535 Diamond proxy where facets declare storage variables without EIP-7201 namespaced storage structs -- each facet using plain `uint256 foo` or `mapping(...)` declarations that Solidity places at sequential storage slots 0, 1, 2, .... Different facets independently start at slot 0, so both write to the same slot. A compromised or buggy facet can corrupt the entire Diamond's state. Pattern: facet with top-level state variable declarations (no `DiamondStorage` struct at a namespaced slot).
- **FP:** All facets store state exclusively in a single `DiamondStorage` struct retrieved via `assembly { ds.slot := DIAMOND_STORAGE_POSITION }` using a namespaced position (EIP-7201 formula). No facet declares top-level state variables. OpenZeppelin's ERC-7201 `@custom:storage-location` pattern used correctly.

**39. Transparent Proxy Admin Routing Confusion**

- **Detect:** Transparent proxy routes calls from the admin address to proxy admin functions, and all other calls to the implementation. If the admin address accidentally interacts with the protocol as a user (e.g. deposits, withdraws), the call hits proxy admin routing instead of being delegated -- silently failing or executing unintended logic. Pattern: admin EOA or contract also used for regular protocol interactions; `ProxyAdmin` contract doubles as treasury or operator.
- **FP:** Dedicated `ProxyAdmin` contract used exclusively for admin calls, never for protocol interaction. OpenZeppelin `TransparentUpgradeableProxy` pattern enforces separate admin contract. Admin address documented and known to never make user-facing calls.

**40. Nonce Gap from Reverted Transactions (CREATE Address Mismatch)**

- **Detect:** Deployment script uses `CREATE` (not CREATE2) and pre-computes expected contract addresses based on the deployer's nonce. If any transaction reverts or if an unrelated transaction is sent from the deployer EOA between script runs, the nonce advances but no contract is deployed. Subsequent deployments land at different addresses than expected, and contracts that were pre-configured to reference the expected addresses now point to empty addresses or wrong contracts. Pattern: script pre-computes addresses via `address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), deployer, nonce)))))` and hardcodes them into other contracts. Multiple scripts share the same deployer EOA without coordinated nonce management. Deployment script assumes a specific starting nonce.
- **FP:** `CREATE2` used with deterministic addressing (nonce-independent). Script reads current nonce from chain via `eth_getTransactionCount` before computing addresses. Addresses are captured from actual deployment receipts and passed forward, never pre-assumed. Dedicated deployer EOA used per deployment (fresh nonce = 0).

**41. Single-Function Reentrancy**

- **Detect:** External call (`call{value:}`, `transfer`, `send`, `safeTransfer`, `safeTransferFrom`) happens _before_ state update (balance set to 0, flag set, counter decremented). Classic: check-external-effect instead of check-effect-external.
- **FP:** State updated before the call (CEI followed). `nonReentrant` modifier present. Callee is a hardcoded immutable address of a contract whose receive/fallback is known to not re-enter.

**42. Beacon Proxy Single-Point-of-Failure Upgrade**

- **Detect:** Multiple proxies read their implementation address from a single Beacon contract. Compromising the Beacon owner upgrades all proxies simultaneously. Pattern: `UpgradeableBeacon` with `owner()` returning a single EOA; tens or hundreds of `BeaconProxy` instances pointing to it. A single `upgradeTo()` on the Beacon replaces logic for every proxy at once.
- **FP:** Beacon owner is a multisig + timelock. `Upgraded` events on the Beacon are monitored for unauthorized changes. Per-proxy upgrade authority used where risk tolerance requires isolation.

**43. EIP-2981 Royalty Signaled But Never Enforced**

- **Detect:** Contract implements `IERC2981.royaltyInfo(tokenId, salePrice)` and `supportsInterface(0x2a55205a)` returns `true`, advertising royalty support. However, the protocol's own transfer, listing, or settlement logic never calls `royaltyInfo()` and never routes payment to the royalty recipient. EIP-2981 is a signaling standard — it cannot force payment. Any marketplace that does not voluntarily query and pay royalties will bypass them entirely. Pattern: `royaltyInfo()` implemented, but `transferFrom` and all settlement paths contain no corresponding payment call.
- **FP:** Protocol's own marketplace or settlement contract reads `royaltyInfo()` and transfers the royalty amount to the recipient before or after completing the sale — enforced on-chain. Royalties are intentionally zero (`royaltyBps = 0`) and this is documented.

**44. Precision Loss - Division Before Multiplication**

- **Detect:** Expression `(a / b) * c` in integer math. Division truncates first, then multiplication amplifies the error. Common in fee calculations: `fee = (amount / 10000) * bps`. Correct form: `(a * c) / b`.
- **FP:** `a` is provably divisible by `b` — enforced by a preceding explicit check (e.g., `require(a % b == 0)`) or by mathematical construction visible in the code.

**45. Upgrade Race Condition / Front-Running**

- **Detect:** Upgrade transaction submitted to a public mempool, creating a window for front-running (exploit old implementation before upgrade lands) or back-running (exploit assumptions the new implementation breaks). Multi-step upgrades are especially dangerous: `upgradeTo(V2)` lands in block N but `setNewParams(...)` is still pending -- attacker sandwiches between them. Pattern: `upgradeTo()` and post-upgrade configuration calls are separate transactions; no private mempool or bundling used; V2 is not safe with V1's state parameters.
- **FP:** Upgrade + initialization bundled into a single `upgradeToAndCall()` invocation. Flashbots Protect or private mempool used for upgrade transactions. V2 designed to be safe with V1's state from block 0. Timelock makes execution block predictable and protectable.
