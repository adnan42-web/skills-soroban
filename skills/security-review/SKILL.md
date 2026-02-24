---
name: security-review
description: Fast, focused security feedback on Solidity code while you develop - before you commit, not after an auditor does. Built for developers, not security researchers. Use when the user asks to "review my changes for security issues", "check this contract", "security-review", or wants a quick sanity check before pushing. Supports three modes - default (reviews git-changed files), ALL (full repo), or a specific filename.
---

# Smart Contract Security Review

Fast, simple, and effective security feedback while you're developing - the kind of check you run before committing, not after hiring an auditor. The goal is to catch real issues quickly so developers can fix them early, not to produce a formal audit report.

You have deep knowledge of Solidity, EVM internals, DeFi protocols, and common attack vectors. Apply that knowledge pragmatically: flag what matters, skip the noise.

## Mode Selection

Determine which mode to run based on how the skill was invoked:

- **Default** (no arguments): Audit only `.sol` files that appear in `git diff HEAD` (both staged and unstaged changes). Run `git diff HEAD --name-only` and filter for `.sol` files. If there are no changed Solidity files, tell the user and stop.
- **ALL**: Audit the entire repository at its current state. Recursively find all `.sol` files (excluding `node_modules/`, `lib/`, `out/`, `.git/`).
- **`$filename`** (a file path is given as argument): Audit that specific file only.

## Context Loading

Before auditing, check the `assets/` directory of this skill for two optional inputs:

**False positives** (`assets/false-positives.md`) - If this file exists, read it. It contains known non-issues specific to this codebase that a previous review flagged incorrectly. Do not report any finding that matches a described false positive. Acknowledge at the bottom of the report how many false positives were suppressed.

**Previous findings** (`assets/findings/` or any `.md` files in `assets/`) - If prior audit reports exist here, read them for context. Use them to understand already-known issues, focus on new attack surface, and avoid duplicating findings the team is already aware of. Note in the report if a finding was previously known.

## Audit Checklist

Check for the full range of smart contract vulnerabilities, including but not limited to:

- Reentrancy (single-function, cross-function, cross-contract, read-only)
- Integer overflow/underflow (pre- and post-0.8.x)
- Access control issues (missing `onlyOwner`, incorrect role checks, unprotected initializers)
- Oracle manipulation and price feed attacks
- Flash loan attack vectors
- Front-running and MEV exposure
- Denial of service (gas griefing, unbounded loops, block gas limit)
- Incorrect use of `delegatecall` and storage collisions
- Timestamp and block number dependence
- Unsafe external calls and unchecked return values
- Signature replay attacks
- Precision loss and rounding errors in fixed-point arithmetic
- Logic errors in reward distribution or accounting invariants

## Output Format

```
# Smart Contract Audit Report

## Executive Summary
<2-4 sentences: overall risk rating (Critical / High / Medium / Low / Minimal), total finding counts by severity, mode used, files reviewed, and key takeaways>

## Findings

### [SEVERITY] Finding Title
- **Contract:** <ContractName>
- **Function:** <functionName> (line N) or N/A
- **Description:** <what the issue is and why it is dangerous>
- **Impact:** <what an attacker can achieve>
- **Proof of Concept:** <minimal attack scenario or call sequence>
- **Recommendation:** <concrete code-level fix>

...repeat for each finding, ordered Critical → Informational...

## Scope & Limitations
<files reviewed, git commit or diff range if applicable, false positives suppressed (N), and any caveats>
```

## Constraints

- Do not fabricate findings. Only report issues genuinely present in the provided code.
- Do not provide fully weaponized exploit code; a concise PoC scenario is sufficient.
- If the input is incomplete or ambiguous, ask clarifying questions before auditing.
