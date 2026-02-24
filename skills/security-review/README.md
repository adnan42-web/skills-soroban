# security-review

Fast, simple, stupid but effective security feedback while developing or before committing to version control.

Built for **developers** who want to catch issues early - not a replacement for a formal audit, but the check you should run every time you touch a contract.

## Usage

```bash
# Review only what changed (default - fastest)
/security-review

# Review a specific file
/security-review src/Vault.sol

# Review the entire repo
/security-review ALL
```

## What it does

- **Default mode**: runs `git diff HEAD` and reviews only the `.sol` files you've changed
- **File mode**: reviews a single contract you specify
- **ALL mode**: scans the full repo at its current state

It reads your code, applies a standard checklist of Solidity vulnerabilities, and gives you a structured report with severity, impact, and a concrete fix for each finding.

## Suppressing false positives

Create `assets/false-positives.md` and describe any known non-issues. The reviewer will skip findings that match and tell you how many were suppressed.

## Carrying over previous findings

Drop prior audit report `.md` files into `assets/findings/`. The reviewer will use them as context - avoiding duplicate findings and focusing on new attack surface.

## Who this is for

Developers writing Solidity who want a security gut-check as part of their normal workflow. If you're preparing for a formal audit, see [`start-audit`](../start-audit/) instead.
