# False Positives

Add known non-issues here so the auditor doesn't re-report them.

Each entry should describe the pattern or finding clearly enough for the auditor to recognize and skip it.

## Example

**Centralization risk in `Ownable.transferOwnership`** - Intentional design, owner is a multisig. Not a finding.
