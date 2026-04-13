# Eval Compare

Compare an audit report against ground truth findings. You will be given two files:

1. **Ground truth** — the benchmark file with known findings
2. **Report** — the audit output (`final-report.md` or `full-output.txt`)

## Steps

1. Read the ground truth file. Parse each `FINDING` line and its `description:` line.
2. Read the report file. Identify two sections:
   - **Findings** — between `## Findings` and `## Leads`
   - **Leads** — from `## Leads` to end of file
3. For each ground truth finding, determine if the report caught it. Use semantic matching — the report doesn't need exact wording, but must describe the same vulnerability in the same contract/function. Classify each as:
   - **FOUND** — in Findings section with same contract, function/entry point, and root cause.
   - **LEAD** — in Leads section with same contract, function/entry point, and root cause.
   - **MISSED** — not present in either section.

## Output

Write `summary.md` to the run directory with this exact format:

```
## Eval Results

| Metric | Value |
|--------|-------|
| Recall (findings) | {found} / {total} ({pct}%) |
| In leads only | {leads} |
| Missed | {missed} |
| High | {high_found} / {high_total} |
| Medium | {med_found} / {med_total} |
| Reported findings | {count from report} |

### Per-finding breakdown

| Status | Severity | ID | Contract.Function | Bug Class |
|--------|----------|----|-------------------|-----------|
| FOUND | High | H-1 | Contract.function | bug-class |
| LEAD | Medium | M-2 | Contract.function | bug-class |
| MISSED | Medium | M-3 | Contract.function | bug-class |
```

## Rules

- Match semantically, not by keyword grep.
- A finding in the Leads section is NOT a finding.
- If root cause matches but function differs inside the same contract, count as FOUND.
- If one report finding covers two ground-truth findings, count both as FOUND.
