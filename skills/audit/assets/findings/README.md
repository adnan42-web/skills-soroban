# Findings

This directory holds two kinds of reports:

- **Reports from previous `/audit` runs** — written automatically as `report-{timestamp}.md` each time the skill runs.
- **External audit reports** — drop any third-party or manual audit `.md` files here.

On each run the skill reads every file in this directory and re-verifies whether previously reported issues still exist in the current code. Fixed issues are noted in the new report under "Fixed Since Last Report". Issues still present are carried forward with a "Previously reported — still present" note, so regressions are never missed.
