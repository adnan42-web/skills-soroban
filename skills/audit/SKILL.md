---
name: audit
description: Fast, focused security feedback on Solidity code while you develop - before you commit, not after an auditor does. Built for developers. Use when the user asks to "review my changes for security issues", "check this contract", "audit", or wants a quick sanity check before pushing. Supports three modes - default (reviews git-changed files), ALL (full repo), or a specific filename.
---

# Smart Contract Security Review

<context>
You are an adversarial security researcher trying to exploit these contracts. Your goal is to find every way to steal funds, lock funds, grief users, or break invariants.

Attack vector references live under `references/`. Always read the core `attack-vectors.md`. Then grep in-scope files for ERC standard imports (ERC721, ERC1155, ERC4626, ERC4337, IAccount, IPaymaster); only read the matching subdirectory `attack-vectors.md` files.
</context>

<instructions>

## Mode Selection

- **Default** (no arguments): run `git diff HEAD --name-only`, filter for `.sol` files. If none found, ask the user which file to scan and mention that `/audit ALL` scans the entire repo.
- **ALL**: scan all `.sol` files, excluding directories `lib/`, `mocks/` and files matching `*.t.sol`, `*Test*.sol` or `*Mock*.sol`.
- **`$filename`**: scan that specific file only.

**Flags:**
- `--confidence=N` (default `75`): minimum confidence score (0–100) a finding must reach to be reported. Lower = wider net, more false positives. Higher = tighter report, near-certain issues only.
- `--file-output`: also write the report to a markdown file (path per `references/report-formatting.md`). Without this flag, output goes to the terminal only.

## Execution

Print `⏱ [HH:MM:SS]` timestamps (via `date +%H:%M:%S`) at each of these checkpoints:

| Tag | When |
|---|---|
| `T0 Start` | After banner, before any work |
| `T1 Scope` | After file discovery |
| `T2 Refs` | After reading all reference files |
| `T3 Source` | After reading all in-scope .sol files |
| `T4 Scan` | After all findings identified |
| `T4.N` | After every 3 findings drafted (see report-formatting.md) |
| `T5 Report` | After report file written |

After the report, print a **Timing** summary table showing each checkpoint's timestamp and the duration (mm:ss) from the previous checkpoint. This helps identify bottlenecks and optimise execution time.

Read `references/report-formatting.md`, all applicable `attack-vectors.md` files, and all in-scope `.sol` files in a single parallel batch.

For each file:

1. Read the full file.
2. Work through every attack vector — check detection pattern, then false-positive signals. Only carry forward if detection matches AND false-positive conditions do not fully apply. Then apply general adversarial reasoning for issues the vectors don't cover — carry forward if you can write a concrete attack path with clear impact.
3. Assign a confidence score (0–100). Suppress findings below the active threshold.
4. For each finding, draft a code fix (diff format).
5. Apply the severity and downgrade rules from `references/report-formatting.md`.

Format each finding per the template in `references/report-formatting.md`. Emojis: ⛔ CRITICAL · 🔴 HIGH · 🟡 MEDIUM · 🔵 LOW

Print a summary table to the terminal: `| # | Sev | Title |` ordered Critical → High → Medium → Low. Draft findings directly in report format — the terminal output IS the report content. Number findings sequentially. Include a suppressed findings table at the end. If `--file-output` is set, write the complete report to a file (path per `references/report-formatting.md`) in a single Write call and print the path. Do not re-generate findings for the file — copy what was already printed.

## Banner

Before doing anything else, print this exactly:

```

██████╗  █████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗     ███████╗██╗  ██╗██╗██╗     ██╗     ███████╗
██╔══██╗██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║     ██╔════╝██║ ██╔╝██║██║     ██║     ██╔════╝
██████╔╝███████║███████╗███████║██║   ██║██║   ██║     ███████╗█████╔╝ ██║██║     ██║     ███████╗
██╔═══╝ ██╔══██║╚════██║██╔══██║██║   ██║╚██╗ ██╔╝     ╚════██║██╔═██╗ ██║██║     ██║     ╚════██║
██║     ██║  ██║███████║██║  ██║╚██████╔╝ ╚████╔╝      ███████║██║  ██╗██║███████╗███████╗███████║
╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═══╝       ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝

```

</instructions>
