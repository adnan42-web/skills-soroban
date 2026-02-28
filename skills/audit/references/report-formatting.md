# Report Formatting

## Output Format

````
# 🔐 Security Review — <ContractName or repo name>

> ⚠️ This review was performed by an AI assistant. AI analysis can never verify the complete absence of vulnerabilities and no guarantee of security is given. Team security reviews, bug bounty programs, and on-chain monitoring are strongly recommended. For a consultation regarding your projects' security, visit [https://www.pashov.com](https://www.pashov.com)

---

## Scope

|                                  |                                                        |
| -------------------------------- | ------------------------------------------------------ |
| **Mode**                         | ALL / default / filename                               |
| **Files reviewed**               | `File1.sol` · `File2.sol`<br>`File3.sol` · `File4.sol` |
| **Confidence threshold (1-100)** | N                                                      |

---

## Findings

| # | | Severity | Title |
|---|---|---|---|
| 1 | 🟠 | HIGH | <title> |
| 2 | 🟡 | MEDIUM | <title> |
| 3 | 🔵 | LOW | <title> |

---

<severity emoji> **1. [HIGH] <Title>**

`ContractName.functionName` · line N · Confidence: N

**Description**
<The vulnerable code pattern and why it is exploitable, in 1–2 sentences.>

**Fix**

```diff
- vulnerable line(s)
+ fixed line(s)
````

---

<severity emoji> **2. [MEDIUM] <Title>**
...

---

## Suppressed Findings

| Confidence | Location            | Description                                                  |
| ---------- | ------------------- | ------------------------------------------------------------ |
| N          | `Contract.function` | One-sentence summary of the issue and why it was suppressed. |

```

**Rules:**

- Title the report with a lock emoji and the repo or contract name.
- Order findings Critical first, then High, Medium, Low in both the table and the detail sections.
- Number findings sequentially; the number in the table matches the heading number.
- Each severity level in the table gets its emoji. Each finding heading is preceded by its severity emoji on the same line.
- Omit severity levels that have no findings.
- Location and Confidence appear as a single inline line below the heading: `` `Contract.fn` · line N · Confidence: N ``.
- Description and Fix are each a bold label on its own line followed by the content on the next line.
- Separate each finding with `---`.
- Fix must include a fenced diff code block showing the exact lines to change.
- The disclaimer is always printed, even when there are no findings.
- The Summary section appears between Scope and Findings. It is 1–2 sentences: state the number and severity breakdown of findings, highlight the most critical risk areas, and recommend that the team address the findings and pursue a formal security review before deployment. Keep the tone professional and direct — no hedging, no filler.
- Scope is a two-column table immediately after the disclaimer, not a prose paragraph.
- The "Confidence threshold" label always reads `Confidence threshold (1-100)`.
- Suppressed findings appear at the end of the report as a `## Suppressed Findings` section rendered as a three-column table (`Confidence · Location · Description`), not as prose. One row per suppressed finding. Descriptions are one sentence: what the issue is and why it was suppressed.
```
