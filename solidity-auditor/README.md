# Soroban Auditor

A security agent with a simple mission - findings in minutes, not weeks.

Built for:

- **Soroban/Rust devs** who want a security check before every commit
- **Security researchers** looking for fast wins before a manual review
- **Just about anyone** who wants an extra pair of eyes.

Not a substitute for a formal audit - but the check you should never skip.

## Demo

_Portrayed below: finding multiple high-confidence vulnerabilities in a codebase_

![Running soroban-auditor in terminal](../static/skill_pag.gif)

## Usage

```
Install https://github.com/pashov/skills/ and run soroban auditor on the codebase
```

```
run soroban auditor on *specified files*
```

```
update skill to latest version
```

## Tips

- **Target hot contracts.** Rather than scanning an entire repo, point the tool at the 2-5 Rust contract files you're actively changing.
- **Run more than once.** LLM output is non-deterministic — two or three passes often catch issues a single pass misses.
