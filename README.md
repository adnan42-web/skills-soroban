# AI Skills

> Modular, agent-agnostic skills for Claude Code, Codex, Copilot, Cursor, Windsurf, and beyond.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![CI](https://github.com/pashov/skills/actions/workflows/ci.yml/badge.svg)](https://github.com/pashov/skills/actions/workflows/ci.yml)

Drop a skill into your AI environment and it gains a focused, reusable capability - like a plugin, but for AI agents.

| | Supported |
|---|---|
| **Models** | Claude · ChatGPT · Gemini |
| **Agents** | Claude Code · Codex · OpenCode · GitHub Copilot |
| **IDEs** | VS Code · Cursor · Windsurf |
| **Extensions** | Claude Code · GitHub Copilot · Gemini Code Assist |

---

## Skills

| Skill | Description | Category |
|-------|-------------|----------|
| [lint](skills/lint/) | Lints Solidity code - unused imports, NatSpec, formatting, naming, custom errors, best practices | Secure Development |
| [security-review](skills/security-review/) | Fast security feedback on Solidity changes while you develop | Secure Development |
| [start-audit](skills/start-audit/) | Full audit prep for security researchers - builds, architecture diagrams, threat model | Security Research |

---

## Install

**Claude Code** - drop a skill into your global skills directory:

```bash
cp -r skills/security-review ~/.claude/skills/
```

Then invoke it:

```
/security-review path/to/Contract.sol
```

**Other agents** - copy `SKILL.md` into your agent's system prompt or context window.

---

## Quick Start

1. Pick a skill from the table above.
2. Copy it to your agent's skills directory (see Install above).
3. Invoke it by name in a new conversation.

---

## Contributing

We welcome new skills, improvements, and fixes. One skill, one purpose - see [AGENTS.md](AGENTS.md) for contribution rules.

1. Copy an existing skill as a starting point.
2. Fill in `SKILL.md` - frontmatter `name` and `description` are required.
3. Add a `README.md` with usage examples.
4. Open a pull request.

---

## Structure

```
skills/
└── skill-name/
    ├── SKILL.md         # Required - frontmatter + instructions
    ├── README.md        # Usage and examples
    ├── scripts/         # Executable helpers
    ├── references/      # Docs loaded into context
    └── assets/          # Templates and static files
```

---

## Security · Code of Conduct · License

Report vulnerabilities via [Security Policy](SECURITY.md). This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). [MIT](LICENSE) © contributors.
