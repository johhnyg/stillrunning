# stillrunning

> Supply chain security for developers and AI coding agents.
> Blocks malicious packages at install AND import time.

![Version](https://img.shields.io/badge/version-2.0.4-blue)
![Protected by stillrunning](https://stillrunning.io/badge/protected)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## What's new in v2.0

- **Python import hook** — blocks at execution, not just install
- **MCP server** — Claude Code checks packages before installing
- **Interactive Telegram approvals** — default deny, one tap to allow
- **Works with every AI coding agent** — Claude Code, Cursor, Devin, Replit, Windsurf, Aider
- **Autonomous mode** for CI/CD pipelines
- **Hash verification** against PyPI registry

## What it blocks

| Attack Vector | Status |
|--------------|--------|
| `pip install malicious-pkg` | Blocked |
| `pip3 install malicious-pkg` | Blocked |
| `python3 -m pip install malicious-pkg` | Blocked |
| `npm install malicious-pkg` | Blocked |
| `pip install -r requirements.txt` | Scans all packages |
| `import malicious_pkg` | Blocked (via hook) |
| `from malicious_pkg import x` | Blocked (via hook) |

## Known limitations

| Gap | Workaround |
|----|------------|
| `/usr/bin/pip` direct binary | Use import hook for coverage |
| Virtual env pip | Activate intercept or use import hook |
| Conda/poetry/pipx | Manual activation required |

## Quick start (30 seconds)

```bash
pip install stillrunning
stillrunning --setup
```

## Import protection (one line)

```python
import stillrunning.hook
```

## Always-on import protection

```bash
stillrunning --install-hook
```

## Autonomous mode (CI/CD + AI agents)

```bash
export STILLRUNNING_APP_NAME="my-app"
export STILLRUNNING_TELEGRAM_TOKEN="..."
export STILLRUNNING_CHAT_ID="..."
stillrunning --autonomous
```

## MCP / Claude Code integration

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "stillrunning": {
      "type": "url",
      "url": "https://stillrunning.io/mcp",
      "name": "stillrunning"
    }
  }
}
```

## Claude Skill

Install the stillrunning skill for automatic package checking in every Claude Code session:

[github.com/johhnyg/stillrunning-skill](https://github.com/johhnyg/stillrunning-skill)

## Works with every AI coding agent

Claude Code, Cursor, Devin, Replit, GitHub Copilot, Windsurf, Aider

Setup: [stillrunning.io/agent-setup](https://stillrunning.io/agent-setup)

## Commands

```bash
stillrunning --setup          # 3-minute setup wizard
stillrunning --doctor         # Health check
stillrunning --install-hook   # Enable always-on import protection
stillrunning --autonomous     # CI/CD mode (no prompts)
stillrunning --allow <pkg>    # Allow a blocked package
stillrunning --block <pkg>    # Manually block a package
stillrunning whitelist add <pkg>    # Add to whitelist
stillrunning whitelist remove <pkg> # Remove from whitelist
stillrunning whitelist list         # Show whitelist
```

## Pricing

| Tier | Price | Scans/day | Features |
|------|-------|-----------|----------|
| **Free** | $0 | 10 | Blocklist checks only |
| **Personal** | $9/mo | — | Guard daemon, 1 machine |
| **Basic** | $29/mo | — | Dashboard, 3 machines, Telegram |
| **AI** | $49/mo | 100 | AI package review, unlimited machines |
| **Enterprise** | $499/mo | 10,000 | SIEM, SSO, compliance |
| **Enterprise+** | $2,499/mo | Unlimited | Dedicated support, on-prem |

## Badge

```markdown
![Protected by stillrunning](https://stillrunning.io/badge/protected)
```

## Links

- [stillrunning.io](https://stillrunning.io)
- [stillrunning.io/agent-setup](https://stillrunning.io/agent-setup)
- [@bit_bot9000](https://x.com/bit_bot9000)

## License

MIT License

Patent Pending — US Provisional Application filed April 12, 2026
