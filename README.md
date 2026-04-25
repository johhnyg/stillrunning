# stillrunning

> Supply chain security for developers and AI coding agents.
> Active protection against 200,000+ verified malicious packages from 8 threat intelligence sources.

[![PyPI version](https://img.shields.io/pypi/v/stillrunning)](https://pypi.org/project/stillrunning/)
![Protected by stillrunning](https://stillrunning.io/badge/protected)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## What's new in v2.7

- **Source tracking** — every blocklist entry records where it came from (OSV, Gemini Hunter, manual)
- **Version-range blocking** — respects OSV's affected-version specifiers
- **OSV.dev bulk ingestion** — 222k malicious packages from PyPI and npm
- **Withdrawn advisory filtering** — removes false positives automatically
- **Registry liveness checking** — marks packages removed from registries

## What it protects against

| Threat Class | Example |
|-------------|---------|
| Typosquats | `reqeusts`, `colourma`, `djanga` |
| Malicious packages | Pre/post-install scripts stealing credentials |
| Prompt injection | README-based attacks targeting AI agents |
| Dependency confusion | Internal package names registered publicly |
| Hallucinated packages | AI-suggested packages that don't exist (then claimed) |

## Supported package managers

| Package Manager | Status |
|----------------|--------|
| pip / pip3 | Intercepted |
| python3 -m pip | Intercepted |
| uv | Intercepted |
| poetry | Intercepted |
| pdm | Intercepted |
| pipenv | Intercepted |
| conda | Intercepted |
| pixi | Intercepted |
| npm | Intercepted |
| bun | Intercepted |
| pnpm | Intercepted |
| requirements.txt | Scanned |
| import statement | Blocked (via hook) |

## Quick start

```bash
pip install stillrunning
stillrunning --setup              # 3-minute setup wizard
stillrunning scan <package>       # One-shot scan
stillrunning --install-hook       # Always-on import protection
```

## Import protection

```python
import stillrunning.hook  # Blocks malicious imports at runtime
```

## AI agent integrations

Works with: Claude Code, Cursor, Devin, Replit, GitHub Copilot, Windsurf, Aider

Setup: [stillrunning.io/agent-setup](https://stillrunning.io/agent-setup)

### Claude Code skill

```bash
claude mcp add stillrunning -- stillrunning mcp
```

Or add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "stillrunning": {
      "type": "url",
      "url": "https://stillrunning.io/mcp"
    }
  }
}
```

## Security Advisories

Browse the full threat database: [stillrunning.io/security-advisories](https://stillrunning.io/security-advisories)

RSS feed: [stillrunning.io/security-advisories/rss.xml](https://stillrunning.io/security-advisories/rss.xml)

## Privacy

Heartbeats contain: command name, version, OS, anonymous UUID, timestamp.
**No code, file paths, or package names are sent.**

Disable: `STILLRUNNING_NO_TELEMETRY=1` or `--no-telemetry` flag.

## Configuration

| Variable | Purpose |
|----------|---------|
| `STILLRUNNING_NO_TELEMETRY=1` | Disable heartbeat |
| `BLOCKLIST_MAX_AGE_DAYS=730` | Max age for blocklist entries (default 2 years) |

Config file: `~/.stillrunning/config.yaml`

## Commands

```bash
stillrunning --setup          # Setup wizard
stillrunning --doctor         # Health check
stillrunning --install-hook   # Enable always-on import protection
stillrunning --autonomous     # CI/CD mode
stillrunning --allow <pkg>    # Allow a blocked package
stillrunning scan <pkg>       # One-shot scan
stillrunning whitelist add <pkg>    # Add to whitelist
stillrunning whitelist list         # Show whitelist
```

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 10 blocklist checks/day |
| **Personal** | $9/mo | Guard daemon, 1 machine |
| **Basic** | $29/mo | Dashboard, 3 machines, Telegram |
| **AI** | $49/mo | AI package review, unlimited machines |
| **Enterprise** | $499/mo | SIEM, SSO, compliance |

## Badge

```markdown
![Protected by stillrunning](https://stillrunning.io/badge/protected)
```

## Links

- [stillrunning.io](https://stillrunning.io)
- [Security Advisories](https://stillrunning.io/security-advisories)
- [Agent Setup](https://stillrunning.io/agent-setup)
- [@bit_bot9000](https://x.com/bit_bot9000)

## License

MIT License

Patent Pending — US Provisional Application filed April 12, 2026
