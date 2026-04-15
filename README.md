# stillrunning

> AI-powered supply chain security.
> Blocks malicious packages at install AND import time.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Protected by stillrunning](https://stillrunning.io/badge/protected)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## What it does

- **Intercepts pip/npm installs** before download
- **Blocks malicious imports** before execution
- **Hash verification** against PyPI registry
- **AI scanning** for unknown packages
- **Real-time Telegram/email alerts**
- **One-tap allow/deny** from your phone

## What it blocks

| Attack Vector | Blocked? |
|--------------|----------|
| `pip install malicious-pkg` | Blocked |
| `pip3 install malicious-pkg` | Blocked |
| `python3 -m pip install malicious-pkg` | Blocked |
| `npm install malicious-pkg` | Blocked |
| `pip install -r requirements.txt` | Scans all packages |
| `import malicious_pkg` | Blocked (via hook) |
| `from malicious_pkg import x` | Blocked (via hook) |

## Known limitations

| Gap | Coverage |
|----|----------|
| `/usr/bin/pip` direct binary | Import hook catches at runtime |
| Virtual env pip | Activate intercept manually, or use import hook |
| Conda/poetry/pipx | Manual activation required |
| Already installed packages | Import hook catches on use |

The import hook provides defense in depth: even if a package sneaks past install-time checks, it can't execute.

## Quick start (30 seconds)

```bash
pip install stillrunning
stillrunning --setup
```

## Import protection (one line)

Add to the top of your main script:

```python
import stillrunning.hook
```

Any malicious import will be blocked with a clear error message.

## Always-on import protection

```bash
stillrunning --install-hook
```

This creates a `.pth` file in site-packages so all Python processes are protected automatically.

## MCP / Claude Code integration

Add to your Claude Code MCP config:

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

Now when you ask Claude to install a package, it checks stillrunning first.

## Interactive approvals

Unknown packages trigger a Telegram alert:

```
UNKNOWN PACKAGE — sketchy-logger==1.0.0
Score: 65/100 — Unusual network calls in __init__.py

Allow this install?
[Allow] [Deny]

Auto-denying in 60 seconds.
```

One tap to approve or deny from your phone.

## Commands

```bash
stillrunning --setup          # 3-minute setup wizard
stillrunning --doctor         # Health check
stillrunning --install-hook   # Enable always-on import protection
stillrunning --allow <pkg>    # Allow a blocked package
stillrunning --block <pkg>    # Manually block a package
stillrunning whitelist add <pkg>    # Add to whitelist
stillrunning whitelist remove <pkg> # Remove from whitelist
stillrunning whitelist list         # Show whitelist
```

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Personal** | $9/mo | Process monitor, auto-restart, Telegram alerts |
| **Basic** | $29/mo | + File integrity, tripwire, honeypot |
| **AI** | $49/mo | + AI package review, import hook, MCP integration |
| **Enterprise** | $499/mo | + Unlimited scans, SIEM, SSO, compliance |

## Badge

Show your project is protected:

```markdown
![Protected by stillrunning](https://stillrunning.io/badge/protected)
```

## API

```bash
# Check a package
curl https://stillrunning.io/api/check-package?name=requests

# MCP endpoint
curl -X POST https://stillrunning.io/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/call", "params": {"name": "check_package", "arguments": {"package_name": "requests"}}}'
```

## Links

- [stillrunning.io](https://stillrunning.io) — homepage
- [stillrunning.io/threats](https://stillrunning.io/threats) — live threat dashboard
- [stillrunning.io/developers](https://stillrunning.io/developers) — integration docs
- [stillrunning.io/coverage](https://stillrunning.io/coverage) — what is/isn't blocked
- [@bit_bot9000](https://x.com/bit_bot9000) — updates

## License

MIT License

Patent Pending — US Provisional Application filed April 12, 2026
