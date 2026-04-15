# Changelog

## v2.0.0 — April 15, 2026

**Import hook + MCP integration**

- **Python import hook** — blocks malicious imports before execution
  - `import stillrunning.hook` to activate
  - `stillrunning --install-hook` for always-on protection
  - Async design: cache check is instant, background scanning for unknown packages
  - Flag on next import if background scan finds issues
- **MCP server** — Claude Code integration
  - `check_package` tool for pre-install verification
  - Add to Claude Code config for automatic package checking
  - Rate limited by tier (100/day AI, unlimited Enterprise)
- **Interactive approvals** — Telegram allow/deny with one tap
  - UNKNOWN packages: blocked pending 60s approval
  - SUSPICIOUS packages: blocked with research link
  - DANGEROUS packages: hard block, no override
  - `/allow_{token}` and `/deny_{token}` commands
- **Coverage page** — honest documentation of what is/isn't blocked
- **Developer docs** — terminal-style integration guide at /developers
- **GitHub Action v2** — import scanning + hash verification

**Breaking changes:**
- Version bump to 2.0.0 — new major version for import hook feature

## v1.9.0 — April 14, 2026

**Tiered feature gating**

- **Tier system**: Personal ($9), Basic ($29), AI ($49), Enterprise ($499)
- Token validation on startup — validates against stillrunning.io API
- Server-side AI package review — Claude Haiku analysis (AI tier+)
- 1-hour token cache with 24-hour offline grace period
- Rate limits: 100 scans/day (AI), 500 (Team), unlimited (Enterprise)
- Feature gates: tripwire, file_integrity, honeypot require Basic+
- New `features.py` module — tier validation and feature checking
- `stillrunning.yaml` now requires `token` field for premium features

**Pricing tiers:**
- Personal: process monitor, restart, Telegram alerts
- Basic: + file integrity, tripwire, honeypot
- AI: + AI package review (server-side)
- Enterprise: + unlimited scans, SIEM, SSO, compliance

## v1.5.0 — April 2026

**Security layer — supply chain protection**

- `stillrunning guard` — always-on security daemon with auto-learning whitelist (214 processes)
- `stillrunning scan` — static analysis: AST parser, entropy detection, pkl inspector
- npm/pip intercept — blocks poisoned packages before install (hash check + static scan)
- Advisor upgrade — Sonnet executor + Opus advisor pattern for AI operations
- Chrome extension scaffold — green/red status dot in browser
- `/scan` route — customer file upload threat scanner (free tier 5/month)
- North Korea supply chain attack response — 1,700+ malicious packages blocked

## v1.4.0 — April 2026

- Email alerts — no Telegram required
- Two-way email — reply to alerts, AI answers from live data
- Monday weekly report — automatic every week
- Uptime milestone alerts — 7, 30, 60, 90, 365 days
- Threat feed — new CVEs auto-pushed to every agent
- Crash pattern AI — detects root cause after 5 events
- `--diagnose` — instant health check on demand
- `--reconfigure` — change alert settings anytime
- Docker support
- Raspberry Pi confirmed support
- Windows PowerShell installer

## v1.3.0 — March 2026

- Shield security system
- Multi-server support
- Telegram two-way control
- AI crash diagnosis (AI tier)
- Daily health audit (AI tier)

## v1.2.0 — February 2026

- Live dashboard at yourname.stillrunning.io
- Process auto-detection (screen, systemd, PM2)
- Resource monitoring (CPU, memory, disk)
- Log rotation

## v1.1.0 — January 2026

- Initial release
- Process watchdog
- Telegram alerts
- Auto-restart
