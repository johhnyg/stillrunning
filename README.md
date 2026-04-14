# stillrunning

![Version](https://img.shields.io/badge/version-1.9.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

**Supply chain security for teams without security teams.**

```bash
pip install stillrunning
```

## What it does

- **AI Package Review** — Claude Haiku scans every unknown pip/npm package at install time
- **Blocks malicious packages before they run** — intercepts installs, checks against live threat feed
- **Tripwire Monitor** — alerts when sensitive files (.env, SSH keys, private_key.pem) are accessed
- **File Integrity** — SHA256 hash monitoring for critical files
- **Honeypot Credentials** — fake .env files that alert when accessed
- **Learns your environment** — auto-whitelists your processes, alerts on anomalies
- **Updates itself** — syncs blocklist every 60 minutes from 8 threat intel sources

## The attack it was built for

In 2026, North Korean state hackers published WAVESHAPER.V2 — 1,700+ malicious packages across npm and PyPI. Credential stealers disguised as logging utilities. Traditional AV found nothing. Enterprise tools cost $50k/year.

stillrunning catches it at install time, before it ever runs.

## Live proof

**[stillrunning.io/threats](https://stillrunning.io/threats)** — real-time intercept dashboard.

Not a demo. Every package check, every block, every threat advisory — live.

## Quick start

```bash
# Install
pip install stillrunning

# Run setup wizard
stillrunning --setup
```

The setup wizard detects your running processes, configures monitoring, and connects to the live threat feed. Takes 3 minutes.

### With subscription token

For premium features (AI review, tripwire, file integrity):

```bash
# Install with token
curl -sSL https://stillrunning.io/install | python3 - --token YOUR_TOKEN

# Or add to stillrunning.yaml
token: "sr_your_token_here"
```

Get your token at [stillrunning.io/pricing](https://stillrunning.io/pricing)

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Personal** | $9/mo | Process monitor, auto-restart, Telegram alerts |
| **Basic** | $29/mo | + File integrity, tripwire, honeypot |
| **AI** | $49/mo | + AI package review (100 scans/day), central dashboard |
| **Enterprise** | $499/mo | + Unlimited scans, SIEM, SSO, SOC2 compliance |

## Features by Tier

### Personal ($9/mo)
- Process monitoring with auto-restart
- Telegram/Slack/Email alerts
- Basic threat blocklist
- 1 machine

### Basic ($29/mo)
Everything in Personal, plus:
- **Tripwire Monitor** — instant alerts when .env, SSH keys, or secrets are accessed
- **File Integrity** — SHA256 tracking of critical files
- **Honeypot Credentials** — canary files that catch malware
- 3 machines

### AI ($49/mo)
Everything in Basic, plus:
- **AI Package Review** — Claude Haiku analyzes every unknown package
- Verdicts: CLEAN / SUSPICIOUS / DANGEROUS
- 100 AI scans per day
- Central dashboard for all machines
- Unlimited machines

### Enterprise ($499/mo)
Everything in AI, plus:
- Unlimited AI scans
- SIEM integration (Splunk, Elastic, etc.)
- SSO (SAML, OIDC)
- SOC2 compliance reports
- 4-hour SLA
- Dedicated support

## Stats

- **56+ malicious packages** in blocklist
- **8 threat sources**: CISA, OSV.dev, NVD, GitHub, npm, Snyk, Socket, Gemini AI
- **AI-powered discovery** — Gemini 2.5 Flash hunts new threats in security blogs
- Updated **hourly**

## Links

- [stillrunning.io](https://stillrunning.io) — homepage
- [stillrunning.io/threats](https://stillrunning.io/threats) — live threat dashboard
- [stillrunning.io/docs](https://stillrunning.io/docs) — API docs
- [stillrunning.io/pricing](https://stillrunning.io/pricing) — get started
- [@bit_bot9000](https://x.com/bit_bot9000) — updates

## License

MIT License

Patent Pending — US Provisional Application filed April 12, 2026
