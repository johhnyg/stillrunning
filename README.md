# stillrunning

**Supply chain security for teams without security teams.**

```bash
pip install stillrunning
```

## What it does

- **Blocks malicious packages before they run** — intercepts npm/pip install, checks against live threat feed
- **Catches what AV misses** — AST analysis, entropy detection, pickle inspection without execution
- **Learns your environment** — auto-whitelists your processes, alerts on anomalies
- **Updates itself** — syncs blocklist every 60 minutes from 6 threat intel sources

## The attack it was built for

In 2026, North Korean state hackers published WAVESHAPER.V2 — 1,700+ malicious packages across npm and PyPI. Credential stealers disguised as logging utilities. Traditional AV found nothing. Enterprise tools cost $50k/year.

stillrunning catches it at install time, before it ever runs.

## Live proof

**[stillrunning.io/threats](https://stillrunning.io/threats)** — real-time intercept dashboard.

Not a demo. Every package check, every block, every threat advisory — live.

## Quick start

```bash
pip install stillrunning
stillrunning --setup
```

The setup wizard detects your running processes, configures monitoring, and connects to the live threat feed. Takes 3 minutes.

## Stats

- **33+ malicious packages** in blocklist
- **817,000+ alerts** suppressed by guard daemon
- **0 incidents** on protected machines
- **6 sources**: CISA, OSV.dev, NVD, GitHub Security, npm advisories, Snyk
- Updated **hourly**

## Pricing

| Tier | Price | What you get |
|------|-------|--------------|
| Open Source | Free | Core tools, local scanning |
| Personal | $9/mo | Live threat rules, guard daemon |
| Basic | $29/mo | + intercept, Telegram alerts |
| AI | $49/mo | + crash diagnosis, auto-fix suggestions |
| Enterprise | $499/mo | SSO, SIEM, SOC2 compliance reports |

## Links

- [stillrunning.io](https://stillrunning.io) — homepage
- [stillrunning.io/threats](https://stillrunning.io/threats) — live threat dashboard
- [stillrunning.io/docs](https://stillrunning.io/docs) — API docs
- [@bit_bot9000](https://x.com/bit_bot9000) — updates

## License

MIT License

Patent Pending — US Provisional Application filed April 12, 2026
