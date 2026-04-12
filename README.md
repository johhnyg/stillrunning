# stillrunning

**Enterprise security and monitoring for developers who can't afford enterprise tools.**

Patent Pending - US Provisional Application filed April 12, 2026

## Install

```bash
pip install stillrunning
```

## What's included

| Command | What it does |
|---|---|
| `stillrunning --setup` | 3-minute setup wizard, auto-detects your processes |
| `stillrunning-scan <file>` | Static analysis - AST, entropy, pkl inspector |
| `stillrunning-guard` | Always-on security daemon, auto-learning whitelist |
| `stillrunning-intercept` | npm/pip supply chain attack blocker |
| `pkl-inspector <file>` | Pickle file analysis without execution (Patent Pending) |

## The threat

In 2026, North Korean state hackers published 1,700+ malicious packages to npm and PyPI. Traditional AV found nothing. stillrunning catches it before it runs.

## Pricing

- **Free**: `pip install stillrunning` - open source core
- **Personal $9/mo**: guard daemon + live threat rules
- **Pro $29/mo**: guard + intercept + Telegram alerts
- **Team $99/mo**: 10 machines, central dashboard
- **Enterprise $499/mo**: SSO, SIEM, compliance reports

[stillrunning.io](https://stillrunning.io)

## Open source siblings

- **pkl-inspector**: `pip install pkl-inspector` (Patent Pending)
- **bitbot-primitives**: `pip install bitbot-primitives`

## Features

### Security Scanner (`stillrunning-scan`)
- AST-based Python code analysis
- Shannon entropy detection for obfuscated payloads
- Pickle file static analysis (no execution)
- Threat scoring with CLEAN/REVIEW/DANGEROUS verdicts

### Guard Daemon (`stillrunning-guard`)
- Always-on process monitoring
- Auto-learning whitelist (reduces false positives)
- macOS keychain/LaunchAgent monitoring
- Telegram alerts for threats

### Supply Chain Protection (`stillrunning-intercept`)
- Wraps npm/pip install commands
- Blocks known malicious packages
- Live threat feed from stillrunning.io
- WAVESHAPER.V2 detection

### Docker Agent (`stillrunning-docker`)
- Container security monitoring
- Privileged container detection
- Sensitive mount alerts
- Malicious image blocking

### Pickle Inspector (`pkl-inspector`)
- Static analysis without execution
- Opcode-level parsing
- CRITICAL/DANGEROUS/SUSPICIOUS verdicts
- Protocol 0-5 support

## Quick Start

```bash
# Install
pip install stillrunning

# Setup wizard (detects your processes)
stillrunning --setup

# Scan a file
stillrunning-scan suspicious.py

# Analyze a pickle
pkl-inspector model.pkl

# Start guard daemon
stillrunning-guard
```

## License

MIT License

Copyright 2026 stillrunning.io
