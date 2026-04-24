# Changelog

## v2.6.0 — April 24, 2026

**Fix OSV.dev integration — now ingests ~220,000 malicious packages**

### Fixed
- **OSV.dev API query was broken** — malformed `/v1/query` call returned 0 results
- Now uses bulk GCS download (`osv-vulnerabilities.storage.googleapis.com`) instead

### Added
- **osv_bulk.py** — server-side bulk ingestion of MAL-* advisories
- **222,873 malicious packages** now blocked (10,962 PyPI + 211,911 npm)
- Nightly cron refresh at 03:00 UTC

### Changed
- Blocklist lookup remains O(1) (dict-based, not list)
- Blocklist served from `/api/blocklist` — package size unchanged (76KB wheel)

### Followups (v2.7.0)
- Version-range blocking (currently blocks all versions via `["any"]`)

---

## v2.5.0 — April 24, 2026

**Completeness release — all deferred items from v2.4.0 shipped**

### Added
- **Virtual environment interception** via sitecustomize.py (survives `source .venv/bin/activate`)
- **`stillrunning venv-install`** command to enable venv persistence
- **`stillrunning venv-uninstall`** command to cleanly remove venv integration
- **Debug logging infrastructure** — set STILLRUNNING_DEBUG=1 for verbose output

### Changed
- **Exception handlers audited** — critical handlers now log to debug instead of silent pass
- **VERSION constant** bumped to 2.5.0 in cli.py

### Internal
- **stillrunning/venv_hook.py** — lightweight hook for sitecustomize.py integration
- **12 new tests** for venv persistence and logging infrastructure
- **40 total tests** passing

### Deferred
- A2 (cache version-aware): Requires dashboard.py changes — documented in v2.6.0-followups.md
- A5 (async scan endpoint): Requires dashboard.py changes — documented in v2.6.0-followups.md
- F (GitHub Action): Separate repo — documented in v2.6.0-followups.md
- A4 (exception audit): ~20 handlers updated, remaining documented for future work

---

## v2.4.0 — April 24, 2026

**Refinement release — closes HIGH-severity gaps from product audit**

### Added
- **Manifest parsing** for requirements.txt, pyproject.toml, Pipfile, package.json, environment.yml, pixi.toml
- **Interception for poetry, pdm, pipenv, conda, pixi, bun, pnpm** — all major package managers now covered
- **`stillrunning scan-manifest`** CLI command — check all packages in a manifest file before install
- **`pip install -r requirements.txt`** now scans each package (previously bypassed entirely)

### Fixed
- **Hardcoded /root/my-app/.env path** in hook.py — now uses XDG-compliant ~/.stillrunning directory
- **Editable installs** (`pip install -e .`) no longer erroneously blocked or flagged
- **Git/URL dependencies** correctly skipped (can't be checked, shouldn't block)

### Internal
- **stillrunning/manifest.py** — shared manifest parser for all package managers
- **28 new tests** covering manifest parsing, package manager support, and intercept behavior
- **MANAGER_ECOSYSTEM mapping** — proper ecosystem detection for all package managers

---

## v2.3.0 — April 24, 2026

**Critical correctness fixes**

- **Fix:** `/api/check-package` now checks blocklist (was returning UNKNOWN for blocked packages)
- **Fix:** `stillrunning scan <package>` command now works (was documented but not implemented)
- **Fix:** `uv pip install` and `uv add` are now intercepted (previously silent bypass)
- **Fix:** Namespace packages (`azure.storage.blob`) now checked against blocklist
- **Security:** All four fixes address cases where the tool appeared to work but didn't protect users

---

## v2.1.0 — April 19, 2026

**Anonymous telemetry (opt-in)**

- **Heartbeat** — sends anonymous ping to stillrunning.io every 6 hours
- **Setup prompt** — Y/n question after Telegram config
- **Privacy-first** — no email, IP, or log content; just random UUID
- **Disable anytime** — set `telemetry: false` in stillrunning.yaml

**Payload:** machine_id, agent_version, os_type, uptime_hours, process_count

This helps us understand how many agents are actually running. Previously we had 1,500 PyPI downloads but zero visibility into active usage.

---

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
- `/scan` route — customer file upload threat scanner (free tier 10/day)
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
