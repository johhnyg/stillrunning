# stillrunning

> Supply chain security for developers and AI coding agents.
> Active protection against 200,000+ verified malicious packages from 8 threat intelligence sources.

[![PyPI version](https://img.shields.io/pypi/v/stillrunning)](https://pypi.org/project/stillrunning/)
![Protected by stillrunning](https://stillrunning.io/badge/protected)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## What's new in v2.8

- **Async scan endpoint** — `POST /api/scan/async` for non-blocking scans
- **Version-aware AI cache** — cache keyed by `(package, version)` tuple
- **Source tracking** — every blocklist entry records where it came from
- **OSV.dev bulk ingestion** — 222k malicious packages from PyPI and npm
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
| poetry | Intercepted: `add`, `update <name>`, `self add`; `install` / `sync` carry a note (lockfile, not looked up) |
| pdm | Intercepted: `add`, `update <name>`, `self add`, `plugin add`; `install` / `sync` carry a note |
| pipenv | Intercepted: `install <name>`; a bare `install` / `sync` carries a note |
| pipx / uvx | Intercepted: `install`, `inject`, `upgrade`, `reinstall`, `run`, `runpip`; `uv tool install` / `upgrade`, `--with` |
| conda / mamba / pixi | Asks you (no threat list for these; not checked) |
| cargo install / gem install / go install | Asks you (not checked) |
| `curl … \| sh` and similar | Asks you (a script straight from a web address) |
| npm | Intercepted |
| bun | Intercepted |
| pnpm | Intercepted |
| requirements.txt | Scanned |
| import statement | Blocked (via hook) |

## Quick start

```bash
pip install stillrunning
stillrunning --setup              # setup wizard; ends by listing what is and is not protected
stillrunning --hook-claude-code   # look up every install Claude Code runs (works without an account)
stillrunning status               # each protection layer: ON / OFF / NOT VERIFIED, and why
stillrunning scan <package>       # One-shot scan
```

Nothing is checked until a layer in `stillrunning status` says ON. Without an
account you are on the anonymous free tier: a limited number of lookups per
day, after which each install asks you first instead of being looked up.

## Import protection

```python
import stillrunning.hook  # Blocks malicious imports at runtime
```

## AI agent integrations

Works with: Claude Code, Cursor, Devin, Replit, GitHub Copilot, Windsurf, Aider

Setup: [stillrunning.io/agent-setup](https://stillrunning.io/agent-setup)

### Claude Code hook

```bash
stillrunning --hook-claude-code                # registers a PreToolUse hook in ~/.claude/settings.json
stillrunning --hook-claude-code --statusline   # also adds a status line (never replaces yours)
stillrunning shield                            # report card: what was checked, blocked, and why
stillrunning --uninstall-hook-claude-code
```

Every `pip` / `npm` / `uv` / `yarn` / `pnpm` / `npx` install Claude Code runs is
looked up first. You see one line per package (`no known threat`, `BLOCKED`, or
`unverified — approval needed`) with a plain-language reason. A known-malicious
package is denied; anything that could not be checked asks you. "No known
threat" means the name is not on the blocklist — it is not a guarantee.

The hook also asks you before Claude Code changes stillrunning's own
protection: a shell command that writes to, deletes or replaces
`~/.stillrunning`, a Claude Code `settings.json` (in `~/.claude` or in a
project's `.claude`, including removing or moving that `.claude` folder), or
stillrunning's own code; a `git stash`, `git reset --hard`, `git clean`,
`git restore` or `git checkout -- <path>` run where it would put those files
back or delete them (`git clean` and `git stash -u` also ask in a project
whose `.claude` holds a settings file; a plain `git stash` or `git checkout
<branch>` there does not);
one that sets or reads a `STILLRUNNING_*` variable; `stillrunning allow`,
`remember`, `forget` or an uninstall; and any Write / Edit aimed at those
files. So is program text that loads stillrunning's own modules or writes to
those places (`python -c`, a here-document handed to an interpreter). Reading
those files, `git add` / `git diff` on them, or text that merely mentions them
(a commit message, a file being written elsewhere), is not asked about. It also asks
before anything changes where packages download from: an index or registry
variable, `pip config set`, `npm config set registry`, or a write to `.npmrc`,
`pip.conf`, `.pypirc` or `uv.toml`. If you set this up with an earlier
version, run `stillrunning --hook-claude-code` again to cover Write / Edit.

What counts as an install: a package installer actually being run — directly,
behind a wrapper or runner (`sudo`, `poetry run`, `uv run`, any other leading
program), inside `sh -c '…'`, `eval`, a here-document or pipe into a shell
(with or without shell options: `bash -euo pipefail <<EOF`), `find -exec` or
`xargs`, or as a notebook cell (`!pip install`, `%pip install`). Text that
only mentions an install (a commit message, a search pattern, a here-document
handed to `python3 -` or written to a file) is not.

Options are read per tool (`-w` is a workspace name for npm and a switch for
pnpm). Because a table like that can be wrong, the other words of an install
command that could be a package name — an option's value, a word after a
subcommand the hook does not know — are also asked about on the blocklist. A
hit there blocks the install like any other; anything else changes nothing,
so this adds no questions. Two limits to that:

- For a command that runs a tool (`npx`, `uvx`, `uv tool run`, `pipx run`,
  `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`), the tool is looked up and so
  are the values of the options before it. If one of those options is not
  one the hook knows, the word after its value is looked at as well, in case
  that is the real tool. The tool's own arguments are not looked at.
- An option's value is not looked at when the word itself shows it is what
  the option expects: one of the option's own fixed words (`--resolution
  lowest`), an address (`--trusted-host pypi.example.com`), a number or
  version (`--python 3.12`), a platform name, or a file or folder that is
  there. Any other value (`-t vendor`, `-w web`) is asked about by name, which
  means that one word is sent to stillrunning.io like any package name.

What it cannot do, stated plainly:

- **What the hook does not see.** It reads the text of the command Claude
  Code is about to run, nothing else. It does not see an install started from
  inside a program (a Python or Node script, a here-document handed to
  `python3 -`, a script file that already exists), anything run in a container
  (`docker run`, `docker exec`, `docker build`), on another machine (`ssh`),
  or by `make` and other task runners, or a command spelled so that its text
  does not show an installer (a renamed copy of `pip`, an alias defined
  earlier). The terminal wrappers (`stillrunning shell-install`) cover part of
  that gap: they sit on PATH, so `pip` and `npm` are checked however the
  command that reached them was spelled. `sudo` and a full path
  (`/usr/bin/pip`) bypass PATH and therefore bypass the wrappers.
- **Things it asks about instead of reading.** A program chosen at run time
  (`$PIP install x`), a folder chosen at run time (`cd $DIR && pip install -r
  requirements.txt`), text that is decoded or downloaded and then run
  (`base64 -d | sh`, `curl … | sh`, a script downloaded and run in one
  command), and inline code that starts an installer (`python -c`, `node -e`,
  `perl -e`).
- **Lockfile installs are not looked up.** `npm ci`, `uv sync`, `poetry
  install`, `pdm install` and `pipenv sync` install whatever the lockfile
  names; the hook shows a note saying so. `bundle install` is not seen at all.
- **"Don't ask again" is switched off.** `stillrunning remember` exists but
  refuses in this version: an approval for a command the hook cannot read
  would keep applying after what that command fetches had changed.
- **Files changed by the same command.** If a command writes a requirements
  file or archive and then installs from it (`curl -o r.txt … && pip install
  -r r.txt`, `git pull && pip install -r requirements.txt`), the hook asks:
  what it can read is not what would be installed.
- **conda, mamba, pixi, cargo, gem and go** have no threat list here. Their
  installs are put to you, not checked.
- **Ranges and tags.** When only some versions of a package are reported as
  malicious, an exact version (`pkg==1.2.3`, `pkg@1.2.3`) is checked as that
  version. A range, a tag, `--pre` or a constraints file is put to you: the
  hook does not work out what the installer would pick.
- **Terminal wrappers trust the environment they run in.** Outside Claude
  Code, anything that can run a command can also set
  `STILLRUNNING_ALLOW_UNVERIFIED=1` in front of it, call the real `pip` by
  its full path, or edit the wrapper. That switch cannot be told apart from
  your own choice, so the wrappers honour it for *unverified* packages; a
  package on the blocklist is still stopped. Other AI agents get this layer
  only — it is a seatbelt, not a sandbox.

### Claude Code MCP server

```bash
claude mcp add --transport http stillrunning https://stillrunning.io/mcp
```

Or put this in a project's `.mcp.json`:

```json
{
  "mcpServers": {
    "stillrunning": {
      "type": "http",
      "url": "https://stillrunning.io/mcp"
    }
  }
}
```

The server offers one tool, `check_package` (PyPI packages only). It answers
BLOCKED, SUSPICIOUS or UNKNOWN; UNKNOWN means "not on the list", not "harmless".
The MCP server only answers when the model asks it; the hook above is what
stops an install.

### GitHub Actions

Add supply chain security to your CI/CD pipeline:

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  stillrunning:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: johhnyg/stillrunning@v1
        with:
          requirements: requirements.txt
          # Optional: fail on suspicious packages too
          # fail-on-suspicious: true
```

For npm projects:

```yaml
      - uses: johhnyg/stillrunning@v1
        with:
          package-json: package.json
          package-lock: package-lock.json
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
| `STILLRUNNING_TOKEN` | API token (enables import-time checks) |
| `STILLRUNNING_API_BASE=<url>` | Point the client at a test server **on this machine** (`localhost`, `127.0.0.1` or `::1`). Any other host is refused with a warning and `https://stillrunning.io` is used. The account token is never sent to a test server |
| `STILLRUNNING_ALLOW_UNVERIFIED=1` | Install packages that could not be checked without asking (a warning is printed every time). Default: ask, or stop when nobody is at the keyboard. It never installs a package that is on the blocklist, and it does not apply when only some versions of a package are listed |
| `STILLRUNNING_FAIL_CLOSED=1` | Wrappers always stop (never ask) when a package could not be checked |
| `STILLRUNNING_HOOK_STRICT=1` | Claude Code hook denies instead of asking when a package could not be checked |
| `STILLRUNNING_TRUSTED_INDEX=<url>` | A package index (`PIP_INDEX_URL` …) the Claude Code hook should not ask about |
| `STILLRUNNING_COLOR=1` | ANSI colour in the Claude Code hook's lines (the status line and `shield` colour themselves; `NO_COLOR` turns it off) |

Token, in the order every command reads it: `STILLRUNNING_TOKEN`, then
`~/.stillrunning/config.json` (`{"token": "..."}`), then the legacy
`~/.stillrunning/stillrunning.yaml` (`token: ...`) and `~/.stillrunning/.env`.

## Platforms

| | Linux | macOS | Windows |
|---|---|---|---|
| `scan`, `scan-manifest`, `status`, `shield` | yes | expected to work, not yet tested | expected to work, not yet tested |
| Claude Code hook | yes | expected to work, not yet tested | not yet tested |
| Terminal wrappers (`shell-install`) | bash, zsh | bash, zsh (not yet tested) | not supported yet |
| Process monitor, `stillrunning-guard` | yes | not supported yet | not supported yet |

Unsupported combinations say so and exit instead of failing part-way.

## Commands

```bash
stillrunning --setup          # Setup wizard
stillrunning --doctor         # Health check (alias: --diagnose); exits 1 when nothing checks installs
stillrunning --reconfigure    # Run setup again
stillrunning --version
stillrunning status           # Protection layers: ON / OFF / NOT VERIFIED
stillrunning shield           # Claude Code hook report card (--json for other front ends)
stillrunning --install-hook   # Enable always-on import protection
stillrunning --autonomous     # CI/CD mode
stillrunning --allow <pkg>    # Allow a blocked package
stillrunning scan <pkg>       # Look one package up (also pkg==1.2.3, or pkg@1.2.3 --npm)
stillrunning scan-manifest <file>   # requirements*.txt, pyproject.toml, Pipfile, poetry.lock, uv.lock,
                                    # package.json, package-lock.json, pnpm-lock.yaml, environment.yml
stillrunning shell-install    # pip / npm wrappers for bash and zsh (shell-uninstall removes them)
stillrunning --hook-claude-code     # Claude Code hook (--uninstall-hook-claude-code removes it)
stillrunning whitelist add <pkg>    # Add to whitelist
stillrunning whitelist list         # Show whitelist
```

## Pricing

<!-- BEGIN:tier-table -->
| Tier | Price | Scans/day | Machines | Dashboard |
|------|-------|-----------|----------|-----------|
| Free | Free | 10 | 1 | No |
| Personal | $9/mo | 100 | 1 | No |
| Basic | $29/mo | Unlimited | 3 | Yes |
| Ai | $49/mo | Unlimited | Unlimited | Yes |
| Enterprise | $499/mo | Unlimited | Unlimited | Yes |
<!-- END:tier-table -->

<!-- BEGIN:feature-list -->
**Personal** ($9/mo)
- Everything in Free
- 100 scans/day
- Telegram + email alerts
- Email support

**Basic** ($29/mo)
- Everything in Personal
- yourname.stillrunning.io dashboard
- Monday weekly reports
- Uptime milestone alerts
- File integrity tripwire
- 3 machines

**Ai** ($49/mo)
- Everything in Basic
- AI crash diagnosis
- Reply to alerts - AI answers
- Crash pattern detection
- AI Agent Integrity Monitor
- Unlimited machines
- Priority support

**Enterprise** ($499/mo)
- Everything in AI
- Dedicated account manager
- Custom integrations
- SLA guarantee
- On-premises option
<!-- END:feature-list -->

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
