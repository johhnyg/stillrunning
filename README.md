# stillrunning

> Checks the packages you and your AI coding agent install against a list of
> about 236,000 packages publicly reported as malicious (OSV and other public
> advisories), before they install. It blocks what is on the list and asks you
> about what it cannot check. It does not catch a malicious package nobody has
> reported yet.

[![PyPI version](https://img.shields.io/pypi/v/stillrunning)](https://pypi.org/project/stillrunning/)
![Protected by stillrunning](https://stillrunning.io/badge/protected)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## What's new (security audit release, November 2026)

- **Claude Code hook** that looks up every package a command would install,
  with a one-line answer and a plain-English reason for each
- **Fail-closed by design** (below): what cannot be checked is put to you
- **Report card** (`stillrunning shield`), **status line**, and side-panel data
  (`stillrunning panel`)
- Six rounds of independent adversarial review before release; what they
  found is listed under "What it catches" and "Known limitations"

## The principle: fail closed

- A package **on the blocklist** is refused.
- A package that **could not be checked** — the server unreachable, the
  free allowance used up, a name that is not on the registry, a command the
  hook cannot read — is **put to you**, never passed silently. `STILLRUNNING_HOOK_STRICT=1`
  refuses instead of asking.
- If the hook **misreads a command** (an option it does not know, an odd
  spelling), the words it could not place are still looked up on the
  blocklist, so a misreading errs toward blocking.
- "No known threat" means the name is not on the list. It is not a
  statement that the package is harmless.

## What it catches

What the hook recognises as an install and looks up, including the
spellings that independent reviewers used to try to get a blocked package
past it (each one is now a test):

| You or your agent types | What happens |
|---|---|
| `pip install <listed package>` (pip, pip3, `python -m pip`, uv, poetry, pdm, pipenv, pipx, uvx, npm, pnpm, yarn, bun, npx) | Blocked, with the advisory id |
| A one-letter look-alike of a popular name (`reqeusts`) | Blocked if listed, otherwise asked about |
| A name that is not on the registry (an AI-invented name) | Asked about |
| A listed **version** (`litellm==1.82.8`, `axios@1.14.1`) | Blocked; a range or tag for such a package is asked about |
| A requirements file, in this folder or one reached by `cd` / `pushd` / a subshell | Every name in it is looked up |
| Clustered flags (`pip install -Ur requirements.txt`), notebook cells (`!pip`, `%pip`) | Read correctly |
| Behind `sudo -n`, `env`, `time -p`, `nohup`, `xargs`, `poetry run`, `uv run`, any other prefix | Looked up |
| Inside `sh -c '…'`, `bash -euo pipefail <<EOF`, `eval`, a pipe into a shell, a variable holding the command | Looked up |
| A blocked name given as an option's value (`pnpm add -w X`, `uv tool install ruff --with X`, `uvx --constraints c.txt X`) | Blocked |
| Plugin and tool installs (`poetry self add`, `pdm plugin add`, `pipx runpip`, `uv tool install`) | Looked up |
| A different spelling of a listed name (`Evil_Pkg`, `evil.pkg`) | Matched (one name rule, as pip itself applies) |
| Changes to stillrunning's own protection, or to where packages download from | Asked about (see below) |

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

### Run, restart, remove

- **Turn on / update the Claude Code hook:** `stillrunning --hook-claude-code`
  (add `--statusline` for the status line). Run it again after upgrading
  stillrunning; it replaces its own entry and leaves your other settings alone.
  New Claude Code sessions pick it up; restart a running one to be sure.
- **Check it is working:** `stillrunning status` (each layer ON / OFF / NOT
  VERIFIED, and why) and `stillrunning --doctor`.
- **See what it did:** `stillrunning shield`.
- **Terminal wrappers** (outside Claude Code): `stillrunning shell-install`,
  then open a new shell.
- **Remove:** `stillrunning --uninstall-hook-claude-code` restores your
  settings file byte for byte; `stillrunning shell-uninstall` removes the
  wrappers; then `pip uninstall stillrunning`.

## Import protection

```python
import stillrunning.hook  # Blocks malicious imports at runtime
```

## AI agent integrations

- **Claude Code:** the hook below — every install is looked up before it runs.
- **Other agents and plain terminals** (Cursor, Aider, a CI job): the terminal
  wrappers (`stillrunning shell-install`) and the MCP tool. Weaker: see
  "Known limitations".

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

## Known vulnerabilities (CVE monitoring)

**What it is:** a check of the packages you already use against known
vulnerabilities (bugs in honest packages, published as CVE / GHSA records), so
you hear about a fix sooner and the time to patch gets shorter.

**What it is not:** it does not detect malware (that is the blocklist's job)
and it does not stop attacks. It covers only what [OSV.dev](https://osv.dev)
knows (GitHub Advisory severities arrive through OSV). Anything it could not
resolve to one exact version reads UNKNOWN, never clear.

**What it checks:** this Python interpreter's installed packages, the
project's virtualenvs (`.venv`, `venv`, `env`), and exact versions from the
project's requirements files, manifests and lockfiles (a range in
`package.json` or `pyproject.toml` counts as resolved only when a lockfile in
the same folder pins it).

**States**

| State | Colour | Means |
|---|---|---|
| CLEAR | green | checked for this very folder, at least one package found and every part resolved, the whole search done, feed refreshed within 24 h, the check complete, and no known vulnerability for those versions |
| AFFECTED | red with a critical or a package OSV lists as malicious, amber otherwise | at least one package has a known vulnerability (count, worst severity, how many critical / malicious) |
| UNKNOWN | amber | never refreshed for this folder (or saved for another one), feed unreachable, older than 24 h or dated in the future, nothing found to check, part of the inventory unresolved or the search cut short, the check failed part-way, or the saved state unreadable or not adding up. This is the default |

The state is saved per project folder; every surface answers for its own
folder (the status line for the folder Claude Code names, the panel and the
CLI for `--cwd` or the current folder). A package OSV lists as malicious
(`MAL-` records) shows as AFFECTED with severity "malicious" and "remove it";
the blocklist is what refuses it at install time.

If some packages are affected and part is unresolved, AFFECTED wins and the
report says what was not checked.

**Commands**

```bash
stillrunning cve                    # report from the saved state (no network)
stillrunning cve --json             # the same as JSON, stable schema (no network)
stillrunning cve --refresh [--cwd DIR]   # inventory + check OSV.dev now
stillrunning cve --schedule [--cwd DIR]  # one crontab line: --refresh every 6 h (flock + timeout)
stillrunning cve --unschedule       # remove that line; other crontab lines are never touched
```

The status line adds one segment once a refresh has run (for example
`CVEs: 2 affected (1 critical) · feed 3h ago`); its freshness is never
dropped. The Claude Code side panel shows one line under "Already here", a
Details list (package, version, where, CVE/GHSA id, severity, first fixed
version, what to do) and a "Refresh CVE data" button. Drawing the panel never
fetches anything. `stillrunning shield` prints one CVE line.

**At install time:** when Claude Code is about to install a package whose
version (the exact pin, or the version an unpinned install would fetch) has a
known **critical** vulnerability, or a known vulnerability whose severity
could not be determined (no GitHub Advisory word and no CVSS v3 score), the
hook holds the install for your approval and names the id and the first fixed
version. When the command names a range, a tag or `--pre`, or the version it
would fetch cannot be worked out, and some version of the package has such a
vulnerability, it holds and says that versions it could install are affected.
These holds are not waved through by `STILLRUNNING_ALLOW_UNVERIFIED=1`. If the
vulnerability check cannot finish (OSV.dev unreachable or slow), it holds too
and says that it was the vulnerability check that could not run. HIGH,
MODERATE and LOW vulnerabilities never hold; they add a "not held" line. A blocklisted package
is still refused. The check runs alongside the blocklist lookup within the
same time limit and uses the saved state when it has that exact version and
is under 24 h old. Switch it off with `STILLRUNNING_CVE_CHECK=0` in the
environment Claude Code runs in.

**What is sent to api.osv.dev:** package names, ecosystems (PyPI / npm) and
versions, with the User-Agent `stillrunning-cve/1`. Never file contents,
paths or your account token. Nothing else is contacted by `--refresh`, and
redirects are refused. Only ids, version numbers and severity words from OSV
are shown; advisory text is not.

## Known limitations

What it does not cover, stated plainly. These were either found by the
independent reviews and accepted, or are outside what a command-reading hook
can do.

- **The CVE state file is trusted as written.** Every reader checks that it is internally consistent (totals, completeness, folder, times), but someone who can already write to `~/.stillrunning` can write a consistent file that reads CLEAR. Only a signature would stop that.
- **Only reported threats.** It matches names against a list of packages
  someone has already reported as malicious. A new malicious package nobody
  has reported yet reads "no known threat". Brand-new and rarely downloaded
  packages are not flagged.
- **Known vulnerabilities cover only what OSV.dev knows,** for the versions
  that could be resolved. A range without a lockfile, an unreadable file, a
  local or git dependency, conda/pixi packages, old-style `.egg-info` packages
  in a project virtualenv and npm packages installed but not in a lockfile are
  not checked; the state reads UNKNOWN when any part is unresolved. The
  project search reads at most 40 dependency files, two folders deep; when
  more exist the state reads UNKNOWN and says so. Severity is the GitHub
  Advisory word, else the CVSS v3 score; a record with only a CVSS v4 vector
  (or no score) has unknown severity, and an install of a version with such a
  record is held.
- **The install-time CVE hold** runs in the Claude Code hook only, not in the
  terminal wrappers. An install that names a range, a tag or `--pre` is held
  when any version of that package has a critical vulnerability, because the
  version it would fetch cannot be worked out. `STILLRUNNING_ALLOW_UNVERIFIED=1`
  lets a "could not run" hold through (with a warning), never a hold for a
  known critical or unknown-severity vulnerability. The status line shows the
  CVE segment only after the first `stillrunning cve --refresh` on this
  machine; in a folder that was never refreshed it reads "unknown · checked
  for another folder".
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
- **Option values are sent by name.** A word in an install command that could
  be a package name (`--filter web`, `uv add --package web`) is looked up on
  the blocklist, which sends that word to stillrunning.io. This is what makes
  a misread flag fail toward blocking; the cost is extra lookups of folder
  and workspace names.
- **Wording after an unknown option.** For `npx --some-unknown-option v tool`
  the ✓ line can name the option's value instead of the tool. The tool is
  still checked against the blocklist.
- **Some secrets can reach the local log.** The hook removes credentials from
  the commands it records, but a few spellings (`vault login TOKEN`,
  `heroku auth:token`, `echo S | sudo -S`) are not recognised. The log is
  readable only by you and is never uploaded.
- **Platforms.** Tested on Linux only (table below).
- **The GitHub Action** checks Python requirements; for npm it reports the
  scan as incomplete rather than checking scoped names.

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

- **Lookups** send the package name, ecosystem and (when given) version to
  stillrunning.io — never file contents. Without an account no token is sent.
  Words that could be package names in an install command are sent the same
  way (see "Known limitations").
- **Heartbeats** contain: command name, version, OS, anonymous UUID,
  timestamp. No code or file paths. Disable: `STILLRUNNING_NO_TELEMETRY=1` or
  `--no-telemetry`.
- **The hook's decision log** (`~/.stillrunning/hook_decisions.jsonl`, owner-only)
  stays on your machine.

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
