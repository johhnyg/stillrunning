# stillrunning

**What it does.** Before you or your AI coding agent install a Python or
JavaScript package, stillrunning looks its name up in a list of about 236,000
packages that have been publicly reported as malicious. A listed package is
refused; anything it could not check is put to you. It does not catch a
malicious package nobody has reported yet.

[![PyPI version](https://img.shields.io/pypi/v/stillrunning)](https://pypi.org/project/stillrunning/)
[![Glama score](https://glama.ai/api/github/johhnyg/stillrunning/score.svg)](https://glama.ai/mcp/connectors/io.stillrunning/stillrunning)
![Protected by stillrunning](https://stillrunning.io/badge/protected)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

> This README describes version 2.14.2. If you have 2.13.7, upgrade
> (`pip install -U stillrunning`): its Claude Code hook does not stop
> blocklisted packages. Tested on Linux.

Words used below:
- **blocklist** — the list of packages security researchers have reported as
  malicious.
- **typosquat** (look-alike) — a package named one letter off a popular one
  (`reqeusts`), published hoping someone mistypes.
- **CVE** — a public record of a known bug (vulnerability) in an honest
  package, usually fixed in a later version.
- **hash-pinned** — a requirements line that also gives the file's checksum
  (`--hash=sha256:…`), so the installer refuses any other file.

## Get started in 2 minutes

```bash
pip install stillrunning
stillrunning --hook-claude-code   # check every install Claude Code runs (no account needed)
                                  # + the /shield side panel (restart Claude Code to see it)
stillrunning status               # each protection layer: ON / OFF / NOT VERIFIED, and why
```

`stillrunning status` should now show `[ON] Claude Code hook`. Start a new
Claude Code session. From then on, every install it runs gets one line per
package, for example:

```
🛡 stillrunning ✓ requests (pip) — no known threat · 180 ms
🛡 stillrunning ✗ BLOCKED reqeusts (pip) — known malicious package · MAL-2024-1234
🛡 stillrunning ⚠ some-new-name (pip) — unverified: not on PyPI — approval needed
```

✓ goes ahead. ✗ is refused. ⚠ means it could not be checked, so Claude Code
asks you before running the command. (The advisory id above is an example.)

**Undo it:** `stillrunning --uninstall-hook-claude-code` puts your Claude Code
settings file back exactly as it was. Then `pip uninstall stillrunning` if you
want it gone completely (see "Troubleshooting" for a clean removal).

Without an account you are on the free tier: a limited number of lookups per
day. After that a listed package is still refused, and every other install
is asked about instead of passed.

## What you'll see while you work

- **One line per package** on every install Claude Code runs (above), with a
  short plain-English reason underneath when something was refused or asked.
- **A side panel** in Claude Code (stillrunning shield): what the hook
  checked, blocked and held for approval, each with its reason, whether the
  hook is on, and known CVEs in packages already installed. It ships inside
  the pip package; `stillrunning --hook-claude-code` adds it (skip it with
  `--no-panel`). Restart Claude Code, then type `/shield`. The panel only
  reads: it runs `stillrunning` and draws what comes back.
- **A status line** in Claude Code, if you turn it on:
  `stillrunning --hook-claude-code --statusline`. It never replaces a status
  line you already have. Once CVE checks have run it adds a segment such as
  `CVEs: 2 affected (1 critical) · feed 3h ago`.
- **A report card:** `stillrunning shield` shows what the hook checked,
  blocked and why, with recent decisions (`-n 20` for more, `--json` for
  tools).
- **Side panel data:** `stillrunning panel` prints what a Claude Code side
  panel shows (protection state, project packages). You do not need it to be
  protected.

## When it asks you

Asking means "I could not be sure, you decide". Claude Code shows its usual
approval prompt. What each kind of ask means:

| You see | What it means | What to do |
|---|---|---|
| `unverified: not on PyPI` / `not on npm` | No package by that name exists on the public registry. Often a typo or a name an AI made up. | Check the spelling. Do not approve a name you did not expect. |
| `unverified: could not be looked up` | The lookup did not finish: offline, stillrunning.io unreachable, or today's free allowance used up. | Approve only if you know the package. Retry later, or get a token. |
| A range or tag (`pkg>=1.0`, `pkg@latest`) for a package with some listed versions | Some versions are reported malicious; the hook does not work out which version the installer would pick. | Pin an exact version that is not listed. |
| A critical or unknown-severity vulnerability | That version has a known critical bug (CVE), or one whose severity is unknown. The line names the id and the first fixed version. | Install the fixed version instead. |
| `vulnerability check could not run` | OSV.dev could not be reached in time. | Approve only if you know the version is fine, or retry. |
| A custom index, a web address, a git URL or a local file | The source is not the public registry, so the list does not apply. | Approve only sources you trust. |
| A change to stillrunning's own files or settings, or to where packages download from | Protects the protection: writes to `~/.stillrunning`, Claude Code `settings.json`, stillrunning's code, `STILLRUNNING_*` variables, `pip config`, `.npmrc` and similar. | Approve if you meant to do it. |
| conda, mamba, pixi, cargo, gem, go, `curl … \| sh` | There is no threat list for these here; nothing was checked. | Your call. |

Lockfile installs (`npm ci`, `uv sync`, `poetry install`) are not asked about;
the hook adds a note that the lockfile's packages were not looked up.
`STILLRUNNING_HOOK_STRICT=1` refuses instead of asking.

## Offline blocklist

The Claude Code hook can block known-malicious packages with no network call:
when stillrunning.io is down, rate-limited or unreachable, or the registry is
slow, a package on the offline list is still blocked.

```bash
stillrunning blocklist --refresh    # download OSV.dev's malicious-package data (~250 MB) and build it
stillrunning blocklist --schedule   # refresh daily at 04:41, lowest priority (adds one crontab line)
stillrunning blocklist --status     # what is installed, and whether it passed its integrity check
```

The list is a small SQLite file (about 11 MB for every malicious pip and npm
package OSV.dev knows) in `~/.stillrunning`. The hook opens it read-only and
does one indexed lookup; it never downloads or rebuilds it. Its manifest
carries an HMAC with a per-machine key, so corruption, a half-written file or
a change by anything that cannot read the key is caught. If the check fails,
every install is blocked until `stillrunning blocklist --refresh` rebuilds it.
Without the list, the hook works as before (the hosted lookup).

A list more than 3 days old (three missed daily refreshes), with no build
time, or with a build time in the future is **stale**: it
still blocks everything on it, but every install check then carries a warning
that packages reported since its build are not on it, with the refresh
command, and `stillrunning blocklist --status` exits 3 and says STALE.

Known limits (tracked, not yet addressed):

- The HMAC is a per-machine MAC, not a third-party signature: code running as
  your user can read the key and re-sign a changed list, and can put back an
  older list that was valid when it was built (its build time is then old, so
  the stale warning shows).
- A package with some versions listed, installed with no exact version, is
  blocked when the version that would install cannot be worked out. Installed
  with a version range or wildcard (`pkg>=1`, `pkg@^1`, `pkg==1.0.*`), with
  `--pre` or with a constraints file, it is asked about instead (never
  allowed on the hosted lookup's word alone): a person decides.
- Version spellings pip treats as equal but written differently
  (`1.0.0-rc1` for a listed `1.0.0rc1`) are not matched offline.
- Packages a command only names indirectly (a shell command inside `npx -c`,
  for example) are looked up on the hosted service only, not offline.
- On Windows the database's hash is checked on every hook call (no stable
  inode/ctime to remember it by): about 0.1 s more per call.
- Version ranges are compared offline only for plain numeric versions;
  anything else (`1.0rc1`) is left to the hosted lookup.

## Known vulnerabilities (CVEs)

Separate from the blocklist: this checks the packages you already use against
known bugs (CVE / GHSA records from [OSV.dev](https://osv.dev)), so you hear
about a fix sooner. It does not detect malware.

```bash
stillrunning cve --refresh          # check this project and this Python now
stillrunning cve --schedule         # also refresh every 6 hours (adds one crontab line)
stillrunning cve                    # show the last result (no network)
```

Run them in the project folder (or add `--cwd DIR`). `stillrunning cve
--unschedule` removes the crontab line and nothing else.

What the answer means:
- **CLEAR** (green) — everything found in this folder was checked in the last
  24 hours and none of those versions has a known vulnerability.
- **AFFECTED** (red for critical or malicious, amber otherwise) — at least one
  package has a known vulnerability. The report lists package, version, id,
  severity and the first fixed version.
- **UNKNOWN** (amber, the default) — it cannot say: never refreshed for this
  folder, the feed is older than 24 hours or unreachable, or part of the
  project could not be resolved to exact versions. It says which.

When AFFECTED: upgrade each listed package to at least its first fixed
version (or remove it if marked "malicious"), then `stillrunning cve
--refresh`. If you cannot upgrade yet, note why; it will stay AFFECTED.

Separately, during installs the Claude Code hook holds a version with a
**critical** or unknown-severity vulnerability for your approval. High,
moderate and low ones are shown but not held. Details: "CVE monitoring — in
detail" below.

## Turning things off

| To turn off | Do this |
|---|---|
| The Claude Code hook | `stillrunning --uninstall-hook-claude-code` |
| The terminal wrappers | `stillrunning shell-uninstall` (then open a new shell) |
| Import-time checks | `stillrunning --uninstall-hook` |
| Venv persistence | `stillrunning venv-uninstall` |
| The 6-hourly CVE refresh | `stillrunning cve --unschedule` |
| The install-time CVE hold | `STILLRUNNING_CVE_CHECK=0` in the environment Claude Code runs in |
| The local verdict cache | `STILLRUNNING_CACHE=0` |
| Heartbeats (usage pings) | `STILLRUNNING_NO_TELEMETRY=1` |
| Setup-wizard and first-scan pings | `STILLRUNNING_NO_FUNNEL=1` (or `STILLRUNNING_NO_TELEMETRY=1`) |

## Privacy: what leaves your machine

- **Lookups** send the package name, ecosystem and (when given) version to
  stillrunning.io — never file contents. Without an account no token is sent.
  Other words in an install command that could be package names (an option's
  value, such as a folder name) are sent the same way.
- **CVE checks** send package names, ecosystems (PyPI / npm) and versions to
  api.osv.dev, with the User-Agent `stillrunning-cve/1`. Never file contents,
  paths or your token.
- **Heartbeats** contain: command name, version, OS, an anonymous id,
  timestamp. No code or file paths. Turn off with `STILLRUNNING_NO_TELEMETRY=1`.
- **Setup-wizard steps** (`stillrunning --setup`): which step was reached, the
  same anonymous id as heartbeats, the version and time. Once per machine, the
  first `stillrunning scan` / `scan-manifest` also sends whether that scan ran
  or could not check (its exit code), never the package name; a marker at
  `~/.stillrunning/first_scan_sent` stops it repeating. Turn off with
  `STILLRUNNING_NO_FUNNEL=1` or `STILLRUNNING_NO_TELEMETRY=1`.
- **Stays on your machine:** the hook's decision log
  (`~/.stillrunning/hook_decisions.jsonl`), the CVE state
  (`~/.stillrunning/cve_state.json`) and the local verdict cache
  (`~/.stillrunning/verdicts.db`), all readable only by you.

## Troubleshooting

- **`stillrunning status` says OFF for the Claude Code hook.** Run
  `stillrunning --hook-claude-code` again (also after every upgrade), then
  start a new Claude Code session. `stillrunning --doctor` gives more detail.
- **Everything says "could not be looked up".** You are offline, stillrunning.io
  is unreachable, or today's free allowance is used up (the reason line says
  which). After the free allowance, listed packages are still refused; the
  rest are asked about, not passed, until lookups work again (tomorrow, or with
  a token: https://stillrunning.io/pricing).
- **CVE says UNKNOWN.** Usually it was never refreshed for this folder
  ("checked for another folder"), or the last refresh is over 24 hours old.
  Run `stillrunning cve --refresh` in the project folder, and
  `stillrunning cve --schedule` to keep it fresh.
- **The hook asks before a command that touches its own files.** That is on
  purpose: anything that edits `~/.stillrunning`, Claude Code settings or
  stillrunning itself could switch the protection off. Approve it if you meant it.
- **Remove it cleanly:**
  ```bash
  stillrunning --uninstall-hook-claude-code   # restores settings.json byte for byte
  stillrunning shell-uninstall                # if you installed the wrappers
  stillrunning --uninstall-hook               # if you turned on import-time checks
  stillrunning cve --unschedule               # if you scheduled CVE refreshes
  pip uninstall stillrunning
  ```
  Your local data is in `~/.stillrunning`; delete that folder too if you want
  nothing left.

---

# Reference

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

What the hook recognises as an install and looks up, including unusual
spellings (each one is a test):

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
| import statement | Blocked by the import hook (`stillrunning --install-hook`, needs a token) |

## Other ways to use it

- **Claude Code:** the hook (above, and in detail below).
- **Other agents and plain terminals** (Cursor, Aider, a CI job): the terminal
  wrappers (`stillrunning shell-install`, bash and zsh) and the MCP tool. These
  are weaker: see "Known limitations".
- Setup notes: [stillrunning.io/agent-setup](https://stillrunning.io/agent-setup)

### The Claude Code hook in detail

```bash
stillrunning --hook-claude-code                # registers a PreToolUse hook in ~/.claude/settings.json
stillrunning --hook-claude-code --statusline   # also adds a status line (never replaces yours)
stillrunning --hook-claude-code --no-panel     # hook without the /shield side panel
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

### Import protection

```python
import stillrunning.hook  # checks imported packages against the blocklist at import time
```

`stillrunning --install-hook` turns this on for every Python start (needs a token).

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

## CVE monitoring — in detail

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

## Local verdict cache

**What it does:** when the Claude Code hook has positively verified an exact
release — the blocklist lookup completed and found no match, and the
known-vulnerability check completed and held nothing — it records that in
`~/.stillrunning/verdicts.db` (SQLite; file 0600, folder 0700), keyed to
ecosystem + name + exact version + artifact hash, with the time, the
blocklist feed age, the vulnerability result and the stillrunning version.
If the same ecosystem + name + version + hash comes up again and the live
check **cannot complete** (stillrunning.io unreachable, free allowance used
up, a timeout, OSV.dev unreachable), the hook answers from that record
instead of asking you:

```
🛡 stillrunning ✓ six 1.16.0 (pip) — no known threat (verified on this machine 3h ago; not re-checked now)
```

It counts as "no known threat" in `stillrunning shield`, with an evidence line
saying it came from the local cache. `stillrunning shield` also shows how many
unexpired verdicts are on this machine.

**What it never does:** the live checks always run first, and any answer they
give wins. The cache never passes a package on the blocklist (the list that
ships with stillrunning, or any live answer — a live "listed" deletes the
record), a version with a critical or unknown-severity vulnerability (from the
live check or from the saved `cve_state.json`), a name the registry says does
not exist, an answer from the server that the hook did not understand, a
range / tag / `--pre` / constraints install, a different version, a different
hash, or a command that also has any other hold (custom index, web address or
git URL, local file that is not there, unreadable requirements file,
protection change, a command the hook cannot read). Those are put to you
exactly as before. It never makes a network call and nothing in it leaves
the machine.

**Where the hash comes from — and why it will rarely apply:** only from a
`--hash=sha256:…` (or sha384 / sha512) pin on an exact `name==version` line of
a requirements file the hook reads — in practice, the output of
`pip-compile --generate-hashes` or `uv pip compile --generate-hashes` — and
only when the command is one whose installer checks that pin: `pip install`
(`python -m pip install`; once any line has `--hash`, pip requires and checks
hashes for the whole install, and pip has no switch that turns this off).
**uv gets no hash**: uv can turn hash checking off from a config file
(`uv.toml`, `[tool.uv.pip]` in `pyproject.toml`, user or system level) that
the hook does not read, so a uv install never earns a cached pass. `uv pip
install`, `uv pip sync`, `uv add -r`, `pip
download` / `pip wheel`, `pipenv`, `poetry`, `pdm`, `pipx`, `uvx`,
`easy_install`, npm, lockfile installs and local files get **no hash**.
Nothing is fetched to get a hash. **Without such a pin the cache does not
apply at all** (nothing stored, nothing answered): for a typical Claude Code
session — `pip install x`, `npm install x`, `poetry add x`, `uvx tool` — it
will almost never apply. The same pin written twice with different hashes
counts as no hash.

**Expiry:** 24 hours by default; `STILLRUNNING_CACHE_TTL_HOURS` changes it, up
to 7 days. An expired verdict never passes; the next completed check stores a
fresh one.

**Switch:** `STILLRUNNING_CACHE=0` (or `false` / `off`) in the environment
Claude Code runs in turns it off completely: nothing is read or written.
An unreadable or corrupt `verdicts.db` is treated as empty (with a warning)
and set aside as `verdicts.db.corrupt` on the next write.

## Known limitations

What it does not cover, stated plainly.

- **The CVE state file is trusted as written.** Every reader checks that it is internally consistent (totals, completeness, folder, times), but someone who can already write to `~/.stillrunning` can write a consistent file that reads CLEAR. Only a signature would stop that.
- **The local verdict cache can be one day behind the blocklist.** A package
  added to the blocklist after this machine verified it is still answered from
  the cache while the live check cannot complete (offline, quota, timeout),
  until the verdict expires (24 h by default, at most 7 days). The same holds
  for a vulnerability published after the verdict. Once a live answer gets
  through, it wins and the record is deleted. Someone who can already write to
  `~/.stillrunning` can also write a verdict; the hook asks before any command
  that touches that folder, but nothing signs the file. A `verdicts.db` (or its
  folder) that another account could write is never used: it is moved aside as
  `verdicts.db.untrusted`. The cache only applies to `--hash` requirements lines
  installed by an installer that checks them (see "Local verdict cache").
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

## Configuration

| Variable | Purpose |
|----------|---------|
| `STILLRUNNING_NO_TELEMETRY=1` | Disable heartbeat |
| `STILLRUNNING_NO_FUNNEL=1` | Disable the setup wizard's step pings and the one-time first-scan ping |
| `STILLRUNNING_CVE_CHECK=0` | Turn off the Claude Code hook's install-time CVE check |
| `BLOCKLIST_MAX_AGE_DAYS=730` | Max age for blocklist entries (default 2 years) |
| `STILLRUNNING_TOKEN` | API token (enables import-time checks) |
| `STILLRUNNING_API_BASE=<url>` | Point the client at a test server **on this machine** (`localhost`, `127.0.0.1` or `::1`). Any other host is refused with a warning and `https://stillrunning.io` is used. The account token is never sent to a test server |
| `STILLRUNNING_ALLOW_UNVERIFIED=1` | Install packages that could not be checked without asking (a warning is printed every time). Default: ask, or stop when nobody is at the keyboard. It never installs a package that is on the blocklist, and it does not apply when only some versions of a package are listed |
| `STILLRUNNING_FAIL_CLOSED=1` | Wrappers always stop (never ask) when a package could not be checked |
| `STILLRUNNING_HOOK_STRICT=1` | Claude Code hook denies instead of asking when a package could not be checked |
| `STILLRUNNING_CACHE=0` | Turn the Claude Code hook's local verdict cache off (no read, no write). Default on |
| `STILLRUNNING_CACHE_TTL_HOURS=24` | How long a local verdict is used (hours, at most 168) |
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
stillrunning --setup          # Setup wizard; exits 4 when it ends with nothing checking installs
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
stillrunning whitelist add <pkg>    # Add to whitelist (whitelist remove / list)
stillrunning cve [--refresh] [--schedule] [--unschedule] [--json] [--cwd DIR]   # known vulnerabilities (OSV.dev)
stillrunning panel [--scan] [--json]   # data for the Claude Code side panel
stillrunning venv-install           # keep import checks in virtualenvs (venv-uninstall removes it)
stillrunning remember / forget      # "don't ask again" — switched off in this version (refuses)
```

### `--setup` exit codes

| Code | Meaning |
|---|---|
| 0 | Setup finished and at least one layer checks installs (for example the Claude Code hook is ON). |
| 1 | The alert settings could not be saved (for example the home directory is not writable). Nothing was saved. |
| 2 | No answer came (piped or closed input), or 5 answers in a row were not valid (menu choice or email address). Nothing was saved. |
| 4 | Setup finished, but **nothing checks the packages you install**: run `stillrunning --hook-claude-code` or `stillrunning shell-install`. Setup changes Claude Code settings only when you type yes in a terminal, so piped setup ends here. |
| 130 | Cancelled with Ctrl-C during the alert questions (Ctrl-C at the hook question counts as no, so that ends with 4). |

`--autonomous` exits 0 as before, even when nothing checks installs (it says so in its output).

## Security Advisories

Browse the full threat database: [stillrunning.io/security-advisories](https://stillrunning.io/security-advisories)

RSS feed: [stillrunning.io/security-advisories/rss.xml](https://stillrunning.io/security-advisories/rss.xml)

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

**Basic** ($29/mo)
- Everything in Personal
- yourname.stillrunning.io dashboard
- 3 machines

**Ai** ($49/mo)
- Everything in Basic
- AI source review of pip packages (100/day, on request)
- AI Agent Integrity Monitor (not available: runs only on the stillrunning server, not shipped to customers)
- Unlimited machines

**Enterprise** ($499/mo)
- Everything in AI
- 10,000 AI package reviews/day
- Team roles (admin / responder / viewer)
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
