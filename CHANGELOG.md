# Changelog

> Older entries record what each release said at the time. Not available
> today: Telegram approve/deny buttons ("interactive approvals"), Telegram
> two-way control, two-way email and reply-to-alert AI answers, the Monday
> weekly report, and email alerts (mail is off on the server). The Windows
> installer is not tested. SIEM, SSO and compliance were tier flags only,
> never built.

## Unreleased (not published)

Six batches since 2.14.3, newest first below. Three change behaviour: the
offline blocklist changes what is blocked (below), the hook failing closed
changes what is blocked (a crash or timeout of the hook now blocks, and a
command over the 128K-character limit is asked about), and setup changes the
exit code of `--setup` (BREAKING, below). The other three change nothing that
is checked or blocked.

### Offline blocklist; no downgrade when the lookup cannot complete (2026-11-25)

A contract test of the hook against the hosted MCP server found that when an
anonymous user's free lookups are used up, a burst of installs is
rate-limited at the edge, and the hook then asked about every package,
including known-malicious ones, instead of blocking them.

- **`stillrunning blocklist --refresh / --schedule / --status`**: builds an
  offline list of every malicious pip and npm package OSV.dev knows (about
  11 MB of SQLite; the build downloads ~250 MB, uses ~180 MB of memory for about
  a minute, single-threaded at the lowest priority). A package on it is
  **blocked with no network call**, whatever the state of stillrunning.io or
  the registry. Names are normalized as the hook does (PEP 503 for pip; npm
  lower case), so case and separator spellings match.
- The list's manifest carries an HMAC with a per-machine key. If it, the key
  or the database does not check out, **every install is blocked** with a
  message naming the rebuild command. Without a list the hook works as before.
- **Stricter (BREAKING):** a package with some versions reported as
  malicious, installed with no exact version, is now **blocked** when the
  version that would install cannot be worked out (it used to ask). When the
  latest version can be worked out it is checked as before, so `npm install
  axios` or `chalk` still installs a release that is not listed. That version
  is checked against the offline list too (the hosted list can lag it), and a
  pinned version inside a listed numeric range is blocked offline.
  Installed with a version range or wildcard, `--pre` or a constraints file,
  such a package is asked about, never allowed on the hosted lookup's word
  alone (the hosted list can lag the offline one).
- A list more than 3 days old (or with no build time, or a build time in the
  future) warns on every install check (it still blocks everything on it);
  `stillrunning blocklist --status` exits 3 and says STALE.
- A refresh that would drop an ecosystem, or shrink one by more than half, is
  refused and the current list stays.
- The offline list is asked first, for every package, before any network
  lookup starts, so a listed package is never left to a lookup that times out;
  and the verdict cache never answers for a package on the offline list (or for
  anything while the list fails its check).
- `stillrunning blocklist --refresh --force` accepts a refresh that was
  refused for dropping an ecosystem or shrinking by more than half (an empty
  list is still refused).
- An error while asking the offline list about one package blocks that
  package (it could make the whole decision fall back to "ask"); a verified
  list that SQLite cannot read (no `sqlite3` module, a broken file) blocks
  instead of falling back to the hosted lookup. With no list at all the hosted
  lookup runs as before.
- The Claude Code hook asks a person before an agent may run
  `stillrunning blocklist --force` or `--unschedule` (in any spelling, also
  through `script -qc`, `python -m` or a variable); forced refreshes stay on
  record in the manifest's history; a manifest removed while the database or
  key is still there counts as tampering; `introduced: "0.0.0"` (any all-zero
  spelling) means every version.
- The hook's own-command rules find `blocklist … --force/--unschedule` and
  `whitelist … add/remove` wherever they stand among the command's words, so an
  option with a value (`--token x`, `--name x`) before, between or after them
  no longer hides them (the whitelist rule had the same gap before this
  release). A failed first build no longer leaves a database without a
  manifest (read as tampering), and any 0.0.0 pre-release (`0.0.0-0`,
  `0.0.0-alpha`, `0.0.0a0`) as an `introduced` version means every version.
- A `stillrunning` command whose words are only known at run time (`$X`,
  `$(…)`, backticks, `"$@"`) or that `xargs`/`parallel` feeds is asked about:
  `X=allow; stillrunning $X evil` and `… | xargs stillrunning blocklist` ran
  without asking, for every own switch (the `allow`/`remember`/uninstall rules
  had this gap before this release). This applies to the program a command
  runs (also behind `nice`, `env`, `sudo`, `xargs`, `python -m`), not to a word
  that merely says "stillrunning" (`grep -r stillrunning $DIR` does not ask).
  `stillrunning scan $PKG` now asks too.
- A refresh that fails or is interrupted (Ctrl-C) anywhere between creating
  the key and writing the manifest takes back what it added (its database, a
  key it created, its temporary manifest), so nothing is left that reads as
  tampering; the list in place before is never touched, and once the new
  manifest is in place the refresh counts as done.
- pip pins are compared in their standard form (PEP 440): `1.0.0-rc1`,
  `1.0.0.rc1` and `1.0c1` all match a listed `1.0.0rc1` (also post, dev,
  alpha/beta spellings), offline and on the hosted path.
- Known limits are listed in the README (Offline blocklist).
- A package the hook lets through without having been able to check that it
  exists on the registry now says so: `no known threat · existence on PyPI
  NOT verified`.

### Setup never ends silently unprotected (setup fuzz, 2026-11-24)

**BREAKING:** `stillrunning --setup` now exits **4** when it ends with
nothing checking installs, where it used to exit 0. That includes piped or
scripted setup (it never installs the Claude Code hook without a typed yes),
answering "n" to the hook question, and choosing "skip". It prints
"YOU ARE NOT PROTECTED" and the command to fix it. Scripts that ran
`stillrunning --setup` and expected 0 should run
`stillrunning --hook-claude-code` (or `shell-install`) afterwards, or accept
4. `--autonomous` still exits 0.

- A normal user running `--setup` on a package root installed no longer gets
  a PermissionError traceback: the config goes to
  `~/.stillrunning/stillrunning.yaml` (owner-only; an existing `token:` is
  kept). Root, virtualenv and `--user` installs keep the package-directory
  file. If neither can be written, setup says so and exits 1.
- An answer outside 1-4 at the first question is refused and asked again
  (it used to save nothing, end normally and be counted as "email"); after 5
  invalid answers setup stops with exit 2 and "Nothing was saved". Invalid
  email addresses get the same limit (they were asked for forever).
- Ctrl-D or Ctrl-C at the hook question counts as "no" instead of a
  traceback.
- `--setup` exit codes are listed in the README.

### The hook fails closed on its own failure (fuzz findings F3, F4, R1, R2)

Claude Code lets a tool call through when a PreToolUse hook crashes, exits
with anything but 0 or 2, or runs past its timeout, unless the hook is
registered with `"onFailure": "block"` (hooks reference). A long enough
command made the hook time out (a 40,000-character comment took 42-59 s
against the 30 s timeout), so a blocked install padded that way went through.

- The hook is registered with `"onFailure": "block"` (Claude Code 2.1.295 or
  later). Existing installs get it when `stillrunning --hook-claude-code`
  (or `--setup`) is run again; until then `stillrunning status` and the side
  panel say so and give that command.
- Any unhandled failure of the hook process exits 2 (blocks), with the reason
  on stderr; deeply nested input no longer crashes with exit 1.
- On Linux and macOS the hook stops itself after 25 s and blocks, even in the
  middle of a slow regular expression (Windows has no such timer; there the
  registration covers it).
- Commands over 128K characters are asked about without being read.
- `stillrunning hook` (the older registration) ends as soon as it has
  answered, like the registered script, instead of waiting for lookups that
  are still running.
- Faster where it was quadratic: long pipelines (2,000 pipes: 187 s → 0.6 s),
  one install naming thousands of packages (4,000: 18 s → 2.2 s), many
  separate install commands (`pip install a ; pip install b ; …`, 4,000:
  16 s → 2.6 s), and the dynamic-install pattern; resolved paths are
  remembered within one call. Not everything is linear: the
  self-protection check is still quadratic on a long chain of `cd`
  steps (`cd sub && pip install q && …`: 1,000 steps take about 10 s, and
  2,000 reach the 25 s limit). Main is just as slow there; the difference
  is that the hook now stops at the limit and blocks. Near the
  128K-character cap other commands can also take longer than the 25 s the
  hook allows itself; those are stopped (blocked), never let through, on
  Linux and macOS.
- A command over 4,096 characters is no longer shown in the decision log or
  the side panel: it appears as `[command of N characters, not shown]` (the
  record still names the package and the reason). Shortening it safely
  proved impossible — every shortened form tried could leave part of a
  password visible. Shorter commands are shown exactly as before.
- A command with invalid UTF-8 is logged with an escape instead of crashing
  the hook.
- Stricter on purpose: a crash or timeout now blocks even a harmless command.
  Every other decision, reason and message is unchanged.

### CI on real Windows and macOS runners; macOS claimed

- **CI matrix** (`.github/workflows/tests.yml`): `windows-latest` and
  `macos-latest` run the full suite on Python 3.12, alongside the Linux
  python:3.8/3.12/3.15-slim jobs. `actions/checkout` (v5.1.0) and
  `actions/setup-python` (v7.1.0) are pinned to full commit SHAs, with
  `persist-credentials: false`.
- **macOS:** the full suite passed on a real `macos-latest` runner
  (3409 passed, the 3 known failures deselected). Classifier
  "Operating System :: MacOS" added.
- **Windows: not claimed, not yet verified.** On a real `windows-latest`
  runner the package installs, imports and runs `--version`, but the suite
  failed. Most failures were the tests, not the product: 44 run the POSIX
  shell wrappers (unsupported on Windows), and the rest isolate state through
  `HOME`, which Windows ignores (it uses `USERPROFILE`), so they shared the
  runner's real profile. The tests now set `USERPROFILE` on Windows, skip the
  shell-wrapper and POSIX-permission tests there by name, and read files as
  UTF-8. Whatever still fails after that is triaged before any Windows claim.
- **Windows product fixes** found by that runner (the simulated tests missed
  all of them). Each has a regression test in `tests/test_windows_real.py` that
  runs on every OS; Linux behaviour and the hook's answers are unchanged.
  - **Fail-open, security:** a blocklisted install inside a script that the same
    command writes and then runs (`cat > x.sh <<EOF … EOF; ./x.sh`) was
    ALLOWED on Windows. The hook tested shell words for `os.sep` (`\` on
    Windows), so `./x.sh`, written with `/` as bash writes it, was never read.
    Shell words now count `/` everywhere and also `\` on Windows. The same
    check also had `"$VIRTUAL_ENV/bin/pip"` asking on Windows instead of
    denying.
  - **Crash:** the hook and the status line, run as bare scripts
    (`python -I -S …`) the way Claude Code runs them, never applied the
    encoding fix, so on a Windows code page `→` or `—` raised
    UnicodeEncodeError (the status line exited 1). A stream that is not UTF-8
    is now switched to UTF-8, which is what Claude Code reads (the status line's
    🛡 arrives intact). This runs on Windows only; Linux and macOS output is
    unchanged in every locale.
  - **CVE monitoring was always UNKNOWN on Windows:** the safe-folder pattern
    accepted only `/…`, so every Windows folder read "checked for another
    folder". Windows drive-letter folders are now accepted (UNC paths still
    are not); the POSIX pattern is unchanged. The status line also ignored a
    Windows folder from Claude Code.
  - `cve --schedule` on Windows now says plainly that there is no crontab.
  - **Self-protection, security:** the hook did not recognise its own files,
    its state folder or Claude Code's settings when a command named them in
    Git Bash's own spelling (`rm /d/…/claude_hook.py`), so `rm`, `sed -i`,
    `echo >>` and the like changed them without asking. A simulation of the
    old matcher missed 8,053 of 12,647 spelling × operation cases. Now
    recognised on Windows: `/d/…`, `/cygdrive/d/…`, any letter case (NTFS
    ignores it), `\\?\D:\…` and `//./D:/…`, this computer's admin shares
    (`//localhost/d$/…`), 8.3 short names, and trailing dots, spaces or
    `::$DATA`. Also covered: `cd` into one of those, `$USERPROFILE` and the
    other inherited variables, Write/Edit of those paths, Git Bash's own
    start-up files, and Windows' own tools (`cmd //c del`, PowerShell
    `Remove-Item` / `Set-Content`, encoded PowerShell, `icacls`, `attrib`,
    `robocopy`…). cmd and PowerShell commands that name a protected file ask
    even when they only read it.
  - **Fail-open, more spellings:** a written script run as `/c/…/x.sh`,
    `C:/…`, a different letter case (`X.sh` then `./x.sh`), `cmd //c x.bat`,
    or PowerShell `-File x.ps1` was allowed on Windows; it is now read.
    Still open on every OS (own fix, tests mark them): a written script run
    through `sh -c ./x.sh` or `$PWD/x.sh`.

### Python 3.15, CI, and a Python 3.8 fix

- **Python 3.15:** tested on python:3.15-slim (3.15.2). The full test suite
  fails nothing that 3.12 does not, under identical conditions. All 24 modules
  import, and `--version` works. With DeprecationWarnings from this package
  turned into errors, 3.15 raises none. The only deprecated use was two
  `re.split(..., 1)` calls in `claude_hook.py` passing `maxsplit` positionally
  (deprecated since 3.13); they now pass `maxsplit=1`, which means the same on
  every version. The "Programming Language :: Python :: 3.15" classifier is
  added. 3.13 and 3.14 have not been tested and are not claimed.
- **Python 3.8: `stillrunning cve` crashed.** `ThreadPoolExecutor.shutdown`
  has `cancel_futures` only from 3.9, so the call raised TypeError. On 3.8 the
  pending futures are now cancelled and the pool shut down; 3.9+ is unchanged.
  Found by running the test suite on 3.8 for the first time.
- **CI** (`.github/workflows/tests.yml`): the full suite on every push to main
  and on pull requests, in the official python:3.8-slim, 3.12-slim and
  3.15-slim images. The three tests that already fail on main are
  deselected, so a red run means something new broke. Two test files
  (`test_v230_fixes.py`, `test_v240_fixes.py`) opened the package at this
  server's absolute path; they now find it next to the tests.

### Windows and Python 3.8/3.9 fixes

- **Python 3.8 and 3.9:** the CLI failed to import (`TypeError: unsupported
  operand type(s) for |`) because annotations written as `X | None` and
  `list[...]` were evaluated at import. Eight modules now use
  `from __future__ import annotations`. Tested on python:3.8-slim and
  python:3.9-slim: all 24 modules import, and `--version` and `--help` work.
- **Windows console output:** when output is piped or redirected (CI,
  PowerShell capture, `> file`), Windows encodes it with the ANSI code page,
  which has no ✓ ✗ ⚠ 🚨 ✅. A BLOCKED result crashed with UnicodeEncodeError
  (exit 1 instead of 10), and the install interceptor failed for every package.
  Each entry point now writes those symbols as ASCII words (`OK`, `X`, `!`,
  `!!`) on a stream that is not UTF-8. Any other character it cannot encode is
  written as a code-point tag such as `<U+0435>`. Nothing is transliterated, so
  a look-alike package name like Cyrillic "rеquests" stays visibly different
  from "requests". An undecodable filename byte is written as `<0xFF>`. UTF-8
  streams are untouched, and nothing changes at import.
- **Windows verdict cache:** Windows reports writable files as 0o666 (read-only
  ones as 0o444) and every folder as 0o777, so the cache judged its own database "writable by another
  account", moved it aside and warned on every lookup; nothing was ever
  cached. The permission-bit checks are now POSIX-only. On Windows, access is
  by ACL, and the user profile that holds `~/.stillrunning` is private by
  default. Trade-off: on Windows the cache file has no owner or permission
  check (only the regular-file and hard-link checks), so another account able
  to write into the profile could plant a verdict. That gains at most this: a
  hash-pinned release whose live check could not complete turns from "ask"
  into "allow". A live "blocked", the local blocklist and a held CVE still
  win, and an account that can write the profile can already edit
  `~/.claude/settings.json`.
- **Windows Claude Code hook:** stopped warning "readable by other accounts …
  now owner-only" on every tool call. chmod cannot change those bits on
  Windows, so the warning repeated forever.
- **Import-time checks on Python 3.8/3.9:** they used
  `importlib.metadata.packages_distributions`, added in Python 3.10, so on
  3.8/3.9 they reported "import checks skipped" and checked nothing. When that
  function is missing, they now use the standard library's own algorithm
  (Python 3.11's; 3.10 read only `top_level.txt`) on top of `distributions()`
  (`top_level.txt`, otherwise the installed `.py` files), built once per
  process (a package installed later in the same process is seen after a
  restart). Verified on python:3.8-slim and 3.9-slim: `pip` and `setuptools`
  map to their distributions and stdlib modules map to none. Python 3.10+
  still calls the native function.
- The "cannot map imports to distributions" warning now names the exception
  type (all Python versions).
- Still not tested on a real Windows machine; Windows behaviour is simulated in
  `tests/test_windows_py38_compat.py`.

## 2.14.3 — November 19, 2026

New: the side panel; no change to what is checked or blocked.

- **Side panel for Claude Code.** The stillrunning shield panel (what the hook
  checked, blocked and held, with plain-English reasons; hook state; CVEs in
  installed packages) now ships inside the pip package.
  `stillrunning --hook-claude-code`, and the hook offer in `--setup`, register
  it in `~/.claude/settings.json` (`extraKnownMarketplaces` +
  `enabledPlugins`, pointing at the installed package folder). Restart Claude
  Code and type `/shield`. `--no-panel` skips it. A panel you switched off
  stays off, and a marketplace of the same name that stillrunning did not add
  is left alone. `--uninstall-hook-claude-code` removes it again.

## 2.14.2 — November 19, 2026

Privacy fix; no change to what is checked or blocked.

- The usage ping sent with each CLI command carried its first two words, so
  a package name (`scan requests`) or a file path (`scan-manifest
  /path/to/requirements.txt`) reached stillrunning.io. It now carries only
  the command or flag name (`scan`, `scan-manifest`, `--setup`); any other
  word is sent as `other`. Option values, package names and paths are never
  sent. This is what the Privacy section already promised.
- Fast commands (`--help`) give the ping up to 2 seconds to go out at exit
  instead of dropping it mid-request.
- Removed unused code that would have sent package names if it had ever
  been called.

## 2.14.1 — November 19, 2026

Telemetry fixes only; no change to what is checked or blocked.

- Setup-wizard step pings now use the same anonymous id as heartbeats. Before,
  the id included the process id, so it changed on every run.
- Pings report the real client version (they said 2.2.2).
- Pings that were still sending when the command finished are given up to 3
  seconds to go out instead of being dropped.
- New: once per machine, the first `stillrunning scan` / `scan-manifest`
  sends whether it ran or could not check (its exit code), never the package
  name. A marker at `~/.stillrunning/first_scan_sent` stops it repeating.
- `STILLRUNNING_NO_TELEMETRY=1` now also turns off the setup and first-scan
  pings (as does `STILLRUNNING_NO_FUNNEL=1`).
- Fix: `stillrunning --setup` (or a first run with no config) with no input
  — CI, a pipe, a sandbox — crashed with a Python traceback. It now says
  setup needs a terminal, points to `--autonomous`, and exits with code 2
  (Ctrl-C exits 130).

## 2.14.0 — November 18, 2026

Fixes the 2.13.7 Claude Code hook, which did not stop blocklisted packages (it
acted only on a DANGEROUS answer; the server answers BLOCKED). Upgrade with
`pip install -U stillrunning`.

Contains everything below down to and including "security audit release":
the local verdict cache, CVE monitoring, and the Claude Code hook.

### Docs (2026-11-17)
- README reorganised for a first-time user: what it does, a 2-minute start
  with example output, what you'll see, when it asks you, CVEs, turning
  things off, privacy, troubleshooting; reference material below. Privacy now
  also lists the setup wizard's step pings (`STILLRUNNING_NO_FUNNEL=1`); the
  `--no-telemetry` flag it used to mention does not exist.

### Local verdict cache (Claude Code hook)

- New `stillrunning/verdict_cache.py`: `~/.stillrunning/verdicts.db` (SQLite,
  0600 in a 0700 folder). An exact release that passed both checks (blocklist
  lookup completed with no match, vulnerability check completed with nothing
  held) is stored by ecosystem + name + exact version + artifact hash.
- When the same release + hash comes up and the live check cannot complete
  (offline, quota, timeout, server error, OSV.dev unreachable), the hook answers
  "✓ … — no known threat (verified on this machine 3h ago; not re-checked now)"
  instead of asking. Counted as no known threat; the evidence says it came from
  the cache.
- The hash comes only from `--hash=` pins on exact requirements-file lines, and
  only for `pip install` (`python -m pip install`). uv installs never carry a
  cache hash: uv can switch hash checking off from a config file the hook does
  not read (an earlier draft allowed `uv pip install` / `uv pip sync`).
  No hash → the cache does not apply. Comments are cut at `#` after any
  whitespace, like pip.
- A `verdicts.db` or folder another account could write, or an unreadable
  `known_bad_packages.json`, means no cached answer. Nothing is stored from a
  command that ends in deny.
- Fix (pre-existing): a package whose blocklist lookup and vulnerability check
  both failed counted twice in "couldn't check"; it now counts once.
- Never covers: a blocklist hit (local list or live; a live hit deletes the
  record), a critical / unknown-severity vulnerability (live or `cve_state.json`),
  a registry "no such package", an unrecognised server answer (new `answered`
  marker on the lookup outcome), ranges / tags / `--pre` / constraints, another
  version or hash, or any command with another hold.
- 24 h expiry (`STILLRUNNING_CACHE_TTL_HOURS`, capped at 7 days);
  `STILLRUNNING_CACHE=0` turns it off; a corrupt database reads as empty.
  No network calls. `stillrunning shield` shows the number of unexpired verdicts
  (text only; the `--json` keys are unchanged).

### Known vulnerabilities (CVE monitoring)

Shortens the time to patch known bugs in packages already in use. Not a malware
check, not attack prevention.
- `stillrunning cve` (`--json`, `--refresh [--cwd]`, `--schedule`, `--unschedule`):
  inventory of this interpreter, the project's virtualenvs and its manifests and
  lockfiles; OSV.dev `querybatch` + `vulns/{id}` (GHSA severity, else CVSS v3
  computed from the vector); CLEAR / AFFECTED / UNKNOWN with green only on proof;
  state in `~/.stillrunning/cve_state.json`, details cached by id+modified.
- Claude Code hook: an install whose resolved version has a known CRITICAL
  vulnerability is held for approval with the id, severity and fixed version;
  a vulnerability check that cannot finish holds too. Runs alongside the
  blocklist lookup within the same deadline. `STILLRUNNING_CVE_CHECK=0` turns it off.
- Status line: one CVE segment (after the first refresh); counts drop before
  either freshness. `stillrunning shield`: one CVE line.
- `panel.installed_packages` reports places it could not list; manifest rows
  count local / URL / git entries; `find_manifests(root, report)` says when its
  limits left a dependency file unread.
- Review round 1 (no false green): the state is kept per project folder and
  every reader answers for its own folder; future-dated feed times, an empty
  inventory, a cut-short search, packages OSV cannot be asked about and a
  summary that disagrees with the details all read UNKNOWN; OSV `MAL-` records
  show as AFFECTED ("malicious"); unknown-severity vulnerabilities and
  critical-in-range installs hold and cannot be waved through.

### Security audit release

Everything below under "unreleased" shipped together in 2.14.0. Six rounds of independent
adversarial review; the sixth approved with conditions, recorded under
"Known limitations" in README.md.

### Fourth to sixth review fixes
- A misread flag fails toward blocking: words the parser did not read as a
  package (an option's value, a word after an unknown subcommand, the word after
  an unknown option of a runner) are looked up on the blocklist; a hit blocks.
- Per-tool flag tables (pnpm `-w` is a switch, npm `-w` takes a value; uv's own
  options for `uv pip`, `uv add`, `uvx`, `uv tool run`, pipx); clustered pip
  flags (`-Ur file`); notebook `!pip` / `%pip`; shells with options reading
  stdin (`bash -euo pipefail <<EOF`); plugin and tool installs.
- Self-protection: shell startup files that set `STILLRUNNING_*`, reinstalling,
  downgrading or uninstalling stillrunning, Claude Code managed settings.
- Redaction: tokens fed on stdin (`--with-token <<< X`, `| … --password-stdin`)
  and several CLI secret flags.
- README: "What it catches", "The principle: fail closed", "Known limitations",
  "Run, restart, remove"; header and privacy text describe what it does.

### Third review fixes (unreleased)
- "Don't ask again for this exact command" is switched off (`REMEMBER_ENABLED = False`);
  `stillrunning remember` refuses. The code and its tests stay for a redesign.
- Hook: a wrapper flag takes a value only for its own wrapper (`sudo -n pip …` is read);
  requirements files resolve against the folder the install runs in (`cd app && …`), and
  a folder decided at run time asks; shells fed by stdin, process substitution, variables
  holding a command, `trap`, `env -S`, scripts written and run in one command, ANSI-C
  strings and decode-then-run pipes are read or put to the user.
- Self-protection: every spelling of stillrunning's own CLI and modules, program text that
  writes to the protected places, links into them, `find … -delete` and `git clean` above
  them. `git add/diff/log` on a settings file and `cd $VAR && …` no longer ask.
- Stored command text: credentials in `-u`, headers, quoted values and known token shapes
  are masked; the state folder is owner-only.

### Session 135 security audit fixes (in 2.14.0)

### Fixed
- **Claude Code hook never ran, and would not have blocked if it had.** It was
  written to `~/.claude/hooks.json`, a file Claude Code does not read, and it
  only acted on the verdict `DANGEROUS`, which the API does not send (it sends
  `BLOCKED`). It is now a `PreToolUse` hook in `~/.claude/settings.json`; every
  verdict maps explicitly (BLOCKED / DANGEROUS / SUSPICIOUS deny, a completed
  lookup with no match shows "no known threat", anything else asks).
- **Hook parser.** Finds every install in a compound command, flags anywhere,
  `python -m pip`, uv, pipx, poetry, pdm, yarn, pnpm, bun, npx / dlx, `-r`
  files, scoped npm names. URL / VCS installs, custom indexes and anything it
  cannot parse are put to the user.
- **Wrappers** no longer `exec /usr/bin/pip`: the real tool is resolved at run
  time (active venv first, then PATH, then `python -m pip`), never the wrapper
  itself. `install` is detected after global flags. The `python` shell
  function no longer forces `/usr/bin/python3` inside a venv.
- **Unverified needs approval by default** (hook: ask; wrappers: prompt, or
  stop when nobody is at the keyboard), including "not on the registry".
  Opt out with `STILLRUNNING_ALLOW_UNVERIFIED=1`.
- **Honest status.** `status`, `--doctor` and the end of `--setup` report each
  layer as ON / OFF / NOT VERIFIED with the reason and next step; `--doctor`
  exits 1 when nothing checks installs. One token precedence for every
  command. The per-command "Import hook installed" line is gone. `status`
  looked for `stillrunning.pth`; the file is `stillrunning-hook.pth`.

- **End-to-end pass (new-user walkthrough).**
  - `npm install axios` / `pip install litellm` were blocked outright: the
    blocklist entry names a few hijacked releases and the command named no
    version. The hook, `scan` and the wrappers now look up the version the
    install would fetch and check exactly that; if it cannot be worked out,
    the user is asked.
  - `scan`, `scan-manifest` and the wrappers run on the same engine as the
    Claude Code hook: when the free allowance is used up they fall back to
    the unmetered blocklist route instead of stopping every install, and
    `scan name==version` / `name@version` checks that version.
  - `scan-manifest` read only files literally named `requirements.txt`, so
    `pip install -r anything-else.txt` passed with "No packages found". Any
    `.txt` / `.in` file is read as a requirements file; `poetry.lock`,
    `uv.lock` and `npm-shrinkwrap.json` are read; lockfile pins are checked
    as pinned; an unreadable kind of file is an error (exit 2), not a pass.
    It no longer prints "CLEAN". The `pyproject.toml` crash with `tomli`
    installed is fixed.
  - Terminal wrappers: activating a virtual environment after the shell
    started put the venv's `pip` first and skipped the check. `pip`, `pip3`
    and `npm` are now shell functions as well. The rc-file line is plain
    POSIX and does nothing in `sh`/`dash` or when `~/.stillrunning` is gone.
  - Uninstall: `--uninstall-hook-claude-code` puts `settings.json` back byte
    for byte when nothing else changed it; `shell-uninstall` does the same
    for rc files and removes every file `shell-install` wrote. The
    `--install-hook` `.pth` line no longer breaks Python start-up after
    `pip uninstall stillrunning`.
  - `STILLRUNNING_API_BASE` points the client at another server.
  - Windows / macOS: `shell-install` (Windows) and the process monitor
    (anything but Linux) say "not supported yet" and exit.
  - README: the MCP config snippet used a file and a `type` Claude Code does
    not read.

- **Independent review fixes.**
  - Version-specific blocklist entries: only an exact pin (`==X`, `===X`,
    `@X`, `@vX`) is looked up as that version. A range, wildcard, dist-tag,
    `--pre` or a constraints file used to be answered for "the latest
    version" and could pass while the listed version installed; these now ask
    and name the listed versions. Another spelling of a listed version
    (`==1.14.1.0`) is blocked. The same package at two versions in one
    command is two lookups.
  - Hook parser: backslash-newline, quoted or escaped program names
    (`p\ip`, `p""ip`), `python -W x -m pip`, `npm update|up|link|install-test`,
    `yarn up|upgrade`, `pnpm up|update`, `corepack <pm>`, `pipenv install`,
    `easy_install`, `eval`, and `yarn workspace <name> add` are parsed. A
    program only known at run time (`$PIP install x`, `$(…) install x`) and
    an install from a local file that is not there are put to the user.
    Redirections (`2>&1`, `>file`) are no longer read as package names.
  - Self-protection: any command naming `~/.stillrunning`, a Claude Code
    settings file, the hook script or a `STILLRUNNING_*` variable asks, and
    the hook now also covers Write / Edit / MultiEdit / NotebookEdit aimed at
    those files (re-run `stillrunning --hook-claude-code`). A local override
    no longer silently allows a package that is on the blocklist.
  - `STILLRUNNING_API_BASE` is accepted for this machine only, and the
    account token is not sent to it.
  - Wrappers: `-rfile`, `-r=file`, `-ihttps://…`, `-f…`, `--index=` are read;
    `npm update|up|link` are checked; `python -W x -m pip` reaches the
    wrapper; `STILLRUNNING_ALLOW_UNVERIFIED=1` never applies to a listed
    package (new exit code 14: "needs a person").

### Added
- Plain-language explanations and per-check evidence on every hook decision,
  a local decisions log, `stillrunning shield` (`--json`), an optional status
  line, `--version`, `--diagnose`, `--reconfigure`.

## 2.13.7 — October 21, 2026 (Session 129)

**Import-time protection works again; `scan`, the import hook and the wrappers no longer report CLEAN on a failure**

### Fixed
- **Import hook never scanned.** It POSTed to `/api/check-package` (GET-only →
  HTTP 405 on every call). It now sends a GET and acts on **BLOCKED**, the
  verdict the API returns (it previously only acted on DANGEROUS). A missing
  verdict is UNKNOWN, never CLEAN.
- **Import hook no longer spends the free tier.** Remote import-time checks run
  only with an API token (`STILLRUNNING_TOKEN` or `token:` in
  `~/.stillrunning/stillrunning.yaml`); without one it warns once. It looks up
  the installed *distribution* (not every module name) and remembers each
  answered result for 24 h per machine (a 429/503 is retried next time).
  Mapping imports to distributions needs Python 3.10+; on 3.8/3.9 import-time
  checks are skipped with a one-time warning (install-time checks still run).
- **`stillrunning scan` exit codes are honest.** The threat API is consulted
  before the registry (a delisted malicious package is BLOCKED, not "not
  found"). API errors are no longer reported as CLEAN:
  `0` not on the blocklist (not a clean bill of health) · `10` BLOCKED ·
  `11` SUSPICIOUS · `12` daily quota exhausted · `1` could not check
  (offline / server error / stale data) · `3` not on the registry · `2` timeout.
- **pip / npm / conda wrappers** block only on a real verdict (10, 11). If the
  check could not run they print a loud *"NOT checked — installing anyway"*;
  set `STILLRUNNING_FAIL_CLOSED=1` to stop the install instead.
- `intercept.py`: a missing verdict is UNKNOWN, never CLEAN.

### Known issue
- `scan-manifest` (AI scan via `/api/scan`) can still print CLEAN when the AI
  scan returns nothing (no token / quota / tier). Fix planned for 2.13.8.

### Upgrade note
Shell wrappers are installed files: after `pip install -U stillrunning`, run
`stillrunning shell-install` once to update them.

## Unreleased — August 18, 2026 (Session 122)

**GitHub Action + CI hardening**

### Added
- **GitHub Action** (`johhnyg/stillrunning@v1`) — CI/CD supply chain scanning via
  `action.yml` + `scan.py`. Scans `requirements.txt` (default) and/or
  `package.json`/`package-lock.json`, fails the build on DANGEROUS packages
  (optionally SUSPICIOUS with `fail-on-suspicious: true`). Outputs: `status`,
  `dangerous-count`, `suspicious-count`, `report`. Optional `token` input enables
  AI scanning of unknown packages.

  ```yaml
  - uses: johhnyg/stillrunning@v1
    with:
      requirements: requirements.txt
  ```

- **ASCII security block banner** — `scan.py` renders a bold red shield banner
  ("SUPPLY-CHAIN SECURITY BLOCK") when malicious packages are detected, so blocks
  are unmissable in CI logs.

### Fixed
- **pip/npm shim subcommand handling** — the wrappers hardcoded `install`
  regardless of the command actually run, breaking `pip download` entirely and
  rewriting `npm i` / `npm add` semantics. Both shims now capture the original
  subcommand and pass it through.

## v2.13.3 — June 12, 2026

**Telemetry heartbeats actually reach the server**

### Fixed
- **Anonymous heartbeats were silently 403'd.** stillrunning.io sits behind
  Cloudflare, which blocks the default `Python-urllib/x.y` User-Agent. The
  heartbeat client sent no User-Agent, so every `install`/`active`/`intercept`/`cli`
  heartbeat was rejected and the exception swallowed — no agent telemetry had ever
  landed. All three request sites (`_send_heartbeat`, `send_intercept_event`,
  `send_cli_ping`) now send `User-Agent: stillrunning/{version}`. Verified: a clean
  container install now lands a heartbeat (HTTP 200).

## v2.13.2 — June 11, 2026

**npm scanning actually works**

### Fixed
- **`stillrunning scan --npm`** — the npm wrapper called `scan <pkg> --npm`, but the
  flag never existed; combined with `set -e` the wrapper failed closed and blocked
  EVERY npm install. scan now checks the npm registry (scoped `@org/pkg` names
  supported), the npm section of the threat feed, and passes `ecosystem=npm` to the
  check-package API.
- **Hardcoded blocklist normalization** — dash-named entries (`pino-debugger`,
  `dev-log-core`, ...) could never match because only the input was normalized to
  underscores. Both sides normalize now.
- **`axios` delegated to the threat feed** — covered by MAL-2026-2307 (malicious
  0.30.4/1.14.1) with proper withdrawal lifecycle instead of a permanent hardcode.

### Added
- **`@anthropic-ai/*` trusted-scope skip** in the npm wrapper template.

---


## v2.11.0 — May 2, 2026

**Single source of truth + bypass route coverage**

### Added
- **features.json** — version, tiers, verify_checks, last_session in one file
- **`/api/version`** — serves features.json with 5-minute cache
- **scripts/sync-version.py** — syncs version to pyproject.toml and cli.py
- **scripts/regen-readme.py** — regenerates tier table from features.json
- **Venv auto-enable** — shell-install now installs sitecustomize.py automatically
- **Conda hook** — conda_hook.sh wraps `conda install/create`

### Security
- **Closes CVE-2026-31431 gaps #1 (venv) and #5 (conda)**

---

## v2.10.0 — May 2, 2026

**CVE-2026-31431 gap fixes — shell auto-activation**

### Added
- **`stillrunning shell-install`** — auto-activate hooks on shell init (bash/zsh/profile)
- **`stillrunning shell-uninstall`** — remove shell hooks
- **`stillrunning status`** — show status of all protection layers
- **Wrapper scripts** — `~/.stillrunning/bin/pip`, `pip3`, `npm` intercept installs
- **Idempotent rc updates** — reinstall won't duplicate lines in shell config

### Security
- **Closes CVE-2026-31431 audit gap #4** — hooks now activate without manual `source activate.sh`

---

## v2.9.0 — April 25, 2026

**Customer experience polish + CLI standardization**

### Added
- **pricing.py** — single source of truth for all tier pricing
- **Welcome email idempotency** — Stripe webhook retries no longer send duplicate emails
- **Telegram wizard** — `/dash/{subdomain}/telegram` for in-dashboard bot setup
- **Resend-welcome endpoint** — admin can resend welcome emails via API

### Changed
- All pricing references now use `pricing.py` (landing, /pricing, emails)
- Welcome emails now use `alerts@stillrunning.io` From header

### Breaking
- **Exit codes standardized** across all CLI tools:
  - 0 = CLEAN, 1 = ERROR, 2 = USAGE
  - 10 = BLOCKED, 11 = SUSPICIOUS, 12 = RATE_LIMITED, 13 = WITHDRAWN

---

## v2.8.0 — April 25, 2026

**Async scan endpoint + version-aware AI cache**

### Added
- **Async scan endpoint** — `POST /api/scan/async` returns immediately with job_id, poll `/api/scan/status/{job_id}` for results
- **Version-aware AI cache** — cache key is now `(package_name, version)` instead of just `package_name`
- **cache_clear_older_than(days)** — maintenance function to purge old cache entries
- **resolve_latest_version()** — resolves "latest" to actual version from PyPI/npm

### Changed
- Async jobs auto-expire after 1 hour (TTL)
- Legacy cache entries marked `version="unknown"` for re-review on next check

### Breaking
- **Exit codes standardized** across the stillrunning family:
  - 0 = CLEAN (operation succeeded, no threats)
  - 1 = Generic error (network failure, internal bug)
  - 2 = Usage error (bad arguments, missing file)
  - 10 = BLOCKED (confirmed malicious package)
  - 11 = SUSPICIOUS (AI flagged, not confirmed)
  - 12 = RATE_LIMITED (free tier exhausted)
- CI pipelines that assumed exit 1 = block must update to check for exit 10

---

## v2.7.0 — April 25, 2026

**Source tracking + curated blocklist**

### Added
- **Source tracking** — each blocked package shows advisory source (OSV, GitHub, NVD, etc.)
- **Advisory ID linking** — direct links to original security advisories
- **Curated blocklist** — 200,000+ packages from 8 threat intelligence sources

### Changed
- `/security-advisories` page shows source metadata badges
- Blocklist entries include `source` and `advisory_id` fields

---

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
- **Interactive approvals** — Telegram allow/deny with one tap (not available today)
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
- Enterprise: + unlimited scans, SIEM, SSO, compliance (tier flags only; never built)

## v1.5.0 — April 2026

**Security layer — supply chain protection**

- `stillrunning guard` — always-on security daemon with auto-learning whitelist (214 processes)
- `stillrunning scan` — static analysis: AST parser, entropy detection, pkl inspector
- npm/pip intercept — blocks poisoned packages before install (hash check + static scan)
- Advisor upgrade — Sonnet executor + Opus advisor pattern for AI operations
- Chrome extension scaffold — green/red status dot in browser
- `/scan` route — customer file upload threat scanner (free tier 10/day)
- North Korea supply chain attack response (the "1,700+ blocked" figure is withdrawn: it is not backed by the blocklist data)

## v1.4.0 — April 2026

- Email alerts — no Telegram required (not available today: mail is off on the server)
- Two-way email — reply to alerts, AI answers from live data (not available today)
- Monday weekly report — automatic every week (not available today)
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
- Telegram two-way control (not available today)
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
