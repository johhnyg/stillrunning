#!/usr/bin/env python3
"""Claude Code integration: PreToolUse hook, command parser, plain-language
explanations, settings.json installer.

Stdlib only. The hook runs THIS FILE BY PATH (`python -I -S claude_hook.py`),
never through the `stillrunning` package, so a command that installs nothing
costs one interpreter start and no network call.
"""
import json
import os
import re
import sys
import time

def _load_apibase():
    """This file also runs as a bare script (python -I -S claude_hook.py), where
    the package is not importable: load the sibling module by path then."""
    try:
        from stillrunning import apibase
        return apibase
    except ImportError:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apibase.py")
        spec = importlib.util.spec_from_file_location("stillrunning_apibase", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


_apibase = _load_apibase()
api_base, api_url = _apibase.api_base, _apibase.api_url
API_URL = api_url("/api/check-package")
USER_AGENT = "stillrunning-claude-hook/2"
CHECK_DEADLINE_S = 12.0
HOOK_TIMEOUT_S = 30
# Claude Code lets a tool call through when a PreToolUse hook fails or times
# out, unless the hook is registered with "onFailure": "block" (v2.1.295+;
# hooks reference, "Block the action when a hook fails"). Fuzz finding F4.
HOOK_ON_FAILURE = "block"
# The hook answers by itself before Claude Code's timeout: past this, it blocks.
HOOK_DEADLINE_S = HOOK_TIMEOUT_S - 5
MAX_REQ_FILE_PACKAGES = 40
SHIELD = "\U0001F6E1"

_INSTALLER_HINT = re.compile(
    r"(?<![\w.-])(pip[\d.]*|pipx|pipenv|easy_install|uv|uvx|poetry|pdm|npm|npx|pnpm|pnpx|yarn"
    r"|bun|bunx|conda|mamba|micromamba|pixi|cargo|gem|go)(?![\w-])"
    r"|-m\s*pip", re.I)
# `curl … | sh`, `bash <(curl …)`, `sh -c "$(curl …)"`: a script straight from a web address.
_REMOTE_SCRIPT_HINT = re.compile(
    r"(?<![\w.-])(?:curl|wget)(?![\w-])[^\n]*\|\s*(?:sudo\s+)?(?:\S*/)?(?:(?:ba|z|da|k|a)?sh|fish|python[\d.]*|perl|ruby|node)\b"
    r"|[<$]\(\s*(?:curl|wget)(?![\w-])|`\s*(?:curl|wget)(?![\w-])")
_PROCESS_SUBST_SCRIPT = re.compile(
    r"(?:(?<![\w.-])(?:(?:ba|z|da|k|a)?sh|fish|source)|(?:^|[;&|\s])\.)\s+(?:-\S+\s+)*<\(\s*(?:curl|wget)(?![\w-])")
# Text that is decoded or downloaded and then run: it cannot be read here.
_DECODERS = {"base64", "base32", "xxd", "uudecode", "zcat", "gzcat", "bzcat", "xzcat", "gunzip",
             "openssl", "rev"}
_HIDDEN_SCRIPT_HINT = re.compile(
    r"(?<![\w.-])(?:base64|base32|xxd|uudecode|zcat|gzcat|bzcat|xzcat|gunzip|openssl|curl|wget)"
    r"(?![\w-])")
# Files and variables that decide WHERE packages are downloaded from.
_INDEX_CONFIG_HINT = re.compile(
    r"\.npmrc|pip\.conf|pip\.ini|\.pypirc|uv\.toml|\.yarnrc|bunfig\.toml|\.condarc"
    r"|poetry\.toml|pdm\.toml"
    r"|(?<![A-Za-z0-9_])(?:PIP|UV|NPM_CONFIG|npm_config|YARN|PIPENV|BUN_CONFIG|COREPACK|POETRY)"
    r"_[A-Za-z0-9_]+=")
# A command word that is only known at run time ($P, $(…), `…`) followed by an
# install verb: the program cannot be read from the text, so it is put to the user.
_INSTALL_VERBS = {"install", "add", "i", "download", "wheel", "update", "up", "upgrade"}
_DYNAMIC_INSTALL = re.compile(
    r"(?:^|[;&|(\n{]|\b(?:sudo|doas|env|exec|command|eval|then|do|else|time|nohup|xargs)\s)\s*"
    r"(?:[A-Za-z_]\w*=\S*\s+)*"
    r"[\"']?(?:\$\([^)]*\)|`[^`]*`|\$\{?\w+\}?)\S*\s+(?:-\S+\s+)*"
    r"(?:install|add|i|download|wheel|update|up|upgrade)\b")
# Commands and names that change stillrunning's own protection whatever file
# they touch. The state directory is matched broadly on purpose: reading it is
# rare (it holds the account token) and a write can be spelled in many ways.
_FILE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
HOOK_MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit"
_SETTINGS_NAMES = ("settings.json", "settings.local.json")
# Organisation-wide Claude Code settings: the same switch, one level up.
_MANAGED_SETTINGS = "managed-settings.json"
# Files a shell reads at start-up. A STILLRUNNING_* switch written into one of
# them takes effect in every later shell without any command naming it.
_RC_NAMES = {".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile", ".zshrc",
             ".zshenv", ".zprofile", ".zlogin", ".kshrc", ".envrc", "config.fish"}
_RC_SYSTEM = ("/etc/profile", "/etc/environment", "/etc/bash.bashrc", "/etc/zshenv",
              "/etc/zsh/zshenv", "/etc/zsh/zshrc", "/etc/zprofile")


def _is_rc_file(path, cwd=None):
    """Is this a shell start-up file (`~/.bashrc`, `/etc/profile.d/x.sh`, …)?"""
    if not isinstance(path, str) or not path.strip():
        return False
    full = os.path.expanduser(path.strip())
    full = _win_spelling(full) or full
    if not os.path.isabs(full):
        full = os.path.join(cwd or os.getcwd(), full)
    full = os.path.normpath(full)
    if os.name == "nt":
        comps = _path_comps(full) or [""]       # ~/.BASHRC is ~/.bashrc there
        # Git Bash's /etc (its install folder's etc\): profile, bash.bashrc, profile.d\*
        return (comps[-1] in _RC_NAMES or "profile.d" in comps[:-1]
                or (len(comps) > 1 and comps[-2] == "etc"
                    and comps[-1] in {os.path.basename(f) for f in _RC_SYSTEM}))
    return (os.path.basename(full) in _RC_NAMES or full in _RC_SYSTEM
            or full.startswith("/etc/profile.d/"))


def rc_switch_write(path, text, cwd=None):
    """Would this write put a STILLRUNNING_* switch into a shell start-up file?"""
    return "STILLRUNNING_" in str(text or "") and _is_rc_file(path, cwd)
# Programs that only read the files they are given. A protected settings file
# named by anything else is treated as a change.
_READ_ONLY = {"cat", "grep", "egrep", "fgrep", "rg", "ag", "ls", "ll", "la", "head", "tail",
              "less", "more", "wc", "stat", "file", "jq", "yq", "bat", "diff", "cmp", "test", "[",
              "[[", "md5sum", "sha1sum", "sha256sum", "shasum", "readlink", "realpath", "du",
              "cd", "pushd", "popd", "echo", "printf", "which", "basename", "dirname", "tree",
              "nl", "sort", "uniq", "cut", "strings", "xxd", "hexdump", "od", "tac", "column",
              "find"}
_DESTRUCTIVE = {"rm", "rmdir", "mv", "shred", "unlink", "chmod", "chown", "chgrp", "chattr",
                "truncate"}
_FILE_WRITERS = _DESTRUCTIVE | {"cp", "tee", "sed", "perl", "dd", "ln", "install", "patch",
                                "touch", "ed", "ex", "sponge", "rsync", "scp", "ruby"}
_LAST_ARG_WRITERS = {"cp", "scp", "rsync", "install", "ln"}


# Options of the read-only programs that take the next word as their value
_UNIQ_VALUE = {"-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"}
_XXD_VALUE = {"-c", "-g", "-l", "-s", "-o", "-n", "-cols", "-len", "-seek", "-groupsize",
              "-octets", "-name", "-C"}
_TREE_VALUE = set("LPIHT")      # tree's options with a value; -o is the output file
_EXEC_END = {";", "\\;", "+"}


def _operands(args, takes_value):
    """The operands of a command, skipping options and the values they take."""
    out, at = [], 0
    while at < len(args):
        arg = args[at]
        if arg == "--":
            out += args[at + 1:]
            break
        if arg.startswith("-") and arg != "-":
            if arg in takes_value:
                at += 1                     # `uniq -f 1 IN OUT`: 1 is not IN
        else:
            out.append(arg)
        at += 1
    return out


def _read_only_outputs(program, args):
    """Files a program on the read-only list writes anyway, given an output
    option or operand (`sort -o F`, `uniq IN OUT`, `xxd -r IN OUT`, `tree -o F`,
    `find -fprint F`), and whether it edits or deletes the files it is given
    (`yq -i`, `find -delete`, `find -exec` with a program that writes).
    → (written files, edits its operands)."""
    written, edits = [], False
    if program == "sort":
        at = 0
        while at < len(args):
            arg = args[at]
            if arg == "--":
                break
            long_ = re.match(r"^--o(u(t(p(u(t)?)?)?)?)?(=(.*))?$", arg, re.S)
            short = re.match(r"^-([bcCdfghiMmnRrsuVz]*)o(.*)$", arg, re.S)
            if long_ or short:
                value = (long_.group(7) if long_ else short.group(2)) or ""
                if long_ and long_.group(6) is None or short and not value:
                    value = args[at + 1] if at + 1 < len(args) else ""
                    at += 1
                written.append(value)
            elif re.match(r"^-[A-Za-z]*[ktST]$", arg):
                at += 1                     # -k 2, -t o, -S 1G, -T dir: the value is not -o
            at += 1
    elif program == "tree":
        at = 0
        while at < len(args):
            arg = args[at]
            if re.match(r"^-[A-Za-z]+$", arg) and not arg.startswith("--"):
                # getopt-style cluster: each letter that takes a value takes the next
                # word in turn (`tree -ao F`, `tree -oJ F`, `tree -Lo 2 F`)
                taken = at
                for letter in arg[1:]:
                    if letter == "o" or letter in _TREE_VALUE:
                        taken += 1
                        if letter == "o" and taken < len(args):
                            written.append(args[taken])
                at = taken
            elif arg.startswith("-o") and len(arg) > 2:
                written.append(arg[2:])
            at += 1
    elif program in ("uniq", "xxd"):
        operands = _operands(args, _UNIQ_VALUE if program == "uniq" else _XXD_VALUE)
        written += operands[1:2]            # uniq [IN [OUT]], xxd [IN [OUT]]
    elif program == "yq":
        for arg in args:
            if arg in ("--inplace", "--in-place") or arg.startswith(("--inplace=", "--in-place=")):
                edits = True
            elif re.match(r"^-[A-Za-z]+$", arg):
                before = arg[1:].split("i", 1)[0]
                # `-i`, `-Pi`, but not `-oini` (-o takes "ini") or `-pi` (-p takes "i")
                if "i" in arg[1:] and not set(before) & set("opI"):
                    edits = True
    elif program == "find":
        at = 0
        while at < len(args):
            arg = args[at]
            if arg in ("-fprint", "-fprint0", "-fprintf", "-fls") and at + 1 < len(args):
                written.append(args[at + 1])
            elif arg == "-delete":
                edits = True
            elif arg in ("-exec", "-execdir", "-ok", "-okdir"):
                end = at + 1
                while end < len(args) and args[end] not in _EXEC_END:
                    end += 1
                sub = args[at + 1:end]
                ran = _prog_name(sub[0]) if sub else ""
                if ran not in _READ_ONLY:
                    edits = True
                else:
                    # a read-only program that writes (`-exec sort -o F {} \;`, `-exec yq -i {} +`)
                    out, sub_edits = _read_only_outputs(ran, sub[1:])
                    written += [w for w in out if "{}" not in w]
                    edits = edits or sub_edits or any("{}" in w for w in out)
                at = end
            at += 1
    return [w for w in written if w], edits


_CODE_RUNNERS = re.compile(r"^(python|pypy)[\d.]*$|^(py|perl|ruby|node|nodejs|php|lua|deno|bun|awk|gawk)$")


_CODE_WRITES = re.compile(
    r"""['"][wax]\+?b?['"]|write|dump|remove|unlink|rename|replace|rmtree|truncate|chmod|chown"""
    r"""|shutil|system|subprocess|popen|exec|eval|spawn|print\s*>|>\s*["']""", re.I)


def _squash(command):
    """The command with shell quoting noise removed (`p\\ip`, `p""ip`, a
    backslash-newline), so a name cannot be hidden from the text checks."""
    return re.sub(r"[\\'\"]", "", re.sub(r"\\\r?\n", "", command or ""))


# _DYNAMIC_INSTALL can only match where an install verb follows whitespace;
# without one it gives no match, so it is not run (on `$($($(…` with no verb
# it took quadratic time — fuzz finding F3). Same answers.
_DYNAMIC_VERB = re.compile(r"\s(?:install|add|i|download|wheel|update|up|upgrade)\b")


def _dynamic_install(text):
    return bool(_DYNAMIC_VERB.search(text)) and bool(_DYNAMIC_INSTALL.search(text))


def looks_like_install(command):
    """Cheap gate: could this command be an install (or change where installs
    download from) at all?"""
    if not command:
        return False
    squashed = _squash(command)
    return bool(_INSTALLER_HINT.search(command) or _INSTALLER_HINT.search(squashed)
                or _dynamic_install(command) or _dynamic_install(squashed)
                or _INDEX_CONFIG_HINT.search(squashed) or _REMOTE_SCRIPT_HINT.search(squashed)
                or _HIDDEN_SCRIPT_HINT.search(squashed))


# Shell words separate paths with "/" on every OS: Claude Code runs Bash tool
# commands through bash (Git Bash on Windows), and `./x.sh` or
# `"$VIRTUAL_ENV/bin/pip"` are written that way there too; Windows also accepts
# "\\". Testing a word for os.sep alone missed every "/" path on Windows — a
# script written and then run as `./x.sh` was never read, so a blocklisted
# install inside it was allowed (fail-open, found on a real windows-latest
# runner 2026-11-21). On POSIX this is exactly os.sep, so nothing changes there.
_WORD_SEPS = "/" if os.sep == "/" else "/" + os.sep


def _has_sep(word):
    return any(sep in word for sep in _WORD_SEPS)


# ── Windows path spellings (2026-11-21) ──
# Under Git Bash one file has many names: D:\a\x, D:/a/x, d:/A/X (NTFS ignores
# case), /d/a/x and /cygdrive/d/a/x (MSYS), \\?\D:\a\x and \\.\D:\a\x (device
# prefixes), \\localhost\d$\a\x (this computer's admin share), and x. / "x " /
# x::$DATA (Win32 drops trailing dots and spaces; ::$DATA is the file itself).
# ntpath knows only the first two, so /d/… and the rest never matched
# stillrunning's own files (found on a real windows-latest runner). Everything
# below is used only when os.name == "nt"; on POSIX none of it runs.
_MSYS_DRIVE = re.compile(r"^(?:/proc)?(?:/cygdrive)?/([A-Za-z])(?=/|$)")
_DEVICE_PREFIX = re.compile(r"^[\\/]{2}[?.][\\/](?!UNC[\\/])", re.I)
_DEVICE_UNC = re.compile(r"^[\\/]{2}[?.][\\/]UNC[\\/]", re.I)
_ADMIN_SHARE = re.compile(r"^[\\/]{2}([^\\/]+)[\\/]([A-Za-z])\$(?=[\\/]|$)")


def _this_computer(host):
    host = host.strip("[]").lower()
    if host in ("localhost", ".", "::1", "0:0:0:0:0:0:0:1", "0--1.ipv6-literal.net") \
            or re.fullmatch(r"127(?:\.\d{1,3}){3}", host):
        return True
    names = {os.environ.get("COMPUTERNAME", "").lower()}
    try:
        import socket
        names.add(socket.gethostname().lower())
    except Exception:  # lint: allowed-silent(no host name → only the fixed names count)
        pass
    names.discard("")
    return host in names or host.split(".", 1)[0] in names


def _win_spelling(text):
    """Windows only: the drive-letter path a bash word names, when it spells
    one in a form ntpath does not read (/d/…, /cygdrive/d/…, \\\\?\\D:\\…,
    \\\\localhost\\d$\\…). None when there is nothing to translate."""
    if os.name != "nt" or not text:
        return None
    t = text
    unc = _DEVICE_UNC.match(t)
    if unc:
        t = "\\\\" + t[unc.end():]
    else:
        device = _DEVICE_PREFIX.match(t)
        if device:
            t = t[device.end():]
    share = _ADMIN_SHARE.match(t)
    if share and _this_computer(share.group(1)):
        t = share.group(2) + ":\\" + t[share.end():].lstrip("\\/")
    msys = _MSYS_DRIVE.match(t)
    if msys:
        t = msys.group(1).upper() + ":\\" + t[msys.end():].lstrip("\\/")
    return t if t != text else None


def _win_no_stream(text):
    """Windows only: a path without its trailing :stream / ::$DATA (the file itself)."""
    drive = 2 if re.match(r"^[A-Za-z]:", text) else 0
    head, tail = text[:drive], text[drive:]
    cut = re.search(r":[^\\/:]*(?::\$data)?$|::\$data$", tail, re.I)
    if cut and cut.start() > 0 and tail[cut.start() - 1] not in "\\/":
        tail = tail[:cut.start()]
    return head + tail


def _win_comp(comp):
    if comp in ("", ".", ".."):
        return comp
    comp = comp.split(":", 1)[0]             # name:stream, name::$DATA
    return comp.rstrip(" .") or comp         # Win32 drops trailing dots and spaces


def _win_canon(path):
    """Windows only: one spelling per file (lower case, \\, no trailing dots,
    spaces or :streams)."""
    path = os.path.normcase(os.path.normpath(path))
    drive, rest = os.path.splitdrive(path)
    return drive + "\\".join(_win_comp(c) for c in rest.split("\\"))


def _path_comps(path):
    """Path components to compare: as they are on POSIX, canonical on Windows."""
    if os.name != "nt":
        return _comps(path)
    return [c for c in _win_canon(path).split("\\") if c]


def _win_candidates(text, cwds):
    """Windows only: the extra files a bash word can name there (added to
    what ntpath reads, never instead of it)."""
    out = []
    spelled = _win_spelling(text)
    if spelled:
        out.append(os.path.normpath(spelled))
    elif re.match(r"^[A-Za-z]:(?![\\/])", text):
        # D:x — relative to D:'s current folder: this one when it is on D:, else D:\x
        drive, rest = text[:2], text[2:]
        out += [os.path.normpath(os.path.join(c, rest)) for c in cwds
                if os.path.splitdrive(c)[0].lower() == drive.lower()]
        out.append(os.path.normpath(drive + "\\" + rest))
    return out


def _win_env(text):
    """Windows only: $NAME / ${NAME} from the environment Git Bash inherits
    (USERPROFILE, LOCALAPPDATA, APPDATA…); unknown names are left as they are."""
    return re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda m: os.environ.get(m.group(1), m.group(0)), text)


# Windows programs reachable from Git Bash that delete, write, move or re-permission
# files. A shell is read for every path in its command text; the rest are writers.
_WIN_SHELLS = {"cmd", "powershell", "pwsh", "cscript", "wscript", "mshta"}
_WIN_FILE_WRITERS = {"robocopy", "xcopy", "attrib", "icacls", "cacls", "takeown", "mklink",
                     "fsutil", "certutil", "expand", "extrac32", "esentutl", "bitsadmin",
                     "forfiles", "compact", "cipher", "replace", "msiexec"}
_WIN_PIECE = re.compile(r"""'([^'\n]*)'|"([^"\n]*)"|([^\s'"`;,|&()<>]+)""")


def _win_shell_touches(args, cwds):
    """Windows only: does a cmd / PowerShell command text name a protected place?
    Every path-like piece counts (reading it asks too: these shells cannot be
    read word by word the way bash is), and encoded PowerShell cannot be read."""
    text = " ".join(args)
    if re.search(r"(?i)(?:^|\s)-e(?:c|n[a-z]*)?(?:\s|$)", text):
        return True                                  # powershell -EncodedCommand …
    text = text.replace("^", "")                     # cmd's escape: de^l, D:\st^illrunning
    text = re.sub(r"%(\w+)%", lambda m: os.environ.get(m.group(1), m.group(0)), text)
    text = re.sub(r"(?i)\$env:(\w+)", lambda m: os.environ.get(m.group(1), m.group(0)), text)
    text = re.sub(r"(?i)\$home\b", lambda m: _home(), text)
    recursive = re.search(r"(?i)(?:^|\s)(?:/s|-r(?:ecurse)?|/mir|/purge|/e)(?:\s|$)", text)
    for match in _WIN_PIECE.finditer(text):
        piece = next(g for g in match.groups() if g is not None).strip()
        piece = re.sub(r"^-\w+:", "", piece)                       # -Path:C:\…
        piece = re.sub(r"^(?:[\w.]+\\)?\w+::", "", piece)          # FileSystem::C:\…
        if not piece or (not _has_sep(piece) and not piece.startswith("~")):
            continue
        kinds = _path_kinds(piece, list(cwds))
        if kinds & {"state", "settings", "claude_dir", "pkg"} or ("ancestor" in kinds and recursive):
            return True
    return False


def _real_prefix(path):
    """A wildcard path with its plain leading folders resolved (8.3 short
    names such as RUNNER~1, links): `C:/Users/RUNNER~1/x/*.py`."""
    drive, rest = os.path.splitdrive(path)
    comps = rest.split(os.sep)
    cut = next((i for i, c in enumerate(comps) if any(ch in c for ch in "*?[{")), len(comps))
    head = drive + os.sep.join(comps[:cut])
    if not head or head == drive:
        return path
    return os.path.join(os.path.realpath(head), *comps[cut:]) if cut < len(comps) else os.path.realpath(head)


def _inside(path, directory):
    if os.name == "nt":
        parts, folder = _path_comps(path), _path_comps(directory)
        return parts[:len(folder)] == folder
    return path == directory or path.startswith(directory.rstrip(os.sep) + os.sep)


def _package_dir():
    return os.path.dirname(os.path.realpath(__file__))


def _comps(path):
    return [c for c in path.split(os.sep) if c]


def _comp_match(pattern, name):
    """Could the shell pattern `pattern` name the path component `name`?"""
    if not any(ch in pattern for ch in "*?[{"):
        return pattern == name
    import fnmatch
    pattern = re.sub(r"\{[^{}]*\}", "*", pattern)
    if name.startswith(".") and not pattern.startswith("."):
        return False                                   # `*` does not match dot-files
    return fnmatch.fnmatchcase(name, pattern)


def _relation(pattern, target):
    """How a (possibly wildcard) path relates to a protected one:
    "equal", "ancestor" (it names a folder above it), "inside", or None."""
    if "**" in pattern:
        cut = pattern.index("**")
        return "equal" if _relation(pattern[:cut], target[:len(pattern[:cut])]) else None
    shared = min(len(pattern), len(target))
    if not all(_comp_match(pattern[i], target[i]) for i in range(shared)):
        return None
    if len(pattern) == len(target):
        return "equal"
    return "ancestor" if len(pattern) < len(target) else "inside"


_REALPATHS = None      # {path: realpath} for the duration of one touches_protection() call


def _realpath(path, parent=False):
    """os.path.realpath, remembered within one touches_protection() call: a
    5,000-line command resolved the same few folders 50,000 times (fuzz R2).
    Outside such a call it is plain realpath. `parent`: the folder of `path`
    (as _package_dir() gives it)."""
    if _REALPATHS is None:
        real = os.path.realpath(path)
    else:
        real = _REALPATHS.get(path)
        if real is None:
            real = _REALPATHS[path] = os.path.realpath(path)
    return os.path.dirname(real) if parent else real


def _path_kinds(word, cwds):
    """Which protected places a command word could name: any of "state",
    "settings", "claude_dir", "pkg", "ancestor"."""
    kinds = set()
    home = _realpath(_home())
    text = word.strip()
    if not text or len(text) > 4096 or "\n" in text:
        return kinds
    unknown = _UNKNOWN_CWD in cwds
    cwds = [c for c in cwds if c != _UNKNOWN_CWD]
    text = re.sub(r"^\$\{?HOME\}?(?=/|$)", lambda m: home, text)
    text = re.sub(r"^\$\{?\w+\}?(?=/\.(?:claude|still))", lambda m: home, text)
    if text == "~" or text.startswith("~/"):
        text = home + text[1:]
    elif text.startswith("~"):
        text = os.path.expanduser(text)                # ~user/…
    if os.name == "nt":
        text = _win_no_stream(text)                    # x::$DATA, x:stream
        spelled = _win_spelling(text)
        if spelled and "$" in text and "$" not in spelled:
            text = spelled                             # //localhost/c$/… is C:\…, not a variable
    if "$" in text:
        low = text.lower()
        if ".still" in low:
            kinds.add("state")
        tail = re.search(r"\.claude/([^/]+)$", low)
        if ".claude/sett" in low or tail and ("$" in tail.group(1) or any(
                _comp_match(tail.group(1), name) for name in _SETTINGS_NAMES)):
            kinds.add("settings")       # `$D/.claude/settings.json`, `$D/.claude/s*.json`, `$D/.claude/$F`
        elif low.rstrip("/").endswith(".claude"):
            kinds.add("claude_dir")
        if os.name == "nt":
            # Git Bash inherits the Windows environment: $USERPROFILE,
            # $LOCALAPPDATA, $APPDATA… name the same folders the hook sees.
            expanded = _win_env(text)
            if "$" not in expanded:
                kinds |= _path_kinds(expanded, cwds + ([_UNKNOWN_CWD] if unknown else []))
        return kinds
    has_glob = any(ch in text for ch in "*?[{")
    if os.path.isabs(text):
        candidates = [os.path.normpath(text)]
    else:
        candidates = [os.path.normpath(os.path.join(c, text)) for c in cwds]
        if unknown:
            # The folder is decided at run time (`cd $X && …`). Guessing it would
            # make every relative path look protected, so only what the word
            # itself spells counts: `.stillrunning/…`, `.claude/settings.json`.
            parts = _path_comps(os.path.normpath(text))
            state_name = os.path.basename(_realpath(_state_dir()))
            if os.name == "nt":
                state_name = state_name.lower()
            if any(_comp_match(part, state_name) for part in parts):
                kinds.add("state")
            for at, part in enumerate(parts):
                if _comp_match(part, ".claude"):
                    if at == len(parts) - 1:
                        kinds.add("claude_dir")
                    elif any(_comp_match(parts[at + 1], name) for name in _SETTINGS_NAMES):
                        kinds.add("settings")
    if os.name == "nt":
        candidates += _win_candidates(text, cwds)
        if has_glob:
            candidates += [_real_prefix(c) for c in list(candidates)]
    if not has_glob:
        candidates += [_realpath(c) for c in list(candidates)]
    state = _path_comps(_realpath(_state_dir()))
    claude = _path_comps(os.path.join(home, ".claude"))
    pkg = _path_comps(_realpath(__file__, parent=True))
    for candidate in candidates:
        parts = _path_comps(candidate)
        rel = _relation(parts, state)
        if rel in ("equal", "inside"):
            kinds.add("state")
        elif rel == "ancestor":
            kinds.add("ancestor")
        rel = _relation(parts, claude)
        if rel == "equal":
            kinds.add("claude_dir")
        elif rel == "ancestor":
            kinds.add("ancestor")
        if len(parts) >= 2 and _comp_match(parts[-2], ".claude") and any(
                _comp_match(parts[-1], name) for name in _SETTINGS_NAMES):
            kinds.add("settings")
        # exact name anywhere; a wildcard only inside Claude Code's own
        # system folder (a bare `*` or find's `{}` matches every file name)
        if parts and (parts[-1] == _MANAGED_SETTINGS or (
                len(parts) >= 2 and parts[-2].lower() in ("claude-code", "claudecode")
                and _comp_match(parts[-1], _MANAGED_SETTINGS))):
            kinds.add("settings")
        rel = _relation(parts, pkg)
        if rel in ("equal", "inside"):
            kinds.add("pkg")
        elif rel == "ancestor":
            kinds.add("ancestor")
        base = parts[-1] if parts else ""
        if re.match(r"^stillrunning[\w.-]*\.pth$", base, re.I):
            kinds.add("pkg")
        if base == ".claude" and _holds_settings(candidate):
            kinds.add("project_claude")     # a project's `.claude` with a settings file in it
    return kinds


def _holds_settings(folder):
    """Is there a Claude Code settings file directly in this `.claude` folder?"""
    try:
        return any(os.path.isfile(os.path.join(folder, name)) for name in _SETTINGS_NAMES)
    except (OSError, ValueError):
        return False


def _project_settings_under(spot, cwds):
    """Does the folder `spot` hold `.claude/settings*.json`?"""
    for cwd in cwds:
        if cwd == _UNKNOWN_CWD:
            continue
        spot_here = _win_spelling(spot) or spot
        base = spot_here if os.path.isabs(spot_here) else os.path.join(cwd, spot_here)
        if _holds_settings(os.path.join(os.path.expanduser(base), ".claude")):
            return True
    return False


_UNKNOWN_CWD = "\0unknown-folder"
_GIT_FILE_REWRITES = {"checkout", "restore", "reset", "stash", "clean", "rm", "mv", "apply", "am",
                      "pull", "merge", "rebase", "switch", "revert", "cherry-pick", "worktree"}
_IMPORTS_US = re.compile(r"\b(?:import|from)\s+stillrunning\b|__import__\(\s*['\"]stillrunning"
                         r"|import_module\(\s*['\"]stillrunning|runpy[^\n]*stillrunning")


def _protected_names():
    """File and folder names that exist in the protected places."""
    names = set(_SETTINGS_NAMES) | {".claude", os.path.basename(os.path.realpath(_state_dir()))}
    for folder in (_state_dir(), _package_dir()):
        try:
            names.update(os.listdir(folder))
        except OSError:  # lint: allowed-silent(folder absent → nothing in it to protect)
            continue
    names.add(os.path.basename(_package_dir()))
    return names


def _find_could_hit(args):
    """Could this `find … -delete / -exec rm` remove a protected file? Yes
    unless every name test it carries excludes all of them."""
    patterns = []
    for i, arg in enumerate(args):
        if arg in ("-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-newer"):
            return True
        if arg in ("-name", "-iname") and i + 1 < len(args):
            negated = i > 0 and args[i - 1] in ("!", "-not")
            if negated:
                return True
            patterns.append((args[i + 1], arg == "-iname"))
    if not patterns:
        return True
    names = _protected_names()
    for pattern, fold in patterns:
        for name in names:
            if _comp_match(pattern.lower() if fold else pattern, name.lower() if fold else name) \
                    or (name.startswith(".") and _comp_match(pattern, name[1:]) and pattern.startswith("*")):
                return True
    return False


def _code_touches(code, cwds):
    """Program text (python -c, a here-document read by an interpreter) that
    changes the protection: it loads stillrunning's own modules, or it writes
    and names a protected place in a string."""
    if _IMPORTS_US.search(code):
        return True
    if not _CODE_WRITES.search(code):
        return False
    for literal in re.findall(r"""['"]([^'"\n]{1,300})['"]""", code):
        if any(ch.isspace() for ch in literal):
            continue
        if _path_kinds(literal, list(cwds) + [_UNKNOWN_CWD]) & {"state", "settings", "claude_dir", "pkg"}:
            return True
    return False


def _stdin_writer(cmd):
    """`… | xargs rm`, `find … -exec rm {} ;`, `find … -delete`: the files a
    command names are changed by something other than its first word."""
    if "-delete" in cmd:
        return True
    for flag in ("-exec", "-execdir", "-ok", "-okdir"):
        if flag in cmd:
            after = cmd[cmd.index(flag) + 1:cmd.index(flag) + 2]
            if not after or _prog_name(after[0]) not in _READ_ONLY:
                return True
    if any(_prog_name(w) in ("xargs", "parallel") for w in cmd[:4]):
        start = _program_index(cmd)
        if start >= len(cmd) or _prog_name(cmd[start]) not in _READ_ONLY:
            return True
        # `… | xargs yq -i`, `… | xargs sort -o`: a read-only program that writes
        out, edits = _read_only_outputs(_prog_name(cmd[start]), list(cmd[start + 1:]))
        return edits or bool(out)
    return False


_SELF_ARGS = {"allow", "--allow", "--block", "--untrust", "--trust", "remember", "forget",
              "shell-uninstall", "venv-uninstall", "--uninstall-hook",
              "--uninstall-hook-claude-code"}
_ENV_WORDS = {"export", "declare", "typeset", "readonly", "local", "unset", "set", "setenv"}


def _own_switch(cmd, start, program, args):
    """A command that changes stillrunning's own switches: a STILLRUNNING_*
    variable set or read, `stillrunning allow / remember / uninstall …`, or
    uninstalling the stillrunning package."""
    if any(_ASSIGN.match(t) and t.startswith("STILLRUNNING_") for t in cmd[:start]):
        return True
    if program in _ENV_WORDS and any(a.startswith("STILLRUNNING_") for a in args):
        return True
    if any("$STILLRUNNING_" in t or "${STILLRUNNING_" in t for t in cmd):
        return True
    names = [_prog_name(t) for t in cmd]
    lowered = [t.lower() for t in cmd]

    def switches(rest):
        plain = [a for a in rest if not a.startswith("-")]
        return any(a in _SELF_ARGS or "uninstall" in a for a in rest) or \
            plain[:2] == ["whitelist", "add"] or plain[:2] == ["whitelist", "remove"]

    for index, name in enumerate(names):
        module = None
        if re.match(r"^-[a-z]*m$", lowered[index]) and index + 1 < len(cmd):
            module = lowered[index + 1]
        elif re.match(r"^-[a-z]*m(stillrunning.*)$", lowered[index]):
            module = re.match(r"^-[a-z]*m(stillrunning.*)$", lowered[index]).group(1)
        if module is not None and module.startswith("stillrunning."):
            return True         # `python -m stillrunning.remembered …`: any inner module
        if name == "stillrunning" or module == "stillrunning":
            if switches(lowered[index + 1:]):
                return True
    # `$sr remember last`, `$(which stillrunning) allow x`: the program is
    # only known at run time and the words after it are our own switches.
    if start < len(cmd) and cmd[start].startswith(("$", "`")):
        rest = lowered[start + 1:]
        plain = [a for a in rest if not a.startswith("-")]
        if plain[:1] and plain[0] in ("remember", "forget", "allow", "shell-uninstall",
                                      "venv-uninstall") \
                or any(a in _SELF_ARGS and a.startswith("--") for a in rest) \
                or plain[:2] == ["whitelist", "add"]:
            return True
    if "stillrunning" in lowered[start + 1:] and any(a in ("uninstall", "remove") for a in lowered) \
            and any(_is_installer(n) for n in names):
        return True
    # Replacing the installed protection with another build of itself: a pinned
    # or ranged version (`stillrunning==0.0.1`), or a forced reinstall.
    if any(_is_installer(n) for n in names):
        pinned = any(re.match(r"^stillrunning(\[[^\]]*\])?\s*(===?|[<>~!]=?|@)", t)
                     for t in lowered[start + 1:])
        forced = "stillrunning" in lowered[start + 1:] and any(
            t in ("--force-reinstall", "--ignore-installed", "-I", "--no-deps", "--reinstall")
            for t in cmd)
        if pinned or forced:
            return True
    return False


def _paths_touch_protection(command, cwds, depth):
    """Does the command change stillrunning's protection: write to, delete or
    replace a protected place, or flip one of its switches? A path counts only
    when a command word resolves to the protected file or folder; text that
    merely mentions it (a commit message, a here-document handed to a program
    that is not a shell) does not, and reading is not a change."""
    home = os.path.realpath(_home())
    sets_switch = "STILLRUNNING_" in command
    command, bodies = _strip_heredocs(_decode_ansi_c(re.sub(r"\\\r?\n", "", command)))
    command, inner = _lift_substitutions(command)
    for piece in inner:
        if depth < 3 and _paths_touch_protection(piece, cwds, depth + 1):
            return True
    commands = _simple_commands(_tokenize(command))
    by_stdin = any(_stdin_writer(c) for c in commands)
    fed = _shell_fed(commands)
    cwds = list(cwds)
    for number, cmd in enumerate(commands):
        body = bodies.pop(0) if cmd.has_heredoc and bodies else None
        start = _program_index(cmd)
        program = _prog_name(cmd[start]) if start < len(cmd) else ""
        if os.name == "nt" and program in _WIN_SHELLS and _win_shell_touches(cmd[start + 1:], cwds):
            return True     # cmd //c del …, powershell -c Remove-Item …
        if program and program not in _FILE_WRITERS and program not in _READ_ONLY \
                and program not in _STRING_RUNNERS and program not in _DATA_COMMANDS \
                and not _CODE_RUNNERS.match(program):
            # an unknown wrapper (`setsid rm -rf …`): judge the destructive word after it
            for later in range(start + 1, len(cmd)):
                if _prog_name(cmd[later]) in _DESTRUCTIVE and not _has_sep(cmd[later].rstrip(_WORD_SEPS)[1:]):
                    start, program = later, _prog_name(cmd[later])
                    break
        args = list(cmd[start + 1:])
        if _own_switch(cmd, start, program, args):
            return True
        if body and depth < 3 and (fed[number] or _reads_stdin_as_shell(cmd)) and \
                _paths_touch_protection(body, cwds, depth + 1):
            return True
        if body and _CODE_RUNNERS.match(program) and _runs_stdin_as_code(cmd) and \
                _code_touches(body, cwds):
            return True         # `python3 - <<EOF` whose code rewrites the protection
        outputs, edits_given = _read_only_outputs(program, args) if program in _READ_ONLY else ([], False)
        for target in list(cmd.writes) + outputs:
            if _path_kinds(target, cwds) & {"state", "settings", "claude_dir", "pkg"}:
                return True
        if sets_switch:
            # a STILLRUNNING_* switch written into a shell start-up file
            here = next((c for c in cwds if c != _UNKNOWN_CWD), None)
            named = list(cmd.writes)
            if program in _FILE_WRITERS:
                named += [a for a in args if not a.startswith("-")]
            if any(_is_rc_file(target, here) for target in named):
                return True
        in_place = any(re.match(r"^-[A-Za-z]*i|^--in-place", a) for a in args)
        edits = program in ("sed", "perl", "ruby", "awk", "gawk")
        read_only = not by_stdin and ((program in _READ_ONLY and not edits_given)
                                      or (edits and not in_place))
        writer = by_stdin or (program in _FILE_WRITERS and (not edits or in_place)) \
            or (os.name == "nt" and program in _WIN_FILE_WRITERS)
        recursive = any(re.match(r"^-[A-Za-z]*[rR]|^--recursive", a) for a in args)
        words = [(a, False) for a in args]
        words += [(t.split("=", 1)[1], True) for t in cmd[:start] if _ASSIGN.match(t)]
        if program in _ENV_WORDS:
            words = [(a.split("=", 1)[1], True) if _ASSIGN.match(a) else (a, False) for a in args]
        if _CODE_RUNNERS.match(program):
            for arg in args:
                # inline code that can write: the file names it holds count as written
                if (" " in arg or "(" in arg) and _code_touches(arg, cwds):
                    return True
        plain = [a for a in args if not a.startswith("-")]
        # `cp -t DIR SRC…`, `install -t DIR …`: DIR is written to
        target_dirs = []
        if program in ("cp", "install"):     # (rsync's and scp's -t are other options)
            for at, arg in enumerate(args):
                if re.match(r"^-[A-Za-z]*t$", arg) and at + 1 < len(args):
                    target_dirs.append(args[at + 1])
                elif re.match(r"^-[A-Za-z]*t.", arg) and not arg.startswith("--"):
                    target_dirs.append(arg[arg.index("t") + 1:])
                elif arg.startswith("--target-directory"):
                    target_dirs.append(arg.split("=", 1)[1] if "=" in arg else
                                       (args[at + 1] if at + 1 < len(args) else ""))
        targets_named = bool(target_dirs)
        for folder in target_dirs:
            if _path_kinds(folder, cwds) & {"state", "settings", "claude_dir", "pkg"}:
                return True
        # H: sed's `w FILE` / `W FILE` command and `s///w FILE` flag write FILE
        if program == "sed":
            scripts, at, named = [], 0, False
            while at < len(args):
                arg = args[at]
                if (arg == "--expression" or re.match(r"^-[A-Za-z]*e$", arg)) and at + 1 < len(args):
                    scripts.append(args[at + 1])
                    named, at = True, at + 1
                elif arg.startswith("--expression="):
                    scripts.append(arg.split("=", 1)[1])
                    named = True
                elif re.match(r"^-[A-Za-z]*e.", arg) and not arg.startswith("--"):
                    scripts.append(arg[arg.index("e") + 1:])
                    named = True
                elif arg in ("-f", "--file"):
                    named, at = True, at + 1
                at += 1
            if not named:
                scripts += [a for a in args if not a.startswith("-")][:1]
            for script in scripts:
                for found in re.finditer(r"[wW]\s*([^\s;}]+)", script):
                    if _path_kinds(found.group(1), cwds) & {"state", "settings", "claude_dir", "pkg"}:
                        return True
        if program == "git":
            verbs = [a for a in plain[:4] if a in _GIT_FILE_REWRITES]
            outputs = []
            for at, arg in enumerate(args):
                if re.match(r"^--output(=|$)", arg) or arg in ("-o", "-f", "--file") or \
                        arg.startswith("--file="):
                    value = arg.split("=", 1)[1] if "=" in arg else (args[at + 1] if at + 1 < len(args) else "")
                    outputs.append(value)
                elif re.match(r"^-o.", arg):
                    outputs.append(arg[2:])
            # `git diff --output F`, `git archive -o F`, `git config -f F …` (-f is a path
            # only for config, and for others a force flag: harmless to check as a path)
            if any(_path_kinds(o, cwds) & {"state", "settings", "claude_dir", "pkg"} for o in outputs):
                return True
            if not verbs:
                continue        # add / status / diff / log / commit: the file itself is not written
            verb = verbs[0]
            after = args[args.index(verb) + 1:]
            named = [a for a in after if not a.startswith("-")]
            git_cwds = cwds
            for at, arg in enumerate(args[:args.index(verb)]):
                if arg == "-C" and at + 1 < len(args):          # git -C <folder> …
                    folder = os.path.expanduser(args[at + 1])
                    folder = _win_spelling(folder) or folder        # Windows: git -C /d/…
                    git_cwds = [folder] if os.path.isabs(folder) else [
                        os.path.normpath(os.path.join(c, folder)) for c in cwds if c != _UNKNOWN_CWD]
            # The forms that put files back to an earlier state or delete them,
            # in whatever folder they are run: `git stash`, `git reset --hard`,
            # `git clean`, `git restore`, `git checkout <ref> -- <path>`,
            # `git checkout .`. (`git checkout <branch>`, pull, merge: not these.)
            spots = None
            if verb == "stash":
                if not (named[:1] and named[0] in ("list", "show", "drop", "clear", "branch",
                                                   "create", "store")):
                    spots = ["."]
            elif verb == "reset":
                if "--hard" in after or "--merge" in after:
                    spots = ["."]
            elif verb in ("clean", "restore"):
                spots = (after[after.index("--") + 1:] if "--" in after else named) or ["."]
            elif verb == "checkout":
                if "--" in after:
                    spots = after[after.index("--") + 1:] or ["."]
                elif "." in named or "-f" in after or "--force" in after:
                    spots = ["."]
            if spots:
                wipes_untracked = verb == "clean" or (verb == "stash" and any(
                    a in ("-u", "--include-untracked", "-a", "--all") for a in after))
                for spot in spots:
                    if _path_kinds(spot, git_cwds) & {"ancestor", "state", "settings",
                                                      "claude_dir", "pkg", "project_claude"}:
                        return True
                    if wipes_untracked and _project_settings_under(spot, git_cwds):
                        return True
        if program == "find" and _stdin_writer(cmd):
            roots = []
            for arg in args:
                if arg.startswith("-") or arg in ("!", "("):
                    break
                roots.append(arg)
            if any("ancestor" in _path_kinds(root, cwds) for root in roots or ["."]) \
                    and _find_could_hit(args):
                return True
        for word, forced in words:
            if any(ch.isspace() for ch in (word.rstrip(" ") if os.name == "nt" else word)):
                continue                # (Windows: "x " is x, Win32 drops the space)
            if word.startswith("-"):
                if "=" not in word:
                    continue
                word = word.split("=", 1)[1]
            elif "=" in word and program == "dd":
                word = word.split("=", 1)[1]
            kinds = _path_kinds(word, cwds)
            if not kinds:
                continue
            # (`ln` is not exempt: a link to a protected place is a way to write through it)
            if targets_named:
                # `cp -t DIR SRC…`: every operand but DIR (checked above) is only read
                source_only = program != "ln" and word not in target_dirs and not forced
            else:
                source_only = (program in _LAST_ARG_WRITERS and program != "ln" and len(plain) > 1
                               and word != plain[-1] and not forced)
            if kinds & {"state", "settings", "claude_dir"} and not (read_only and not forced) \
                    and not source_only:
                return True
            if "pkg" in kinds and (writer or forced) and not source_only:
                return True
            if "project_claude" in kinds and program in _DESTRUCTIVE and not forced \
                    and not source_only:
                return True     # `rm -rf .claude`, `mv .claude x` in a project
            if "ancestor" in kinds and program in _DESTRUCTIVE and not forced:
                needs_recursion = program in ("rm", "chmod", "chown", "chgrp", "chattr")
                moved_into = program == "mv" and len(plain) > 1 and word == plain[-1]
                if (recursive or not needs_recursion) and not moved_into \
                        and program not in ("truncate", "unlink", "rmdir", "shred"):
                    return True
        if program in ("cd", "pushd"):
            target = plain[0] if plain else "~"
            if os.name == "nt":
                if "$" in target and "$" not in _win_env(target):
                    target = _win_env(target)                    # Windows: cd $USERPROFILE/…
                target = _win_spelling(target) or target         # cd /d/…, cd //localhost/d$/…
            if "$" in target and not re.match(r"^\$\{?HOME\}?(/|$)", target) or target == "-":
                cwds = [_UNKNOWN_CWD]
            elif _UNKNOWN_CWD in cwds and not os.path.isabs(os.path.expanduser(target)) \
                    and not target.startswith("$"):
                cwds = [_UNKNOWN_CWD]
            else:
                target = re.sub(r"^\$\{?HOME\}?", lambda m: home, target)
                target = home + target[1:] if target == "~" or target.startswith("~/") else target
                target = _win_spelling(target) or target        # Windows: cd /d/…
                cwds = [target] if os.path.isabs(target) else \
                    [os.path.normpath(os.path.join(c, target)) for c in cwds]
            cwds = cwds[:8]
        if depth < 3 and not _CODE_RUNNERS.match(program) and program not in _DATA_COMMANDS \
                and _is_shell_text(cmd):
            for word in cmd:
                if (" " in word or "\n" in word or ";" in word) and \
                        _paths_touch_protection(word, cwds, depth + 1):
                    return True
    return False


_SELF_PROTECT_TEXT = re.compile(
    r"stillrunning\b[^|;&\n]*(\ballow\b|uninstall|--block\b|--untrust\b|--trust\b|\bremember\b"
    r"|\bforget\b)|uninstall\s+(-\S+\s+)*stillrunning\b|\.stillrunning|\.claude/sett"
    r"|(?<![A-Za-z0-9_])STILLRUNNING_[A-Z]", re.I)


def touches_protection(command, cwd=None):
    """Does this shell command change stillrunning's own protection: its state
    directory, the Claude Code settings that switch the hook on, the hook's
    own code, or a STILLRUNNING_* switch?"""
    if not command:
        return False
    global _REALPATHS
    outer = _REALPATHS
    if outer is None:
        _REALPATHS = {}
    try:
        here = os.path.realpath(cwd) if cwd else os.getcwd()
        return _paths_touch_protection(command, [here], 0)
    except Exception as exc:    # cannot read the command → fall back to a broad text match
        _warn(f"could not work out which files this command touches ({type(exc).__name__}) — "
              "judged on its text")
        return bool(_SELF_PROTECT_TEXT.search(_squash(command)))
    finally:
        _REALPATHS = outer


def index_config_file(path):
    """Is this one of the files that decide where packages download from?"""
    if not isinstance(path, str):
        return False
    if os.name == "nt":                 # PIP.INI is pip.ini there
        return _win_comp(os.path.basename(path.strip())).lower() in {n.lower() for n in INDEX_CONFIG_FILES}
    return os.path.basename(path.strip()) in INDEX_CONFIG_FILES


def protected_path(path, cwd=None):
    """Is this file one that Write/Edit must not change without a person's
    say-so: stillrunning's state directory, a Claude Code settings file, or
    stillrunning's own code?"""
    if not isinstance(path, str) or not path.strip():
        return False
    full = os.path.expanduser(path.strip())
    if os.name == "nt":
        full = _win_spelling(_win_env(full)) or _win_env(full)
    if not os.path.isabs(full):
        full = os.path.join(cwd or os.getcwd(), full)
    real = os.path.realpath(full)
    if _inside(real, os.path.realpath(_state_dir())):
        return True
    name, parent = os.path.basename(real), os.path.basename(os.path.dirname(real))
    if os.name == "nt":                     # Settings.JSON, claude_hook.py. , x::$DATA
        comps = _path_comps(real)
        name, parent = (comps[-1] if comps else ""), (comps[-2] if len(comps) > 1 else "")
    if name in _SETTINGS_NAMES and parent == ".claude":
        return True
    if name == _MANAGED_SETTINGS:
        return True
    if re.match(r"^stillrunning[\w.-]*\.pth$", name, re.I):
        return True
    return _inside(real, _package_dir())

# ───────────────────────── plain-language templates ─────────────────────────
# One place for every surface (hook, wrappers, CLI, dashboard). Fixed text;
# the only substituted values are the package name, a look-alike name, an
# advisory id and the registry name — all validated before they get here.
# Never "safe", never "clean": a lookup can find a known threat, it cannot
# vouch for a package.
EXPLANATIONS = {
    "blocked_advisory": (
        "Blocked `{name}`. It is listed as malware (software written to steal data or damage "
        "a computer) in {advisory}, a public security report. Installing it would run that "
        "code on this machine. Do not install it; if a website, README or AI suggestion told "
        "you to, treat that source with suspicion."),
    "blocked_listed": (
        "Blocked `{name}`. It is on the stillrunning blocklist (a list of packages reported "
        "as malicious). Installing it would run its code on this machine. Do not install it; "
        "if a website, README or AI suggestion told you to, treat that source with suspicion."),
    "blocked_typosquat": (
        "Blocked `{name}`. Its name is one letter off from the popular `{lookalike}`; attackers "
        "publish look-alikes hoping someone mistypes (this is called typosquatting). If you "
        "meant `{lookalike}`, install that instead."),
    "suspicious": (
        "Stopped `{name}`. It is on an older watch list with no public security report behind "
        "it, so it may or may not be harmful — nobody has confirmed either way. Look up who "
        "publishes it before installing. If you decide to trust it, run "
        "`stillrunning allow {name} --once` yourself in a terminal and try again."),
    "not_found": (
        "`{name}` does not exist on {registry} (the public registry, i.e. the official download "
        "site for these packages). AI assistants sometimes invent package names, and attackers "
        "later register those names with harmful code. Check the spelling. If it is your "
        "organisation's private package, approve the install."),
    "not_found_lookalike": (
        "`{name}` does not exist on {registry} (the public registry, i.e. the official download "
        "site for these packages), and its name is one letter off from the popular "
        "`{lookalike}`. This is probably a typo. If you meant `{lookalike}`, install that "
        "instead."),
    "check_failed": (
        "Could not look up `{name}`: {why}. That means it was NOT checked — not that it passed. "
        "Approve only if you already know and trust this package; otherwise try again in a "
        "minute."),
    "remote_url": (
        "This installs code straight from a web address or code repository instead of the "
        "public registry, so it cannot be looked up in the blocklist (a list of packages "
        "reported as malicious). Approve only if you recognise the address and trust who "
        "controls it."),
    "custom_index": (
        "This install uses a custom package index (a download server other than the public "
        "registry). Whoever runs that server decides what code you get, even for well-known "
        "names. Approve only if this is a server your organisation set up."),
    "requirements_unread": (
        "This installs every package named in a requirements file that stillrunning could not "
        "read, so none of them were checked. Open the file, or run "
        "`stillrunning scan-manifest <file>` in a terminal, before approving."),
    "requirements_large": (
        "This requirements file names more packages than the hook checks in one go, so they "
        "were NOT all checked. Run `stillrunning scan-manifest <file>` in a terminal first, "
        "then approve."),
    "unparsed": (
        "This looks like a package install, but stillrunning could not work out which packages "
        "it would fetch, so nothing was checked. Read the command yourself before approving."),
    "self_protect": (
        "This command changes stillrunning's own protection (its allow list, settings, "
        "wrappers or hook). A person may do that on purpose; an AI assistant that has been fed "
        "hidden instructions may try it to slip a blocked package through. Approve only if you "
        "asked for this."),
    "self_protect_file": (
        "This would write to one of stillrunning's own protection files (its allow list, "
        "settings, wrappers or hook, or the Claude Code settings that switch the hook on). A "
        "person may do that on purpose; an AI assistant that has been fed hidden instructions "
        "may try it to slip a blocked package through. Approve only if you asked for this."),
    "override_blocked": (
        "`{name}` is on the stillrunning blocklist (a list of packages reported as malicious), "
        "and a local override on this machine says to allow it anyway. If you did not add that "
        "override yourself, do not approve: something else added it. Overrides are kept in "
        "the file overrides.json in the .stillrunning folder in your home directory."),
    "version_range": (
        "Some versions of `{name}` are reported as malicious ({affected}), and this command "
        "does not name one exact version, so stillrunning cannot tell which version it would "
        "install. Name an exact version that is not on that list and try again."),
    "local_missing": (
        "This installs from a local file or folder that is not there, so stillrunning cannot "
        "tell what it is. If an earlier part of the same command downloads or builds it, "
        "nothing about it was checked. Approve only if you know where that file comes from."),
    "dynamic_command": (
        "This looks like a package install, but the program it runs is only decided when the "
        "command runs (a variable or a command inside the command), so stillrunning cannot "
        "tell what would be installed and nothing was checked. Read the command yourself "
        "before approving."),
    "file_changed": (
        "This installs from a file that the same command writes or replaces first (a "
        "download, a redirect, a copy, an unpack or a git update), so what stillrunning can "
        "read now is not what would be installed and it could not be checked. Run the two "
        "steps separately, or read the file yourself before approving."),
    "unknown_folder": (
        "This installs from a file or folder named relative to a directory that is only "
        "decided when the command runs (a `cd` to a variable or to another command's output), "
        "so stillrunning could not tell which file would be read and nothing in it was "
        "checked. Name the folder plainly, or check the file yourself before approving."),
    "hidden_script": (
        "This runs commands that are decoded, unpacked or downloaded at the moment it runs "
        "(for example text passed through base64 and into a shell), so stillrunning cannot "
        "read what would be run or installed. People rarely need this; attackers use it to "
        "hide what a command does. Approve only if you wrote it and know what it contains."),
    "index_config": (
        "This changes where package installers download from (an index or registry setting, "
        "or one of the files that hold it). Whoever runs that server decides what code later "
        "installs fetch, even for well-known names. Approve only if this is a server your "
        "organisation set up."),
    "unsupported_installer": (
        "This installs packages with an installer stillrunning has no threat list for (conda, "
        "mamba, pixi, cargo, gem or go), so nothing here was checked. Approve only if you know "
        "and trust every package it names."),
    "remote_script": (
        "This runs a script straight from a web address. Whoever controls that address decides "
        "what runs on this machine, and stillrunning cannot see what the script installs, so "
        "nothing was checked. Approve only if you recognise the address and trust who controls "
        "it."),
    "too_large": (
        "This command is too long to check in the time Claude Code gives the hook, so it "
        "was not checked. Approve it only if you know what it runs."),
    "hook_deadline": (
        "The check did not finish in the time Claude Code gives the hook, so the command "
        "was stopped rather than let through unchecked."),
    "hook_error": (
        "stillrunning hit an internal error while checking this install, so nothing was "
        "checked. Approve only if you already trust every package in the command."),
}
# Known vulnerabilities (OSV.dev). About bugs in honest packages, never malware.
# Same rules as EXPLANATIONS; rendered by explain() too.
CVE_EXPLANATIONS = {
    "cve_critical_fixed": (
        "{name} {version} has a critical known vulnerability ({advisory}); {fixed} fixes it. "
        "This is about a bug in an honest package, not malware. Install {fixed} or later "
        "instead, or approve if you need this exact version."),
    "cve_critical_nofix": (
        "{name} {version} has a critical known vulnerability ({advisory}); no fixed version "
        "is known yet. This is about a bug in an honest package, not malware. Approve only "
        "if you need this package now."),
    "cve_unchecked": (
        "The vulnerability check could not run for `{name}`: {cve_why}. It looks up known "
        "vulnerabilities (bugs in honest packages) and holds the install when it cannot "
        "finish. This is separate from the malware blocklist. Approve only if you know this "
        "version is fine."),
    "cve_some_critical": (
        "A critical known vulnerability ({advisory}) affects versions of `{name}` that this "
        "command could install, and {cve_why}, so it may install an affected one. This is "
        "about a bug in an honest package, not malware. Name an exact, fixed version, or "
        "approve if you know the version it installs is fine."),
    "cve_some_unknown": (
        "A known vulnerability ({advisory}) whose severity could not be determined affects "
        "versions of `{name}` that this command could install, and {cve_why}, so it may "
        "install an affected one. It is held because it could be critical. This is about a bug "
        "in an honest package, not malware. Name an exact, fixed version, or approve if you "
        "know the version it installs is fine."),
    "cve_unknown_fixed": (
        "{name} {version} has a known vulnerability ({advisory}) whose severity could not be "
        "determined; {fixed} fixes it. It is held because it could be critical. This is about "
        "a bug in an honest package, not malware. Install {fixed} or later instead, or approve "
        "if you need this exact version."),
    "cve_unknown_nofix": (
        "{name} {version} has a known vulnerability ({advisory}) whose severity could not be "
        "determined; no fixed version is known yet. It is held because it could be critical. "
        "This is about a bug in an honest package, not malware. Approve only if you need this "
        "package now."),
}
CVE_WHY = {
    "offline": "api.osv.dev could not be reached",
    "timeout": "api.osv.dev took too long to answer",
    "http": "api.osv.dev answered with an error",
    "garbage": "api.osv.dev sent an answer that could not be read",
    "budget": "the time allowed for the check ran out",
    "version": "the version that would be installed could not be worked out",
    "range": "the command does not name one exact version",
    "error": "the check hit an internal error",
}
CHECK_FAILED_WHY = {
    "quota": "today's free lookup allowance is used up",
    "offline": "stillrunning.io could not be reached",
    "stale": "the threat list on the server is out of date",
    "server": "the server answered with an error",
    "timeout": "the lookup took too long",
    "ecosystem": "stillrunning has no threat list for this kind of package",
    "version": "some versions of it are reported as malicious, and the version this "
               "command would install could not be worked out — name an exact version",
}
CHECK_FAILED_WHY.update({
    "override": "you allowed this package yourself",
    "override_unchecked": "a local override allows it, but the blocklist could not be reached "
                          "to confirm it is not listed there",
    "no_name": "there is no package name to look up",
    "version_range": "some versions of it are reported as malicious, and this command does "
                     "not name one exact version",
})
# "Not checked" outcomes that are more than "unverified": part of the package
# IS on the blocklist. The unverified opt-out never waves these through.
NEEDS_PERSON_WHY = ("version", "version_range")
REGISTRY_NAME = {"pip": "PyPI", "npm": "npm"}

# What each check found, in plain English. A check that did not run is always
# reported as "not checked" — never left out, never worded as a pass.
EVIDENCE = {
    "blocklist_none_sized": "Looked up in the stillrunning blocklist ({size} packages reported "
                            "as malicious): no match",
    "blocklist_none": "Looked up in the stillrunning blocklist: no match",
    "blocklist_hit": "Found in the stillrunning blocklist",
    "blocklist_hit_advisory": "Found in the stillrunning blocklist, advisory {advisory}",
    "blocklist_hit_local": "Found in the blocklist that ships inside stillrunning on this machine",
    "blocklist_watch": "Found on an older watch list that has no public report behind it",
    "blocklist_not_checked": "Blocklist lookup: not checked ({why})",
    "listed_since": "On the blocklist since {date}",
    "version_resolved": "Some versions of this package are reported as malicious "
                        "({affected}); the version that would be installed now is "
                        "{version}, which is not one of them",
    "version_bad": "The version that would be installed now is {version}, which is "
                   "reported as malicious",
    "lookalike_none": "Name compared with {count} popular package names: not a one-letter "
                      "look-alike",
    "lookalike_hit": "Name is one letter off from the popular `{lookalike}`",
    "registry_yes": "Exists on {registry}",
    "registry_no": "Not found on {registry}",
    "registry_not_checked": "Existence on {registry}: not checked",
    "override": "Allowed by your own override",
    "override_local": "A local override on this machine says to allow it",
    "version_affected": "Versions reported as malicious: {affected}",
}
CVE_EVIDENCE = {
    "cve_none": "Known vulnerabilities (OSV.dev) for {version}: none",
    "cve_found": "Known vulnerability (OSV.dev) for {version}: {advisory}, {severity}{fix}",
    "cve_not_checked": "Known vulnerabilities (OSV.dev): not checked ({cve_why})",
    "cve_none_any": "Known vulnerabilities (OSV.dev): none critical in any version",
}
GLOSSARY = {
    "blocklist": "a list of packages that security researchers have reported as malicious",
    "advisory": "a public security report describing a specific harmful package",
    "look-alike": "a package whose name is one letter off from a popular one, published "
                  "hoping someone mistypes",
    "registry": "the official public download site for packages (PyPI for Python, npm for "
                "JavaScript)",
    "needs approval": "stillrunning could not check it, so a person has to decide",
}
VERDICT_LABEL = {"no_known_threat": "no known threat", "blocked": "BLOCKED",
                 "needs_approval": "needs approval", "override": "allowed by you",
                 "note": "not looked up"}


def _ev(check, status, key, **fields):
    fields = dict(fields)
    if "why" in fields:
        fields["why"] = CHECK_FAILED_WHY.get(fields["why"], CHECK_FAILED_WHY["server"])
    if "registry" in fields:
        fields["registry"] = REGISTRY_NAME.get(fields["registry"], "the public registry")
    if "cve_why" in fields:
        fields["cve_why"] = CVE_WHY.get(fields["cve_why"], CVE_WHY["error"])
    if "version" in fields and not _SAFE_VERSION.match(str(fields["version"])):
        fields["version"] = "this version"
    if "advisory" in fields and not _SAFE_ADVISORY.match(str(fields["advisory"])):
        fields["advisory"] = "an advisory"
    if "severity" in fields:
        fields["severity"] = (str(fields["severity"]).lower() if fields["severity"] in
                              ("LOW", "MODERATE", "HIGH", "CRITICAL") else "severity unknown")
    template = EVIDENCE.get(key) or CVE_EVIDENCE[key]
    return {"check": check, "status": status, "text": template.format(**fields)}


def build_evidence(pkg, outcome):
    """The checks that ran for one package and what each found.
    status: found | nothing_found | not_checked | info."""
    eco, name, status = pkg["eco"], pkg["name"], outcome["status"]
    evidence = []
    if status == "override":
        evidence.append(_ev("override", "info", "override"))
        evidence.append(_ev("blocklist", "not_checked", "blocklist_not_checked", why="override"))
    elif status in ("blocked", "override_blocked"):
        advisory = outcome.get("advisory")
        if status == "override_blocked":
            evidence.append(_ev("override", "found", "override_local"))
        if outcome.get("local"):
            evidence.append(_ev("blocklist", "found", "blocklist_hit_local"))
        elif advisory and _SAFE_ADVISORY.match(advisory):
            evidence.append(_ev("blocklist", "found", "blocklist_hit_advisory", advisory=advisory))
        else:
            evidence.append(_ev("blocklist", "found", "blocklist_hit"))
        if outcome.get("listed_since"):
            evidence.append(_ev("blocklist", "info", "listed_since", date=outcome["listed_since"]))
    elif status == "suspicious":
        evidence.append(_ev("blocklist", "found", "blocklist_watch"))
    elif status in ("ok", "not_found"):
        size = outcome.get("feed_size")
        if size:
            evidence.append(_ev("blocklist", "nothing_found", "blocklist_none_sized",
                                size=f"{size:,}"))
        else:
            evidence.append(_ev("blocklist", "nothing_found", "blocklist_none"))
    else:
        evidence.append(_ev("blocklist", "not_checked", "blocklist_not_checked",
                            why=outcome.get("why", "server")))
    resolved, affected = outcome.get("resolved_version"), outcome.get("affected") or []
    affected = [a for a in affected if isinstance(a, str) and _SAFE_VERSION.match(a)]
    if affected and (outcome.get("why") in NEEDS_PERSON_WHY or status == "override_blocked"):
        evidence.append(_ev("version", "found", "version_affected",
                            affected=", ".join(affected)))
    if resolved and _SAFE_VERSION.match(str(resolved)):
        if status == "blocked":
            evidence.append(_ev("version", "found", "version_bad", version=resolved))
        elif status in ("ok", "not_found") and affected:
            evidence.append(_ev("version", "info", "version_resolved", version=resolved,
                                affected=", ".join(affected)))
    twin = lookalike_of(eco, name)
    if twin:
        evidence.append(_ev("lookalike", "found", "lookalike_hit", lookalike=twin))
    else:
        evidence.append(_ev("lookalike", "nothing_found", "lookalike_none",
                            count=len(POPULAR.get(eco, ()))))
    exists = outcome.get("registry")
    if exists is True:
        evidence.append(_ev("registry", "info", "registry_yes", registry=eco))
    elif exists is False:
        evidence.append(_ev("registry", "found", "registry_no", registry=eco))
    else:
        evidence.append(_ev("registry", "not_checked", "registry_not_checked", registry=eco))
    return evidence


def top_evidence(evidence, limit=3):
    order = {"found": 0, "not_checked": 1, "info": 2, "nothing_found": 3}
    ranked = sorted(evidence, key=lambda e: order.get(e["status"], 9))
    return [e["text"] for e in ranked[:limit]]

_SAFE_FIELD = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@/._~-]{0,213}$")
_SAFE_ADVISORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$")


def explain(kind: str, **fields) -> str:
    """Render one fixed template. Field values that are not plain package
    names / advisory ids are replaced, so no outside text reaches the user."""
    clean = {}
    for key, value in fields.items():
        value = str(value)
        if key == "why":
            value = CHECK_FAILED_WHY.get(value, CHECK_FAILED_WHY["server"])
        elif key == "registry":
            value = REGISTRY_NAME.get(value, "the public registry")
        elif key == "advisory":
            value = value if _SAFE_ADVISORY.match(value) else "a security advisory"
        elif key == "affected":
            parts = [p for p in value.split(", ") if _SAFE_VERSION.match(p)]
            value = ", ".join(parts[:8]) or "see the security report"
        elif key == "cve_why":
            value = CVE_WHY.get(value, CVE_WHY["error"])
        elif key in ("version", "fixed"):
            value = value if _SAFE_VERSION.match(value) else (
                "this version" if key == "version" else "a later version")
        elif key == "severity":
            value = value.lower() if value in ("LOW", "MODERATE", "HIGH", "CRITICAL") else "unknown"
        elif not _SAFE_FIELD.match(value):
            value = "this package"
        clean[key] = value
    return (EXPLANATIONS.get(kind) or CVE_EXPLANATIONS[kind]).format(**clean)


POPULAR = {
    "pip": (
        "requests urllib3 numpy pandas boto3 botocore setuptools pip wheel certifi idna "
        "charset-normalizer python-dateutil six pyyaml typing-extensions packaging cryptography "
        "pydantic fastapi flask django jinja2 click sqlalchemy pytest scipy matplotlib pillow "
        "scikit-learn tensorflow torch transformers openai anthropic langchain httpx aiohttp "
        "beautifulsoup4 lxml selenium psycopg2 pymongo redis celery uvicorn gunicorn rich tqdm "
        "colorama attrs protobuf grpcio pyjwt paramiko docker kubernetes jupyter notebook "
        "ipython black ruff mypy poetry virtualenv tox coverage pylint flake8 isort litellm "
        "streamlit gradio tiktoken playwright websockets starlette alembic marshmallow"
    ).split(),
    "npm": (
        "react react-dom lodash express axios chalk commander debug typescript webpack vite "
        "next vue angular svelte jquery moment dayjs uuid dotenv cors body-parser mongoose "
        "prisma sequelize redis socket.io ws eslint prettier jest mocha chai vitest babel-core "
        "rollup esbuild tailwindcss postcss autoprefixer sass nodemon pm2 yargs inquirer ora "
        "glob rimraf fs-extra minimist semver async bluebird rxjs zod yup joi ajv "
        "jsonwebtoken bcrypt passport nodemailer puppeteer playwright cheerio node-fetch "
        "cross-env concurrently husky lint-staged tslib core-js redux zustand immer openai "
        "electron three d3 underscore request colors"
    ).split(),
}


def normalize(eco: str, name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if eco == "pip" else name


def _one_edit_apart(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return (len(diff) == 2 and diff[1] == diff[0] + 1
                and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    for i in range(len(b)):
        if b[:i] + b[i + 1:] == a:
            return True
    return False


def lookalike_of(eco: str, name: str):
    """The popular package this name is one edit away from, or None."""
    name = normalize(eco, name)
    popular = POPULAR.get(eco, ())
    if len(name) < 4 or name in popular:
        return None
    for candidate in popular:
        if len(candidate) >= 4 and _one_edit_apart(name, candidate):
            return candidate
    return None


# ───────────────────────────── command parser ─────────────────────────────
_PUNCT = "();<>|&\n"
_WRAPPERS = {"sudo", "doas", "env", "command", "exec", "time", "nice", "nohup", "builtin",
             "xargs", "timeout", "then", "do", "else", "if", "while", "!", "{", "stdbuf",
             "ionice", "flock", "watch", "caffeinate", "unbuffer", "eval"}
_SHELL_RUNNERS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "eval", "ssh", "su", "sudo",
                  "docker", "podman", "kubectl", "xargs", "watch", "timeout", "env", "nohup",
                  "script", "wsl", "flock", "time", "parallel", "doas", "nice"}
# Which of each wrapper's own flags take a value. A flag is given a value only
# for the wrapper that defines it: `sudo -n pip …` must not swallow `pip`
# because `nice -n` takes a number. An unknown flag takes no value.
_WRAPPER_FLAGS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t", "--user",
             "--group", "--host", "--prompt", "--chdir", "--chroot", "--role", "--type",
             "--close-from", "--other-user", "--command-timeout"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"},
    "xargs": {"-I", "-n", "-P", "-d", "-E", "-L", "-s", "-a", "--max-args", "--max-procs",
              "--delimiter", "--replace", "--max-lines", "--max-chars", "--arg-file", "--eof"},
    "time": {"-o", "-f", "--output", "--format"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-k", "-s", "--kill-after", "--signal"},
    "watch": {"-n", "--interval"},
    "exec": {"-a"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "ionice": {"-c", "-n", "-p", "--class", "--classdata", "--pid"},
    "flock": {"-w", "--timeout", "-E", "--conflict-exit-code"},
    "caffeinate": {"-t", "-w"},
}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_INDEX_ENV = ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_INDEX_URL",
              "UV_DEFAULT_INDEX", "UV_INDEX", "UV_EXTRA_INDEX_URL", "NPM_CONFIG_REGISTRY",
              "npm_config_registry", "YARN_NPM_REGISTRY_SERVER",
              # a config file or mirror decides the download source just the same
              "PIP_CONFIG_FILE", "PIP_TRUSTED_HOST", "PIP_REQUIREMENT", "NPM_CONFIG_USERCONFIG",
              "npm_config_userconfig", "NPM_CONFIG_GLOBALCONFIG", "npm_config_globalconfig",
              "UV_FIND_LINKS", "UV_CONFIG_FILE", "PIPENV_PYPI_MIRROR", "BUN_CONFIG_REGISTRY",
              "COREPACK_NPM_REGISTRY", "YARN_RC_FILENAME", "PNPM_CONFIG_REGISTRY")
_INDEX_ENV_PREFIXES = ("UV_INDEX_", "POETRY_REPOSITORIES_", "POETRY_HTTP_BASIC_",
                       "POETRY_PYPI_TOKEN_", "npm_config_@", "NPM_CONFIG_@")


def _is_index_env(key):
    return key in _INDEX_ENV or key.startswith(_INDEX_ENV_PREFIXES)


_PIP_VALUE_FLAGS = {
    "-c", "--constraint", "-t", "--target", "--prefix", "--root", "--python", "--platform",
    "--python-version", "--implementation", "--abi", "--src", "--upgrade-strategy", "-C",
    "--config-settings", "--global-option", "--no-binary", "--only-binary", "--progress-bar",
    "--report", "--cert", "--client-cert", "--proxy", "--retries", "--timeout",
    "--trusted-host", "--cache-dir", "--log", "--use-feature", "--use-deprecated",
    "--exists-action", "--root-user-action", "--keyring-provider", "--hash", "-d", "--dest",
    "-w", "--wheel-dir", "--group", "--dev-group", "--optional", "-G", "--extra", "-p",
    "--index-strategy", "--resolution", "--prerelease", "--exclude-newer", "--link-mode",
    "--directory", "--project", "--script", "--source", "--pip-args", "--suffix",
    "--python-preference", "--color", "--config-file", "--bounds", "--tag", "--branch", "--rev",
}
_PIP_INDEX_FLAGS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--index",
                    "--default-index"}
# uv's own options that take a value (uvx, `uv tool run / install`, `uv run`,
# `uv add`, `uv pip install`), and pipx's. Kept apart from pip's table: read
# with pip's, `uvx --constraints c.txt TOOL` took `c.txt` for the tool and
# never looked at TOOL.
_UV_VALUE_FLAGS = {
    "--constraints", "--constraint", "-c", "--build-constraints", "--build-constraint", "-b",
    "--overrides", "--override", "--env-file", "--python-platform", "--torch-backend",
    "--fork-strategy", "--exclude-newer-package", "--config-setting", "--config-settings",
    "--config-settings-package", "-C", "--no-build-package", "--no-binary-package",
    "--no-build-isolation-package", "--no-sources-package", "--allow-insecure-host",
    "--python", "-p", "--python-version", "--index-strategy", "--keyring-provider",
    "--resolution", "--prerelease", "--exclude-newer", "--link-mode", "--cache-dir", "--color",
    "--config-file", "--directory", "--project", "--extra", "--group", "--only-group",
    "--no-group", "--no-extra", "--package", "--script", "-s", "--module", "-m",
    "--python-preference", "--python-fetch", "--python-downloads", "--target", "--prefix",
    "--tool-dir", "--tool-bin-dir", "--rev", "--tag", "--branch", "--bounds", "--marker",
    "--optional", "--output-file", "-o", "--only-binary", "--no-binary", "--no-emit-package",
    "--exclude", "--extra-build-dependencies", "--build-backend", "--executable", "-e",
    "--no-install-package", "--only-install-package", "--refresh-package",
    "--reinstall-package", "--upgrade-package", "-P", "--allow-python-downloads",
    # pipx run / install
    "--pip-args", "--suffix", "--backend", "--installer", "--path", "--fetch-python",
}
_PIPLIKE_VALUE_FLAGS = _PIP_VALUE_FLAGS | _UV_VALUE_FLAGS
# uv flags whose value is itself a package fetched by name
_UV_PACKAGE_FLAGS = {"--upgrade-package", "-P", "--reinstall-package", "--refresh-package",
                     "--preinstall"}
# Options known to take NO value, per runner. A word that follows one of these
# is the tool itself. A flag in neither table is unknown: the word after it may
# be its value or the tool, so both it and the next bare word are looked at
# (see _collect_shadow).
_RUNNER_SWITCHES = {
    "uv": {"-q", "--quiet", "-v", "--verbose", "-vv", "--offline", "--no-cache", "-n",
           "--isolated", "--no-config", "--no-progress", "--native-tls", "--no-python-downloads",
           "--managed-python", "--no-managed-python", "--refresh", "-U", "--upgrade",
           "--reinstall", "--no-index", "--pre", "--no-build", "--no-binary", "--no-sources",
           "--compile-bytecode", "--no-compile-bytecode", "--no-env-file", "--show-resolution",
           "--locked", "--frozen", "--preview", "--no-preview", "--no-build-isolation", "--lfs",
           "-h", "--help", "-V", "--version", "--all-extras", "--no-dev", "--dev", "--no-sync",
           "--no-project", "--active", "--exact", "--no-editable", "--system", "--force",
           "--no-cache-dir", "--yes", "-y", "--global", "--verbose", "--pypackages"},
    "npm": {"-y", "--yes", "-n", "--no", "--no-install", "--ignore-existing", "-q", "--quiet",
            "--silent", "-s", "--verbose", "-d", "-dd", "-ddd", "--offline", "--prefer-offline",
            "--prefer-online", "--legacy-peer-deps", "--force", "-f", "--no-audit", "--no-fund",
            "--foreground-scripts", "--ignore-scripts", "-g", "--global", "--ws", "--workspaces",
            "--include-workspace-root", "-iwr", "-h", "--help", "-v", "--version", "--json",
            "--no-update-notifier", "--no-color", "--color"},
    "pnpm": {"--silent", "-s", "--shell-mode", "--ignore-scripts", "--offline",
             "--prefer-offline", "-r", "--recursive", "--yes", "-y", "-w", "--workspace-root",
             "--workspace", "-h", "--help", "--no-color", "--color", "--aggregate-output",
             "--stream", "--frozen-lockfile", "--no-frozen-lockfile"},
    "yarn": {"-q", "--quiet", "--silent", "-s", "--verbose", "--offline", "--json", "-h",
             "--help", "--non-interactive", "--no-progress", "--frozen-lockfile",
             "--ignore-scripts", "--prefer-offline"},
    "bun": {"--bun", "--silent", "--verbose", "--no-install", "-y", "--yes", "-h", "--help",
            "--no-cache", "--frozen-lockfile", "--ignore-scripts", "--no-progress", "--force",
            "-f", "--no-summary", "-g", "--global"},
}
# Which flags take a value, PER TOOL. One shared table read pnpm's `-w`
# (--workspace-root, a switch) as npm's `-w <workspace>` and so skipped the
# package after it. A flag missing from a tool's table takes no value; a word
# wrongly skipped as a value is still looked up by the shadow pass below.
_NPM_VALUE_FLAGS_BY_TOOL = {
    "npm": {"--prefix", "-w", "--workspace", "--tag", "--cache", "--userconfig", "--loglevel",
            "--omit", "--include", "--install-strategy", "--otp", "--call", "-c",
            "--node-options", "--globalconfig", "--before", "--min-release-age",
            "--script-shell", "--scope", "--access", "--depth", "--save-prefix", "--cafile",
            "--cert", "--key", "--proxy", "--https-proxy", "--fetch-retries", "--fetch-timeout",
            "--maxsockets", "--logs-dir", "--logs-max", "--location", "--os", "--cpu", "--libc"},
    "pnpm": {"--prefix", "-C", "--dir", "--filter", "-F", "--loglevel", "--reporter",
             "--store-dir", "--virtual-store-dir", "--modules-dir", "--lockfile-dir",
             "--cache-dir", "--otp", "--tag", "--workspace-concurrency", "--config",
             "--node-linker", "--allow-build", "--os", "--cpu", "--libc",
             "--network-concurrency", "--child-concurrency", "--fetch-retries",
             "--fetch-timeout", "--userconfig", "--globalconfig"},
    "yarn": {"--cwd", "--modules-folder", "--cache-folder", "--mutex", "--network-timeout",
             "--network-concurrency", "--link-folder", "--global-folder",
             "--preferred-cache-folder", "--use-yarnrc", "--otp", "--tag", "--mode", "--scope",
             "--https-proxy", "--proxy", "--userconfig", "--globalconfig"},
    "bun": {"--cwd", "-c", "--config", "--cache-dir", "--backend", "--filter", "--omit",
            "--lockfile", "--global-dir", "--global-bin-dir", "--network-concurrency",
            "--cafile", "--ca", "--os", "--cpu", "--minimum-release-age", "--userconfig",
            "--globalconfig"},
}
_NPM_TOOL = {"npx": "npm", "pnpx": "pnpm", "bunx": "bun"}


def _npm_value_flags(prog):
    return _NPM_VALUE_FLAGS_BY_TOOL.get(_NPM_TOOL.get(prog, prog), _NPM_VALUE_FLAGS_BY_TOOL["npm"])


_NPM_INDEX_FLAGS = {"--registry", "--userconfig", "--globalconfig"}
_PIP_REQ = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$")
_NPM_NAME = re.compile(
    r"^(@[a-z0-9~-][a-z0-9._~-]*/[a-z0-9~-][a-z0-9._~-]*|[a-z0-9~-][a-z0-9._~-]*)(?:@(.*))?$",
    re.I)
_NPM_INSTALL = {"install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt",
                "isnta", "isntal", "isntall",
                # these fetch named packages too
                "update", "up", "upgrade", "udpate", "install-test", "it", "link", "ln"}
_NPM_LINK = {"link", "ln"}
_NPM_MANIFEST = {"ci", "clean-install", "install-clean", "ic", "install-ci-test", "cit",
                 "clean-install-test", "sit"}
_PYTHON = re.compile(r"^(python|pypy)[\d.]*$|^py$")
_PIP = re.compile(r"^pip[\d.]*$")
_KNOWN_PROGRAMS = {"pipx", "pipenv", "easy_install", "uv", "uvx", "poetry", "pdm", "npm",
                   "npx", "pnpm", "pnpx", "yarn", "bun", "bunx"}
# Flags and variables that change WHICH version an unpinned name resolves to.
# With any of them present, "the latest version" is not what would be installed.
_VERSION_SHIFT_FLAGS = {"--pre", "--prerelease", "-c", "--constraint", "--constraints",
                        "--override", "--overrides", "--exclude-newer", "--resolution",
                        "--tag", "--before", "--min-release-age", "--allow-prereleases",
                        "--index-strategy", "--python-version", "--platform", "--abi",
                        "--implementation"}
_VERSION_SHIFT_ENV = ("PIP_PRE", "PIP_CONSTRAINT", "UV_PRERELEASE", "UV_CONSTRAINT",
                      "UV_OVERRIDE", "UV_EXCLUDE_NEWER", "UV_RESOLUTION", "NPM_CONFIG_TAG",
                      "npm_config_tag", "NPM_CONFIG_BEFORE", "npm_config_before")
_PIP_EXACT = re.compile(r"^={2,3}\s*v?([A-Za-z0-9][A-Za-z0-9._+!-]*)$")
_NPM_EXACT = re.compile(r"^[=v]{0,2}(\d+\.\d+\.\d+[\w.+-]*)$")


def split_pip_version(rest):
    """The part after a pip package name → (exact version or None, the
    specifier when it is NOT one exact version, else None). Only `==X` / `===X`
    with no wildcard is exact; a range, `~=`, `==1.*` or several clauses is not."""
    rest = (rest or "").strip()
    if not rest:
        return None, None
    match = _PIP_EXACT.match(rest)
    if match and "*" not in rest:
        return match.group(1), None
    return None, rest[:80]


def split_npm_version(version):
    """The part after `name@` → (exact version or None, spec or None). `1.2.3`,
    `v1.2.3` and `=1.2.3` are exact; ranges (`^`, `~`, `<`, `x`) and dist-tags
    (`latest`, `next`, anything else) are not."""
    version = (version or "").strip()
    if not version:
        return None, None
    if version.lower() in ("latest", "*"):      # what an unpinned install fetches anyway
        return None, None
    match = _NPM_EXACT.match(version)
    if match:
        return match.group(1), None
    return None, version[:80]


class _Result:
    def __init__(self):
        self.packages = []      # {"eco","name","version","raw"}
        self._by_key = {}       # add()'s key → the first package in self.packages with it
        self.unverifiable = []  # {"kind", "raw"}  → ask the user
        self.notes = []         # plain strings → shown, never block
        self.uncertain = False  # a flag in force changes which version resolves
        self.cwd = None
        self.exists = os.path.exists
        self.written = set()    # files this same command writes before/around the install
        self.unknown_writes = False   # git pull / tar x / unzip: files change, which ones is unknown
        self.here = None        # the here-string of the simple command being parsed
        self.stdin_file = None  # `< file` of that command
        self.heredoc = None     # its here-document body, when the text has exactly one
        self.piped = False      # its stdin is another command's output
        self.touched = 0        # how many times a parser reported something (repeats included)
        self.cwd_unknown = False      # a `cd` to a variable: relative paths cannot be resolved
        self.cd_seen = False          # the command changes folder somewhere
        self.script_text = {}         # file → literal text this command writes into it
        self.downloaded = set()       # files this command downloads
        self.shadow = []        # words the parser did not read as packages but that could be
        self.known_names = (0, 0, set())   # _known_names(): how far it has read, and the names
        self.line_hashes = None  # `--hash` pins of the requirements line being read (verdict cache)
        self.hash_enforced = False  # the installer being parsed refuses a file that misses them
        self.hash_off_env = False   # UV_NO_VERIFY_HASHES is in force for this command

    def add(self, eco, name, version, raw, spec=None):
        # The same name asked for at two versions is two lookups: the second
        # one may be the bad version.
        self.touched += 1
        key = (eco, normalize(eco, name), version, spec, bool(self.uncertain))
        # first package with this key; add() is the only writer of
        # self.packages, so the index never goes stale (a list scan here made
        # a command naming thousands of packages quadratic)
        first = self._by_key.get(key)
        # a hash names the artifact only when this installer enforces it
        hashes = self.line_hashes if self.hash_enforced else None
        if first is None:
            self.packages.append({"eco": eco, "name": name, "version": version, "raw": raw,
                                  "spec": spec, "uncertain": bool(self.uncertain)})
            self._by_key[key] = self.packages[-1]
            if hashes:
                self.packages[-1]["hash"] = hashes
        elif first.get("hash") != hashes:
            # the same pin named twice with different (or missing) hashes:
            # no one artifact is known, so the verdict cache stays out of it
            first.pop("hash", None)
            first["hash_conflict"] = True

    def full(self, path):
        path = os.path.expanduser(path)
        if os.name == "nt":
            path = _win_spelling(path) or path
        if not os.path.isabs(path):
            path = os.path.join(self.cwd or ".", path)
        if os.name == "nt":
            return _win_canon(path)     # one key per file: X.sh, x.sh, /c/p/x.sh, C:/P/x.sh
        return os.path.normpath(path)

    def changed_here(self, path):
        """Is this file written by the very command that installs from it?"""
        if self.unknown_writes or self.full(path) in self.written:
            return True
        # the command moves between folders: the same file name written anywhere counts
        name = os.path.basename(self.full(path)) if os.name == "nt" else os.path.basename(path)
        return self.cd_seen and name in {os.path.basename(w) for w in self.written}

    def local(self, arg, raw, what):
        """A local file or folder: nothing to look up when it is there; an
        install of something that is not there cannot be judged."""
        path = arg[5:] if arg.lower().startswith("file:") else arg
        if os.name == "nt":
            path = _win_spelling(path) or path
        path = os.path.expanduser(path.lstrip("/") if path.startswith("//") else path)
        path = path.split("[", 1)[0] if what != "npm" else path
        if not os.path.isabs(path):
            if self.cwd_unknown:
                self.ask("unknown_folder", raw)
                return
            path = os.path.join(self.cwd or ".", path)
        try:
            there = bool(self.exists(path))
        except (OSError, ValueError):
            there = False
        if (_win_canon(path) if os.name == "nt" else os.path.normpath(path)) in self.written or (
                self.unknown_writes and path.lower().endswith(_ARCHIVE_SUFFIXES)):
            self.ask("file_changed", raw)
        elif there:
            self.note(f"local {'path' if what == 'npm' else what} install — not looked up")
        else:
            self.ask("local_missing", raw)

    def stdin_text(self, read_file):
        """What the command being parsed reads on its standard input, when the
        command text itself says so (a literal here-string, a here-document, or
        `< file`). None when it cannot be known."""
        if self.here is not None:
            return None if ("$" in self.here or "`" in self.here) else self.here
        if self.heredoc is not None:
            return None if ("$" in self.heredoc or "`" in self.heredoc) else self.heredoc
        if self.stdin_file and not self.piped:
            if self.changed_here(self.stdin_file):
                return None
            try:
                return read_file(self.full(self.stdin_file))
            except (OSError, UnicodeDecodeError, ValueError):
                return None
        return None

    def ask(self, kind, raw):
        self.touched += 1
        if all(u["kind"] != kind or u["raw"] != raw for u in self.unverifiable):
            self.unverifiable.append({"kind": kind, "raw": raw})

    def note(self, text):
        self.touched += 1
        if text not in self.notes:
            self.notes.append(text)

    @property
    def is_install(self):
        return bool(self.packages or self.unverifiable or self.notes)

    def as_dict(self):
        packages = [{k: v for k, v in p.items() if k not in ("spec", "uncertain") or v}
                    for p in self.packages]
        return {"packages": packages, "unverifiable": self.unverifiable,
                "notes": self.notes, "shadow": list(self.shadow)}


# What may not reach the decision log or the side panel. Applied to the raw
# command, before its whitespace is squashed, so a quoted value is masked whole.
_QUOTED_OR_WORD = r"""(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s"';&|]+)"""
_SECRET_NAME = r"(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|KEY|PAT|AUTH|CREDENTIALS?|COOKIE|SESSION)"
_REDACTIONS = [
    # https://user:pass@host and https://token@host
    (re.compile(r"(://)[^/\s:@'\"]+(?::[^/\s@'\"]*)?@"), r"\1***@"),
    # NAME_TOKEN=value, npm's //registry/:_authToken=value, --password=value
    (re.compile(r"(?i)((?<![A-Za-z0-9])[A-Za-z0-9_.-]*" + _SECRET_NAME + r"[A-Za-z0-9_]*=)"
                + _QUOTED_OR_WORD), r"\1***"),
    # --token value, --password value, --user a:b
    (re.compile(r"(?i)(--(?:[a-z0-9-]*(?:token|password|passwd|passphrase|secret|api-key|apikey"
                r"|auth|credential|otp)[a-z0-9-]*|user|proxy-user)(?<!-stdin)\s+)(?![<>|])" + _QUOTED_OR_WORD),
     r"\1***"),   # (?![<>|]): `--with-token <<< VALUE` is left to the stdin rule below
    # curl -u user:pass, wget --user, mysql -pSECRET, sshpass -p secret, docker login -p secret
    (re.compile(r"(?<![\w-])(-u\s*)(?:\"[^\"]*:[^\"]*\"|'[^']*:[^']*'|[^\s\"';&|]+:[^\s\"';&|]*)"), r"\1***"),
    (re.compile(r"(?i)(\b(?:sshpass|mysql|mysqldump|mariadb|psql|redis-cli|mongo\w*|docker|podman"
                r"|helm|htpasswd|smbclient|lftp|ldapsearch)\b[^\n;&|]*?\s-p\s*)" + _QUOTED_OR_WORD),
     r"\1***"),
    # -H 'Authorization: Bearer …' and the other headers that carry credentials
    (re.compile(r"(?i)((?:proxy-)?authorization|x-[a-z0-9-]*(?:key|token|auth|secret)[a-z0-9-]*"
                r"|cookie|set-cookie|private-token|[a-z0-9-]*api-?key)(\s*:\s*)[^'\"\n]+"),
     r"\1\2***"),
    # npm config set //host/:_authToken VALUE (key and value as separate words)
    (re.compile(r"(?i)((?:\S*:_authToken|\S*:_auth|\S*:_password|(?<![\w-])_authToken|(?<![\w-])_auth"
                r"|(?<![\w-])_password)\s+)" + _QUOTED_OR_WORD), r"\1***"),
    # poetry config pypi-token.<repo> VALUE / http-basic.<repo> USER PASS
    (re.compile(r"(?i)(\bpypi-token\.[\w.-]+\s+)" + _QUOTED_OR_WORD), r"\1***"),
    (re.compile(r"(?i)(\bhttp-basic\.[\w.-]+\s+)" + _QUOTED_OR_WORD + r"(?:\s+" + _QUOTED_OR_WORD + r")?"),
     r"\1*** ***"),
    # twine upload -u name -p VALUE (also devpi, flit)
    (re.compile(r"(?i)(\b(?:twine|devpi|flit)\b[^\n;&|]*?\s-p\s*)" + _QUOTED_OR_WORD), r"\1***"),
    # --client-cert VALUE, --cert VALUE, --key VALUE
    (re.compile(r"(?i)(--(?:client-cert|cert|key|cacert|cert-key|private-key|keyfile|certfile)(?:=|\s+))"
                + _QUOTED_OR_WORD), r"\1***"),
    # echo SECRET | docker login --password-stdin, … --password-stdin <<< SECRET
    (re.compile(r"(?i)(\b(?:echo|printf)\s+(?:-[A-Za-z]+\s+)*)[^|\n]+?"
                r"(\s*\|[^|\n]*--(?:password-stdin|with-token|token-stdin|stdin-token))"),
     r"\1***\2"),
    (re.compile(r"(?i)(--(?:password-stdin|with-token|token-stdin|stdin-token)[^\n|;&]*<<<\s*)"
                + _QUOTED_OR_WORD), r"\1***"),
    # yarn config set npmAuthToken VALUE (and npmAuthIdent)
    (re.compile(r"(?i)(\bnpmAuth(?:Token|Ident)\s+)" + _QUOTED_OR_WORD), r"\1***"),
    # openssl enc -k VALUE, -pass pass:VALUE, -passin / -passout
    (re.compile(r"(?i)(\bopenssl\b[^\n;&|]*?\s-k\s+)" + _QUOTED_OR_WORD), r"\1***"),
    (re.compile(r"(?i)(-pass(?:in|out)?\s+)" + _QUOTED_OR_WORD), r"\1***"),
    # op signin --raw VALUE
    (re.compile(r"(?i)(\bop\s+signin\b[^\n;&|]*?--raw\s+)" + _QUOTED_OR_WORD), r"\1***"),
    # code handed to `python -c` / `node -e`: a string given to a name that says it is a secret
    (re.compile(r"(?i)(\b[A-Za-z0-9_.]*" + _SECRET_NAME + r"[A-Za-z0-9_]*\s*[:=]\s*)"
                r"(?:'[^'\n]*'|\"[^\"\n]*\"|\\\"[^\"\n]*\\\")"), r"\1'***'"),
    # `aws configure set aws_secret_access_key VALUE`: a secret's name, then its value
    (re.compile(r"(?i)(\b[a-z0-9_]*(?:secret|password|passwd)[a-z0-9_]*\s+)" + _QUOTED_OR_WORD), r"\1***"),
    # well-known token shapes, wherever they stand
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{6,}|github_pat_[A-Za-z0-9_]{6,}|glpat-[A-Za-z0-9_-]{6,}"
                r"|xox[abprs]-[A-Za-z0-9-]{6,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}"
                r"|ASIA[0-9A-Z]{12,}|npm_[A-Za-z0-9]{16,}|pypi-[A-Za-z0-9_-]{16,}"
                r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"
                r"|AIza[0-9A-Za-z_-]{20,}|hf_[A-Za-z0-9]{16,})"), "***"),
]


def _without_comments(text):
    """The text with trailing `# comments` removed: a comment is not part of
    what runs and may say anything. A `#` inside quotes, or inside a word
    (`page#section`), is not a comment."""
    out = []
    for line in text.split("\n"):
        quote, cut = None, len(line)
        for at, ch in enumerate(line):
            if quote:
                if ch == quote and (quote == "'" or line[at - 1:at] != "\\"):
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "#" and (at == 0 or line[at - 1] in " \t") and line[at + 1:at + 2] != "!":
                cut = at
                break
        out.append(line[:cut])
    return "\n".join(out)


# Several redaction patterns take quadratic time on one long run of
# non-space characters (a 40,000-character comment took 42-59 s, past the
# hook's 30 s timeout — fuzz finding F3), and no shortened form of a long
# command has proved safe to show: a cut or a skipped part can leave a
# password the redactions no longer recognise (two independent reviews found
# such leaks). So a command over _SHOW_EXACT characters is not shown at all;
# the decision record still names the package and the reason. Shorter
# commands are redacted and shown exactly as before.
_SHOW_EXACT = 4096


def show_command(command, limit=400):
    """The command as the decision log and side panel may show it: one line,
    credentials removed, cut to `limit`. For display only; never parsed."""
    text = str(command or "")
    if len(text) > _SHOW_EXACT:
        return f"[command of {len(text)} characters, not shown]"
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    text = " ".join(_without_comments(text).split())
    return text[:limit] + ("…" if len(text) > limit else "")


_ARCHIVE_SUFFIXES = (".whl", ".tar.gz", ".zip", ".tgz", ".tar.bz2", ".tar")


def _is_op(token):
    return bool(token) and all(ch in _PUNCT for ch in token)


def _tokenize(command):
    import shlex
    command = re.sub(r"\\\r?\n", "", command)       # backslash-newline joins the lines
    lex = shlex.shlex(command.replace("`", " ; "), posix=True, punctuation_chars=_PUNCT)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    return list(lex)


class _Cmd(list):
    """The words of one simple command, plus what the shell does around it."""

    def __init__(self):
        super().__init__()
        self.op = ""            # the operator before it (";", "&&", "|", …)
        self.here = None        # <<< word
        self.stdin_file = None  # < file
        self.has_heredoc = False
        self.writes = []        # > file, >> file, &> file


def _simple_commands(tokens):
    out, current, in_comment, pending, op = [], _Cmd(), False, None, ""

    def flush(next_op):
        nonlocal current, op
        if current or current.writes:
            current.op = op
            out.append(current)
            current, op = _Cmd(), next_op
        else:
            op += next_op           # `) | (`: every operator since the last command

    for token in tokens:
        if pending:                          # the file / fd a redirection points at
            kind, pending = pending, None
            if not _is_op(token):
                if kind == "write" and not token.isdigit() and token != "-":
                    current.writes.append(token)
                elif kind == "here":
                    current.here = token
                elif kind == "read":
                    current.stdin_file = token
                continue
        if _is_op(token) and ("<" in token or ">" in token) and not set(token) & set(";()\n"):
            # A redirection (2>&1, >file, 2>/dev/null, &>, <file, <<<word) belongs
            # to the command: it is not a package and does not end the command.
            fd = None
            if current and current[-1].isdigit():
                fd = current.pop()           # the file-descriptor number before it
            if token == "<>":
                # opened for reading and writing; on fd 1, 2 or one `exec` keeps open it is
                # written (`echo {} 1<> F`, `exec 3<> F`)
                pending = "read" if fd in (None, "0") else "write"
            elif token == "<<<":
                pending = "here"
            elif token.startswith("<<"):
                pending, current.has_heredoc = "heredoc", True
            elif token == "<":
                pending = "read"
            elif ">" in token and not token.startswith("<"):
                pending = "write"
            else:
                pending = "other"
            continue
        if _is_op(token):
            if "\n" in token:
                in_comment = False
            flush(token)
            continue
        if in_comment:
            continue
        if token.startswith("#") and not current:
            in_comment = True
            continue
        current.append(token)
    flush("")
    return out


def _prog_name(token):
    name = os.path.basename(token).lower()
    return name[:-4] if name.endswith(".exe") else name


def _is_installer(name):
    return bool(_PIP.match(name)) or name in _KNOWN_PROGRAMS or bool(_PYTHON.match(name))


def _program_index(tokens):
    """Index of the word that is actually run: past `VAR=x` assignments and
    wrappers such as sudo / env / time / xargs and their options."""
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if _ASSIGN.match(token):
            i += 1
            continue
        if _prog_name(token) in _WRAPPERS:
            valued = _WRAPPER_FLAGS.get(_prog_name(token), ())
            i += 1
            while i < len(tokens) and (tokens[i].startswith("-") or _ASSIGN.match(tokens[i])
                                       or re.match(r"^\d+(\.\d+)?[smhd]?$", tokens[i])):
                if tokens[i] == "--":
                    i += 1
                    break
                i += 2 if tokens[i] in valued and i + 1 < len(tokens) else 1
            continue
        break
    return i


def _is_url(arg):
    low = arg.lower()
    return ("://" in low or low.startswith(("git+", "git@", "github:", "gitlab:", "bitbucket:",
                                            "gist:", "hg+", "svn+", "bzr+", "jsr:")))


def _is_local_path(arg):
    return (arg.startswith((".", "/", "~", "file:")) or arg.endswith((".whl", ".tar.gz", ".zip",
                                                                      ".tgz")))


_AT_VERSION = re.compile(r"^v?(\d[A-Za-z0-9._+!-]*)$")


def _parse_pip_requirement(spec, res, raw):
    spec = spec.split(";", 1)[0].strip()
    match = _PIP_REQ.match(spec)
    if not match:
        res.ask("unparsed", raw)
        return
    name, _extras, rest = match.groups()
    rest = rest.strip()
    if rest.startswith("@"):
        # `name@1.2.3` (uvx, uv tool, uv add, poetry, pipx) names a version;
        # `name @ https://…` (PEP 508) names a download address.
        target = rest[1:].strip()
        if target.lower() == "latest":
            res.add("pip", name, None, raw)
        elif _AT_VERSION.match(target) and "*" not in target:
            res.add("pip", name, _AT_VERSION.match(target).group(1), raw)
        elif target[:1] in tuple("^~<>=!*0123456789") and "/" not in target:
            res.add("pip", name, None, raw, spec="@" + target[:79])      # a range
        else:
            res.ask("remote_url", raw)
        return
    if rest and rest[0] not in "=<>!~^":
        res.ask("unparsed", raw)
        return
    exact, spec = split_pip_version(rest)
    res.add("pip", name, exact, raw, spec=spec)


_STDIN_PATH = re.compile(r"^(-|/dev/stdin|/dev/fd/\d+|/proc/(self|\d+)/fd/\d+)$")


def _read_requirements(path, cwd, res, depth, read_file, raw):
    if depth > 3:
        res.ask("requirements_unread", raw)
        return
    if _STDIN_PATH.match(path):
        # The list comes in on standard input. It is only readable here when
        # the command text carries it (here-string, here-document, `< file`).
        text = res.stdin_text(read_file)
        if text is None:
            res.ask("requirements_unread", raw)
        else:
            _parse_requirements_text(text, cwd or ".", cwd, res, depth, read_file, raw)
        return
    if res.cwd_unknown and not os.path.isabs(os.path.expanduser(path)):
        res.ask("unknown_folder", raw)
        return
    full = path if os.path.isabs(path) else os.path.join(cwd or ".", path)
    full = os.path.expanduser(full)
    if res.changed_here(full):
        # Reading it now would judge the old contents, not what gets installed.
        res.ask("file_changed", raw)
    try:
        text = read_file(full)
    except (OSError, UnicodeDecodeError, ValueError):
        res.ask("requirements_unread", raw)
        return
    _parse_requirements_text(text, os.path.dirname(full), cwd, res, depth, read_file, raw)


def _parse_requirements_text(text, base, cwd, res, depth, read_file, raw):
    for line in text.replace("\\\n", " ").splitlines():
        line = re.split(r"(?:^|\s)#", line, maxsplit=1)[0].strip()   # pip: a comment is `#` after whitespace
        if not line or line.startswith("#"):
            continue
        if len(res.packages) > MAX_REQ_FILE_PACKAGES:
            res.ask("requirements_large", raw)
            return
        parts = line.split()
        flag = parts[0].split("=", 1)[0]
        if flag in ("-r", "--requirement"):
            nested = parts[1] if len(parts) > 1 else parts[0].split("=", 1)[-1]
            _read_requirements(os.path.join(base, nested), cwd, res, depth + 1, read_file, raw)
        elif flag in _PIP_INDEX_FLAGS or flag == "--trusted-host":
            res.ask("custom_index", raw)
        elif flag in ("-e", "--editable"):
            target = parts[1] if len(parts) > 1 else ""
            if _is_url(target):
                res.ask("remote_url", raw)
            else:
                res.note("local project install — not looked up")
        elif line.startswith("-"):
            if flag in _VERSION_SHIFT_FLAGS:
                res.uncertain = True
            continue
        elif _is_url(line):
            res.ask("remote_url", raw)
        elif _is_local_path(line):
            res.note("local file install — not looked up")
        else:
            res.line_hashes = _requirement_hashes(line)
            try:
                _parse_pip_requirement(re.split(r"\s--", line, maxsplit=1)[0], res, raw)
            finally:
                res.line_hashes = None


# Switches that turn installer hash checking off (uv). pip has none: once a
# requirement carries --hash, `pip install` requires and checks hashes.
_HASH_OFF_FLAGS = {"--no-verify-hashes", "--no-require-hashes"}
_HASH_OFF_ENV = ("UV_NO_VERIFY_HASHES",)
_REQ_HASH_OPTION = re.compile(r"(?:^|\s)--hash(?:=|\s+)(\S+)")
_REQ_HASH_VALUE = re.compile(r"^(sha256|sha384|sha512):([0-9A-Fa-f]+)$")
_REQ_HASH_LEN = {"sha256": 64, "sha384": 96, "sha512": 128}


def _requirement_hashes(line):
    """The `--hash=algo:hex` pins on one requirements line (which pip and uv
    enforce at install time) as one canonical string, or None when there are
    none or any is malformed. Used only as the verdict cache's artifact key."""
    values = _REQ_HASH_OPTION.findall(line)
    out = set()
    for value in values:
        match = _REQ_HASH_VALUE.match(value)
        if not match or len(match.group(2)) != _REQ_HASH_LEN[match.group(1)]:
            return None
        out.add(f"{match.group(1)}:{match.group(2).lower()}")
    return ",".join(sorted(out)) or None


_PIP_SWITCH_LETTERS = "UqvIhVy"
_PIP_VALUE_LETTERS = "rceiftdwCGp"
_REQ_FILE_NAME = re.compile(r"(?i)^[\w.-]*(requirements?|constraints?)[\w.-]*\.(txt|in|pip)$|^reqs?[\w.-]*\.txt$")


def _there(res, path):
    """Does this file or folder exist, seen from the folder the command runs in?"""
    if res.cwd_unknown and not os.path.isabs(os.path.expanduser(path)):
        return False
    try:
        return bool(res.exists(res.full(path)))
    except (OSError, ValueError):
        return False


def _parse_pip_args(args, res, cwd, read_file, raw, poetry=False, uv=False):
    # uv and pipx take options pip does not (`--python-platform linux`,
    # `--package web`): read with pip's table alone, their values were looked
    # up as packages (review 6). A misread value still fails toward blocking:
    # the shadow pass looks every option value up on the blocklist.
    # (`uv pip install` reaches here through the pip branch too, so the union is
    # used for every caller; no uv value flag is a pip switch.)
    value_flags = _PIPLIKE_VALUE_FLAGS
    i, saw_target = 0, False
    while i < len(args):
        arg = args[i]
        i += 1
        if arg.startswith("-") and arg != "-":
            flag, _, inline = arg.partition("=")
            takes = None
            if flag in _PIP_INDEX_FLAGS:
                res.ask("custom_index", raw)
                saw_target = True
                takes = "skip"
            elif flag in ("-r", "--requirement", "--requirements", "--with-requirements"):
                takes = "req"
            elif flag in ("-e", "--editable", "--with-editable"):
                takes = "editable"
            elif flag in ("--with", "--from"):
                takes = "skip" if poetry else "pkg"     # poetry: a dependency group
            elif flag in ("--upgrade-package", "-P"):
                takes = "pkg"
            elif flag in value_flags:
                takes = "skip"
            elif len(arg) > 2 and not arg.startswith("--"):
                # Short flags written together: `-rfile`, `-Ur file`, `-qUr file`,
                # `-Urfile`, `-ihttps://…`. The switches come first; the first
                # letter that takes a value takes the rest of the word, or the
                # next word. (Reading only `-r…` let `-Ur file` through unread.)
                letters = arg[1:]
                at = next((k for k, ch in enumerate(letters) if ch not in _PIP_SWITCH_LETTERS), None)
                if at is not None and letters[at] in _PIP_VALUE_LETTERS:
                    flag, inline = "-" + letters[at], letters[at + 1:].lstrip("=")
                    takes = {"r": "req", "e": "editable"}.get(letters[at], "skip")
                    if letters[at] in "if":
                        res.ask("custom_index", raw)
                    if letters[at] == "c":
                        res.uncertain = True    # a constraints file decides the versions
            if takes is None:
                continue
            value = inline
            if not value:
                if i >= len(args):
                    res.ask("unparsed", raw)
                    return saw_target
                value = args[i]
                i += 1
            saw_target = True
            if takes == "req":
                _read_requirements(value, cwd, res, 0, read_file, raw)
            elif takes == "editable":
                if _is_url(value):
                    res.ask("remote_url", raw)
                else:
                    res.note("local project install — not looked up")
            elif takes == "pkg":
                for one in value.split(","):
                    if one.strip():
                        _parse_pip_requirement(one, res, raw)
            continue
        saw_target = True
        if _is_url(arg):
            res.ask("remote_url", raw)
        elif _REQ_FILE_NAME.search(os.path.basename(arg)) and _there(res, arg):
            # a requirements file named without `-r` (or after a flag that was
            # misread): its lines are what would be installed
            _read_requirements(arg, cwd, res, 0, read_file, raw)
        elif _is_local_path(arg) or (_has_sep(arg) and not arg.startswith("@")):
            res.local(arg, raw, "path")
        else:
            _parse_pip_requirement(arg, res, raw)
    return saw_target


_NPM_TAGS = {"latest", "next", "beta", "alpha", "canary", "rc", "stable", "nightly", "dev",
             "experimental", "lts"}


def _parse_npm_spec(arg, res, raw):
    low = arg.lower()
    if low.startswith("npm:"):
        arg, low = arg[4:], low[4:]
    elif "@npm:" in low:
        # yarn / npm aliases. `alias@npm:real@1.2.3` installs the package `real`;
        # `name@npm:1.2.3` (yarn) installs `name` at that version.
        cut = low.index("@npm:")
        left, right = arg[:cut], arg[cut + 5:]
        if right[:1].isdigit() or right[:1] in "^~<>=*" or right.lower() in _NPM_TAGS:
            arg = f"{left}@{right}"
        else:
            arg = right
        low = arg.lower()
    if _is_url(arg):
        res.ask("remote_url", raw)
        return
    if _is_local_path(arg) and not arg.startswith("@"):
        res.local(arg, raw, "npm")
        return
    match = _NPM_NAME.match(arg)
    if not match:
        res.ask("remote_url" if "/" in arg else "unparsed", raw)
        return
    name, version = match.group(1).lower(), match.group(2)
    if version is not None and _is_url(version):
        res.ask("remote_url", raw)
        return
    exact, spec = split_npm_version(version)
    res.add("npm", name, exact, raw, spec=spec)


def _npm_positionals(args, res, raw, prog="npm"):
    out, i, valued = [], 0, _npm_value_flags(prog)
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            out.extend(args[i:])            # everything after `--` is a package, not an option
            break
        if arg.startswith("-"):
            flag, _, inline = arg.partition("=")
            if flag in _NPM_INDEX_FLAGS:
                res.ask("custom_index", raw)
                i += 0 if inline else 1
            elif flag in valued and not inline:
                i += 1
            continue
        out.append(arg)
    return out


def _parse_exec(args, res, cwd, raw, exists, prog="npm", named=()):
    """npx / pnpm dlx / bunx / yarn dlx: `-p pkg` values, else the first word.
    `named` are packages given before the subcommand (`pnpm --package=x dlx cmd`)."""
    explicit, i, first, valued = list(named), 0, None, _npm_value_flags(prog)
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            first = first or (args[i] if i < len(args) else None)
            break
        if arg.startswith("-"):
            flag, _, inline = arg.partition("=")
            if flag in ("-p", "--package"):
                value = inline or (args[i] if i < len(args) else "")
                i += 0 if inline else 1
                explicit.append(value)
            elif flag in _NPM_INDEX_FLAGS:
                res.ask("custom_index", raw)
                i += 0 if inline else 1
            elif flag in ("-c", "--call"):
                i += 0 if inline else 1         # a command line, parsed by _parse_simple
                first = first or "-"
            elif flag in valued and not inline:
                i += 1
            continue
        first = arg
        break
    if explicit:
        for spec in explicit:
            _parse_npm_spec(spec, res, raw)
    elif first and first != "-":
        bare = first.split("@")[0] if not first.startswith("@") else first
        if "/" not in bare and exists(os.path.join(cwd or ".", "node_modules", ".bin", bare)):
            return
        _parse_npm_spec(first, res, raw)


def _create_package(name):
    """`npm create vite` runs the package `create-vite`."""
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        if not rest:
            return f"{scope}/create"
        base, at, ver = rest.partition("@")
        return f"{scope}/create-{base}{at}{ver}"
    base, at, ver = name.partition("@")
    return f"create-{base}{at}{ver}"


def _subcommand(args, words):
    """Index of the first subcommand word; flags, their values and words only
    known at run time (`$OPTS`) may precede it."""
    for i, arg in enumerate(args):
        if arg in words:
            return i
        if arg.startswith("-") or arg.startswith("$"):
            continue
        if i > 0 and args[i - 1].startswith("-") and "=" not in args[i - 1]:
            continue
        return None
    return None


_PY_FLAG_CLUSTER = "bBdEhiIOPqRsSuvx"
# Inline code (`python -c …`) that starts another program. Code that only
# mentions an install in a string it prints or writes is not an install.
_CODE_EXECS = re.compile(r"system|subprocess|popen|check_call|check_output|\brun\(|\bcall\("
                         r"|spawn|exec|pip\.main|pip\._internal|pipmain|runpy|__import__", re.I)
# Words that make each installer fetch packages. Used by the safety net below:
# an invocation with one of these that the parsers read nothing from is put to
# the user instead of passing in silence.
_FETCH_VERBS = {
    "pip": {"install", "download", "wheel"},
    "npm": (_NPM_INSTALL - _NPM_LINK) | {"create", "init"},
    "uv": {"add", "tool", "pip"},
    "pipx": {"install", "inject", "run"},
    "poetry": {"add"}, "pdm": {"add"},
    "pipenv": {"install", "update", "upgrade"},
}
_ALL_FETCH_VERBS = set().union(*_FETCH_VERBS.values())
_UNSUPPORTED = {"conda": {"install", "create", "update", "upgrade", "env"},
                "mamba": {"install", "create", "update", "upgrade", "env"},
                "micromamba": {"install", "create", "update", "upgrade", "env"},
                "pixi": {"add", "install", "update", "upgrade", "global"},
                "cargo": {"install", "binstall"}, "gem": {"install", "update"},
                "go": {"install", "get"}}
_REGISTRY_KEY = re.compile(r"regist|index|proxy|cafile|ca-file|strict-ssl|find-links|trusted-host"
                           r"|channel|repositor|pypi|\bpre\b|constraint|\btag\b|before", re.I)


def _family(prog):
    if _PIP.match(prog) or prog == "easy_install":
        return "pip"
    if prog in ("npm", "pnpm", "yarn", "bun"):
        return "npm"
    return prog if prog in _FETCH_VERBS else None


def _config_change(prog, args):
    """`pip config set …`, `npm config set registry …`, `poetry source add …`:
    commands that change where later installs download from."""
    plain = [a for a in args if not a.startswith("-")]
    if _PIP.match(prog):
        return plain[:1] == ["config"] and plain[1:2] and plain[1] in ("set", "unset", "edit")
    if prog in ("npm", "pnpm", "yarn", "bun"):
        if plain[:1] in (["config"], ["c"]) and plain[1:2] and plain[1] in (
                "set", "delete", "rm", "edit", "unset"):
            return plain[1] == "edit" or any(_REGISTRY_KEY.search(a) for a in args)
        return plain[:1] == ["set"] and any(_REGISTRY_KEY.search(a) for a in args)
    if prog == "poetry":
        return (plain[:1] == ["config"] and any(_REGISTRY_KEY.search(a) for a in plain[1:])) or \
            plain[:2] == ["source", "add"]
    if prog == "pdm":
        return plain[:1] == ["config"] and any(_REGISTRY_KEY.search(a) for a in plain[1:])
    if prog in _UNSUPPORTED:
        return plain[:1] == ["config"] and any(_REGISTRY_KEY.search(a) for a in args)
    return False


def _dispatch(prog, args, res, cwd, read_file, exists, raw):
    """Parse one installer invocation. While it runs, `res.uncertain` says
    whether a flag on this command changes which version a name resolves to."""
    before, size = res.uncertain, res.touched
    res.uncertain = before or any(a.split("=", 1)[0] in _VERSION_SHIFT_FLAGS for a in args)
    try:
        if _config_change(prog, args):
            res.ask("index_config", raw)
            return
        _dispatch_program(prog, args, res, cwd, read_file, exists, raw)
        if res.touched == size:
            _safety_net(prog, args, res, raw)
        _collect_shadow(prog, args, res, raw, res.touched > size)
    finally:
        res.uncertain = before


# ── a misread flag must fail toward blocking ─────────────────────────────────
# The parsers above decide, flag by flag, which words are packages. Every
# time a flag table was wrong (`pnpm add -w evil`: `-w` read as taking a
# value), the package after it was never looked up and the install passed in
# silence. So every OTHER word of an install command that could be a package
# name is kept here as a "shadow" candidate. decide() asks the blocklist about
# each one: a hit is a block like any other; anything else — not listed, not
# found, lookup failed — is nothing at all (no line, no question), which is
# what keeps this from raising false alarms. A shadow candidate never counts
# as "the package was checked".
_SHADOW_CAP = 12
_SHADOW_STOP = {"true", "false", "yes", "no", "on", "off", "null", "none", "all", "auto",
                "always", "never", "debug", "info", "warn", "error", "silent", "verbose",
                "notice", "silly", "http", "timing", "latest", "next", "dev", "test", "tests",
                "docs", "lint", "main", "prod", "production", "staging", "default", "stable",
                "beta", "alpha", "canary", "rc", "nightly", "eager", "user", "global", "json"}
_SHADOW_SUFFIXES = (".txt", ".in", ".json", ".toml", ".cfg", ".ini", ".py", ".js", ".ts",
                    ".mjs", ".cjs", ".lock", ".yml", ".yaml", ".whl", ".zip", ".gz", ".tgz",
                    ".md", ".log", ".sh", ".conf", ".pem", ".crt", ".key", ".html", ".xml",
                    ".csv", ".pip", ".tar", ".bz2", ".exe")
_SHADOW_PIP = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?)(?:\[[A-Za-z0-9._, -]*\])?"
                         r"(?:(?:===?|@)v?([A-Za-z0-9][A-Za-z0-9._+!-]{0,40}))?$")
_SHADOW_NPM = re.compile(r"^(@[a-z0-9~-][a-z0-9._~-]*/[a-z0-9~-][a-z0-9._~-]*|[a-z0-9~-][a-z0-9._~-]*)"
                         r"(?:@[=v]?(\d[\w.+-]{0,40}))?$", re.I)
_SHADOW_FETCH_VERBS = {"install", "i", "add", "download", "wheel", "update", "up", "upgrade",
                       "inject", "reinstall", "runpip", "self", "plugin", "tool", "pip", "sync",
                       "lock", "pack", "create", "init", "link", "ln", "it", "install-test",
                       "exec", "x", "dlx", "run", "global", "a", "in", "ins", "inst", "isntall"}
_SHADOW_RUN_VERBS = {"run", "exec", "x", "dlx"}
_SHADOW_WORDS = _SHADOW_FETCH_VERBS | _NPM_INSTALL | _NPM_MANIFEST | {
    "compile", "cache", "config", "workspace", "remove", "uninstall", "rm", "un", "show",
    "list", "ls", "freeze", "check", "outdated", "search", "view", "audit", "dedupe", "prune",
    "rebuild", "test", "start", "build", "publish", "version", "help", "env", "venv", "python",
    "export", "tree", "why", "info", "store", "import"}
_FLAG_SHAPE = re.compile(r"^--?[A-Za-z][A-Za-z0-9-]{0,30}$")
# What an option's value is NOT looked up for. The rule stays "a misread flag
# fails toward blocking": a value is dropped only when the word itself shows
# it is what the option expects — one of the option's own fixed words, an
# address, a Python version, a platform name. (`--fork-strategy
# requires-python` collided with a package name on the blocklist.) Any other
# word after an option is asked about by name.
_SHADOW_ENUM_VALUES = {
    "--fork-strategy": {"fewest", "requires-python"},
    "--resolution": {"highest", "lowest", "lowest-direct"},
    "--prerelease": {"disallow", "allow", "if-necessary", "explicit", "if-necessary-or-explicit"},
    "--index-strategy": {"first-index", "first-match", "unsafe-first-match", "unsafe-best-match",
                         "unsafe-any-match"},
    "--keyring-provider": {"disabled", "subprocess", "auto", "import"},
    "--link-mode": {"clone", "copy", "hardlink", "symlink"},
    "--color": {"auto", "always", "never"},
    "--python-preference": {"only-managed", "managed", "system", "only-system"},
    "--python-downloads": {"automatic", "manual", "never"},
    "--python-fetch": {"automatic", "manual", "never"},
    "--upgrade-strategy": {"eager", "only-if-needed", "to-satisfy-only"},
    "--progress-bar": {"on", "off", "raw"},
    "--exists-action": {"s", "i", "w", "b", "a", "switch", "ignore", "wipe", "backup", "abort"},
    "--root-user-action": {"warn", "ignore"},
    "--implementation": {"pp", "jy", "cp", "ip", "py"},
    "--loglevel": {"silent", "error", "warn", "notice", "http", "info", "verbose", "silly",
                   "timing", "debug"},
    "--reporter": {"default", "append-only", "ndjson", "silent"},
    "--omit": {"dev", "optional", "peer"},
    "--include": {"prod", "dev", "optional", "peer"},
    "--install-strategy": {"hoisted", "nested", "shallow", "linked"},
    "--node-linker": {"isolated", "hoisted", "pnp"},
    "--access": {"public", "restricted"},
    "--location": {"default", "user", "global", "project"},
    "--backend": {"clonefile", "hardlink", "symlink", "copyfile", "uv", "pip"},
    "--torch-backend": {"auto", "cpu"},
    "--mode": {"skip-build", "update-lockfile"},
    "--save-prefix": {"none"},
}
_SHADOW_HOST_FLAGS = {"--trusted-host", "--allow-insecure-host", "--proxy", "--https-proxy",
                      "--registry", "--noproxy"}
_SHADOW_PYTHON_FLAGS = {"--python", "-p", "--python-version"}
_SHADOW_PLATFORM_FLAGS = {"--platform", "--python-platform", "--os", "--cpu", "--libc", "--abi",
                          "--torch-backend"}
_PY_VALUE = re.compile(r"^(?:python|pypy|cpython|graalpy|cp|pp|py)?-?\d[\d.]*t?$")
_PLATFORM_VALUE = re.compile(r"linux|darwin|macos|windows|win32|win_|manylinux|musllinux|x86|x64"
                             r"|amd64|aarch64|arm64|armv|ia32|ppc64|s390x|riscv|glibc|musl|^cu\d+$"
                             r"|^cp\d+|^abi3$|^none$|^any$")
# Stricter choice, off by default: with this True the value of an option that
# names a path, file, folder, number or group (the tables below) is compared
# only with the blocklist that ships inside stillrunning and never sent to
# the server. It is off because it narrows the cover above: a blocklisted
# name standing where such a value goes (`pip install --target NAME`) would
# then be checked against the shipped list only.
SHADOW_VALUES_LOCAL_ONLY = False
_SHADOW_LOCAL_FLAGS = {
    "--target", "--prefix", "--root", "--src", "--cache-dir", "--cache", "--log", "--cert",
    "--client-cert", "--key", "--cafile", "--ca", "--retries", "--timeout", "--report", "--dest",
    "--wheel-dir", "--directory", "--project", "--script", "--config-file", "--env-file",
    "--cwd", "--dir", "--store-dir", "--virtual-store-dir", "--modules-dir", "--lockfile-dir",
    "--modules-folder", "--cache-folder", "--link-folder", "--global-folder",
    "--preferred-cache-folder", "--network-timeout", "--network-concurrency",
    "--child-concurrency", "--workspace-concurrency", "--fetch-retries", "--fetch-timeout",
    "--maxsockets", "--logs-dir", "--logs-max", "--depth", "--userconfig", "--globalconfig",
    "--lockfile", "--global-dir", "--global-bin-dir", "--tool-dir", "--tool-bin-dir",
    "--group", "--dev-group", "--only-group", "--no-group", "--extra", "--no-extra",
}
_SHADOW_LOCAL_SHORT_PIP = {"-t", "-d"}


def _shadow_kind(eco, flag, word):
    """How a word that follows `flag` is treated: "skip" (plainly the
    option's own kind of value), "local" (shipped blocklist only) or "full"."""
    if not flag:
        return "full"
    low = word.lower()
    if low in _SHADOW_ENUM_VALUES.get(flag, ()):
        return "skip"
    if flag in _SHADOW_HOST_FLAGS and ("." in word or ":" in word or low == "localhost"):
        return "skip"
    if flag in _SHADOW_PYTHON_FLAGS and (eco == "pip" or flag != "-p") and _PY_VALUE.match(low):
        return "skip"
    if flag in _SHADOW_PLATFORM_FLAGS and _PLATFORM_VALUE.search(low):
        return "skip"
    if SHADOW_VALUES_LOCAL_ONLY and (flag in _SHADOW_LOCAL_FLAGS
                                     or (eco == "pip" and flag in _SHADOW_LOCAL_SHORT_PIP)):
        return "local"
    return "full"


def _runner_tables(prog):
    """(options known to take no value, options known to take one) for the
    program a runner command starts with."""
    if prog in ("uv", "uvx", "pipx"):
        return _RUNNER_SWITCHES["uv"], (_PIPLIKE_VALUE_FLAGS | _PIP_INDEX_FLAGS | {
            "--with", "--from", "--spec", "-w", "--with-requirements", "--with-editable"})
    family = _NPM_TOOL.get(prog, prog)
    return _RUNNER_SWITCHES.get(family, _RUNNER_SWITCHES["npm"]), (
        _npm_value_flags(prog) | _NPM_INDEX_FLAGS | {"-p", "--package", "-c", "--call"})


def _known_names(res):
    """{(eco, normalized name)} of res.packages and res.shadow. Both lists only
    grow (append), so the set is brought up to date from where it was left
    instead of rebuilt for every simple command (that made `pip install a ;
    pip install b ; …` quadratic). A key added here by _collect_shadow is
    always appended to res.shadow right after, so the set never holds a name
    the lists do not."""
    done_packages, done_shadow, names = res.known_names
    for p in res.packages[done_packages:]:
        names.add((p["eco"], normalize(p["eco"], p["name"])))
    for s in res.shadow[done_shadow:]:
        names.add((s["eco"], normalize(s["eco"], s["name"])))
    res.known_names = (len(res.packages), len(res.shadow), names)
    return names


def _collect_shadow(prog, args, res, raw, touched):
    if _PIP.match(prog) or prog in ("easy_install", "uv", "uvx", "pipx", "poetry", "pdm", "pipenv"):
        eco, pattern = "pip", _SHADOW_PIP
    elif prog in ("npm", "pnpm", "yarn", "bun", "npx", "pnpx", "bunx"):
        eco, pattern = "npm", _SHADOW_NPM
    else:
        return
    plain = [a for a in args if not a.startswith(("-", "$"))]
    verb = plain[0] if plain else ""
    if not touched and verb not in _SHADOW_FETCH_VERBS \
            and not any(word in ("install", "add") for word in plain[1:3]):
        return                          # `npm run build`, `pip show x`: nothing is fetched
    # For a runner (`npx tool args`, `uv run cmd args`, `npm exec cmd`), the
    # words from the command on belong to that command, not to the installer.
    runner = prog in ("npx", "pnpx", "bunx", "uvx") or any(w in _SHADOW_RUN_VERBS for w in plain[:2])
    run_at = next((i for i, a in enumerate(args) if a in _SHADOW_RUN_VERBS), -1) if runner else None
    have = _known_names(res)
    switches, valued = _runner_tables(prog) if runner else (frozenset(), frozenset())
    after_flag, unsure, last = None, False, False
    for index, arg in enumerate(args):
        if last:
            break
        if arg == "--":
            after_flag = None
            continue
        word, where = arg, after_flag
        if arg.startswith("-"):
            flag, eq, value = arg.partition("=")
            if not (eq and value):
                after_flag = arg
                continue
            word, where = value, flag
        elif arg.startswith("$"):
            after_flag = None
            continue
        elif runner and index > run_at:
            if after_flag is None:
                # The first bare word. Normally it is the command being run and
                # the parser has looked it up. But if an option before it was
                # one this table does not know, the parser may have taken that
                # option's value for the command and this word is the real one:
                # look at it too, then stop — what follows belongs to it.
                if not unsure:
                    break
                last = True
            elif after_flag in switches:
                last = True             # a switch takes no value: this word IS the command
            elif after_flag not in valued:
                unsure = True           # value of an unknown option, or the command itself
        after_flag = None
        kind = _shadow_kind(eco, where if where and _FLAG_SHAPE.match(where) else None, word)
        if kind == "skip":
            continue
        low = word.lower()
        if len(word) < 2 or len(word) > 120 or low in _SHADOW_STOP or low in _SHADOW_WORDS:
            continue
        if _is_url(word) or word.startswith((".", "/", "~")) or low.endswith(_SHADOW_SUFFIXES):
            continue
        if "/" in word and not word.startswith("@"):
            continue
        if re.match(r"^v?\d[\d.]*[a-z]{0,2}\d*$", low):
            continue                    # a number or a version: `3.12`, `20`, `1.2.3rc1`
        match = pattern.match(word)
        if not match:
            continue
        name = match.group(1).lower() if eco == "npm" else match.group(1)
        key = (eco, normalize(eco, name))
        if key in have or _there(res, word):
            continue                    # already looked up, or a file / folder that is there
        have.add(key)
        res.shadow.append({
            "eco": eco, "name": name, "version": match.group(2), "raw": raw,
            "local_only": kind == "local",
            "where": (f"the value of `{where}`" if where and _FLAG_SHAPE.match(where)
                      else "a word in the install command")})


def _safety_net(prog, args, res, raw):
    """The parsers read nothing from this installer invocation. If it still
    plainly fetches packages, look up what can be read from it and put the
    rest to the user — it never passes in silence."""
    family = _family(prog)
    if family is None:
        return
    verbs = _FETCH_VERBS[family]
    if prog == "easy_install":
        return
    plain = [(i, a) for i, a in enumerate(args) if not a.startswith("-")]
    first = next(((i, a) for i, a in plain if not a.startswith("$")), None)
    hidden = bool(plain) and plain[0][1].startswith("$")
    if hidden:
        # `pip $(echo install) x`, `npm $CMD x`: the subcommand is decided at run time.
        res.ask("dynamic_command", raw)
        rest = [a for i, a in plain if not a.startswith("$")]
        if rest and rest[0] in _ALL_FETCH_VERBS:
            rest = rest[1:]
    elif first is not None and first[1] in verbs:
        rest = [a for i, a in plain if i > first[0] and not a.startswith("$")]
        if family == "uv" and first[1] in ("pip", "tool"):
            if not rest or rest[0] not in ("install", "run"):
                return
            rest = rest[1:]
        if not rest:
            return
        res.ask("unparsed", raw)
    else:
        return
    for word in rest[:20]:
        if _is_url(word) or _is_local_path(word) or _has_sep(word) and not word.startswith("@"):
            continue
        if family == "npm":
            if _NPM_NAME.match(word):
                _parse_npm_spec(word, res, raw)
        elif _PIP_REQ.match(word):
            _parse_pip_requirement(word, res, raw)


def _dispatch_program(prog, args, res, cwd, read_file, exists, raw):
    if _PYTHON.match(prog):
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-W", "-X", "--check-hash-based-pycs"):     # these take a value
                i += 2
                continue
            cluster = (re.match(r"^-([A-Za-z]*?)([mc])(.*)$", arg)
                       if not arg.startswith("--") else None)
            if cluster and all(ch in _PY_FLAG_CLUSTER for ch in cluster.group(1)):
                kind, inline = cluster.group(2), cluster.group(3)
                if inline:
                    value, rest = inline, args[i + 1:]
                elif i + 1 < len(args):
                    value, rest = args[i + 1], args[i + 2:]
                else:
                    return
                if kind == "m":
                    module = value.lower()
                    if module.endswith(".__main__"):
                        module = module[:-9]
                    module = module.split(".", 1)[0] if module.startswith("pip.") else module
                    if _PIP.match(module) or module in _KNOWN_PROGRAMS:
                        _dispatch(module, rest, res, cwd, read_file, exists, raw)
                    elif module.startswith("$"):
                        if next((a for a in rest if not a.startswith("-")), "") in _INSTALL_VERBS:
                            res.ask("dynamic_command", raw)
                elif looks_like_install(value) and _CODE_EXECS.search(value):
                    res.ask("unparsed", raw)     # inline code that starts an installer
                elif _CODE_WRITES.search(value) and any(
                        os.path.basename(name) in INDEX_CONFIG_FILES
                        for name in re.findall(r"""['"]([^'"\n]{1,300})['"]""", value)):
                    res.ask("index_config", raw)    # inline code that rewrites .npmrc / pip.conf
                return
            if not arg.startswith("-"):
                return                                          # a script: not an install
            i += 1
        return
    if prog in _UNSUPPORTED:
        idx = _subcommand(args, _UNSUPPORTED[prog])
        if idx is not None:
            if args[idx] == "env" and not any(a in ("create", "update") for a in args[idx + 1:idx + 3]):
                return
            named = [a for a in args[idx + 1:] if not a.startswith("-")]
            if prog in ("cargo", "go") and ("--path" in args or (
                    named and all(a.startswith((".", "/")) for a in named)) or
                    (prog == "go" and not named)):
                return                          # builds the local project: nothing is fetched by name
            res.ask("unsupported_installer", raw)
        return
    if prog == "pipenv":
        idx = _subcommand(args, {"install", "update", "upgrade", "sync"})
        if idx is not None and args[idx] == "sync":
            res.note("installs everything in the lockfile — those packages were not looked up")
        elif idx is not None:
            if not _parse_pip_args(args[idx + 1:], res, cwd, read_file, raw):
                res.note("installs everything in the Pipfile — those packages were not "
                         "looked up")
        return
    if prog == "easy_install":
        _parse_pip_args(args, res, cwd, read_file, raw)
        return
    if _PIP.match(prog):
        idx = _subcommand(args, {"install", "download", "wheel"})
        if idx is not None:
            # pip install checks every file against the --hash pins once any
            # requirement has one (implied --require-hashes); pip has no switch
            # that turns that off. download / wheel do not install: not counted.
            res.hash_enforced = args[idx] == "install"
            try:
                _parse_pip_args(args[idx + 1:], res, cwd, read_file, raw)
            finally:
                res.hash_enforced = False
        return
    if prog == "uv":
        idx = _subcommand(args, {"pip", "add", "tool", "run", "sync", "lock"})
        if idx is None:
            return
        sub, rest = args[idx], args[idx + 1:]
        if sub == "sync":
            res.note("installs everything in the lockfile — those packages were not looked up")
        if sub in ("sync", "lock"):
            # `uv sync --upgrade-package x`, `uv lock -P x`: x is fetched by name
            for at, arg in enumerate(rest):
                flag, eq, inline = arg.partition("=")
                if flag in ("--upgrade-package", "-P"):
                    value = inline if eq else (rest[at + 1] if at + 1 < len(rest) else "")
                    if value:
                        _parse_pip_requirement(value, res, raw)
        if sub == "pip":
            j = _subcommand(rest, {"install", "sync", "compile"})
            # review 2 (R1b): uv can switch hash checking off from a config file
            # (uv.toml / pyproject [tool.uv.pip] verify-hashes = false, user or
            # system level) that the hook does not see, so a uv hash never binds
            # the artifact for the cache. Only pip, which has no off switch, does.
            res.hash_enforced = False
            try:
                if j is not None and rest[j] == "install":
                    _parse_pip_args(rest[j + 1:], res, cwd, read_file, raw, uv=True)
                elif j is not None and rest[j] == "sync":
                    for value in [a for a in rest[j + 1:] if not a.startswith("-")]:
                        _read_requirements(value, cwd, res, 0, read_file, raw)
            finally:
                res.hash_enforced = False
        elif sub == "add":
            _parse_pip_args(rest, res, cwd, read_file, raw, uv=True)
        elif sub == "tool":
            j = _subcommand(rest, {"install", "run", "upgrade"})
            if j is not None and rest[j] == "upgrade":
                _parse_pip_args(rest[j + 1:], res, cwd, read_file, raw, uv=True)
            elif j is not None:
                _parse_uvx(rest[j + 1:], res, raw, run=rest[j] == "run", cwd=cwd,
                           read_file=read_file)
        elif sub == "run":
            _parse_uv_run(rest, res, cwd, read_file, raw)
        return
    if prog == "uvx":
        _parse_uvx(args, res, raw)
        return
    if prog == "pipx":
        idx = _subcommand(args, {"install", "run", "inject", "install-all", "runpip",
                                 "upgrade", "reinstall"})
        if idx is None:
            return
        rest = args[idx + 1:]
        if args[idx] == "inject":
            names = [a for a in rest if not a.startswith("-")]
            rest = names[1:]
        if args[idx] == "run":
            _parse_uvx(rest, res, raw)
        elif args[idx] == "runpip":
            # `pipx runpip <app> install x`: pip, run inside that app's environment
            app = next((k for k, a in enumerate(rest) if not a.startswith("-")), None)
            if app is not None:
                _dispatch_program("pip", rest[app + 1:], res, cwd, read_file, exists, raw)
        elif args[idx] in ("upgrade", "reinstall"):
            _parse_pip_args(rest, res, cwd, read_file, raw, uv=True)
        else:
            _parse_pip_args(rest, res, cwd, read_file, raw, uv=True)
        return
    if prog in ("poetry", "pdm"):
        idx = _subcommand(args, {"add", "install", "sync", "update", "self", "plugin"})
        if idx is None:
            return
        sub, rest = args[idx], args[idx + 1:]
        if sub in ("self", "plugin"):
            # `poetry self add x`, `pdm self add x`, `pdm plugin add x`: x is
            # installed into the tool's own environment
            j = _subcommand(rest, {"add"})
            if j is not None:
                _parse_pip_args(rest[j + 1:], res, cwd, read_file, raw, poetry=True)
        elif sub == "add":
            _parse_pip_args(rest, res, cwd, read_file, raw, poetry=True)
        elif sub == "update":
            seen = res.touched
            _parse_pip_args(rest, res, cwd, read_file, raw, poetry=True)
            if res.touched == seen:         # no package named: everything in the lockfile
                res.note("installs everything in the lockfile — those packages were not looked up")
        else:
            res.note("installs everything in the lockfile — those packages were not looked up")
        return
    if prog in ("npx", "bunx", "pnpx"):
        _parse_exec(args, res, cwd, raw, exists, prog)
        return
    if prog in ("npm", "pnpm", "yarn", "bun"):
        if prog == "bun" and args[:1] == ["a"]:
            args = ["add"] + list(args[1:])
        if prog == "yarn" and args[:1] == ["global"]:
            args = args[1:]
        if prog == "yarn" and args[:1] == ["workspace"] and len(args) > 2:
            args = args[2:]
        words = _NPM_INSTALL | _NPM_MANIFEST | {"exec", "x", "dlx", "create", "init"}
        if prog == "npm":
            words = words | {"pack", "cache"}
        idx = _subcommand(args, words)
        if idx is None:
            if prog == "yarn" and not [a for a in args if not a.startswith("-")]:
                res.note("installs everything in package.json — those packages were not looked up")
            return
        sub, rest = args[idx], args[idx + 1:]
        if any(a.split("=", 1)[0] in _NPM_INDEX_FLAGS for a in args[:idx]):
            res.ask("custom_index", raw)
        if sub in ("pack", "cache"):
            # `npm pack x`, `npm cache add x`: x is downloaded by name
            names = _npm_positionals(rest, res, raw, prog)
            if sub == "cache":
                names = names[1:] if names[:1] == ["add"] else []
            for spec in names:
                _parse_npm_spec(spec, res, raw)
        elif sub in ("exec", "x", "dlx"):
            # `pnpm --package=x dlx cmd`: the package is named before the subcommand
            named = []
            for at, arg in enumerate(args[:idx]):
                flag, eq, inline = arg.partition("=")
                if flag in ("-p", "--package"):
                    value = inline if eq else (args[at + 1] if at + 1 < idx else "")
                    if value:
                        named.append(value)
            _parse_exec(rest, res, cwd, raw, exists, prog, named)
        elif sub in ("create", "init"):
            names = _npm_positionals(rest, res, raw, prog)
            if names:
                _parse_npm_spec(_create_package(names[0]), res, raw)
        elif sub in _NPM_MANIFEST:
            res.note("installs everything in the lockfile — those packages were not looked up")
        else:
            names = _npm_positionals(rest, res, raw, prog)
            if not names and sub not in _NPM_LINK:
                res.note("installs everything in package.json — those packages were not looked up")
            for spec in names:
                _parse_npm_spec(spec, res, raw)


def _parse_uv_run(args, res, cwd, read_file, raw):
    """`uv run [--with pkg | -w pkg | --with-requirements file] command …`:
    the packages it adds for the run. The command itself is parsed separately."""
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if not arg.startswith("-"):
            return                      # the command to run starts here
        flag, _, inline = arg.partition("=")
        if len(arg) > 2 and arg.startswith("-w") and not arg.startswith("--"):
            flag, inline = "-w", arg[2:]
        if flag in ("--with", "-w", "--from", "--with-requirements", "--with-editable"):
            value = inline or (args[i] if i < len(args) else "")
            i += 0 if inline else 1
            if not value:
                res.ask("unparsed", raw)
            elif flag == "--with-requirements":
                _read_requirements(value, cwd, res, 0, read_file, raw)
            elif flag == "--with-editable":
                res.note("local project install — not looked up")
            else:
                for one in value.split(","):
                    if _is_url(one):
                        res.ask("remote_url", raw)
                    elif one.strip():
                        _parse_pip_requirement(one, res, raw)
        elif flag in _PIP_INDEX_FLAGS:
            res.ask("custom_index", raw)
            i += 0 if inline else 1
        elif flag in _PIPLIKE_VALUE_FLAGS and not inline:
            i += 1


def _parse_uvx(args, res, raw, run=True, cwd=None, read_file=None):
    """`uvx tool …`, `uv tool run tool …` (run=True: the words after the tool
    are the tool's own) and `uv tool install tool --with extra` (run=False:
    every later `--with` is installed too)."""
    first, i = None, 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg.startswith("-"):
            flag, _, inline = arg.partition("=")
            if len(arg) > 2 and arg.startswith("-w") and not arg.startswith("--"):
                flag, inline = "-w", arg[2:]
            if flag in ("--with", "--from", "--spec", "-w"):
                value = inline or (args[i] if i < len(args) else "")
                i += 0 if inline else 1
                for one in value.split(","):
                    if _is_url(one):
                        res.ask("remote_url", raw)
                    elif one.strip():
                        _parse_pip_requirement(one, res, raw)
                if flag in ("--from", "--spec"):
                    first = first or "-"        # the package is named; the next word is its command
            elif flag == "--with-requirements":
                value = inline or (args[i] if i < len(args) else "")
                i += 0 if inline else 1
                if value and read_file is not None:
                    _read_requirements(value, cwd, res, 0, read_file, raw)
                else:
                    res.ask("requirements_unread", raw)
            elif flag == "--with-editable":
                i += 0 if inline else 1
                res.note("local project install — not looked up")
            elif flag in _UV_PACKAGE_FLAGS:
                # `--upgrade-package x`, `--reinstall-package x`: x is fetched by name
                value = inline or (args[i] if i < len(args) else "")
                i += 0 if inline else 1
                if value and not _is_url(value):
                    _parse_pip_requirement(value, res, raw)
            elif flag in _PIP_INDEX_FLAGS:
                res.ask("custom_index", raw)
                i += 0 if inline else 1
            elif flag in _PIPLIKE_VALUE_FLAGS and not inline:
                i += 1
            continue
        if first is None or (not run and first != "-"):
            if _is_url(arg):
                res.ask("remote_url", raw)
            elif _is_local_path(arg):
                res.note("local path run — not looked up")
            else:
                _parse_pip_requirement(arg, res, raw)
        if run:
            break
        first = first or arg


# Commands whose arguments are text or other ecosystems' packages: an
# installer's name among them is not an install (`grep pip install README`,
# `apt install npm`, `git commit -m …`).
_DATA_COMMANDS = {
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "bat", "less", "more",
    "head", "tail", "man", "info", "which", "whereis", "whatis", "type", "hash", "alias", "git",
    "gh", "hub", "glab", "sed", "awk", "gawk", "cut", "tr", "sort", "uniq", "wc", "ls", "ll",
    "cd", "pushd", "popd", "mkdir", "touch", "rm", "rmdir", "cp", "mv", "ln", "diff", "cmp",
    "tee", "curl", "wget", "jq", "yq", "test", "[", "[[", "read", "basename", "dirname",
    "realpath", "readlink", "stat", "file", "du", "df", "chmod", "chown", "tar", "zip", "unzip",
    "gzip", "gunzip", "apt", "apt-get", "aptitude", "apt-cache", "dpkg", "brew", "dnf", "yum",
    "zypper", "pacman", "apk", "snap", "flatpak", "port", "nix", "nix-env",
    "bundle", "composer", "dotnet", "mvn", "gradle", "make", "gmake", "cmake", "ninja", "bazel",
    "code", "vim", "vi", "nvim", "nano", "emacs", "open", "xdg-open", "history", "unset", "true",
    "false", ":", "sleep", "date", "kill", "pkill", "ps", "pgrep", "tree", "fd", "wait", "exit",
    "return", "pytest", "tox", "ruff", "black", "mypy", "flake8", "pylint", "eslint", "tsc",
    "rustc", "gcc", "clang", "java", "javac", "claude", "systemctl", "journalctl", "service",
    "crontab", "ssh-keygen", "openssl", "md5sum", "sha256sum", "xxd", "column", "paste", "comm",
    "rev", "tac", "nl", "fold", "fmt", "pr", "seq", "yes", "printenv", "locate", "updatedb",
}
# Programs that run their command somewhere else (a container, another host):
# only quoted shell text handed to them is parsed, as before.
_REMOTE_RUNNERS = {"docker", "podman", "nerdctl", "kubectl", "ssh", "wsl", "lxc", "vagrant",
                   "docker-compose"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"}
# Programs that take a command as ONE quoted string and run it.
_STRING_RUNNERS = _SHELLS | {"eval", "su", "ssh", "watch", "parallel", "script", "flock", "tmux",
                             "runuser", "busybox", "trap", "nix-shell", "sg", "pkexec",
                             "screen", "nsenter", "unshare", "chroot", "setsid", "systemd-run"}
_EXPORTERS = {"export", "declare", "typeset", "readonly", "local", "setenv"}


def _is_shell_text(tokens):
    """Does this command hand a quoted string to something that runs it
    (`bash -c '…'`, `su -c '…'`, `ssh host '…'`, `eval '…'`)? Quoted text given
    to anything else is data: a commit message, a search pattern, a file's
    contents."""
    names = [_prog_name(t) for t in tokens if " " not in t and "\n" not in t]
    if any(name in _STRING_RUNNERS for name in names):
        return True
    # `env -S 'cmd args'` splits the string and runs it
    return "env" in names and any(t == "--split-string" or t.startswith("--split-string=")
                                  or re.match(r"^-[A-Za-z]*S", t) for t in tokens)


def _shell_operands(after):
    """A shell's own operands (the script file and its arguments), past its
    options. `-o NAME`, `+o NAME`, `-O NAME`, `--rcfile F`, `--init-file F` and
    clusters ending in `o` (`-euxo pipefail`) take the next word: counting
    that word as a script file hid `bash -euo pipefail <<EOF …`."""
    out, i = [], 0
    while i < len(after):
        arg = after[i]
        i += 1
        if arg == "--":
            out.extend(after[i:])
            break
        if arg in ("--rcfile", "--init-file"):
            i += 1
        elif arg.startswith("--"):
            continue
        elif arg[:1] in "-+" and len(arg) > 1:
            if arg[-1] in "oO":
                i += 1
        else:
            out.append(arg)
    return out


def _reads_stdin_as_shell(tokens, there=None):
    """`… | sh`, `… | sudo bash -s`, `bash -euo pipefail <<EOF`: a shell with
    no script file runs its input. A named script that is not there (seen
    through `there`) does not count as one: the input is parsed anyway."""
    i = _program_index(tokens)
    if i >= len(tokens):
        return False
    name, after = _prog_name(tokens[i]), list(tokens[i + 1:])
    if name in ("at", "batch"):
        return True                                   # `at now <<< 'pip install x'`
    if name in (".", "source"):
        return bool(after) and bool(_STDIN_PATH.match(after[0]))     # `. /dev/stdin <<EOF`
    if name not in _SHELLS:
        return False
    if any(re.match(r"^-[A-Za-z]*c$", a) for a in after):
        return False
    if any(re.match(r"^-[A-Za-z]*s[A-Za-z]*$", a) for a in after):
        return True                                   # `bash -s -- arg`: still reads its input
    rest = _shell_operands(after)
    if not rest or _STDIN_PATH.match(rest[0]):                      # `sh /dev/stdin`
        return True
    try:
        return not (there or os.path.exists)(os.path.expanduser(rest[0]))
    except (OSError, ValueError):
        return True


def _runs_stdin_as_code(tokens):
    """`… | python3`, `… | python -`, `… | perl`: an interpreter with no script runs its input."""
    i = _program_index(tokens)
    if i >= len(tokens) or not (_PYTHON.match(_prog_name(tokens[i]))
                                or _prog_name(tokens[i]) in ("perl", "ruby", "node")):
        return False
    return not [a for a in tokens[i + 1:] if not a.startswith("-")]


def _track_env(token, env, into):
    key, value = token.split("=", 1)
    if key in _HASH_OFF_ENV:
        into[key] = value
        return False
    if _is_index_env(key) or key in _VERSION_SHIFT_ENV:
        into[key] = value
        return _is_index_env(key) and value != env.get("STILLRUNNING_TRUSTED_INDEX", "")
    return False


_FOLDER_FLAGS = {"npm": {"--prefix", "-C", "--dir", "--cwd"},
                 "uv": {"--directory", "--project"},
                 "poetry": {"-C", "--directory", "-P", "--project"},
                 "pdm": {"-p", "--project"}}
_CODE_FLAGS = {"node": ("-e", "--eval", "-p", "--print", "-pe"), "nodejs": ("-e", "--eval", "-p", "--print"),
               "deno": ("eval",), "perl": ("-e", "-E"), "ruby": ("-e",), "php": ("-r",),
               "lua": ("-e",)}


def _installer_folder(prog, args, cwd):
    """The folder an installer is told to work in (`npm --prefix app`,
    `uv --directory app`), else the current one. → (folder, cannot_tell)."""
    family = "npm" if prog in ("npm", "pnpm", "yarn", "bun") else prog
    flags = _FOLDER_FLAGS.get(family)
    if not flags:
        return cwd, False
    for i, arg in enumerate(args):
        if arg == "--":
            break
        flag, eq, inline = arg.partition("=")
        if flag in flags:
            value = inline if eq else (args[i + 1] if i + 1 < len(args) else "")
            if not value or "$" in value or "`" in value:
                return cwd, True
            value = os.path.expanduser(value)
            return (value if os.path.isabs(value) else os.path.normpath(os.path.join(cwd or ".", value))), False
    return cwd, False


def _inline_code_installs(program, args, res, cwd, env, read_file, exists, depth, raw):
    """Code or commands handed to a program that is not a shell: `node -e`,
    `perl -e`, `awk 'system(…)'`, `vim -c '!…'`, `git -c alias.x='!…'`.
    → True when the command was dealt with here."""
    if program in _CODE_FLAGS:
        flags = _CODE_FLAGS[program]
        for i, arg in enumerate(args):
            if arg in flags and i + 1 < len(args):
                code = args[i + 1]
                if _CODE_EXECS.search(code) and _INSTALLER_HINT.search(code):
                    res.ask("unparsed", raw)        # inline code that starts an installer
                return program != "bun"
        return False
    if program in ("awk", "gawk", "mawk"):
        if any(("system(" in a or "| \"sh" in a or "|\"sh" in a or "getline" in a)
               and _INSTALLER_HINT.search(a) for a in args):
            res.ask("unparsed", raw)
        return False
    if program in ("vim", "vi", "nvim", "ex", "view", "gvim"):
        for i, arg in enumerate(args):
            text = None
            if arg in ("-c", "--cmd") and i + 1 < len(args):
                text = args[i + 1]
            elif arg.startswith("+"):
                text = arg[1:]
            if text and text.lstrip(": ").startswith("!") and depth < 3:
                _parse_into(text.lstrip(": ")[1:], res, cwd, env, read_file, exists, depth + 1)
        return False
    if program == "git":
        for arg in args:
            match = re.match(r"^alias\.[\w.-]+=!(.+)$", arg, re.S)
            if match and depth < 3:                 # `git -c alias.x='!cmd' x` runs cmd in a shell
                _parse_into(match.group(1), res, cwd, env, read_file, exists, depth + 1)
        return False
    return False


def _parse_simple(tokens, res, cwd, env, read_file, exists, depth, feeds_shell=False,
                  heredoc=None):
    raw = " ".join(tokens)[:200]
    if not tokens:
        return
    res.here, res.stdin_file = getattr(tokens, "here", None), getattr(tokens, "stdin_file", None)
    res.heredoc = heredoc
    res.piped = "|" in getattr(tokens, "op", "") and "||" not in getattr(tokens, "op", "")
    lead = 0
    while lead < len(tokens) and _ASSIGN.match(tokens[lead]):
        lead += 1
    if lead == len(tokens):
        # `PIP_INDEX_URL=… ; pip install x`: stays in force for the commands after it
        for token in tokens:
            _track_env(token, env, env)
        return
    if _prog_name(tokens[lead]) in _EXPORTERS:
        for token in tokens[lead + 1:]:
            if _ASSIGN.match(token) and _track_env(token, env, env):
                res.ask("custom_index", raw)
        return
    start = _program_index(tokens)
    program = _prog_name(tokens[start]) if start < len(tokens) else ""
    local_env = dict(env)
    via_stdin = any(_prog_name(t) in ("xargs", "parallel") for t in tokens[:6])

    if _inline_code_installs(program, list(tokens[start + 1:]), res, cwd, env, read_file, exists,
                             depth, raw):
        return
    if program in _DATA_COMMANDS:
        if feeds_shell and program in ("echo", "printf", "cat") and depth < 3:
            text = " ".join(tokens[start + 1:]).replace("\\n", "\n").replace("\\t", " ")
            if looks_like_install(text):
                _parse_into(text, res, cwd, env, read_file, exists, depth + 1)
        return

    if _reads_stdin_as_shell(tokens, lambda path: _there(res, path)) and res.here is not None \
            and depth < 3:
        if looks_like_install(res.here):                    # sh <<< 'pip install x'
            _parse_into(res.here, res, cwd, env, read_file, exists, depth + 1)
    if program in ("npx", "npm", "pnpm", "pnpx") and depth < 3:
        # `npx -c 'cmd …'`, `npm exec -c 'cmd …'`: the string is a command line
        words = list(tokens[start + 1:])
        for at, word in enumerate(words[:-1]):
            if word not in ("-c", "--call"):
                continue
            if looks_like_install(words[at + 1]):
                _parse_into(words[at + 1], res, cwd, env, read_file, exists, depth + 1)
            # the program that string runs may be a package's own command
            head = (words[at + 1].split() or [""])[0]
            match = _SHADOW_NPM.match(head)
            if match and len(head) > 1 and head.lower() not in _SHADOW_STOP | _SHADOW_WORDS:
                res.shadow.append({"eco": "npm", "name": match.group(1).lower(),
                                   "version": match.group(2), "raw": raw,
                                   "where": "the command given to `-c`"})
    python_like = bool(_PYTHON.match(program))
    if depth < 3 and not python_like and _is_shell_text(tokens[lead:]):
        for token in tokens[lead:]:
            if (" " in token or "\n" in token or "$(" in token) and looks_like_install(token):
                _parse_into(token.replace("$(", " ( "), res, cwd, local_env, read_file, exists,
                            depth + 1)
    if program in _REMOTE_RUNNERS:
        return

    # Every installer word in the command is tried, wherever it stands: after
    # `poetry run`, `uv run`, an unknown wrapper (`setsid`, `strace`, …), a
    # variable (`$SUDO pip …`), `find -exec`, or inside a function body.
    # The scan starts at the first word, not at the word the wrapper handling
    # settled on, so a wrapper flag read wrongly can never hide an installer.
    positions = []
    for index in range(lead, len(tokens)):
        token = tokens[index]
        if token.startswith("-") or " " in token or "\n" in token:
            continue
        name = _prog_name(token)
        if token.startswith("$") and not (_has_sep(token) and _is_installer(name)):
            if index == start:
                positions.append(index)
            continue
        if _is_installer(name) or name in _UNSUPPORTED:
            positions.append(index)
        if python_like and index > start:
            break       # `python script.py npm install`: words after a script are its own
    for index in positions:
        for token in tokens[:index]:
            if _ASSIGN.match(token):
                _track_env(token, env, local_env)
        token, rest = tokens[index], tokens[index + 1:]
        before = res.touched
        res.uncertain = bool(any(local_env.get(k) for k in _VERSION_SHIFT_ENV))
        # any value counts: a set-but-"false" switch is not worth the risk
        res.hash_off_env = any(k in local_env for k in _HASH_OFF_ENV)
        was_cwd, was_unknown = res.cwd, res.cwd_unknown
        cwd_here, unknown_here = _installer_folder(_prog_name(token), rest, cwd)
        if unknown_here:
            res.cwd_unknown = True
        res.cwd = cwd_here
        if local_env.get("PIP_REQUIREMENT") and (_PIP.match(_prog_name(token)) or "pip" in rest[:3]):
            res.ask("requirements_unread", raw)     # the list of packages is named by a variable
        try:
            if token.startswith("$") and not (_has_sep(token) and _is_installer(_prog_name(token))):
                # The program is only known at run time ($PIP, $(which pip), `…`).
                if any(re.match(r"^-[A-Za-z]*m$", a) for a in rest[:4]) and \
                        _INSTALLER_HINT.search(" ".join(rest[:6])):
                    _dispatch("python", rest, res, cwd, read_file, exists, raw)   # "$PYTHON" -m pip …
                else:
                    verb = next((a for a in rest if not a.startswith("-")), "")
                    if verb in _INSTALL_VERBS:
                        res.ask("dynamic_command", raw)
            else:
                _dispatch(_prog_name(token), rest, res, cwd_here, read_file, exists, raw)
        finally:
            res.uncertain = False
            res.hash_off_env = False
            res.cwd, res.cwd_unknown = was_cwd, was_unknown
        name = _prog_name(token)
        if via_stdin and (_PIP.match(name) or name in _KNOWN_PROGRAMS):
            res.ask("unparsed", raw)        # the package names arrive on standard input
        if res.touched > before:
            trusted = local_env.get("STILLRUNNING_TRUSTED_INDEX", "")
            for key in list(local_env):
                if _is_index_env(key) and local_env.get(key) and local_env.get(key) != trusted:
                    res.ask("custom_index", raw)
                    break


_SUBSTITUTION = re.compile(r"\$\(([^()`]*)\)|`([^`]*)`")
_SUBST_MARK = "$__SUBST__"
_HEREDOC = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_]\w*)\1([^\n]*)\n(.*?)\n[ \t]*\2[ \t]*(?=\n|$)",
                      re.S)


def _strip_heredocs(command):
    """The command with here-document bodies taken out, and the bodies in
    order. A body is what a program reads on its input — a script for
    `python3 -`, the contents for `cat > file` — so it is data. Only a shell
    that reads one (`bash <<EOF`, `cat <<EOF | sh`) runs it as commands."""
    bodies = []

    def cut(match):
        bodies.append(match.group(4))
        return "<<" + match.group(2) + match.group(3)

    return _HEREDOC.sub(cut, command), bodies


def _lift_substitutions(command):
    """`$(…)` and backtick spans → a placeholder that reads as "decided at run
    time", plus the commands found inside them (parsed on their own)."""
    inner = []

    def lift(match):
        inner.append(match.group(1) if match.group(1) is not None else match.group(2))
        return _SUBST_MARK

    for _ in range(4):                              # nested: innermost first
        command, count = _SUBSTITUTION.subn(lift, command)
        if not count:
            break
    return command, inner


_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'", re.S)
_ANSI_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "a": "\a",
                 "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v", "?": "?"}


def _decode_ansi_c(command):
    """`$'pip\x20install'` → `'pip install'`: bash decodes the escapes before
    it runs the string, so the text is read the way the shell will read it."""
    if "$'" not in (command or ""):
        return command

    def decode(match):
        body = match.group(1)

        def one(m):
            text = m.group(1)
            try:
                if text[0] in "xuU":
                    return chr(int(text[1:], 16))
                if text[0] in "01234567":
                    return chr(int(text, 8) & 0xFF)
            except (ValueError, OverflowError):
                return m.group(0)
            return _ANSI_ESCAPES.get(text, "\\" + text)

        body = re.sub(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|.)",
                      one, body, flags=re.S)
        return "'" + body.replace("'", "'\\''") + "'"

    return _ANSI_C.sub(decode, command)


def _is_pipe(op):
    return "|" in op and "||" not in op


def _stdin_consumer(commands, j, there=None, memo=None):
    """What the pipeline that starts by piping into command j ends up feeding:
    "shell" (the text is run as commands), "code" (an interpreter runs it) or
    None. Programs in between (`tee`, `cat`, `sed`) pass the text along.

    `memo` (a dict, one per pipeline list and folder state) remembers the
    answer for every command the walk passed: asking again for each command
    of an n-command pipeline was O(n^2) (2,000 pipes took 187 s, past the
    hook's 30 s timeout — fuzz finding R2). The answers are the same."""
    k, walked, result = j, [], None
    while k < len(commands):
        if memo is not None and k in memo:
            result = memo[k]
            break
        walked.append(k)
        if _reads_stdin_as_shell(commands[k], there):
            result = "shell"
            break
        if _runs_stdin_as_code(commands[k]):
            result = "code"
            break
        k += 1
        if k >= len(commands) or not _is_pipe(commands[k].op) or ")" in commands[k].op:
            break
    if memo is not None:
        for step in walked:
            memo[step] = result
    return result


def _shell_fed(commands, there=None):
    """For each simple command: is what it prints run by a shell? True for
    `cat <<EOF | tee x | sh`, `{ …; } | bash`, `( … ) | sh`, `bash <(…)`,
    `source <(…)`, `bash < <(…)`."""
    count = len(commands)
    fed = [False] * count
    stack = []
    memo = {}
    for i, cmd in enumerate(commands):
        op = cmd.op
        for pos, ch in enumerate(op):
            if ch == ")" and stack:
                kind, begin = stack.pop()
                piped_on = _is_pipe(op[pos + 1:])
                if kind == "psub" or (piped_on and _stdin_consumer(commands, i, there, memo) == "shell"):
                    for k in range(begin, i):
                        fed[k] = True
            elif ch == "(":
                reader = commands[i - 1] if i else None
                is_psub = pos > 0 and op[pos - 1] == "<"
                runs = False
                if is_psub and reader is not None:
                    at = _program_index(reader)
                    runs = at < len(reader) and (_prog_name(reader[at]) in _SHELLS
                                                 or _prog_name(reader[at]) in (".", "source"))
                stack.append(("psub" if runs else "sub", i))
        if cmd and cmd[0] == "{":
            stack.append(("brace", i))
        if cmd and cmd[0] == "}" and stack and stack[-1][0] == "brace":
            _, begin = stack.pop()
            if i + 1 < count and _is_pipe(commands[i + 1].op) and \
                    _stdin_consumer(commands, i + 1, there, memo) == "shell":
                for k in range(begin, i + 1):
                    fed[k] = True
        if i + 1 < count and _is_pipe(commands[i + 1].op) and ")" not in commands[i + 1].op \
                and _stdin_consumer(commands, i + 1, there, memo) == "shell":
            fed[i] = True
    for kind, begin in stack:                   # `bash <(echo …` with the bracket left open
        if kind == "psub":
            for k in range(begin, count):
                fed[k] = True
    return fed


def _is_decoder(program, args):
    if program not in _DECODERS:
        return False
    if program in ("base64", "base32"):
        return any(a in ("-d", "-D", "--decode") or re.match(r"^-[A-Za-z]*[dD]", a) for a in args)
    if program == "xxd":
        return any(re.match(r"^-[A-Za-z]*r", a) for a in args)
    if program == "openssl":
        return "-d" in args or "-D" in args
    return True                                 # zcat, gunzip, uudecode, rev: always transform


_VAR_WORD = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")
_UNKNOWN_FOLDER = object()


def _cd_target(args, here, home):
    """Where `cd <args>` leaves the shell, or _UNKNOWN_FOLDER."""
    plain = [a for a in args if not a.startswith("-") or a == "-"]
    target = plain[0] if plain else home
    if target == "-" or "`" in target:
        return _UNKNOWN_FOLDER
    target = re.sub(r"^\$\{?HOME\}?(?=/|$)", lambda m: home, target)
    target = _win_spelling(target) or target        # Windows: cd /c/…, cd //localhost/c$/…
    if "$" in target:
        return _UNKNOWN_FOLDER
    target = os.path.expanduser(target)
    if os.path.isabs(target):
        return os.path.normpath(target)
    if here is _UNKNOWN_FOLDER:
        return _UNKNOWN_FOLDER
    return os.path.normpath(os.path.join(here or ".", target))


# `!pip install x`, `%pip install x`: how a notebook cell spells a shell command
_NOTEBOOK_PREFIX = re.compile(r"(?m)^([ \t]*)[!%]{1,2}[ \t]*(?=(?:pip|python|py|uv|uvx|npm|npx|pnpm|yarn|bun"
                              r"|conda|mamba|poetry|pdm|pipx|pipenv)[\d.]*(?:\s|$))")


def _parse_into(command, res, cwd, env, read_file, exists, depth, output_runs=False):
    command = _NOTEBOOK_PREFIX.sub(r"\1", _decode_ansi_c(re.sub(r"\\\r?\n", "", command)))
    command, bodies = _strip_heredocs(command)
    command, inner = _lift_substitutions(command)
    try:
        commands = _simple_commands(_tokenize(command))
    except ValueError:
        commands = None
    # `bash -c "$(echo pip install x)"`, `eval $(printf …)`: the text a
    # substitution prints is run, so what it echoes is parsed as a command.
    runs_output = bool(commands) and any(
        any(_SUBST_MARK in t for t in cmd) and (_is_shell_text(cmd) or cmd[0].startswith(_SUBST_MARK))
        for cmd in commands if cmd)
    if depth < 3:
        for piece in inner:
            if runs_output and "<<" in piece.replace("<<<", "") and bodies:
                body = bodies.pop(0)                # bash -c "$(cat <<EOF … EOF)"
                if looks_like_install(body):
                    _parse_into(body, res, cwd, env, read_file, exists, depth + 1)
            if looks_like_install(piece) or (runs_output and re.match(r"\s*(curl|wget)\b", piece)):
                _parse_into(piece, res, cwd, env, read_file, exists, depth + 1, runs_output)
            if runs_output:
                words = piece.split()
                if words and _is_decoder(_prog_name(words[0]), words[1:]):
                    res.ask("hidden_script", piece.strip()[:200])
    if commands is None:
        if looks_like_install(command):
            res.ask("unparsed", command.strip()[:200])
        return
    there = lambda path: _there(res, path)      # noqa: E731 — seen from the tracked folder
    fed = _shell_fed(commands, there)
    home = os.path.realpath(_home())
    here = _UNKNOWN_FOLDER if res.cwd_unknown else cwd
    outer_cwd, outer_unknown = res.cwd, res.cwd_unknown
    scopes, pushed, variables = [], [], {}
    consumer_memo = {}      # per folder state: what `there` sees depends on it
    try:
        for index, simple in enumerate(commands):
            for ch in simple.op:                    # a subshell keeps its `cd` to itself
                if ch == "(":
                    scopes.append(here)
                elif ch == ")" and scopes:
                    here = scopes.pop()
            res.cwd_unknown = here is _UNKNOWN_FOLDER
            now = cwd if here is _UNKNOWN_FOLDER else here
            res.cwd = now
            feeds = output_runs or fed[index]
            body = bodies.pop(0) if simple.has_heredoc and bodies else None
            start = _program_index(simple)
            program = _prog_name(simple[start]) if start < len(simple) else ""
            args = list(simple[start + 1:])
            raw = " ".join(simple)[:200]
            lead = 0
            while lead < len(simple) and _ASSIGN.match(simple[lead]):
                lead += 1
            if simple and lead == len(simple):
                for token in simple:                # X='pip install evil'; $X
                    key, value = token.split("=", 1)
                    if "$" not in value and "`" not in value:
                        variables[key] = value
                    else:
                        variables.pop(key, None)
            if program in ("cd", "pushd"):
                res.cd_seen = True
                if program == "pushd":
                    pushed.append(here)
                here = _cd_target(args, here, home)
            elif program == "popd":
                here = pushed.pop() if pushed else _UNKNOWN_FOLDER
            consumer = None
            if index + 1 < len(commands) and _is_pipe(commands[index + 1].op):
                consumer = _stdin_consumer(commands, index + 1, there,
                                           consumer_memo.setdefault((res.cwd, res.cwd_unknown), {}))
            if program in ("curl", "wget") and (feeds or consumer in ("shell", "code")):
                res.ask("remote_script", raw)                       # curl … | sh
            if _is_decoder(program, args) and (feeds or consumer in ("shell", "code")):
                res.ask("hidden_script", raw)                       # … | base64 -d | sh
            if depth < 3 and variables:
                for at in range(lead, len(simple)):
                    match = _VAR_WORD.match(simple[at])
                    if not match or match.group(1) not in variables:
                        continue
                    value = variables[match.group(1)]
                    if at == start:                 # the variable IS the command
                        import shlex
                        tail = " ".join(shlex.quote(t) for t in simple[at + 1:])
                        _parse_into(value + " " + tail, res, now, env, read_file, exists, depth + 1)
                    elif _is_shell_text(simple[lead:]) and looks_like_install(value):
                        _parse_into(value, res, now, env, read_file, exists, depth + 1)
            if depth < 3:
                ran = None                          # a script this same command wrote, then runs
                if program in _SHELLS or program in (".", "source"):
                    if not any(re.match(r"^-[A-Za-z]*c$", a) for a in args):
                        ran = next((a for a in args if not a.startswith("-")), None)
                elif os.name == "nt" and program in _WIN_SHELLS:
                    # cmd //c x.bat, powershell -File x.ps1, pwsh ./x.ps1: a script this command wrote
                    pieces = [p for a in args for p in re.findall(r"[^\s'\"]+", a)]
                    ran = next((p for p in pieces if res.full(p) in res.written or (
                        res.cd_seen and os.path.basename(res.full(p)) in {os.path.basename(w) for w in res.written})),
                        None)
                elif start < len(simple) and _has_sep(simple[start]) and not simple[start].startswith("$"):
                    ran = simple[start]
                if ran and not _STDIN_PATH.match(ran):
                    full = res.full(ran)
                    known = full in res.written or (
                        res.cd_seen and os.path.basename(full) in {os.path.basename(w) for w in res.written})
                    if known:
                        text = res.script_text.get(full)
                        if text is None and res.cd_seen:
                            text = next((t for f, t in res.script_text.items()
                                         if os.path.basename(f) == os.path.basename(full)), None)
                        if text is not None:
                            if looks_like_install(text):
                                _parse_into(text, res, now, env, read_file, exists, depth + 1)
                        else:
                            res.ask("remote_script" if full in res.downloaded else "file_changed", raw)
            _parse_simple(simple, res, now, env, read_file, exists, depth, feeds, body)
            if body and depth < 3 and (feeds or _reads_stdin_as_shell(simple, there)) \
                    and looks_like_install(body):
                _parse_into(body, res, now, env, read_file, exists, depth + 1)
    finally:
        res.cwd, res.cwd_unknown = outer_cwd, outer_unknown


_GIT_REWRITES = {"pull", "checkout", "merge", "rebase", "reset", "stash", "restore", "clone",
                 "apply", "am", "cherry-pick", "revert", "switch", "submodule"}
INDEX_CONFIG_FILES = {".npmrc", "pip.conf", "pip.ini", ".pypirc", "uv.toml", ".yarnrc",
                      ".yarnrc.yml", "bunfig.toml", ".condarc", "poetry.toml", "pdm.toml"}


def _collect_writes(command, res, depth=0):
    """Which files does this command itself write (redirections, tee, curl -o,
    wget, cp, mv, sed -i, dd)? An install that reads one of them cannot be
    judged from what the file holds now."""
    command, _bodies = _strip_heredocs(_decode_ansi_c(re.sub(r"\\\r?\n", "", command)))
    command, inner = _lift_substitutions(command)
    for piece in inner:
        if depth < 3:
            _collect_writes(piece, res, depth + 1)
    try:
        commands = _simple_commands(_tokenize(command))
    except ValueError:
        res.unknown_writes = True
        return
    for cmd in commands:
        targets = list(cmd.writes)
        start = _program_index(cmd)
        program = _prog_name(cmd[start]) if start < len(cmd) else ""
        args = cmd[start + 1:]
        plain = [a for a in args if not a.startswith("-")]
        body = _bodies.pop(0) if cmd.has_heredoc and _bodies else None
        literal = None                  # the exact text this command puts in its targets
        if program in ("echo", "printf") and cmd.writes:
            literal = " ".join(a for a in args if not (program == "echo" and re.match(r"^-[neE]+$", a)))
            literal = literal.replace("\\n", "\n").replace("\\t", "\t")
        elif program in ("cat", "tee") and body is not None:
            literal = body
        if literal is not None and ("$(" in literal or "`" in literal):
            literal = None
        if program in ("curl", "wget"):
            res.cd_seen = res.cd_seen                 # (downloads are recorded below)
        if program == "tee":
            targets += plain
        elif program == "curl":
            for i, arg in enumerate(args):
                if arg in ("--output", "--output-dir") or re.match(r"^-[A-Za-z]*o$", arg):
                    targets += args[i + 1:i + 2]
                elif arg.startswith("--output="):
                    targets.append(arg.split("=", 1)[1])
                elif arg == "--remote-name" or re.match(r"^-[A-Za-z]*O[A-Za-z]*$", arg):
                    targets += [a.rstrip("/").rsplit("/", 1)[-1].split("?", 1)[0]
                                for a in plain if "://" in a]
        elif program == "wget":
            named = False
            for i, arg in enumerate(args):
                if arg in ("-O", "--output-document") or re.match(r"^-[A-Za-z]*O$", arg):
                    targets += args[i + 1:i + 2]
                    named = True
                elif arg.startswith("--output-document="):
                    targets.append(arg.split("=", 1)[1])
                    named = True
            if not named:
                targets += [a.rstrip("/").rsplit("/", 1)[-1].split("?", 1)[0]
                            for a in plain if "://" in a]
        elif program in ("cp", "mv", "install", "rsync", "scp", "ln") and len(plain) >= 2:
            targets.append(plain[-1])
            targets += [os.path.join(plain[-1], os.path.basename(a.rstrip("/"))) for a in plain[:-1]]
        elif program in ("sed", "perl", "ruby") and any(
                re.match(r"^-[A-Za-z]*i|^--in-place", a) for a in args):
            targets += plain
        elif program == "dd":
            targets += [a[3:] for a in args if a.startswith("of=")]
        elif program in ("truncate", "touch", "patch"):
            targets += plain
        elif program == "git" and any(a in _GIT_REWRITES for a in plain[:2]):
            res.unknown_writes = True
        elif program in ("unzip", "gunzip", "7z", "bunzip2", "unxz") or (
                program == "tar" and any(re.fullmatch(r"-?[A-Za-z]*x[A-Za-z]*", a)
                                         or a in ("--extract", "--get") for a in args[:1])):
            res.unknown_writes = True
        for target in targets:
            if target and "\n" not in target:
                full = res.full(target)
                res.written.add(full)
                if literal is not None and full not in res.script_text:
                    res.script_text[full] = literal
                else:
                    res.script_text.pop(full, None) if literal is None else None
                if program in ("curl", "wget"):
                    res.downloaded.add(full)
        if depth < 3:
            for word in cmd:
                if " " in word or "\n" in word:
                    _collect_writes(word, res, depth + 1)


def _default_read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read(2_000_000)


def parse_install_commands(command, cwd=None, env=None, read_file=None, exists=None):
    """Which packages would this shell command fetch?

    Returns {"packages": [{eco, name, version, raw}], "unverifiable": [{kind, raw}],
    "notes": [str]}. `unverifiable` means "this is an install we cannot look up"
    and must be put to the user; an empty result means "not an install".
    Deterministic: the only I/O is `read_file` (requirements files) and
    `exists` (node_modules/.bin), both injectable.
    """
    res = _Result()
    res.cwd, res.exists = cwd, exists or os.path.exists
    command = _decode_ansi_c(command or "")
    if command and looks_like_install(command):
        _collect_writes(command, res)
        if _PROCESS_SUBST_SCRIPT.search(_squash(command)):
            res.ask("remote_script", command.strip()[:200])       # bash <(curl …)
        for path in sorted(res.written):
            if (index_config_file(path) if os.name == "nt" else os.path.basename(path) in INDEX_CONFIG_FILES):
                res.ask("index_config", os.path.basename(path))
        _parse_into(command, res, cwd, dict(env or {}), read_file or _default_read,
                    exists or os.path.exists, 0)
    return res.as_dict()


# ─────────────────────────────── lookups ───────────────────────────────
KNOWN_BAD = {"logutilkit", "apachelicense", "fluxhttp", "license-utils-kit", "logkitx",
             "pino-debugger", "dev-log-core", "logger-base", "axois", "plain-crypto-js",
             "termncolor", "colorinal"}


def _home():
    return os.path.expanduser("~")


def _state_dir():
    return os.path.join(_home(), ".stillrunning")


def _warn(message):
    sys.stderr.write(f"[stillrunning hook] WARNING: {message}\n")


_TOKEN_LINE = re.compile(
    r"""^\s*(?:STILLRUNNING_TOKEN|api_token|token)\s*[:=]\s*["']?([^"'\s#]+)""", re.M)


def _token_from_text_file(path):
    """`token:` / `api_token:` / `STILLRUNNING_TOKEN=` from a YAML or .env
    file, read as plain text (the hook runs without site-packages, so no YAML
    parser is available)."""
    try:
        with open(path, encoding="utf-8") as handle:
            match = _TOKEN_LINE.search(handle.read(200_000))
    except (OSError, UnicodeDecodeError):  # lint: allowed-silent(absent or unreadable source → next source)
        return None
    return match.group(1) if match else None


def resolve_token():
    """→ (token or None, where it came from). The ONE token precedence, used
    by every command, the import hook, the wrappers' `scan` and this hook:

      1. $STILLRUNNING_TOKEN
      2. ~/.stillrunning/config.json            {"token": "..."}   ← canonical
      3. ~/.stillrunning/stillrunning.yaml      token: ...         (legacy)
      4. ~/.stillrunning/.env                   STILLRUNNING_TOKEN=...  (legacy)
      5. stillrunning.yaml next to the package  api_token: ...     (legacy --setup)
    """
    if not _apibase.token_allowed():
        return None, ("no token sent (STILLRUNNING_API_BASE points at a test server; the "
                      "account token only goes to stillrunning.io)")
    value = os.environ.get("STILLRUNNING_TOKEN", "").strip()
    if value:
        return value, "the STILLRUNNING_TOKEN environment variable"
    path = os.path.join(_state_dir(), "config.json")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict) and data.get("token"):
                return str(data["token"]).strip(), "~/.stillrunning/config.json"
        except (OSError, ValueError) as exc:
            _warn(f"config.json unreadable ({type(exc).__name__}) — trying the legacy token files")
    for path, label in (
            (os.path.join(_state_dir(), "stillrunning.yaml"), "~/.stillrunning/stillrunning.yaml"),
            (os.path.join(_state_dir(), ".env"), "~/.stillrunning/.env"),
            (os.path.join(os.path.dirname(os.path.abspath(__file__)), "stillrunning.yaml"),
             "the package's stillrunning.yaml")):
        value = _token_from_text_file(path)
        if value:
            return value, label
    return None, "no token (anonymous tier)"


def _token():
    return resolve_token()[0]


def consume_override(eco, name):
    """True when the user allowed this package themselves (allow list or a
    one-time override, which is used up here)."""
    path = os.path.join(_state_dir(), "overrides.json")
    if not os.path.exists(path):
        return False
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle) or {}
        want = normalize(eco, name)
        once = list(data.get("once", []))
        if any(normalize(eco, p) == want for p in once):
            data["once"] = [p for p in once if normalize(eco, p) != want]
            _atomic_write(path, json.dumps(data, indent=2))
            return True
        return any(normalize(eco, p) == want for p in data.get("allow", []))
    except (OSError, ValueError, AttributeError) as exc:
        _warn(f"overrides.json unreadable ({type(exc).__name__}) — no override applied")
        return False


def _locally_blocked(eco, name):
    want = normalize(eco, name)
    if want in {normalize(eco, k) for k in KNOWN_BAD}:
        return True
    path = os.path.join(_state_dir(), "known_bad_packages.json")
    try:
        if os.path.exists(path) and os.path.getsize(path) < 20_000_000:
            with open(path, encoding="utf-8") as handle:
                listed = (json.load(handle) or {}).get(eco, {})
            return any(normalize(eco, k) == want for k in listed)
    except (OSError, ValueError, AttributeError) as exc:
        _warn(f"local blocklist unreadable ({type(exc).__name__}) — relying on the API")
    return False


def _local_list_unreadable():
    """True when the shipped blocklist file is there but cannot be read
    (corrupt, too large, unreadable): `_locally_blocked` then answers False
    without knowing, and the verdict cache must not rely on that answer."""
    path = os.path.join(_state_dir(), "known_bad_packages.json")
    try:
        if not os.path.lexists(path):
            return False
        if os.path.getsize(path) >= 20_000_000:
            return True
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return not isinstance(data, dict) or not all(isinstance(v, (dict, list))
                                                     for v in data.values())
    except (OSError, ValueError, UnicodeDecodeError):
        return True


def _api_lookup(eco, name, version, token, timeout):
    import urllib.error
    import urllib.parse
    import urllib.request
    query = {"name": name, "ecosystem": eco}
    if version:
        query["version"] = version
    headers = {"User-Agent": USER_AGENT}
    if token and _apibase.token_allowed():
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(API_URL + "?" + urllib.parse.urlencode(query), headers=headers)
    http_ok = True
    try:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read(200_000).decode())
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                return {"status": "unverified", "why": "quota"}
            http_ok = False
            try:
                body = json.loads(exc.read(200_000).decode())
            except (ValueError, OSError):
                return {"status": "unverified", "why": "server"}
    except (urllib.error.URLError, OSError):
        return {"status": "unverified", "why": "offline"}
    except ValueError:
        return {"status": "unverified", "why": "server"}
    if not isinstance(body, dict):
        return {"status": "unverified", "why": "server"}
    verdict = str(body.get("verdict") or "").upper()
    ids = body.get("advisory_ids") or []
    advisory = next((str(a) for a in ids if _SAFE_ADVISORY.match(str(a))), None) \
        if isinstance(ids, list) else None
    age = body.get("threat_data_age_hours")
    age = float(age) if isinstance(age, (int, float)) and not isinstance(age, bool) else None
    size = body.get("threat_database_size")
    size = size if isinstance(size, int) and not isinstance(size, bool) and size > 0 else None
    since = str(body.get("first_seen") or "")[:10]
    since = since if len(since) == 10 and since[:4].isdigit() and since[4] == "-" else None
    extra = {"feed_age_h": age, "feed_size": size}
    if verdict in ("BLOCKED", "DANGEROUS"):
        if body.get("version_specific") is True and not version:
            return dict(extra, status="version_needed", advisory=advisory,
                        listed_since=since, affected=_safe_specs(body.get("affected_versions")))
        return dict(extra, status="blocked", advisory=advisory, listed_since=since)
    if verdict == "SUSPICIOUS":
        return dict(extra, status="suspicious")
    state = body.get("status")
    # Every verdict maps explicitly. "No known threat" needs the one answer
      # that means a completed lookup with no match; any other UNKNOWN, an
      # unrecognised verdict string, or a non-200 answer is "not checked".
    if verdict == "UNKNOWN" and http_ok and state == "not_in_threat_database":
        return dict(extra, status="ok")
    why = {"stale_data": "stale", "unsupported_ecosystem": "ecosystem"}.get(state, "server")
    # `answered`: the server did reply (HTTP 200) with something not mapped
    # above — an answer not understood, which the verdict cache never covers.
    return dict(extra, status="unverified", why=why, answered=http_ok)


def _blocklist_only_lookup(eco, name, version, timeout, quiet=False):
    """When the metered lookup is out of quota, ask the unmetered blocklist
    route. A hit is always a block. A miss only counts as a completed lookup
    when the server says its list is fresh (`"fresh": true`) — today it does
    not report that, so a miss stays "not checked" and the user is asked."""
    import urllib.error
    import urllib.parse
    import urllib.request
    query = {"ecosystem": eco}
    if version:
        query["version"] = version
    url = (API_URL.rsplit("/", 1)[0] + "/blocklist/" + urllib.parse.quote(name, safe="")
           + "?" + urllib.parse.urlencode(query))
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=min(timeout, 6.0)) as response:
            body = json.loads(response.read(200_000).decode())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if not quiet:
            _warn(f"quota used up and the blocklist-only lookup failed ({type(exc).__name__})")
        return None
    if not isinstance(body, dict):
        return None
    if body.get("blocked") is True:
        ids = body.get("advisory_ids") if isinstance(body.get("advisory_ids"), list) else []
        advisory = next((str(a) for a in ids if _SAFE_ADVISORY.match(str(a))), None)
        if str(body.get("verdict") or "").upper() == "SUSPICIOUS":
            return {"status": "suspicious"}
        if body.get("version_specific") is True and not version:
            return {"status": "version_needed", "advisory": advisory,
                    "affected": _safe_specs(body.get("versions"))}
        return {"status": "blocked", "advisory": advisory}
    if body.get("blocked") is False and body.get("fresh") is True:
        age, size = body.get("threat_data_age_hours"), body.get("threat_database_size")
        return {"status": "ok",
                "feed_age_h": float(age) if isinstance(age, (int, float)) and not isinstance(age, bool) else None,
                "feed_size": size if isinstance(size, int) and not isinstance(size, bool) and size > 0 else None}
    if body.get("blocked") is False:
        # The server answered "not listed" without saying its list is current.
        return {"status": "miss_unconfirmed"}
    return None


def _shadow_lookup(pkg, timeout=4.0):
    """Is a shadow candidate on the blocklist? Uses only the list that ships
    with stillrunning and the unmetered blocklist route — never the metered
    lookup, never the registry. Anything but a hit is "nothing"."""
    if _locally_blocked(pkg["eco"], pkg["name"]):
        return {"status": "blocked", "advisory": None, "local": True}
    return _blocklist_only_lookup(pkg["eco"], pkg["name"], pkg.get("version"), timeout,
                                  quiet=True) or {"status": "unverified", "why": "server"}


def _on_registry(eco, name, timeout):
    """False only on a definite 404; None when the probe itself failed."""
    import urllib.error
    import urllib.parse
    import urllib.request
    if eco == "pip":
        url = f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json"
    else:
        url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=timeout):
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        _warn(f"registry probe for {name} answered HTTP {exc.code} — existence not checked")
    except (urllib.error.URLError, OSError) as exc:
        _warn(f"registry probe for {name} failed ({type(exc).__name__}) — existence not checked")
    return None


_SAFE_SPEC = re.compile(r"^(?:[=<>!~]{1,3}\s*)?([A-Za-z0-9][A-Za-z0-9._+!*-]{0,63})$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}$")


def _safe_specs(value, limit=200):
    """Version specifiers from a server answer, as plain version strings.
    Anything that is not a simple specifier is dropped (no outside prose)."""
    out = []
    for item in value if isinstance(value, list) else []:
        match = _SAFE_SPEC.match(item) if isinstance(item, str) else None
        if match and match.group(1) != "any":
            out.append(match.group(1))
    return out[:limit]


def _canon_version(version):
    """One spelling for versions that mean the same release: `v1.2.0`,
    `1.2`, `1.02.0` and `1.2.0+local` all name 1.2."""
    text = str(version or "").strip().lower().lstrip("=v").split("+", 1)[0]
    if "!" in text and text.split("!", 1)[0].strip("0") == "":
        text = text.split("!", 1)[1]                      # epoch 0 is the default
    parts = [str(int(p)) if p.isdigit() else p for p in text.split(".")]
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts)


def _odd_pin(version):
    """A pin that could be another spelling of a listed version."""
    return _canon_version(version) != str(version) or str(version).count(".") < 2


def _latest_version(eco, name, timeout):
    """The version an unpinned install would fetch from the public registry
    right now, or None when that cannot be established."""
    import urllib.error
    import urllib.parse
    import urllib.request
    if eco == "pip":
        url = f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json"
    else:
        url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/latest"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read(30_000_000).decode())
        version = (body.get("info") or {}).get("version") if eco == "pip" else body.get("version")
    except (urllib.error.URLError, OSError, ValueError, AttributeError) as exc:
        _warn(f"could not work out the latest version of {name} ({type(exc).__name__})")
        return None
    return version if isinstance(version, str) and _SAFE_VERSION.match(version) else None


def _query(eco, name, version, token, timeout):
    """Metered lookup, falling back to the unmetered blocklist route on quota."""
    result = _api_lookup(eco, name, version, token, timeout)
    if result["status"] == "unverified" and result.get("why") == "quota":
        fallback = _blocklist_only_lookup(eco, name, version, timeout)
        if fallback and fallback.get("status") != "miss_unconfirmed":
            result = fallback
    return result


def _resolve_version_needed(eco, name, first, token, timeout):
    """The list names specific bad versions and the command named none: find
    the version that would be installed and ask about exactly that one."""
    affected = first.get("affected") or []
    latest = _latest_version(eco, name, min(timeout, 6.0))
    if latest is None:
        return {"status": "unverified", "why": "version", "affected": affected}
    second = _query(eco, name, latest, token, timeout)
    if second["status"] == "version_needed":      # a server that ignored the version
        second = dict(second, status="blocked")
    return dict(second, resolved_version=latest, affected=affected)


def _override_outcome(eco, name, version, timeout):
    """The user allowed this package. That stands unless the package is on the
    blocklist: an override must never be a quiet way round a known threat, so
    that case is put to a person. Uses the unmetered route (no quota cost)."""
    if _locally_blocked(eco, name):
        return {"status": "override_blocked", "advisory": None, "local": True}
    probe = _blocklist_only_lookup(eco, name, version, timeout)
    if probe is None:
        # No answer at all (offline, rate-limited, garbage): the override cannot
        # be shown to be harmless, so a person decides.
        return {"status": "unverified", "why": "override_unchecked"}
    if probe.get("status") in ("blocked", "suspicious", "version_needed"):
        return {"status": "override_blocked", "advisory": probe.get("advisory"),
                "affected": probe.get("affected") or []}
    return {"status": "override"}


def lookup(pkg, token=None, timeout=8.0):
    """One package → {"status": ok|blocked|suspicious|unverified|not_found|override|
    override_blocked, ...}.

    `pkg["version"]` is an exact pin or None. `pkg["spec"]` (a range, tag or
    wildcard) or `pkg["uncertain"]` (a flag such as --pre or a constraints
    file is in force) mean the version that would be installed is NOT simply
    the latest one."""
    eco, name, version = pkg["eco"], pkg["name"], pkg.get("version")
    if consume_override(eco, name):
        return _override_outcome(eco, name, version, timeout)
    if _locally_blocked(eco, name):
        return {"status": "blocked", "advisory": None, "local": True}
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        api = pool.submit(_query, eco, name, version, token, timeout)
        registry = pool.submit(_on_registry, eco, name, min(timeout, 6.0))
        result, exists = api.result(), registry.result()
    if result["status"] == "version_needed":
        if pkg.get("spec") or pkg.get("uncertain"):
            # Some versions are listed and the command names a range, a tag or a
            # flag that changes what resolves: "latest" is not the answer.
            result = {"status": "unverified", "why": "version_range",
                      "affected": (result.get("affected") or [])[:8],
                      "advisory": result.get("advisory"),
                      "feed_age_h": result.get("feed_age_h"),
                      "feed_size": result.get("feed_size")}
        else:
            result = _resolve_version_needed(eco, name, result, token, timeout)
            result = dict(result, affected=(result.get("affected") or [])[:8])
    elif version and result["status"] == "ok" and _odd_pin(version):
        # `==1.14.1.0`, `==1.14` or `v1.14.1` can be another spelling of a
        # listed version that a plain text match on the server would miss.
        probe = _blocklist_only_lookup(eco, name, None, timeout)
        if probe and probe.get("status") == "version_needed" and any(
                _canon_version(version) == _canon_version(bad)
                for bad in probe.get("affected") or []):
            result = dict(result, status="blocked", advisory=probe.get("advisory"))
    result = dict(result, registry=exists)
    if result["status"] == "ok" and exists is False:
        result["status"] = "not_found"
    return result


# ─────────────────────── known vulnerabilities (OSV.dev) ───────────────────────
CVE_CHECK_ENV = "STILLRUNNING_CVE_CHECK"
CVE_TIMEOUT_S = 5.0
CVE_CACHE_FRESH_S = 24 * 3600
_OSV = []


def cve_check_enabled():
    """Default ON. STILLRUNNING_CVE_CHECK=0 switches the install-time check off."""
    return os.environ.get(CVE_CHECK_ENV, "1").strip().lower() not in ("0", "false", "no", "off")


def _osv_module():
    """osv.py, loaded only when an install is checked (bare-script safe)."""
    if not _OSV:
        try:
            from stillrunning import osv as module
        except ImportError:
            import importlib.util
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "osv.py")
            spec = importlib.util.spec_from_file_location("stillrunning_osv", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        _OSV.append(module)
    return _OSV[0]


def _cve_cached(eco, name, version, now=None):
    """Clusters saved by `stillrunning cve --refresh` for exactly this
    name+version, when that refresh is under 24 hours old; else None."""
    now = time.time() if now is None else now
    key = f"{eco}:{normalize(eco, name)}@{version}"
    try:
        with open(os.path.join(_state_dir(), "cve_state.json"), encoding="utf-8") as handle:
            doc = json.load(handle)
        projects = doc.get("projects") if doc.get("schema") == 2 else None
        for entry in (projects or {}).values():
            feed = entry.get("feed_updated_at") if isinstance(entry, dict) else None
            # a fact about a package version, whichever project's refresh found it;
            # only from a refresh under a day old and not dated in the future
            if (not isinstance(feed, (int, float)) or isinstance(feed, bool)
                    or not -120 <= now - feed <= CVE_CACHE_FRESH_S):
                continue
            found = (entry.get("results") or {}).get(key)
            if isinstance(found, list) and all(isinstance(c, dict) for c in found):
                return found
    except FileNotFoundError:
        return None
    except (OSError, ValueError, AttributeError) as exc:
        _warn(f"cve_state.json unreadable ({type(exc).__name__}) — asking OSV.dev directly")
        return None
    return None


def _cve_verdict(clusters, version, resolved=None):
    osv = _osv_module()
    clean = []
    for c in clusters:
        vid = str(c.get("id") or "")
        if not osv.SAFE_ID.match(vid):
            continue
        sev = c.get("severity") if c.get("severity") in osv.SEVERITIES else None
        fixed = c.get("fixed") if isinstance(c.get("fixed"), str) and \
            osv.SAFE_VERSION.match(c["fixed"]) else None
        clean.append({"id": vid, "severity": sev, "fixed": fixed})
    out = {"version": version, "vulns": clean}
    if resolved:
        out["resolved_version"] = resolved
    crit = [c for c in clean if c["severity"] == "CRITICAL"]
    if crit:
        return dict(out, status="critical", top=crit[0])
    unknown = [c for c in clean if c["severity"] is None]
    if unknown:                      # uncertainty holds: it could be critical
        return dict(out, status="unknown_severity", top=unknown[0])
    if clean:
        return dict(out, status="noncritical", top=clean[0])
    return dict(out, status="none")


def cve_lookup(pkg, timeout=CVE_TIMEOUT_S, now=None, latest_fn=None):
    """Known vulnerabilities for the version this install would fetch.
    → {"status": critical|noncritical|none|none_any|failed, ...}.

    An exact pin is checked as that version. An unpinned install is first
    asked about every version; only when some version has a CRITICAL
    vulnerability is the version that would be installed worked out (the
    same registry lookup the blocklist check uses) and checked. A range, a
    tag or a flag that changes what resolves cannot be worked out: if some
    version is critical, the check could not run for this one."""
    eco, version = pkg["eco"], pkg.get("version")
    name = normalize(eco, pkg["name"])
    osv = _osv_module()
    latest_fn = latest_fn or _latest_version

    def at(v):
        cached = _cve_cached(eco, name, v, now)
        if cached is not None:
            return cached, None
        records, why = osv.query_package(eco, name, v, timeout)
        if why:
            return None, why
        return osv.cluster([osv.summarize(r, eco, name, v) for r in records], v), None

    if version:
        clusters, why = at(version)
        if why:
            return {"status": "failed", "why": why, "version": version}
        return _cve_verdict(clusters, version)
    records, why = osv.query_package(eco, name, None, timeout)
    if why:
        return {"status": "failed", "why": why}
    worry = [c for c in osv.cluster([osv.summarize(r, eco, name, None) for r in records])
             if c["severity"] in ("CRITICAL", None)]
    if not worry:
        return {"status": "none_any"}
    worry.sort(key=lambda c: c["severity"] != "CRITICAL")
    some = {"id": worry[0]["id"], "severity": worry[0]["severity"]}
    if pkg.get("spec") or pkg.get("uncertain"):
        return {"status": "failed", "why": "range", "some": some}
    latest = latest_fn(eco, name, timeout)
    if latest is None:
        return {"status": "failed", "why": "version", "some": some}
    clusters, why = at(latest)
    if why:
        return {"status": "failed", "why": why, "version": latest}
    return _cve_verdict(clusters, latest, resolved=latest)


# ─────────────────────────────── rendering ───────────────────────────────
_COLORS = {"green": "\033[32m", "yellow": "\033[33m", "red": "\033[1;31m", "dim": "\033[2m"}


def _paint(text, color, enabled):
    return f"{_COLORS[color]}{text}\033[0m" if enabled else text


def _color_enabled():
    return (os.environ.get("STILLRUNNING_COLOR", "") in ("1", "true", "yes")
            and not os.environ.get("NO_COLOR"))


def _label(pkg):
    version = f" {pkg['version']}" if pkg.get("version") else ""
    return f"{pkg['name']}{version} ({pkg['eco']})"


def status_line(kind, subject, detail, ms=None, color=False):
    """The compact one-liner. kind: ok | unverified | blocked | note."""
    mark, paint = {"ok": ("✓", "green"), "unverified": ("⚠", "yellow"),
                   "blocked": ("✗ BLOCKED", "red"), "note": ("·", "dim")}[kind]
    took = f" · {int(ms)} ms" if ms is not None else ""
    return f"{SHIELD} stillrunning {_paint(mark, paint, color)} {subject} — {detail}{took}"


_REMEMBERED = []


def _remembered_module():
    """The store of commands the user chose not to be asked about again
    (stillrunning/remembered.py), or None when it is not installed. The hook
    runs as a bare script, so the sibling file is loaded by path then."""
    if _REMEMBERED:
        return _REMEMBERED[0]
    module = None
    try:
        from stillrunning import remembered as module
    except ImportError:
        # Bare script (python -I -S): the package is not importable. remembered.py
        # imports this module relatively, so stand in for the package and hand
        # it the module that is already running.
        here = os.path.dirname(os.path.abspath(__file__))
        if os.path.exists(os.path.join(here, "remembered.py")):
            try:
                import importlib
                import types
                if "stillrunning" not in sys.modules:
                    package = types.ModuleType("stillrunning")
                    package.__path__ = [here]
                    sys.modules["stillrunning"] = package
                sys.modules.setdefault("stillrunning.claude_hook", sys.modules[__name__])
                module = importlib.import_module("stillrunning.remembered")
            except Exception as exc:
                _warn(f"remembered commands could not be loaded ({type(exc).__name__}: {exc}) — "
                      "you will be asked as usual")
                module = None
    _REMEMBERED.append(module)
    return module


def command_id(command, cwd):
    """Identity of one exact command in one folder (see remembered.command_id)."""
    try:
        module = _remembered_module()
        if module is not None:
            return module.command_id(command, cwd)
    except Exception as exc:
        _warn(f"remembered-commands module failed ({type(exc).__name__}: {exc}) — using the built-in id")
    import hashlib
    where = os.path.realpath(cwd) if cwd else ""
    return hashlib.sha256(((command or "").strip() + "\0" + where)
                          .encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _remembered_on(cmd_id):
    """None when this command is not remembered (or the store cannot be
    read); otherwise the day it was allowed, or "" when the store has no date."""
    try:
        module = _remembered_module()
        if module is None or not module.is_remembered(cmd_id):
            return None
        module.touch(cmd_id)
        return _remembered_day(module, cmd_id)
    except Exception as exc:    # any fault in the store → not remembered: the user is asked
        _warn(f"remembered-commands store failed ({type(exc).__name__}: {exc}) — asking as usual")
        return None


def _remembered_day(module, cmd_id):
    """The day the command was remembered, as YYYY-MM-DD, or "" when the
    store does not say. Display only."""
    try:
        if hasattr(module, "remembered_on"):
            when = module.remembered_on(cmd_id)
        else:
            added = (module._load().get(cmd_id) or {}).get("added_at")
            when = time.strftime("%Y-%m-%d", time.localtime(added)) if isinstance(
                added, (int, float)) and not isinstance(added, bool) else ""
    except Exception as exc:
        _warn(f"could not read when this command was remembered ({type(exc).__name__})")
        return ""
    return when if isinstance(when, str) and re.match(r"^\d{4}-\d{2}-\d{2}$", when) else ""


# Remembered commands are OFF. The 2026-11-15 review showed that an ask about
# something the hook could not read (a web script, a variable, a file the
# command rewrites) stayed allowed after its content changed, and that the
# record a "remember" relies on is written before anyone has approved. Until
# the feature is redesigned no decision is rememberable and the store is never
# consulted. Tests that exercise the old path set this True.
REMEMBER_ENABLED = False

# Lookup outcomes that are not "an identifiable package threat or an unknown":
# only with these may an ask be remembered for the exact command.
_REMEMBERABLE_STATUS = ("ok", "override", "not_found")


def _safe_adv(value):
    value = str(value or "")
    return value if _SAFE_ADVISORY.match(value) else "an advisory"


def _cve_report(cve, pkg):
    """→ (kind, one evidence item) for a vulnerability-check outcome."""
    status, version = cve.get("status"), pkg.get("version") or ""
    if status in ("critical", "noncritical", "unknown_severity"):
        top = cve.get("top") or {}
        fixed = top.get("fixed")
        fix = f"; {fixed} fixes it" if isinstance(fixed, str) and _SAFE_VERSION.match(fixed) else ""
        return status, _ev("vulnerability", "found", "cve_found", version=version,
                           advisory=str(top.get("id")), severity=top.get("severity"), fix=fix)
    if status == "none":
        return "none", _ev("vulnerability", "nothing_found", "cve_none", version=version)
    if status == "none_any":
        return "none", _ev("vulnerability", "nothing_found", "cve_none_any")
    return "failed", _ev("vulnerability", "not_checked", "cve_not_checked",
                         cve_why=cve.get("why") or "error")


# ─────────────────────────── local verdict cache ───────────────────────────
# stillrunning/verdict_cache.py. It may only answer for an exact, hash-pinned
# release that passed both checks on this machine before, and only when a
# live check could not complete now. No network; see that module.
_VCACHE = []


def _verdict_cache():
    """The verdict cache module, or None when switched off or not loadable."""
    try:
        if not _VCACHE:
            try:
                from stillrunning import verdict_cache as module
            except ImportError:
                import importlib.util
                path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verdict_cache.py")
                spec = importlib.util.spec_from_file_location("stillrunning_verdict_cache", path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            _VCACHE.append(module)
        module = _VCACHE[0]
        return module if module.enabled() else None
    except Exception as exc:  # no cache is the normal behaviour: every package is checked
        _warn(f"verdict cache could not be loaded ({type(exc).__name__}) — not used")
        return None


def _local_cve_held(eco, name, version):
    """Does the saved CVE state (any refresh, any age) hold this exact
    version — a critical or unknown-severity vulnerability? Unreadable → True."""
    key = f"{eco}:{normalize(eco, name)}@{version}"
    try:
        with open(os.path.join(_state_dir(), "cve_state.json"), encoding="utf-8") as handle:
            doc = json.load(handle)
        for entry in ((doc.get("projects") or {}) if isinstance(doc, dict) else {}).values():
            found = (entry.get("results") or {}).get(key) if isinstance(entry, dict) else None
            if found is None:
                continue
            if not isinstance(found, list) or not all(isinstance(c, dict) for c in found):
                return True
            if _cve_verdict(found, version)["status"] in ("critical", "unknown_severity"):
                return True
        return False
    except FileNotFoundError:
        return False
    except Exception as exc:
        _warn(f"cve_state.json unreadable ({type(exc).__name__}) — verdict cache not used")
        return True


def _cache_serve(packages, results, cve_results, cve_ran, unverifiable, protect, blocked, now):
    """→ {package index: cached verdict} for the packages the local verdict
    cache answers: an exact hash-pinned release, verified here before and
    unexpired, whose live check could not complete now — and nothing else."""
    vc = _verdict_cache()
    if vc is None or protect or unverifiable:
        return {}
    if _local_list_unreadable():
        _warn("local blocklist unreadable — verdict cache not used")
        return {}
    served, ttl = {}, None
    for index, pkg in enumerate(packages):
        if not vc.cacheable(pkg):
            continue
        outcome, cve = results[index][0], cve_results.get(index)
        eco, name, version = pkg["eco"], normalize(pkg["eco"], pkg["name"]), pkg["version"]
        if cve_ran and (cve is None or vc.cve_held(cve)):
            continue
        cve_could = cve_ran and vc.cve_could_not(cve)
        cve_clear = (not cve_ran) or vc.cve_completed_clear(cve, version)
        if not ((vc.blocklist_could_not(outcome) and (cve_could or cve_clear))
                or (vc.blocklist_completed_clear(outcome) and cve_could)):
            continue
        if (eco, name) in blocked or _locally_blocked(eco, name) or _local_cve_held(eco, name, version):
            continue
        ttl = vc.ttl_seconds(warn=_warn) if ttl is None else ttl
        entry = vc.find(_state_dir(), eco, name, version, pkg["hash"], now, ttl, _warn)
        if entry:
            served[index] = dict(entry, blocklist_live=outcome.get("status") == "ok")
    return served


def _cache_line(entry, now):
    vc = _verdict_cache() or _VCACHE[0]
    age = vc.age_text(now - entry["verified_at"])
    if entry.get("blocklist_live"):
        return f"no known threat (vulnerability check from this machine {age}; not re-run now)"
    return f"no known threat (verified on this machine {age}; not re-checked now)"


def _cache_evidence(entry, now):
    vc = _verdict_cache() or _VCACHE[0]
    algo, _, digest = str(entry.get("artifact") or "").partition(",")[0].partition(":")
    redo = ("the vulnerability check" if entry.get("blocklist_live") else "the checks")
    return {"check": "local_cache", "status": "info",
            "text": (f"Local verdict cache: this exact version and file hash ({algo}:{digest[:12]}…) "
                     f"had no blocklist match and no held vulnerability on this machine "
                     f"{vc.age_text(now - entry['verified_at'])}; {redo} could not run now and "
                     "were not repeated")}


def _cache_update(packages, results, cve_results, cve_ran, unverifiable, protect, blocked,
                  served, now, denied=False):
    """After a decision: drop verdicts that a live answer contradicts, and
    store new ones for exact hash-pinned releases that passed both checks."""
    vc = _verdict_cache()
    if vc is None:
        return
    state = _state_dir()
    for eco, name in blocked:
        vc.forget(state, eco, name, warn=_warn)
    version_tag = None
    for index, pkg in enumerate(packages):
        outcome, cve = results[index][0], cve_results.get(index)
        eco, name = pkg["eco"], normalize(pkg["eco"], pkg["name"])
        if (outcome.get("status") in ("blocked", "suspicious", "override_blocked", "not_found")
                or outcome.get("why") in NEEDS_PERSON_WHY or outcome.get("registry") is False
                or _locally_blocked(eco, name)):
            vc.forget(state, eco, name, warn=_warn)
            continue
        if vc.cve_held(cve):
            held = cve.get("resolved_version") or cve.get("version") or pkg.get("version")
            vc.forget(state, eco, name, held if held and not cve.get("some") else None, warn=_warn)
            continue
        if (index in served or protect or unverifiable or denied or not cve_ran
                or not vc.cacheable(pkg)
                or not vc.blocklist_completed_clear(outcome)
                or not vc.cve_completed_clear(cve, pkg["version"])):
            continue
        version_tag = version_tag or vc.client_version()
        age = outcome.get("feed_age_h")
        vc.store(state, {
            "eco": eco, "name": name, "version": str(pkg["version"]), "artifact": pkg["hash"],
            "verified_at": now, "blocklist_answer": "no match (completed lookup)",
            "blocklist_feed_age_h": float(age) if isinstance(age, (int, float))
            and not isinstance(age, bool) else None,
            "cve_status": cve["status"], "cve_checked_at": now, "client_version": version_tag},
            now, _warn, ensure_dir=_private_state_dir)


def cache_count(now=None):
    """Unexpired verdicts in the local cache (for `stillrunning shield`);
    None when the cache is off or unreadable."""
    vc = _verdict_cache()
    if vc is None:
        return None
    now = time.time() if now is None else now
    return vc.count(_state_dir(), now, vc.ttl_seconds(warn=_warn), warn=_warn)


def decide(command, cwd=None, env=None, lookup_fn=None, deadline=CHECK_DEADLINE_S, now=None,
           shadow_fn=None, cve_fn=None):
    """→ {"action": allow|ask|deny, "lines": [user-visible], "reason": str,
          "stats": {...}, "records": [one decision record per item]}

    Every package is also checked for known vulnerabilities (OSV.dev), in
    parallel with the blocklist and within the same deadline, unless
    STILLRUNNING_CVE_CHECK=0. With an injected `lookup_fn` (tests, the
    self-test) that check runs only when `cve_fn` is injected too."""
    color = _color_enabled()
    now = time.time() if now is None else now
    lines, details, records = [], [], []
    stats = {"checked": 0, "blocked": 0, "unverified": 0, "ok": 0}
    action = "allow"
    shown_command = show_command(command)

    def escalate(new):
        nonlocal action
        if new == "deny" or (new == "ask" and action == "allow"):
            action = new

    def record(verdict, subject, evidence, explanation=None, pkg=None, ms=None):
        records.append({
            "v": 1, "ts": now, "verdict": verdict, "subject": subject,
            "eco": pkg["eco"] if pkg else None, "name": pkg["name"] if pkg else None,
            "version": pkg.get("version") if pkg else None,
            "ms": int(ms) if ms is not None else None,
            "command": shown_command,
            "evidence": evidence, "explanation": explanation})
        if verdict in ("blocked", "needs_approval"):
            details.append((explanation, top_evidence(evidence)))

    no_name = [_ev("blocklist", "not_checked", "blocklist_not_checked", why="no_name")]
    protect = touches_protection(command or "", cwd)
    hold = protect          # True → the unverified opt-out must not wave this through
    if protect:
        lines.append(status_line("unverified", "protection change",
                                 "approval needed", color=color))
        record("needs_approval", "change to stillrunning's own protection", no_name,
               explain("self_protect"))
        escalate("ask")
        stats["unverified"] += 1

    parsed = parse_install_commands(command, cwd=cwd, env=env if env is not None else os.environ)
    packages = parsed["packages"]
    shadow = parsed.get("shadow") or []
    if len(shadow) > _SHADOW_CAP:
        # more unread words than will be looked up: say so instead of dropping them
        parsed["unverifiable"].append({"kind": "unparsed", "raw": shadow[0]["raw"]})
        shadow = shadow[:_SHADOW_CAP]
    results, shadow_results, cve_results = {}, {}, {}
    run_cve = bool(packages) and cve_check_enabled() and (cve_fn is not None or lookup_fn is None)
    cve_texts = []
    if packages or shadow:
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
        fn = lookup_fn or (lambda pkg: lookup(pkg, token=_token()))
        # Shadow candidates only ever ask "is this name on the blocklist". With
        # an injected lookup (tests, the self-test) that function is the server.
        asked = shadow_fn or lookup_fn or _shadow_lookup

        def shadow_fn(pkg):
            # the value of an option that names a path, file, number or group
            # never leaves the machine: the shipped blocklist only
            if pkg.get("local_only"):
                if _locally_blocked(pkg["eco"], pkg["name"]):
                    return {"status": "blocked", "advisory": None, "local": True}
                return {"status": "unverified", "why": "local_only"}
            return asked(pkg)

        started = time.monotonic()

        def timed(pkg, call=fn):
            begin = time.monotonic()
            try:
                outcome = call(pkg)
            except Exception as exc:  # any lookup crash is "not checked", never a pass
                _warn(f"lookup for {pkg['name']} crashed ({type(exc).__name__}: {exc})")
                outcome = {"status": "unverified", "why": "server"}
            return outcome, (time.monotonic() - begin) * 1000

        pool = ThreadPoolExecutor(max_workers=min(8, len(packages) + len(shadow)))
        futures = [pool.submit(timed, pkg) for pkg in packages]
        shadow_futures = [pool.submit(timed, pkg, shadow_fn) for pkg in shadow]
        cve_pool, cve_futures = None, []
        if run_cve:
            cve_call = cve_fn or cve_lookup

            def cve_timed(pkg):
                try:
                    return cve_call(pkg)
                except Exception as exc:  # a crash is "could not run", never a pass
                    _warn(f"vulnerability check for {pkg['name']} crashed ({type(exc).__name__})")
                    return {"status": "failed", "why": "error"}

            cve_pool = ThreadPoolExecutor(max_workers=min(8, len(packages)))
            cve_futures = [cve_pool.submit(cve_timed, pkg) for pkg in packages]
        for index, future in enumerate(futures):
            left = max(0.05, deadline - (time.monotonic() - started))
            try:
                results[index] = future.result(timeout=left)
            except FutureTimeout:
                results[index] = ({"status": "unverified", "why": "timeout"}, deadline * 1000)
        for index, future in enumerate(shadow_futures):
            left = max(0.05, deadline - (time.monotonic() - started))
            try:
                shadow_results[index] = future.result(timeout=left)
            except FutureTimeout:   # lint: allowed-silent(a shadow candidate is extra cover; no answer = nothing)
                continue
        for index, future in enumerate(cve_futures):
            left = max(0.05, deadline - (time.monotonic() - started))
            try:
                cve_results[index] = future.result(timeout=left)
            except FutureTimeout:
                _warn(f"vulnerability check for {packages[index]['name']} did not finish in time")
                cve_results[index] = {"status": "failed", "why": "budget"}
        pool.shutdown(wait=False)
        if cve_pool is not None:
            cve_pool.shutdown(wait=False)

    # names the live blocklist answered "listed" for, wherever they appeared
    blocked = {(p["eco"], normalize(p["eco"], p["name"])) for i, p in enumerate(shadow)
               if isinstance(shadow_results.get(i, ({},))[0], dict)
               and shadow_results[i][0].get("status") == "blocked"}
    try:
        served = _cache_serve(packages, results, cve_results, run_cve, parsed["unverifiable"],
                              protect, blocked, now) if packages else {}
    except Exception as exc:  # a cache fault is "no cached verdict", never a pass
        _warn(f"verdict cache not used ({type(exc).__name__})")
        served = {}

    for index, pkg in enumerate(packages):
        outcome, ms = results[index]
        if outcome.get("resolved_version") and not pkg.get("version"):
            # show (and record) the version that was actually looked up
            pkg = dict(pkg, version=str(outcome["resolved_version"]))
        status, name, eco = outcome["status"], pkg["name"], pkg["eco"]
        twin = lookalike_of(eco, name)
        evidence = build_evidence(pkg, outcome)
        stats["checked"] += 1
        for key in ("feed_age_h", "feed_size"):
            if outcome.get(key) is not None:
                stats[key] = outcome[key]
        first_record = len(records)
        unverified_before = stats["unverified"]
        if index in served:
            # the live check could not complete; this exact release passed both
            # checks here before (local verdict cache) — counted as no known threat
            stats["ok"] += 1
            lines.append(status_line("ok", _label(pkg), _cache_line(served[index], now), ms, color))
            record("no_known_threat", _label(pkg),
                   evidence + [_cache_evidence(served[index], now)], None, pkg, ms)
        elif status == "ok":
            stats["ok"] += 1
            lines.append(status_line("ok", _label(pkg), "no known threat", ms, color))
            record("no_known_threat", _label(pkg), evidence, None, pkg, ms)
        elif status == "override":
            lines.append(status_line("note", _label(pkg),
                                     "allowed by your own override, not looked up", ms, color))
            record("override", _label(pkg), evidence, None, pkg, ms)
        elif status == "blocked":
            advisory = outcome.get("advisory")
            detail = "known malicious package" + (f" · {advisory}" if advisory else "")
            lines.append(status_line("blocked", _label(pkg), detail, ms, color))
            if twin:
                text = explain("blocked_typosquat", name=name, lookalike=twin)
            elif advisory:
                text = explain("blocked_advisory", name=name, advisory=advisory)
            else:
                text = explain("blocked_listed", name=name)
            record("blocked", _label(pkg), evidence, text, pkg, ms)
            stats["blocked"] += 1
            escalate("deny")
        elif status == "suspicious":
            lines.append(status_line("blocked", _label(pkg), "on a watch list, unconfirmed",
                                     ms, color))
            record("blocked", _label(pkg), evidence, explain("suspicious", name=name), pkg, ms)
            stats["blocked"] += 1
            escalate("deny")
        elif status == "override_blocked":
            lines.append(status_line("unverified", _label(pkg),
                                     "on the blocklist, allowed by a local override — "
                                     "approval needed", ms, color))
            record("needs_approval", _label(pkg), evidence,
                   explain("override_blocked", name=name), pkg, ms)
            stats["unverified"] += 1
            hold = True
            escalate("ask")
        elif status == "unverified" and outcome.get("why") in NEEDS_PERSON_WHY:
            lines.append(status_line("unverified", _label(pkg),
                                     "some versions are reported as malicious — "
                                     "approval needed", ms, color))
            bad = [a for a in outcome.get("affected") or [] if isinstance(a, str)]
            text = (explain("version_range", name=name, affected=", ".join(bad))
                    if outcome.get("why") == "version_range"
                    else explain("check_failed", name=name, why="version"))
            record("needs_approval", _label(pkg), evidence, text, pkg, ms)
            stats["unverified"] += 1
            hold = True
            escalate("ask")
        elif status == "not_found":
            lines.append(status_line("unverified", _label(pkg),
                                     f"unverified: not on {REGISTRY_NAME[eco]} — approval needed",
                                     ms, color))
            text = (explain("not_found_lookalike", name=name, registry=eco, lookalike=twin)
                    if twin else explain("not_found", name=name, registry=eco))
            record("needs_approval", _label(pkg), evidence, text, pkg, ms)
            stats["unverified"] += 1
            escalate("ask")
        else:
            lines.append(status_line("unverified", _label(pkg),
                                     "unverified: could not be looked up — approval needed",
                                     ms, color))
            record("needs_approval", _label(pkg), evidence,
                   explain("check_failed", name=name, why=outcome.get("why", "server")), pkg, ms)
            stats["unverified"] += 1
            if outcome.get("why") == "override_unchecked":
                hold = True         # an override is in play: the opt-out does not apply
            escalate("ask")
        cve = cve_results.get(index) if status not in ("blocked", "suspicious") else None
        if isinstance(cve, dict):
            vuln_pkg = dict(pkg, version=str(cve.get("resolved_version") or pkg.get("version") or "")
                            or None)
            label = _label(vuln_pkg)
            kind, cve_ev = _cve_report(cve, vuln_pkg)
            if len(records) > first_record:
                records[first_record]["evidence"].append(cve_ev)
            if kind == "critical":
                top = cve["top"]
                text = (explain("cve_critical_fixed", name=name, version=vuln_pkg["version"],
                                advisory=top["id"], fixed=top["fixed"]) if top.get("fixed") else
                        explain("cve_critical_nofix", name=name, version=vuln_pkg["version"],
                                advisory=top["id"]))
                lines.append(status_line("unverified", label, "critical known vulnerability · "
                                         + _safe_adv(top["id"]) + " — approval needed",
                                         None, color))
                record("needs_approval", label, [cve_ev], text, vuln_pkg)
                cve_texts.append(text)
                hold = True         # checked and found: the unverified opt-out does not apply
                escalate("ask")
            elif kind == "unknown_severity":
                top = cve["top"]
                text = (explain("cve_unknown_fixed", name=name, version=vuln_pkg["version"],
                                advisory=top["id"], fixed=top["fixed"]) if top.get("fixed") else
                        explain("cve_unknown_nofix", name=name, version=vuln_pkg["version"],
                                advisory=top["id"]))
                lines.append(status_line("unverified", label, "known vulnerability of unknown "
                                         "severity · " + _safe_adv(top["id"]) +
                                         " — approval needed", None, color))
                record("needs_approval", label, [cve_ev], text, vuln_pkg)
                cve_texts.append(text)
                hold = True         # checked and found: the unverified opt-out does not apply
                escalate("ask")
            elif kind == "failed" and (cve.get("some") or {}).get("id"):
                some = cve["some"]
                text = explain("cve_some_critical" if some.get("severity") == "CRITICAL"
                               else "cve_some_unknown", name=name, cve_why=cve.get("why"),
                               advisory=some["id"])
                lines.append(status_line("unverified", label, (
                    "critical known vulnerability in versions it could install"
                    if some.get("severity") == "CRITICAL" else
                    "known vulnerability in versions it could install") + " · "
                    + _safe_adv(some["id"]) + " — approval needed", None, color))
                record("needs_approval", label, [cve_ev], text, vuln_pkg)
                cve_texts.append(text)
                hold = True         # a known vulnerability is in reach: no opt-out
                escalate("ask")
            elif kind == "failed" and index not in served:
                text = explain("cve_unchecked", name=name, cve_why=cve.get("why"))
                lines.append(status_line("unverified", label,
                                         "vulnerability check could not run — approval needed",
                                         None, color))
                record("needs_approval", label, [cve_ev], text, vuln_pkg)
                if stats["unverified"] == unverified_before:
                    stats["unverified"] += 1    # one package counts once, whichever checks failed
                escalate("ask")
            elif kind == "noncritical":
                top = cve["top"]
                fix = f" · {top['fixed']} fixes it" if top.get("fixed") and \
                    _SAFE_VERSION.match(top["fixed"]) else ""
                sev = (top.get("severity") or "unknown severity").lower()
                lines.append(status_line("note", label, f"known vulnerability · "
                                         f"{_safe_adv(top['id'])} ({sev}){fix} — not held",
                                         None, color))

    # A word the parser did not read as a package, but that IS on the blocklist:
    # blocked like any other. Every other answer for such a word is dropped.
    for index, pkg in enumerate(shadow):
        outcome, ms = shadow_results.get(index, ({}, None))
        if not isinstance(outcome, dict) or outcome.get("status") != "blocked":
            continue
        name, eco = pkg["name"], pkg["eco"]
        twin, advisory = lookalike_of(eco, name), outcome.get("advisory")
        evidence = build_evidence(pkg, outcome) + [{
            "check": "position", "status": "info",
            "text": "Named in the command as " + pkg["where"]}]
        detail = "known malicious package" + (f" · {advisory}" if advisory and
                                              _SAFE_ADVISORY.match(str(advisory)) else "")
        lines.append(status_line("blocked", _label(pkg), detail, ms, color))
        if twin:
            text = explain("blocked_typosquat", name=name, lookalike=twin)
        elif advisory and _SAFE_ADVISORY.match(str(advisory)):
            text = explain("blocked_advisory", name=name, advisory=advisory)
        else:
            text = explain("blocked_listed", name=name)
        record("blocked", _label(pkg), evidence, text, pkg, ms)
        stats["checked"] += 1
        stats["blocked"] += 1
        escalate("deny")

    seen_kinds = set()
    for item in parsed["unverifiable"]:
        if item["kind"] in seen_kinds:
            continue
        seen_kinds.add(item["kind"])
        subject = {"remote_url": "install from a web address", "custom_index": "custom package index",
                   "requirements_unread": "requirements file", "requirements_large": "requirements file",
                   "unparsed": "install command", "dynamic_command": "install command",
                   "local_missing": "local file install",
                   "file_changed": "file changed by this command",
                   "index_config": "package source change",
                   "unsupported_installer": "install command",
                   "remote_script": "script from a web address",
                   "unknown_folder": "install from an unknown folder",
                   "hidden_script": "commands hidden until run"}[item["kind"]]
        lines.append(status_line("unverified", subject, "unverified — approval needed",
                                 color=color))
        record("needs_approval", subject, no_name, explain(item["kind"]))
        stats["unverified"] += 1
        escalate("ask")
    for note in parsed["notes"]:
        lines.append(status_line("note", "note", note, color=color))
        record("note", note, no_name)

    if packages or shadow:
        try:
            _cache_update(packages, [results[i] for i in range(len(packages))], cve_results,
                          run_cve, parsed["unverifiable"], protect, blocked, served, now,
                          denied=action == "deny")
        except Exception as exc:  # the cache never changes a decision already made
            _warn(f"verdict cache not updated ({type(exc).__name__})")

    cmd_id = command_id(command or "", cwd)
    can_remember = bool(REMEMBER_ENABLED and action == "ask" and not protect and not hold and all(
        results[index][0].get("status") in _REMEMBERABLE_STATUS for index in range(len(packages))))
    if can_remember:
        when = _remembered_on(cmd_id)
        if when is not None:
            action, can_remember = "allow", False
            lines.append(f"{SHIELD} stillrunning • remembered: you allowed this exact command"
                         + (f" on {when}" if when else " before"))
            for item in records:
                if item["verdict"] == "needs_approval":
                    item["verdict"] = "override"
                    item["evidence"] = list(item["evidence"]) + [{
                        "check": "remembered", "status": "info",
                        "text": "You chose not to be asked again for this exact command"}]
            stats["unverified"] = 0
    for item in records:
        item["cmd_id"], item["can_remember"] = cmd_id, can_remember
    user_lines = list(lines)
    explanations = [text for text, _ in details if text]
    if action != "allow":
        for text, evidence_lines in details:
            if text:
                user_lines.append("   " + text)
            user_lines += ["     • " + line for line in evidence_lines]
    reason = ""
    if action == "deny":
        reason = ("stillrunning blocked this install. " + " ".join(explanations) +
                  " Do not retry with another installer, flag or spelling; tell the user what "
                  "was blocked and why.")
    elif action == "ask":
        lead = ("stillrunning is holding this install for your approval. "
                if explanations and all(t in cve_texts for t in explanations)
                else "stillrunning could not verify this command. ")
        reason = lead + " ".join(explanations)
    return {"action": action, "lines": user_lines, "reason": reason, "stats": stats,
            "records": records, "protect": bool(hold), "cmd_id": cmd_id,
            "can_remember": can_remember}


# ─────────────────────────────── counters ───────────────────────────────
_TIGHTENED = []


def _private_state_dir():
    """The state directory holds the account token, the decision log and the
    overrides: it is created for its owner only, and one left open to other
    accounts by an older version is closed."""
    directory = _state_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.name == "nt":
        # Windows reports every folder as 0o777 and chmod cannot change that:
        # checking the bits warned "readable by other accounts" on every hook
        # call. Access there is by ACL; the user profile is private by default.
        return
    try:
        mode = os.stat(directory).st_mode & 0o777
        if mode & 0o077:
            os.chmod(directory, 0o700)
            if not _TIGHTENED:
                _TIGHTENED.append(True)
                _warn(f"{directory} was readable by other accounts (mode {oct(mode)[2:]}); "
                      "it is now owner-only")
    except OSError as exc:
        _warn(f"could not make {directory} owner-only ({type(exc).__name__})")


def _atomic_write(path, text, errors="strict"):
    directory = os.path.dirname(path)
    if os.path.realpath(directory) == os.path.realpath(_state_dir()):
        _private_state_dir()
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    mode = None
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:  # lint: allowed-silent(new file → default mode below)
        mode = None
    with open(tmp, "w", encoding="utf-8", errors=errors) as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, mode if mode is not None else 0o600)
    os.replace(tmp, path)


def stats_path():
    return os.path.join(_state_dir(), "hook_stats.json")


def decisions_path():
    return os.path.join(_state_dir(), "hook_decisions.jsonl")


MAX_DECISIONS = 500
KEEP_DAYS = 14


def record_stats(stats, now=None):
    """Today's counters (plus 14 days of history) for the status line and
    `stillrunning shield`. Never affects the decision."""
    now = time.time() if now is None else now
    today = time.strftime("%Y-%m-%d", time.localtime(now))
    path = stats_path()
    data = {}
    try:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                data = {}
    except (OSError, ValueError) as exc:
        _warn(f"hook_stats.json unreadable ({type(exc).__name__}) — counters restarted")
        data = {}
    if data.get("date") != today:
        data.update({"date": today, "checked": 0, "blocked": 0, "unverified": 0, "ok": 0})
    days = data.get("days") if isinstance(data.get("days"), dict) else {}
    day = days.get(today) if isinstance(days.get(today), dict) else {}
    for key in ("checked", "blocked", "unverified", "ok"):
        add = int(stats.get(key, 0))
        data[key] = int(data.get(key, 0)) + add
        data["total_" + key] = int(data.get("total_" + key, 0)) + add
        day[key] = int(day.get(key, 0)) + add
    days[today] = day
    data["days"] = {k: days[k] for k in sorted(days)[-KEEP_DAYS:]}
    data["last_ts"] = now
    if stats.get("feed_age_h") is not None:
        data["feed_age_h"], data["feed_seen_ts"] = stats["feed_age_h"], now
    if stats.get("feed_size") is not None:
        data["feed_size"] = stats["feed_size"]
    try:
        _atomic_write(path, json.dumps(data))
    except OSError as exc:
        _warn(f"could not write hook_stats.json ({exc}) — status line counters are behind")


def log_decisions(records):
    """Append to the local decisions log (JSONL, newest last, last 500, mode
    600). Rewritten atomically so a reader never sees a half-written line."""
    if not records:
        return
    path = decisions_path()
    kept = []
    try:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                kept = [line for line in handle.read().splitlines() if line.strip()]
    except OSError as exc:
        _warn(f"hook_decisions.jsonl unreadable ({type(exc).__name__}) — log restarted")
    kept += [json.dumps(dict({"cmd_id": None, "can_remember": False}, **record),
                        ensure_ascii=False) for record in records]
    try:
        # backslashreplace: a lone surrogate (a command with invalid UTF-8)
        # is written as a \udcff escape, which inside a JSON string reads
        # back as the same text, instead of crashing the hook
        _atomic_write(path, chr(10).join(kept[-MAX_DECISIONS:]) + chr(10), errors="backslashreplace")
        os.chmod(path, 0o600)
    except OSError as exc:
        _warn(f"could not write hook_decisions.jsonl ({exc}) — `stillrunning shield` is behind")


# ─────────────────────────────── hook entry ───────────────────────────────
def _emit(decision):
    out = {}
    if decision["lines"]:
        out["systemMessage"] = "\n".join(decision["lines"])
    if decision["action"] in ("ask", "deny"):
        out["hookSpecificOutput"] = {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision["action"],
            "permissionDecisionReason": decision["reason"],
        }
    try:
        text = json.dumps(out)
    except (TypeError, ValueError):
        if decision["action"] == "allow":
            return 0
        sys.stderr.write(decision["reason"] + "\n")
        return 2
    if out:
        try:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
        except OSError as exc:
            _warn(f"could not hand the decision to Claude Code ({type(exc).__name__})")
            if decision["action"] != "allow":
                sys.stderr.write(decision["reason"] + "\n")
                _ANSWERED.append(2)
                return 2
    _ANSWERED.append(0)
    return 0


def _run_file_tool(tool_input, cwd):
    """Write / Edit / MultiEdit / NotebookEdit: a file tool aimed at
    stillrunning's own protection files is put to the user. No network."""
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    kind = "self_protect_file"
    try:
        written = " ".join(str(tool_input.get(key) or "") for key in
                           ("content", "new_string", "new_source"))
        written += " ".join(str(edit.get("new_string") or "") for edit in
                            (tool_input.get("edits") or []) if isinstance(edit, dict))
        if not protected_path(path, cwd) and not rc_switch_write(path, written, cwd):
            if not index_config_file(path):
                return 0
            kind = "index_config"
    except Exception as exc:    # cannot tell which file → ask, never a silent pass
        _warn(f"hook path check error ({type(exc).__name__}: {exc})")
    text = explain(kind)
    action = ("deny" if os.environ.get("STILLRUNNING_HOOK_STRICT", "") in ("1", "true", "yes")
              else "ask")
    decision = {
        "action": action, "reason": "stillrunning: " + text, "stats": {"unverified": 1},
        "lines": [status_line("unverified", "protection change" if kind == "self_protect_file"
                              else "package source change", "approval needed",
                              color=_color_enabled()), "   " + text],
        "records": [{"v": 1, "ts": time.time(), "verdict": "needs_approval",
                     "subject": ("change to stillrunning's own protection"
                                 if kind == "self_protect_file" else "package source change"),
                     "eco": None,
                     "name": None, "version": None, "ms": None, "explanation": text,
                     "evidence": [_ev("blocklist", "not_checked", "blocklist_not_checked",
                                      why="no_name")]}]}
    record_stats(decision["stats"])
    log_decisions(decision["records"])
    return _emit(decision)


MAX_COMMAND_CHARS = 128 * 1024    # longer: asked without being read (see run_hook)


def _unread_decision(kind, subject):
    text = explain(kind)
    return {"action": "ask", "reason": "stillrunning: " + text, "stats": {"unverified": 1}, "protect": True,
            "lines": [status_line("unverified", subject, "approval needed", color=_color_enabled()),
                      "   " + text],
            "records": [{"v": 1, "ts": time.time(), "verdict": "needs_approval", "subject": subject,
                         "eco": None, "name": None, "version": None, "ms": None, "explanation": text,
                         "evidence": [_ev("blocklist", "not_checked", "blocklist_not_checked",
                                          why="server")]}]}


def run_hook(stdin_text):
    """Exit code for one PreToolUse event. Prints the decision JSON."""
    try:
        event = json.loads(stdin_text) if stdin_text.strip() else {}
    except RecursionError:      # nested too deeply to read: block, never crash (fuzz R1)
        sys.stderr.write("stillrunning: hook input nested too deeply to read — stopped. "
                         + explain("hook_error") + "\n")
        return 2
    except ValueError:
        if looks_like_install(stdin_text):
            sys.stderr.write("stillrunning: unreadable hook input for what looks like an "
                             "install — stopped. " + explain("hook_error") + "\n")
            return 2
        _warn("unreadable hook input (not an install) — not checked")
        return 0
    if not isinstance(event, dict):
        return 0
    tool_input = event.get("tool_input")
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) and event.get("cwd") else None
    if event.get("tool_name") in _FILE_TOOLS:
        return _run_file_tool(tool_input, cwd)
    if event.get("tool_name") != "Bash":
        return 0
    command = tool_input.get("command") or ""
    if not isinstance(command, str):
        return 0
    if len(command) > MAX_COMMAND_CHARS:
        # Too long to read before Claude Code gives up on the hook (whose
        # timeout would let it through): put it to the user, unread. `protect`
        # keeps STILLRUNNING_ALLOW_UNVERIFIED from waving it through.
        decision = _unread_decision("too_large", "command too long to check")
        return _finish(decision)
    try:
        relevant = looks_like_install(command) or touches_protection(command, cwd)
    except Exception as exc:    # cannot tell → evaluate it rather than wave it through
        _warn(f"hook gate error ({type(exc).__name__}: {exc})")
        relevant = True
    if not relevant:
        return 0
    try:
        decision = decide(command, cwd=cwd or os.getcwd())
    except Exception as exc:  # fail closed: an install we could not evaluate is put to the user
        _warn(f"hook error ({type(exc).__name__}: {exc})")
        decision = {"action": "ask", "reason": explain("hook_error"), "stats": {"unverified": 1},
                    "lines": [status_line("unverified", "install command",
                                          "unverified — approval needed"),
                              "   " + explain("hook_error")],
                    "records": [{"v": 1, "ts": time.time(), "verdict": "needs_approval",
                                 "subject": "install command", "eco": None, "name": None,
                                 "version": None, "ms": None,
                                 "explanation": explain("hook_error"),
                                 "evidence": [_ev("blocklist", "not_checked",
                                                  "blocklist_not_checked", why="server")]}]}
    return _finish(decision)


def _finish(decision):
    """The opt-in switches, the stats and the log, then the answer to Claude Code."""
    if decision["action"] == "ask":
        if os.environ.get("STILLRUNNING_HOOK_STRICT", "") in ("1", "true", "yes"):
            decision["action"] = "deny"
        elif (os.environ.get("STILLRUNNING_ALLOW_UNVERIFIED", "") == "1"
              and not decision.get("protect")):
            # The documented opt-out: warn every time, then proceed.
            decision["action"] = "allow"
            decision["lines"].append(
                "   WARNING: STILLRUNNING_ALLOW_UNVERIFIED=1 is set, so this unverified "
                "install proceeds without asking you. It was NOT checked.")
    if decision["lines"]:
        record_stats(decision["stats"])
        log_decisions(decision.get("records", []))
    return _emit(decision)


# ─────────────────────────── settings.json installer ───────────────────────────
class InstallError(Exception):
    pass


def _settings_path():
    return os.path.join(_home(), ".claude", "settings.json")


def hook_command():
    import shlex
    return f"{shlex.quote(sys.executable)} -I -S {shlex.quote(os.path.abspath(__file__))}"


def statusline_command():
    import shlex
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "statusline.py")
    return f"{shlex.quote(sys.executable)} -I -S {shlex.quote(script)}"


# The Claude Code side panel shipped inside this package (stillrunning/claude_plugin).
# install() registers it in settings.json as a local-folder marketplace, so a
# pip install plus --hook-claude-code is all it takes; Claude Code loads it at
# its next start.
PANEL_MARKETPLACE = "stillrunning-shield"
PANEL_PLUGIN_ID = "stillrunning-shield@stillrunning-shield"
PANEL_REPO = "johhnyg/stillrunning-shield"


def panel_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "claude_plugin")


def _is_our_panel_source(entry):
    source = entry.get("source") if isinstance(entry, dict) else None
    if not isinstance(source, dict):
        return False
    if source.get("source") == "directory":
        path = str(source.get("path", ""))
        return "stillrunning" in path and path.rstrip("/\\").endswith("claude_plugin")
    return source.get("source") == "github" and source.get("repo") == PANEL_REPO


def _add_panel(data, messages):
    """Register the bundled side panel. Never overrides the person's own
    choice: a panel they switched off stays off, and a marketplace of the
    same name that is not ours is left alone."""
    folder = panel_dir()
    if not os.path.isfile(os.path.join(folder, ".claude-plugin", "marketplace.json")):
        messages.append("Side panel NOT added: its files are missing from this stillrunning "
                        "install (reinstall stillrunning).")
        return
    enabled = data.get("enabledPlugins", {})
    markets = data.get("extraKnownMarketplaces", {})
    if not isinstance(enabled, dict) or not isinstance(markets, dict):
        messages.append("Side panel NOT added: settings.json has enabledPlugins or "
                        "extraKnownMarketplaces in a form stillrunning does not edit.")
        return
    if enabled.get(PANEL_PLUGIN_ID) is False:
        messages.append("Side panel left off (it is switched off in settings.json).")
        return
    current = markets.get(PANEL_MARKETPLACE)
    if current is not None and not _is_our_panel_source(current):
        messages.append(f"Side panel NOT added: a marketplace named {PANEL_MARKETPLACE} that "
                        "stillrunning did not add is already in settings.json.")
        return
    markets[PANEL_MARKETPLACE] = {"source": {"source": "directory", "path": folder}}
    enabled[PANEL_PLUGIN_ID] = True
    data["extraKnownMarketplaces"] = markets
    data["enabledPlugins"] = enabled
    messages.append("Side panel added (stillrunning-shield): restart Claude Code, then type "
                    "/shield to open it.")


def _remove_panel(data):
    """→ True when our panel registration was removed."""
    changed = False
    markets = data.get("extraKnownMarketplaces")
    if isinstance(markets, dict) and _is_our_panel_source(markets.get(PANEL_MARKETPLACE)):
        markets.pop(PANEL_MARKETPLACE)
        changed = True
        if not markets:
            data.pop("extraKnownMarketplaces")
    enabled = data.get("enabledPlugins")
    if changed and isinstance(enabled, dict) and PANEL_PLUGIN_ID in enabled:
        enabled.pop(PANEL_PLUGIN_ID)
        if not enabled:
            data.pop("enabledPlugins")
    return changed


def _is_ours(command):
    command = str(command)
    return (command.strip() == "stillrunning hook"
            or ("stillrunning" in command and "claude_hook.py" in command))


def _is_our_statusline(value):
    command = str((value or {}).get("command", "")) if isinstance(value, dict) else ""
    return "stillrunning" in command and "statusline" in command


def _load_settings(path):
    if not os.path.exists(path):
        return {}, False
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    if not text.strip():
        return {}, True
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InstallError(
            f"{path} is not valid JSON ({exc}). stillrunning did not touch it — fix the file "
            f"(Claude Code ignores a broken settings file too) and run this again.")
    if not isinstance(data, dict):
        raise InstallError(f"{path} does not contain a JSON object — not touched.")
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict) or not isinstance(hooks.get("PreToolUse", []), list):
        raise InstallError(f"{path} has a `hooks` section in a shape stillrunning does not "
                           f"recognise — not touched.")
    return data, True


def _backup(path):
    import shutil
    stem = f"{path}.stillrunning-bak-{time.strftime('%Y%m%dT%H%M%S')}"
    backup, n = stem, 1
    while os.path.exists(backup):          # never overwrite an earlier backup
        n += 1
        backup = f"{stem}-{n}"
    shutil.copy2(path, backup)
    return backup


def _strip_ours(groups):
    kept = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
            kept.append(group)
            continue
        remaining = [h for h in group["hooks"]
                     if not (isinstance(h, dict) and _is_ours(h.get("command", "")))]
        if remaining:
            kept.append(dict(group, hooks=remaining))
        elif len(remaining) == len(group["hooks"]):
            kept.append(group)
    return kept


def _clean_legacy_hooks_json(messages):
    """Earlier versions wrote ~/.claude/hooks.json, which Claude Code never read."""
    path = os.path.join(_home(), ".claude", "hooks.json")
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        messages.append(f"Left {path} alone (unreadable). Claude Code does not use that file.")
        return
    entries = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return
    kept = [e for e in entries
            if not (isinstance(e, dict) and "stillrunning" in str(e.get("hooks", [])))]
    if len(kept) == len(entries):
        return
    if not kept and set(data) == {"hooks"}:
        os.remove(path)
        messages.append(f"Removed the old {path} (Claude Code never read it).")
    else:
        _atomic_write(path, json.dumps(dict(data, hooks=kept), indent=2) + "\n")
        messages.append(f"Removed the old stillrunning entry from {path}.")


def _receipt_path():
    return os.path.join(_state_dir(), "claude_settings_receipt.json")


def _sha256_file(path):
    import hashlib
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:  # lint: allowed-silent(absent file has no hash; callers compare against None)
        return None


def _load_receipt(path):
    """The record of what settings.json held before stillrunning's install,
    or None. Used to put the file back byte for byte on uninstall."""
    try:
        with open(_receipt_path(), encoding="utf-8") as handle:
            receipt = json.load(handle)
    except (OSError, ValueError):  # lint: allowed-silent(no receipt → uninstall edits the JSON instead)
        return None
    if not isinstance(receipt, dict) or receipt.get("path") != path:
        return None
    return receipt


def _write_receipt(path, original, installed_sha):
    import base64
    receipt = {"v": 1, "path": path, "existed": original is not None,
               "original_b64": base64.b64encode(original or b"").decode(),
               "installed_sha256": installed_sha}
    try:
        _atomic_write(_receipt_path(), json.dumps(receipt) + "\n")
    except OSError as exc:
        _warn(f"could not record the original settings.json ({type(exc).__name__}) — "
              "uninstall will edit the file instead of restoring it exactly")


def _restore_exact(path, receipt):
    """True when settings.json is exactly what install wrote and has been put
    back exactly as it was before (or removed, if it did not exist)."""
    import base64
    if not receipt or _sha256_file(path) != receipt.get("installed_sha256"):
        return False
    try:
        if receipt.get("existed"):
            original = base64.b64decode(receipt.get("original_b64", ""))
            mode = os.stat(path).st_mode & 0o777
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "wb") as handle:
                handle.write(original)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        else:
            os.remove(path)
    except (OSError, ValueError) as exc:
        _warn(f"exact restore of settings.json failed ({type(exc).__name__}: {exc}) — editing it instead")
        return False
    return True


def _forget_receipt():
    try:
        os.remove(_receipt_path())
    except OSError:  # lint: allowed-silent(no receipt to remove)
        pass


def install(statusline=False, panel=True):
    """Register the PreToolUse hook in ~/.claude/settings.json. Returns messages."""
    path = _settings_path()
    data, existed = _load_settings(path)
    messages = []
    # What the file held before our FIRST install: a re-install on top of our
    # own unmodified install keeps the earlier original.
    receipt = _load_receipt(path)
    if receipt and _sha256_file(path) == receipt.get("installed_sha256"):
        import base64
        original = base64.b64decode(receipt.get("original_b64", "")) if receipt.get("existed") else None
    elif existed:
        with open(path, "rb") as handle:
            original = handle.read()
    else:
        original = None
    if existed:
        messages.append(f"Backup: {_backup(path)}")
    hooks = data.setdefault("hooks", {})
    groups = _strip_ours(hooks.get("PreToolUse", []))
    groups.append({"matcher": HOOK_MATCHER, "hooks": [
        {"type": "command", "command": hook_command(), "timeout": HOOK_TIMEOUT_S,
         "onFailure": HOOK_ON_FAILURE}]})
    hooks["PreToolUse"] = groups
    if statusline:
        if "statusLine" in data and not _is_our_statusline(data["statusLine"]):
            messages.append("You already have a status line — left untouched. To add the shield "
                            "to it, call this from your own script: " + statusline_command())
        else:
            data["statusLine"] = {"type": "command", "command": statusline_command()}
            messages.append("Status line installed (shield + today's checked/blocked counts).")
    if panel:
        _add_panel(data, messages)
    _atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    _write_receipt(path, original, _sha256_file(path))
    _clean_legacy_hooks_json(messages)
    messages.insert(0, f"Claude Code hook installed in {path}")
    return messages


def uninstall():
    path = _settings_path()
    data, existed = _load_settings(path)
    messages = []
    changed = False
    # Nothing else changed the file since install → put it back byte for byte.
    if existed and _restore_exact(path, _load_receipt(path)):
        _forget_receipt()
        _clean_legacy_hooks_json(messages)
        messages.insert(0, "Claude Code hook removed. settings.json is exactly as it was "
                           "before stillrunning was installed.")
        return messages
    _forget_receipt()
    if existed:
        hooks = data.get("hooks", {})
        before = hooks.get("PreToolUse", [])
        after = _strip_ours(before)
        if after != before:
            changed = True
            if after:
                hooks["PreToolUse"] = after
            else:
                hooks.pop("PreToolUse", None)
            if not hooks:
                data.pop("hooks", None)
        if _is_our_statusline(data.get("statusLine")):
            data.pop("statusLine")
            changed = True
        if _remove_panel(data):
            changed = True
        if changed:
            messages.append(f"Backup: {_backup(path)}")
            _atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    _clean_legacy_hooks_json(messages)
    messages.insert(0, "Claude Code hook removed." if changed
                    else "No stillrunning hook found in settings.json.")
    return messages


def verify_install():
    """→ (state, reason). state is "on" ONLY when our entry is present in
    ~/.claude/settings.json AND the interpreter and hook script it names
    exist and can be run; "off" when it is absent (or only the dead
    hooks.json exists); "not_verified" when we cannot tell."""
    import shlex
    try:
        data, _ = _load_settings(_settings_path())
    except InstallError:
        return "not_verified", "~/.claude/settings.json could not be parsed"
    except OSError as exc:
        return "not_verified", f"~/.claude/settings.json could not be read ({type(exc).__name__})"
    commands = [h.get("command", "") for group in data.get("hooks", {}).get("PreToolUse", [])
                if isinstance(group, dict) and isinstance(group.get("hooks"), list)
                for h in group["hooks"] if isinstance(h, dict) and _is_ours(h.get("command", ""))]
    if not commands:
        legacy = os.path.join(_home(), ".claude", "hooks.json")
        try:
            if os.path.exists(legacy):
                with open(legacy, encoding="utf-8") as handle:
                    if "stillrunning" in handle.read():
                        return "off", ("an older version wrote ~/.claude/hooks.json, a file "
                                       "Claude Code does not read")
        except OSError:  # lint: allowed-silent(legacy file unreadable → reported as not installed)
            return "off", "not installed"
        return "off", "not installed"
    command = commands[0]
    if command.strip() == "stillrunning hook":
        import shutil
        if shutil.which("stillrunning"):
            return "on", "registered in ~/.claude/settings.json"
        return "not_verified", "registered, but `stillrunning` is not on PATH for this shell"
    try:
        parts = shlex.split(command)
    except ValueError:
        return "not_verified", "registered, but the hook command could not be parsed"
    interpreter = parts[0] if parts else ""
    script = next((p for p in parts if p.endswith("claude_hook.py")), "")
    if not (os.path.isfile(interpreter) and os.access(interpreter, os.X_OK)):
        return "off", f"registered, but its Python ({interpreter}) no longer exists"
    if not (os.path.isfile(script) and os.access(script, os.R_OK)):
        return "off", f"registered, but the hook script ({script}) no longer exists"
    return "on", "registered in ~/.claude/settings.json; hook script found"


REREGISTER_ADVICE = ("registered without \"onFailure\": \"block\", so a crash or timeout of the "
                     "hook lets the command through; re-register: stillrunning --hook-claude-code")


def registered_fail_open():
    """True when one of our entries in ~/.claude/settings.json lacks
    "onFailure": "block" (registered by a version before it was added): the
    hook still decides, but Claude Code runs the command when the hook
    itself fails or times out. False when there is no entry or the file
    cannot be read (verify_install reports those)."""
    try:
        data, _ = _load_settings(_settings_path())
    except (InstallError, OSError):  # lint: allowed-silent(unreadable settings are reported by verify_install)
        return False
    return any(h.get("onFailure") != HOOK_ON_FAILURE
               for group in data.get("hooks", {}).get("PreToolUse", [])
               if isinstance(group, dict) and isinstance(group.get("hooks"), list)
               for h in group["hooks"] if isinstance(h, dict) and _is_ours(h.get("command", "")))


def installed_state():
    """'active' | 'legacy' (only the dead hooks.json) | 'absent' | 'unreadable'."""
    state, reason = verify_install()
    if state == "on":
        return "active"
    if state == "not_verified":
        return "unreadable"
    return "legacy" if "hooks.json" in reason else "absent"


# ── fail closed on the hook's own failure (fuzz findings F3, F4, R1, R2) ──
# A hook that crashes, exits with anything but 0 or 2, or runs past Claude
# Code's timeout lets the tool call through (hooks reference). So: any
# unhandled exception, and running past HOOK_DEADLINE_S, exit 2 — the code
# that blocks a PreToolUse call — with the reason on stderr.
_ANSWERED = []      # the exit code, once the decision has been handed to Claude Code


def _safe_script_streams():
    """The bare-script path (`python -I -S <this file>`, how Claude Code runs it)
    cannot import the package, so the entry points' make_output_safe() never ran
    here: on a Windows code page a non-ASCII warning (→, —) raised
    UnicodeEncodeError and crashed the process (found on a real windows-latest
    runner 2026-11-21). What reads these streams is Claude Code, which decodes
    them as UTF-8 — so a stream that is not UTF-8 is switched to UTF-8 (the
    status line's 🛡 arrives as 🛡, not as an ASCII tag). Windows only: on
    Linux and macOS nothing here runs, in any locale, so their output is
    exactly what it was."""
    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        name = (getattr(stream, "encoding", "") or "").lower().replace("-", "").replace("_", "")
        if name in ("utf8", "utf8sig"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            try:
                stream.reconfigure(errors="backslashreplace")
            except (AttributeError, ValueError, OSError):
                continue


def _block_now(why, kind="hook_error"):
    try:
        sys.stderr.write(f"stillrunning: {why} — the command was stopped. {explain(kind)}\n")
        sys.stderr.flush()
    except Exception:  # lint: allowed-silent(stderr gone: exit 2 still blocks)
        pass
    os._exit(2)


def _on_deadline(signum, frame):
    if _ANSWERED:
        os._exit(_ANSWERED[-1])          # the answer is out: end with it
    _block_now(f"the check did not finish within {HOOK_DEADLINE_S} s", "hook_deadline")


def _arm_deadline():
    """POSIX: a SIGALRM that interrupts even a long regex. Windows has no
    SIGALRM; there the registration's onFailure covers a timeout."""
    try:
        import signal
        import threading
        if hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGALRM, _on_deadline)
            signal.setitimer(signal.ITIMER_REAL, HOOK_DEADLINE_S)
            return True
    except (ImportError, ValueError, OSError, AttributeError):  # lint: allowed-silent(no deadline; onFailure covers it)
        pass
    return False


def _disarm_deadline():
    try:
        import signal
        if hasattr(signal, "setitimer"):
            signal.setitimer(signal.ITIMER_REAL, 0)
    except (ImportError, ValueError, OSError, AttributeError):  # lint: allowed-silent(nothing armed)
        pass


def _guarded_run():
    """run_hook on stdin; any failure of the hook itself blocks (exit 2)."""
    _arm_deadline()
    try:
        return run_hook(sys.stdin.read())
    except SystemExit:
        raise
    except BaseException as exc:      # RecursionError, MemoryError, KeyboardInterrupt, …
        try:
            _warn(f"hook failed ({type(exc).__name__}) — blocking")
        except Exception:  # lint: allowed-silent(stderr gone: exit 2 still blocks)
            pass
        _block_now(f"the hook failed ({type(exc).__name__})")
    finally:
        _disarm_deadline()


def _end_with(code):
    """End the hook process with `code` at once, after flushing: a lookup
    thread still waiting on the network can never hold the hook past its
    deadline (the decision was already printed and flushed by run_hook)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):  # lint: allowed-silent(stream already closed; the decision was flushed in _emit)
            continue
    os._exit(code)


def main():
    """`stillrunning hook`. Exits normally (SystemExit) unless a lookup thread
    is still running after the answer: then a normal exit would wait for it
    past Claude Code's timeout (the deadline is disarmed by then), so it ends
    at once like _script_main. No usage ping is sent on this path, so nothing
    at exit is skipped."""
    from ._stdio import make_output_safe
    make_output_safe()   # never crash on a non-UTF-8 console (Windows code pages)
    import threading
    before = set(threading.enumerate())
    code = _guarded_run()
    stop = time.monotonic() + 0.5          # idle pool workers end within milliseconds
    for thread in set(threading.enumerate()) - before:
        if not thread.daemon:
            thread.join(max(0.0, stop - time.monotonic()))
    if any(t.is_alive() and not t.daemon for t in set(threading.enumerate()) - before):
        _end_with(code)
    sys.exit(code)


def _script_main():
    """Run as the hook process (`python -I -S <this file>`)."""
    try:
        _safe_script_streams()
    except BaseException as exc:      # never let the output fix itself fail open
        _block_now(f"the hook failed ({type(exc).__name__})")
    _end_with(_guarded_run())


if __name__ == "__main__":
    _script_main()
