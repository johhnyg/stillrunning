"""Regression tests for the bugs a real windows-latest runner found (2026-11-21).

Every test runs on every OS in CI. On Linux each one proves the behaviour is
unchanged; on Windows it proves the fix. The simulated Windows tests of
2026-11-20 (tests/test_windows_py38_compat.py) missed all of these.
"""
import json
import os
import subprocess
import sys

import pytest

from stillrunning import claude_hook as ch
from stillrunning import cve, statusline

PKG = os.path.dirname(os.path.abspath(ch.__file__))
WINDOWS = os.name == "nt"


def _lookup(pkg, token=None, timeout=8.0):
    if ch.normalize(pkg["eco"], pkg["name"]) == "evilx":
        return {"status": "blocked", "advisory": "MAL-2026-0001"}
    return {"status": "ok"}


def _decide(command, cwd):
    return ch.decide(command, cwd=cwd, lookup_fn=_lookup, env={})


# ── 1. fail-open: a blocklisted install inside a script written then run ──

WRITTEN_THEN_RUN = [
    "cat > x.sh <<EOF\npip install evilx\nEOF\nchmod +x x.sh && ./x.sh",       # the case found
    "cat > x.sh <<EOF\npip install evilx\nEOF\n./x.sh",
    "printf 'pip install evilx\\n' > x.sh && sh ./x.sh",
    "echo 'pip install evilx' > run.sh; chmod +x run.sh; ./run.sh",
    "cat > sub/x.sh <<'EOF'\npip install evilx\nEOF\nbash sub/x.sh",
    "cat > sub/x.sh <<EOF\npip install evilx\nEOF\n./sub/x.sh",
]


@pytest.mark.parametrize("command", WRITTEN_THEN_RUN)
def test_blocklisted_install_in_a_written_then_run_script_is_denied(command, tmp_path):
    """DENY on every OS. Before the fix Windows returned ALLOW: `./x.sh` has no
    os.sep there ("\\"), so the script was never read."""
    (tmp_path / "sub").mkdir()
    d = _decide(command, str(tmp_path))
    assert d["action"] == "deny", (command, [r["subject"] for r in d["records"]])
    assert any(r["verdict"] == "blocked" and r["name"] == "evilx" for r in d["records"])


def test_a_variable_path_to_pip_is_still_recognised_as_pip(tmp_path):
    """`"$VIRTUAL_ENV/bin/pip"` was "unverified" on Windows (no os.sep in it)."""
    d = _decide('"$VIRTUAL_ENV/bin/pip" install evilx', str(tmp_path))
    assert d["action"] == "deny"


def test_shell_word_separators():
    assert ch._WORD_SEPS == ("/\\" if WINDOWS else "/")
    assert ch._has_sep("./x.sh") and ch._has_sep("sub/x.sh") and not ch._has_sep("x.sh")
    assert ch._has_sep(".\\x.sh") is WINDOWS          # "\\" counts only where Windows uses it


# ── 2. the bare-script path (how Claude Code runs the hook) never crashes on output ──

def _bare(script, stdin, env_extra=None, isolated=True):
    env = dict(os.environ, **(env_extra or {}))
    flags = ["-I", "-S"] if isolated else ["-S"]
    return subprocess.run([sys.executable, *flags, os.path.join(PKG, script)], input=stdin.encode("utf-8"),
                          capture_output=True, env=env, timeout=60)


def test_status_line_runs_as_a_bare_script_with_non_ascii_output(tmp_path):
    """Claude Code pipes the output. On Windows the pipe is the ANSI code page,
    which crashed on the status line's symbols before the fix (exit 1)."""
    payload = json.dumps({"workspace": {"current_dir": str(tmp_path)}, "cwd": str(tmp_path)})
    r = _bare("statusline.py", payload, {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)})
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-500:]
    assert r.stdout.strip() and b"Traceback" not in r.stderr
    assert "\U0001f6e1".encode("utf-8") in r.stdout          # the shield arrives as UTF-8, not "<U+1F6E1>"


def test_bare_hook_streams_survive_a_code_page(tmp_path):
    """The hook's own stream set-up under cp1252 (on Windows the real default
    for a pipe). Before the fix → and — raised UnicodeEncodeError there; now the
    stream is UTF-8. Off Windows the set-up does nothing at all, in any locale
    (Linux output stays exactly what it was)."""
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('hook', {os.path.join(PKG, 'claude_hook.py')!r})\n"
        "hook = importlib.util.module_from_spec(spec); spec.loader.exec_module(hook)\n"
        "before = (sys.stdout.encoding, sys.stdout.errors, sys.stderr.encoding, sys.stderr.errors)\n"
        "hook._safe_script_streams()\n"
        "after = (sys.stdout.encoding, sys.stdout.errors, sys.stderr.encoding, sys.stderr.errors)\n"
        "if hook.os.name != 'nt':\n"
        "    print('UNCHANGED' if before == after else 'CHANGED'); sys.exit(0)\n"
        "hook._warn('install → checked — ok')\n"
        "print('result → done — ok')\n", encoding="utf-8")
    env = dict(os.environ, PYTHONIOENCODING="cp1252", HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    r = subprocess.run([sys.executable, "-S", str(driver)], capture_output=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr.decode("cp1252", "replace")[-500:]
    if not WINDOWS:
        assert r.stdout.strip() == b"UNCHANGED"
        return
    # a non-UTF-8 stream is switched to UTF-8 (Claude Code reads these as UTF-8)
    assert "result → done — ok" in r.stdout.decode("utf-8")
    assert "install → checked — ok" in r.stderr.decode("utf-8")


def test_bare_hook_answer_is_unchanged_json(tmp_path):
    """The hook's JSON answer to Claude Code is ASCII and unaffected (same on every OS)."""
    r = _bare("claude_hook.py", json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls -la"}}),
              {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)})
    assert r.returncode == 0 and all(b < 128 for b in r.stdout)


# ── 3. CVE monitoring on Windows folders ──

def test_this_platforms_own_folders_are_safe_roots(tmp_path):
    """Before the fix the pattern accepted only "/…", so every Windows folder
    read "checked for another folder" (UNKNOWN)."""
    assert cve._SAFE_ROOT.match(os.path.realpath(str(tmp_path)))


def test_unsafe_roots_stay_rejected():
    for bad in ["relative/x", "x;rm -rf /", "/a\nb", "$(id)"]:
        assert not cve._SAFE_ROOT.match(bad), bad
    if WINDOWS:
        for bad in [r"\\server\share\x", "C:relative", r"C:\a;b", r"C:\x\$y"]:
            assert not cve._SAFE_ROOT.match(bad), bad
    else:
        assert cve._SAFE_ROOT.pattern == r"^/[A-Za-z0-9 ._/@+-]{0,400}$"     # unchanged on POSIX


def test_saved_state_for_this_folder_is_not_another_folder(tmp_path):
    root = os.path.realpath(str(tmp_path))
    out = cve.evaluate_for({"root": root}, 1_800_000_000.0, root)
    assert not any("another folder" in r for r in out["reasons"]), out["reasons"]


@pytest.mark.skipif(not WINDOWS, reason="8.3 short names exist only on Windows")
def test_a_short_name_is_the_same_folder(tmp_path):
    import ctypes
    long_path = os.path.realpath(str(tmp_path))
    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetShortPathNameW(long_path, buf, len(buf)) or buf.value == long_path:
        pytest.skip("no 8.3 short name for this folder on this runner")
    assert os.path.realpath(buf.value) == long_path
    out = cve.evaluate_for({"root": long_path}, 1_800_000_000.0, buf.value)
    assert not any("another folder" in r for r in out["reasons"])
    out = cve.evaluate_for({"root": long_path}, 1_800_000_000.0, long_path.upper())
    assert not any("another folder" in r for r in out["reasons"])


def test_status_line_takes_this_platforms_folder_from_claude_code(tmp_path, monkeypatch):
    import io
    folder = str(tmp_path)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"cwd": folder})))
    assert statusline._cwd_from_stdin() == folder
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"cwd": "C:\\x\\y"})))
    assert statusline._cwd_from_stdin() == ("C:\\x\\y" if WINDOWS else None)   # POSIX: unchanged


@pytest.mark.skipif(not WINDOWS, reason="Windows has no crontab")
def test_schedule_says_windows_has_no_crontab(capsys, monkeypatch):
    called = []
    monkeypatch.setattr(cve, "_crontab", lambda *a, **k: called.append(a))
    assert cve.schedule("C:\\x") == 1 and not called
    assert "Windows does not have" in capsys.readouterr().out


# ── 4. self-protection: stillrunning's own files under every Windows spelling ──
# Found on the real runner 2026-11-21: `rm /d/…/claude_hook.py` (Git Bash's own
# spelling) changed the hook's code without asking. Every spelling below must
# now be seen, for every operation that is seen on Linux. On Windows real Git
# Bash is asked first (`[ a -ef b ]`) that the spelling is that file, so the
# test can never pass by testing spellings that name something else.

def _git_bash():
    import shutil
    git = shutil.which("git")
    for candidate in ([os.path.join(os.path.dirname(os.path.dirname(git)), "bin", "bash.exe")] if git else []) + \
            [r"C:\Program Files\Git\bin\bash.exe"]:
        if os.path.isfile(candidate):
            return candidate          # never System32\bash.exe (the WSL stub)
    return None


def _short(path):
    import ctypes
    buf = ctypes.create_unicode_buffer(32768)
    if ctypes.windll.kernel32.GetShortPathNameW(path, buf, len(buf)) and buf.value.lower() != path.lower():
        return buf.value
    return None


def _spellings(path):
    """name → (the word as typed in a bash command, the same name as one argument)."""
    if not WINDOWS:
        return {"plain": (path, path), "quoted": (f"'{path}'", path)}
    drive, rest = os.path.splitdrive(path)
    fwd, msys = path.replace("\\", "/"), rest.replace("\\", "/")
    d = drive[0].lower()
    host = os.environ.get("COMPUTERNAME", "localhost")
    out = {
        "quoted D:\\": (f"'{path}'", path), "D:/": (fwd, fwd), "d:/ (lower drive)": (d + fwd[1:], d + fwd[1:]),
        "/d/ (Git Bash)": ("/" + d + msys, "/" + d + msys), "/D/": ("/" + d.upper() + msys, "/" + d.upper() + msys),
        "/cygdrive/d/": ("/cygdrive/" + d + msys, "/cygdrive/" + d + msys),
        "/proc/cygdrive/d/": ("/proc/cygdrive/" + d + msys, "/proc/cygdrive/" + d + msys),
        "UPPER CASE": (fwd.upper(), fwd.upper()), "mixed separators": (f"'{drive}{rest.replace(os.sep, '/', 2)}'", drive + rest.replace(os.sep, "/", 2)),
        "//?/D:/": ("//?/" + fwd, "//?/" + fwd), "//./D:/": ("//./" + fwd, "//./" + fwd),
        "quoted \\\\?\\D:\\": (f"'\\\\?\\{path}'", "\\\\?\\" + path),
        "//localhost/d$/": (f"'//localhost/{d}$'{msys}", f"//localhost/{d}$" + msys),
        "//127.0.0.1/d$/": (f"'//127.0.0.1/{d}$'{msys}", f"//127.0.0.1/{d}$" + msys),
        "//COMPUTERNAME/d$/": (f"'//{host}/{d}$'{msys}", f"//{host}/{d}$" + msys),
        "//?/UNC/localhost/d$/": (f"'//?/UNC/localhost/{d}$'{msys}", f"//?/UNC/localhost/{d}$" + msys),
        "/d/ doubled slashes": ("/" + d + msys.replace("/", "//"), "/" + d + msys.replace("/", "//")),
        "trailing dot": (fwd + ".", fwd + "."), "trailing space": (f"'{fwd} '", fwd + " "),
        "::$DATA": (f"'{fwd}::$DATA'", fwd + "::$DATA"),
    }
    short = _short(path)
    if short:
        out["8.3 short name"] = (short.replace("\\", "/"), short.replace("\\", "/"))
    return out


_FILE_OPS = ["rm {t}", "rm -f {t}", "unlink {t}", "shred -u {t}", "mv {t} /tmp/x", "mv /tmp/x {t}",
             "cp /tmp/x {t}", "ln -sf /tmp/x {t}", "install /tmp/x {t}", "truncate -s0 {t}", "chmod 000 {t}",
             "sed -i s/a/b/ {t}", "sed -i.bak s/a/b/ {t}", "perl -pi -e s/a/b/ {t}", "echo x > {t}",
             "echo x >> {t}", ": > {t}", "cat /tmp/x > {t}", "tee {t} < /tmp/x", "tee -a {t} < /tmp/x",
             "dd if=/tmp/x of={t}", "printf x >| {t}", "exec 3>{t}", "touch {t}", "patch {t} < /tmp/p",
             "rsync /tmp/x {t}", "git checkout -- {t}", "env rm {t}", "command rm {t}", "sudo rm {t}",
             "nohup rm {t}", "rm.exe {t}", "/usr/bin/rm {t}", "cat > {t} <<E\nx\nE"]
_QUOTING_OPS = ["bash -c 'rm {t}'", "python3 -c \"open('{t}','w')\""]   # only for unquoted spellings
_FOLDER_OPS = ["rm -rf {d}", "find {d} -delete", "cp -r /tmp/d {d}", "cd {d} && rm {n}",
               "pushd {d}; rm {n}", "rm {d}/*", "cp /tmp/x {d}/", "mv /tmp/x {d}", "git -C {d} checkout ."]
_WINDOWS_OPS = ["cmd //c del {w}", "cmd //c \"del /f {w}\"", "cmd.exe /c del {w}", "cmd //c \"type nul > {w}\"",
                "cmd //c \"echo x >> {w}\"", "cmd //c \"copy /y x {w}\"", "cmd //c \"move x {w}\"",
                "cmd //c \"ren {w} y\"", "powershell -c \"Remove-Item {w}\"",
                "powershell -Command \"Set-Content -Path {w} -Value x\"", "pwsh -c \"Add-Content {w} x\"",
                "powershell -c \"'' | Out-File {w}\"", "powershell -c \"ri -Force {w}\"",
                "icacls {w} //deny Everyone:F", "attrib +r {w}", "takeown //f {w}", "xcopy x {w}",
                "certutil -decode x {w}"]


@pytest.fixture
def home(monkeypatch, tmp_path):
    """A temporary home on every OS (never the real ~/.stillrunning or ~/.claude)."""
    folder = tmp_path / "home"
    folder.mkdir()
    monkeypatch.setenv("HOME", str(folder))      # conftest moves USERPROFILE with it on Windows
    monkeypatch.setenv("USERPROFILE", str(folder))
    assert os.path.realpath(ch._home()) == os.path.realpath(str(folder))
    return folder


def _targets():
    home = os.path.realpath(ch._home())
    state = os.path.join(home, ".stillrunning", "config.json")
    settings = os.path.join(home, ".claude", "settings.json")
    for path in (state, settings):           # real files, so bash and 8.3 names can see them
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            open(path, "w").close()
    return {"the hook's code": os.path.join(PKG, "claude_hook.py"), "the state folder": state,
            "Claude Code settings": settings}


def _same_file_per_bash(bash, a, b):
    r = subprocess.run([bash, "-c", '[ "$1" -ef "$2" ]', "_", a, b], capture_output=True, timeout=30)
    return r.returncode == 0


_MUST_BE_SAME = ("quoted D:\\", "D:/", "/d/ (Git Bash)", "d:/ (lower drive)", "UPPER CASE")


@pytest.mark.parametrize("target", ["the hook's code", "the state folder", "Claude Code settings"])
def test_own_files_are_protected_in_every_bash_spelling(target, home):
    """REQUIRED (was an expected failure): every operation x every spelling asks."""
    path = _targets()[target]
    folder, name = os.path.split(path)
    bash = _git_bash() if WINDOWS else None
    missed, checked, bash_says = [], 0, {}
    for label, (word, arg) in _spellings(path).items():
        if bash:
            bash_says[label] = _same_file_per_bash(bash, arg, path.replace("\\", "/"))
        ops = _FILE_OPS + ([] if "'" in word else _QUOTING_OPS)
        commands = [op.format(t=word) for op in ops]
        if label not in ("trailing dot", "trailing space", "::$DATA"):
            fword = _spellings(folder)[label][0] if label in _spellings(folder) else None
            if fword:
                commands += [op.format(d=fword, n=name) for op in _FOLDER_OPS]
        for command in commands:
            checked += 1
            if not ch.touches_protection(command, os.path.dirname(PKG)):
                missed.append(f"{label}: {command!r}")
    for label, same in sorted(bash_says.items()):
        print(f"SELF-PROTECTION {target} | {label} | Git Bash says same file: {same}")
    print(f"SELF-PROTECTION {target}: {checked - len(missed)}/{checked} protected")
    if bash:
        not_same = [label for label in _MUST_BE_SAME if not bash_says.get(label)]
        assert not not_same, f"Git Bash did not see these as the file (test would be vacuous): {not_same}"
    assert not missed, f"{len(missed)} of {checked} not protected:\n" + "\n".join(missed[:40])


@pytest.mark.skipif(not WINDOWS, reason="cmd / PowerShell / Windows tools exist only on Windows")
@pytest.mark.parametrize("target", ["the hook's code", "the state folder", "Claude Code settings"])
def test_windows_tools_changing_own_files_ask(target, home):
    path = _targets()[target]
    spellings = _spellings(path)
    missed = []
    for label in ("quoted D:\\", "D:/", "/d/ (Git Bash)", "UPPER CASE"):
        word = spellings[label][0].strip("'")
        for op in _WINDOWS_OPS:
            command = op.format(w=word if "\"" in op else f"'{word}'" if "\\" in word else word)
            if not ch.touches_protection(command, os.path.dirname(PKG)):
                missed.append(f"{label}: {command!r}")
    assert not missed, "\n".join(missed)


@pytest.mark.skipif(not WINDOWS, reason="Windows variables and tools")
def test_windows_variables_and_encoded_powershell_ask(home):
    _targets()
    for command in ["rm -rf $USERPROFILE/.stillrunning", "rm -rf \"$USERPROFILE\\.stillrunning\"",
                    "echo x > ${USERPROFILE}/.claude/settings.json", "rm -rf ~/.STILLRUNNING",
                    "echo x > ~/.claude/Settings.JSON", "cd $USERPROFILE && rm -rf .stillrunning",
                    "cmd //c \"rmdir /s /q %USERPROFILE%\\.stillrunning\"",
                    "powershell -c \"Remove-Item -Recurse $env:USERPROFILE\\.stillrunning\"",
                    "powershell -c \"rm -r ~\\.stillrunning\"", "powershell -e SQBFAFgA",
                    "powershell -EncodedCommand SQBFAFgA"]:
        assert ch.touches_protection(command, os.path.dirname(PKG)), command


@pytest.mark.parametrize("target", ["the hook's code", "the state folder", "Claude Code settings"])
def test_write_and_edit_tools_see_own_files_in_every_spelling(target, home):
    path = _targets()[target]
    missed = [label for label, (word, arg) in _spellings(path).items()
              if not ch.protected_path(arg, os.path.dirname(PKG))]
    assert not missed, missed


# ── 5. fail-open, the Windows spellings of "a script this command wrote, then runs" ──

@pytest.mark.skipif(not WINDOWS, reason="Windows path spellings")
@pytest.mark.parametrize("make", [
    lambda d: f"cat > x.sh <<EOF\npip install evilx\nEOF\n{d['msys']}/x.sh",
    lambda d: f"cat > x.sh <<EOF\npip install evilx\nEOF\nbash {d['msys']}/x.sh",
    lambda d: f"cat > x.sh <<EOF\npip install evilx\nEOF\n{d['fwd']}/x.sh",
    lambda d: f"cat > x.sh <<EOF\npip install evilx\nEOF\n{d['fwd'].lower()}/x.sh",
    lambda d: f"cat > x.sh <<EOF\npip install evilx\nEOF\n{d['fwd'].upper()}/X.SH",
    lambda d: f"cat > {d['msys']}/x.sh <<EOF\npip install evilx\nEOF\n./x.sh",
    lambda d: "cat > X.sh <<EOF\npip install evilx\nEOF\n./x.sh",
    lambda d: "cat > X.sh <<EOF\npip install evilx\nEOF\nbash x.sh",
    lambda d: f"cd {d['msys']} && cat > x.sh <<EOF\npip install evilx\nEOF\n./x.sh",
    lambda d: "echo pip install evilx > x.bat && cmd //c x.bat",
    lambda d: "echo pip install evilx > x.cmd && ./x.cmd",
    lambda d: "echo 'pip install evilx' > x.ps1 && powershell -ExecutionPolicy Bypass -File x.ps1",
    lambda d: "echo 'pip install evilx' > x.ps1 && pwsh ./x.ps1",
], ids=["/c/…/x.sh", "bash /c/…", "C:/…", "c:/… lower", "C:/…/X.SH case", "write /c/… run ./",
        "X.sh then ./x.sh", "X.sh then bash x.sh", "cd /c/… then ./x.sh", "x.bat via cmd", "./x.cmd",
        "x.ps1 via powershell", "x.ps1 via pwsh"])
def test_windows_spellings_of_a_written_then_run_script_are_denied(make, tmp_path):
    here = os.path.realpath(str(tmp_path))
    drive, rest = os.path.splitdrive(here)
    d = {"fwd": here.replace("\\", "/"), "msys": "/" + drive[0].lower() + rest.replace("\\", "/")}
    command = make(d)
    assert _decide(command, here)["action"] == "deny", command


@pytest.mark.parametrize("command", [
    "cat > x.sh <<EOF\npip install evilx\nEOF\nsh -c ./x.sh",
    "cat > x.sh <<EOF\npip install evilx\nEOF\nbash -c 'bash x.sh'",
    "cat > x.sh <<EOF\npip install evilx\nEOF\n$PWD/x.sh",
    "cat > x.sh <<EOF\npip install evilx\nEOF\n\"$(pwd)/x.sh\"",
])
def test_known_gap_on_every_os_written_script_run_through_c_or_pwd(command, tmp_path):
    """Known gap on every OS (not Windows-specific), kept visible for its own fix."""
    if _decide(command, str(tmp_path))["action"] != "deny":
        pytest.xfail("known gap on every OS: -c strings and $PWD paths are not matched to written files")
