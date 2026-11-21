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
    """The hook's own stream set-up, under cp1252 (forced here so it also runs
    on Linux; on Windows that is the real default for a pipe). → and — raised
    UnicodeEncodeError before the fix; now the stream is UTF-8."""
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('hook', {os.path.join(PKG, 'claude_hook.py')!r})\n"
        "hook = importlib.util.module_from_spec(spec); spec.loader.exec_module(hook)\n"
        "hook._safe_script_streams()\n"
        "hook._warn('install → checked — ok')\n"
        "print('result → done — ok')\n", encoding="utf-8")
    env = dict(os.environ, PYTHONIOENCODING="cp1252", HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    r = subprocess.run([sys.executable, "-S", str(driver)], capture_output=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr.decode("cp1252", "replace")[-500:]
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


# ── investigation: does the hook see its OWN files named in bash-accepted forms? ──

def _forms(path):
    """Ways a bash command can name this file. Windows (Git Bash) accepts the
    quoted backslash form, forward slashes and the /d/… form; an unquoted
    backslash path is mangled by bash itself (D:\\a\\b → D:ab) and is listed
    only for the record."""
    if not WINDOWS:
        return {"plain": path, "quoted": f"'{path}'"}
    drive, rest = os.path.splitdrive(path)
    fwd = path.replace("\\", "/")
    return {"quoted backslash": f"'{path}'", "forward slash": fwd,
            "msys /d/": "/" + drive[0].lower() + rest.replace("\\", "/"),
            "unquoted backslash (bash mangles it)": path}


_TARGET = os.path.join(PKG, "claude_hook.py")


@pytest.mark.parametrize("form", list(_forms(_TARGET)))
@pytest.mark.parametrize("verb", ["rm {}", "sed -i s/a/b/ {}", "echo x >> {}"])
def test_investigate_own_files_in_bash_path_forms(form, verb, capsys):
    named = _forms(_TARGET)[form]
    command = verb.format(named)
    seen = ch.touches_protection(command, os.path.dirname(PKG))
    print(f"SELF-PROTECTION {sys.platform} | {form} | {command} -> {'PROTECTED' if seen else 'NOT SEEN'}")
    if not WINDOWS or "mangles" in form:
        if not WINDOWS:
            assert seen, command                  # POSIX: must hold (regression)
        return
    if not seen:
        pytest.xfail(f"investigation: {form} not recognised as the hook's own file")
