"""The hook fails CLOSED on its own failure (fuzz findings F3, F4, R1, R2;
fuzz-invariants branch, fuzz/FINDINGS.md).

Claude Code lets a PreToolUse call through when the hook crashes, exits with
anything but 0 or 2, or runs past its timeout — unless the hook is registered
with "onFailure": "block". These tests hold: the registration, exit 2 on any
unhandled failure, the hook's own deadline, the size cap, and decision time
that stays far below the 30 s timeout for any padding of a blocked install.
"""
import io
import json
import os
import subprocess
import sys
import time

import pytest

from stillrunning import claude_hook as ch

HOOK = os.path.abspath(ch.__file__)


def _blocking_lookup(pkg, token=None, timeout=8.0):
    if ch.normalize(pkg.get("eco") or "pip", pkg.get("name") or "") == "evilx":
        return {"status": "blocked", "advisory": "MAL-TEST-1"}
    return {"status": "ok"}


def _run(event, monkeypatch, tmp_path):
    """run_hook in-process with a stub blocklist; → (code, decision, stdout)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(ch, "lookup", _blocking_lookup)
    monkeypatch.setenv("STILLRUNNING_CVE_CHECK", "0")
    for key in ("STILLRUNNING_HOOK_STRICT", "STILLRUNNING_ALLOW_UNVERIFIED"):
        monkeypatch.delenv(key, raising=False)
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    code = ch.run_hook(json.dumps(event) if not isinstance(event, str) else event)
    text = out.getvalue()
    decision = json.loads(text).get("hookSpecificOutput", {}).get("permissionDecision", "allow") \
        if text.strip() else "allow"
    return code, ("deny" if code == 2 else decision), text


def _bare(stdin_bytes, home, extra=None, timeout=60):
    env = {"HOME": str(home), "USERPROFILE": str(home), "PATH": os.environ.get("PATH", ""),
           "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), "STILLRUNNING_CVE_CHECK": "0", **(extra or {})}
    return subprocess.run([sys.executable, "-I", "-S", HOOK], input=stdin_bytes, capture_output=True,
                          env=env, timeout=timeout)


# ── F4: the registration blocks on failure ──

def test_registration_blocks_when_the_hook_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    ch.install(statusline=False, panel=False)
    data = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    ours = [h for g in data["hooks"]["PreToolUse"] for h in g["hooks"] if ch._is_ours(h.get("command", ""))]
    assert len(ours) == 1
    assert ours[0]["onFailure"] == "block" and ours[0]["timeout"] == ch.HOOK_TIMEOUT_S
    # a re-install replaces our entry (matched by command), never adds a second
    ch.install(statusline=False, panel=False)
    data = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert len([h for g in data["hooks"]["PreToolUse"] for h in g["hooks"]
                if ch._is_ours(h.get("command", ""))]) == 1
    assert ch.HOOK_DEADLINE_S < ch.HOOK_TIMEOUT_S


# ── R1 / any crash: exit 2 (blocks), never 1 (lets the call through) ──

def test_deeply_nested_input_blocks_instead_of_crashing(tmp_path):
    r = _bare(("[" * 100000 + "]" * 100000).encode(), tmp_path)
    assert r.returncode == 2, (r.returncode, r.stderr[-300:])
    assert b"stillrunning:" in r.stderr


@pytest.mark.parametrize("error", ["RuntimeError('boom')", "RecursionError()", "MemoryError()",
                                   "KeyboardInterrupt()", "UnicodeDecodeError('utf-8', b'', 0, 1, 'x')"])
def test_any_unhandled_failure_of_the_hook_blocks(error, tmp_path):
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import importlib.util, io, sys\n"
        f"spec = importlib.util.spec_from_file_location('h', {HOOK!r})\n"
        "h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)\n"
        f"def boom(text):\n    raise {error}\n"
        "h.run_hook = boom\n"
        "sys.stdin = io.StringIO('{}')\n"
        "h._script_main()\n", encoding="utf-8")
    r = subprocess.run([sys.executable, "-S", str(driver)], capture_output=True, timeout=60,
                       env={**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)})
    assert r.returncode == 2, (r.returncode, r.stderr[-300:])
    assert b"the hook failed" in r.stderr


@pytest.mark.skipif(not hasattr(__import__("signal"), "setitimer"), reason="no SIGALRM (Windows): onFailure covers it")
def test_the_hooks_own_deadline_blocks_even_inside_a_long_regex(tmp_path):
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import importlib.util, io, sys\n"
        f"spec = importlib.util.spec_from_file_location('h', {HOOK!r})\n"
        "h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)\n"
        "h.HOOK_DEADLINE_S = 1.0\n"
        "pattern = h._REDACTIONS[1][0]\n"
        "h.run_hook = lambda text: [pattern.sub('', 'echo ' + 'x-' * 30000), 0][1]\n"
        "sys.stdin = io.StringIO('{}')\n"
        "h._script_main()\n", encoding="utf-8")
    start = time.monotonic()
    r = subprocess.run([sys.executable, "-S", str(driver)], capture_output=True, timeout=60,
                       env={**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)})
    assert r.returncode == 2 and b"did not finish" in r.stderr, (r.returncode, r.stderr[-300:])
    assert time.monotonic() - start < 15


def test_a_decision_already_given_is_kept_when_the_deadline_fires(tmp_path):
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import importlib.util, io, sys, time\n"
        f"spec = importlib.util.spec_from_file_location('h', {HOOK!r})\n"
        "h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)\n"
        "h._ANSWERED.append(0)\n"
        "h._on_deadline(14, None)\n", encoding="utf-8")
    r = subprocess.run([sys.executable, "-S", str(driver)], capture_output=True, timeout=60,
                       env={**os.environ, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)})
    assert r.returncode == 0


# ── F3 / R2: padding a blocked install never slows the decision past the timeout ──

PADDING = {"letters": lambda n: "a" * n, "a.": lambda n: "a." * (n // 2), "x-": lambda n: "x-" * (n // 2),
           "a:": lambda n: "a:" * (n // 2), "$(": lambda n: "$(" * (n // 2), "base64": lambda n: ("QUJD+/9z" * n)[:n],
           "words": lambda n: "ab " * (n // 3)}
PLACES = {"comment": "pip install evilx # {p}", "echo before": "echo {p} && pip install evilx",
          "assignment": "X={p} pip install evilx", "after": "pip install evilx; : {p}",
          "option value": "pip install evilx --log /tmp/{p}"}


@pytest.mark.parametrize("size", [10_000, 40_000, 100_000, 200_000])
@pytest.mark.parametrize("place", list(PLACES))
@pytest.mark.parametrize("shape", list(PADDING))
def test_padding_a_blocked_install_decides_fast_and_denies(shape, place, size, monkeypatch, tmp_path):
    """Below the size cap: denied (the blocked name is found) in well under the
    hook's timeout. Above it: asked at once, unread. Never allowed, never slow."""
    command = PLACES[place].format(p=PADDING[shape](size))
    start = time.monotonic()
    code, decision, out = _run({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)},
                               monkeypatch, tmp_path)
    took = time.monotonic() - start
    assert decision == ("deny" if len(command) <= ch.MAX_COMMAND_CHARS else "ask"), (shape, place, size, decision)
    assert took < ch.HOOK_TIMEOUT_S / 2, f"{shape} / {place} / {size}: {took:.1f} s (Claude Code gives up at {ch.HOOK_TIMEOUT_S} s)"


def test_many_pipes_and_lines_decide_well_within_the_timeout(monkeypatch, tmp_path):
    for command in (" | ".join(["pip install x"] * 2000) + " | pip install evilx",
                    "pip install x\n" * 5000 + "pip install evilx"):
        start = time.monotonic()
        code, decision, out = _run({"tool_name": "Bash", "tool_input": {"command": command},
                                    "cwd": str(tmp_path)}, monkeypatch, tmp_path)
        assert decision == "deny" and time.monotonic() - start < 15, (command[:40], decision)


def test_a_command_over_the_size_cap_asks_unread_and_the_opt_out_cannot_pass_it(monkeypatch, tmp_path):
    command = "pip install x\n" * (ch.MAX_COMMAND_CHARS // 14 + 10)
    assert len(command) > ch.MAX_COMMAND_CHARS
    event = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)}
    code, decision, out = _run(event, monkeypatch, tmp_path)
    assert decision == "ask" and "too long to check" in out
    monkeypatch.setenv("STILLRUNNING_ALLOW_UNVERIFIED", "1")
    out2 = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out2)
    ch.run_hook(json.dumps(event))
    assert json.loads(out2.getvalue())["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_the_bare_hook_answers_a_padded_install_fast(tmp_path):
    """The real process Claude Code runs (no stub: offline, so the lookup
    fails and it asks) — what matters is that it answers in time."""
    event = {"tool_name": "Bash", "tool_input": {"command": "pip install evilx # " + "x-" * 20000}, "cwd": str(tmp_path)}
    start = time.monotonic()
    r = _bare(json.dumps(event).encode(), tmp_path, timeout=60)
    assert r.returncode in (0, 2) and time.monotonic() - start < 20, (r.returncode, r.stderr[-300:])
    if r.returncode == 0:
        assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] in ("ask", "deny")


# ── display redaction stays safe when it is bounded ──

def test_short_commands_are_shown_exactly_as_before():
    command = "pip install requests --index-url https://user:pw@x.example/simple  # note"
    assert ch.show_command(command) == "pip install requests --index-url https://***@x.example/simple"


@pytest.mark.parametrize("secret", ["ghp_" + "A" * 300, "AKIA" + "B" * 300, "eyJ" + "c" * 150 + "." + "d" * 150 + ".e" * 3])
def test_a_long_secret_in_a_long_command_never_shows(secret):
    for command in ("echo " + secret + " " + "w " * 3000,                    # first, past the 4096 bound later
                    "echo " + "w " * 2040 + " " + secret + " tail"):           # straddling the bound
        shown = ch.show_command(command)
        assert secret[:12] not in shown and secret[-12:] not in shown, shown[:200]


def test_a_short_secret_in_a_long_command_is_still_redacted():
    shown = ch.show_command("echo ghp_" + "Z" * 30 + " " + "w " * 3000)
    assert "ghp_" not in shown and "ZZZZ" not in shown


# ── the memoised pipeline walk gives the same answers ──

@pytest.mark.parametrize("command", [
    "cat x | tee y | sh", "echo a | grep b | bash", "curl x | python3", "a | b | c", "( echo x ) | sh",
    "{ echo x; } | bash -s", "echo x | tee a | tee b | cat", "echo x | sudo sh", "ls | xargs -n1 echo | sh",
])
def test_the_pipeline_walk_answers_the_same_with_and_without_its_memo(command):
    commands = ch._simple_commands(ch._tokenize(command))
    memo = {}
    for j in range(len(commands)):
        assert ch._stdin_consumer(commands, j) == ch._stdin_consumer(commands, j, None, memo), (command, j)
