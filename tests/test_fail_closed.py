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


def _driver(path, home, timeout=60, flags=("-I", "-S")):
    """Run a driver script as the hook runs: isolated (-I -S), minimal env,
    so no PYTHONPATH or user site can change what is imported. The
    `stillrunning hook` path needs site-packages (PyYAML): flags=("-I",)."""
    env = {"HOME": str(home), "USERPROFILE": str(home), "PATH": os.environ.get("PATH", ""),
           "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), "STILLRUNNING_CVE_CHECK": "0"}
    return subprocess.run([sys.executable, *flags, str(path)], capture_output=True, timeout=timeout, env=env)


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
    r = _driver(driver, tmp_path)
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
    r = _driver(driver, tmp_path)
    assert r.returncode == 2 and b"did not finish" in r.stderr, (r.returncode, r.stderr[-300:])
    assert time.monotonic() - start < ch.HOOK_DEADLINE_S


def test_a_decision_already_given_is_kept_when_the_deadline_fires(tmp_path):
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import importlib.util, io, sys, time\n"
        f"spec = importlib.util.spec_from_file_location('h', {HOOK!r})\n"
        "h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)\n"
        "h._ANSWERED.append(0)\n"
        "h._on_deadline(14, None)\n", encoding="utf-8")
    r = _driver(driver, tmp_path)
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
    assert took < ch.HOOK_DEADLINE_S, f"{shape} / {place} / {size}: {took:.1f} s (the hook stops itself at {ch.HOOK_DEADLINE_S} s)"


def test_many_pipes_and_lines_decide_well_within_the_timeout(monkeypatch, tmp_path):
    for command in (" | ".join(["pip install x"] * 2000) + " | pip install evilx",
                    "pip install x\n" * 5000 + "pip install evilx"):
        start = time.monotonic()
        code, decision, out = _run({"tool_name": "Bash", "tool_input": {"command": command},
                                    "cwd": str(tmp_path)}, monkeypatch, tmp_path)
        assert decision == "deny" and time.monotonic() - start < ch.HOOK_DEADLINE_S, (command[:40], decision)


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
    took = time.monotonic() - start
    assert r.returncode in (0, 2) and took < ch.HOOK_DEADLINE_S, (r.returncode, took, r.stderr[-300:])
    assert b"did not finish" not in r.stderr        # answered, not stopped by the deadline
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


# ── reviews 3 and 4: a command over 4,096 characters is not shown at all ──

PASS = "Tr0ub4dor&3horse"
HEREDOC = "cat > notes.md <<'EOF'\nIt's the release checklist.\nEOF\n"


@pytest.mark.parametrize("command", [
    # review 3: a cut inside quotes, a long word swallowing the opening quote, a long comment
    "# " + " ".join(["note"] * 900) + f'\nmysql -u root --password "{PASS} battery staple" -e "select 1"',
    "x " * 900 + f'curl --password "{"a" * 300} {PASS} more" https://x.example' + " ok" * 1000,
    "x " * 900 + f'export API_TOKEN="{"a" * 300} {PASS}"' + " ok" * 1000,
    # review 4 A1: an apostrophe in a heredoc body before a quoted password
    HEREDOC + f"mysql -u root --password '{PASS} battery' -e \"select 1\"\n" + "echo step done\n" * 400,
    "echo don't " + "w " * 100 + f"mysql --password '{PASS} battery'" + " ok" * 1500,
    # review 4 A2: a long word that takes the program name with it
    "/" + "v" * 300 + f"/twine upload dist/* -u __token__ -p {PASS}" + " ok" * 1500,
    'X="' + "a" * 300 + f'";mysql -u root -p{PASS} db' + " ok" * 1500,
    'cd "' + "a" * 300 + f'"&&docker login -u bob -p {PASS} reg' + " ok" * 1500,
    # review 4 A3: the cut dropping a trailing anchor; a two-value rule misaligned
    " ".join("TOKEN=" + "t" * 250 for _ in range(16)) + f" && echo {PASS} | docker login --password-stdin",
    "poetry config http-basic.r " + "u" * 300 + f" {PASS}" + " ok" * 1500,
])
def test_a_long_command_is_not_shown_so_no_secret_in_it_can_show(command):
    assert len(command) > ch._SHOW_EXACT
    shown = ch.show_command(command)
    assert shown == f"[command of {len(command)} characters, not shown]"
    assert PASS not in shown and "battery" not in shown


def test_the_decision_log_of_a_long_command_names_the_package_but_not_the_command(monkeypatch, tmp_path):
    command = HEREDOC + f"mysql --password '{PASS} battery'\n" + "echo step done\n" * 400 + "pip install evilx"
    code, decision, out = _run({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)},
                               monkeypatch, tmp_path)
    assert decision == "deny" and PASS not in out
    log = (tmp_path / ".stillrunning" / "hook_decisions.jsonl").read_text(encoding="utf-8")
    assert PASS not in log and "battery" not in log and "evilx" in log
    assert f"[command of {len(command)} characters, not shown]" in log


def test_the_boundary_is_exact():
    command = "echo " + "a " * 2045 + "b"
    assert len(command) == ch._SHOW_EXACT
    assert ch.show_command(command, limit=10 ** 6) == " ".join(command.split())
    assert ch.show_command(command + "c") == f"[command of {ch._SHOW_EXACT + 1} characters, not shown]"


@pytest.mark.parametrize("count", [1000, 4000])
def test_many_separate_install_commands_decide_in_linear_time(count, monkeypatch, tmp_path):
    """review 4 B: `pip install x ; pip install q1 ; …` rebuilt the known names
    for every command (4,000 commands 16 s)."""
    command = " ; ".join(f"pip install q{i}" for i in range(count)) + " ; pip install evilx"
    start = time.monotonic()
    code, decision, out = _run({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)},
                               monkeypatch, tmp_path)
    assert decision == "deny" and time.monotonic() - start < count / 400 + 2, time.monotonic() - start


# ── review 3: many packages, and the band just under the size cap ──

@pytest.mark.parametrize("count", [5000, 10000])
def test_a_command_naming_thousands_of_packages_decides_fast_and_denies(count, monkeypatch, tmp_path):
    command = "pip install " + " ".join(f"pkg{i}" for i in range(count)) + " evilx"
    start = time.monotonic()
    code, decision, out = _run({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)},
                               monkeypatch, tmp_path)
    assert decision == "deny" and time.monotonic() - start < ch.HOOK_DEADLINE_S


@pytest.mark.parametrize("place", ["comment", "assignment", "echo before"])
@pytest.mark.parametrize("shape", ["letters", "$(", "x-", "words"])
def test_padding_right_under_the_size_cap_still_denies_in_time(shape, place, monkeypatch, tmp_path):
    room = ch.MAX_COMMAND_CHARS - len(PLACES[place].format(p=""))
    command = PLACES[place].format(p=PADDING[shape](room))
    assert ch.MAX_COMMAND_CHARS - 3 <= len(command) <= ch.MAX_COMMAND_CHARS
    start = time.monotonic()
    code, decision, out = _run({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)},
                               monkeypatch, tmp_path)
    assert decision == "deny" and time.monotonic() - start < ch.HOOK_DEADLINE_S, (shape, place, decision)


# ── review 3: `stillrunning hook` ends at once, like the registered script ──

def test_the_cli_hook_path_does_not_wait_for_lookup_threads(tmp_path):
    root = os.path.dirname(os.path.dirname(HOOK))
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import io, sys, threading, time\n"
        f"sys.path.insert(0, {root!r})\n"
        "from stillrunning import claude_hook as h\n"
        "def answer(text):\n"
        "    threading.Thread(target=time.sleep, args=(120,)).start()   # a hung lookup (not daemon)\n"
        "    print('{}'); return 0\n"
        "h.run_hook = answer\n"
        "sys.stdin = io.StringIO('{}')\n"
        "h.main()\n", encoding="utf-8")
    start = time.monotonic()
    r = _driver(driver, tmp_path, flags=("-I",))
    assert r.returncode == 0 and time.monotonic() - start < 20, (r.returncode, r.stdout[-300:], r.stderr[-300:])


# ── review 3: an entry from before onFailure is reported, with the fix ──

def test_an_old_registration_without_on_failure_is_reported(tmp_path, monkeypatch):
    from stillrunning import layers, panel
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    ch.install(statusline=False, panel=False)
    assert ch.registered_fail_open() is False
    path = tmp_path / ".claude" / "settings.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for group in data["hooks"]["PreToolUse"]:
        for hook in group["hooks"]:
            hook.pop("onFailure", None)
    path.write_text(json.dumps(data), encoding="utf-8")
    assert ch.verify_install()[0] == "on" and ch.registered_fail_open() is True
    layer = next(x for x in layers.protection_layers() if x["key"] == "claude_hook")
    assert layer["next"] == "stillrunning --hook-claude-code" and "onFailure" in layer["reason"]
    assert any("onFailure" in p for p in panel.protection()["problems"])
    ch.install(statusline=False, panel=False)          # re-registering clears it
    assert ch.registered_fail_open() is False
    layer = next(x for x in layers.protection_layers() if x["key"] == "claude_hook")
    assert layer["next"] is None


# ── review 3: invalid UTF-8 in a command is logged, not a crash ──

def test_a_command_with_invalid_utf8_is_decided_and_logged(tmp_path, monkeypatch):
    event = '{"tool_name": "Bash", "tool_input": {"command": "pip install \\udcff evilx"}, "cwd": "/tmp"}'
    code, decision, out = _run(event, monkeypatch, tmp_path)
    assert decision == "deny"
    lines = (tmp_path / ".stillrunning" / "hook_decisions.jsonl").read_text(encoding="utf-8").splitlines()
    assert any("\udcff" in json.loads(line).get("command", "") for line in lines)
