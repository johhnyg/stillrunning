"""Session 135, fifth review: runner commands with flags the parser does not
know, plus the redaction and self-protection notes.

The rule under test: a misread flag fails toward blocking. Whatever flag
stands before the tool a runner will execute, a blocklisted tool is denied,
and a harmless tool with the same flags gets no extra answer.
"""
import json
import os

import pytest

from stillrunning import claude_hook as h

BAD = "evilpkg"


def stub(pkg, token=None, timeout=8.0):
    return {"status": "blocked", "advisory": "MAL-1"} if pkg["name"] == BAD else {"status": "ok"}


@pytest.fixture
def cwd(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.setattr(h, "_shadow_lookup", lambda pkg, timeout=4.0: stub(pkg))   # no network
    work = tmp_path / "work"
    work.mkdir()
    (work / "constraints.txt").write_text("requests<3\n")
    (work / ".env").write_text("A=1\n")
    return str(work)


def decide(command, cwd):
    return h.decide(command, cwd=cwd, lookup_fn=stub)


# the fifth reviewer's verbatim misses (uv's own value-taking flags)
UV_FLAGS = [
    "--constraints constraints.txt", "--build-constraints constraints.txt", "-b constraints.txt",
    "--overrides constraints.txt", "--env-file .env", "--python-platform linux", "--torch-backend cpu",
    "--upgrade-package requests", "-P requests", "--reinstall-package requests",
    "--refresh-package requests", "--fork-strategy fewest", "--exclude-newer-package requests=2025-01-01",
    "--config-setting k=v", "--no-build-package requests", "--no-binary-package requests",
    "--no-build-isolation-package requests", "--allow-insecure-host example.com",
]
# flags that exist in no tool: the parser cannot know whether they take a value
UNKNOWN_FLAGS = ["--zz-unknown v", "-Z v", "--zz=v"]


@pytest.mark.parametrize("runner", ["uvx", "uv tool run"])
@pytest.mark.parametrize("flag", UV_FLAGS)
def test_reviewer_misses_now_deny(cwd, runner, flag):
    assert decide(f"{runner} {flag} {BAD}", cwd)["action"] == "deny"


@pytest.mark.parametrize("runner", ["uvx", "uv tool run", "uv tool install", "pipx run", "pipx install",
                                    "npx", "pnpm dlx", "yarn dlx", "bunx"])
@pytest.mark.parametrize("flag", UV_FLAGS + UNKNOWN_FLAGS)
def test_any_flag_before_a_blocklisted_tool_never_lets_it_through(cwd, runner, flag):
    assert decide(f"{runner} {flag} {BAD}", cwd)["action"] == "deny"


def test_npm_exec_after_double_dash_with_an_odd_first_word_is_not_silent(cwd):
    """After `--` the first word is the command itself; a flag-shaped one is
    not a package npm can fetch, so this asks rather than passing silently."""
    assert decide(f"npm exec -- --zz=v {BAD}", cwd)["action"] in ("deny", "ask")


@pytest.mark.parametrize("runner", ["uvx", "uv tool run", "npx", "pnpm dlx"])
@pytest.mark.parametrize("flag", UV_FLAGS + UNKNOWN_FLAGS)
def test_a_harmless_tool_with_the_same_flags_is_never_blocked(cwd, runner, flag):
    assert decide(f"{runner} {flag} ruff", cwd)["action"] != "deny"


def test_a_fixed_option_word_that_collides_with_a_package_name_does_not_block(cwd, monkeypatch):
    """`requires-python` is a `--fork-strategy` value and also a name on the
    live blocklist; the option's own word is never looked up."""
    monkeypatch.setattr(h, "_shadow_lookup", lambda pkg, timeout=4.0: (
        {"status": "blocked"} if pkg["name"] == "requires-python" else {"status": "ok"}))
    assert decide("uvx --fork-strategy requires-python ruff", cwd)["action"] != "deny"


# ── redaction notes ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "yarn config set npmAuthToken SECRETV1",
    "openssl enc -aes256 -k SECRETV2 -in a",
    "openssl enc -pass pass:SECRETV3 -in a",
    "gh auth login --with-token <<< SECRETV4",
    "echo 'SECRETV5' | gh auth login --with-token",
    "op signin --raw SECRETV6",
    "python -c \"api_token = 'SECRETV7'; print(1)\"",
    "printf SECRETV8 | docker login --password-stdin",
    "docker login --password-stdin <<< SECRETV9",
])
def test_secrets_never_reach_the_decision_log(command):
    assert "SECRETV" not in h.show_command(command)


# ── self-protection notes ───────────────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "echo 'export STILLRUNNING_ALLOW_UNVERIFIED=1' >> ~/.bashrc",
    "echo 'STILLRUNNING_API_BASE=x' >> ~/.zshrc",
    "pip install --force-reinstall stillrunning==0.0.1",
    "pip uninstall -y stillrunning",
    "pip install stillrunning==1.0.0",
    "echo '{}' > /etc/claude-code/managed-settings.json",
])
def test_changes_to_the_protection_itself_ask(cwd, command):
    assert decide(command, cwd)["action"] == "ask"


@pytest.mark.parametrize("path", ["~/.bashrc", "/etc/claude-code/managed-settings.json"])
def test_file_tool_writes_to_shell_startup_or_managed_settings_ask(cwd, path, capsys):
    code = h.run_hook(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": cwd,
        "tool_input": {"file_path": os.path.expanduser(path),
                       "content": "export STILLRUNNING_ALLOW_UNVERIFIED=1\n"}}))
    printed = capsys.readouterr().out.strip().splitlines()[-1]
    assert code == 0
    assert json.loads(printed)["hookSpecificOutput"]["permissionDecision"] == "ask"


# ── review 6, condition 1: uv's own options are not packages ────────────────

@pytest.mark.parametrize("command,package", [
    ("uv pip install --python-platform linux requests", "requests"),
    ("uv pip install --torch-backend cpu torch", "torch"),
    ("uv pip install --allow-insecure-host example.com requests", "requests"),
    ("uv add --package web requests", "requests"),
])
def test_uv_option_values_are_not_looked_up_as_packages(cwd, command, package):
    parsed = h.parse_install_commands(command, cwd=cwd)
    assert [p["name"] for p in parsed["packages"]] == [package]


@pytest.mark.parametrize("command", [
    "uv pip install --python-platform linux evilpkg",
    "uv pip install --python-platform evilpkg requests",          # a misread value still blocks
    "uv add --package evilpkg requests",
])
def test_uv_options_still_fail_toward_blocking(cwd, command):
    assert decide(command, cwd)["action"] == "deny"
