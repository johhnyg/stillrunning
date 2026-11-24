"""Regression tests for --setup onboarding bugs found by the 2026-11-24 setup fuzz.

Seeded stdlib fuzzing (no extra test dependency): each property is checked
over fixed junk inputs plus a few hundred random answer sequences."""
import builtins
import os
import random
import stat
import sys

import pytest
import yaml

from stillrunning import cli, funnel

JUNK_ALPHABET = "1234 \t\x00\x1b\x7fé中１@.yn" + "abc"


def _random_answers(rnd):
    return ["".join(rnd.choice(JUNK_ALPHABET) for _ in range(rnd.randint(0, 12)))
            for _ in range(rnd.randint(0, 8))]


@pytest.fixture
def env(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(home)
    steps = []
    monkeypatch.setattr(funnel, "track_step", lambda step, extra=None: steps.append(step) or True)
    monkeypatch.setattr(funnel, "track_setup_start", lambda: steps.append("setup_started") or True)
    monkeypatch.setattr(funnel, "track_telegram_config", lambda **k: True)
    monkeypatch.setattr(cli, "_post_early_signup", lambda *a, **k: True)
    monkeypatch.setattr(cli, "test_telegram_credentials", lambda *a, **k: False)
    monkeypatch.setattr(cli, "main", lambda *a, **k: None)
    # A package directory this user cannot write: as a normal user on a root
    # install. A missing directory is unwritable for root too, so this runs in CI.
    monkeypatch.setattr(cli, "PACKAGE_CONFIG_FILE", tmp_path / "site-packages-ro" / "stillrunning.yaml")
    return home, steps


def _feed(monkeypatch, answers):
    queue = list(answers)

    def fake_input(prompt=""):
        if not queue:
            raise EOFError
        return queue.pop(0)
    monkeypatch.setattr(builtins, "input", fake_input)


# --- Bug: PermissionError traceback for a normal user on a root install -----

@pytest.mark.parametrize("answers,channel", [
    (["3"], "silent"), (["4"], "skipped"), (["1", "a@example.com"], "email"),
    (["1", ""], "silent"), (["2", "123:abc", "42"], "telegram"),
])
def test_setup_on_unwritable_package_dir_saves_to_home(env, monkeypatch, answers, channel):
    home, _ = env
    _feed(monkeypatch, answers)
    cli._run_alert_setup()
    saved = home / ".stillrunning" / "stillrunning.yaml"
    assert cli.config_file() == saved
    assert yaml.safe_load(saved.read_text())["alert_channel"] == channel
    if os.name == "posix":
        assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert not list(saved.parent.glob("*.tmp"))
    assert cli.load_config()["alert_channel"] == channel


def test_setup_keeps_a_legacy_token_in_the_home_file(env, monkeypatch):
    home, _ = env
    (home / ".stillrunning").mkdir()
    (home / ".stillrunning" / "stillrunning.yaml").write_text("token: legacy-tok\n")
    _feed(monkeypatch, ["3"])
    cli._run_alert_setup()
    saved = yaml.safe_load((home / ".stillrunning" / "stillrunning.yaml").read_text())
    assert saved["token"] == "legacy-tok" and saved["alert_channel"] == "silent"


def test_writable_package_dir_is_still_used(env, monkeypatch, tmp_path):
    pkg = tmp_path / "site-packages-rw"
    pkg.mkdir()
    monkeypatch.setattr(cli, "PACKAGE_CONFIG_FILE", pkg / "stillrunning.yaml")
    _feed(monkeypatch, ["3"])
    cli._run_alert_setup()
    assert cli.config_file() == pkg / "stillrunning.yaml"
    assert yaml.safe_load((pkg / "stillrunning.yaml").read_text())["alert_channel"] == "silent"


def test_unwritable_home_fails_with_a_clear_error_not_a_traceback(env, monkeypatch, capsys, tmp_path):
    not_a_dir = tmp_path / "home-is-a-file"
    not_a_dir.write_text("")
    monkeypatch.setenv("HOME", str(not_a_dir))
    monkeypatch.setenv("USERPROFILE", str(not_a_dir))
    _feed(monkeypatch, ["3"])
    with pytest.raises(SystemExit) as e:
        cli.run_setup_wizard()
    out = capsys.readouterr().out
    assert e.value.code == cli.EXIT_ERROR
    assert "were NOT saved" in out and "Traceback" not in out
    assert "setup_failed_config_save" in env[1]


def test_fuzz_setup_on_unwritable_package_dir_never_raises(env, monkeypatch):
    rnd = random.Random(20261124)
    for _ in range(300):
        _feed(monkeypatch, _random_answers(rnd))
        try:
            cli._run_alert_setup()
        except (EOFError, cli.SetupInputError):
            pass
        path = cli.config_file()
        if path.exists():
            assert isinstance(yaml.safe_load(path.read_text()), dict)
            path.unlink()


# --- Bug: an answer outside 1-4 saved nothing, ended normally, logged "email" ----

JUNK_CHOICES = ["5", "0", "x", "１", "\x1b[A", "4\x00", "3;rm -rf /", "a" * 5000, "é", "-1", "1.0"]


@pytest.mark.parametrize("junk", JUNK_CHOICES)
def test_junk_menu_answer_is_rejected_then_a_valid_one_is_used(env, monkeypatch, capsys, junk):
    home, steps = env
    _feed(monkeypatch, [junk, "3"])
    cli._run_alert_setup()
    assert "is not one of the choices" in capsys.readouterr().out
    assert yaml.safe_load(cli.config_file().read_text())["alert_channel"] == "silent"
    assert [s for s in steps if s.startswith("alert_channel_")] == ["alert_channel_silent"]


@pytest.mark.parametrize("junk", JUNK_CHOICES)
def test_only_junk_menu_answers_stop_setup_loudly(env, monkeypatch, capsys, junk):
    home, steps = env
    _feed(monkeypatch, [junk] * 60)
    with pytest.raises(SystemExit) as e:
        cli.run_setup_wizard()
    out = capsys.readouterr().out
    assert e.value.code == cli.EXIT_USAGE
    assert "Nothing was saved" in out and "Traceback" not in out
    assert not cli.config_file().exists()
    assert "setup_aborted_invalid_input" in steps
    assert not [s for s in steps if s.startswith("alert_channel_")]


def test_fuzz_menu_never_saves_nothing_silently(env, monkeypatch):
    """Every random answer sequence ends in exactly one of: a saved config with
    a logged channel, a loud invalid-input stop, or the no-input stop."""
    rnd = random.Random(1124)
    for _ in range(300):
        _, steps = env
        steps.clear()
        _feed(monkeypatch, _random_answers(rnd))
        try:
            cli._run_alert_setup()
            ended = "returned"
        except cli.SetupInputError:
            ended = "invalid"
        except EOFError:
            ended = "eof"
        channels = [s for s in steps if s.startswith("alert_channel_")]
        path = cli.config_file()
        if ended == "returned":
            assert path.exists() and len(channels) == 1
            assert yaml.safe_load(path.read_text())["alert_channel"] == channels[0][len("alert_channel_"):] \
                or channels == ["alert_channel_email"]
        if ended == "invalid":
            assert not path.exists() and not channels
        if path.exists():
            path.unlink()


# --- Bug: piped setup never offered the hook and ended "normally" unprotected ---

from stillrunning import claude_hook, layers as layers_mod


@pytest.fixture
def no_layers(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(cli, "_run_alert_setup", lambda autonomous=False: None)


def _protected():
    return layers_mod.install_time_protection(layers_mod.protection_layers())


@pytest.mark.parametrize("tty,answer", [(False, None), (True, "n"), (True, EOFError), (True, KeyboardInterrupt)])
def test_setup_that_ends_unprotected_exits_non_zero_and_says_how(env, no_layers, monkeypatch, capsys, tty, answer):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: tty, raising=False)

    def fake_input(prompt=""):
        if isinstance(answer, type):
            raise answer
        return answer
    monkeypatch.setattr(builtins, "input", fake_input)
    with pytest.raises(SystemExit) as e:
        cli.run_setup_wizard(autonomous=False)
    out = capsys.readouterr().out
    assert e.value.code == cli.EXIT_NOT_PROTECTED
    assert "YOU ARE NOT PROTECTED" in out and "stillrunning --hook-claude-code" in out
    assert "Traceback" not in out
    assert "setup_ended_unprotected" in env[1]
    assert not _protected()
    assert not (env[0] / ".claude").exists()  # never installed without a typed yes


def test_setup_that_ends_protected_exits_normally(env, no_layers, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "")
    cli.run_setup_wizard(autonomous=False)
    out = capsys.readouterr().out
    assert claude_hook.verify_install()[0] == "on" and "YOU ARE NOT PROTECTED" not in out


def test_fuzz_setup_ends_protected_or_fails_loudly(env, monkeypatch, capsys):
    """Whole wizard, real menu, random answers, terminal or pipe: it must end
    protected with exit 0, or exit non-zero. Never exit 0 unprotected."""
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    rnd = random.Random(424)
    home = env[0]
    for _ in range(150):
        tty = rnd.random() < 0.5
        monkeypatch.setattr(sys.stdin, "isatty", lambda: tty, raising=False)
        _feed(monkeypatch, _random_answers(rnd) + (["", "y", "n"][rnd.randrange(3):][:1] if rnd.random() < 0.5 else []))
        try:
            cli.run_setup_wizard(autonomous=False)
            code = 0
        except SystemExit as e:
            code = e.code
        assert "Traceback" not in capsys.readouterr().out
        assert code != 0 or _protected(), "setup exited 0 while nothing checks installs"
        claude_hook.uninstall() if (home / ".claude").exists() else None
        if cli.config_file().exists():
            cli.config_file().unlink()
