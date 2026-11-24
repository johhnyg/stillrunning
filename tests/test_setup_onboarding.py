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
        except EOFError:
            pass
        path = cli.config_file()
        if path.exists():
            assert isinstance(yaml.safe_load(path.read_text()), dict)
            path.unlink()
