"""Remembered "your call" commands: the store, its rules and its CLI."""
import json
import os

import pytest

from stillrunning import claude_hook, remembered


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(claude_hook, "REMEMBER_ENABLED", True)   # off in the shipped hook
    os.makedirs(claude_hook._state_dir(), exist_ok=True)
    return tmp_path


def log(*records):
    with open(claude_hook.decisions_path(), "a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def decision(command, cwd="/proj", ts=1000.0, can=True, verdict="needs_approval", **extra):
    return dict({"v": 1, "ts": ts, "verdict": verdict, "subject": "install command",
                 "command": command, "cmd_id": remembered.command_id(command, cwd),
                 "can_remember": can}, **extra)


def test_id_is_exact_command_and_exact_folder(tmp_path):
    a = remembered.command_id("pip install -e .", str(tmp_path))
    assert a == remembered.command_id("  pip install -e .\n", str(tmp_path))      # outer space only
    assert a != remembered.command_id("pip install  -e .", str(tmp_path))         # inner space
    assert a != remembered.command_id("pip install -e . evil", str(tmp_path))
    assert a != remembered.command_id("pip install -e .", str(tmp_path / "other"))
    assert len(a) == 32


def test_remember_last_then_list_touch_forget(home):
    log(decision("pip install -e ."))
    entry = remembered.remember("last")
    cid = remembered.command_id("pip install -e .", "/proj")
    assert entry["id"] == cid and entry["command"] == "pip install -e ."
    assert remembered.is_remembered(cid)
    assert not remembered.is_remembered(remembered.command_id("pip install -e .", "/elsewhere"))
    assert oct(os.stat(remembered.path()).st_mode & 0o777) == "0o600"
    remembered.touch(cid)
    remembered.touch(cid)
    assert remembered.list_all()[0]["uses"] == 2
    assert remembered.forget(cid[:8]) == 1
    assert not remembered.is_remembered(cid) and remembered.list_all() == []


def test_remember_by_id_prefix_needs_eight_characters(home):
    log(decision("uv pip install -r req.txt"))
    cid = remembered.command_id("uv pip install -r req.txt", "/proj")
    with pytest.raises(remembered.Refused):
        remembered.remember(cid[:5])
    assert remembered.remember(cid[:10])["id"] == cid


@pytest.mark.parametrize("why", ["blocked package", "lookup failed", "protection change"])
def test_a_decision_the_hook_marked_not_rememberable_is_refused(home, why):
    log(decision("pip install evilpkg", can=False))
    with pytest.raises(remembered.Refused) as err:
        remembered.remember("last")
    assert "cannot be remembered" in str(err.value)
    assert remembered.list_all() == []


def test_one_command_with_a_rememberable_and_a_refusable_reason_is_refused(home):
    # same run (same ts) produced two records: an unreadable part and a blocked package
    log(decision("pip install $X evilpkg", can=True), decision("pip install $X evilpkg", can=False))
    with pytest.raises(remembered.Refused):
        remembered.remember("last")


def test_a_later_run_decides_not_an_older_one(home):
    log(decision("pip install x", ts=1.0, can=True), decision("pip install x", ts=2.0, can=False))
    with pytest.raises(remembered.Refused):
        remembered.remember(remembered.command_id("pip install x", "/proj"))


def test_old_records_without_an_id_are_refused_plainly(home):
    log({"v": 1, "ts": 5.0, "verdict": "needs_approval", "subject": "install command"})
    with pytest.raises(remembered.Refused) as err:
        remembered.remember("last")
    assert "once more" in str(err.value)


def test_nothing_to_remember(home):
    with pytest.raises(remembered.Refused):
        remembered.remember("last")
    with pytest.raises(remembered.Refused):
        remembered.remember("deadbeefdeadbeef")


@pytest.mark.parametrize("content", ["{not json", "[]", '{"commands": []}', '{"commands": {"short": {}}}'])
def test_a_damaged_file_means_nothing_is_remembered(home, content):
    cid = remembered.command_id("pip install -e .", "/proj")
    with open(remembered.path(), "w") as handle:
        handle.write(content)
    assert remembered.is_remembered(cid) is False
    assert remembered.list_all() == []


def test_is_remembered_rejects_non_strings(home):
    assert remembered.is_remembered(None) is False
    assert remembered.is_remembered(123) is False


def test_forget_all_and_no_match(home):
    log(decision("a", ts=1.0), decision("b", ts=2.0))
    remembered.remember(remembered.command_id("a", "/proj"))
    remembered.remember(remembered.command_id("b", "/proj"))
    assert remembered.forget("ffffffff") == 0
    assert remembered.forget("all") == 2
    assert remembered.list_all() == []


def test_cap_on_how_many_are_remembered(home, monkeypatch):
    monkeypatch.setattr(remembered, "MAX_ENTRIES", 2)
    for i in range(3):
        log(decision(f"cmd {i}", ts=float(i)))
    remembered.remember(remembered.command_id("cmd 0", "/proj"))
    remembered.remember(remembered.command_id("cmd 1", "/proj"))
    with pytest.raises(remembered.Refused):
        remembered.remember(remembered.command_id("cmd 2", "/proj"))
    assert remembered.remember(remembered.command_id("cmd 1", "/proj"))     # re-remembering is fine


def test_cli_list_remember_forget(home, capsys):
    assert remembered.main(["remember", "--list"]) == 0
    assert "No commands are remembered" in capsys.readouterr().out
    log(decision("npm i -- ./local-pkg"))
    assert remembered.main(["remember", "last"]) == 0
    out = capsys.readouterr().out
    assert "exact command" in out and "$ npm i -- ./local-pkg" in out and "still checked every time" in out
    assert remembered.main(["remember", "--list"]) == 0
    listed = capsys.readouterr().out
    cid = remembered.command_id("npm i -- ./local-pkg", "/proj")
    assert cid[:12] in listed and "used 0x" in listed
    assert remembered.main(["remember", "--list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["commands"][0]["id"] == cid
    assert remembered.main(["forget"]) == 2
    capsys.readouterr()
    assert remembered.main(["forget", cid[:12]]) == 0
    assert "asked again" in capsys.readouterr().out
    assert remembered.main(["forget", cid[:12]]) == 1


def test_cli_refusal_exits_1_and_says_why(home, capsys):
    log(decision("pip install evilpkg", can=False))
    assert remembered.main(["remember", "last"]) == 1
    assert "Not remembered." in capsys.readouterr().out
    assert remembered.main(["remember", "last", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
