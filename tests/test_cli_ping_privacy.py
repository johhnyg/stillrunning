import argparse
import sys

import pytest

from stillrunning import cli, heartbeat


@pytest.fixture
def pings(monkeypatch):
    sent = []
    monkeypatch.setattr(heartbeat, "send_cli_ping", lambda version, command: sent.append(command))
    return sent


def _run(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["stillrunning", *argv])
    def stop(self, *a, **k):
        raise SystemExit(0)

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", stop)
    with pytest.raises(SystemExit):
        cli.main_cli()


@pytest.mark.parametrize("argv,expected", [
    (["scan", "requests"], "scan"),
    (["scan", "--npm", "lodash"], "scan"),
    (["scan-manifest", "/home/alice/project/requirements.txt"], "scan-manifest"),
    (["allow", "evilpkg", "--once"], "allow"),
    (["--setup"], "--setup"),
    (["--help"], "--help"),
    (["--token=secret-value"], "--token"),
    (["fcddaf2a69362a75e"], "other"),
    (["/etc/passwd"], "other"),
    ([], ""),
])
def test_ping_carries_command_name_only(pings, monkeypatch, argv, expected):
    _run(monkeypatch, *argv)
    assert pings == [expected]


@pytest.mark.parametrize("argv", [["hook"], ["statusline"], ["shield"], ["cve", "--json"]])
def test_fast_paths_send_no_ping(pings, monkeypatch, argv):
    _run(monkeypatch, *argv)
    assert pings == []


def test_command_label_never_returns_unknown_words():
    known = {"scan", "--setup"}
    assert heartbeat.command_label(["requests"], known) == "other"
    assert heartbeat.command_label(["scan", "requests"], known) == "scan"
    assert heartbeat.command_label(["--setup=x"], known) == "--setup"
