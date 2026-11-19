import os
import sys

import pytest

from stillrunning import funnel, __version__
from stillrunning import cli


@pytest.fixture
def sent(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    for var in ("STILLRUNNING_DEV", "STILLRUNNING_NO_FUNNEL", "STILLRUNNING_NO_TELEMETRY"):
        monkeypatch.delenv(var, raising=False)
    events = []
    monkeypatch.setattr(funnel, "_send_event", lambda step, extra=None: events.append(step))
    yield events
    funnel._flush_pending()


def test_first_scan_ok_sent_once(sent, tmp_path):
    assert funnel.track_first_scan(0)
    assert not funnel.track_first_scan(0)
    funnel._flush_pending()
    assert sent == ["first_scan_ok"]
    assert (tmp_path / ".stillrunning" / "first_scan_sent").exists()


@pytest.mark.parametrize("code", [0, 3, 10, 11])
def test_scan_that_ran_counts_as_ok(sent, code):
    funnel.track_first_scan(code)
    funnel._flush_pending()
    assert sent == ["first_scan_ok"]


@pytest.mark.parametrize("code", [1, 2, 12])
def test_scan_that_could_not_check_reports_failure(sent, code):
    funnel.track_first_scan(code)
    funnel._flush_pending()
    assert sent == [f"first_scan_failed_exit{code}"]


@pytest.mark.parametrize("var", ["STILLRUNNING_NO_TELEMETRY", "STILLRUNNING_NO_FUNNEL", "STILLRUNNING_DEV"])
def test_opt_out_sends_nothing_and_writes_no_marker(sent, monkeypatch, tmp_path, var):
    monkeypatch.setenv(var, "1")
    assert not funnel.track_first_scan(0)
    assert sent == []
    assert not (tmp_path / ".stillrunning").exists()


def test_unwritable_marker_sends_nothing(sent, tmp_path):
    (tmp_path / ".stillrunning").write_text("not a directory")
    assert not funnel.track_first_scan(0)
    assert sent == []


def test_machine_id_is_stable_and_matches_heartbeat():
    from stillrunning.heartbeat import _get_anonymous_machine_id
    assert funnel._get_machine_id_hash() == funnel._get_machine_id_hash() == _get_anonymous_machine_id()


def test_payload_carries_package_version(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout):
        captured["ua"] = req.headers["User-agent"]
        raise OSError("offline")

    monkeypatch.setattr(funnel.urllib.request, "urlopen", fake_urlopen)
    assert funnel._send_event("setup_started") is False
    assert captured["ua"] == f"stillrunning-funnel/{__version__}"


def test_exit_after_scan_reports_timeout_exit(sent):
    def timed_out():
        sys.exit(2)

    with pytest.raises(SystemExit) as e:
        cli._exit_after_scan(timed_out)
    assert e.value.code == 2
    funnel._flush_pending()
    assert sent == ["first_scan_failed_exit2"]


def test_exit_after_scan_keeps_exit_code_when_telemetry_breaks(sent, monkeypatch):
    def boom(code):
        raise RuntimeError("telemetry broke")

    monkeypatch.setattr(funnel, "track_first_scan", boom)
    with pytest.raises(SystemExit) as e:
        cli._exit_after_scan(lambda: 10)
    assert e.value.code == 10
