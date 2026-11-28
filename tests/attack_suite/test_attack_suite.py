"""The attack suite: every bypass a review found, and ordinary commands that must
stay allowed. Probe strings are only passed to touches_protection() in a child
process with a temporary HOME and no network (tools/scoreboard.py); this file
never starts a shell.

The gate: a probe caught at any commit on docs/scoreboard.jsonl must still be
caught, the must-allow controls must not drop, and the false-ask debt must not
go up. Every new review finding becomes a probe (status "open") before it is fixed."""
import ast
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUITE = os.path.join(ROOT, "tests", "attack_suite")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import scoreboard  # noqa: E402

CATEGORIES = {"launcher", "wrapper", "shell-string", "quoting", "prefix", "here-string", "glob/brace",
              "settings-write", "state-write", "kill-guard", "terminal-code", "run-time-word", "own-switch",
              "crontab", "indirect", "interpreter", "install-parse"}


def _json(name):
    with open(os.path.join(SUITE, name), encoding="utf-8") as f:
        return json.load(f)


def test_every_probe_is_complete_and_unique():
    probes = _json("probes.json")["probes"]
    ids = [p["id"] for p in probes]
    assert len(ids) == len(set(ids)) and len({p["command"] for p in probes}) == len(probes)
    for p in probes:
        assert p["expect"] in ("ask", "deny"), p
        assert p["category"] in CATEGORIES, p
        assert p["status"] in ("fixed", "open", "known-limit"), p
        assert p["found_by"] and p["reason"], p
        assert "/tmp/eqrun" not in p["command"] and "/src/" not in p["command"]     # nothing from the corpus


def test_every_control_is_complete_and_unique():
    controls = _json("controls.json")["controls"]
    assert len({c["id"] for c in controls}) == len(controls)
    probe_commands = {p["command"] for p in _json("probes.json")["probes"]}
    for c in controls:
        assert c["kind"] in ("must-allow", "false-ask-debt"), c
        assert c["command"] not in probe_commands, c


def test_this_suite_never_starts_a_shell():
    for name in ("test_attack_suite.py",):
        tree = ast.parse(open(os.path.join(SUITE, name), encoding="utf-8").read())
        imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
        assert "subprocess" not in imported and "pty" not in imported
    source = open(os.path.join(ROOT, "tools", "scoreboard.py"), encoding="utf-8").read()
    assert "shell=True" not in source and "os.system" not in source and "os.popen" not in source
    # its one child process is this Python running scoreboard.py itself
    assert source.count("subprocess.run(") == 1 and "[sys.executable, os.path.abspath(__file__)" in source


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the scoreboard rows are recorded on Linux")
def test_no_caught_probe_regresses_and_controls_hold():
    board = os.path.join(ROOT, "docs", "scoreboard.jsonl")
    if not os.path.exists(board):
        pytest.skip("no scoreboard yet")
    assert scoreboard.check(ROOT, board) == 0
