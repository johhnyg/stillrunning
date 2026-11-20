"""Windows and Python 3.8/3.9 compatibility (2026-11-20 audit).

Four bugs, each pinned here:
1. output crashed on a non-UTF-8 console (Windows code pages, piped output);
2. the verdict cache rejected every file on Windows (synthesized mode bits);
3. the Claude Code hook warned "readable by other accounts" on every call on
   Windows;
4. the CLI could not be imported on Python 3.8/3.9 (PEP 604/585 annotations
   evaluated at import).
No network; Windows is simulated by the mode bits and os.name it reports.
"""
import ast
import importlib
import importlib.metadata
import io
import os
import pathlib
import stat
import subprocess
import sys
import textwrap

import pytest

from stillrunning import _stdio
from stillrunning import claude_hook as ch
from stillrunning import verdict_cache as vc

PKG = pathlib.Path(__file__).resolve().parent.parent / "stillrunning"
H1 = "sha256:" + "a1" * 32


# ── 1. non-UTF-8 consoles ──

def _run_cp1252(code):
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONPATH=str(PKG.parent))
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], capture_output=True,
                          env=env, timeout=60)


def test_blocked_result_prints_on_a_cp1252_pipe():
    r = _run_cp1252("""
        from stillrunning._stdio import make_output_safe
        make_output_safe()
        from stillrunning import cli
        rc = cli._print_outcome({"eco": "pip", "name": "evilpkg", "version": None},
                                {"status": "blocked", "advisory": None})
        raise SystemExit(0 if rc == 10 else 3)
    """)
    out = r.stdout.decode("cp1252")
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-600:]
    assert "X stillrunning BLOCKED" in out and "UnicodeEncodeError" not in r.stderr.decode("cp1252", "replace")


def test_without_the_fix_the_same_print_crashes():
    """Positive control: proves the cp1252 pipe really reproduces the bug."""
    r = _run_cp1252("""
        from stillrunning import cli
        cli._print_outcome({"eco": "pip", "name": "evilpkg", "version": None},
                           {"status": "blocked", "advisory": None})
    """)
    assert r.returncode != 0 and b"UnicodeEncodeError" in r.stderr


def test_symbols_are_spelled_in_ascii():
    _stdio._register()
    raw = "✓ ok ✗ no ⚠️ warn \U0001f6a8 alarm ✅ • — é"
    assert raw.encode("cp1252", _stdio.ERROR_HANDLER).decode("cp1252") == \
        "OK ok X no ! warn !! alarm OK • — é"   # • — é exist in cp1252
    assert "• —".encode("ascii", _stdio.ERROR_HANDLER) == b"* --"
    assert "中".encode("ascii", _stdio.ERROR_HANDLER) == b"<U+4E2D>"


def test_lookalike_names_stay_visibly_different():
    """No transliteration: Cyrillic "rеquests" must not print as "requests"."""
    _stdio._register()
    assert "rеquests".encode("cp1252", _stdio.ERROR_HANDLER) == b"r<U+0435>quests"
    assert "ｒequests".encode("cp1252", _stdio.ERROR_HANDLER) == b"<U+FF52>equests"   # fullwidth r


def test_undecodable_filename_bytes_keep_their_value():
    _stdio._register()
    assert "bad\udcffname".encode("ascii", _stdio.ERROR_HANDLER) == b"bad<0xFF>name"
    assert "⚠️".encode("ascii", _stdio.ERROR_HANDLER) == b"!"      # empty mapping kept


def test_utf8_streams_are_left_alone(monkeypatch):
    buf = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", buf)
    assert "stdout" not in _stdio.make_output_safe(("stdout",))
    assert buf.errors == "strict"


def test_cp1252_stream_is_switched_to_the_ascii_fallback(monkeypatch):
    buf = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", buf)
    assert _stdio.make_output_safe(("stdout",)) == ["stdout"]
    print("✗ BLOCKED")          # would raise without the fix
    buf.flush()
    assert buf.buffer.getvalue() == b"X BLOCKED\n"


ENTRY_POINTS = {"cli.py": {"main", "main_cli"}, "scan.py": {"main"}, "intercept.py": {"main"},
                "guard.py": {"main_loop"}, "pkl_inspector.py": {"main"},
                "docker_agent.py": {"main"}, "claude_hook.py": {"main"}}


def test_every_entry_point_makes_output_safe_first():
    for fn, names in ENTRY_POINTS.items():
        tree = ast.parse((PKG / fn).read_text(encoding="utf-8"))
        found = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in names:
                body = [s for s in node.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
                calls = [s for s in body[:2] if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
                         and getattr(s.value.func, "id", None) == "make_output_safe"]
                found[node.name] = bool(calls)
        assert found == {n: True for n in names}, (fn, found)


def test_importing_the_package_does_not_touch_streams():
    """sitecustomize imports stillrunning into other programs: never at import."""
    r = _run_cp1252("""
        import sys
        import stillrunning, stillrunning.cli, stillrunning.claude_hook, stillrunning.intercept
        print(sys.stdout.errors)
    """)
    assert r.stdout.decode().strip() == "strict"


# ── 2/3. Windows mode bits ──

class _WinStat:
    """os.stat_result look-alike carrying the mode bits Windows synthesizes."""
    def __init__(self, st):
        self._st = st

    def __getattr__(self, name):
        value = getattr(self._st, name)
        if name == "st_mode":
            if stat.S_ISDIR(value):
                return value | 0o777
            if stat.S_ISREG(value):
                return value | 0o666
        return value


@pytest.fixture
def windows(monkeypatch):
    real_stat, real_lstat = os.stat, os.lstat
    monkeypatch.setattr(os, "stat", lambda *a, **k: _WinStat(real_stat(*a, **k)))
    monkeypatch.setattr(os, "lstat", lambda *a, **k: _WinStat(real_lstat(*a, **k)))
    monkeypatch.setattr(os, "chmod", lambda *a, **k: None)     # cannot change these bits there
    # Derive the flag the real way: verdict_cache reads os.name when it loads.
    monkeypatch.setattr(os, "name", "nt")
    importlib.reload(vc)
    assert vc._POSIX_MODES is False
    yield
    monkeypatch.undo()
    importlib.reload(vc)                 # back to this platform's value for later tests
    assert vc._POSIX_MODES is (os.name != "nt")


def test_verdict_cache_works_with_windows_modes(windows, tmp_path):
    state = str(tmp_path / ".stillrunning")
    os.makedirs(state)
    warns = []
    now = 1_800_000_000.0
    assert vc.store(state, {"eco": "pip", "name": "six", "version": "1.16.0", "artifact": H1,
                            "verified_at": now}, now, warns.append)
    assert vc.find(state, "pip", "six", "1.16.0", H1, now + 1, 3600, warns.append)
    assert warns == [] and not any("untrusted" in f for f in os.listdir(state))


def test_verdict_cache_still_rejects_foreign_files_on_posix(tmp_path):
    assert vc._POSIX_MODES is True
    state = str(tmp_path / ".stillrunning")
    os.makedirs(state, mode=0o700)
    now = 1_800_000_000.0
    assert vc.store(state, {"eco": "pip", "name": "six", "version": "1.16.0", "artifact": H1,
                            "verified_at": now}, now, lambda m: None)
    os.chmod(os.path.join(state, vc.DB_NAME), 0o666)            # another account could write it
    warns = []
    assert vc.find(state, "pip", "six", "1.16.0", H1, now + 1, 3600, warns.append) is None
    assert any("untrusted" in w for w in warns)


def test_hook_state_dir_is_quiet_on_windows(windows, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(ch, "_state_dir", lambda: str(tmp_path / ".stillrunning"))
    monkeypatch.setattr(ch.os, "name", "nt")
    for _ in range(3):                    # each hook call is a fresh process
        ch._TIGHTENED.clear()
        ch._private_state_dir()
    assert "readable by other accounts" not in capsys.readouterr().err


def test_hook_state_dir_still_tightened_on_posix(monkeypatch, tmp_path, capsys):
    d = tmp_path / ".stillrunning"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    monkeypatch.setattr(ch, "_state_dir", lambda: str(d))
    ch._TIGHTENED.clear()
    ch._private_state_dir()
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    assert "readable by other accounts" in capsys.readouterr().err


# ── 4. Python 3.8/3.9 imports ──

def _evaluated_new_annotations(tree):
    """PEP 604 (X | Y) and PEP 585 (list[...]) inside annotations that are
    evaluated at import (no `from __future__ import annotations`)."""
    hits = []
    for node in ast.walk(tree):
        anns = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            anns = [x.annotation for x in a.posonlyargs + a.args + a.kwonlyargs if x.annotation]
            anns += [x.annotation for x in (a.vararg, a.kwarg) if x is not None and x.annotation]
            anns += [node.returns] if node.returns else []
        elif isinstance(node, ast.AnnAssign):
            anns = [node.annotation]
        for ann in anns:
            for sub in ast.walk(ann):
                if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr):
                    hits.append(sub.lineno)
                if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) and \
                        sub.value.id in ("list", "dict", "tuple", "set", "frozenset", "type"):
                    hits.append(sub.lineno)
    return hits


def test_no_module_evaluates_annotations_python38_cannot_read():
    bad = {}
    for path in sorted(PKG.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        future = any(isinstance(n, ast.ImportFrom) and n.module == "__future__"
                     and any(a.name == "annotations" for a in n.names) for n in tree.body)
        if not future:
            hits = _evaluated_new_annotations(tree)
            if hits:
                bad[path.name] = hits[:5]
    assert bad == {}, f"add `from __future__ import annotations`: {bad}"


def test_every_module_parses_as_python38():
    for path in sorted(PKG.rglob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 8))


# ── import-time checks on Python 3.8/3.9 (no packages_distributions) ──

class _MetadataWithoutPackagesDistributions:
    """importlib.metadata as Python 3.8/3.9 have it."""
    distributions = staticmethod(importlib.metadata.distributions)


@pytest.mark.skipif(sys.version_info < (3, 10), reason="no native packages_distributions to compare with")
def test_fallback_map_matches_the_native_one(monkeypatch):
    from stillrunning import hook
    monkeypatch.setattr(hook, "_PD_FALLBACK", None)
    native = importlib.metadata.packages_distributions()
    fallback = hook._packages_distributions(_MetadataWithoutPackagesDistributions)
    # 3.12+ also infers names from .pyc files (e.g. "__pycache__"); real import names must agree
    real = {k for k in set(native) | set(fallback) if k.isidentifier() and k != "__pycache__"}
    assert real and all(sorted(native.get(k, [])) == sorted(fallback.get(k, [])) for k in real)


def test_import_checks_map_distributions_without_packages_distributions(monkeypatch, capsys):
    from stillrunning import hook
    monkeypatch.delattr(importlib.metadata, "packages_distributions", raising=False)   # absent on 3.8/3.9
    monkeypatch.setattr(hook, "_PD_FALLBACK", None)
    hook._warned.discard("dist_map")
    assert hook._distribution_for("pytest") == "pytest"
    assert hook._distribution_for("json") is None                  # stdlib: not a distribution
    assert "import checks skipped" not in capsys.readouterr().err


def test_native_packages_distributions_still_used_when_present(monkeypatch):
    from stillrunning import hook
    calls = []
    monkeypatch.setattr(importlib.metadata, "packages_distributions",
                        lambda: calls.append(1) or {"pytest": ["pytest"]}, raising=False)
    assert hook._distribution_for("pytest") == "pytest" and calls == [1]


def test_fallback_map_is_built_once_per_process(monkeypatch):
    """On 3.8/3.9 every first stdlib import asks: rescanning each time slowed
    the host program's own imports (review: 0.5 s -> 11.7 s with 200 dists)."""
    from stillrunning import hook
    monkeypatch.setattr(hook, "_PD_FALLBACK", None)
    scans = []

    class Counting:
        @staticmethod
        def distributions():
            scans.append(1)
            return importlib.metadata.distributions()
    first = hook._packages_distributions(Counting)
    second = hook._packages_distributions(Counting)
    assert scans == [1] and first is second and first
