"""The offline blocklist: a listed package is blocked with no network call, the
database's integrity is checked, and the builder replaces it atomically.

tests/conftest.py makes every urlopen raise, so any test here that reaches the
network fails: "blocks offline" is enforced, not assumed."""
import io
import json
import os
import subprocess
import sys
import time
import zipfile

import pytest

from stillrunning import claude_hook as ch
from stillrunning import offline_blocklist as ob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, "stillrunning", "claude_hook.py")


def _advisory(mal_id, eco, name, versions=None, ranges=None, withdrawn=None):
    affected = {"package": {"ecosystem": eco, "name": name}}
    if versions is not None:
        affected["versions"] = versions
    if ranges is not None:
        affected["ranges"] = ranges
    data = {"id": mal_id, "affected": [affected]}
    if withdrawn:
        data["withdrawn"] = withdrawn
    return data


ALL_VERSIONS = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
PYPI = [
    _advisory("MAL-2026-1", "PyPI", "Evil_Pkg", ranges=ALL_VERSIONS),
    _advisory("MAL-2026-2", "PyPI", "partly-bad", versions=["1.0.1", "1.0.2"]),
    _advisory("MAL-2026-3", "PyPI", "was-bad", ranges=ALL_VERSIONS, withdrawn="2026-01-01T00:00:00Z"),
]
NPM = [
    _advisory("MAL-2026-4", "npm", "@Evil/Pkg", ranges=ALL_VERSIONS),
    _advisory("MAL-2026-5", "npm", "chalky", versions=["5.6.1"]),
]


def _zip(path, advisories):
    with zipfile.ZipFile(path, "w") as archive:
        for data in advisories:
            archive.writestr(data["id"] + ".json", json.dumps(data))
        archive.writestr("GHSA-xxxx-yyyy-zzzz.json", json.dumps({"id": "GHSA-x", "affected": []}))


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("STILLRUNNING_CVE_CHECK", "0")
    ch._OFFLINE_STATE.clear()
    yield home
    ch._OFFLINE_STATE.clear()


@pytest.fixture
def built(home, tmp_path, monkeypatch):
    zips = {"pip": tmp_path / "pypi.zip", "npm": tmp_path / "npm.zip"}
    _zip(zips["pip"], PYPI)
    _zip(zips["npm"], NPM)

    def fake_download(url, dest):
        with open(str(url), "rb") as src, open(dest, "wb") as out:
            out.write(src.read())
        return os.path.getsize(dest)
    monkeypatch.setattr(ob, "_download", fake_download)
    manifest = ob.build(sources={"pip": str(zips["pip"]), "npm": str(zips["npm"])}, log=lambda *a: None)
    ch._OFFLINE_STATE.clear()
    return home / ".stillrunning", manifest


def _no_hosted(monkeypatch):
    """Every hosted path fails as if the network were unplugged."""
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "unverified", "why": "server"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: None)
    monkeypatch.setattr(ch, "_latest_version", lambda *a, **k: None)


# ── 1. a listed package is blocked offline ──

@pytest.mark.parametrize("spelling", ["evil-pkg", "Evil_Pkg", "EVIL.PKG", "evil__pkg", "evil-pkg==9.9"])
def test_listed_pip_package_blocks_with_no_network(built, monkeypatch, spelling):
    calls = []
    monkeypatch.setattr(ch, "_query", lambda *a, **k: calls.append(a) or {"status": "ok"})
    decision = ch.decide("pip install '%s'" % spelling, env={})
    assert decision["action"] == "deny", decision["lines"]
    assert "offline list" in decision["lines"][0] and "MAL-2026-1" in decision["lines"][0]
    assert calls == []                          # decided before any hosted lookup


@pytest.mark.parametrize("command", ["npm install @Evil/Pkg", "npm i @evil/pkg@latest", "npx @EVIL/pkg"])
def test_listed_npm_scoped_package_blocks_offline(built, monkeypatch, command):
    _no_hosted(monkeypatch)
    assert ch.decide(command, env={})["action"] == "deny"


def test_listed_package_blocks_when_every_hosted_path_is_down(built, monkeypatch):
    """Network unplugged, MCP and API down, rate-limited, PyPI slow: still a block."""
    _no_hosted(monkeypatch)
    out = ch.lookup({"eco": "pip", "name": "evil_pkg", "version": None})
    assert out["status"] == "blocked" and out.get("offline") is True


def test_bare_hook_blocks_a_listed_package_with_its_server_unreachable(built):
    """The hook exactly as Claude Code runs it, its server a dead port."""
    import socket
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    home = built[0].parent
    env = {"HOME": str(home), "USERPROFILE": str(home), "PATH": os.environ.get("PATH", ""),
           "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), "STILLRUNNING_CVE_CHECK": "0",
           "STILLRUNNING_API_BASE": "http://127.0.0.1:%d" % port}
    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "pip install Evil_Pkg"}, "cwd": str(home)})
    start = time.monotonic()
    proc = subprocess.run([sys.executable, "-I", "-S", HOOK], input=event.encode(), capture_output=True,
                          env=env, timeout=60)
    took = time.monotonic() - start
    answer = json.loads(proc.stdout)["hookSpecificOutput"]
    assert proc.returncode == 0 and answer["permissionDecision"] == "deny", proc.stdout
    assert took < 10


def test_withdrawn_advisory_is_not_listed(built, monkeypatch):
    assert ch._offline_lookup("pip", "was-bad", None) is None


def test_unlisted_package_falls_through_to_the_hosted_lookup(built, monkeypatch):
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    assert ch.lookup({"eco": "pip", "name": "requests", "version": None})["status"] == "ok"


def test_no_database_means_the_hosted_lookup_as_before(home, monkeypatch):
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    assert ch._offline_db() == ("missing", None)
    assert ch.lookup({"eco": "pip", "name": "evil-pkg", "version": None})["status"] == "ok"


# ── 2. listed for some versions ──

def test_some_versions_pinned_listed_version_blocks_offline(built, monkeypatch):
    _no_hosted(monkeypatch)
    out = ch.lookup({"eco": "pip", "name": "partly_bad", "version": "1.0.2"})
    assert out["status"] == "blocked" and out.get("offline")


def test_some_versions_unpinned_and_unresolvable_blocks(built, monkeypatch):
    _no_hosted(monkeypatch)
    decision = ch.decide("pip install partly-bad", env={})
    assert decision["action"] == "deny"
    assert "could not be worked out" in decision["lines"][0]


def test_some_versions_unpinned_with_a_clean_latest_still_installs(built, monkeypatch):
    def query(eco, name, version, token, timeout):
        if version is None:
            return {"status": "version_needed", "affected": ["==1.0.1", "==1.0.2"]}
        return {"status": "ok"}
    monkeypatch.setattr(ch, "_query", query)
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    monkeypatch.setattr(ch, "_latest_version", lambda *a, **k: "2.0.0")
    assert ch.decide("pip install partly-bad", env={})["action"] == "allow"


def test_some_versions_unresolvable_blocks_without_a_local_database(home, monkeypatch):
    """Same rule on the hosted path alone: the latest cannot be worked out → block."""
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "version_needed", "affected": ["==1.0"]})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    monkeypatch.setattr(ch, "_latest_version", lambda *a, **k: None)
    out = ch.lookup({"eco": "pip", "name": "litellm-ish", "version": None})
    assert out["status"] == "blocked" and out["why"] == "version_unresolved"


def test_some_versions_with_an_unlisted_exact_pin_is_the_hosted_lookups_call(built, monkeypatch):
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    monkeypatch.setattr(ch, "_blocklist_only_lookup", lambda *a, **k: None)
    assert ch.lookup({"eco": "pip", "name": "partly-bad", "version": "3.0.0"})["status"] == "ok"


# ── 3. existence not verified is said, not hidden ──

def test_registry_probe_failure_says_existence_not_verified(home, monkeypatch):
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: None)
    decision = ch.decide("pip install somepkg", env={})
    assert decision["action"] == "allow"
    assert "existence on PyPI NOT verified" in decision["lines"][0]


def test_registry_answer_keeps_the_plain_line(home, monkeypatch):
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    assert "NOT verified" not in ch.decide("pip install somepkg", env={})["lines"][0]


# ── integrity: tampered → block, never trusted ──

def _tamper_db(folder, manifest):
    path = folder / manifest["db"]
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))


def _tamper_manifest(folder, manifest):
    path = folder / ch.OFFLINE_MANIFEST
    doc = json.loads(path.read_text())
    doc["counts"]["pip"] = 1
    path.write_text(json.dumps(doc))


def _drop_key(folder, manifest):
    (folder / ch.OFFLINE_KEY).unlink()


def _swap_db(folder, manifest):
    other = folder / ("blocklist-%s.sqlite" % ("0" * 16))
    other.write_bytes((folder / manifest["db"]).read_bytes()[:-10])
    path = folder / ch.OFFLINE_MANIFEST
    doc = json.loads(path.read_text())
    doc["db"] = other.name
    path.write_text(json.dumps(doc))


@pytest.mark.parametrize("tamper", [_tamper_db, _tamper_manifest, _drop_key, _swap_db])
def test_tampered_database_blocks_every_install(built, monkeypatch, tamper):
    folder, manifest = built
    tamper(folder, manifest)
    ch._OFFLINE_STATE.clear()
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    decision = ch.decide("pip install requests", env={})
    assert decision["action"] == "deny"
    assert "integrity check" in decision["lines"][0]
    assert any("blocklist --refresh" in (r.get("explanation") or "") for r in decision["records"])


@pytest.mark.skipif(os.name == "nt", reason="the verified note needs a stable inode and ctime")
def test_verified_note_skips_the_hash_but_not_a_change(built, monkeypatch):
    import hashlib
    folder, manifest = built
    assert ch._offline_db()[0] == "ok"                       # full check, note written
    assert (folder / "blocklist.verified").exists()
    hashed = []
    real = hashlib.sha256
    monkeypatch.setattr(hashlib, "sha256", lambda *a: hashed.append(1) or real(*a))
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok" and hashed == []      # note matched: no hash
    time.sleep(0.01)
    _tamper_db(folder, manifest)                             # same size, new content, new ctime
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "tampered" and hashed      # note no longer matches: hashed, caught


def test_forged_verified_note_does_not_hide_a_change(built):
    folder, manifest = built
    ch._offline_db()
    _tamper_db(folder, manifest)
    (folder / "blocklist.verified").write_text("0" * 64)
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "tampered"


def test_symlinked_database_is_tampered(built):
    folder, manifest = built
    if os.name == "nt":
        pytest.skip("symlinks need privileges on Windows")
    real = folder / manifest["db"]
    moved = folder.parent / "elsewhere.sqlite"
    real.rename(moved)
    os.symlink(str(moved), str(real))
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "tampered"


# ── the builder ──

def test_build_is_atomic_and_keeps_the_old_list_on_failure(built, monkeypatch, tmp_path):
    folder, manifest = built
    before = (folder / ch.OFFLINE_MANIFEST).read_bytes()

    def broken(conn, eco, zip_path):
        raise RuntimeError("feed broke mid-way")
    monkeypatch.setattr(ob, "_ingest", broken)
    with pytest.raises(RuntimeError):
        ob.build(sources={"pip": str(tmp_path / "pypi.zip")}, log=lambda *a: None)
    assert (folder / ch.OFFLINE_MANIFEST).read_bytes() == before
    assert not [f for f in os.listdir(str(folder)) if f.startswith(".blocklist-")]
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok"


def test_build_refuses_an_empty_list(home, monkeypatch, tmp_path):
    empty = tmp_path / "empty.zip"
    _zip(empty, [])
    monkeypatch.setattr(ob, "_download", lambda url, dest: open(dest, "wb").write(open(str(url), "rb").read()))
    with pytest.raises(RuntimeError):
        ob.build(sources={"pip": str(empty)}, log=lambda *a: None)
    assert not (home / ".stillrunning" / ch.OFFLINE_MANIFEST).exists()


def test_built_database_is_normalized_and_indexed(built):
    import sqlite3
    folder, manifest = built
    conn = sqlite3.connect(str(folder / manifest["db"]))
    rows = dict(((e, n), v) for e, n, v in conn.execute("SELECT eco, name, versions FROM entries"))
    plan = " ".join(r[3] for r in conn.execute(
        "EXPLAIN QUERY PLAN SELECT versions FROM entries WHERE eco='pip' AND name='evil-pkg'"))
    conn.close()
    assert rows[("pip", "evil-pkg")] == "*" and rows[("npm", "@evil/pkg")] == "*"
    assert rows[("pip", "partly-bad")] == "==1.0.1\n==1.0.2"
    assert ("pip", "was-bad") not in rows
    assert "PRIMARY KEY" in plan or "USING" in plan
    mode = os.stat(str(folder / ch.OFFLINE_KEY)).st_mode & 0o777
    if os.name != "nt":
        assert mode == 0o600


def test_status_reports_verified_and_tampered(built, capsys):
    folder, manifest = built
    assert ob.status() == 0 and "verified" in capsys.readouterr().out
    _tamper_db(folder, manifest)
    assert ob.status() == 2 and "FAILED" in capsys.readouterr().out


def test_cron_line_is_low_priority_and_single_instance(home):
    line = ob.cron_line()
    assert line.startswith("41 4 * * * nice -n 19 ") and "flock -n" in line and "timeout 1800" in line
    assert line.endswith(ob.CRON_MARK)


# ── the new files are protected like stillrunning's own ──

@pytest.mark.parametrize("target", ["blocklist.manifest.json", "blocklist.key", "blocklist-0123456789abcdef.sqlite"])
@pytest.mark.parametrize("op", ["rm {p}", "mv /tmp/x {p}", "cp /tmp/x {p}", "echo x > {p}", "sqlite3 {p} 'DELETE FROM entries'",
                                "python3 -c \"open('{p}','w')\"", "ln -sf /tmp/x {p}", "truncate -s0 {p}"])
def test_offline_blocklist_files_are_self_protected(home, target, op):
    path = str(home / ".stillrunning" / target)
    for spelling in (path, "~/.stillrunning/" + target, "$HOME/.stillrunning/" + target):
        assert ch.touches_protection(op.format(p=spelling)), op.format(p=spelling)


@pytest.mark.parametrize("target", ["blocklist.manifest.json", "blocklist.key", "blocklist-0123456789abcdef.sqlite"])
def test_write_tool_to_offline_blocklist_files_asks(home, target):
    from stillrunning.claude_hook import run_hook
    path = str(home / ".stillrunning" / target)
    out = io.StringIO()
    import contextlib
    with contextlib.redirect_stdout(out):
        run_hook(json.dumps({"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"},
                             "cwd": str(home)}))
    answer = json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"]
    assert answer in ("ask", "deny")
