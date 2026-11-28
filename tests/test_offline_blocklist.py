"""The offline blocklist: a listed package is blocked with no network call, the
database's integrity is checked, and the builder replaces it atomically.

tests/conftest.py makes every urlopen raise, so any test here that reaches the
network fails: "blocks offline" is enforced, not assumed."""
import contextlib
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

    def broken(conn, eco, zip_path, log=None):
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
    spellings = [path, "~/.stillrunning/" + target, "$HOME/.stillrunning/" + target]
    if os.name == "nt":
        # an unquoted C:\… is not that path in bash (the backslashes are escapes);
        # these are the spellings Git Bash really uses for it
        drive, rest = os.path.splitdrive(path)
        spellings[0] = path.replace("\\", "/")
        spellings.append("/" + drive[0].lower() + rest.replace("\\", "/"))
    for spelling in spellings:
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


# ── review 1 findings, one test each ──

def _hosted(monkeypatch, query, latest):
    monkeypatch.setattr(ch, "_query", query)
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    monkeypatch.setattr(ch, "_latest_version", lambda *a, **k: latest)
    monkeypatch.setattr(ch, "_blocklist_only_lookup", lambda *a, **k: None)


def test_b1_hosted_says_ok_but_the_latest_is_on_the_offline_list(built, monkeypatch):
    """Blocking 1: the hosted list lags the offline one; the version that would
    install (the latest, 1.0.2) is offline-listed → blocked, not allowed."""
    _hosted(monkeypatch, lambda *a, **k: {"status": "ok"}, "1.0.2")
    out = ch.lookup({"eco": "pip", "name": "partly-bad", "version": None})
    assert out["status"] == "blocked" and out.get("offline") and out.get("resolved_version") == "1.0.2"
    assert ch.decide("pip install partly-bad", env={})["action"] == "deny"


def test_b1_hosted_lists_other_versions_but_the_latest_is_offline_listed(built, monkeypatch):
    def query(eco, name, version, token, timeout):
        if version is None:
            return {"status": "version_needed", "affected": ["==0.9"]}
        return {"status": "ok"}                     # hosted: 1.0.1 is fine
    _hosted(monkeypatch, query, "1.0.1")
    assert ch.lookup({"eco": "pip", "name": "partly-bad", "version": None})["status"] == "blocked"


def test_b1_hosted_ok_and_latest_unknown_blocks(built, monkeypatch):
    _hosted(monkeypatch, lambda *a, **k: {"status": "ok"}, None)
    out = ch.lookup({"eco": "pip", "name": "partly-bad", "version": None})
    assert out["status"] == "blocked" and out["why"] == "version_unresolved"


def test_b1_hosted_ok_and_latest_not_listed_installs(built, monkeypatch):
    _hosted(monkeypatch, lambda *a, **k: {"status": "ok"}, "2.0.0")
    out = ch.lookup({"eco": "pip", "name": "partly-bad", "version": None})
    assert out["status"] == "ok" and out.get("resolved_version") == "2.0.0"


def _edit_manifest(folder, change):
    path = folder / ch.OFFLINE_MANIFEST
    doc = json.loads(path.read_text())
    change(doc)
    path.write_text(json.dumps(doc))


@pytest.mark.parametrize("damage", [
    lambda f: _edit_manifest(f, lambda d: d.update(mac="é" * 64)),             # TypeError in compare_digest
    lambda f: (f / ch.OFFLINE_MANIFEST).write_text("[" * 30000 + "]" * 30000),       # RecursionError
    lambda f: _edit_manifest(f, lambda d: d.update(sha256="é" * 64)),
    lambda f: _edit_manifest(f, lambda d: d.update(size="big")),
])
def test_b2_malformed_manifest_is_tampered_and_blocks(built, monkeypatch, damage):
    """Blocking 2: an exception while checking never becomes 'unverified (ask)'."""
    damage(built[0])
    ch._OFFLINE_STATE.clear()
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    assert ch._offline_db()[0] == "tampered"
    decision = ch.decide("pip install requests", env={})
    assert decision["action"] == "deny" and "integrity check" in decision["lines"][0]


@pytest.mark.parametrize("note", [b"\xc3\xa9" * 40, b"\xff\xfe\x00", b"", b"x" * 500])
def test_b2_damaged_verified_note_only_forces_a_rehash(built, note):
    folder = built[0]
    ch._offline_db()
    (folder / "blocklist.verified").write_bytes(note)
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok"


def test_nb_pinned_version_inside_a_listed_range_blocks_offline(home, monkeypatch, tmp_path):
    rng = lambda *events: [{"type": "ECOSYSTEM", "events": list(events)}]
    advisories = [
        _advisory("MAL-R-1", "PyPI", "rng-fixed", ranges=rng({"introduced": "0"}, {"fixed": "2.0.0"})),
        _advisory("MAL-R-2", "PyPI", "rng-open", ranges=rng({"introduced": "1.0.0"})),
        _advisory("MAL-R-3", "PyPI", "rng-last", ranges=rng({"introduced": "1.0"}, {"last_affected": "1.4"})),
        _advisory("MAL-R-4", "PyPI", "rng-multi",
                  ranges=rng({"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"}, {"fixed": "3.0"})),
    ]
    _build_from(monkeypatch, tmp_path, advisories)
    _no_hosted(monkeypatch)
    for name, version, blocked in [("rng-fixed", "1.5.0", True), ("rng-fixed", "2.0.0", False),
                                   ("rng-open", "1.2.0", True), ("rng-open", "0.9", False),
                                   ("rng-last", "1.4", True), ("rng-last", "1.4.1", False),
                                   ("rng-multi", "0.5", True), ("rng-multi", "1.5", False),
                                   ("rng-multi", "2.5", True)]:
        out = ch.lookup({"eco": "pip", "name": name, "version": version})
        assert (out["status"] == "blocked") is blocked, (name, version, out)


def test_nb_non_numeric_version_against_a_range_is_not_guessed(home, monkeypatch, tmp_path):
    _build_from(monkeypatch, tmp_path, [_advisory("MAL-R-5", "PyPI", "rng-x", ranges=[
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}])])
    assert ch._offline_version_listed("1.0rc1", ["<2.0"]) is None
    _no_hosted(monkeypatch)
    out = ch.lookup({"eco": "pip", "name": "rng-x", "version": "1.0rc1"})
    assert out["status"] == "unverified"            # pinned: a person decides, as before


def test_nb_too_many_versions_becomes_every_version(home, monkeypatch, tmp_path):
    _build_from(monkeypatch, tmp_path, [_advisory("MAL-V-1", "PyPI", "many",
                                                  versions=["1.0.%d" % i for i in range(300)])])
    _no_hosted(monkeypatch)
    assert ch.lookup({"eco": "pip", "name": "many", "version": "1.0.250"})["status"] == "blocked"
    assert ch.lookup({"eco": "pip", "name": "many", "version": None})["status"] == "blocked"


def test_nb_multi_event_range_is_split_not_collapsed():
    specs = ob._version_specs({"ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"}]}]})
    assert specs == ["<1.0", ">=2.0"]
    assert ob._version_specs({"ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "1.0"}, {"last_affected": "1.4"}]}]}) == [">=1.0,<=1.4"]


def test_nb_oversized_or_malformed_advisories_are_skipped_and_logged(home, monkeypatch, tmp_path):
    feed = tmp_path / "feed.zip"
    with zipfile.ZipFile(str(feed), "w") as archive:
        archive.writestr("MAL-OK.json", json.dumps(_advisory("MAL-OK", "PyPI", "good-entry", ranges=ALL_VERSIONS)))
        archive.writestr("MAL-BIG.json", json.dumps({"id": "MAL-BIG", "pad": "x" * (ob.MAX_MEMBER_BYTES + 10)}))
        archive.writestr("MAL-LIST.json", json.dumps(["not", "a", "dict"]))
        archive.writestr("MAL-ITEM.json", json.dumps({"id": "MAL-ITEM", "affected": ["not-a-dict"]}))
        archive.writestr("MAL-BADJSON.json", "{")
    logged = []
    monkeypatch.setattr(ob, "_download", lambda url, dest: open(dest, "wb").write(open(str(url), "rb").read()))
    ob.build(sources={"pip": str(feed)}, log=logged.append)
    ch._OFFLINE_STATE.clear()
    assert ch._offline_lookup("pip", "good-entry", None)["status"] == "blocked"
    assert any("4 advisories skipped" in line for line in logged), logged


def test_nb_entries_from_another_ecosystem_are_not_filed_here(home, monkeypatch, tmp_path):
    _build_from(monkeypatch, tmp_path, [_advisory("MAL-E-1", "PyPI", "real-pip", ranges=ALL_VERSIONS),
                                        _advisory("MAL-E-2", "npm", "npm-in-pypi-zip", ranges=ALL_VERSIONS)])
    assert ch._offline_lookup("pip", "real-pip", None)["status"] == "blocked"
    assert ch._offline_lookup("pip", "npm-in-pypi-zip", None) is None


def test_nb_stale_list_warns_on_every_install_check(built, monkeypatch):
    folder, manifest = built
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    assert ch.offline_stale_note() is None
    assert not any("offline blocklist" in l for l in ch.decide("pip install requests", env={})["lines"])
    old = time.time() + (ch.OFFLINE_STALE_HOURS + 24) * 3600
    monkeypatch.setattr(ch.time, "time", lambda: old)
    ch._OFFLINE_STATE.clear()
    note = ch.offline_stale_note()
    assert note and "days old" in note and "blocklist --refresh" in note
    decision = ch.decide("pip install requests", env={})
    assert any("days old" in l for l in decision["lines"])
    assert ch.decide("pip install evil-pkg", env={})["action"] == "deny"     # a stale list still blocks what it has


def test_nb_build_time_in_the_future_is_stale(built, monkeypatch):
    folder, manifest = built
    monkeypatch.setattr(ch.time, "time", lambda: manifest["built"] - 3 * 86400)
    ch._OFFLINE_STATE.clear()
    assert "future" in ch.offline_stale_note()


def test_nb_status_reports_stale(built, monkeypatch, capsys):
    folder, manifest = built
    monkeypatch.setattr(ch.time, "time", lambda: manifest["built"] + 10 * 86400)
    assert ob.status() == 3 and "STALE" in capsys.readouterr().out


@pytest.mark.skipif(os.name == "nt", reason="fcntl lock")
def test_nb_second_build_while_one_runs_is_refused(built, monkeypatch, tmp_path):
    folder = built[0]
    held = ob._lock(str(folder))
    try:
        with pytest.raises(ob.BuildBusy):
            ob.build(sources={"pip": str(tmp_path / "pypi.zip")}, log=lambda *a: None)
    finally:
        held.close()


def test_nb_killed_build_leftovers_are_removed(built, monkeypatch, tmp_path):
    folder = built[0]
    stale = folder / ".blocklist-npm-dead.zip"
    fresh = folder / ".blocklist-pip-running.zip"
    for path in (stale, fresh):
        path.write_bytes(b"x" * 10)
    os.utime(str(stale), (time.time() - 7200, time.time() - 7200))
    ob._clean_leftovers(str(folder))
    assert not stale.exists() and fresh.exists()


def test_nb_concurrent_hook_threads_verify_once(built, monkeypatch):
    import hashlib
    import threading
    folder = built[0]
    (folder / "blocklist.verified").unlink(missing_ok=True)
    ch._OFFLINE_STATE.clear()
    count = []
    real = hashlib.sha256
    monkeypatch.setattr(hashlib, "sha256", lambda *a: count.append(1) or real(*a))
    threads = [threading.Thread(target=ch._offline_db) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(count) == 1 and ch._offline_db()[0] == "ok"


def _build_from(monkeypatch, tmp_path, advisories, eco="pip"):
    feed = tmp_path / ("feed-%d.zip" % len(os.listdir(str(tmp_path))))
    _zip(feed, advisories)
    monkeypatch.setattr(ob, "_download", lambda url, dest: open(dest, "wb").write(open(str(url), "rb").read()))
    ch._OFFLINE_STATE.clear()
    ob.build(sources={eco: str(feed)}, log=lambda *a: None)
    ch._OFFLINE_STATE.clear()


# ── review 2 findings, one test each ──

@pytest.mark.parametrize("command", [
    "pip install 'partly-bad>=1'", "pip install 'partly-bad~=1.0'", "pip install 'partly-bad==1.0.*'",
    "pip install --pre partly-bad", "npm install chalky@^5", "npm install chalky@'>=5'",
])
def test_r2_important_range_or_flag_with_listed_versions_asks_even_if_hosted_says_ok(built, monkeypatch, tmp_path, command):
    """IMPORTANT (review 2): the hosted list lags; a range/wildcard/--pre install of a
    package with offline-listed versions must not be allowed on its 'ok' alone."""
    _hosted(monkeypatch, lambda *a, **k: {"status": "ok"}, "9.9.9")
    decision = ch.decide(command, env={}, cwd=str(tmp_path))
    assert decision["action"] == "ask", (command, decision["lines"])


def test_r2_important_constraints_file_with_listed_versions_asks(built, monkeypatch, tmp_path):
    (tmp_path / "c.txt").write_text("partly-bad<2\n")
    _hosted(monkeypatch, lambda *a, **k: {"status": "ok"}, "9.9.9")
    decision = ch.decide("pip install -c c.txt partly-bad", env={}, cwd=str(tmp_path))
    assert decision["action"] == "ask", decision["lines"]


def test_r2_range_on_an_unlisted_package_is_unchanged(built, monkeypatch, tmp_path):
    _hosted(monkeypatch, lambda *a, **k: {"status": "ok"}, "9.9.9")
    assert ch.decide("pip install 'requests>=2'", env={}, cwd=str(tmp_path))["action"] == "allow"


def test_r2_tampered_list_blocks_even_with_an_override(built, monkeypatch):
    folder, manifest = built
    monkeypatch.setattr(ch, "consume_override", lambda eco, name: True)
    _tamper_db(folder, manifest)
    ch._OFFLINE_STATE.clear()
    monkeypatch.setattr(ch, "_blocklist_only_lookup", lambda *a, **k: {"status": "miss_unconfirmed"})
    out = ch.lookup({"eco": "pip", "name": "requests", "version": None})
    assert out["status"] == "blocked" and out["why"] == "offline_tampered"


def test_r2_refresh_that_loses_an_ecosystem_is_refused(built, monkeypatch, tmp_path):
    folder, manifest = built
    before = (folder / ch.OFFLINE_MANIFEST).read_bytes()
    empty_npm = tmp_path / "npm-empty.zip"
    _zip(empty_npm, [])
    with pytest.raises(RuntimeError, match="no entries for npm"):
        ob.build(sources={"pip": str(tmp_path / "pypi.zip"), "npm": str(empty_npm)}, log=lambda *a: None)
    assert (folder / ch.OFFLINE_MANIFEST).read_bytes() == before


def test_r2_refresh_that_shrinks_by_more_than_half_is_refused(home, monkeypatch, tmp_path):
    big = [_advisory("MAL-B-%d" % i, "PyPI", "bad-%d" % i, ranges=ALL_VERSIONS) for i in range(10)]
    _build_from(monkeypatch, tmp_path, big)
    with pytest.raises(RuntimeError, match="shrank by more than half"):
        _build_from(monkeypatch, tmp_path, big[:3])
    assert ch._offline_lookup("pip", "bad-9", None)["status"] == "blocked"     # the old list stays


def test_r2_manifest_without_build_time_is_stale(built, monkeypatch, capsys):
    folder, manifest = built
    path = folder / ch.OFFLINE_MANIFEST
    doc = json.loads(path.read_text())
    del doc["built"]
    key = (folder / ch.OFFLINE_KEY).read_bytes().strip()
    doc["mac"] = ch.offline_manifest_mac(key, doc)
    path.write_text(json.dumps(doc))
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok"
    assert "no build time" in ch.offline_stale_note()
    assert ob.status() == 3 and "STALE" in capsys.readouterr().out


def test_r2_build_time_a_few_hours_in_the_future_is_stale(built, monkeypatch):
    folder, manifest = built
    monkeypatch.setattr(ch.time, "time", lambda: manifest["built"] - 3 * 3600)
    ch._OFFLINE_STATE.clear()
    assert "future" in ch.offline_stale_note()


def test_r2_verification_is_per_state_folder(built, monkeypatch, tmp_path):
    """Windows CI: a result remembered for one HOME must not answer for another."""
    assert ch._offline_db()[0] == "ok"
    other = tmp_path / "other-home"
    other.mkdir()
    monkeypatch.setenv("HOME", str(other))
    monkeypatch.setenv("USERPROFILE", str(other))
    assert ch._offline_db() == ("missing", None)


# ── pip pin spellings: PEP 440 forms of a listed version match ──

PEP440_LISTED = [
    _advisory("MAL-P-1", "PyPI", "pre-bad", versions=["1.0.0rc1"]),
    _advisory("MAL-P-2", "PyPI", "post-bad", versions=["2.0.post1"]),
    _advisory("MAL-P-3", "PyPI", "dev-bad", versions=["3.0.dev2"]),
    _advisory("MAL-P-4", "PyPI", "alpha-bad", versions=["4.1a1", "4.1b2"]),
]


@pytest.mark.parametrize("name,pin", [
    ("pre-bad", "1.0.0-rc1"), ("pre-bad", "1.0.0.rc1"), ("pre-bad", "1.0.0c1"), ("pre-bad", "1.0rc1"),
    ("pre-bad", "1.0.0RC1"), ("pre-bad", "1.0.0-pre1"), ("pre-bad", "1.0.0preview1"), ("pre-bad", "v1.0.0rc1"),
    ("pre-bad", "1.0.0_rc_1"), ("pre-bad", "0!1.0.0rc1"),
    ("post-bad", "2.0-1"), ("post-bad", "2.0.post1"), ("post-bad", "2.0_post1"), ("post-bad", "2.0-r1"),
    ("post-bad", "2.0.0.rev1"),
    ("dev-bad", "3.0-dev2"), ("dev-bad", "3.0.0.dev2"), ("dev-bad", "3.0_dev_2"),
    ("alpha-bad", "4.1alpha1"), ("alpha-bad", "4.1-beta2"), ("alpha-bad", "4.1.0.b2"),
])
def test_pep440_spelling_of_a_listed_pip_version_blocks_offline(home, monkeypatch, tmp_path, name, pin):
    _build_from(monkeypatch, tmp_path, PEP440_LISTED)
    _no_hosted(monkeypatch)
    out = ch.lookup({"eco": "pip", "name": name, "version": pin})
    assert out["status"] == "blocked" and out.get("offline"), (name, pin, out)


@pytest.mark.parametrize("name,pin", [
    ("pre-bad", "1.0.0rc2"), ("pre-bad", "1.0.0"), ("pre-bad", "1.0.0.post1"), ("pre-bad", "1.0.1rc1"),
    ("post-bad", "2.0"), ("post-bad", "2.0.post2"), ("dev-bad", "3.0.dev3"), ("alpha-bad", "4.1b1"),
])
def test_pep440_different_versions_are_not_matched(home, monkeypatch, tmp_path, name, pin):
    _build_from(monkeypatch, tmp_path, PEP440_LISTED)
    _hosted(monkeypatch, lambda *a, **k: {"status": "ok"}, None)
    assert ch.lookup({"eco": "pip", "name": name, "version": pin})["status"] == "ok", (name, pin)


def test_pep440_spelling_is_caught_on_the_hosted_path_too(home, monkeypatch):
    """No offline list: hosted says ok for the exact pin, but the unmetered
    blocklist route lists 1.0.0rc1 — `1.0.0-rc1` is the same release."""
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    monkeypatch.setattr(ch, "_blocklist_only_lookup", lambda *a, **k: {
        "status": "version_needed", "affected": ["==1.0.0rc1"], "advisory": "MAL-P-1"})
    for pin in ("1.0.0-rc1", "1.0.0.rc1", "1.0.0c1"):
        out = ch.lookup({"eco": "pip", "name": "pre-bad", "version": pin})
        assert out["status"] == "blocked", (pin, out)


def test_npm_versions_keep_npm_rules(home, monkeypatch, tmp_path):
    _build_from(monkeypatch, tmp_path, [_advisory("MAL-N-1", "npm", "npm-pre", versions=["5.6.1-rc.1"])], eco="npm")
    _hosted(monkeypatch, lambda *a, **k: {"status": "ok"}, None)
    assert ch.lookup({"eco": "npm", "name": "npm-pre", "version": "5.6.1-rc.1"})["status"] == "blocked"
    assert ch.lookup({"eco": "npm", "name": "npm-pre", "version": "5.6.1-rc1"})["status"] == "ok"


@pytest.mark.parametrize("raw,canon", [
    ("1.0.0rc1", "1rc1"), ("1.0.0-RC.1", "1rc1"), ("1.0c1", "1rc1"), ("v2.0.0", "2"), ("0!1.2", "1.2"),
    ("1!1.2", "1!1.2"), ("2.0-1", "2.post1"), ("2.0.r", "2.post0"), ("3.0.dev", "3.dev0"),
    ("1.2+local.7", "1.2"), ("1.0a", "1a0"), ("1.0.0.0.0", "1"),
])
def test_pep440_canonical_forms(raw, canon):
    assert ch._pep440(raw) == canon


@pytest.mark.parametrize("raw", ["latest", "1.0.x", "", "^1.2", "1.0²", "٣.1", None, 1.0])
def test_non_pep440_versions_are_not_forced(raw):
    assert ch._pep440(raw) is None


def test_unicode_digits_do_not_crash_the_range_check():
    assert ch._numeric_version("1.²") is None
    assert ch._offline_version_listed("1.2", ["<².0"]) is None


# ── review 3 findings ──

class _PermissiveCache:
    """A verdict cache that would serve any hash-pinned package as clean."""
    def __getattr__(self, name):
        return {
            "cacheable": lambda pkg: True, "cve_held": lambda cve: False,
            "cve_could_not": lambda cve: True, "cve_completed_clear": lambda cve, v: True,
            "blocklist_could_not": lambda outcome: True, "blocklist_completed_clear": lambda outcome: False,
            "ttl_seconds": lambda warn=None: 86400,
            "find": lambda *a: {"verified_at": 0, "eco": "pip", "name": a[2], "version": a[3]},
        }[name]


def _pinned(name, version="1.0"):
    return {"eco": "pip", "name": name, "version": version, "hash": "sha256:" + "a" * 64}


def test_r3_cache_never_serves_an_offline_listed_package(built, monkeypatch):
    """IMPORTANT (review 3): a timed-out lookup must not be answered from the
    verdict cache when the offline list has the package."""
    monkeypatch.setattr(ch, "_verdict_cache", lambda: _PermissiveCache())
    packages = [_pinned("evil-pkg"), _pinned("partly-bad", "1.0.0"), _pinned("requests")]
    timeout = ({"status": "unverified", "why": "timeout"}, 1.0)
    served = ch._cache_serve(packages, {0: timeout, 1: timeout, 2: timeout}, {}, False, [], False, set(), 0)
    assert set(served) == {2}                       # only the unlisted one


def test_r3_cache_serves_nothing_while_the_list_is_tampered(built, monkeypatch):
    folder, manifest = built
    _tamper_db(folder, manifest)
    ch._OFFLINE_STATE.clear()
    monkeypatch.setattr(ch, "_verdict_cache", lambda: _PermissiveCache())
    timeout = ({"status": "unverified", "why": "timeout"}, 1.0)
    assert ch._cache_serve([_pinned("requests")], {0: timeout}, {}, False, [], False, set(), 0) == {}


def test_r3_listed_package_late_in_a_long_install_blocks_when_lookups_hang(built, monkeypatch, tmp_path):
    """End to end: 24 packages, every hosted lookup hangs past the deadline; the
    listed one (last) is decided offline before the pool, so it is denied."""
    def hang(*a, **k):
        time.sleep(2)
        return {"status": "ok"}
    monkeypatch.setattr(ch, "_query", hang)
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    monkeypatch.setattr(ch, "_verdict_cache", lambda: _PermissiveCache())
    names = ["pkg-%02d" % i for i in range(23)] + ["evil-pkg"]
    decision = ch.decide("pip install " + " ".join(names), env={}, deadline=0.5)
    assert decision["action"] == "deny"
    assert any("evil-pkg" in line and "offline list" in line for line in decision["lines"])


def test_r3_tampered_list_denies_every_package_of_a_long_install(built, monkeypatch):
    folder, manifest = built
    _tamper_db(folder, manifest)
    ch._OFFLINE_STATE.clear()
    monkeypatch.setattr(ch, "_query", lambda *a, **k: time.sleep(2) or {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    decision = ch.decide("pip install " + " ".join("p%d" % i for i in range(20)), env={}, deadline=0.5)
    assert decision["action"] == "deny"
    blocked = [r for r in decision["records"] if r["verdict"] == "blocked"]
    assert len(blocked) == 20 and all("integrity check" in (r.get("explanation") or "") for r in blocked)


def test_r3_partly_listed_unpinned_that_times_out_is_blocked(built, monkeypatch):
    monkeypatch.setattr(ch, "_query", lambda *a, **k: time.sleep(2) or {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    decision = ch.decide("pip install partly-bad", env={}, deadline=0.3)
    assert decision["action"] == "deny" and "could not be worked out" in decision["lines"][0]


def test_r3_listed_package_with_an_override_still_asks(built, monkeypatch):
    """The early offline decision respects a user's override (ask), as lookup() does."""
    (built[0] / "overrides.json").write_text(json.dumps({"allow": ["evil-pkg"]}))
    _no_hosted(monkeypatch)
    monkeypatch.setattr(ch, "_blocklist_only_lookup", lambda *a, **k: None)
    assert ch.decide("pip install evil-pkg", env={})["action"] == "ask"
    assert json.loads((built[0] / "overrides.json").read_text())["allow"] == ["evil-pkg"]


def test_r3_force_accepts_a_refresh_that_was_refused(built, monkeypatch, tmp_path):
    empty_npm = tmp_path / "npm-empty.zip"
    _zip(empty_npm, [])
    sources = {"pip": str(tmp_path / "pypi.zip"), "npm": str(empty_npm)}
    with pytest.raises(RuntimeError, match="--refresh --force"):
        ob.build(sources=sources, log=lambda *a: None)
    manifest = ob.build(sources=sources, log=lambda *a: None, force=True)
    assert manifest["counts"] == {"pip": 2}
    with pytest.raises(RuntimeError, match="no entries:"):          # an empty list: never, even forced
        ob.build(sources={"pip": str(empty_npm)}, log=lambda *a: None, force=True)


def test_r3_second_introduced_does_not_drop_later_ranges():
    specs = ob._version_specs({"ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.5"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "7.0"}, {"fixed": "7.1"}]},
    ]})
    assert specs == [">=1.0", ">=2.0,<2.5", ">=7.0,<7.1"]


@pytest.mark.parametrize("outcome,says,never", [
    ({"status": "blocked", "why": "offline_tampered", "local": True}, "integrity check", "reported as malicious"),
    ({"status": "blocked", "why": "version_unresolved", "affected": ["==1.0"]}, "could not be worked out",
     "It is on the stillrunning blocklist"),
])
def test_r3_scan_cli_says_why_it_blocked(home, capsys, outcome, says, never):
    from stillrunning import cli
    cli._print_outcome({"eco": "pip", "name": "requests", "version": None}, outcome)
    out = capsys.readouterr().out
    assert says in out and never not in out


# ── --force only from a person; what it drops is printed and logged ──

def test_force_is_refused_without_a_terminal(built, monkeypatch, capsys):
    called = []
    monkeypatch.setattr(ob, "build", lambda **k: called.append(k))
    monkeypatch.setattr(ob.sys, "stdin", io.StringIO(""))           # cron, a script, a pipe
    assert ob.main(["--refresh", "--force"]) == 2
    assert called == [] and "only accepted from a person" in capsys.readouterr().err


def test_force_alone_is_refused(built, capsys):
    assert ob.main(["--force"]) == 2


def test_force_from_a_terminal_reaches_the_build(built, monkeypatch):
    called = []
    monkeypatch.setattr(ob, "build", lambda **k: called.append(k))
    monkeypatch.setattr(ob, "_a_person_is_typing", lambda: True)
    monkeypatch.setattr(ob, "status", lambda: 0)
    assert ob.main(["--refresh", "--force"]) == 0 and called == [{"force": True}]
    called.clear()
    monkeypatch.setattr(ob, "_a_person_is_typing", lambda: False)
    assert ob.main(["--refresh"]) == 0 and called == [{"force": False}]     # plain refresh needs no terminal


def test_automatic_refresh_and_the_hook_never_pass_force(home):
    assert "--force" not in ob.cron_line()
    import ast
    hook_source = open(HOOK, encoding="utf-8").read()
    tree = ast.parse(hook_source)
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names} | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any("offline_blocklist" in name for name in imported)        # the hook never builds
    assert "offline_blocklist" not in hook_source and "refresh --force" not in hook_source
    assert "force" not in ch.lookup.__code__.co_varnames and "force" not in ch.decide.__code__.co_varnames


def test_forced_refresh_prints_logs_and_records_what_it_dropped(built, monkeypatch, tmp_path, capsys):
    folder, _ = built
    empty_npm = tmp_path / "npm-empty.zip"
    _zip(empty_npm, [])
    lines = []
    manifest = ob.build(sources={"pip": str(tmp_path / "pypi.zip"), "npm": str(empty_npm)},
                        log=lines.append, force=True)
    assert any("FORCED" in l and "npm 2 -> 0" in l for l in lines), lines
    logged = (folder / ob.FORCE_LOG).read_text()
    assert "FORCED" in logged and "npm 2 -> 0" in logged
    assert manifest["forced"]["dropped"] == ["npm 2 -> 0"]
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok"                              # the record is covered by the MAC
    ob.status()
    assert "Built with --force, accepting: npm 2 -> 0" in capsys.readouterr().out


def test_unforced_refresh_with_nothing_dropped_writes_no_force_log(built, monkeypatch, tmp_path):
    folder, _ = built
    ob.build(sources={"pip": str(tmp_path / "pypi.zip"), "npm": str(tmp_path / "npm.zip")}, log=lambda *a: None)
    assert not (folder / ob.FORCE_LOG).exists()


def test_status_survives_a_non_numeric_build_time(built, capsys):
    folder, _ = built
    path = folder / ch.OFFLINE_MANIFEST
    doc = json.loads(path.read_text())
    doc["built"] = "yesterday"
    doc["mac"] = ch.offline_manifest_mac((folder / ch.OFFLINE_KEY).read_bytes().strip(), doc)
    path.write_text(json.dumps(doc))
    assert ob.status() == 3 and "build time unknown" in capsys.readouterr().out


# ── review 4 findings ──

def test_r4_huge_version_cannot_turn_a_block_into_ask(built, monkeypatch):
    """IMPORTANT (review 4): a 4,400-digit pin on a partly-listed package made the
    pre-pass raise, and the whole decision fell back to 'ask'."""
    _no_hosted(monkeypatch)
    command = "pip install evil-pkg; pip install 'partly-bad==1.%s'" % ("9" * 4400)
    decision = ch.decide(command, env={})
    assert decision["action"] == "deny"
    assert any("evil-pkg" in line and "offline list" in line for line in decision["lines"])


def test_r4_an_error_in_the_offline_pre_pass_blocks_that_package(built, monkeypatch):
    real = ch._offline_lookup

    def boom(eco, name, version):
        if name == "boom-pkg":
            raise RuntimeError("synthetic")
        return real(eco, name, version)
    monkeypatch.setattr(ch, "_offline_lookup", boom)
    _no_hosted(monkeypatch)
    decision = ch.decide("pip install boom-pkg", env={})
    assert decision["action"] == "deny" and "check failed on this package" in decision["lines"][0]


@pytest.mark.parametrize("command", [
    "stillrunning blocklist --refresh --force", "stillrunning blocklist --force --refresh",
    "stillrunning blocklist --refresh --fo", "stillrunning blocklist --unschedule",
    "python3 -m stillrunning blocklist --refresh --force",
    "script -qc 'stillrunning blocklist --refresh --force' /dev/null",
    "sr=stillrunning; $sr blocklist --refresh --force",
    "cd /tmp && stillrunning blocklist --refresh --force=1",
])
def test_r4_forcing_or_unscheduling_the_blocklist_asks(home, command):
    """IMPORTANT (review 4): an agent could run --force through a pseudo-terminal
    (`script -qc`); the hook now asks a person first, as for `stillrunning allow`."""
    assert ch.touches_protection(command), command
    assert ch.decide(command, env={})["action"] == "ask"


@pytest.mark.parametrize("command", [
    "stillrunning blocklist --refresh", "stillrunning blocklist --status",
    # (`--schedule` asks since review 11: see test_r11_blocklist_schedule_always_asks)
])
def test_r4_ordinary_blocklist_commands_do_not_ask(home, command):
    assert not ch.touches_protection(command)


def test_r4_package_manager_force_flags_are_unaffected(home):
    assert not ch.touches_protection("npm install --force lodash")
    assert not ch.touches_protection("pip install --force-reinstall requests")


def test_r4_a_forced_refresh_stays_on_record_after_normal_refreshes(built, monkeypatch, tmp_path, capsys):
    folder, _ = built
    empty_npm = tmp_path / "npm-empty.zip"
    _zip(empty_npm, [])
    ob.build(sources={"pip": str(tmp_path / "pypi.zip"), "npm": str(empty_npm)}, log=lambda *a: None, force=True)
    after = ob.build(sources={"pip": str(tmp_path / "pypi.zip")}, log=lambda *a: None)     # normal (cron) refresh
    assert "forced" not in after and after["forced_history"][-1]["dropped"] == ["npm 2 -> 0"]
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok"                        # the history is under the MAC
    ob.status()
    assert "Forced refreshes so far: 1" in capsys.readouterr().out


def test_r4_deleted_manifest_with_the_list_still_there_is_tampered(built, monkeypatch):
    folder, _ = built
    (folder / ch.OFFLINE_MANIFEST).unlink()
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "tampered"
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    assert ch.decide("pip install requests", env={})["action"] == "deny"


def test_r4_no_list_files_at_all_is_still_missing(home):
    assert ch._offline_db() == ("missing", None)


@pytest.mark.parametrize("zero", ["0", "0.0", "0.0.0", "v0.0.0", "00.0"])
def test_r4_introduced_zero_in_any_spelling_is_every_version(zero):
    assert ob._version_specs({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": zero}]}]}) == "*"
    assert ob._version_specs({"ranges": [{"type": "SEMVER", "events": [
        {"introduced": zero}, {"fixed": "2.0"}]}]}) == ["<2.0"]


# ── a verified list SQLite cannot read: fail closed, never "not listed" ──

def test_verified_list_that_sqlite_cannot_open_blocks_on_hosted_ok(built, monkeypatch):
    import sqlite3

    def broken(*a, **k):
        raise sqlite3.OperationalError("unable to open database file")
    monkeypatch.setattr(sqlite3, "connect", broken)
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    assert ch._offline_db()[0] == "ok"                       # verified: the files check out
    for name in ("evil-pkg", "requests"):
        decision = ch.decide("pip install " + name, env={})
        assert decision["action"] == "deny", (name, decision["lines"])
        assert "could not be checked" in " ".join(r.get("explanation") or "" for r in decision["records"])


def test_verified_list_with_no_sqlite3_module_blocks(built, monkeypatch):
    monkeypatch.setitem(sys.modules, "sqlite3", None)        # `import sqlite3` raises ImportError
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    out = ch.lookup({"eco": "pip", "name": "evil-pkg", "version": None})
    assert out["status"] == "blocked" and out["why"] == "offline_error"


def test_no_list_at_all_still_falls_through_without_sqlite(home, monkeypatch):
    monkeypatch.setitem(sys.modules, "sqlite3", None)
    monkeypatch.setattr(ch, "_query", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda *a, **k: True)
    assert ch.lookup({"eco": "pip", "name": "requests", "version": None})["status"] == "ok"


# ── review 5: an option with a value before, between or after the subcommand ──

_VALUE_OPTIONS = ["--token x", "--token=x", "--tok x", "--tok=x", "--to x",
                  "--name x", "--name=x", "--nam x", "--na=x"]
_OWN_SUBCOMMANDS = {
    "blocklist-force": ("blocklist", ["--refresh", "--force"]),
    "blocklist-unschedule": ("blocklist", ["--unschedule"]),
    "whitelist-add": ("whitelist", ["add", "evil"]),
    "whitelist-remove": ("whitelist", ["remove", "evil"]),
}


def _placed(sub, args, option, where):
    words = [sub] + args
    if where == "before":
        words = [option] + words
    elif where == "between":
        words = [sub, option] + args
    else:
        words = words + [option]
    return " ".join(words)


@pytest.mark.parametrize("option", _VALUE_OPTIONS)
@pytest.mark.parametrize("where", ["before", "between", "after"])
@pytest.mark.parametrize("kind", sorted(_OWN_SUBCOMMANDS))
@pytest.mark.parametrize("launcher", ["stillrunning {}", "python3 -m stillrunning {}",
                                      "script -qc 'stillrunning {}' /dev/null", "sr=stillrunning; $sr {}"])
def test_r5_value_options_never_hide_an_own_subcommand(home, option, where, kind, launcher):
    """IMPORTANT (review 5): `stillrunning --token x blocklist --unschedule` ran
    without asking because `x` was taken for the subcommand. The whitelist rule
    had the same flaw already on main."""
    sub, args = _OWN_SUBCOMMANDS[kind]
    command = launcher.format(_placed(sub, args, option, where))
    assert ch.touches_protection(command), command


@pytest.mark.parametrize("command", [
    "stillrunning --token x blocklist --refresh", "stillrunning --name x blocklist --status",
    "stillrunning blocklist --status --token x", "stillrunning --token x scan requests",
    "stillrunning whitelist list --name x", "stillrunning --name x status",
])
def test_r5_ordinary_commands_with_value_options_do_not_ask(home, command):
    assert not ch.touches_protection(command), command


def test_r5_first_build_that_fails_writing_the_manifest_leaves_no_orphan(home, monkeypatch, tmp_path):
    """MINOR 1 (review 5): a crash after the database landed but before its
    manifest left a database with no manifest: read as tampering."""
    feed = tmp_path / "feed.zip"
    _zip(feed, PYPI)
    monkeypatch.setattr(ob, "_download", lambda url, dest: open(dest, "wb").write(open(str(url), "rb").read()))

    def disk_full(folder, manifest):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(ob, "_write_manifest", disk_full)
    with pytest.raises(OSError):
        ob.build(sources={"pip": str(feed)}, log=lambda *a: None)
    state = home / ".stillrunning"
    left = sorted(os.listdir(str(state)))
    assert not [f for f in left if ch._OFFLINE_DB_NAME.match(f)], left
    assert ch.OFFLINE_KEY not in left and not [f for f in left if f.endswith(".tmp")], left
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db() == ("missing", None)       # as if nothing was ever built: no install blocked


def test_r5_failed_refresh_over_a_good_list_keeps_it_working(built, monkeypatch, tmp_path):
    folder, manifest = built
    monkeypatch.setattr(ob, "_write_manifest", lambda f, m: (_ for _ in ()).throw(OSError(28, "disk full")))
    with pytest.raises(OSError):
        ob.build(sources={"pip": str(tmp_path / "pypi.zip"), "npm": str(tmp_path / "npm.zip")}, log=lambda *a: None)
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok" and (folder / manifest["db"]).exists()     # same content: not removed


def test_r5_failed_refresh_message_does_not_promise_an_old_list(home, monkeypatch, capsys):
    monkeypatch.setattr(ob, "build", lambda **k: (_ for _ in ()).throw(RuntimeError("feed down")))
    assert ob.main(["--refresh"]) == 1
    err = capsys.readouterr().err
    assert "Whatever was in place before this refresh is unchanged" in err and "stays in place and verified" not in err


@pytest.mark.parametrize("zero", ["0.0.0-0", "0.0.0-alpha", "0.0.0-rc.1", "0.0.0a0", "0.0.0.dev0", "0.0.0+local",
                                  "v0.0.0-beta.2", "0.0.0_rc1"])
def test_r5_any_zero_pre_release_introduced_means_every_version(zero):
    assert ob._version_specs({"ranges": [{"type": "SEMVER", "events": [{"introduced": zero}]}]}) == "*"


@pytest.mark.parametrize("not_zero", ["0.1", "0.0.1", "0.0.1-0", "0.10", "0.0.0.1", "1.0.0-0"])
def test_r5_versions_after_zero_are_not_widened(not_zero):
    assert ob._version_specs({"ranges": [{"type": "SEMVER", "events": [{"introduced": not_zero}]}]}) == [">=" + not_zero]



# ── review 6: words only known at run time, or handed over by another program ──

@pytest.mark.parametrize("command", [
    "U=--unschedule; stillrunning blocklist $U", "X=blocklist; stillrunning $X --unschedule",
    "stillrunning blocklist $(echo --unschedule)", "stillrunning $(echo blocklist) --unschedule",
    "stillrunning ${B:-blocklist} --unschedule", "stillrunning blocklist `echo --unschedule`",
    "echo --unschedule | xargs stillrunning blocklist", "echo blocklist --unschedule | xargs stillrunning",
    'f(){ stillrunning blocklist "$@"; }; f --unschedule', 'parallel stillrunning ::: "blocklist --unschedule"',
    'F=--force; script -qc "stillrunning blocklist --refresh $F" /dev/null',
    "script -qc 'F=--force; stillrunning blocklist --refresh $F' /dev/null",
    "A=add; stillrunning whitelist $A evil", "W=whitelist; stillrunning $W add evil",
    "echo whitelist add evil | xargs stillrunning",
    # the same gap on main's own rules
    "X=allow; stillrunning $X evil", "R=remember; stillrunning $R last", "U=--uninstall-hook-claude-code; stillrunning $U",
    "sr=stillrunning; $sr blocklist $U", "nice stillrunning $X evil", "python3 -m stillrunning $X evil",
    "env stillrunning $(cat cmd.txt)", "echo allow evil | xargs -n2 stillrunning",
])
def test_r6_run_time_words_in_a_stillrunning_command_ask(home, command):
    """IMPORTANT (review 6): a switch supplied by expansion or by xargs/parallel
    ran without asking; this held for every own-command rule, not only the new ones."""
    assert ch.touches_protection(command), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", [
    "stillrunning scan requests", "stillrunning --version", "stillrunning blocklist --status",
    "stillrunning blocklist --refresh", "echo $HOME", "ls | xargs grep foo", 'git commit -m "$MSG"',
    "stillrunning scan requests && echo $?", "npm install --force lodash", "parallel gzip ::: a b",
])
def test_r6_ordinary_commands_still_do_not_ask(home, command):
    assert not ch.touches_protection(command), command


def test_r6_failed_manifest_write_leaves_no_temp_file(built, monkeypatch, tmp_path):
    folder, _ = built
    def fail_after_writing(path, tmp, manifest):
        with open(tmp, "w") as handle:
            handle.write("{}")
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(ob, "_write_manifest_to", fail_after_writing)
    with pytest.raises(OSError):
        ob.build(sources={"pip": str(tmp_path / "pypi.zip"), "npm": str(tmp_path / "npm.zip")}, log=lambda *a: None)
    assert not [f for f in os.listdir(str(folder)) if f.endswith(".tmp")]


def test_r6_an_interrupt_never_deletes_the_database_a_manifest_points_at(built, monkeypatch, tmp_path):
    folder, _ = built
    real = ob._write_manifest_to

    def interrupted(path, tmp, manifest):     # the new manifest lands, then Ctrl-C before returning
        real(path, tmp, manifest)
        raise KeyboardInterrupt
    monkeypatch.setattr(ob, "_write_manifest_to", interrupted)
    big = [_advisory("MAL-K-%d" % i, "PyPI", "k-%d" % i, ranges=ALL_VERSIONS) for i in range(4)]
    feed = tmp_path / "k.zip"
    _zip(feed, big)
    with pytest.raises(KeyboardInterrupt):
        ob.build(sources={"pip": str(feed), "npm": str(tmp_path / "npm.zip")}, log=lambda *a: None)
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok"        # the manifest and its database are both there


# ── review 7 (items 1 and 5) ──

@pytest.mark.parametrize("command", [
    "grep -r stillrunning $DIR", "echo stillrunning $HOME", 'rg stillrunning "$PWD"', "ls | xargs grep stillrunning",
    "cat ~/notes/stillrunning.md | xargs echo",
    # (review 9's fail-closed rule: `pip download stillrunning -d $TMP`, `docker run --name
    # stillrunning img $CMD` and `python3 script.py stillrunning $X` now ask, see test_r9_*)
])
def test_r7_a_word_stillrunning_that_is_not_the_program_does_not_ask(home, command):
    """IMPORTANT (review 7): the run-time-word rule fired on any word `stillrunning`,
    not only on the program a command runs."""
    assert not ch.touches_protection(command), command


@pytest.mark.parametrize("command", [
    "nice stillrunning $X evil", "sudo -u bob stillrunning $X evil", "env A=1 stillrunning $X", "timeout 5 stillrunning $X",
    "python3 -Im stillrunning $X", "python3 -mstillrunning $X", "/usr/local/bin/stillrunning $X",
])
def test_r7_the_program_stillrunning_behind_wrappers_still_asks(home, command):
    assert ch.touches_protection(command), command


def _first_build_feed(monkeypatch, tmp_path):
    feed = tmp_path / "feed.zip"
    _zip(feed, PYPI)
    monkeypatch.setattr(ob, "_download", lambda url, dest: open(dest, "wb").write(open(str(url), "rb").read()))
    return {"pip": str(feed)}


def _assert_nothing_left_as_tampering(home):
    state = home / ".stillrunning"
    left = sorted(f for f in os.listdir(str(state)) if not f.endswith(".lock"))
    assert left == [], left
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db() == ("missing", None)


def test_r7_first_build_whose_database_rename_fails_leaves_no_key(home, monkeypatch, tmp_path):
    """MINOR->fixed (review 7 item 5): a failure between creating the key and the
    manifest left a lone key, read as tampering (every install blocked)."""
    sources = _first_build_feed(monkeypatch, tmp_path)
    monkeypatch.setattr(ob, "_replace_retrying", lambda a, b: (_ for _ in ()).throw(PermissionError(13, "in use")))
    with pytest.raises(PermissionError):
        ob.build(sources=sources, log=lambda *a: None)
    _assert_nothing_left_as_tampering(home)


def test_r7_ctrl_c_during_the_first_manifest_write_leaves_nothing(home, monkeypatch, tmp_path):
    sources = _first_build_feed(monkeypatch, tmp_path)

    def interrupted(path, tmp, manifest):          # before the manifest is replaced into place
        raise KeyboardInterrupt
    monkeypatch.setattr(ob, "_write_manifest_to", interrupted)
    with pytest.raises(KeyboardInterrupt):
        ob.build(sources=sources, log=lambda *a: None)
    _assert_nothing_left_as_tampering(home)


def test_r7_ctrl_c_right_after_the_first_manifest_landed_keeps_the_new_list(home, monkeypatch, tmp_path):
    sources = _first_build_feed(monkeypatch, tmp_path)
    real = ob._write_manifest_to

    def interrupted(path, tmp, manifest):
        real(path, tmp, manifest)
        raise KeyboardInterrupt
    monkeypatch.setattr(ob, "_write_manifest_to", interrupted)
    with pytest.raises(KeyboardInterrupt):
        ob.build(sources=sources, log=lambda *a: None)
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok"


def test_r7_failure_over_an_existing_list_keeps_it_and_its_key(built, monkeypatch, tmp_path):
    folder, manifest = built
    big = [_advisory("MAL-Q-%d" % i, "PyPI", "q-%d" % i, ranges=ALL_VERSIONS) for i in range(5)]
    feed = tmp_path / "q.zip"
    _zip(feed, big)
    monkeypatch.setattr(ob, "_write_manifest_to", lambda p, t, m: (_ for _ in ()).throw(KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        ob.build(sources={"pip": str(feed), "npm": str(tmp_path / "npm.zip")}, log=lambda *a: None)
    ch._OFFLINE_STATE.clear()
    assert ch._offline_db()[0] == "ok" and (folder / manifest["db"]).exists() and (folder / ch.OFFLINE_KEY).exists()
    assert len([f for f in os.listdir(str(folder)) if ch._OFFLINE_DB_NAME.match(f)]) == 1     # the new one taken back


# ── review 8 ──

@pytest.mark.parametrize("command", [
    # python options that take a value, separate or attached, and clustered flags
    "X=--unschedule; python3 -W ignore -m stillrunning blocklist $X",
    "python3 -Wignore -m stillrunning blocklist $X", 'python3 -X dev -m stillrunning blocklist "$X"',
    "python3 -Xdev -m stillrunning $X evil", "python3 -IW ignore -m stillrunning $X",
    "python3 -IBm stillrunning $X", "python3 -mstillrunning $X", "python3 -W ignore -mstillrunning $X",
    "python3 -W ignore -X dev -IB -m stillrunning $X", "python3 --check-hash-based-pycs never -m stillrunning $X",
    "python3.12 -W ignore -m stillrunning $X", "/usr/bin/python3 -X dev -m stillrunning $X",
    "env python3 -W ignore -m stillrunning $X", "env -u A python3 -Xdev -m stillrunning $X",
    "python3 -W ignore -m stillrunning blocklist $(echo --unschedule)",
    "echo --unschedule | xargs python3 -W ignore -m stillrunning blocklist",
    "script -qc 'python3 -W ignore -m stillrunning blocklist --refresh $X' /dev/null",
    "python3 -W ignore -m stillrunning $X evil", "X=allow; python3 -X dev -m stillrunning $X evil",
])
def test_r8_python_options_before_dash_m_still_ask(home, command):
    """IMPORTANT (review 8): `python3 -W ignore -m stillrunning …` read `ignore` as
    a script name, so the run-time-word rule never fired."""
    assert ch.touches_protection(command), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", [
    "uvx stillrunning blocklist $X", "uvx stillrunning@latest $X evil", "uvx stillrunning==2.14.3 $X",
    "uvx 'stillrunning[cli]' $X", "uvx --python 3.12 stillrunning $X", "uvx -p 3.12 stillrunning $X",
    "uvx --from stillrunning stillrunning $X", "uvx --from stillrunning==2.14.3 stillrunning blocklist $X",
    "uvx --with requests --isolated stillrunning $X", "uvx --python=3.12 stillrunning $X",
    "pipx run stillrunning $X", "pipx run --spec stillrunning stillrunning $X",
    "pipx run --spec stillrunning==2.14.3 --python python3.12 stillrunning $X", "pipx run stillrunning==2.14.3 $X",
    "uv run stillrunning $X", "uv run --with requests stillrunning $X", "uv run python -m stillrunning $X",
    "uv run python3 -W ignore -m stillrunning $X", "uv run -m stillrunning $X", "uv run --module stillrunning $X",
    "uv tool run stillrunning $X", "uv tool run --with requests stillrunning $X",
    "uv tool run --from stillrunning@latest stillrunning $X", "uv -q tool run stillrunning $X",
    "uv --directory /tmp run stillrunning $X", "uv run -- stillrunning $X",
    "echo --unschedule | xargs uvx stillrunning blocklist", "nice uvx stillrunning $X",
    "X=allow; uvx stillrunning $X evil",
    # literal switches behind a launcher or a version suffix
    "uvx stillrunning@latest allow evil", "uvx stillrunning==2.14.3 blocklist --unschedule",
    "pipx run stillrunning --uninstall-hook-claude-code", "uv tool run stillrunning@latest remember last",
])
def test_r8_launchers_that_run_stillrunning_ask(home, command):
    """IMPORTANT (review 8): uvx / pipx run / uv run / uv tool run were not seen as running stillrunning."""
    assert ch.touches_protection(command), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", [
    "uvx ruff check $X", "uvx --from black black $X", "uv run pytest $X", "pipx run black $X",
    "uvx --python 3.12 ruff $X", "uv tool run ruff $X", "uv pip list", "python3 -X dev other.py $X",
    "python3 -W ignore -m pytest $X", "uv run python -m pytest $X",
    # (with the word `stillrunning` and a run-time word these now ask: review 9's fail-closed rule)
])
def test_r8_launchers_and_python_running_something_else_do_not_ask(home, command):
    assert not ch.touches_protection(command), command


@pytest.mark.parametrize("command", [
    "stillrunning {allow,allow} evil", "stillrunning whitelist ad{d,d} evil", "stillrunning whitelist *",
    "stillrunning blocklist --unschedul{e,e}", "script -qc 'stillrunning blocklist --refresh --forc{e,e}' /dev/null",
    "stillrunning blocklist *", "stillrunning blocklist --unsched?le", "stillrunning blocklist --[u]nschedule",
    "python3 -m stillrunning {allow,allow} evil", "uvx stillrunning blocklist --unschedul*",
    "stillrunning blocklist --{force,refresh}", "stillrunning {remember,x} last",
    # the program itself spelled with a brace or a glob
    "stillrunnin{g,g} allow evil", "/usr/local/bin/stillrunnin? allow evil", "python3 -m stillrunnin{g,g} $X",
    # rules that do not need the program to be proven: a word `stillrunning` (unknown wrapper),
    # and a program known only at run time
    "setsid stillrunning {allow,allow} evil", "setsid stillrunning whitelist ad{d,d} evil",
    "$sr {allow,allow} evil", "$sr whitelist ad{d,d} evil", "$sr blocklist --unschedul{e,e}",
    "$sr blocklist --unsched*",
])
def test_r8_braces_and_globs_count_as_run_time_words(home, command):
    """Pre-existing gap widened by this PR's new switches (review 8): brace expansion
    and globs were taken literally, so `--unschedul{e,e}` was not seen as `--unschedule`."""
    assert ch.touches_protection(command), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", [
    "echo {a,b}", "cp *.txt /tmp/", "ls stillrunning/*", "grep -r stillrunning *.py",
    "stillrunning scan requests", "stillrunning blocklist --status", "$EDITOR *.py", "mv file.{txt,bak}",
    "grep -r stillrunning src/{a,b}",
])
def test_r8_braces_and_globs_elsewhere_do_not_ask(home, command):
    assert not ch.touches_protection(command), command


# Every prefix of the two new switches, with and without `=value`.
_R8_PREFIXES = ["--" + full[2:n] for full in ("--unschedule", "--force") for n in range(3, len(full) + 1)]


@pytest.mark.parametrize("word", _R8_PREFIXES)
def test_r8_each_prefix_argparse_accepts_makes_the_hook_ask(home, monkeypatch, word):
    """UNVERIFIED in review 8, settled here: which prefixes of --unschedule / --force
    reach the blocklist subcommand depends on the Python version (3.8 and 3.12 reject
    `--u` and `--un` as ambiguous with the top-level --uninstall-hook*; 3.15 passes them
    on). Whatever this Python's argparse accepts, the hook must ask for it."""
    from stillrunning import cli
    seen = []
    monkeypatch.setattr(ob, "main", lambda flags: seen.append(flags) or 0)
    monkeypatch.setattr(sys, "argv", ["stillrunning", "blocklist", word])
    with pytest.raises(SystemExit):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            cli.main_cli()
    reached = any(set(flags) & {"--unschedule", "--force"} for flags in seen)
    print("python %s: blocklist %s -> %s" % (sys.version.split()[0], word, seen or "rejected"))
    if reached:
        assert ch.touches_protection("stillrunning blocklist " + word), word


@pytest.mark.parametrize("word", _R8_PREFIXES + [w + "=1" for w in _R8_PREFIXES])
def test_r8_every_prefix_asks_on_every_python(home, word):
    """3.15's argparse passes `blocklist --u` on to --unschedule: ask for every prefix,
    whatever the Python version."""
    assert ch.touches_protection("stillrunning blocklist " + word), word
    assert ch.touches_protection("python3 -W ignore -m stillrunning blocklist " + word), word


def test_r8_ctrl_c_while_writing_the_manifest_leaves_no_temp_file(built, monkeypatch, tmp_path):
    """Nit (review 8): `_write_manifest` caught Exception only, so Ctrl-C left
    blocklist.manifest.json.<pid>.tmp behind, although the CHANGELOG says it is taken back."""
    folder, _ = built

    def interrupted(path, tmp, manifest):      # the temp file is written, then Ctrl-C
        with open(tmp, "w") as handle:
            handle.write("{}")
        raise KeyboardInterrupt
    monkeypatch.setattr(ob, "_write_manifest_to", interrupted)
    with pytest.raises(KeyboardInterrupt):
        ob._write_manifest(str(folder), {"v": 1})
    assert not [f for f in os.listdir(str(folder)) if f.endswith(".tmp")]


def test_r8_ctrl_c_while_writing_a_new_key_leaves_no_temp_file(home, monkeypatch):
    folder = home / ".stillrunning"
    folder.mkdir()

    def interrupted(src, dst):
        raise KeyboardInterrupt
    monkeypatch.setattr(ob.os, "replace", interrupted)
    with pytest.raises(KeyboardInterrupt):
        ob._key(str(folder))
    assert not [f for f in os.listdir(str(folder)) if f.endswith(".tmp")]


# ── review 9: fail-closed with a read-only allow-list ──

@pytest.mark.parametrize("command", [
    # A: `uv run -m` is a flag; options may stand before the module
    "uv run -m --no-sync stillrunning blocklist $(echo --unschedule)",
    "uv run -m -q stillrunning blocklist $(echo --unschedule)",
    "uv run --with x -m --python 3.12 stillrunning blocklist $(echo --unschedule)",
    # B: words fed by parallel
    "parallel stillrunning blocklist ::: $(echo --unschedule)", "parallel stillrunning blocklist :::: args.txt",
    "parallel stillrunning ::: 'blocklist --unschedule'",
    # C: wrappers and interpreter names the parser does not know
    "flock -n /tmp/l stillrunning blocklist $(echo --unschedule)",
    "nice -n 19 ionice -c 3 flock -n /tmp/l timeout 1800 python3 -m stillrunning blocklist $X",
    "setsid stillrunning blocklist $(echo --unschedule)", "chrt -i 0 stillrunning blocklist $(echo --unschedule)",
    "taskset -c 0 stillrunning blocklist $(echo --unschedule)",
    "python3.13t -m stillrunning blocklist $(echo --unschedule)",
    # review 9 section 5 (the same gaps for `allow`)
    "setsid stillrunning $(echo allow) evil", "python3.13t -m stillrunning $(echo allow) evil",
    "uv run -m --no-sync stillrunning $(echo allow) evil", "parallel stillrunning $(echo allow) ::: evil",
    # wrappers that must ask by default
    "nohup stillrunning blocklist $X", "stdbuf -oL stillrunning blocklist $X", "sudo -u bob stillrunning blocklist $X",
    "env -i stillrunning blocklist $X", "ssh localhost stillrunning blocklist $X",
    "frobnicate --wrap=7 stillrunning blocklist $X", "frobnicate -q stillrunning $(cat args)",
    # the word only somewhere in the command, or only inside a substitution / assignment
    "sr=stillrunning; $sr $X evil", "$(echo stillrunning) $X evil", "$(which stillrunning) blocklist $X",
    "cat args | stillrunning blocklist", "stillrunning blocklist < args", "stillrunning blocklist <<< --unschedule",
    "bash -c 'stillrunning blocklist $X'", "sh -c \"python3 -m stillrunning $X\"",
    "nohup sh -c 'stillrunning blocklist $1' _ --unschedule",
    "stillrunning blocklist --unsch{e,e}dule", "stillrunning blocklist --uns*",
    # not read-only, so they ask too (the cost of the rule)
    "pip download stillrunning -d $TMP", "docker run --name stillrunning img $CMD", "python3 script.py stillrunning $X",
    "uv run grep stillrunning $X", "find . -name stillrunning -exec rm {} $X", "rg --pre ./x stillrunning $X",
    "git -c core.pager=sh log stillrunning $X", "xargs -I{} sh -c 'stillrunning {}' < $F",
])
def test_r9_a_run_time_word_with_stillrunning_asks_unless_read_only(home, command):
    """IMPORTANT (review 9 A, B, C): each new launcher or wrapper case left another one
    out. Fail closed: a run-time word plus an unquoted word `stillrunning` asks, unless
    the program that receives it is a read-only tool."""
    assert ch.touches_protection(command), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", [
    # review 7's read-only controls
    "grep -r stillrunning $DIR", "echo stillrunning $HOME", 'rg stillrunning "$PWD"', "ls | xargs grep stillrunning",
    "cat ~/notes/stillrunning.md | xargs echo",
    # the rest of the read-only allow-list
    "head -n 5 ~/stillrunning.log $X", "tail -f /var/log/stillrunning.log | grep $X", "wc -l stillrunning/*.py",
    "printf '%s\\n' stillrunning $X", "find . -name 'stillrunning*' -newer $X", "find ~/stillrunning -type f | wc -l",
    "git log --oneline -- stillrunning/ $X", "git -C ~/stillrunning-mcp status $X", "git diff HEAD -- stillrunning/$F",
    "git show $REV:stillrunning/cli.py", "grep -r stillrunning *.py", "ls stillrunning/*", "grep -r stillrunning src/{a,b}",
    "cat stillrunning.txt | grep -c $X",
    # the word only inside quotes
    'git commit -m "stillrunning: fix $X"', "echo 'stillrunning blocklist' > notes.txt && ls $X",
    'pytest -k "stillrunning and $X"',
    # no run-time word at all
    "stillrunning scan requests", "stillrunning blocklist --status", "pip download stillrunning -d /tmp/x",
    # no word stillrunning
    "echo $HOME", "ls | xargs grep foo", "cp *.txt /tmp/", "$EDITOR *.py",
])
def test_r9_read_only_tools_and_quoted_mentions_do_not_ask(home, command):
    assert not ch.touches_protection(command), command


@pytest.mark.parametrize("command", [
    "stillrunning check-package requests[socks]", "stillrunning scan 'requests[socks]'",
    "python3 -m stillrunning scan requests[security,socks]", "stillrunning scan requests[socks]==2.31.0",
])
def test_r9_extras_are_not_globs(home, command):
    """False ask (review 9): `name[extras]` was read as a glob."""
    assert not ch.touches_protection(command), command


@pytest.mark.parametrize("command", [
    "stillrunning blocklist --[u]nschedule", "stillrunning blocklist [-]-unschedule", "stillrunning blocklist x[yz]*",
])
def test_r9_bracket_globs_still_ask(home, command):
    assert ch.touches_protection(command), command


# ── review 10: here-strings handed to a shell ──

@pytest.mark.parametrize("command", [
    "bash <<<'stillrunning allow evil'", "sh <<< 'stillrunning --uninstall-hook-claude-code'",
    "bash -s <<<'stillrunning blocklist --unschedule'", "sudo bash <<< \"stillrunning blocklist --unschedule\"",
    "bash <<<'script -qc \"stillrunning blocklist --refresh --force\" /dev/null'",
    "bash <<<'X=--unschedule; stillrunning blocklist $X'", "dash <<<'python3 -m stillrunning blocklist --uns'",
    "at now <<< 'stillrunning blocklist --unschedule'", "bash <<< 'rm -rf ~/.stillrunning'",
    "env bash <<<'stillrunning remember last'", "bash /dev/stdin <<<'stillrunning allow evil'",
])
def test_r10_here_strings_handed_to_a_shell_are_judged(home, command):
    """Borderline (review 10): `bash <<<'…'` ran its text unjudged, while a
    here-document to a shell was judged; it reached `blocklist --refresh --force`
    through `script -qc`, which gives the child a terminal."""
    assert ch.touches_protection(command, cwd=str(home)), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", [
    "cat <<<'stillrunning allow evil'", "grep -c allow <<< 'stillrunning allow evil'",
    "bash -c 'echo hi' <<< 'stillrunning allow evil'", "python3 <<< 'print(1)'", "bash <<<'echo hello'",
    "wc -l <<< \"stillrunning blocklist --unschedule\"",
])
def test_r10_here_strings_to_other_programs_are_data(home, command):
    assert not ch.touches_protection(command, cwd=str(home)), command


# ── review 11: --schedule, and `$` inside single quotes ──

@pytest.mark.parametrize("command", [
    "stillrunning blocklist --schedule", "HOME=/tmp/zz stillrunning blocklist --schedule",
    "env HOME=/nonexistent stillrunning blocklist --schedule", "/tmp/venv/bin/python -m stillrunning blocklist --schedule",
    "/tmp/venv/bin/stillrunning blocklist --schedule", "stillrunning blocklist --sch", "stillrunning blocklist --sched",
    "python3 -m stillrunning blocklist --schedule", "uvx stillrunning blocklist --schedule",
    "stillrunning blocklist --schedule=1",
])
def test_r11_blocklist_schedule_always_asks(home, command):
    """IMPORTANT (review 11): `HOME=/tmp/zz stillrunning blocklist --schedule` replaced a
    working refresh line with one that never runs, without asking."""
    assert ch.touches_protection(command, cwd=str(home)), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", ["stillrunning blocklist --status", "stillrunning blocklist --refresh"])
def test_r11_other_blocklist_switches_still_do_not_ask(home, command):
    assert not ch.touches_protection(command, cwd=str(home)), command


def _fake_crontab(monkeypatch, lines):
    from stillrunning import cve
    written = []
    monkeypatch.setattr(cve, "_read_crontab", lambda: (list(lines), None))
    monkeypatch.setattr(cve, "_crontab", lambda args, text=None: written.append(text) or
                        type("Ran", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    return written


@pytest.mark.skipif(os.name == "nt", reason="crontab")
def test_r11_schedule_will_not_replace_a_different_refresh_line_without_a_person(home, monkeypatch, capsys):
    old = "41 4 * * * nice -n 19 flock -n /x/.stillrunning/blocklist.lock timeout 1800 /usr/bin/python3 " \
          "-m stillrunning blocklist --refresh >/dev/null 2>>/x/.stillrunning/blocklist_cron.log " + ob.CRON_MARK
    written = _fake_crontab(monkeypatch, ["17 * * * * other job", old])
    monkeypatch.setattr(ob, "_a_person_is_typing", lambda: False)
    assert ob.schedule() == 2
    assert written == []                                   # crontab left exactly as it was
    assert "person" in capsys.readouterr().out.lower()


@pytest.mark.skipif(os.name == "nt", reason="crontab")
def test_r11_schedule_replaces_a_different_line_for_a_person(home, monkeypatch):
    old = "41 4 * * * /old/python3 -m stillrunning blocklist --refresh " + ob.CRON_MARK
    written = _fake_crontab(monkeypatch, ["17 * * * * other job", old])
    monkeypatch.setattr(ob, "_a_person_is_typing", lambda: True)
    assert ob.schedule() == 0
    assert written and old not in written[0] and ob.cron_line() in written[0] and "other job" in written[0]


@pytest.mark.skipif(os.name == "nt", reason="crontab")
def test_r11_schedule_adds_a_first_line_and_keeps_an_identical_one_without_a_person(home, monkeypatch):
    monkeypatch.setattr(ob, "_a_person_is_typing", lambda: False)
    written = _fake_crontab(monkeypatch, ["17 * * * * other job"])
    assert ob.schedule() == 0 and ob.cron_line() in written[0]
    written = _fake_crontab(monkeypatch, ["17 * * * * other job", ob.cron_line()])
    assert ob.schedule() == 0 and written == []


@pytest.mark.parametrize("command", [
    "awk '{print $1}' ~/stillrunning/x.txt", "sed -n 's/$/x/p' ~/stillrunning/x.txt",
    "perl -ne 'print if /a$/' ~/stillrunning/a.txt", "jq '.a | $__loc__' ~/stillrunning/x.json",
])
def test_r11_a_dollar_inside_single_quotes_is_not_a_run_time_word(home, command):
    """Nit (review 11): `$` inside single quotes is never expanded."""
    assert not ch.touches_protection(command, cwd=str(home)), command


@pytest.mark.parametrize("command", [
    'X=--unschedule; stillrunning blocklist "$X"', 'sed -n "s/$X/y/p" ~/stillrunning/x.txt',
    "stillrunning blocklist \"$(echo --unschedule)\"", 'X=allow; stillrunning "$X" evil',
    "nohup sh -c 'stillrunning blocklist $1' _ --unschedule",
])
def test_r11_a_dollar_inside_double_quotes_still_counts(home, command):
    assert ch.touches_protection(command, cwd=str(home)), command


# ── review 12: shell strings with no space, ${IFS} and '$(' ; a code typed back on the terminal ──

T = "\t"
R12_ASK = [
    # A: no space in the string handed to the shell
    "bash -c 'stillrunning" + T + "blocklist" + T + "--unschedule'",
    "bash -c $'stillrunning\\tblocklist\\t--unschedule'",
    "bash -c 'true&&stillrunning" + T + "blocklist" + T + "--unschedule'",
    "bash -c '{stillrunning,blocklist,--unschedule}'",
    "sh -c 'stillrunning" + T + "allow" + T + "evil'",
    # B: ${IFS} and other expansions inside single quotes handed to a shell
    "bash -c 'stillrunning${IFS}blocklist${IFS}--unschedule'",
    "sh -c 'stillrunning${IFS}blocklist${IFS}--unschedule'",
    "script -qc 'stillrunning${IFS}blocklist${IFS}--unschedule' /dev/null",
    "bash -c 'stillrunning$IFS\"blocklist\"$IFS--unschedule'",
    "bash -c 'stillrunning${IFS}blocklist${IFS}--schedule'",
    "bash -c 'stillrunning${IFS}allow${IFS}evil'",
    "X=allow bash -c 'stillrunning${IFS}$X${IFS}evil'",
    "bash -c \"stillrunning\\${IFS}\\$X\"",
    "bash -c 'stillrunning$(echo \" allow evil\")'",
    "bash -c 'stillrunning`echo \" allow evil\"`'",
    "su -c 'stillrunning${IFS}$X'", "watch 'stillrunning${IFS}$X'", "flock /tmp/l -c 'stillrunning${IFS}$X'",
    "ssh host 'stillrunning${IFS}$X'",
    "bash -c 'stillrunning${IFS}--uninstall-hook-claude-code'",
    "bash -c '$(echo stillrunning) $X evil'", "bash -c '`echo stillrunning` $X evil'",
    # C: a quoted '$(' … ')' pair around an unquoted word
    "X=--unschedule; chrt 1 stillrunning --token '$(' blocklist $X; echo ')'",
    "X=--unschedule; chrt 1 stillrunning --token '`' blocklist $X; echo '`'",
    "chrt 1 stillrunning --token '$(' $X evil ')'",
]


@pytest.mark.parametrize("command", R12_ASK)
def test_r12_shell_strings_and_lifted_quotes_ask(home, command):
    """IMPORTANT (review 12): these removed the refresh line or flipped a switch without asking."""
    assert ch.touches_protection(command, cwd=str(home)), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", [
    "awk '{print $1}' ~/stillrunning/x.txt", "sed -n 's/$/x/p' ~/stillrunning/x.txt",
    "bash -c 'stillrunning blocklist --status'", "bash -c 'ls" + T + "-la'", "bash -c ls",
    "git commit -m 'stillrunning${IFS}x'", "stillrunning scan x && echo $?",
    "grep -r 'stillrunning${IFS}' ~/notes", "ssh host uptime",
])
def test_r12_controls_still_allow(home, command):
    assert not ch.touches_protection(command, cwd=str(home)), command


@pytest.mark.skipif(os.name == "nt", reason="crontab")
def test_r12_unschedule_needs_a_person(home, monkeypatch, capsys):
    """IMPORTANT (review 12): --unschedule removed the refresh line with no terminal check."""
    line = "41 4 * * * /usr/bin/python3 -m stillrunning blocklist --refresh " + ob.CRON_MARK
    written = _fake_crontab(monkeypatch, ["17 * * * * other job", line])
    monkeypatch.setattr(ob, "_a_person_is_typing", lambda: False)
    assert ob.main(["--unschedule"]) == 2 and written == []
    assert "person" in capsys.readouterr().out
    monkeypatch.setattr(ob, "_a_person_is_typing", lambda: True)
    assert ob.main(["--unschedule"]) == 0 and written == ["17 * * * * other job\n"]


@pytest.mark.skipif(os.name == "nt", reason="crontab")
def test_r12_unschedule_with_nothing_scheduled_asks_nobody(home, monkeypatch):
    _fake_crontab(monkeypatch, ["17 * * * * other job"])
    monkeypatch.setattr(ob, "_a_person_is_typing", lambda: pytest.fail("asked for a code"))
    assert ob.main(["--unschedule"]) == 0


def test_r12_a_terminal_on_stdin_is_not_enough(monkeypatch):
    """isatty alone passed `script -qc`; the code must also be typed back on /dev/tty."""
    monkeypatch.setattr(ob.sys, "stdin", type("Tty", (), {"isatty": lambda self: True})())
    monkeypatch.setattr(ob, "_code_typed_back", lambda: False)
    assert ob._a_person_is_typing() is False
    monkeypatch.setattr(ob, "_code_typed_back", lambda: True)
    assert ob._a_person_is_typing() is True


def test_r12_the_code_is_random_and_unambiguous():
    import inspect
    assert "secrets.choice" in inspect.getsource(ob._code_typed_back)
    assert not set("0O1I5S8B") & set(ob._CODE_LETTERS) and ob._CODE_WAIT <= 300


# Real processes: a fake `crontab` first on PATH records any write; nothing touches the real one.
CRON_LINE = "41 4 * * * /usr/bin/python3 -m stillrunning blocklist --refresh "


def _fake_cron_env(tmp_path, home):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    tab = tmp_path / "crontab.txt"
    tab.write_text("17 * * * * other job\n" + CRON_LINE + ob.CRON_MARK + "\n")
    fake = bindir / "crontab"
    fake.write_text('#!/bin/sh\nif [ "$1" = "-l" ]; then cat "%s"; exit 0; fi\n'
                    'cat > "%s"; exit 0\n' % (tab, tmp_path / "WRITTEN"))
    fake.chmod(0o755)
    env = dict(os.environ, HOME=str(home), PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""),
               PYTHONPATH=os.pathsep.join(p for p in (ROOT, os.environ.get("PYTHONPATH")) if p),
               STILLRUNNING_CVE_CHECK="0", STILLRUNNING_NO_TELEMETRY="1")
    return env, tmp_path / "WRITTEN"


SR = "%s -m stillrunning blocklist " % sys.executable


@pytest.mark.skipif(os.name == "nt", reason="crontab and /dev/tty")
@pytest.mark.parametrize("feed", ["echo AAAA |", "printf 'AAAA\\n' |", "printf 'y\\ny\\n' |", "", "yes |"])
@pytest.mark.parametrize("args", ["--unschedule", "--refresh --force"])
def test_r12_piped_input_never_passes(home, tmp_path, feed, args):
    env, written = _fake_cron_env(tmp_path, home)
    line = "%s %s%s" % (feed, SR, args) if feed else "%s%s </dev/null" % (SR, args)
    ran = subprocess.run(line,
                         shell=True, env=env, capture_output=True, text=True, timeout=60,
                         start_new_session=True)          # no controlling terminal either
    assert ran.returncode == 2, ran.stdout + ran.stderr
    assert not written.exists()


def _script_ok():
    import shutil
    return sys.platform.startswith("linux") and shutil.which("script") is not None


@pytest.mark.skipif(not _script_ok(), reason="util-linux script")
@pytest.mark.parametrize("feed", ["", "printf 'AAAA\\n' |", "echo y |"])
def test_r12_script_qc_does_not_pass(home, tmp_path, feed):
    """`script -qc` gives the command a terminal; with stdin from /dev/null or a pipe nobody can
    see the code it prints, so a guess fails and end of input refuses."""
    env, written = _fake_cron_env(tmp_path, home)
    inner = "%s--unschedule" % SR
    cmd = "%s script -qec '%s' /dev/null%s" % (feed, inner, "" if feed else " </dev/null")
    ran = subprocess.run(cmd, shell=True, env=env, capture_output=True, text=True, timeout=200,
                         start_new_session=True)
    assert not written.exists(), ran.stdout
    assert "Removed" not in ran.stdout and "Nothing was changed" in ran.stdout


def _in_a_pty(env, argv, answer):
    """Run argv with a new pseudo-terminal as its controlling terminal; `answer(screen)` returns
    what to type once the prompt shows (or None to type nothing)."""
    import pty
    import select as sel
    pid, fd = pty.fork()
    if pid == 0:                                   # child
        try:
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)
    screen, typed, deadline = b"", False, time.monotonic() + 60
    while time.monotonic() < deadline:
        ready, _, _ = sel.select([fd], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            screen += chunk
        if not typed and b"> " in screen:
            reply = answer(screen.decode("utf-8", "replace"))
            typed = True
            if reply is not None:
                os.write(fd, reply.encode() + b"\r")
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.WEXITSTATUS(status), screen.decode("utf-8", "replace")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pty")
def test_r12_a_wrong_code_on_a_real_terminal_refuses(home, tmp_path):
    env, written = _fake_cron_env(tmp_path, home)
    rc, screen = _in_a_pty(env, [sys.executable, "-m", "stillrunning", "blocklist", "--unschedule"],
                           lambda s: "AAAA")
    assert rc == 2 and not written.exists(), screen


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pty")
def test_r12_the_right_code_on_a_real_terminal_passes_this_is_also_the_known_limit(home, tmp_path):
    """A person reads the code and types it. So can a program that drives a pseudo-terminal and
    reads the screen (this test is one): that is the documented limit of the check."""
    import re as _re
    env, written = _fake_cron_env(tmp_path, home)
    rc, screen = _in_a_pty(env, [sys.executable, "-m", "stillrunning", "blocklist", "--unschedule"],
                           lambda s: _re.search(r"press Enter: (\w{4})", s).group(1))
    assert rc == 0 and written.read_text() == "17 * * * * other job\n", screen


# ── review 13: attached option values, runner-named words, the depth limit, false asks ──

R13_ASK = [
    # F1 (a): the string attached to an option
    "script -qc'rm -rf ~/.stillrunning' /dev/null",
    "script -qc'cp /tmp/x ~/.claude/settings.json' /dev/null",
    "script -qc'echo {} > ~/.claude/settings.json' /dev/null",
    "script -qc'sed -i s/a/b/ ~/.claude/settings.json' /dev/null",
    "script -q --command='rm -rf ~/.stillrunning' /dev/null",
    "script --command='mv ~/.claude/settings.json /tmp/s' /dev/null",
    "env -S'rm -rf ~/.stillrunning'", "env --split-string='rm -rf ~/.stillrunning'",
    "su -c'stillrunning allow evil'", "su --command='stillrunning whitelist add evil'",
    "runuser -u me -c'rm -rf ~/.stillrunning'",
    "script -q --command='HOME=/tmp/x stillrunning blocklist --schedule' /dev/null",
    "script -q --command='stillrunning blocklist --refresh --force' /dev/null",
    # F1 (b): a string whose last word is a runner's name
    "bash -c 'rm -rf ~/.stillrunning; ls /bin/sh'", "bash -c 'rm -rf ~/.stillrunning #/sh'",
    "bash -c 'cp /tmp/x ~/.claude/settings.json; type /usr/bin/bash'",
    "bash -c 'stillrunning allow evil; : /bin/sh'",
    "bash -c 'stillrunning blocklist --unschedule; : /bin/sh'",
    "bash -c 'HOME=/tmp/x stillrunning blocklist --schedule; : /bin/sh'",
    # F2: the hook part of the coproc line, and attached script forms
    "coproc S { script -qfec'stillrunning blocklist --unschedule' /dev/null; }; "
    "read -t5 -u ${S[0]} l; echo ${l: -4} >&${S[1]}",
    "script -qf --command='stillrunning blocklist --unschedule' /dev/null",
    "script -qfc'stillrunning blocklist --unschedule; : /bin/sh' /tmp/t",
    # past the depth the hook follows: a string that names the protection asks
    "bash -c \"bash -c \\\"bash -c 'bash -c stillrunning\\ allow\\ evil'\\\"\"",
    "bash -c \"bash -c \\\"bash -c 'bash -c rm\\ -rf\\ ~/.stillrunning'\\\"\"",
    "sh -c \"sh -c \\\"sh -c 'sh -c stillrunning\\ blocklist\\ --unschedule'\\\"\"",
]


@pytest.mark.parametrize("command", R13_ASK)
def test_r13_attached_and_runner_named_shell_strings_ask(home, command):
    """IMPORTANT (review 13 F1/F2): round 13 skipped words starting with `-` and words
    whose basename is a runner; these deleted the state or rewrote settings unasked."""
    assert ch.touches_protection(command, cwd=str(home)), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", [
    # review 13 §6: round 13's false asks (a `$` anywhere in a shell string)
    "bash -c 'stillrunning scan .; echo $?'", "ssh host 'stillrunning scan . && echo done: $?'",
    "bash -lc 'stillrunning cve --list; echo $SHELL'", "bash -c 'stillrunning --version; ls ~/*.txt'",
    "bash -c 'ls *.py; stillrunning scan .'", "ssh host 'cd $HOME/app && stillrunning scan .'",
    "watch -n 5 'ls -la ~/.stillrunning/*.db'",
    "bash -c 'cd ~/stillrunning && python -m pytest tests -k $K'",
    "bash -c 'cd ~/stillrunning-x && make test JOBS=$(nproc)'",
    "bash -c \"awk '{print \\$1}' ~/stillrunning/x.txt\"",
    # options with no command in them
    "bash -lc ls", "script -q /tmp/log", "env -i PATH=/bin ls", "su -l me",
])
def test_r13_shell_strings_without_a_run_time_stillrunning_command_do_not_ask(home, command):
    assert not ch.touches_protection(command, cwd=str(home)), command


@pytest.mark.parametrize("command", [
    # what round 13 fixed must stay fixed
    "bash -c 'stillrunning${IFS}blocklist${IFS}--unschedule'", "bash -c '{stillrunning,blocklist,--unschedule}'",
    "bash -c 'stillrunning\tblocklist\t--unschedule'", "nohup sh -c 'stillrunning blocklist $1' _ --unschedule",
    "bash -c 'stillrunning blocklist $X'", "xargs -I{} sh -c 'stillrunning {}' < f",
    "ssh host 'stillrunning${IFS}$X'", "bash -c '$(echo stillrunning) $X evil'",
])
def test_r13_round_12_cases_still_ask(home, command):
    assert ch.touches_protection(command, cwd=str(home)), command


# ── review 14: words split between a shell string and its positional arguments; ssh joins words ──

R14_ASK = [
    # 5.1: the string refers to $0…$9 / $@ / $*, and stillrunning's words follow it
    "bash -c '$0 $1 --unschedule' stillrunning blocklist",
    "bash -c '$0 blocklist $1' stillrunning --unschedule",
    "bash -c '$0 $1 --refresh --force' stillrunning blocklist",
    "bash -c '$0 blocklist --refresh $1' stillrunning --force",
    "bash -c '$0 $1 --schedule' stillrunning blocklist",
    "bash -c 'HOME=/tmp/x $0 $1 --schedule' stillrunning blocklist",
    "bash -c '$0 $1 --uns' stillrunning blocklist",
    "bash -c '\"$0\" \"$1\" --unschedule' stillrunning blocklist",
    "sh -c '$0 $1 --unschedule' stillrunning blocklist",
    "bash -c '\"$@\" --unschedule' stillrunning blocklist",
    "bash -c '${0} ${1} --unschedule' stillrunning blocklist",
    "nohup bash -c '$0 $1 --unschedule' stillrunning blocklist",
    "timeout 5 bash -c '$0 $1 --unschedule' stillrunning blocklist",
    "coproc S { bash -c 'script -qfec \"$0 $1 --unschedule\" /dev/null' stillrunning blocklist; }; "
    "read -t5 -u ${S[0]} l; echo ${l: -4} >&${S[1]}",
    # §6, same mechanism, switches that exist on base
    "bash -c '$0 $1 add evil' stillrunning whitelist", "bash -c '$0 whitelist $1 evil' stillrunning add",
    "bash -c '$0 -m $1 allow evil' python3 stillrunning", "bash -c 'rm -rf $0/$1' ~ .stillrunning",
    # 5.2: ssh joins the words after the host into one remote line
    "ssh host stillrunning 'blocklist${IFS}--unschedule'", "ssh host stillrunning 'blocklist --uns{c,c}hedule'",
    "ssh host stillrunning '$X' --unschedule", "ssh host stillrunning 'whitelist${IFS}add${IFS}evil'",
    "ssh host stillrunning '$(echo allow)' evil", "ssh -p 22 -o BatchMode=yes host stillrunning '$X' --unschedule",
    "ssh localhost stillrunning blocklist '--unschedule'",
]


@pytest.mark.parametrize("command", R14_ASK)
def test_r14_positional_and_joined_words_ask(home, command):
    """IMPORTANT (review 14 5.1/5.2): round 14 judged each word of a shell-text command on its own,
    losing $0/$1 binding and ssh's joining; `HOME=/tmp/x $0 $1 --schedule` wrote a dead line."""
    assert ch.touches_protection(command, cwd=str(home)), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", [
    # round 14's removed false asks stay removed
    "bash -c 'stillrunning scan .; echo $?'", "ssh host 'cd $HOME/app && stillrunning scan .'",
    "bash -c 'echo $1' _ hello", "ssh host uptime", "ssh host 'ls -la'", "ssh -p 2222 host df -h",
    "bash -c 'stillrunning --version'", "ssh host stillrunning scan .",
])
def test_r14_ordinary_shell_strings_still_do_not_ask(home, command):
    assert not ch.touches_protection(command, cwd=str(home)), command


def test_r14_a_long_option_cluster_is_judged_quickly(home):
    import time as _time
    command = "bash -c x -" + "a" * 4000 + ","
    started = _time.monotonic()
    ch.touches_protection(command, cwd=str(home))
    assert _time.monotonic() - started < 5


# ── review 15: the cluster cut at 12 letters lost values attached after a long cluster ──

_PAYLOADS = ["stillrunning allow evil", "stillrunning blocklist --unschedule", "stillrunning blocklist --schedule",
             "stillrunning blocklist --refresh --force", "stillrunning whitelist add evil",
             "stillrunning --trust evil", "pip uninstall -y stillrunning"]


@pytest.mark.parametrize("payload", _PAYLOADS)
@pytest.mark.parametrize("cluster", ["-qqqqqqqqqqqc", "-qqqqqqqqqqqqqqqc", "-" + "q" * 30 + "c", "-qfqfqfqfqfqfqfc"])
def test_r15_a_value_after_a_long_option_cluster_is_judged(home, cluster, payload):
    """IMPORTANT (review 15): getopt takes `-qqqqqqqqqqqqqqqc'…'`; round 15 cut only at 12 letters."""
    for command in ("script %s'%s' /dev/null" % (cluster, payload),
                    "env -%sS'%s'" % ("i" * (len(cluster) - 2), payload),
                    "su -%sc'%s'" % ("l" * (len(cluster) - 2), payload)):
        assert ch.touches_protection(command, cwd=str(home)), command


def test_r15_a_long_cluster_with_a_symbol_is_still_quick(home):
    import time as _time
    command = "bash -c x -" + "a" * 16000 + "c'stillrunning allow evil'"
    started = _time.monotonic()
    assert ch.touches_protection(command, cwd=str(home))
    assert _time.monotonic() - started < 5
