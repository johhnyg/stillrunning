"""Local verdict cache (stillrunning/verdict_cache.py + claude_hook.decide).

The cache may only turn a hold-because-could-not-check into a pass, and only
for an exact ecosystem + name + version + artifact hash that passed both
checks on this machine before and has not expired. Every test runs with a
temp HOME and with socket connections refused."""
import json
import os
import socket
import stat
import time

import pytest

from stillrunning import claude_hook as ch
from stillrunning import shield
from stillrunning import verdict_cache as vc

T0 = time.mktime((2026, 11, 17, 9, 0, 0, 0, 0, -1))
H1 = "sha256:" + "a1" * 32
H2 = "sha256:" + "b2" * 32
FORBIDDEN = __import__("re").compile(r"\b(safe|clean)\b", __import__("re").I)
CONNECTS = []


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    """No socket can connect (and every attempt is recorded); HOME is temp."""
    CONNECTS.clear()

    def refuse(*a, **k):
        CONNECTS.append(a)
        raise OSError("network disabled in tests")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for name in ("STILLRUNNING_CACHE", "STILLRUNNING_CACHE_TTL_HOURS", "STILLRUNNING_CVE_CHECK",
                 "STILLRUNNING_HOOK_STRICT", "STILLRUNNING_ALLOW_UNVERIFIED"):
        monkeypatch.delenv(name, raising=False)
    os.makedirs(tmp_path / "home", exist_ok=True)
    yield
    assert CONNECTS == [], "the verdict cache tests must make no network call"


def state():
    return os.path.join(os.path.expanduser("~"), ".stillrunning")


def db():
    return os.path.join(state(), "verdicts.db")


def req(tmp_path, *lines, name="requirements.txt"):
    (tmp_path / name).write_text("\n".join(lines) + "\n")
    return f"pip install -r {name}"


def pin(version="1.16.0", digest=H1, name="six"):
    return f"{name}=={version} --hash={digest}"


# ── stub outcomes (shapes as claude_hook.lookup / cve_lookup return them) ──
OK = {"status": "ok", "feed_age_h": 2.0, "feed_size": 236000, "registry": True}
OFFLINE = {"status": "unverified", "why": "offline", "registry": None}
QUOTA = {"status": "unverified", "why": "quota", "registry": True}
TIMEOUT = {"status": "unverified", "why": "timeout"}
SERVER = {"status": "unverified", "why": "server", "registry": None}


def blk(outcome):
    return lambda pkg: dict(outcome)


def cve_none(pkg):
    return {"status": "none", "version": pkg["version"], "vulns": []}


def cve_failed(pkg):
    return {"status": "failed", "why": "offline", "version": pkg["version"]}


def cve_noncritical(pkg):
    top = {"id": "GHSA-aaaa-bbbb-cccc", "severity": "HIGH", "fixed": "9.9.9"}
    return {"status": "noncritical", "version": pkg["version"], "vulns": [top], "top": top}


def cve_critical(pkg):
    top = {"id": "GHSA-cccc-dddd-eeee", "severity": "CRITICAL", "fixed": "9.9.9"}
    return {"status": "critical", "version": pkg["version"], "vulns": [top], "top": top}


def cve_unknown(pkg):
    top = {"id": "GHSA-eeee-ffff-gggg", "severity": None, "fixed": None}
    return {"status": "unknown_severity", "version": pkg["version"], "vulns": [top], "top": top}


def run(tmp_path, command, lookup=OK, cve=cve_none, now=T0, **kw):
    return ch.decide(command, cwd=str(tmp_path), lookup_fn=blk(lookup) if isinstance(lookup, dict)
                     else lookup, cve_fn=cve, now=now, **kw)


def verify(tmp_path, *lines, now=T0, cve=cve_none):
    command = req(tmp_path, *(lines or (pin(),)))
    first = run(tmp_path, command, OK, cve, now)
    assert first["action"] == "allow"
    return command


def rows():
    if not os.path.exists(db()):
        return []
    import sqlite3
    with sqlite3.connect(db()) as conn:
        return conn.execute("SELECT eco, name, version, artifact FROM verdicts").fetchall()


# ───────────────────────────── the pass ─────────────────────────────
def test_same_release_and_hash_passes_when_the_live_check_cannot_complete(tmp_path):
    command = verify(tmp_path)
    assert rows() == [("pip", "six", "1.16.0", H1)]
    later = T0 + 3 * 3600
    out = run(tmp_path, command, OFFLINE, cve_failed, later)
    assert out["action"] == "allow"
    assert out["stats"]["ok"] == 1 and out["stats"]["unverified"] == 0
    line = out["lines"][0]
    assert ("✓ six 1.16.0 (pip) — no known threat (verified on this machine 3h ago; "
            "not re-checked now)") in line
    record = out["records"][0]
    assert record["verdict"] == "no_known_threat"
    checks = {e["check"]: e for e in record["evidence"]}
    assert checks["blocklist"]["status"] == "not_checked"           # the truth about now
    assert "Local verdict cache" in checks["local_cache"]["text"]
    assert not any(FORBIDDEN.search(e["text"]) for e in record["evidence"])
    assert not FORBIDDEN.search(line)


@pytest.mark.parametrize("outcome", [OFFLINE, QUOTA, TIMEOUT, SERVER])
def test_every_could_not_check_reason_is_covered(tmp_path, outcome):
    command = verify(tmp_path)
    assert run(tmp_path, command, outcome, cve_none, T0 + 60)["action"] == "allow"


def test_cve_feed_unreachable_alone_is_covered(tmp_path):
    command = verify(tmp_path)
    out = run(tmp_path, command, OK, cve_failed, T0 + 7200)
    assert out["action"] == "allow"
    assert "vulnerability check from this machine 2h ago; not re-run now" in out["lines"][0]
    assert not any("could not run" in line for line in out["lines"])


def test_without_the_cache_the_same_sequence_holds(tmp_path, monkeypatch):
    monkeypatch.setenv("STILLRUNNING_CACHE", "0")
    command = verify(tmp_path)
    out = run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    assert out["action"] == "ask" and out["stats"]["unverified"] >= 1


def test_a_lookup_crash_and_the_real_network_path_are_covered(tmp_path):
    command = verify(tmp_path)

    def crash(pkg):
        raise RuntimeError("boom")
    assert run(tmp_path, command, crash, cve_failed, T0 + 60)["action"] == "allow"


def test_real_lookup_with_the_network_refused(tmp_path, monkeypatch):
    """No stubs: the real lookup and OSV check fail on the refused socket;
    the cached verdict answers and nothing reached the network."""
    command = verify(tmp_path)
    out = ch.decide(command, cwd=str(tmp_path), now=T0 + 60, deadline=5)
    CONNECTS.clear()          # the live checks tried (and were refused) — not the cache
    assert out["action"] == "allow"
    assert "verified on this machine" in out["lines"][0]


# ───────────────────────── what is not covered ─────────────────────────
def test_a_new_version_gets_normal_review(tmp_path):
    verify(tmp_path)
    command = req(tmp_path, pin("1.17.0"))
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_a_new_hash_is_unknown_and_holds(tmp_path):
    verify(tmp_path)
    command = req(tmp_path, pin(digest=H2))
    out = run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    assert out["action"] == "ask"
    # two hashes where one was verified: not the same artifact set either
    command = req(tmp_path, f"six==1.16.0 --hash={H1} --hash={H2}")
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_no_hash_means_no_store_and_no_serve(tmp_path):
    command = req(tmp_path, "six==1.16.0")
    assert run(tmp_path, command, OK, cve_none)["action"] == "allow"
    assert rows() == []
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"
    # a plain command-line pin has no hash either
    out = ch.decide("pip install six==1.16.0", cwd=str(tmp_path), lookup_fn=blk(OK),
                    cve_fn=cve_none, now=T0)
    assert out["action"] == "allow" and rows() == []
    out = ch.decide("npm install left-pad@1.3.0", cwd=str(tmp_path), lookup_fn=blk(OK),
                    cve_fn=cve_none, now=T0)
    assert out["action"] == "allow" and rows() == []


def test_never_extrapolates_from_a_name(tmp_path):
    verify(tmp_path)
    command = req(tmp_path, pin(name="sixx"))
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_expired_verdict_is_reviewed_again(tmp_path, monkeypatch):
    command = verify(tmp_path)
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 23.9 * 3600)["action"] == "allow"
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 24 * 3600)["action"] == "ask"
    monkeypatch.setenv("STILLRUNNING_CACHE_TTL_HOURS", "1")
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 3601)["action"] == "ask"
    monkeypatch.setenv("STILLRUNNING_CACHE_TTL_HOURS", "100000")      # capped at 7 days
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 6 * 86400)["action"] == "allow"
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 7 * 86400)["action"] == "ask"
    monkeypatch.setenv("STILLRUNNING_CACHE_TTL_HOURS", "0")
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 1)["action"] == "ask"


def test_expired_verdict_is_refreshed_by_a_completed_check(tmp_path):
    command = verify(tmp_path)
    assert run(tmp_path, command, OK, cve_none, T0 + 30 * 3600)["action"] == "allow"
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 31 * 3600)["action"] == "allow"


def test_future_dated_verdict_never_passes(tmp_path):
    command = verify(tmp_path, now=T0 + 86400)
    assert run(tmp_path, command, OFFLINE, cve_failed, T0)["action"] == "ask"


def test_ttl_parsing():
    assert vc.ttl_seconds({}) == 24 * 3600
    assert vc.ttl_seconds({"STILLRUNNING_CACHE_TTL_HOURS": "nonsense"}) == 24 * 3600
    assert vc.ttl_seconds({"STILLRUNNING_CACHE_TTL_HOURS": "nan"}) == 24 * 3600
    assert vc.ttl_seconds({"STILLRUNNING_CACHE_TTL_HOURS": "-5"}) == 0
    assert vc.ttl_seconds({"STILLRUNNING_CACHE_TTL_HOURS": "999"}) == 7 * 24 * 3600


# ─────────────────────────── blocklist wins ───────────────────────────
def test_local_shipped_list_wins(tmp_path):
    command = verify(tmp_path)
    with open(os.path.join(state(), "known_bad_packages.json"), "w") as handle:
        json.dump({"pip": {"six": {}}}, handle)
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_hardcoded_bad_name_is_never_served(tmp_path):
    os.makedirs(state(), mode=0o700)
    vc.store(state(), {"eco": "pip", "name": "fluxhttp", "version": "1.0.0", "artifact": H1,
                       "verified_at": T0}, T0, ch._warn)
    command = req(tmp_path, pin("1.0.0", name="fluxhttp"))
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


@pytest.mark.parametrize("answer, action", [
    ({"status": "blocked", "advisory": "MAL-2026-1", "registry": True}, "deny"),
    ({"status": "suspicious", "registry": True}, "deny"),
    ({"status": "not_found", "registry": False}, "ask"),
    ({"status": "unverified", "why": "version_range", "affected": ["1.16.0"]}, "ask"),
    ({"status": "override_blocked", "advisory": None}, "ask"),
])
def test_a_live_answer_wins_and_deletes_the_verdict(tmp_path, answer, action):
    command = verify(tmp_path)
    assert rows()
    out = run(tmp_path, command, answer, cve_none, T0 + 60)
    assert out["action"] == action
    assert rows() == []
    # and with the verdict gone, a later failed check holds
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 120)["action"] == "ask"


def test_blocked_as_an_unread_word_also_deletes(tmp_path):
    verify(tmp_path)
    out = ch.decide("uv add --package six requests", cwd=str(tmp_path),
                    lookup_fn=blk(OFFLINE), cve_fn=cve_failed, now=T0 + 60,
                    shadow_fn=lambda pkg: {"status": "blocked", "advisory": None})
    assert out["action"] == "deny"
    assert rows() == []


def test_registry_says_no_such_package_while_lookup_is_down(tmp_path):
    command = verify(tmp_path)
    gone = {"status": "unverified", "why": "offline", "registry": False}
    assert run(tmp_path, command, gone, cve_failed, T0 + 60)["action"] == "ask"


def test_an_answer_that_was_not_understood_is_not_covered(tmp_path):
    command = verify(tmp_path)
    odd = {"status": "unverified", "why": "server", "answered": True, "registry": True}
    assert run(tmp_path, command, odd, cve_failed, T0 + 60)["action"] == "ask"
    stale = {"status": "unverified", "why": "stale", "registry": True}
    assert run(tmp_path, command, stale, cve_failed, T0 + 60)["action"] == "ask"


def test_api_marks_an_unmapped_200_answer(monkeypatch):
    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return json.dumps(self.body).encode()
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: Response({"verdict": "QUARANTINED"}))
    out = ch._api_lookup("pip", "six", "1.16.0", None, 1)
    assert out["status"] == "unverified" and out["answered"] is True
    assert not vc.blocklist_could_not(dict(out, registry=True))


# ───────────────────────────── CVE wins ─────────────────────────────
@pytest.mark.parametrize("cve", [cve_critical, cve_unknown])
def test_a_live_cve_hold_is_never_overridden(tmp_path, cve):
    command = verify(tmp_path)
    out = run(tmp_path, command, OFFLINE, cve, T0 + 60)
    assert out["action"] == "ask" and out["protect"] is True
    assert rows() == []                      # that version's verdict is gone


def test_cve_in_reach_for_a_failed_check_is_never_overridden(tmp_path):
    command = verify(tmp_path)

    def some(pkg):
        return {"status": "failed", "why": "version", "some": {"id": "GHSA-aaaa-bbbb-cccc",
                                                               "severity": "CRITICAL"}}
    assert run(tmp_path, command, OFFLINE, some, T0 + 60)["action"] == "ask"


@pytest.mark.parametrize("severity", ["CRITICAL", None])
def test_saved_cve_state_hold_is_never_overridden(tmp_path, severity):
    command = verify(tmp_path)
    doc = {"schema": 2, "projects": {"/p": {"feed_updated_at": T0 - 30 * 86400, "results": {
        "pip:six@1.16.0": [{"id": "GHSA-hhhh-iiii-jjjj", "severity": severity, "fixed": None}]}}}}
    with open(os.path.join(state(), "cve_state.json"), "w") as handle:
        json.dump(doc, handle)
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_unreadable_cve_state_holds(tmp_path):
    command = verify(tmp_path)
    with open(os.path.join(state(), "cve_state.json"), "w") as handle:
        handle.write("{not json")
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_noncritical_is_stored_and_a_later_critical_still_holds(tmp_path):
    command = verify(tmp_path, cve=cve_noncritical)
    assert rows()
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "allow"
    assert run(tmp_path, command, OK, cve_critical, T0 + 120)["action"] == "ask"
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 180)["action"] == "ask"


def test_nothing_is_stored_unless_both_checks_completed(tmp_path, monkeypatch):
    command = req(tmp_path, pin())
    run(tmp_path, command, OK, cve_failed)
    run(tmp_path, command, OFFLINE, cve_none)
    run(tmp_path, command, QUOTA, cve_none)
    run(tmp_path, command, OK, cve_critical)
    run(tmp_path, command, OK, cve_unknown)
    assert rows() == []
    monkeypatch.setenv("STILLRUNNING_CVE_CHECK", "0")          # CVE check off: not completed
    run(tmp_path, command, OK, cve_none)
    assert rows() == []


# ──────────────── version-shifting and non-package holds ────────────────
@pytest.mark.parametrize("lines, extra", [
    (("--pre", pin()), ""),
    ((f"six>=1.16 --hash={H1}",), ""),
    ((f"six~=1.16.0 --hash={H1}",), ""),
    ((pin(),), " -c constraints.txt"),
    ((pin(),), " --pre"),
])
def test_range_tag_pre_and_constraints_are_never_served(tmp_path, lines, extra):
    verify(tmp_path)
    (tmp_path / "constraints.txt").write_text("six==1.16.0\n")
    command = req(tmp_path, *lines, name="other-requirements.txt") + extra
    out = run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    assert out["action"] == "ask"
    assert not any("verified on this machine" in line for line in out["lines"])


@pytest.mark.parametrize("variant", [
    lambda tmp: req(tmp, "--index-url https://mirror.example/simple", pin(), name="r2.txt"),
    lambda tmp: req(tmp, pin(), "git+https://example.com/x.git", name="r2.txt"),
    lambda tmp: req(tmp, pin(), name="r2.txt") + " ./missing-0.1-py3-none-any.whl",
    lambda tmp: req(tmp, pin(), name="r2.txt") + " && rm -rf ~/.stillrunning",
    lambda tmp: req(tmp, pin(), name="r2.txt") + " && $PIP install x",
])
def test_non_package_holds_are_never_served(tmp_path, variant):
    verify(tmp_path)
    command = variant(tmp_path)
    out = run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    assert out["action"] == "ask"
    assert not any("verified on this machine" in line for line in out["lines"])


def test_unreadable_requirements_file_holds(tmp_path):
    verify(tmp_path)
    out = run(tmp_path, "pip install -r nowhere.txt", OFFLINE, cve_failed, T0 + 60)
    assert out["action"] == "ask"


# ─────────────────────────── the switch ───────────────────────────
@pytest.mark.parametrize("value", ["0", "false", "off", "OFF", "no"])
def test_switch_off_means_no_read_and_no_write(tmp_path, monkeypatch, value):
    command = verify(tmp_path)                    # stored while on
    before, path = rows(), db()
    with open(path, "rb") as handle:
        raw = handle.read()
    monkeypatch.setenv("STILLRUNNING_CACHE", value)

    def touched(*a, **k):
        raise AssertionError("the cache was opened while switched off")
    monkeypatch.setattr(vc, "_connect", touched)
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"
    assert run(tmp_path, req(tmp_path, pin("2.0.0")), OK, cve_none, T0 + 60)["action"] == "allow"
    blocked = {"status": "blocked", "advisory": None, "registry": True}
    assert run(tmp_path, command, blocked, cve_none, T0 + 60)["action"] == "deny"
    with open(path, "rb") as handle:
        assert handle.read() == raw               # not one byte written
    assert before and not os.path.exists(path + "-journal")


def test_switch_off_from_the_start_creates_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("STILLRUNNING_CACHE", "0")
    verify(tmp_path)
    assert not os.path.exists(db())


def test_the_switch_cannot_be_flipped_inside_a_command(tmp_path):
    verify(tmp_path)
    command = "STILLRUNNING_CACHE=1 " + req(tmp_path, pin(), name="r3.txt")
    out = run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    assert out["action"] == "ask"         # a STILLRUNNING_* switch is a protection change


# ───────────────────────── corrupt / odd files ─────────────────────────
def test_corrupt_db_is_empty_and_holds(tmp_path, capsys):
    command = req(tmp_path, pin())
    os.makedirs(state(), mode=0o700)
    with open(db(), "wb") as handle:
        handle.write(b"this is not sqlite" * 100)
    os.chmod(db(), 0o600)
    out = run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    assert out["action"] == "ask"
    assert "verdicts.db unreadable" in capsys.readouterr().err


def test_corrupt_db_is_set_aside_on_the_next_store(tmp_path):
    os.makedirs(state(), mode=0o700)
    with open(db(), "wb") as handle:
        handle.write(b"garbage" * 200)
    verify(tmp_path)
    assert os.path.exists(db() + ".corrupt") and rows() == [("pip", "six", "1.16.0", H1)]


def test_unknown_schema_is_treated_as_empty(tmp_path):
    command = verify(tmp_path)
    import sqlite3
    with sqlite3.connect(db()) as conn:
        conn.execute("PRAGMA user_version = 99")
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_a_symlinked_db_is_not_followed(tmp_path):
    command = verify(tmp_path)
    real = tmp_path / "elsewhere.db"
    os.replace(db(), real)
    os.symlink(real, db())
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_garbage_row_values_never_pass(tmp_path):
    command = verify(tmp_path)
    import sqlite3
    with sqlite3.connect(db()) as conn:
        conn.execute("UPDATE verdicts SET verified_at = 'yesterday'")
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_db_and_directory_are_owner_only(tmp_path):
    verify(tmp_path)
    assert stat.S_IMODE(os.stat(state()).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(db()).st_mode) == 0o600


def test_a_loosened_db_mode_is_tightened(tmp_path):
    command = verify(tmp_path)
    os.chmod(db(), 0o644)
    run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    assert stat.S_IMODE(os.stat(db()).st_mode) == 0o600


# ───────────────────────────── the hash ─────────────────────────────
def test_requirement_hashes():
    assert ch._requirement_hashes(f"six==1.16.0 --hash={H1}") == H1
    assert ch._requirement_hashes(f"six==1.16.0 --hash {H1.upper().replace('SHA256', 'sha256')}") == H1
    assert ch._requirement_hashes(f"six==1.16.0 --hash={H2} --hash={H1}") == f"{H1},{H2}"
    assert ch._requirement_hashes("six==1.16.0 --hash=sha384:" + "c" * 96).startswith("sha384:")
    assert ch._requirement_hashes("six==1.16.0") is None
    assert ch._requirement_hashes("six==1.16.0 --hash=sha256:abc") is None          # too short
    assert ch._requirement_hashes("six==1.16.0 --hash=md5:" + "d" * 32) is None
    assert ch._requirement_hashes(f"six==1.16.0 --hash={H1} --hash=sha1:" + "e" * 40) is None


def test_the_hash_reaches_the_parsed_package(tmp_path):
    (tmp_path / "r.txt").write_text(f"six==1.16.0 \\\n    --hash={H1}\nidna==3.7\n")
    parsed = ch.parse_install_commands("pip install -r r.txt", cwd=str(tmp_path))
    by_name = {p["name"]: p for p in parsed["packages"]}
    assert by_name["six"]["hash"] == H1 and "hash" not in by_name["idna"]


def test_the_same_pin_with_two_different_hashes_has_no_hash(tmp_path):
    (tmp_path / "r.txt").write_text(f"six==1.16.0 --hash={H1}\nsix==1.16.0 --hash={H2}\n")
    parsed = ch.parse_install_commands("pip install -r r.txt", cwd=str(tmp_path))
    six = [p for p in parsed["packages"] if p["name"] == "six"]
    assert len(six) == 1 and "hash" not in six[0] and six[0]["hash_conflict"]
    assert not vc.cacheable(six[0])


def test_a_local_wheel_is_not_looked_up_and_not_cached(tmp_path):
    wheel = tmp_path / "six-1.16.0-py3-none-any.whl"
    wheel.write_bytes(b"PK\x03\x04")
    out = ch.decide(f"pip install {wheel}", cwd=str(tmp_path), lookup_fn=blk(OK),
                    cve_fn=cve_none, now=T0)
    assert out["action"] == "allow" and rows() == []


# ─────────────────────── dashboards and counts ───────────────────────
def test_shield_counts_cached_verdicts_and_keeps_its_json_keys(tmp_path):
    command = verify(tmp_path)
    out = run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    ch.record_stats(out["stats"], now=T0 + 60)
    ch.log_decisions(out["records"])
    data = shield.collect(now=T0 + 60)
    assert set(data) == {"schema", "generated_at", "has_data", "hook", "today", "week",
                         "blocklist", "decisions", "glossary"}
    assert data["today"]["needs_approval"] == 0 and data["decisions"][0]["verdict"] == "no_known_threat"
    text = shield.render(data)
    assert "local verdict cache: 1 verdict" in text
    assert not FORBIDDEN.search(text.replace("unsafe", ""))
    assert ch.cache_count(now=T0 + 60) == 1
    assert ch.cache_count(now=T0 + 25 * 3600) == 0


def test_no_network_anywhere_in_the_module(tmp_path):
    """Store, find, forget and count with sockets refused (fixture asserts)."""
    os.makedirs(state(), mode=0o700)
    assert vc.store(state(), {"eco": "pip", "name": "six", "version": "1.16.0", "artifact": H1,
                              "verified_at": T0}, T0, ch._warn)
    assert vc.find(state(), "pip", "six", "1.16.0", H1, T0 + 1, 3600, ch._warn)
    assert vc.count(state(), T0 + 1, 3600) == 1
    assert vc.forget(state(), "pip", "six") == 1
    assert vc.find(state(), "pip", "six", "1.16.0", H1, T0 + 1, 3600, ch._warn) is None


# ───────────── review round 1: hashes the installer does not enforce ─────────────
@pytest.mark.parametrize("command", [
    "uv pip install --no-verify-hashes -r requirements.txt",
    "uv pip install --no-require-hashes -r requirements.txt",
    "UV_NO_VERIFY_HASHES=1 uv pip install -r requirements.txt",
    "export UV_NO_VERIFY_HASHES=1; uv pip install -r requirements.txt",
    "UV_NO_VERIFY_HASHES=1; uv pip install -r requirements.txt",
    "uv add -r requirements.txt",
    "pip download -r requirements.txt",
    "pip wheel -r requirements.txt",
    "pipenv install -r requirements.txt",
    "poetry add six==1.16.0",
    "pipx install six==1.16.0",
    "uvx six==1.16.0",
    "easy_install six==1.16.0",
])
def test_unenforced_hash_is_never_stored_or_served(tmp_path, command):
    req(tmp_path, pin())
    os.makedirs(state(), mode=0o700)
    vc.store(state(), {"eco": "pip", "name": "six", "version": "1.16.0", "artifact": H1,
                       "verified_at": T0}, T0, ch._warn)
    parsed = ch.parse_install_commands(command, cwd=str(tmp_path))
    assert all("hash" not in p for p in parsed["packages"])
    out = run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    assert not any("verified on this machine" in line for line in out["lines"])


def test_uv_no_verify_hashes_in_claude_codes_environment(tmp_path):
    req(tmp_path, pin())
    parsed = ch.parse_install_commands("uv pip install -r requirements.txt", cwd=str(tmp_path),
                                       env={"UV_NO_VERIFY_HASHES": "1"})
    assert "hash" not in parsed["packages"][0]


@pytest.mark.parametrize("command", [
    "pip install -r requirements.txt",
    "pip3 install -r requirements.txt",
    "python3 -m pip install -r requirements.txt",
    "uv pip install -r requirements.txt",
    "uv pip sync requirements.txt",
])
def test_enforcing_installers_keep_the_hash(tmp_path, command):
    req(tmp_path, pin())
    parsed = ch.parse_install_commands(command, cwd=str(tmp_path), env={})
    assert parsed["packages"][0]["hash"] == H1


# ───────────── review round 1: a database another account could write ─────────────
@pytest.mark.parametrize("dir_mode, db_mode", [(0o777, 0o666), (0o700, 0o666), (0o700, 0o620),
                                               (0o777, 0o600), (0o770, 0o600)])
def test_db_writable_by_others_is_never_served(tmp_path, dir_mode, db_mode, capsys):
    command = verify(tmp_path)
    os.chmod(db(), db_mode)
    os.chmod(state(), dir_mode)
    out = run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)
    assert out["action"] == "ask"
    assert "not used" in capsys.readouterr().err
    # moved aside, so fixing the modes does not make the planted file trusted
    os.chmod(state(), 0o700)
    assert not os.path.exists(db()) and os.path.exists(db() + ".untrusted")
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 120)["action"] == "ask"


def test_db_owned_by_another_account_is_never_served(tmp_path, monkeypatch):
    command = verify(tmp_path)
    real = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real + 1)
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


def test_db_readable_by_others_is_tightened_and_still_ours(tmp_path):
    command = verify(tmp_path)
    os.chmod(db(), 0o644)
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "allow"
    assert stat.S_IMODE(os.stat(db()).st_mode) == 0o600


# ───────────── review round 1: conditions ─────────────
@pytest.mark.parametrize("content", ["{not json", "[]", '{"pip": 5}'])
def test_unreadable_local_blocklist_means_no_cached_pass(tmp_path, content):
    command = verify(tmp_path)
    with open(os.path.join(state(), "known_bad_packages.json"), "w") as handle:
        handle.write(content)
    assert run(tmp_path, command, OFFLINE, cve_failed, T0 + 60)["action"] == "ask"


@pytest.mark.parametrize("line", [f"six==1.16.0\t# --hash={H1}", f"six==1.16.0\t#--hash={H1}",
                                  f"six==1.16.0  # --hash={H1}"])
def test_a_hash_inside_a_comment_is_no_hash(tmp_path, line):
    req(tmp_path, line)
    parsed = ch.parse_install_commands("pip install -r requirements.txt", cwd=str(tmp_path))
    assert parsed["packages"][0]["name"] == "six" and "hash" not in parsed["packages"][0]


def test_nothing_is_stored_from_a_denied_command(tmp_path):
    command = req(tmp_path, pin(), "evil==1.0.0")

    def lookup(pkg):
        if pkg["name"] == "evil":
            return {"status": "blocked", "advisory": "MAL-2026-9", "registry": True}
        return dict(OK)
    out = run(tmp_path, command, lookup, cve_none)
    assert out["action"] == "deny"
    six = next(r for r in out["records"] if r["name"] == "six")
    assert six["verdict"] == "no_known_threat"          # its own lookup, reported as such
    assert rows() == []


def test_each_package_counts_once_as_could_not_check(tmp_path):
    out = ch.decide("pip install six==1.16.0 idna==3.7", cwd=str(tmp_path),
                    lookup_fn=blk(OFFLINE), cve_fn=cve_failed, now=T0)
    assert out["stats"]["checked"] == 2 and out["stats"]["unverified"] == 2
    ch.record_stats(out["stats"], now=T0)
    assert shield.collect(now=T0)["today"]["needs_approval"] == 2
    from stillrunning import statusline
    assert "2 couldn't check" in statusline.render(now=T0, color=False, width=200)
