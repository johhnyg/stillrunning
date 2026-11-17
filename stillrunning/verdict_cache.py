"""Local verdict cache for the Claude Code hook.

When the hook has positively verified an exact package release — the
blocklist lookup completed and answered "no match", and the known-
vulnerability check completed and held nothing — it can remember that in
`~/.stillrunning/verdicts.db` (SQLite, owner-only). The record is keyed to
ecosystem + normalised name + EXACT version + artifact hash.

A later install of the SAME ecosystem + name + version + hash, whose live
check could not complete (server unreachable, free allowance used up, a
timeout, OSV.dev unreachable), is then answered from that record instead of
being put to the user. Nothing else is ever turned into a pass:

- the record is only consulted after the live checks ran; any answer they
  gave that is not "could not check" wins, and a blocklist hit or a held
  vulnerability deletes the record;
- a different version or a different hash is not covered;
- a package without a known hash is not covered at all (nothing stored,
  nothing served). Today the only hash the hook can know without fetching
  anything is a `--hash=sha256:…` pin on a requirements-file line, which pip
  (and uv) enforce at install time (read by `claude_hook._requirement_hashes`);
- records expire (24 h by default, `STILLRUNNING_CACHE_TTL_HOURS`, at most
  7 days); an expired record never passes;
- `STILLRUNNING_CACHE=0` (or false / off / no) switches it off: no read, no write;
- an unreadable or corrupt database is treated as empty, with a warning.

This module makes no network calls. It reads and writes one local file.
The decision logic that uses it lives in `claude_hook.decide`.
"""
import os
import re
import stat

SWITCH_ENV = "STILLRUNNING_CACHE"
TTL_ENV = "STILLRUNNING_CACHE_TTL_HOURS"
DEFAULT_TTL_HOURS = 24.0
MAX_TTL_HOURS = 7 * 24.0
DB_NAME = "verdicts.db"
SCHEMA_VERSION = 1
FUTURE_SLACK_S = 120

# Live outcomes that mean "the check could not complete" — the only ones the
# cache may answer for. Anything else (an answer, even one not understood) is
# left exactly as it was.
BLOCKLIST_COULD_NOT = frozenset({"offline", "quota", "timeout", "server"})
CVE_COULD_NOT = frozenset({"offline", "timeout", "http", "budget", "error"})
# Vulnerability-check outcomes that count as "completed, nothing held".
CVE_NOTHING_HELD = frozenset({"none", "noncritical"})

_COLUMNS = ("eco", "name", "version", "artifact", "verified_at", "blocklist_answer",
            "blocklist_feed_age_h", "cve_status", "cve_checked_at", "client_version")


def enabled(env=None):
    """Default ON. STILLRUNNING_CACHE=0 / false / off / no switches it off."""
    env = os.environ if env is None else env
    return str(env.get(SWITCH_ENV, "1")).strip().lower() not in ("0", "false", "off", "no")


def ttl_seconds(env=None, warn=None):
    """The verdict lifetime in seconds: STILLRUNNING_CACHE_TTL_HOURS (default
    24, capped at 7 days). Unreadable → the default; zero or less → 0 (no
    verdict is ever fresh, so nothing is served)."""
    env = os.environ if env is None else env
    raw = str(env.get(TTL_ENV, "")).strip()
    if not raw:
        return DEFAULT_TTL_HOURS * 3600
    try:
        hours = float(raw)
        if hours != hours:                      # NaN
            raise ValueError(raw)
    except ValueError:
        if warn:
            warn(f"{TTL_ENV}={raw[:20]!r} is not a number — using {int(DEFAULT_TTL_HOURS)} h")
        return DEFAULT_TTL_HOURS * 3600
    return max(0.0, min(hours, MAX_TTL_HOURS)) * 3600


def client_version():
    try:
        from stillrunning import __version__
        return str(__version__)
    except Exception:  # lint: allowed-silent(bare-script hook: read the version from the file instead)
        pass
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "__init__.py"), encoding="utf-8") as handle:
            match = re.search(r'^__version__\s*=\s*["\']([^"\']{1,40})["\']', handle.read(), re.M)
        return match.group(1) if match else "unknown"
    except OSError:
        return "unknown"


def db_path(state_dir):
    return os.path.join(state_dir, DB_NAME)


# ───────────────────────────── eligibility (pure) ─────────────────────────────
def cacheable(pkg):
    """An exact pin with a known artifact hash, nothing that shifts the
    version (range, tag, --pre, constraints), and no conflicting hash."""
    return bool(pkg.get("version") and not pkg.get("spec") and not pkg.get("uncertain")
                and pkg.get("hash") and not pkg.get("hash_conflict"))


def blocklist_could_not(outcome):
    """The live blocklist lookup did not complete — and nothing it did learn
    argues against the package (the registry did not answer "no such
    package", the server did not send an answer we failed to understand)."""
    return (isinstance(outcome, dict) and outcome.get("status") == "unverified"
            and outcome.get("why") in BLOCKLIST_COULD_NOT and not outcome.get("answered")
            and outcome.get("registry") is not False and not outcome.get("resolved_version"))


def blocklist_completed_clear(outcome):
    return (isinstance(outcome, dict) and outcome.get("status") == "ok"
            and outcome.get("registry") is not False and not outcome.get("resolved_version"))


def cve_could_not(cve):
    """The vulnerability check could not run, and it did not report that a
    version in reach has a critical / unknown-severity vulnerability."""
    return (isinstance(cve, dict) and cve.get("status") == "failed"
            and cve.get("why") in CVE_COULD_NOT and not cve.get("some"))


def cve_completed_clear(cve, version):
    return (isinstance(cve, dict) and cve.get("status") in CVE_NOTHING_HELD
            and not cve.get("resolved_version") and str(cve.get("version") or "") == str(version))


def cve_held(cve):
    return isinstance(cve, dict) and (cve.get("status") in ("critical", "unknown_severity")
                                      or bool(cve.get("some")))


def age_text(seconds):
    seconds = max(0, int(seconds))
    if seconds < 3600:
        return f"{max(1, seconds // 60)} min ago"
    if seconds < 48 * 3600:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


# ─────────────────────────────── the database ───────────────────────────────
class _Unusable(Exception):
    """The database cannot be trusted or opened: treat it as empty."""


class _Untrusted(_Unusable):
    """Another account could have written it: its contents are never used."""


class _Corrupt(_Unusable):
    """The file is ours but not a verdict database we can read."""


def _sqlite():
    try:
        import sqlite3
        return sqlite3
    except ImportError as exc:      # a Python built without sqlite: the cache is simply absent
        raise _Unusable(f"sqlite3 unavailable ({type(exc).__name__})")


def _foreign(st):
    """Writable by another account, or not ours."""
    return bool(st.st_mode & 0o022) or (hasattr(os, "getuid") and st.st_uid != os.getuid())


def _check_file(path):
    """Our own regular file, never a link, writable by us alone."""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise _Unusable("not a regular file")
    if _foreign(st):
        raise _Untrusted("writable by another account or not owned by this one")
    if st.st_nlink > 1:
        raise _Untrusted("has another name (hard link) elsewhere")
    if st.st_mode & 0o044:
        os.chmod(path, 0o600)       # readable by others only: tighten, contents still ours


def _connect(path, create):
    sqlite3 = _sqlite()
    if create and not os.path.lexists(path):
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
    _check_file(path)
    conn = sqlite3.connect(path, timeout=2.0, isolation_level=None)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if create and version == 0:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS verdicts (eco TEXT NOT NULL, name TEXT NOT NULL, "
                "version TEXT NOT NULL, artifact TEXT NOT NULL, verified_at REAL NOT NULL, "
                "blocklist_answer TEXT, blocklist_feed_age_h REAL, cve_status TEXT, "
                "cve_checked_at REAL, client_version TEXT, "
                "PRIMARY KEY (eco, name, version, artifact))")
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        elif version != SCHEMA_VERSION:
            raise _Corrupt(f"unknown schema {version}")
    except Exception:
        conn.close()
        raise
    return conn


def _usable(state_dir, warn, create, ensure_dir=None):
    """→ an open connection, or None (treated as an empty cache)."""
    path = db_path(state_dir)
    if not create and not os.path.lexists(path):
        return None
    try:
        folder = os.lstat(state_dir) if os.path.lexists(path) else None
        if folder is not None and (_foreign(folder) or not stat.S_ISDIR(folder.st_mode)):
            raise _Untrusted("its folder is writable by another account or not owned by this one")
    except _Untrusted as exc:
        _set_aside(path, exc, warn)
        if not create:
            return None
    except OSError as exc:
        warn(f"{DB_NAME} folder unreadable ({type(exc).__name__}) — treated as empty")
        return None
    try:
        if create and ensure_dir is not None:
            ensure_dir()
        return _connect(path, create)
    except _Untrusted as exc:
        _set_aside(path, exc, warn)
        if create:
            try:
                return _connect(path, create)
            except Exception as again:
                warn(f"{DB_NAME} unusable ({type(again).__name__}) — not cached")
        return None
    except Exception as exc:
        if create and _is_corrupt(exc) and os.path.isfile(path) and not os.path.islink(path):
            # Set the unreadable file aside (kept for inspection) and start empty.
            try:
                os.replace(path, path + ".corrupt")
                warn(f"{DB_NAME} was unreadable ({type(exc).__name__}) — moved to "
                     f"{DB_NAME}.corrupt; starting an empty cache")
                return _connect(path, create)
            except Exception as again:
                exc = again
        warn(f"{DB_NAME} unreadable ({type(exc).__name__}) — treated as empty; "
             "nothing is answered from it")
        return None


def _set_aside(path, exc, warn):
    """A verdict file someone else could have written is never trusted —
    not now and not after its mode is fixed: it is moved aside, kept for
    inspection, and the cache starts empty."""
    warn(f"{DB_NAME} not used: {exc} — moved to {DB_NAME}.untrusted; treated as empty")
    try:
        if os.path.lexists(path):
            os.replace(path, path + ".untrusted")
    except OSError as again:
        warn(f"could not move {DB_NAME} aside ({type(again).__name__})")


def _is_corrupt(exc):
    try:
        sqlite3 = _sqlite()
    except _Unusable:
        return False
    if isinstance(exc, _Untrusted):
        return False
    return isinstance(exc, _Corrupt) or (isinstance(exc, sqlite3.DatabaseError)
                                         and not isinstance(exc, sqlite3.OperationalError))


def find(state_dir, eco, name, version, artifact, now, ttl_s, warn):
    """The unexpired verdict for exactly this eco+name+version+artifact, or
    None. An expired or future-dated one is never returned."""
    conn = _usable(state_dir, warn, create=False)
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT " + ", ".join(_COLUMNS) + " FROM verdicts WHERE eco=? AND name=? AND "
            "version=? AND artifact=?", (eco, name, str(version), artifact)).fetchone()
        if row is None:
            return None
        entry = dict(zip(_COLUMNS, row))
        verified = entry.get("verified_at")
        if not isinstance(verified, (int, float)) or isinstance(verified, bool):
            return None
        age = now - float(verified)
        if age < -FUTURE_SLACK_S or age >= ttl_s:
            return None
        if (entry["eco"], entry["name"], entry["version"], entry["artifact"]) != \
                (eco, name, str(version), artifact):
            return None
        return entry
    except Exception as exc:
        warn(f"{DB_NAME} unreadable ({type(exc).__name__}) — treated as empty; "
             "nothing is answered from it")
        return None
    finally:
        conn.close()


def store(state_dir, entry, now, warn, ensure_dir=None):
    """Save one verdict (replacing the same key) and drop records older
    than the longest allowed lifetime. Never raises."""
    conn = _usable(state_dir, warn, create=True, ensure_dir=ensure_dir)
    if conn is None:
        return False
    try:
        values = tuple(entry.get(column) for column in _COLUMNS)
        conn.execute("INSERT OR REPLACE INTO verdicts (" + ", ".join(_COLUMNS) + ") VALUES ("
                     + ", ".join("?" * len(_COLUMNS)) + ")", values)
        conn.execute("DELETE FROM verdicts WHERE verified_at < ? OR verified_at > ?",
                     (now - MAX_TTL_HOURS * 3600, now + FUTURE_SLACK_S))
        return True
    except Exception as exc:
        warn(f"could not write {DB_NAME} ({type(exc).__name__}) — verdict not cached")
        return False
    finally:
        conn.close()


def forget(state_dir, eco, name, version=None, warn=None):
    """Delete every verdict for this package (or only this version). Used
    when a live check found it listed or held a vulnerability."""
    warn = warn or (lambda message: None)
    conn = _usable(state_dir, warn, create=False)
    if conn is None:
        return 0
    try:
        if version is None:
            cursor = conn.execute("DELETE FROM verdicts WHERE eco=? AND name=?", (eco, name))
        else:
            cursor = conn.execute("DELETE FROM verdicts WHERE eco=? AND name=? AND version=?",
                                  (eco, name, str(version)))
        return cursor.rowcount or 0
    except Exception as exc:
        warn(f"could not update {DB_NAME} ({type(exc).__name__})")
        return 0
    finally:
        conn.close()


def count(state_dir, now, ttl_s, warn=None):
    """How many unexpired verdicts are on this machine; None when unknown."""
    warn = warn or (lambda message: None)
    conn = _usable(state_dir, warn, create=False)
    if conn is None:
        return 0 if not os.path.lexists(db_path(state_dir)) else None
    try:
        return int(conn.execute("SELECT COUNT(*) FROM verdicts WHERE verified_at > ? AND "
                                "verified_at <= ?", (now - ttl_s, now + FUTURE_SLACK_S)
                                ).fetchone()[0])
    except Exception as exc:
        warn(f"{DB_NAME} unreadable ({type(exc).__name__})")
        return None
    finally:
        conn.close()
