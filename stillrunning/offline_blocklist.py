"""The offline blocklist: known-malicious packages the Claude Code hook can
block without any network call.

    stillrunning blocklist --refresh      build it now (OSV.dev malicious-package data)
    stillrunning blocklist --status       what is installed, verified or not
    stillrunning blocklist --schedule     one crontab line: --refresh daily, low priority
    stillrunning blocklist --unschedule   remove that line

The hook never builds or fetches this; it opens the database read-only and
does one indexed lookup. Files, all in ~/.stillrunning:

    blocklist-<sha256[:16]>.sqlite   entries(eco, name, versions, advisory), names
                                     normalized as the hook does (PEP 503 for pip)
    blocklist.manifest.json          the only pointer to the database, with its
                                     size and SHA-256, and an HMAC over all of it
    blocklist.key                    the per-machine HMAC key (0600)

The HMAC catches corruption, half-written files and tampering by anything that
cannot read the key. Code running as the same user can read the key and
re-sign, so this is a MAC, not a signature from a third party.
"""
import json
import os
import secrets
import sqlite3
import sys
import tempfile
import time
import urllib.request
import zipfile

from . import claude_hook

SOURCES = {
    "pip": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    "npm": "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
}
MAX_ZIP_BYTES = 1024 ** 3            # PyPI ~40 MB, npm ~220 MB today
MAX_MEMBER_BYTES = 5 * 1024 ** 2     # one MAL-*.json advisory is a few KB (osv_bulk uses the same cap)
MAX_VERSIONS = 200
BATCH = 5000
KEEP_OLD_DATABASES = 1
CRON_MARK = "# stillrunning-blocklist (added by: stillrunning blocklist --schedule)"


def _state():
    folder = claude_hook._state_dir()
    os.makedirs(folder, mode=0o700, exist_ok=True)
    return folder


def _low_priority():
    """Single-threaded already; also the lowest CPU priority (the cron line adds
    `ionice -c 3` where it exists)."""
    try:
        os.nice(19)
    except (AttributeError, OSError):  # lint: allowed-silent(no nice on Windows: still single-threaded)
        pass


def _key(folder):
    path = os.path.join(folder, claude_hook.OFFLINE_KEY)
    try:
        with open(path, "rb") as handle:
            key = handle.read(4096).strip()
        if key:
            return key
    except FileNotFoundError:  # lint: allowed-silent(first build: a new key is made below)
        pass
    key = secrets.token_hex(32).encode("ascii")
    tmp = "%s.%d.tmp" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    os.replace(tmp, path)
    return key


def _version_specs(affected):
    """OSV `affected` → "*" (every version) or a list of specifiers. Anything
    it cannot represent exactly is widened to "*" (over-blocking is the safe side)."""
    versions = affected.get("versions") or []
    if len(versions) > MAX_VERSIONS:
        return "*"
    specs = ["==" + str(v) for v in versions]
    for rng in affected.get("ranges") or []:
        if not isinstance(rng, dict) or rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        introduced = None
        for event in rng.get("events") or []:
            if "introduced" in event:
                if introduced is not None:                 # an open interval: everything from there
                    return "*" if introduced == "0" else specs + [">=" + str(introduced)]
                introduced = str(event["introduced"])
            elif "fixed" in event or "last_affected" in event:
                end = str(event.get("fixed", event.get("last_affected")))
                op = "<" if "fixed" in event else "<="
                specs.append(op + end if introduced in (None, "0") else ">=%s,%s%s" % (introduced, op, end))
                introduced = None
        if introduced == "0":
            return "*"
        if introduced is not None:
            specs.append(">=" + introduced)
    return specs or "*"


def _download(url, dest):
    total = 0
    request = urllib.request.Request(url, headers={"User-Agent": "stillrunning-blocklist"})
    with urllib.request.urlopen(request, timeout=120) as response, open(dest, "wb") as out:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ZIP_BYTES:
                raise RuntimeError("download exceeds %d bytes" % MAX_ZIP_BYTES)
            out.write(chunk)
    return total


OSV_ECOSYSTEM = {"pip": "PyPI", "npm": "npm"}


def _ingest(conn, eco, zip_path, log=print):
    """Stream one ecosystem's zip into the staging table, one member at a time.
    A bad advisory is skipped and counted, never the end of the refresh."""
    rows, kept, withdrawn, skipped = [], 0, 0, 0
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            base = os.path.basename(info.filename)
            if not base.startswith("MAL-"):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                skipped += 1
                continue
            try:
                with archive.open(info) as handle:
                    data = json.load(handle)
                if data.get("withdrawn"):
                    withdrawn += 1
                    continue
                advisory = str(data.get("id") or base[:-5])[:64]
                for affected in data.get("affected") or []:
                    package = affected.get("package") or {}
                    name = str(package.get("name") or "").strip()
                    if not name or package.get("ecosystem", OSV_ECOSYSTEM[eco]) != OSV_ECOSYSTEM[eco]:
                        continue
                    specs = _version_specs(affected)
                    key = claude_hook.normalize(eco, name)
                    for spec in (["*"] if specs == "*" else specs):
                        rows.append((eco, key, spec, advisory))
                    kept += 1
            except (ValueError, OSError, zipfile.BadZipFile, AttributeError, TypeError, KeyError):
                skipped += 1
                continue
            if len(rows) >= BATCH:
                conn.executemany("INSERT INTO staging VALUES (?, ?, ?, ?)", rows)
                rows = []
    if rows:
        conn.executemany("INSERT INTO staging VALUES (?, ?, ?, ?)", rows)
    if skipped:
        log("%s: WARNING: %d advisories skipped (too large or malformed)" % (eco, skipped))
    return kept, withdrawn


class BuildBusy(RuntimeError):
    pass


def _lock(folder):
    """One build at a time (cron and a manual run): → an open lock file, or BuildBusy."""
    handle = open(os.path.join(folder, "blocklist.build.lock"), "a+")
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise BuildBusy("another blocklist build is running")
    return handle


def _clean_leftovers(folder, older_than_s=3600):
    """Temp files of a build that was killed (timeout, reboot): they can be ~250 MB."""
    now = time.time()
    for name in os.listdir(folder):
        if name.startswith(".blocklist-"):
            path = os.path.join(folder, name)
            try:
                if now - os.path.getmtime(path) > older_than_s:
                    os.unlink(path)
            except OSError:  # lint: allowed-silent(still in use on Windows: removed next time)
                pass


def build(folder=None, sources=None, log=print):
    """Build a new database and switch the manifest to it. → the manifest."""
    folder = folder or _state()
    lock = _lock(folder)
    try:
        _clean_leftovers(folder)
        return _build(folder, sources or SOURCES, log)
    finally:
        lock.close()


def _build(folder, sources, log):
    started = time.time()
    fd, tmp_db = tempfile.mkstemp(prefix=".blocklist-build-", suffix=".sqlite", dir=folder)
    os.close(fd)
    counts = {}
    try:
        conn = sqlite3.connect(tmp_db)
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA cache_size=-8000")              # ~8 MB page cache
        conn.execute("CREATE TABLE staging (eco TEXT, name TEXT, spec TEXT, advisory TEXT)")
        for eco, url in sources.items():
            zfd, zip_path = tempfile.mkstemp(prefix=".blocklist-%s-" % eco, suffix=".zip", dir=folder)
            os.close(zfd)
            try:
                size = _download(url, zip_path)
                kept, withdrawn = _ingest(conn, eco, zip_path, log)
                conn.commit()
                log("%s: %.1f MB downloaded, %d advisories kept, %d withdrawn skipped"
                    % (eco, size / 1048576.0, kept, withdrawn))
            finally:
                os.unlink(zip_path)
        conn.execute("CREATE TABLE entries (eco TEXT NOT NULL, name TEXT NOT NULL, versions TEXT NOT NULL,"
                     " advisory TEXT, PRIMARY KEY (eco, name)) WITHOUT ROWID")
        conn.execute("INSERT INTO entries SELECT eco, name,"
                     " CASE WHEN SUM(spec = '*') > 0 THEN '*' ELSE group_concat(spec, char(10)) END,"
                     " MIN(advisory)"
                     " FROM (SELECT eco, name, spec, MIN(advisory) AS advisory FROM staging"
                     "       GROUP BY eco, name, spec ORDER BY eco, name, spec)"
                     " GROUP BY eco, name")
        conn.execute("DROP TABLE staging")
        conn.commit()
        for eco, total in conn.execute("SELECT eco, COUNT(*) FROM entries GROUP BY eco"):
            counts[eco] = total
        if not counts:
            raise RuntimeError("no entries: refusing to replace the blocklist with an empty one")
        conn.execute("VACUUM")
        conn.close()
        with open(tmp_db, "r+b") as handle:          # Windows: fsync needs a writable handle
            import hashlib
            digest = hashlib.sha256()
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
            os.fsync(handle.fileno())
        sha = digest.hexdigest()
        name = "blocklist-%s.sqlite" % sha[:16]
        final_db = os.path.join(folder, name)
        os.replace(tmp_db, final_db)
        manifest = {"v": 1, "db": name, "sha256": sha, "size": os.path.getsize(final_db),
                    "built": int(time.time()), "counts": counts, "source": "OSV.dev MAL advisories"}
        manifest["mac"] = claude_hook.offline_manifest_mac(_key(folder), manifest)
        _write_manifest(folder, manifest)
        _prune(folder, keep=name)
        log("offline blocklist: %s (%d bytes, %s) in %.0f s"
            % (name, manifest["size"], ", ".join("%s %d" % kv for kv in sorted(counts.items())),
               time.time() - started))
        return manifest
    finally:
        if os.path.exists(tmp_db):
            os.unlink(tmp_db)


def _write_manifest(folder, manifest):
    path = os.path.join(folder, claude_hook.OFFLINE_MANIFEST)
    tmp = "%s.%d.tmp" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    for attempt in range(5):                 # Windows: the hook may hold the old file open
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.2 * (attempt + 1))


def _prune(folder, keep):
    """Remove databases no manifest points at, keeping the newest older one."""
    old = sorted((f for f in os.listdir(folder)
                  if claude_hook._OFFLINE_DB_NAME.match(f) and f != keep),
                 key=lambda f: os.path.getmtime(os.path.join(folder, f)), reverse=True)
    for name in old[KEEP_OLD_DATABASES:]:
        try:
            os.unlink(os.path.join(folder, name))
        except OSError:  # lint: allowed-silent(Windows: still open by a hook; removed on the next refresh)
            pass


def status():
    claude_hook._OFFLINE_STATE.clear()
    state, detail = claude_hook._offline_db()
    if state == "missing":
        print("No offline blocklist. Build one: stillrunning blocklist --refresh")
        return 1
    if state == "tampered":
        print("Offline blocklist FAILED its integrity check (%s). Every install is blocked until "
              "it is rebuilt: stillrunning blocklist --refresh" % detail)
        return 2
    with open(os.path.join(claude_hook._state_dir(), claude_hook.OFFLINE_MANIFEST), encoding="utf-8") as h:
        manifest = json.load(h)
    age_h = (time.time() - manifest.get("built", 0)) / 3600.0
    print("Offline blocklist verified: %s, %d bytes, %s, built %.1f h ago"
          % (manifest["db"], manifest["size"],
             ", ".join("%s %d" % kv for kv in sorted(manifest.get("counts", {}).items())), age_h))
    stale = claude_hook.offline_stale_note()
    if stale:
        print("STALE: " + stale)
        return 3
    return 0


def cron_line():
    import shlex
    folder = claude_hook._state_dir()
    lock, log = os.path.join(folder, "blocklist.lock"), os.path.join(folder, "blocklist_cron.log")
    nice = "nice -n 19 " + ("ionice -c 3 " if os.path.exists("/usr/bin/ionice") else "")
    cmd = ("%sflock -n %s timeout 1800 %s -m stillrunning blocklist --refresh >/dev/null 2>>%s"
           % (nice, shlex.quote(lock), shlex.quote(sys.executable), shlex.quote(log)))
    return "41 4 * * * %s %s" % (cmd, CRON_MARK)


def schedule(remove=False):
    from . import cve
    if os.name == "nt":
        print("Scheduling uses crontab, which Windows does not have; nothing was changed. "
              "Run `stillrunning blocklist --refresh` yourself, or add it to Task Scheduler.")
        return 1
    lines, problem = cve._read_crontab()
    if problem:
        print(problem)
        return 1
    ours = [line for line in lines if line.rstrip().endswith(CRON_MARK)]
    rest = [line for line in lines if not line.rstrip().endswith(CRON_MARK)]
    if remove:
        if not ours:
            print("No offline-blocklist refresh is scheduled; crontab unchanged.")
            return 0
        new, said = rest, "Removed the offline-blocklist refresh line from your crontab."
    else:
        want = cron_line()
        if ours == [want]:
            print("Already scheduled (daily); crontab unchanged:\n  " + want)
            return 0
        new = rest + [want]
        said = "Scheduled: stillrunning blocklist --refresh daily at 04:41, lowest priority:\n  " + want
    ran = cve._crontab(["-"], "\n".join(new) + ("\n" if new else ""))
    if ran.returncode != 0:
        print("crontab - failed; your crontab may be unchanged. Check: crontab -l")
        return 1
    print(said)
    return 0


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="stillrunning blocklist")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--schedule", action="store_true")
    parser.add_argument("--unschedule", action="store_true")
    args = parser.parse_args(argv)
    if args.schedule or args.unschedule:
        return schedule(remove=args.unschedule)
    if args.refresh:
        _low_priority()
        try:
            build()
        except Exception as exc:      # the old list (if any) stays in place and verified
            print("Offline blocklist NOT refreshed: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
            return 1
    return status()
