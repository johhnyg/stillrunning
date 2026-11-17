"""Data for the Claude Code side panel: is the protection intact, and is
anything this project names or this machine already has installed on the
threat list.

    stillrunning panel --json            protection + the last saved scan
    stillrunning panel --json --scan     run the scan first (network)

The scan asks the blocklist-only route once per package name. That route
needs no account and no token is sent. Only package names and the ecosystem
leave the machine, never versions or file contents. The server limits how
fast names can be asked, so a scan runs in short passes and remembers each
answer for twelve hours.

A package counts as "checked" only when the server answered for it. A failed
lookup is counted as not checked, never as a pass. Nothing the server says
is shown except advisory ids, version numbers and a date, each matched
against a strict pattern.
"""

import json
import os
import re
import sys
import time
from pathlib import Path

from . import claude_hook
from .apibase import api_url

SCHEMA = 1
MAX_NAMES = 600
MAX_MANIFESTS = 40
SCAN_BUDGET_S = 40.0
_SKIP_DIRS = {"node_modules", ".git", ".hg", ".venv", "venv", "env", "__pycache__", "dist",
              "build", ".tox", ".mypy_cache", ".pytest_cache", "site-packages", ".next", "target"}
_VENV_DIRS = (".venv", "venv", "env")
_EXACT = re.compile(r"^v?\d+(\.\d+)*([a-z0-9.+!-]*)$", re.I)
_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_DIST_INFO = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._]*)-(?P<version>[0-9][^-]*)\.dist-info$")
_NAME_OK = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)


def cache_path():
    return os.path.join(claude_hook._state_dir(), "panel_scan.json")


# --------------------------------------------------------------- protection

def protection():
    """Is the Claude Code hook still in place? → {state, problems, ...}.
    state: "on" | "off" | "unknown". Every problem is a plain sentence."""
    state, reason = claude_hook.verify_install()
    problems = []
    watches_edits = False
    if state == "on":
        try:
            data, _ = claude_hook._load_settings(claude_hook._settings_path())
        except (claude_hook.InstallError, OSError) as exc:
            return {"state": "unknown", "watches_edits": False,
                    "problems": [f"The Claude Code settings file could not be read ({type(exc).__name__})."]}
        for group in data.get("hooks", {}).get("PreToolUse", []):
            if not (isinstance(group, dict) and isinstance(group.get("hooks"), list)):
                continue
            if any(isinstance(h, dict) and claude_hook._is_ours(h.get("command", ""))
                   for h in group["hooks"]):
                matcher = str(group.get("matcher") or "")
                tools = set(matcher.split("|"))
                if "Bash" not in tools and matcher not in ("", "*"):
                    state = "off"
                    problems.append("The hook is registered but no longer watches commands.")
                watches_edits = matcher in ("", "*") or {"Write", "Edit"} <= tools
        if state == "on" and not watches_edits:
            problems.append("The hook does not watch file edits, so its own settings could be changed "
                            "without asking you. Fix: stillrunning --hook-claude-code")
    elif state == "off":
        problems.append("The Claude Code hook is not switched on (" + reason + "). "
                        "Fix: stillrunning --hook-claude-code")
    else:
        problems.append("Could not confirm the Claude Code hook is on (" + reason + ").")
    return {"state": "on" if state == "on" else ("off" if state == "off" else "unknown"),
            "watches_edits": watches_edits, "problems": problems}


# ------------------------------------------------------------ what to check

def find_manifests(root):
    """Dependency files in the project, at most two folders deep."""
    from .manifest import manifest_kind
    root = Path(root)
    found = []
    for folder, dirs, files in os.walk(root):
        depth = len(Path(folder).relative_to(root).parts)
        dirs[:] = [] if depth >= 2 else sorted(d for d in dirs if d not in _SKIP_DIRS
                                               and not d.startswith("."))
        for name in sorted(files):
            path = Path(folder) / name
            kind = manifest_kind(path)
            # `pip -r` reads any .txt, but a project scan only trusts the usual names
            if kind is None or (kind == "requirements" and "requirement" not in name.lower()
                                and "constraint" not in name.lower()):
                continue
            found.append(path)
            if len(found) >= MAX_MANIFESTS:
                return found
    return found


def _exact(version):
    """A version string that names one release, else None (a range or tag)."""
    text = str(version or "").strip()
    if text.startswith("==="):
        text = text[3:]
    elif text.startswith("=="):
        text = text[2:]
    text = text.strip()
    if not text or "*" in text or not _EXACT.match(text):
        return None
    return text


def project_packages(root):
    """→ (manifest rows, packages). A file that cannot be parsed is reported,
    not skipped silently."""
    from .manifest import parse_manifest_strict
    rows, packages = [], []
    for path in find_manifests(root):
        rel = str(path.relative_to(root))
        try:
            specs = parse_manifest_strict(path)
        except Exception as exc:  # a broken file must not hide the others
            claude_hook._warn(f"panel: could not read {rel} ({type(exc).__name__})")
            rows.append({"file": rel, "packages": 0, "unreadable": True})
            continue
        if not specs and path.suffix == ".json":
            # the JSON parsers answer "no packages" for a file they cannot read
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                rows.append({"file": rel, "packages": 0, "unreadable": True})
                continue
        every = list(specs or [])
        specs = [s for s in every if not (s.is_local or s.is_url or s.is_git)]
        # local paths, web addresses and git sources have no registry version
        rows.append({"file": rel, "packages": len(specs), "unreadable": False,
                     "not_registry": len(every) - len(specs)})
        for spec in specs:
            eco = "npm" if spec.ecosystem == "npm" else "pip"
            packages.append({"where": "project", "file": rel, "eco": eco,
                             "name": claude_hook.normalize(eco, spec.name),
                             "version": _exact(spec.version)})
    return rows, packages


def installed_packages(root, problems=None):
    """Python packages installed for this interpreter and in the project's
    own virtual environment. A place that could not be listed is reported
    in `problems` (a list, when given) as {"place", "why"}."""
    seen, out = set(), []
    problems = problems if problems is not None else []

    def add(name, version, place):
        name = claude_hook.normalize("pip", name)
        if name and (name, version) not in seen:
            seen.add((name, version))
            out.append({"where": "installed", "file": place, "eco": "pip",
                        "name": name, "version": _exact(version)})

    try:
        from importlib import metadata
        for dist in metadata.distributions():
            name = dist.metadata["Name"] if dist.metadata else None
            if name:
                add(name, dist.version, "this machine")
    except Exception as exc:
        claude_hook._warn(f"panel: could not list installed packages ({type(exc).__name__})")
        problems.append({"place": "this machine", "why": "could not be listed"})
    for venv in _VENV_DIRS:
        sites = sorted(Path(root, venv).glob("lib/python*/site-packages"))
        if not sites and Path(root, venv, "pyvenv.cfg").is_file():
            claude_hook._warn(f"panel: {venv} looks like a virtual environment but has no "
                              "site-packages folder to list")
            problems.append({"place": venv, "why": "could not be listed"})
        for site in sites:
            try:
                entries = os.listdir(site)
            except OSError as exc:
                claude_hook._warn(f"panel: could not read {site} ({type(exc).__name__})")
                problems.append({"place": venv, "why": "could not be read"})
                continue
            legacy = sum(1 for entry in entries if entry.endswith(".egg-info"))
            if legacy:
                problems.append({"place": venv, "why": f"{legacy} old-style (.egg-info) "
                                 "package(s) not listed"})
            for entry in entries:
                match = _DIST_INFO.match(entry)
                if match:
                    add(match.group("name"), match.group("version"), venv)
    return out


# ------------------------------------------------------------------ lookups

RATE_LIMITED = "rate_limited"


def _get_json(url, timeout):
    """→ (body, None) | (None, RATE_LIMITED, wait_s) | (None, "error", 0)."""
    import urllib.error
    import urllib.request
    try:
        request = urllib.request.Request(url, headers={"User-Agent": claude_hook.USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read(2_000_000).decode()), None, 0
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            try:
                wait = float(exc.headers.get("Retry-After") or 8)
            except ValueError:
                wait = 8.0
            return None, RATE_LIMITED, max(1.0, min(wait, 30.0))
        return None, "error", 0
    except (urllib.error.URLError, OSError, ValueError):
        return None, "error", 0


def fetch_entry(eco, name, timeout=6.0):
    """One blocklist-only lookup. → {"hit": False, "fresh": bool} |
    {"hit": True, "versions": [...], "advisory", "since", "suspicious"} |
    (RATE_LIMITED, wait_s) | None when the server did not answer usably
    (= not checked)."""
    import urllib.parse
    url = (api_url("/api/blocklist/") + urllib.parse.quote(name, safe="")
           + "?" + urllib.parse.urlencode({"ecosystem": eco}))
    body, problem, wait = _get_json(url, timeout)
    if problem == RATE_LIMITED:
        return (RATE_LIMITED, wait)
    if not isinstance(body, dict) or not isinstance(body.get("blocked"), bool):
        return None
    if body["blocked"] is False:
        return {"hit": False, "fresh": body.get("fresh") is True}
    ids = body.get("advisory_ids") if isinstance(body.get("advisory_ids"), list) else []
    since = _DATE.match(str(body.get("first_seen") or ""))
    return {"hit": True,
            "versions": claude_hook._safe_specs(body.get("versions")),
            "advisory": next((str(a) for a in ids if claude_hook._SAFE_ADVISORY.match(str(a))), None),
            "since": since.group(1) if since else None,
            "suspicious": str(body.get("verdict") or "").upper() == "SUSPICIOUS"}


def fetch_recent(timeout=10.0):
    """Names added to the blocklist in the last week, as {(eco, name)}; one
    request. Used only to decide which names to look up first. None when the
    list could not be fetched."""
    body, _, _ = _get_json(api_url("/api/blocklist/recent"), timeout)
    rows = body.get("packages") if isinstance(body, dict) else None
    if not isinstance(rows, list):
        return None
    out = set()
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("package"), str):
            eco = "npm" if row.get("ecosystem") == "npm" else "pip"
            out.add((eco, claude_hook.normalize(eco, row["package"])))
    return out


def judge(package, entry):
    """A finding for one package given its blocklist entry, or None."""
    if not entry or not entry.get("hit"):
        return None
    bad = [v.lstrip("=") for v in entry.get("versions") or []]
    base = {k: package[k] for k in ("where", "file", "eco", "name", "version")}
    base.update(advisory=entry.get("advisory"), listed_since=entry.get("since"), bad_versions=bad[:12])
    if entry.get("suspicious"):
        return dict(base, kind="suspicious")
    if not bad:
        return dict(base, kind="blocked")
    if package["version"] is None:
        return dict(base, kind="some_versions")
    canon = claude_hook._canon_version(package["version"])
    if any(claude_hook._canon_version(v) == canon for v in bad):
        return dict(base, kind="blocked")
    return None


ENTRY_TTL_S = 12 * 3600


def scan(root, fetch=fetch_entry, recent=fetch_recent, entries=None, now=None,
         budget_s=SCAN_BUDGET_S, sleep=time.sleep, clock=time.time):
    """Check every package the project names and every installed Python
    package against the blocklist.

    The server limits how fast names can be looked up, so one run does what
    fits in `budget_s` and remembers each answer for twelve hours (`entries`,
    updated in place). Run it again to continue; `partial` says whether
    anything is still unchecked."""
    started = clock()
    stamp = now if now is not None else time.time()
    entries = entries if entries is not None else {}
    root = os.path.realpath(root)
    manifests, project = project_packages(root)
    installed = installed_packages(root)
    packages = project + installed
    names = []
    for p in packages:
        key = (p["eco"], p["name"])
        if _NAME_OK.match(p["name"]) and key not in names:
            names.append(key)
    capped = len(names) > MAX_NAMES
    names = names[:MAX_NAMES]

    def cached(key):
        row = entries.get(f"{key[0]}:{key[1]}")
        if not isinstance(row, dict):
            return None
        age, entry = row.get("t", 0), row.get("e")
        if isinstance(age, bool) or not isinstance(age, (int, float)) \
                or not isinstance(entry, dict) or not isinstance(entry.get("hit"), bool):
            # a saved answer that does not have the right shape is no answer
            if key not in malformed:
                malformed.add(key)
                claude_hook._warn(f"panel: saved answer for {key[1]} is malformed — "
                                  "counted as not checked")
            return None
        return entry if stamp - age < ENTRY_TTL_S else None

    malformed = set()

    todo = [k for k in names if cached(k) is None]
    if todo:
        # names added to the list this week go first: they are the likeliest hits
        new = recent() or set()
        todo.sort(key=lambda k: k not in new)
    waited = False
    for key in todo:
        if clock() - started > budget_s:
            break
        answer = fetch(key[0], key[1])
        if isinstance(answer, tuple) and answer[0] == RATE_LIMITED:
            if waited or clock() - started + answer[1] > budget_s:
                break               # limited twice in a row, or no time to wait: resume next run
            sleep(answer[1])
            waited = True
            answer = fetch(key[0], key[1])
            if isinstance(answer, tuple):
                break
        waited = False
        if isinstance(answer, dict):
            entries[f"{key[0]}:{key[1]}"] = {"t": stamp, "e": answer}

    findings, fresh_all, any_entry = [], True, False
    counts = {"project": {"total": 0, "checked": 0}, "installed": {"total": 0, "checked": 0}}
    seen = set()
    for p in packages:
        counts[p["where"]]["total"] += 1
        entry = cached((p["eco"], p["name"]))
        if entry is None:
            continue
        any_entry = True
        counts[p["where"]]["checked"] += 1
        if not entry["hit"] and not entry.get("fresh"):
            fresh_all = False
        finding = judge(p, entry)
        mark = (p["where"], p["eco"], p["name"], p["version"])
        if finding and mark not in seen:
            seen.add(mark)
            findings.append(finding)
    order = {"blocked": 0, "suspicious": 1, "some_versions": 2}
    findings.sort(key=lambda f: (order[f["kind"]], f["where"] != "installed", f["name"]))
    for c in counts.values():
        c["not_checked"] = c["total"] - c["checked"]
    return {"root": root, "scanned_at": stamp,
            "manifests": manifests, "project": counts["project"], "installed": counts["installed"],
            "findings": findings[:100],
            # True only when the server said its list is up to date for every miss
            "list_confirmed_fresh": bool(fresh_all and any_entry),
            "partial": capped or any(c["not_checked"] for c in counts.values())}


# --------------------------------------------------------------------- cache

def _load_cache():
    try:
        with open(cache_path(), encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {"entries": {}, "scans": {}}
    except (OSError, ValueError) as exc:
        claude_hook._warn(f"panel: saved scan unreadable ({type(exc).__name__}); starting again")
        return {"entries": {}, "scans": {}}
    if not (isinstance(data, dict) and isinstance(data.get("entries"), dict)
            and isinstance(data.get("scans"), dict)):
        return {"entries": {}, "scans": {}}
    return data


def load_scan(root):
    """The saved scan for this project, or None."""
    saved = _load_cache()["scans"].get(os.path.realpath(root))
    return saved if isinstance(saved, dict) else None


def run_scan(root):
    """Scan, continuing from what earlier runs learned, and save."""
    cache = _load_cache()
    now = time.time()
    cache["entries"] = {k: v for k, v in cache["entries"].items()
                        if isinstance(v, dict) and now - v.get("t", 0) < ENTRY_TTL_S}
    result = scan(root, entries=cache["entries"], now=now)
    cache["scans"][result["root"]] = result
    for old in sorted(cache["scans"], key=lambda k: cache["scans"][k].get("scanned_at", 0))[:-20]:
        del cache["scans"][old]
    try:
        os.makedirs(claude_hook._state_dir(), mode=0o700, exist_ok=True)
        claude_hook._atomic_write(cache_path(), json.dumps(cache))
    except OSError as exc:
        claude_hook._warn(f"panel: could not save the scan ({type(exc).__name__})")
    return result


def report(root, do_scan=False):
    result = run_scan(root) if do_scan else load_scan(root)
    return {"schema": SCHEMA, "generated_at": time.time(), "protection": protection(), "scan": result}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="stillrunning panel")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--cwd", default=os.getcwd())
    args = parser.parse_args(argv)
    data = report(args.cwd, do_scan=args.scan)
    if args.json:
        print(json.dumps(data))
        return 0
    prot, result = data["protection"], data["scan"]
    print("Claude Code hook:", prot["state"])
    for line in prot["problems"]:
        print("  !", line)
    if not result:
        print("No scan saved for this folder. Run: stillrunning panel --scan")
        return 0
    for where in ("project", "installed"):
        c = result[where]
        print(f"{where}: {c['checked']} of {c['total']} packages checked")
    for f in result["findings"]:
        print(f"  {f['kind']}: {f['name']} {f['version'] or ''} ({f['eco']}, {f['where']})")
    return 10 if any(f["kind"] == "blocked" for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
