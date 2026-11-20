"""Known vulnerabilities (CVE monitoring) for the packages a project and this
machine already use. Its job is to shorten the time to patch known bugs in
honest packages. It does not detect malware (the blocklist does that) and it
does not stop attacks; it covers only what OSV.dev knows.

    stillrunning cve [--cwd DIR]            report from the saved state (no network)
    stillrunning cve --json [--cwd DIR]     the same as JSON, stable schema (no network)
    stillrunning cve --refresh [--cwd DIR]  inventory + OSV.dev check, saves the state
    stillrunning cve --schedule [--cwd DIR] one crontab line: --refresh every 6 hours
    stillrunning cve --unschedule           remove that line

The state is kept per project folder (~/.stillrunning/cve_state.json,
{"schema": 2, "projects": {"/abs/folder": {...}}}). Every reader answers for
one folder and uses only that folder's entry.

States (green only with positive proof):
    CLEAR     this folder's entry, inventory fully resolved and not empty,
              feed refreshed within 24 h (and not in the future), the check
              complete, zero known vulnerabilities, and the saved summary
              agreeing with the saved details
    AFFECTED  at least one resolved package has a known vulnerability, or is
              listed by OSV as malicious (severity "MALICIOUS")
    UNKNOWN   anything else (the default)

`--json` shape (schema 1 of the output; fields are only ever added):
    {"schema": 1, "generated_at": ts, "state": "CLEAR"|"AFFECTED"|"UNKNOWN",
     "reasons": [str], "root": str|null, "refreshed_at": ts|null,
     "feed_updated_at": ts|null, "feed_age_hours": float|null,
     "newest_modified": str|null,
     "counts": {"affected_packages", "critical", "malicious", "worst", "resolved",
                "unresolved", "not_checked"},
     "inventory": [{"part", "kind", "resolved", "unresolved", "why"}],
     "affected": [{"eco", "name", "version", "where": [str],
                   "vulns": [{"id", "ids", "severity", "fixed", "todo"}]}],
     "failures": [str]}
"""
import json
import os
import re
import sys
import time
from pathlib import Path

from . import claude_hook, osv, panel

SCHEMA = 1                 # of the --json output
FILE_SCHEMA = 2            # of cve_state.json
FRESH_S = 24 * 3600
FUTURE_SLACK_S = 120
KEEP_PROJECTS = 20
REFRESH_BUDGET_S = 150.0
DETAIL_WORKERS = 8
STATE_WORDS = ("CLEAR", "AFFECTED", "UNKNOWN")
SEVERITY_WORDS = osv.SEVERITIES + ("MALICIOUS",)
PART_KINDS = ("project file", "installed", "search")
CRON_MARK = "# stillrunning-cve (added by: stillrunning cve --schedule)"
LOCKFILES = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "npm",
             "poetry.lock": "pip", "uv.lock": "pip"}
NO_FEED_KINDS = {"conda", "pixi"}
MAL_TODO = "listed as malicious — remove it (the blocklist refuses it)"
_SAFE_PLACE = re.compile(r"^[A-Za-z0-9 ._/@+-]{1,120}$")
_SAFE_ROOT = re.compile(r"^/[A-Za-z0-9 ._/@+-]{0,400}$")
_SAFE_WHY = re.compile(r"^[A-Za-z0-9 ._/()+;,-]{1,300}$")


def state_path():
    return os.path.join(claude_hook._state_dir(), "cve_state.json")


def vulns_cache_path():
    return os.path.join(claude_hook._state_dir(), "cve_vulns.json")


def _sendable(eco, name, version):
    """Can OSV.dev be asked about exactly this package and version?"""
    return (eco in osv.ECOSYSTEM and bool(version)
            and bool(osv.SAFE_NAME.match(claude_hook.normalize(eco, name)))
            and bool(osv.SAFE_VERSION.match(version)))


# ─────────────────────────────── inventory ───────────────────────────────
def inventory(root):
    """→ {"packages": [resolved {eco,name,version,place}], "parts": [...],
    "complete": bool}. Every part says how many packages were resolved to one
    exact version OSV.dev can be asked about and, when not all, why."""
    from .manifest import manifest_kind
    root = os.path.realpath(root)
    search = []
    rows, project = panel.project_packages(root, search)
    parts, resolved = [], []
    if search:
        parts.append({"part": "project search", "kind": "search", "resolved": 0,
                      "unresolved": len(search), "why": "; ".join(search)})
    # exact versions each lockfile gives, by folder and ecosystem
    locked = {}
    for p in project:
        if Path(p["file"]).name in LOCKFILES and p["version"]:
            locked.setdefault((str(Path(p["file"]).parent), p["eco"]), {})[p["name"]] = p["version"]
    for row in rows:
        rel = row["file"]
        part = {"part": rel, "kind": "project file", "resolved": 0, "unresolved": 0, "why": None}
        parts.append(part)
        kind = manifest_kind(Path(root, rel))
        if row.get("unreadable"):
            part["unresolved"], part["why"] = max(1, row.get("packages", 0)), "could not be read"
            continue
        if kind in NO_FEED_KINDS:
            part["unresolved"] = max(1, row.get("packages", 0))
            part["why"] = "conda/pixi packages are not checked here"
            continue
        loose, unsendable = [], []
        for p in (x for x in project if x["file"] == rel):
            version = p["version"] or locked.get((str(Path(rel).parent), p["eco"]), {}).get(p["name"])
            if not version or not panel._NAME_OK.match(p["name"]):
                loose.append(p["name"])
            elif not _sendable(p["eco"], p["name"], version):
                unsendable.append(p["name"])
            else:
                part["resolved"] += 1
                resolved.append({"eco": p["eco"], "name": p["name"], "version": version,
                                 "place": rel})
        others = row.get("not_registry", 0)
        part["unresolved"] = len(loose) + len(unsendable) + others
        reasons = []
        if loose:
            reasons.append(f"{len(loose)} without one exact version and no lockfile")
        if unsendable:
            reasons.append(f"{len(unsendable)} with a name or version that cannot be sent to OSV.dev")
        if others:
            reasons.append(f"{others} from a local path, web address or git")
        part["why"] = "; ".join(reasons) or None
    problems = []
    installed = panel.installed_packages(root, problems)
    places = {}
    for p in installed:
        places.setdefault(p["file"], []).append(p)
    for place in ["this machine"] + [v for v in panel._VENV_DIRS if v in places or
                                     any(x["place"] == v for x in problems)]:
        items = places.get(place, [])
        part = {"part": place, "kind": "installed", "resolved": 0, "unresolved": 0, "why": None}
        loose = [p for p in items if not p["version"] or not panel._NAME_OK.match(p["name"])]
        unsendable = [p for p in items if p not in loose
                      and not _sendable("pip", p["name"], p["version"])]
        good = [p for p in items if p not in loose and p not in unsendable]
        part["resolved"] = len(good)
        part["unresolved"] = len(loose) + len(unsendable)
        whys = [x["why"] for x in problems if x["place"] == place]
        if loose:
            whys.append(f"{len(loose)} without a plain version number")
        if unsendable:
            whys.append(f"{len(unsendable)} with a name or version that cannot be sent to OSV.dev")
        if whys:
            part["unresolved"] = max(part["unresolved"], 1)
            part["why"] = "; ".join(whys)
        parts.append(part)
        resolved += [{"eco": "pip", "name": p["name"], "version": p["version"],
                      "place": "installed" if place == "this machine" else f"installed in {place}"}
                     for p in good]
    return {"packages": resolved, "parts": parts,
            "complete": bool(parts) and all(p["unresolved"] == 0 for p in parts)}


# ─────────────────────────────── refresh ───────────────────────────────
def _load_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        claude_hook._warn(f"cve: {os.path.basename(path)} unreadable ({type(exc).__name__})")
        return None


def _save(path, data):
    claude_hook._atomic_write(path, json.dumps(data))


def check(packages, now=None, budget_s=REFRESH_BUDGET_S, query_batch=None, get_vuln=None,
          cache=None, clock=time.monotonic):
    """Look up every resolved package on OSV.dev. → (per-item clusters (None
    = not checked), failures, newest modified, cache)."""
    query_batch = query_batch or osv.query_batch
    get_vuln = get_vuln or osv.get_vuln
    cache = cache if cache is not None else {}
    deadline = clock() + budget_s
    items = sorted({(p["eco"], claude_hook.normalize(p["eco"], p["name"]), p["version"])
                    for p in packages
                    if p["eco"] in osv.ECOSYSTEM and osv.SAFE_NAME.match(p["name"])
                    and osv.SAFE_VERSION.match(p["version"])})
    failures = []
    try:
        found, why = query_batch(items, deadline=deadline, clock=clock)
    except Exception as exc:     # any fault = not checked, said out loud
        claude_hook._warn(f"cve: OSV query failed ({type(exc).__name__})")
        found, why = [None] * len(items), ["offline"]
    for w in why:
        if w not in failures:
            failures.append(w)
            claude_hook._warn(f"cve: OSV query problem: {osv.WHY.get(w, w)}")
    wanted = {}
    for hits in found:
        for vid, modified in hits or []:
            if not vid.startswith("MAL-"):       # malicious packages are the blocklist's job
                wanted[vid] = modified
    todo = [vid for vid, mod in wanted.items()
            if not (isinstance(cache.get(vid), dict) and cache[vid].get("modified") == mod
                    and mod is not None and isinstance(cache[vid].get("raw"), dict))]
    detail_failed = set()
    problems = []
    # one retry for the details that failed (a slow answer is common under load)
    for attempt in (1, 2):
        if not todo or clock() > deadline:
            break
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
        pool = ThreadPoolExecutor(max_workers=DETAIL_WORKERS)
        futures = {vid: pool.submit(get_vuln, vid) for vid in todo}
        again, problems = [], []
        for vid, future in futures.items():
            try:
                raw, problem = future.result(timeout=max(0.05, deadline - clock()))
            except FutureTimeout:
                raw, problem = None, "budget"
            except Exception as exc:
                claude_hook._warn(f"cve: detail fetch crashed ({type(exc).__name__})")
                raw, problem = None, "offline"
            if problem or not isinstance(raw, dict) or raw.get("id") != vid:
                again.append(vid)
                problems.append(problem or "garbage")
                continue
            cache[vid] = {"modified": wanted[vid], "raw": _slim(raw)}
        if sys.version_info >= (3, 9):
            pool.shutdown(wait=False, cancel_futures=True)
        else:
            # Python 3.8 has no cancel_futures (it raised TypeError and stopped
            # `stillrunning cve`): cancel what has not started, then shut down.
            for pending in futures.values():
                pending.cancel()
            pool.shutdown(wait=False)
        if again and attempt == 1:
            claude_hook._warn(f"cve: {len(again)} advisory detail(s) did not arrive; trying once more")
        todo = again
    detail_failed = set(todo)
    for w in problems if detail_failed else []:
        if w not in failures:
            failures.append(w)
            claude_hook._warn(f"cve: OSV detail problem: {osv.WHY.get(w, w)} "
                              f"({len(detail_failed)} advisory detail(s) missing)")
    newest = max((m for m in wanted.values() if m), default=None)
    out = []
    for (eco, name, version), hits in zip(items, found):
        if hits is None:
            out.append(None)
            continue
        summaries = []
        for vid, _ in hits:
            if vid.startswith("MAL-"):
                continue
            entry = cache.get(vid)
            if vid in detail_failed or not isinstance(entry, dict):
                # known to affect this version; severity and fix unknown
                summaries.append({"id": vid, "aliases": [], "severity": None, "fixed": None,
                                  "fixed_all": [], "malicious": False, "withdrawn": False})
                continue
            s = osv.summarize(entry["raw"], eco, name, version)
            if s:
                summaries.append(s)
        # OSV MAL- records are the blocklist's job at install time, but a package
        # already here that OSV lists as malicious must never read clear
        mal = sorted(vid for vid, _ in hits if vid.startswith("MAL-"))
        listed = [{"id": mal[0], "ids": mal[:12], "severity": "MALICIOUS", "fixed": None}] \
            if mal else []
        out.append(listed + osv.cluster(summaries, version))
    return items, out, failures, newest, cache


def _slim(raw):
    """Only the fields summarize() reads are cached."""
    keep = {k: raw.get(k) for k in ("id", "aliases", "modified", "withdrawn", "severity")}
    db = raw.get("database_specific")
    keep["database_specific"] = {"severity": db.get("severity")} if isinstance(db, dict) else {}
    keep["affected"] = [{"package": a.get("package"), "ranges": a.get("ranges")}
                        for a in raw.get("affected") or [] if isinstance(a, dict)]
    return keep


def refresh(root, now=None, **kw):
    """Inventory, check, save this folder's entry. The only function here that
    uses the network."""
    now = time.time() if now is None else now
    root = os.path.realpath(root)
    inv = inventory(root)
    cache = _load_json(vulns_cache_path()) or {}
    items, clusters, failures, newest, cache = check(inv["packages"], now=now, cache=cache, **kw)
    dropped = len({(p["eco"], claude_hook.normalize(p["eco"], p["name"]), p["version"])
                   for p in inv["packages"]}) - len(items)
    where = {}
    for p in inv["packages"]:
        key = (p["eco"], claude_hook.normalize(p["eco"], p["name"]), p["version"])
        where.setdefault(key, [])
        if p["place"] not in where[key]:
            where[key].append(p["place"])
    affected, results = [], {}
    for item, found in zip(items, clusters):
        if found is None:
            continue
        results[f"{item[0]}:{item[1]}@{item[2]}"] = [c for c in found if c["severity"] != "MALICIOUS"]
        if found:
            affected.append({"eco": item[0], "name": item[1], "version": item[2],
                             "where": where.get(item, [])[:6], "vulns": found[:20]})
    affected.sort(key=lambda a: (-osv.RANK[osv.worst(a["vulns"])], a["name"]))
    not_checked = sum(1 for c in clusters if c is None) + max(0, dropped)
    answered = any(c is not None for c in clusters)
    entry = {
        "schema": FILE_SCHEMA, "root": root, "refreshed_at": now,
        "feed_updated_at": now if answered else None,
        "newest_modified": newest,
        "inventory": {"parts": inv["parts"], "complete": inv["complete"],
                      "resolved": len(items),
                      "unresolved": sum(p["unresolved"] for p in inv["parts"])},
        "check": {"complete": not failures and not_checked == 0, "not_checked": not_checked,
                  "failures": [osv.WHY.get(f, osv.WHY["garbage"]) for f in failures]},
        "affected": affected, "results": results,
    }
    entry["summary"] = _summary(entry)
    doc = _load_json(state_path())
    projects = doc.get("projects") if isinstance(doc, dict) and doc.get("schema") == FILE_SCHEMA \
        and isinstance(doc.get("projects"), dict) else {}
    projects[root] = entry
    keep = sorted(projects, key=lambda k: _num((projects[k] or {}).get("refreshed_at")
                                              if isinstance(projects[k], dict) else 0) or 0)
    for old in keep[:-KEEP_PROJECTS]:
        del projects[old]
    try:
        _save(state_path(), {"schema": FILE_SCHEMA, "projects": projects})
        _save(vulns_cache_path(), {k: v for k, v in cache.items() if isinstance(v, dict)})
    except OSError as exc:
        claude_hook._warn(f"cve: could not save the state ({type(exc).__name__})")
    return entry


def _counts(affected):
    def has(a, word):
        return any(v["severity"] == word for v in a["vulns"])
    return {"affected_packages": len(affected),
            "critical": sum(1 for a in affected if has(a, "CRITICAL")),
            "malicious": sum(1 for a in affected if has(a, "MALICIOUS")),
            "worst": osv.worst([v for a in affected for v in a["vulns"]])}


def _summary(entry):
    """What the saved details add up to. Readers recompute it from the details
    and treat any disagreement as UNKNOWN."""
    return dict(_counts(entry["affected"]),
                inventory_complete=entry["inventory"]["complete"] is True,
                check_complete=entry["check"]["complete"] is True)


# ─────────────────────────────── state ───────────────────────────────
def _clean_vuln(v):
    if not isinstance(v, dict) or not osv.SAFE_ID.match(str(v.get("id") or "")):
        return None
    if v.get("severity") is not None and v.get("severity") not in SEVERITY_WORDS:
        return None
    sev = v.get("severity")
    fixed = v.get("fixed") if isinstance(v.get("fixed"), str) and osv.SAFE_VERSION.match(
        v["fixed"]) else None
    ids = [i for i in v.get("ids") or [] if isinstance(i, str) and osv.SAFE_ID.match(i)][:12]
    if sev == "MALICIOUS":
        todo = MAL_TODO
    elif fixed:
        todo = f"upgrade to {fixed}"
    else:
        todo = "no fixed version is known yet; check whether you use the affected feature"
    return {"id": v["id"], "ids": ids, "severity": sev, "fixed": fixed, "todo": todo}


def _clean_affected(a):
    if not isinstance(a, dict) or a.get("eco") not in osv.ECOSYSTEM:
        return None
    name, version = str(a.get("name") or ""), str(a.get("version") or "")
    if not osv.SAFE_NAME.match(name) or not osv.SAFE_VERSION.match(version):
        return None
    raw = a.get("vulns") if isinstance(a.get("vulns"), list) else []
    vulns = [c for c in (_clean_vuln(v) for v in raw) if c]
    if not vulns or len(vulns) != len(raw):
        return None
    where = [w for w in a.get("where") or [] if isinstance(w, str) and _SAFE_PLACE.match(w)][:6]
    return {"eco": a["eco"], "name": name, "version": version, "where": where, "vulns": vulns}


def _clean_part(p):
    if not isinstance(p, dict) or not isinstance(p.get("part"), str) \
            or not _SAFE_PLACE.match(p["part"]) or p.get("kind") not in PART_KINDS:
        return None
    nums = [p.get("resolved"), p.get("unresolved")]
    if any(isinstance(n, bool) or not isinstance(n, int) or n < 0 for n in nums):
        return None
    why = p.get("why")
    if why is not None and not (isinstance(why, str) and _SAFE_WHY.match(why)):
        return None
    return {"part": p["part"], "kind": p["kind"], "resolved": nums[0], "unresolved": nums[1],
            "why": why}


def _num(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _blank(now):
    return {"schema": SCHEMA, "generated_at": now, "state": "UNKNOWN", "reasons": [],
            "root": None, "refreshed_at": None, "feed_updated_at": None, "feed_age_hours": None,
            "newest_modified": None,
            "counts": {"affected_packages": 0, "critical": 0, "malicious": 0, "worst": None,
                       "resolved": 0, "unresolved": 0, "not_checked": 0},
            "inventory": [], "affected": [], "failures": []}


def evaluate_for(entry, now, root):
    """One folder's saved entry → what every surface shows. The state comes
    from the details, never from the saved summary (mirrored in
    statusline.py, which must stay stdlib-only; a test keeps them in step)."""
    out = _blank(now)
    reasons = out["reasons"]
    root = os.path.realpath(root)
    if not isinstance(entry, dict):
        reasons.append("This folder has not been checked yet. Run: stillrunning cve --refresh")
        return out
    saved_root = entry.get("root")
    if saved_root != root or not _SAFE_ROOT.match(root):
        reasons.append("The saved CVE state was checked for another folder. "
                       "Run: stillrunning cve --refresh")
        return out
    out["root"] = root
    try:
        inv, chk, summary = entry["inventory"], entry["check"], entry["summary"]
        if not (isinstance(inv, dict) and isinstance(chk, dict) and isinstance(summary, dict)
                and entry.get("schema") == FILE_SCHEMA):
            raise TypeError
        raw_affected = entry.get("affected")
        raw_parts = inv.get("parts")
        failures = chk.get("failures")
        if not (isinstance(raw_affected, list) and isinstance(raw_parts, list)
                and isinstance(failures, list)):
            raise TypeError
        affected = [c for c in (_clean_affected(a) for a in raw_affected) if c]
        parts = [c for c in (_clean_part(p) for p in raw_parts) if c]
        clean_failures = [f for f in failures if f in osv.WHY.values()]
        resolved, not_checked = inv.get("resolved"), chk.get("not_checked")
        for n in (resolved, not_checked):
            if isinstance(n, bool) or not isinstance(n, int) or n < 0:
                raise TypeError
        feed, refreshed = entry.get("feed_updated_at"), entry.get("refreshed_at")
        if (feed is not None and _num(feed) is None) or _num(refreshed) is None:
            raise TypeError
    except (KeyError, TypeError, ValueError, AttributeError):
        reasons.append("The saved CVE state could not be read. Run: stillrunning cve --refresh")
        out["root"] = None
        return out
    feed, refreshed = _num(feed), _num(refreshed)
    counts = _counts(affected)
    unresolved = sum(p["unresolved"] for p in parts)
    inv_body = bool(parts) and unresolved == 0
    chk_body = not_checked == 0 and not failures
    consistent = (len(affected) == len(raw_affected) and len(parts) == len(raw_parts)
                  and len(clean_failures) == len(failures)
                  and (inv.get("complete") is True) == inv_body
                  and (chk.get("complete") is True) == chk_body
                  and all(summary.get(k) == counts[k] for k in counts)
                  and summary.get("inventory_complete") is inv_body
                  and summary.get("check_complete") is chk_body
                  # review 2: totals must add up, and the feed time cannot
                  # be later than the refresh that recorded it
                  and resolved <= sum(p["resolved"] for p in parts)
                  and (resolved == 0) == (sum(p["resolved"] for p in parts) == 0)
                  and (feed is None or feed <= refreshed + FUTURE_SLACK_S))
    modified = entry.get("newest_modified")
    out.update(refreshed_at=refreshed, feed_updated_at=feed,
               newest_modified=modified if isinstance(modified, str)
               and osv.SAFE_TIME.match(modified) else None,
               inventory=parts, affected=affected, failures=clean_failures)
    out["counts"] = dict(counts, resolved=resolved, unresolved=unresolved, not_checked=not_checked)
    blocking = []
    if not consistent:
        blocking.append("The saved CVE state is inconsistent (its summary and details "
                        "disagree). Run: stillrunning cve --refresh")
    if any(t is not None and t > now + FUTURE_SLACK_S for t in (feed, refreshed)):
        blocking.append("The saved time is in the future, so its age cannot be trusted.")
    age = None if feed is None else max(0.0, now - feed)
    out["feed_age_hours"] = None if age is None else round(age / 3600, 1)
    if feed is None:
        if resolved:      # with nothing to ask about, the feed was never asked
            reasons.append("The feed could not be reached at the last refresh.")
    elif age > FRESH_S:
        reasons.append(f"The feed is {int(age // 3600)}h old (older than 24h).")
    if not inv_body:
        reasons.append(f"{unresolved} package(s) or place(s) could not be resolved to one "
                       "exact version, so they were not checked.")
    if not chk_body:
        reasons.append("The check did not finish" +
                       (f": {not_checked} package(s) not checked." if not_checked else "."))
    for p in parts:
        if p["kind"] == "search" and p["why"]:
            reasons.append(f"The project search was cut short: {p['why']}.")
    if resolved == 0:
        reasons.append("Nothing to check was found in this folder or this Python environment.")
    reasons[:0] = blocking
    if blocking:
        out["state"] = "UNKNOWN"
    elif affected:
        out["state"] = "AFFECTED"
    elif not reasons:
        out["state"] = "CLEAR"
    return out


def evaluate(entry, now=None, malformed=False, root=None):
    """Kept for callers that hold an entry: the folder is the entry's own."""
    now = time.time() if now is None else now
    if malformed:
        out = _blank(now)
        out["reasons"].append("The saved CVE state could not be read. Run: stillrunning cve --refresh")
        return out
    if entry is None:
        out = _blank(now)
        out["reasons"].append("Never refreshed. Run: stillrunning cve --refresh")
        return out
    return evaluate_for(entry, now, root or str((entry or {}).get("root") or "/"))


def load(now=None, root=None):
    """What to show for one folder (default: the current one). Local only."""
    now = time.time() if now is None else now
    root = os.path.realpath(root or os.getcwd())
    path = state_path()
    if not os.path.exists(path):
        return evaluate(None, now)
    doc = _load_json(path)
    if not (isinstance(doc, dict) and doc.get("schema") == FILE_SCHEMA
            and isinstance(doc.get("projects"), dict)):
        return evaluate(None, now, malformed=True)
    entry = doc["projects"].get(root)
    if entry is None and doc["projects"]:
        out = _blank(now)
        out["reasons"].append("The saved CVE state was checked for another folder. "
                              "Run: stillrunning cve --refresh")
        return out
    if entry is None:
        return evaluate(None, now)
    return evaluate_for(entry, now, root)


def relative(seconds):
    """Same wording as the status line."""
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{int(seconds // 60)}m ago"
    if seconds < 172800:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


def headline(data):
    """One line, e.g. "CVEs · 2 affected deps (1 critical) · feed updated 3h ago"."""
    c, feed = data["counts"], data["feed_updated_at"]
    if any("another folder" in r for r in data["reasons"]):
        fresh = "checked for another folder"
    elif any("in the future" in r for r in data["reasons"]):
        fresh = "feed time in the future"
    elif feed is not None:
        fresh = "feed updated " + relative(max(0.0, data["generated_at"] - feed))
    else:
        fresh = "feed never refreshed" if data["refreshed_at"] is None else "feed unreachable"
    if data["state"] == "AFFECTED":
        n = c["affected_packages"]
        bits = [f"{c[k]} {k}" for k in ("critical", "malicious") if c.get(k)]
        detail = (f"{n} affected dep{'s' if n != 1 else ''} ("
                  + (", ".join(bits) or f"worst {(c['worst'] or 'unknown').lower()}") + ")")
    elif data["state"] == "CLEAR":
        detail = "clear"
    else:
        detail = "unknown"
    return f"CVEs · {detail} · {fresh}"


def render(data):
    out = ["Known vulnerabilities (CVE monitoring, OSV.dev)", "", headline(data)]
    out += [f"  ! {r}" for r in data["reasons"]]
    if data["root"] and _SAFE_ROOT.match(data["root"]):
        out.append(f"Project: {data['root']}")
    if data["newest_modified"]:
        out.append(f"Newest advisory change seen: {data['newest_modified']}")
    if data["inventory"]:
        out += ["", "Inventory (exact versions):"]
        for p in data["inventory"]:
            if p["kind"] not in PART_KINDS or not _SAFE_PLACE.match(p["part"]):
                continue
            extra = f", {p['unresolved']} not resolved ({p['why']})" if p["unresolved"] else ""
            out.append(f"  {p['part']} [{p['kind']}]: {p['resolved']} resolved{extra}")
    if data["affected"]:
        out += ["", "Affected:"]
        for a in data["affected"]:
            out.append(f"  {a['name']} {a['version']} ({a['eco']}) · {', '.join(a['where']) or '?'}")
            for v in a["vulns"]:
                out.append(f"    {v['id']} · {(v['severity'] or 'unknown severity').lower()}"
                           f" · {('fixed in ' + v['fixed']) if v['fixed'] else 'no fix known'}"
                           f" → {v['todo']}")
    out += ["", "This shortens the time to patch known bugs in packages you already use. It does "
                "not detect malware or stop attacks, and it covers only what OSV.dev knows."]
    return "\n".join(out)


# ─────────────────────────────── schedule ───────────────────────────────
def cron_line(cwd):
    import shlex
    state = claude_hook._state_dir()
    lock, log = os.path.join(state, "cve.lock"), os.path.join(state, "cve_cron.log")
    cmd = (f"flock -n {shlex.quote(lock)} timeout 600 {shlex.quote(sys.executable)} -m stillrunning "
           f"cve --refresh --cwd {shlex.quote(os.path.realpath(cwd))} >/dev/null 2>>{shlex.quote(log)}")
    return f"17 */6 * * * {cmd} {CRON_MARK}"


def _crontab(args, text=None):
    import subprocess
    return subprocess.run(["crontab"] + args, input=text, capture_output=True, text=True, timeout=20)


def _read_crontab():
    """→ (lines, None) or (None, problem). "no crontab for user" is empty."""
    try:
        ran = _crontab(["-l"])
    except (OSError, ValueError) as exc:
        return None, f"crontab could not be run ({type(exc).__name__})"
    if ran.returncode != 0:
        if "no crontab" in (ran.stderr or "").lower():
            return [], None
        return None, "crontab -l failed; nothing was changed"
    return ran.stdout.splitlines(), None


def schedule(cwd, remove=False):
    lines, problem = _read_crontab()
    if problem:
        print(problem)
        return 1
    ours = [line for line in lines if line.rstrip().endswith(CRON_MARK)]
    rest = [line for line in lines if not line.rstrip().endswith(CRON_MARK)]
    if remove:
        if not ours:
            print("No stillrunning CVE refresh is scheduled; crontab unchanged.")
            return 0
        new = rest
        said = f"Removed the stillrunning CVE refresh line ({len(ours)} line) from your crontab."
    else:
        want = cron_line(cwd)
        if ours == [want]:
            print("Already scheduled (every 6 hours); crontab unchanged:\n  " + want)
            return 0
        new = rest + [want]
        said = ("Scheduled: stillrunning cve --refresh every 6 hours (" +
                ("replaced the earlier line" if ours else "added one line") + "):\n  " + want)
    ran = _crontab(["-"], "\n".join(new) + ("\n" if new else ""))
    if ran.returncode != 0:
        print("crontab - failed; your crontab may be unchanged. Check: crontab -l")
        return 1
    print(said)
    return 0


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="stillrunning cve")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--schedule", action="store_true")
    parser.add_argument("--unschedule", action="store_true")
    parser.add_argument("--cwd", default=None)
    args = parser.parse_args(argv)
    if args.schedule or args.unschedule:
        return schedule(args.cwd or os.getcwd(), remove=args.unschedule)
    if args.refresh:
        refresh(args.cwd or os.getcwd())
    data = load(root=args.cwd or os.getcwd())
    if args.json:
        print(json.dumps(data))
    else:
        print(render(data))
    return {"CLEAR": 0, "AFFECTED": 10, "UNKNOWN": 3}[data["state"]] if args.refresh else 0


if __name__ == "__main__":
    sys.exit(main())
