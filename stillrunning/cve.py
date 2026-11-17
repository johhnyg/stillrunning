"""Known vulnerabilities (CVE monitoring) for the packages a project and this
machine already use. Its job is to shorten the time to patch known bugs in
honest packages. It does not detect malware (the blocklist does that) and it
does not stop attacks; it covers only what OSV.dev knows.

    stillrunning cve                 human report from the saved state (no network)
    stillrunning cve --json          the same as JSON, stable schema (no network)
    stillrunning cve --refresh       inventory + OSV.dev check, saves the state
    stillrunning cve --schedule      one crontab line: --refresh every 6 hours
    stillrunning cve --unschedule    remove that line

States (green only with positive proof):
    CLEAR     inventory fully resolved, feed refreshed within 24 h, zero known
              vulnerabilities for the resolved versions
    AFFECTED  at least one resolved package has a known vulnerability
    UNKNOWN   anything else: never refreshed, feed unreachable or stale,
              inventory not fully resolved, the check failed part-way,
              or the saved state cannot be read

`--json` shape (schema 1; fields are only ever added):
    {"schema": 1, "generated_at": ts, "state": "CLEAR"|"AFFECTED"|"UNKNOWN",
     "reasons": [str], "root": str|null, "refreshed_at": ts|null,
     "feed_updated_at": ts|null, "feed_age_hours": float|null,
     "newest_modified": str|null,
     "counts": {"affected_packages", "critical", "worst", "resolved",
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

SCHEMA = 1
FRESH_S = 24 * 3600
REFRESH_BUDGET_S = 150.0
DETAIL_WORKERS = 8
STATE_WORDS = ("CLEAR", "AFFECTED", "UNKNOWN")
CRON_MARK = "# stillrunning-cve (added by: stillrunning cve --schedule)"
LOCKFILES = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "npm",
             "poetry.lock": "pip", "uv.lock": "pip"}
NO_FEED_KINDS = {"conda", "pixi"}
_SAFE_PLACE = re.compile(r"^[A-Za-z0-9 ._/@+-]{1,120}$")
_SAFE_WHY = re.compile(r"^[A-Za-z0-9 ._/()+;,-]{1,200}$")


def state_path():
    return os.path.join(claude_hook._state_dir(), "cve_state.json")


def vulns_cache_path():
    return os.path.join(claude_hook._state_dir(), "cve_vulns.json")


# ─────────────────────────────── inventory ───────────────────────────────
def inventory(root):
    """→ {"packages": [resolved {eco,name,version,where,place}], "parts": [...],
    "complete": bool}. Every part says how many packages were resolved to one
    exact version and, when not all, why."""
    from .manifest import manifest_kind
    root = os.path.realpath(root)
    rows, project = panel.project_packages(root)
    parts, resolved = [], []
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
            part["unresolved"] = row.get("packages", 0)
            part["why"] = "conda/pixi packages are not checked here"
            continue
        loose = []
        for p in (x for x in project if x["file"] == rel):
            if not panel._NAME_OK.match(p["name"]):
                loose.append(p["name"])
                continue
            version = p["version"] or locked.get((str(Path(rel).parent), p["eco"]), {}).get(p["name"])
            if version:
                part["resolved"] += 1
                resolved.append({"eco": p["eco"], "name": p["name"], "version": version,
                                 "place": rel})
            else:
                loose.append(p["name"])
        others = row.get("not_registry", 0)
        part["unresolved"] = len(loose) + others
        reasons = []
        if loose:
            reasons.append(f"{len(loose)} without one exact version and no lockfile")
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
        part["resolved"] = len(items) - len(loose)
        part["unresolved"] = len(loose)
        whys = [x["why"] for x in problems if x["place"] == place]
        if loose:
            whys.append(f"{len(loose)} without a plain version number")
        if whys:
            part["unresolved"] = max(part["unresolved"], 1)
            part["why"] = "; ".join(whys)
        parts.append(part)
        resolved += [{"eco": "pip", "name": p["name"], "version": p["version"],
                      "place": "installed" if place == "this machine" else f"installed in {place}"}
                     for p in items if p not in loose]
    return {"packages": resolved, "parts": parts,
            "complete": all(p["unresolved"] == 0 for p in parts)}


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
        pool.shutdown(wait=False, cancel_futures=True)
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
        out.append(osv.cluster(summaries, version))
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
    """Inventory, check, save. The only function here that uses the network."""
    now = time.time() if now is None else now
    inv = inventory(root)
    cache = _load_json(vulns_cache_path()) or {}
    items, clusters, failures, newest, cache = check(inv["packages"], now=now, cache=cache, **kw)
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
        results[f"{item[0]}:{item[1]}@{item[2]}"] = found
        if found:
            affected.append({"eco": item[0], "name": item[1], "version": item[2],
                             "where": where.get(item, [])[:6], "vulns": found[:20]})
    affected.sort(key=lambda a: (-osv.RANK[osv.worst(a["vulns"])], a["name"]))
    not_checked = sum(1 for c in clusters if c is None)
    answered = any(c is not None for c in clusters) or not items
    doc = {
        "schema": SCHEMA, "root": os.path.realpath(root), "refreshed_at": now,
        "feed_updated_at": now if answered else None,
        "newest_modified": newest,
        "inventory": {"parts": inv["parts"], "complete": inv["complete"],
                      "resolved": len(items), "unresolved": sum(p["unresolved"] for p in inv["parts"])},
        "check": {"complete": not failures and not_checked == 0, "not_checked": not_checked,
                  "failures": [osv.WHY.get(f, f) for f in failures]},
        "affected": affected, "results": results,
    }
    doc["summary"] = _summary(doc)
    try:
        _save(state_path(), doc)
        _save(vulns_cache_path(), {k: v for k, v in cache.items() if isinstance(v, dict)})
    except OSError as exc:
        claude_hook._warn(f"cve: could not save the state ({type(exc).__name__})")
    return doc


def _summary(doc):
    """The few numbers the status line reads (it cannot import this module)."""
    affected = doc.get("affected") or []
    crit = sum(1 for a in affected if any(v["severity"] == "CRITICAL" for v in a["vulns"]))
    return {"affected_packages": len(affected), "critical": crit,
            "worst": osv.worst([v for a in affected for v in a["vulns"]]),
            "inventory_complete": bool(doc["inventory"]["complete"]),
            "check_complete": bool(doc["check"]["complete"])}


# ─────────────────────────────── state ───────────────────────────────
def _clean_vuln(v):
    if not isinstance(v, dict) or not osv.SAFE_ID.match(str(v.get("id") or "")):
        return None
    sev = v.get("severity") if v.get("severity") in osv.SEVERITIES else None
    fixed = v.get("fixed") if isinstance(v.get("fixed"), str) and osv.SAFE_VERSION.match(
        v["fixed"]) else None
    ids = [i for i in v.get("ids") or [] if isinstance(i, str) and osv.SAFE_ID.match(i)][:12]
    return {"id": v["id"], "ids": ids, "severity": sev, "fixed": fixed,
            "todo": f"upgrade to {fixed}" if fixed else "no fixed version is known yet; "
                    "check whether you use the affected feature"}


def _clean_affected(a):
    if not isinstance(a, dict) or a.get("eco") not in osv.ECOSYSTEM:
        return None
    name, version = str(a.get("name") or ""), str(a.get("version") or "")
    if not osv.SAFE_NAME.match(name) or not osv.SAFE_VERSION.match(version):
        return None
    vulns = [c for c in (_clean_vuln(v) for v in a.get("vulns") or []) if c]
    if not vulns:
        return None
    where = [w for w in a.get("where") or [] if isinstance(w, str) and _SAFE_PLACE.match(w)][:6]
    return {"eco": a["eco"], "name": name, "version": version, "where": where, "vulns": vulns}


def _num(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def evaluate(doc, now=None, malformed=False):
    """The saved state → what every surface shows. One rule (mirrored in
    statusline.py, which must stay stdlib-only)."""
    now = time.time() if now is None else now
    out = {"schema": SCHEMA, "generated_at": now, "state": "UNKNOWN", "reasons": [],
           "root": None, "refreshed_at": None, "feed_updated_at": None, "feed_age_hours": None,
           "newest_modified": None,
           "counts": {"affected_packages": 0, "critical": 0, "worst": None, "resolved": 0,
                      "unresolved": 0, "not_checked": 0},
           "inventory": [], "affected": [], "failures": []}
    if malformed:
        out["reasons"].append("The saved CVE state could not be read. Run: stillrunning cve --refresh")
        return out
    if doc is None:
        out["reasons"].append("Never refreshed. Run: stillrunning cve --refresh")
        return out
    try:
        summary = doc["summary"]
        inv, chk = doc["inventory"], doc["check"]
        if not (isinstance(summary, dict) and isinstance(inv, dict) and isinstance(chk, dict)
                and doc.get("schema") == SCHEMA):
            raise TypeError
        affected = [c for c in (_clean_affected(a) for a in doc.get("affected") or []) if c]
        feed = _num(doc.get("feed_updated_at"))
        root = doc.get("root") if isinstance(doc.get("root"), str) else None
        parts = []
        for p in inv.get("parts") or []:
            if isinstance(p, dict) and isinstance(p.get("part"), str) and _SAFE_PLACE.match(p["part"]):
                parts.append({"part": p["part"], "kind": str(p.get("kind"))[:20],
                              "resolved": int(p.get("resolved") or 0),
                              "unresolved": int(p.get("unresolved") or 0),
                              "why": p["why"] if isinstance(p.get("why"), str)
                              and _SAFE_WHY.match(p["why"]) else
                              (None if not p.get("why") else "not resolved")})
        failures = [f for f in chk.get("failures") or [] if f in osv.WHY.values()]
        inv_complete = summary.get("inventory_complete") is True
        chk_complete = summary.get("check_complete") is True
    except (KeyError, TypeError, ValueError, AttributeError):
        return evaluate(None, now, malformed=True)
    out.update(root=root, refreshed_at=_num(doc.get("refreshed_at")), feed_updated_at=feed,
               newest_modified=doc.get("newest_modified") if isinstance(doc.get(
                   "newest_modified"), str) and osv.SAFE_TIME.match(doc["newest_modified"]) else None,
               inventory=parts, affected=affected, failures=failures)
    crit = sum(1 for a in affected if any(v["severity"] == "CRITICAL" for v in a["vulns"]))
    out["counts"] = {"affected_packages": len(affected), "critical": crit,
                     "worst": osv.worst([v for a in affected for v in a["vulns"]]),
                     "resolved": int(_num(inv.get("resolved")) or 0),
                     "unresolved": sum(p["unresolved"] for p in parts),
                     "not_checked": int(_num(chk.get("not_checked")) or 0)}
    age = None if feed is None else max(0.0, now - feed)
    out["feed_age_hours"] = None if age is None else round(age / 3600, 1)
    reasons = out["reasons"]
    if feed is None:
        reasons.append("The feed could not be reached at the last refresh.")
    elif age > FRESH_S:
        reasons.append(f"The feed is {int(age // 3600)}h old (older than 24h).")
    if not inv_complete:
        reasons.append(f"{out['counts']['unresolved']} package(s) could not be resolved to one "
                       "exact version, so they were not checked.")
    if not chk_complete:
        n = out["counts"]["not_checked"]
        reasons.append("The check did not finish" + (f": {n} package(s) not checked." if n else "."))
    if affected:
        out["state"] = "AFFECTED"
    elif not reasons:
        out["state"] = "CLEAR"
    return out


def load(now=None):
    path = state_path()
    if not os.path.exists(path):
        return evaluate(None, now)
    doc = _load_json(path)
    return evaluate(doc, now, malformed=doc is None)


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
    fresh = ("feed updated " + relative(max(0.0, data["generated_at"] - feed))
             if feed is not None else
             "feed never refreshed" if data["refreshed_at"] is None else "feed unreachable")
    if data["state"] == "AFFECTED":
        n = c["affected_packages"]
        detail = (f"{n} affected dep{'s' if n != 1 else ''} "
                  + (f"({c['critical']} critical)" if c["critical"]
                     else f"(worst {(c['worst'] or 'unknown').lower()})"))
    elif data["state"] == "CLEAR":
        detail = "clear"
    else:
        detail = "unknown"
    return f"CVEs · {detail} · {fresh}"


def render(data):
    out = ["Known vulnerabilities (CVE monitoring, OSV.dev)", "", headline(data)]
    out += [f"  ! {r}" for r in data["reasons"]]
    if data["root"]:
        out.append(f"Project: {data['root']}")
    if data["newest_modified"]:
        out.append(f"Newest advisory change seen: {data['newest_modified']}")
    if data["inventory"]:
        out += ["", "Inventory (exact versions):"]
        for p in data["inventory"]:
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
    data = load()
    if args.json:
        print(json.dumps(data))
    else:
        print(render(data))
    return {"CLEAR": 0, "AFFECTED": 10, "UNKNOWN": 3}[data["state"]] if args.refresh else 0


if __name__ == "__main__":
    sys.exit(main())
