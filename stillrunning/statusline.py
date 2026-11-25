#!/usr/bin/env python3
"""Claude Code status line: shield, how fresh the threat list is, and
today's outcomes.

Run by path (`python -I -S statusline.py`); imports only json/os/sys/time so
it prints in a few milliseconds. Reads the counter file the hook maintains.

Labels are the same ones the side panel uses, and the scope is always
"today" (the machine's local calendar day):
    no known threat   looked up, not on the blocklist           green
    couldn't check    could not be verified; a person decided   amber
    blocked           on the blocklist                          red
When the list was updated is the proof the shield is live, so it comes
right after the name and is never dropped when space is short.

Then one segment for known vulnerabilities (CVE monitoring), read from
~/.stillrunning/cve_state.json (written by `stillrunning cve --refresh`;
no file = the feature is not set up = no segment), for the project folder
Claude Code names on stdin (else the current folder):
    CVEs: clear · feed 3h ago                      green  (proof only)
    CVEs: 2 affected (1 critical) · feed 3h ago    red when any is critical,
                                                   amber otherwise
    CVEs: unknown · feed 30h old                   amber  (the default)
Its freshness is never dropped either: when space is short the counts go
first (threat-list counts, then the CVE counts), never a freshness.
The CLEAR/AFFECTED/UNKNOWN rule mirrors stillrunning.cve.evaluate (this
file must stay json/os/sys/time only); a test keeps the two in step.
"""
import json
import os
import sys
import time

SHIELD = "\U0001F6E1"
FALLBACK = f"{SHIELD} stillrunning · on guard · no installs checked yet"


def _age(seconds):
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{int(seconds // 60)}m ago"
    if seconds < 172800:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


CVE_FRESH_S = 24 * 3600
CVE_FUTURE_S = 120
_SEVERITIES = ("LOW", "MODERATE", "HIGH", "CRITICAL", "MALICIOUS")
_PART_KINDS = ("project file", "installed", "search")
_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _chars(text, extra, first=_ALNUM, most=214):
    return (isinstance(text, str) and 0 < len(text) <= most and text[0] in first
            and all(c in _ALNUM + extra for c in text))


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _num(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _vuln_ok(v):
    if not isinstance(v, dict):
        return False
    vid = v.get("id")
    head = vid.split("-", 1)[0] if isinstance(vid, str) else ""
    return (_chars(vid, "-._:", first="ABCDEFGHIJKLMNOPQRSTUVWXYZ", most=77) and "-" in vid
            and _chars(head, "", first="ABCDEFGHIJKLMNOPQRSTUVWXYZ", most=16)
            and (v.get("severity") is None or v.get("severity") in _SEVERITIES))


def _affected_ok(a):
    return (isinstance(a, dict) and a.get("eco") in ("pip", "npm")
            and _chars(a.get("name"), "._~-@/", first=_ALNUM + "@")
            and _chars(a.get("version"), "._+!-", most=64)
            and isinstance(a.get("vulns"), list) and a["vulns"]
            and all(_vuln_ok(v) for v in a["vulns"]))


def _part_ok(p):
    return (isinstance(p, dict) and _chars(p.get("part"), " ._/@+-", most=120)
            and p.get("kind") in _PART_KINDS and _int(p.get("resolved"))
            and _int(p.get("unresolved"))
            and (p.get("why") is None or isinstance(p.get("why"), str)))


def cve_segment(path=None, now=None, cwd=None):
    """→ (state, detail, freshness, compact detail) for the folder `cwd`, or
    None when CVE monitoring is not set up (no state file). The state comes
    from the saved details, never from the saved summary alone; anything odd
    is UNKNOWN."""
    path = path or os.path.join(os.path.expanduser("~"), ".stillrunning", "cve_state.json")
    now = time.time() if now is None else now
    root = os.path.realpath(cwd or os.getcwd())
    unreadable = ("UNKNOWN", "unknown", "state unreadable", "unknown")
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except FileNotFoundError:
        return None                 # CVE monitoring not set up: no segment
    except (OSError, ValueError):
        return unreadable
    if not (isinstance(doc, dict) and doc.get("schema") == 2
            and isinstance(doc.get("projects"), dict)):
        return unreadable
    entry = doc["projects"].get(root)
    if not isinstance(entry, dict) or entry.get("root") != root:
        return "UNKNOWN", "unknown", "checked for another folder", "unknown"
    try:
        inv, chk, summary = entry["inventory"], entry["check"], entry["summary"]
        affected, parts = entry["affected"], inv["parts"]
        failures, resolved, not_checked = chk["failures"], inv["resolved"], chk["not_checked"]
        feed, refreshed = entry.get("feed_updated_at"), entry.get("refreshed_at")
        if not (entry.get("schema") == 2 and isinstance(summary, dict)
                and isinstance(affected, list) and isinstance(parts, list)
                and isinstance(failures, list) and _int(resolved) and _int(not_checked)
                and (feed is None or _num(feed)) and _num(refreshed)):
            raise TypeError
    except (KeyError, TypeError, AttributeError):
        return unreadable
    good = [a for a in affected if _affected_ok(a)]
    counts = {"affected_packages": len(good),
              "critical": sum(1 for a in good if any(v.get("severity") == "CRITICAL"
                                                     for v in a["vulns"])),
              "malicious": sum(1 for a in good if any(v.get("severity") == "MALICIOUS"
                                                      for v in a["vulns"]))}
    inv_body = (bool(parts) and all(_part_ok(p) for p in parts)
                and sum(p["unresolved"] for p in parts) == 0)
    chk_body = not_checked == 0 and not failures
    consistent = (len(good) == len(affected) and all(_part_ok(p) for p in parts)
                  and all(isinstance(f, str) for f in failures)
                  and (inv.get("complete") is True) == inv_body
                  and (chk.get("complete") is True) == chk_body
                  and all(summary.get(k) == n for k, n in counts.items())
                  and summary.get("inventory_complete") is inv_body
                  and summary.get("check_complete") is chk_body
                  and resolved <= sum(p["resolved"] for p in parts if _part_ok(p))
                  and (resolved == 0) == (sum(p["resolved"] for p in parts if _part_ok(p)) == 0)
                  and (feed is None or feed <= refreshed + CVE_FUTURE_S))
    if not consistent:
        return "UNKNOWN", "unknown", "state inconsistent", "unknown"
    if any(t is not None and t > now + CVE_FUTURE_S for t in (feed, refreshed)):
        return "UNKNOWN", "unknown", "feed time in the future", "unknown"
    if feed is None:
        fresh, stale = "feed unreachable", True
    else:
        age = max(0.0, now - feed)
        stale = age > CVE_FRESH_S
        fresh = f"feed {int(age // 3600)}h old" if stale else "feed " + _age(age)
    if counts["affected_packages"]:
        bits = [f"{counts[k]} {k}" for k in ("critical", "malicious") if counts[k]]
        if not bits:
            worst = max((v.get("severity") for a in good for v in a["vulns"]),
                        key=lambda w: _SEVERITIES.index(w) + 1 if w else 0)
            bits = ["worst " + (worst.lower() if worst else "unknown")]
        red = counts["critical"] or counts["malicious"]
        return ("AFFECTED_CRITICAL" if red else "AFFECTED",
                f"{counts['affected_packages']} affected ({', '.join(bits)})", fresh, "affected")
    if resolved == 0:
        return "UNKNOWN", "unknown (nothing to check)", fresh, "unknown"
    if stale or not inv_body or not chk_body:
        detail = "unknown" if stale or (inv_body and chk_body) else "unknown (not all checked)"
        return "UNKNOWN", detail, fresh, "unknown"
    return "CLEAR", "clear", fresh, "clear"


def _piece(text, code, color):
    return (f"\033[{code}m{text}\033[0m" if color and code else text), len(text)


def _cve_pieces(segment, color):
    """→ (full piece, piece without counts, freshness piece). Green only for
    CLEAR; red when a critical is among the affected; amber otherwise."""
    state, detail, fresh, compact = segment
    code = {"CLEAR": "32", "AFFECTED_CRITICAL": "1;31"}.get(state, "33")
    old = state != "CLEAR" and not fresh.endswith("ago")
    return (_piece("CVEs: " + detail, code, color), _piece("CVEs: " + compact, code, color),
            _piece(fresh, "33" if old else "", color))


def _width():
    """Columns available, when the caller says (COLUMNS); else None."""
    try:
        cols = int(os.environ.get("COLUMNS", ""))
    except ValueError:
        return None
    return cols if cols >= 20 else None


def render(path=None, now=None, color=None, width=None, cve_path=None, cwd=None):
    path = path or os.path.join(os.path.expanduser("~"), ".stillrunning", "hook_stats.json")
    now = time.time() if now is None else now
    color = (not os.environ.get("NO_COLOR")) if color is None else color
    width = _width() if width is None else width
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        today = data.get("date") == time.strftime("%Y-%m-%d", time.localtime(now))
        checked = int(data.get("checked", 0)) if today else 0
        blocked = int(data.get("blocked", 0)) if today else 0
        unverified = int(data.get("unverified", 0)) if today else 0
        # written by newer hooks only; None = this file predates the counter
        ok = (int(data["ok"]) if today else 0) if "ok" in data else None
        feed_age = data.get("feed_age_h")
        feed_seen = float(data.get("feed_seen_ts", 0))
    except (OSError, ValueError, TypeError, AttributeError):
        segment = cve_segment(cve_path, now, cwd)
        if not segment:
            return FALLBACK
        cve, _, age = _cve_pieces(segment, color)
        return " · ".join([FALLBACK, cve[0], age[0]])

    def piece(text, code=""):
        """(what to print, how many cells it takes)."""
        return _piece(text, code, color)

    if isinstance(feed_age, (int, float)) and not isinstance(feed_age, bool) and feed_seen:
        seconds = float(feed_age) * 3600 + max(0.0, now - feed_seen)
        fresh = piece("list updated " + ("<1h ago" if seconds < 3600 else _age(seconds)),
                      "33" if seconds > 86400 else "")
    else:
        fresh = piece("list age unknown", "33")
    head = piece(f"{SHIELD} stillrunning", "1;31" if blocked else ("33" if unverified else "32"))

    # shown in this order; when space is short the first is dropped first
    counts = []
    if ok:
        counts.append(piece(f"{ok} no known threat", "32"))
    elif ok is None and checked:
        counts.append(piece(f"{checked} checked"))
    if unverified:
        counts.append(piece(f"{unverified} couldn't check", "33"))
    if blocked:
        counts.append(piece(f"{blocked} blocked", "1;31"))
    if not counts:
        counts.append(piece("nothing to check yet"))

    segment = cve_segment(cve_path, now, cwd)
    cve_full, cve_short, cve_age = _cve_pieces(segment, color) if segment else ((), (), ())

    def build(kept, cve):
        parts = [head, fresh] + kept
        if kept:
            parts[2] = ("today: " + kept[0][0], kept[0][1] + 7)
        if segment:
            parts += [cve, cve_age]
        text = " · ".join(p[0] for p in parts)
        cells = sum(p[1] for p in parts) + 3 * (len(parts) - 1) + 1   # the shield is two cells
        return text, cells

    cve = cve_full
    text, cells = build(counts, cve)
    # counts go first (threat list, then CVE); neither freshness is ever dropped
    while width and cells > width and (counts or (segment and cve is cve_full)):
        if counts:
            counts = counts[1:]
        else:
            cve = cve_short
        text, cells = build(counts, cve)
    return text


def _cwd_from_stdin():
    """Claude Code hands the status line a JSON object on stdin that names the
    project folder; the CVE segment answers for that folder."""
    try:
        if sys.stdin is None or sys.stdin.isatty():
            return None
        data = json.loads(sys.stdin.read(200_000) or "{}")
        space = data.get("workspace") if isinstance(data.get("workspace"), dict) else {}
        for value in (space.get("project_dir"), space.get("current_dir"), data.get("cwd")):
            # Windows folders (C:\\…) were ignored, so the line was built for the
            # wrong folder there; POSIX keeps exactly the old test.
            if isinstance(value, str) and (value.startswith("/") or (os.name == "nt" and os.path.isabs(value))):
                return value
    except (OSError, ValueError, AttributeError):
        return None
    return None


def _safe_script_streams():
    """The bare-script path (`python -I -S <this file>`, how Claude Code runs it)
    cannot import the package, so the entry points' make_output_safe() never ran
    here: on a Windows code page a non-ASCII warning (→, —) raised
    UnicodeEncodeError and crashed the process (found on a real windows-latest
    runner 2026-11-21). What reads these streams is Claude Code, which decodes
    them as UTF-8 — so a stream that is not UTF-8 is switched to UTF-8 (the
    status line's 🛡 arrives as 🛡, not as an ASCII tag). Windows only: on
    Linux and macOS nothing here runs, in any locale, so their output is
    exactly what it was."""
    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        name = (getattr(stream, "encoding", "") or "").lower().replace("-", "").replace("_", "")
        if name in ("utf8", "utf8sig"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            try:
                stream.reconfigure(errors="backslashreplace")
            except (AttributeError, ValueError, OSError):
                continue


if __name__ == "__main__":
    _safe_script_streams()
    try:
        sys.stdout.write(render(cwd=_cwd_from_stdin()) + "\n")
    except Exception:  # a status line must never print a traceback into the UI
        sys.stdout.write(FALLBACK + "\n")
