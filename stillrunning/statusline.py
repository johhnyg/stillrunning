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
no file = the feature is not set up = no segment):
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


def cve_segment(path=None, now=None):
    """→ (state, detail, freshness, compact detail)."""
    path = path or os.path.join(os.path.expanduser("~"), ".stillrunning", "cve_state.json")
    now = time.time() if now is None else now
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except FileNotFoundError:
        return None                 # CVE monitoring not set up: no segment
    except (OSError, ValueError):
        return "UNKNOWN", "unknown", "state unreadable", "unknown"
    try:
        summary = doc["summary"]
        affected, critical = summary["affected_packages"], summary["critical"]
        worst = summary.get("worst")
        for n in (affected, critical):
            if isinstance(n, bool) or not isinstance(n, int) or n < 0:
                raise TypeError
        feed = doc.get("feed_updated_at")
        if feed is not None and (isinstance(feed, bool) or not isinstance(feed, (int, float))):
            raise TypeError
        complete = summary["inventory_complete"] is True and summary["check_complete"] is True
    except (KeyError, TypeError, AttributeError):
        return "UNKNOWN", "unknown", "state unreadable", "unknown"
    if feed is None:
        fresh, stale = "feed unreachable", True
    else:
        age = max(0.0, now - feed)
        stale = age > CVE_FRESH_S
        fresh = f"feed {int(age // 3600)}h old" if stale else "feed " + _age(age)
    if affected:
        sev = (f"{critical} critical" if critical else
               "worst " + (worst.lower() if worst in ("LOW", "MODERATE", "HIGH") else "unknown"))
        return ("AFFECTED_CRITICAL" if critical else "AFFECTED",
                f"{affected} affected ({sev})", fresh, "affected")
    if stale or not complete:
        detail = "unknown" if complete or stale else "unknown (not all checked)"
        return "UNKNOWN", detail, fresh, "unknown"
    return "CLEAR", "clear", fresh, "clear"


def _piece(text, code, color):
    return (f"\033[{code}m{text}\033[0m" if color and code else text), len(text)


def _cve_pieces(segment, color):
    """→ (full piece, piece without counts, freshness piece). Green only for
    CLEAR; red when a critical is among the affected; amber otherwise."""
    state, detail, fresh, compact = segment
    code = {"CLEAR": "32", "AFFECTED_CRITICAL": "1;31"}.get(state, "33")
    old = any(word in fresh for word in ("old", "unreach", "unreadable"))
    return (_piece("CVEs: " + detail, code, color), _piece("CVEs: " + compact, code, color),
            _piece(fresh, "33" if old else "", color))


def _width():
    """Columns available, when the caller says (COLUMNS); else None."""
    try:
        cols = int(os.environ.get("COLUMNS", ""))
    except ValueError:
        return None
    return cols if cols >= 20 else None


def render(path=None, now=None, color=None, width=None, cve_path=None):
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
        segment = cve_segment(cve_path, now)
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

    segment = cve_segment(cve_path, now)
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


if __name__ == "__main__":
    try:
        sys.stdout.write(render() + "\n")
    except Exception:  # a status line must never print a traceback into the UI
        sys.stdout.write(FALLBACK + "\n")
