"""`stillrunning shield` — a report card built from the Claude Code hook's
local counter file and decisions log. No network, no model: it only shows
what the hook already recorded.

`--json` prints the same data for other front ends. Shape (schema 1; fields
are only ever added, never renamed or removed):

    {
      "schema": 1,
      "generated_at": <unix seconds>,
      "has_data": true | false,
      "hook": "active" | "legacy" | "absent" | "unreadable",
      "today": {"checked": int, "blocked": int, "needs_approval": int} | null,
      "week":  {"checked": int, "blocked": int, "needs_approval": int,
                "days_with_data": int} | null,
      "blocklist": {"size": int | null, "age_hours": float | null},
      "decisions": [            # newest first
        {"v": 1, "ts": <unix seconds>,
         "verdict": "no_known_threat" | "blocked" | "needs_approval" | "override" | "note",
         "subject": str, "eco": "pip" | "npm" | null, "name": str | null,
         "version": str | null, "ms": int | null,
         "evidence": [{"check": str,
                       "status": "found" | "nothing_found" | "not_checked" | "info",
                       "text": str}],
         "explanation": str | null}
      ],
      "glossary": {"<term>": "<one sentence>"}   # only terms used above
    }

The text report adds one line on known vulnerabilities (`stillrunning cve`).

`today` and `week` are null — not zeros — when nothing has been recorded.
"""
import json
import os
import sys
import textwrap
import time

from . import claude_hook

WIDTH = 80
MARK = {"no_known_threat": ("✓", "32"), "blocked": ("✗", "1;31"),
        "needs_approval": ("⚠", "33"), "override": ("·", "2"), "note": ("·", "2")}


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _read_decisions(path, limit):
    records = []
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return records
    for line in reversed(lines):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("verdict") in MARK:
            records.append(record)
        if len(records) >= limit:
            break
    return records


def collect(now=None, limit=8):
    """The report as plain data (the `--json` payload)."""
    now = time.time() if now is None else now
    stats = _read_json(claude_hook.stats_path())
    decisions = _read_decisions(claude_hook.decisions_path(), limit)
    has_data = bool(stats and isinstance(stats.get("days"), dict) and stats["days"]) or bool(decisions)
    today = week = None
    blocklist = {"size": None, "age_hours": None}
    if has_data and stats:
        days = stats.get("days") if isinstance(stats.get("days"), dict) else {}

        def total(keys):
            out = {"checked": 0, "blocked": 0, "needs_approval": 0}
            for key in keys:
                day = days.get(key) if isinstance(days.get(key), dict) else {}
                out["checked"] += int(day.get("checked", 0))
                out["blocked"] += int(day.get("blocked", 0))
                out["needs_approval"] += int(day.get("unverified", 0))
            return out

        last7 = [time.strftime("%Y-%m-%d", time.localtime(now - 86400 * i)) for i in range(7)]
        today = total(last7[:1])
        week = total(last7)
        week["days_with_data"] = sum(1 for key in last7 if key in days)
        size = stats.get("feed_size")
        if isinstance(size, int) and not isinstance(size, bool) and size > 0:
            blocklist["size"] = size
        age, seen = stats.get("feed_age_h"), stats.get("feed_seen_ts")
        if isinstance(age, (int, float)) and isinstance(seen, (int, float)):
            blocklist["age_hours"] = round(float(age) + max(0.0, now - seen) / 3600, 1)
    elif has_data:
        today = week = None
    text = " ".join([r.get("subject") or "" for r in decisions]
                    + [e.get("text", "") for r in decisions for e in r.get("evidence") or []]
                    + [r.get("explanation") or "" for r in decisions]
                    + [claude_hook.VERDICT_LABEL.get(r["verdict"], "") for r in decisions]).lower()
    if blocklist["size"]:
        text += " blocklist"
    glossary = {term: meaning for term, meaning in claude_hook.GLOSSARY.items() if term in text}
    return {"schema": 1, "generated_at": now, "has_data": has_data,
            "hook": claude_hook.installed_state(), "today": today, "week": week,
            "blocklist": blocklist, "decisions": decisions, "glossary": glossary}


def _cve(now):
    """One line on known vulnerabilities, from the saved state (no network)."""
    try:
        from . import cve
        data = cve.load(now)
        return {"state": data["state"], "line": cve.headline(data)}
    except Exception as exc:     # the report card must still print
        claude_hook._warn(f"shield: CVE state could not be read ({type(exc).__name__})")
        return {"state": "UNKNOWN", "line": "CVEs · unknown · state unreadable"}


def _wrap(text, indent, width):
    return textwrap.wrap(text, width=width, initial_indent=indent,
                         subsequent_indent=" " * len(indent)) or [indent.rstrip()]


def render(data, color=False, width=WIDTH):
    """The terminal report. Every line fits `width` columns with colour off."""
    def paint(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    now = data["generated_at"]
    cve_line = _cve(now)["line"]
    out = [f"{claude_hook.SHIELD}  stillrunning shield · "
           + time.strftime("%a %d %b %Y", time.localtime(now))]
    hook = {"active": "Claude Code hook: on",
            "legacy": "Claude Code hook: NOT active (old install) — run "
                      "`stillrunning --hook-claude-code`",
            "absent": "Claude Code hook: not installed — run `stillrunning --hook-claude-code`",
            "unreadable": "Claude Code hook: unknown (settings.json could not be read)"}[data["hook"]]
    if not data["has_data"]:
        out += ["", hook, cve_line, ""]
        out += _wrap("No installs have been checked yet, so there is nothing to report.", "", width)
        out += _wrap("This is not a result: nothing has been looked at. Counts appear here "
                     "after the first pip or npm install that Claude Code runs with the hook on.",
                     "", width)
        return "\n".join(out)

    inner = width - 4

    def row(text=""):
        return "│ " + text[:inner].ljust(inner) + " │"

    out.append("┌" + "─" * (width - 2) + "┐")
    if data["today"] is None:
        out.append(row("Counts: not available (the counter file could not be read)"))
    else:
        out.append(row(f"{'':<14}{'checked':>10}{'blocked':>10}{'needs approval':>17}"))
        for label, block in (("today", data["today"]), ("last 7 days", data["week"])):
            out.append(row(f"{label:<14}{block['checked']:>10}{block['blocked']:>10}"
                           f"{block['needs_approval']:>17}"))
    size, age = data["blocklist"]["size"], data["blocklist"]["age_hours"]
    size_text = f"{size:,} packages reported as malicious" if size else "size not reported yet"
    if age is None:
        age_text = "age not reported yet"
    elif age < 1:
        age_text = "updated within the last hour"
    else:
        age_text = f"updated about {int(age)}h ago"
    out.append(row(f"blocklist: {size_text} · {age_text}"))
    out.append(row(cve_line))
    out.append(row(hook))
    out.append("└" + "─" * (width - 2) + "┘")

    out.append("")
    if not data["decisions"]:
        out.append("Recent decisions: none recorded yet.")
    else:
        out.append("Recent decisions (newest first)")
    today = time.strftime("%Y-%m-%d", time.localtime(now))
    for record in data["decisions"]:
        mark, code = MARK[record["verdict"]]
        stamp = time.localtime(record.get("ts") or 0)
        when = time.strftime("%H:%M" if time.strftime("%Y-%m-%d", stamp) == today
                             else "%d %b %H:%M", stamp)
        label = claude_hook.VERDICT_LABEL[record["verdict"]]
        head = f" {mark} {label:<16}{record.get('subject') or ''}"
        head = head[:width - len(when) - 2].ljust(width - len(when) - 1) + when
        out.append(paint(head, code) if record["verdict"] != "no_known_threat" else
                   head.replace(mark, paint(mark, code), 1))
        if record.get("explanation"):
            out += _wrap(record["explanation"], "     ", width)
        for item in record.get("evidence") or []:
            out += _wrap(str(item.get("text", "")), "     • ", width)
    if data["glossary"]:
        out += ["", "Words used here"]
        for term, meaning in data["glossary"].items():
            out += _wrap(f"{term}: {meaning}.", "  ", width)
    out += [""] + _wrap("\"No known threat\" means the name is not on the blocklist. It is not a "
                        "guarantee: a brand-new harmful package may not be listed yet.", "", width)
    return "\n".join(out)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    limit = 8
    for i, arg in enumerate(argv):
        if arg in ("-n", "--last") and i + 1 < len(argv) and argv[i + 1].isdigit():
            limit = max(1, min(500, int(argv[i + 1])))
    data = collect(limit=limit)
    if "--json" in argv:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    print(render(data, color=color))
    return 0
