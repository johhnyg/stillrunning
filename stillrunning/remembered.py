"""Commands the person chose not to be asked about again.

    stillrunning remember last        remember the most recent "your call" command
    stillrunning remember <id>        remember one by the id the panel shows
    stillrunning remember --list      show what is remembered
    stillrunning forget <id>          stop remembering one
    stillrunning forget --all         stop remembering all of them

What a remembered command is: one exact command string in one exact folder.
The id is a hash of both; a single different character, or the same command
run somewhere else, is a different command and is asked about as usual.

What it is not: permission for a package. Every package a remembered command
names is still looked up every time, and a blocked one is still refused.
Only the hook decides whether a command may be remembered at all
(`can_remember` in its decision record): never a blocked or suspicious
package, never a lookup that failed, never a change to stillrunning's own
protection.

The file is ~/.stillrunning/remembered_commands.json, readable by its owner
only. An unreadable file means nothing is remembered: the hook asks.
"""

import hashlib
import json
import os
import sys
import time

from . import claude_hook

MAX_ENTRIES = 200


def path():
    return os.path.join(claude_hook._state_dir(), "remembered_commands.json")


def command_id(command, cwd):
    """The identity of one exact command in one exact folder."""
    exact = str(command or "").strip()
    where = os.path.realpath(cwd) if cwd else ""
    return hashlib.sha256((exact + "\0" + where).encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _load():
    try:
        with open(path(), encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        claude_hook._warn(f"remembered commands unreadable ({type(exc).__name__}) — none applied")
        return {}
    entries = data.get("commands") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        claude_hook._warn("remembered commands file has the wrong shape — none applied")
        return {}
    return {k: v for k, v in entries.items()
            if isinstance(k, str) and len(k) == 32 and isinstance(v, dict)}


def _save(entries):
    os.makedirs(claude_hook._state_dir(), mode=0o700, exist_ok=True)
    claude_hook._atomic_write(path(), json.dumps({"v": 1, "commands": entries}, indent=1))
    os.chmod(path(), 0o600)


def is_remembered(cmd_id):
    return isinstance(cmd_id, str) and cmd_id in _load()


def touch(cmd_id):
    """Count a use. Losing the count never changes a decision."""
    entries = _load()
    if cmd_id in entries:
        entries[cmd_id]["uses"] = int(entries[cmd_id].get("uses", 0)) + 1
        entries[cmd_id]["last_used"] = time.time()
        try:
            _save(entries)
        except OSError as exc:
            claude_hook._warn(f"could not update remembered commands ({type(exc).__name__})")


def _decisions():
    """Decision records, newest first."""
    try:
        with open(claude_hook.decisions_path(), encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


class Refused(Exception):
    """Why a command cannot be remembered, in plain words."""


def remember(which):
    """Remember the command of a past "your call" decision, by id or "last".
    → the stored entry. Raises Refused with the reason."""
    if not claude_hook.REMEMBER_ENABLED:
        raise Refused("Remembering commands is switched off in this version.")
    records = _decisions()
    if which == "last":
        record = next((r for r in records if r.get("verdict") == "needs_approval"), None)
        if record is None:
            raise Refused("There is no \"your call\" decision to remember yet.")
    else:
        matches = [r for r in records if isinstance(r.get("cmd_id"), str)
                   and r["cmd_id"].startswith(which) and len(which) >= 8]
        if not matches:
            raise Refused(f"No decision with id {which} was found (use at least 8 characters of the id).")
        if len({r["cmd_id"] for r in matches}) > 1:
            raise Refused(f"More than one command starts with {which}; give more of the id.")
        record = matches[0]
    cmd_id = record.get("cmd_id")
    if not (isinstance(cmd_id, str) and len(cmd_id) == 32):
        raise Refused("That decision was recorded before commands could be remembered. "
                      "Run the command once more, then remember it.")
    # every record of this command from its most recent run must agree
    newest = record.get("ts")
    same_run = [r for r in records if r.get("cmd_id") == cmd_id and r.get("ts") == newest]
    if not all(r.get("can_remember") is True for r in same_run):
        raise Refused("This one cannot be remembered: it involves a package that is blocked, "
                      "suspicious or could not be looked up, or it changes stillrunning's own "
                      "protection. You will be asked each time.")
    entries = _load()
    if cmd_id not in entries and len(entries) >= MAX_ENTRIES:
        raise Refused(f"{MAX_ENTRIES} commands are already remembered. Forget some first: "
                      "stillrunning remember --list")
    entry = entries.get(cmd_id) or {"added_at": time.time(), "uses": 0, "last_used": None}
    if not str(record.get("command") or "").strip():
        raise Refused("That decision has no command text recorded, so it cannot be shown to you "
                      "later. Run the command once more, then remember it.")
    # display only: the text is what the hook showed, with credentials removed;
    # the id above, not this text, is what a later command is matched against
    entry["command"] = str(record.get("command") or "")[:400]
    entry["subject"] = str(record.get("subject") or "")[:120]
    entries[cmd_id] = entry
    _save(entries)
    return dict(entry, id=cmd_id)


def list_all():
    entries = _load()
    return sorted((dict(v, id=k) for k, v in entries.items()),
                  key=lambda e: e.get("added_at") or 0, reverse=True)


def forget(which):
    """Forget one by id (8+ characters) or all with "all". → how many."""
    entries = _load()
    if which == "all":
        count = len(entries)
        _save({})
        return count
    hits = [k for k in entries if len(which) >= 8 and k.startswith(which)]
    for key in hits:
        del entries[key]
    if hits:
        _save(entries)
    return len(hits)


def _when(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "never"


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="stillrunning remember")
    parser.add_argument("action", choices=["remember", "forget"])
    parser.add_argument("which", nargs="?")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.action == "remember" and (args.list or not args.which):
        entries = list_all()
        if args.json:
            print(json.dumps({"schema": 1, "commands": entries}))
            return 0
        if not entries:
            print("No commands are remembered. You are asked about every \"your call\" command.")
            return 0
        print(f"{len(entries)} remembered command(s). Each applies only to that exact command "
              "in that exact folder;\npackages it names are still checked every time.\n")
        for e in entries:
            print(f"  {e['id'][:12]}  added {_when(e.get('added_at'))}  used {e.get('uses', 0)}x  "
                  f"last {_when(e.get('last_used'))}")
            print(f"      $ {e.get('command') or '(command text not recorded)'}")
        print("\nForget one: stillrunning forget <id>     Forget all: stillrunning forget --all")
        return 0
    if args.action == "remember":
        try:
            entry = remember(args.which)
        except Refused as exc:
            print(json.dumps({"ok": False, "reason": str(exc)}) if args.json else f"Not remembered. {exc}")
            return 1
        if args.json:
            print(json.dumps({"ok": True, "id": entry["id"]}))
        else:
            print(f"Remembered ({entry['id'][:12]}). You will not be asked again for this exact command:")
            print(f"  $ {entry['command']}")
            print("Packages it names are still checked every time. Undo: stillrunning forget "
                  + entry["id"][:12])
        return 0
    if not (args.all or args.which):
        print("Say which: stillrunning forget <id>   or   stillrunning forget --all")
        return 2
    count = forget("all" if args.all else args.which)
    print(json.dumps({"ok": True, "forgotten": count}) if args.json
          else (f"Forgot {count} command(s). You will be asked again." if count
                else "Nothing matched; nothing was forgotten."))
    return 0 if count or args.all else 1


if __name__ == "__main__":
    sys.exit(main())
