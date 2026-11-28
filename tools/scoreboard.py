"""Attack-suite scoreboard.

  scoreboard.py eval  --tree DIR                       → JSON: each probe caught or not, each control
  scoreboard.py row   --tree DIR | --eval-json F  --commit SHA --date D [--corpus-base B --corpus-head H]
                      [--fuzz-base B --fuzz-head H] [--tests "N passed, M failed"] [--append FILE]
  scoreboard.py check --tree DIR [--board docs/scoreboard.jsonl]
  scoreboard.py md    [--board docs/scoreboard.jsonl] [--out docs/scoreboard.md]

Probe strings are only ever passed to stillrunning.claude_hook.touches_protection()
in a process with a temporary HOME and every socket refused: nothing is run by a
shell. Run eval/row on machines you care about only inside the sandbox container.
The corpus and fuzz inputs are private; a row keeps only their counts."""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE = os.path.join(os.path.dirname(HERE), "tests", "attack_suite")
BOARD = os.path.join(os.path.dirname(HERE), "docs", "scoreboard.jsonl")


def _load(name):
    with open(os.path.join(SUITE, name), encoding="utf-8") as f:
        return json.load(f)


# ───────────────────────────── eval (child process) ─────────────────────────────
def _eval_here(tree):
    """Runs in a fresh process: imports stillrunning from `tree`."""
    import socket

    def refuse(*a, **k):
        raise OSError("the attack suite never uses the network")
    socket.socket.connect = refuse
    socket.socket.connect_ex = refuse
    socket.create_connection = refuse
    home = tempfile.mkdtemp(prefix="attack-home-")
    os.environ.update(HOME=home, USERPROFILE=home, STILLRUNNING_CVE_CHECK="0",
                      STILLRUNNING_NO_TELEMETRY="1")
    for sub in (".claude", ".stillrunning", "proj/.claude"):
        os.makedirs(os.path.join(home, sub), exist_ok=True)
    for name in (".claude/settings.json", ".claude/settings.local.json", "proj/.claude/settings.local.json",
                 ".stillrunning/config.json"):
        with open(os.path.join(home, name), "w") as f:
            f.write("{}")
    sys.path.insert(0, os.path.abspath(tree))
    from stillrunning import claude_hook as ch
    pkg = os.path.dirname(os.path.abspath(ch.__file__))
    has_blocklist = os.path.exists(os.path.join(pkg, "offline_blocklist.py"))

    def judge(command):
        command = command.replace("{PKG}", pkg)
        try:
            return bool(ch.touches_protection(command, cwd=home))
        except Exception as exc:                       # a crash is reported, never hidden
            return "error: %s" % type(exc).__name__

    probes = {}
    for p in _load("probes.json")["probes"]:
        if not has_blocklist and "blocklist" in p["command"]:
            probes[p["id"]] = "n/a"                     # the command did not exist yet
        else:
            probes[p["id"]] = judge(p["command"])
    controls = {c["id"]: judge(c["command"]) for c in _load("controls.json")["controls"]}
    return {"probes": probes, "controls": controls}


def evaluate(tree):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "_eval_child", "--tree", tree],
                         capture_output=True, text=True, env=env, timeout=900)
    if out.returncode != 0:
        raise SystemExit("eval failed:\n" + out.stderr[-2000:])
    return json.loads(out.stdout.strip().splitlines()[-1])


# ───────────────────────────── one row ─────────────────────────────
def summarize(result):
    probes = _load("probes.json")["probes"]
    controls = _load("controls.json")["controls"]
    by_cat, caught_ids, open_limits, na, errors = {}, [], 0, 0, []
    for p in probes:
        got = result["probes"].get(p["id"])
        if got == "n/a":
            na += 1
            continue
        if isinstance(got, str):
            errors.append(p["id"])
        hit = got is True
        cat = by_cat.setdefault(p["category"], [0, 0])
        cat[1] += 1
        cat[0] += hit
        if hit:
            caught_ids.append(p["id"])
        elif p["status"] == "known-limit":
            open_limits += 1
    must = [c for c in controls if c["kind"] == "must-allow"]
    debt = [c for c in controls if c["kind"] == "false-ask-debt"]
    asked = lambda c: result["controls"].get(c["id"]) is not False          # noqa: E731
    return {
        "probes": {"caught": len(caught_ids), "total": len(probes) - na, "not_applicable": na,
                   "by_category": dict(sorted(by_cat.items())), "errors": errors},
        "known_limits_open": open_limits,
        "controls": {"must_allow_passing": sum(not asked(c) for c in must), "must_allow_total": len(must),
                     "false_ask_debt": sum(asked(c) for c in debt), "debt_items": len(debt),
                     "must_allow_failing_ids": [c["id"] for c in must if asked(c)]},
        "caught_ids": sorted(caught_ids),
    }


def corpus_counts(base, head):
    if not (base and head):
        return None
    a = [json.loads(line) for line in open(base, encoding="utf-8")]
    b = [json.loads(line) for line in open(head, encoding="utf-8")]
    if len(a) != len(b):
        raise SystemExit("corpus runs differ in length")
    out = {"events": len(a), "allow_to_ask": 0, "ask_to_allow": 0, "deny_changes": 0, "other_changes": 0}
    for x, y in zip(a, b):
        dx, dy = x.get("decision"), y.get("decision")
        if dx == dy:
            continue
        if (dx, dy) == ("allow", "ask"):
            out["allow_to_ask"] += 1
        elif (dx, dy) == ("ask", "allow"):
            out["ask_to_allow"] += 1
        elif "deny" in (dx, dy):
            out["deny_changes"] += 1
        else:
            out["other_changes"] += 1
    return out


def fuzz_counts(base, head):
    if not head:
        return None
    key = lambda p: {(x["invariant"], x["bucket"]) for x in json.load(open(p, encoding="utf-8"))["failed"]}  # noqa
    h = key(head)
    out = {"failing_buckets": len(h)}
    if base:
        b = key(base)
        out.update(new_vs_base=len(h - b), fixed_vs_base=len(b - h))
    return out


def tests_counts(text):
    if not text:
        return None
    import re
    out = {}
    for n, word in re.findall(r"(\d+) (passed|failed|skipped|xfailed|deselected|errors?)", text):
        out[word] = int(n)
    return out


def review_for(commit):
    try:
        reviews = _load("reviews.json")["reviews"]
    except FileNotFoundError:
        return None
    for r in reviews:
        if commit.startswith(r["commit"]) or r["commit"].startswith(commit):
            return {k: r[k] for k in ("review", "verdict", "important", "pre_existing", "nits") if k in r}
    return None


def make_row(args):
    row = {"commit": args.commit[:7], "date": args.date}
    if args.eval_json:                 # computed earlier, in the sandbox
        with open(args.eval_json, encoding="utf-8") as f:
            result = json.load(f)
    else:
        result = evaluate(args.tree)
    row.update(summarize(result))
    row["corpus_vs_base"] = corpus_counts(args.corpus_base, args.corpus_head)
    row["fuzz"] = fuzz_counts(args.fuzz_base, args.fuzz_head)
    row["tests"] = tests_counts(args.tests)
    row["review"] = review_for(args.commit)
    return row


# ───────────────────────────── the gate ─────────────────────────────
def check(tree, board):
    rows = [json.loads(line) for line in open(board, encoding="utf-8") if line.strip()]
    if not rows:
        raise SystemExit("no scoreboard rows to compare with")
    now = summarize(evaluate(tree))
    ever = set().union(*(set(r["caught_ids"]) for r in rows))
    lost = sorted(ever - set(now["caught_ids"]))
    probes = {p["id"]: p for p in _load("probes.json")["probes"]}
    last = rows[-1]
    problems = []
    for pid in lost:
        if pid in probes:
            problems.append("probe caught before, now allowed: %s  %s" % (pid, probes[pid]["command"]))
    if now["controls"]["must_allow_passing"] < last["controls"]["must_allow_passing"]:
        problems.append("must-allow controls dropped: %d → %d (now asking: %s)" % (
            last["controls"]["must_allow_passing"], now["controls"]["must_allow_passing"],
            ", ".join(now["controls"]["must_allow_failing_ids"])))
    if now["controls"]["false_ask_debt"] > last["controls"]["false_ask_debt"]:
        problems.append("false-ask debt went up: %d → %d" % (last["controls"]["false_ask_debt"],
                                                             now["controls"]["false_ask_debt"]))
    if now["probes"]["errors"]:
        problems.append("the hook raised on probes: " + ", ".join(now["probes"]["errors"]))
    print("probes caught %d/%d · must-allow %d/%d · false-ask debt %d (last row %s: %d/%d · %d/%d · %d)" % (
        now["probes"]["caught"], now["probes"]["total"], now["controls"]["must_allow_passing"],
        now["controls"]["must_allow_total"], now["controls"]["false_ask_debt"], last["commit"],
        last["probes"]["caught"], last["probes"]["total"], last["controls"]["must_allow_passing"],
        last["controls"]["must_allow_total"], last["controls"]["false_ask_debt"]))
    for p in problems:
        print("FAIL:", p)
    return 1 if problems else 0


# ───────────────────────────── markdown ─────────────────────────────
def markdown(board):
    rows = [json.loads(line) for line in open(board, encoding="utf-8") if line.strip()]
    cats = sorted({c for r in rows for c in r["probes"]["by_category"]})
    head = ["commit", "date", "probes caught", "known limits open", "must-allow", "false-ask debt",
            "corpus allow→ask", "ask→allow", "deny changes", "fuzz buckets", "tests passed / failed",
            "review"] + cats
    out = ["# Attack-suite scoreboard", "",
           "Generated by `tools/scoreboard.py md` from `docs/scoreboard.jsonl`. Probes: "
           "`tests/attack_suite/probes.json` (each a bypass a review found); controls: "
           "`tests/attack_suite/controls.json`. Corpus and fuzz counts come from private inputs "
           "run in the sandbox; only the counts are kept. A probe for a command the commit did "
           "not have yet (`blocklist …` before the offline list existed) is not counted.", "",
           "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        c, k = r.get("corpus_vs_base") or {}, r["controls"]
        t, rv, f = r.get("tests") or {}, r.get("review") or {}, r.get("fuzz") or {}
        cells = [r["commit"], r["date"], "%d/%d" % (r["probes"]["caught"], r["probes"]["total"]),
                 str(r["known_limits_open"]), "%d/%d" % (k["must_allow_passing"], k["must_allow_total"]),
                 "%d/%d" % (k["false_ask_debt"], k["debt_items"]),
                 str(c.get("allow_to_ask", "–")), str(c.get("ask_to_allow", "–")), str(c.get("deny_changes", "–")),
                 str(f.get("failing_buckets", "–")),
                 "%s / %s" % (t.get("passed", "–"), t.get("failed", "–")),
                 ("%s %s (%s important)" % (rv["review"], rv["verdict"], rv.get("important", "?"))) if rv else "–"]
        for cat in cats:
            got = r["probes"]["by_category"].get(cat)
            cells.append("%d/%d" % tuple(got) if got else "–")
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["eval", "row", "check", "md", "_eval_child"])
    ap.add_argument("--tree", default=os.path.dirname(HERE))
    ap.add_argument("--commit")
    ap.add_argument("--date")
    ap.add_argument("--corpus-base")
    ap.add_argument("--corpus-head")
    ap.add_argument("--fuzz-base")
    ap.add_argument("--fuzz-head")
    ap.add_argument("--tests")
    ap.add_argument("--append")
    ap.add_argument("--eval-json")
    ap.add_argument("--board", default=BOARD)
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    if args.action == "_eval_child":
        print(json.dumps(_eval_here(args.tree)))
        return 0
    if args.action == "eval":
        print(json.dumps(evaluate(args.tree), indent=1))
        return 0
    if args.action == "row":
        row = make_row(args)
        line = json.dumps(row, sort_keys=True)
        print(line)
        if args.append:
            with open(args.append, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return 0
    if args.action == "check":
        return check(args.tree, args.board)
    text = markdown(args.board)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
