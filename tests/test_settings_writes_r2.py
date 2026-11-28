"""PR #9 review findings A–I: more writes to Claude Code's settings that must ask,
and the reads the first version wrongly asked about."""
import pytest

from stillrunning import claude_hook as ch


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    for name in ("settings.json", "settings.local.json"):
        (home / ".claude" / name).write_text("{}")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("STILLRUNNING_CVE_CHECK", "0")
    return home


S = "~/.claude/settings.json"
WRITES = [
    # A: options with a value before uniq's / xxd's IN OUT
    "uniq -f 1 /tmp/x " + S, "uniq -s 2 /tmp/x " + S, "uniq -w 9 /tmp/x " + S,
    "uniq --skip-fields 1 /tmp/x " + S,
    "xxd -r -s 0 /tmp/x " + S, "xxd -c 16 /tmp/x " + S, "xxd -l 9 -r /tmp/x " + S,
    "xxd -r -p -c 64 /tmp/x " + S, "xxd -o 0 -r /tmp/x " + S, "xxd -n name -i /tmp/x " + S,
    "xxd -cols 8 /tmp/x " + S,
    # B: tree's -o inside a cluster
    "tree -ao " + S + " /tmp", "tree -Co " + S + " /tmp", "tree -oJ " + S + " /tmp",
    # C: Python yq's spelling
    "yq --in-place . " + S, "yq -i . " + S,
    # D: find -exec running a read-only program that writes
    "find ~/.claude -name settings.json -exec yq -i .a=1 {} \\;",
    "find ~/.claude -name settings.json -exec yq --inplace .a=1 {} +",
    "find ~/.claude -name settings.json -execdir yq -i .a=1 {} \\;",
    "find ~/.claude -name settings.json -exec sort -o {} {} \\;",
    "find ~/.claude -name settings.json -exec uniq {} {} \\;",
    "find /etc/hostname -exec sort -o " + S + " {} \\;",
    "find /tmp/x -exec uniq {} " + S + " \\;", "find /tmp/x -exec xxd -r {} " + S + " \\;",
    "find /tmp -exec tree -o " + S + " /tmp \\;",
    "cd ~/.claude && find . -name settings.json -exec yq -i . {} \\;",
    # E: xargs handing the names to yq -i
    "echo " + S + " | xargs yq -i .a=1", "ls " + S + " | xargs yq -i .a=1",
    "find ~/.claude -name settings.json | xargs yq -i .a=1",
    "find ~/.claude -name settings.json -print0 | xargs -0 yq -i .a=1",
    # F: cp -t / install -t
    "cp -t ~/.claude /tmp/settings.json", "cp -rt ~/.claude /tmp/settings.json",
    "cp -t ~/.claude/ /tmp/settings.local.json", "install -t ~/.claude /tmp/settings.json",
    "cp --target-directory ~/.claude /tmp/settings.json",
    "rsync -t /tmp/settings.json ~/.claude/", "rsync -avt /tmp/x " + S, "scp -t /tmp/x " + S,
    # G: read-write redirections
    "echo {} 1<> " + S, "echo {} 1<>HOME/.claude/settings.json", "exec 1<> " + S, "exec 3<> " + S,
    # H: sed's w command and s///w flag
    "sed 'w HOME/.claude/settings.json' /tmp/x", "sed -n 'w HOME/.claude/settings.json' /tmp/x",
    "sed 's/a/b/w HOME/.claude/settings.json' /tmp/x", "sed -e '$w HOME/.claude/settings.json' /tmp/x",
    "sed -s 'W HOME/.claude/settings.json' /tmp/x", "sed -ne 'w HOME/.claude/settings.json' /tmp/x",
    # I: git output options
    "git diff --output " + S, "git show HEAD:settings.json --output " + S,
    "git archive -o " + S + " HEAD", "git config -f " + S + " a.b c", "git config --file " + S + " a.b c",
]
READS = [
    # the false asks of PR #9's first version
    "uniq -f 1 " + S, "uniq -w 2 " + S, "xxd -l 64 " + S, "xxd -c 16 " + S, "xxd -s 0 " + S,
    "xxd -g 1 " + S, "xxd -len 8 " + S, "yq -oini . " + S, "yq -o json . " + S,
    # ordinary reads that must stay allowed
    "sed -n p " + S, "sed -n '/www/p' " + S, "sed -n p ~/work/.claude/settings.json",
    "git diff ~/.claude", "git log -o /tmp/x", "cp " + S + " /tmp/backup.json", "cp -t /tmp " + S,
    "find ~/.claude -name settings.json -exec cat {} \\;", "find ~/.claude | xargs grep hook",
    "tree -a ~/.claude", "tree -L 2 ~/.claude", "cat <> /tmp/x", "echo hi 1<> /tmp/x",
]


def _fill(command, home):
    return command.replace("HOME/", str(home) + "/")


@pytest.mark.parametrize("command", WRITES)
def test_pr9_review_writes_ask(home, command):
    command = _fill(command, home)
    assert ch.touches_protection(command, cwd=str(home)), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", READS)
def test_pr9_review_reads_do_not_ask(home, command):
    command = _fill(command, home)
    assert not ch.touches_protection(command, cwd=str(home)), command
