"""Any write to Claude Code's settings files asks, whatever the spelling.

`~/.claude/settings.json` and `settings.local.json` (and a project's
`.claude/settings*.json`) switch the hook on. Programs on the read-only list
(`sort`, `uniq`, `xxd`, `tree`, `yq`, `find`) write a file when given an output
option or operand, and that write did not ask: `sort -o $HOME/.claude/settings.json
$HOME/.claude/settings.json` rewrote the settings with no question."""
import os

import pytest

from stillrunning import claude_hook as ch


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    for name in ("settings.json", "settings.local.json"):
        (home / ".claude" / name).write_text("{}")
    proj = home / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.local.json").write_text("{}")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("STILLRUNNING_CVE_CHECK", "0")
    return home


SORT_WRITES = [
    "sort -o $HOME/.claude/settings.json $HOME/.claude/settings.json",
    "sort -o ${HOME}/.claude/settings.json x", "sort -o ~/.claude/setting?.json x",
    "sort -o ~/.claude/settings.json x", "sort -o ~/.claude/settings.local.json x",
    "sort -o ~/.claude/s*.json x", "sort -o ~/.claude/{settings,zz}.json x",
    "sort -o ~/.claude/[s]ettings.json x", "sort -o\"$HOME/.claude/settings.json\" x",
    "sort -o$HOME/.claude/settings.json x", "sort -uo ~/.claude/settings.json x",
    "sort -u -o ~/.claude/settings.json x", "sort --output=$HOME/.claude/settings.json x",
    "sort --output $HOME/.claude/settings.json x", "sort --outp=$HOME/.claude/settings.json x",
    "cd ~/.claude && sort -o settings.json settings.json", "sort -o $D/.claude/settings.json x",
    "sort -o $D/.claude/setting?.json x", "sort -o $D/.claude/$F x",
    "bash -c 'sort -o $HOME/.claude/settings.json x'", "nice sort -o ~/.claude/settings.json x",
    "sort -o PROJ/.claude/settings.local.json x", "cd PROJ && sort -o .claude/settings.local.json x",
]
OTHER_WRITES = [
    "uniq x ~/.claude/settings.json", "uniq -c x $HOME/.claude/settings.json",
    "uniq ~/.claude/settings.json ~/.claude/settings.json", "xxd -r x ~/.claude/settings.json",
    "tree -o ~/.claude/settings.json /tmp", "tree -o$HOME/.claude/settings.json /tmp",
    "yq -i '.a=1' ~/.claude/settings.json", "yq --inplace '.a=1' $HOME/.claude/settings.json",
    "yq e -i '.a=1' ~/.claude/setting?.json",
    "find /tmp -fprint ~/.claude/settings.json", "find /tmp -fprintf $HOME/.claude/settings.json %p",
    "find ~/.claude -name settings.json -delete", "find ~/.claude -name 'setting*' -exec rm {} +",
    # these already asked; kept so they stay that way
    "echo {} > ~/.claude/settings.json", "echo {} > $HOME/.claude/setting?.json",
    "echo {} | tee ~/.claude/settings.json", "echo {} | tee -a $HOME/.claude/s*.json",
    "sed -i s/a/b/ ~/.claude/settings.json", "sed -i s/a/b/ ~/.claude/*.json",
    "cp /tmp/x ~/.claude/setting?.json", "mv /tmp/x $HOME/.claude/settings.local.json",
    "python3 -c \"open('HOME/.claude/settings.json','w').write('{}')\"",
    "cd ~/.claude && echo {} > settings.json", "jq . x > ~/.claude/settings.json",
    "dd if=/tmp/x of=$HOME/.claude/settings.json", "rm $HOME/.claude/settings.json",
    "curl -o $HOME/.claude/settings.json http://x.invalid", "exec 3>$HOME/.claude/settings.json",
]
READS = [
    "cat ~/.claude/settings.json", "cat $HOME/.claude/settings.json", "jq . ~/.claude/settings.json",
    "grep hook ~/.claude/setting?.json", "less $HOME/.claude/settings.json", "head ~/.claude/*.json",
    "ls -la $HOME/.claude", "diff ~/.claude/settings.json /tmp/x", "sort $HOME/.claude/settings.json",
    "sort -u ~/.claude/settings.json", "sort -o /tmp/out ~/.claude/settings.json",
    "sort -t o ~/.claude/settings.json", "sort -k 2 -o /tmp/o ~/.claude/settings.json",
    "uniq ~/.claude/settings.json", "uniq ~/.claude/settings.json /tmp/out",
    "xxd ~/.claude/settings.json", "xxd ~/.claude/settings.json /tmp/dump",
    "tree ~/.claude", "tree -o /tmp/t ~/.claude", "yq . ~/.claude/settings.json",
    "find ~/.claude -name settings.json", "find ~/.claude -fprint /tmp/list",
    "find ~/.claude -name '*.md' -exec grep -l foo {} \\;", "find ~/.claude -exec cat {} +",
    "wc -c ~/.claude/settings.json", "sha256sum ~/.claude/settings.json",
    "cp $HOME/.claude/settings.json /tmp/backup.json", "cat ~/.claude/settings.json > /tmp/x",
    "echo $HOME/.claude/settings.json", "grep -r claude $DIR", "git log", "git diff ~/.claude",
]


def _fill(command, home):
    return command.replace("PROJ", str(home / "proj")).replace("'HOME/", "'%s/" % home)


@pytest.mark.parametrize("command", SORT_WRITES + OTHER_WRITES)
def test_writes_to_claude_settings_ask(home, command):
    command = _fill(command, home)
    assert ch.touches_protection(command, cwd=str(home)), command
    assert ch.decide(command, env={})["action"] == "ask", command


@pytest.mark.parametrize("command", READS)
def test_reading_claude_settings_still_does_not_ask(home, command):
    command = _fill(command, home)
    assert not ch.touches_protection(command, cwd=str(home)), command


def test_the_read_only_list_is_still_read_only_for_other_files(home):
    for command in ("sort -o /srv/a /srv/b", "uniq /srv/a /srv/b", "xxd -r /srv/a /srv/b",
                    "tree -o /srv/t /srv", "yq -i . /srv/a.yml", "find /srv/x -delete"):
        assert not ch.touches_protection(command, cwd=str(home)), command
