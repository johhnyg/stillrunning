"""Fourth review (2026-11-15): plainly spelled installs that passed in silence.

Every miss had one cause: a flag table decided a word was an option's value
(or a script file), so the package after it was never looked up. The fix is
a rule, not a list: a misread flag must fail toward blocking.

FIRE          the reviewer's commands, and their families: must be DENIED
QUIET         real commands with option values: the shadow pass adds nothing
SILENT        everyday commands: no prompt, no record
PROTECT       changes to stillrunning's own protection: must ask

`evilx` is on the blocklist in every version; nothing else is listed.
"""
import importlib.util
import os
import sys

import pytest

from stillrunning import claude_hook as ch

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("review3_tables",
                                               os.path.join(_here, "test_s135_review3_fixes.py"))
_review3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_review3)

FIRE = [
    # 1. short flags written together, ending in -r
    'pip install -Ur app/requirements.txt',
    'pip install -qr app/requirements.txt',
    'pip install -Urrequirements.txt',
    '!pip install -qr requirements.txt',
    '%pip install -qr requirements.txt',
    'pip install -Ur requirements.txt',
    'pip install -qr requirements.txt',
    'pip install -qUr requirements.txt',
    'pip install -Ir requirements.txt',
    'pip install -vr requirements.txt',
    'pip3 install -Ur requirements.txt',
    'python -m pip install -Ur requirements.txt',
    'python3 -m pip install -qUr requirements.txt',
    'uv pip install -Ur requirements.txt',
    'sudo pip install -Ur requirements.txt',
    'cd app && pip install -Ur requirements.txt',
    'pip install -U -r requirements.txt',
    'pip install requirements.txt',
    '!pip install evilx',
    '%pip install evilx',
    '!python -m pip install evilx',
    # 2. shell options before a here-document, a pipe or a here-string
    "bash -euo pipefail <<'EOF'\npip install evilx\nEOF",
    'bash -eo pipefail <<EOF\npip install evilx\nEOF',
    'bash -o pipefail <<EOF\npip install evilx\nEOF',
    'sudo bash -euxo pipefail <<EOF\npip install evilx\nEOF',
    'sh -o errexit <<EOF\npip install evilx\nEOF',
    'bash -O globstar <<EOF\npip install evilx\nEOF',
    'bash --rcfile /dev/null <<EOF\npip install evilx\nEOF',
    'bash --init-file /dev/null <<EOF\npip install evilx\nEOF',
    'bash +o histexpand <<EOF\npip install evilx\nEOF',
    'bash --noprofile --norc -eu <<EOF\npip install evilx\nEOF',
    'cat <<EOF | bash -euo pipefail\npip install evilx\nEOF',
    "echo 'pip install evilx' | bash -euo pipefail",
    "echo 'npm install evilx' | sh -o errexit",
    "bash -o pipefail <<< 'pip install evilx'",
    'bash missing-script.sh <<EOF\npip install evilx\nEOF',
    # 3. pnpm -w is a switch
    'pnpm add -w evilx',
    'pnpm i -w evilx',
    'pnpm install -w evilx',
    'pnpm add -w evilx@1.0.0',
    'pnpm add --save-dev -w evilx',
    'pnpm up -w evilx',
    'sudo pnpm add -w evilx',
    'cd app && pnpm add -w evilx',
    'pnpm add -w evilx other',
    'pnpm add --workspace-root evilx',
    'pnpm add --workspace evilx',
    'pnpm add -wD evilx',
    # 4. uv tool install X --with Y
    'uv tool install ruff --with evilx',
    'uv tool install ruff --with=evilx',
    'uv tool install ruff -w evilx',
    'uv tool install ruff --with-requirements requirements.txt',
    'uv tool install --with evilx ruff',
    'uvx --with evilx ruff',
    'uv run --with evilx python x.py',
    'uv tool run --from evilx cmd',
    # 5. plugin and tool installs
    'poetry self add evilx',
    'pdm self add evilx',
    'pdm plugin add evilx',
    'pipx runpip app install evilx',
    'pipx inject app evilx',
    'pipx upgrade evilx',
    'pipx reinstall evilx',
    'uv tool upgrade evilx',
    'poetry update evilx',
    'pdm update evilx',
    'uv sync --upgrade-package evilx',
    'uv lock --upgrade-package evilx',
    'uv lock -P evilx',
    'uv add requests --upgrade-package evilx',
    'npm pack evilx',
    'npm cache add evilx',
    'pip download evilx',
    'pip wheel evilx',
    'yarn up evilx',
    # 6. the package named before or beside the runner's subcommand
    'pnpm --package=evilx dlx cmd',
    'pnpm --package evilx dlx cmd',
    'pnpm dlx --package evilx cmd',
    'npm exec --package=evilx -- cmd',
    'npx -p evilx cmd',
    'npx --package evilx cmd',
    'yarn dlx -p evilx cmd',
    # the same family, rarer: caught by the shadow lookup, whatever the table says
    'npm i -c evilx',
    'bun add -c evilx',
    'yarn add -C evilx',
    "npx -c 'evilx --help'",
    'npm install --prefix evilx lodash',
    'npm install -w evilx lodash',
    'pip install --target evilx requests',
    'pip install -t evilx requests',
    'pip install --python evilx requests',
    'pip install --progress-bar evilx',
    'pip install --upgrade-strategy evilx requests',
    'uv pip install --resolution evilx requests',
    'poetry add --group evilx',
    'pdm add -G evilx',
    'pip install --no-binary=evilx requests',
    'npm install --tag=evilx',
    'yarn add --mutex evilx',
    'bun add --backend evilx',
    'pnpm add --filter evilx',
    'pip frobnicate install evilx',
    'poetry self install evilx',
]

# Commands a developer really types, with option values that are not packages.
# With nothing on the blocklist, the shadow pass must change nothing at all.
QUIET = [
    'pip install --target build requests',
    'pip install --target ./vendor requests',
    'pip install --prefix /opt/x requests',
    'pip install -t vendor requests flask',
    'pip install --root /tmp/root requests',
    'pip install --python 3.12 requests',
    'pip install --python-version 3.11 --only-binary=:all: requests',
    'pip install --platform manylinux2014_x86_64 --only-binary=:all: requests',
    'pip install --implementation cp --abi cp312 --only-binary=:all: requests',
    'pip install --upgrade-strategy eager requests',
    'pip install --progress-bar off requests',
    'pip install --no-binary numpy numpy',
    'pip install --only-binary pandas pandas',
    'pip install --config-settings editable_mode=strict -e .',
    'pip install --cache-dir /tmp/pipcache requests',
    'pip install --retries 5 --timeout 30 requests',
    'pip install --exists-action w requests',
    'pip install --root-user-action ignore requests',
    'pip install --use-feature fast-deps requests',
    'pip install --report out.json --dry-run requests',
    'pip install --src ./src -e .',
    'pip install -Uq requests',
    'pip install -U pip setuptools wheel',
    'python -m pip install -qU pip',
    'pip install -qqq requests',
    'pip install -r requirements.txt --no-deps',
    'pip install "requests[socks]>=2.31"',
    'pip download -d wheels requests',
    'pip wheel -w dist requests',
    'uv pip install --python 3.12 requests',
    'uv pip install --resolution lowest-direct requests',
    'uv pip install --index-strategy unsafe-best-match requests',
    'uv add --extra dev requests',
    'uv add --group lint ruff',
    'uv add --optional docs sphinx',
    'uv tool install ruff --python 3.12',
    'uv tool upgrade ruff',
    'uv run --with rich python x.py',
    'uv run --python 3.12 pytest -k smoke',
    'uvx --python 3.11 ruff check .',
    'pipx install black --python python3.11',
    'pipx upgrade black',
    'pipx inject poetry poetry-plugin-export',
    'poetry add --group dev pytest',
    'poetry add -E socks requests',
    'poetry update requests',
    'poetry update',
    'pdm add -G test pytest',
    'pdm add -dG lint ruff',
    'pdm update',
    'pipenv install --dev pytest',
    'npm install --tag next react',
    'npm install -w packages/web lodash',
    'npm install -w web lodash',
    'npm install --workspace api express',
    'npm install --loglevel verbose lodash',
    'npm install --omit dev',
    'npm install --omit=dev --ignore-scripts',
    'npm install --save-dev --save-exact jest',
    'npm install --prefix ./frontend',
    'npm install --cache /tmp/npmcache lodash',
    'npm install --install-strategy nested lodash',
    'npm i -D typescript @types/node',
    'npm update --depth 2 lodash',
    'npm pack',
    'npm exec -- eslint src',
    'npx --yes cowsay hello',
    'npx -p typescript tsc --init',
    'pnpm add --filter web lodash',
    'pnpm add -w lodash',
    'pnpm add -D --filter api vitest',
    'pnpm add --dir packages/ui react',
    'pnpm install --frozen-lockfile --reporter append-only',
    'pnpm dlx create-vite my-app --template react',
    'yarn add --cwd packages/app lodash',
    'yarn add -D -E typescript',
    'yarn add --mutex network lodash',
    'bun add --cwd apps/web zod',
    'bun add -d typescript',
]

SILENT = list(_review3.SILENT) + [
    # option values and subcommands that look a little like installs
    'npm run build -- --mode production',
    'npm test -- --watch unit',
    'yarn test unit',
    'yarn build',
    'pnpm run lint',
    'pnpm test --filter web',
    'pip show requests',
    'pip list --format json',
    'pip check',
    'pip freeze',
    'pip uninstall -y requests',
    'pip config list',
    'npm ls --depth 0',
    'npm outdated',
    'npm view react version',
    'npm cache clean --force',
    'npm cache verify',
    'uv run pytest -k foo',
    'uv run python manage.py migrate',
    'poetry run pytest tests',
    'poetry self update',
    'poetry self show plugins',
    'pdm run lint',
    'pipx list',
    'pipx upgrade-all',
    'uv tool list',
    'uv lock',
    # shells with options, running nothing that installs
    "bash -euo pipefail <<'EOF'\necho hello\nmake build\nEOF",
    "bash -o pipefail -c 'make build'",
    'set -euo pipefail',
    'bash -x scripts/run.sh',
    'cat data.txt | bash process.sh',
    'sh -o errexit <<EOF\nls -la\nEOF',
    # git in an ordinary project
    'git stash',
    'git stash pop',
    'git stash -u',
    'git checkout main',
    'git checkout -- src/app.py',
    'git checkout .',
    'git reset --hard HEAD~1',
    'git clean -fd',
    'git clean -fdx',
    'git restore src/x.py',
    'git pull --rebase',
    # folders that are not a settings folder
    'rm -rf node_modules',
    'rm -rf build docs/_build',
    'mv docs documentation',
    # notebook-style lines that install nothing
    '!ls -la',
    '%timeit sum(range(10))',
]

PROTECT_PROJECT = [
    'rm -rf .claude',
    'rm -r .claude',
    'mv .claude .claude.bak',
    'sudo rm -rf .claude',
    'cd . && rm -rf .claude',
    'rm -rf ./.claude',
    'git clean -fdx',
    'git clean -fd',
    'git stash -u',
    'git stash --include-untracked',
    'git checkout HEAD -- .claude/settings.json',
    'git restore .claude/settings.json',
    'git checkout -- .claude',
]
PROTECT_PACKAGE = [
    'git checkout HEAD -- stillrunning/',
    'git checkout HEAD -- stillrunning/claude_hook.py',
    'git stash',
    'git stash -u',
    'git stash push',
    'git reset --hard',
    'git reset --hard HEAD~1',
    'git clean -fdx',
    'git restore .',
    'git restore stillrunning/claude_hook.py',
    'git checkout .',
    'git checkout -f',
]
PACKAGE_SILENT = [
    'git status',
    'git diff',
    'git log --oneline -5',
    'git add -A',
    'git commit -m "fix"',
    'git checkout -b feature',
    'git checkout main',
    'git pull',
    'git stash list',
    'git stash show',
    'git fetch origin',
]


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    root = tmp_path / "home"
    (root / ".claude").mkdir(parents=True)
    (root / ".claude" / "settings.json").write_text("{}")
    (root / ".stillrunning").mkdir(mode=0o700)
    (root / ".stillrunning" / "overrides.json").write_text("{}")
    (root / ".npmrc").write_text("")
    monkeypatch.setenv("HOME", str(root))
    for name in list(os.environ):
        if name.startswith(("STILLRUNNING_", "PIP_", "UV_", "NPM_CONFIG_", "npm_config_", "POETRY_",
                            "PIPENV_", "BUN_", "COREPACK_")) or name == "NO_COLOR":
            monkeypatch.delenv(name, raising=False)
    work = tmp_path / "work"
    for sub in ("app", "docs", "build"):
        (work / sub).mkdir(parents=True)
    (work / "requirements.txt").write_text("evilx\n")
    (work / "app" / "requirements.txt").write_text("evilx\n")
    monkeypatch.chdir(work)
    return root


@pytest.fixture
def work(home):
    return str(home.parent / "work")


@pytest.fixture
def plain(work):
    """A work folder whose requirements files name nothing listed."""
    for path in ("requirements.txt", os.path.join("app", "requirements.txt")):
        with open(os.path.join(work, path), "w", encoding="utf-8") as handle:
            handle.write("requests\n")
    return work


def lookup(pkg, token=None, timeout=8.0):
    if ch.normalize(pkg["eco"], pkg["name"]) == "evilx":
        return {"status": "blocked", "advisory": "MAL-2026-0001"}
    return {"status": "ok"}


def decide(command, cwd, **kw):
    kw.setdefault("env", {})
    kw.setdefault("lookup_fn", lookup)
    return ch.decide(command, cwd=cwd, **kw)


def summary(decision):
    return decision["action"], [(r["verdict"], r["subject"]) for r in decision["records"]]


# ─────────────────────────────── the tables ───────────────────────────────
def test_table_sizes():
    assert len(FIRE) >= 95 and len(QUIET) >= 60 and len(SILENT) >= 300
    assert len(set(FIRE)) == len(FIRE) and len(set(QUIET)) == len(QUIET)


@pytest.mark.parametrize("command", FIRE)
def test_plainly_spelled_install_of_a_blocked_package_is_denied(command, work):
    d = decide(command, work)
    assert d["action"] == "deny", (command, summary(d))
    assert any(r["verdict"] == "blocked" and r["name"] == "evilx" for r in d["records"])


@pytest.mark.parametrize("command", QUIET)
def test_the_shadow_pass_adds_nothing_to_a_real_command(command, plain, monkeypatch):
    with_shadow = summary(decide(command, plain))
    monkeypatch.setattr(ch, "_collect_shadow", lambda *a, **k: None)
    without = summary(decide(command, plain))
    assert with_shadow == without, command
    assert with_shadow[0] == "allow", (command, with_shadow)


@pytest.mark.parametrize("command", SILENT)
def test_everyday_command_is_silent(command, plain):
    d = decide(command, plain)
    assert d["action"] == "allow", (command, summary(d))
    assert not [r for r in d["records"] if r["verdict"] != "note"], (command, summary(d))


# ───────────── the rule: a misread flag fails toward blocking ─────────────
INSTALLS = {
    "pip install": ("pip", ch._PIP_VALUE_FLAGS | ch._PIP_INDEX_FLAGS),
    "pip3 install": ("pip", ch._PIP_VALUE_FLAGS),
    "python -m pip install": ("pip", ch._PIP_VALUE_FLAGS),
    "uv pip install": ("pip", ch._PIP_VALUE_FLAGS),
    "uv add": ("pip", ch._PIP_VALUE_FLAGS),
    "poetry add": ("pip", ch._PIP_VALUE_FLAGS),
    "pdm add": ("pip", ch._PIP_VALUE_FLAGS),
    "pipx install": ("pip", ch._PIP_VALUE_FLAGS),
    "npm install": ("npm", ch._NPM_VALUE_FLAGS_BY_TOOL["npm"] | ch._NPM_INDEX_FLAGS),
    "pnpm add": ("npm", ch._NPM_VALUE_FLAGS_BY_TOOL["pnpm"] | ch._NPM_INDEX_FLAGS),
    "yarn add": ("npm", ch._NPM_VALUE_FLAGS_BY_TOOL["yarn"] | ch._NPM_INDEX_FLAGS),
    "bun add": ("npm", ch._NPM_VALUE_FLAGS_BY_TOOL["bun"] | ch._NPM_INDEX_FLAGS),
}
FLAG_CASES = [(prefix, flag) for prefix, (_, flags) in sorted(INSTALLS.items())
              for flag in sorted(flags)]


def test_the_property_covers_every_table():
    assert len(FLAG_CASES) > 400


@pytest.mark.parametrize("prefix,flag", FLAG_CASES)
def test_a_blocked_name_beside_any_value_flag_never_passes_in_silence(prefix, flag, work):
    """`evilx` as the flag's value, right after the flag's value, with `=`,
    and with another package before the flag: never a silent allow. (An ask is
    acceptable where the flag itself makes the install uncheckable.)"""
    for command in (f"{prefix} {flag} evilx",
                    f"{prefix} {flag} evilx lodash",
                    f"{prefix} {flag} somevalue evilx",
                    f"{prefix} {flag}=evilx lodash",
                    f"{prefix} lodash {flag} evilx",
                    f"{prefix} lodash {flag} somevalue evilx"):
        d = decide(command, work)
        assert d["action"] != "allow", (command, summary(d))
        assert d["action"] == "deny" or any(
            r["verdict"] == "needs_approval" for r in d["records"]), (command, summary(d))


@pytest.mark.parametrize("prefix,flag", [
    ("pip install", "--frobnicate"), ("npm install", "--frobnicate"), ("pnpm add", "-Z"),
    ("yarn add", "--some-new-flag"), ("uv pip install", "--future-option"),
    ("bun add", "--whatever"), ("poetry add", "--newflag"), ("pip install", "-Z")])
def test_a_flag_no_table_knows_does_not_hide_a_package(prefix, flag, work):
    for command in (f"{prefix} {flag} evilx", f"{prefix} {flag} value evilx",
                    f"{prefix} {flag}=evilx requests"):
        assert decide(command, work)["action"] == "deny", command


# ─────────────────────── what a shadow candidate is ───────────────────────
def test_a_shadow_hit_says_where_the_name_was_found(work):
    d = decide("npm install -w evilx lodash", work)
    assert d["action"] == "deny"
    record = next(r for r in d["records"] if r["name"] == "evilx")
    assert any(e["text"] == "Named in the command as the value of `-w`" for e in record["evidence"])
    assert "evilx" in d["reason"] and "blocked" in d["reason"].lower()
    assert d["stats"]["blocked"] == 1


def test_a_shadow_candidate_that_is_not_listed_leaves_no_trace(plain):
    seen = []

    def shadow(pkg):
        seen.append((pkg["eco"], pkg["name"]))
        return {"status": "ok"}

    d = decide("pip install -t vendor requests", plain, shadow_fn=shadow)
    assert seen == [("pip", "vendor")]
    assert summary(d) == ("allow", [("no_known_threat", "requests (pip)")])
    assert not any("vendor" in line for line in d["lines"])
    assert d["stats"]["checked"] == 1


@pytest.mark.parametrize("answer", [
    {"status": "not_found"}, {"status": "unverified", "why": "offline"},
    {"status": "unverified", "why": "quota"}, {"status": "suspicious"},
    {"status": "version_needed", "affected": ["1.0"]}, {"status": "miss_unconfirmed"}, {}, None,
    "boom"])
def test_only_a_definite_hit_counts_for_a_shadow_candidate(answer, plain):
    def shadow(pkg):
        if answer == "boom":
            raise RuntimeError("lookup crashed")
        return answer

    d = decide("pip install -t vendor requests", plain, shadow_fn=shadow)
    assert summary(d) == ("allow", [("no_known_threat", "requests (pip)")])


def test_a_shadow_candidate_never_stands_in_for_the_real_lookup(plain):
    """The real package is still looked up by the real path, and a failed
    real lookup still asks even when every shadow candidate is fine."""
    def real(pkg, token=None, timeout=8.0):
        return {"status": "unverified", "why": "offline"}

    d = decide("pip install -t vendor requests", plain, lookup_fn=real,
               shadow_fn=lambda pkg: {"status": "ok"})
    assert d["action"] == "ask"


def test_shadow_lookups_use_only_the_blocklist_route(plain, monkeypatch):
    asked = {"metered": [], "blocklist": [], "registry": []}
    monkeypatch.setattr(ch, "_api_lookup", lambda eco, name, version, token, timeout:
                        asked["metered"].append(name) or {"status": "ok"})
    monkeypatch.setattr(ch, "_on_registry", lambda eco, name, timeout:
                        asked["registry"].append(name) or True)
    monkeypatch.setattr(ch, "_latest_version", lambda eco, name, timeout: None)

    def blocklist(eco, name, version, timeout, quiet=False):
        asked["blocklist"].append((name, quiet))
        return {"status": "blocked", "advisory": "MAL-2026-0002"} if name == "vendor" else None

    monkeypatch.setattr(ch, "_blocklist_only_lookup", blocklist)
    d = ch.decide("pip install -t vendor requests", cwd=plain, env={})
    assert d["action"] == "deny"
    assert ("vendor", True) in asked["blocklist"]           # quiet: a failure prints nothing
    assert "vendor" not in asked["metered"] and "vendor" not in asked["registry"]
    assert "requests" in asked["metered"]


def test_the_list_that_ships_with_stillrunning_counts_for_shadow_too(plain):
    d = decide("pip install -t logutilkit requests", plain, shadow_fn=ch._shadow_lookup)
    assert d["action"] == "deny"
    assert any(e["text"].startswith("Found in the blocklist that ships inside stillrunning")
               for r in d["records"] for e in r["evidence"])


def test_more_candidates_than_the_cap_asks_instead_of_dropping_them(plain):
    words = " ".join(f"--opt{n}=value{n}" for n in range(ch._SHADOW_CAP + 3))
    d = decide(f"pip install {words} requests", plain)
    assert d["action"] == "ask"
    assert ("needs_approval", "install command") in summary(d)[1]


@pytest.mark.parametrize("command,expected", [
    ("pip install -t vendor requests", ["vendor"]),
    ("pip install --target ./vendor requests", []),              # a path
    ("pip install --target build requests", []),                 # a folder that is there
    ("pip install --python 3.12 requests", []),                  # a version
    ("pip install --index-url https://pypi.org/simple requests", []),
    ("pip install -r requirements.txt", []),
    ("pip install --progress-bar off requests", []),             # a switch word
    ("pip install requests", []),
    ("npm install --loglevel debug lodash", []),
    ("npm install -w web lodash", ["web"]),
    ("npm install -w packages/web lodash", []),
    ("npm install --tag=next react", []),
    ("npm run build", []),
    ("npm test unit", []),
    ("pip show requests", []),
    ("uv run pytest -k smoke tests", []),                        # words of the command being run
    ("npx cowsay hello world", []),
    ("npx --yes cowsay hello", []),
    ("poetry add --group dev pytest", []),
    ("poetry add --group tooling pytest", ["tooling"]),
    ("pip install pkg-a --extra-opt=value pkg-b", ["value"]),
])
def test_which_words_become_shadow_candidates(command, expected, plain):
    parsed = ch.parse_install_commands(command, cwd=plain, env={})
    assert [s["name"] for s in parsed["shadow"]] == expected, command


def test_a_typical_install_makes_no_extra_lookups(plain):
    total = 0
    for command in QUIET:
        total += len(ch.parse_install_commands(command, cwd=plain, env={})["shadow"])
    assert total <= len(QUIET) // 3                # well under one per command on average
    assert max(len(ch.parse_install_commands(c, cwd=plain, env={})["shadow"]) for c in QUIET) <= 2


# ───────────────────────── per-tool flags and files ─────────────────────────
def test_w_means_different_things_to_npm_and_pnpm(plain):
    npm = ch.parse_install_commands("npm install -w web lodash", cwd=plain, env={})
    assert [p["name"] for p in npm["packages"]] == ["lodash"]
    pnpm = ch.parse_install_commands("pnpm add -w web lodash", cwd=plain, env={})
    assert [p["name"] for p in pnpm["packages"]] == ["web", "lodash"]


@pytest.mark.parametrize("command", [
    "pip install -Ur requirements.txt", "pip install -qUr requirements.txt",
    "pip install -Urrequirements.txt", "pip install -rrequirements.txt",
    "pip install requirements.txt", "!pip install -qr requirements.txt"])
def test_a_requirements_file_is_read_however_the_flag_is_written(command, plain):
    parsed = ch.parse_install_commands(command, cwd=plain, env={})
    assert [p["name"] for p in parsed["packages"]] == ["requests"], command
    assert parsed["unverifiable"] == []


def test_a_cluster_ending_in_c_marks_the_versions_as_uncertain(plain):
    with open(os.path.join(plain, "constraints.txt"), "w", encoding="utf-8") as handle:
        handle.write("requests<3\n")
    parsed = ch.parse_install_commands("pip install -Uc constraints.txt requests", cwd=plain, env={})
    assert [(p["name"], p.get("uncertain")) for p in parsed["packages"]] == [("requests", True)]


def test_a_missing_requirements_file_in_a_cluster_asks(plain):
    d = decide("pip install -Ur missing-requirements.txt", plain)
    assert d["action"] == "ask"


@pytest.mark.parametrize("after,operands", [
    (["-euo", "pipefail"], []), (["-o", "pipefail"], []), (["+o", "histexpand"], []),
    (["-O", "globstar"], []), (["--rcfile", "/dev/null"], []), (["--norc", "-eu"], []),
    (["-eux", "script.sh", "arg"], ["script.sh", "arg"]), (["script.sh"], ["script.sh"]),
    (["--", "script.sh"], ["script.sh"]), (["-euxo", "pipefail", "run.sh"], ["run.sh"])])
def test_shell_options_are_not_script_files(after, operands):
    assert ch._shell_operands(after) == operands


def test_a_script_file_that_is_there_keeps_stdin_as_data(plain):
    with open(os.path.join(plain, "process.sh"), "w", encoding="utf-8") as handle:
        handle.write("cat\n")
    d = decide("bash process.sh <<EOF\npip install evilx\nEOF", plain)
    assert d["action"] == "allow" and d["records"] == []


def test_npx_dash_c_runs_its_string_as_a_command(work):
    assert decide("npx -c 'pip install evilx'", work)["action"] == "deny"
    assert decide("npm exec -c 'npm install evilx'", work)["action"] == "deny"
    assert decide("npx -c 'eslint src'", work)["action"] == "allow"


# ──────────────────────────── self-protection ────────────────────────────
@pytest.fixture
def project(work):
    os.makedirs(os.path.join(work, ".claude"))
    with open(os.path.join(work, ".claude", "settings.json"), "w", encoding="utf-8") as handle:
        handle.write("{}")
    return work


@pytest.mark.parametrize("command", PROTECT_PROJECT)
def test_a_projects_claude_settings_folder_is_protected(command, project):
    assert ch.touches_protection(command, project), command
    assert decide(command, project)["action"] == "ask"


@pytest.mark.parametrize("command", [
    "ls .claude", "cat .claude/settings.json", "git add .claude", "git status",
    "git stash", "git stash pop", "git checkout main", "git checkout -b x", "git pull",
    "git diff .claude/settings.json", "mkdir -p .claude/commands", "git reset HEAD~1",
    "cp .claude/settings.json /tmp/backup.json", "tar czf backup.tgz .claude"])
def test_ordinary_work_in_a_project_with_claude_settings_is_silent(command, project):
    assert not ch.touches_protection(command, project), command


@pytest.mark.parametrize("command", [
    "rm -rf .claude", "mv .claude .claude.bak", "git clean -fdx", "git stash -u", "git stash",
    "git reset --hard", "git checkout ."])
def test_a_project_without_claude_settings_is_not_protected(command, work):
    os.makedirs(os.path.join(work, ".claude"))            # an empty .claude: nothing to protect
    assert not ch.touches_protection(command, work), command


@pytest.fixture
def package_repo():
    return os.path.dirname(ch._package_dir())


@pytest.mark.parametrize("command", PROTECT_PACKAGE)
def test_git_putting_the_hooks_own_code_back_asks(command, package_repo):
    assert ch.touches_protection(command, package_repo), command


@pytest.mark.parametrize("command", PACKAGE_SILENT)
def test_ordinary_git_in_the_hooks_own_repository_is_silent(command, package_repo):
    assert not ch.touches_protection(command, package_repo), command


def test_git_dash_c_names_the_folder(work, package_repo):
    assert ch.touches_protection(f"git -C {package_repo} stash", work)
    assert not ch.touches_protection("git -C docs stash", work)


def test_git_stash_in_the_home_folder_asks(home):
    assert ch.touches_protection("git stash", str(home))
    assert ch.touches_protection("git clean -fdx", str(home))


# ─────────────────────────────── redaction ───────────────────────────────
@pytest.mark.parametrize("command,gone", [
    ("npm config set //registry.npmjs.org/:_authToken npm_s3cretvalue", "npm_s3cretvalue"),
    ("npm config set //registry.npmjs.org/:_authToken abc123def", "abc123def"),
    ("npm config set //npm.corp/:_password hunter2pw", "hunter2pw"),
    ("npm config set _auth dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ("poetry config pypi-token.pypi tokvalue123", "tokvalue123"),
    ("poetry config pypi-token.internal 'tok value'", "tok value"),
    ("poetry config http-basic.corp alice s3cretpw", "s3cretpw"),
    ("twine upload -u alice -p s3cretpw dist/*", "s3cretpw"),
    ("twine upload --password s3cretpw dist/*", "s3cretpw"),
    ("pip install --client-cert /home/a/keys/me.pem requests", "/home/a/keys/me.pem"),
    ("pip install --cert /etc/ssl/corp.pem requests", "/etc/ssl/corp.pem"),
    ("curl --key /home/a/id.key https://x.example", "/home/a/id.key"),
    ("echo s3cretpw | docker login --password-stdin -u alice", "s3cretpw"),
    ("printf '%s' s3cretpw | docker login -u alice --password-stdin registry.corp", "s3cretpw"),
    ("docker login -u alice --password-stdin <<< s3cretpw", "s3cretpw"),
    ("pip install requests  # my token is s3cretpw", "s3cretpw"),
    ("pip install requests # password=hunter2pw", "hunter2pw"),
    ('PASSWORD="a b" pip install requests', "a b"),
])
def test_credentials_never_reach_the_stored_command(command, gone):
    shown = ch.show_command(command)
    assert gone not in shown, shown
    assert "***" in shown or "#" not in shown


@pytest.mark.parametrize("command", [
    "pip install requests==2.32.3",
    "npm install --save-dev jest",
    "curl -fsSL https://example.com/page#section -o out.html",
    "pnpm add -w lodash",
    "echo hello | tee out.txt",
    "git commit -m 'fix #123'",
])
def test_ordinary_commands_are_still_shown_as_typed(command):
    assert ch.show_command(command) == command


def test_the_decision_log_gets_the_redacted_command(work):
    d = decide("pip install evilx  # token s3cretpw", work)
    assert d["action"] == "deny"
    assert all("s3cretpw" not in r["command"] for r in d["records"])


# ─────────────────────────── the installed script ───────────────────────────
def test_the_hook_script_blocks_a_package_hidden_behind_a_flag(home, work):
    """End to end through the script Claude Code runs, with a blocklist entry
    planted in the local list (no server)."""
    import json
    import subprocess
    with open(os.path.join(str(home), ".stillrunning", "known_bad_packages.json"), "w", encoding="utf-8") as handle:
        json.dump({"npm": {"evilx": ["any"]}, "pip": {"evilx": ["any"]}}, handle)
    env = dict(os.environ, HOME=str(home), STILLRUNNING_API_BASE="http://127.0.0.1:9")
    for command, action in (("pnpm add -w evilx", "deny"),
                            ("npm install -w evilx", "deny"),
                            ("pip install --target evilx", "deny"),
                            ("bash -euo pipefail <<EOF\npip install evilx\nEOF", "deny"),
                            ("poetry self add evilx", "deny"),
                            ("ls -la", None)):
        payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": work,
                              "tool_input": {"command": command}})
        ran = subprocess.run([sys.executable, "-I", "-S", ch.__file__], input=payload, text=True,
                             capture_output=True, timeout=60, env=env, cwd=work)
        assert ran.returncode == 0, ran.stderr
        if action is None:
            assert ran.stdout.strip() == "", ran.stdout
        else:
            out = json.loads(ran.stdout)
            assert out["hookSpecificOutput"]["permissionDecision"] == action, (command, ran.stdout)
