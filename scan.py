#!/usr/bin/env python3
"""
StillRunning GitHub Action Scanner

Parses requirements.txt/package.json and checks packages against the
stillrunning.io threat database. Exits non-zero if dangerous packages found.
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error

API_URL = "https://stillrunning.io/api/github-action/scan"

# ── ANSI palette (GitHub Actions log viewer renders basic ANSI) ─────────
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
BRIGHT_RED = "\033[91m"
YELLOW = "\033[93m"
WHITE = "\033[97m"
DIM = "\033[2m"

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
_BOX_WIDTH = 58  # inner width of the security-block banner


def _row(content: str = "") -> str:
    """One banner row, padded to the box width (ANSI codes excluded)."""
    pad = " " * max(0, _BOX_WIDTH - len(_ANSI_RE.sub("", content)))
    edge = f"{BOLD}{RED}║{RESET}"
    return f"{edge} {content}{pad} {edge}"


def print_security_block(dangerous: list[dict]) -> None:
    """Render the StillRunning security-block banner."""
    top = f"{BOLD}{RED}╔{'═' * (_BOX_WIDTH + 2)}╗{RESET}"
    mid = f"{BOLD}{RED}╠{'═' * (_BOX_WIDTH + 2)}╣{RESET}"
    bot = f"{BOLD}{RED}╚{'═' * (_BOX_WIDTH + 2)}╝{RESET}"

    shield = [
        "▗▄▄▄▄▄▄▄▖",
        "▐███████▌",
        "▐██ ✗ ██▌",
        "▐███████▌",
        " ▜█████▛ ",
        "   ▜█▛   ",
    ]
    tags = [
        "",
        f"{BOLD}{WHITE}S T I L L R U N N I N G{RESET}",
        f"{BOLD}{YELLOW}SUPPLY-CHAIN SECURITY BLOCK{RESET}",
        "",
        f"{DIM}Deliberate security stop — not a flaky build.{RESET}",
        f"{DIM}Do not re-run. Remove the package below.{RESET}",
    ]

    lines = [top]
    for art, tag in zip(shield, tags):
        lines.append(_row(f"{BRIGHT_RED}{art}{RESET}   {tag}"))
    lines.append(mid)
    for pkg in dangerous:
        name = str(pkg.get("package", "unknown"))[: _BOX_WIDTH - 11]
        reason = str(pkg.get("reason", "Known malicious"))[: _BOX_WIDTH - 11]
        lines.append(_row(f"{BOLD}{BRIGHT_RED}✗ BLOCKED{RESET}  {BOLD}{YELLOW}{name}{RESET}"))
        lines.append(_row(f"{DIM}           {reason}{RESET}"))
    lines.append(mid)
    n = len(dangerous)
    plural = "s" if n != 1 else ""
    lines.append(_row(f"{BOLD}{WHITE}{n} malicious package{plural} stopped before install.{RESET}"))
    lines.append(_row(f"{DIM}stillrunning.io — so your code is still running tomorrow.{RESET}"))
    lines.append(bot)
    print("\n" + "\n".join(lines) + "\n", flush=True)


def parse_requirements(path: str) -> list[str]:
    """Parse requirements.txt and return list of package specs."""
    packages = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Remove comments
                line = line.split("#")[0].strip()
                if line:
                    packages.append(line)
    except FileNotFoundError:
        print(f"::warning::Requirements file not found: {path}")
    return packages


def parse_package_json(path: str) -> list[str]:
    """Parse package.json and return list of package specs."""
    packages = []
    try:
        with open(path) as f:
            data = json.load(f)
        for dep_type in ["dependencies", "devDependencies", "peerDependencies"]:
            deps = data.get(dep_type, {})
            for name, version in deps.items():
                # Normalize version spec
                version = re.sub(r'^[\^~>=<]', '', str(version))
                packages.append(f"{name}@{version}")
    except FileNotFoundError:
        print(f"::warning::package.json not found: {path}")
    except json.JSONDecodeError as e:
        print(f"::error::Invalid package.json: {e}")
    return packages


def parse_package_lock(path: str) -> list[str]:
    """Parse package-lock.json and return list of package specs."""
    packages = []
    try:
        with open(path) as f:
            data = json.load(f)
        # npm v2+ lockfile format
        deps = data.get("packages", {})
        for key, info in deps.items():
            if not key:  # Skip root
                continue
            name = key.replace("node_modules/", "")
            version = info.get("version", "")
            if name and version:
                packages.append(f"{name}@{version}")
    except FileNotFoundError:
        print(f"::warning::package-lock.json not found: {path}")
    except json.JSONDecodeError as e:
        print(f"::error::Invalid package-lock.json: {e}")
    return packages


def scan_packages(packages: list[str], repo: str, token: str = "") -> dict:
    """Call StillRunning API to scan packages."""
    payload = json.dumps({
        "packages": packages,
        "repo": repo,
        "token": token
    }).encode()

    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "stillrunning-github-action/1.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        print(f"::error::API error {e.code}: {body}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"::error::Network error: {e.reason}")
        sys.exit(1)


def main():
    # Get inputs from environment
    requirements_path = os.environ.get("INPUT_REQUIREMENTS", "requirements.txt")
    package_json_path = os.environ.get("INPUT_PACKAGE_JSON", "")
    package_lock_path = os.environ.get("INPUT_PACKAGE_LOCK", "")
    token = os.environ.get("INPUT_TOKEN", "")
    fail_on_suspicious = os.environ.get("INPUT_FAIL_ON_SUSPICIOUS", "false").lower() == "true"
    repo = os.environ.get("GITHUB_REPOSITORY", "unknown")

    # Collect packages from all sources
    packages = []

    if requirements_path and os.path.exists(requirements_path):
        pip_packages = parse_requirements(requirements_path)
        print(f"Found {len(pip_packages)} packages in {requirements_path}")
        packages.extend(pip_packages)

    if package_json_path and os.path.exists(package_json_path):
        npm_packages = parse_package_json(package_json_path)
        print(f"Found {len(npm_packages)} packages in {package_json_path}")
        packages.extend(npm_packages)

    if package_lock_path and os.path.exists(package_lock_path):
        lock_packages = parse_package_lock(package_lock_path)
        print(f"Found {len(lock_packages)} packages in {package_lock_path}")
        packages.extend(lock_packages)

    if not packages:
        print("::warning::No packages found to scan")
        print("::set-output name=status::CLEAN")
        print("::set-output name=dangerous-count::0")
        print("::set-output name=suspicious-count::0")
        return

    print(f"\nScanning {len(packages)} packages against stillrunning.io...")

    # Call API
    result = scan_packages(packages, repo, token)

    # Parse results
    results = result.get("results", [])
    summary = result.get("summary", {})
    fail_ci = result.get("fail_ci", False)
    comment = result.get("comment_markdown", "")

    dangerous = [r for r in results if r.get("verdict") == "DANGEROUS"]
    suspicious = [r for r in results if r.get("verdict") == "SUSPICIOUS"]
    clean = [r for r in results if r.get("verdict") == "CLEAN"]

    # Print summary
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE: {len(clean)} clean, {len(suspicious)} suspicious, {len(dangerous)} dangerous")
    print(f"{'='*60}\n")

    if dangerous:
        print_security_block(dangerous)
        # Plain workflow commands (no ANSI) so GitHub renders proper
        # annotations in the Checks / PR UI alongside the banner above.
        for pkg in dangerous:
            print(f"::error title=StillRunning security block::"
                  f"{pkg.get('package')}: {pkg.get('reason', 'Known malicious')}")

    if suspicious:
        level = "error" if fail_on_suspicious else "warning"
        print(f"::{level}::SUSPICIOUS packages found:")
        for pkg in suspicious:
            print(f"  - {pkg.get('package')}: {pkg.get('reason', 'Needs review')}")

    # Set outputs
    status = "DANGEROUS" if dangerous else ("SUSPICIOUS" if suspicious else "CLEAN")
    print(f"::set-output name=status::{status}")
    print(f"::set-output name=dangerous-count::{len(dangerous)}")
    print(f"::set-output name=suspicious-count::{len(suspicious)}")

    # Write report to file for PR comment action
    if comment:
        with open("stillrunning-report.md", "w") as f:
            f.write(comment)
        print("::set-output name=report::stillrunning-report.md")

    # Exit with error if dangerous found (or suspicious if configured)
    if dangerous:
        print("\n::error title=StillRunning security block::"
              "CI blocked: malicious packages detected — this is a security stop, not a build failure")
        sys.exit(1)

    if suspicious and fail_on_suspicious:
        print("\n::error::CI blocked: Suspicious packages detected (fail-on-suspicious enabled)")
        sys.exit(1)

    print("\n✅ All packages passed security scan")


if __name__ == "__main__":
    main()
