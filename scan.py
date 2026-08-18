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
        print("::error::DANGEROUS packages found:")
        for pkg in dangerous:
            print(f"  - {pkg.get('package')}: {pkg.get('reason', 'Known malicious')}")

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
        print("\n::error::CI blocked: Dangerous packages detected")
        sys.exit(1)

    if suspicious and fail_on_suspicious:
        print("\n::error::CI blocked: Suspicious packages detected (fail-on-suspicious enabled)")
        sys.exit(1)

    print("\n✅ All packages passed security scan")


if __name__ == "__main__":
    main()
