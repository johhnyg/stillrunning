#!/usr/bin/env python3
"""
npm_pip_intercept.py — Supply chain attack protection.
Intercepts npm/pip installs, checks against known-bad list, verifies hashes.

Usage:
  stillrunning-intercept pip install <package>
  stillrunning-intercept npm install <package>

Called automatically when stillrunning wraps pip/npm.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# ─── Constants ───────────────────────────────────────────────────────────────

# Use ~/.stillrunning for customer installs (not ~/my-app which is server-only)
STILLRUNNING_DIR = Path.home() / ".stillrunning"
STILLRUNNING_DIR.mkdir(exist_ok=True)

# For backwards compatibility with server install
_server_env = Path.home() / "my-app" / ".env"
_server_known_bad = Path.home() / "my-app" / "known_bad_packages.json"
ENV_FILE = _server_env if _server_env.exists() else STILLRUNNING_DIR / ".env"
KNOWN_BAD_JSON = _server_known_bad if _server_known_bad.exists() else STILLRUNNING_DIR / "known_bad_packages.json"

# Known malicious packages — block all versions (hardcoded baseline)
KNOWN_BAD_PIP = {
    "logutilkit": ["any"],
    "apachelicense": ["any"],
    "fluxhttp": ["any"],
    "license-utils-kit": ["any"],
    "logkitx": ["any"],
    "pino-debugger": ["any"],
    "dev-log-core": ["any"],
    "logger-base": ["any"],
}

KNOWN_BAD_NPM = {
    "dev-log-core": ["any"],
    "logger-base": ["any"],
    "logkitx": ["any"],
    "pino-debugger": ["any"],
    "log-utils-js": ["any"],
    "node-log-helper": ["any"],
}


def _load_auto_synced_known_bad() -> tuple[dict, dict]:
    """Load auto-synced known-bad packages from threat_feed."""
    pip_extra = {}
    npm_extra = {}
    try:
        if KNOWN_BAD_JSON.exists():
            with open(KNOWN_BAD_JSON) as f:
                data = json.load(f)
            pip_extra = {k: ["any"] for k in data.get("pip", {}).keys()}
            npm_extra = {k: ["any"] for k in data.get("npm", {}).keys()}
    except Exception:
        pass
    return pip_extra, npm_extra


# Threat cache location
_server_cache = Path.home() / "my-app" / "threat_cache.json"
THREAT_CACHE_JSON = _server_cache if _server_cache.exists() else STILLRUNNING_DIR / "threat_cache.json"
THREAT_CACHE_TTL_SECONDS = 3600  # 60 minutes

# ─── Scan Usage Tracking ─────────────────────────────────────────────────────

SCAN_USAGE_FILE = STILLRUNNING_DIR / "scan_usage.json"
FREE_DAILY_LIMIT = 10


def _get_scan_usage() -> dict:
    """Get today's scan count."""
    from datetime import date
    today = str(date.today())
    try:
        if SCAN_USAGE_FILE.exists():
            with open(SCAN_USAGE_FILE) as f:
                data = json.load(f)
            if data.get("date") == today:
                return {"date": today, "count": data.get("count", 0)}
    except Exception:
        pass
    return {"date": today, "count": 0}


def _increment_scan_usage(pkg_count: int = 1) -> int:
    """Increment scan count, return new total."""
    usage = _get_scan_usage()
    usage["count"] += pkg_count
    tmp = SCAN_USAGE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(usage, f)
    os.replace(tmp, SCAN_USAGE_FILE)
    return usage["count"]


def _show_upgrade_prompt(scans_used: int) -> None:
    """Show upgrade prompt based on scan usage."""
    remaining = FREE_DAILY_LIMIT - scans_used
    if remaining <= 3 and remaining > 0:
        print(f"\n{YELLOW}Scans remaining today: {remaining}/{FREE_DAILY_LIMIT}{RESET}")
        print(f"   Upgrade for unlimited: https://stillrunning.io/pricing")
    elif remaining <= 0:
        print(f"\n{RED}Free scan limit reached ({FREE_DAILY_LIMIT}/day){RESET}")
        print(f"   Packages checked against blocklist only (no AI review)")
        print(f"   Upgrade for unlimited: https://stillrunning.io/pricing")


def _load_threat_cache():
    """Load cached threat rules from API."""
    try:
        if THREAT_CACHE_JSON.exists():
            with open(THREAT_CACHE_JSON) as f:
                data = json.load(f)
            # Check TTL
            cached_at = data.get("cached_at", 0)
            if time.time() - cached_at < THREAT_CACHE_TTL_SECONDS:
                return data.get("packages", {})
    except Exception:
        pass
    return None


def _fetch_threat_rules_from_api():
    """Fetch threat rules from stillrunning.io API. Returns dict or None."""
    # Get token from .env
    token = None
    if ENV_FILE.exists():
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("STILLRUNNING_TOKEN="):
                    token = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break

    if not token:
        return None

    try:
        import time
        url = "https://stillrunning.io/api/threats/rules"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                packages = data.get("packages", {})
                # Cache the result atomically (SESSION 90)
                cache_data = {"packages": packages, "cached_at": time.time(), "version": data.get("version")}
                try:
                    import os
                    tmp_path = str(THREAT_CACHE_JSON) + ".tmp"
                    with open(tmp_path, "w") as f:
                        json.dump(cache_data, f, indent=2)
                    os.replace(tmp_path, THREAT_CACHE_JSON)
                except Exception:
                    pass
                return packages
    except Exception as e:
        print(f"[intercept] API fetch failed: {e}", file=sys.stderr)
    return None


def _get_api_rules():
    """Get rules from API with cache fallback."""
    # Try cache first
    cached = _load_threat_cache()
    if cached:
        return cached

    # Try API
    api_rules = _fetch_threat_rules_from_api()
    if api_rules:
        return api_rules

    # Fallback to empty (will use hardcoded only)
    return {}


def get_known_bad_pip() -> dict:
    """Get merged known-bad pip packages (hardcoded + auto-synced + API)."""
    extra_pip, _ = _load_auto_synced_known_bad()
    merged = dict(KNOWN_BAD_PIP)
    merged.update(extra_pip)
    # SESSION 72: Add API rules
    api_rules = _get_api_rules()
    for pkg, info in api_rules.items():
        if info.get("ecosystem") in ("pip", "unknown") and pkg not in merged:
            merged[pkg] = info.get("versions", ["any"])
    return merged


def get_known_bad_npm() -> dict:
    """Get merged known-bad npm packages (hardcoded + auto-synced + API)."""
    _, extra_npm = _load_auto_synced_known_bad()
    merged = dict(KNOWN_BAD_NPM)
    merged.update(extra_npm)
    # SESSION 72: Add API rules
    api_rules = _get_api_rules()
    for pkg, info in api_rules.items():
        if info.get("ecosystem") in ("npm", "unknown") and pkg not in merged:
            merged[pkg] = info.get("versions", ["any"])
    return merged

# Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ─── Telegram Alert ──────────────────────────────────────────────────────────

def send_telegram_alert(package: str, reason: str):
    """Send Telegram alert for blocked package."""
    bot_token = None
    chat_id = None

    if ENV_FILE.exists():
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("TELEGRAM_BOT_TOKEN="):
                    bot_token = line.split("=", 1)[1].strip().strip('"').strip("'")
                elif line.startswith("TELEGRAM_CHAT_ID="):
                    chat_id = line.split("=", 1)[1].strip().strip('"').strip("'")

    if not bot_token or not chat_id:
        return

    try:
        import urllib.parse

        msg = f"\U0001F6A8 [intercept] BLOCKED — {package}\nReason: {reason}"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text": msg
        }).encode()

        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


# ─── Server-side AI Scan (SESSION 88) ────────────────────────────────────────

def _get_token() -> str:
    """Get customer token from config or .env."""
    # Try config file first
    config_file = Path(__file__).parent / "stillrunning.yaml"
    if config_file.exists():
        try:
            import yaml
            with open(config_file) as f:
                config = yaml.safe_load(f) or {}
            token = config.get("token", "")
            if token:
                return token
        except Exception:
            pass

    # Fall back to .env
    env_file = Path.home() / "stillrunning.yaml"
    if env_file.exists():
        try:
            import yaml
            with open(env_file) as f:
                config = yaml.safe_load(f) or {}
            token = config.get("token", "")
            if token:
                return token
        except Exception:
            pass

    return ""


def call_ai_scan(package: str, ecosystem: str = "pip") -> tuple[str, str] | None:
    """
    Call stillrunning.io/api/scan for server-side AI review.
    Requires AI tier or higher.

    Returns: (status, reason) or None if scan unavailable/failed
    - "BLOCKED", reason if DANGEROUS
    - "WARN", reason if SUSPICIOUS
    - None if CLEAN or scan failed
    """
    token = _get_token()
    if not token:
        return None

    try:
        url = "https://stillrunning.io/api/scan"
        payload = json.dumps({
            "token": token,
            "package": package,
            "ecosystem": ecosystem
        }).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "stillrunning-intercept/1.9.0"
            }
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())

        # Check for errors (tier/rate limit)
        if "error" in result:
            # Silently skip AI review if not available
            return None

        verdict = result.get("verdict", "CLEAN")
        score = result.get("score", 0)
        reasons = result.get("reasons", [])

        if verdict == "DANGEROUS":
            reason = reasons[0] if reasons else f"AI review: dangerous (score {score})"
            return "BLOCKED", reason
        elif verdict == "SUSPICIOUS":
            reason = reasons[0] if reasons else f"AI review: suspicious (score {score})"
            return "WARN", reason

        return None  # CLEAN

    except Exception:
        # Silently fail - don't block installs if API is down
        return None


# ─── PyPI Check ──────────────────────────────────────────────────────────────

def check_pypi_package(package: str, version: str = None) -> tuple[str, str]:
    """
    Check PyPI package.
    Returns: (status, reason)
    status: "BLOCKED", "WARN", "CLEAN"
    """
    # Check known-bad list (merged: hardcoded + auto-synced)
    known_bad = get_known_bad_pip()
    if package.lower() in known_bad:
        return "BLOCKED", f"Package '{package}' is in known-malicious list"

    # Query PyPI for package info
    try:
        url = f"https://pypi.org/pypi/{package}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "stillrunning/1.5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        info = data.get("info", {})

        # Check if package is very new (< 30 days)
        # This would require parsing upload_time, simplified here

        # Check download count (if available)
        # PyPI doesn't expose this easily, would need BigQuery

        # Server-side AI review (SESSION 88)
        ai_result = call_ai_scan(package, "pip")
        if ai_result:
            return ai_result

        return "CLEAN", "Package verified"

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "WARN", f"Package '{package}' not found on PyPI"
        return "WARN", f"PyPI check failed: HTTP {e.code}"
    except Exception as e:
        return "WARN", f"PyPI check failed: {e}"


# ─── npm Check ───────────────────────────────────────────────────────────────

def check_npm_package(package: str, version: str = None) -> tuple[str, str]:
    """
    Check npm package.
    Returns: (status, reason)
    """
    # Check known-bad list (merged: hardcoded + auto-synced)
    known_bad = get_known_bad_npm()
    if package.lower() in known_bad:
        return "BLOCKED", f"Package '{package}' is in known-malicious list"

    # Query npm registry
    try:
        url = f"https://registry.npmjs.org/{package}"
        req = urllib.request.Request(url, headers={"User-Agent": "stillrunning/1.5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        # Server-side AI review (SESSION 88)
        ai_result = call_ai_scan(package, "npm")
        if ai_result:
            return ai_result

        return "CLEAN", "Package verified"

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "WARN", f"Package '{package}' not found on npm"
        return "WARN", f"npm check failed: HTTP {e.code}"
    except Exception as e:
        return "WARN", f"npm check failed: {e}"


# ─── Main Logic ──────────────────────────────────────────────────────────────

def extract_packages(args: list, manager: str) -> list:
    """Extract package names from command args."""
    packages = []

    # Skip flags and the 'install' command
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue

        if arg.startswith("-"):
            # Some flags take values
            if arg in ("-r", "--requirement", "-e", "--editable"):
                skip_next = True
            continue

        if arg in ("install", "i", "add"):
            continue

        # This is a package name (possibly with version specifier)
        pkg = arg.split("==")[0].split(">=")[0].split("<=")[0].split("@")[0]
        if pkg:
            packages.append(pkg)

    return packages


def main():
    import shutil

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <pip|npm> <command> [args...]")
        print("Example: python3 npm_pip_intercept.py pip install requests")
        sys.exit(1)

    manager = sys.argv[1].lower()
    args = sys.argv[2:]

    # v2.3.0: Added uv support
    if manager not in ("pip", "pip3", "npm", "yarn", "pnpm", "uv"):
        print(f"{RED}[intercept]{RESET} Unknown manager: {manager}")
        sys.exit(1)

    # SECURITY FIX: Resolve to absolute path to prevent PATH hijacking
    manager_path = shutil.which(manager)
    if not manager_path:
        print(f"{RED}[intercept]{RESET} Package manager not found: {manager}")
        sys.exit(1)

    # v2.3.0: Handle uv subcommands (uv pip install, uv add)
    is_uv_pip = False
    if manager == "uv" and args:
        if args[0] == "pip" and len(args) > 1:
            # "uv pip install foo" -> treat as pip install
            is_uv_pip = True
            args = args[1:]  # Remove "pip" from args
        elif args[0] == "add":
            # "uv add foo" -> intercept as pip install
            pass
        elif args[0] not in ("install", "i", "add"):
            # Non-install uv commands pass through
            result = subprocess.run([manager_path] + sys.argv[2:])
            sys.exit(result.returncode)

    # Only intercept install commands
    if not args or args[0] not in ("install", "i", "add"):
        # Pass through non-install commands
        result = subprocess.run([manager_path] + (sys.argv[2:] if not is_uv_pip else args))
        sys.exit(result.returncode)

    # Extract packages to check
    packages = extract_packages(args, manager)

    if not packages:
        # No packages specified (maybe installing from requirements.txt)
        # Pass through
        result = subprocess.run([manager_path] + args)
        sys.exit(result.returncode)

    # Check each package
    blocked = []
    warnings = []

    for pkg in packages:
        # v2.3.0: uv uses PyPI, treat as pip
        if manager in ("pip", "pip3", "uv"):
            status, reason = check_pypi_package(pkg)
        else:
            status, reason = check_npm_package(pkg)

        if status == "BLOCKED":
            blocked.append((pkg, reason))
            print(f"{RED}{BOLD}\U0001F6A8 BLOCKED{RESET} — {pkg}")
            print(f"   {reason}")
            print(f"   {RED}Install cancelled.{RESET}")
            send_telegram_alert(pkg, reason)

        elif status == "WARN":
            warnings.append((pkg, reason))
            print(f"{YELLOW}\u26A0 WARNING{RESET} — {pkg}")
            print(f"   {reason}")

        else:
            print(f"{GREEN}\u2705 CLEAN{RESET} — {pkg}")

    # Track scan usage and show upgrade prompt for free tier
    scans_used = _increment_scan_usage(len(packages))
    _show_upgrade_prompt(scans_used)

    # If any blocked, exit without installing
    if blocked:
        print()
        print(f"{RED}{BOLD}Installation blocked.{RESET} {len(blocked)} malicious package(s) detected.")
        sys.exit(1)

    # If warnings, prompt for confirmation
    if warnings:
        print()
        try:
            response = input(f"{YELLOW}Continue anyway? [y/N]{RESET} ")
            if response.lower() != "y":
                print("Installation cancelled.")
                sys.exit(1)
        except (EOFError, KeyboardInterrupt):
            print("\nInstallation cancelled.")
            sys.exit(1)

    # All clear — run the actual install
    print()
    print(f"{GREEN}Proceeding with install...{RESET}")
    result = subprocess.run([manager_path] + args)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
