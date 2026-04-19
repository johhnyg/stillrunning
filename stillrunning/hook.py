#!/usr/bin/env python3
"""
stillrunning Import Hook — Intercepts Python imports for supply chain security.

DESIGN (SESSION 93):
- sys.meta_path finder intercepts every import
- Cache check is SYNC and instant (<1ms) — never blocks imports
- Unknown packages: allow import, scan in BACKGROUND thread
- Flag on NEXT import if background scan found issues
- DANGEROUS packages: hard block (ImportError), no override
- SUSPICIOUS/UNKNOWN: Telegram prompt with 60s auto-deny (install-time only)

Usage:
    import stillrunning.hook  # Activates hook for this session

Always-on:
    stillrunning --install-hook  # Creates .pth file in site-packages
"""

import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import sqlite3
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional

# ─── Constants ───────────────────────────────────────────────────────────────

# Database path — same as npm_pip_intercept uses
DB_PATH = Path("/root/my-app/package_security.db")
FALLBACK_DB_PATH = Path.home() / ".stillrunning" / "package_security.db"

# Config file for token
CONFIG_PATH = Path.home() / ".stillrunning" / "stillrunning.yaml"
ENV_PATH = Path("/root/my-app/.env")

# Cache for instant lookups (populated from SQLite)
_import_cache: dict = {}  # {package_name: {"status": "CLEAN/DANGEROUS/SUSPICIOUS", "score": int, "reason": str}}
_cache_lock = threading.Lock()

# Background scan queue
_scan_queue: set = set()  # Packages currently being scanned
_scan_queue_lock = threading.Lock()

# Flagged packages (found bad during background scan)
_flagged_packages: dict = {}  # {package_name: {"status": str, "reason": str}}
_flagged_lock = threading.Lock()

# Track what we've already scanned this session to avoid spam
_scanned_this_session: set = set()

# Trusted core packages — never scan, always allow
TRUSTED_CORE_PACKAGES = {
    # Python packaging infrastructure
    "pip", "setuptools", "wheel", "distutils", "packaging", "pyparsing",
    # Standard library adjacent
    "typing_extensions", "typing", "collections", "functools", "itertools",
    # AWS ecosystem
    "boto3", "botocore", "s3transfer", "aiobotocore", "awscli",
    # HTTP/network fundamentals
    "urllib3", "requests", "certifi", "charset_normalizer", "idna",
    # Type checking and validation
    "pydantic", "pydantic_core", "annotated_types", "attrs",
    # Flask/web ecosystem
    "flask", "werkzeug", "jinja2", "click", "itsdangerous", "markupsafe",
    "starlette", "uvicorn", "fastapi",
    # Cryptography
    "cryptography", "cffi", "pycparser", "pyjwt", "rsa", "pyasn1",
    # Testing
    "pytest", "pluggy", "coverage", "iniconfig", "mypy", "black", "flake8",
    # gRPC/protobuf
    "grpcio", "grpcio_status", "protobuf", "googleapis_common_protos",
    # Data science
    "pandas", "numpy", "scipy", "matplotlib", "pillow", "imageio", "pyarrow",
    # Database
    "sqlalchemy", "alembic", "greenlet", "sqlite3",
    # Date/time
    "python_dateutil", "pytz", "tzdata",
    # Async
    "aiohttp", "httpx", "httpcore", "anyio", "sniffio",
    # JSON/data
    "jsonschema", "jmespath", "pyyaml", "toml", "tomli", "dotenv",
    # Utilities
    "six", "tqdm", "rich", "pygments", "colorama", "wrapt",
    # AI SDKs
    "anthropic", "openai", "tiktoken", "google_genai",
    # stillrunning itself
    "stillrunning",
}


# ─── Database Functions ──────────────────────────────────────────────────────

def _get_db_path() -> Path:
    """Get the database path, falling back to home directory if server DB unavailable."""
    if DB_PATH.exists():
        return DB_PATH
    # Ensure fallback directory exists
    FALLBACK_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return FALLBACK_DB_PATH


def _init_local_db():
    """Initialize local database if needed."""
    db_path = _get_db_path()
    if not db_path.exists():
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                reasons TEXT,
                source TEXT DEFAULT 'hook',
                scanned_at TEXT NOT NULL,
                UNIQUE(name, version, ecosystem)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS flagged_imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                reason TEXT,
                flagged_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()


def _lookup_package(name: str) -> Optional[dict]:
    """Look up package in cache or database. Returns None if not found."""
    name_lower = name.lower().replace("-", "_")

    # Check memory cache first (instant)
    with _cache_lock:
        if name_lower in _import_cache:
            return _import_cache[name_lower]

    # Check database
    try:
        db_path = _get_db_path()
        if not db_path.exists():
            return None

        conn = sqlite3.connect(str(db_path), timeout=1.0)
        conn.row_factory = sqlite3.Row

        # Query for any version of this package
        row = conn.execute(
            "SELECT * FROM packages WHERE name=? AND ecosystem='pip' ORDER BY scanned_at DESC LIMIT 1",
            (name_lower,)
        ).fetchone()
        conn.close()

        if row:
            result = {
                "status": row["classification"],
                "score": row["score"],
                "reason": row["reasons"] or "",
            }
            # Cache it
            with _cache_lock:
                _import_cache[name_lower] = result
            return result
    except Exception:
        pass

    return None


def _check_flagged(name: str) -> Optional[dict]:
    """Check if package was flagged by background scan."""
    name_lower = name.lower().replace("-", "_")

    with _flagged_lock:
        if name_lower in _flagged_packages:
            return _flagged_packages[name_lower]

    # Also check database for flagged imports
    try:
        db_path = _get_db_path()
        if db_path.exists():
            conn = sqlite3.connect(str(db_path), timeout=1.0)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM flagged_imports WHERE name=?",
                (name_lower,)
            ).fetchone()
            conn.close()

            if row:
                return {"status": row["status"], "reason": row["reason"]}
    except Exception:
        pass

    return None


def _save_flagged(name: str, status: str, reason: str):
    """Save flagged package to database."""
    name_lower = name.lower().replace("-", "_")

    with _flagged_lock:
        _flagged_packages[name_lower] = {"status": status, "reason": reason}

    try:
        from datetime import datetime, timezone
        db_path = _get_db_path()
        _init_local_db()

        conn = sqlite3.connect(str(db_path), timeout=5.0)
        conn.execute("""
            INSERT OR REPLACE INTO flagged_imports (name, status, reason, flagged_at)
            VALUES (?, ?, ?, ?)
        """, (name_lower, status, reason, datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _clear_flagged(name: str):
    """Clear flagged status after user acknowledges."""
    name_lower = name.lower().replace("-", "_")

    with _flagged_lock:
        _flagged_packages.pop(name_lower, None)

    try:
        db_path = _get_db_path()
        if db_path.exists():
            conn = sqlite3.connect(str(db_path), timeout=5.0)
            conn.execute("DELETE FROM flagged_imports WHERE name=?", (name_lower,))
            conn.commit()
            conn.close()
    except Exception:
        pass


# ─── Background Scanning ─────────────────────────────────────────────────────

def _get_api_token() -> Optional[str]:
    """Get stillrunning API token from config or .env."""
    # Try config file
    if CONFIG_PATH.exists():
        try:
            import yaml
            with open(CONFIG_PATH) as f:
                config = yaml.safe_load(f) or {}
            token = config.get("token")
            if token:
                return token
        except Exception:
            pass

    # Try .env file
    if ENV_PATH.exists():
        try:
            with open(ENV_PATH) as f:
                for line in f:
                    if line.strip().startswith("STILLRUNNING_TOKEN="):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            pass

    return None


def _background_scan(package_name: str):
    """Scan package in background thread. Results flagged for next import."""
    name_lower = package_name.lower().replace("-", "_")

    # Already scanning?
    with _scan_queue_lock:
        if name_lower in _scan_queue:
            return
        _scan_queue.add(name_lower)

    def scan_worker():
        try:
            # Call stillrunning.io API for scan
            token = _get_api_token()
            if not token:
                # No token — can't scan, just allow
                return

            url = "https://stillrunning.io/api/check-package"
            payload = json.dumps({
                "name": package_name,
                "ecosystem": "pip",
                "source": "import_hook"
            }).encode()

            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "stillrunning-hook/2.0"
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())

            status = result.get("verdict", "CLEAN")
            score = result.get("score", 0)
            reason = result.get("reason", "")

            # Cache the result
            with _cache_lock:
                _import_cache[name_lower] = {
                    "status": status,
                    "score": score,
                    "reason": reason
                }

            # If suspicious or dangerous, flag for next import
            if status in ("DANGEROUS", "SUSPICIOUS") or score >= 50:
                _save_flagged(name_lower, status, reason)
                _send_alert(package_name, status, score, reason)

        except Exception as e:
            # Scan failed — don't block, just log
            print(f"[stillrunning] Background scan failed for {package_name}: {e}", file=sys.stderr)
        finally:
            with _scan_queue_lock:
                _scan_queue.discard(name_lower)

    # Start background thread
    thread = threading.Thread(target=scan_worker, daemon=True)
    thread.start()


def _send_alert(package: str, status: str, score: int, reason: str):
    """Send Telegram alert for flagged package."""
    try:
        # Read telegram config from .env
        bot_token = None
        chat_id = None

        if ENV_PATH.exists():
            with open(ENV_PATH) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("TELEGRAM_BOT_TOKEN="):
                        bot_token = line.split("=", 1)[1].strip().strip('"').strip("'")
                    elif line.startswith("TELEGRAM_CHAT_ID="):
                        chat_id = line.split("=", 1)[1].strip().strip('"').strip("'")

        if not bot_token or not chat_id:
            return

        emoji = "\U0001F6A8" if status == "DANGEROUS" else "\U0001F7E1"
        msg = (
            f"{emoji} [import hook] {status} package detected\n\n"
            f"Package: {package}\n"
            f"Score: {score}/100\n"
            f"Reason: {reason}\n\n"
            f"This package will be blocked on next import."
        )

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": msg}).encode()
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


# ─── Import Hook ─────────────────────────────────────────────────────────────

class StillRunningFinder(importlib.abc.MetaPathFinder):
    """
    Meta path finder that intercepts imports for security scanning.

    Design principles:
    1. NEVER block the import thread — cache lookups only
    2. Unknown packages: allow now, scan in background, flag for next time
    3. DANGEROUS packages (cached): hard block with ImportError
    4. SUSPICIOUS packages (cached): block with warning
    """

    def find_spec(self, fullname: str, path, target=None):
        """Called for every import. Must be fast."""
        # Only check top-level packages
        top_level = fullname.split(".")[0]

        # Skip trusted packages (instant)
        if top_level.lower().replace("-", "_") in TRUSTED_CORE_PACKAGES:
            return None

        # Skip standard library
        if top_level in sys.stdlib_module_names if hasattr(sys, 'stdlib_module_names') else False:
            return None

        # Skip if already in sys.modules (already imported)
        if fullname in sys.modules:
            return None

        name_lower = top_level.lower().replace("-", "_")

        # Check if flagged by previous background scan
        flagged = _check_flagged(name_lower)
        if flagged:
            status = flagged["status"]
            reason = flagged["reason"]

            if status == "DANGEROUS":
                # Hard block — no override
                raise ImportError(
                    f"\n\n"
                    f"\U0001F6A8 IMPORT BLOCKED by stillrunning\n"
                    f"Package: {top_level}\n"
                    f"Status: DANGEROUS\n"
                    f"Reason: {reason}\n\n"
                    f"This package was flagged as malicious during background scanning.\n"
                    f"No override available for DANGEROUS packages.\n"
                    f"Report false positive: security@stillrunning.io\n"
                )
            elif status == "SUSPICIOUS":
                # Block with warning — can be cleared
                raise ImportError(
                    f"\n\n"
                    f"\U0001F7E1 IMPORT BLOCKED by stillrunning\n"
                    f"Package: {top_level}\n"
                    f"Status: SUSPICIOUS\n"
                    f"Reason: {reason}\n\n"
                    f"This package behaves unusually.\n"
                    f"Review at: https://pypi.org/project/{top_level}\n"
                    f"To allow: stillrunning --allow {top_level}\n"
                    f"Upgrade for AI analysis: https://stillrunning.io/pricing\n"
                )

        # Check cache/database (instant lookup)
        cached = _lookup_package(name_lower)
        if cached:
            status = cached["status"]
            score = cached.get("score", 0)
            reason = cached.get("reason", "")

            if status == "DANGEROUS" or score >= 80:
                raise ImportError(
                    f"\n\n"
                    f"\U0001F6A8 IMPORT BLOCKED by stillrunning\n"
                    f"Package: {top_level}\n"
                    f"Score: {score}/100 — DANGEROUS\n"
                    f"Reason: {reason}\n\n"
                    f"No override available for DANGEROUS packages.\n"
                    f"Report false positive: security@stillrunning.io\n"
                )
            elif status == "SUSPICIOUS" or score >= 50:
                raise ImportError(
                    f"\n\n"
                    f"\U0001F7E1 IMPORT BLOCKED by stillrunning\n"
                    f"Package: {top_level}\n"
                    f"Score: {score}/100 — SUSPICIOUS\n"
                    f"Reason: {reason}\n\n"
                    f"To allow: stillrunning --allow {top_level}\n"
                    f"Upgrade for AI analysis: https://stillrunning.io/pricing\n"
                )
            # CLEAN — allow (return None to continue normal import)
            return None

        # Not in cache — allow import but scan in background
        if name_lower not in _scanned_this_session:
            _scanned_this_session.add(name_lower)
            _background_scan(top_level)

        # Return None to allow normal import mechanism to proceed
        return None


# ─── Hook Installation ───────────────────────────────────────────────────────

_hook_installed = False
_finder_instance = None


def install():
    """Install the import hook."""
    global _hook_installed, _finder_instance

    if _hook_installed:
        return

    _init_local_db()
    _finder_instance = StillRunningFinder()

    # Insert at the beginning to intercept before other finders
    sys.meta_path.insert(0, _finder_instance)
    _hook_installed = True

    print("[stillrunning] Import hook installed", file=sys.stderr)


def uninstall():
    """Uninstall the import hook."""
    global _hook_installed, _finder_instance

    if not _hook_installed or _finder_instance is None:
        return

    try:
        sys.meta_path.remove(_finder_instance)
    except ValueError:
        pass

    _hook_installed = False
    _finder_instance = None
    print("[stillrunning] Import hook uninstalled", file=sys.stderr)


def is_installed() -> bool:
    """Check if hook is installed."""
    return _hook_installed


# ─── .pth File Support ───────────────────────────────────────────────────────

def install_pth():
    """Install .pth file for always-on import protection."""
    import site

    # Find site-packages directory
    site_packages = None
    for path in site.getsitepackages():
        if "site-packages" in path and os.path.isdir(path):
            site_packages = path
            break

    if not site_packages:
        # Fallback to user site-packages
        site_packages = site.getusersitepackages()
        os.makedirs(site_packages, exist_ok=True)

    pth_path = os.path.join(site_packages, "stillrunning-hook.pth")

    # Write .pth file that imports the hook
    with open(pth_path, "w") as f:
        f.write("import stillrunning.hook\n")

    print(f"[stillrunning] Installed .pth file: {pth_path}")
    return pth_path


def uninstall_pth():
    """Remove .pth file."""
    import site

    for path in site.getsitepackages() + [site.getusersitepackages()]:
        pth_path = os.path.join(path, "stillrunning-hook.pth")
        if os.path.exists(pth_path):
            os.remove(pth_path)
            print(f"[stillrunning] Removed .pth file: {pth_path}")
            return True

    return False


# ─── CLI Support ─────────────────────────────────────────────────────────────

def allow_package(package_name: str):
    """Allow a previously blocked package."""
    name_lower = package_name.lower().replace("-", "_")

    # Clear from flagged
    _clear_flagged(name_lower)

    # Remove from cache if suspicious
    with _cache_lock:
        if name_lower in _import_cache:
            cached = _import_cache[name_lower]
            if cached.get("status") == "SUSPICIOUS":
                del _import_cache[name_lower]

    print(f"[stillrunning] Allowed package: {package_name}")


def block_package(package_name: str, reason: str = "Manually blocked"):
    """Manually block a package."""
    name_lower = package_name.lower().replace("-", "_")

    _save_flagged(name_lower, "DANGEROUS", reason)

    with _cache_lock:
        _import_cache[name_lower] = {
            "status": "DANGEROUS",
            "score": 100,
            "reason": reason
        }

    print(f"[stillrunning] Blocked package: {package_name}")


# ─── Auto-install on import ──────────────────────────────────────────────────

# Install hook when this module is imported
install()
