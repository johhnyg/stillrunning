#!/usr/bin/env python3
"""
StillRunning v1.2 — Lightweight process monitor with Telegram alerts and Shield security.

Usage:
    Quick start:  python3 stillrunning.py --setup
    Manual:       Edit stillrunning.yaml, then run: screen -dmS stillrunning python3 stillrunning.py
    Commands:     Text "status" or "help" to your Telegram bot

Requires: PyYAML (pip install pyyaml)
"""
from __future__ import annotations  # annotations stay strings: Python 3.8/3.9 can import this module

from stillrunning.apibase import api_base, api_url
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: pip install pyyaml")
    sys.exit(1)

# Version constant for telemetry — synced from features.json
VERSION = "2.14.3"

# Exit codes (v2.9.0 standardization)
EXIT_CLEAN = 0          # not on the blocklist (NOT a clean bill of health)
EXIT_ERROR = 1          # the check could not run (offline / server error / stale data)
EXIT_NOT_FOUND = 3      # name not on the registry (typo, typosquat or private index)
EXIT_USAGE = 2
EXIT_BLOCKED = 10
EXIT_SUSPICIOUS = 11
EXIT_RATE_LIMITED = 12
EXIT_WITHDRAWN = 13
EXIT_NEEDS_PERSON = 14  # part of it IS on the blocklist (some versions, or a local override
                        # allows a listed package): only a person at the keyboard may continue
EXIT_NOT_PROTECTED = 4  # --setup ended with no layer checking installs

# v2.5.0: Simple logger for exception visibility
import logging
_logger = logging.getLogger("stillrunning")
_logger.addHandler(logging.NullHandler())  # No output by default

def _enable_debug_logging():
    """Enable debug logging to stderr."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[stillrunning] %(levelname)s: %(message)s"))
    _logger.addHandler(handler)
    _logger.setLevel(logging.DEBUG)

if os.environ.get("STILLRUNNING_DEBUG", "").lower() in ("1", "true", "yes"):
    _enable_debug_logging()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PACKAGE_CONFIG_FILE = Path(__file__).parent / "stillrunning.yaml"
CONFIG: dict = {}


def config_file(for_write: bool = False) -> Path:
    """The --setup config: next to the package when this user can write there
    (root, venv and --user installs), else ~/.stillrunning/stillrunning.yaml
    (a normal user running a package root installed). Reading falls back to
    the package copy when the user has none of their own."""
    if os.access(PACKAGE_CONFIG_FILE.parent, os.W_OK):
        return PACKAGE_CONFIG_FILE
    user = Path.home() / ".stillrunning" / "stillrunning.yaml"
    if for_write or user.exists() or not PACKAGE_CONFIG_FILE.exists():
        return user
    return PACKAGE_CONFIG_FILE


class SetupSaveError(Exception):
    pass


class SetupInputError(Exception):
    pass


MENU_ATTEMPTS = 5


def _ask_menu_choice(choices: dict) -> str:
    """Ask until the answer is one of `choices` (Enter = "1"); give up after
    MENU_ATTEMPTS so piped junk cannot loop forever."""
    for _ in range(MENU_ATTEMPTS):
        answer = input("  Choose [1]: ").strip() or "1"
        if answer in choices:
            return answer
        print(f"  {answer[:20]!r} is not one of the choices. Type {', '.join(choices)} and press Enter.")
    raise SetupInputError(f"no valid choice after {MENU_ATTEMPTS} tries")


def _save_setup_config(config: dict) -> Path:
    """Write the setup config atomically. In the per-user file, owner-only (it
    can hold a Telegram token), keeping a legacy `token:` / `api_token:`."""
    path = config_file(for_write=True)
    in_home = path != PACKAGE_CONFIG_FILE
    tmp = path.with_suffix(".yaml.tmp")
    try:
        if in_home:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(path) as f:
                    old = yaml.safe_load(f)
            except FileNotFoundError:
                old = None
            except (OSError, ValueError, yaml.YAMLError) as e:
                print(f"  WARNING: could not read the old {path} ({type(e).__name__}); replacing it.")
                old = None
            if isinstance(old, dict):
                config = {**{k: old[k] for k in ("token", "api_token") if old.get(k)}, **config}
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            f = os.fdopen(fd, "w")
        else:
            f = open(tmp, "w")
        with f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        os.replace(tmp, path)
    except OSError as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise SetupSaveError(f"could not save the setup config to {path}: {e.strerror or e}") from e
    return path


def load_config() -> dict:
    global CONFIG
    config_path = config_file()
    if not config_path.exists():
        print(f"ERROR: Config file not found: {config_path}")
        print("Copy stillrunning.yaml.example to stillrunning.yaml and fill in your config.")
        sys.exit(1)

    with open(config_path) as f:
        CONFIG = yaml.safe_load(f) or {}

    # Set defaults
    CONFIG.setdefault("app_name", "StillRunning")
    CONFIG.setdefault("working_dir", str(Path(__file__).parent))
    CONFIG.setdefault("processes", [])
    CONFIG.setdefault("log_files", [])
    CONFIG.setdefault("health_file", None)
    CONFIG.setdefault("health_max_age_sec", 180)
    CONFIG.setdefault("thresholds", {})
    CONFIG.setdefault("intervals", {})

    # Threshold defaults
    thresholds = CONFIG["thresholds"]
    thresholds.setdefault("cpu_percent", 85)
    thresholds.setdefault("mem_percent", 85)
    thresholds.setdefault("disk_percent", 85)
    thresholds.setdefault("process_mem_mb", 500)
    thresholds.setdefault("latency_url", None)
    thresholds.setdefault("latency_warn_ms", 1500)

    # Interval defaults
    intervals = CONFIG["intervals"]
    intervals.setdefault("process_check_sec", 30)
    intervals.setdefault("resource_check_sec", 60)
    intervals.setdefault("log_archive_sec", 300)
    intervals.setdefault("health_check_sec", 60)
    intervals.setdefault("latency_check_sec", 120)
    intervals.setdefault("heartbeat_sec", 86400)
    intervals.setdefault("telegram_poll_sec", 5)

    # Restart behavior
    CONFIG.setdefault("restart_cooldown_sec", 120)
    CONFIG.setdefault("max_consecutive_failures", 3)

    return CONFIG


# ---------------------------------------------------------------------------
# Paths & state
# ---------------------------------------------------------------------------
def get_working_dir() -> Path:
    return Path(CONFIG.get("working_dir", "."))


def get_state_file() -> Path:
    return Path(__file__).parent / ".stillrunning_state.json"


_state: dict = {
    "restart_cooldowns": {},       # {process_name: last_restart_timestamp}
    "consecutive_failures": {},    # {process_name: count}
    "disabled_processes": set(),   # processes that hit max failures
}

# Subscription features (populated on startup from token validation)
# Default: free tier features only
SUBSCRIPTION_FEATURES: list = ["process_monitor", "restart", "alerts"]


def load_state() -> None:
    global _state
    state_file = get_state_file()
    try:
        if state_file.exists():
            with open(state_file) as f:
                data = json.load(f)
                _state["restart_cooldowns"] = data.get("restart_cooldowns", {})
                _state["consecutive_failures"] = data.get("consecutive_failures", {})
                _state["disabled_processes"] = set(data.get("disabled_processes", []))
    except Exception as e:
        _logger.debug("load_state failed (fresh start): %s", e)


def save_state() -> None:
    """Save state atomically (SESSION 90: temp file + rename)."""
    try:
        state_file = get_state_file()
        tmp_file = state_file.with_suffix(".tmp")
        with open(tmp_file, "w") as f:
            json.dump({
                "restart_cooldowns": _state["restart_cooldowns"],
                "consecutive_failures": _state["consecutive_failures"],
                "disabled_processes": list(_state["disabled_processes"]),
            }, f, indent=2)
        import os
        os.replace(tmp_file, state_file)
    except Exception as e:
        _logger.debug("save_state failed: %s", e)


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------
def get_telegram_token() -> str:
    return CONFIG.get("telegram_bot_token", "")


def get_telegram_chat_id() -> str:
    return str(CONFIG.get("telegram_chat_id", ""))


def send_telegram(msg: str) -> bool:
    """Send a message via Telegram. Returns True on success."""
    token = get_telegram_token()
    chat_id = get_telegram_chat_id()
    if not token or not chat_id:
        return False
    try:
        app_name = CONFIG.get("app_name", "StillRunning")
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": chat_id,
            "text": f"[{app_name}] {msg}",
        }).encode()
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False


def get_telegram_updates(offset: int = 0) -> list:
    """Get updates from Telegram bot."""
    token = get_telegram_token()
    if not token:
        return []
    try:
        url = f"https://api.telegram.org/bot{token}/getUpdates"
        params = f"?timeout=1&offset={offset}"
        req = urllib.request.Request(url + params)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
            return data.get("result", [])
    except Exception:
        return []


def send_telegram_typing(chat_id: str) -> None:
    """Send typing indicator to Telegram."""
    token = get_telegram_token()
    if not token:
        return
    try:
        url = f"https://api.telegram.org/bot{token}/sendChatAction"
        payload = json.dumps({"chat_id": chat_id, "action": "typing"}).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Telegram Two-Way Control (AI tier)
# ---------------------------------------------------------------------------
_telegram_rate_limit: dict = {}  # {chat_id: [(timestamp, ...), ...]}
_telegram_conversation: dict = {}  # {chat_id: [{"role": "user/assistant", "content": "..."}, ...]}
TELEGRAM_RATE_LIMIT = 20  # messages per hour
TELEGRAM_CONV_MAX = 6  # keep last 6 messages


def _sanitize_log_content(text: str) -> str:
    """Remove potential secrets from log content before sending."""
    patterns = [
        r'sk-[a-zA-Z0-9-_]{20,}',              # Anthropic keys
        r'sk_live_[a-zA-Z0-9]{20,}',           # Stripe live keys
        r'sk_test_[a-zA-Z0-9]{20,}',           # Stripe test keys
        r'[a-zA-Z0-9]{32,}:[a-zA-Z0-9-_]{32,}', # API key:secret pairs
        r'password\s*[=:]\s*\S+',              # password=value
        r'passwd\s*[=:]\s*\S+',                # passwd=value
        r'secret\s*[=:]\s*\S+',                # secret=value
        r'token\s*[=:]\s*[a-zA-Z0-9-_]{10,}',  # token=value
        r'key\s*[=:]\s*[a-zA-Z0-9-_]{20,}',    # key=value (long)
        r'Bearer\s+[a-zA-Z0-9-_.]{20,}',       # Bearer tokens
        r'[0-9a-f]{64}',                       # 64-char hex (common secret format)
    ]
    sanitized = text
    for pattern in patterns:
        sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
    return sanitized


def _check_telegram_rate_limit(chat_id: str) -> bool:
    """Check if user is within rate limit. Returns True if allowed."""
    now = time.time()
    if chat_id not in _telegram_rate_limit:
        _telegram_rate_limit[chat_id] = []
    # Remove old entries (older than 1 hour)
    _telegram_rate_limit[chat_id] = [ts for ts in _telegram_rate_limit[chat_id] if now - ts < 3600]
    if len(_telegram_rate_limit[chat_id]) >= TELEGRAM_RATE_LIMIT:
        return False
    _telegram_rate_limit[chat_id].append(now)
    return True


def _get_process_logs(process_name: str, lines: int = 20) -> str | None:
    """Get last N lines of a process log. Only for configured processes."""
    # SECURITY FIX: Prevent path traversal attacks
    if not process_name or "/" in process_name or "\\" in process_name or ".." in process_name:
        return None
    # Only allow alphanumeric, dash, underscore
    if not all(c.isalnum() or c in "-_" for c in process_name):
        return None

    processes = CONFIG.get("processes", [])
    # Verify process is in config
    if not any(p.get("name") == process_name or p.get("screen") == process_name for p in processes):
        return None

    # Try common log paths
    log_paths = CONFIG.get("log_files", [])
    working_dir = get_working_dir()

    # Also check standard locations
    check_paths = [
        working_dir / f"{process_name}.log",
        working_dir / "logs" / f"{process_name}.log",
        Path(f"/var/log/{process_name}.log"),
    ]
    # Add configured log files
    for lf in log_paths:
        check_paths.append(working_dir / lf.get("path", ""))

    for path in check_paths:
        try:
            if path.exists() and path.is_file():
                with open(path, "r", errors="ignore") as f:
                    all_lines = f.readlines()
                    content = "".join(all_lines[-lines:])
                    return _sanitize_log_content(content)
        except Exception:
            continue
    return None


def _restart_configured_process(process_name: str) -> tuple[bool, str]:
    """Restart a process if it's in the config. Returns (success, message)."""
    processes = CONFIG.get("processes", [])
    for proc in processes:
        if proc.get("name") == process_name or proc.get("screen") == process_name:
            success = restart_session(proc)
            if success:
                return True, f"Restarted {process_name}"
            else:
                return False, f"Failed to restart {process_name} (may be on cooldown)"
    return False, f"Process '{process_name}' not found in config"


def _get_ai_context() -> str:
    """Build context string for AI chat."""
    processes = CONFIG.get("processes", [])
    process_status = []
    for proc in processes:
        name = proc.get("name", "unknown")
        screen = proc.get("screen", name)
        running = is_session_running(screen)
        status = "UP" if running else "DOWN"
        process_status.append(f"  {name}: {status}")

    cpu = get_cpu_percent()
    mem = get_mem_percent()
    disk = get_disk_percent("/")

    # Get Shield status
    shield_status = f"Grade {_shield_stats.get('grade', 'A')}, {_shield_stats.get('attacks_today', 0)} attacks today"

    # Get last 5 crashes from process history
    crashes = []
    for name, history in list(_process_history.items())[-5:]:
        for ts, status in history[-5:]:
            if status == "DOWN":
                crashes.append(f"{name} at {datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%H:%M')}")

    context = f"""System Status:
Processes:
{chr(10).join(process_status) if process_status else '  (none configured)'}

Resources:
  CPU: {cpu:.1f}% if cpu else 'n/a'
  Memory: {mem:.1f}% if mem else 'n/a'
  Disk: {disk:.1f}% if disk else 'n/a'

Shield: {shield_status}

Recent crashes: {', '.join(crashes[-5:]) if crashes else 'none'}

Available commands: status, restart [process], logs [process], shield, help"""
    return context


def _ask_claude(question: str, chat_id: str) -> str | None:
    """Ask Claude a question with system context. AI tier only."""
    anthropic_key = CONFIG.get("anthropic_api_key", "")
    if not anthropic_key:
        return None

    try:
        # Get conversation history
        history = _telegram_conversation.get(chat_id, [])

        # Build context
        context = _get_ai_context()

        # Build messages
        messages = [
            {"role": "user", "content": f"[System context - do not repeat this to user]\n{context}\n\n[User question]\n{question}"}
        ]
        # Add conversation history (last 6)
        for msg in history[-TELEGRAM_CONV_MAX:]:
            messages.append(msg)
        messages.append({"role": "user", "content": question})

        payload = json.dumps({
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 500,
            "system": "You are a helpful server monitoring assistant. Keep responses concise (under 200 words). You can explain process status, suggest fixes, and answer questions about the monitored system. Never execute commands yourself - only explain what the user can do.",
            "messages": messages[-6:]  # Keep context small
        }).encode()

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": anthropic_key,
                "anthropic-version": "2023-06-01"
            }
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            response = result.get("content", [{}])[0].get("text", "")

            # Update conversation history
            if chat_id not in _telegram_conversation:
                _telegram_conversation[chat_id] = []
            _telegram_conversation[chat_id].append({"role": "user", "content": question})
            _telegram_conversation[chat_id].append({"role": "assistant", "content": response})
            # Trim history
            _telegram_conversation[chat_id] = _telegram_conversation[chat_id][-TELEGRAM_CONV_MAX:]

            return response
    except Exception as e:
        print(f"[stillrunning] Claude API error: {e}", flush=True)
        return None


# ---------------------------------------------------------------------------
# Screen session management
# ---------------------------------------------------------------------------
_restart_lock = threading.Lock()


def is_session_running(session_name: str) -> bool:
    """Check if a screen session exists."""
    try:
        result = subprocess.run(
            ["screen", "-ls"],
            capture_output=True, text=True, timeout=10,
        )
        return session_name in result.stdout
    except Exception as e:
        print(f"[stillrunning] WARNING: screen check failed: {e}", flush=True)
        return True  # Assume alive to avoid false restart


def restart_session(process_config: dict) -> bool:
    """
    Restart a screen session.
    Returns True if restart was attempted, False if skipped (cooldown/disabled).
    """
    name = process_config["name"]
    screen = process_config["screen"]
    script = process_config["script"]
    cooldown = CONFIG.get("restart_cooldown_sec", 120)
    max_failures = CONFIG.get("max_consecutive_failures", 3)

    with _restart_lock:
        now = time.time()

        # Check if disabled due to max failures
        if name in _state["disabled_processes"]:
            return False

        # Check cooldown
        last_restart = _state["restart_cooldowns"].get(name, 0.0)
        if now - last_restart < cooldown:
            return False

        # Update state
        _state["restart_cooldowns"][name] = now
        failures = _state["consecutive_failures"].get(name, 0) + 1
        _state["consecutive_failures"][name] = failures
        save_state()

        # Check if we've hit max failures
        if failures >= max_failures:
            _state["disabled_processes"].add(name)
            save_state()
            print(f"[stillrunning] DISABLED: {name} after {failures} consecutive failures", flush=True)
            send_telegram(
                f"CRITICAL: {name} disabled after {failures} consecutive restart failures.\n"
                f"Manual intervention required.\n"
                f"To re-enable: delete {name} from .stillrunning_state.json disabled_processes"
            )
            return False

        # Attempt restart
        try:
            script_path = get_working_dir() / script
            print(f"[stillrunning] Restarting {name} (attempt {failures}/{max_failures})", flush=True)
            subprocess.run(
                ["screen", "-dmS", screen, "python3", str(script_path)],
                cwd=str(get_working_dir()),
                timeout=30,
            )
            send_telegram(f"{name} crashed — restarted (attempt {failures}/{max_failures})")
            return True
        except Exception as exc:
            print(f"[stillrunning] Restart failed for {name}: {exc}", flush=True)
            return False


def mark_process_healthy(name: str) -> None:
    """Reset failure count when process is seen running."""
    if _state["consecutive_failures"].get(name, 0) > 0:
        _state["consecutive_failures"][name] = 0
        save_state()


# ---------------------------------------------------------------------------
# Resource monitoring
# ---------------------------------------------------------------------------
def get_cpu_percent() -> float | None:
    """Two-sample /proc/stat read — 0.5s apart."""
    try:
        def read_stat():
            with open("/proc/stat") as f:
                line = f.readline()
            vals = list(map(int, line.split()[1:8]))
            idle = vals[3]
            total = sum(vals)
            return idle, total

        idle1, total1 = read_stat()
        time.sleep(0.5)
        idle2, total2 = read_stat()
        diff_total = total2 - total1
        diff_idle = idle2 - idle1
        if diff_total == 0:
            return None
        return 100.0 * (1.0 - diff_idle / diff_total)
    except Exception:
        return None


def get_mem_percent() -> float | None:
    """Read memory usage from /proc/meminfo."""
    try:
        info: dict = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(":")] = int(parts[1])
        total = info.get("MemTotal", 0)
        available = info.get("MemAvailable", 0)
        if total == 0:
            return None
        return 100.0 * (1.0 - available / total)
    except Exception:
        return None


def get_disk_percent(path: str = "/") -> float | None:
    """Get disk usage percentage for a path."""
    try:
        result = subprocess.run(
            ["df", "-P", path],
            capture_output=True, text=True, timeout=10,
        )
        lines = result.stdout.strip().splitlines()
        if len(lines) < 2:
            return None
        parts = lines[1].split()
        return float(parts[4].rstrip("%"))
    except Exception:
        return None


def get_process_memory_kb(process_name: str) -> int | None:
    """Get RSS memory in KB for a process by name."""
    try:
        pgrep_result = subprocess.run(
            ["pgrep", "-f", process_name],
            capture_output=True, text=True, timeout=10,
        )
        pids = pgrep_result.stdout.strip().split()
        if not pids:
            return None

        pid = pids[0]
        ps_result = subprocess.run(
            ["ps", "-o", "rss=", "-p", pid],
            capture_output=True, text=True, timeout=10,
        )
        rss_str = ps_result.stdout.strip()
        if rss_str:
            return int(rss_str)
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Latency monitoring
# ---------------------------------------------------------------------------
def measure_latency_ms(url: str) -> float | None:
    """Measure round-trip latency to a URL in milliseconds."""
    try:
        start = time.monotonic()
        req = urllib.request.Request(url, headers={"User-Agent": "StillRunning/1.0"})
        urllib.request.urlopen(req, timeout=10)
        return (time.monotonic() - start) * 1000.0
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Log archiving
# ---------------------------------------------------------------------------
def archive_log(log_config: dict) -> None:
    """Archive a log file if it exceeds max size."""
    try:
        log_path = get_working_dir() / log_config["path"]
        max_bytes = log_config.get("max_mb", 10) * 1024 * 1024
        keep = log_config.get("keep_archives", 5)

        if not log_path.exists():
            return
        if log_path.stat().st_size < max_bytes:
            return

        archive_dir = log_path.parent / "log_archives"
        archive_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive = archive_dir / f"{log_path.stem}_{ts}.log.gz"

        # Compress
        with open(log_path, "rb") as f_in, gzip.open(archive, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        # Truncate
        with open(log_path, "r+b") as f:
            f.truncate(0)

        # Prune old archives
        archives = sorted(archive_dir.glob(f"{log_path.stem}_*.log.gz"))
        for old in archives[:-keep]:
            try:
                old.unlink()
            except Exception:
                pass

        print(f"[stillrunning] Archived {log_path.name} -> {archive.name}", flush=True)
    except Exception as exc:
        print(f"[stillrunning] Log archive failed: {exc}", flush=True)


def force_log_rotation(log_config: dict) -> None:
    """Force rotation regardless of size — called when disk critical."""
    try:
        log_path = get_working_dir() / log_config["path"]
        keep = log_config.get("keep_archives", 5)

        if not log_path.exists():
            return

        archive_dir = log_path.parent / "log_archives"
        archive_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive = archive_dir / f"{log_path.stem}_{ts}.log.gz"

        with open(log_path, "rb") as f_in, gzip.open(archive, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        with open(log_path, "r+b") as f:
            f.truncate(0)

        archives = sorted(archive_dir.glob(f"{log_path.stem}_*.log.gz"))
        for old in archives[:-keep]:
            try:
                old.unlink()
            except Exception:
                pass

        print(f"[stillrunning] Forced rotation: {log_path.name}", flush=True)
    except Exception as exc:
        print(f"[stillrunning] Force rotation failed: {exc}", flush=True)


# ---------------------------------------------------------------------------
# Status summary
# ---------------------------------------------------------------------------
def get_status_summary() -> str:
    """Generate a live status summary."""
    lines = []
    app_name = CONFIG.get("app_name", "StillRunning")
    lines.append(f"=== {app_name} Status ===")
    lines.append("")

    # Process status
    processes = CONFIG.get("processes", [])
    if processes:
        lines.append("Processes:")
        for proc in processes:
            name = proc["name"]
            screen = proc["screen"]
            running = is_session_running(screen)
            disabled = name in _state["disabled_processes"]
            failures = _state["consecutive_failures"].get(name, 0)

            if disabled:
                status = "DISABLED"
            elif running:
                status = "OK"
            else:
                status = "DOWN"

            line = f"  {name}: {status}"
            if failures > 0 and not disabled:
                line += f" (failures: {failures})"
            lines.append(line)
        lines.append("")

    # Resources
    cpu = get_cpu_percent()
    mem = get_mem_percent()
    disk = get_disk_percent("/")

    lines.append("Resources:")
    lines.append(f"  CPU:  {cpu:.1f}%" if cpu is not None else "  CPU:  n/a")
    lines.append(f"  Mem:  {mem:.1f}%" if mem is not None else "  Mem:  n/a")
    lines.append(f"  Disk: {disk:.1f}%" if disk is not None else "  Disk: n/a")

    # Latency
    latency_url = CONFIG["thresholds"].get("latency_url")
    if latency_url:
        latency = measure_latency_ms(latency_url)
        lines.append(f"  Latency: {latency:.0f}ms" if latency else "  Latency: n/a")

    lines.append("")
    lines.append(f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Startup check
# ---------------------------------------------------------------------------
def startup_check() -> None:
    """Verify all configured processes are running at startup."""
    print("[stillrunning] Running startup check...", flush=True)

    processes = CONFIG.get("processes", [])
    if not processes:
        print("[stillrunning] No processes configured", flush=True)
        return

    all_ok = True
    problems = []
    ok_count = 0

    for proc in processes:
        name = proc["name"]
        screen = proc["screen"]

        if name in _state["disabled_processes"]:
            problems.append(f"{name}: DISABLED (hit max failures)")
            all_ok = False
        elif not is_session_running(screen):
            problems.append(f"{name}: NOT RUNNING")
            all_ok = False
        else:
            print(f"  {name}: OK", flush=True)
            ok_count += 1

    if all_ok:
        send_telegram(f"Startup check passed — {ok_count} process(es) running")
    else:
        msg = "Startup check FAILED:\n" + "\n".join(f"  - {p}" for p in problems)
        print(f"[stillrunning] {msg}", flush=True)
        send_telegram(msg)


# ---------------------------------------------------------------------------
# Monitor loops
# ---------------------------------------------------------------------------
_alert_state: dict = {
    "cpu": {"alerted": False, "last": 0.0},
    "mem": {"alerted": False, "last": 0.0},
    "disk": {"alerted": False, "last": 0.0},
    "latency": {"alerted": False, "last": 0.0},
    "health": {"alerted": False, "last": 0.0},
}
_process_mem_alerts: dict = {}  # {name: {"alerted": bool, "last": float}}
ALERT_COOLDOWN = 3600  # 1 hour


def process_watchdog_loop() -> None:
    """Monitor all configured processes."""
    interval = CONFIG["intervals"]["process_check_sec"]
    while True:
        try:
            for proc in CONFIG.get("processes", []):
                name = proc["name"]
                screen = proc["screen"]

                if is_session_running(screen):
                    mark_process_healthy(name)
                else:
                    restart_session(proc)
        except Exception as exc:
            print(f"[stillrunning] Process watchdog error: {exc}", flush=True)
        time.sleep(interval)


def resource_check_loop() -> None:
    """Monitor CPU, memory, disk."""
    interval = CONFIG["intervals"]["resource_check_sec"]
    thresholds = CONFIG["thresholds"]

    while True:
        try:
            now = time.time()
            cpu = get_cpu_percent()
            mem = get_mem_percent()
            disk = get_disk_percent("/")

            # CPU
            if cpu is not None:
                cpu_warn = thresholds["cpu_percent"]
                state = _alert_state["cpu"]
                if cpu >= cpu_warn:
                    if not state["alerted"] or now - state["last"] > ALERT_COOLDOWN:
                        send_telegram(f"ALERT: CPU at {cpu:.1f}% (threshold {cpu_warn}%)")
                        state["alerted"] = True
                        state["last"] = now
                else:
                    state["alerted"] = False

            # Memory
            if mem is not None:
                mem_warn = thresholds["mem_percent"]
                state = _alert_state["mem"]
                if mem >= mem_warn:
                    if not state["alerted"] or now - state["last"] > ALERT_COOLDOWN:
                        send_telegram(f"ALERT: Memory at {mem:.1f}% (threshold {mem_warn}%)")
                        state["alerted"] = True
                        state["last"] = now
                else:
                    state["alerted"] = False

            # Disk
            if disk is not None:
                disk_warn = thresholds["disk_percent"]
                state = _alert_state["disk"]
                if disk >= disk_warn:
                    if not state["alerted"] or now - state["last"] > ALERT_COOLDOWN:
                        send_telegram(f"ALERT: Disk at {disk:.1f}% (threshold {disk_warn}%)")
                        state["alerted"] = True
                        state["last"] = now
                else:
                    state["alerted"] = False

                # Force log rotation at 90%
                if disk >= 90:
                    send_telegram(f"CRITICAL: Disk at {disk:.1f}% — forcing log rotation")
                    for log_cfg in CONFIG.get("log_files", []):
                        force_log_rotation(log_cfg)

            # Per-process memory
            proc_mem_warn_kb = thresholds["process_mem_mb"] * 1024
            for proc in CONFIG.get("processes", []):
                name = proc["name"]
                script = proc["script"]
                rss_kb = get_process_memory_kb(script)

                if rss_kb is not None:
                    if name not in _process_mem_alerts:
                        _process_mem_alerts[name] = {"alerted": False, "last": 0.0}
                    state = _process_mem_alerts[name]

                    if rss_kb >= proc_mem_warn_kb:
                        if not state["alerted"] or now - state["last"] > ALERT_COOLDOWN:
                            rss_mb = rss_kb / 1024
                            send_telegram(
                                f"ALERT: {name} using {rss_mb:.0f}MB "
                                f"(threshold {thresholds['process_mem_mb']}MB)"
                            )
                            state["alerted"] = True
                            state["last"] = now
                    else:
                        state["alerted"] = False

        except Exception as exc:
            print(f"[stillrunning] Resource check error: {exc}", flush=True)
        time.sleep(interval)


def latency_check_loop() -> None:
    """Monitor latency to configured URL."""
    interval = CONFIG["intervals"]["latency_check_sec"]
    url = CONFIG["thresholds"].get("latency_url")

    if not url:
        return  # No URL configured, exit thread

    time.sleep(30)  # Startup delay

    while True:
        try:
            now = time.time()
            latency = measure_latency_ms(url)
            warn_ms = CONFIG["thresholds"]["latency_warn_ms"]
            state = _alert_state["latency"]

            if latency is not None and latency >= warn_ms:
                if not state["alerted"] or now - state["last"] > ALERT_COOLDOWN:
                    send_telegram(
                        f"ALERT: Latency to {url} is {latency:.0f}ms (threshold {warn_ms}ms)"
                    )
                    state["alerted"] = True
                    state["last"] = now
            elif latency is not None:
                state["alerted"] = False

        except Exception as exc:
            print(f"[stillrunning] Latency check error: {exc}", flush=True)
        time.sleep(interval)


def health_file_loop() -> None:
    """Monitor health file freshness."""
    health_file = CONFIG.get("health_file")
    if not health_file:
        return  # Not configured, exit thread

    interval = CONFIG["intervals"]["health_check_sec"]
    max_age = CONFIG["health_max_age_sec"]

    while True:
        try:
            path = get_working_dir() / health_file
            if path.exists():
                age = time.time() - os.path.getmtime(path)
                now = time.time()
                state = _alert_state["health"]

                if age > max_age:
                    if not state["alerted"] or now - state["last"] > ALERT_COOLDOWN:
                        send_telegram(
                            f"WARNING: {health_file} is {age:.0f}s old "
                            f"(threshold {max_age}s) — app may be frozen"
                        )
                        state["alerted"] = True
                        state["last"] = now
                else:
                    state["alerted"] = False

        except Exception as exc:
            print(f"[stillrunning] Health file check error: {exc}", flush=True)
        time.sleep(interval)


def log_archiver_loop() -> None:
    """Archive log files when they exceed size limits."""
    interval = CONFIG["intervals"]["log_archive_sec"]

    while True:
        try:
            for log_cfg in CONFIG.get("log_files", []):
                archive_log(log_cfg)
        except Exception as exc:
            print(f"[stillrunning] Log archiver error: {exc}", flush=True)
        time.sleep(interval)


def heartbeat_loop() -> None:
    """Send daily status summary."""
    interval = CONFIG["intervals"]["heartbeat_sec"]
    time.sleep(60)  # Startup delay

    while True:
        try:
            summary = get_status_summary()
            shield_summary = get_shield_summary()
            send_telegram(f"Daily heartbeat\n\n{summary}\n\n{shield_summary}")
        except Exception as exc:
            print(f"[stillrunning] Heartbeat error: {exc}", flush=True)
        time.sleep(interval)


def telegram_command_loop() -> None:
    """Listen for Telegram commands and AI chat (AI tier)."""
    interval = CONFIG["intervals"]["telegram_poll_sec"]
    last_update_id = 0
    chat_id = get_telegram_chat_id()
    tier = CONFIG.get("tier", "basic")
    anthropic_key = CONFIG.get("anthropic_api_key", "")

    if not chat_id:
        return  # No chat ID configured, exit thread

    while True:
        try:
            updates = get_telegram_updates(offset=last_update_id + 1)
            for update in updates:
                last_update_id = update.get("update_id", last_update_id)
                message = update.get("message", {})
                msg_chat_id = str(message.get("chat", {}).get("id", ""))
                text = message.get("text", "").strip()
                text_lower = text.lower()

                # Only respond to configured chat
                if msg_chat_id != chat_id:
                    continue

                # Check rate limit
                if not _check_telegram_rate_limit(msg_chat_id):
                    send_telegram("Rate limit reached (20 messages/hour). Try again later.")
                    continue

                # Handle commands
                if text_lower == "status":
                    summary = get_status_summary()
                    shield_summary = get_shield_summary()
                    send_telegram(f"{summary}\n\n{shield_summary}")

                elif text_lower == "help":
                    help_text = (
                        "Commands:\n"
                        "  status — process & resource status\n"
                        "  restart [name] — restart a process\n"
                        "  logs [name] — view last 20 log lines\n"
                        "  shield — security status\n"
                        "  enable all — re-enable disabled processes\n"
                        "  help — show this message"
                    )
                    if tier == "ai" and anthropic_key:
                        help_text += "\n\nAI chat enabled — ask any question!"
                    send_telegram(help_text)

                elif text_lower.startswith("restart "):
                    process_name = text[8:].strip()
                    if not process_name:
                        send_telegram("Usage: restart [process_name]")
                    else:
                        success, msg = _restart_configured_process(process_name)
                        send_telegram(msg)

                elif text_lower.startswith("logs "):
                    process_name = text[5:].strip()
                    if not process_name:
                        send_telegram("Usage: logs [process_name]")
                    else:
                        logs = _get_process_logs(process_name)
                        if logs:
                            # Truncate if too long for Telegram
                            if len(logs) > 3500:
                                logs = logs[-3500:]
                            send_telegram(f"Last 20 lines of {process_name}:\n\n{logs}")
                        else:
                            send_telegram(f"No logs found for '{process_name}' (must be in config)")

                elif text_lower == "shield":
                    shield_info = (
                        f"Shield Security\n\n"
                        f"Grade: {_shield_stats.get('grade', 'A')}\n"
                        f"Attacks today: {_shield_stats.get('attacks_today', 0)}\n"
                        f"IPs banned: {_shield_stats.get('ips_banned', 0)}\n"
                    )
                    last_attack = _shield_stats.get('last_attack_ts')
                    if last_attack:
                        shield_info += f"Last attack: {last_attack[:19]}"
                    send_telegram(shield_info)

                elif text_lower == "enable all":
                    if _state["disabled_processes"]:
                        names = list(_state["disabled_processes"])
                        _state["disabled_processes"].clear()
                        for name in names:
                            _state["consecutive_failures"][name] = 0
                        save_state()
                        send_telegram(f"Re-enabled: {', '.join(names)}")
                    else:
                        send_telegram("No disabled processes")

                else:
                    # Free-text: route to AI if available (AI tier only)
                    if tier == "ai" and anthropic_key:
                        send_telegram_typing(msg_chat_id)
                        response = _ask_claude(text, msg_chat_id)
                        if response:
                            send_telegram(response)
                        else:
                            send_telegram("Sorry, I couldn't process that. Try a command like 'status' or 'help'.")
                    else:
                        send_telegram(
                            "Unknown command. Try 'help' for available commands.\n\n"
                            "Upgrade to AI tier at stillrunning.io to enable Telegram conversations."
                        )

        except Exception as exc:
            print(f"[stillrunning] Telegram command error: {exc}", flush=True)
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Setup Wizard
# ---------------------------------------------------------------------------
def scan_screen_sessions() -> list[dict]:
    """Scan for running screen sessions."""
    sessions = []
    try:
        result = subprocess.run(
            ["screen", "-ls"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            # Match lines like: "12345.sessionname (Detached)"
            if "." in line and ("Detached" in line or "Attached" in line):
                parts = line.split(".")
                if len(parts) >= 2:
                    session_name = parts[1].split()[0].strip("()")
                    # Try to find the script being run
                    script = _guess_script_for_session(session_name)
                    sessions.append({
                        "name": session_name,
                        "screen": session_name,
                        "script": script,
                        "type": "screen",
                    })
    except Exception:
        pass
    return sessions


def _guess_script_for_session(session_name: str) -> str:
    """Try to find what script a screen session is running."""
    try:
        # Use pgrep to find processes matching the session name
        result = subprocess.run(
            ["pgrep", "-a", "-f", f"python.*{session_name}"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            # Extract the .py file from the command line
            parts = line.split()
            for part in parts:
                if part.endswith(".py"):
                    return Path(part).name
    except Exception:
        pass
    return f"{session_name}.py"  # Default guess


def scan_systemd_services() -> list[dict]:
    """Scan for user-defined systemd services."""
    services = []
    try:
        # List active services, filter for likely user services
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=10,
        )
        skip_prefixes = (
            "systemd-", "dbus", "ssh", "cron", "rsyslog", "snapd",
            "networkd", "resolved", "udev", "polkit", "accounts-daemon",
            "ModemManager", "udisks", "avahi", "cups", "bluetooth",
            "getty", "serial-getty", "console-", "user@", "session-",
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 1 and parts[0].endswith(".service"):
                name = parts[0].replace(".service", "")
                if not any(name.startswith(p) for p in skip_prefixes):
                    services.append({
                        "name": name,
                        "screen": name,  # Will use systemctl instead
                        "script": f"{name}.service",
                        "type": "systemd",
                    })
    except Exception:
        pass
    return services


def scan_log_files(working_dir: Path) -> list[dict]:
    """Scan for log files in common locations."""
    log_files = []
    patterns = ["*.log", "logs/*.log", "log/*.log"]

    for pattern in patterns:
        try:
            for log_path in working_dir.glob(pattern):
                if log_path.is_file():
                    size_mb = log_path.stat().st_size / (1024 * 1024)
                    log_files.append({
                        "path": str(log_path.relative_to(working_dir)),
                        "max_mb": 10,
                        "keep_archives": 5,
                        "current_size_mb": round(size_mb, 2),
                    })
        except Exception:
            pass

    # Also check common paths
    common_logs = [
        Path("/var/log/syslog"),
        Path("/var/log/messages"),
    ]
    for log_path in common_logs:
        try:
            if log_path.exists() and log_path.is_file():
                size_mb = log_path.stat().st_size / (1024 * 1024)
                log_files.append({
                    "path": str(log_path),
                    "max_mb": 50,
                    "keep_archives": 3,
                    "current_size_mb": round(size_mb, 2),
                })
        except Exception:
            pass

    return log_files


def detect_health_file(working_dir: Path) -> str | None:
    """Look for common health/status files."""
    candidates = [
        "status.json", "health.json", "heartbeat.json",
        "state.json", ".health", ".heartbeat",
    ]
    for name in candidates:
        path = working_dir / name
        if path.exists():
            return name
    return None


def test_telegram_credentials(token: str, chat_id: str) -> bool:
    """Test if Telegram credentials work by sending a test message."""
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": chat_id,
            "text": "[StillRunning] Setup wizard test message - credentials verified!",
        }).encode()
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status == 200
    except Exception:
        return False


def _test_api_connection() -> tuple:
    """Test connection to stillrunning.io API. Returns (success, version, scans_remaining)."""
    try:
        req = urllib.request.Request(
            api_url("/api/version"),
            headers={"User-Agent": "stillrunning-cli"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return True, data.get("version", "unknown"), data.get("free_scans_remaining", 10)
    except Exception:
        return False, None, None


def _post_early_signup(email: str, channel: str, machine_id_hash: str) -> bool:
    """POST to /api/early-signup. Returns True on success, fails silently."""
    import hashlib
    import socket
    try:
        payload = {
            "channel": channel,
            "machine_id_hash": machine_id_hash,
            "agent_version": VERSION,
            "os_type": sys.platform,
            "source": "setup",
        }
        if email:
            payload["email"] = email

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            api_url("/api/early-signup"),
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": f"stillrunning/{VERSION}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False  # Fail silently, don't block setup


def _get_setup_machine_id() -> str:
    """Generate a privacy-preserving machine ID hash for setup tracking."""
    import hashlib
    import socket
    import getpass
    try:
        raw = f"{socket.gethostname()}:{getpass.getuser()}"
    except Exception:
        raw = f"unknown:{time.time()}"
    return hashlib.sha256(f"setup:{raw}".encode()).hexdigest()[:16]


def _validate_email(email: str) -> bool:
    """Basic email validation."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def run_setup_wizard(autonomous: bool = False) -> None:
    """Setup: the alert questions, then an honest report of what is and is
    not protected (and an offer to switch the Claude Code hook on)."""
    from . import funnel
    try:
        _run_alert_setup(autonomous=autonomous)
    except EOFError:
        funnel.track_step("setup_aborted_no_input")
        print("\n\n  Setup needs answers typed in a terminal, and none came (no input).")
        print("  For CI or scripts, run `stillrunning --autonomous` with STILLRUNNING_* env vars.")
        print("  Nothing was changed. Run `stillrunning --setup` in a terminal anytime.\n")
        sys.exit(EXIT_USAGE)
    except KeyboardInterrupt:
        funnel.track_step("setup_aborted_interrupt")
        print("\n\n  Setup cancelled. Run `stillrunning --setup` anytime.\n")
        sys.exit(130)
    except SetupInputError as e:
        funnel.track_step("setup_aborted_invalid_input")
        print(f"\n  Setup stopped: {e}. Nothing was saved.")
        print("  Run `stillrunning --setup` again and answer with one of the numbers shown.\n")
        sys.exit(EXIT_USAGE)
    except SetupSaveError as e:
        funnel.track_step("setup_failed_config_save")
        print(f"\n  ERROR: {e}")
        print("  Your alert settings were NOT saved. Make sure your home directory is writable,")
        print("  or install stillrunning for your own user (`pip install --user stillrunning`")
        print("  or a virtualenv), then run `stillrunning --setup` again.\n")
        sys.exit(EXIT_ERROR)
    if not _finish_setup(interactive=not autonomous) and not autonomous:
        funnel.track_step("setup_ended_unprotected")
        sys.exit(EXIT_NOT_PROTECTED)


def _run_alert_setup(autonomous: bool = False) -> None:
    """Interactive setup wizard. If autonomous=True, reads config from env vars."""
    # Import funnel telemetry (opt-out, anonymous aggregate stats)
    from . import funnel
    funnel.track_setup_start()

    machine_id_hash = _get_setup_machine_id()

    print("\n" + "=" * 60)
    print("  StillRunning Setup Wizard")
    print("=" * 60 + "\n")

    # --- Autonomous mode (CI/CD) ---
    if autonomous:
        print("Running in autonomous mode (CI/CD)...\n")
        app_name = os.environ.get("STILLRUNNING_APP_NAME", Path.cwd().name)
        telegram_token = os.environ.get("STILLRUNNING_TELEGRAM_TOKEN", "")
        telegram_chat_id = os.environ.get("STILLRUNNING_CHAT_ID", "")
        api_token = os.environ.get("STILLRUNNING_API_TOKEN", "")

        config = {
            "app_name": app_name,
            "working_dir": str(Path.cwd()),
            "alert_channel": "telegram" if telegram_token else "silent",
            "telegram_bot_token": telegram_token,
            "telegram_chat_id": telegram_chat_id,
            "api_token": api_token,
            "processes": [],
            "log_files": [],
            "thresholds": {"cpu_percent": 85, "mem_percent": 85, "disk_percent": 85},
            "intervals": {"process_check_sec": 30, "resource_check_sec": 60},
        }

        config_path = _save_setup_config(config)

        _post_early_signup("", "autonomous", machine_id_hash)
        print(f"Config saved to: {config_path}")
        print("Autonomous setup complete. Starting monitor...\n")
        main()
        return

    # === FIRST QUESTION: How to receive alerts? ===
    print("  How would you like to receive alerts?\n")
    print("    1) email        - weekly digest of what I caught")
    print("    2) telegram     - real-time alerts (needs Telegram app)")
    print("    3) silent mode  - just scan and log, no alerts")
    print("    4) skip for now")
    print()
    channel_map = {"1": "email", "2": "telegram", "3": "silent", "4": "skipped"}
    alert_choice = _ask_menu_choice(channel_map)
    print()
    funnel.track_step(f"alert_channel_{channel_map[alert_choice]}")

    cwd = Path.cwd()

    # === SKIP PATH ===
    if alert_choice == "4":
        config = {"setup_skipped": True, "alert_channel": "skipped"}
        config_path = _save_setup_config(config)
        _post_early_signup("", "skipped", machine_id_hash)
        funnel.track_step("setup_skipped")
        print("  Skipped. Run `stillrunning --setup` anytime to enable.\n")
        return

    # === SILENT PATH ===
    if alert_choice == "3":
        config = {
            "alert_channel": "silent",
            "working_dir": str(cwd),
            "processes": [],
            "log_files": [],
            "thresholds": {"cpu_percent": 85, "mem_percent": 85, "disk_percent": 85},
        }
        config_path = _save_setup_config(config)
        _post_early_signup("", "silent", machine_id_hash)
        funnel.track_step("setup_completed")
        print("  Silent mode. Scans will log to ~/.stillrunning/scan.log")
        print("  You can change this later with `stillrunning --setup`")
        print()
        print("  Try a scan now:")
        print("    stillrunning scan <package_name>")
        print()
        return

    # === EMAIL PATH ===
    if alert_choice == "1":
        print("  Enter your email for weekly digest:")
        user_email = input("  > ").strip()

        while user_email and not _validate_email(user_email):
            print("  Invalid email format. Try again (or press Enter to skip):")
            user_email = input("  > ").strip()

        if user_email:
            config = {
                "alert_channel": "email",
                "email": user_email,
                "working_dir": str(cwd),
                "processes": [],
                "log_files": [],
                "thresholds": {"cpu_percent": 85, "mem_percent": 85, "disk_percent": 85},
            }
            config_path = _save_setup_config(config)
            _post_early_signup(user_email, "email", machine_id_hash)
            funnel.track_step("email_captured")
            funnel.track_step("setup_completed")
            print()
            print(f"  Got it. I'll email you a weekly digest at {user_email}")
            print("  Run `stillrunning scan <package>` to try a scan now.")
            print()
            return
        else:
            # No email provided, fall through to silent
            print("  No email provided. Defaulting to silent mode.\n")
            config = {
                "alert_channel": "silent",
                "working_dir": str(cwd),
                "processes": [],
                "log_files": [],
                "thresholds": {"cpu_percent": 85, "mem_percent": 85, "disk_percent": 85},
            }
            config_path = _save_setup_config(config)
            _post_early_signup("", "silent", machine_id_hash)
            funnel.track_step("setup_completed")
            print("  Silent mode enabled. Run `stillrunning scan <package>` to try a scan.\n")
            return

    # === TELEGRAM PATH (existing flow, slightly simplified) ===
    if alert_choice == "2":
        _post_early_signup("", "telegram", machine_id_hash)

        print("  Telegram requires a bot token and chat ID.\n")
        print("  1. Create a bot: https://t.me/BotFather -> /newbot")
        print("  2. Get your chat ID: https://t.me/userinfobot -> /start")
        print()

        print("  Telegram bot token (from @BotFather):")
        telegram_token = input("  > ").strip()
        print()

        print("  Telegram chat ID (your user ID):")
        telegram_chat_id = input("  > ").strip()
        print()

        # Test Telegram
        telegram_ok = False
        if telegram_token and telegram_chat_id:
            print("  Testing Telegram credentials...")
            telegram_ok = test_telegram_credentials(telegram_token, telegram_chat_id)
            funnel.track_telegram_config(configured=True, test_result=telegram_ok)
            if telegram_ok:
                print("  Telegram test passed! Check your Telegram for the test message.\n")
            else:
                print("  WARNING: Telegram test failed. Check your token and chat ID.")
                print("  Continuing anyway — you can fix this in stillrunning.yaml\n")
        else:
            funnel.track_telegram_config(configured=False)
            print("  No Telegram credentials provided. Alerts disabled.\n")

        # Generate machine_id for telemetry
        import secrets
        machine_id = f"sr_{secrets.token_urlsafe(16)}"

        config = {
            "alert_channel": "telegram",
            "working_dir": str(cwd),
            "telegram_bot_token": telegram_token,
            "telegram_chat_id": telegram_chat_id,
            "telemetry": True,
            "machine_id": machine_id,
            "processes": [],
            "log_files": [],
            "thresholds": {
                "cpu_percent": 85,
                "mem_percent": 85,
                "disk_percent": 85,
                "process_mem_mb": 500,
            },
            "intervals": {
                "process_check_sec": 30,
                "resource_check_sec": 60,
                "heartbeat_sec": 86400,
                "telegram_poll_sec": 5,
            },
            "restart_cooldown_sec": 120,
            "max_consecutive_failures": 3,
        }

        config_path = _save_setup_config(config)
        funnel.track_step("config_saved")
        funnel.track_step("setup_completed")

        print(f"  Config saved to: {config_path}")
        print()
        print("  =" * 30)
        print("  Setup Complete!")
        print("  =" * 30)
        print()
        print(f"  Telegram: {'configured' if telegram_token else 'not configured'}")
        print()
        print("  Try a scan:")
        print("    stillrunning scan <package_name>")
        print()
        print("  Or start monitoring:")
        print(f"    screen -dmS stillrunning python3 -m stillrunning")
        print()


# ---------------------------------------------------------------------------
# Shield — SSH Attack Detection and Response
# ---------------------------------------------------------------------------
_SHIELD_CHECK_INTERVAL = 60  # Check every 60 seconds
_SHIELD_ATTACKS_CAP = 10000  # Max entries in stillrunning_attacks.json
_SHIELD_LEARNING_THRESHOLD = 50  # AI analysis every N attacks (AI tier)
_SHIELD_API_URL = api_base()

# Shield runtime state
_shield_tier: str = "basic"  # Set by validate_token response
_shield_attack_counter: int = 0
_shield_stats: dict = {
    "attacks_today": 0,
    "ips_banned": 0,
    "grade": "A",
    "last_attack_ts": None,
}


def _get_shield_attacks_file() -> Path:
    return Path(__file__).parent / "stillrunning_attacks.json"


def _get_shield_security_file() -> Path:
    return Path(__file__).parent / "stillrunning_security.json"


def _load_shield_attacks() -> dict:
    """Load stillrunning_attacks.json or return empty structure."""
    try:
        attacks_file = _get_shield_attacks_file()
        if attacks_file.exists():
            with open(attacks_file) as f:
                return json.load(f)
    except Exception:
        pass
    return {"attacks": [], "stats": {"total_blocked": 0, "total_reported": 0}}


def _save_shield_attacks(data: dict) -> None:
    """Atomically save stillrunning_attacks.json, capping at 10000 entries."""
    try:
        if len(data.get("attacks", [])) > _SHIELD_ATTACKS_CAP:
            data["attacks"] = data["attacks"][-_SHIELD_ATTACKS_CAP:]
        attacks_file = _get_shield_attacks_file()
        tmp = attacks_file.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, attacks_file)
    except Exception as e:
        print(f"[stillrunning] Shield: save_attacks failed: {e}", flush=True)


def _save_shield_security(data: dict) -> None:
    """Save stillrunning_security.json with grade and daily stats."""
    try:
        security_file = _get_shield_security_file()
        tmp = security_file.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, security_file)
    except Exception as e:
        print(f"[stillrunning] Shield: save_security failed: {e}", flush=True)


def _parse_auth_log_attacks(since_seconds: int = 60) -> dict:
    """Parse /var/log/auth.log for failed SSH attempts in last N seconds."""
    attacks: dict = {}  # {ip: {"count": N, "usernames": set(), "first_ts": str, "last_ts": str}}
    cutoff = time.time() - since_seconds
    auth_log = Path("/var/log/auth.log")

    try:
        if not auth_log.exists():
            return attacks

        with open(auth_log, "r", errors="ignore") as f:
            for line in f:
                if "Failed password" not in line and "Invalid user" not in line:
                    continue

                try:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    month_day_time = " ".join(parts[0:3])
                    year = datetime.now().year
                    ts_str = f"{year} {month_day_time}"
                    ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                    ts = ts.replace(tzinfo=timezone.utc)
                    ts_epoch = ts.timestamp()

                    if ts_epoch < cutoff:
                        continue
                except Exception:
                    continue

                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if not ip_match:
                    continue
                ip = ip_match.group(1)

                user_match = re.search(r"for (?:invalid user )?(\S+) from", line)
                username = user_match.group(1) if user_match else "unknown"

                if ip not in attacks:
                    attacks[ip] = {
                        "count": 0,
                        "usernames": set(),
                        "first_ts": ts.isoformat(),
                        "last_ts": ts.isoformat(),
                    }
                attacks[ip]["count"] += 1
                attacks[ip]["usernames"].add(username)
                attacks[ip]["last_ts"] = ts.isoformat()

    except PermissionError:
        print("[stillrunning] Shield: Cannot read auth.log - permission denied", flush=True)
    except Exception as e:
        print(f"[stillrunning] Shield: parse_auth_log failed: {e}", flush=True)

    # Convert sets to lists for JSON
    for ip in attacks:
        attacks[ip]["usernames"] = list(attacks[ip]["usernames"])

    return attacks


def _get_threat_level(ip: str, count: int, known_attacks: dict) -> str:
    """Determine threat level based on attempt count and history. AI tier only."""
    for entry in known_attacks.get("attacks", []):
        if entry.get("ip") == ip:
            return "REPEAT"

    if count >= 20:
        return "HIGH"
    elif count >= 5:
        return "MEDIUM"
    else:
        return "LOW"


def _apply_basic_punishment(ip: str) -> str:
    """Basic tier: fail2ban only after 10 attempts."""
    try:
        subprocess.run(
            ["fail2ban-client", "set", "sshd", "banip", ip],
            capture_output=True, timeout=10
        )
        return "fail2ban_ban"
    except Exception:
        return "failed"


def _apply_ai_punishment(ip: str, threat_level: str) -> str:
    """AI tier: intelligent punishment based on threat level."""
    try:
        if threat_level == "LOW":
            subprocess.run(
                ["fail2ban-client", "set", "sshd", "banip", ip],
                capture_output=True, timeout=10
            )
            return "fail2ban_ban"

        elif threat_level == "MEDIUM":
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=10
            )
            return "iptables_24h"

        elif threat_level in ("HIGH", "REPEAT"):
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=10
            )
            return "permanent_ban"

        return "none"
    except Exception as e:
        print(f"[stillrunning] Shield: apply_punishment failed for {ip}: {e}", flush=True)
        return "failed"


def _report_to_abuseipdb(ip: str, comment: str, api_key: str) -> bool:
    """Report an IP to AbuseIPDB. AI tier only."""
    if not api_key:
        return False

    try:
        url = "https://api.abuseipdb.com/api/v2/report"
        headers = {
            "Key": api_key,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = f"ip={ip}&categories=18,22&comment={comment[:1024]}"

        req = urllib.request.Request(url, data=data.encode(), headers=headers, method="POST")
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status == 200
    except Exception as e:
        print(f"[stillrunning] Shield: abuseipdb report failed for {ip}: {e}", flush=True)
        return False


def _get_ip_country(ip: str) -> str:
    """Get country code for an IP using ip-api.com."""
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=countryCode",
            headers={"User-Agent": "stillrunning-shield/1.0"}
        )
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read().decode())
        return data.get("countryCode", "??")
    except Exception:
        return "??"


def _calculate_security_grade(attacks_today: int, high_threats: int) -> str:
    """Calculate security grade A/B/C/D based on attack volume."""
    if attacks_today == 0:
        return "A"
    elif attacks_today < 10 and high_threats == 0:
        return "A"
    elif attacks_today < 50 and high_threats < 3:
        return "B"
    elif attacks_today < 100 and high_threats < 10:
        return "C"
    else:
        return "D"


def _fetch_shared_blocklist(token: str) -> list:
    """Fetch shared blocklist from server. AI tier only."""
    try:
        req = urllib.request.Request(
            f"{_SHIELD_API_URL}/api/threats",
            headers={"User-Agent": "stillrunning-shield/1.0", "X-API-Key": token}
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        return data.get("blocked_ips", [])
    except Exception:
        return []


def _report_threat_to_server(token: str, ip: str, threat_level: str) -> bool:
    """Report a HIGH+ threat to shared blocklist. AI tier only."""
    from stillrunning.apibase import token_allowed
    if not token_allowed():      # the account token only goes to the default server
        return False
    try:
        payload = json.dumps({"token": token, "ip": ip, "threat_level": threat_level}).encode()
        req = urllib.request.Request(
            f"{_SHIELD_API_URL}/api/report-threat",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "stillrunning-shield/1.0"},
            method="POST"
        )
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status == 200
    except Exception:
        return False


def _apply_shared_blocklist(ips: list) -> int:
    """Apply shared blocklist via iptables. AI tier only."""
    applied = 0
    for ip in ips:
        try:
            # Check if already blocked
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
            if check.returncode != 0:  # Not already blocked
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
                applied += 1
        except Exception:
            pass
    return applied


def _run_shield_ai_analysis(attacks_data: dict, anthropic_key: str) -> None:
    """Run AI analysis on recent attacks. AI tier only."""
    if not anthropic_key:
        return

    try:
        recent_attacks = attacks_data.get("attacks", [])[-50:]
        if len(recent_attacks) < 10:
            return

        prompt = f"""Analyze these SSH brute force attack records and identify patterns.
Look for: subnets using same methods, time clustering, common usernames, geographic patterns.
Return JSON only: {{"patterns": ["pattern 1", ...], "risk_subnets": ["x.x.x.0/24", ...], "recommendations": ["rec 1", ...]}}

Attack data:
{json.dumps(recent_attacks[-30:], indent=2)[:2000]}"""

        payload = json.dumps({
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 500,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": anthropic_key,
                "anthropic-version": "2023-06-01"
            }
        )
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read().decode())
        text = result.get("content", [{}])[0].get("text", "")

        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        analysis = json.loads(text)
        print(f"[stillrunning] Shield AI: {len(analysis.get('patterns', []))} patterns found", flush=True)

    except Exception as e:
        print(f"[stillrunning] Shield AI analysis failed: {e}", flush=True)


def shield_monitor_loop() -> None:
    """Monitor SSH attacks, apply punishments based on tier."""
    global _shield_attack_counter, _shield_stats

    # Get config values
    tier = CONFIG.get("tier", "basic")
    token = CONFIG.get("token", "")
    anthropic_key = CONFIG.get("anthropic_api_key", "")
    abuseipdb_key = CONFIG.get("abuseipdb_api_key", "")

    print(f"[stillrunning] Shield starting ({tier} tier)", flush=True)

    # AI tier: fetch shared blocklist on startup
    if tier == "ai" and token:
        shared_ips = _fetch_shared_blocklist(token)
        if shared_ips:
            applied = _apply_shared_blocklist(shared_ips)
            print(f"[stillrunning] Shield: Applied {applied} IPs from shared blocklist", flush=True)

    last_blocklist_fetch = time.time()

    while True:
        try:
            new_attacks = _parse_auth_log_attacks(since_seconds=_SHIELD_CHECK_INTERVAL)

            if not new_attacks:
                time.sleep(_SHIELD_CHECK_INTERVAL)
                continue

            attacks_data = _load_shield_attacks()
            known_ips = {a["ip"] for a in attacks_data.get("attacks", [])}

            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            today_ts = today_start.timestamp()
            attacks_today = 0
            high_threats_today = 0

            for ip, info in new_attacks.items():
                is_new = ip not in known_ips

                if tier == "ai":
                    # AI tier: intelligent threat scoring
                    threat_level = _get_threat_level(ip, info["count"], attacks_data)
                    punishment = _apply_ai_punishment(ip, threat_level)

                    # Report HIGH+ to AbuseIPDB
                    reported = False
                    if threat_level in ("HIGH", "REPEAT") and abuseipdb_key:
                        comment = f"SSH brute force: {info['count']} attempts"
                        reported = _report_to_abuseipdb(ip, comment, abuseipdb_key)
                        if reported:
                            attacks_data["stats"]["total_reported"] = attacks_data["stats"].get("total_reported", 0) + 1

                    # Report to shared blocklist
                    if threat_level in ("HIGH", "REPEAT") and token:
                        _report_threat_to_server(token, ip, threat_level)

                    country = _get_ip_country(ip)

                    if threat_level in ("HIGH", "REPEAT"):
                        high_threats_today += 1

                else:
                    # Basic tier: simple fail2ban after 10 attempts
                    threat_level = "LOW"
                    punishment = "none"
                    reported = False
                    country = "??"

                    if info["count"] >= 10:
                        punishment = _apply_basic_punishment(ip)

                # Create attack entry
                entry = {
                    "ip": ip,
                    "first_seen": info["first_ts"],
                    "last_seen": info["last_ts"],
                    "attempt_count": info["count"],
                    "threat_level": threat_level,
                    "punishment": punishment,
                    "reported": reported,
                    "country": country,
                    "punished_at": datetime.now(timezone.utc).isoformat(),
                }

                if is_new:
                    attacks_data["attacks"].append(entry)
                    attacks_data["stats"]["total_blocked"] = attacks_data["stats"].get("total_blocked", 0) + 1
                    _shield_attack_counter += 1
                else:
                    for existing in attacks_data["attacks"]:
                        if existing["ip"] == ip:
                            existing["last_seen"] = info["last_ts"]
                            existing["attempt_count"] += info["count"]
                            break

                print(f"[stillrunning] Shield: {ip} ({country}) - {threat_level} - {punishment}", flush=True)

            # Count attacks today
            for attack in attacks_data.get("attacks", []):
                try:
                    attack_ts = datetime.fromisoformat(attack["first_seen"].replace("Z", "+00:00")).timestamp()
                    if attack_ts >= today_ts:
                        attacks_today += 1
                except Exception:
                    pass

            # Calculate security grade
            grade = _calculate_security_grade(attacks_today, high_threats_today)

            # Update stats
            _shield_stats["attacks_today"] = attacks_today
            _shield_stats["ips_banned"] = attacks_data["stats"].get("total_blocked", 0)
            _shield_stats["grade"] = grade
            _shield_stats["last_attack_ts"] = datetime.now(timezone.utc).isoformat()

            # Save attacks and security files
            _save_shield_attacks(attacks_data)
            _save_shield_security({
                "grade": grade,
                "attacks_today": attacks_today,
                "ips_banned": attacks_data["stats"].get("total_blocked", 0),
                "tier": tier,
                "last_updated": datetime.now(timezone.utc).isoformat(),
            })

            # AI tier: run analysis every N attacks
            if tier == "ai" and _shield_attack_counter >= _SHIELD_LEARNING_THRESHOLD:
                _shield_attack_counter = 0
                threading.Thread(
                    target=_run_shield_ai_analysis,
                    args=(attacks_data, anthropic_key),
                    daemon=True
                ).start()

            # AI tier: refresh shared blocklist every hour
            if tier == "ai" and token and time.time() - last_blocklist_fetch >= 3600:
                shared_ips = _fetch_shared_blocklist(token)
                if shared_ips:
                    _apply_shared_blocklist(shared_ips)
                last_blocklist_fetch = time.time()

        except Exception as exc:
            print(f"[stillrunning] Shield error: {exc}", flush=True)

        time.sleep(_SHIELD_CHECK_INTERVAL)


def get_shield_summary() -> str:
    """Get Shield summary for heartbeat."""
    return f"Shield: {_shield_stats['attacks_today']} attacks blocked, Grade {_shield_stats['grade']}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    from ._stdio import make_output_safe
    make_output_safe()   # never crash on a non-UTF-8 console (Windows code pages)
    if _unsupported_os("monitor", "Package checks work here: stillrunning scan <package>, "
                                  "stillrunning --hook-claude-code, stillrunning shell-install."):
        sys.exit(1)
    load_config()
    load_state()

    app_name = CONFIG.get("app_name", "StillRunning")
    print(f"[stillrunning] Starting {app_name}...", flush=True)
    print(f"[stillrunning] Working dir: {get_working_dir()}", flush=True)
    print(f"[stillrunning] Processes: {len(CONFIG.get('processes', []))}", flush=True)

    # Validate subscription token (SESSION 88)
    global SUBSCRIPTION_FEATURES
    token = CONFIG.get("token", "")
    if token:
        print("[stillrunning] Validating subscription...", flush=True)
        from .features import validate_token, print_tier_status
        result = validate_token(token)
        print_tier_status(result)
        SUBSCRIPTION_FEATURES = result.get("features", ["process_monitor", "restart", "alerts"])
    else:
        print("[stillrunning] No token configured - running in free mode", flush=True)
        print("   Get a token at https://stillrunning.io/pricing", flush=True)
        SUBSCRIPTION_FEATURES = ["process_monitor", "restart", "alerts"]

    # Startup check
    startup_check()

    # Launch monitor threads
    threads = [
        threading.Thread(target=process_watchdog_loop, daemon=True, name="process-watchdog"),
        threading.Thread(target=resource_check_loop, daemon=True, name="resource-monitor"),
        threading.Thread(target=latency_check_loop, daemon=True, name="latency-monitor"),
        threading.Thread(target=health_file_loop, daemon=True, name="health-monitor"),
        threading.Thread(target=log_archiver_loop, daemon=True, name="log-archiver"),
        threading.Thread(target=heartbeat_loop, daemon=True, name="heartbeat"),
        threading.Thread(target=telegram_command_loop, daemon=True, name="telegram-commands"),
        threading.Thread(target=shield_monitor_loop, daemon=True, name="shield-monitor"),
    ]

    for t in threads:
        t.start()

    # Start telemetry heartbeat if opted in (SESSION 98)
    if CONFIG.get("telemetry", False) and CONFIG.get("machine_id"):
        from .heartbeat import start_heartbeat_thread
        start_heartbeat_thread(CONFIG, VERSION)
        threads.append(None)  # Count it

    print(f"[stillrunning] All monitors started ({len(threads)} threads)", flush=True)

    # Keep main thread alive
    while True:
        try:
            time.sleep(60)
        except KeyboardInterrupt:
            print("\n[stillrunning] Shutting down...", flush=True)
            break
        except Exception:
            pass


def _add_server_to_account(token: str, server_name: str) -> None:
    """Add a new server to an existing account via API."""
    import urllib.request
    import urllib.error

    print(f"\nAdding server '{server_name}' to your account...")

    try:
        url = api_url("/api/servers/add")
        payload = json.dumps({"token": token, "server_name": server_name}).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())

        if "error" in result:
            print(f"Error: {result['error']}")
            return

        server_token = result.get("server_token")
        subdomain = result.get("subdomain")

        print(f"\nServer added successfully!")
        print(f"  Server name: {server_name}")
        print(f"  Subdomain: {subdomain}")
        print(f"  Token: {server_token}")
        print(f"\nNow run on your new server:")
        print(f"  curl -sSL https://stillrunning.io/install | python3 - --token {server_token}")

    except urllib.error.HTTPError as e:
        try:
            error_data = json.loads(e.read().decode())
            print(f"Error: {error_data.get('error', str(e))}")
        except Exception:
            print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")


def run_doctor() -> int:
    """Health check. Returns the exit code: 1 when no layer that checks
    installs is ON, or when any check failed; 0 otherwise."""
    import urllib.error
    import urllib.request
    import subprocess
    import shutil
    from . import claude_hook, layers as layers_mod

    print("\n" + "=" * 50)
    print("STILLRUNNING DOCTOR")
    print("=" * 50 + "\n")

    issues = []
    warnings = []

    # 1. What is actually protecting this machine
    print("[1/6] Protection layers...")
    layers = layers_mod.protection_layers()
    for line in layers_mod.render(layers).splitlines():
        print("  " + line)
    if not layers_mod.install_time_protection(layers):
        issues.append("No layer that checks installs is ON "
                      "(fix: stillrunning --hook-claude-code, or stillrunning shell-install)")

    # 2. Can the blocklist be reached, and does it answer?
    print("\n[2/6] Blocklist lookup (a known-malicious test name)...")
    try:
        req = urllib.request.Request(
            api_url("/api/blocklist/axois?ecosystem=npm"),
            headers={"User-Agent": f"stillrunning/{VERSION}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            answer = json.loads(resp.read().decode())
        if isinstance(answer, dict) and answer.get("blocked") is True:
            print("  [OK] stillrunning.io answered and recognises the test package as blocked")
        else:
            issues.append("The blocklist did not recognise a known-malicious test package")
            print("  [FAIL] The server answered, but did not flag the known-malicious test package")
    except Exception as e:
        warnings.append(f"Blocklist not reachable ({type(e).__name__}) — NOT VERIFIED")
        print(f"  [NOT VERIFIED] Could not reach stillrunning.io ({type(e).__name__}).")
        print("  While it is unreachable, installs are not looked up: each one asks you first.")

    # 3. Token (optional)
    print("\n[3/6] API token...")
    token, source = claude_hook.resolve_token()
    if not token:
        print("  [OFF] No token — anonymous free tier (a limited number of lookups per day;")
        print("        after that every install asks you first). Optional: stillrunning.io/pricing")
    else:
        try:
            req = urllib.request.Request(api_url("/api/validate-token"),
                                         headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            if data.get("valid"):
                print(f"  [OK] Token from {source} is valid (tier: {data.get('tier', 'unknown')})")
                if data.get("trial"):
                    expires = data.get("trial_expires", "soon")
                    warnings.append(f"Trial expires: {expires}")
                    print(f"  [WARN] Trial mode - expires {expires}")
            else:
                issues.append(f"Token from {source} is invalid or expired")
                print(f"  [FAIL] Token from {source} is invalid")
                print("  Fix: Check your token at stillrunning.io/dashboard")
        except urllib.error.HTTPError as e:
            issues.append(f"Token validation failed: HTTP {e.code}")
            print(f"  [FAIL] Server returned {e.code}")
        except Exception as e:
            warnings.append(f"Token from {source} could not be validated ({type(e).__name__})")
            print(f"  [NOT VERIFIED] Validation could not run: {type(e).__name__}")

    # 4. Process monitor (optional)
    print("\n[4/6] Process monitor (optional)...")
    try:
        result = subprocess.run(["pgrep", "-f", "stillrunning"], capture_output=True, timeout=5)
        pids = [p for p in result.stdout.decode().split() if p != str(os.getpid())]
        if result.returncode == 0 and pids:
            print(f"  [NOT VERIFIED] A process with 'stillrunning' in its command line is running "
                  f"(PID {pids[0]}); doctor cannot tell whether it is the monitor.")
        else:
            print("  [OFF] Not running. Only needed for process monitoring and alerts,")
            print("        not for package checks. Start it with: stillrunning")
    except Exception as e:
        print(f"  [NOT VERIFIED] Process check failed: {type(e).__name__}")

    # 5. Check disk space
    print("\n[5/6] Checking disk space...")
    try:
        total, used, free = shutil.disk_usage("/")
        pct_used = (used / total) * 100
        if pct_used > 90:
            issues.append(f"Disk nearly full: {pct_used:.1f}%")
            print(f"  [FAIL] Disk {pct_used:.1f}% used - critically low!")
            print("  Fix: Free up disk space immediately")
        elif pct_used > 80:
            warnings.append(f"Disk usage high: {pct_used:.1f}%")
            print(f"  [WARN] Disk {pct_used:.1f}% used")
        else:
            print(f"  [OK] Disk {pct_used:.1f}% used ({free // (1024**3)}GB free)")
    except Exception as e:
        warnings.append(f"Disk check failed: {e}")
        print(f"  [NOT VERIFIED] Could not check disk: {e}")

    # 6. Check memory
    print("\n[6/6] Checking memory...")
    try:
        with open("/proc/meminfo") as f:
            meminfo = f.read()
        total_kb = int([l for l in meminfo.split('\n') if 'MemTotal' in l][0].split()[1])
        avail_kb = int([l for l in meminfo.split('\n') if 'MemAvailable' in l][0].split()[1])
        pct_used = ((total_kb - avail_kb) / total_kb) * 100
        if pct_used > 90:
            issues.append(f"Memory critically low: {pct_used:.1f}%")
            print(f"  [FAIL] Memory {pct_used:.1f}% used")
        elif pct_used > 80:
            warnings.append(f"Memory usage high: {pct_used:.1f}%")
            print(f"  [WARN] Memory {pct_used:.1f}% used")
        else:
            print(f"  [OK] Memory {pct_used:.1f}% used ({avail_kb // 1024}MB available)")
    except Exception:
        print("  [NOT VERIFIED] Memory check is not available on this OS")

    print("\n" + "=" * 50)
    if issues:
        print(f"CRITICAL: {len(issues)} issue(s) found")
        for issue in issues:
            print(f"  - {issue}")
    if warnings:
        print(f"WARNINGS: {len(warnings)} warning(s)")
        for warn in warnings:
            print(f"  - {warn}")
    if not issues and not warnings:
        print("HEALTHY: All checks passed!")
    print("=" * 50 + "\n")

    if issues:
        print("Status: CRITICAL")
        return 1
    print("Status: WARNINGS" if warnings else "Status: HEALTHY")
    return 0


def _finish_setup(interactive: bool) -> bool:
    """End of --setup: say exactly what is protected and what is not. Setup
    used to stop after the alert questions with nothing checking installs."""
    from . import claude_hook, layers as layers_mod
    token, source = claude_hook.resolve_token()
    canonical = Path.home() / ".stillrunning" / "config.json"
    if token and not source.startswith(("~/.stillrunning/config.json", "the STILLRUNNING_TOKEN")):
        try:
            data = {}
            if canonical.exists():
                with open(canonical) as f:
                    data = json.load(f)
            if isinstance(data, dict) and not data.get("token"):
                data["token"] = token
                canonical.parent.mkdir(parents=True, exist_ok=True)
                tmp = canonical.with_suffix(".tmp")
                with open(tmp, "w") as f:
                    json.dump(data, f, indent=2)
                os.chmod(tmp, 0o600)
                tmp.replace(canonical)
                print(f"  Token copied from {source} to ~/.stillrunning/config.json "
                      "(the one place every command reads it from).")
        except (OSError, ValueError) as e:
            print(f"  WARNING: could not copy the token to ~/.stillrunning/config.json ({e}).")

    layers = layers_mod.protection_layers()
    hook_on = any(l["key"] == "claude_hook" and l["state"] == layers_mod.ON for l in layers)
    if interactive and not hook_on and sys.stdin.isatty():
        print("  Package checks are not switched on yet.")
        try:
            answer = input("  Install the Claude Code hook now, so every install Claude Code "
                           "runs is looked up first? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
            print("\n  No answer, so the Claude Code hook was not installed.")
        print()
        if answer in ("", "y", "yes"):
            try:
                for message in claude_hook.install():
                    print("  " + message)
            except (claude_hook.InstallError, OSError) as e:
                print(f"  Claude Code hook NOT installed: {e}")
            print()
            layers = layers_mod.protection_layers()

    print("  What is protected right now")
    print("  " + "-" * 40)
    for line in layers_mod.render(layers).splitlines():
        print("  " + line)
    print()
    if layers_mod.install_time_protection(layers):
        return True
    print("  " + "!" * 60)
    print("  YOU ARE NOT PROTECTED. Setup finished, but nothing checks the packages you install.")
    if not (interactive and sys.stdin.isatty()):
        print("  (Setup changes your Claude Code settings only when you type yes in a terminal.)")
    print("  To get protected, run one of:")
    print("      stillrunning --hook-claude-code    (installs made by Claude Code)")
    print("      stillrunning shell-install         (installs typed in your terminal)")
    print("  " + "!" * 60)
    print()
    return False


# ---------------------------------------------------------------------------
# SESSION 91: Package Whitelist Commands
# ---------------------------------------------------------------------------
def _get_customer_token() -> str | None:
    """The API token, by the one precedence every command uses
    (see claude_hook.resolve_token)."""
    from .claude_hook import resolve_token
    return resolve_token()[0]


def _whitelist_add(package: str) -> None:
    """Add package to customer whitelist."""
    token = _get_customer_token()
    if not token:
        print("Error: No token configured. Run 'stillrunning --setup' first.")
        return

    try:
        url = api_url("/api/whitelist/add")
        payload = json.dumps({"token": token, "package": package.lower()}).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())

        if result.get("success"):
            print(f"Added '{package}' to your whitelist")
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")
    except urllib.error.HTTPError as e:
        print(f"Error: Server returned {e.code}")
    except Exception as e:
        print(f"Error: {e}")


def _whitelist_remove(package: str) -> None:
    """Remove package from customer whitelist."""
    token = _get_customer_token()
    if not token:
        print("Error: No token configured. Run 'stillrunning --setup' first.")
        return

    try:
        url = api_url("/api/whitelist/remove")
        payload = json.dumps({"token": token, "package": package.lower()}).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())

        if result.get("success"):
            print(f"Removed '{package}' from your whitelist")
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")
    except urllib.error.HTTPError as e:
        print(f"Error: Server returned {e.code}")
    except Exception as e:
        print(f"Error: {e}")


def _whitelist_list() -> None:
    """List all whitelisted packages."""
    token = _get_customer_token()
    if not token:
        print("Error: No token configured. Run 'stillrunning --setup' first.")
        return

    try:
        url = api_url("/api/whitelist/list")
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())

        packages = result.get("packages", [])
        if not packages:
            print("No whitelisted packages.")
            print("\nTo add a package: stillrunning whitelist add <package>")
            return

        print(f"Whitelisted packages ({len(packages)}):\n")
        for pkg in packages:
            name = pkg.get("package_name", "?")
            auto = " (auto)" if pkg.get("auto_whitelisted") else ""
            version = pkg.get("last_clean_version", "")
            version_str = f" v{version}" if version else ""
            print(f"  {name}{version_str}{auto}")

    except urllib.error.HTTPError as e:
        print(f"Error: Server returned {e.code}")
    except Exception as e:
        print(f"Error: {e}")


# ---------------------------------------------------------------------------
# SESSION 97/98: Claude Code PreToolUse Hook
# ---------------------------------------------------------------------------
def _is_package_allowed(pkg_name: str) -> bool:
    """Check if package is in local allowlist or has a one-time override."""
    override_file = Path.home() / ".stillrunning" / "overrides.json"
    if override_file.exists():
        try:
            with open(override_file) as f:
                overrides = json.load(f)
            # Check one-time overrides
            once_list = overrides.get("once", [])
            if pkg_name.lower() in [p.lower() for p in once_list]:
                # Remove from once list (it's consumed)
                overrides["once"] = [p for p in once_list if p.lower() != pkg_name.lower()]
                tmp = override_file.with_suffix(".tmp")
                with open(tmp, "w") as f:
                    json.dump(overrides, f, indent=2)
                tmp.replace(override_file)
                return True
            # Check permanent allowlist
            if pkg_name.lower() in [p.lower() for p in overrides.get("allow", [])]:
                return True
        except Exception:
            pass
    return False


def _log_override(pkg_name: str, override_type: str, reason: str = ""):
    """Log override to ~/.stillrunning/overrides.log."""
    log_file = Path.home() / ".stillrunning" / "overrides.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(log_file, "a") as f:
            ts = datetime.now(timezone.utc).isoformat()
            f.write(f"{ts} | {override_type} | {pkg_name} | {reason}\n")
    except Exception:
        pass


def _allow_package_local(pkg_name: str, once: bool = False) -> None:
    """Add package to local allowlist or one-time override list."""
    override_file = Path.home() / ".stillrunning" / "overrides.json"
    override_file.parent.mkdir(parents=True, exist_ok=True)

    overrides = {"allow": [], "once": []}
    if override_file.exists():
        try:
            with open(override_file) as f:
                overrides = json.load(f)
        except Exception:
            pass

    pkg_lower = pkg_name.lower()

    if once:
        once_list = overrides.get("once", [])
        if pkg_lower not in [p.lower() for p in once_list]:
            once_list.append(pkg_lower)
            overrides["once"] = once_list
        print(f"⚠️  One-time override added for '{pkg_name}'")
        print(f"   The next install of this package will be allowed.")
        print(f"   After that, it will be checked again.")
        _log_override(pkg_name, "once", "user requested")
    else:
        allow_list = overrides.get("allow", [])
        if pkg_lower not in [p.lower() for p in allow_list]:
            allow_list.append(pkg_lower)
            overrides["allow"] = allow_list
        print(f"✓ Package '{pkg_name}' added to permanent allowlist")
        print(f"   All future installs will be allowed without checking.")
        print(f"   To remove: stillrunning deny {pkg_name}")
        _log_override(pkg_name, "permanent", "user requested")

    tmp = override_file.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(overrides, f, indent=2)
    tmp.replace(override_file)


_PIP_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_NPM_SPEC = re.compile(r"^(@[^/@\s]+/[^@\s]+|[^@\s/]+)(?:@(.+))?$")
def _split_spec3(spec: str, npm: bool = False) -> tuple:
    """'requests==2.32.3' / 'axios@1.7.0' / 'pkg[extra]>=1' →
    (name, exact version or None, range/tag or None). Only one exact version
    counts as a pin; a range, wildcard or dist-tag is returned as the third
    value so the engine does NOT answer for "the latest version" when some
    versions of the package are listed. (None, None, None) when the name
    cannot be read."""
    from . import claude_hook as ch
    spec = (spec or "").strip()
    if npm:
        match = _NPM_SPEC.match(spec)
        if not match:
            return None, None, None
        exact, ranged = ch.split_npm_version(match.group(2) or "")
        return match.group(1).lower(), exact, ranged
    match = _PIP_SPEC.match(spec)
    if not match:
        return None, None, None
    # drop environment markers, comments, --hash options and line continuations
    rest = re.split(r"[;#]|\s--|\\", match.group(3), maxsplit=1)[0].strip()
    if rest and rest[0] not in "<>=!~":
        return None, None, None       # `name @ url`, stray words: not a registry spec
    exact, ranged = ch.split_pip_version(rest)
    return match.group(1), exact, ranged


def _split_spec(spec: str, npm: bool = False) -> tuple:
    """(name, exact version or None) — see _split_spec3."""
    return _split_spec3(spec, npm=npm)[:2]


def _check_one(ecosystem: str, name: str, version=None, spec=None, uncertain=False) -> tuple:
    """One package through the same engine the Claude Code hook uses
    (blocklist API, unmetered fallback when the free allowance is used up,
    registry existence, look-alike names, version resolution for entries that
    name specific bad versions). Returns (pkg, outcome); never raises — any
    crash is "could not check"."""
    from . import claude_hook as ch
    pkg = {"eco": ecosystem, "name": name.strip().lower(), "version": version,
           "spec": spec, "uncertain": bool(uncertain)}
    try:
        outcome = ch.lookup(pkg, token=ch.resolve_token()[0])
    except Exception as exc:
        print(f"[stillrunning] WARNING: lookup for {name} failed ({type(exc).__name__}: {exc})",
              file=sys.stderr)
        outcome = {"status": "unverified", "why": "server"}
    if outcome.get("resolved_version") and not version:
        pkg = dict(pkg, version=str(outcome["resolved_version"]))
    return pkg, outcome


def _outcome_exit(outcome: dict) -> int:
    status = outcome.get("status")
    if status in ("ok", "override"):
        return EXIT_CLEAN
    if status == "blocked":
        return EXIT_BLOCKED
    if status == "suspicious":
        return EXIT_SUSPICIOUS
    if status == "not_found":
        return EXIT_NOT_FOUND
    if status == "override_blocked" or outcome.get("why") in ("version", "version_range",
                                                              "override_unchecked"):
        return EXIT_NEEDS_PERSON
    return EXIT_RATE_LIMITED if outcome.get("why") == "quota" else EXIT_ERROR


def _print_outcome(pkg: dict, outcome: dict, indent: str = "") -> int:
    """Plain-language result for one package. Returns the exit code."""
    from . import claude_hook as ch
    eco, name = pkg["eco"], pkg["name"]
    label = name + (f" {pkg['version']}" if pkg.get("version") else "")
    rc = _outcome_exit(outcome)
    status = outcome.get("status")
    twin = ch.lookalike_of(eco, name)
    registry = ch.REGISTRY_NAME.get(eco, "the public registry")
    evidence = ch.build_evidence(pkg, outcome)
    if status == "blocked":
        advisory = outcome.get("advisory")
        print(f"{indent}✗ stillrunning BLOCKED [exit {rc}]: {label}")
        text = (ch.explain("blocked_typosquat", name=name, lookalike=twin) if twin
                else ch.explain("blocked_advisory", name=name, advisory=advisory) if advisory
                else ch.explain("blocked_listed", name=name))
        print(f"{indent}   {text}")
        print(f"{indent}   See: https://stillrunning.io/security-advisories?pkg={name}")
    elif status == "suspicious":
        print(f"{indent}⚠ stillrunning SUSPICIOUS [exit {rc}]: {label}")
        print(f"{indent}   {ch.explain('suspicious', name=name)}")
    elif status == "not_found":
        print(f"{indent}? '{name}' is not on {registry} [exit {rc}] — check the spelling "
              f"(or it comes from a private index).")
        if twin:
            print(f"{indent}   Its name is one letter off from the popular `{twin}`. "
                  f"If you meant `{twin}`, use that.")
    elif status == "override":
        print(f"{indent}· stillrunning: {label} — allowed by your own override [exit {rc}]")
    elif status == "override_blocked":
        print(f"{indent}⚠ stillrunning: {label} is ON THE BLOCKLIST and a local override allows it [exit {rc}]")
        print(f"{indent}   {ch.explain('override_blocked', name=name)}")
    elif rc == EXIT_NEEDS_PERSON:
        print(f"{indent}⚠ stillrunning: {label} — some versions are reported as malicious [exit {rc}]")
        bad = ", ".join(a for a in outcome.get("affected") or [] if isinstance(a, str))
        print(f"{indent}   " + (ch.explain("version_range", name=name, affected=bad)
                               if outcome.get("why") == "version_range"
                               else ch.explain("check_failed", name=name, why="version")))
    elif status == "ok":
        print(f"{indent}✓ stillrunning: {label} is not on the blocklist [exit {rc}]")
        print(f"{indent}   This is not a guarantee — only that no known report matches.")
    else:
        why = ch.CHECK_FAILED_WHY.get(outcome.get("why", "server"), ch.CHECK_FAILED_WHY["server"])
        print(f"{indent}WARNING: {label} was NOT checked — {why} [exit {rc}]")
    for line in ch.top_evidence(evidence, limit=4):
        print(f"{indent}     • {line}")
    return rc


def _scan_package(pkg_name: str, npm: bool = False, not_latest: bool = False) -> int:
    """Check one package (optionally `name==version` / `name@version`).
    Returns 0 not on blocklist, 10 BLOCKED, 11 SUSPICIOUS, 12 free allowance
    used up and the fallback failed, 1 could not check, 3 not on the registry,
    2 timeout/usage."""
    import signal

    ecosystem = "npm" if npm else "pip"

    # 30-second timeout
    def timeout_handler(signum, frame):
        print("\n\033[91mERROR\033[0m: Scan timed out (30s)")
        sys.exit(2)

    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(30)

    name, version, ranged = _split_spec3(pkg_name, npm=npm)
    if not name:
        print(f"\033[91mERROR\033[0m: could not read a package name from {pkg_name!r} [exit {EXIT_USAGE}]")
        return EXIT_USAGE

    print(f"Scanning package: {name}" + (f" {version}" if version else ""))
    print()
    try:
        pkg, outcome = _check_one(ecosystem, name, version, ranged, not_latest)
        return _print_outcome(pkg, outcome)
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)


def _exit_after_scan(run) -> None:
    try:
        code = run()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else EXIT_ERROR
    try:
        from . import funnel
        funnel.track_first_scan(code)
    except Exception:  # lint: allowed-silent(optional telemetry; a scan's exit code never depends on it)
        pass
    sys.exit(code)


MAX_MANIFEST_PACKAGES = 400


def _scan_manifest(path_str: str) -> int:
    """Check every package named in a requirements / lock / manifest file.
    Returns 0 nothing on the blocklist, 10 BLOCKED, 11 SUSPICIOUS, 3 a name is
    not on the registry, 12/1 one or more could not be checked, 2 the file
    could not be read as a manifest. Worst result wins; "could not check" is
    never reported as a pass."""
    from pathlib import Path
    from concurrent.futures import ThreadPoolExecutor

    path = Path(path_str).expanduser().resolve()
    if not path.exists():
        print(f"\033[91mERROR\033[0m: File not found: {path}")
        return 2

    try:
        from .manifest import parse_manifest_strict
    except ImportError as e:
        print(f"\033[91mERROR\033[0m: Could not import manifest module: {e}")
        return EXIT_ERROR

    print(f"Scanning manifest: {path}")
    print()

    specs = parse_manifest_strict(path)
    if specs is None:
        print(f"\033[91mERROR\033[0m: {path.name} is not a kind of file stillrunning can read "
              f"(requirements files, pyproject.toml, Pipfile, package.json, package-lock.json, "
              f"pnpm-lock.yaml, environment.yml, pixi.toml). Nothing was checked [exit {EXIT_USAGE}]")
        return EXIT_USAGE
    if not specs:
        print(f"No packages found in {path.name}")
        return 0

    skipped = [s.name for s in specs if s.is_local or s.is_url or s.is_git]
    todo, seen = [], set()
    for spec in specs:
        if spec.is_local or spec.is_url or spec.is_git:
            continue
        eco = "npm" if spec.ecosystem == "npm" else "pip"
        _, version, ranged = _split_spec3(
            f"{spec.name}{'@' if eco == 'npm' else ''}{spec.version or ''}",
            npm=(eco == "npm")) if spec.version else (None, None, None)
        key = (eco, spec.name.lower(), version, ranged)
        if key not in seen:
            seen.add(key)
            todo.append(key)
    not_checked_extra = 0
    if len(todo) > MAX_MANIFEST_PACKAGES:
        not_checked_extra = len(todo) - MAX_MANIFEST_PACKAGES
        todo = todo[:MAX_MANIFEST_PACKAGES]

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda k: _check_one(*k), todo))

    counts = {"no known threat": 0, "blocked": 0, "suspicious": 0, "not on the registry": 0,
              "not checked": not_checked_extra}
    worst = EXIT_CLEAN
    rank = {EXIT_CLEAN: 0, EXIT_NOT_FOUND: 1, EXIT_ERROR: 2, EXIT_RATE_LIMITED: 2,
            EXIT_SUSPICIOUS: 3, EXIT_BLOCKED: 4}
    for pkg, outcome in results:
        rc = _outcome_exit(outcome)
        if rc == EXIT_CLEAN:
            counts["no known threat"] += 1
        else:
            _print_outcome(pkg, outcome)
            print()
            counts[{EXIT_BLOCKED: "blocked", EXIT_SUSPICIOUS: "suspicious",
                    EXIT_NOT_FOUND: "not on the registry"}.get(rc, "not checked")] += 1
        if rank.get(rc, 2) > rank.get(worst, 0):
            worst = rc
    if not_checked_extra:
        print(f"WARNING: {not_checked_extra} package(s) beyond the first {MAX_MANIFEST_PACKAGES} "
              f"were NOT checked.")
        if rank[worst] < rank[EXIT_ERROR]:
            worst = EXIT_ERROR
    if skipped:
        print(f"Not looked up ({len(skipped)}): local paths, web addresses and repositories "
              f"cannot be checked against the blocklist.")
    print("Summary: " + ", ".join(f"{n} {label}" for label, n in counts.items()) +
          f" [exit {worst}]")
    if worst == EXIT_CLEAN:
        print("   This is not a guarantee — only that no known report matches these names.")
    return worst


# ─── v2.5.0: Venv Persistence ────────────────────────────────────────────────

_SITECUSTOMIZE_MARKER = "# Added by stillrunning v2.5.0"
_SITECUSTOMIZE_BLOCK = f'''{_SITECUSTOMIZE_MARKER}
try:
    import stillrunning.venv_hook
except ImportError:
    pass
# End stillrunning block
'''


def _get_user_site_packages() -> Path:
    """Get the user site-packages directory."""
    import site
    user_site = site.getusersitepackages()
    return Path(user_site)


def _venv_install() -> int:
    """Install sitecustomize.py hook for venv persistence."""
    try:
        user_site = _get_user_site_packages()
        user_site.mkdir(parents=True, exist_ok=True)

        sitecustomize_path = user_site / "sitecustomize.py"

        if sitecustomize_path.exists():
            content = sitecustomize_path.read_text()
            if _SITECUSTOMIZE_MARKER in content:
                print(f"stillrunning venv hook already installed in {sitecustomize_path}")
                return 0
            new_content = content.rstrip() + "\n\n" + _SITECUSTOMIZE_BLOCK
        else:
            new_content = _SITECUSTOMIZE_BLOCK

        tmp_path = sitecustomize_path.with_suffix(".tmp")
        tmp_path.write_text(new_content)
        tmp_path.replace(sitecustomize_path)

        print(f"Venv persistence installed!")
        print(f"  File: {sitecustomize_path}")
        print()
        print("stillrunning will now intercept packages even inside virtual environments.")
        print("Remove with: stillrunning venv-uninstall")
        return 0

    except PermissionError:
        print(f"Permission denied. Try: sudo stillrunning venv-install")
        return 1
    except Exception as e:
        print(f"Error installing venv hook: {e}")
        return 1


def _venv_uninstall() -> int:
    """Remove sitecustomize.py hook."""
    try:
        user_site = _get_user_site_packages()
        sitecustomize_path = user_site / "sitecustomize.py"

        if not sitecustomize_path.exists():
            print("No sitecustomize.py found. Nothing to remove.")
            return 0

        content = sitecustomize_path.read_text()
        if _SITECUSTOMIZE_MARKER not in content:
            print("stillrunning block not found in sitecustomize.py. Nothing to remove.")
            return 0

        lines = content.split("\n")
        new_lines = []
        skip = False
        for line in lines:
            if _SITECUSTOMIZE_MARKER in line:
                skip = True
                continue
            if skip and "# End stillrunning block" in line:
                skip = False
                continue
            if not skip:
                new_lines.append(line)

        new_content = "\n".join(new_lines).strip()

        if not new_content:
            sitecustomize_path.unlink()
            print(f"Removed {sitecustomize_path} (was empty after removing stillrunning block)")
        else:
            tmp_path = sitecustomize_path.with_suffix(".tmp")
            tmp_path.write_text(new_content + "\n")
            tmp_path.replace(sitecustomize_path)
            print(f"Removed stillrunning block from {sitecustomize_path}")

        print("Venv persistence removed.")
        return 0

    except PermissionError:
        print(f"Permission denied. Try: sudo stillrunning venv-uninstall")
        return 1
    except Exception as e:
        print(f"Error removing venv hook: {e}")
        return 1


def _venv_install_silent() -> bool:
    """Install venv hook silently. Returns True on success."""
    try:
        user_site = _get_user_site_packages()
        user_site.mkdir(parents=True, exist_ok=True)
        sitecustomize_path = user_site / "sitecustomize.py"

        if sitecustomize_path.exists():
            content = sitecustomize_path.read_text()
            if _SITECUSTOMIZE_MARKER in content:
                return True  # Already installed
            new_content = content.rstrip() + "\n\n" + _SITECUSTOMIZE_BLOCK
        else:
            new_content = _SITECUSTOMIZE_BLOCK

        tmp_path = sitecustomize_path.with_suffix(".tmp")
        tmp_path.write_text(new_content)
        tmp_path.replace(sitecustomize_path)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Shell auto-activation (CVE-2026-31431 gap fix)
# ---------------------------------------------------------------------------

_SHELL_ACTIVATE_MARKER = "# >>> stillrunning shell hooks >>>"
_SHELL_ACTIVATE_END = "# <<< stillrunning shell hooks <<<"
# POSIX on purpose: ~/.profile is read by plain sh (dash) on Debian/Ubuntu,
# where `source` does not exist and activate.sh's bash syntax is an error.
# Does nothing in other shells, or when ~/.stillrunning has been deleted.
_SHELL_RC_BLOCK = (
    f'\n{_SHELL_ACTIVATE_MARKER}\n'
    '[ -n "${BASH_VERSION:-}${ZSH_VERSION:-}" ] && [ -r "$HOME/.stillrunning/activate.sh" ] '
    '&& . "$HOME/.stillrunning/activate.sh" || :\n'
    f'{_SHELL_ACTIVATE_END}\n')
_SHELL_RC_BLOCK_LEGACY = (f'\n{_SHELL_ACTIVATE_MARKER}\nsource "$HOME/.stillrunning/activate.sh"\n'
                          f'{_SHELL_ACTIVATE_END}\n')


def _unsupported_os(feature: str, alternative: str = "") -> bool:
    """Say plainly when a feature cannot work on this OS. True = stop."""
    names = {"win32": "Windows", "cygwin": "Windows", "darwin": "macOS"}
    if feature == "shell" and sys.platform in ("win32", "cygwin"):
        print("Terminal wrappers are not supported on Windows yet (they are bash scripts; "
              "PowerShell and cmd are not covered).")
    elif feature == "monitor" and not sys.platform.startswith("linux"):
        print(f"The process monitor is not supported on {names.get(sys.platform, sys.platform)} yet "
              "(it reads /proc and restarts processes through screen or systemd, which exist only on Linux).")
    else:
        return False
    if alternative:
        print(alternative)
    return True


# Shared by every wrapper. A real verdict (10 BLOCKED, 11 SUSPICIOUS) always
# stops. Everything that means "this could not be checked" — check failed (1),
# quota (12), CLI missing (127), not on the registry (3), a URL/VCS install, a
# custom index — needs a person's approval: asked on a terminal, stopped when
# nobody is there. STILLRUNNING_ALLOW_UNVERIFIED=1 warns and installs anyway
# (the warning is printed every time); STILLRUNNING_FAIL_CLOSED=1 always stops
# without asking.
_WRAPPER_VERDICT_FN = '''__stillrunning_verdict() {
    local pkg="$1" rc="$2" why answer=""
    case "$rc" in
        0|13) return 0 ;;
        10) echo "stillrunning: BLOCKED '$pkg' — known malicious. See https://stillrunning.io/blocked?pkg=$pkg" >&2; return 1 ;;
        11) echo "stillrunning: BLOCKED '$pkg' — suspicious. Review: https://stillrunning.io/blocked?pkg=$pkg" >&2; return 1 ;;
        14)
            # Part of it IS on the blocklist (some versions, or a local override
            # allows a listed package). Only a person at the keyboard may go on;
            # STILLRUNNING_ALLOW_UNVERIFIED does not apply.
            if [[ "${STILLRUNNING_FAIL_CLOSED:-0}" != "1" && -t 0 && -t 2 ]]; then
                read -r -p "stillrunning: '$pkg' is on the blocklist (some versions, or allowed only by a local override). Run 'stillrunning scan $pkg' for details. Install anyway? [y/N] " answer
                if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
                    return 0
                fi
            fi
            echo "stillrunning: install of '$pkg' stopped — it is on the blocklist (some versions, or allowed only by a local override). Name an exact version, or run 'stillrunning scan $pkg' for details." >&2
            return 1 ;;
        3) why="it is not on the public registry (typo, invented name or private package)" ;;
        12) why="daily scan quota exhausted" ;;
        127) why="the stillrunning CLI is not installed or not on PATH" ;;
        url) why="it installs from a web address or repository, which cannot be looked up" ;;
        index) why="a custom package index is in use, so the names cannot be trusted to mean the public packages" ;;
        *) why="the check could not run (offline or server error, exit $rc)" ;;
    esac
    if [[ "${STILLRUNNING_FAIL_CLOSED:-0}" == "1" ]]; then
        echo "stillrunning: install of '$pkg' stopped — $why (STILLRUNNING_FAIL_CLOSED=1)." >&2
        return 1
    fi
    if [[ "${STILLRUNNING_ALLOW_UNVERIFIED:-0}" == "1" ]]; then
        echo "stillrunning: WARNING — '$pkg' was NOT checked: $why. Installing anyway (STILLRUNNING_ALLOW_UNVERIFIED=1)." >&2
        return 0
    fi
    if [[ -t 0 && -t 2 ]]; then
        read -r -p "stillrunning: '$pkg' was NOT checked: $why. Install anyway? [y/N] " answer
        if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
            return 0
        fi
        echo "stillrunning: install of '$pkg' stopped." >&2
        return 1
    fi
    echo "stillrunning: install of '$pkg' stopped — $why. Nobody is at the keyboard to approve it (set STILLRUNNING_ALLOW_UNVERIFIED=1 to install unchecked packages anyway)." >&2
    return 1
}
'''

# Find the real tool at run time. Never a fixed path (a venv's pip, Homebrew's
# npm and macOS all live somewhere else) and never this wrapper again.
_WRAPPER_RESOLVE_FN = '''__stillrunning_is_wrapper() {
    [[ "$1" -ef "${BASH_SOURCE[0]}" ]] && return 0
    head -n 3 "$1" 2>/dev/null | grep -q "^# stillrunning .* wrapper" && return 0
    return 1
}
__stillrunning_real() {
    local tool="$1" dir candidate self_dir
    self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)"
    local IFS=:
    for dir in $PATH; do
        [[ -z "$dir" ]] && continue
        [[ "$(cd "$dir" 2>/dev/null && pwd -P)" == "$self_dir" ]] && continue
        candidate="$dir/$tool"
        if [[ -f "$candidate" && -x "$candidate" ]] && ! __stillrunning_is_wrapper "$candidate"; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}
__stillrunning_run_pip() {
    local real py
    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
        if [[ -x "$VIRTUAL_ENV/bin/$__sr_tool" ]] && ! __stillrunning_is_wrapper "$VIRTUAL_ENV/bin/$__sr_tool"; then
            exec "$VIRTUAL_ENV/bin/$__sr_tool" "$@"
        fi
        if [[ -x "$VIRTUAL_ENV/bin/python" ]]; then
            exec "$VIRTUAL_ENV/bin/python" -m pip "$@"
        fi
    fi
    if real="$(__stillrunning_real "$__sr_tool")"; then
        exec "$real" "$@"
    fi
    for py in python3 python; do
        if real="$(__stillrunning_real "$py")"; then
            exec "$real" -m pip "$@"
        fi
    done
    echo "stillrunning: cannot find the real $__sr_tool — it is not in an active virtual environment or anywhere on PATH (other than this wrapper), and no python was found to run 'python -m pip'. Nothing was run." >&2
    exit 127
}
__stillrunning_run_tool() {
    local real
    if real="$(__stillrunning_real "$__sr_tool")"; then
        exec "$real" "$@"
    fi
    echo "stillrunning: cannot find the real $__sr_tool anywhere on PATH (other than this wrapper). Nothing was run." >&2
    exit 127
}
'''

_WRAPPER_SCRIPT_PIP = '''#!/bin/bash
# stillrunning pip wrapper — checks packages before install
set -e
__sr_tool="pip"

''' + _WRAPPER_VERDICT_FN + _WRAPPER_RESOLVE_FN + '''
# `install` may follow global flags (pip -q install x), so look at every argument.
sub_idx=0
n=0
for arg in "$@"; do
    n=$((n + 1))
    if [[ "$arg" == "install" || "$arg" == "download" || "$arg" == "wheel" ]]; then
        sub_idx=$n
        break
    fi
done
if (( sub_idx > 0 )); then
    packages=()
    skip=""
    not_latest=()
    if [[ -n "${PIP_INDEX_URL:-}${PIP_EXTRA_INDEX_URL:-}${PIP_FIND_LINKS:-}" ]]; then
        __stillrunning_verdict "this install" index || exit 1
    fi
    # --pre or a constraints file changes which version an unpinned name gets.
    if [[ -n "${PIP_PRE:-}${PIP_CONSTRAINT:-}" ]]; then
        not_latest=(--not-latest)
    fi
    for arg in "${@:$((sub_idx + 1))}"; do
        case "$arg" in
            --pre|-c|-c?*|--constraint|--constraint=*) not_latest=(--not-latest) ;;
        esac
    done
    for arg in "${@:$((sub_idx + 1))}"; do
        if [[ -n "$skip" ]]; then
            kind="$skip"
            skip=""
            if [[ "$kind" == "req" ]]; then
                pkg="$arg"
                rc=0
                stillrunning scan-manifest "$arg" >/dev/null 2>&1 || rc=$?
                __stillrunning_verdict "$pkg" "$rc" || exit 1
            elif [[ "$kind" == "edit" && ( "$arg" == *://* || "$arg" == git+* ) ]]; then
                __stillrunning_verdict "$arg" url || exit 1
            fi
            continue
        fi
        case "$arg" in
            -r|--requirement) skip="req"; continue ;;
            -e|--editable) skip="edit"; continue ;;
            -i|--index-url|--extra-index-url|-f|--find-links)
                __stillrunning_verdict "this install" index || exit 1
                skip="val"; continue ;;
            --index-url=*|--extra-index-url=*|--find-links=*)
                __stillrunning_verdict "this install" index || exit 1
                continue ;;
            --requirement=*)
                pkg="${arg#*=}"
                rc=0
                stillrunning scan-manifest "$pkg" >/dev/null 2>&1 || rc=$?
                __stillrunning_verdict "$pkg" "$rc" || exit 1
                continue ;;
            -c|--constraint|-t|--target|--prefix|--root|--python|--platform|--python-version|--implementation|--abi|--src|--upgrade-strategy|-C|--config-settings|--global-option|--no-binary|--only-binary|--progress-bar|--report|--cert|--client-cert|--proxy|--retries|--timeout|--trusted-host|--cache-dir|--log|--use-feature|--use-deprecated|--exists-action|--root-user-action|--keyring-provider|--hash|-d|--dest|-w|--wheel-dir)
                skip="val"; continue ;;
            --index|--default-index)
                __stillrunning_verdict "this install" index || exit 1
                skip="val"; continue ;;
            --index=*|--default-index=*)
                __stillrunning_verdict "this install" index || exit 1
                continue ;;
            --requirements=*|-r?*)
                # value attached to the flag: -rreq.txt, -r=req.txt
                if [[ "$arg" == --* ]]; then pkg="${arg#*=}"; else pkg="${arg#-r}"; pkg="${pkg#=}"; fi
                rc=0
                stillrunning scan-manifest "$pkg" >/dev/null 2>&1 || rc=$?
                __stillrunning_verdict "$pkg" "$rc" || exit 1
                continue ;;
            -i?*|-f?*)
                __stillrunning_verdict "this install" index || exit 1
                continue ;;
            --editable=*|-e?*)
                if [[ "$arg" == --* ]]; then pkg="${arg#*=}"; else pkg="${arg#-e}"; pkg="${pkg#=}"; fi
                if [[ "$pkg" == *://* || "$pkg" == git+* ]]; then
                    __stillrunning_verdict "$pkg" url || exit 1
                fi
                continue ;;
            -*) continue ;;
            *://*|git+*)
                __stillrunning_verdict "$arg" url || exit 1
                continue ;;
            .*|/*|~*|*/*|*.whl|*.tar.gz|*.zip) continue ;;  # local path: nothing to look up
        esac
        pkg="${arg%%[]<>=!~;@ []*}"       # name only, for messages
        [[ -n "$pkg" ]] && packages+=("$arg")   # full spec: an exact pin is checked as that version
    done
    for spec in "${packages[@]}"; do
        pkg="${spec%%[]<>=!~;@ []*}"
        rc=0
        stillrunning scan "$spec" "${not_latest[@]}" >/dev/null 2>&1 || rc=$?
        __stillrunning_verdict "$pkg" "$rc" || exit 1
    done
fi
__stillrunning_run_pip "$@"
'''

_WRAPPER_SCRIPT_NPM = '''#!/bin/bash
# stillrunning npm wrapper — checks packages before install
set -e
__sr_tool="npm"

''' + _WRAPPER_VERDICT_FN + _WRAPPER_RESOLVE_FN + '''
# `install` may follow global flags (npm --silent install x), so look at every argument.
sub_idx=0
n=0
for arg in "$@"; do
    n=$((n + 1))
    case "$arg" in
        install|i|add|update|up|upgrade|install-test|it|link|ln)
            sub_idx=$n
            break ;;
    esac
done
if (( sub_idx > 0 )); then
    packages=()
    skip=""
    not_latest=()
    if [[ -n "${NPM_CONFIG_TAG:-}${npm_config_tag:-}${NPM_CONFIG_BEFORE:-}${npm_config_before:-}" ]]; then
        not_latest=(--not-latest)
    fi
    for arg in "$@"; do
        case "$arg" in
            --tag|--tag=*|--before|--before=*) not_latest=(--not-latest) ;;
        esac
    done
    if [[ -n "${NPM_CONFIG_REGISTRY:-}${npm_config_registry:-}" ]]; then
        __stillrunning_verdict "this install" index || exit 1
    fi
    for arg in "$@"; do
        if [[ "$arg" == "--registry" || "$arg" == --registry=* ]]; then
            __stillrunning_verdict "this install" index || exit 1
        fi
    done
    for arg in "${@:$((sub_idx + 1))}"; do
        if [[ -n "$skip" ]]; then
            skip=""
            continue
        fi
        case "$arg" in
            --registry|--prefix|-C|-w|--workspace|--tag|--cache|--userconfig|--loglevel|--omit|--include|--install-strategy|--otp)
                skip="val"; continue ;;
            -*) continue ;;
            *://*|git+*|git@*|github:*|gitlab:*|bitbucket:*|gist:*)
                __stillrunning_verdict "$arg" url || exit 1
                continue ;;
            .*|/*|~*|file:*) continue ;;  # local path: nothing to look up
        esac
        arg="${arg#npm:}"
        [[ "$arg" == *@npm:* ]] && arg="${arg#*@npm:}"
        if [[ "$arg" == @* ]]; then
            rest="${arg#@}"
            pkg="@${rest%%@*}"
        else
            pkg="${arg%%@*}"
            if [[ "$pkg" == */* ]]; then
                __stillrunning_verdict "$arg" url || exit 1   # user/repo shorthand
                continue
            fi
        fi
        [[ -n "$pkg" ]] && packages+=("$arg")   # full spec: an exact pin is checked as that version
    done
    for spec in "${packages[@]}"; do
        if [[ "$spec" == @* ]]; then
            rest="${spec#@}"
            pkg="@${rest%%@*}"
        else
            pkg="${spec%%@*}"
        fi
        rc=0
        stillrunning scan "$spec" --npm "${not_latest[@]}" >/dev/null 2>&1 || rc=$?
        __stillrunning_verdict "$pkg" "$rc" || exit 1
    done
fi
__stillrunning_run_tool "$@"
'''

_ACTIVATE_SCRIPT = '''#!/bin/bash
# stillrunning shell hooks — auto-loaded on shell init (bash and zsh)
# Remove with: stillrunning shell-uninstall

export STILLRUNNING_SHELL_ACTIVE=1
# Once only: a shell that sources its rc file twice must not grow PATH.
case ":$PATH:" in
    *":$HOME/.stillrunning/bin:"*) ;;
    *) export PATH="$HOME/.stillrunning/bin:$PATH" ;;
esac

# Functions, not only PATH: activating a virtual environment afterwards puts
# its bin/ ahead of ours on PATH, and `pip install` would then skip the check.
# The wrapper itself runs the environment's own pip (see __stillrunning_run_pip).
function pip() { "$HOME/.stillrunning/bin/pip" "$@"; }
function pip3() { "$HOME/.stillrunning/bin/pip3" "$@"; }
function npm() { "$HOME/.stillrunning/bin/npm" "$@"; }

# python -m pip intercept. Everything else runs the python the shell would
# have run anyway (`command` skips this function, so a venv's python stays
# the venv's python — never a fixed /usr/bin path).
# Interpreter flags may come first (python3 -W ignore -m pip install x).
function __stillrunning_python() {
    local tool="$1"
    shift
    local idx=0 n=0 skip=0 a
    for a in "$@"; do
        n=$((n + 1))
        if [[ "$skip" == "1" ]]; then skip=0; continue; fi
        case "$a" in
            -m) idx=$n; break ;;
            -W|-X) skip=1 ;;
            -c) break ;;
            -*) ;;
            *) break ;;
        esac
    done
    if [[ "$idx" -gt 0 ]]; then
        local rest=("${@:$((idx + 1))}")
        if [[ "${rest[@]:0:1}" == "pip" ]]; then
            "$HOME/.stillrunning/bin/pip" "${rest[@]:1}"
            return $?
        fi
    fi
    command "$tool" "$@"
}

function python3() { __stillrunning_python python3 "$@"; }

function python() { __stillrunning_python python "$@"; }

# bash can hand functions to the scripts it starts; zsh has no `export -f`.
if [[ -n "${BASH_VERSION:-}" ]]; then
    export -f pip pip3 npm python3 python __stillrunning_python
fi

# Source conda hook if present
[[ -f "$HOME/.stillrunning/conda_hook.sh" ]] && source "$HOME/.stillrunning/conda_hook.sh"
'''

_CONDA_ACTIVATE_SCRIPT = '''#!/bin/bash
# stillrunning conda hook — wraps conda install
''' + _WRAPPER_VERDICT_FN + '''
# Auto-installed by stillrunning shell-install

_original_conda=$(which -a conda 2>/dev/null | grep -v stillrunning | head -1)
[[ -z "$_original_conda" ]] && _original_conda="/opt/conda/bin/conda"

function conda() {
    if [[ "$1" == "install" || "$1" == "create" ]]; then
        local cmd="$1"
        shift
        local packages=()
        for arg in "$@"; do
            [[ "$arg" == -* ]] && continue
            [[ "$arg" == *=* ]] && arg="${arg%%=*}"
            packages+=("$arg")
        done
        for pkg in "${packages[@]}"; do
            rc=0
            stillrunning scan "$pkg" >/dev/null 2>&1 || rc=$?
            __stillrunning_verdict "$pkg" "$rc" || return 1
        done
        "$_original_conda" "$cmd" "$@"
    else
        "$_original_conda" "$@"
    fi
}
export -f conda
'''


def _venv_uninstall_silent() -> None:
    """Remove the sitecustomize block shell-install added, without output."""
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        _venv_uninstall()


def _shell_install() -> int:
    """Install shell hooks for auto-activation."""
    if _unsupported_os("shell", "What works on Windows today: stillrunning --hook-claude-code "
                                "(checks every install Claude Code runs) and stillrunning scan <package>."):
        return 1
    sr_dir = Path.home() / ".stillrunning"
    bin_dir = sr_dir / "bin"

    try:
        bin_dir.mkdir(parents=True, exist_ok=True)

        # Create wrapper scripts
        pip_wrapper = bin_dir / "pip"
        pip3_wrapper = bin_dir / "pip3"
        npm_wrapper = bin_dir / "npm"
        activate_script = sr_dir / "activate.sh"

        pip_wrapper.write_text(_WRAPPER_SCRIPT_PIP)
        pip_wrapper.chmod(0o755)
        pip3_wrapper.write_text(_WRAPPER_SCRIPT_PIP.replace('__sr_tool="pip"', '__sr_tool="pip3"'))
        pip3_wrapper.chmod(0o755)
        npm_wrapper.write_text(_WRAPPER_SCRIPT_NPM)
        npm_wrapper.chmod(0o755)
        activate_script.write_text(_ACTIVATE_SCRIPT)
        activate_script.chmod(0o755)

        # Conda hook (sourced by activate.sh if conda is present)
        conda_hook = sr_dir / "conda_hook.sh"
        conda_hook.write_text(_CONDA_ACTIVATE_SCRIPT)
        conda_hook.chmod(0o755)

        # Detect and update shell rc files
        rc_files = []
        home = Path.home()

        # Check which shells exist
        if (home / ".bashrc").exists() or shutil.which("bash"):
            rc_files.append(home / ".bashrc")
        if (home / ".zshrc").exists() or shutil.which("zsh"):
            rc_files.append(home / ".zshrc")
        if (home / ".profile").exists():
            rc_files.append(home / ".profile")

        source_line = _SHELL_RC_BLOCK

        updated = []
        for rc_file in rc_files:
            try:
                content = rc_file.read_text() if rc_file.exists() else ""
                if _SHELL_ACTIVATE_MARKER in content:
                    continue  # Already installed

                # Append idempotently
                with open(rc_file, "a") as f:
                    f.write(source_line)
                updated.append(str(rc_file))
            except PermissionError:
                continue

        # Also install venv hook for Python-level coverage
        venv_ok = _venv_install_silent()

        print("stillrunning shell hooks installed!")
        print()
        print("Created:")
        print(f"  {bin_dir}/pip, pip3, npm — wrapper scripts")
        print(f"  {activate_script} — shell activation")
        print(f"  {sr_dir}/conda_hook.sh — conda intercept")
        if venv_ok:
            print(f"  sitecustomize.py — venv persistence")
        print()
        if updated:
            print(f"Updated: {', '.join(updated)}")
            print()
        print("stillrunning hooks now active in all new shells.")
        print("Open a new terminal, or run: source ~/.stillrunning/activate.sh")
        print("(bash and zsh. Other shells such as fish are not covered yet.)")
        print()
        print("Verify with: stillrunning status")
        return 0

    except Exception as e:
        print(f"Error installing shell hooks: {e}")
        return 1


def _shell_uninstall() -> int:
    """Remove shell hooks."""
    sr_dir = Path.home() / ".stillrunning"
    bin_dir = sr_dir / "bin"

    try:
        # Remove wrapper scripts
        for script in ["pip", "pip3", "npm"]:
            script_path = bin_dir / script
            if script_path.exists():
                script_path.unlink()
        if bin_dir.is_dir() and not any(bin_dir.iterdir()):
            bin_dir.rmdir()

        for name in ("activate.sh", "conda_hook.sh"):
            leftover = sr_dir / name
            if leftover.exists():
                leftover.unlink()

        # Clean up rc files
        home = Path.home()
        for rc_name in [".bashrc", ".zshrc", ".profile"]:
            rc_file = home / rc_name
            if not rc_file.exists():
                continue

            content = rc_file.read_text()
            if _SHELL_ACTIVATE_MARKER not in content:
                continue

            # The exact text install appended → the file is byte for byte
            # what it was (and is removed if install created it).
            exact = next((b for b in (_SHELL_RC_BLOCK, _SHELL_RC_BLOCK_LEGACY) if b in content), None)
            if exact is not None:
                restored = content.replace(exact, "", 1)
                if restored == "":
                    rc_file.unlink()
                else:
                    tmp_path = rc_file.with_name(rc_file.name + ".stillrunning-tmp")
                    tmp_path.write_text(restored)
                    shutil.copymode(rc_file, tmp_path)
                    tmp_path.replace(rc_file)
                continue

            # Remove the stillrunning block
            lines = content.split("\n")
            new_lines = []
            skip = False
            for line in lines:
                if _SHELL_ACTIVATE_MARKER in line:
                    skip = True
                    continue
                if _SHELL_ACTIVATE_END in line:
                    skip = False
                    continue
                if not skip:
                    new_lines.append(line)

            new_content = "\n".join(new_lines).rstrip() + "\n"
            tmp_path = rc_file.with_suffix(".tmp")
            tmp_path.write_text(new_content)
            tmp_path.replace(rc_file)

        _venv_uninstall_silent()
        print("stillrunning shell hooks removed.")
        print("Open a new terminal for changes to take effect (this one still has the")
        print("pip / npm functions loaded; they stop working here, so open a new one).")
        return 0

    except Exception as e:
        print(f"Error removing shell hooks: {e}")
        return 1


def _status() -> int:
    """Show every protection layer as ON / OFF / NOT VERIFIED, with the reason."""
    from . import layers as layers_mod
    print("stillrunning protection status")
    print("=" * 40)
    print()
    print(layers_mod.render(layers_mod.protection_layers()))
    print()
    try:
        import site
        sitecustomize = Path(site.getusersitepackages()) / "sitecustomize.py"
        if sitecustomize.exists() and _SITECUSTOMIZE_MARKER in sitecustomize.read_text():
            print("[ON] Venv persistence (keeps the import checks on inside virtualenvs)")
        else:
            print("[OFF] Venv persistence (optional): stillrunning venv-install")
    except Exception as e:
        print(f"[NOT VERIFIED] Venv persistence: could not check ({type(e).__name__})")
    print()
    return 0


def _run_claude_code_hook() -> None:
    """Run as the Claude Code PreToolUse hook (reads the tool call on stdin)."""
    from . import claude_hook
    claude_hook.main()


def _install_claude_code_hook(statusline: bool = False, panel: bool = True) -> None:
    """Register the PreToolUse hook in ~/.claude/settings.json."""
    from . import claude_hook
    try:
        messages = claude_hook.install(statusline=statusline, panel=panel)
    except (claude_hook.InstallError, OSError) as e:
        print(f"Claude Code hook NOT installed: {e}")
        sys.exit(1)
    for message in messages:
        print(message)
    print()
    print("Every pip / npm / uv / yarn / pnpm install Claude Code runs is now looked up first.")
    print("You will see one line per package, for example:")
    print("  " + claude_hook.status_line("ok", "requests 2.32.3 (pip)", "no known threat", 140))
    print("Known-malicious packages are blocked; anything that cannot be checked asks you first.")
    print("Report card: stillrunning shield (in a terminal) or /shield (side panel in Claude Code)")
    if not panel:
        print("Optional side panel in Claude Code: stillrunning --hook-claude-code")
    if not statusline:
        print("Optional status line with today's counts: stillrunning --hook-claude-code --statusline")
    print("Remove: stillrunning --uninstall-hook-claude-code")


def _uninstall_claude_code_hook() -> None:
    """Remove the hook (and our status line, if we installed it)."""
    from . import claude_hook
    try:
        messages = claude_hook.uninstall()
    except (claude_hook.InstallError, OSError) as e:
        print(f"Claude Code hook not removed: {e}")
        sys.exit(1)
    for message in messages:
        print(message)


def main_cli() -> None:
    """Entry point for the stillrunning command."""
    from ._stdio import make_output_safe
    make_output_safe()   # never crash on a non-UTF-8 console (Windows code pages)
    import argparse
    parser = argparse.ArgumentParser(
        description="StillRunning — Lightweight process monitor with Telegram alerts"
    )
    parser.add_argument(
        "--setup", action="store_true",
        help="Run interactive setup wizard to auto-generate config"
    )
    parser.add_argument(
        "--autonomous", action="store_true",
        help="Non-interactive setup for CI/CD (reads STILLRUNNING_* env vars)"
    )
    parser.add_argument(
        "--add-server", action="store_true",
        help="Add a new server to your existing account"
    )
    parser.add_argument(
        "--doctor", action="store_true",
        help="Run comprehensive health check on the agent"
    )
    parser.add_argument(
        "--diagnose", action="store_true",
        help="Same as --doctor"
    )
    parser.add_argument(
        "--reconfigure", action="store_true",
        help="Run the setup wizard again (same as --setup)"
    )
    parser.add_argument("--version", action="version", version=f"stillrunning {VERSION}")
    parser.add_argument(
        "--token",
        help="Your customer API token (for --add-server)"
    )
    parser.add_argument(
        "--name",
        help="Name for the new server (for --add-server)"
    )
    # SESSION 93: Import hook commands
    parser.add_argument(
        "--install-hook", action="store_true",
        help="Install always-on import protection (.pth file)"
    )
    parser.add_argument(
        "--uninstall-hook", action="store_true",
        help="Remove always-on import protection"
    )
    parser.add_argument(
        "--allow",
        help="Allow a previously blocked package"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Single-use override (use with --allow)"
    )
    parser.add_argument(
        "--block",
        help="Manually block a package"
    )
    # SESSION 97: Claude Code PreToolUse hook
    parser.add_argument(
        "--hook-claude-code", action="store_true",
        help="Install Claude Code PreToolUse hook"
    )
    parser.add_argument(
        "--uninstall-hook-claude-code", action="store_true",
        help="Remove Claude Code PreToolUse hook"
    )
    parser.add_argument(
        "--statusline", action="store_true",
        help="With --hook-claude-code: also add the shield status line "
             "(never replaces a status line you already have)"
    )
    parser.add_argument(
        "--no-panel", action="store_true",
        help="With --hook-claude-code: do not add the stillrunning shield side panel"
    )

    # SESSION 91: Whitelist subcommand
    subparsers = parser.add_subparsers(dest="command")
    whitelist_parser = subparsers.add_parser("whitelist", help="Manage package whitelist")
    whitelist_sub = whitelist_parser.add_subparsers(dest="whitelist_action")
    whitelist_add = whitelist_sub.add_parser("add", help="Add package to whitelist")
    whitelist_add.add_argument("package", help="Package name to whitelist")
    whitelist_remove = whitelist_sub.add_parser("remove", help="Remove package from whitelist")
    whitelist_remove.add_argument("package", help="Package name to remove")
    whitelist_sub.add_parser("list", help="List all whitelisted packages")

    # SESSION 97: Hook subcommand for Claude Code PreToolUse
    subparsers.add_parser("hook", help="Run as Claude Code PreToolUse hook (reads stdin)")
    subparsers.add_parser("statusline", help="Print the Claude Code status line")
    shield_parser = subparsers.add_parser(
        "shield", help="Report card: what the Claude Code hook checked, blocked and why")
    shield_parser.add_argument("--json", action="store_true",
                               help="Print the report as JSON (stable schema, see shield.py)")
    shield_parser.add_argument("-n", "--last", type=int, default=8,
                               help="How many recent decisions to show (default 8)")

    remember_parser = subparsers.add_parser(
        "remember", help="Don't ask again for one exact command (last | <id> | --list)")
    remember_parser.add_argument("which", nargs="?", help="'last' or the id shown in the panel")
    remember_parser.add_argument("--list", action="store_true", help="Show remembered commands")
    remember_parser.add_argument("--json", action="store_true", help="Print as JSON")
    forget_parser = subparsers.add_parser("forget", help="Stop remembering a command (<id> | --all)")
    forget_parser.add_argument("which", nargs="?", help="The id from `stillrunning remember --list`")
    forget_parser.add_argument("--all", action="store_true", help="Forget every remembered command")
    forget_parser.add_argument("--json", action="store_true", help="Print as JSON")

    panel_parser = subparsers.add_parser(
        "panel", help="Data for the Claude Code side panel: protection state and a project scan")
    panel_parser.add_argument("--json", action="store_true", help="Print as JSON")
    panel_parser.add_argument("--scan", action="store_true",
                              help="Check this project's and this machine's packages now (network)")
    panel_parser.add_argument("--cwd", default=None, help="Project folder (default: current)")

    cve_parser = subparsers.add_parser(
        "cve", help="Known vulnerabilities in packages you already use (OSV.dev); "
                    "shortens the time to patch, does not detect malware")
    cve_parser.add_argument("--json", action="store_true",
                            help="Print the saved state as JSON (local only, no network)")
    cve_parser.add_argument("--refresh", action="store_true",
                            help="Inventory this project and machine and check OSV.dev now")
    cve_parser.add_argument("--schedule", action="store_true",
                            help="Add one crontab line that runs --refresh every 6 hours")
    cve_parser.add_argument("--unschedule", action="store_true",
                            help="Remove that crontab line")
    cve_parser.add_argument("--cwd", default=None, help="Project folder (default: current)")

    # SESSION 98: Allow subcommand with --once support
    allow_parser = subparsers.add_parser("allow", help="Allow a blocked package")
    allow_parser.add_argument("package", help="Package name to allow")
    allow_parser.add_argument("--once", action="store_true", help="Single-use override")

    # v2.3.0: Scan subcommand — check if a package is safe
    scan_parser = subparsers.add_parser("scan", help="Look a package up in the blocklist before installing (name, name==version, or name@version with --npm)")
    scan_parser.add_argument("package", help="Package name to scan")
    scan_parser.add_argument("--not-latest", action="store_true", dest="not_latest",
                             help="The install uses a flag that changes which version resolves "
                                  "(--pre, a constraints file, --tag): do not assume the latest version")
    scan_parser.add_argument("--npm", action="store_true",
                             help="Scan an npm package (default: PyPI). Used by the npm wrapper.")

    # v2.4.0: Scan-manifest subcommand — check all packages in a manifest file
    manifest_parser = subparsers.add_parser("scan-manifest", help="Scan a requirements.txt or similar file")
    manifest_parser.add_argument("path", help="Path to manifest file")

    # v2.5.0: Venv persistence commands
    subparsers.add_parser("venv-install", help="Install sitecustomize.py hook for venv persistence")
    subparsers.add_parser("venv-uninstall", help="Remove sitecustomize.py hook")

    # CVE-2026-31431: Shell auto-activation
    subparsers.add_parser("shell-install", help="Install shell hooks for auto-activation")
    subparsers.add_parser("shell-uninstall", help="Remove shell hooks")
    subparsers.add_parser("status", help="Show status of all protection layers")

    # Sent before parse_args so --help and usage errors still count.
    # The Claude Code hook and status line run on every tool call / redraw:
    # they must stay fast and make no network call of their own.
    # `cve` talks only to api.osv.dev (and only with --refresh).
    if sys.argv[1:2] not in (["hook"], ["statusline"], ["shield"], ["cve"]):
        from .heartbeat import send_cli_ping, command_label
        known = set(subparsers.choices) | set(parser._option_string_actions)
        send_cli_ping(VERSION, command_label(sys.argv[1:], known))

    args = parser.parse_args()

    # Handle whitelist commands
    if args.command == "whitelist":
        if args.whitelist_action == "add":
            _whitelist_add(args.package)
        elif args.whitelist_action == "remove":
            _whitelist_remove(args.package)
        elif args.whitelist_action == "list":
            _whitelist_list()
        else:
            whitelist_parser.print_help()
        return

    # SESSION 97: Handle hook command (Claude Code PreToolUse)
    if args.command == "hook":
        _run_claude_code_hook()
        return
    if args.command == "statusline":
        from . import statusline
        print(statusline.render())
        return
    if args.command == "shield":
        from . import shield
        sys.exit(shield.main((["--json"] if args.json else []) + ["-n", str(args.last)]))

    if args.command in ("remember", "forget"):
        from . import remembered
        extra = ([args.which] if args.which else []) + (["--json"] if args.json else [])
        extra += ["--list"] if getattr(args, "list", False) else []
        extra += ["--all"] if getattr(args, "all", False) else []
        sys.exit(remembered.main([args.command] + extra))

    if args.command == "panel":
        from . import panel
        sys.exit(panel.main((["--json"] if args.json else []) + (["--scan"] if args.scan else [])
                            + (["--cwd", args.cwd] if args.cwd else [])))

    if args.command == "cve":
        from . import cve
        sys.exit(cve.main([flag for flag, on in (("--json", args.json), ("--refresh", args.refresh),
                                                 ("--schedule", args.schedule),
                                                 ("--unschedule", args.unschedule)) if on]
                          + (["--cwd", args.cwd] if args.cwd else [])))

    # SESSION 98: Handle allow subcommand
    if args.command == "allow":
        _allow_package_local(args.package, once=args.once)
        return

    # v2.3.0: Handle scan subcommand (v2.13.2: --npm)
    if args.command == "scan":
        _exit_after_scan(lambda: _scan_package(args.package, npm=args.npm,
                                               not_latest=getattr(args, "not_latest", False)))

    # v2.4.0: Handle scan-manifest subcommand
    if args.command == "scan-manifest":
        _exit_after_scan(lambda: _scan_manifest(args.path))

    # v2.5.0: Handle venv-install/uninstall
    if args.command == "venv-install":
        sys.exit(_venv_install())
    if args.command == "venv-uninstall":
        sys.exit(_venv_uninstall())

    # CVE-2026-31431: Shell auto-activation
    if args.command == "shell-install":
        sys.exit(_shell_install())
    if args.command == "shell-uninstall":
        sys.exit(_shell_uninstall())
    if args.command == "status":
        sys.exit(_status())

    # SESSION 97: Handle Claude Code hook install/uninstall
    if args.hook_claude_code:
        _install_claude_code_hook(statusline=args.statusline, panel=not args.no_panel)
        return
    elif args.uninstall_hook_claude_code:
        _uninstall_claude_code_hook()
        return

    # SESSION 93: Handle import hook commands
    if args.install_hook:
        from . import hook
        pth_path = hook.install_pth()
        print(f"Always-on import protection installed.")
        print(f"All Python imports will now be checked for malicious packages.")
        return
    elif args.uninstall_hook:
        from . import hook
        if hook.uninstall_pth():
            print("Always-on import protection removed.")
        else:
            print("No .pth file found to remove.")
        return
    elif args.allow:
        _allow_package_local(args.allow, once=getattr(args, 'once', False))
        return
    elif args.block:
        from . import hook
        hook.block_package(args.block, "Manually blocked via CLI")
        print(f"Package '{args.block}' is now blocked.")
        return

    if args.doctor or args.diagnose:
        sys.exit(run_doctor())
    elif args.add_server:
        if not args.token:
            print("Error: --token required with --add-server")
            print("Usage: stillrunning --add-server --token YOUR_TOKEN --name my-server")
            return
        if not args.name:
            print("Error: --name required with --add-server")
            print("Usage: stillrunning --add-server --token YOUR_TOKEN --name my-server")
            return
        _add_server_to_account(args.token, args.name)
    elif args.setup or args.autonomous or args.reconfigure:
        run_setup_wizard(autonomous=args.autonomous)
    else:
        # First-run detection: no config → run setup wizard
        if not config_file().exists():
            print()
            print("  No configuration found. Starting setup wizard...")
            print()
            run_setup_wizard(autonomous=False)
        else:
            main()


if __name__ == "__main__":
    main_cli()
