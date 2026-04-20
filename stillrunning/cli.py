#!/usr/bin/env python3
"""
StillRunning v1.2 — Lightweight process monitor with Telegram alerts and Shield security.

Usage:
    Quick start:  python3 stillrunning.py --setup
    Manual:       Edit stillrunning.yaml, then run: screen -dmS stillrunning python3 stillrunning.py
    Commands:     Text "status" or "help" to your Telegram bot

Requires: PyYAML (pip install pyyaml)
"""

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

# Version constant for telemetry
VERSION = "2.2.1"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CONFIG_FILE = Path(__file__).parent / "stillrunning.yaml"
CONFIG: dict = {}


def load_config() -> dict:
    global CONFIG
    if not CONFIG_FILE.exists():
        print(f"ERROR: Config file not found: {CONFIG_FILE}")
        print("Copy stillrunning.yaml.example to stillrunning.yaml and fill in your config.")
        sys.exit(1)

    with open(CONFIG_FILE) as f:
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
    except Exception:
        pass


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
    except Exception:
        pass


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
            "https://stillrunning.io/api/version",
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
            "https://stillrunning.io/api/early-signup",
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

        config_path = Path(__file__).parent / "stillrunning.yaml"
        config_tmp = config_path.with_suffix(".yaml.tmp")
        with open(config_tmp, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        os.replace(config_tmp, config_path)

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
    alert_choice = input("  Choose [1]: ").strip() or "1"
    print()

    # Track the choice
    channel_map = {"1": "email", "2": "telegram", "3": "silent", "4": "skipped"}
    channel = channel_map.get(alert_choice, "email")
    funnel.track_step(f"alert_channel_{channel}")

    config_path = Path(__file__).parent / "stillrunning.yaml"
    cwd = Path.cwd()

    # === SKIP PATH ===
    if alert_choice == "4":
        config = {"setup_skipped": True, "alert_channel": "skipped"}
        config_tmp = config_path.with_suffix(".yaml.tmp")
        with open(config_tmp, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        os.replace(config_tmp, config_path)
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
        config_tmp = config_path.with_suffix(".yaml.tmp")
        with open(config_tmp, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        os.replace(config_tmp, config_path)
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
            config_tmp = config_path.with_suffix(".yaml.tmp")
            with open(config_tmp, "w") as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            os.replace(config_tmp, config_path)
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
            config_tmp = config_path.with_suffix(".yaml.tmp")
            with open(config_tmp, "w") as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            os.replace(config_tmp, config_path)
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

        config_tmp = config_path.with_suffix(".yaml.tmp")
        with open(config_tmp, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        os.replace(config_tmp, config_path)
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
_SHIELD_API_URL = "https://stillrunning.io"

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
        url = "https://stillrunning.io/api/servers/add"
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


def run_doctor() -> None:
    """Run comprehensive health check on stillrunning agent."""
    import urllib.request
    import subprocess
    import shutil

    print("\n" + "=" * 50)
    print("STILLRUNNING DOCTOR")
    print("=" * 50 + "\n")

    issues = []
    warnings = []

    # 1. Check config file exists
    config_path = Path.home() / ".stillrunning" / "config.json"
    print("[1/6] Checking configuration...")
    if not config_path.exists():
        issues.append("Config file not found: ~/.stillrunning/config.json")
        print("  [FAIL] Config file missing")
        print("  Fix: Run 'stillrunning --setup' to create config")
    else:
        print("  [OK] Config file exists")
        try:
            with open(config_path) as f:
                config = json.load(f)
            token = config.get("token", "")
            if not token:
                issues.append("No token in config file")
                print("  [FAIL] No token configured")
        except Exception as e:
            issues.append(f"Config file invalid: {e}")
            print(f"  [FAIL] Config parse error: {e}")

    # 2. Check agent process is running
    print("\n[2/6] Checking agent process...")
    try:
        result = subprocess.run(
            ["pgrep", "-f", "stillrunning"],
            capture_output=True, timeout=5
        )
        if result.returncode == 0:
            pids = result.stdout.decode().strip().split('\n')
            print(f"  [OK] Agent running (PID: {pids[0]})")
        else:
            warnings.append("Agent process not detected")
            print("  [WARN] Agent not running")
            print("  Fix: Run 'stillrunning' to start the agent")
    except Exception as e:
        warnings.append(f"Could not check process: {e}")
        print(f"  [WARN] Process check failed: {e}")

    # 3. Validate token with API
    print("\n[3/6] Validating token with server...")
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = json.load(f)
            token = config.get("token", "")
            if token:
                url = f"https://stillrunning.io/api/validate-token"
                req = urllib.request.Request(
                    url,
                    headers={"Authorization": f"Bearer {token}"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode())
                    if data.get("valid"):
                        print(f"  [OK] Token valid (tier: {data.get('tier', 'unknown')})")
                        if data.get("trial"):
                            expires = data.get("trial_expires", "soon")
                            warnings.append(f"Trial expires: {expires}")
                            print(f"  [WARN] Trial mode - expires {expires}")
                    else:
                        issues.append("Token invalid or expired")
                        print("  [FAIL] Token invalid")
                        print("  Fix: Check your token at stillrunning.io/dashboard")
        except urllib.error.HTTPError as e:
            issues.append(f"Token validation failed: HTTP {e.code}")
            print(f"  [FAIL] Server returned {e.code}")
        except Exception as e:
            warnings.append(f"Could not validate token: {e}")
            print(f"  [WARN] Validation failed: {e}")
    else:
        print("  [SKIP] No config to validate")

    # 4. Check Telegram connectivity
    print("\n[4/6] Testing Telegram alerts...")
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = json.load(f)
            tg_token = config.get("telegram_bot_token", "")
            tg_chat = config.get("telegram_chat_id", "")
            if tg_token and tg_chat:
                # Just check the bot is valid, don't send message
                url = f"https://api.telegram.org/bot{tg_token}/getMe"
                with urllib.request.urlopen(url, timeout=10) as resp:
                    data = json.loads(resp.read().decode())
                    if data.get("ok"):
                        print(f"  [OK] Telegram bot connected ({data['result']['username']})")
                    else:
                        issues.append("Telegram bot token invalid")
                        print("  [FAIL] Bot token invalid")
            else:
                warnings.append("Telegram not configured")
                print("  [WARN] Telegram not configured")
                print("  Fix: Run 'stillrunning --setup' to configure alerts")
        except Exception as e:
            warnings.append(f"Telegram check failed: {e}")
            print(f"  [WARN] Telegram check failed: {e}")
    else:
        print("  [SKIP] No config")

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
        print(f"  [WARN] Could not check disk: {e}")

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
    except Exception as e:
        # macOS or other OS
        print(f"  [SKIP] Memory check not available on this OS")

    # Summary
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

    # Return status
    if issues:
        print("Status: CRITICAL")
        return
    elif warnings:
        print("Status: WARNINGS")
        return
    else:
        print("Status: HEALTHY")
        return


# ---------------------------------------------------------------------------
# SESSION 91: Package Whitelist Commands
# ---------------------------------------------------------------------------
def _get_customer_token() -> str | None:
    """Get customer token from config file."""
    config_path = Path.home() / ".stillrunning" / "config.json"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = json.load(f)
            return config.get("token", "")
        except Exception:
            pass
    return None


def _whitelist_add(package: str) -> None:
    """Add package to customer whitelist."""
    token = _get_customer_token()
    if not token:
        print("Error: No token configured. Run 'stillrunning --setup' first.")
        return

    try:
        url = "https://stillrunning.io/api/whitelist/add"
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
        url = "https://stillrunning.io/api/whitelist/remove"
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
        url = f"https://stillrunning.io/api/whitelist/list"
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
# SESSION 97: Claude Code PreToolUse Hook
# ---------------------------------------------------------------------------
def _run_claude_code_hook() -> None:
    """Run as Claude Code PreToolUse hook. Reads stdin, checks packages, exits 0/1."""
    import re
    try:
        stdin_data = sys.stdin.read()
        if not stdin_data.strip():
            sys.exit(0)

        data = json.loads(stdin_data)
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})

        # Only intercept Bash commands
        if tool_name != "Bash":
            sys.exit(0)

        command = tool_input.get("command", "")
        if not command:
            sys.exit(0)

        # Extract package names from pip/npm install commands
        packages = []

        # pip install patterns
        pip_match = re.search(r'pip3?\s+install\s+([^\s|&;]+(?:\s+[^\s|&;-][^\s|&;]*)*)', command)
        if pip_match:
            pkg_str = pip_match.group(1)
            for pkg in pkg_str.split():
                if pkg.startswith('-'):
                    continue
                pkg_name = re.split(r'[=<>!\[]', pkg)[0]
                if pkg_name:
                    packages.append(("pip", pkg_name.lower()))

        # npm install patterns
        npm_match = re.search(r'npm\s+(?:install|i|add)\s+([^\s|&;]+(?:\s+[^\s|&;-][^\s|&;]*)*)', command)
        if npm_match:
            pkg_str = npm_match.group(1)
            for pkg in pkg_str.split():
                if pkg.startswith('-'):
                    continue
                pkg_name = re.split(r'[@]', pkg)[0] if not pkg.startswith('@') else pkg.split('@')[0] + '@' + pkg.split('@')[1].split('/')[0] if '@' in pkg and '/' in pkg else pkg
                if pkg_name:
                    packages.append(("npm", pkg_name.lower()))

        if not packages:
            sys.exit(0)

        # Check each package against stillrunning.io
        token = _get_customer_token()
        for pkg_type, pkg_name in packages:
            try:
                url = f"https://stillrunning.io/api/check-package?name={pkg_name}"
                headers = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    result = json.loads(resp.read().decode())

                status = result.get("status", "UNKNOWN")
                if status == "DANGEROUS":
                    reason = result.get("reason", "Malicious package detected")
                    sys.stderr.write(f"BLOCKED: {pkg_name} is DANGEROUS — {reason}\n")
                    sys.stderr.write(f"See: https://stillrunning.io/threats\n")
                    sys.exit(1)
                elif status == "SUSPICIOUS":
                    reason = result.get("reason", "Package flagged as suspicious")
                    sys.stderr.write(f"WARNING: {pkg_name} is SUSPICIOUS — {reason}\n")
                    sys.stderr.write(f"To proceed anyway, add to allow list:\n")
                    sys.stderr.write(f"  stillrunning whitelist add {pkg_name}\n")
                    sys.exit(1)

            except urllib.error.HTTPError as e:
                if e.code == 429:
                    sys.stderr.write("LIMIT: Daily scan limit reached.\n")
                    sys.stderr.write("Upgrade at https://stillrunning.io/pricing\n")
                    sys.exit(1)
            except Exception:
                pass

        sys.exit(0)

    except json.JSONDecodeError:
        sys.exit(0)
    except Exception:
        sys.exit(0)


def _install_claude_code_hook() -> None:
    """Install Claude Code PreToolUse hook to ~/.claude/hooks.json."""
    hooks_dir = Path.home() / ".claude"
    hooks_file = hooks_dir / "hooks.json"

    hooks_dir.mkdir(parents=True, exist_ok=True)

    existing_hooks = {"hooks": []}
    if hooks_file.exists():
        try:
            with open(hooks_file) as f:
                existing_hooks = json.load(f)
        except Exception:
            pass

    hooks_list = existing_hooks.get("hooks", [])
    sr_hook = {
        "matcher": {
            "tool_name": "Bash",
            "command_pattern": "(pip3?|npm)\\s+(install|i|add)"
        },
        "hooks": [{
            "type": "preToolUse",
            "command": "stillrunning hook"
        }]
    }

    # Remove any existing stillrunning hook
    hooks_list = [h for h in hooks_list if "stillrunning" not in str(h.get("hooks", []))]
    hooks_list.append(sr_hook)

    existing_hooks["hooks"] = hooks_list

    tmp_file = hooks_file.with_suffix(".tmp")
    with open(tmp_file, "w") as f:
        json.dump(existing_hooks, f, indent=2)
    tmp_file.replace(hooks_file)

    print("Claude Code hook installed!")
    print(f"  File: {hooks_file}")
    print("\nAll pip/npm install commands will now be checked.")
    print("DANGEROUS packages will be blocked. SUSPICIOUS packages will warn.")


def _uninstall_claude_code_hook() -> None:
    """Remove Claude Code PreToolUse hook."""
    hooks_file = Path.home() / ".claude" / "hooks.json"

    if not hooks_file.exists():
        print("No hooks.json found.")
        return

    try:
        with open(hooks_file) as f:
            existing_hooks = json.load(f)
    except Exception:
        print("Could not read hooks.json")
        return

    hooks_list = existing_hooks.get("hooks", [])
    original_len = len(hooks_list)
    hooks_list = [h for h in hooks_list if "stillrunning" not in str(h.get("hooks", []))]

    if len(hooks_list) == original_len:
        print("No stillrunning hook found to remove.")
        return

    existing_hooks["hooks"] = hooks_list

    tmp_file = hooks_file.with_suffix(".tmp")
    with open(tmp_file, "w") as f:
        json.dump(existing_hooks, f, indent=2)
    tmp_file.replace(hooks_file)

    print("Claude Code hook removed.")


def main_cli() -> None:
    """Entry point for the stillrunning command."""
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

    # SESSION 97: Handle Claude Code hook install/uninstall
    if args.hook_claude_code:
        _install_claude_code_hook()
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
        from . import hook
        hook.allow_package(args.allow)
        print(f"Package '{args.allow}' is now allowed.")
        return
    elif args.block:
        from . import hook
        hook.block_package(args.block, "Manually blocked via CLI")
        print(f"Package '{args.block}' is now blocked.")
        return

    if args.doctor:
        run_doctor()
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
    elif args.setup or args.autonomous:
        run_setup_wizard(autonomous=args.autonomous)
    else:
        main()


if __name__ == "__main__":
    main_cli()
