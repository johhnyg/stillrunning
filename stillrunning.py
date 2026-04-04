#!/usr/bin/env python3
"""
StillRunning v1.1 — Lightweight process monitor with Telegram alerts.

Usage:
    Quick start:  python3 stillrunning.py --setup
    Manual:       Edit stillrunning.yaml, then run: screen -dmS stillrunning python3 stillrunning.py
    Commands:     Text "status" or "help" to your Telegram bot

Requires: PyYAML (pip install pyyaml)
"""

import gzip
import json
import os
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
    try:
        with open(get_state_file(), "w") as f:
            json.dump({
                "restart_cooldowns": _state["restart_cooldowns"],
                "consecutive_failures": _state["consecutive_failures"],
                "disabled_processes": list(_state["disabled_processes"]),
            }, f, indent=2)
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
            send_telegram(f"Daily heartbeat\n\n{summary}")
        except Exception as exc:
            print(f"[stillrunning] Heartbeat error: {exc}", flush=True)
        time.sleep(interval)


def telegram_command_loop() -> None:
    """Listen for Telegram commands (status, help)."""
    interval = CONFIG["intervals"]["telegram_poll_sec"]
    last_update_id = 0
    chat_id = get_telegram_chat_id()

    if not chat_id:
        return  # No chat ID configured, exit thread

    while True:
        try:
            updates = get_telegram_updates(offset=last_update_id + 1)
            for update in updates:
                last_update_id = update.get("update_id", last_update_id)
                message = update.get("message", {})
                msg_chat_id = str(message.get("chat", {}).get("id", ""))
                text = message.get("text", "").strip().lower()

                # Only respond to configured chat
                if msg_chat_id != chat_id:
                    continue

                if text == "status":
                    summary = get_status_summary()
                    send_telegram(summary)
                elif text == "help":
                    send_telegram(
                        "Commands:\n"
                        "  status — live process & resource status\n"
                        "  help — show this message"
                    )
                elif text == "enable all":
                    # Re-enable all disabled processes
                    if _state["disabled_processes"]:
                        names = list(_state["disabled_processes"])
                        _state["disabled_processes"].clear()
                        for name in names:
                            _state["consecutive_failures"][name] = 0
                        save_state()
                        send_telegram(f"Re-enabled: {', '.join(names)}")
                    else:
                        send_telegram("No disabled processes")

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


def run_setup_wizard() -> None:
    """Interactive setup wizard."""
    print("\n" + "=" * 60)
    print("  StillRunning Setup Wizard")
    print("=" * 60 + "\n")

    # Determine working directory
    cwd = Path.cwd()
    print(f"Working directory: {cwd}\n")

    # --- Scan for processes ---
    print("Scanning for running processes...\n")

    screen_sessions = scan_screen_sessions()
    systemd_services = scan_systemd_services()

    all_processes = []

    if screen_sessions:
        print(f"Found {len(screen_sessions)} screen session(s):")
        for i, s in enumerate(screen_sessions, 1):
            print(f"  [{i}] {s['name']} (script: {s['script']})")
            all_processes.append(s)
        print()

    if systemd_services:
        print(f"Found {len(systemd_services)} systemd service(s):")
        offset = len(screen_sessions)
        for i, s in enumerate(systemd_services, 1):
            print(f"  [{offset + i}] {s['name']} (systemd)")
            all_processes.append(s)
        print()

    if not all_processes:
        print("No screen sessions or systemd services found.")
        print("You can add processes manually to stillrunning.yaml later.\n")

    # Select processes to monitor
    selected_processes = []
    if all_processes:
        print("Which processes should StillRunning monitor?")
        print("Enter numbers separated by commas, or 'all' for all, or 'none' to skip")
        choice = input("> ").strip().lower()

        if choice == "all":
            selected_processes = all_processes
        elif choice != "none" and choice:
            try:
                indices = [int(x.strip()) - 1 for x in choice.split(",")]
                selected_processes = [all_processes[i] for i in indices if 0 <= i < len(all_processes)]
            except (ValueError, IndexError):
                print("Invalid selection, skipping processes.")
        print()

    # --- Scan for log files ---
    print("Scanning for log files...\n")
    log_files = scan_log_files(cwd)

    selected_logs = []
    if log_files:
        print(f"Found {len(log_files)} log file(s):")
        for i, lf in enumerate(log_files, 1):
            print(f"  [{i}] {lf['path']} ({lf['current_size_mb']} MB)")
        print()
        print("Which logs should StillRunning auto-rotate?")
        print("Enter numbers separated by commas, or 'all' for all, or 'none' to skip")
        choice = input("> ").strip().lower()

        if choice == "all":
            selected_logs = log_files
        elif choice != "none" and choice:
            try:
                indices = [int(x.strip()) - 1 for x in choice.split(",")]
                selected_logs = [log_files[i] for i in indices if 0 <= i < len(log_files)]
            except (ValueError, IndexError):
                print("Invalid selection, skipping logs.")
        print()

    # --- Detect health file ---
    health_file = detect_health_file(cwd)
    if health_file:
        print(f"Detected health file: {health_file}")
        print("Monitor this file for freshness? [Y/n]")
        if input("> ").strip().lower() != "n":
            pass  # Keep it
        else:
            health_file = None
        print()

    # --- Ask 3 questions ---
    print("-" * 40)
    print("Configuration Questions (3 total)")
    print("-" * 40 + "\n")

    # 1. App name
    default_app_name = cwd.name.replace("-", " ").replace("_", " ").title()
    print(f"1. App name (appears in alerts) [{default_app_name}]:")
    app_name = input("> ").strip() or default_app_name
    print()

    # 2. Telegram bot token
    print("2. Telegram bot token (from @BotFather):")
    print("   Create a bot: https://t.me/BotFather -> /newbot")
    telegram_token = input("> ").strip()
    print()

    # 3. Telegram chat ID
    print("3. Telegram chat ID (your user ID):")
    print("   Get yours: https://t.me/userinfobot -> /start")
    telegram_chat_id = input("> ").strip()
    print()

    # --- Test Telegram ---
    if telegram_token and telegram_chat_id:
        print("Testing Telegram credentials...")
        if test_telegram_credentials(telegram_token, telegram_chat_id):
            print("Telegram test passed! Check your Telegram for the test message.\n")
        else:
            print("WARNING: Telegram test failed. Check your token and chat ID.\n")

    # --- Generate config ---
    print("Generating stillrunning.yaml...\n")

    config = {
        "app_name": app_name,
        "working_dir": str(cwd),
        "telegram_bot_token": telegram_token,
        "telegram_chat_id": telegram_chat_id,
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

    # Add selected processes (screen only for now)
    for proc in selected_processes:
        if proc["type"] == "screen":
            config["processes"].append({
                "name": proc["name"],
                "screen": proc["screen"],
                "script": proc["script"],
            })

    # Add selected logs
    for lf in selected_logs:
        config["log_files"].append({
            "path": lf["path"],
            "max_mb": lf["max_mb"],
            "keep_archives": lf["keep_archives"],
        })

    # Add health file
    if health_file:
        config["health_file"] = health_file
        config["health_max_age_sec"] = 180

    # Write config
    config_path = Path(__file__).parent / "stillrunning.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"Config saved to: {config_path}")
    print()

    # --- Summary ---
    print("=" * 60)
    print("  Setup Complete!")
    print("=" * 60)
    print(f"\n  App name:    {app_name}")
    print(f"  Processes:   {len(config['processes'])}")
    print(f"  Log files:   {len(config['log_files'])}")
    print(f"  Health file: {health_file or 'none'}")
    print(f"  Telegram:    {'configured' if telegram_token else 'not configured'}")
    print()

    # --- Start monitoring ---
    print("Start monitoring now? [Y/n]")
    if input("> ").strip().lower() != "n":
        print("\nStarting StillRunning...\n")
        main()
    else:
        print("\nTo start later, run:")
        print(f"  screen -dmS stillrunning python3 {__file__}")
        print()


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
    ]

    for t in threads:
        t.start()

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
    args = parser.parse_args()

    if args.setup:
        run_setup_wizard()
    else:
        main()


if __name__ == "__main__":
    main_cli()
