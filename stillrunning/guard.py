#!/usr/bin/env python3
"""
stillrunning_guard.py - Always-on security daemon.
Monitors processes, detects suspicious behavior, blocks threats.

Start: screen -dmS guard python3 ~/my-app/stillrunning_guard.py
"""

import os
import platform
import sys
import time
import json
import signal
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# ─── Constants ───────────────────────────────────────────────────────────────

BOT_DIR = Path.home() / "my-app"
STATUS_FILE = BOT_DIR / "guard_status.json"
LEARNED_FILE = BOT_DIR / "guard_learned.json"
SCAN_SCRIPT = BOT_DIR / "stillrunning_scan.py"
ENV_FILE = BOT_DIR / ".env"

POLL_INTERVAL = 5        # seconds
STATUS_WRITE_INTERVAL = 30
SPAWN_WINDOW = 10        # seconds - watch new processes for this long
SELF_DESTRUCT_WINDOW = 60
AUTO_TRUST_THRESHOLD = 3  # flag 3x in 24h → auto-trust
AUTO_TRUST_WINDOW = 86400  # 24 hours

# ─── LAYER 1: Permanent System Whitelist ─────────────────────────────────────
# Never alert on these. Ever.
SYSTEM_WHITELIST = {
    # Linux kernel threads
    "kworker", "kthread", "migration", "rcu_sched", "rcu_bh",
    "watchdog", "cpuhp", "idle", "khugepaged", "kswapd",
    "ksoftirqd", "kdevtmpfs", "netns", "kauditd", "bioset",
    "writeback", "kblockd", "oom_reaper", "kcompactd", "crypto",
    # Standard system daemons
    "sshd", "cron", "crond", "systemd", "systemd-journald",
    "systemd-udevd", "systemd-resolved", "systemd-logind",
    "systemd-networkd", "systemd-timesyncd", "dbus-daemon",
    "bash", "sh", "dash", "sleep", "run-parts", "zsh",
    "nginx", "python3", "python", "python3.10", "python3.11", "python3.12",
    # DigitalOcean specific
    "droplet-agent", "do-agent", "metrics-agent",
    # Common tools
    "apt", "apt-get", "dpkg", "curl", "wget", "ssh",
    "rsync", "grep", "awk", "sed", "cat", "ls", "ps",
    "top", "htop", "tail", "head", "find", "which",
    "git", "node", "npm", "pip", "pip3", "screen", "tmux",
    "vi", "vim", "nano", "less", "more", "sort", "uniq",
    "wc", "cut", "tr", "xargs", "tee", "touch", "mkdir",
    "rm", "mv", "cp", "chmod", "chown", "ln", "df", "du",
    "free", "uptime", "who", "w", "id", "whoami", "hostname",
    "uname", "date", "env", "printenv", "echo", "printf",
    "test", "[", "true", "false", "yes", "timeout", "strace",
    "lsof", "netstat", "ss", "ip", "ifconfig", "ping", "traceroute",
    "dig", "nslookup", "host", "nc", "telnet", "openssl",
    "tar", "gzip", "gunzip", "zip", "unzip", "bzip2",
    "man", "info", "help", "type", "which", "whereis",
    "sudo", "su", "passwd", "useradd", "usermod", "groupadd",
    "service", "systemctl", "journalctl", "loginctl",
    "iptables", "ip6tables", "nft", "fail2ban-server",
    "crontab", "at", "atd", "anacron",
    # Databases and servers
    "postgres", "postgresql", "mysql", "mysqld", "redis-server", "redis-cli",
    "mongod", "mongo", "sqlite3", "memcached",
    # Web servers
    "apache2", "httpd", "caddy", "haproxy", "varnishd",
    # Docker/containers
    "docker", "dockerd", "containerd", "runc", "docker-proxy",
    # Claude Code / development
    "claude", "code", "node", "npm", "yarn", "pnpm",
}

# Private IP ranges (don't flag outbound to these)
PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                       "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                       "172.30.", "172.31.", "192.168.", "127.", "0.", "::1", "fe80:")

# Sensitive paths to monitor
SENSITIVE_PATHS = {
    str(Path.home() / ".ssh"),
    str(Path.home() / ".aws" / "credentials"),
    str(BOT_DIR / ".env"),
    "/etc/passwd",
    "/etc/shadow",
}

# Package managers to intercept
PACKAGE_MANAGERS = {"npm", "pip", "pip3", "brew", "apt", "apt-get", "yarn", "pnpm"}

# Threat scores
SCORE_READS_PASSWD = 40
SCORE_OUTBOUND_CONNECTION = 30
SCORE_TOUCHES_SSH = 60
SCORE_READS_ENV = 50
SCORE_SELF_DESTRUCT = 80

SCORE_KILL_THRESHOLD = 80   # Raised — only kill on CRITICAL
SCORE_ALERT_THRESHOLD = 50  # Raised — Telegram only for DANGEROUS+

# ─── macOS-specific monitoring (SESSION 71) ─────────────────────────────────
IS_MACOS = platform.system() == "Darwin"

# macOS paths to watch for WAVESHAPER.V2-style attacks
MAC_KEYCHAIN_DIR = Path.home() / "Library" / "Keychains"
MAC_ACCOUNTD_FILE = Path.home() / ".com.apple.accountd"
MAC_LAUNCHAGENTS_DIR = Path.home() / "Library" / "LaunchAgents"
MAC_TCC_DIR = Path.home() / "Library" / "Application Support" / "com.apple.TCC"
MAC_AUTH_DB = Path("/var/db/auth.db")

# macOS threat scores
SCORE_MAC_KEYCHAIN_ACCESS = 70
SCORE_MAC_ACCOUNTD_ACCESS = 80  # WAVESHAPER.V2 signature
SCORE_MAC_LAUNCHAGENT_NEW = 100  # INSTANT CRITICAL — persistence
SCORE_MAC_TCC_ACCESS = 60

# Track mtimes for change detection
_mac_path_mtimes = {}
_mac_launchagent_files = set()

# Colors for logging
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ─── Globals ─────────────────────────────────────────────────────────────────

_known_pids = set()
_process_spawn_times = {}  # pid -> spawn_time
_process_files_modified = defaultdict(set)  # pid -> set of modified files
_alerts_today = 0
_threats_blocked = 0
_suppressed_today = 0
_last_alert = None
_started_at = None
_telegram_token = None
_telegram_chat_id = None
_learned_whitelist = {}  # process_name -> {"count": N, "first_seen": ts, "last_seen": ts, "trusted": bool}
_first_run = False


# ─── Logging ─────────────────────────────────────────────────────────────────

def log(level: str, msg: str):
    """Log with timestamp."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    color = {"INFO": GREEN, "WARN": YELLOW, "ERROR": RED, "CRITICAL": RED}.get(level, "")
    print(f"[{ts}] [{color}{level}{RESET}] {msg}", flush=True)


# ─── Telegram ────────────────────────────────────────────────────────────────

def load_telegram_credentials():
    """Load Telegram credentials from .env file."""
    global _telegram_token, _telegram_chat_id

    if not ENV_FILE.exists():
        log("WARN", "No .env file found - Telegram alerts disabled")
        return

    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("TELEGRAM_BOT_TOKEN="):
                    _telegram_token = line.split("=", 1)[1].strip().strip('"').strip("'")
                elif line.startswith("TELEGRAM_CHAT_ID="):
                    _telegram_chat_id = line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception as e:
        log("ERROR", f"Failed to load .env: {e}")


def send_telegram_alert(level: str, process_name: str, pid: int, command: str, trigger: str, score: int, action: str):
    """Send Telegram alert — cleaner format."""
    global _alerts_today, _last_alert

    if not _telegram_token or not _telegram_chat_id:
        log("WARN", "Telegram credentials not configured")
        return

    emoji = "\U0001F6A8" if level == "CRITICAL" else "\U0001F6A8" if level == "DANGEROUS" else "\U000026A0"

    # Cleaner format
    message = f"""{emoji} [guard] NEW THREAT — {process_name} PID {pid}
Reason: {trigger}
Score: {score} | Action: {action}"""

    try:
        import urllib.request
        import urllib.parse

        url = f"https://api.telegram.org/bot{_telegram_token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": _telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }).encode()

        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                log("INFO", f"Telegram alert sent: {level}")
                _alerts_today += 1
                _last_alert = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        log("ERROR", f"Telegram alert failed: {e}")


# ─── Whitelist Management ────────────────────────────────────────────────────

def load_learned_whitelist():
    """Load learned whitelist from disk."""
    global _learned_whitelist, _first_run

    if not LEARNED_FILE.exists():
        _first_run = True
        _learned_whitelist = {}
        return

    try:
        with open(LEARNED_FILE) as f:
            _learned_whitelist = json.load(f)
        log("INFO", f"Loaded {len(_learned_whitelist)} learned processes")
    except Exception as e:
        log("ERROR", f"Failed to load learned whitelist: {e}")
        _learned_whitelist = {}


def save_learned_whitelist():
    """Save learned whitelist to disk."""
    try:
        tmp = LEARNED_FILE.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(_learned_whitelist, f, indent=2)
        os.replace(tmp, LEARNED_FILE)
    except Exception as e:
        log("ERROR", f"Failed to save learned whitelist: {e}")


def is_system_whitelisted(name: str) -> bool:
    """Check if process name is in permanent system whitelist."""
    # Exact match
    if name in SYSTEM_WHITELIST:
        return True
    # Prefix match for kworker/0:1, migration/0, etc.
    base = name.split("/")[0].split(":")[0]
    return base in SYSTEM_WHITELIST


def is_learned_trusted(name: str) -> bool:
    """Check if process is auto-trusted via learning."""
    entry = _learned_whitelist.get(name, {})
    return entry.get("trusted", False)


def record_flagged_process(name: str, trigger: str):
    """Record a flagged process for auto-learning."""
    global _learned_whitelist

    now = time.time()

    if name not in _learned_whitelist:
        _learned_whitelist[name] = {
            "count": 1,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "trigger": trigger,
            "trusted": False
        }
    else:
        entry = _learned_whitelist[name]
        entry["count"] += 1
        entry["last_seen"] = datetime.now(timezone.utc).isoformat()

        # Auto-trust if flagged 3+ times within 24h
        first_seen_ts = datetime.fromisoformat(entry["first_seen"].replace("Z", "+00:00")).timestamp()
        if entry["count"] >= AUTO_TRUST_THRESHOLD and (now - first_seen_ts) < AUTO_TRUST_WINDOW:
            if not entry.get("trusted"):
                entry["trusted"] = True
                log("INFO", f"Auto-trusted: {name} (flagged {entry['count']}x)")

    save_learned_whitelist()


def onboard_existing_processes():
    """LAYER 3: Auto-trust long-running processes on first start."""
    global _learned_whitelist

    if not _first_run:
        return 0

    trusted_count = 0
    now = time.time()

    for pid in get_all_pids():
        info = get_process_info(pid)
        if not info:
            continue

        name = info["name"]

        # Skip if already in system whitelist
        if is_system_whitelisted(name):
            continue

        # Check process uptime via /proc/pid/stat
        try:
            with open(f"/proc/{pid}/stat") as f:
                stat = f.read().split()
            # Field 22 is starttime in clock ticks
            starttime_ticks = int(stat[21])
            # Get system boot time
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("btime"):
                        boot_time = int(line.split()[1])
                        break
            # Calculate process start time
            hz = os.sysconf("SC_CLK_TCK")
            start_time = boot_time + (starttime_ticks / hz)
            uptime_seconds = now - start_time

            # Trust if running > 5 minutes
            if uptime_seconds > 300:
                _learned_whitelist[name] = {
                    "count": 0,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "trigger": "auto-onboarded",
                    "trusted": True,
                    "uptime_at_trust": int(uptime_seconds)
                }
                trusted_count += 1
        except Exception:
            pass

    if trusted_count > 0:
        save_learned_whitelist()
        log("INFO", f"Onboarded {trusted_count} existing processes")

        # Send Telegram notification
        if _telegram_token and _telegram_chat_id:
            try:
                import urllib.request
                import urllib.parse

                msg = f"\u2705 [guard] Started. Auto-trusted {trusted_count} existing processes. Watching for new threats."
                url = f"https://api.telegram.org/bot{_telegram_token}/sendMessage"
                data = urllib.parse.urlencode({
                    "chat_id": _telegram_chat_id,
                    "text": msg
                }).encode()
                req = urllib.request.Request(url, data=data)
                urllib.request.urlopen(req, timeout=10)
            except Exception:
                pass

    return trusted_count


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private/local."""
    return any(ip_str.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


# ─── Process Utilities ───────────────────────────────────────────────────────

def get_all_pids():
    """Get all running PIDs from /proc."""
    pids = set()
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.add(int(entry))
    except Exception:
        pass
    return pids


def get_process_info(pid: int) -> dict | None:
    """Get process info from /proc."""
    try:
        # Get command line
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().decode("utf-8", errors="replace").replace("\x00", " ").strip()

        # Get process name
        with open(f"/proc/{pid}/comm") as f:
            name = f.read().strip()

        # Get parent PID
        ppid = None
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("PPid:"):
                    ppid = int(line.split(":")[1].strip())
                    break

        return {
            "pid": pid,
            "name": name,
            "cmdline": cmdline,
            "ppid": ppid
        }
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def get_process_fds(pid: int) -> list:
    """Get file descriptors opened by a process."""
    fds = []
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
                fds.append(target)
            except (OSError, PermissionError):
                pass
    except (FileNotFoundError, PermissionError):
        pass
    return fds


def get_process_connections(pid: int) -> list:
    """Check if process has network connections."""
    connections = []

    # Check /proc/pid/net/tcp and /proc/pid/net/tcp6
    for proto in ["tcp", "tcp6", "udp", "udp6"]:
        net_file = f"/proc/{pid}/net/{proto}"
        try:
            with open(net_file) as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        # Check if connection is ESTABLISHED or SYN_SENT (outbound)
                        state = parts[3]
                        if state in ("01", "02"):  # ESTABLISHED or SYN_SENT
                            connections.append(proto)
                            break
        except (FileNotFoundError, PermissionError):
            pass

    return connections


def kill_process(pid: int) -> bool:
    """Kill a process."""
    global _threats_blocked
    try:
        os.kill(pid, signal.SIGKILL)
        _threats_blocked += 1
        log("CRITICAL", f"Killed process {pid}")
        return True
    except (ProcessLookupError, PermissionError) as e:
        log("ERROR", f"Failed to kill process {pid}: {e}")
        return False


# ─── Threat Detection ────────────────────────────────────────────────────────

def analyze_process_threat(pid: int, info: dict) -> tuple[int, list, bool]:
    """Analyze a process for threats. Returns (score, reasons, is_whitelisted)."""
    global _suppressed_today

    name = info.get("name", "")

    # LAYER 1: Check permanent system whitelist
    if is_system_whitelisted(name):
        _suppressed_today += 1
        return 0, [], True

    # LAYER 2: Check auto-learned trusted
    is_trusted = is_learned_trusted(name)

    score = 0
    reasons = []

    fds = get_process_fds(pid)

    # Check file descriptors for sensitive file access
    for fd in fds:
        # Check .ssh access
        if "/.ssh" in fd:
            score += SCORE_TOUCHES_SSH
            reasons.append(f"Accessing ~/.ssh: {fd}")

        # Check .env access
        if ".env" in fd and "my-app" in fd:
            score += SCORE_READS_ENV
            reasons.append(f"Reading .env: {fd}")

        # Check /etc/passwd
        if fd == "/etc/passwd":
            score += SCORE_READS_PASSWD
            reasons.append("Reading /etc/passwd")

        # Check /etc/shadow
        if fd == "/etc/shadow":
            score += SCORE_READS_PASSWD + 20  # Extra penalty
            reasons.append("Reading /etc/shadow")

    # Check for network connections (for new processes)
    # Only flag if NOT trusted AND NOT private IP destination
    spawn_time = _process_spawn_times.get(pid)
    if spawn_time and time.time() - spawn_time < SPAWN_WINDOW and not is_trusted:
        connections = get_process_connections(pid)
        if connections:
            # TODO: would need to parse actual destination IP for more precision
            # For now, only flag non-trusted processes with connections
            score += SCORE_OUTBOUND_CONNECTION
            reasons.append(f"Outbound connection within {SPAWN_WINDOW}s of spawn")

    # NOTE: Removed "spawned by recently started process" — too noisy

    # If auto-trusted, halve the score
    if is_trusted and score > 0:
        score = score // 2
        reasons.append("(score halved — auto-trusted)")
        _suppressed_today += 1

    return score, reasons, is_trusted


def check_self_destruct(pid: int) -> bool:
    """Check if a process modified then deleted a file (self-destruction pattern)."""
    modified = _process_files_modified.get(pid, set())

    for path in list(modified):
        if not os.path.exists(path):
            log("CRITICAL", f"Self-destruction detected: {path} modified then deleted by PID {pid}")
            return True

    return False


# ─── macOS Keychain/LaunchAgent Monitor (SESSION 71) ────────────────────────

def _init_mac_watchers():
    """Initialize macOS path watchers — track initial mtimes."""
    global _mac_path_mtimes, _mac_launchagent_files

    if not IS_MACOS:
        return

    # Track mtimes for sensitive directories
    for path in [MAC_KEYCHAIN_DIR, MAC_ACCOUNTD_FILE, MAC_TCC_DIR]:
        if path.exists():
            try:
                _mac_path_mtimes[str(path)] = path.stat().st_mtime
            except Exception:
                pass

    # Track existing LaunchAgent files
    if MAC_LAUNCHAGENTS_DIR.exists():
        try:
            _mac_launchagent_files = set(f.name for f in MAC_LAUNCHAGENTS_DIR.iterdir())
        except Exception:
            pass

    log("INFO", f"macOS watchers initialized: {len(_mac_path_mtimes)} paths, {len(_mac_launchagent_files)} LaunchAgents")


def _get_lsof_process(path: str) -> str | None:
    """Use lsof to find what process has a file/dir open."""
    try:
        result = subprocess.run(
            ["lsof", "+D", path],
            capture_output=True,
            text=True,
            timeout=5
        )
        # Parse lsof output — second line onwards, first column is process name
        lines = result.stdout.strip().split("\n")[1:]
        if lines:
            return lines[0].split()[0]
    except Exception:
        pass
    return None


def check_mac_paths() -> list:
    """Check macOS-sensitive paths for unauthorized access. Returns list of (score, reason) tuples."""
    global _mac_path_mtimes, _mac_launchagent_files

    if not IS_MACOS:
        return []

    alerts = []

    # Check keychain directory
    if MAC_KEYCHAIN_DIR.exists():
        try:
            current_mtime = MAC_KEYCHAIN_DIR.stat().st_mtime
            if str(MAC_KEYCHAIN_DIR) in _mac_path_mtimes:
                if current_mtime > _mac_path_mtimes[str(MAC_KEYCHAIN_DIR)]:
                    proc = _get_lsof_process(str(MAC_KEYCHAIN_DIR))
                    if proc and not is_system_whitelisted(proc):
                        alerts.append((SCORE_MAC_KEYCHAIN_ACCESS, f"Keychain access by {proc}"))
            _mac_path_mtimes[str(MAC_KEYCHAIN_DIR)] = current_mtime
        except Exception:
            pass

    # Check .com.apple.accountd (WAVESHAPER.V2 signature)
    if MAC_ACCOUNTD_FILE.exists():
        try:
            current_mtime = MAC_ACCOUNTD_FILE.stat().st_mtime
            if str(MAC_ACCOUNTD_FILE) in _mac_path_mtimes:
                if current_mtime > _mac_path_mtimes[str(MAC_ACCOUNTD_FILE)]:
                    proc = _get_lsof_process(str(MAC_ACCOUNTD_FILE))
                    if proc and not is_system_whitelisted(proc):
                        alerts.append((SCORE_MAC_ACCOUNTD_ACCESS, f"WAVESHAPER signature: .accountd access by {proc}"))
            _mac_path_mtimes[str(MAC_ACCOUNTD_FILE)] = current_mtime
        except Exception:
            pass

    # Check TCC database
    if MAC_TCC_DIR.exists():
        try:
            current_mtime = MAC_TCC_DIR.stat().st_mtime
            if str(MAC_TCC_DIR) in _mac_path_mtimes:
                if current_mtime > _mac_path_mtimes[str(MAC_TCC_DIR)]:
                    proc = _get_lsof_process(str(MAC_TCC_DIR))
                    if proc and not is_system_whitelisted(proc):
                        alerts.append((SCORE_MAC_TCC_ACCESS, f"TCC database access by {proc}"))
            _mac_path_mtimes[str(MAC_TCC_DIR)] = current_mtime
        except Exception:
            pass

    # Check for NEW LaunchAgent files (persistence mechanism)
    if MAC_LAUNCHAGENTS_DIR.exists():
        try:
            current_files = set(f.name for f in MAC_LAUNCHAGENTS_DIR.iterdir())
            new_files = current_files - _mac_launchagent_files
            for new_file in new_files:
                # New LaunchAgent = INSTANT CRITICAL
                alerts.append((SCORE_MAC_LAUNCHAGENT_NEW, f"New LaunchAgent detected: {new_file}"))
                log("CRITICAL", f"New LaunchAgent file: {new_file}")
            _mac_launchagent_files = current_files
        except Exception:
            pass

    return alerts


# ─── Install Interceptor ─────────────────────────────────────────────────────

def scan_install_cache(manager: str, cmdline: str):
    """Scan package install cache for malicious files."""
    log("INFO", f"Install interceptor: {manager} detected")

    # Common cache directories
    cache_dirs = []

    if manager in ("pip", "pip3"):
        cache_dirs = [
            Path.home() / ".cache" / "pip",
            Path("/tmp") / "pip-*"
        ]
    elif manager == "npm":
        cache_dirs = [
            Path.home() / ".npm",
            Path("node_modules")
        ]

    # Find .py files in cache and scan
    for cache_dir in cache_dirs:
        if not cache_dir.exists():
            continue

        try:
            for py_file in cache_dir.rglob("*.py"):
                if not py_file.is_file():
                    continue

                # Run scanner
                result = subprocess.run(
                    ["python3", str(SCAN_SCRIPT), str(py_file)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                # Check exit code
                if result.returncode == 2:  # DANGEROUS
                    send_telegram_alert(
                        "DANGEROUS",
                        manager,
                        0,
                        cmdline,
                        f"Malicious package detected: {py_file.name}",
                        60,
                        "FLAGGED"
                    )
                elif result.returncode == 1:  # REVIEW
                    send_telegram_alert(
                        "REVIEW",
                        manager,
                        0,
                        cmdline,
                        f"Suspicious package: {py_file.name}",
                        30,
                        "FLAGGED"
                    )
        except Exception as e:
            log("ERROR", f"Install scan failed: {e}")


# ─── Main Loop ───────────────────────────────────────────────────────────────

def write_status():
    """Write guard_status.json."""
    uptime = int(time.time() - _started_at) if _started_at else 0

    # Calculate whitelist size
    whitelist_size = len(SYSTEM_WHITELIST) + len(_learned_whitelist)

    status = {
        "running": True,
        "uptime_seconds": uptime,
        "processes_watched": len(_known_pids),
        "alerts_today": _alerts_today,
        "alerts_sent_today": _alerts_today,
        "suppressed_today": _suppressed_today,
        "whitelist_size": whitelist_size,
        "system_whitelist": len(SYSTEM_WHITELIST),
        "learned_whitelist": len(_learned_whitelist),
        "last_alert": _last_alert,
        "threats_blocked": _threats_blocked,
        "started_at": datetime.fromtimestamp(_started_at, tz=timezone.utc).isoformat() if _started_at else None
    }

    try:
        tmp = STATUS_FILE.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(status, f, indent=2)
        os.replace(tmp, STATUS_FILE)
    except Exception as e:
        log("ERROR", f"Failed to write status: {e}")


def main_loop():
    """Main daemon loop."""
    global _known_pids, _started_at

    _started_at = time.time()
    last_status_write = 0

    log("INFO", "Guard daemon starting...")
    load_telegram_credentials()
    load_learned_whitelist()

    # Feature gating check (SESSION 88)
    try:
        from .cli import SUBSCRIPTION_FEATURES
        features = SUBSCRIPTION_FEATURES
    except ImportError:
        features = ["process_monitor", "restart", "alerts"]

    # Log available premium features
    if "tripwire" in features:
        log("INFO", "Tripwire file monitoring: ENABLED")
    else:
        log("INFO", "Tripwire file monitoring: DISABLED (requires Basic tier)")
    if "file_integrity" in features:
        log("INFO", "File integrity monitoring: ENABLED")
    else:
        log("INFO", "File integrity monitoring: DISABLED (requires Basic tier)")
    if "honeypot" in features:
        log("INFO", "Honeypot credentials: ENABLED")
    else:
        log("INFO", "Honeypot credentials: DISABLED (requires Basic tier)")

    # Initial process snapshot
    _known_pids = get_all_pids()
    log("INFO", f"Initial snapshot: {len(_known_pids)} processes")

    # LAYER 3: Auto-trust existing processes on first run
    onboarded = onboard_existing_processes()
    if onboarded > 0:
        log("INFO", f"Onboarded {onboarded} existing processes as trusted")

    log("INFO", f"Whitelist size: {len(SYSTEM_WHITELIST)} system + {len(_learned_whitelist)} learned")

    # Initialize macOS watchers (SESSION 71)
    if IS_MACOS:
        _init_mac_watchers()

    while True:
        try:
            now = time.time()
            current_pids = get_all_pids()

            # Find new processes
            new_pids = current_pids - _known_pids

            for pid in new_pids:
                info = get_process_info(pid)
                if not info:
                    continue

                # Skip logging for system whitelisted processes
                if not is_system_whitelisted(info["name"]):
                    # Record spawn time
                    _process_spawn_times[pid] = now
                    log("INFO", f"New process: {info['name']} (PID {pid})")

                # Check for package managers
                if info["name"] in PACKAGE_MANAGERS:
                    scan_install_cache(info["name"], info["cmdline"])

            # Analyze all known processes
            for pid in list(_known_pids):
                if pid not in current_pids:
                    # Process exited - clean up
                    _process_spawn_times.pop(pid, None)
                    _process_files_modified.pop(pid, None)
                    continue

                info = get_process_info(pid)
                if not info:
                    continue

                # Check for threats (returns is_whitelisted flag)
                score, reasons, is_whitelisted = analyze_process_threat(pid, info)

                # Skip completely if whitelisted with zero score
                if is_whitelisted and score == 0:
                    continue

                # Check for self-destruction
                if check_self_destruct(pid):
                    score += SCORE_SELF_DESTRUCT
                    reasons.append("Self-destruction pattern detected")

                # Take action based on score
                # CRITICAL (80+): Telegram + kill
                if score >= SCORE_KILL_THRESHOLD:
                    action = "KILLED" if kill_process(pid) else "KILL_FAILED"
                    send_telegram_alert(
                        "CRITICAL",
                        info["name"],
                        pid,
                        info["cmdline"],
                        "; ".join(r for r in reasons if "halved" not in r),
                        score,
                        action
                    )
                # DANGEROUS (50-79): Telegram alert
                elif score >= SCORE_ALERT_THRESHOLD:
                    # Record for auto-learning
                    record_flagged_process(info["name"], "; ".join(reasons))

                    # Only send Telegram for non-trusted or high scores
                    if not is_learned_trusted(info["name"]):
                        send_telegram_alert(
                            "DANGEROUS",
                            info["name"],
                            pid,
                            info["cmdline"],
                            "; ".join(r for r in reasons if "halved" not in r),
                            score,
                            "FLAGGED"
                        )
                    else:
                        log("INFO", f"Suppressed alert for trusted process: {info['name']} (score {score})")
                # REVIEW (20-49): Log only, no Telegram
                elif score >= 20:
                    record_flagged_process(info["name"], "; ".join(reasons))
                    log("INFO", f"REVIEW: {info['name']} PID {pid} score={score} — {'; '.join(reasons)}")

            # Update known pids
            _known_pids = current_pids

            # Clean up old spawn times
            cutoff = now - SELF_DESTRUCT_WINDOW
            for pid in list(_process_spawn_times.keys()):
                if _process_spawn_times[pid] < cutoff:
                    del _process_spawn_times[pid]

            # macOS-specific path monitoring (SESSION 71)
            if IS_MACOS:
                mac_alerts = check_mac_paths()
                for mac_score, mac_reason in mac_alerts:
                    if mac_score >= SCORE_KILL_THRESHOLD:
                        send_telegram_alert(
                            "CRITICAL",
                            "macOS",
                            0,
                            "system",
                            mac_reason,
                            mac_score,
                            "DETECTED"
                        )
                    elif mac_score >= SCORE_ALERT_THRESHOLD:
                        send_telegram_alert(
                            "DANGEROUS",
                            "macOS",
                            0,
                            "system",
                            mac_reason,
                            mac_score,
                            "DETECTED"
                        )

            # Write status periodically
            if now - last_status_write >= STATUS_WRITE_INTERVAL:
                write_status()
                last_status_write = now

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            log("INFO", "Guard daemon shutting down...")
            break
        except Exception as e:
            log("ERROR", f"Main loop error: {e}")
            time.sleep(POLL_INTERVAL)


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main_loop()
