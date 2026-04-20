"""Anonymous telemetry heartbeat for stillrunning agent.

Sends a minimal heartbeat to stillrunning.io every 6 hours if opt-in.
No email, IP, or log content — just a random UUID and basic stats.

Disable by setting telemetry: false in stillrunning.yaml.

Event types:
- install: First run (one-time)
- active: Running agent (every 6h)
- intercept: Package was intercepted (per-event)

Dev/CI exclusion: Set STILLRUNNING_DEV=1 to flag as internal usage.
"""

import hashlib
import json
import os
import sys
import time
import threading
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

HEARTBEAT_URL = "https://stillrunning.io/api/heartbeat/anonymous"
HEARTBEAT_INTERVAL_SEC = 6 * 60 * 60  # 6 hours

_start_time = time.time()
_last_crash_ts = None
_install_sent = False


def set_last_crash(ts: float) -> None:
    """Called by cli.py when a monitored process crashes."""
    global _last_crash_ts
    _last_crash_ts = ts


def is_dev_mode() -> bool:
    """Check if running in dev/CI mode (excluded from user counts)."""
    return os.environ.get("STILLRUNNING_DEV", "").lower() in ("1", "true", "yes")


def _get_hashed_machine_id(config: dict) -> str:
    """Get privacy-preserving hashed machine ID."""
    raw_id = config.get("machine_id", "")
    if not raw_id:
        return ""
    return hashlib.sha256(f"sr:{raw_id}".encode()).hexdigest()[:16]


def _send_heartbeat(config: dict, version: str, event_type: str = "active") -> bool:
    """Send a single heartbeat. Returns True on success."""
    machine_id = _get_hashed_machine_id(config)
    if not machine_id:
        return False

    uptime_hours = round((time.time() - _start_time) / 3600, 1)
    process_count = len(config.get("processes", []))

    payload = {
        "machine_id": machine_id,
        "agent_version": version,
        "os_type": sys.platform,
        "uptime_hours": uptime_hours,
        "process_count": process_count,
        "last_crash_ts": _last_crash_ts,
        "event_type": event_type,
        "is_dev": is_dev_mode(),
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            HEARTBEAT_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def send_install_event(config: dict, version: str) -> bool:
    """Send one-time install event (called on first run)."""
    global _install_sent
    if _install_sent:
        return False
    _install_sent = True
    return _send_heartbeat(config, version, event_type="install")


def send_intercept_event(config: dict, version: str, package: str, result: str) -> bool:
    """Send intercept event when a package is blocked/warned."""
    machine_id = _get_hashed_machine_id(config)
    if not machine_id:
        return False

    payload = {
        "machine_id": machine_id,
        "agent_version": version,
        "os_type": sys.platform,
        "event_type": "intercept",
        "is_dev": is_dev_mode(),
        "package": package,
        "result": result,
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            HEARTBEAT_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def heartbeat_loop(config: dict, version: str) -> None:
    """
    Background thread that sends heartbeats every 6 hours.
    First heartbeat fires 30 seconds after start.
    """
    time.sleep(30)  # Initial delay

    while True:
        try:
            _send_heartbeat(config, version)
        except Exception:
            pass
        time.sleep(HEARTBEAT_INTERVAL_SEC)


def start_heartbeat_thread(config: dict, version: str) -> threading.Thread:
    """Start the heartbeat background thread. Returns the thread object."""
    t = threading.Thread(
        target=heartbeat_loop,
        args=(config, version),
        daemon=True,
        name="telemetry-heartbeat",
    )
    t.start()
    return t
