"""Anonymous telemetry heartbeat for stillrunning agent.

Sends a minimal heartbeat to stillrunning.io every 6 hours if opt-in.
No email, IP, or log content — just a random UUID and basic stats.

Disable by setting telemetry: false in stillrunning.yaml.
"""

import json
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


def set_last_crash(ts: float) -> None:
    """Called by cli.py when a monitored process crashes."""
    global _last_crash_ts
    _last_crash_ts = ts


def _get_machine_id(config: dict) -> str:
    """Get or generate the machine_id from config."""
    return config.get("machine_id", "")


def _send_heartbeat(config: dict, version: str) -> bool:
    """Send a single heartbeat. Returns True on success."""
    machine_id = _get_machine_id(config)
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
