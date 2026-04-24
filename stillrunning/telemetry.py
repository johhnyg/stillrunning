"""
Lightweight anonymous telemetry for stillrunning.

Fires a non-blocking heartbeat on every command (scan, hook, setup, etc).
Only sends: command name, version, os, uuid, timestamp. No user data.

Disable with STILLRUNNING_NO_TELEMETRY=1 or --no-telemetry flag.
"""

import hashlib
import json
import os
import sys
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

HEARTBEAT_URL = "https://stillrunning.io/api/heartbeat/anonymous"
MACHINE_ID_FILE = Path.home() / ".stillrunning" / "machine_id"
_heartbeat_sent_this_session = False


def _is_telemetry_disabled() -> bool:
    """Check if telemetry is disabled via env var."""
    val = os.environ.get("STILLRUNNING_NO_TELEMETRY", "").lower()
    return val in ("1", "true", "yes")


def _get_or_create_machine_id() -> str:
    """Get existing machine_id or create a new one. Lazy initialization."""
    try:
        if MACHINE_ID_FILE.exists():
            return MACHINE_ID_FILE.read_text().strip()
    except Exception:
        pass

    # Generate new UUID-based machine_id
    import uuid
    machine_id = f"sr_{uuid.uuid4().hex[:24]}"

    try:
        MACHINE_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
        MACHINE_ID_FILE.write_text(machine_id)
        os.chmod(MACHINE_ID_FILE, 0o600)
    except Exception:
        pass  # Use ephemeral ID if can't persist

    return machine_id


def _hash_machine_id(machine_id: str) -> str:
    """Privacy-preserving hash of machine_id."""
    return hashlib.sha256(f"sr:{machine_id}".encode()).hexdigest()[:16]


def _send_heartbeat_sync(command: str, version: str) -> bool:
    """Blocking heartbeat send. Returns True on success."""
    if _is_telemetry_disabled():
        return False

    machine_id = _get_or_create_machine_id()
    if not machine_id:
        return False

    payload = {
        "machine_id": _hash_machine_id(machine_id),
        "agent_version": version,
        "os_type": sys.platform,
        "command": command,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "command",
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            HEARTBEAT_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def send_heartbeat_async(command: str, version: str) -> None:
    """
    Non-blocking heartbeat. Fires in background thread, never blocks caller.
    Safe to call from any command — silently no-ops if disabled or fails.
    """
    if _is_telemetry_disabled():
        return

    def _worker():
        try:
            _send_heartbeat_sync(command, version)
        except Exception:
            pass

    t = threading.Thread(target=_worker, daemon=True, name="telemetry")
    t.start()


def send_heartbeat_once_per_session(command: str, version: str) -> None:
    """
    Send heartbeat only once per shell session (for import hook).
    Uses module-level flag to avoid spam on repeated imports.
    """
    global _heartbeat_sent_this_session
    if _heartbeat_sent_this_session:
        return
    _heartbeat_sent_this_session = True
    send_heartbeat_async(command, version)
