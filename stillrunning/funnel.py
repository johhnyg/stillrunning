"""Setup funnel telemetry for stillrunning.

Tracks anonymous, aggregate conversion data through the setup wizard.
This is OPT-OUT (enabled by default for anonymous aggregate stats).
Set STILLRUNNING_NO_FUNNEL=1 to disable, or set STILLRUNNING_DEV=1.

No personal data is collected. Only: hashed machine ID, step name,
timestamp, and agent version.
"""

import hashlib
import json
import os
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

__version__ = "2.2.0"

FUNNEL_URL = "https://stillrunning.io/api/setup-funnel"
_funnel_enabled = True
_machine_id_hash = None


def _get_machine_id_hash() -> str:
    """Generate a privacy-preserving machine ID hash."""
    global _machine_id_hash
    if _machine_id_hash:
        return _machine_id_hash

    # Use a combination of hostname + username for uniqueness
    # Hash it so we can't reverse-engineer the actual values
    import socket
    import getpass
    try:
        raw = f"{socket.gethostname()}:{getpass.getuser()}:{os.getpid()}"
    except Exception:
        raw = f"unknown:{time.time()}"

    _machine_id_hash = hashlib.sha256(f"funnel:{raw}".encode()).hexdigest()[:16]
    return _machine_id_hash


def is_funnel_enabled() -> bool:
    """Check if funnel telemetry is enabled."""
    # Disabled if STILLRUNNING_DEV=1 (internal usage)
    if os.environ.get("STILLRUNNING_DEV", "").lower() in ("1", "true", "yes"):
        return False
    # Disabled if STILLRUNNING_NO_FUNNEL=1 (explicit opt-out)
    if os.environ.get("STILLRUNNING_NO_FUNNEL", "").lower() in ("1", "true", "yes"):
        return False
    return _funnel_enabled


def disable_funnel():
    """Disable funnel telemetry for this session."""
    global _funnel_enabled
    _funnel_enabled = False


def track_step(step: str, extra: dict = None) -> bool:
    """
    Track a setup wizard step. Fire-and-forget (async).

    Steps:
        setup_started
        api_connection_success / api_connection_failed
        processes_scanned
        logs_scanned
        app_name_entered
        email_entered / email_skipped
        telegram_configured / telegram_skipped
        telegram_test_success / telegram_test_failed
        telemetry_opted_in / telemetry_opted_out
        config_saved
        setup_completed
        monitoring_started / monitoring_skipped

    Returns True if event was queued, False if disabled.
    """
    if not is_funnel_enabled():
        return False

    # Fire in background thread to avoid blocking
    t = threading.Thread(
        target=_send_event,
        args=(step, extra),
        daemon=True
    )
    t.start()
    return True


def _send_event(step: str, extra: dict = None) -> bool:
    """Send a single funnel event. Returns True on success."""
    payload = {
        "machine_id": _get_machine_id_hash(),
        "step": step,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_version": __version__,
        "is_dev": is_dev_mode(),
    }

    if extra:
        # Only allow safe extra fields
        for key in ("error_type", "duration_sec"):
            if key in extra:
                payload[key] = str(extra[key])[:100]

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            FUNNEL_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"stillrunning-funnel/{__version__}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def track_setup_start():
    """Track setup wizard started."""
    return track_step("setup_started")


def track_api_test(success: bool):
    """Track API connection test result."""
    step = "api_connection_success" if success else "api_connection_failed"
    return track_step(step)


def track_telegram_config(configured: bool, test_result: bool = None):
    """Track Telegram configuration."""
    if not configured:
        return track_step("telegram_skipped")

    track_step("telegram_configured")
    if test_result is not None:
        step = "telegram_test_success" if test_result else "telegram_test_failed"
        return track_step(step)
    return True


def track_telemetry_choice(opted_in: bool):
    """Track telemetry opt-in/out choice."""
    step = "telemetry_opted_in" if opted_in else "telemetry_opted_out"
    return track_step(step)


def track_setup_complete():
    """Track setup completed."""
    return track_step("setup_completed")


def track_monitoring_choice(started: bool):
    """Track whether user started monitoring after setup."""
    step = "monitoring_started" if started else "monitoring_skipped"
    return track_step(step)
