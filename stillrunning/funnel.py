"""Setup funnel telemetry for stillrunning.

Tracks anonymous, aggregate conversion data through the setup wizard.
This is OPT-OUT (enabled by default for anonymous aggregate stats).
Set STILLRUNNING_NO_FUNNEL=1 or STILLRUNNING_NO_TELEMETRY=1 to disable,
or set STILLRUNNING_DEV=1.

No personal data is collected. Only: hashed machine ID (the same one the
anonymous heartbeat uses), step name, timestamp, and agent version.
"""

from stillrunning.apibase import api_url
import atexit
import json
import os
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from stillrunning import __version__

FUNNEL_URL = api_url("/api/setup-funnel")
FLUSH_AT_EXIT_SEC = 3.0
FIRST_SCAN_MARKER = ".stillrunning/first_scan_sent"
SCAN_OK_EXIT_CODES = {0, 3, 10, 11}
_funnel_enabled = True
_pending: list[threading.Thread] = []


def _get_machine_id_hash() -> str:
    from stillrunning.heartbeat import _get_anonymous_machine_id
    return _get_anonymous_machine_id()


def is_dev_mode() -> bool:
    """Check if running in dev mode (STILLRUNNING_DEV=1)."""
    return os.environ.get("STILLRUNNING_DEV", "").lower() in ("1", "true", "yes")


def is_funnel_enabled() -> bool:
    """Check if funnel telemetry is enabled."""
    # Disabled if STILLRUNNING_DEV=1 (internal usage)
    if is_dev_mode():
        return False
    # Disabled if STILLRUNNING_NO_FUNNEL=1 (explicit opt-out)
    for var in ("STILLRUNNING_NO_FUNNEL", "STILLRUNNING_NO_TELEMETRY"):
        if os.environ.get(var, "").lower() in ("1", "true", "yes"):
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
        first_scan_ok / first_scan_failed_exit<code>

    Returns True if event was queued, False if disabled.
    """
    if not is_funnel_enabled():
        return False

    t = threading.Thread(
        target=_send_event,
        args=(step, extra),
        daemon=True
    )
    t.start()
    _pending.append(t)
    return True


@atexit.register
def _flush_pending() -> None:
    # Daemon threads die at interpreter exit; give in-flight events a short window.
    deadline = time.monotonic() + FLUSH_AT_EXIT_SEC
    for t in _pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        t.join(remaining)


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


def track_first_scan(exit_code: int) -> bool:
    """Send one event for this machine's first CLI scan; later scans send nothing."""
    if not is_funnel_enabled():
        return False
    marker = Path.home() / FIRST_SCAN_MARKER
    if marker.exists():
        return False
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(datetime.now(timezone.utc).isoformat() + "\n")
    except OSError:
        # Without the marker every scan would report itself as the first.
        return False
    if exit_code in SCAN_OK_EXIT_CODES:
        return track_step("first_scan_ok")
    return track_step(f"first_scan_failed_exit{exit_code}")


def track_monitoring_choice(started: bool):
    """Track whether user started monitoring after setup."""
    step = "monitoring_started" if started else "monitoring_skipped"
    return track_step(step)
