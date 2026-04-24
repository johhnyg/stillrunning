"""Tests for telemetry module."""

import os
import time
import threading
from unittest import mock

import pytest


def test_send_heartbeat_async_does_not_block():
    """Heartbeat must complete in <50ms (non-blocking)."""
    from stillrunning.telemetry import send_heartbeat_async

    start = time.time()
    send_heartbeat_async("test", "1.0.0")
    elapsed = time.time() - start

    assert elapsed < 0.05, f"Heartbeat took {elapsed*1000:.1f}ms, should be <50ms"


def test_send_heartbeat_handles_network_failure():
    """Network errors must be silently swallowed."""
    from stillrunning import telemetry

    with mock.patch.object(telemetry.urllib.request, "urlopen") as mock_urlopen:
        mock_urlopen.side_effect = Exception("Network error")

        # Should not raise
        result = telemetry._send_heartbeat_sync("test", "1.0.0")
        assert result is False


def test_no_telemetry_env_disables():
    """STILLRUNNING_NO_TELEMETRY=1 must disable telemetry completely."""
    from stillrunning import telemetry

    with mock.patch.dict(os.environ, {"STILLRUNNING_NO_TELEMETRY": "1"}):
        with mock.patch.object(telemetry.urllib.request, "urlopen") as mock_urlopen:
            telemetry.send_heartbeat_async("test", "1.0.0")
            time.sleep(0.1)  # Let background thread run
            mock_urlopen.assert_not_called()


def test_payload_contains_only_whitelisted_fields():
    """Payload must not contain package names, paths, or user data."""
    from stillrunning import telemetry
    import json

    captured_data = None

    def capture_request(req, **kwargs):
        nonlocal captured_data
        captured_data = json.loads(req.data.decode())
        raise Exception("Stop here")

    with mock.patch.object(telemetry.urllib.request, "urlopen", side_effect=capture_request):
        telemetry._send_heartbeat_sync("scan", "2.2.4")

    assert captured_data is not None
    allowed_fields = {"machine_id", "agent_version", "os_type", "command", "timestamp", "event_type"}
    actual_fields = set(captured_data.keys())
    forbidden = actual_fields - allowed_fields
    assert not forbidden, f"Payload contains forbidden fields: {forbidden}"


def test_machine_id_is_stable():
    """Machine ID must be the same across calls."""
    from stillrunning.telemetry import _get_or_create_machine_id

    id1 = _get_or_create_machine_id()
    id2 = _get_or_create_machine_id()
    assert id1 == id2
    assert len(id1) > 10
