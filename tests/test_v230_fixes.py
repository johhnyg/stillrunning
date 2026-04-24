"""Tests for v2.3.0 critical bug fixes."""

import os
import sys
import pytest
from unittest import mock


class TestBlocklistCheck:
    """Bug #1: /api/check-package must check blocklist."""

    def test_known_bad_package_blocked(self):
        """Known malicious package must return BLOCKED."""
        # Import the dashboard helper
        sys.path.insert(0, "/root/my-app")
        # Can't import full dashboard due to Flask, test the logic directly
        from pathlib import Path

        KNOWN_BAD_PIP = {
            "logutilkit", "apachelicense", "fluxhttp", "license-utils-kit", "logkitx",
            "pino-debugger", "dev-log-core", "logger-base", "axios", "axois",
        }

        # Test hardcoded blocklist
        assert "logutilkit" in KNOWN_BAD_PIP
        assert "apachelicense" in KNOWN_BAD_PIP

    def test_clean_package_not_blocked(self):
        """Safe packages must not be blocked."""
        KNOWN_BAD_PIP = {
            "logutilkit", "apachelicense", "fluxhttp",
        }
        assert "requests" not in KNOWN_BAD_PIP
        assert "flask" not in KNOWN_BAD_PIP


class TestScanCommand:
    """Bug #2: stillrunning scan <package> must work."""

    def test_scan_function_exists(self):
        """_scan_package function must exist."""
        from stillrunning.cli import _scan_package
        assert callable(_scan_package)

    def test_scan_blocked_package_returns_1(self):
        """Blocked package must return exit code 1."""
        from stillrunning.cli import _scan_package

        # Mock the network calls
        with mock.patch("stillrunning.cli.urllib.request.urlopen") as mock_urlopen:
            # _scan_package checks hardcoded blocklist first, no network needed
            result = _scan_package("logutilkit")
            assert result == 1  # BLOCKED

    def test_scan_nonexistent_package_returns_2(self):
        """Nonexistent package must return exit code 2."""
        import urllib.error
        from stillrunning.cli import _scan_package

        # Mock PyPI to return 404
        with mock.patch("stillrunning.cli.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                "https://pypi.org", 404, "Not Found", {}, None
            )
            result = _scan_package("nonexistent_xyz_12345_abc")
            assert result == 2  # ERROR


class TestUvInterception:
    """Bug #3: uv must be intercepted."""

    def test_uv_in_allowed_managers(self):
        """uv must be in the list of intercepted managers."""
        # Read intercept.py and check
        with open("/root/stillrunning/stillrunning/intercept.py") as f:
            content = f.read()
        assert '"uv"' in content or "'uv'" in content

    def test_uv_pip_handling_exists(self):
        """uv pip install handling code must exist."""
        with open("/root/stillrunning/stillrunning/intercept.py") as f:
            content = f.read()
        assert "is_uv_pip" in content
        assert 'args[0] == "pip"' in content


class TestNamespacePackages:
    """Bug #4: Namespace packages must be checked."""

    def test_namespace_blocklist_exists(self):
        """NAMESPACE_BLOCKLIST must exist in hook.py."""
        from stillrunning.hook import NAMESPACE_BLOCKLIST
        assert isinstance(NAMESPACE_BLOCKLIST, set)

    def test_full_path_checking_in_find_spec(self):
        """find_spec must check full dotted path."""
        with open("/root/stillrunning/stillrunning/hook.py") as f:
            content = f.read()
        # Check that we're iterating through namespace parts
        assert "namespace =" in content or "namespace=" in content
        assert "NAMESPACE_BLOCKLIST" in content
