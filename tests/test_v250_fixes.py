"""Tests for v2.5.0 completeness release."""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest import mock


class TestVenvHook:
    """Part D: Virtual environment persistence."""

    def test_venv_hook_module_exists(self):
        """venv_hook.py should exist and be importable."""
        from stillrunning import venv_hook
        assert hasattr(venv_hook, '_activate_hook')

    def test_venv_hook_has_skip_check(self):
        """Should have STILLRUNNING_DISABLE check."""
        from stillrunning import venv_hook
        assert hasattr(venv_hook, '_should_skip')

    def test_venv_hook_respects_disable_env(self):
        """Should skip when STILLRUNNING_DISABLE=1."""
        from stillrunning import venv_hook
        with mock.patch.dict(os.environ, {"STILLRUNNING_DISABLE": "1"}):
            assert venv_hook._should_skip() is True

    def test_venv_hook_normal_operation(self):
        """Should not skip when env var not set."""
        from stillrunning import venv_hook
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("STILLRUNNING_DISABLE", None)
            os.environ.pop("STILLRUNNING_DEV", None)
            assert venv_hook._should_skip() is False


class TestVenvInstallCLI:
    """Part D: venv-install/uninstall CLI commands."""

    def test_venv_install_function_exists(self):
        """_venv_install function should exist."""
        from stillrunning.cli import _venv_install
        assert callable(_venv_install)

    def test_venv_uninstall_function_exists(self):
        """_venv_uninstall function should exist."""
        from stillrunning.cli import _venv_uninstall
        assert callable(_venv_uninstall)

    def test_sitecustomize_marker_defined(self):
        """Marker for sitecustomize block should be defined."""
        from stillrunning.cli import _SITECUSTOMIZE_MARKER
        assert "stillrunning" in _SITECUSTOMIZE_MARKER.lower()


class TestLoggingInfrastructure:
    """Part A4: Exception handler audit logging."""

    def test_logger_exists(self):
        """Logger should be configured."""
        from stillrunning.cli import _logger
        assert _logger is not None
        assert _logger.name == "stillrunning"

    def test_debug_logging_function_exists(self):
        """_enable_debug_logging should exist."""
        from stillrunning.cli import _enable_debug_logging
        assert callable(_enable_debug_logging)


class TestVersionUpdate:
    """Version should be 2.5.0."""

    def test_version_is_250(self):
        """VERSION constant should be 2.5.0."""
        from stillrunning.cli import VERSION
        assert VERSION == "2.5.0"


class TestScanManifestStillWorks:
    """Ensure v2.4.0 scan-manifest still works."""

    def test_scan_manifest_function_exists(self):
        """_scan_manifest should still exist."""
        from stillrunning.cli import _scan_manifest
        assert callable(_scan_manifest)


class TestPackageManagersStillSupported:
    """Ensure v2.4.0 package manager support still works."""

    def test_supported_managers(self):
        """All package managers should be supported."""
        from stillrunning.intercept import SUPPORTED_MANAGERS
        expected = {"pip", "pip3", "npm", "yarn", "pnpm", "uv", "bun",
                    "poetry", "pdm", "pipenv", "conda", "pixi"}
        assert expected.issubset(SUPPORTED_MANAGERS)
