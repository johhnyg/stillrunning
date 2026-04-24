"""Tests for v2.4.0 refinement release."""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest import mock


class TestManifestParser:
    """Part C: Manifest file parsing."""

    def test_parse_requirements_txt(self):
        """requirements.txt should parse correctly."""
        from stillrunning.manifest import parse_manifest

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("requests==2.31.0\n")
            f.write("flask>=2.0\n")
            f.write("# comment line\n")
            f.write("django\n")
            f.name
        try:
            path = Path(f.name)
            path = path.rename(path.parent / "requirements.txt")
            specs = parse_manifest(path)
            names = [s.name for s in specs]
            assert "requests" in names
            assert "flask" in names
            assert "django" in names
            assert len([s for s in specs if s.name.startswith("#")]) == 0
        finally:
            path.unlink(missing_ok=True)

    def test_parse_requirements_with_blocked_package(self):
        """Blocked package in requirements.txt should be detected."""
        from stillrunning.manifest import parse_manifest

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("requests\n")
            f.write("logutilkit\n")  # Known malicious
            f.write("flask\n")
            f.name
        try:
            path = Path(f.name)
            path = path.rename(path.parent / "requirements.txt")
            specs = parse_manifest(path)
            names = [s.name for s in specs]
            assert "logutilkit" in names
        finally:
            path.unlink(missing_ok=True)

    def test_parse_pyproject_toml(self):
        """pyproject.toml should parse correctly."""
        from stillrunning.manifest import parse_manifest

        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write('[project]\n')
            f.write('dependencies = ["requests", "click>=8.0"]\n')
            f.name
        try:
            path = Path(f.name)
            path = path.rename(path.parent / "pyproject.toml")
            specs = parse_manifest(path)
            names = [s.name for s in specs]
            assert "requests" in names
            assert "click" in names
        finally:
            path.unlink(missing_ok=True)

    def test_parse_package_json(self):
        """package.json should parse correctly."""
        from stillrunning.manifest import parse_manifest
        import json

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "dependencies": {"express": "^4.0.0", "lodash": "^4.17.0"},
                "devDependencies": {"jest": "^29.0.0"}
            }, f)
            f.name
        try:
            path = Path(f.name)
            path = path.rename(path.parent / "package.json")
            specs = parse_manifest(path)
            names = [s.name for s in specs]
            assert "express" in names
            assert "lodash" in names
            assert "jest" in names
            assert all(s.ecosystem == "npm" for s in specs)
        finally:
            path.unlink(missing_ok=True)

    def test_skip_local_git_url_deps(self):
        """Local, git, and URL deps should be marked appropriately."""
        from stillrunning.manifest import parse_manifest

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("requests\n")
            f.write("git+https://github.com/user/repo.git\n")
            f.write("./local-package\n")
            f.write("https://example.com/pkg.tar.gz\n")
            f.name
        try:
            path = Path(f.name)
            path = path.rename(path.parent / "requirements.txt")
            specs = parse_manifest(path)

            local_specs = [s for s in specs if s.is_local or s.is_git or s.is_url]
            regular_specs = [s for s in specs if not s.is_local and not s.is_git and not s.is_url]

            assert len(regular_specs) == 1
            assert regular_specs[0].name == "requests"
            assert len(local_specs) == 3
        finally:
            path.unlink(missing_ok=True)


class TestPackageManagerSupport:
    """Part B: Additional package manager interception."""

    def test_all_managers_supported(self):
        """All target package managers should be in SUPPORTED_MANAGERS."""
        from stillrunning.intercept import SUPPORTED_MANAGERS

        expected = {"pip", "pip3", "npm", "yarn", "pnpm", "uv", "bun",
                    "poetry", "pdm", "pipenv", "conda", "pixi"}
        assert expected.issubset(SUPPORTED_MANAGERS)

    def test_install_commands_defined(self):
        """Each manager should have install commands defined."""
        from stillrunning.intercept import INSTALL_COMMANDS, SUPPORTED_MANAGERS

        for manager in SUPPORTED_MANAGERS:
            assert manager in INSTALL_COMMANDS
            assert len(INSTALL_COMMANDS[manager]) > 0

    def test_ecosystem_mapping(self):
        """Each manager should map to an ecosystem."""
        from stillrunning.intercept import MANAGER_ECOSYSTEM, SUPPORTED_MANAGERS

        for manager in SUPPORTED_MANAGERS:
            assert manager in MANAGER_ECOSYSTEM
            assert MANAGER_ECOSYSTEM[manager] in ("pip", "npm", "conda")


class TestHookPathFix:
    """Part A1: Hardcoded path fix."""

    def test_no_hardcoded_root_paths(self):
        """hook.py should not have hardcoded /root/my-app paths."""
        with open("/root/stillrunning/stillrunning/hook.py") as f:
            content = f.read()

        # Check the constants section only
        lines = content.split("\n")
        constants_section = []
        in_constants = False
        for line in lines:
            if "# ─── Constants" in line:
                in_constants = True
            elif "# ───" in line and in_constants:
                break
            elif in_constants:
                constants_section.append(line)

        constants_text = "\n".join(constants_section)
        assert "/root/my-app" not in constants_text

    def test_uses_home_directory(self):
        """hook.py should use Path.home() for paths."""
        with open("/root/stillrunning/stillrunning/hook.py") as f:
            content = f.read()
        assert "Path.home()" in content or "_STILLRUNNING_DIR" in content


class TestScanManifestCommand:
    """Part C: scan-manifest CLI command."""

    def test_scan_manifest_function_exists(self):
        """_scan_manifest function should exist."""
        from stillrunning.cli import _scan_manifest
        assert callable(_scan_manifest)

    def test_scan_manifest_file_not_found(self):
        """Non-existent file should return error code 2."""
        from stillrunning.cli import _scan_manifest
        result = _scan_manifest("/nonexistent/file.txt")
        assert result == 2

    def test_scan_manifest_empty_file(self):
        """Empty file should return 0 (no issues)."""
        from stillrunning.cli import _scan_manifest

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("")
            f.name
        try:
            path = Path(f.name)
            path = path.rename(path.parent / "requirements.txt")
            result = _scan_manifest(str(path))
            assert result == 0
        finally:
            path.unlink(missing_ok=True)


class TestInterceptManifestParsing:
    """Part C: intercept.py manifest parsing integration."""

    def test_extract_manifests_from_args(self):
        """-r requirements.txt should be extracted as manifest."""
        from stillrunning.intercept import extract_packages_and_manifests

        packages, manifests = extract_packages_and_manifests(
            ["install", "-r", "requirements.txt", "flask"],
            "pip"
        )

        assert Path("requirements.txt") in manifests
        assert "flask" in packages

    def test_extract_inline_requirement_flag(self):
        """Inline -rrequirements.txt should work."""
        from stillrunning.intercept import extract_packages_and_manifests

        packages, manifests = extract_packages_and_manifests(
            ["install", "-rrequirements.txt"],
            "pip"
        )

        assert Path("requirements.txt") in manifests

    def test_skip_editable_installs(self):
        """Editable installs (-e .) should be skipped."""
        from stillrunning.intercept import extract_packages_and_manifests

        packages, manifests = extract_packages_and_manifests(
            ["install", "-e", ".", "flask"],
            "pip"
        )

        # "." should not be in packages
        assert "." not in packages
        assert "flask" in packages

    def test_skip_git_urls(self):
        """git+https URLs should be skipped."""
        from stillrunning.intercept import extract_packages_and_manifests

        packages, manifests = extract_packages_and_manifests(
            ["install", "git+https://github.com/user/repo.git", "flask"],
            "pip"
        )

        assert len([p for p in packages if "git+" in p]) == 0
        assert "flask" in packages


class TestBlockedPackageDetection:
    """Ensure blocked packages are actually blocked."""

    def test_blocklist_contains_known_bad(self):
        """KNOWN_BAD_PIP should contain known malicious packages."""
        from stillrunning.intercept import KNOWN_BAD_PIP

        assert "logutilkit" in KNOWN_BAD_PIP
        assert "apachelicense" in KNOWN_BAD_PIP

    def test_check_pypi_blocks_bad_package(self):
        """check_pypi_package should block known bad packages."""
        from stillrunning.intercept import check_pypi_package

        status, reason = check_pypi_package("logutilkit")
        assert status == "BLOCKED"
        assert "malicious" in reason.lower()
