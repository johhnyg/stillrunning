#!/usr/bin/env python3
"""
Manifest file parser for stillrunning.

Parses dependency manifests from various package managers and extracts
package specifications for security checking.

Supported formats:
- requirements.txt (pip, uv pip)
- requirements.in (pip-tools)
- pyproject.toml (poetry, pdm, uv, pip build)
- Pipfile (pipenv)
- package.json (npm, pnpm, yarn, bun)
- package-lock.json (npm ci)
- pnpm-lock.yaml (pnpm)
- environment.yml (conda)
- pixi.toml (pixi)
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class PackageSpec:
    """A package specification extracted from a manifest."""
    name: str
    version: Optional[str] = None
    ecosystem: str = "pip"
    source: str = "manifest"
    is_local: bool = False
    is_url: bool = False
    is_git: bool = False

@dataclass
class ManifestCheckResult:
    """Result of checking all packages in a manifest."""
    path: Path
    packages: list[PackageSpec]
    blocked: list[tuple[PackageSpec, str]]
    suspicious: list[tuple[PackageSpec, str]]
    clean: list[PackageSpec]
    skipped: list[tuple[PackageSpec, str]]
    error: Optional[str] = None


def _parse_requirements_txt(path: Path) -> list[PackageSpec]:
    """Parse requirements.txt format (pip, uv pip, pip-tools)."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return packages

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            if line.startswith("-r ") or line.startswith("--requirement "):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    included = path.parent / parts[1]
                    if included.exists():
                        packages.extend(_parse_requirements_txt(included))
            continue

        if line.startswith("git+") or line.startswith("https://") or line.startswith("http://"):
            packages.append(PackageSpec(name=line, is_url=True if not line.startswith("git+") else False, is_git=line.startswith("git+")))
            continue

        if line.startswith(".") or line.startswith("/") or line.startswith("~"):
            packages.append(PackageSpec(name=line, is_local=True))
            continue

        match = re.match(r'^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)(?:\[.*?\])?(?:([<>=!~]+.*))?', line)
        if match:
            name = match.group(1).lower().replace("_", "-")
            version = match.group(2) if match.group(2) else None
            packages.append(PackageSpec(name=name, version=version))

    return packages


def _parse_pyproject_toml(path: Path) -> list[PackageSpec]:
    """Parse pyproject.toml for dependencies."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return packages

    try:
        import tomli
        data = tomli.loads(content)
    except ImportError:
        import re
        deps = re.findall(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
        for dep_block in deps:
            for match in re.findall(r'"([^"]+)"', dep_block):
                pkg_match = re.match(r'^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)', match)
                if pkg_match:
                    packages.append(PackageSpec(name=pkg_match.group(1).lower().replace("_", "-")))
        return packages
    except Exception:
        return packages

    project_deps = data.get("project", {}).get("dependencies", [])
    for dep in project_deps:
        pkg_match = re.match(r'^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)', dep)
        if pkg_match:
            packages.append(PackageSpec(name=pkg_match.group(1).lower().replace("_", "-")))

    optional = data.get("project", {}).get("optional-dependencies", {})
    for group, deps in optional.items():
        for dep in deps:
            pkg_match = re.match(r'^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)', dep)
            if pkg_match:
                packages.append(PackageSpec(name=pkg_match.group(1).lower().replace("_", "-")))

    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name in poetry_deps:
        if name.lower() != "python":
            packages.append(PackageSpec(name=name.lower().replace("_", "-")))

    poetry_dev = data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {})
    for name in poetry_dev:
        packages.append(PackageSpec(name=name.lower().replace("_", "-")))

    pdm_deps = data.get("tool", {}).get("pdm", {}).get("dev-dependencies", {})
    for group, deps in pdm_deps.items() if isinstance(pdm_deps, dict) else []:
        for dep in deps:
            pkg_match = re.match(r'^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)', dep)
            if pkg_match:
                packages.append(PackageSpec(name=pkg_match.group(1).lower().replace("_", "-")))

    return packages


def _parse_pipfile(path: Path) -> list[PackageSpec]:
    """Parse Pipfile format (pipenv)."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return packages

    in_packages = False
    in_dev = False

    for line in content.splitlines():
        line = line.strip()
        if line == "[packages]":
            in_packages = True
            in_dev = False
            continue
        elif line == "[dev-packages]":
            in_dev = True
            in_packages = False
            continue
        elif line.startswith("["):
            in_packages = False
            in_dev = False
            continue

        if in_packages or in_dev:
            match = re.match(r'^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)\s*=', line)
            if match:
                packages.append(PackageSpec(name=match.group(1).lower().replace("_", "-")))

    return packages


def _parse_package_json(path: Path) -> list[PackageSpec]:
    """Parse package.json format (npm, pnpm, yarn, bun)."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
    except Exception:
        return packages

    for dep_key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(dep_key, {})
        for name in deps:
            if name.startswith("file:") or name.startswith("link:"):
                packages.append(PackageSpec(name=name, ecosystem="npm", is_local=True))
            elif name.startswith("git") or "github" in str(deps[name]):
                packages.append(PackageSpec(name=name, ecosystem="npm", is_git=True))
            else:
                packages.append(PackageSpec(name=name.lower(), ecosystem="npm"))

    return packages


def _parse_package_lock_json(path: Path) -> list[PackageSpec]:
    """Parse package-lock.json (npm ci)."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
    except Exception:
        return packages

    deps = data.get("packages", {})
    for pkg_path, info in deps.items():
        if not pkg_path or pkg_path == "":
            continue
        name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
        if name and not name.startswith("."):
            packages.append(PackageSpec(name=name.lower(), ecosystem="npm", version=info.get("version")))

    return packages


def _parse_pnpm_lock_yaml(path: Path) -> list[PackageSpec]:
    """Parse pnpm-lock.yaml."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return packages

    for line in content.splitlines():
        match = re.match(r"^\s+'?/?([^@:]+)@", line)
        if match:
            name = match.group(1).strip()
            if name and not name.startswith("."):
                packages.append(PackageSpec(name=name.lower(), ecosystem="npm"))

    return packages


def _parse_environment_yml(path: Path) -> list[PackageSpec]:
    """Parse environment.yml (conda)."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return packages

    in_deps = False
    in_pip = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("dependencies:"):
            in_deps = True
            continue
        elif stripped.startswith("- pip:"):
            in_pip = True
            continue
        elif not line.startswith(" ") and not line.startswith("\t"):
            in_deps = False
            in_pip = False
            continue

        if in_pip and stripped.startswith("- "):
            pkg = stripped[2:].strip()
            match = re.match(r'^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)', pkg)
            if match:
                packages.append(PackageSpec(name=match.group(1).lower().replace("_", "-"), ecosystem="pip"))
        elif in_deps and stripped.startswith("- "):
            pkg = stripped[2:].strip()
            if pkg != "pip" and not pkg.startswith("pip:"):
                match = re.match(r'^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)', pkg)
                if match:
                    packages.append(PackageSpec(name=match.group(1).lower(), ecosystem="conda"))

    return packages


def _parse_pixi_toml(path: Path) -> list[PackageSpec]:
    """Parse pixi.toml."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return packages

    in_deps = False
    in_pypi = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[dependencies]") or stripped.startswith("[target."):
            in_deps = True
            in_pypi = False
            continue
        elif stripped.startswith("[pypi-dependencies]"):
            in_pypi = True
            in_deps = False
            continue
        elif stripped.startswith("["):
            in_deps = False
            in_pypi = False
            continue

        if in_deps or in_pypi:
            match = re.match(r'^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)\s*=', stripped)
            if match:
                ecosystem = "pip" if in_pypi else "conda"
                packages.append(PackageSpec(name=match.group(1).lower().replace("_", "-"), ecosystem=ecosystem))

    return packages


def parse_manifest(path: Path) -> list[PackageSpec]:
    """
    Detect manifest file type and extract package specs.

    Args:
        path: Path to the manifest file

    Returns:
        List of PackageSpec objects
    """
    if not path.exists():
        return []

    name = path.name.lower()

    if name == "requirements.txt" or name == "requirements.in" or name.endswith("-requirements.txt"):
        return _parse_requirements_txt(path)
    elif name == "pyproject.toml":
        return _parse_pyproject_toml(path)
    elif name == "pipfile":
        return _parse_pipfile(path)
    elif name == "package.json":
        return _parse_package_json(path)
    elif name == "package-lock.json":
        return _parse_package_lock_json(path)
    elif name == "pnpm-lock.yaml":
        return _parse_pnpm_lock_yaml(path)
    elif name == "environment.yml" or name == "environment.yaml":
        return _parse_environment_yml(path)
    elif name == "pixi.toml":
        return _parse_pixi_toml(path)
    else:
        return []


def check_manifest(path: Path, check_fn=None) -> ManifestCheckResult:
    """
    Parse manifest and check each package against blocklist.

    Args:
        path: Path to the manifest file
        check_fn: Optional function(name, ecosystem) -> (status, reason)
                  If None, returns packages without checking

    Returns:
        ManifestCheckResult with per-package verdicts
    """
    packages = parse_manifest(path)

    blocked = []
    suspicious = []
    clean = []
    skipped = []

    if check_fn is None:
        return ManifestCheckResult(
            path=path,
            packages=packages,
            blocked=[],
            suspicious=[],
            clean=packages,
            skipped=[]
        )

    for pkg in packages:
        if pkg.is_local or pkg.is_url or pkg.is_git:
            skipped.append((pkg, "local/url/git dependency - not checked"))
            continue

        try:
            status, reason = check_fn(pkg.name, pkg.ecosystem)
            if status == "BLOCKED":
                blocked.append((pkg, reason))
            elif status == "WARN" or status == "SUSPICIOUS":
                suspicious.append((pkg, reason))
            else:
                clean.append(pkg)
        except Exception as e:
            skipped.append((pkg, f"check failed: {e}"))

    return ManifestCheckResult(
        path=path,
        packages=packages,
        blocked=blocked,
        suspicious=suspicious,
        clean=clean,
        skipped=skipped
    )


def find_manifest_in_dir(directory: Path) -> Optional[Path]:
    """Find the most relevant manifest file in a directory."""
    priority = [
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "package.json",
        "environment.yml",
        "pixi.toml",
    ]

    for name in priority:
        candidate = directory / name
        if candidate.exists():
            return candidate

    return None
