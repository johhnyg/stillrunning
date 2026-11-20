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
from __future__ import annotations  # annotations stay strings: Python 3.8/3.9 can import this module

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
        try:
            import tomllib as tomli          # Python 3.11+
        except ImportError:
            import tomli
        data = tomli.loads(content)
    except ImportError:
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
                # keep the spec: an exact pin ("1.14.1") must be checked as that
                # version, not as whatever is latest today
                spec = deps[name] if isinstance(deps[name], str) else None
                packages.append(PackageSpec(name=name.lower(), version=spec, ecosystem="npm"))

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
        # '/@scope/name@1.2.3(peer...)': or  name@1.2.3:  — scoped names and
        # the locked version are both kept
        match = re.match(r"^\s+'?/?((?:@[^/@\s']+/)?[^@:\s'/]+)@(\d[^:('\s]*)?", line)
        if match:
            name = match.group(1).strip()
            if name and not name.startswith("."):
                packages.append(PackageSpec(name=name.lower(), ecosystem="npm",
                                            version=match.group(2)))

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


def _parse_toml_lock(path: Path) -> list[PackageSpec]:
    """poetry.lock / uv.lock: every [[package]] block has name and version.
    Read as text — no TOML parser is needed for these two keys."""
    packages = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return packages
    for block in re.split(r"^\[\[package\]\]\s*$", content, flags=re.M)[1:]:
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        version = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        if name:
            packages.append(PackageSpec(name=name.group(1).lower(),
                                        version=f"=={version.group(1)}" if version else None))
    return packages


_REQUIREMENTS_LIKE = re.compile(r"(requirements|constraints).*\.(txt|in)$|\.(txt|in)$")


def manifest_kind(path: Path) -> Optional[str]:
    """Which parser reads this file, or None when no parser does. `pip -r`
    accepts any file name, so any .txt / .in file is read as a requirements
    file."""
    name = path.name.lower()
    exact = {
        "pyproject.toml": "pyproject", "pipfile": "pipfile", "package.json": "package_json",
        "package-lock.json": "package_lock", "npm-shrinkwrap.json": "package_lock",
        "pnpm-lock.yaml": "pnpm_lock", "environment.yml": "conda", "environment.yaml": "conda",
        "pixi.toml": "pixi", "poetry.lock": "toml_lock", "uv.lock": "toml_lock",
    }
    if name in exact:
        return exact[name]
    if _REQUIREMENTS_LIKE.search(name):
        return "requirements"
    return None


_PARSERS = {
    "requirements": _parse_requirements_txt, "pyproject": _parse_pyproject_toml,
    "pipfile": _parse_pipfile, "package_json": _parse_package_json,
    "package_lock": _parse_package_lock_json, "pnpm_lock": _parse_pnpm_lock_yaml,
    "conda": _parse_environment_yml, "pixi": _parse_pixi_toml, "toml_lock": _parse_toml_lock,
}


def parse_manifest(path: Path) -> list[PackageSpec]:
    """Detect the manifest type and extract package specs. An unknown file
    type gives [] here; callers that must tell "no packages" from "cannot
    read this kind of file" use parse_manifest_strict()."""
    return parse_manifest_strict(path) or []


def parse_manifest_strict(path: Path) -> Optional[list[PackageSpec]]:
    """Like parse_manifest, but None when the file is missing or of a kind no
    parser reads — so "nothing was checked" is never mistaken for "nothing
    to check"."""
    if not path.exists():
        return None
    kind = manifest_kind(path)
    if kind is None:
        return None
    return _PARSERS[kind](path)


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
