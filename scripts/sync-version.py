#!/usr/bin/env python3
"""
Sync version from features.json to all distribution files.

Run before release:
    python scripts/sync-version.py

Updates:
- pyproject.toml version
- stillrunning/cli.py VERSION constant
- CHANGELOG.md header (if releasing new version)
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
FEATURES = ROOT / "features.json"
PYPROJECT = ROOT / "pyproject.toml"
CLI = ROOT / "stillrunning" / "cli.py"


def main():
    with open(FEATURES) as f:
        data = json.load(f)

    version = data["version"]
    print(f"Syncing version: {version}")

    # Update pyproject.toml
    content = PYPROJECT.read_text()
    content = re.sub(r'version = "[^"]+"', f'version = "{version}"', content)
    PYPROJECT.write_text(content)
    print(f"  Updated {PYPROJECT}")

    # Update cli.py VERSION constant
    content = CLI.read_text()
    content = re.sub(r'VERSION = "[^"]+"', f'VERSION = "{version}"', content)
    CLI.write_text(content)
    print(f"  Updated {CLI}")

    print("Done!")


if __name__ == "__main__":
    main()
