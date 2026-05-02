#!/usr/bin/env python3
"""
Regenerate README.md tier table from features.json.

Run as pre-commit hook or manually:
    python scripts/regen-readme.py

Replaces content between <!-- TIERS-START --> and <!-- TIERS-END --> markers.
"""

import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
FEATURES = ROOT / "features.json"
README = ROOT / "README.md"

START_MARKER = "<!-- TIERS-START -->"
END_MARKER = "<!-- TIERS-END -->"


def generate_tier_table(tiers: dict) -> str:
    """Generate markdown tier comparison table."""
    lines = [
        "| Tier | Price | Scans/day | Machines | Dashboard |",
        "|------|-------|-----------|----------|-----------|",
    ]

    for name, config in tiers.items():
        price = f"${config['price']}/mo" if config['price'] > 0 else "Free"
        scans = str(config['scans_per_day']) if config['scans_per_day'] else "Unlimited"
        machines = str(config['machines']) if config['machines'] else "Unlimited"
        dashboard = "Yes" if config['dashboard'] else "No"
        lines.append(f"| {name.capitalize()} | {price} | {scans} | {machines} | {dashboard} |")

    return "\n".join(lines)


def main():
    with open(FEATURES) as f:
        data = json.load(f)

    table = generate_tier_table(data["tiers"])

    content = README.read_text()

    # Find and replace tier table
    if START_MARKER in content and END_MARKER in content:
        start_idx = content.index(START_MARKER) + len(START_MARKER)
        end_idx = content.index(END_MARKER)
        new_content = content[:start_idx] + "\n" + table + "\n" + content[end_idx:]
        README.write_text(new_content)
        print(f"Updated tier table in {README}")
    else:
        print(f"Markers not found in {README}. Add {START_MARKER} and {END_MARKER}.")


if __name__ == "__main__":
    main()
