#!/usr/bin/env python3
"""
Regenerate README.md tier table and feature list from features.json.

Run as pre-commit hook or manually:
    python scripts/regen-readme.py

Replaces content between markers:
  <!-- BEGIN:tier-table --> ... <!-- END:tier-table -->
  <!-- BEGIN:feature-list --> ... <!-- END:feature-list -->
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
FEATURES = ROOT / "features.json"
README = ROOT / "README.md"


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


def generate_feature_list(tiers: dict) -> str:
    """Generate markdown feature list per tier."""
    lines = []
    for name, config in tiers.items():
        if name == "free":
            continue
        price = f"${config['price']}/mo"
        lines.append(f"**{name.capitalize()}** ({price})")
        for feat in config.get("features", []):
            lines.append(f"- {feat}")
        lines.append("")
    return "\n".join(lines).rstrip()


def replace_section(content: str, start_marker: str, end_marker: str, new_content: str) -> str:
    """Replace content between markers."""
    if start_marker not in content or end_marker not in content:
        return content
    start_idx = content.index(start_marker) + len(start_marker)
    end_idx = content.index(end_marker)
    return content[:start_idx] + "\n" + new_content + "\n" + content[end_idx:]


def main():
    with open(FEATURES) as f:
        data = json.load(f)

    content = README.read_text()
    updated = False

    # Tier table
    if "<!-- BEGIN:tier-table -->" in content:
        table = generate_tier_table(data["tiers"])
        content = replace_section(content, "<!-- BEGIN:tier-table -->", "<!-- END:tier-table -->", table)
        updated = True
        print("Updated tier-table")

    # Feature list
    if "<!-- BEGIN:feature-list -->" in content:
        features = generate_feature_list(data["tiers"])
        content = replace_section(content, "<!-- BEGIN:feature-list -->", "<!-- END:feature-list -->", features)
        updated = True
        print("Updated feature-list")

    if updated:
        README.write_text(content)
        print(f"Wrote {README}")
    else:
        print("No markers found. Add <!-- BEGIN:tier-table --> and <!-- END:tier-table --> to README.md")
        sys.exit(1)


if __name__ == "__main__":
    main()
