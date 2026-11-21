"""--hook-claude-code also registers the bundled side panel (stillrunning-shield)."""
import json
import os

import pytest

from stillrunning import claude_hook

PLUGIN = claude_hook.PANEL_PLUGIN_ID
MARKET = claude_hook.PANEL_MARKETPLACE


@pytest.fixture
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    os.makedirs(tmp_path / ".claude")
    return tmp_path


def settings(home):
    with open(home / ".claude" / "settings.json", encoding="utf-8") as handle:
        return json.load(handle)


def write_settings(home, data):
    with open(home / ".claude" / "settings.json", "w", encoding="utf-8") as handle:
        json.dump(data, handle)


def test_panel_files_ship_in_the_package():
    folder = claude_hook.panel_dir()
    for rel in (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json",
                "hooks/hooks.json", "hooks/register.tsx", "types/index.d.ts"):
        assert os.path.isfile(os.path.join(folder, rel)), rel
    with open(os.path.join(folder, ".claude-plugin", "marketplace.json"), encoding="utf-8") as handle:
        market = json.load(handle)
    assert market["name"] == MARKET
    assert [p["name"] for p in market["plugins"]] == ["stillrunning-shield"]
    assert PLUGIN == "stillrunning-shield@" + MARKET


def test_install_registers_the_panel_from_the_package_folder(home):
    messages = claude_hook.install()
    data = settings(home)
    assert data["extraKnownMarketplaces"][MARKET] == {
        "source": {"source": "directory", "path": claude_hook.panel_dir()}}
    assert data["enabledPlugins"][PLUGIN] is True
    assert any("/shield" in m for m in messages)
    assert data["hooks"]["PreToolUse"]  # the hook itself is still installed


def test_no_panel_leaves_plugins_untouched(home):
    claude_hook.install(panel=False)
    data = settings(home)
    assert "extraKnownMarketplaces" not in data and "enabledPlugins" not in data


def test_a_panel_switched_off_stays_off(home):
    write_settings(home, {"enabledPlugins": {PLUGIN: False}})
    messages = claude_hook.install()
    data = settings(home)
    assert data["enabledPlugins"][PLUGIN] is False
    assert MARKET not in data.get("extraKnownMarketplaces", {})
    assert any("left off" in m for m in messages)


def test_a_foreign_marketplace_of_the_same_name_is_left_alone(home):
    foreign = {"source": {"source": "github", "repo": "someone/else"}}
    write_settings(home, {"extraKnownMarketplaces": {MARKET: foreign}})
    messages = claude_hook.install()
    data = settings(home)
    assert data["extraKnownMarketplaces"][MARKET] == foreign
    assert PLUGIN not in data.get("enabledPlugins", {})
    assert any("NOT added" in m for m in messages)


def test_the_github_install_of_the_panel_is_replaced_by_the_bundled_one(home):
    gh = {"source": {"source": "github", "repo": claude_hook.PANEL_REPO}}
    write_settings(home, {"extraKnownMarketplaces": {MARKET: gh}, "enabledPlugins": {PLUGIN: True}})
    claude_hook.install()
    assert settings(home)["extraKnownMarketplaces"][MARKET]["source"]["source"] == "directory"


def test_other_plugins_and_marketplaces_are_kept(home):
    other_market = {"source": {"source": "github", "repo": "a/b"}}
    write_settings(home, {"extraKnownMarketplaces": {"mine": other_market},
                          "enabledPlugins": {"x@mine": True}})
    claude_hook.install()
    data = settings(home)
    assert data["extraKnownMarketplaces"]["mine"] == other_market
    assert data["enabledPlugins"]["x@mine"] is True
    claude_hook.uninstall()
    data = settings(home)
    assert data["extraKnownMarketplaces"] == {"mine": other_market}
    assert data["enabledPlugins"] == {"x@mine": True}


def test_uninstall_removes_the_panel_even_after_other_edits(home):
    claude_hook.install()
    data = settings(home)
    data["model"] = "edited-after-install"  # defeats the byte-for-byte restore
    write_settings(home, data)
    claude_hook.uninstall()
    data = settings(home)
    assert "extraKnownMarketplaces" not in data and "enabledPlugins" not in data
    assert data["model"] == "edited-after-install"


def test_settings_in_an_unexpected_shape_are_not_edited(home):
    write_settings(home, {"enabledPlugins": ["not", "a", "dict"]})
    messages = claude_hook.install()
    assert settings(home)["enabledPlugins"] == ["not", "a", "dict"]
    assert any("NOT added" in m for m in messages)
