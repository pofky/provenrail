"""The Claude Code plugin marketplace shipped from this repo must stay loadable.

`/plugin marketplace add pofky/provenrail` reads `.claude-plugin/marketplace.json` straight from
the default branch, so a malformed file or a moved path breaks installation for everyone at the
moment they try it, with no build step in between to catch it.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"
PLUGIN_DIR = ROOT / "plugins" / "provenrail-guard"

# Anthropic reserves these; a marketplace using one stops loading entirely.
RESERVED = {
    "claude-code-marketplace", "claude-code-plugins", "claude-plugins-official",
    "claude-plugins-community", "claude-community", "anthropic-marketplace",
    "anthropic-plugins", "agent-skills", "anthropic-agent-skills",
    "knowledge-work-plugins", "life-sciences", "claude-for-legal",
    "claude-for-financial-services", "financial-services-plugins",
    "first-party-plugins", "healthcare",
}


@pytest.fixture(scope="module")
def marketplace() -> dict:
    assert MARKETPLACE.is_file(), "marketplace.json is missing"
    return json.loads(MARKETPLACE.read_text(encoding="utf-8"))


def test_required_fields(marketplace: dict) -> None:
    for field in ("name", "owner", "plugins"):
        assert field in marketplace, f"marketplace.json must define {field}"
    assert isinstance(marketplace["plugins"], list) and marketplace["plugins"]
    assert "name" in marketplace["owner"]


def test_name_is_not_reserved_and_is_kebab_case(marketplace: dict) -> None:
    name = marketplace["name"]
    assert name not in RESERVED, f"{name} is reserved for Anthropic and would refuse to load"
    assert name == name.lower() and " " not in name


def test_every_plugin_source_exists(marketplace: dict) -> None:
    for entry in marketplace["plugins"]:
        src = entry["source"]
        if isinstance(src, str) and src.startswith("."):
            assert (ROOT / src).is_dir(), f"plugin source {src} does not exist in the repo"


def test_plugin_manifest_is_valid() -> None:
    manifest = PLUGIN_DIR / ".claude-plugin" / "plugin.json"
    assert manifest.is_file()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["name"] == "provenrail-guard"


def test_hooks_reference_the_plugin_root_not_an_absolute_path() -> None:
    """Plugins are copied to a cache directory on install, so any path that is not resolved
    through ${CLAUDE_PLUGIN_ROOT} points at the author's machine and fails for every user."""
    hooks = json.loads((PLUGIN_DIR / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    commands = [h["command"] for group in hooks.values() for entry in group
                for h in entry["hooks"]]
    assert commands, "hooks.json defines no commands"
    for cmd in commands:
        assert "${CLAUDE_PLUGIN_ROOT}" in cmd, f"{cmd!r} must resolve through CLAUDE_PLUGIN_ROOT"
        assert not cmd.startswith("/"), f"{cmd!r} is an absolute path"


def test_hook_script_exists_and_is_executable() -> None:
    script = PLUGIN_DIR / "scripts" / "pr-guard-hook.sh"
    assert script.is_file()
    mode = script.stat().st_mode
    assert mode & stat.S_IXUSR, "the hook script must be executable or every hook call fails"


def test_hook_script_fails_open() -> None:
    """If Provenrail is absent the hook must exit 0 and stay silent on stdout.

    A non-zero exit or stray stdout from this script is read by Claude Code as a decision, so a
    missing dependency would start blocking the user's tool calls. That turns "you forgot to
    install something" into "your agent is broken", which is how a safety plugin gets uninstalled.
    """
    script = (PLUGIN_DIR / "scripts" / "pr-guard-hook.sh").read_text(encoding="utf-8")
    assert "exit 0" in script
    assert "command -v pr" in script


def test_every_hook_event_is_one_claude_code_supports() -> None:
    hooks = json.loads((PLUGIN_DIR / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    assert set(hooks) <= {"PreToolUse", "PostToolUse"}, (
        "only the two tool-boundary events are wired; anything else is a typo that "
        "silently never fires"
    )
    assert "PreToolUse" in hooks, "without PreToolUse nothing is ever blocked"


def test_marketplace_is_not_gitignored() -> None:
    """A gitignored marketplace file loads locally and 404s for every real user."""
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".claude-plugin", "plugins/"):
        assert pattern not in gitignore.split(), f"{pattern} is gitignored"
    assert os.path.relpath(MARKETPLACE, ROOT) == ".claude-plugin/marketplace.json"
