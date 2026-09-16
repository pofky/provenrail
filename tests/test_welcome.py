"""The first-run notice must describe the rules that are actually armed.

This module exists because of a specific failure: the notice used to be a hand-written string
naming "rm -rf, dd of=/dev/, terraform destroy, git push --force, DROP/TRUNCATE, chmod 777,
committed API keys", and when 0.4 added the git pack, which is the pack that matches what
actually destroys people's work, the notice went on describing the previous release for a
whole version, on the one screen a new user reads. So the tests below are not about wording.
They hold the one property that failure violated: the notice is DERIVED from the armed rules
and cannot describe a release other than the one running.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from provenrail import guard, rulesets, welcome

ROOT = Path(__file__).resolve().parent.parent
VENDORED = ROOT / "plugins" / "provenrail-guard" / "scripts" / "welcome.py"

PACKS = {"delete": {"title": "Deletes"}, "git": {"title": "Git"}, "cloud": {"title": "Cloud"}}


def _armed(*pairs):
    return [{"id": rule_id, "effect": effect} for rule_id, effect in pairs]


def test_a_pack_with_any_deny_rule_is_described_as_refusing_not_as_asking():
    """A pack that both refuses and asks must be named once, under the stronger claim.

    Listing it in both halves reads as two separate protections, which overstates what is
    armed. `summarise` folds it into "refuses" and drops it from "asks".
    """
    refuse, ask = welcome.summarise(
        _armed(("git.reset_hard", "deny"), ("git.clean", "ask")), PACKS)
    assert refuse == [("Git", 1)]
    assert ask == []


def test_packs_that_only_ask_are_listed_separately_from_packs_that_refuse():
    refuse, ask = welcome.summarise(
        _armed(("delete.catastrophic", "deny"), ("cloud.volume_delete", "ask")), PACKS)
    assert refuse == [("Deletes", 1)]
    assert ask == [("Cloud", 1)]


def _refused_line(notice):
    """The line that names the packs. Asserting on the whole notice is wrong, because the
    fixed `_QUIET` sentence mentions `git reset --hard` in every notice regardless of what is
    armed, which would make a "this pack is not named" assertion pass for the wrong reason."""
    return next(ln for ln in notice.splitlines() if ln.strip().startswith("Refused outright:"))


def test_the_notice_names_the_packs_that_are_armed_and_not_a_fixed_list():
    """The regression that motivated this module: arm a different pack, get a different notice."""
    git_only = _refused_line(welcome.first_run_notice(
        _armed(("git.reset_hard", "deny")), PACKS, ".provenrail.json", signed=False))
    delete_only = _refused_line(welcome.first_run_notice(
        _armed(("delete.catastrophic", "deny")), PACKS, ".provenrail.json", signed=False))
    assert "git" in git_only.lower()
    assert "git" not in delete_only.lower()
    assert "delete" in delete_only.lower()


def test_nothing_armed_says_nothing_rather_than_claiming_an_empty_protection():
    assert welcome.first_run_notice([], PACKS, ".provenrail.json", signed=False) == ""


def test_the_notice_states_the_false_positive_claim_because_that_is_why_guards_get_uninstalled():
    """People uninstall guardrails over false positives, not over missed catches.

    Both examples in `_QUIET` are measured claims held by tests/test_predicates.py. If that
    sentence ever leaves the notice, the notice has stopped answering the question a new user
    actually has.
    """
    notice = welcome.first_run_notice(
        _armed(("git.reset_hard", "deny")), PACKS, ".provenrail.json", signed=False)
    assert "rm -rf ./build" in notice
    assert "git reset --hard" in notice
    assert "clean, pushed tree" in notice


def test_the_unsigned_notice_offers_the_cli_and_the_signed_one_does_not():
    """`signed` is the only honest difference between the free plugin and the paid CLI.

    Telling a user who already installed the CLI to install the CLI is the kind of stale
    instruction this module exists to prevent.
    """
    plugin = welcome.first_run_notice(
        _armed(("git.reset_hard", "deny")), PACKS, ".provenrail.json", signed=False)
    cli = welcome.first_run_notice(
        _armed(("git.reset_hard", "deny")), PACKS, ".provenrail.json", signed=True)
    assert "uv tool install provenrail" in plugin
    assert "/guard-card" in plugin
    assert "uv tool install provenrail" not in cli
    assert "pr guard card" in cli


def test_every_default_pack_has_a_title_so_the_notice_never_prints_a_bare_pack_id():
    """`_pack_of` falls back to the raw id when a pack has no title, which would leak
    `git-worktree` into a sentence meant for a human. Hold the catalogue to having titles."""
    for name in guard.DEFAULT_PACKS:
        assert rulesets.CATALOG[name].get("title"), name


def test_the_vendored_copy_is_identical_to_the_source_module():
    """The plugin runs its own copy with no Provenrail installed, so a drifted copy means the
    two engines describe themselves differently. `tools/vendor_guard_rules.py --check` is the
    build gate; this asserts the gate's subject directly."""
    assert VENDORED.is_file()
    source = (ROOT / "src" / "provenrail" / "welcome.py").read_text(encoding="utf-8")
    vendored = VENDORED.read_text(encoding="utf-8")
    assert source in vendored, "regenerate with python tools/vendor_guard_rules.py"


def test_the_vendored_module_imports_with_no_provenrail_on_the_path():
    """It is vendored precisely so it runs where the package does not exist. Import it the way
    the standalone hook does, from its own directory, with the repo off sys.path."""
    proc = subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(VENDORED.parent)!r}); import welcome; "
         "print(welcome.first_run_notice([{'id':'git.x','effect':'deny'}], "
         "{'git':{'title':'Git'}}, '.provenrail.json', False))"],
        capture_output=True, text=True, cwd=str(Path(VENDORED.parent)))
    assert proc.returncode == 0, proc.stderr
    # `_phrase` lower-cases titles so they read as part of a sentence, so match accordingly.
    assert "git (1)" in proc.stdout
