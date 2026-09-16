"""`pr guard budget`: arming a spend cap in one command.

The reason this is a command rather than a default is the whole design. A cap nobody chose is a
claim about somebody else's money and would be wrong for almost everyone, so the product ships
with none at all; what it owes the user instead is one short command and a config file that
cannot quietly fail to bind. Everything below is about that second half: a value that could
never cap anything is refused here rather than written and discovered later.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from provenrail import cli

PLUGIN_COMMAND = (Path(__file__).resolve().parent.parent / "plugins" / "provenrail-guard" /
                  "commands" / "guard-budget.md")


@pytest.fixture()
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def config(project: Path) -> dict:
    return json.loads((project / ".provenrail.json").read_text(encoding="utf-8"))


def test_one_command_writes_a_cap_and_nothing_else(project):
    assert cli.main(["guard", "budget", "25"]) == 0
    assert config(project) == {"policy": {"budgets": [{"scope": "day", "limit_usd": 25}]}}


def test_setting_a_cap_preserves_the_packs_and_rules_already_configured(project):
    """The config file is the user's, not ours. Rewriting it around our own key would throw
    away the guardrails they came for."""
    (project / ".provenrail.json").write_text(json.dumps({
        "endpoint": "http://localhost:8000", "stream_id": "abc",
        "policy": {"use": ["destructive"],
                   "rules": [{"id": "x.y", "effect": "deny", "arg_contains": "zzz"}]}}),
        encoding="utf-8")
    assert cli.main(["guard", "budget", "25"]) == 0
    cfg = config(project)
    assert cfg["endpoint"] == "http://localhost:8000"
    assert cfg["stream_id"] == "abc"
    assert cfg["policy"]["use"] == ["destructive"]
    assert cfg["policy"]["rules"][0]["id"] == "x.y"
    assert cfg["policy"]["budgets"] == [{"scope": "day", "limit_usd": 25}]


def test_the_default_scope_is_the_one_that_catches_an_overnight_run(project):
    """`session` cannot see the failure everyone actually has, which is an agent running all
    night across hundreds of short sessions."""
    cli.main(["guard", "budget", "25"])
    assert config(project)["policy"]["budgets"][0]["scope"] == "day"


@pytest.mark.parametrize("scope", ["session", "day", "total"])
def test_every_scope_the_engine_understands_can_be_set(project, scope):
    assert cli.main(["guard", "budget", "5", "--scope", scope]) == 0
    assert config(project)["policy"]["budgets"][0]["scope"] == scope


def test_warn_at_is_written_only_when_it_is_asked_for(project):
    """A written-out default is a claim; an absent one is the engine's documented 0.8."""
    cli.main(["guard", "budget", "25"])
    assert "warn_at" not in config(project)["policy"]["budgets"][0]
    cli.main(["guard", "budget", "25", "--warn-at", "0.5", "--replace"])
    assert config(project)["policy"]["budgets"][0]["warn_at"] == 0.5


def test_a_second_cap_at_the_same_scope_is_refused_unless_replacing(project, capsys):
    """Two caps at one scope is a config where the tighter one binds and the one you just typed
    looks like it did nothing."""
    cli.main(["guard", "budget", "25"])
    assert cli.main(["guard", "budget", "50"]) == 2
    assert "--replace" in capsys.readouterr().out
    assert config(project)["policy"]["budgets"] == [{"scope": "day", "limit_usd": 25}]
    assert cli.main(["guard", "budget", "50", "--replace"]) == 0
    assert config(project)["policy"]["budgets"] == [{"scope": "day", "limit_usd": 50}]


def test_a_cap_at_another_scope_is_added_alongside(project):
    cli.main(["guard", "budget", "25"])
    cli.main(["guard", "budget", "5", "--scope", "session"])
    scopes = [b["scope"] for b in config(project)["policy"]["budgets"]]
    assert sorted(scopes) == ["day", "session"]


@pytest.mark.parametrize("amount,expected", [
    ("abc", 'needs a numeric "limit_usd"'),
    ("0", "must be greater than zero"),
    ("-5", "must be greater than zero"),
])
def test_a_value_that_could_never_cap_anything_is_refused_with_the_engines_own_message(
        project, capsys, amount, expected):
    """Refused by `easy._validate_budgets`, so the sentence is the same whether the bad value
    was typed here or hand-edited into the file."""
    assert cli.main(["guard", "budget", amount]) == 2
    assert expected in capsys.readouterr().out
    assert not (project / ".provenrail.json").exists()


def test_a_warn_threshold_outside_the_range_is_refused(project, capsys):
    assert cli.main(["guard", "budget", "25", "--warn-at", "2"]) == 2
    assert "between 0 and 1" in capsys.readouterr().out


def test_no_amount_at_all_refuses_to_invent_one(project, capsys):
    """There is no default cap, and the command says why rather than picking a number."""
    assert cli.main(["guard", "budget"]) == 2
    out = capsys.readouterr().out
    assert "no default cap" in out
    assert not (project / ".provenrail.json").exists()


def test_the_cap_is_shown_by_guard_status_with_the_estimate_caveat(project, capsys):
    cli.main(["guard", "budget", "25"])
    capsys.readouterr()
    cli.main(["guard", "status"])
    out = capsys.readouterr().out
    assert "budget.day" in out
    assert "$25.00" in out
    assert "estimated at API list price" in out


def test_setting_a_cap_in_a_fresh_project_does_not_disarm_the_rules(project, capsys):
    """The file this writes has no `use` key, and a policy block with no `use` and no `rules`
    used to mean "the user chose to run with no rules". So `pr guard budget 25` on a fresh
    install switched off every destructive rule while reporting a cap as armed: turning one
    control on turned another one off, silently, which is the one failure a guard cannot have."""
    cli.main(["guard", "budget", "25"])
    capsys.readouterr()
    cli.main(["guard", "status"])
    out = capsys.readouterr().out
    assert "NONE ARMED" not in out
    assert "0 rules armed" not in out
    assert "budget.day" in out


def test_an_explicit_empty_use_is_still_a_decision_to_arm_nothing(project, capsys):
    """Whoever wrote `"use": []` outranks our defaults, and adding a cap must not overturn it."""
    (project / ".provenrail.json").write_text(json.dumps({"policy": {"use": []}}),
                                              encoding="utf-8")
    cli.main(["guard", "budget", "25"])
    capsys.readouterr()
    cli.main(["guard", "status"])
    assert "0 rules armed" in capsys.readouterr().out


def test_the_written_file_is_a_policy_the_engine_actually_loads(project):
    """A command that writes a file the loader then rejects would arm nothing while reporting
    success, which is the failure mode this whole feature is about."""
    from provenrail.easy import load_policy

    cli.main(["guard", "budget", "25", "--warn-at", "0.5"])
    policy = load_policy(config(project)["policy"])
    assert [(b.scope, b.limit_usd, b.warn_at) for b in policy.effective_budgets()] == \
        [("day", 25.0, 0.5)]


# ---------------------------------------------------------------- the zero-install twin


def test_the_slash_command_writes_the_same_file_with_no_cli_installed(project):
    """`/guard-budget 25` is the only way in for the people the plugin exists for, who have not
    installed anything. If it wrote a different shape, their cap would be the one that does not
    bind."""
    script = _python_block(PLUGIN_COMMAND.read_text(encoding="utf-8"))
    proc = subprocess.run([sys.executable, "-c", script, "25"], capture_output=True, text=True,
                          cwd=str(project))
    assert proc.returncode == 0, proc.stderr
    assert config(project) == {"policy": {"budgets": [{"scope": "day", "limit_usd": 25}]}}


def test_the_slash_command_refuses_the_same_values_the_cli_refuses(project):
    script = _python_block(PLUGIN_COMMAND.read_text(encoding="utf-8"))
    for amount in ("abc", "0", "-5"):
        proc = subprocess.run([sys.executable, "-c", script, amount], capture_output=True,
                              text=True, cwd=str(project))
        assert proc.returncode != 0, amount
        assert not (project / ".provenrail.json").exists()


def test_the_slash_command_refuses_a_second_cap_at_the_same_scope(project):
    script = _python_block(PLUGIN_COMMAND.read_text(encoding="utf-8"))
    subprocess.run([sys.executable, "-c", script, "25"], capture_output=True, cwd=str(project))
    proc = subprocess.run([sys.executable, "-c", script, "50"], capture_output=True, text=True,
                          cwd=str(project))
    assert proc.returncode != 0
    assert "--replace" in proc.stderr
    assert config(project)["policy"]["budgets"] == [{"scope": "day", "limit_usd": 25}]


def test_the_slash_command_never_invents_a_cap_of_its_own(project):
    """Run with no argument it must refuse, and the prose has to tell the reader not to pick a
    number either: the command file is read by a model, and a model will happily choose 100."""
    script = _python_block(PLUGIN_COMMAND.read_text(encoding="utf-8"))
    proc = subprocess.run([sys.executable, "-c", script, ""], capture_output=True, text=True,
                          cwd=str(project))
    assert proc.returncode != 0
    assert not (project / ".provenrail.json").exists()
    text = PLUGIN_COMMAND.read_text(encoding="utf-8")
    assert "do not pick one" in text
    assert "There is no default cap" in text
    # No em-dashes or en-dashes anywhere in copy the user reads.
    assert "—" not in text and "–" not in text


def _python_block(markdown: str) -> str:
    """The heredoc the command runs when no CLI is installed."""
    start = markdown.index("python3 - \"$ARGUMENTS\" <<'PY'")
    body = markdown[markdown.index("\n", start) + 1:]
    return body[:body.index("\nPY\n")]
