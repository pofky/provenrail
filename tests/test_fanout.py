"""The subagent fan-out cap.

The pain this exists for is public and unfixed: anthropics/claude-code #68619 (open, critical)
records 1.2M tokens in 30 minutes with recursion 50+ levels deep and the documented off switch
`CLAUDE_CODE_FORK_SUBAGENT=0` ignored, and #68110 records unbounded recursive spawning. What
this cap adds over the host's own behaviour is BREADTH: Claude Code already refuses at depth 3
of 3, so depth is the host's, and nothing anywhere caps how many subagents one session starts.

Every claim the site makes about this rule is a test here, because a claim in the copy is not
evidence the code keeps it.
"""

from __future__ import annotations

import pytest

from provenrail import guard, hosts, rulesets
from provenrail.easy import load_policy
from provenrail.policy import ALLOW, DENY, REQUIRE_OVERSIGHT, SessionState

RULE = "fan-out.subagent-spawn-cap"
CAP = 20


def spec() -> dict:
    r = rulesets.rule_by_id(RULE)
    assert r is not None, "the fan-out rule is not in the catalogue"
    return r


def test_the_cap_is_armed_by_default() -> None:
    """An opt-in cap protects nobody. The pack ships on."""
    assert "fan-out" in guard.DEFAULT_PACKS


def test_the_documented_cap_is_the_one_in_the_code() -> None:
    assert spec()["max_per_session"] == CAP


@pytest.mark.parametrize("tool", ["Task", "Agent"])
def test_both_spawn_tool_names_are_matched(tool: str) -> None:
    """Claude Code renamed Task to Agent. A rule naming one of them fires on half the hosts and
    reports itself armed on all of them, which is the failure mode this project has already
    paid for once."""
    policy = load_policy({"use": ["fan-out"]})
    state = SessionState()
    ctx = {"tool": tool, "match_text": "", "cwd": ""}
    for _ in range(CAP):
        assert policy.decide("tool_call", ctx, state).effect == ALLOW
    assert policy.decide("tool_call", ctx, state).effect == REQUIRE_OVERSIGHT


def test_the_cap_asks_rather_than_walls() -> None:
    """Wide fan-out is often exactly what the user wanted, so the cap is a question. A wall
    here would be uninstalled by lunchtime, which is how a guardrail stops guarding."""
    assert spec()["on_exceed"] == REQUIRE_OVERSIGHT


def test_ordinary_fan_out_is_never_interrupted() -> None:
    """Measured over 915 real sessions: 12% spawn at all, and among those the median is 4.
    A session doing the median amount of work must see nothing."""
    policy = load_policy({"use": ["fan-out"]})
    state = SessionState()
    ctx = {"tool": "Agent", "match_text": "", "cwd": ""}
    for _ in range(4):
        assert policy.decide("tool_call", ctx, state).effect == ALLOW


def test_a_recorded_oversight_lets_the_fan_out_continue() -> None:
    policy = load_policy({"use": ["fan-out"]})
    state = SessionState()
    ctx = {"tool": "Agent", "match_text": "", "cwd": ""}
    for _ in range(CAP + 1):
        policy.decide("tool_call", ctx, state)
    state.oversight_rules.add(RULE)
    assert policy.decide("tool_call", ctx, state).effect == ALLOW


def test_the_question_becomes_a_refusal_where_nobody_can_answer() -> None:
    """On a host with no permission prompt there is no human to say yes, and an unattended run
    is exactly the one that must stay bounded."""
    for host in hosts.HOSTS:
        expected = "ask" if hosts.supports_ask(host) else "deny"
        assert hosts.host_verdict(host, "ask") == expected, host


def test_the_cap_does_not_touch_any_other_tool() -> None:
    policy = load_policy({"use": ["fan-out"]})
    state = SessionState()
    for tool in ("Bash", "Read", "Write", "Edit", "WebFetch"):
        ctx = {"tool": tool, "match_text": "", "cwd": ""}
        for _ in range(CAP + 5):
            assert policy.decide("tool_call", ctx, state).effect == ALLOW, tool


def test_a_limit_still_denies_by_default() -> None:
    """`on_exceed` is an addition. A limit rule that does not name it must behave exactly as
    it did before, or every existing blast-radius cap quietly becomes a prompt."""
    policy = load_policy({"use": [], "rules": [
        {"id": "t.cap", "effect": "limit", "tool": "Bash", "max_per_session": 2},
    ]})
    state = SessionState()
    ctx = {"tool": "Bash", "match_text": "", "cwd": ""}
    for _ in range(2):
        assert policy.decide("tool_call", ctx, state).effect == ALLOW
    assert policy.decide("tool_call", ctx, state).effect == DENY


def test_a_misspelled_on_exceed_is_rejected_not_ignored() -> None:
    """Falling back to a wall where the rule asked for a question is a silent behaviour change,
    and the reverse would be a silent hole."""
    from provenrail.easy import PolicyConfigError

    with pytest.raises(PolicyConfigError, match="on_exceed"):
        load_policy({"use": [], "rules": [
            {"id": "t.cap", "effect": "limit", "tool": "Bash", "max_per_session": 2,
             "on_exceed": "aks"},
        ]})


def _report_with(sessions):
    from provenrail.report import Report, SessionStats

    r = Report()
    for i, (spawns, nested, side, cost) in enumerate(sessions):
        r.sessions[f"s{i}"] = SessionStats(session_id=f"s{i}", project=f"proj-{i}",
                                           spawns=spawns, nested_spawns=nested,
                                           sidechain_usd=side, cost_usd=cost)
    return r


def test_the_fanout_report_reads_the_cap_from_the_catalogue() -> None:
    """A second copy of the number would drift from the rule it describes."""
    from provenrail.report import render_fanout

    out = render_fanout(_report_with([(30, 0, 5.0, 10.0)]))
    assert f"shipped cap of {CAP}" in out


def test_the_fanout_report_says_so_when_nothing_spawned() -> None:
    """Silence would read as a broken command. A zero is a result."""
    from provenrail.report import render_fanout

    out = render_fanout(_report_with([(0, 0, 0.0, 1.0)]))
    assert "none of which spawned" in out


def test_the_fanout_report_survives_an_empty_corpus() -> None:
    from provenrail.report import Report, render_fanout

    assert "nothing to say" in render_fanout(Report())


def test_the_shareable_fanout_report_carries_no_project_names() -> None:
    """It is the number people are asked to post, so the posting-safe form is the one that
    has to be right: a project name is the operator's client list."""
    from provenrail.report import render_fanout

    out = render_fanout(_report_with([(40, 2, 9.0, 20.0)]), share=True)
    assert "proj-0" not in out


def test_the_fanout_report_carries_the_estimate_caveat() -> None:
    """Every figure derived from token counts says what it is, and on a flat-rate plan it is
    notional. A dollar figure presented as a bill is the mistake this caveat exists for."""
    from provenrail.report import render_fanout
    from provenrail.transcript import ESTIMATE_CAVEAT

    assert ESTIMATE_CAVEAT in render_fanout(_report_with([(40, 2, 9.0, 20.0)]))


def test_both_spawn_tool_names_are_counted_by_the_report() -> None:
    """The corpus spans the Task-to-Agent rename, so a report naming one of them reports a
    silent zero for every session recorded on the other side of it."""
    from provenrail.report import SPAWN_TOOLS

    assert set(SPAWN_TOOLS) == {"Task", "Agent"}
