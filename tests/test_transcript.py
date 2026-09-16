"""Reading spend off a coding agent's transcript, which is the only place a tool hook can see it.

The failure these defend against is not an incorrect total, it is a total that looks correct.
A transcript read that silently returns $0.00 after a truncated write, or that charges the same
streamed message once per chunk, produces a spend cap that reports itself armed and either binds
nothing or denies the first tool call of the morning. Both are worse than having no cap.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from provenrail import transcript

FIXTURE = Path(__file__).parent / "fixtures" / "transcripts" / "claude-code-spend.jsonl"

#: The fixture labels every line with the cost a human computed for it from the published rates.
#: Summing the labels and comparing against the code is a check of the code against arithmetic;
#: recomputing the expectation with `pricing.cost_for` would only check the code against itself.
FIXTURE_LINES = [json.loads(line) for line in
                 FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]
FIXTURE_TOTAL_USD = sum(line.get("_expected_usd", 0.0) for line in FIXTURE_LINES)
SPLIT_AT = next(i for i, line in enumerate(FIXTURE_LINES) if line.get("_split"))
PREFIX_TOTAL_USD = sum(line.get("_expected_usd", 0.0) for line in FIXTURE_LINES[:SPLIT_AT])


def write_lines(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def assistant(message_id: str, input_tokens: int, model: str = "claude-sonnet-4-5") -> dict:
    return {"type": "assistant", "uuid": f"u-{message_id}-{input_tokens}",
            "message": {"id": message_id, "role": "assistant", "model": model,
                        "usage": {"input_tokens": input_tokens, "output_tokens": 0}}}


# $3.00 per million input tokens, so 100,000 input tokens is $0.30.
ONE_MESSAGE_USD = 0.30


def test_three_assistant_messages_are_summed(tmp_path):
    path = tmp_path / "t.jsonl"
    write_lines(path, [assistant("a", 100_000), assistant("b", 100_000), assistant("c", 100_000)])
    cost, unpriced, state = transcript.accrue(path)
    assert cost == pytest.approx(3 * ONE_MESSAGE_USD)
    assert unpriced == 0
    assert state.known is True


def test_a_streamed_message_written_several_times_is_charged_once(tmp_path):
    """Claude Code writes one line per chunk of a streaming reply, all sharing message.id, and
    the last carries the final usage. Charging every line would multiply a turn by its chunk
    count and blow a correct cap by lunchtime."""
    path = tmp_path / "t.jsonl"
    write_lines(path, [assistant("a", 20_000), assistant("a", 60_000), assistant("a", 100_000)])
    cost, _, _ = transcript.accrue(path)
    assert cost == pytest.approx(ONE_MESSAGE_USD)


def test_a_later_line_for_the_same_message_only_ever_adds_the_increase(tmp_path):
    """The partials arrive across separate hook processes too, so the correction has to survive
    a round trip through the state file."""
    path = tmp_path / "t.jsonl"
    write_lines(path, [assistant("a", 20_000)])
    first, _, state = transcript.accrue(path)
    state = transcript.TranscriptState.from_dict(state.to_dict())
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(assistant("a", 100_000)) + "\n")
    second, _, state = transcript.accrue(path, state)
    assert first + second == pytest.approx(ONE_MESSAGE_USD)
    assert state.session_usd == pytest.approx(ONE_MESSAGE_USD)


def test_a_model_with_no_verified_price_is_reported_unpriced_and_never_as_free(tmp_path):
    """$0.00 added to a cap never crosses it, so an unpriced model silently stops a budget
    binding. The count is what lets the caller say the total is a floor."""
    path = tmp_path / "t.jsonl"
    write_lines(path, [assistant("a", 100_000, model="grok-4-fast")])
    cost, unpriced, state = transcript.accrue(path)
    assert cost == 0.0
    assert unpriced == 1
    assert state.unpriced_calls == 1


def test_resuming_from_a_saved_offset_counts_nothing_twice(tmp_path):
    path = tmp_path / "t.jsonl"
    write_lines(path, [assistant("a", 100_000)])
    first, _, state = transcript.accrue(path)
    again, _, state = transcript.accrue(path, state)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(assistant("b", 100_000)) + "\n")
    third, _, state = transcript.accrue(path, state)
    assert (first, again, third) == (pytest.approx(ONE_MESSAGE_USD), 0.0,
                                     pytest.approx(ONE_MESSAGE_USD))
    assert state.session_usd == pytest.approx(2 * ONE_MESSAGE_USD)


def test_a_file_that_shrank_resets_the_offset_and_reports_the_total_as_unknown(tmp_path):
    """A rotated or truncated transcript has taken real spend with it. Restarting at zero while
    still claiming the figure is authoritative would hand a blown cap its headroom back."""
    path = tmp_path / "t.jsonl"
    write_lines(path, [assistant("a", 100_000), assistant("b", 100_000)])
    _, _, state = transcript.accrue(path)
    assert state.offset > 0
    write_lines(path, [assistant("c", 100_000)])
    cost, _, state = transcript.accrue(path, state)
    assert state.known is False
    assert cost == pytest.approx(ONE_MESSAGE_USD)
    assert state.offset == path.stat().st_size


def test_an_unreadable_transcript_is_unknown_rather_than_zero(tmp_path):
    cost, unpriced, state = transcript.accrue(tmp_path / "does-not-exist.jsonl")
    assert (cost, unpriced) == (0.0, 0)
    assert state.known is False


def test_a_line_that_is_not_json_makes_the_total_a_floor_instead_of_being_skipped(tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text(json.dumps(assistant("a", 100_000)) + "\n{ truncated\n", encoding="utf-8")
    cost, _, state = transcript.accrue(path)
    assert cost == pytest.approx(ONE_MESSAGE_USD)
    assert state.known is False


def test_a_half_written_final_line_is_left_for_the_next_read(tmp_path):
    """The hooks documentation says the transcript is written asynchronously and may lag, so the
    tail is routinely a partial line. Consuming it would skip that message's cost forever."""
    path = tmp_path / "t.jsonl"
    complete = json.dumps(assistant("a", 100_000)) + "\n"
    partial = json.dumps(assistant("b", 100_000))
    path.write_text(complete + partial[:40], encoding="utf-8")
    cost, _, state = transcript.accrue(path)
    assert cost == pytest.approx(ONE_MESSAGE_USD)
    assert state.offset == len(complete)
    path.write_text(complete + partial + "\n", encoding="utf-8")
    rest, _, state = transcript.accrue(path, state)
    assert rest == pytest.approx(ONE_MESSAGE_USD)


def test_user_lines_and_assistant_lines_without_usage_cost_nothing(tmp_path):
    path = tmp_path / "t.jsonl"
    write_lines(path, [
        {"type": "user", "message": {"role": "user", "content": "hello"}},
        {"type": "assistant", "message": {"id": "x", "model": "claude-sonnet-4-5"}},
        {"type": "system", "subtype": "hook", "message": {"usage": {"input_tokens": 999_999}}},
    ])
    cost, unpriced, _ = transcript.accrue(path)
    assert (cost, unpriced) == (0.0, 0)


def test_a_mangled_state_file_does_not_read_as_a_fresh_transcript(tmp_path):
    """Reading it as offset zero would re-price the whole transcript and charge it again."""
    state = transcript.TranscriptState.from_dict({"offset": "not a number"})
    assert state.known is False
    assert transcript.TranscriptState.from_dict(None).known is False


def test_the_state_survives_the_json_round_trip_the_guard_puts_it_through(tmp_path):
    path = tmp_path / "t.jsonl"
    write_lines(path, [assistant("a", 100_000)])
    _, _, state = transcript.accrue(path)
    restored = transcript.TranscriptState.from_dict(json.loads(json.dumps(state.to_dict())))
    assert (restored.offset, restored.session_usd) == (state.offset, state.session_usd)
    assert restored.charged == state.charged


# ---------------------------------------------------------------- the labelled fixture


def test_the_fixture_costs_what_its_own_labels_say_it_costs():
    """Every line of the fixture carries the dollar figure a human computed for it from the
    published rates. If the reader and the arithmetic disagree, one of them is wrong and this is
    the only test in the suite that can tell."""
    cost, unpriced, state = transcript.accrue(FIXTURE)
    assert cost == pytest.approx(FIXTURE_TOTAL_USD)
    assert unpriced == 1
    assert state.known is True


def test_the_fixture_prefix_is_the_documented_fraction_of_the_cap(tmp_path):
    """The budget tests write the fixture up to its split marker to stand under a $1.00 cap and
    over the 80% warning line. If that stops being true those tests stop testing what they say."""
    assert 0.8 <= PREFIX_TOTAL_USD < 1.0
    assert FIXTURE_TOTAL_USD > 1.0
    path = tmp_path / "t.jsonl"
    write_lines(path, FIXTURE_LINES[:SPLIT_AT])
    cost, _, _ = transcript.accrue(path)
    assert cost == pytest.approx(PREFIX_TOTAL_USD)


# ---------------------------------------------------------------- the verdict both engines use


def test_a_cap_that_is_over_denies_and_names_the_file_that_raises_it():
    answer = transcript.verdict_for([("budget.day", "day", 1.0, 0.8)], {"day": 1.5}, 0, "warn",
                                    ".provenrail.json")
    verdict, rule, reason = answer
    assert (verdict, rule) == ("deny", "budget.day")
    assert "$1.5000" in reason and "$1.0000" in reason
    assert ".provenrail.json" in reason
    assert transcript.ESTIMATE_CAVEAT in reason


def test_a_cap_that_is_merely_close_allows_and_warns():
    verdict, rule, warning = transcript.verdict_for(
        [("budget.day", "day", 1.0, 0.8)], {"day": 0.9}, 0, "warn", ".provenrail.json")
    assert (verdict, rule) == ("allow", "")
    assert "90%" in warning


def test_a_cap_with_room_left_says_nothing_at_all():
    assert transcript.verdict_for([("budget.day", "day", 1.0, 0.8)], {"day": 0.1}, 0, "warn",
                                  ".provenrail.json") is None
    assert transcript.verdict_for([], {"day": 99.0}, 0, "warn", ".provenrail.json") is None


def test_an_unpriced_call_warns_by_default_and_denies_when_the_policy_says_so():
    warn = transcript.verdict_for([("budget.day", "day", 1.0, 0.8)], {"day": 0.0}, 2, "warn",
                                  ".provenrail.json")
    assert warn[0] == "allow" and "floor" in warn[2]
    deny = transcript.verdict_for([("budget.day", "day", 1.0, 0.8)], {"day": 0.0}, 2, "deny",
                                  ".provenrail.json")
    assert (deny[0], deny[1]) == ("deny", "budget.unpriced")


def test_a_blown_cap_outranks_the_unpriced_warning():
    """The warning must not become the answer: an agent told "some calls are unpriced" would
    carry on spending past a cap that is already over."""
    verdict, rule, _ = transcript.verdict_for([("budget.day", "day", 1.0, 0.8)], {"day": 2.0},
                                              3, "warn", ".provenrail.json")
    assert (verdict, rule) == ("deny", "budget.day")


def test_every_dollar_figure_shown_to_a_person_carries_the_estimate_caveat():
    """On Pro and Max there is no per-token charge at all, so an unqualified dollar amount would
    be a claim about the user's money that we cannot defend."""
    assert "list price" in transcript.ESTIMATE_CAVEAT
    assert "Pro and Max" in transcript.ESTIMATE_CAVEAT
    deny = transcript.deny_reason("day", 2.0, 1.0, ".provenrail.json")
    warn = transcript.warn_reason("budget.day", "day", 0.9, 1.0)
    assert transcript.ESTIMATE_CAVEAT in deny
    assert transcript.ESTIMATE_CAVEAT in warn
    for text in (deny, warn, transcript.unpriced_reason(1, deny=False)):
        assert "—" not in text and "–" not in text
