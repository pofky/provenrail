"""`pr report`, the command a stranger runs first.

Four properties are worth a test here, and they are the four that decide whether the report is
worth running at all rather than whether the arithmetic is tidy.

It must stay offline, because a tool that reads every transcript on the machine and then opens
a socket is one nobody can run at work. It must never turn something it could not read into a
zero, because a total reported on authority gets acted on. It must charge one model call once,
however many times the transcript wrote it down. And `--share` must be postable without being
read first, which is the same property `tests/test_guard_card.py` holds for the card and is
tested here against the same regex, not against a second copy of it.

The corpus under `fixtures/transcripts/report-corpus/` is synthetic and says so on its first
line. Its paths, keys, hosts and project names are invented and several of them are
deliberately identifying, so that the share test has something real to fail on.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from provenrail import report as report_mod
from provenrail import transcript
from tests.test_guard_card import IDENTIFYING

CORPUS = Path(__file__).parent / "fixtures" / "transcripts" / "report-corpus"
SPEND_FIXTURE = Path(__file__).parent / "fixtures" / "transcripts" / "claude-code-spend.jsonl"

#: Every dollar in the fixture corpus: seven priced calls of 100,000 input tokens at the
#: published claude-sonnet-4-5 input rate of $3.00/M, which is $0.30 each. Written out rather
#: than read from the code so the test checks the report against arithmetic, not against itself.
EXPECTED_USD = 7 * 0.30


@pytest.fixture(scope="module")
def built():
    return report_mod.build(CORPUS)


def test_a_transcript_with_a_line_that_cannot_be_read_is_counted_as_unread_not_as_empty(built):
    assert built.unreadable_transcripts == 1
    assert built.unreadable_lines == 1
    text = report_mod.render_text(built)
    assert "could not be read" in text
    assert "floor" in text


def test_a_model_with_no_verified_rate_is_reported_as_unpriced_and_never_as_free(built):
    assert built.unpriced_calls == 1
    assert "grok-4-fast" in built.unpriced_models
    assert built.model_cost.get("grok-4-fast", 0.0) == 0.0
    assert "unpriced" in report_mod.render_text(built)
    rows = {row["model"]: row for row in report_mod.as_json(built)["cost"]["by_model"]}
    assert rows["grok-4-fast"]["priced"] is False
    assert rows["claude-sonnet-4-5"]["priced"] is True


def test_an_assistant_line_carrying_no_usage_costs_nothing_and_is_not_counted_as_a_call(built):
    """The fixture holds one assistant line with no `usage` at all. Pricing it as $0.00 would
    be a guess dressed as a measurement, and counting it as a call would say the corpus has more
    priced model calls in it than it does."""
    assert built.model_calls == 9      # eight with usage, plus the zero-token line below
    assert built.estimated_usd == pytest.approx(EXPECTED_USD, abs=0.005)


def test_a_call_that_reported_no_tokens_is_free_with_certainty_and_not_called_unpriced(built):
    """Claude Code writes assistant text it generated itself under the model name
    `<synthetic>`, with every token count zero. There is no rate for it and there does not need
    to be: zero tokens cost zero at every rate, so calling it unpriced declared the total
    uncertain by exactly nothing and buried the calls that really are uncertain."""
    assert "<synthetic>" in built.by_model
    assert "<synthetic>" not in built.unpriced_models
    assert built.unpriced_calls == 1


def test_a_model_call_copied_into_a_resumed_session_is_charged_exactly_once(built):
    """Two shapes of the same failure. A streamed reply is written to the transcript three
    times as it grows, and a forked session is a whole second file carrying a copy of the first
    one's history. Charging either one per line multiplies the invoice by the transcript's
    formatting."""
    assert built.repeat_lines_folded == 3
    assert built.estimated_usd == pytest.approx(EXPECTED_USD, abs=0.005)
    # And the fork is still its own session, because it is: two sessions ran.
    assert {"sess-alpha-1", "sess-alpha-2"} <= set(built.sessions)


def test_the_report_prices_a_transcript_to_the_same_total_as_the_spend_cap_does():
    """`transcript.accrue` is the reader a live budget cap uses and this is the reader a report
    uses, and the two would eventually disagree about what one turn cost. They are pinned to
    each other over the shared fixture instead of to a number written down twice."""
    expected, _unpriced, _state = transcript.accrue(SPEND_FIXTURE)
    built = report_mod.build(SPEND_FIXTURE.parent, project="synthetic")
    assert built.estimated_usd == pytest.approx(expected, abs=1e-6)


def test_a_dangerous_command_in_a_transcript_is_reported_as_one_the_guard_would_have_stopped(built):
    fired = {rule for rule, _verdict in built.by_rule}
    assert "production.terraform-destroy" in fired
    assert "git-worktree.reset-hard" in fired
    assert built.deny + built.ask == 3
    # `git status --short` and `pytest -q` are ordinary work and must not appear.
    assert built.screened == 8
    assert built.deny + built.ask < built.screened


def test_a_session_that_ended_in_the_middle_of_a_tool_call_is_counted_as_abandoned(built):
    """The signal is a tool_use whose result never arrived, which is what a killed or
    interrupted session leaves behind. Counting sessions by their last line instead reports
    every session as abandoned, because the last line of a transcript is host bookkeeping."""
    assert built.abandoned == 1
    assert built.sessions["sess-beta-2"].pending


def test_blast_radius_names_the_packs_that_fired_rather_than_a_second_list_of_categories(built):
    titles = {row["title"] for row in report_mod.as_json(built)["blast_radius"]["by_pack"]}
    assert "Losing uncommitted work" in titles
    assert "Production infrastructure" in titles
    busiest = report_mod.as_json(built)["blast_radius"]["busiest_session"]
    assert busiest["files"] == 1


def test_the_hosts_own_total_is_printed_beside_ours_rather_than_reconciled_away(built):
    """A `cost-state` line is the one figure in a transcript this code did not produce, so it is
    the only second opinion available. Adopting it would hide a disagreement and dropping it
    would hide that a second opinion existed, so both numbers are printed, over exactly the
    sessions that have both."""
    cross = report_mod.as_json(built)["cost"]["host_crosscheck"]
    assert cross == {"sessions": 1, "host_recorded_usd": 1.0, "estimated_here_usd": 0.9}
    assert "Claude Code recorded its own total" in report_mod.render_text(built)


#: What one line built by `_call` is worth: 100,000 input tokens at the published
#: claude-sonnet-4-5 input rate of $3.00/M. Written out rather than read from the price table so
#: the tests below check the report against arithmetic and not against itself.
CALL_USD = 0.30


def _call(session: str, msg_id: str, stamp: str) -> str:
    """One assistant line of the shape verified on 2026-09-16, worth `CALL_USD`.

    The same `msg_id` under two session ids is what a fork's copied history looks like on disk.
    """
    return json.dumps({
        "type": "assistant", "uuid": f"u-{session}-{msg_id}", "sessionId": session,
        "timestamp": stamp, "cwd": "/Users/dana/Projects/acme-billing",
        "message": {"id": msg_id, "role": "assistant", "model": "claude-sonnet-4-5",
                    "usage": {"input_tokens": 100_000, "output_tokens": 0,
                              "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
                    "content": [{"type": "text", "text": "(elided)"}]}})


def _host_total(session: str, usd: float) -> str:
    return json.dumps({"type": "cost-state", "sessionId": session, "totalCostUSD": usd})


def _transcript(path: Path, lines: list[str], mtime: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if mtime:
        stamp = time.mktime(time.strptime(mtime, "%Y-%m-%d"))
        os.utime(path, (stamp, stamp))


def test_a_model_call_that_two_sessions_both_hold_is_credited_to_each_of_their_own_totals(
        tmp_path):
    """The host writes one running total per session, and a session that shares a message id
    with another one, as a fork's copied history does, still spent that money. Deduplicating
    across the corpus charges the call to whichever file was read first, which is right for the
    corpus total and leaves the other session cross-checked against a figure with a hole in it.
    So the cross-check deduplicates inside one session and the total keeps deduplicating across
    all of them."""
    root = tmp_path / "projects" / "-Users-dana-Projects-acme-billing"
    _transcript(root / "s-first.jsonl",
                [_call("s-first", "msg_shared", "2026-09-14T10:00:00.000Z"),
                 _call("s-first", "msg_first", "2026-09-14T10:01:00.000Z"),
                 _host_total("s-first", 0.60)])
    _transcript(root / "s-second.jsonl",
                [_call("s-second", "msg_shared", "2026-09-14T11:00:00.000Z"),
                 _call("s-second", "msg_second", "2026-09-14T11:01:00.000Z"),
                 _host_total("s-second", 0.60)])

    built = report_mod.build(tmp_path / "projects")
    cross = report_mod.as_json(built)["cost"]["host_crosscheck"]
    assert cross["sessions"] == 2
    assert cross["estimated_here_usd"] == pytest.approx(4 * CALL_USD, abs=0.005)
    # And the shared call is still charged to the corpus exactly once, which is the whole reason
    # the dedupe is corpus-wide in the first place.
    assert built.estimated_usd == pytest.approx(3 * CALL_USD, abs=0.005)


def test_a_session_the_date_filter_cut_in_half_is_cross_checked_over_the_whole_of_it(tmp_path):
    """`--since` narrows the report, and the host's `cost-state` line is written whatever the
    report was asked for: it totals the session end to end. Comparing the two printed a
    session's whole life against one day of it as though the numbers disagreed, and on the
    corpus this was written against that read as $359.62 against $4.52."""
    root = tmp_path / "projects" / "-Users-dana-Projects-acme-billing"
    _transcript(root / "s-long.jsonl",
                [_call("s-long", "msg_old_1", "2026-09-14T10:00:00.000Z"),
                 _call("s-long", "msg_old_2", "2026-09-14T10:01:00.000Z"),
                 _call("s-long", "msg_new", "2026-09-16T10:00:00.000Z"),
                 _host_total("s-long", 0.90)])

    built = report_mod.build(tmp_path / "projects", since="2026-09-16")
    # The report itself still answers the question that was asked: one day of that session.
    assert built.estimated_usd == pytest.approx(CALL_USD, abs=0.005)
    cross = report_mod.as_json(built)["cost"]["host_crosscheck"]
    assert cross["estimated_here_usd"] == pytest.approx(3 * CALL_USD, abs=0.005)
    assert "end to end" in report_mod.render_text(built)


def test_a_subagent_transcript_older_than_the_cutoff_still_counts_against_the_hosts_total(
        tmp_path):
    """A session is more than one file. Claude Code writes each subagent's turns to
    `<session id>/subagents/agent-*.jsonl`, stamped with the subagent's own mtime, so `--since`
    skipped all twenty-eight of one session's subagent files on the corpus this was written
    against and cross-checked it as though its subagents had cost nothing."""
    root = tmp_path / "projects" / "-Users-dana-Projects-acme-billing"
    _transcript(root / "s-parent.jsonl",
                [_call("s-parent", "msg_new", "2026-09-16T10:00:00.000Z"),
                 _host_total("s-parent", 0.60)])
    _transcript(root / "s-parent" / "subagents" / "agent-a1.jsonl",
                [_call("s-parent", "msg_agent", "2026-09-14T09:00:00.000Z")],
                mtime="2026-09-14")

    built = report_mod.build(tmp_path / "projects", since="2026-09-16")
    assert built.estimated_usd == pytest.approx(CALL_USD, abs=0.005)
    cross = report_mod.as_json(built)["cost"]["host_crosscheck"]
    assert cross["estimated_here_usd"] == pytest.approx(2 * CALL_USD, abs=0.005)
    # A file this opened is one it read, so the count of transcripts read and the count skipped
    # as older both have to move. Printing "1 skipped as older" over a file that was opened
    # anyway is the same class of untrue as the figure this test exists for.
    assert (built.transcripts, built.skipped_by_since) == (2, 0)


# ---------------------------------------------------------------- shareable


def test_the_shared_report_carries_nothing_identifying():
    """The whole point of `--share`: the launch post is this output, and a thing you have to
    read line by line before pasting does not get pasted."""
    built = report_mod.build(CORPUS)
    text = report_mod.render_text(built, share=True)
    leak = IDENTIFYING.search(text)
    assert not leak, f"--share leaked {leak.group(0)!r}:\n{text}"
    assert "acme-billing" not in text
    assert "zephyr-internal" not in text
    assert str(CORPUS) not in text


def test_the_shared_report_carries_nothing_identifying_over_the_whole_dangerous_corpus(tmp_path):
    """The same property `tests/test_guard_card.py` holds for the card, asked of the report and
    driven through a real transcript rather than asserted about the reducer. Those corpora are
    the dangerous commands precisely because they are the ones that reach a shared summary, and
    they are full of home directories, buckets, hostnames and keys."""
    from tests.test_guard_card import SHAPES
    from tests.test_predicates import DATA_INCIDENTS, GIT_INCIDENTS, UNRECOVERABLE

    commands = GIT_INCIDENTS + DATA_INCIDENTS + UNRECOVERABLE + [c for c, _ in SHAPES]
    root = tmp_path / "projects" / "-Users-ana-clients-northwind"
    root.mkdir(parents=True)
    lines = []
    for i, command in enumerate(commands):
        lines.append(json.dumps({
            "type": "assistant", "uuid": f"u{i}", "sessionId": "s-1",
            "timestamp": "2026-09-14T10:00:00.000Z", "cwd": "/Users/ana/clients/northwind",
            "message": {"id": f"msg_{i}", "role": "assistant", "model": "claude-sonnet-4-5",
                        "usage": {"input_tokens": 10, "output_tokens": 1},
                        "content": [{"type": "tool_use", "id": f"t{i}", "name": "Bash",
                                     "input": {"command": command}}]}}))
    (root / "s-1.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    built = report_mod.build(tmp_path / "projects")
    assert built.deny + built.ask > 20, "the corpus should have set the guard off repeatedly"
    for text in (report_mod.render_text(built, share=True),
                 json.dumps(report_mod.as_json(built, share=True))):
        leak = IDENTIFYING.search(text)
        assert not leak, f"--share leaked {leak.group(0)!r} out of the dangerous corpus"
        assert "northwind" not in text
    # Not only the rows that made the top of a table: every shape the report holds at all,
    # because which ones get printed depends on how often they happened to be run.
    for shape in list(built.bash_shapes) + [shape for shape, _verdict in built.by_shape]:
        assert not IDENTIFYING.search(shape), f"{shape!r} would have been printable"


def test_the_shared_json_carries_nothing_identifying():
    built = report_mod.build(CORPUS)
    blob = json.dumps(report_mod.as_json(built, share=True))
    leak = IDENTIFYING.search(blob)
    assert not leak, f"--share --json leaked {leak.group(0)!r}"
    assert blob.count("acme-billing") == 0
    assert json.loads(blob)["root"] is None


def test_the_plain_report_does_show_the_user_their_own_paths():
    """It is their machine and their data, and a report that hides it from them is useless.
    The redaction is a thing `--share` does, not a thing the tool does to its own owner."""
    text = report_mod.render_text(report_mod.build(CORPUS))
    assert "acme-billing" in text
    assert str(CORPUS) in text


def test_a_project_the_user_named_themselves_is_not_hidden_from_the_shared_report():
    """`--project acme-billing` means the user typed that name and asked for a report about it.
    Hashing it back out would be theatre, and would make the output impossible to read."""
    built = report_mod.build(CORPUS, project="acme-billing")
    assert "acme-billing" in report_mod.render_text(built, share=True)
    assert {"sess-alpha-1", "sess-alpha-2"} == set(built.sessions)


# ---------------------------------------------------------------- offline, and cheap


def test_the_report_never_opens_a_socket(monkeypatch):
    """Asserted by breaking the network rather than by reading the code, because the import
    graph is what would eventually reach out, not this file."""

    def refuse(*args, **kwargs):
        raise AssertionError("pr report opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    built = report_mod.build(CORPUS)
    report_mod.render_text(built)
    report_mod.as_json(built)


def test_since_skips_a_transcript_written_before_the_cutoff_without_opening_it():
    """The point of `--since` is that the common case does not read 3.5 GB. A transcript is
    appended to, so its mtime is the time of its last line and one older than the cutoff can
    hold nothing after it."""
    built = report_mod.build(CORPUS, since="2099-01-01")
    assert built.skipped_by_since == 5
    assert built.transcripts == 0
    assert built.estimated_usd == 0.0


def test_a_bad_since_date_says_so_rather_than_reporting_an_empty_corpus():
    with pytest.raises(ValueError):
        report_mod.build(CORPUS, since="last tuesday")


def test_a_directory_with_no_transcripts_says_where_it_looked(tmp_path):
    with pytest.raises(FileNotFoundError) as caught:
        report_mod.build(tmp_path / "nope")
    assert "~/.claude/projects" in str(caught.value)


# ---------------------------------------------------------------- the documented shapes


def test_the_json_document_keeps_the_shape_its_schema_promises(built):
    doc = report_mod.as_json(built)
    assert doc["schema"] == report_mod.SCHEMA
    assert set(doc) == {"schema", "root", "since", "share", "read", "cost", "activity", "risk",
                        "blast_radius", "projects"}
    assert set(doc["read"]) == {"transcripts", "unreadable_transcripts", "unreadable_lines",
                                "bytes", "skipped_by_since", "seconds"}
    assert set(doc["cost"]) == {"estimated_usd", "caveat", "model_calls", "unpriced_calls",
                                "repeat_lines_folded", "host_crosscheck", "by_model"}
    assert set(doc["activity"]) == {"sessions", "first", "last", "tool_calls", "bash_commands",
                                    "files_written", "sessions_ended_mid_tool_call", "by_tool"}
    assert set(doc["risk"]) == {"screened", "deny", "ask", "by_rule", "by_shape"}
    assert set(doc["blast_radius"]) == {"by_pack", "busiest_session"}
    assert set(doc["projects"][0]) == {"name", "sessions", "estimated_usd", "tool_calls",
                                       "deny", "ask", "first", "last"}
    json.dumps(doc)  # every value is JSON, including the sets and counters above


def test_the_caveat_is_the_one_the_rest_of_the_product_already_says(built):
    """A second wording of "this is an estimate" is a second claim to defend. The sentence lives
    in `transcript.ESTIMATE_CAVEAT` and is quoted from there."""
    # Wrapped to 80 columns on the way out, so the comparison is against the unwrapped text.
    assert transcript.ESTIMATE_CAVEAT in " ".join(report_mod.render_text(built).split())
    assert report_mod.as_json(built)["cost"]["caveat"] == transcript.ESTIMATE_CAVEAT


def test_the_headline_is_the_first_thing_and_is_sized_to_the_data(built):
    """Five sessions and two dollars must not be laid out like a dashboard for a fleet."""
    lines = report_mod.render_text(built).splitlines()
    assert lines[1] == "PROVENRAIL REPORT"
    assert "5 sessions across 2 projects" in lines[3]
    assert "$2.10" in lines[4]
    # The user's own transcript directory is the one thing allowed to be longer: breaking a
    # path across lines makes it uncopyable, and `--share` does not print one at all.
    assert max(len(line) for line in lines if built.root not in line) <= 80
    assert max(len(line) for line in report_mod.render_text(built, share=True).splitlines()) <= 80


def test_nothing_in_the_output_uses_a_dash_that_is_not_a_hyphen(built):
    """An em dash or an en dash in terminal output is the signature of generated prose, and
    this output exists to be pasted somewhere people are deciding whether to trust it. Spelled
    by code point so this file does not itself contain the characters it is banning."""
    banned = (chr(0x2014), chr(0x2013))
    for text in (report_mod.render_text(built), report_mod.render_text(built, share=True),
                 Path(report_mod.__file__).read_text(encoding="utf-8")):
        for dash in banned:
            assert dash not in text


# ---------------------------------------------------------------- the command line


def _pr(*args: str) -> subprocess.CompletedProcess:
    root = Path(__file__).resolve().parent.parent
    return subprocess.run([sys.executable, "-c",
                           "import sys; from provenrail.cli import main; sys.exit(main())",
                           *args],
                          capture_output=True, text=True, cwd=str(root),
                          env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(root / "src"),
                               "HOME": str(root)})


def test_pr_report_given_a_directory_reads_transcripts():
    proc = _pr("report", str(CORPUS))
    assert proc.returncode == 0, proc.stderr
    assert "PROVENRAIL REPORT" in proc.stdout


def test_pr_report_given_a_bundle_still_maps_it_to_a_regime():
    """`pr report <bundle>` is documented in the README, on the site and in two tutorials. The
    transcript report took the same name, so the argument has to decide which one ran, and the
    invocation that worked before has to keep working."""
    bundle = Path(__file__).resolve().parent.parent / "bundle.json"
    proc = _pr("report", str(bundle), "--regime", "eu-ai-act")
    assert "PROVENRAIL REPORT" not in proc.stdout
    assert json.loads(proc.stdout)["regime"]


def test_an_evidence_flag_with_no_bundle_is_refused_rather_than_ignored():
    proc = _pr("report", str(CORPUS), "--md")
    assert proc.returncode == 2
    assert "needs a bundle file" in proc.stderr


def test_pr_report_json_is_parseable_on_the_command_line():
    proc = _pr("report", str(CORPUS), "--json", "--share")
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["schema"] == report_mod.SCHEMA
    assert doc["share"] is True
    assert doc["root"] is None
