"""AI authorship attestation, driven against real git repositories.

Every test here builds an actual repo and runs actual git, because the whole artefact is a
claim about git's output and a mock would only prove that the mock agrees with itself. The
shortstat parsing in particular was wrong in a way no unit test with a canned string would
have caught: `--shortstat` prints AFTER the format, so the diffstat lands at the head of the
next record and every commit reported zero lines changed while the sha carried the stat text.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from provenrail import attest
from provenrail.keys import SigningKey


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True)
    return proc.stdout


def commit(repo: Path, filename: str, content: str, message: str, when: str | None = None):
    (repo / filename).write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", message],
                   check=True, capture_output=True, env=_env(when))


def _env(when: str | None):
    import os
    env = dict(os.environ)
    if when:
        env["GIT_AUTHOR_DATE"] = when
        env["GIT_COMMITTER_DATE"] = when
    return env


CLAUDE_TRAILER = "add a feature\n\nCo-Authored-By: Claude Opus 5 <noreply@anthropic.com>"


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "A Dev")
    git(root, "config", "user.email", "dev@example.com")
    # Spaced an hour apart so a test can put a recorded session around exactly one of them.
    commit(root, "a.py", "one\n", "first, by hand", when="2026-03-01T09:00:00+00:00")
    commit(root, "a.py", "one\ntwo\n", CLAUDE_TRAILER, when="2026-03-01T10:00:00+00:00")
    commit(root, "a.py", "one\ntwo\nthree\n", "third\n\nGenerated-by: internal-agent v2",
           when="2026-03-01T11:00:00+00:00")
    return root


def test_it_finds_the_agents_and_leaves_the_human_alone(repo):
    doc = attest.build(repo)
    assert doc["summary"]["commits_total"] == 3
    assert doc["summary"]["commits_ai_assisted"] == 2
    assert doc["summary"]["by_tool"] == {"Claude Code": 1, "internal-agent v2": 1}
    assert doc["commits"][0]["ai_assisted"] is False


def test_line_counts_are_real_and_not_zero(repo):
    """The bug this exists for: --shortstat lands on the next record, so a naive reader
    reports every commit as changing nothing while the sha carries the diffstat text."""
    doc = attest.build(repo)
    assert doc["summary"]["insertions_total"] == 3
    assert doc["summary"]["insertions_ai_assisted"] == 2
    for entry in doc["commits"]:
        assert len(entry["sha"]) == 40, entry["sha"]
        assert entry["files_changed"] == 1


def test_every_finding_names_the_source_it_came_from(repo):
    """A reader has to be able to weigh a finding, which means knowing whether it rests on a
    trailer the committer typed or on something they could not have."""
    doc = attest.build(repo)
    findings = doc["commits"][1]["findings"]
    assert findings
    for finding in findings:
        assert finding["source"]
        assert finding["grade"] in attest.GRADES


def test_the_document_says_what_it_cannot_prove(repo):
    doc = attest.build(repo)
    assert doc["limits"]
    joined = " ".join(doc["limits"]).lower()
    assert "does not prove the findings are true" in joined or "neither proves" in joined
    assert "understated" in joined


def test_a_signature_covers_the_document_and_survives_a_round_trip(repo, tmp_path):
    key = SigningKey.generate()
    doc = attest.sign(attest.build(repo), key)
    reloaded = json.loads(json.dumps(doc))
    from provenrail.keys import verify_signature
    digest = attest.document_hash(reloaded)
    assert digest == reloaded["document_hash"]
    assert verify_signature(reloaded["signature"]["public_key"], bytes.fromhex(digest),
                            reloaded["signature"]["value"])


def test_editing_one_finding_breaks_the_signature_and_the_leaves(repo):
    key = SigningKey.generate()
    doc = attest.sign(attest.build(repo), key)
    doc["commits"][1]["ai_assisted"] = False
    doc["commits"][1]["findings"] = []
    from provenrail.keys import verify_signature
    digest = attest.document_hash(doc)
    assert digest != doc["document_hash"]
    assert not verify_signature(doc["signature"]["public_key"], bytes.fromhex(digest),
                                doc["signature"]["value"])


def test_the_stream_id_is_stable_per_repository_and_differs_between_them(repo, tmp_path):
    """Anchors of the same repo must land on the same stream, or the service's
    monotonic-coverage rule never bites and a shorter history can be substituted."""
    other = tmp_path / "other"
    other.mkdir()
    git(other, "init", "-q")
    git(other, "config", "user.name", "A Dev")
    git(other, "config", "user.email", "dev@example.com")
    commit(other, "b.py", "x\n", "unrelated")
    first = attest.stream_id(attest.build(repo))
    commit(repo, "a.py", "one\ntwo\nthree\nfour\n", "more")
    assert attest.stream_id(attest.build(repo)) == first
    assert attest.stream_id(attest.build(other)) != first


def test_blame_separates_unattributed_lines_from_human_ones(repo):
    """Lines from commits outside the range are not "human". Reporting them as human would be
    a finding the document never made."""
    head = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, "a.py", "one\ntwo\nthree\nfour\n", "later, by hand")
    doc = attest.build(repo, since=head, blame=True)
    tree = doc["working_tree"]
    assert tree["lines_unattributed"] == 3
    assert tree["lines_human"] == 1
    assert tree["lines_ai_assisted"] == 0


def test_an_empty_range_refuses_rather_than_signing_nothing(repo):
    head = git(repo, "rev-parse", "HEAD").strip()
    with pytest.raises(attest.GitError) as exc:
        attest.build(repo, since=head)
    assert "nothing to attest" in str(exc.value)


def test_a_directory_that_is_not_a_repo_refuses(tmp_path):
    with pytest.raises(attest.GitError):
        attest.build(tmp_path)


def test_a_recorded_session_upgrades_the_grade_and_says_what_it_claims(repo):
    """The one source the committer cannot have typed. Its claim is narrow on purpose: an
    agent session was running, NOT that the agent wrote this commit."""
    doc = attest.build(repo)
    stamp = datetime.fromisoformat(doc["commits"][1]["authored_at"].replace("Z", "+00:00"))
    bundle = {"stream_id": "s1", "records": [
        {"server_record_hash": "a" * 64,
         "record": {"session_id": "sess-1", "stream_id": "s1",
                    "ts_utc": (stamp - timedelta(seconds=30)).isoformat()}},
        {"server_record_hash": "b" * 64,
         "record": {"session_id": "sess-1", "stream_id": "s1",
                    "ts_utc": (stamp + timedelta(seconds=30)).isoformat()}},
    ]}
    doc = attest.build(repo, bundle=bundle)
    entry = doc["commits"][1]
    assert entry["evidence_grade"] == attest.RECORDED
    recorded = [f for f in entry["findings"] if f["grade"] == attest.RECORDED]
    assert recorded and "was running when this commit was authored" in recorded[0]["detail"]
    assert doc["summary"]["commits_recorded_grade"] == 1
    assert doc["commits"][0]["evidence_grade"] == "none"
    assert doc["commits"][2]["evidence_grade"] == attest.ASSERTED
    assert doc["recorded_sessions"][0]["session_id"] == "sess-1"


def test_a_session_that_does_not_cover_the_commit_changes_nothing(repo):
    bundle = {"stream_id": "s1", "records": [
        {"server_record_hash": "a" * 64,
         "record": {"session_id": "sess-1", "stream_id": "s1",
                    "ts_utc": "2001-01-01T00:00:00+00:00"}},
    ]}
    doc = attest.build(repo, bundle=bundle)
    assert doc["summary"]["commits_recorded_grade"] == 0


def test_an_uncommitted_working_tree_is_declared(repo):
    (repo / "dirty.txt").write_text("not committed", encoding="utf-8")
    doc = attest.build(repo)
    assert doc["repository"]["working_tree_clean"] is False


# ---------------------------------------------------------------- the CLI


def run_cli(args, cwd):
    import contextlib
    import io
    import os

    from provenrail.cli import main
    out, err = io.StringIO(), io.StringIO()
    prev = os.getcwd()
    os.chdir(cwd)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(args)
    finally:
        os.chdir(prev)
    return code, out.getvalue(), err.getvalue()


def test_attest_then_verify_is_green_end_to_end(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    code, out, err = run_cli(["attest", "--out", "att.json"], repo)
    assert code == 0, err
    assert "AI-assisted   2 of 3" in out
    code, out, err = run_cli(["attest-verify", "att.json"], repo)
    assert code == 0, err
    assert "ATTESTATION VERIFIED" in out
    assert "What this does NOT prove" in out


def test_verify_rejects_a_document_whose_history_was_rewritten(repo, tmp_path, monkeypatch):
    """The property that makes this worth signing: it cannot be pointed at a different tree."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert run_cli(["attest", "--out", "att.json"], repo)[0] == 0
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "--amend", "-m", "rewritten"],
                   check=True, capture_output=True, env=_env(None))
    code, out, err = run_cli(["attest-verify", "att.json"], repo)
    assert code == 1
    assert "ATTESTATION REJECTED" in out
    assert "different history" in out


def test_verify_rejects_findings_edited_before_signing(repo, tmp_path, monkeypatch):
    """A signature alone cannot catch this: the document is internally consistent and correctly
    signed, and only re-deriving from git shows the finding was changed."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert run_cli(["attest", "--out", "att.json"], repo)[0] == 0
    doc = json.loads((repo / "att.json").read_text())
    doc["commits"][1]["ai_assisted"] = False
    doc["commits"][1]["findings"] = []
    doc["commits"][1]["tools"] = []
    doc["leaves"][1] = attest.Commit(
        sha=doc["commits"][1]["sha"], parents=doc["commits"][1]["parents"],
        author=doc["commits"][1]["author"], committer=doc["commits"][1]["committer"],
        authored_at=doc["commits"][1]["authored_at"],
        committed_at=doc["commits"][1]["committed_at"],
        subject=doc["commits"][1]["subject"], body="",
        insertions=doc["commits"][1]["insertions"], deletions=doc["commits"][1]["deletions"],
        files=doc["commits"][1]["files_changed"], findings=[]).leaf()
    doc["document_hash"] = attest.document_hash(doc)
    doc.pop("signature")
    (repo / "edited.json").write_text(json.dumps(doc), encoding="utf-8")
    code, out, err = run_cli(["attest-verify", "edited.json"], repo)
    assert code == 1
    assert "disagree with this repository" in out


def test_verify_says_plainly_when_a_document_is_unsigned(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert run_cli(["attest", "--unsigned", "--out", "att.json"], repo)[0] == 0
    code, out, err = run_cli(["attest-verify", "att.json"], repo)
    assert code == 0
    assert "unsigned" in out


def test_verify_refuses_a_file_that_is_not_an_attestation(repo, tmp_path, monkeypatch):
    (repo / "nope.json").write_text('{"schema": "something-else"}', encoding="utf-8")
    code, out, err = run_cli(["attest-verify", "nope.json"], repo)
    assert code == 2
    assert "not a Provenrail attestation" in err


def test_anchoring_refuses_an_edited_document_before_it_reaches_the_network(repo, tmp_path,
                                                                           monkeypatch):
    """Timestamping a document that does not match its own contents would mint a receipt that
    can never verify: an evidence-shaped object that proves nothing."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert run_cli(["attest", "--out", "att.json"], repo)[0] == 0
    doc = json.loads((repo / "att.json").read_text())
    doc["summary"]["commits_ai_assisted"] = 0
    (repo / "att.json").write_text(json.dumps(doc), encoding="utf-8")
    code, out, err = run_cli(["attest-anchor", "att.json", "--key", "x"], repo)
    assert code == 2
    assert "edited since it was written" in err


# ---------------------------------------------------------------- the anchored path
#
# `--receipt` shipped with the wrong argument order into `_verify_anchor_receipt` and crashed
# with a TypeError on the first real receipt, because nothing here exercised it. A verifier
# path with no test is a verifier path that does not work.


def _local_receipt(leaves, key, gen_time="2026-03-02T00:00:00Z", root=None):
    """A self-signed ("local") anchor receipt, the shape the sink issues when no authority is
    reachable. Enough to drive coverage and tamper checks without a network call."""
    from provenrail.anchor import merkle_root
    root = root if root is not None else merkle_root(leaves)
    return {
        "anchor_id": "anc_test",
        "covers_up_to": len(leaves),
        "merkle_root": root,
        "receipt": {
            "kind": "local", "merkle_root": root, "gen_time": gen_time,
            "anchor_pubkey": key.public_key_hex(),
            "signature": key.sign((root + "|" + gen_time).encode("utf-8")),
        },
    }


def test_a_valid_receipt_is_accepted_and_its_time_is_not_oversold(repo, tmp_path, monkeypatch):
    """A self-signed anchor proves the document is unchanged, NOT when it existed. The weaker
    outcome must never wear the stronger sentence."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert run_cli(["attest", "--out", "att.json"], repo)[0] == 0
    doc = json.loads((repo / "att.json").read_text())
    key = SigningKey.generate()
    (repo / "r.json").write_text(json.dumps(_local_receipt(doc["leaves"], key)),
                                 encoding="utf-8")
    code, out, err = run_cli(["attest-verify", "att.json", "--receipt", "r.json"], repo)
    assert code == 0, out + err
    assert "ATTESTATION VERIFIED" in out
    assert "self-asserted" in out
    assert "proved by an independent authority" not in out


def test_a_receipt_for_different_commits_is_rejected(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert run_cli(["attest", "--out", "att.json"], repo)[0] == 0
    doc = json.loads((repo / "att.json").read_text())
    key = SigningKey.generate()
    (repo / "r.json").write_text(
        json.dumps(_local_receipt(doc["leaves"][:1], key)), encoding="utf-8")
    code, out, err = run_cli(["attest-verify", "att.json", "--receipt", "r.json"], repo)
    assert code == 1
    assert "does not timestamp this document" in out


def test_a_receipt_whose_envelope_disagrees_with_its_signature_is_rejected(repo, tmp_path,
                                                                          monkeypatch):
    """A valid signature over some other root must never vouch for this document."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert run_cli(["attest", "--out", "att.json"], repo)[0] == 0
    doc = json.loads((repo / "att.json").read_text())
    key = SigningKey.generate()
    envelope = _local_receipt(doc["leaves"], key)
    envelope["merkle_root"] = "0" * 64
    (repo / "r.json").write_text(json.dumps(envelope), encoding="utf-8")
    code, out, err = run_cli(["attest-verify", "att.json", "--receipt", "r.json"], repo)
    assert code == 1
    assert "has been altered" in out


def test_a_forged_receipt_signature_is_rejected(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert run_cli(["attest", "--out", "att.json"], repo)[0] == 0
    doc = json.loads((repo / "att.json").read_text())
    envelope = _local_receipt(doc["leaves"], SigningKey.generate())
    envelope["receipt"]["anchor_pubkey"] = SigningKey.generate().public_key_hex()
    (repo / "r.json").write_text(json.dumps(envelope), encoding="utf-8")
    code, out, err = run_cli(["attest-verify", "att.json", "--receipt", "r.json"], repo)
    assert code == 1
    assert "signature invalid" in out.lower()


def test_a_missing_receipt_file_says_so_rather_than_crashing(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert run_cli(["attest", "--out", "att.json"], repo)[0] == 0
    code, out, err = run_cli(["attest-verify", "att.json", "--receipt", "nope.json"], repo)
    assert code == 2
    assert "no such anchor receipt" in err
