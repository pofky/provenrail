"""The published GitHub Action, checked for the things that only fail on someone else's runner.

An action is the one artefact in this repo nobody here executes before a stranger does, so the
failures it can carry are exactly the ones that are invisible locally. These tests cover the
three that would have shipped.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

yaml = pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
ACTION = ROOT / "action.yml"


@pytest.fixture(scope="module")
def action():
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


def _run_blocks(action):
    for step in action["runs"]["steps"]:
        if "run" in step:
            yield step.get("name", "?"), step["run"]


def test_it_parses_and_declares_what_a_marketplace_listing_needs(action):
    assert action["name"] and action["description"]
    assert action["runs"]["using"] == "composite"
    assert action["branding"]["icon"] and action["branding"]["color"]


def test_no_run_block_uses_an_and_list_that_set_e_would_kill(action):
    """`set -e` exits on `[ ... ] && cmd` when the test is false, because the and-list's status
    is 1 and it is not in a condition context. Written that way, this action failed for every
    user who did not pass `since` or turn `blame` on, which is the common case and not the one
    anybody tests."""
    offences = []
    for name, block in _run_blocks(action):
        if "set -e" not in block:
            continue
        for n, line in enumerate(block.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.match(r"^\[ .* \]\s*&&", stripped):
                offences.append(f"{name}:{n}: {stripped}")
    assert not offences, ("an and-list under set -e will exit the step when it is false:\n  "
                          + "\n  ".join(offences))


def test_the_signing_key_never_survives_the_step(action):
    """The key is written to the working directory because that is where the SDK reads it. A
    runner's workspace can be uploaded as an artifact by a later step, so leaving it there
    would publish an organisation's private key."""
    block = dict((n, b) for n, b in _run_blocks(action))["Attest"]
    assert ".provenrail.key" in block
    assert "rm -f .provenrail.key" in block
    # And after the CLI has run, not before, or a generated key is left behind too.
    assert block.index("rm -f .provenrail.key") > block.index("python3 -m provenrail")


def test_it_refuses_a_shallow_checkout_rather_than_attesting_to_a_stump(action):
    """actions/checkout is shallow by default. An attestation over a truncated history would
    name a range it cannot see, and would understate AI authorship for reasons that have
    nothing to do with the code."""
    block = dict((n, b) for n, b in _run_blocks(action))["Attest"]
    assert "is-shallow-repository" in block
    assert "fetch-depth: 0" in block


def test_the_step_body_is_valid_bash(action):
    """`bash -n` on the real block, with the action expressions substituted the way the runner
    substitutes them. A heredoc whose terminator lost its indentation to the YAML block scalar
    is a syntax error that only appears on the runner."""
    for name, block in _run_blocks(action):
        script = re.sub(r"\$\{\{[^}]+\}\}", "x", block)
        proc = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
        assert proc.returncode == 0, f"{name} is not valid bash:\n{proc.stderr}"


def test_the_summary_says_what_the_attestation_does_not_prove(action):
    """The step summary is the only part of this most people will read, so the limit has to be
    in it rather than one link away."""
    summary = dict((n, b) for n, b in _run_blocks(action))["Summary"]
    assert "does not prove the findings are true" in summary
    assert "attest-verify" in summary
