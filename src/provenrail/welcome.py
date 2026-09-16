"""The one thing the guard says the first time it runs in a project.

This is the whole onboarding. There is no install wizard, no dashboard and no email: a user
runs `/plugin install`, keeps working, and the next tool call is the first and possibly only
moment where the plugin gets to explain itself. It gets four lines on stderr, once a day.

Two failures to avoid, and the second is the one that actually happened. The first is silence:
a guard that arms itself without saying so is indistinguishable from a guard that did not
install. The second is a hand-written list of what is armed. The notice used to name
"rm -rf, dd of=/dev/, terraform destroy, git push --force, DROP/TRUNCATE, chmod 777, committed
API keys" as a string constant, and when 0.4 added the git pack, which is the pack that matches
what actually destroys people's work, the notice went on describing the previous release. So
this reads the armed rules and describes those, and cannot drift from them.

Stdlib only and free of imports from the rest of the package: it is vendored verbatim into the
plugin by tools/vendor_guard_rules.py and runs there with no Provenrail installed.
"""

from __future__ import annotations

#: What a user needs after "something is on": that it is not going to interrupt ordinary work.
#: This is the sentence that decides whether the plugin survives its first week, because the
#: reason people uninstall guardrails is false positives, not missed catches. Both halves are
#: measured claims held by tests/test_predicates.py, not reassurance.
_QUIET = ("  Quiet on ordinary work: `rm -rf ./build` and `git reset --hard` on a clean, "
          "pushed tree are not touched.")

#: Why the defaults are armed, and how to disarm them, for each of the two situations that arm
#: them. The caller passes the situation it MEASURED and never the sentence, because the notice
#: used to assert "this project has no .provenrail.json" whatever the truth was: `pr guard
#: budget 1` writes a file with a spend cap and no rules, the defaults arm because that file
#: named no rules, and the very next tool call told the user the file it had just written did
#: not exist. Same class of drift as the hand-written rule list above, same fix: derive it.
#: The disarm instruction is part of the situation too. `echo ... >` is correct only when there
#: is no file to clobber; telling the budgets-only user to run it would delete their cap.
_REASONS = {
    False: ("because this project has no {name}",
            "echo '{{\"policy\": {{\"use\": []}}}}' > {name}"),
    True: ("because {name} sets no rules of its own, so it has not turned these off",
           "add \"use\": [] to \"policy\" in {name}"),
}


def _pack_of(rule_id: str) -> str:
    return rule_id.split(".", 1)[0]


def summarise(armed: list, catalog_packs: dict) -> tuple[list, list]:
    """Split the armed packs into the ones that refuse and the ones that ask.

    A pack lands in "refuses" when any of its armed rules denies, because that is the stronger
    claim and the one a user needs to predict. Returns two lists of (title, count).
    """
    refuse: dict = {}
    ask: dict = {}
    for rule in armed:
        pack = _pack_of(rule.get("id", ""))
        title = (catalog_packs.get(pack) or {}).get("title") or pack
        bucket = refuse if rule.get("effect") == "deny" else ask
        bucket[title] = bucket.get(title, 0) + 1
    # A pack with even one deny rule is described as refusing; do not also list it as asking,
    # which would read as two separate protections rather than one.
    for title in list(refuse):
        ask.pop(title, None)
    return sorted(refuse.items()), sorted(ask.items())


def _phrase(items: list) -> str:
    return ", ".join(f"{title.lower()} ({n})" for title, n in items)


def first_run_notice(armed: list, catalog_packs: dict, config_filename: str,
                     signed: bool, config_exists: bool) -> str:
    """The notice, or "" when there is nothing armed to describe.

    `signed` says whether the engine answering can sign what it decides, which is the only
    honest difference between the free plugin and the paid CLI and therefore the only place to
    mention it.

    `config_exists` is whether the project has a config file at all, which is the one fact that
    separates the two ways the defaults can arm. It has no default: a wrong guess here is
    exactly the failure this argument was added to end.
    """
    if not armed:
        return ""
    reason, disarm = _REASONS[bool(config_exists)]
    reason = reason.format(name=config_filename)
    disarm = disarm.format(name=config_filename)
    refuse, ask = summarise(armed, catalog_packs)
    lines = [f"provenrail-guard: armed with {len(armed)} rules, {reason}."]
    if refuse:
        lines.append(f"  Refused outright: {_phrase(refuse)}.")
    if ask:
        lines.append(f"  Sent to you to approve: {_phrase(ask)}.")
    lines.append(_QUIET)
    if signed:
        lines.append(f"  See what it stopped:  pr guard card       Turn it off:  {disarm}")
    else:
        lines.append(f"  See what it stopped:  /guard-card       Turn it off:  {disarm}")
        lines.append("  Signed receipts anyone can verify:  uv tool install provenrail")
    return "\n".join(lines) + "\n"
