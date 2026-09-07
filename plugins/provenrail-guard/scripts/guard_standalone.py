#!/usr/bin/env python3
"""The guard, with nothing installed.

`/plugin install provenrail-guard@provenrail` has to protect the very next tool call. If it
instead prints "now run three more commands", most people never run them and the plugin
blocks nothing while sitting in their plugin list looking like it does. So this file is a
complete, dependency-free copy of the enforcement path: stdlib only, no network, no account,
no `pip install`, no sink.

What it is NOT is a second policy engine with its own opinions. The rules come from
`rules.json`, generated from `provenrail.rulesets` by `tools/vendor_guard_rules.py`, and the
matching below is held against `provenrail.guard.decide` case by case in
`tests/test_guard_standalone.py`. Two implementations that quietly disagree is the exact
failure this project has already paid for once in the verifier; the answer there was a
lockstep test and the answer here is the same one.

The division of labour with the installed CLI:

    standalone (this file)   blocks, asks, counts, and writes a local journal line
    provenrail installed     all of that, plus an Ed25519-signed hash-chained record that
                             someone else can verify, and a receipt you can hand over

Both write the same journal in the same place, so installing `provenrail` later picks up the
history this file already wrote rather than starting from an empty one.

Failure policy, in one line: this must never break the session. Anything unexpected exits 0
with no output, which Claude Code reads as "no opinion", and the tool call proceeds. A guard
that bricks the agent gets uninstalled by lunchtime and takes the useful rules with it. The
cost of that choice is stated out loud in the README rather than hidden.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
import time
from pathlib import Path

# The two engines have to reach the same verdict on the same command, so the parts that decide
# it are vendored from `src/provenrail/` by `tools/vendor_guard_rules.py` rather than written a
# second time here. Imported by path, because this file runs before Provenrail is installed.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from predicates import evaluate as predicate_ok   # noqa: E402
from shell import segments                        # noqa: E402

HERE = Path(__file__).resolve().parent
RULES_FILE = HERE / "rules.json"

CONFIG_FILENAME = ".provenrail.json"
JOURNAL_FILENAME = ".provenrail-guard.jsonl"
COUNTS_FILENAME = ".provenrail-guard-counts.json"
NOTICE_FILENAME = ".provenrail-guard-notice"
PENDING_FILENAME = ".provenrail-guard-pending.json"

# One notice a day, not one per tool call. Noise is why people uninstall guardrails.
NOTICE_INTERVAL_S = 24 * 60 * 60
# Mirrors provenrail.policy.MAX_MATCH_TEXT, and the reason for the +1 in match_text is the
# same: the decision layer has to be able to tell a whole argument from a prefix of one. The
# old value here was 20,000 with a silent truncation, which meant twenty thousand characters of
# padding in front of `rm -rf /` matched no rule and the call was allowed. Both engines.
MAX_MATCH_TEXT = 4000000
MATCH_TEXT_LIMIT = MAX_MATCH_TEXT + 1
#: The rule id an unscreenable argument fires. Not in any pack: it is the engine saying it could
#: not answer, which is a different thing from a rule saying no. It asks a human rather than
#: denying, because hard-blocking here would refuse a legitimate multi-megabyte file write.
UNSCREENABLE = "policy.unscreenable-argument"

DENY = "deny"
REQUIRE_OVERSIGHT = "require_oversight"
LIMIT = "limit"
ALLOW = "allow"
ENGINE_FIELDS = ("id", "effect", "event_type", "tool", "not_tool", "resource", "provider",
                 "predicate", "arg_contains", "max_per_session", "reason")


# ---------------------------------------------------------------- rules


def load_catalog():
    with RULES_FILE.open(encoding="utf-8") as fh:
        return json.load(fh)


def resolve(catalog, names):
    """Expand pack ids and rule ids into engine-ready rules, in the order given.

    An unknown name raises, exactly as `rulesets.resolve` does. Skipping it would leave
    someone who typed "destuctive" believing a pack is armed while nothing is.
    """
    if not names:
        return []
    if isinstance(names, str):
        names = [names]
    packs = catalog["packs"]
    by_id = {r["id"]: r for pack in packs.values() for r in pack["rules"]}
    out, seen = [], set()
    for name in names:
        if name in packs:
            chosen = packs[name]["rules"]
        elif name in by_id:
            chosen = [by_id[name]]
        else:
            raise ValueError(
                '"%s" is not a known rule pack or rule id. Packs: %s'
                % (name, sorted(packs)))
        for rule in chosen:
            if rule["id"] in seen:
                continue
            seen.add(rule["id"])
            out.append({k: v for k, v in rule.items() if k in ENGINE_FIELDS})
    return out


# ---------------------------------------------------------------- config


def find_config_file(start=None):
    """`.provenrail.json`, searched upward from cwd and then in the home directory.

    Upward, because an agent is routinely launched from a subdirectory of the repo whose root
    holds the policy. Looking only at the current directory would silently find no policy and
    allow everything, while the user believes they are covered.
    """
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
    home = Path.home() / CONFIG_FILENAME
    return home if home.is_file() else None


def load_rules(catalog, config_path):
    """(rules, source) for this invocation.

    With no config file, the default packs are armed. That is the whole point of the zero
    install path: installing a plugin called "guard" IS the opt-in, and a guard that waits for
    a config file protects nobody. A config file, once present, wins completely, including an
    explicit empty `use` that arms nothing: whoever wrote it outranks our defaults.
    """
    if config_path is None:
        return resolve(catalog, catalog["default_packs"]), "defaults"
    try:
        with config_path.open(encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ValueError("%s is not readable JSON (%s)" % (config_path, exc))
    policy = cfg.get("policy")
    if policy is None:
        # A config file that configures a stream but says nothing about guardrails is not a
        # decision to run unguarded, so the defaults still apply.
        return resolve(catalog, catalog["default_packs"]), "defaults"
    if not isinstance(policy, dict):
        raise ValueError('"policy" in %s must be an object' % config_path)
    rules = resolve(catalog, policy.get("use"))
    custom = policy.get("rules") or []
    if not isinstance(custom, list):
        raise ValueError('"policy.rules" in %s must be a list' % config_path)
    for rule in custom:
        if not isinstance(rule, dict) or not rule.get("id") or not rule.get("effect"):
            raise ValueError('every rule in %s needs "id" and "effect"' % config_path)
        if rule.get("arg_contains"):
            # Compiled here so a broken pattern is reported as a policy that will not load,
            # the same answer `pr` gives. Discovering it inside the matcher would mean one
            # rule silently never fires while the guard reports itself armed.
            try:
                re.compile(rule["arg_contains"])
            except re.error as exc:
                raise ValueError('rule "%s" has an invalid arg_contains regex: %s'
                                 % (rule["id"], exc))
        rules.append({k: v for k, v in rule.items() if k in ENGINE_FIELDS})
    return rules, str(config_path)


# ---------------------------------------------------------------- payload


def coerce_tool_input(value):
    """Whatever the host sent, in a shape the content rules can read.

    A shape we do not recognise must fail towards being READ, never towards being ignored: a
    payload that becomes `{}` matches every content rule against two characters and lets a
    `rm -rf /` straight through.
    """
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    if isinstance(value, str):
        return {"command": value}
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        # An argv array IS a command line. As JSON it reads `["rm","-rf","/"]`, and the commas
        # defeat every `\brm\s+-rf` pattern ever written.
        return {"command": " ".join(value)}
    return {"input": value}


def match_text(value):
    """The bounded text a content rule matches against. Local only, never sent anywhere."""
    if isinstance(value, str):
        return value[:MATCH_TEXT_LIMIT]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return " ".join(value)[:MATCH_TEXT_LIMIT]
    if isinstance(value, dict) and isinstance(value.get("command"), str):
        # Verbatim, with its line breaks intact. JSON rendering turned every newline into a
        # space, and a heredoc body is delimited by lines: flattened, a file being WRITTEN and
        # a command being RUN are the same string, and the guard denied the first as if it were
        # the second. Other keys follow after a newline so they are still screened.
        rest = {k: v for k, v in value.items() if k != "command"}
        text = value["command"]
        if rest:
            try:
                text = text + "\n" + json.dumps(rest, default=str, ensure_ascii=False)
            except Exception:
                text = text + "\n" + str(rest)
        return text[:MATCH_TEXT_LIMIT]
    try:
        text = json.dumps(value, default=str, ensure_ascii=False)[:MATCH_TEXT_LIMIT]
    except Exception:
        return str(value)[:MATCH_TEXT_LIMIT]
    # json.dumps turns a real tab into backslash-t, and a shell treats a tab as whitespace
    # while `\s` in the escaped form no longer matches it.
    return text.replace("\\t", " ").replace("\\n", " ").replace("\\r", " ")


def parse_hook_input(data, default_event="pre"):
    event = (data.get("hook_event_name") or "").strip().lower()
    if event.startswith("posttool"):
        phase = "post"
    elif event.startswith("pretool"):
        phase = "pre"
    else:
        phase = default_event
    return {
        "event": phase,
        "tool": data.get("tool_name") or "",
        "input": coerce_tool_input(data.get("tool_input")),
        "session_id": data.get("session_id") or "",
        "cwd": data.get("cwd") or "",
    }


# ---------------------------------------------------------------- state


def state_dir(config_path):
    """Where the journal and its siblings live: beside the policy, else the current directory.

    Anchored to the config, not to cwd, so a session launched from `apps/web` keeps writing to
    the same journal and the same blast-radius counters as one launched from the repo root.
    """
    override = os.environ.get("PROVENRAIL_GUARD_JOURNAL")
    if override:
        return Path(override).parent
    return config_path.parent if config_path else Path.cwd()


def journal_path(config_path):
    override = os.environ.get("PROVENRAIL_GUARD_JOURNAL")
    if override:
        return Path(override)
    return state_dir(config_path) / JOURNAL_FILENAME


#: Above this, the journal is trimmed to its most recent half on the next write. A local log
#: that grows without bound eventually becomes the thing the user deletes, taking the whole
#: history with it, so it is bounded here rather than by them.
JOURNAL_MAX_BYTES = 2 * 1024 * 1024


def append_journal(config_path, entry):
    """A journal line is not evidence. It is unsigned, local, and editable by anything that can
    write the file. It exists so the history is not simply lost, and so `pr guard receipt` has
    something to turn into a signed one the day Provenrail is installed."""
    path = journal_path(config_path)
    try:
        if path.is_file() and path.stat().st_size > JOURNAL_MAX_BYTES:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            keep = lines[len(lines) // 2:]
            path.write_text("\n".join(keep) + "\n", encoding="utf-8")
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError:
        pass


def load_counts(config_path, session_id):
    if not session_id:
        return {}
    try:
        with (state_dir(config_path) / COUNTS_FILENAME).open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    entry = data.get(session_id)
    if isinstance(entry, dict) and isinstance(entry.get("counts"), dict):
        return {k: int(v) for k, v in entry["counts"].items() if isinstance(v, int)}
    return {}


def save_counts(config_path, session_id, counts):
    if not session_id:
        return
    path = state_dir(config_path) / COUNTS_FILENAME
    try:
        try:
            with path.open(encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data[session_id] = {"counts": counts, "updated": int(time.time())}
        # Keep the file from growing without bound across months of sessions.
        if len(data) > 200:
            newest = sorted(data.items(), key=lambda kv: kv[1].get("updated", 0), reverse=True)
            data = dict(newest[:100])
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(str(tmp), str(path))
    except OSError:
        pass


def mark_ask(config_path, session_id, tool, rule):
    """Remember that a rule turned into a permission prompt, so the human's answer can be
    recorded as the oversight the rule asked for once Provenrail is installed."""
    path = state_dir(config_path) / PENDING_FILENAME
    try:
        try:
            with path.open(encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data["%s|%s" % (session_id, tool)] = {"rule": rule, "at": int(time.time())}
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(str(tmp), str(path))
    except OSError:
        pass


def once_a_day(config_path, name, message):
    """Return `message` at most once per day, keyed by `name`. Silence otherwise.

    `message` may be a callable, and for the armed notice it is: this runs inside every single
    tool call, and building that string eagerly meant re-reading and re-parsing rules.json on
    every one of them to say nothing.
    """
    try:
        path = state_dir(config_path) / (NOTICE_FILENAME + "-" + name)
        now = time.time()
        if path.is_file() and now - path.stat().st_mtime < NOTICE_INTERVAL_S:
            return ""
        path.write_text(str(int(now)), encoding="utf-8")
    except OSError:
        return ""
    return message() if callable(message) else message


# ---------------------------------------------------------------- matching


def glob_ok(pattern, value):
    return fnmatch.fnmatch((value or "").lower(), (pattern or "*").lower())


def rule_matches(rule, event_type, ctx):
    if rule.get("event_type", "*") not in ("*", event_type):
        return False
    if not glob_ok(rule.get("tool", "*"), ctx.get("tool", "")):
        return False
    # Tools this rule is NOT about. A rule screening shell commands must not read the body of a
    # file a Write or Edit is creating: documentation that explains `rm -rf /`, a migration that
    # drops a table, a fixture holding a fake token. Denying those makes the guard something an
    # agent has to be uninstalled to work around.
    for pattern in (rule.get("not_tool") or "").split("|"):
        if pattern and glob_ok(pattern, ctx.get("tool", "")):
            return False
    if not glob_ok(rule.get("resource", "*"), ctx.get("resource", "")):
        return False
    if not glob_ok(rule.get("provider", "*"), ctx.get("provider", "")):
        return False
    pattern = rule.get("arg_contains") or ""
    predicate = rule.get("predicate") or ""
    if pattern:
        text = ctx.get("match_text", "")
        if not isinstance(text, str):
            text = match_text(text)
        if not text:
            return False
        # Per command, not per string handed to the tool: a heredoc body writing a file that
        # mentions `dd of=/dev/` is data, and the `-f` after `git push origin main 2>&1;` may
        # belong to the `pkill` that follows it.
        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        if not any(compiled.search(part) and predicate_ok(predicate, part, ctx)
                   for part in segments(text)):
            return False
    elif predicate:
        text = ctx.get("match_text", "")
        if not isinstance(text, str):
            text = match_text(text)
        if not any(predicate_ok(predicate, part, ctx) for part in segments(text)):
            return False
    return True


def decide(rules, tool, tool_input, counts, cwd=""):
    """The verdict for one attempted tool call. Mutates `counts` for `limit` rules.

    Returns (verdict, rule_id, reason) where verdict is "allow", "deny" or "ask".
    """
    text = match_text(tool_input)
    ctx = {"tool": tool, "match_text": text, "cwd": cwd or ""}
    if len(text) > MAX_MATCH_TEXT and any(r.get("arg_contains") for r in rules):
        return "ask", UNSCREENABLE, (
            "this call's arguments are %d characters, past the %d a content rule can be "
            "matched against, so it cannot be screened. An argument too large to read is not "
            "an argument known to be safe." % (len(text), MAX_MATCH_TEXT))

    # An allow found in this loop is provisional, exactly as in the installed engine: a `limit`
    # rule under its cap must not preempt a `deny` rule that comes after it.
    provisional = None
    for rule in rules:
        if not rule_matches(rule, "tool_call", ctx):
            continue
        effect = rule.get("effect")
        reason = rule.get("reason") or "denied by policy"
        if effect == DENY:
            return "deny", rule["id"], reason
        if effect == REQUIRE_OVERSIGHT:
            # The human answering Claude Code's permission prompt IS the oversight this rule
            # asked for. Hard-blocking work they would have approved is how a ruleset gets
            # switched off wholesale.
            return "ask", rule["id"], reason
        if effect == LIMIT:
            cap = rule.get("max_per_session")
            counts[rule["id"]] = counts.get(rule["id"], 0) + 1
            if isinstance(cap, int) and counts[rule["id"]] > cap:
                return "deny", rule["id"], rule.get("reason") or (
                    "exceeds the %d-per-session limit" % cap)
            if provisional is None:
                provisional = ("allow", rule["id"], "within the per-session limit (%d/%s)"
                               % (counts[rule["id"]], cap))
    if provisional is not None:
        return provisional
    return "allow", None, ""


# ---------------------------------------------------------------- the hook


def welcome(config_path, catalog, rules, source):
    if source != "defaults":
        return ""
    return once_a_day(config_path, "armed", lambda: (
        "provenrail-guard: armed with %d rules (packs: %s) because this project has no "
        "%s.\n"
        "  Blocking now: rm -rf, dd of=/dev/, terraform destroy, git push --force, DROP/TRUNCATE, "
        "chmod 777, committed API keys.\n"
        "  Asking first: .env reads, deploys, migrations, DNS and IAM changes.\n"
        "  Change or switch off:  echo '{\"policy\": {\"use\": []}}' > %s\n"
        "  Signed receipts anyone can verify:  uv tool install provenrail && pr guard receipt\n"
        % (len(rules), ", ".join(catalog["default_packs"]), CONFIG_FILENAME,
           CONFIG_FILENAME)))


def run(raw, default_event="pre"):
    """Handle one hook invocation. Returns (stdout, stderr)."""
    try:
        data = json.loads(raw) if raw.strip() else {}
    except ValueError:
        return "", "provenrail-guard: hook input was not JSON; allowing.\n"
    if not isinstance(data, dict):
        return "", "provenrail-guard: unexpected hook input; allowing.\n"

    hook = parse_hook_input(data, default_event=default_event)
    config_path = find_config_file()
    catalog = load_catalog()
    try:
        rules, source = load_rules(catalog, config_path)
    except ValueError as exc:
        # A broken policy must be loud, not silently permissive.
        return "", "provenrail-guard: could not load the policy (%s); NOT enforcing.\n" % exc

    if not rules:
        return "", once_a_day(config_path, "unarmed", (
            "provenrail-guard: hooks are installed but NO guardrails are armed, so nothing is "
            "being blocked. Remove \"policy\" from %s to get the defaults back.\n"
            % (config_path or CONFIG_FILENAME)))

    notice = welcome(config_path, catalog, rules, source)
    if hook["event"] != "pre":
        return "", notice

    counts = load_counts(config_path, hook["session_id"])
    before = dict(counts)
    verdict, rule_id, reason = decide(rules, hook["tool"], hook["input"], counts,
                                      hook.get("cwd") or "")
    if counts != before:
        save_counts(config_path, hook["session_id"], counts)
    if verdict == "ask":
        mark_ask(config_path, hook["session_id"], hook["tool"], rule_id or "")

    if verdict == "allow":
        # Only blocks and prompts are journalled. A line per allowed tool call would add
        # thousands of rows a day to a file whose entire purpose is to be readable, and the
        # standalone is not the recorder: capturing what the agent DID is what installing
        # Provenrail adds. What it must not lose is what it stopped.
        return "", notice

    append_journal(config_path, {
        "at": int(time.time()), "event": "pre", "tool": hook["tool"],
        "session_id": hook["session_id"], "verdict": verdict, "rule": rule_id,
        "reason": reason, "by": "standalone",
    })

    text = "Provenrail guardrail %s: %s" % (rule_id, reason)
    if verdict == "ask":
        text += " (approve here and the approval is recorded as human oversight)"
    else:
        text += (" [blocked locally and journalled. Install provenrail for a signed receipt "
                 "anyone can verify: uv tool install provenrail]")
    out = {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": verdict,
        "permissionDecisionReason": text,
    }}
    return json.dumps(out), notice


def status():
    """What is armed, and what it has actually stopped. Printed by `/guard-status`.

    The second half is the part that matters. A guardrail that reports itself armed and has
    never fired is indistinguishable from one that is silently broken, and this is the only
    place a user can tell those apart without reading a log file by hand.
    """
    config_path = find_config_file()
    catalog = load_catalog()
    lines = []
    try:
        rules, source = load_rules(catalog, config_path)
    except ValueError as exc:
        return "provenrail-guard: the policy will not load, so NOTHING is enforced: %s\n" % exc
    where = "built-in defaults (no %s in this project)" % CONFIG_FILENAME \
        if source == "defaults" else source
    lines.append("provenrail-guard: %d rules armed, from %s" % (len(rules), where))
    blocked = sum(1 for r in rules if r.get("effect") == DENY)
    asks = sum(1 for r in rules if r.get("effect") == REQUIRE_OVERSIGHT)
    caps = sum(1 for r in rules if r.get("effect") == LIMIT)
    lines.append("  %d block outright, %d ask a human first, %d cap blast radius"
                 % (blocked, asks, caps))
    if not rules:
        lines.append("  Nothing is being blocked. Remove \"policy\" from the config to restore "
                     "the defaults.")

    entries = []
    path = journal_path(config_path)
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    denies = [e for e in entries if e.get("verdict") == "deny"]
    prompts = [e for e in entries if e.get("verdict") == "ask"]
    lines.append("")
    lines.append("  Stopped so far: %d blocked, %d sent to you for approval."
                 % (len(denies), len(prompts)))
    for entry in entries[-8:]:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.get("at", 0)))
        lines.append("    %s  %-5s %-10s %s"
                     % (stamp, entry.get("verdict", "?"), entry.get("tool", "?"),
                        entry.get("rule") or ""))
    if not entries:
        lines.append("    (nothing yet: either the agent has done nothing dangerous, or the "
                     "hooks are not wired. Ask Claude to run `echo test` and check again.)")
    lines.append("")
    lines.append("  This history is a local text file. It is not signed and anything on this "
                 "machine can edit it.")
    lines.append("  For a receipt someone else can verify: uv tool install provenrail && "
                 "pr guard receipt")
    return "\n".join(lines) + "\n"


def main(argv):
    if "--status" in argv:
        sys.stdout.write(status())
        return 0
    event = "pre"
    for i, arg in enumerate(argv):
        if arg == "--event" and i + 1 < len(argv):
            event = argv[i + 1]
        elif arg in ("pre", "post"):
            event = arg
    try:
        stdout, stderr = run(sys.stdin.read(), default_event=event)
    except Exception as exc:  # never break the session
        sys.stderr.write("provenrail-guard: internal error (%s); allowing.\n" % exc)
        return 0
    if stderr:
        sys.stderr.write(stderr)
    if stdout:
        sys.stdout.write(stdout + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
