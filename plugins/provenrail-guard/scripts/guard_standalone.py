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
import hosts  # noqa: E402
import spend as spend_ledger  # noqa: E402
import transcript  # noqa: E402
from predicates import evaluate as predicate_ok  # noqa: E402
from shell import command_shape, segments  # noqa: E402
from welcome import first_run_notice  # noqa: E402

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
                f'"{name}" is not a known rule pack or rule id. Packs: {sorted(packs)}')
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
        raise ValueError(f"{config_path} is not readable JSON ({exc})") from exc
    policy = cfg.get("policy")
    if policy is None:
        # A config file that configures a stream but says nothing about guardrails is not a
        # decision to run unguarded, so the defaults still apply.
        return resolve(catalog, catalog["default_packs"]), "defaults"
    if not isinstance(policy, dict):
        raise ValueError(f'"policy" in {config_path} must be an object')
    if "use" not in policy and "rules" not in policy:
        # A policy block that says nothing about RULES is not a decision to run without any.
        # `/guard-budget 25` in a fresh project writes exactly such a block, and reading it as
        # "the user chose no rules" meant arming a spend cap silently switched every destructive
        # rule off. Turning one control on must never turn another one off without saying so.
        return resolve(catalog, catalog["default_packs"]), "defaults"
    rules = resolve(catalog, policy.get("use"))
    custom = policy.get("rules") or []
    if not isinstance(custom, list):
        raise ValueError(f'"policy.rules" in {config_path} must be a list')
    for rule in custom:
        if not isinstance(rule, dict) or not rule.get("id") or not rule.get("effect"):
            raise ValueError(f'every rule in {config_path} needs "id" and "effect"')
        if rule.get("arg_contains"):
            # Compiled here so a broken pattern is reported as a policy that will not load,
            # the same answer `pr` gives. Discovering it inside the matcher would mean one
            # rule silently never fires while the guard reports itself armed.
            try:
                re.compile(rule["arg_contains"])
            except re.error as exc:
                raise ValueError(
                    f'rule "{rule["id"]}" has an invalid arg_contains regex: {exc}') from exc
        rules.append({k: v for k, v in rule.items() if k in ENGINE_FIELDS})
    return rules, str(config_path)


def load_budgets(config_path):
    """(budgets, on_unpriced) from the config, as the tuples `transcript.verdict_for` takes.

    There is no default cap and there must never be one: a dollar figure nobody chose is a claim
    about somebody else's money, and it would be wrong for almost everyone. A budget exists only
    because a person wrote one, with `pr guard budget 25` or `/guard-budget 25`.

    A budget that cannot bind is rejected rather than ignored, because a misspelled scope or a
    missing limit produces a config that reads like a spend control and enforces nothing, which
    is the single worst failure this feature has.
    """
    if config_path is None:
        return [], "warn"
    try:
        with config_path.open(encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{config_path} is not readable JSON ({exc})") from exc
    policy = cfg.get("policy")
    if not isinstance(policy, dict):
        return [], "warn"
    raw = policy.get("budgets") or []
    if not isinstance(raw, list):
        raise ValueError(f'"policy.budgets" in {config_path} must be a list')
    on_unpriced = str(policy.get("on_unpriced") or "warn").lower()
    if on_unpriced not in ("warn", "deny"):
        raise ValueError(f'"policy.on_unpriced" in {config_path} must be "warn" or "deny"')
    out = []
    for i, budget in enumerate(raw):
        if not isinstance(budget, dict):
            raise ValueError(f"policy budget {i} in {config_path} must be an object")
        unknown = sorted(set(budget) - set(transcript.BUDGET_FIELDS))
        if unknown:
            raise ValueError(f"policy budget {i} has unknown field(s) {unknown}. A misspelled "
                             "field would silently disable the cap, so it is rejected rather "
                             "than ignored.")
        scope = str(budget.get("scope", transcript.SESSION)).lower()
        if scope not in transcript.BUDGET_SCOPES:
            raise ValueError(f"policy budget {i} has scope {scope!r}; expected one of "
                             f"{sorted(transcript.BUDGET_SCOPES)}")
        try:
            limit_usd = float(budget["limit_usd"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f'policy budget {i} needs a numeric "limit_usd" (without one it '
                             "would never cap anything)") from exc
        if limit_usd <= 0:
            raise ValueError(f"policy budget {i} has limit_usd {limit_usd}; a cap must be "
                             "greater than zero")
        try:
            warn_at = float(budget.get("warn_at", 0.8))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"policy budget {i} warn_at must be a number between 0 and 1") from exc
        if not 0.0 <= warn_at <= 1.0:
            raise ValueError(f"policy budget {i} warn_at must be between 0 and 1")
        out.append((str(budget.get("id") or "budget." + scope), scope, limit_usd, warn_at))
    return out, on_unpriced


def spend_agent_id(config_path):
    """Ledger key for guard mode: the configured stream, else a shared default.

    Read the same way the installed CLI reads it, because the two engines write the same ledger
    file and a different key would split one agent's day spend across two rows, each of them
    under the cap.
    """
    if config_path is None:
        return "default"
    try:
        with config_path.open(encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        return "default"
    return str(cfg.get("stream_id") or cfg.get("agent_id") or "default")


# ---------------------------------------------------------------- payload


#: The five hosts' payload field names and output envelopes live in `hosts.py`, vendored
#: alongside this file. A second hand-written copy of that table is how one engine ends up
#: parsing `toolName` and the other `tool_name` for the same agent.
coerce_tool_input = hosts.coerce_tool_input
parse_hook_input = hosts.parse


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


def load_spend_state(config_path, session_id, transcript_path):
    """How far this transcript has already been priced, and what this session has spent.

    Keyed as `transcript.find_state` describes: the read cursor on the transcript, the session
    figure on the session.
    """
    if not session_id:
        return transcript.TranscriptState()
    try:
        with (state_dir(config_path) / COUNTS_FILENAME).open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return transcript.TranscriptState()
    return transcript.find_state(data, transcript.state_key(transcript_path), session_id)


def save_session_entry(config_path, session_id, **fields):
    """Merge fields into this session's entry, rather than replacing it.

    The entry carries two independent things now, the blast-radius counters and the transcript
    spend cursor, and writing one by assigning a whole new entry dropped the other. Dropping the
    spend cursor resets the read offset to zero, which charges the entire transcript again on
    the very next tool call.
    """
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
        entry = data.get(session_id)
        entry = dict(entry) if isinstance(entry, dict) else {}
        entry.update(fields)
        entry["updated"] = int(time.time())
        data[session_id] = entry
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
        data[f"{session_id}|{tool}"] = {"rule": rule, "at": int(time.time())}
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


def any_glob(patterns, value):
    """`|`-separated alternatives, any of which may match. `fnmatch` has no alternation."""
    if not patterns:
        return True
    return any(glob_ok(part, value) for part in str(patterns).split("|") if part)


def rule_matches(rule, event_type, ctx):
    if rule.get("event_type", "*") not in ("*", event_type):
        return False
    if not any_glob(rule.get("tool", "*"), ctx.get("tool", "")):
        return False
    # Tools this rule is NOT about. A rule screening shell commands must not read the body of a
    # file a Write or Edit is creating: documentation that explains `rm -rf /`, a migration that
    # drops a table, a fixture holding a fake token. Denying those makes the guard something an
    # agent has to be uninstalled to work around.
    if rule.get("not_tool") and any_glob(rule["not_tool"], ctx.get("tool", "")):
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
            f"this call's arguments are {len(text)} characters, past the {MAX_MATCH_TEXT} a "
            "content rule can be matched against, so it cannot be screened. An argument too "
            "large to read is not an argument known to be safe.")

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
                    f"exceeds the {cap}-per-session limit")
            if provisional is None:
                provisional = ("allow", rule["id"],
                               f"within the per-session limit ({counts[rule['id']]}/{cap})")
    if provisional is not None:
        return provisional
    return "allow", None, ""


# ---------------------------------------------------------------- the hook


def welcome(config_path, catalog, rules, source):
    """The first-run notice, once a day, and only when the defaults armed themselves.

    A project with its own .provenrail.json that names rules chose what it wants and does not
    need telling. A file that names no rules did NOT choose, so the defaults arm and the notice
    is shown, saying that second reason rather than claiming the file is missing.
    """
    if source != "defaults":
        return ""
    return once_a_day(config_path, "armed", lambda: first_run_notice(
        rules, catalog.get("packs", {}), CONFIG_FILENAME, signed=False,
        config_exists=config_path is not None))


# ---------------------------------------------------------------- spend


#: Said on stderr, at most once a day, when budgets are configured but the spend they exist to
#: cap cannot be counted. A guard that cannot bind and does not say so is worse than no guard.
CANNOT_BIND = "provenrail-guard: spend cap cannot bind: "


def apply_spend(config_path, budgets, on_unpriced, hook):
    """Price the transcript since the last tool call and answer the budgets. (verdict, stderr).

    `verdict` is the ("deny"|"allow", rule id, text) tuple `transcript.verdict_for` returns, or
    None. The arithmetic and every sentence come from the vendored `transcript` module, which
    the installed CLI also calls, so the two engines cannot quote different dollar figures for
    the same ledger.
    """
    if not budgets:
        # No budget, no transcript I/O. Pricing a multi-megabyte transcript on every tool call
        # would be a tax paid by every project that has never set a cap, which is nearly all.
        return None, ""
    transcript_path = hook.get("transcript_path") or ""
    if not transcript_path:
        return None, once_a_day(config_path, "spend-no-transcript", CANNOT_BIND + (
            "this hook payload carried no transcript_path, so no model spend can be seen from "
            "here. The cap in the policy is not enforcing anything.\n"))
    session_id = hook.get("session_id") or ""
    if not session_id:
        # The read cursor is keyed on the transcript and survives this, but a `session`-scope
        # figure has nowhere to live without a session key, and answering a session cap from a
        # total that restarts at zero every tool call would report a cap as binding while it
        # never fired. Not counting is the honest answer, and the notice says so.
        return None, once_a_day(config_path, "spend-no-session", CANNOT_BIND + (
            "this hook payload carried no session_id, so this session's own spend total cannot "
            "be kept between tool calls and spend is not being counted.\n"))

    state = load_spend_state(config_path, session_id, transcript_path)
    resumed_known = state.known
    new_cost, _unpriced, state = transcript.accrue(transcript_path, state)
    save_session_entry(config_path, transcript.state_key(transcript_path),
                       spend=state.cursor_dict())
    save_session_entry(config_path, session_id, spend=state.session_dict())
    agent_id = spend_agent_id(config_path)
    if new_cost > 0:
        spend_ledger.add_spend(new_cost, agent_id)
    day, total, ledger_known = spend_ledger.prior_spend(agent_id)

    # The ledger already contains this session's spend, because it was just added to it. A
    # `session` budget still needs the session figure on its own, so it is subtracted out of the
    # cross-session figures rather than counted twice.
    session_usd = state.session_usd
    spent = transcript.spent_by_scope(session_usd, max(0.0, day - session_usd),
                                      max(0.0, total - session_usd))
    verdict = transcript.verdict_for(budgets, spent, state.unpriced_calls, on_unpriced,
                                     CONFIG_FILENAME)

    notice = ""
    if not state.known or not resumed_known:
        notice = once_a_day(config_path, "spend-unreadable", CANNOT_BIND + (
            "transcript unreadable. Part of this session's model spend could not be priced, so "
            f"the figures are a floor, not a total ({transcript_path}).\n"))
    elif not ledger_known and any(scope != transcript.SESSION for _, scope, _, _ in budgets):
        notice = once_a_day(config_path, "spend-ledger", CANNOT_BIND + (
            "the local spend ledger could not be read, so spend from earlier sessions is not "
            "counted and a day or total cap sees only this session.\n"))
    return verdict, notice


def allow_out(host):
    """Stdout for "no opinion", which is not the empty string on every host.

    Cursor documents that invalid JSON or a schema mismatch BLOCKS the action, so silence there
    would block every ordinary command, including on the paths where nothing is armed. The
    other four hosts read silence as no opinion and get "".
    """
    return hosts.render(host, "allow", "")


def run(raw, default_event="pre", host=hosts.DEFAULT_HOST):
    """Handle one hook invocation. Returns (stdout, stderr)."""
    try:
        data = json.loads(raw) if raw.strip() else {}
    except ValueError:
        return allow_out(host), "provenrail-guard: hook input was not JSON; allowing.\n"
    if not isinstance(data, dict):
        return allow_out(host), "provenrail-guard: unexpected hook input; allowing.\n"

    try:
        hook = parse_hook_input(host, data, default_event)
    except hosts.PayloadShapeError as exc:
        # A shape we do not recognise on a host nobody has driven means this adapter is wrong,
        # and an adapter that is wrong must not wave the call through as though it had read it.
        reason = (f"Provenrail could not read this {hosts.label(host)} hook payload ({exc}), so "
                  "it could not screen the call. Blocking rather than passing an unscreened "
                  "tool call through.")
        return hosts.render(host, "deny", reason), f"provenrail-guard: {reason}\n"
    config_path = find_config_file()
    catalog = load_catalog()
    try:
        rules, source = load_rules(catalog, config_path)
        budgets, on_unpriced = load_budgets(config_path)
    except ValueError as exc:
        # A broken policy must be loud, not silently permissive.
        return (allow_out(host),
                f"provenrail-guard: could not load the policy ({exc}); NOT enforcing.\n")

    # A budget with no rules IS an armed policy. Counting only rules here sent a config whose
    # whole purpose was a spend cap into the "nothing is armed" path, where it was never
    # evaluated at all.
    if not rules and not budgets:
        return allow_out(host), once_a_day(config_path, "unarmed", (
            "provenrail-guard: hooks are installed but NO guardrails are armed, so nothing is "
            "being blocked. Remove \"policy\" from %s to get the defaults back.\n"
            % (config_path or CONFIG_FILENAME)))

    notice = welcome(config_path, catalog, rules, source)
    if hook["event"] != "pre":
        return allow_out(host), notice

    spent, spend_notice = apply_spend(config_path, budgets, on_unpriced, hook)
    notice += spend_notice
    warning = ""
    if spent is not None and spent[0] == DENY:
        # Before the rules, because a blown cap is not a question about this particular command:
        # once the money is gone, the next tool call is the one that has to stop, whatever it is.
        verdict, rule_id, reason = spent
    else:
        if spent is not None:
            warning = spent[2]
        counts = load_counts(config_path, hook["session_id"])
        before = dict(counts)
        verdict, rule_id, reason = decide(rules, hook["tool"], hook["input"], counts,
                                          hook.get("cwd") or "")
        if counts != before:
            save_session_entry(config_path, hook["session_id"], counts=counts)
    if verdict == "ask":
        mark_ask(config_path, hook["session_id"], hook["tool"], rule_id or "")

    if verdict == "allow":
        # Only blocks, prompts and budget warnings are journalled. A line per allowed tool call
        # would add thousands of rows a day to a file whose entire purpose is to be readable,
        # and the standalone is not the recorder: capturing what the agent DID is what
        # installing Provenrail adds. What it must not lose is what it stopped, and a cap about
        # to stop it, because a warning that only appears once the work is blocked is a
        # post-mortem rather than a control.
        if warning:
            append_journal(config_path, {
                "at": int(time.time()), "event": "pre", "tool": hook["tool"],
                "session_id": hook["session_id"], "verdict": "allow", "rule": None,
                "reason": "", "warning": warning, "by": "standalone"})
            notice += once_a_day(config_path, "spend-warn",
                                 f"provenrail-guard: {warning}\n")
        return allow_out(host), notice

    entry = {
        "at": int(time.time()), "event": "pre", "tool": hook["tool"],
        "session_id": hook["session_id"], "host": host,
        # What the POLICY said. What the host could be told, when it is coarser, goes beside it
        # rather than over it: an oversight rule enforced as a block is still an oversight rule.
        "verdict": verdict, "rule": rule_id,
        "reason": reason, "by": "standalone",
    }
    if hosts.host_verdict(host, verdict) != verdict:
        entry["host_verdict"] = hosts.host_verdict(host, verdict)
    if verdict != "allow":
        # The verb and its flags, never the operands. See `shell.command_shape`: this is what
        # makes `/guard-card` something a person can paste in public without reading it first.
        entry["shape"] = matched_shape(rules, rule_id, match_text(hook["input"]))
    append_journal(config_path, entry)

    text = f"Provenrail guardrail {rule_id}: {reason}"
    if verdict != "ask":
        text += (" [blocked locally and journalled. Install provenrail for a signed receipt "
                 "anyone can verify: uv tool install provenrail]")
    # The ask wording, the note a host that cannot ask gets instead, and the envelope itself
    # are all in `hosts.render`, so the two engines cannot spell them differently.
    return hosts.render(host, verdict, text), notice


def matched_shape(rules, rule_id, text):
    """The shape of the single command that fired `rule_id`."""
    if not isinstance(text, str) or not text:
        return ""
    rule = next((r for r in rules if r.get("id") == rule_id), None)
    pattern = (rule or {}).get("arg_contains") or ""
    if not pattern:
        return command_shape(text)
    compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    for part in segments(text):
        if compiled.search(part):
            return command_shape(part)
    return command_shape(text)


def read_journal(config_path):
    path = journal_path(config_path)
    entries = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    return entries


def card():
    """A paste-ready summary of what the guard has stopped here.

    The one visible moment this product has is the moment it says no, and until now that moment
    left nothing behind but a rule id in a terminal that scrolls away. Every incident thread
    about a coding agent is a post-mortem written after the loss; this is the same story told
    before it, which is the version worth reading.

    Nothing identifying goes in. Not the repository name, not a path, not an operand: the
    directory is a truncated hash so two cards from the same project match without naming it,
    and each command is reduced to its verb and flags.
    """
    import hashlib

    config_path = find_config_file()
    entries = [e for e in read_journal(config_path) if e.get("verdict") in ("deny", "ask")]
    root = str(state_dir(config_path))
    digest = hashlib.sha256(root.encode("utf-8")).hexdigest()[:8]
    lines = []
    if not entries:
        lines.append("Provenrail guard has not had to stop anything here yet.")
        lines.append("")
        lines.append("  Armed and watching. `/guard-status` shows what is armed.")
        return "\n".join(lines) + "\n"

    denies = sum(1 for e in entries if e["verdict"] == "deny")
    asks = len(entries) - denies
    plural = "" if len(entries) == 1 else "s"
    lines.append(f"Provenrail guard stopped {len(entries)} command{plural} in this repo "
                 f"({denies} refused, {asks} sent to me to approve).")
    lines.append("")
    for entry in entries[-10:]:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.get("at", 0)))
        shape = entry.get("shape") or entry.get("tool") or "?"
        lines.append(f"  {stamp}  {entry.get('verdict', '?'):<8} {shape}")
        lines.append("  {}  {}".format(" " * len(stamp), entry.get("rule") or ""))
    lines.append("")
    lines.append(f"  repo {digest} (hashed, not the name). Commands are shown as verb and flags only;")
    lines.append("  every operand is dropped, so nothing here can be a path or a key.")
    lines.append("")
    lines.append("  This card is a local text file and anyone could have typed it. For a "
                 "version")
    lines.append("  signed and hash-chained so somebody else can check it:")
    lines.append("      uv tool install provenrail && pr guard receipt")
    return "\n".join(lines) + "\n"


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
        return f"provenrail-guard: the policy will not load, so NOTHING is enforced: {exc}\n"
    if source != "defaults":
        where = source
    elif config_path is None:
        where = f"built-in defaults (no {CONFIG_FILENAME} in this project)"
    else:
        # There IS a config file; it just says nothing about rules, which is what a file holding
        # only a spend cap looks like. Saying "no config file" there sends the user looking for
        # one that is sitting in front of them.
        where = f"built-in defaults ({config_path} sets no rules)"
    lines.append(f"provenrail-guard: {len(rules)} rules armed, from {where}")
    blocked = sum(1 for r in rules if r.get("effect") == DENY)
    asks = sum(1 for r in rules if r.get("effect") == REQUIRE_OVERSIGHT)
    caps = sum(1 for r in rules if r.get("effect") == LIMIT)
    lines.append(f"  {blocked} block outright, {asks} ask a human first, "
                 f"{caps} cap blast radius")
    if not rules:
        lines.append("  Nothing is being blocked. Remove \"policy\" from the config to restore "
                     "the defaults.")

    # A cap the user set and cannot see is a cap they will assume is working. There is no
    # default budget, so this section is absent unless somebody wrote one.
    try:
        budgets, _on_unpriced = load_budgets(config_path)
    except ValueError as exc:
        return f"provenrail-guard: the policy will not load, so NOTHING is enforced: {exc}\n"
    if budgets:
        day, total, known = spend_ledger.prior_spend(spend_agent_id(config_path))
        lines.append("")
        lines.append(f"  Spend caps ({transcript.ESTIMATE_CAVEAT}):")
        for budget_id, scope, limit_usd, _warn_at in budgets:
            spent = {transcript.DAY: day, transcript.TOTAL: total}.get(scope)
            if spent is None or not known:
                # A session figure lives in the per-session state, not the ledger, and an
                # unreadable ledger is unknown rather than zero. Printing $0.00 of $25 here
                # would be the reassuring lie this whole feature exists to avoid.
                lines.append(f"    {budget_id:<16} cap ${limit_usd:.2f}, spent so far not "
                             "known from here")
            else:
                lines.append(f"    {budget_id:<16} ${spent:.4f} of ${limit_usd:.2f}")

    entries = read_journal(config_path)
    denies = [e for e in entries if e.get("verdict") == "deny"]
    prompts = [e for e in entries if e.get("verdict") == "ask"]
    lines.append("")
    lines.append(f"  Stopped so far: {len(denies)} blocked, {len(prompts)} sent to you "
                 "for approval.")
    for entry in entries[-8:]:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.get("at", 0)))
        verdict = entry.get("verdict", "?")
        shape = entry.get("shape") or entry.get("tool", "?")
        lines.append(f"    {stamp}  {verdict:<5} {shape:<22} {entry.get('rule') or ''}")
    if not entries:
        lines.append("    (nothing yet: either the agent has done nothing dangerous, or the "
                     "hooks are not wired. Ask Claude to run `echo test` and check again.)")
    lines.append("")
    lines.append("  This history is a local text file. It is not signed and anything on this "
                 "machine can edit it.")
    lines.append("  For a receipt someone else can verify: uv tool install provenrail && "
                 "pr guard receipt")
    if denies or prompts:
        lines.append("  To show someone what it caught: /guard-card")
    return "\n".join(lines) + "\n"


def main(argv):
    if "--status" in argv:
        sys.stdout.write(status())
        return 0
    if "--card" in argv:
        sys.stdout.write(card())
        return 0
    event = "pre"
    host = hosts.DEFAULT_HOST
    for i, arg in enumerate(argv):
        if arg == "--event" and i + 1 < len(argv):
            event = argv[i + 1]
        elif arg == "--host" and i + 1 < len(argv):
            host = argv[i + 1]
        elif arg in ("pre", "post"):
            event = arg
    if host not in hosts.HOSTS:
        # Exit 2 is the one blocking signal every supported host documents. A host we have no
        # contract for must not be answered with silence, because silence is "allow" on four of
        # the five and this file would then be a guard that had quietly stopped guarding.
        sys.stderr.write(
            "provenrail-guard: unknown host {!r}; known hosts: {}. NOT enforcing: nothing here "
            "has screened this tool call.\n".format(host, ", ".join(hosts.HOST_NAMES)))
        return 2
    try:
        stdout, stderr = run(sys.stdin.read(), default_event=event, host=host)
    except Exception as exc:  # never break the session
        sys.stderr.write(f"provenrail-guard: internal error ({exc}); allowing.\n")
        return 0
    if stderr:
        sys.stderr.write(stderr)
    if stdout:
        sys.stdout.write(stdout + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
