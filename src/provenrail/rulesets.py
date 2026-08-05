"""A catalogue of prebuilt guardrail rules, grouped into packs you switch on by name.

Writing good rules from a blank page is the reason most people never configure guardrails at
all. This is the starting point: named packs of rules for the things agents actually do
damage with, enabled from `.provenrail.json` with no code:

    {"policy": {"use": ["destructive", "secrets", "money"]}}

You can enable a whole pack, or a single rule by its id, and mix either with your own
`rules`. Nothing here is on by default. An empty `use` means no guardrails, exactly as
before, because a tool that silently starts blocking an agent's actions after an upgrade
would be worse than one that blocks nothing.

**The limitation that matters, stated up front.** These rules match on *tool names* and on
*argument text*, and every codebase names its tools differently. A rule for `delete_*` does
nothing if your tool is called `remove_record` or `db_exec`. So a pack is a well-informed
guess about your naming, not a guarantee of coverage, and enabling one does not mean you are
covered. Run `pr rules --check bundle.json` against a real recorded run: it reports which of
your actual tool names each enabled rule would have matched, which turns the guess into
evidence. Rules that match nothing are the ones to worry about.

Each rule also carries a `note` describing its false-positive risk, because a guardrail that
blocks legitimate work gets switched off within a day, taking the useful rules with it.
"""

from __future__ import annotations

from typing import Any

# Effects: "deny" blocks outright, "require_oversight" allows only after a recorded human
# approval in the same session, "limit" allows N per session then blocks.

CATALOG: dict[str, dict[str, Any]] = {
    "destructive": {
        "title": "Destructive actions",
        "description": "Tools that delete, drop, or irreversibly overwrite data.",
        "rules": [
            {"id": "destructive.delete-tools", "effect": "deny", "event_type": "tool_call",
             "tool": "delete_*", "reason": "destructive tool: deletes data",
             "note": "Blocks every tool whose name starts with delete_. If your agent is "
                     "supposed to delete things, scope this to the specific tool instead."},
            {"id": "destructive.drop-tools", "effect": "deny", "event_type": "tool_call",
             "tool": "drop_*", "reason": "destructive tool: drops a table or database",
             "note": "Low false-positive risk; drop_ is rarely a safe operation."},
            {"id": "destructive.truncate-tools", "effect": "deny", "event_type": "tool_call",
             "tool": "truncate_*", "reason": "destructive tool: truncates a table",
             "note": "Low false-positive risk."},
            {"id": "destructive.destroy-tools", "effect": "deny", "event_type": "tool_call",
             "tool": "destroy_*", "reason": "destructive tool: destroys a resource",
             "note": "Matches Terraform-style destroy_ helpers."},
            {"id": "destructive.raw-device-write", "effect": "deny",
             "event_type": "tool_call", "arg_contains": r"\bdd\s[^\n]*\bof=/dev/",
             "reason": "argument writes raw bytes to a block device",
             "note": "Very low false-positive risk: `dd of=/dev/...` outside an imaging "
                     "workflow destroys a disk and cannot be undone."},
            {"id": "destructive.kubectl-delete-namespace", "effect": "deny",
             "event_type": "tool_call",
             # `namespaces` (plural) is equally valid kubectl and equally destructive; the
             # word boundary after `namespace` refused to match it.
             "arg_contains": r"kubectl\s+delete\s+(namespaces?|ns)\b",
             "reason": "argument deletes a Kubernetes namespace and everything in it",
             "note": "A namespace delete cascades to every resource inside it. Scope this "
                     "out if your agent legitimately tears down ephemeral namespaces."},
            {"id": "destructive.recursive-force-remove", "effect": "deny",
             # RECURSION is the thing that cannot be undone: `rm -rf` empties a tree, `rm -f`
             # deletes the files you named. Both spellings of recursion are here (short flags in
             # any order, GNU --recursive) plus `find ... -delete`, which deletes every match and
             # is what an agent asked to "clean up old files" actually emits.
             #
             # Plain `rm -f one-file.txt` used to be denied by this rule, and the destructive
             # pack is on by default. An agent that cannot delete a build artifact is an agent
             # whose owner switches the whole pack off inside a day, taking every working rule
             # with it. Forced non-recursive deletes are covered below, as an approval rather
             # than a refusal.
             "event_type": "tool_call",
             "arg_contains": r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*|--recursive)\b"
                             r"|\brm\s+(-[a-zA-Z]+\s+)*--recursive\b"
                             r"|\bfind\s[^\n]*\s-delete\b",
             "reason": "argument contains a recursive delete",
             "note": "Recursive deletes only (rm -r / -rf / --recursive, and find -delete). A "
                     "forced but non-recursive `rm -f file` is handled by "
                     "destructive.force-remove instead, because denying it breaks ordinary "
                     "work. Matches shell text in ANY tool's arguments, so it also covers a "
                     "generic `terminal` or `bash` tool, and can fire on a doc string that "
                     "quotes rm -rf."},
            {"id": "destructive.force-remove", "effect": "require_oversight",
             # Not a refusal: `rm -f` is ordinary in a build directory and irreversible in a
             # home directory, and the rule cannot tell which one it is looking at. A recorded
             # human decision is the honest response to a genuinely ambiguous action.
             "event_type": "tool_call",
             "arg_contains": r"\brm\s+((-[a-zA-Z]*f[a-zA-Z]*|--force)\s+)+",
             "reason": "a forced delete skips every confirmation, so it needs a recorded human "
                       "decision",
             "note": "Fires on `rm -f` without recursion. Scope it out if your agent's job is "
                     "cleaning build output; the recursive rule above still denies `rm -rf`."},
            {"id": "destructive.sql-drop-or-truncate", "effect": "deny",
             "event_type": "tool_call",
             # `TABLE` is optional after TRUNCATE: PostgreSQL and MySQL both accept
             # `TRUNCATE orders`, and requiring the keyword let the most common spelling of the
             # statement straight through while the copy advertised TRUNCATE as blocked.
             # Every DROP object type, not three of them. Dropping a unique index on a
             # production key, or a view a report depends on, is as destructive as the table.
             "arg_contains": r"\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|MATERIALIZED\s+VIEW"
                             r"|FUNCTION|PROCEDURE|TRIGGER|SEQUENCE|TYPE|ROLE|USER|EXTENSION"
                             r"|CONSTRAINT|COLUMN|POLICY|PUBLICATION|SUBSCRIPTION|TABLESPACE)\b"
                             r"|TRUNCATE\s+(TABLE\s+)?[\"'`\w])",
             "reason": "argument contains a destructive SQL statement",
             "note": "Covers a generic query tool. Fires on the text, so a migration tool "
                     "that legitimately drops tables will be blocked."},
            {"id": "destructive.delete-without-where", "effect": "deny",
             "event_type": "tool_call",
             # Arguments arrive as JSON text, so a statement's end can be a closing quote
             # rather than end-of-string; without the quote alternative, {"q": "DELETE FROM
             # orders", "db": "prod"} slips through because ", \"db\"..." follows the table.
             # The table-name class excluded quotes, so a quoted identifier (`DELETE FROM
             # "users"`, which Postgres, MySQL and SQLite all accept, and which codegen emits)
             # left the name group matching nothing and the whole rule failing.
             "arg_contains": r"\bDELETE\s+FROM\s+[\"'`]?[^\s;\"'`]+[\"'`]?\s*(;|\"|'|$)",
             "reason": "argument contains a DELETE with no WHERE clause",
             "note": "Targets the classic accident: an unbounded DELETE. A deliberate "
                     "full-table delete is blocked too."},
        ],
    },
    "secrets": {
        "title": "Credentials and secrets",
        "description": "Keys, tokens and private material appearing in tool arguments.",
        "rules": [
            {"id": "secrets.aws-access-key", "effect": "deny", "event_type": "tool_call",
             "arg_contains": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
             "reason": "argument contains what looks like an AWS access key id",
             "note": "The AKIA/ASIA prefix plus 16 chars is specific; false positives are rare."},
            {"id": "secrets.private-key-block", "effect": "deny", "event_type": "tool_call",
             "arg_contains": r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
             "reason": "argument contains a private key block",
             "note": "Very low false-positive risk."},
            {"id": "secrets.bearer-token", "effect": "deny", "event_type": "tool_call",
             # `sk-[A-Za-z0-9]{16,}` missed every current OpenAI and Anthropic key, because
             # `sk-proj-...` and `sk-ant-...` carry a hyphen inside the prefix and the class
             # stopped at it. The copy has advertised "leaked API keys are blocked" throughout,
             # so this matched only the retired key format.
             # Stripe uses sk_ with an UNDERSCORE, so the hyphen form matched every OpenAI and
             # Anthropic key and no Stripe one, and GitHub's fine-grained PATs (github_pat_,
             # shipped 2022) matched nothing at all. Both are live formats a leaked key arrives
             # in today.
             "arg_contains": r"\b(sk-[A-Za-z0-9_-]{20,}|sk_(live|test)_[A-Za-z0-9]{16,}"
                             r"|rk_(live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,}"
                             r"|github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{20,}"
                             r"|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}"
                             r"|xapp-[0-9]-[A-Za-z0-9-]{10,}"
                             r"|AIza[0-9A-Za-z_-]{30,}|ya29\.[0-9A-Za-z_-]{20,}"
                             r"|glpat-[A-Za-z0-9_-]{16,}|dop_v1_[a-f0-9]{32,}"
                             r"|npm_[A-Za-z0-9]{30,}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{10,}"
                             r"|hf_[A-Za-z0-9]{30,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})",
             "reason": "argument contains what looks like an API token",
             "note": "Covers OpenAI/Anthropic sk-, Stripe sk_live/sk_test and webhook secrets, "
                     "GitHub classic and fine-grained PATs, GitLab, Slack, Google, "
                     "DigitalOcean, npm, PyPI, HuggingFace and SendGrid. A doc example "
                     "containing a fake token will also match."},
            {"id": "secrets.jwt", "effect": "deny", "event_type": "tool_call",
             "arg_contains": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
             "reason": "argument contains what looks like a JWT",
             "note": "Some agents legitimately pass their own JWT to a tool; scope or drop "
                     "this rule if that is your design."},
            {"id": "secrets.env-file-read", "effect": "require_oversight",
             "event_type": "tool_call", "arg_contains": r"(^|[\s'\"/])\.env(\.[a-z]+)?\b",
             "reason": "action touches a .env file",
             "note": "Oversight rather than deny: reading .env is sometimes legitimate setup."},
        ],
    },
    "money": {
        "title": "Money movement",
        "description": "Payments, transfers and refunds. Human approval rather than a block.",
        "rules": [
            {"id": "money.wire-transfer", "effect": "require_oversight",
             "event_type": "tool_call", "tool": "*transfer*",
             "reason": "money movement requires a recorded human approval",
             "note": "Also matches file transfer helpers; rename or scope if that is a "
                     "problem in your toolset."},
            {"id": "money.payment", "effect": "require_oversight", "event_type": "tool_call",
             "tool": "*payment*", "reason": "payment requires a recorded human approval",
             "note": "Matches create_payment, payment_intent and similar."},
            {"id": "money.refund", "effect": "require_oversight", "event_type": "tool_call",
             "tool": "*refund*", "reason": "refund requires a recorded human approval",
             "note": "Refunds are a common target for prompt-injection abuse."},
            {"id": "money.charge", "effect": "require_oversight", "event_type": "tool_call",
             "tool": "*charge*", "reason": "charging a customer requires a recorded approval",
             "note": "May match discharge_ or recharge_ helpers."},
        ],
    },
    "production": {
        "title": "Production infrastructure",
        "description": "Deploys, migrations and infrastructure changes.",
        "rules": [
            {"id": "production.deploy", "effect": "require_oversight", "event_type": "tool_call",
             "tool": "deploy*", "reason": "deploying requires a recorded human approval",
             "note": "Oversight, not deny, so a human-in-the-loop pipeline still works."},
            {"id": "production.migrate", "effect": "require_oversight",
             "event_type": "tool_call", "tool": "*migrat*",
             "reason": "a schema migration requires a recorded human approval",
             "note": "Matches migrate, run_migration and similar."},
            {"id": "production.dns-change", "effect": "require_oversight",
             "event_type": "tool_call", "tool": "*dns*",
             "reason": "a DNS change requires a recorded human approval",
             "note": "DNS mistakes are slow to detect and hard to reverse."},
            {"id": "production.connection-string", "effect": "require_oversight",
             "event_type": "tool_call",
             # The three tool-name rules above (deploy*, *migrat*, *dns*) never fire under a
             # coding agent, whose tools are Bash/Edit/Write. Without a text rule the whole
             # pack was inert for the host we actually ship for, while the copy advertised
             # "anything pointed at a production host or database".
             "arg_contains": r"(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^\s\"']*"
                             r"(prod|production)",
             "reason": "argument points a database connection at production",
             "note": "Oversight, not deny: reading production is often legitimate, deciding "
                     "to is a human's call. Matches the host or database name, so a staging "
                     "host called prod-replica also matches."},
            {"id": "production.deploy-command", "effect": "require_oversight",
             "event_type": "tool_call",
             # Only the verbs that CHANGE production. The old pattern matched any kubectl or
             # helm command carrying `--namespace prod`, so `kubectl get pods --namespace prod`,
             # the most ordinary read there is, needed a human approval. A rule that stops people
             # looking at production is a rule they turn off.
             "arg_contains": r"\b((kubectl\s+(apply|delete|create|replace|patch|scale|rollout|"
                             r"drain|cordon|taint|edit|set|annotate|label)|helm\s+(install|"
                             r"upgrade|uninstall|rollback|delete))\s[^\n]*(--context|--namespace)"
                             r"[= ]\s*[\"']?(prod|production)"
                             r"|(vercel|netlify|fly|wrangler|serverless|sls)\s+deploy\b"
                             r"|npx\s+wrangler\s+(pages\s+)?deploy\b"
                             r"|git\s+push\s+[^\n]*\b(production|prod)\b)",
             "reason": "argument runs a deployment",
             "note": "Oversight, not deny: shipping is the job. The point is that a human "
                     "signed off and it is recorded, not that it is impossible."},
            {"id": "production.force-push", "effect": "deny", "event_type": "tool_call",
             "arg_contains": r"git\s+push\b[^\n]*(--force\b|(?<![\w-])-f(?![\w-]))",
             "reason": "argument contains a force push",
             "note": "A force push can destroy history irrecoverably. "
                     "--force-with-lease also matches."},
            {"id": "production.terraform-destroy", "effect": "deny", "event_type": "tool_call",
             # `terraform destroy` is the deprecated spelling. Current Terraform documents
             # `terraform apply -destroy` and `terraform plan -destroy`, which is what a
             # modern pipeline and a modern agent both emit, and -auto-approve makes the flag
             # form the more dangerous of the two.
             "arg_contains": r"terraform\s+(destroy\b|(apply|plan)\s[^\n]*-destroy\b)",
             "reason": "argument contains terraform destroy",
             "note": "Very low false-positive risk."},
        ],
    },
    "access": {
        "title": "Access and permissions",
        "description": "Privilege changes, which are how a small incident becomes a large one.",
        "rules": [
            {"id": "access.grant-permissions", "effect": "require_oversight",
             "event_type": "tool_call", "tool": "grant_*",
             "reason": "granting access requires a recorded human approval",
             "note": "Covers grant_role, grant_access and similar."},
            {"id": "access.iam-change", "effect": "require_oversight", "event_type": "tool_call",
             "tool": "*iam*", "reason": "an IAM change requires a recorded human approval",
             "note": "Cloud privilege escalation is a common post-compromise step."},
            {"id": "access.world-writable-chmod", "effect": "deny", "event_type": "tool_call",
             # An octal prefix (`chmod 0777`, which is what most documentation shows) and the
             # symbolic forms (`chmod a+rwx`, `chmod o+w`, which is what people type) both
             # walked past a pattern that demanded the literal digits 777.
             # World-writable is the "other" digit carrying the write bit, which is 2, 3, 6 or
             # 7, in a 3 or 4 digit octal mode. Plus the symbolic forms that grant write to
             # other (`a+rwx`, `o+w`, `ugo+w`). The old pattern demanded the literal digits
             # 777, so `chmod 0777` (what the docs show) and `chmod a+rwx` (what people type)
             # both walked straight past it.
             "arg_contains": r"chmod\s[^\n]*?(0?[0-7]{2}[2367]\b"
                             r"|[augo]*[ao][augo]*[+=][rwxXst]*w)",
             "reason": "argument makes a path world-writable",
             "note": "World-writable is the OTHER digit carrying the write bit (2, 3, 6 or 7), "
                     "or a symbolic clause granting write to a or o, so `chmod 755` and "
                     "`chmod u+w` are untouched. Low false-positive risk."},
            {"id": "access.disable-mfa", "effect": "deny", "event_type": "tool_call",
             "arg_contains": r"(disable|remove|deactivate)[\s_-]*(mfa|2fa|two[\s_-]?factor)",
             "reason": "argument attempts to disable multi-factor authentication",
             "note": "Rarely legitimate for an autonomous agent."},
        ],
    },
    "exfiltration": {
        "title": "Data movement outward",
        "description": "Bulk reads and outbound sends, the shape of data exfiltration.",
        "rules": [
            {"id": "exfiltration.select-star-no-limit", "effect": "require_oversight",
             "event_type": "tool_call",
             # Same JSON-boundary handling as destructive.delete-without-where, INCLUDING the
             # optional quoted identifier: `SELECT * FROM "users"` is what Postgres, Supabase and
             # most ORM codegen emit, and the unquoted-only class left the name group matching
             # nothing, so the whole rule failed on the commonest spelling.
             "arg_contains": r"\bSELECT\s+\*\s+FROM\s+[\"'`]?[^\s;\"'`]+[\"'`]?\s*(;|\"|'|$)",
             "reason": "unbounded SELECT * with no WHERE or LIMIT",
             "note": "Fires on legitimate small-table reads too; oversight rather than deny."},
            {"id": "exfiltration.external-upload", "effect": "require_oversight",
             "event_type": "tool_call", "tool": "upload_*",
             "reason": "an outbound upload requires a recorded human approval",
             "note": "Scope to the specific tool if uploading is your agent's main job."},
            {"id": "exfiltration.paste-sites", "effect": "deny", "event_type": "tool_call",
             # A five-site list is a list an agent walks around by changing one word. This is
             # still not exhaustive and cannot be: it is a speed bump, and the note says so.
             "arg_contains": r"\b(pastebin\.com|gist\.github\.com|transfer\.sh|file\.io"
                             r"|0x0\.st|ix\.io|dpaste\.(com|org)|hastebin\.com|sprunge\.us"
                             r"|termbin\.com|paste\.rs|bashupload\.com|oshi\.at|catbox\.moe"
                             r"|litterbox\.catbox\.moe|anonfiles\.com|gofile\.io|tmpfiles\.org"
                             r"|ttm\.sh|clbin\.com|envs\.sh|paste\.ee|controlc\.com)\b",
             "reason": "argument references a public paste or file-drop site",
             "note": "A classic exfiltration destination. Blocks legitimate gist use too."},
        ],
    },
    "blast-radius": {
        "title": "Blast radius limits",
        "description": "Per-session caps, so a loop cannot do unlimited damage.",
        "rules": [
            {"id": "blast-radius.email-cap", "effect": "limit", "event_type": "tool_call",
             "tool": "*email*", "max_per_session": 25,
             "reason": "per-session email cap reached",
             "note": "Raise the cap for a bulk-mail agent. The point is to stop a runaway "
                     "loop, not to stop normal work."},
            {"id": "blast-radius.message-cap", "effect": "limit", "event_type": "tool_call",
             "tool": "*message*", "max_per_session": 50,
             "reason": "per-session messaging cap reached",
             "note": "Covers Slack, SMS and chat helpers."},
            {"id": "blast-radius.tool-call-cap", "effect": "limit", "event_type": "tool_call",
             "tool": "*", "max_per_session": 500,
             "reason": "per-session tool-call cap reached",
             "note": "A backstop against an infinite agent loop. Set well above your normal "
                     "session length before enabling."},
        ],
    },
}

# Fields the policy engine understands. `note` is catalogue metadata for humans and is
# stripped before the rule reaches the engine.
_ENGINE_FIELDS = ("id", "effect", "event_type", "tool", "resource", "provider",
                  "arg_contains", "max_per_session", "reason")


def pack_ids() -> list[str]:
    return list(CATALOG)


def all_rules() -> list[dict[str, Any]]:
    """Every catalogue rule, with its pack recorded, for listing and lookup."""
    out = []
    for pack, spec in CATALOG.items():
        for rule in spec["rules"]:
            out.append({**rule, "pack": pack})
    return out


def rule_by_id(rule_id: str) -> dict[str, Any] | None:
    return next((r for r in all_rules() if r["id"] == rule_id), None)


class UnknownRuleError(ValueError):
    """A `use` entry names no pack and no rule.

    Raised rather than skipped: a typo'd pack name would otherwise leave the operator
    believing a guardrail is enabled when nothing is.
    """


def resolve(names: list[str] | tuple[str, ...] | None) -> list[dict[str, Any]]:
    """Expand a list of pack ids and rule ids into engine-ready rules.

    Order follows the order given, duplicates are dropped (first wins), and every name must
    resolve or it raises.
    """
    if not names:
        return []
    if isinstance(names, str):
        names = [names]
    resolved: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(rule: dict[str, Any]) -> None:
        if rule["id"] in seen:
            return
        seen.add(rule["id"])
        resolved.append({k: v for k, v in rule.items() if k in _ENGINE_FIELDS})

    for name in names:
        if name in CATALOG:
            for rule in CATALOG[name]["rules"]:
                _add(rule)
            continue
        found = rule_by_id(name)
        if found is None:
            raise UnknownRuleError(
                f'"{name}" is not a known rule pack or rule id. Packs: {sorted(CATALOG)}. '
                f"Run `pr rules` to list every rule.")
        _add(found)
    return resolved
