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

#: Tools that carry TEXT rather than a command to run. A rule about shell commands has no
#: business reading a document, a search query or a prompt: `docs/security.md` explaining what
#: `rm -rf /` does, a migration containing `DROP TABLE legacy`, a test fixture holding a fake
#: token, a web search for "git reset --hard recovery", a subagent prompt quoting a dangerous
#: command. All of those were refused, which makes the guard something an agent has to be
#: uninstalled to work around.
#:
#: The secrets pack deliberately does NOT carry this on the key-shaped rules, because writing a
#: real credential into a file IS the harm they exist to catch.
WRITERS = ("Write|Edit|MultiEdit|NotebookEdit|Task|Agent|WebFetch|WebSearch|AskUserQuestion"
           "|TodoWrite|str_replace*|create_file|*write_file")

#: The above, plus the tools that only LOOK at things. A rule about shell commands must not
#: fire because a file being read, a glob, or a grep pattern contains the text of one:
#: `grep -rn "rm -rf" docs/` is a search, not a delete. Reading is left in `WRITERS` rather
#: than here on purpose, because two secrets rules are specifically about what gets read.
NOT_A_COMMAND = WRITERS + "|Read|Glob|Grep"


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
            {"id": "destructive.mcp-delete-tools", "effect": "require_oversight",
             # The incident this product's own homepage cites was an agent calling a hosting
             # provider's volume-delete through an MCP server. MCP tools are named
             # `mcp__<server>__<camelCaseMethod>`, so `delete_*` never matched one, and the
             # hook matcher did not even hand them over. Oversight rather than deny, because
             # deleting a resource through an MCP tool is frequently the task.
             "event_type": "tool_call",
             # Anchored to the METHOD, which is the segment after the last `__`. Unanchored,
             # `mcp__*[wW]ipe*` matched `mcp__ios-simulator-mcp__ui_swipe`, because "swipe"
             # ends in "wipe", and a simulator gesture is not a resource being destroyed.
             "tool": "mcp__*__[dD]elete*|mcp__*__[dD]estroy*|mcp__*__[dD]rop*"
                     "|mcp__*__[rR]emove*|mcp__*__[tT]erminate*|mcp__*__[pP]urge*"
                     "|mcp__*__[wW]ipe*|mcp__*__*_[dD]elete*|mcp__*__*_[dD]estroy*",
             "reason": "an MCP tool that deletes or destroys a resource",
             "note": "Matches on the tool NAME, so it needs no argument text and covers a "
                     "server this catalogue has never heard of. Rename or scope it out if "
                     "your agent's job is tearing down ephemeral resources."},
            {"id": "destructive.raw-device-write", "effect": "deny",
             "not_tool": NOT_A_COMMAND,
             "event_type": "tool_call", "arg_contains": r"\bdd\s[^\n]*\bof=/dev/",
             "reason": "argument writes raw bytes to a block device",
             "note": "Very low false-positive risk: `dd of=/dev/...` outside an imaging "
                     "workflow destroys a disk and cannot be undone."},
            {"id": "destructive.kubectl-delete-namespace", "effect": "deny",
             "event_type": "tool_call",
             # `namespaces` (plural) is equally valid kubectl and equally destructive; the
             # word boundary after `namespace` refused to match it.
             "not_tool": NOT_A_COMMAND,
             "arg_contains": r"kubectl\s+delete\s+(namespaces?|ns)\b",
             "reason": "argument deletes a Kubernetes namespace and everything in it",
             "note": "A namespace delete cascades to every resource inside it. Scope this "
                     "out if your agent legitimately tears down ephemeral namespaces."},
            {"id": "destructive.recursive-force-remove", "effect": "deny",
             # Screening the VERB was the original mistake, and it was measured rather than
             # argued: over 36,929 real agent Bash calls this rule and its sibling produced 646
             # of 824 interruptions, and the samples were `rm -rf .next out` before a build and
             # `rm -rf app/en` during a refactor. Nobody has ever lost work to the letters
             # `rm -rf`; they lost it to the target. So the regex still finds the recursive
             # delete and a predicate decides where it points: `/`, a home directory, a whole
             # disk, a two-segment container of unrelated things, or a variable that becomes
             # `/` when it is unset. Everything inside the repository is the agent doing its job.
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*|--recursive)\b"
                             r"|\brm\s+(-[a-zA-Z]+\s+)*--recursive\b"
                             r"|\bfind\s[^\n]*\s-delete\b",
             "predicate": "delete.catastrophic",
             "reason": "argument recursively deletes something outside the project that cannot "
                       "be regenerated",
             "note": "Denies a recursive delete only when the target is unrecoverable: /, a "
                     "home directory, a top-level or two-segment system path, an unset "
                     "variable followed by a slash, or --no-preserve-root. A recursive delete "
                     "inside the repository, under a temp directory, or in a package cache is "
                     "allowed outright; one that merely leaves the repository is handled by "
                     "destructive.force-remove as an approval. Scoped to Bash, because the same "
                     "text inside a file being WRITTEN is documentation, not a command."},
            {"id": "destructive.force-remove", "effect": "require_oversight",
             # Deleting outside the project you are working in is the ambiguous case: it can be
             # a stale sibling checkout or it can be somebody's photographs, and no amount of
             # regex tells the two apart. A recorded human decision is the honest answer. Inside
             # the project it is not ambiguous at all, so it is not asked about.
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\brm\s+(-[a-zA-Z]+|--force|--recursive)"
                             r"|\bfind\s[^\n]*\s-delete\b",
             "predicate": "delete.outside_workspace",
             "reason": "this delete targets a path outside the project, so it needs a recorded "
                       "human decision",
             "note": "Fires only on deletes that leave the repository the agent is working in. "
                     "Build output, node_modules, __pycache__, /tmp and package caches are "
                     "allowed silently. Falls back to asking when a target contains a variable "
                     "it cannot resolve, because an unknown path is not a path known to be safe."},
            {"id": "destructive.sql-drop-or-truncate", "effect": "deny",
             "event_type": "tool_call",
             # `TABLE` is optional after TRUNCATE: PostgreSQL and MySQL both accept
             # `TRUNCATE orders`, and requiring the keyword let the most common spelling of the
             # statement straight through while the copy advertised TRUNCATE as blocked.
             # Every DROP object type, not three of them. Dropping a unique index on a
             # production key, or a view a report depends on, is as destructive as the table.
             "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|MATERIALIZED\s+VIEW"
                             r"|FUNCTION|PROCEDURE|TRIGGER|SEQUENCE|TYPE|ROLE|USER|EXTENSION"
                             r"|CONSTRAINT|COLUMN|POLICY|PUBLICATION|SUBSCRIPTION|TABLESPACE)\b"
                             r"|TRUNCATE\s+(TABLE\s+)?[\"'`]?[A-Za-z_][\w$.]*[\"'`]?\s*(;|$|[\"']))",
             "predicate": "command.not_a_rehearsal",
             "reason": "argument contains a destructive SQL statement",
             "note": "The statement must END after the object name (semicolon, quote, or end "
                     "of the argument). Without that, `class=\"min-w-0 truncate text-sm\"`, a "
                     "Tailwind class every frontend agent writes hourly, was a denied DROP. "
                     "Covers a generic query tool. Fires on the text, so a migration tool "
                     "that legitimately drops tables will be blocked."},
            {"id": "destructive.delete-without-where", "effect": "deny",
             "event_type": "tool_call",
             # Arguments arrive as JSON text, so a statement's end can be a closing quote
             # rather than end-of-string; without the quote alternative, {"q": "DELETE FROM
             # orders", "db": "prod"} slips through because ", \"db\"..." follows the table.
             # The table-name class excluded quotes, so a quoted identifier (`DELETE FROM
             # "users"`, which Postgres, MySQL and SQLite all accept, and which codegen emits)
             # left the name group matching nothing and the whole rule failing.
             "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bDELETE\s+FROM\s+[\"'`]?[^\s;\"'`]+[\"'`]?\s*(;|\"|'|$)",
             "predicate": "command.not_a_rehearsal",
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
            {"id": "secrets.credential-file-read", "effect": "require_oversight",
             # Distinct from the `.env` rule because these are the machine's own credentials
             # rather than the project's: an SSH private key, cloud CLI tokens, a kubeconfig, a
             # browser cookie jar. An agent has no routine reason to open one, and until the
             # hook matcher covered every tool this could not fire on a `Read` at all.
             "event_type": "tool_call", "not_tool": WRITERS,
             "arg_contains": r"\.ssh/(id_[a-z0-9]+|identity)(?![a-z0-9]|\.pub)"
                             r"|\.aws/credentials\b"
                             r"|\.config/gcloud/[\w./-]*credentials"
                             r"|\.kube/config\b"
                             r"|\.docker/config\.json\b"
                             r"|\.netrc\b"
                             r"|\.npmrc\b"
                             r"|\.pypirc\b"
                             r"|\.gnupg/[\w.-]*\.(key|gpg)\b"
                             r"|Library/Keychains/|/etc/shadow\b",
             "reason": "action reads a credential file belonging to this machine",
             "note": "Oversight rather than deny: setting up a deploy legitimately touches "
                     "these. Public keys (`id_rsa.pub`) are excluded."},
            {"id": "secrets.env-file-read", "effect": "require_oversight",
             # This one is about READING the file. The other rules in this pack deliberately do
             # screen file writes, because putting a live credential into a file is the harm
             # they exist to catch; a source comment that says `BASE_URL=... see .env` is not.
             "event_type": "tool_call", "not_tool": WRITERS, "arg_contains": r"(^|[\s'\"/])\.env"
                             r"(?!\.(example|sample|template|dist|schema|md)\b)"
                             r"(\.[a-z]+)?\b",
             "reason": "action touches a .env file",
             "note": "Oversight rather than deny: reading .env is sometimes legitimate setup. "
                     "`.env.example` and the other template spellings are excluded: they are "
                     "committed to the repository on purpose and hold no secret, and asking "
                     "about `cp .env.example .env` teaches people to approve without reading."},
        ],
    },
    "git-worktree": {
        "title": "Losing uncommitted work",
        "description": "Git commands that throw away changes no remote has a copy of.",
        "rules": [
            # This pack exists because the incident everyone actually has is not `rm -rf /`. It
            # is an agent running `git reset --hard` or `git checkout -- .` over work that was
            # never committed. Read forty data-loss reports against a coding agent and the same
            # eight commands appear; not one of them contains the word `rm`.
            #
            # Every rule here asks rather than refuses, and asks only when there is something
            # to lose: `git.would_lose_work` runs `git status --porcelain` and checks for
            # commits the upstream has not seen. On a clean, pushed tree `git reset --hard`
            # destroys nothing, and a prompt about nothing is how people learn to click through
            # prompts. When the repository cannot be read the answer is "at risk", because a
            # guard that could not look has not checked.
            {"id": "git-worktree.reset-hard", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bgit\s+(-[cC]\s+\S+\s+)*reset\s[^\n]*(--hard|--merge)\b",
             "predicate": "git.would_lose_work",
             "reason": "this resets the working tree and there are changes or commits here that "
                       "exist nowhere else",
             "note": "Silent when the tree is clean and pushed, because then it loses nothing."},
            {"id": "git-worktree.discard-changes", "effect": "require_oversight",
             # `git checkout -- .`, `git checkout .`, `git restore .`. `git restore --staged`
             # on its own only unstages and is left alone; adding `--worktree` makes it destroy
             # the file, so that spelling is caught.
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bgit\s+checkout\s+(--\s|\.(\s|$)|[^\n]*\s--\s)"
                             r"|\bgit\s+restore\s+(?!--staged(?![^\n]*--worktree))",
             "predicate": "git.would_lose_work",
             "reason": "this discards edits in the working tree that are not committed anywhere",
             "note": "Excludes `git restore --staged`, which only unstages."},
            {"id": "git-worktree.clean-force", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bgit\s+clean\s+(-[a-zA-Z]*f|--force)",
             "predicate": "git.would_lose_work",
             "reason": "this deletes untracked files, which by definition no commit holds",
             "note": "`git clean -xdff` also removes ignored files: .env, local databases, "
                     "anything the repository was told not to track."},
            {"id": "git-worktree.stash-drop", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bgit\s+stash\s+(drop|clear)\b",
             "reason": "a dropped stash is not recoverable through any git command",
             "note": "`git stash` and `git stash pop` are untouched; only discarding is asked "
                     "about."},
            {"id": "git-worktree.branch-delete-force", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bgit\s+branch\s+(-[a-zA-Z]*D|--delete\s+--force"
                             r"|--force\s+--delete)\b",
             "predicate": "git.force_delete_branch",
             "reason": "-D deletes a branch whether or not it is merged",
             "note": "`git branch -d` refuses to delete unmerged work and is not matched."},
            {"id": "git-worktree.worktree-remove-force", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bgit\s+worktree\s+remove\s[^\n]*(--force|\s-f)\b",
             "reason": "--force removes a worktree that still has modifications in it",
             "note": "Without --force git refuses, so only the forced spelling is matched."},
            {"id": "git-worktree.history-rewrite", "effect": "deny",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bgit\s+(filter-branch|filter-repo)\b"
                             r"|\bgit\s+reflog\s+expire\b",
             "reason": "this rewrites or expires history, which removes the last way back",
             "note": "The reflog is what recovers a bad reset. Expiring it removes the "
                     "recovery path for every other rule in this pack. Deny rather than ask, "
                     "because no routine task needs it."},
            {"id": "git-worktree.delete-remote-branch", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bgit\s+push\s[^\n]*--delete\b"
                             r"|\bgit\s+push\s+\S+\s+:\S",
             "reason": "this deletes a branch on the remote, which may be the only copy left",
             "note": "Covers both `--delete` and the colon refspec spelling."},
            {"id": "git-worktree.recursive-delete-windows", "effect": "require_oversight",
             # The path logic the rm rules use is POSIX, so a PowerShell or cmd delete cannot be
             # told safe from catastrophic here and is always asked about.
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"Remove-Item\s[^\n]*(-Recurse|-r\b)"
                             r"|\brmdir\s+/[sS]\b|\bdel\s+/[sS]\b",
             "reason": "a recursive delete on Windows, where the target cannot be resolved here",
             "note": "Always asks: this rule has no way to tell a build directory from a home "
                     "directory on a Windows path."},
            {"id": "git-worktree.rsync-delete", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\brsync\s[^\n]*--delete(-\w+)?\b",
             "reason": "--delete removes files at the destination that are absent from the source",
             "note": "A mistyped source directory turns a sync into a wipe of the destination."},
        ],
    },
    "database": {
        "title": "Resetting a database",
        "description": "Framework commands that drop and recreate a database in one step.",
        "rules": [
            # The shape of this incident: an agent debugging a migration reaches for the reset
            # command its framework documents, and the connection string in the environment
            # points at production. Every one of these is one word away from being routine, so
            # every one of them asks rather than refuses, and none fires on a --dry-run.
            {"id": "database.framework-reset", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "predicate": "command.not_a_rehearsal",
             "arg_contains": r"\bprisma\s+migrate\s+reset\b"
                             r"|\bprisma\s+db\s+push\b[^\n]*--force-reset"
                             r"|\bsupabase\s+db\s+reset\b"
                             r"|\brails\s+db:(drop|reset|purge)\b"
                             r"|\brake\s+db:(drop|reset|purge)\b"
                             r"|\bmanage\.py\s+flush\b"
                             r"|\bartisan\s+migrate:(fresh|refresh)\b"
                             r"|\bdrizzle-kit\s+push\b[^\n]*--force"
                             r"|\balembic\s+downgrade\s+base\b"
                             r"|\bsequelize\s+db:drop\b",
             "reason": "this drops the database and recreates it empty",
             "note": "Skipped for --dry-run and --local. A reset against a local development "
                     "database is routine; the same command reads its connection string from "
                     "the environment, and the environment is what changes."},
            {"id": "database.drop-server-side", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "predicate": "command.not_a_rehearsal",
             "arg_contains": r"\bdropdb\b|\bmongo\w*\s[^\n]*dropDatabase\("
                             r"|\bdb\.dropDatabase\(|\bFLUSHALL\b|\bFLUSHDB\b",
             "reason": "this drops or empties an entire database",
             "note": "Covers the direct client commands rather than a framework wrapper."},
        ],
    },
    "cloud": {
        "title": "Deleting cloud resources",
        "description": "Provider commands that destroy storage, databases or whole projects.",
        "rules": [
            # The public incident this product's own copy cites was an agent calling a hosting
            # provider's volume-delete API. It contained no `rm`, touched no database client,
            # and every guardrail in this catalogue allowed it.
            {"id": "cloud.delete-managed-data", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "predicate": "command.not_a_rehearsal",
             "arg_contains": r"\baws\s+rds\s+delete-db-(instance|cluster)\b"
                             r"|\baws\s+s3\s+rb\b[^\n]*--force"
                             r"|\baws\s+s3\s+rm\b[^\n]*--recursive"
                             r"|\baws\s+ec2\s+terminate-instances\b"
                             r"|\baws\s+dynamodb\s+delete-table\b"
                             r"|\bgcloud\s+sql\s+instances\s+delete\b"
                             r"|\bgcloud\s+projects\s+delete\b"
                             r"|\bgsutil\s+rm\s+-r\b"
                             r"|\baz\s+group\s+delete\b"
                             r"|\bfly\s+(apps|volumes|postgres)\s+destroy\b"
                             r"|\bheroku\s+pg:reset\b"
                             r"|\bwrangler\s+(d1\s+delete|r2\s+bucket\s+delete"
                             r"|kv:namespace\s+delete|kv\s+namespace\s+delete)\b"
                             r"|\brailway\s+(volume|service)\s+delete\b"
                             r"|\bvolumeDelete\b"
                             r"|\bsupabase\s+projects\s+delete\b",
             "reason": "this deletes managed storage, a database or a project on a provider",
             "note": "Managed data has no reflog and usually no undo. Asks rather than refuses, "
                     "because tearing down an environment is a real task."},
            {"id": "cloud.destroy-stack", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "predicate": "command.not_a_rehearsal",
             "arg_contains": r"\bpulumi\s+destroy\b|\bcdk\s+destroy\b"
                             r"|\bterraform\s+state\s+(rm|push)\b"
                             r"|\bserverless\s+remove\b|\bsls\s+remove\b"
                             r"|\bhelm\s+uninstall\b"
                             r"|\bkubectl\s+delete\s+(pvc|persistentvolumeclaim|-f)\b",
             "reason": "this tears down infrastructure or the state file that describes it",
             "note": "`terraform state rm` and `state push` are here because they make "
                     "terraform forget or misremember what exists, and the next apply then "
                     "destroys it."},
            {"id": "cloud.docker-prune-volumes", "effect": "require_oversight",
             "event_type": "tool_call", "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bdocker\s+system\s+prune\b[^\n]*--volumes"
                             r"|\bdocker\s+volume\s+prune\b"
                             r"|\bdocker\s+compose\s+down\b[^\n]*(-v\b|--volumes)",
             "reason": "this deletes docker volumes, which is where local database data lives",
             "note": "`docker compose down` without -v is untouched."},
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
             "not_tool": NOT_A_COMMAND,
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
             "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\b((kubectl\s+(apply|delete|create|replace|patch|scale|rollout|"
                             r"drain|cordon|taint|edit|set|annotate|label)|helm\s+(install|"
                             r"upgrade|uninstall|rollback|delete))\s[^\n]*(--context|--namespace)"
                             r"[= ]\s*[\"']?(prod|production)"
                             r"|(vercel|netlify|fly|wrangler|serverless|sls)\s+deploy\b"
                             r"|npx\s+wrangler\s+(pages\s+)?deploy\b"
                             r"|git\s+push\s+[^\n]*\b(production|prod)\b)",
             "predicate": "command.not_a_rehearsal",
             "reason": "argument runs a deployment",
             "note": "Oversight, not deny: shipping is the job. The point is that a human "
                     "signed off and it is recorded, not that it is impossible."},
            {"id": "production.force-push", "effect": "deny", "event_type": "tool_call",
             "not_tool": NOT_A_COMMAND,
             "arg_contains": r"git\s+push\b[^\n]*(--force\b|(?<![\w-])-f(?![\w-]))",
             "reason": "argument contains a force push",
             "note": "A force push can destroy history irrecoverably. "
                     "--force-with-lease also matches."},
            {"id": "production.terraform-destroy", "effect": "deny", "event_type": "tool_call",
             # `terraform destroy` is the deprecated spelling. Current Terraform documents
             # `terraform apply -destroy` and `terraform plan -destroy`, which is what a
             # modern pipeline and a modern agent both emit, and -auto-approve makes the flag
             # form the more dangerous of the two.
             "not_tool": NOT_A_COMMAND,
             "arg_contains": r"terraform\s+(destroy\b|(apply|plan)\s[^\n]*-destroy\b)",
             "predicate": "command.not_a_rehearsal",
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
             # Anchored to the MODE ARGUMENT, not to any digits on the line. Unanchored, the
             # pattern read the digits out of a path: `chmod +x /private/tmp/claude-501/
             # -Volumes-T7-Projects-voyara/a37a2760-a164-4732-b4ec-.../run.sh` matched on
             # "4732" and was denied. `chmod +x` on a script an agent just wrote is one of the
             # most ordinary commands there is, and this was 9 of the 27 denies measured over
             # 36,929 real calls.
             "not_tool": NOT_A_COMMAND,
             "arg_contains": r"\bchmod\s+(-[a-zA-Z-]+\s+)*"
                             r"(0?[0-7]{2}[2367](\s|$)"
                             r"|[a-zA-Z,+=-]*[ao][augo]*[+=][rwxXst]*w)",
             "reason": "argument makes a path world-writable",
             "note": "World-writable is the OTHER digit carrying the write bit (2, 3, 6 or 7), "
                     "or a symbolic clause granting write to a or o, so `chmod 755` and "
                     "`chmod u+w` are untouched. Low false-positive risk."},
            {"id": "access.disarm-the-guard", "effect": "require_oversight",
             # The FAQ has always said that editing the policy is itself a tool call the
             # guardrail sees. It saw it and did nothing, which is a different sentence. An
             # agent rewriting `.provenrail.json` to `{"policy": {"use": []}}` or removing the
             # hooks from `.claude/settings.json` is not necessarily wrong, and it is never
             # something to do without the person noticing.
             "event_type": "tool_call", "tool": "Write|Edit|MultiEdit|NotebookEdit|Bash",
             "arg_contains": r"\.provenrail\.json\b"
                             r"|\.claude/settings(\.local)?\.json\b"
                             r"|\.claude/hooks\b",
             "reason": "this edits the guardrail's own configuration",
             "note": "Asks rather than denies: changing your own policy is allowed, silently "
                     "changing it is not. Reads are unaffected; this fires on writes and on a "
                     "shell command that rewrites one of these files."},
            {"id": "access.disable-mfa", "effect": "deny", "event_type": "tool_call",
             "not_tool": NOT_A_COMMAND,
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
             "not_tool": NOT_A_COMMAND,
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
             "not_tool": NOT_A_COMMAND,
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
_ENGINE_FIELDS = ("id", "effect", "event_type", "tool", "not_tool", "resource", "provider",
                  "arg_contains", "predicate", "max_per_session", "reason")



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
