"""What the guard must stop, and what it must never interrupt.

Both lists are evidence rather than opinion. `MUST_STOP` is drawn from public data-loss
reports against coding agents, plus the shapes that have destroyed machines for decades.
`MUST_PASS` is ordinary work: every entry either appeared in a corpus of 36,929 Bash commands
from real agent sessions, or is the immediate neighbour of one that did.

The point of keeping them together in one file is that a guardrail has two failure modes and
they pull in opposite directions. A rule that stops nothing is useless; a rule that stops
everything gets uninstalled, which also stops nothing. Neither list may be trimmed to make the
other pass.
"""

from __future__ import annotations

import pathlib
import subprocess

import pytest

from provenrail import guard
from provenrail.easy import load_policy
from provenrail.predicates import (
    CATASTROPHIC,
    INSIDE,
    OUTSIDE,
    classify_target,
    delete_targets,
    work_at_risk,
    workspace_root,
)

REPO = str(pathlib.Path(__file__).resolve().parent.parent)


@pytest.fixture(scope="module")
def policy():
    return load_policy({"use": guard.DEFAULT_PACKS})


def _verdict(policy, command, cwd=REPO, tool="Bash"):
    return guard.decide(policy, tool, {"command": command}, None, cwd)


# ---------------------------------------------------------------- deletes

# A delete that cannot be undone. `rm -rf $VAR/` is here because an unset variable makes it
# `rm -rf /`, which is the accident, not the typo.
UNRECOVERABLE = [
    "rm -rf /", "rm -rf /*", "sudo rm -rf --no-preserve-root /", "rm -rf ~", "rm -rf ~/",
    "rm -rf ~/Documents", "rm -rf $HOME", "rm -rf ${HOME}/Projects", "rm -rf /etc",
    "rm -rf /usr/local", "rm -rf /var", "rm -rf /System/Library", "rm -rf /Users/povkon",
    "rm -rf /Volumes/T7", "rm -fr /", "rm --recursive --force /home/user", "rm -rf /home",
    "rm -rf /opt", "rm -rf $OUT/", 'cd /tmp && rm -rf "$HOME/Documents"', "rm -rf ~/Downloads",
]

# A delete that leaves the project but is not a catastrophe: it gets a recorded human decision.
NEEDS_A_DECISION = [
    "rm -rf ..", "rm -rf ../..", "rm -rf ../sibling-project", 'rm -rf "$BUILD_DIR"',
    "rm -rf ${TARGET}",
]

# Ordinary work. Every one of these must be silent, or the guard is uninstalled by lunchtime.
ROUTINE_DELETES = [
    "rm -rf .next out", "rm -rf node_modules", "rm -rf dist build",
    "rm -rf app/en app/layout.tsx app/page.tsx", "rm -rf .pytest_cache",
    "rm -f deploy-prd0017.txt", "rm -f ibm-plex-sans-500-latin.woff2",
    "rm -f /tmp/step.sh", "rm -rf /tmp/attest-demo",
    "rm -rf /Volumes/T7/Projects/Voyara/.next",
    "rm -rf /Users/povkon/Library/Caches/pip/wheels",
    "cd website/fonts && rm -f a.woff2 b.woff2", "rm -rf ./build", "rm -f coverage.xml",
    "rm -rf target/debug", "rm -rf $PWD/dist",
    "rm -rf /private/tmp/claude-501/scratch/build", "npm run clean && rm -rf .turbo",
    "rm -f package-lock.json && npm install", "rm -rf .venv && python3 -m venv .venv",
    "SP=/private/tmp/claude-501/scratch; rm -rf $SP/fixed && mkdir -p $SP/fixed",
]


@pytest.mark.parametrize("command", UNRECOVERABLE)
def test_an_unrecoverable_delete_is_refused(policy, command):
    assert _verdict(policy, command)["verdict"] == "deny", command


@pytest.mark.parametrize("command", NEEDS_A_DECISION)
def test_a_delete_that_leaves_the_project_asks(policy, command):
    assert _verdict(policy, command)["verdict"] == "ask", command


@pytest.mark.parametrize("command", ROUTINE_DELETES)
def test_routine_deletes_are_silent(policy, command):
    """Measured: before targets were screened, these were 646 of 824 interruptions across
    36,929 real commands. Every one is a build directory, a cache, or a file the agent was
    asked to remove."""
    assert _verdict(policy, command)["verdict"] == "allow", command


def test_a_variable_assigned_in_the_same_command_is_read_rather_than_feared():
    """`SP=/private/tmp/x; rm -rf $SP/fixed` is not `rm -rf /`. The value is in the same
    string, and refusing to look at it was 41 of 68 denies in the corpus."""
    assert classify_target("$SP/fixed", REPO, {"SP": "/private/tmp/x"}) == INSIDE
    # With nothing to resolve it from, the shape is the hazard: an unset SP makes it `/fixed`.
    assert classify_target("$SP/fixed", REPO, {}) == CATASTROPHIC


def test_a_bare_unresolvable_variable_asks_rather_than_refusing():
    """`rm -rf $D` with D unset deletes nothing. `rm -rf $D/` with D unset deletes the disk."""
    assert classify_target("$D", REPO, {}) == OUTSIDE
    assert classify_target("$D/", REPO, {}) == CATASTROPHIC


def test_a_home_directory_under_a_temp_root_is_still_a_home_directory(monkeypatch, tmp_path):
    """The exemptions are asked last on purpose. With HOME pointed at a scratch directory,
    checking "is it under /tmp" first made `rm -rf ~/` read as a temp clean-up."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert classify_target("~/", str(tmp_path), {}) == CATASTROPHIC


def test_the_workspace_is_the_repository_not_the_current_directory():
    """An agent in `apps/web` running `rm -rf ../api/dist` is still inside its own project."""
    assert workspace_root(REPO + "/tests") == REPO


def test_a_json_argument_object_is_still_read_as_a_delete():
    """Not every tool takes a shell string. `{"args": {"cmd": "rm -rf /var/data"}}` is rendered
    as JSON, where shlex reads the whole quoted value as one token and the `rm` never appears
    as a word."""
    assert delete_targets('{"args": {"cmd": "rm -rf /var/data"}}') == ["/var/data"]


def test_echo_is_not_a_delete_but_is_still_screened():
    """The strict pass will not call `echo rm -rf /` a delete. The loose pass, which only runs
    when the strict one found nothing, will, and that is the safe direction."""
    assert delete_targets("echo hello") is None
    assert delete_targets('echo "rm -rf /"') == ["/"]


# ---------------------------------------------------------------- git working tree

# Every one of these appears in a public report of a coding agent destroying someone's work,
# or is the same command in a different spelling. All were ALLOWED by the default install.
GIT_INCIDENTS = [
    "git fetch origin && git reset --hard origin/main",
    "git reset --hard 35eb731",
    "git checkout -- .",
    "git checkout .",
    "git restore .",
    "git restore src/",
    "git clean -fd",
    "git clean -xdff",
    "git stash drop",
    "git stash clear",
    "git branch -D feature/wip",
    "git worktree remove --force ../wt",
    "git push origin --delete main",
    "git push origin :main",
    "Remove-Item -Recurse -Force *",
    "rsync -a --delete build/ /srv/www/",
]

DATA_INCIDENTS = [
    "npx prisma migrate reset --force",
    "npx prisma db push --force-reset",
    "supabase db reset",
    "rails db:drop",
    "php artisan migrate:fresh",
    "python manage.py flush",
    "alembic downgrade base",
    "dropdb myapp_production",
    "redis-cli FLUSHALL",
    "aws rds delete-db-instance --db-instance-identifier prod",
    "aws s3 rb s3://my-bucket --force",
    "gcloud sql instances delete prod-db",
    "az group delete --name prod-rg",
    "fly volumes destroy vol_123",
    "heroku pg:reset DATABASE_URL",
    "npx wrangler d1 delete provenrail-prod",
    "npx wrangler r2 bucket delete uploads",
    "pulumi destroy --yes",
    "terraform state rm module.db",
    "terraform state push old.tfstate",
    "helm uninstall api -n prod",
    "kubectl delete pvc data-postgres-0",
    "docker system prune -af --volumes",
    "docker compose down -v",
]

# Ordinary git and infrastructure work.
ROUTINE_GIT = [
    "git status", "git add -A && git commit -m 'wip'", "git restore --staged src/index.ts",
    "git stash", "git stash pop", "git branch -d merged-branch", "git checkout main",
    "git checkout -b feature/new", "git reset HEAD~1", "git reset --soft HEAD~1",
    "git clean -n", "git push origin main", "docker compose down", "docker system prune -f",
    "npx prisma migrate dev", "npx prisma generate", "supabase db diff", "terraform plan",
    "kubectl get pods -n prod", "helm list -n prod", "aws s3 ls s3://my-bucket",
    "rsync -a build/ /srv/www/",
]


@pytest.fixture(scope="module")
def dirty_repo(tmp_path_factory):
    """A repository holding work that exists nowhere else, which is when the git rules bite."""
    path = tmp_path_factory.mktemp("dirty")
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q",
                    "--allow-empty", "-m", "init"], cwd=path, check=True)
    (path / "uncommitted.txt").write_text("work nobody else has\n", encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("command", GIT_INCIDENTS + DATA_INCIDENTS)
def test_a_documented_data_loss_command_is_not_allowed_silently(policy, dirty_repo, command):
    assert _verdict(policy, command, dirty_repo)["verdict"] != "allow", command


@pytest.mark.parametrize("command", ROUTINE_GIT)
def test_routine_git_and_infrastructure_work_is_silent(policy, dirty_repo, command):
    assert _verdict(policy, command, dirty_repo)["verdict"] == "allow", command


def test_a_clean_pushed_tree_makes_the_git_rules_silent(policy, tmp_path):
    """`git reset --hard` on a tree with nothing uncommitted and nothing unpushed destroys
    nothing, and a prompt about nothing teaches people to click through prompts."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    work = tmp_path / "work"
    subprocess.run(["git", "clone", "-q", str(origin), str(work)], check=True)
    (work / "a.txt").write_text("committed\n", encoding="utf-8")
    for args in (["add", "-A"],
                 ["-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q", "-m", "one"],
                 ["push", "-q", "-u", "origin", "HEAD"]):
        subprocess.run(["git", *args], cwd=work, check=True)

    assert work_at_risk(str(work)) is False
    assert _verdict(policy, "git reset --hard origin/main", str(work))["verdict"] == "allow"
    assert _verdict(policy, "git checkout -- .", str(work))["verdict"] == "allow"


def test_a_directory_that_is_not_a_repository_counts_as_at_risk(tmp_path):
    """A guard that could not look has not checked."""
    assert work_at_risk(str(tmp_path)) is True


def test_history_rewrite_is_refused_rather_than_asked(policy, dirty_repo):
    """The reflog is what recovers a bad reset, so expiring it removes the way back from every
    other rule in the pack."""
    for command in ("git reflog expire --expire=now --all",
                    "git filter-branch --tree-filter 'rm -f secret' HEAD"):
        assert _verdict(policy, command, dirty_repo)["verdict"] == "deny", command


# ---------------------------------------------------------------- scope and rehearsals


def test_a_command_rule_does_not_read_a_document(policy):
    """Writing `docs/security.md` explaining what `rm -rf /` does, a migration that drops a
    table, or a subagent prompt quoting a dangerous command must not be refused. An agent that
    cannot write down the commands this guard blocks is an agent working around the guard."""
    content = ("# Security\n\nNever run `rm -rf /` on production.\n"
               "Migrations may contain `DROP TABLE legacy;`.\n"
               "Use `git push --force` with care.\n")
    for tool in ("Write", "Edit", "MultiEdit", "Task"):
        d = guard.decide(policy, tool, {"file_path": "docs/security.md", "content": content},
                         None, REPO)
        assert d["verdict"] == "allow", f"{tool}: {d['rule']}"
    # The same text as a command is still refused.
    assert _verdict(policy, "rm -rf /")["verdict"] == "deny"


def test_writing_a_live_credential_into_a_file_is_still_caught(policy):
    """The secrets pack deliberately keeps reading file writes, because putting a real key in a
    file IS the harm it exists to catch."""
    d = guard.decide(policy, "Write",
                     {"file_path": "config.py", "content": "KEY = 'AKIAIOSFODNN7EXAMPLE'"},
                     None, REPO)
    assert d["verdict"] == "deny"
    assert d["rule"] == "secrets.aws-access-key"


def test_a_rehearsal_is_not_the_act(policy):
    """`wrangler deploy --dry-run` deploys nothing and `d1 execute --local` runs against a file
    in .wrangler/. Asking a human to approve either is asking them to approve nothing."""
    for command in ("npx wrangler deploy --dry-run --outdir /tmp/out",
                    'npx wrangler d1 execute app --local --command "DROP TABLE IF EXISTS t"',
                    'npx wrangler d1 execute app --local --command "DELETE FROM licenses"'):
        assert _verdict(policy, command)["verdict"] == "allow", command
    assert _verdict(policy, "npx wrangler deploy")["verdict"] == "ask"


def test_a_flag_inside_a_quoted_argument_is_not_split_away_from_it():
    """A newline inside `--command "DELETE FROM ...\\n WHERE ..."` used to split the flag that
    made the call harmless into one segment and the statement into another."""
    from provenrail.shell import segments

    command = 'wrangler d1 execute app --local --command "DELETE FROM t\nWHERE id = 1"'
    assert segments(command) == [command]


def test_chmod_reads_the_mode_not_the_path(policy):
    """`chmod +x` on a script in a directory whose name contains a UUID was denied because the
    digits 4732 appeared somewhere in the path."""
    allowed = "chmod +x /private/tmp/claude-501/a37a2760-a164-4732-b4ec/run.sh"
    assert _verdict(policy, allowed)["verdict"] == "allow"
    assert _verdict(policy, "chmod 664 file")["verdict"] == "allow"
    assert _verdict(policy, "chmod 755 file")["verdict"] == "allow"
    for denied in ("chmod 777 /srv", "chmod 0777 /srv", "chmod 666 f", "chmod a+rwx f",
                   "chmod u+rwx,g+rwx,o+rwx f", "chmod -R 777 d", "chmod o+w f"):
        assert _verdict(policy, denied)["verdict"] == "deny", denied


def test_a_tailwind_class_is_not_a_sql_statement(policy):
    """`class="min-w-0 truncate text-sm"` matched TRUNCATE. Frontend agents write that hourly."""
    assert _verdict(policy, 'grep -n "min-w-0 truncate text-sm" src/app.tsx')["verdict"] == "allow"
    assert _verdict(policy, "psql -c 'TRUNCATE orders'")["verdict"] == "deny"
    assert _verdict(policy, "psql -c 'TRUNCATE TABLE orders'")["verdict"] == "deny"


def test_an_env_template_is_not_a_secret(policy):
    """`.env.example` is committed on purpose and holds no secret. Asking about `cp .env.example
    .env` teaches people to approve without reading."""
    for allowed in ("cat .env.example", "diff .env.example .env.sample",
                    "git add .env.sample", "ls -la .env.template"):
        assert _verdict(policy, allowed)["verdict"] == "allow", allowed
    assert _verdict(policy, "cat .env")["verdict"] == "ask"


def test_an_unknown_predicate_leaves_the_rule_exactly_as_it_was():
    """A rule from a newer catalogue must keep firing on an older engine rather than silently
    switching itself off, so a predicate can only ever narrow a rule, never open a hole."""
    from provenrail.predicates import evaluate

    assert evaluate("nothing.like.this", "rm -rf /", {}) is True
    assert evaluate("", "rm -rf /", {}) is True


# ---------------------------------------------------------------- what the matcher can see

# Until the plugin's PreToolUse matcher covered every tool, it listed the built-in ones and
# nothing else. That looked careful and was a hole: the catalogue advertised rules for a
# credential read and for a destructive MCP call, and neither could ever fire, because neither
# tool was handed to the hook. These are the cases that were unreachable.
REACHABLE = [
    ("Read", {"file_path": "/Users/ana/.ssh/id_ed25519"}, "ask"),
    ("Read", {"file_path": "/Users/ana/.aws/credentials"}, "ask"),
    ("Read", {"file_path": "/Users/ana/.kube/config"}, "ask"),
    ("Read", {"file_path": ".env"}, "ask"),
    ("mcp__railway__deleteVolume", {"volumeId": "v1"}, "ask"),
    ("mcp__supabase__dropTable", {"name": "users"}, "ask"),
    ("mcp__aws__delete_bucket", {"bucket": "b"}, "ask"),
    ("Write", {"file_path": ".provenrail.json", "content": '{"policy": {"use": []}}'}, "ask"),
    ("Bash", {"command": "echo '{}' > .claude/settings.json"}, "ask"),
]

# The other half. Reaching every tool means every tool's arguments are text a rule can misread.
UNREACHED = [
    ("Read", {"file_path": "/Users/ana/.ssh/id_ed25519.pub"}, "allow"),
    ("Read", {"file_path": "src/app.ts"}, "allow"),
    ("Read", {"file_path": ".env.example"}, "allow"),
    ("mcp__linear__createIssue", {"title": "delete the old bucket"}, "allow"),
    ("mcp__ios-simulator-mcp__ui_swipe", {"direction": "up"}, "allow"),
    ("WebSearch", {"query": "git reset --hard recovery reflog"}, "allow"),
    ("Grep", {"pattern": "rm -rf", "path": "docs/"}, "allow"),
    ("Task", {"prompt": "Explain what git clean -fd does and why it is dangerous"}, "allow"),
    ("AskUserQuestion", {"question": "Should I run terraform destroy on staging?"}, "allow"),
]


@pytest.mark.parametrize(("tool", "args", "expected"), REACHABLE + UNREACHED,
                         ids=[f"{t}-{e}" for t, _, e in REACHABLE + UNREACHED])
def test_every_tool_reaches_the_rules_and_only_the_right_ones_fire(policy, tool, args, expected):
    got = guard.decide(policy, tool, args, None, REPO)
    assert got["verdict"] == expected, f"{tool} {args}: {got['rule']}"
