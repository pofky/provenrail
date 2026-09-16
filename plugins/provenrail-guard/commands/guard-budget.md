---
description: Set a spend cap in dollars, so the guard refuses the next tool call once it is over
argument-hint: <usd> [day|session|total]
allowed-tools: Bash(*)
---

Set the spend cap the guard enforces. The user typed: `$ARGUMENTS` (the first word is the cap
in US dollars, an optional second word is the scope: `day`, `session` or `total`; the default
scope is `day`).

If they gave no amount, do not pick one. There is no default cap and there must not be: a
dollar figure the user did not choose is a claim about their money, and it is wrong for almost
everybody. Ask them what the cap should be, and say that `day` is the scope that catches an
agent running all night across many short sessions.

Prefer the installed CLI when it exists, because it also validates the file it writes:

```bash
if command -v pr >/dev/null 2>&1 && pr --help 2>&1 | grep -qi provenrail; then
  pr guard budget $ARGUMENTS
else
  python3 - "$ARGUMENTS" <<'PY'
import json, os, sys
args = (sys.argv[1] if len(sys.argv) > 1 else "").split()
if not args:
    sys.exit("no amount given; a cap you did not choose is a claim about your money")
try:
    limit = float(args[0].lstrip("$").replace(",", ""))
except ValueError:
    sys.exit("%r is not a number of dollars" % args[0])
if limit <= 0:
    sys.exit("a cap must be greater than zero")
limit = int(limit) if limit.is_integer() else limit
scope = (args[1] if len(args) > 1 else "day").lower()
if scope not in ("day", "session", "total"):
    sys.exit("scope must be day, session or total")

path = ".provenrail.json"
cfg = {}
if os.path.isfile(path):
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
policy = cfg.get("policy") if isinstance(cfg.get("policy"), dict) else {}
budgets = [b for b in (policy.get("budgets") or []) if isinstance(b, dict)]
same = [b for b in budgets if str(b.get("scope", "session")).lower() == scope]
if same and "--replace" not in args:
    # Two caps at one scope is a config where the tighter one binds and the one just typed
    # appears to have done nothing.
    sys.exit("a %s budget already exists ($%s). Add --replace to change it."
             % (scope, same[0].get("limit_usd")))
policy["budgets"] = [b for b in budgets
                     if str(b.get("scope", "session")).lower() != scope] + [
    {"scope": scope, "limit_usd": limit}]
cfg["policy"] = policy
with open(path, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")
print("Spend cap: $%s per %s, written to %s" % (limit, scope, path))
PY
fi
```

Then tell the user three things, in one short paragraph, and nothing more:

1. what was written and where, quoting the line back to them;
2. that the figure is an estimate at API list price, read from this session's transcript, and
   that on a Pro or Max plan it is notional because those plans have no per-token charge;
3. that the guard stops the next tool call after the cap is crossed, within a turn, not at the
   exact dollar, because the transcript is written asynchronously.

Do not claim the cap stops model calls themselves. It does not: nothing here sits between the
agent and the API. It refuses the agent's next tool call, which is what ends the run.
