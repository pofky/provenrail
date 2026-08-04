# provenrail-guard

Stops your coding agent one command before it deletes prod, and hands you a receipt nobody can
forge.

```
/plugin marketplace add pofky/provenrail
/plugin install provenrail-guard@provenrail
```

Then, once, in each project you want guarded:

```bash
uv tool install provenrail    # or: pip install provenrail
pr quickstart                 # local sink, no account, nothing leaves your machine
pr guard install              # arms destructive + secrets + production
```

## What it does

- **Blocks before it runs.** `rm -rf`, `terraform destroy`, `git push --force`, `DROP TABLE`,
  `chmod 777` and leaked API keys are denied at the tool boundary, and the agent is told which
  rule fired. The model does not get a vote.
- **Asks when a human should decide.** Touching `.env`, a deploy, a migration: these become a
  permission prompt instead of a hard block, and your approval is recorded as human oversight.
  Guardrails that block legitimate work get uninstalled by lunchtime; these do not.
- **Makes the block into evidence.** Every decision is Ed25519 signed and hash-chained. Run
  `pr guard receipt` and hand the file to anyone; `pr verify` recomputes it from scratch, and a
  browser verifier does the same without contacting any server.

## What it does not do

- It cannot constrain a process that never calls Claude Code's hooks. Completeness is never
  claimed anywhere in Provenrail, and this is no exception.
- The policy is read from the nearest `.provenrail.json` at or above your working directory, so a
  package inside a monorepo inherits the repo root's rules. `pr guard status` prints the exact
  file it used. If the hooks are wired but nothing is armed, you are told once a day rather than
  being allowed in silence.
- Per-session `limit` rules (blast-radius caps) carry their counts in a local state file so a cap
  actually caps across hook processes. That file is local and editable, so it is a convenience,
  not evidence. `deny` and `require_oversight` never read it and cannot be bypassed by editing it.
- If Provenrail is not installed, the hook exits silently and **nothing is blocked or recorded**.
  It tells you once a day rather than failing on every tool call, because a guardrail that bricks
  your agent is worse than no guardrail. `pr guard status` always tells you the truth about what
  is armed.

## Verify the claim rather than believing it

```bash
pr guard receipt            # export the signed record of what was blocked
pr verify guard-receipt.json
```

Change one byte of that file and the verifier exits non-zero and names the broken link. There is
a live in-browser demo at <https://provenrail.com/verify?demo> and a tampered counter-example at
<https://provenrail.com/verify?tamper>.

MIT licensed. Source: <https://github.com/pofky/provenrail>
