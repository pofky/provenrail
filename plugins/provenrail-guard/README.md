# provenrail-guard

Stops your coding agent one command before it deletes prod.

```
/plugin marketplace add pofky/provenrail
/plugin install provenrail-guard@provenrail
```

That is the whole setup. There is no second step, no `pip install`, no account, no server, and
nothing leaves your machine. The next tool call your agent makes is already being checked.

```
/guard-status      what is armed, and what it has actually stopped
/guard-rules       every rule, including the packs that are off by default
```

## What it does

- **Blocks before it runs.** `rm -rf`, `dd of=/dev/...`, `terraform destroy`,
  `git push --force`, `DROP TABLE`, `DELETE` with no `WHERE`, `kubectl delete namespace`,
  `chmod 777` and committed API keys are denied at the tool boundary, and the agent is told
  which rule fired. The model does not get a vote.
- **Asks when a human should decide.** Reading `.env`, a deploy, a migration, a DNS or IAM
  change: these become a permission prompt instead of a hard block, and your approval is
  recorded as human oversight. Guardrails that block legitimate work get uninstalled by
  lunchtime; these do not.
- **Keeps a local record of every block and every prompt.** `/guard-status` shows it. It is a
  plain text file in your project, and anything on your machine can edit it, which is exactly
  why the paid layer exists.

41 rules are armed by default, from four packs: destructive, secrets, production, access.
Money, exfiltration and blast-radius caps are opt in, because they match tool names a coding
agent does not emit and would add noise without adding protection.

## Turning it up, or off

Write a `.provenrail.json` at your repo root. It wins over the defaults completely.

```json
{"policy": {"use": ["destructive", "secrets", "production", "access", "money"]}}
```

`{"policy": {"use": []}}` arms nothing and says so once a day, so a disarmed guard can never
look like a working one. `/guard-rules` prints every pack and rule id; you can name a single
rule instead of a whole pack.

## Making the record into evidence

The local history is a text file. It is enough to see what happened; it is not enough to show
somebody else, because you could have written it yourself. Installing Provenrail upgrades the
same journal in place, in the same directory, with no migration:

```bash
uv tool install provenrail    # or: pip install provenrail
pr guard receipt              # a signed, hash-chained export of what was blocked
pr verify guard-receipt.json
```

Every decision is then Ed25519 signed and hash-chained. Change one byte of that receipt and
the verifier exits non-zero and names the broken link, and a second implementation in the
browser reaches the same verdict without contacting any server. Live demo:
<https://provenrail.com/verify?demo>, tampered counter-example:
<https://provenrail.com/verify?tamper>.

`pr anchor-push` then adds an RFC 3161 timestamp from an independent authority, which is what
turns "these are my logs" into "these records existed in this order at that time, and someone
who is not me says so."

## What it does not do

- **It cannot constrain a process that never calls Claude Code's hooks.** Completeness is
  never claimed anywhere in Provenrail, and this is no exception. What a clean record shows is
  that for the calls that did go through the hook, the stated policy was applied.
- **The rules match tool names and argument text.** A rule for `delete_*` does nothing against
  a tool called `remove_record`, and a command obfuscated past a regex is a command that gets
  through. This raises the floor a great deal; it is not a sandbox.
- **Per-session `limit` rules carry their counts in a local state file**, so a blast-radius cap
  actually caps across hook processes. That file is editable, so it is a convenience, not
  evidence. `deny` and `require_oversight` never read it and cannot be bypassed by editing it.
- **If anything at all goes wrong, the tool call proceeds.** The hook exits with no opinion
  rather than failing, and tells you once a day rather than on every call. A guardrail that
  bricks your agent is worse than no guardrail. The cost of that choice is that a broken guard
  is quiet, which is why `/guard-status` reports what it has actually stopped rather than only
  what it claims to be watching.
- **The policy is read from the nearest `.provenrail.json` at or above your working
  directory**, so a package inside a monorepo inherits the repo root's rules.

MIT licensed. Source: <https://github.com/pofky/provenrail>
