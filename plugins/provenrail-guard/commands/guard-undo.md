---
description: Put the working tree back to before an agent action, including what a shell command changed
allowed-tools: Bash(*/guard_standalone.py --undo*), Bash(pr undo*)
argument-hint: [n | last] [--diff]
---

Provenrail takes a checkpoint of the working tree before every action that can change a
file. Run the command below with the user's arguments (`$ARGUMENTS`) and show its output
verbatim.

- No arguments lists the checkpoints and what each action changed.
- `last` restores to before the most recent action that changed anything.
- A number restores to that checkpoint. Add `--diff` to see what would change first.

Never restore without the user having asked for that specific restore. Listing is always safe.
If the output says a restore was NOT verified, say so plainly and show the lines marked `!`.

```bash
if command -v pr >/dev/null 2>&1 && pr --help 2>&1 | grep -qi provenrail; then
  pr undo $ARGUMENTS
else
  python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard_standalone.py" --undo $ARGUMENTS
fi
```
