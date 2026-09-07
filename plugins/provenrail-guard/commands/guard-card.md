---
description: A paste-ready summary of what Provenrail has stopped in this repo, safe to share
allowed-tools: Bash(*/guard_standalone.py --card), Bash(pr guard card)
---

Print the guard's shareable card and show the user its output verbatim, inside a fenced code
block so it can be copied in one action:

```bash
if command -v pr >/dev/null 2>&1 && pr --help 2>&1 | grep -qi provenrail; then
  pr guard card
else
  python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard_standalone.py" --card
fi
```

The card already drops every operand, so it cannot contain a path, a hostname or a key. Do not
add any of that back. Do not name the repository, do not paste the commands in full, and do not
embellish what was stopped: if the card says two commands were sent for approval, that is what
happened, and adding "and it saved your work" claims something nobody measured.

If the card says nothing has been stopped yet, show that. It is the honest answer and it is
also the useful one: a guard that has never fired and a guard that is silently broken read the
same from outside, and `/guard-status` is where the user checks which they have.
