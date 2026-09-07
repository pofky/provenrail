---
description: Show which Provenrail guardrails are armed and what they have actually stopped
allowed-tools: Bash(*/guard_standalone.py --status), Bash(pr guard status)
---

Run the guard's own status report and show the user its output verbatim. Prefer the installed
CLI when it exists, because it also reports the signed receipt chain:

```bash
if command -v pr >/dev/null 2>&1 && pr --help 2>&1 | grep -qi provenrail; then
  pr guard status
else
  python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard_standalone.py" --status
fi
```

Do not summarise or reformat the output, and do not add reassurance the report does not
contain. If it says nothing has been stopped yet, say exactly that: a guardrail that has
never fired and a guardrail that is silently broken look identical from the outside, and the
user needs to know which one they are looking at.
