---
description: Stop every agent on this machine at its next tool call, or resume them
allowed-tools: Bash(*/guard_standalone.py --stop*), Bash(*/guard_standalone.py --resume), Bash(pr stop*), Bash(pr resume)
argument-hint: [reason] | resume
---

If the user asked to resume, run the resume form instead (`--resume` or `pr resume`).
Otherwise stop. Show the output verbatim.

After a stop, every tool call from every agent on this machine is refused, including yours.
Do not try to work around it and do not run the resume command yourself: resuming is the
user's decision, typed by them.

```bash
if command -v pr >/dev/null 2>&1 && pr --help 2>&1 | grep -qi provenrail; then
  pr stop $ARGUMENTS
else
  python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard_standalone.py" --stop $ARGUMENTS
fi
```
