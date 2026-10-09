---
description: List what in a repository runs or steers an agent without asking: hooks, MCP servers, editor tasks, hidden instructions
allowed-tools: Bash(*/guard_standalone.py --scan*), Bash(pr scan*)
argument-hint: [path]
---

Run the scan on the path the user gave (`$ARGUMENTS`, default the current directory) and
show its output verbatim. It reads files only and executes nothing from the scanned tree.

Do not soften a finding and do not call the repository safe: the scan screens known auto-run
surfaces and says so itself. If there are high findings, list them first.

```bash
if command -v pr >/dev/null 2>&1 && pr --help 2>&1 | grep -qi provenrail; then
  pr scan ${ARGUMENTS:-.}
else
  python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard_standalone.py" --scan ${ARGUMENTS:-.}
fi
```
