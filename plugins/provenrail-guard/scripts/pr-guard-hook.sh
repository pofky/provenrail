#!/usr/bin/env bash
# Provenrail guard hook shim.
#
# Claude Code pipes the hook payload on stdin and reads our decision from stdout. This script
# picks who answers it:
#
#   1. `pr` (the installed Provenrail CLI), when it is on the machine. Blocks, asks, AND signs
#      every decision into a hash-chained record someone else can verify.
#   2. the bundled zero-dependency engine next to this file, otherwise. Blocks, asks, and
#      journals locally. No pip install, no account, no sink, nothing to set up.
#
# So `/plugin install` protects the very next tool call, and installing Provenrail later
# upgrades the same journal in place rather than starting a new one.
#
# The hard rule: this must NEVER break the user's session. If nothing can answer, or anything
# at all goes wrong, we exit 0 with no output, which Claude Code reads as "no opinion" and the
# tool call proceeds exactly as it would without the plugin. A guardrail that bricks your agent
# is worse than no guardrail, and it is why people uninstall these.
set -uo pipefail

EVENT="${1:-pre}"
PAYLOAD="$(cat)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_pr() {
  if command -v pr >/dev/null 2>&1; then
    # `pr` is also a POSIX text-formatting utility. Only accept ours.
    if pr --help 2>&1 | grep -qi provenrail; then command -v pr; return 0; fi
  fi
  for candidate in "$HOME/.local/bin/pr" "$HOME/.cargo/bin/pr" /opt/homebrew/bin/pr /usr/local/bin/pr; do
    if [ -x "$candidate" ] && "$candidate" --help 2>&1 | grep -qi provenrail; then
      echo "$candidate"; return 0
    fi
  done
  return 1
}

find_python() {
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
        command -v "$candidate"; return 0
      fi
    fi
  done
  return 1
}

# stdout is the decision Claude Code parses, so it is passed through untouched. stderr is
# forwarded rather than discarded: both engines use it to say things the user genuinely needs,
# above all "hooks are installed but nothing is armed", which is invisible otherwise. Both
# rate-limit themselves to once a day, so forwarding does not make the session noisy.
run_and_forward() {
  local err out
  err="$(mktemp -t provenrail-guard.XXXXXX 2>/dev/null || echo "${TMPDIR:-/tmp}/provenrail-guard.$$")"
  out="$("$@" <<<"$PAYLOAD" 2>"$err")" || { rm -f "$err"; exit 0; }
  [ -s "$err" ] && cat "$err" >&2
  rm -f "$err"
  [ -n "$out" ] && printf '%s\n' "$out"
  exit 0
}

PR_BIN="$(find_pr || true)"
if [ -n "${PR_BIN:-}" ]; then
  run_and_forward "$PR_BIN" guard hook --event "$EVENT"
fi

PY_BIN="$(find_python || true)"
if [ -n "${PY_BIN:-}" ] && [ -f "$HERE/guard_standalone.py" ]; then
  run_and_forward "$PY_BIN" "$HERE/guard_standalone.py" --event "$EVENT"
fi

# Neither engine is available. Say so once a day rather than on every tool call, and get out
# of the way.
STAMP="${TMPDIR:-/tmp}/.provenrail-guard-missing-$(date +%Y%m%d)"
if [ ! -f "$STAMP" ]; then
  : > "$STAMP"
  echo "provenrail-guard: no Python 3.8+ found, so nothing is being blocked or recorded." >&2
  echo "  Install Provenrail instead:  uv tool install provenrail" >&2
fi
exit 0
