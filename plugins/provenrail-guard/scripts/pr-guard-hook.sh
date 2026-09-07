#!/usr/bin/env bash
# Provenrail guard hook shim.
#
# Claude Code pipes the hook payload on stdin and reads our decision from stdout. This script
# picks who answers it:
#
#   1. `pr` (the installed Provenrail CLI), when it is on the machine AND is at least as new as
#      this plugin. Blocks, asks, AND signs every decision into a hash-chained record someone
#      else can verify.
#   2. the bundled zero-dependency engine next to this file, otherwise. Blocks, asks, and
#      journals locally. No pip install, no account, no sink, nothing to set up.
#
# So `/plugin install` protects the very next tool call, and installing Provenrail later
# upgrades the same journal in place rather than starting a new one.
#
# The version comparison is not tidiness. Updating the plugin ships new rules; an older `pr`
# left on the machine from months ago would answer with its own older ruleset and the user
# would see none of what the update added, with nothing anywhere saying why. Whichever engine
# knows more rules answers.
#
# The hard rule: this must NEVER break the user's session. If nothing can answer, or anything
# at all goes wrong, we exit 0 with no output, which Claude Code reads as "no opinion" and the
# tool call proceeds exactly as it would without the plugin. A guardrail that bricks your agent
# is worse than no guardrail, and it is why people uninstall these.
set -uo pipefail

EVENT="${1:-pre}"
PAYLOAD="$(cat)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# This plugin's own version, from the manifest beside it. Used only to refuse an older CLI.
plugin_version() {
  sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$HERE/../.claude-plugin/plugin.json" 2>/dev/null | head -1
}

# True when $1 is >= $2, comparing dotted numbers left to right. `sort -V` is not portable
# enough to rely on inside a hook that has to work on whatever machine it lands on.
at_least() {
  local have="$1" want="$2" h w i
  for i in 1 2 3; do
    h="$(printf '%s' "$have" | cut -d. -f$i | tr -cd '0-9')"
    w="$(printf '%s' "$want" | cut -d. -f$i | tr -cd '0-9')"
    h="${h:-0}"; w="${w:-0}"
    [ "$h" -gt "$w" ] 2>/dev/null && return 0
    [ "$h" -lt "$w" ] 2>/dev/null && return 1
  done
  return 0
}

# A candidate is ours if `--help` says so, and usable if it is not older than this plugin.
usable_pr() {
  local bin="$1" version
  "$bin" --help 2>&1 | grep -qi provenrail || return 1
  version="$("$bin" --version 2>/dev/null | tr -cd '0-9.' )"
  [ -n "$version" ] || return 1
  at_least "$version" "$(plugin_version)"
}

find_pr() {
  if command -v pr >/dev/null 2>&1; then
    # `pr` is also a POSIX text-formatting utility. Only accept ours.
    if usable_pr pr; then command -v pr; return 0; fi
  fi
  for candidate in "$HOME/.local/bin/pr" "$HOME/.cargo/bin/pr" /opt/homebrew/bin/pr /usr/local/bin/pr; do
    if [ -x "$candidate" ] && usable_pr "$candidate"; then
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
