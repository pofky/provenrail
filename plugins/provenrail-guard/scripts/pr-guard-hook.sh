#!/usr/bin/env bash
# Provenrail guard hook shim.
#
# Claude Code pipes the hook payload on stdin and reads our decision from stdout. This script's
# only job is to hand that payload to `pr guard hook` and pass the answer back untouched.
#
# The hard rule here is that this must NEVER break the user's session. If Provenrail is not
# installed, or anything at all goes wrong, we exit 0 with no output, which Claude Code reads as
# "no opinion" and the tool call proceeds exactly as it would without the plugin. A guardrail that
# bricks your agent is worse than no guardrail, and it is the reason people uninstall these.
#
# The trade-off is stated plainly in the README: while Provenrail is missing, nothing is blocked
# and nothing is recorded. We tell you once rather than failing loudly on every call.
set -uo pipefail

EVENT="${1:-pre}"
PAYLOAD="$(cat)"

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

PR_BIN="$(find_pr || true)"

if [ -z "${PR_BIN:-}" ]; then
  # Tell the user once per day, not once per tool call.
  STAMP="${TMPDIR:-/tmp}/.provenrail-guard-missing-$(date +%Y%m%d)"
  if [ ! -f "$STAMP" ]; then
    : > "$STAMP"
    echo "provenrail-guard: Provenrail is not installed, so nothing is being blocked or recorded." >&2
    echo "  Install it with:  uv tool install provenrail && pr quickstart" >&2
  fi
  exit 0
fi

# stdout is the decision Claude Code parses, so it is passed through untouched. stderr is
# forwarded rather than discarded: `pr guard hook` uses it to say things the user genuinely
# needs, above all "hooks are installed but nothing is armed", which is invisible otherwise.
# It rate-limits itself to once a day, so forwarding it does not make the session noisy.
ERR="$(mktemp -t provenrail-guard.XXXXXX 2>/dev/null || echo "${TMPDIR:-/tmp}/provenrail-guard.$$")"
OUT="$("$PR_BIN" guard hook --event "$EVENT" <<<"$PAYLOAD" 2>"$ERR")" || { rm -f "$ERR"; exit 0; }
[ -s "$ERR" ] && cat "$ERR" >&2
rm -f "$ERR"
[ -n "$OUT" ] && printf '%s\n' "$OUT"
exit 0
