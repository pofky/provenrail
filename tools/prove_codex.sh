#!/usr/bin/env bash
# Prove undo on Codex CLI with a real session, and capture the real hook payload.
#
# Why this is a script and not a test: it needs a logged-in Codex, it spends a model call, and
# it is the one thing standing between "the Codex adapter is written from the documented
# contract" and "the Codex adapter has been driven". Until it has passed once, nothing public
# may say undo works on Codex.
#
#   codex login                 # once, interactive
#   tools/prove_codex.sh
#
# It builds a scratch repository holding two files that were never committed, installs the
# hook for Codex in it, asks Codex to delete the directory, then runs `pr undo last` and
# compares checksums. The payload Codex sent is left in $WORK/payloads.jsonl so it can be
# added to hosts.CAPTURED_PAYLOAD.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PR="$ROOT/.venv/bin/pr"
WORK="$(mktemp -d -t provenrail-codex.XXXXXX)"
export PROVENRAIL_HOME="$WORK/home"
mkdir -p "$WORK/repo/src" "$WORK/bin"

# A `pr` in front of the real one that keeps a copy of every hook payload it is handed.
cat > "$WORK/bin/pr" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = guard ] && [ "\${2:-}" = hook ]; then
  tee -a "$WORK/payloads.jsonl" | "$PR" "\$@"
else
  exec "$PR" "\$@"
fi
EOF
chmod +x "$WORK/bin/pr"
export PATH="$WORK/bin:$PATH"

cd "$WORK/repo"
git init -q
echo "print('keep me')" > src/app.py
echo "never committed" > src/wip.py
echo "# scratch" > README.md
git add README.md
git -c user.name=t -c user.email=t@example.com commit -qm init
shasum src/* > "$WORK/before.txt"

pr guard install --host codex > /dev/null
DELETE="rm"
DELETE="$DELETE -rf src"
codex exec -s workspace-write --dangerously-bypass-hook-trust \
  "Run exactly this shell command and then stop, do nothing else: $DELETE" || true

if [ -d src ]; then
  echo "FAIL: Codex did not delete src, so there is nothing to undo. See the output above."
  exit 1
fi
if [ ! -s "$WORK/payloads.jsonl" ]; then
  echo "FAIL: the hook was never called, so Codex is not reading .codex/hooks.json here."
  exit 1
fi
pr undo
pr undo last
if shasum src/* | diff -q - "$WORK/before.txt" > /dev/null; then
  echo "PASS: both files are back, byte for byte. Payload: $WORK/payloads.jsonl"
else
  echo "FAIL: the restored files differ from the originals."
  exit 1
fi
