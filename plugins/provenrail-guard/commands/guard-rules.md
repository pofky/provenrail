---
description: List every Provenrail guardrail rule, including the packs that are not armed
allowed-tools: Bash(*)
---

Show the user which rules exist and which are switched on.

```bash
python3 - "${CLAUDE_PLUGIN_ROOT}/scripts/rules.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
on = set(data["default_packs"])
for pack, spec in data["packs"].items():
    mark = "ARMED by default" if pack in on else "off (opt in)"
    print("\n%s  [%s]  %s" % (pack, mark, spec["description"]))
    for rule in spec["rules"]:
        print("  %-42s %-18s %s" % (rule["id"], rule["effect"], rule.get("reason", "")))
PY
```

Then tell the user, in one line, how to change it: a `.provenrail.json` at the repo root with
`{"policy": {"use": ["destructive", "secrets", "production", "access", "money"]}}`, listing the
packs they want. An empty list arms nothing.

Only mention rules that appear in that output. Do not invent coverage the catalogue does not
have: these rules match on tool names and on argument text, so a rule for `delete_*` does
nothing against a tool called `remove_record`, and saying otherwise is the one lie a guardrail
cannot survive.
