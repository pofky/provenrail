"""Generate the rule data the zero-install guard hook reads.

The plugin has to work before Provenrail is installed, which means the hook cannot import
`provenrail.rulesets`. It reads a JSON copy instead. That copy is generated from the
catalogue by this script and checked in, so there is exactly one place a rule is written
and the copy cannot drift silently: `tests/test_guard_standalone.py` regenerates it and
fails if the checked-in file differs.

    python tools/vendor_guard_rules.py          # rewrite the vendored file
    python tools/vendor_guard_rules.py --check  # exit 1 if it is stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "plugins" / "provenrail-guard" / "scripts" / "rules.json"


def build() -> dict:
    sys.path.insert(0, str(ROOT / "src"))
    from provenrail import rulesets
    from provenrail.guard import DEFAULT_PACKS

    packs = {}
    for pack, spec in rulesets.CATALOG.items():
        packs[pack] = {
            "title": spec["title"],
            "description": spec["description"],
            "rules": [{k: v for k, v in rule.items() if k in rulesets._ENGINE_FIELDS}
                      for rule in spec["rules"]],
        }
    return {
        "generated_by": "tools/vendor_guard_rules.py",
        "schema": 1,
        "default_packs": list(DEFAULT_PACKS),
        "packs": packs,
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=False) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""
        if current != text:
            print(f"{TARGET} is stale; run: python tools/vendor_guard_rules.py",
                  file=sys.stderr)
            return 1
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(text, encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
