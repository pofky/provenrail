"""`python -m provenrail`, for when the `pr` command is not the one you meant.

`pr` is also a POSIX utility (the paginator from coreutils), and on Windows under Git Bash it
is the one that wins: `pr --version` there prints "pr (GNU coreutils) 8.32" and `pr verify`
fails with "unknown option". Our CI caught exactly that. Whoever hits it needs a way in that
does not depend on PATH order, and `python -m provenrail` cannot be shadowed by anything.

Every subcommand works identically:  python -m provenrail verify bundle.json
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
