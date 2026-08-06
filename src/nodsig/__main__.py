"""Makes `python3 -m nodsig …` behave exactly like the installed
`nodsig` command, so a clone with nothing installed still gets the
public command surface (and not only the per-module one)."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
