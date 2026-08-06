#!/usr/bin/env python3
"""
test_fixtures_present.py — the safety net underneath conftest.

The whole suite rests on the shared fixtures in `conftest.py`. If that
file goes missing — which has happened, when it was untracked and left
with a `git clean` — pytest does not say so in any understandable way:
it emits a couple of dozen "fixture 'archive' not found", one per test,
and the real cause stays buried under the noise.

This file surfaces it with ONE message. It is deliberately independent
of the fixtures (it asks for none), so it runs even when every other
test fails, and it checks two things:

  1. that `conftest.py` exists;
  2. that it still declares every fixture the tests rely on.

It is tracked on purpose: even in a freshly cloned repository, a missing
conftest is reported by the suite itself, with the way out beside it. If
you add a new shared fixture that tests request by name, add it to
`REQUIRED_FIXTURES` below as well.
"""

import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CONFTEST = os.path.join(HERE, "conftest.py")

# The fixtures the tests depend on, by name. This is the only list to
# keep in step with the conftest.
REQUIRED_FIXTURES = [
    "tmp", "blocks", "locks_dir",
    "archive", "archive_oneshot",
    "graph", "graph_oneshot", "graph_from_ra",
    "out_csv",
]

_RECOVERY = (
    "Rebuild it from the main() functions of the test files — they "
    "declare the exact wiring of every fixture — and COMMIT it, so it "
    "cannot happen again."
)


def test_conftest_present():
    """The file is there. If not, it is the cause of the burst of
    'fixture not found'."""
    assert os.path.exists(CONFTEST), (
        f"{os.path.basename(CONFTEST)} is missing: without it every test "
        f"using a shared fixture fails with 'fixture not found'. "
        f"{_RECOVERY}"
    )


def test_required_fixtures_declared():
    """Every expected fixture is still defined in the conftest. This
    looks at the SOURCE, not at resolved fixtures, so that it keeps
    standing even when resolution is the thing that broke."""
    if not os.path.exists(CONFTEST):
        return                       # test_conftest_present already says so
    src = open(CONFTEST, encoding="utf-8").read()
    declared = set(re.findall(r"^def (\w+)\(", src, re.MULTILINE))
    missing = [name for name in REQUIRED_FIXTURES if name not in declared]
    assert not missing, (
        f"conftest.py no longer defines: {', '.join(missing)}. "
        f"The tests requesting them will fail with 'fixture not found'. "
        f"{_RECOVERY}"
    )
