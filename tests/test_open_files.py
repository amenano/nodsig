#!/usr/bin/env python3
"""
test_open_files.py: a many-way merge and the limit on open files.

A merge opens every one of its sources together, and a full-chain scan
leaves more than a thousand runs in one category. The usual soft limit
on open files is 1,024, so on an ordinary system the first fusion after
the scan used to die on whichever run crossed the limit, with an
`[Errno 24]` that named a file and no remedy. `recio.reserve_descriptors`
is the answer, and every merge reaches it through `budgeted_slab`, the
call it already makes to learn its read buffer.

What is checked, each time in a CHILD process, because a limit on open
files belongs to the process and a lowered hard limit cannot be raised
again:

- the failure is real: with the soft limit below the number of sources,
  opening them without asking fails with EMFILE. Without this the other
  checks could pass on a system where nothing was ever at stake;
- asking first raises the soft limit as far as the merge needs, and the
  same files then open;
- a limit that is already enough is left alone;
- when the hard limit is too low the step refuses BEFORE opening
  anything, in the caller's own error type, and the message carries the
  number to ask for;
- end to end: a store with more runs than the soft limit fuses, and
  holds every record.

Usage:
    python3 test_open_files.py      # prints PASS or fails loudly
    (also runs under pytest)
"""

import os
import subprocess
import sys
import tempfile

import nodsig

try:
    import resource
except ImportError:                 # a platform without these limits
    resource = None

SOFT = 64                           # the lowered soft limit
SOURCES = 200                       # more than SOFT, by a wide margin
SRC = os.path.dirname(os.path.dirname(os.path.abspath(nodsig.__file__)))


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


def supported():
    """The checks need limits to lower and a hard limit with room for
    SOURCES files. Where either is missing there is nothing to test, and
    the suite says so instead of passing in silence."""
    if resource is None:
        return False
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    return hard == resource.RLIM_INFINITY or hard >= 2 * SOURCES


def child(body, *args):
    """Run `body` in a fresh interpreter whose soft limit is SOFT. The
    child prints one line; that line is the answer."""
    preamble = (
        "import errno, os, resource, sys\n"
        "N = resource.RLIMIT_NOFILE\n"
        f"resource.setrlimit(N, ({SOFT}, resource.getrlimit(N)[1]))\n"
        f"SOURCES = {SOURCES}\n")
    env = dict(os.environ, PYTHONPATH=SRC)
    done = subprocess.run([sys.executable, "-c", preamble + body, *args],
                          capture_output=True, text=True, env=env)
    check(done.returncode == 0,
          f"the child failed:\n{done.stdout}\n{done.stderr}")
    return done.stdout.strip()


def test_the_failure_is_real():
    if not supported():
        print("skip  no limit on open files to lower here")
        return
    said = child(
        "held = []\n"
        "try:\n"
        "    for _ in range(SOURCES):\n"
        "        held.append(open(os.devnull, 'rb'))\n"
        "    print('opened')\n"
        "except OSError as e:\n"
        "    print('EMFILE' if e.errno == errno.EMFILE else e)\n")
    check(said == "EMFILE",
          f"opening {SOURCES} files under a limit of {SOFT} must fail "
          f"with EMFILE, got {said!r}")
    print("ok  without asking, the sources do not open")


def test_asking_first_raises_the_soft_limit():
    if not supported():
        print("skip  no limit on open files to lower here")
        return
    said = child(
        "from nodsig.recio import budgeted_slab\n"
        "budgeted_slab(SOURCES)\n"
        "held = [open(os.devnull, 'rb') for _ in range(SOURCES)]\n"
        "print(resource.getrlimit(N)[0])\n")
    check(said.isdigit() and int(said) >= SOURCES,
          f"the soft limit must cover the {SOURCES} sources, got {said!r}")
    print(f"ok  asked first, the soft limit went from {SOFT} to {said} "
          "and the sources open")


def test_a_limit_that_is_enough_is_left_alone():
    if not supported():
        print("skip  no limit on open files to lower here")
        return
    said = child(
        "from nodsig.recio import budgeted_slab, reserve_descriptors\n"
        "budgeted_slab(1)\n"
        "reserve_descriptors(0)\n"
        "print(resource.getrlimit(N)[0])\n")
    check(said == str(SOFT),
          f"nothing needed raising and the limit moved to {said!r}")
    print("ok  a limit that is enough is not touched")


def test_a_hard_limit_too_low_is_refused_with_the_number():
    if not supported():
        print("skip  no limit on open files to lower here")
        return
    said = child(
        f"resource.setrlimit(N, ({SOFT}, {SOFT}))\n"
        "from nodsig import recio\n"
        "class Mine(RuntimeError): pass\n"
        "try:\n"
        "    recio.budgeted_slab(SOURCES, Mine)\n"
        "    print('accepted')\n"
        "except Mine as e:\n"
        "    need = SOURCES + recio._FD_HEADROOM\n"
        "    print('refused', f'ulimit -n {need}' in str(e),\n"
        "          f'LimitNOFILE={need}' in str(e),\n"
        "          resource.getrlimit(N)[0])\n")
    check(said == f"refused True True {SOFT}",
          "a hard limit below the need must be refused in the caller's "
          f"type, naming the number and leaving the limit, got {said!r}")
    print("ok  a hard limit too low is refused before anything opens, "
          "and the message carries the number")


def test_a_store_with_more_runs_than_the_limit_fuses(tmp):
    if not supported():
        print("skip  no limit on open files to lower here")
        return
    said = child(
        "from nodsig.genstore import GenStore, new_state_fields\n"
        "class StoreError(RuntimeError): pass\n"
        "d = sys.argv[1]\n"
        "state = {'format': 'test-v1', **new_state_fields()}\n"
        "store = GenStore(d, state, label='test', error=StoreError)\n"
        "store.make_runs_dir()\n"
        "for k in range(SOURCES):\n"
        "    store.write_run(f'run_{k:04d}.bin', 'cat',\n"
        "                    [k.to_bytes(3, 'big') + b'\\0\\0'])\n"
        "dups, delete = store.fuse('m', (5, 3, 4), 'cat', dedup=None)\n"
        "store.commit(delete)\n"
        "print(store.state['files']['m']['records'], dups)\n", tmp)
    check(said == f"{SOURCES} 0",
          f"the fusion of {SOURCES} runs under a soft limit of {SOFT} "
          f"must hold every record, got {said!r}")
    print(f"ok  {SOURCES} runs fuse under a soft limit of {SOFT}")


def main():
    test_the_failure_is_real()
    test_asking_first_raises_the_soft_limit()
    test_a_limit_that_is_enough_is_left_alone()
    test_a_hard_limit_too_low_is_refused_with_the_number()
    with tempfile.TemporaryDirectory() as tmp:
        test_a_store_with_more_runs_than_the_limit_fuses(tmp)
    print("PASS")


if __name__ == "__main__":
    main()
