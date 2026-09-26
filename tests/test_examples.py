#!/usr/bin/env python3
"""
test_examples.py: the examples under `examples/` keep working, and nothing
else in the repository depends on them.

Two guarantees, both executable:

- **Detachment.** No tracked file outside `examples/` refers to it (this
  file excepted). An example can therefore be rewritten or deleted without
  breaking a link, a doc or an import: the documentation stays the
  reference, and examples point at it, never the reverse.
- **They run.** `examples/address-set-profile/profile.py` is exercised on
  the suite's synthetic pipeline (graph -> index -> derivatives, and the
  merged archive of the shared chain), with numbers known in advance: a
  real co-spend, addresses never seen, a revealed and an unrevealed key,
  an invalid line, and a capability left unconfigured.

Usage:
    python3 test_examples.py     # prints PASS or fails loudly
    (also runs under pytest via the shared conftest fixtures)
"""

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile

import pytest

from nodsig import derivatives as dvm
from nodsig.hashing import hash160
import test_check_addresses as tca
import test_derivatives as tdv
import test_reuse_scan as trs

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
PROFILE = EXAMPLES / "address-set-profile" / "profile.py"
TEXT = {".md", ".py", ".toml", ".txt", ".cfg", ".yml", ".yaml", ".json", ".sh", ".in"}


def tracked_files():
    """The files git tracks; without git (an unpacked sdist), every file
    under the root except the directories that are never tracked."""
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                             text=True, check=True).stdout.split("\n")
        return [ROOT / p for p in out if p]
    except (OSError, subprocess.CalledProcessError):
        skip = {".git", "local", "lab", "__pycache__", ".pytest_cache", "dist", "build"}
        return [p for p in ROOT.rglob("*")
                if p.is_file() and not skip & set(p.relative_to(ROOT).parts)]


def load_profile():
    spec = importlib.util.spec_from_file_location("example_profile", PROFILE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Detachment
# ---------------------------------------------------------------------------

def test_nothing_outside_examples_refers_to_them():
    here = pathlib.Path(__file__).resolve()
    offenders = []
    for p in tracked_files():
        rel = p.relative_to(ROOT)
        if rel.parts[0] == "examples" or p.resolve() == here:
            continue
        if p.suffix not in TEXT or not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if "examples/" in text or "](examples" in text:
            offenders.append(str(rel))
    assert not offenders, ("examples must stay detachable; these files refer "
                           f"to them: {offenders}")


# ---------------------------------------------------------------------------
# The profile example on the synthetic pipeline
# ---------------------------------------------------------------------------

def build_pipeline(tmp):
    """The derivatives suite's chain: lock A (P2PKH) receives six outputs
    and spends two, one of them together with lock B's coin (tx t4); lock
    B (P2WPKH) receives two and spends both."""
    blocks, _ = tdv.derived_chain()
    _graph, index = tdv.build_index(tmp, blocks, name="ex_index")
    derived = os.path.join(tmp, "ex_derived")
    dvm.run_build(index, derived)
    return index, derived


ADDR_A = tca.b58check_encode(0x00, bytes(range(20)))          # SPK_A's lock
ADDR_B = tca.segwit_addr(b"\xBB" * 20, 0)                     # SPK_B's lock
ADDR_REVEALED = tca.segwit_addr(hash160(trs.PUB1), 0)         # key in a scriptSig
ADDR_HIDDEN = tca.segwit_addr(hash160(trs.PUB5), 0)           # key never revealed
LIST = [ADDR_A, ADDR_B, ADDR_REVEALED, ADDR_HIDDEN, "not-an-address"]


def check_profile(tmp, archive):
    index, derived = build_pipeline(tmp)
    ex = load_profile()
    from nodsig.check_addresses import build_backends
    backends = build_backends({"index": index, "derived": derived, "archive": archive})

    got = ex.profile(LIST, backends, before=10)
    assert got["addresses"] == 5 and got["invalid"] == 1, got
    assert got["history"] == {"first funded before": 2, "never seen": 2,
                              "seen": 2, "spent": 2}, got["history"]
    assert got["receipts"] == {"2-5": 1, "6-20": 1}, got["receipts"]
    assert got["co_inputs"] == {"co-spent with other locks": 2,
                                "never spent": 2}, got["co_inputs"]
    assert got["first_height"] == {"min": 1, "median": 2, "max": 2}, got

    rev = ex.profile([ADDR_REVEALED], backends, before=10**6)["exposure"]
    assert rev == {"revealed": 1, "revealed before": 1}, rev
    hid = ex.profile([ADDR_HIDDEN], backends, before=10**6)["exposure"]
    assert hid == {"never revealed": 1}, hid

    # An unconfigured capability is reported for every address, never as a
    # negative.
    bare = build_backends({"index": index, "derived": derived})
    got = ex.profile(LIST, bare)
    assert got["exposure"] == {"UNSUPPORTED": 4}, got["exposure"]

    # The command line: the same numbers, plus which artifact answered.
    listing = os.path.join(tmp, "addresses.txt")
    with open(listing, "w", encoding="utf-8") as f:
        f.write("# a comment\n\n" + "\n".join(LIST) + "\n")
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    run = subprocess.run([sys.executable, str(PROFILE), "--index", index,
                          "--derived", derived, "--archive", archive,
                          "--addresses", listing, "--before", "10", "--json"],
                         capture_output=True, text=True, env=env, check=True)
    cli = json.loads(run.stdout)
    assert cli["history"] == ex.profile(LIST, backends, before=10)["history"]
    assert set(cli["answered_by"]) == {"history", "co-inputs", "exposure"}
    assert all("1.." in line for line in cli["answered_by"].values()), cli["answered_by"]


def test_profile_example(tmp, archive):
    check_profile(tmp, archive)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        test_nothing_outside_examples_refers_to_them()
        print("ok  detachment: nothing outside examples/ refers to them")
        check_profile(tmp, tca.build_archive(tmp))
        print("ok  profile example: history, co-inputs, exposure, unsupported, CLI")
    print("PASS")


if __name__ == "__main__":
    main()
