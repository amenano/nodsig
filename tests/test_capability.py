#!/usr/bin/env python3
"""
test_capability.py — self-test for the answer envelope.

`Result{status, value, source}` exists to keep three things apart
that are easy to collapse and dangerous to confuse:

    "no backend is configured"        UNSUPPORTED
    "the backend looked, nothing"     OK + None
    "the backend cannot decide"       UNDETERMINED

Only the second is reassuring, and a check tool that printed the same
answer for all three would tell someone their key is safe when nobody
actually looked. The backends' own suites check that they RETURN the
right envelope; this one checks the envelope itself.

What is checked:

- the three statuses are distinct, and `found`/`answered` read them the
  way callers do (a definite negative ANSWERED but did not FIND);
- a `id` containing a path is refused at construction — results
  must carry identity, never the topology of the machine that produced
  them, or they stop being portable and start leaking;
- a sealed source shows its fingerprint, an unsealed one says so
  instead of staying silent (silence would read as sealed);
- a live source is described as a tip, not as an unsealed artifact.

Usage:
    python3 test_capability.py       # prints PASS or fails loudly
    (also runs under pytest)
"""

import sys

from nodsig.capability import Source, Result, Status

FP = "22cb979ba56dfbc0b437a1d8af2c578cf15fc0a7e6aedf6c946b7617d3f69860"


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


def test_statuses_stay_distinct():
    prov = Source.artifact("outpoint-derived-v2", 957_301, FP)
    negative = Result.ok(None, prov)
    positive = Result.ok({"outputs": 3}, prov)
    missing = Result.unsupported(prov)
    unsure = Result.undetermined(prov)

    check(negative.answered and not negative.found,
          "a definite negative ANSWERED the question without finding")
    check(positive.answered and positive.found,
          "a value must read as both answered and found")
    check(not missing.answered and not missing.found,
          "an unconfigured capability never answered anything")
    check(not unsure.answered,
          "UNDETERMINED is not an answer")
    check(len({negative.status, missing.status, unsure.status}) == 3,
          "the three cases must not collapse into one status")
    print("ok  statuses: nothing-found, not-configured and cannot-decide "
          "stay three different answers")


def test_source_id_refuses_a_path():
    for bad in ("/srv/artifacts/derived", "C:\\artifacts\\index",
                "./derived"):
        try:
            Source(bad, 1)
            fail(f"a path must be refused as a id: {bad}")
        except ValueError:
            pass
    print("ok  id: a filesystem path is refused — a result "
          "carries identity, not local topology")


def test_sealed_and_unsealed_are_told_apart():
    sealed = Source.artifact("outpoint-derived-v2", 957_301, FP)
    line = sealed.describe("history")
    check(line.startswith("history: outpoint-derived-v2"),
          f"the header must name the format tag: {line}")
    check("confirmed blocks 1..957,301" in line,
          f"the header must state the perimeter: {line}")
    check("sealed 22cb979b…9860" in line,
          f"a sealed source must show its fingerprint: {line}")

    unsealed = Source.artifact("reveal-archive-v2", 957_301, None)
    line = unsealed.describe("exposure")
    check("NOT sealed" in line,
          f"an unsealed source must SAY so, not stay silent: {line}")
    check("sealed 2" not in line,
          "an unsealed source must not show a fingerprint")
    print("ok  describe: sealed shows its fingerprint, unsealed admits "
          "it is not sealed")


def test_live_source_is_a_tip_not_a_seal():
    line = Source.node("bitcoin-core-rpc scantxoutset",
                           957_400).describe("balance")
    check("node height 957,400" in line, f"the tip must appear: {line}")
    check("NOT sealed" not in line and "sealed" not in line,
          f"a running node is not an unsealed artifact: {line}")
    unknown = Source.node("bitcoin-core-rpc scantxoutset", None)
    check(unknown.describe("balance") ==
          "balance: bitcoin-core-rpc scantxoutset",
          "before the scan there is no height to claim")
    print("ok  live source: described by its tip, never by a seal it "
          "cannot have")


TESTS = (test_statuses_stay_distinct,
         test_source_id_refuses_a_path,
         test_sealed_and_unsealed_are_told_apart,
         test_live_source_is_a_tip_not_a_seal)


def main():
    for t in TESTS:
        t()
    print("PASS: capability")


if __name__ == "__main__":
    main()
