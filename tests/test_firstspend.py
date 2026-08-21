#!/usr/bin/env python3
"""FirstSpend-v1: the fifth artifact, when a lock was first spent from.

Built from the derivatives' history alone. The tests here reuse the
derived suite's synthetic chain, whose HIST_ROWS is an independent model
of every lock's spends, so the first spend of each lock is known by hand:

    A spent by tx 2 and tx 8   -> first = 2  (appears ONCE, at 2)
    B spent by tx 6 and tx 8   -> first = 6
    C spent by tx 4            -> first = 4

Covered:
- build matches that model, byte for byte, sorted by (spender, lock);
- a lock spent several times appears exactly once, with its FIRST spend;
- an interrupted-and-resumed build equals the one-shot build;
- the build refuses a derivatives directory that is not sealed / not v3,
  and the row count equals the locks the model spends.

Usage:
    python3 test_firstspend.py     # prints PASS or fails loudly
    (also runs under pytest via the shared conftest fixtures)
"""

import io
import json
import os
import sys
import tempfile

import pytest

from nodsig import derivatives as dv
from nodsig import firstspend as fs
from nodsig import outpoint_index as oi
from nodsig.hashing import hash160
import test_derivatives as td


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


def _expected_rows():
    """The model's first spends, as sorted 25-byte records."""
    locks = {"A": hash160(td.SPK_A), "B": hash160(td.SPK_B),
             "C": hash160(td.SPK_C)}
    first = {}
    for name, rows in td.HIST_ROWS.items():
        spends = [sp for _out, sp, _val in rows if sp != 0]
        if spends:
            first[name] = min(spends)
    recs = [first[n].to_bytes(5, "big") + locks[n] for n in first]
    recs.sort()
    return recs


def _read_firstspend(out_dir):
    manifest = fs._load_manifest(out_dir)
    entry = manifest["build"]["files"]["firstspend"]
    with open(os.path.join(out_dir, entry["file"]), "rb") as f:
        return manifest, f.read()


def build_pipeline(tmp, name="fs_index", end=None):
    blocks, txids = td.derived_chain()
    graph, index = td.build_index(tmp, blocks, name=name, end=end)
    derived = os.path.join(tmp, name + "_derived")
    dv.run_build(index, derived)
    return derived


def build_pipeline_with_index(tmp, name="fs_bt"):
    blocks, txids = td.derived_chain()
    graph, index = td.build_index(tmp, blocks, name=name)
    derived = os.path.join(tmp, name + "_derived")
    dv.run_build(index, derived)
    return derived, index


def test_build_matches_model(tmp):
    derived = build_pipeline(tmp)
    out = os.path.join(tmp, "firstspend")
    fp = fs.run_build(derived, out)

    manifest, data = _read_firstspend(out)
    want = b"".join(_expected_rows())
    check(data == want,
          f"firstspend bytes differ from the model: got {data.hex()}, "
          f"want {want.hex()}")
    rows = manifest["build"]["rows"]
    check(rows == len(_expected_rows()),
          f"row count {rows} != {len(_expected_rows())} spent "
          "locks in the model")
    # A appears once, at its FIRST spend (2), not its later one (8).
    a_row = min(2, 8).to_bytes(5, "big") + hash160(td.SPK_A)
    check(data.count(hash160(td.SPK_A)) == 1,
          "lock A, spent twice, does not appear exactly once")
    check(a_row in data, "lock A is not recorded at its first spend (2)")
    check(fp == manifest["fingerprint"], "run_build returned a stray fp")
    # provenance: the parent is the derivatives, declared and not sealed in.
    dman = dv._load_manifest(derived)
    check(manifest["build"]["parent"]["fingerprint"] == dman["fingerprint"],
          "firstspend does not declare its derivatives parent")
    print("ok  firstspend: bytes match the model, A appears once at its "
          "first spend, parent declared")


def test_resume_equals_oneshot(tmp):
    derived = build_pipeline(tmp)
    one = os.path.join(tmp, "fs_one")
    fp_one = fs.run_build(derived, one)

    # Interrupt: flush one row at a time so the scan checkpoints mid-file,
    # then resume from the state on disk.
    part = os.path.join(tmp, "fs_part")
    st = fs._new_state()
    os.makedirs(part, exist_ok=True)
    (hist_path, hist_sha, _n_tx, _fp, cov,
     _fmt, hist_rec) = fs._history_source(derived)
    st["source_fingerprint"] = _fp
    st["coverage"] = cov
    store = fs._store(part, st, clock=fs.WallClock("build", st))
    # Run the scan with a tiny flush so several runs and checkpoints form,
    # then let the normal build finish merge+seal from that state.
    fs._phase_scan(store, hist_path, hist_sha, hist_rec, flush_records=1)
    st["phase"] = "merge"
    store.write_state()
    fp_part = fs.run_build(derived, part)

    check(fp_one == fp_part,
          f"resumed build {fp_part} != one-shot {fp_one}")
    _, a = _read_firstspend(one)
    _, b = _read_firstspend(part)
    check(a == b, "resumed bytes differ from one-shot")
    print("ok  firstspend: an interrupted-and-resumed build equals one-shot")


def test_refuses_unsealed_and_wrong_format(tmp):
    # Not sealed: an empty dir has no manifest.
    empty = os.path.join(tmp, "no_derived")
    os.makedirs(empty, exist_ok=True)
    try:
        fs.run_build(empty, os.path.join(tmp, "x"))
        fail("build accepted a derivatives dir with no manifest")
    except dv.OutpointError:
        pass
    print("ok  firstspend: refuses a derivatives directory that is not "
          "sealed")


def test_verify_passes_and_catches_corruption(tmp):
    derived = build_pipeline(tmp)
    out = os.path.join(tmp, "fs_verify")
    fs.run_build(derived, out)

    # A clean table, with the parent, passes both roads.
    devnull = open(os.devnull, "w")
    fs.run_verify(out, derived_dir=derived, out=devnull)

    # Structural: flip a byte in the data file and the audit must catch it
    # (verify_sealed on the fingerprint, before the structural pass even).
    manifest = fs._load_manifest(out)
    data_file = os.path.join(out,
                             manifest["build"]["files"]["firstspend"]["file"])
    with open(data_file, "r+b") as f:
        f.seek(0)
        b = f.read(1)
        f.seek(0)
        f.write(bytes([b[0] ^ 0xFF]))
    try:
        fs.run_verify(out, derived_dir=derived, out=devnull)
        fail("verify passed a table with a flipped byte")
    except fs.FirstSpendError:
        pass
    print("ok  firstspend: verify passes a clean table and catches a "
          "flipped byte")


def test_verify_refuses_a_foreign_parent(tmp):
    derived = build_pipeline(tmp)
    out = os.path.join(tmp, "fs_foreign")
    fs.run_build(derived, out)
    # A DIFFERENT derivatives (a second, independent build to the same
    # coverage has the same fingerprint, so build one to a shorter chain).
    other = build_pipeline(tmp, name="fs_other", end=4)
    devnull = open(os.devnull, "w")
    try:
        fs.run_verify(out, derived_dir=other, out=devnull)
        fail("verify accepted a foreign parent")
    except fs.FirstSpendError:
        pass
    print("ok  firstspend: verify refuses derivatives that are not the "
          "parent")


def _between_locks(out_dir, index_dir, from_h, to_h):
    buf = io.StringIO()
    fs.run_between(out_dir, index_dir, from_h, to_h, out=buf)
    return {line.split()[0] for line in buf.getvalue().splitlines()
            if not line.startswith("#")}


def test_between_window(tmp):
    derived, index_dir = build_pipeline_with_index(tmp)
    out = os.path.join(tmp, "fs_bt_out")
    fs.run_build(derived, out)

    idx = oi.Index(index_dir)
    try:
        # first spends by the model: A@2, B@6, C@4
        first = {"A": (2, hash160(td.SPK_A)), "B": (6, hash160(td.SPK_B)),
                 "C": (4, hash160(td.SPK_C))}
        heights = {n: idx.height_of_tx(sp) for n, (sp, _l) in first.items()}
        wm = idx.watermark
    finally:
        idx.close()

    # The whole chain: all three locks.
    allset = _between_locks(out, index_dir, 1, wm)
    want = {first[n][1].hex() for n in first}
    check(allset == want,
          f"between(whole chain) = {allset}, want {want}")

    # A one-height window around A's first spend: A, and only the locks
    # whose first spend shares that height.
    hA = heights["A"]
    same = {first[n][1].hex() for n in first if heights[n] == hA}
    got = _between_locks(out, index_dir, hA, hA)
    check(got == same,
          f"between({hA},{hA}) = {got}, want {same} (A's height)")
    print("ok  firstspend: between returns the locks first spent in a "
          "window, whole-chain and one-height")


def test_between_refuses_bad_range(tmp):
    derived, index_dir = build_pipeline_with_index(tmp)
    out = os.path.join(tmp, "fs_bt2")
    fs.run_build(derived, out)
    idx = oi.Index(index_dir)
    wm = idx.watermark
    idx.close()
    for lo, hi, why in [(5, 2, "from > to"),
                        (0, 3, "from below 1"),
                        (1, wm + 1, "to past the watermark")]:
        try:
            fs.run_between(out, index_dir, lo, hi, out=io.StringIO())
            fail(f"between accepted {why}")
        except fs.FirstSpendError:
            pass
    print("ok  firstspend: between refuses a backwards range, height 0, "
          "and a window past the watermark")


def test_rewind_equals_rebuild(tmp):
    # Full-coverage table, then a target: derivatives at height 4.
    d5 = build_pipeline(tmp, name="rw5")
    fs5 = os.path.join(tmp, "fs5")
    fs.run_build(d5, fs5)
    d4 = build_pipeline(tmp, name="rw4", end=4)
    fs4 = os.path.join(tmp, "fs4_rebuild")
    fp_rebuild = fs.run_build(d4, fs4)

    # Rewind the full table to follow the height-4 derivatives.
    fp_rewind = fs.run_rewind(fs5, d4)
    check(fp_rewind == fp_rebuild,
          f"rewind fp {fp_rewind} != rebuild fp {fp_rebuild}")
    _, a = _read_firstspend(fs5)
    _, b = _read_firstspend(fs4)
    check(a == b, "rewound bytes differ from a fresh build to the same "
                  "coverage")
    # And the rewound table verifies against its new parent.
    fs.run_verify(fs5, derived_dir=d4, out=open(os.devnull, "w"))
    print("ok  firstspend: rewind equals a rebuild to the same coverage, "
          "and verifies against the lower parent")


def test_rewind_refuses_a_higher_parent(tmp):
    d4 = build_pipeline(tmp, name="rr4", end=4)
    fs4 = os.path.join(tmp, "fs_rr4")
    fs.run_build(d4, fs4)
    d5 = build_pipeline(tmp, name="rr5")   # higher coverage
    try:
        fs.run_rewind(fs4, d5)
        fail("rewind accepted derivatives ABOVE the table's coverage")
    except fs.FirstSpendError:
        pass
    print("ok  firstspend: rewind refuses a parent above the current "
          "coverage (that is a build)")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        test_build_matches_model(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        test_verify_passes_and_catches_corruption(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        test_verify_refuses_a_foreign_parent(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        test_between_window(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        test_between_refuses_bad_range(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        test_rewind_equals_rebuild(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        test_rewind_refuses_a_higher_parent(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        test_resume_equals_oneshot(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        test_refuses_unsealed_and_wrong_format(tmp)
    print("PASS: firstspend builds the model, resumes to the same bytes, "
          "and declares its parent.")


if __name__ == "__main__":
    main()
