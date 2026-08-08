#!/usr/bin/env python3
"""
test_derivatives.py — self-test for derivatives.py. The synthetic
chain of the index suite grows a fifth block holding a real CO-SPEND
(t4 consumes two outputs with two different locks in one transaction),
so all three derivatives have something true to say: histories with
receives and spends, fees including a same-block spend and the BIP30
twin, and a common-input group that crosses locks.

Everything is checked byte for byte against a model computed
independently from the writers' txids, then the properties:

- determinism: a build forced through tiny runs and checkpoints is
  byte-identical to the default build;
- append == rebuild: derivatives built on the index at height 4, then
  appended after the index grew to 5, equal the one-shot build — the
  update rows (outputs spent AFTER their cycle) counted and correct;
  and the same on a second chain whose new edge sorts BELOW an
  already-spent ordinal, so it lands in the middle of the re-sorted
  spends.bin instead of at its tail (the real chain's normal case);
- a crash mid-scan resumes from the checkpointed cursors and lands on
  the same bytes;
- the build refuses a degraded (tolerated-unresolved) index, and the
  reader refuses derivatives whose source index has moved on;
- history/fee/cospends tell true stories, verify catches flipped bytes
  and a ladder that is intact but samples the wrong rows.

Usage:
    python3 test_derivatives.py     # prints PASS or fails loudly
    (also runs under pytest via the shared conftest fixtures)
"""

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile

import pytest

from nodsig import __version__
from nodsig import derivatives as dv
from nodsig import genstore
from nodsig import outpoint_index as oi
import test_blockparse as tbw
import test_outpoint_index as toi
import test_reuse_scan as trs
from nodsig.hashing import hash160
from nodsig.reuse_scan import SAT

SPK_A, SPK_B, SPK_C = toi.SPK_A, toi.SPK_B, toi.SPK_C
S = 50 * SAT


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


# ---------------------------------------------------------------------------
# The chain: the index suite's four blocks + one block with a co-spend
# ---------------------------------------------------------------------------

def derived_chain():
    """height → (hash_display_hex, raw_hex), and the txids. Blocks
    1..4 restate toi.index_chain (same txs, same txids); block 5 adds:

        h5  cbD;  t4 spends t2:0 AND t3:0 together → 5 sat to C

    t4 is the co-spend: two inputs, two different locks (A and B),
    one spender — the common-input hint made concrete, fee 3 sat.
    """
    blocks = {}
    txids = {}
    prev = bytes(32)

    def add(height, raw_txs, ids):
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_700_000_000 + height,
                                      0x1700_0000, height, raw_txs, ids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())

    cbA, cbA_id, _ = toi._coinbase(b"\x01A",
                                   [tbw.w_output(S, SPK_A)])
    add(1, [cbA], [cbA_id])
    txids["cbA"] = cbA_id

    cbB, cbB_id, _ = toi._coinbase(b"\x01B",
                                   [tbw.w_output(S, SPK_A)])
    t1, t1_id, _ = tbw.w_tx(
        1, [tbw.w_input(cbB_id, 0, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(7, SPK_B), tbw.w_output(3, SPK_C)], 0)
    add(2, [cbB, t1], [cbB_id, t1_id])
    txids["cbB"], txids["t1"] = cbB_id, t1_id

    cbC, cbC_id, _ = toi._coinbase(b"\x01C",
                                   [tbw.w_output(S, SPK_A)])
    t2, t2_id, _ = tbw.w_tx(
        1, [tbw.w_input(t1_id, 1, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(2, SPK_A)], 0)
    add(3, [cbC, t2], [cbC_id, t2_id])
    txids["cbC"], txids["t2"] = cbC_id, t2_id

    t3, t3_id, _ = tbw.w_tx(
        1, [tbw.w_input(t1_id, 0, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(6, SPK_B)], 0)
    add(4, [cbA, t3], [cbA_id, t3_id])       # cbA again: BIP30 twin
    txids["t3"] = t3_id

    cbD, cbD_id, _ = toi._coinbase(b"\x01D",
                                   [tbw.w_output(S, SPK_A)])
    t4, t4_id, _ = tbw.w_tx(
        1, [tbw.w_input(t2_id, 0, b"\x00", 0xFFFFFFFF),
            tbw.w_input(t3_id, 0, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(5, SPK_C)], 0)
    add(5, [cbD, t4], [cbD_id, t4_id])
    txids["cbD"], txids["t4"] = cbD_id, t4_id
    return blocks, txids


# The independent model, ordinals worked out by hand:
#   tx:  0 cbA  1 cbB  2 t1  3 cbC  4 t2  5 cbA'  6 t3  7 cbD  8 t4
#   out: 0 cbA:0(50,A) 1 cbB:0(50,A) 2 t1:0(7,B) 3 t1:1(3,C)
#        4 cbC:0(50,A) 5 t2:0(2,A) 6 cbA':0(50,A) 7 t3:0(6,B)
#        8 cbD:0(50,A) 9 t4:0(5,C)
#   spends: out1←tx2, out3←tx4, out2←tx6, out5←tx8, out7←tx8
HIST_ROWS = {  # lock → [(out_ord, spender, value)], spender 0=unspent
    "A": [(0, 0, S), (1, 2, S), (4, 0, S), (5, 8, 2), (6, 0, S),
          (8, 0, S)],
    "B": [(2, 6, 7), (7, 8, 6)],
    "C": [(3, 4, 3), (9, 0, 5)],
}
TXIN_ROWS = [(2, 1), (4, 3), (6, 2), (8, 5), (8, 7)]
FEES = [0, 0, S - 10, 0, 1, 0, 1, 0, 3]


def expected_files():
    locks = {"A": hash160(SPK_A), "B": hash160(SPK_B),
             "C": hash160(SPK_C)}
    history = b""
    for name in sorted(locks, key=lambda n: locks[n]):
        for out, sp, val in HIST_ROWS[name]:
            history += (locks[name] + out.to_bytes(5, "big")
                        + sp.to_bytes(5, "big")
                        + val.to_bytes(dv.VAL, "big"))
    txin = b"".join(sp.to_bytes(5, "big") + out.to_bytes(5, "big")
                    for sp, out in TXIN_ROWS)
    fees = b"".join(f.to_bytes(dv.VAL, "big") for f in FEES)
    return {"history": history, "tx_inputs": txin, "fees": fees}, locks


def build_index(tmp, blocks, name="index", end=None):
    graph = toi.emit_graph(tmp, blocks, name + "_graph")
    index = os.path.join(tmp, name)
    oi.run_build(graph, index, end_height=end)
    return graph, index


def read_derived_files(derived_dir):
    manifest = json.load(open(os.path.join(derived_dir,
                                           dv.MANIFEST_NAME)))
    got = {}
    for name, entry in manifest["build"]["files"].items():
        with open(os.path.join(derived_dir, entry["file"]), "rb") as f:
            got[name] = f.read()
    return manifest, got


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def dbuilt(tmp):
    """(tmp, graph, index, derived, txids, locks) — the built pipeline
    the dependent tests share; main() passes the same tuple by hand."""
    blocks, txids = derived_chain()
    graph, index = build_index(tmp, blocks)
    derived = os.path.join(tmp, "derived")
    dv.run_build(index, derived)
    _, locks = expected_files()
    return tmp, graph, index, derived, txids, locks


def test_build_matches_model(tmp):
    blocks, txids = derived_chain()
    graph, index = build_index(tmp, blocks)
    derived = os.path.join(tmp, "derived")
    dv.run_build(index, derived)
    manifest, got = read_derived_files(derived)
    want, locks = expected_files()
    for name in dv.FP_ORDER:
        check(got[name] == want[name],
              f"{name}: bytes differ from the independent model\n"
              f" got  {got[name].hex()}\n want {want[name].hex()}")
    t = manifest["build"]["totals"]
    check(t["total_fees_sats"] == sum(FEES), "fee total wrong")
    check(t["input_sats"] == S + 3 + 7 + 2 + 6, "input total wrong")
    check(t["spent_outputs"] == 5 and t["unspent_outputs"] == 5,
          "spent/unspent split wrong")
    check(t["distinct_locks"] == 3, "distinct lock count wrong")
    check(t["updated_rows"] == 0, "a fresh build has no updated rows")
    idx_manifest = json.load(open(os.path.join(index, oi.MANIFEST_NAME)))
    check(manifest["build"]["parent"]["fingerprint"]
          == idx_manifest["fingerprint"],
          "ancestry: the source index fingerprint must be carried")
    for what, m in (("index", idx_manifest), ("derived", manifest)):
        check(m["build"]["producer"]["version"] == __version__,
              f"{what}: a sealed manifest must name what wrote it")
    dv.run_verify(derived)
    print("ok  build: three files byte-equal the model, totals and "
          "ancestry exact, audit passes, both manifests name their "
          "producer")
    return graph, index, derived, txids, locks


def test_determinism_tiny(dbuilt):
    tmp, _graph, index, derived, _txids, _locks = dbuilt
    tiny = os.path.join(tmp, "derived_tiny")
    dv.run_build(index, tiny, flush_records=1, checkpoint_every=1)
    _, got_a = read_derived_files(derived)
    _, got_b = read_derived_files(tiny)
    for name in dv.FP_ORDER:
        check(got_a[name] == got_b[name],
              f"{name}: tiny-run build differs from default build")
    print("ok  determinism: buffering leaves no trace in the bytes")


def test_append_equals_rebuild(tmp):
    """Index at height 4 → derivatives; index grows to 5 (t4 spends
    two OLD outputs → two update rows) → append; must equal the
    one-shot pipeline, and the reader must refuse the stale pairing
    in between."""
    blocks, txids = derived_chain()
    graph, index = build_index(tmp, blocks, name="index_app", end=4)
    derived = os.path.join(tmp, "derived_app")
    dv.run_build(index, derived)
    mid = json.load(open(os.path.join(derived, dv.MANIFEST_NAME)))
    check(mid["identity"]["coverage"]["to"] == 4, "partial build wrong")

    oi.run_build(graph, index)               # index grows to height 5
    idx = oi.Index(index)
    try:
        dv.Derived(derived, idx)
        fail("the reader accepted derivatives from a stale index")
    except oi.OutpointError:
        pass
    finally:
        idx.close()

    dv.run_build(index, derived)             # append
    manifest, got_a = read_derived_files(derived)
    check(manifest["build"]["totals"]["updated_rows"] == 2,
          "t4 spends two old outputs: exactly 2 update rows")
    fresh = os.path.join(tmp, "derived_fresh")
    dv.run_build(index, fresh)
    _, got_b = read_derived_files(fresh)
    for name in dv.FP_ORDER:
        check(got_a[name] == got_b[name],
              f"{name}: append produced different bytes than rebuild")
    print("ok  append: growing 1..4 then 5 equals building 1..5, "
          "stale pairing refused, update rows counted")


def test_append_equals_rebuild_through_the_gallop(tmp):
    """The same append, with the fusion allowed to move the previous
    generation in STRETCHES rather than record by record.

    The fast path is proved against a reference in the genstore suite;
    what is proved here is that it lands on the artifact's own bytes
    with the artifact's own widths — history deduplicates on 25 bytes
    but is searched by 20, and a stretch moved whole samples its ladder
    by position, so a confusion between the two would show up as a
    fingerprint that no longer matches the rebuild.

    The threshold is lowered because a five-block fixture has no
    stretch long enough to reach the bulk path otherwise, and a test
    that cannot reach the code it names is not a test of it; the
    assertion at the end is what keeps that honest."""
    taken = []
    real = genstore._adjacent_equal
    floor = genstore.MIN_BULK

    def counting(*args):
        taken.append(args[2])
        return real(*args)

    genstore._adjacent_equal = counting
    genstore.MIN_BULK = 2
    try:
        blocks, _txids = derived_chain()
        graph, index = build_index(tmp, blocks, name="index_gal", end=4)
        derived = os.path.join(tmp, "derived_gal")
        dv.run_build(index, derived)
        oi.run_build(graph, index)           # index grows to height 5
        dv.run_build(index, derived)         # append, with the gallop
        _, got_a = read_derived_files(derived)
    finally:
        genstore._adjacent_equal = real
        genstore.MIN_BULK = floor

    fresh = os.path.join(tmp, "derived_gal_fresh")
    dv.run_build(index, fresh)
    _, got_b = read_derived_files(fresh)
    for name in dv.FP_ORDER:
        check(got_a[name] == got_b[name],
              f"{name}: an append that moved stretches whole produced "
              f"different bytes than a rebuild\n got  {got_a[name].hex()}"
              f"\n want {got_b[name].hex()}")
    check(taken, "no stretch was ever moved whole: this test proved "
                 "nothing about the path it is named after")
    dv.run_verify(derived)
    print(f"ok  append: the fusion moving {len(taken)} stretches whole "
          "lands on the rebuild's bytes")


def _same_derived(a, b, what):
    ma, got_a = read_derived_files(a)
    mb, got_b = read_derived_files(b)
    for name in dv.FP_ORDER:
        check(got_a[name] == got_b[name],
              f"{what}: {name} differs from the rebuild")
    check(ma["fingerprint"] == mb["fingerprint"],
          f"{what}: same bytes but a different fingerprint")
    check(ma["identity"] == mb["identity"],
          f"{what}: same bytes but a different identity")
    for key in ("transactions", "outputs", "spends", "totals"):
        check(ma["build"][key] == mb["build"][key],
              f"{what}: manifest {key} is {ma['build'][key]!r}, "
              f"the rebuild says {mb['build'][key]!r}")


def _rewound_pair(tmp, blocks, height, tag):
    """Build index + derivatives over the whole chain, take both back
    to `height`, and build the reference that stopped there."""
    graph, index = build_index(tmp, blocks, name=f"{tag}_i")
    derived = os.path.join(tmp, f"{tag}_d")
    dv.run_build(index, derived)
    oi.run_rewind(index, graph, height)
    dv.run_rewind(index, derived)
    _, ref_index = build_index(tmp, blocks, name=f"{tag}_ri", end=height)
    ref = os.path.join(tmp, f"{tag}_rd")
    dv.run_build(ref_index, ref)
    return derived, ref


def test_rewind_equals_rebuild(tmp):
    """rewind ≡ rebuild for the derivatives, including the rows put
    BACK to unspent: block 5's co-spend consumed two outputs created at
    heights 3 and 4, so cutting at 4 must un-spend both — a transform,
    not a drop, and the only one the format allows.

    This chain also carries a duplicate txid (h1 and h4), below the cut
    on both sides: the rewind must NOT refuse here."""
    blocks, _ = derived_chain()
    derived, ref = _rewound_pair(tmp, blocks, 4, "rw")
    _same_derived(derived, ref, "rewind 5→4")
    man, files = read_derived_files(derived)
    spent = sum(1 for i in range(0, len(files["history"]), dv.HIST_REC)
                if files["history"][i + 25:i + 30] != dv.UNSPENT)
    check(spent == man["build"]["spends"] == 3,
          f"the rewound history must hold 3 spent rows, holds {spent}")
    print("ok  rewind: coming back from 5 to 4 equals building to 4, "
          "spent rows put back to unspent included")


def test_rewind_with_interleaved_spend(tmp):
    """The edge that goes sorts FIRST in spends.bin, not last: the sift
    must leave the hole in the MIDDLE of a sorted file and keep the
    rest in place. Same chain as the append test, read backwards."""
    blocks, _ = interleaved_chain()
    derived, ref = _rewound_pair(tmp, blocks, 3, "il_rw")
    _same_derived(derived, ref, "rewind 4→3 (interleaved)")
    print("ok  rewind: a removed edge from the middle of spends.bin "
          "leaves the same bytes as never having had it")


def test_rewind_survives_a_kill_before_the_truncations(tmp):
    """The positional step commits the shrunken counts FIRST and
    truncates after: a kill between the two leaves the files LONGER
    than the state says, which is the direction the next load heals on
    its own. Under the old order the same kill read as 'tampered with
    or lost data' and wedged both rewind and build behind a false
    corruption report."""
    blocks, _ = derived_chain()
    graph, index = build_index(tmp, blocks, name="rwc_i")
    derived = os.path.join(tmp, "rwc_d")
    dv.run_build(index, derived)
    oi.run_rewind(index, graph, 4)

    real_ws = dv.GenStore.write_state
    fired = []

    def flaky_ws(self):
        real_ws(self)
        st = self.state
        if (st.get("rewind") is not None
                and "positional" in st["rewind"].get("done", ())):
            fired.append(1)
            raise RuntimeError("simulated kill before the truncations")

    dv.GenStore.write_state = flaky_ws
    try:
        dv.run_rewind(index, derived)
        fail("the simulated kill did not fire")
    except RuntimeError:
        pass
    finally:
        dv.GenStore.write_state = real_ws
    check(fired, "the kill fired in the wrong write")
    state = json.load(open(os.path.join(derived, dv.STATE_NAME)))
    fees_size = os.path.getsize(os.path.join(derived, "fees.bin"))
    check(fees_size > state["files"]["fees"]["records"] * dv.FEE_REC,
          "the kill must land with the files longer than the state")

    dv.run_rewind(index, derived)            # resume: heal and seal
    _, ref_index = build_index(tmp, blocks, name="rwc_ri", end=4)
    ref = os.path.join(tmp, "rwc_rd")
    dv.run_build(ref_index, ref)
    _same_derived(derived, ref, "rewind resumed over the kill")
    print("ok  rewind: a kill between the state write and the "
          "truncations resumes and equals the rebuild")


def test_seal_survives_a_kill_right_after_the_tmp_removal(tmp):
    """_phase_seal persists the zeroed out_sums counters BEFORE it
    removes the tmp file (the store's own state-first rule): a kill
    right after the removal leaves a state that claims no bytes of the
    file that is gone. Under the old order the stale claim made the
    next build refuse a perfectly sealed artifact as corrupted."""
    blocks, _ = derived_chain()
    _graph, index = build_index(tmp, blocks, name="sealc_i")
    derived = os.path.join(tmp, "sealc_d")

    real_remove = os.remove

    def flaky_remove(path):
        real_remove(path)
        if os.path.basename(path) == "out_sums.tmp.bin":
            raise RuntimeError("simulated kill right after the removal")

    os.remove = flaky_remove
    try:
        dv.run_build(index, derived)
        fail("the simulated kill did not fire")
    except RuntimeError:
        pass
    finally:
        os.remove = real_remove

    fp = dv.run_build(index, derived)        # resume: reseal, no refusal
    clean = os.path.join(tmp, "sealc_ref")
    dv.run_build(index, clean)
    check(fp == dv._load_manifest(clean)["fingerprint"],
          "the resumed seal must land on the clean build's fingerprint")
    print("ok  seal: a kill right after the tmp removal reseals on "
          "resume instead of refusing")


def test_rewind_refuses_a_matching_index(dbuilt):
    """The derivatives never choose their own coverage: with an index
    that still covers the same height there is nothing to come back
    from, and the order (index first, then these) is the message."""
    tmp, graph, index, derived, _, _ = dbuilt
    try:
        dv.run_rewind(index, derived)
        fail("the derivatives were rewound to the height they already "
             "cover")
    except dv.OutpointError as e:
        check("rewind the index first" in str(e),
              f"the refusal must name the order, said: {e}")
    print("ok  rewind: derivatives follow the index, and say so")


def interleaved_chain():
    """A chain whose LAST block spends an output older than the one
    already spent — the general shape of an append, and the one the
    fixture above does not have.

        h1  cb1 → out0            h3  cb3 → out2; t1 spends out1
        h2  cb2 → out1            h4  cb4 → out3; t2 spends out0

    Built to height 3, spends.bin holds one edge, on ordinal 1. Grown
    to height 4 it holds two, and the NEW one (ordinal 0) sorts FIRST:
    it lands ahead of the edge the previous cycle already consumed. A
    derivatives cursor that is a record offset into spends.bin reads
    the wrong record from here on; the cycle partition by spender is
    what survives it.
    """
    blocks, txids = {}, {}
    prev = bytes(32)

    def add(height, raw_txs, ids):
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_700_000_000 + height,
                                      0x1700_0000, height, raw_txs, ids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())

    cb1, cb1_id, _ = toi._coinbase(b"\x011", [tbw.w_output(S, SPK_A)])
    add(1, [cb1], [cb1_id])
    cb2, cb2_id, _ = toi._coinbase(b"\x012", [tbw.w_output(S, SPK_A)])
    add(2, [cb2], [cb2_id])

    cb3, cb3_id, _ = toi._coinbase(b"\x013", [tbw.w_output(S, SPK_A)])
    t1, t1_id, _ = tbw.w_tx(                       # spends out1 (cb2:0)
        1, [tbw.w_input(cb2_id, 0, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(7, SPK_B)], 0)
    add(3, [cb3, t1], [cb3_id, t1_id])

    cb4, cb4_id, _ = toi._coinbase(b"\x014", [tbw.w_output(S, SPK_A)])
    t2, t2_id, _ = tbw.w_tx(                       # spends out0 (cb1:0)
        1, [tbw.w_input(cb1_id, 0, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(6, SPK_B)], 0)
    add(4, [cb4, t2], [cb4_id, t2_id])
    txids.update(cb1=cb1_id, cb2=cb2_id, t1=t1_id, t2=t2_id)
    return blocks, txids


def test_append_with_interleaved_spend(tmp):
    """Append == rebuild when the new edge lands in the MIDDLE of the
    re-sorted spends.bin, which on a real chain is the normal case:
    almost every block spends outputs older than the highest one
    already spent."""
    blocks, _txids = interleaved_chain()
    graph, index = build_index(tmp, blocks, name="index_mid", end=3)
    derived = os.path.join(tmp, "derived_mid")
    dv.run_build(index, derived)

    oi.run_build(graph, index)               # index grows to height 4
    dv.run_build(index, derived)             # append
    _, got_a = read_derived_files(derived)

    fresh = os.path.join(tmp, "derived_mid_fresh")
    dv.run_build(index, fresh)
    _, got_b = read_derived_files(fresh)
    for name in dv.FP_ORDER:
        check(got_a[name] == got_b[name],
              f"{name}: appending an interleaved spend produced "
              f"different bytes than a rebuild\n got  {got_a[name].hex()}"
              f"\n want {got_b[name].hex()}")
    dv.run_verify(derived)
    print("ok  append: an edge inserted BELOW an already-spent ordinal "
          "still lands on the rebuild's bytes")


def test_crash_resume(tmp):
    """Kill the scan after a checkpoint, run build again: the cursors
    resume mid-file and the sealed bytes match a clean build."""
    blocks, _txids = derived_chain()
    _graph, index = build_index(tmp, blocks, name="index_crash")
    clean = os.path.join(tmp, "derived_clean")
    dv.run_build(index, clean)

    # The seam is the record reader this module uses to walk the SOURCE
    # index (`_index_stream`): cutting outputs.bin short mid-file is a
    # crash exactly where the scan cursors are supposed to save us.
    real = dv.read_fixed

    def flaky(path, rec, expect_sha=None, slab_bytes=oi.IO_CHUNK,
              start_record=0, error=RuntimeError):
        gen = real(path, rec, expect_sha=expect_sha,
                   slab_bytes=slab_bytes, start_record=start_record,
                   error=error)
        if (os.path.basename(path) == "outputs.bin"
                and rec == oi.OUT_REC and start_record == 0):
            def limited():
                for i, r in enumerate(gen):
                    if i >= 5:
                        raise RuntimeError("simulated crash")
                    yield r
            return limited()
        return gen

    crashed = os.path.join(tmp, "derived_crash")
    dv.read_fixed = flaky
    try:
        dv.run_build(index, crashed, flush_records=2,
                     checkpoint_every=2)
        fail("the simulated crash did not fire")
    except RuntimeError:
        pass
    finally:
        dv.read_fixed = real
    state = json.load(open(os.path.join(crashed, dv.STATE_NAME)))
    check(0 < state["out_pos"] < 10,
          "the crash must land between checkpoints, not at the ends")
    dv.run_build(index, crashed)             # resume
    _, got_a = read_derived_files(clean)
    _, got_b = read_derived_files(crashed)
    for name in dv.FP_ORDER:
        check(got_a[name] == got_b[name],
              f"{name}: resumed build differs from clean build")
    print("ok  crash: a build killed mid-scan resumes from its "
          "cursors and lands on the same bytes")



# ---------------------------------------------------------------------------
# The readable predecessor: sealed v2 derivatives must stay readable
# ---------------------------------------------------------------------------

def make_v2_derived(src, dst, index_fp):
    """A genuine outpoint-derived-v2 artifact, projected from a v3 one:
    satoshi fields widened back from u56 to u64 in `history` and
    `fees`, ladders resampled, the v2 tag resealed. `tx_inputs` holds
    no value and is copied as is.

    Written against the v2 format text, not by calling code that still
    exists — the point is that the reader meets an artifact it did not
    produce."""
    import shutil
    from nodsig.artifact import (make_identity, seal_manifest,
                                 sha_and_ladder)
    shutil.copytree(src, dst)
    manifest = json.load(open(os.path.join(dst, dv.MANIFEST_NAME)))
    build = manifest["build"]

    def widen(blob, rec, val_at):
        out = bytearray()
        for i in range(0, len(blob), rec):
            r = blob[i:i + rec]
            out += r[:val_at] + int.from_bytes(r[val_at:], "big").to_bytes(8, "big")
        return bytes(out)

    for logical, rec, val_at, spec in (
            ("history", dv.HIST_REC, dv.HIST_VAL,
             (20 + 5 + 5 + 8, dv.HIST_KEY, dv.HIST_EVERY)),
            ("fees", dv.FEE_REC, 0, None)):
        entry = build["files"][logical]
        path = os.path.join(dst, entry["file"])
        with open(path, "rb") as f:
            blob = f.read()
        wide = widen(blob, rec, val_at)
        with open(path, "wb") as f:
            f.write(wide)
        if spec is None:                       # fees: positional, no ladder
            entry["sha256"] = hashlib.sha256(wide).hexdigest()
            continue
        sha, ladder = sha_and_ladder(path, *spec, dv.OutpointError)
        entry["sha256"] = sha
        cache = build["caches"][logical]
        with open(os.path.join(dst, cache["file"]), "wb") as f:
            f.write(ladder)
        cache["sha256"] = hashlib.sha256(ladder).hexdigest()

    build["parent"] = dict(build["parent"], fingerprint=index_fp)
    identity = make_identity(
        "outpoint-derived-v2", 1, manifest["identity"]["coverage"]["to"],
        ((n, build["files"][n]["sha256"]) for n in dv.FP_ORDER))
    with open(os.path.join(dst, dv.MANIFEST_NAME), "w") as f:
        json.dump(seal_manifest("outpoint-derived-v2", identity, build), f)

    spath = os.path.join(dst, dv.STATE_NAME)
    state = json.load(open(spath))
    state["format"] = "outpoint-derived-v2"
    state["files"] = dict(build["files"])
    state["caches"] = dict(build["caches"])
    with open(spath, "w") as f:
        json.dump(state, f)
    return dst


def test_a_v2_pair_is_still_readable(dbuilt):
    """A v2 index and the v2 derivatives built on it: the pair a
    stranger downloaded under 1.0.0 or 1.1.0. It must still answer."""
    tmp, _graph, index, derived, _txids, locks = dbuilt
    v2i = toi.make_v2_index(index, os.path.join(tmp, "v2_index"))
    ifp = json.load(open(os.path.join(v2i, oi.MANIFEST_NAME)))["fingerprint"]
    v2d = make_v2_derived(derived, os.path.join(tmp, "v2_derived"), ifp)

    idx = oi.Index(v2i)
    d = dv.Derived(v2d, idx)
    try:
        check(d.format == "outpoint-derived-v2",
              "the reader must see the artifact for what it is")
        check(d.val == 8, "v2 satoshis are u64, and the reader must know")
        want = {lock: [(o, sp, v) for o, sp, v in HIST_ROWS[name]]
                for name, lock in locks.items()}
        for name, lock in locks.items():
            got = [(o, sp or 0, v) for o, sp, v in d.rows(lock)]
            check(got == want[lock],
                  f"{name}: v2 history rows must read identically: "
                  f"{got} vs {want[lock]}")
        for t, f in enumerate(FEES):
            check(d.fee(t) == f,
                  f"v2 fee of tx {t} must read as {f}, got {d.fee(t)}")
    finally:
        d.close()
        idx.close()
    dv.run_verify(v2d)
    # And with the parent, which is the line the real artifacts ran and
    # this test did not: confirming a v2 derived artifact against the v2
    # index it declares. It was strict, and refused at the door.
    dv.run_verify(v2d, v2i)
    print("ok  a sealed v2 pair still reads, verifies, and confirms its "
          "own ancestry")


def test_building_on_v2_derivatives_refuses_loudly(dbuilt):
    """Reading widens, building does not: extending a v2 directory
    would fuse 38-byte rows into a 37-byte file."""
    tmp, _graph, index, derived, _txids, _locks = dbuilt
    v2i = toi.make_v2_index(index, os.path.join(tmp, "v2_index_b"))
    ifp = json.load(open(os.path.join(v2i, oi.MANIFEST_NAME)))["fingerprint"]
    v2d = make_v2_derived(derived, os.path.join(tmp, "v2_derived_b"), ifp)
    try:
        dv.run_build(index, v2d)
    except dv.OutpointError as e:
        check("outpoint-derived-v2" in str(e) or "one byte narrower" in str(e),
              f"the refusal must name what and why: {e}")
        print("ok  a build refuses v2 derivatives, and says why")
        return
    fail("building onto v2 derivatives must refuse")


# The frozen outpoint-derived-v3 fingerprint of the synthetic chain — an
# absolute anchor beyond run-to-run determinism. Update deliberately if the
# format or the fixture chain changes.
#
# Moved once, on purpose: v3 narrowed satoshi fields from u64 to u56, so
# history and fees records changed width and every fingerprint with them.
# The v2 value was
# 8e581e76d8584286b686434045eac233f0d15be471b6ba82ca80647e8bc79b65;
# it stays written here rather than deleted, because "the golden value
# moved" is only a safe sentence when the old one is still readable.
GOLDEN_DERIVED_FINGERPRINT = \
    "0eaf00a8d78210a82920b37c169ee84d3a22921422805ea0982dbd54598c0504"


def test_golden_fingerprint(dbuilt):
    _tmp, _graph, _index, derived, _txids, _locks = dbuilt
    manifest = json.load(open(os.path.join(derived, dv.MANIFEST_NAME)))
    check(manifest["fingerprint"] == GOLDEN_DERIVED_FINGERPRINT,
          "outpoint-derived-v3 fingerprint drifted from the frozen value: "
          f"{manifest['fingerprint']}")
    print("ok  golden: the synthetic derivatives fingerprint is unchanged")


def test_refuses_degraded_index(tmp):
    graph = toi.emit_graph(tmp, trs.build_chain(), name="reuse_graph")
    index = os.path.join(tmp, "index_tolerant")
    oi.run_build(graph, index, tolerate_unresolved=True)
    try:
        dv.run_build(index, os.path.join(tmp, "derived_bad"))
        fail("derivatives were built on a degraded index")
    except oi.OutpointError:
        print("ok  guard: a tolerated-unresolved index is refused")


def test_reader(dbuilt):
    _tmp, _graph, index_dir, derived_dir, _txids, locks = dbuilt
    index = oi.Index(index_dir)
    derived = dv.Derived(derived_dir, index)
    try:
        check(list(derived.rows(locks["B"])) == [(2, 6, 7), (7, 8, 6)],
              "lock B's rows wrong")
        check(derived.balance(locks["A"]) == (4, 4 * S + 0),
              "lock A's balance must be its 4 unspent coinbases")
        check(derived.balance(locks["C"]) == (1, 5),
              "lock C's balance wrong")
        check(derived.fee(2) == S - 10 and derived.fee(8) == 3,
              "fees wrong")
        check(derived.inputs_of(8) == [5, 7],
              "t4 must have spent ordinals 5 and 7")
        check(derived.inputs_of(0) == [], "a coinbase spends nothing")
        check(list(derived.rows(b"\xEE" * 20)) == [],
              "an unknown lock has no rows")
    finally:
        derived.close()
        index.close()
    print("ok  reader: rows/balance/fee/inputs_of all answer "
          "correctly")


def test_cli_windows(dbuilt):
    _tmp, _graph, index, derived, txids, locks = dbuilt

    buf = io.StringIO()
    dv.run_history(derived, index, locks["A"], out=buf)
    text = buf.getvalue()
    check(text.count("IN   +") == 6 and text.count("OUT  -") == 2,
          "lock A must show 6 receives and 2 spends")
    check("balance 200.00000000" in text,
          "lock A's balance line wrong")
    buf = io.StringIO()
    dv.run_history(derived, index, locks["A"], limit=3, out=buf)
    check("omitted" in buf.getvalue(), "--limit must say what it hid")
    buf = io.StringIO()
    dv.run_history(derived, index, b"\xEE" * 20, out=buf)
    check("never seen" in buf.getvalue(),
          "an unknown lock must be an honest absence")

    buf = io.StringIO()
    dv.run_fee(derived, index,
               [txids["t1"][::-1].hex(), txids["cbA"][::-1].hex(),
                txids["t4"][::-1].hex(), "ff" * 32], out=buf)
    text = buf.getvalue()
    check("fee 4,999,999,990 sat" in text, "t1's fee wrong")
    check("coinbase" in text, "cbA must be reported as coinbase")
    check("fee 3 sat" in text, "t4's fee wrong")
    check("NOT in confirmed history" in text,
          "unknown txid must be an honest absence")

    buf = io.StringIO()
    dv.run_cospends(derived, index, txids["t4"][::-1].hex(), out=buf)
    text = buf.getvalue()
    check("spends 2 output(s) together" in text, "co-spend count wrong")
    check(locks["A"].hex() in text and locks["B"].hex() in text,
          "the two co-spent locks must both be shown")
    check("HINT" in text, "the Q2 caveat must be stated")
    buf = io.StringIO()
    dv.run_cospends(derived, index, txids["t2"][::-1].hex() + ":0",
                    out=buf)
    check("spends 2 output(s) together" in buf.getvalue(),
          "outpoint mode must reach the same spender")
    buf = io.StringIO()
    dv.run_cospends(derived, index, txids["cbD"][::-1].hex() + ":0",
                    out=buf)
    check("UNSPENT" in buf.getvalue(),
          "an unspent outpoint has no co-spends, honestly")
    print("ok  windows: history, fee and cospends tell true stories "
          "with their caveats")


def test_verify_catches_corruption(dbuilt):
    tmp, _graph, index, _derived, _txids, _locks = dbuilt
    victim = os.path.join(tmp, "derived_victim")
    dv.run_build(index, victim)
    manifest = json.load(open(os.path.join(victim, dv.MANIFEST_NAME)))
    path = os.path.join(victim, manifest["build"]["files"]["history"]["file"])
    data = bytearray(open(path, "rb").read())
    data[7] ^= 0xFF
    open(path, "wb").write(data)
    try:
        dv.run_verify(victim)
        fail("verify missed a flipped byte in history.bin")
    except oi.OutpointError:
        pass
    data[7] ^= 0xFF
    open(path, "wb").write(data)
    lad = os.path.join(victim, "tx_inputs.lad")
    ldata = bytearray(open(lad, "rb").read())
    ldata[0] ^= 0xFF
    open(lad, "wb").write(ldata)
    try:
        dv.run_verify(victim)
        fail("verify missed a flipped byte in a ladder")
    except oi.OutpointError:
        print("ok  verify: flipped bytes in data and caches are "
              "caught")


def test_verify_confirms_the_parent_it_was_handed(dbuilt):
    """With --index the audit compares the declared parent against the
    index it was given, so the report must SAY confirmed: an audit that
    checks a claim and then prints 'not confirmed (pass --index to
    confront it)' contradicts itself and teaches the operator to
    distrust either the tool or the parent. Without the flag the
    declaration stays a declaration, and a wrong index is refused."""
    tmp, _graph, index, derived, _txids, _locks = dbuilt

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        dv.run_verify(derived, index)
    text = out.getvalue()
    check("ok  parent" in text,
          f"a confronted parent must be reported ok, got:\n{text}")
    check("not confirmed" not in text,
          f"a confronted parent still reported unconfirmed:\n{text}")

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        dv.run_verify(derived)
    check("not confirmed" in out.getvalue() and "--index" in out.getvalue(),
          "without the index the declaration must stay declared, with "
          "the flag named")

    stranger = os.path.join(tmp, "index_stranger")
    build_index(tmp, derived_chain()[0], name="index_stranger", end=3)
    try:
        dv.run_verify(derived, stranger)
        fail("verify confirmed a parent against a stranger index")
    except oi.OutpointError as e:
        check("not this artifact's parent" in str(e),
              f"stranger index refused as: {e}")
    print("ok  verify: the parent is confirmed when confronted, "
          "declared when not, refused when wrong")


def test_verify_catches_a_wrong_ladder(dbuilt):
    """The same audit the index gets: a ladder that is intact but
    indexes the wrong rows must be caught, here for the fused history
    and for the tx_inputs ladder built by hand at seal."""
    tmp, _graph, index, _derived, _txids, _locks = dbuilt
    planted = 0
    for logical in dv.LADDERS:
        victim = os.path.join(tmp, f"derived_lad_{logical}")
        dv.run_build(index, victim)
        dv.run_verify(victim)                  # pristine: must pass
        if not toi.plant_wrong_ladder(victim, dv.MANIFEST_NAME, logical,
                                      dv.LADDERS[logical]):
            continue                           # too few records to shift
        planted += 1
        try:
            dv.run_verify(victim)
            fail(f"verify accepted a wrong {logical} ladder")
        except oi.OutpointError as e:
            check("not the ladder" in str(e),
                  f"{logical}: wrong diagnosis for a wrong ladder: {e}")
    check(planted, "no ladder was long enough to plant a wrong one")
    print(f"ok  verify: a wrong ladder is caught ({planted} rebuilt "
          "from their files)")


# ---------------------------------------------------------------------------
# Standalone runner (pytest uses the same functions via fixtures)
# ---------------------------------------------------------------------------

def main():
    with tempfile.TemporaryDirectory() as tmp:
        graph, index, derived, txids, locks = \
            test_build_matches_model(tmp)
        sextet = (tmp, graph, index, derived, txids, locks)
        test_determinism_tiny(sextet)
        test_append_equals_rebuild(tmp)
        test_append_with_interleaved_spend(tmp)
        test_append_equals_rebuild_through_the_gallop(tmp)
        test_rewind_equals_rebuild(tmp)
        test_rewind_with_interleaved_spend(tmp)
        test_rewind_survives_a_kill_before_the_truncations(tmp)
        test_seal_survives_a_kill_right_after_the_tmp_removal(tmp)
        test_rewind_refuses_a_matching_index(sextet)
        test_crash_resume(tmp)
        test_refuses_degraded_index(tmp)
        test_reader(sextet)
        test_cli_windows(sextet)
        test_golden_fingerprint(sextet)
        test_verify_catches_corruption(sextet)
        test_verify_confirms_the_parent_it_was_handed(sextet)
        test_verify_catches_a_wrong_ladder(sextet)
    print("PASS: the three derivatives equal the independently "
          "derived model byte for byte, append and resume "
          "deterministically, and their windows tell true stories.")


if __name__ == "__main__":
    main()
