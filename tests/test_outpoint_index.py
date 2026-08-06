#!/usr/bin/env python3
"""
test_outpoint_index.py — self-test for outpoint_index.py. No node, no
real data: a purpose-built synthetic chain whose spends reference REAL
earlier outputs (unlike the shared reuse chain, whose fake prevouts
exist precisely to test the other tools) is emitted into a real
graph-v2 archive, the index is built through the real five phases, and
every file is checked byte for byte against a model computed
INDEPENDENTLY from the writers' txids — two roads meet, as everywhere.

The chain also stages the two historical edge cases on purpose:

- a BIP30 duplicate (the height-4 coinbase repeats the height-1
  coinbase byte for byte, hence the same txid): the resolver must
  keep the LATER instance and count 1 overwritten txid, while the
  positional files keep both honestly;
- a same-block spend (t1 spends the height-2 coinbase inside
  height 2): the join must resolve it like any other.

On top of the byte-exact build:
- determinism: a build forced through many tiny runs is byte-identical
  to the default build, fingerprint included;
- append == rebuild: build to height 2, then extend to 4 — same bytes,
  same fingerprint as the one-shot build to 4;
- the resolve join fails loudly on unknown prevouts (the shared reuse
  chain triggers it) and only --tolerate-unresolved turns that into a
  counted statistic; a vout past the tx's output count always fails;
- lookup tells the whole story (created/value/lock/spent, same-block
  spend, BIP30 winner, honest absences);
- verify catches a flipped byte in data files and ladders, and a ladder
  that is intact but samples the wrong rows.

Usage:
    python3 test_outpoint_index.py     # prints PASS or fails loudly
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

from nodsig import outpoint_index as oi
from nodsig import reveal_archive as ra
import test_blockparse as tbw
import test_reuse_scan as trs
from nodsig.hashing import hash160
from nodsig.reuse_scan import SAT


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


# ---------------------------------------------------------------------------
# The synthetic chain of this suite: real prevouts, one BIP30 twin
# ---------------------------------------------------------------------------

SPK_A = tbw.P2PKH_SPK                                  # a P2PKH lock
SPK_B = bytes([0x00, 0x14]) + b"\xBB" * 20             # a P2WPKH lock
SPK_C = bytes([0x51])                                  # anyone-can-spend


def _coinbase(tag, outputs):
    return tbw.w_tx(1, [tbw.w_input(bytes(32), 0xFFFFFFFF, tag,
                                    0xFFFFFFFF)], outputs, 0)


def index_chain():
    """height → (hash_display_hex, raw_hex), plus the txids the model
    needs. Four legacy blocks:

        h1  cbA  (50 BTC to A)          ← duplicated at h4 (BIP30)
        h2  cbB; t1 spends cbB:0 SAME BLOCK → 7 sat to B, 3 sat to C
        h3  cbC; t2 spends t1:1            → 2 sat to A
        h4  cbA AGAIN (same bytes, same txid); t3 spends t1:0
                                           → 6 sat to B
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

    cbA, cbA_id, _ = _coinbase(b"\x01A", [tbw.w_output(50 * SAT, SPK_A)])
    add(1, [cbA], [cbA_id])
    txids["cbA"] = cbA_id

    cbB, cbB_id, _ = _coinbase(b"\x01B", [tbw.w_output(50 * SAT, SPK_A)])
    t1, t1_id, _ = tbw.w_tx(
        1, [tbw.w_input(cbB_id, 0, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(7, SPK_B), tbw.w_output(3, SPK_C)], 0)
    add(2, [cbB, t1], [cbB_id, t1_id])
    txids["cbB"], txids["t1"] = cbB_id, t1_id

    cbC, cbC_id, _ = _coinbase(b"\x01C", [tbw.w_output(50 * SAT, SPK_A)])
    t2, t2_id, _ = tbw.w_tx(
        1, [tbw.w_input(t1_id, 1, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(2, SPK_A)], 0)
    add(3, [cbC, t2], [cbC_id, t2_id])
    txids["cbC"], txids["t2"] = cbC_id, t2_id

    t3, t3_id, _ = tbw.w_tx(
        1, [tbw.w_input(t1_id, 0, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(6, SPK_B)], 0)
    add(4, [cbA, t3], [cbA_id, t3_id])       # cbA verbatim: BIP30 twin
    txids["t3"] = t3_id
    return blocks, txids


def emit_graph(tmp, blocks, name="index_graph"):
    """The chain through the real host path (reveal_archive's --graph
    plug), like the other suites do."""
    graph = os.path.join(tmp, name)
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", max(blocks),
                    os.path.join(tmp, name + "_host"),
                    batch_size=2, checkpoint_every=2, graph_dir=graph)
    finally:
        server.shutdown()
    return graph


# ---------------------------------------------------------------------------
# The independent model: every file's exact bytes, from the txids alone
# ---------------------------------------------------------------------------

def expected_files(txids):
    """The chain above, re-derived by hand: tx ordinals 0..6 in chain
    order (cbA cbB t1 cbC t2 cbA' t3), output ordinals 0..7. This is
    the whole format restated independently — if the module and this
    model agree byte for byte, both read the format the same way."""
    order = ["cbA", "cbB", "t1", "cbC", "t2", "cbA", "t3"]
    outs = {          # tx → [(value, spk)]
        "cbA": [(50 * SAT, SPK_A)], "cbB": [(50 * SAT, SPK_A)],
        "t1": [(7, SPK_B), (3, SPK_C)], "cbC": [(50 * SAT, SPK_A)],
        "t2": [(2, SPK_A)], "t3": [(6, SPK_B)],
    }
    per_block = {1: ["cbA"], 2: ["cbB", "t1"], 3: ["cbC", "t2"],
                 4: ["cbA", "t3"]}

    first_out = []
    n = 0
    for name in order:
        first_out.append(n)
        n += len(outs[name])

    blocks = b""
    tx_i = out_i = 0
    for h in (1, 2, 3, 4):
        blocks += (tx_i.to_bytes(5, "big") + out_i.to_bytes(5, "big")
                   + (1_700_000_000 + h).to_bytes(4, "big"))
        for name in per_block[h]:
            tx_i += 1
            out_i += len(outs[name])

    txids_bin = b"".join(txids[name] for name in order)
    tfo = b"".join(fo.to_bytes(5, "big") for fo in first_out)
    outputs = b"".join(v.to_bytes(8, "big") + hash160(spk)
                       for name in order for v, spk in outs[name])

    # Resolver: unique txids sorted as bytes; the BIP30 twin keeps the
    # LATER instance (tx ordinal 5, first_out 6).
    entries = {}
    for i, name in enumerate(order):
        entries[txids[name]] = (first_out[i], len(outs[name]))
    resolver = b"".join(
        txid + fo.to_bytes(5, "big") + no.to_bytes(3, "big")
        for txid, (fo, no) in sorted(entries.items()))

    # Spends: t1 spends cbB:0 (out 1, spender 2); t2 spends t1:1
    # (out 3, spender 4); t3 spends t1:0 (out 2, spender 6).
    spends = b"".join(
        so.to_bytes(5, "big") + sp.to_bytes(5, "big")
        for so, sp in sorted([(1, 2), (3, 4), (2, 6)]))

    return {"blocks": blocks, "txids": txids_bin, "tx_first_out": tfo,
            "outputs": outputs, "txid_index": resolver,
            "spends": spends}


def plant_wrong_ladder(directory, manifest_name, logical, spec):
    """Replace a ladder with a COHERENT wrong one and re-declare it in
    the manifest, so every intactness check still passes.

    Not a flipped byte: a ladder built by the right machinery from the
    right file, anchored a few records off. That is the failure mode
    that used to slip through — the seal hashed the samples it had just
    made, so the manifest agreed with the mistake — and it surfaces only
    as a lookup that lands in the wrong bucket and answers short.

    The shift walks forward until the samples actually differ: keys
    repeat (history rows share a lock), so the first offset is not
    always a visible mistake. Returns False when NO offset changes a
    byte — then every ladder over that file is the same ladder, and
    there is nothing to catch. The derivatives' suite uses this too."""
    rec, key_len, every = spec
    man_path = os.path.join(directory, manifest_name)
    manifest = json.load(open(man_path))
    with open(os.path.join(directory,
                           manifest["build"]["files"][logical]["file"]), "rb") as f:
        data = f.read()
    rows = len(data) // rec
    lad_path = os.path.join(directory, manifest["build"]["caches"][logical]["file"])
    with open(lad_path, "rb") as f:
        right = f.read()
    for shift in range(1, max(rows, 1)):
        wrong = b"".join(data[i * rec:i * rec + key_len]
                         for i in range(shift, rows, every))
        if wrong != right:
            break
    else:
        return False
    with open(lad_path, "wb") as f:
        f.write(wrong)
    manifest["build"]["caches"][logical]["sha256"] = hashlib.sha256(wrong).hexdigest()
    with open(man_path, "w") as f:
        json.dump(manifest, f)
    return True


def read_index_files(index_dir):
    manifest = json.load(open(os.path.join(index_dir,
                                           oi.MANIFEST_NAME)))
    got = {}
    for name, entry in manifest["build"]["files"].items():
        with open(os.path.join(index_dir, entry["file"]), "rb") as f:
            got[name] = f.read()
    return manifest, got


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def built(tmp):
    """The (tmp, graph, index, txids) quartet the dependent tests
    share — under pytest this fixture builds it; the standalone main()
    passes the same tuple by hand, like the other suites do."""
    blocks, txids = index_chain()
    graph = emit_graph(tmp, blocks)
    index = os.path.join(tmp, "index")
    oi.run_build(graph, index)
    return tmp, graph, index, txids


def test_build_matches_model(tmp):
    blocks, txids = index_chain()
    graph = emit_graph(tmp, blocks)
    index = os.path.join(tmp, "index")
    oi.run_build(graph, index)
    manifest, got = read_index_files(index)
    want = expected_files(txids)
    for name in oi.FP_ORDER:
        check(got[name] == want[name],
              f"{name}: bytes differ from the independent model\n"
              f" got  {got[name].hex()}\n want {want[name].hex()}")
    check(manifest["identity"]["coverage"]["to"] == 4, "watermark wrong")
    check(manifest["build"]["transactions"] == 7, "tx count wrong")
    check(manifest["build"]["outputs"] == 8, "output count wrong")
    check(manifest["build"]["spends"] == 3, "spend count wrong")
    t = manifest["build"]["totals"]
    check(t["overwritten_txids"] == 1,
          "the BIP30 twin must count exactly 1 overwritten txid")
    check(t["duplicate_spends"] == 0 and t["unresolved_spends"] == 0,
          "clean chain must have no duplicate/unresolved spends")
    check(manifest["build"]["parent"] is None,
          "unsealed graph must be recorded as unknown source")
    print("ok  build: all six files byte-equal the independent model, "
          "BIP30 twin counted")
    return graph, index, txids


def test_determinism_multirun(built):
    """Tiny flush + checkpoint every block → many runs per category;
    the fused result must not remember the buffering."""
    tmp, graph, index, _ = built
    tiny = os.path.join(tmp, "index_tiny")
    oi.run_build(graph, tiny, flush_records=1, checkpoint_every=1)
    _, got_a = read_index_files(index)
    _, got_b = read_index_files(tiny)
    for name in oi.FP_ORDER:
        check(got_a[name] == got_b[name],
              f"{name}: multi-run build differs from default build")
    fa = json.load(open(os.path.join(index, oi.MANIFEST_NAME)))
    fb = json.load(open(os.path.join(tiny, oi.MANIFEST_NAME)))
    check(fa["fingerprint"] == fb["fingerprint"],
          "fingerprints differ across buffering choices")
    print("ok  determinism: run boundaries leave no trace in the bytes")


def test_append_equals_rebuild(built):
    tmp, graph, index, _ = built
    grown = os.path.join(tmp, "index_grown")
    oi.run_build(graph, grown, end_height=2)
    mid = json.load(open(os.path.join(grown, oi.MANIFEST_NAME)))
    check(mid["identity"]["coverage"]["to"] == 2, "partial build wrong")
    check(mid["build"]["spends"] == 1, "partial build must hold only t1's spend")
    oi.run_build(graph, grown)               # extend 3..4 = append
    _, got_a = read_index_files(index)
    _, got_b = read_index_files(grown)
    for name in oi.FP_ORDER:
        check(got_a[name] == got_b[name],
              f"{name}: append produced different bytes than rebuild")
    print("ok  append: growing 1..2 then 3..4 equals building 1..4")


def _same_index(a, b, what):
    """Two index directories hold the same artifact: every file in the
    fingerprint order byte for byte, the fingerprint, and the manifest
    facts a reader acts on."""
    ma, got_a = read_index_files(a)
    mb, got_b = read_index_files(b)
    for name in oi.FP_ORDER:
        check(got_a[name] == got_b[name],
              f"{what}: {name} differs from the rebuild")
    check(ma["fingerprint"] == mb["fingerprint"],
          f"{what}: same bytes but a different fingerprint")
    check(ma["identity"] == mb["identity"],
          f"{what}: same bytes but a different identity")
    for key in ("last_block_hash", "transactions", "outputs", "spends",
                "totals"):
        check(ma["build"][key] == mb["build"][key],
              f"{what}: manifest {key} is {ma['build'][key]!r}, "
              f"the rebuild says {mb['build'][key]!r}")


def test_rewind_equals_rebuild(built):
    """rewind ≡ rebuild, the mirror of append ≡ rebuild.

    Heights 1..3 hold no duplicate txid, so this is the clean cut; the
    duplicate at h4 is the next test's business."""
    tmp, graph, _, _ = built
    back = os.path.join(tmp, "index_back")
    oi.run_build(graph, back, end_height=3)
    oi.run_rewind(back, graph, 2)
    ref = os.path.join(tmp, "index_ref_2")
    oi.run_build(graph, ref, end_height=2)
    _same_index(back, ref, "rewind 3→2")
    print("ok  rewind: coming back from 3 to 2 equals building to 2")


def test_rewind_refuses_bip30_straddle(built):
    """The one case a rewind cannot serve, and the only one where it
    could be WRONG instead of merely refused: cbA is at h1 and again at
    h4, and the resolver kept only the later record. Cutting between
    them would make the txid vanish, where a rebuild still holds it."""
    tmp, graph, index, _ = built
    before = json.load(open(os.path.join(index, oi.MANIFEST_NAME)))
    try:
        oi.run_rewind(index, graph, 3)
        fail("a rewind across a collapsed duplicate txid was allowed")
    except oi.OutpointError as e:
        check("BIP30" in str(e),
              f"the refusal must say why, said: {e}")
    after = json.load(open(os.path.join(index, oi.MANIFEST_NAME)))
    check(before == after,
          "a refused rewind still changed the index: the plan must "
          "refuse before a byte moves")
    print("ok  rewind: refuses to cut between two instances of one "
          "txid, and refuses before touching anything")


def test_rewind_survives_a_kill_before_the_truncations(built):
    """The positional step commits the shrunken sizes FIRST and
    truncates after: a kill between the two leaves the files LONGER
    than the state says, the one direction the next load heals. The
    old order turned the same kill into a false 'tampered with or
    lost data' refusal on an artifact that was whole."""
    from nodsig.genstore import GenStore
    tmp, graph, _, _ = built
    idx = os.path.join(tmp, "index_kill")
    oi.run_build(graph, idx, end_height=3)

    real_ws = GenStore.write_state
    fired = []

    def flaky_ws(self):
        real_ws(self)
        st = self.state
        if (st.get("rewind") is not None
                and "positional" in st["rewind"].get("done", ())):
            fired.append(1)
            raise RuntimeError("simulated kill before the truncations")

    GenStore.write_state = flaky_ws
    try:
        oi.run_rewind(idx, graph, 2)
        fail("the simulated kill did not fire")
    except RuntimeError:
        pass
    finally:
        GenStore.write_state = real_ws
    check(fired, "the kill fired in the wrong write")
    state = oi._load_state(idx)
    blocks_size = os.path.getsize(os.path.join(idx, "blocks.bin"))
    check(blocks_size > state["sizes"]["blocks"],
          "the kill must land with the files longer than the state")

    oi.run_rewind(idx, graph, 2)                 # resume: heal and seal
    ref = os.path.join(tmp, "index_ref_kill")
    oi.run_build(graph, ref, end_height=2)
    _same_index(idx, ref, "rewind resumed over the kill")
    print("ok  rewind: a kill between the state write and the "
          "truncations resumes and equals the rebuild")


def test_straddle_guard_walks_the_same_two_roads(tmp):
    """The BIP30 guard has two roads — the collisions the fusion
    recorded in the state, and the pass over txids.bin for an index
    sealed before they were kept — and they must give the same answer
    on the same cuts: refuse a pair split by the cut, allow a pair
    wholly on one side."""
    d = os.path.join(tmp, "guard")
    os.makedirs(d)
    A, B, C = b"\xaa" * 32, b"\xbb" * 32, b"\xcc" * 32

    def rec(txid, first_out):
        return txid + first_out.to_bytes(oi.ORD, "big") + b"\x00" * 3

    def write_txids(*txids):
        with open(os.path.join(d, "txids.bin"), "wb") as f:
            f.write(b"".join(txids))

    def state_with(records):
        totals = {"overwritten_txids": 1}
        if records is not None:
            totals["overwritten_txid_records"] = records
        return {"totals": totals}

    # A at ordinals 0 and 3 (first_outs 0 and 9): a cut between them
    # must refuse, on either road.
    write_txids(A, B, C, A)
    recorded = [(rec(A, 0) + rec(A, 9)).hex()]
    for state in (state_with(recorded), state_with(None)):
        try:
            oi._refuse_straddling_duplicate(d, state, 2, 5, 1)
            fail("a straddling duplicate passed the guard")
        except oi.OutpointError as e:
            check("BIP30" in str(e), f"wrong refusal: {e}")

    # The same pair wholly below the cut: nothing to refuse. The
    # recorded road reads only the state; the fallback reads the file,
    # which now holds the pair at ordinals 0 and 1.
    write_txids(A, A, B, C)
    recorded = [(rec(A, 0) + rec(A, 2)).hex()]
    oi._refuse_straddling_duplicate(d, state_with(recorded), 2, 5, 1)
    oi._refuse_straddling_duplicate(d, state_with(None), 2, 5, 1)
    print("ok  straddle guard: recorded collisions and the file pass "
          "agree, both ways")


def test_rewind_refuses_out_of_range(built):
    """A rewind only ever removes."""
    tmp, graph, index, _ = built
    for height in (4, 5, 0):
        try:
            oi.run_rewind(index, graph, height)
            fail(f"a rewind to height {height} was allowed on an index "
                 "covering 1..4")
        except oi.OutpointError:
            pass
    print("ok  rewind: only backwards, and only inside what is covered")


def test_rewind_resumes_after_a_crash(built):
    """The plan is written before a byte moves, so an interruption
    between the two fusions resumes instead of guessing — and a build
    refuses to extend an index left half-cut."""
    tmp, graph, _, _ = built
    idx = os.path.join(tmp, "index_crash")
    oi.run_build(graph, idx, end_height=3)
    state = oi._load_state(idx)
    oi._rewind_plan(idx, graph, state, oi._store(idx, state), 2)
    try:
        oi.run_build(graph, idx)
        fail("a build extended an index with an unfinished rewind")
    except oi.OutpointError:
        pass
    try:
        oi.run_rewind(idx, graph, 1)
        fail("an unfinished rewind accepted a different target height")
    except oi.OutpointError:
        pass
    oi.run_rewind(idx, graph, 2)                  # the interrupted one
    ref = os.path.join(tmp, "index_ref_crash")
    oi.run_build(graph, ref, end_height=2)
    _same_index(idx, ref, "resumed rewind")
    print("ok  rewind: an interrupted one blocks a build and finishes "
          "into the same bytes")


def test_unresolved_policy(tmp):
    """The shared reuse chain spends prevouts that never existed: the
    honest default is a loud stop; tolerance records the count."""
    graph = emit_graph(tmp, trs.build_chain(), name="reuse_graph")
    strict = os.path.join(tmp, "index_strict")
    try:
        oi.run_build(graph, strict)
        fail("a graph with unknown prevouts was indexed silently")
    except oi.OutpointError:
        pass
    tolerant = os.path.join(tmp, "index_tolerant")
    oi.run_build(graph, tolerant, tolerate_unresolved=True)
    manifest = json.load(open(os.path.join(tolerant, oi.MANIFEST_NAME)))
    check(manifest["build"]["totals"]["unresolved_spends"] == 5,
          "the reuse chain has exactly 5 fake prevouts")
    check(manifest["build"]["spends"] == 0, "no spend should have resolved")
    print("ok  join policy: unknown prevouts stop the build unless "
          "tolerated, and then they are counted")


def test_join_refuses_bad_vout():
    """A vout past the tx's output count is corruption, never data."""
    txid = b"\x11" * 32
    resolver = [txid + (0).to_bytes(5, "big") + (2).to_bytes(3, "big")]
    spends = [txid + (2).to_bytes(4, "big") + (9).to_bytes(5, "big")]
    totals = {"unresolved_spends": 0}
    try:
        list(oi.resolve_join(iter(spends), iter(resolver), True, totals))
        fail("a vout >= n_out was resolved")
    except oi.OutpointError:
        print("ok  join guard: vout past the output count fails loudly")


def test_lookup(built):
    _, _, index, txids = built
    buf = io.StringIO()
    ops = [txids["cbB"][::-1].hex() + ":0",     # spent same-block by t1
           txids["t1"][::-1].hex() + ":0",      # spent at h4 by t3
           txids["cbA"][::-1].hex() + ":0",     # BIP30: h4 wins, unspent
           txids["t1"][::-1].hex() + ":9",      # no such vout
           "ff" * 32 + ":0"]                    # unknown txid
    oi.run_lookup(index, ops, out=buf)
    text = buf.getvalue()
    check("height 2" in text and txids["t1"][::-1].hex() in text,
          "cbB:0 must be spent at height 2 by t1")
    check(txids["t3"][::-1].hex() in text,
          "t1:0 must be spent by t3")
    check("height 4" in text and "UNSPENT" in text,
          "cbA:0 must resolve to the height-4 twin, unspent")
    check("only 2 outputs" in text, "vout overflow must be reported")
    check("NOT in confirmed history" in text,
          "an unknown txid must be an honest absence")
    check("50.00000000 BTC" in text and "0.00000007 BTC" in text,
          "values must be printed from the index")
    print("ok  lookup: whole stories, same-block spend, BIP30 winner, "
          "honest absences")


def test_index_object(built):
    """The reuse point the address-check backends will call."""
    _, _, index, txids = built
    idx = oi.Index(index)
    try:
        first_out, n_out = idx.resolve(txids["t1"])
        check((first_out, n_out) == (2, 2), "t1 must own outputs 2..3")
        value, lock = idx.output(3)
        check(value == 3 and lock == hash160(SPK_C),
              "output ordinal 3 must be t1's 3-sat anyone-can-spend")
        check(idx.spenders(3) == [4], "output 3 must be spent by t2")
        check(idx.spenders(6) == [], "the BIP30 output must be unspent")
        check(idx.tx_of_output(3) == 2, "output 3 belongs to tx 2")
        check(idx.height_of_tx(6) == 4, "t3 sits at height 4")
        check(idx.height_of_output(5) == 3, "output 5 born at height 3")
        check(idx.txid_of(2) == txids["t1"], "catalog must return t1")
        check(idx.resolve(b"\xEE" * 32) is None,
              "unknown txid must resolve to None")
    finally:
        idx.close()
    print("ok  Index object: resolve/output/spenders/ordinal walks "
          "all answer correctly")


# The frozen outpoint-index-v2 fingerprint of the synthetic chain — an
# absolute anchor beyond run-to-run determinism. Update deliberately if the
# format or the fixture chain changes.
GOLDEN_INDEX_FINGERPRINT = \
    "9040d59c747256a7a9c012f5c4499f850aaf25de7e56ff5728c8f00931cab42d"


def test_golden_fingerprint(built):
    _tmp, _graph, index, _txids = built
    manifest = json.load(open(os.path.join(index, oi.MANIFEST_NAME)))
    check(manifest["fingerprint"] == GOLDEN_INDEX_FINGERPRINT,
          "outpoint-index-v2 fingerprint drifted from the frozen value: "
          f"{manifest['fingerprint']}")
    print("ok  golden: the synthetic index fingerprint is unchanged")


def test_verify_catches_corruption(built):
    tmp, graph, _, _ = built
    victim = os.path.join(tmp, "index_victim")
    oi.run_build(graph, victim)
    oi.run_verify(victim)                      # pristine: must pass
    manifest = json.load(open(os.path.join(victim, oi.MANIFEST_NAME)))
    path = os.path.join(victim, "outputs.bin")
    data = bytearray(open(path, "rb").read())
    data[10] ^= 0xFF
    open(path, "wb").write(data)
    try:
        oi.run_verify(victim)
        fail("verify missed a flipped byte in outputs.bin")
    except oi.OutpointError:
        pass
    data[10] ^= 0xFF                           # restore, corrupt ladder
    open(path, "wb").write(data)
    lad = os.path.join(victim,
                       manifest["build"]["caches"]["txid_index"]["file"])
    ldata = bytearray(open(lad, "rb").read())
    ldata[0] ^= 0xFF
    open(lad, "wb").write(ldata)
    try:
        oi.run_verify(victim)
        fail("verify missed a flipped byte in a ladder")
    except oi.OutpointError:
        print("ok  verify: flipped bytes in data and caches are caught")


def test_verify_catches_a_wrong_ladder(built):
    """Intact is not the same as right: every ladder must be rebuilt
    from the file it indexes, not merely compared with the digest the
    seal wrote for it."""
    tmp, graph, _, _ = built
    planted = 0
    for logical in oi.LADDERS:
        victim = os.path.join(tmp, f"index_lad_{logical}")
        oi.run_build(graph, victim)
        oi.run_verify(victim)                  # pristine: must pass
        if not plant_wrong_ladder(victim, oi.MANIFEST_NAME, logical,
                                  oi.LADDERS[logical]):
            continue                           # too few records to shift
        planted += 1
        try:
            oi.run_verify(victim)
            fail(f"verify accepted a wrong {logical} ladder")
        except oi.OutpointError as e:
            check("not the ladder" in str(e),
                  f"{logical}: wrong diagnosis for a wrong ladder: {e}")
    check(planted, "no ladder was long enough to plant a wrong one")
    print(f"ok  verify: a wrong ladder is caught ({planted} rebuilt "
          "from their files)")


def test_verify_refuses_a_restepped_ladder(built):
    """The step is part of the format: a manifest that declares another
    one describes a ladder this artifact cannot have, and a reader would
    bisect it with the wrong stride."""
    tmp, graph, _, _ = built
    victim = os.path.join(tmp, "index_step_victim")
    oi.run_build(graph, victim)
    man_path = os.path.join(victim, oi.MANIFEST_NAME)
    manifest = json.load(open(man_path))
    manifest["build"]["caches"]["txid_index"]["every"] *= 2
    with open(man_path, "w") as f:
        json.dump(manifest, f)
    try:
        oi.run_verify(victim)
        fail("verify accepted a ladder step the format does not fix")
    except oi.OutpointError as e:
        check("fixes it at" in str(e), f"wrong diagnosis: {e}")
    print("ok  verify: a re-declared ladder step is refused")


def test_verify_confirms_the_parent_it_was_handed(built):
    """The twin of derived verify's test, one level up the ancestry:
    with --graph the audit compares the declared parent against the
    graph it was given and the report must SAY confirmed; without the
    flag the declaration stays declared with the flag named; a stranger
    graph is refused; a graph whose manifest disagrees with its own
    identity block confirms nothing."""
    tmp, graph, _, _ = built
    from nodsig import graphemit as ge
    ge.run_fingerprint(graph)                      # seal the parent
    index = os.path.join(tmp, "index_with_parent")
    oi.run_build(graph, index)

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        oi.run_verify(index, graph_dir=graph)
    text = out.getvalue()
    check("ok  parent" in text,
          f"a confronted parent must be reported ok, got:\n{text}")
    check("not confirmed" not in text,
          f"a confronted parent still reported unconfirmed:\n{text}")

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        oi.run_verify(index)
    check("not confirmed" in out.getvalue()
          and "--graph" in out.getvalue(),
          "without the graph the declaration must stay declared, with "
          "the flag named")

    # A stranger: same chain, sealed on a shorter coverage, so its
    # fingerprint differs from the declared parent's.
    blocks, _ = index_chain()
    stranger = emit_graph(tmp, {h: blocks[h] for h in blocks if h <= 3},
                          name="index_graph_stranger")
    ge.run_fingerprint(stranger)
    try:
        oi.run_verify(index, graph_dir=stranger)
        fail("verify confirmed a parent against a stranger graph")
    except oi.OutpointError as e:
        check("not this index's parent" in str(e),
              f"stranger graph refused as: {e}")

    # A parent whose manifest no longer matches its own identity block
    # can confirm nothing, whatever fingerprint string it carries.
    man_path = os.path.join(graph, ge.MANIFEST_NAME)
    manifest = json.load(open(man_path))
    manifest["identity"]["coverage"]["to"] += 1
    with open(man_path, "w") as f:
        json.dump(manifest, f)
    try:
        oi.run_verify(index, graph_dir=graph)
        fail("verify trusted a graph manifest that contradicts itself")
    except oi.OutpointError as e:
        check("does not match its own identity" in str(e),
              f"self-inconsistent graph refused as: {e}")
    print("ok  verify: the parent is confirmed when confronted, "
          "declared when not, refused when wrong or self-inconsistent")


# ---------------------------------------------------------------------------
# Standalone runner (pytest uses the same functions via conftest's tmp)
# ---------------------------------------------------------------------------

def main():
    with tempfile.TemporaryDirectory() as tmp:
        graph, index, txids = test_build_matches_model(tmp)
        quartet = (tmp, graph, index, txids)
        test_determinism_multirun(quartet)
        test_append_equals_rebuild(quartet)
        test_rewind_equals_rebuild(quartet)
        test_rewind_refuses_bip30_straddle(quartet)
        test_rewind_survives_a_kill_before_the_truncations(quartet)
        test_straddle_guard_walks_the_same_two_roads(tmp)
        test_rewind_refuses_out_of_range(quartet)
        test_rewind_resumes_after_a_crash(quartet)
        test_unresolved_policy(tmp)
        test_join_refuses_bad_vout()
        test_lookup(quartet)
        test_index_object(quartet)
        test_golden_fingerprint(quartet)
        test_verify_catches_corruption(quartet)
        test_verify_catches_a_wrong_ladder(quartet)
        test_verify_refuses_a_restepped_ladder(quartet)
    print("PASS: the outpoint index equals the independently derived "
          "model byte for byte, appends deterministically, joins "
          "honestly, and its lookups tell true stories.")


if __name__ == "__main__":
    main()
