#!/usr/bin/env python3
"""
test_headers.py — self-test for headers.py. No node, no real data.

The other suites share a four-block chain that starts at height 1 with a
zero prev_hash: it plays the part of a genesis without being one. A
header archive cannot use it, because the whole point of the artifact is
that the first record IS genesis and every later one links back to it.
So this suite builds its own chain, rooted at height 0, and it earns its
keep twice: the spends reference REAL earlier outputs, so the same chain
also produces a graph and an outpoint index, which is what the Merkle
cross-check needs.

What is exercised:

- the 88-byte record against a model computed from the mirror writers:
  the header bytes, the size, and the WEIGHT — the one field that is
  not simply copied, checked on a block that carries witness data (the
  test builds each SegWit transaction a second time without its witness
  and uses that length as the base size, so the two roads to the weight
  are independent);
- genesis at index 0, and the coinbase scriptSigs read back through the
  offsets file;
- the BIP 34 tally: five coinbases declare their own height, and the
  genesis-style one declares a number that is not a height — counted as
  a disagreement, reported, never raised;
- seal and verify, with the canonical fingerprint pinned;
- resume: a scan stopped at height 3 and resumed to 5 must produce
  byte-identical files (and fingerprint) to the one-shot scan, crash
  leftovers past the committed sizes included;
- the archive refuses to be started midway, where its early headers
  could never come back, and refuses a block that does not name its last
  record as its parent — the link is checked when it is WRITTEN, not
  only when the archive is sealed;
- verify catches a broken link and a flipped byte;
- crosscheck recomputes every Merkle root from an outpoint index built
  over the same chain, and refuses an index built over another one;
- `curve dates` reads the same timestamps and the same median-time-past
  from the archive as it would get from a node.

Usage:
    python3 test_headers.py        # prints PASS or fails loudly
"""

import json
import os
import sys
import tempfile

import pytest

from nodsig import block_dates as bd
from nodsig import headers as hd
from nodsig import outpoint_index as oi
from nodsig import reveal_archive as ra
from nodsig import reuse_scan as rs
import test_blockparse as tbw
import test_outpoint_index as toi
import test_reuse_scan as trs
from nodsig.reuse_scan import SAT


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


# ---------------------------------------------------------------------------
# The chain of this suite: a real genesis, real prevouts, one SegWit block
# ---------------------------------------------------------------------------

SPK_A = tbw.P2PKH_SPK
SPK_B = bytes([0x00, 0x14]) + b"\xBB" * 20             # a P2WPKH lock
SPK_C = bytes([0x51])                                  # anyone-can-spend

# The genesis coinbase's scriptSig, shaped like the real one: a 4-byte
# push that decodes as a number (486604799) which is NOT a height. It is
# there so the BIP 34 tally has one honest disagreement to report.
GENESIS_SCRIPT = bytes([0x04]) + bytes.fromhex("ffff001d") + b"\x01\x04"


def bip34_push(height):
    """A coinbase scriptSig declaring its own height, BIP 34 style:
    a minimally-encoded little-endian push."""
    n = max(1, (height.bit_length() + 8) // 8)         # room for the sign
    return bytes([n]) + height.to_bytes(n, "little")


def headers_chain():
    """height → (hash_display_hex, raw_hex), plus the per-height model.

        h0  genesis: cbG (50 BTC to A), a non-BIP34 scriptSig
        h1  cb1 (50 BTC to A)
        h2  cb2; t1 spends cb1:0 → 7 sat to B, 3 sat to C
        h3  cb3 (+ witness commitment); t2 spends t1:0 WITH a witness
        h4  cb4; t3 spends t1:1
        h5  cb5 alone
    """
    blocks = {}
    model = {}
    prev = bytes(32)

    def coinbase(height, extra_outs=(), witness=False):
        """The block's coinbase, and — when it carries the BIP 141
        reserved witness — the same transaction serialized without it,
        which is the base size the model needs."""
        script = GENESIS_SCRIPT if height == 0 else bip34_push(height)
        ins = [tbw.w_input(bytes(32), 0xFFFFFFFF, script, 0xFFFFFFFF)]
        outs = [tbw.w_output(50 * SAT, SPK_A), *extra_outs]
        raw, txid, _wtxid = tbw.w_tx(
            1, ins, outs, 0,
            witnesses=[[bytes(32)]] if witness else None)
        stripped = tbw.w_tx(1, ins, outs, 0)[0] if witness else raw
        return raw, txid, script, stripped

    def add(height, txs, ids, script, base_sizes):
        """txs are the serialized transactions; base_sizes their lengths
        WITHOUT witness data — the model's own road to the weight."""
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_600_000_000 + 600 * height,
                                      0x1700_0000, height, txs, ids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())
        base = 80 + len(tbw.w_compactsize(len(txs))) + sum(base_sizes)
        model[height] = {"hash": block_hash, "raw": raw,
                         "header": raw[:80], "coinbase": script,
                         "time": 1_600_000_000 + 600 * height,
                         "size": len(raw), "weight": 3 * base + len(raw)}

    cbG, cbG_id, script, _ = coinbase(0)
    add(0, [cbG], [cbG_id], script, [len(cbG)])

    cb1, cb1_id, script, _ = coinbase(1)
    add(1, [cb1], [cb1_id], script, [len(cb1)])

    cb2, cb2_id, script, _ = coinbase(2)
    t1, t1_id, _ = tbw.w_tx(
        1, [tbw.w_input(cb1_id, 0, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(7, SPK_B), tbw.w_output(3, SPK_C)], 0)
    add(2, [cb2, t1], [cb2_id, t1_id], script, [len(cb2), len(t1)])

    # The SegWit block: t2 carries a witness, so the block's weight is
    # NOT four times its size. The same transaction is serialized a
    # second time without its witness to give the model the base size.
    t2_ins = [tbw.w_input(t1_id, 0, b"", 0xFFFFFFFF)]
    t2_outs = [tbw.w_output(6, SPK_A)]
    t2, t2_id, t2_wtxid = tbw.w_tx(1, t2_ins, t2_outs, 0,
                                   witnesses=[[trs.FAKE_SIG, trs.PUB3]])
    t2_stripped, _, _ = tbw.w_tx(1, t2_ins, t2_outs, 0)
    cb3, cb3_id, script, cb3_stripped = coinbase(
        3, [tbw.w_output(0, tbw.w_commitment_spk([t2_wtxid], bytes(32)))],
        witness=True)
    add(3, [cb3, t2], [cb3_id, t2_id], script,
        [len(cb3_stripped), len(t2_stripped)])

    cb4, cb4_id, script, _ = coinbase(4)
    t3, t3_id, _ = tbw.w_tx(
        1, [tbw.w_input(t1_id, 1, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(2, SPK_C)], 0)
    add(4, [cb4, t3], [cb4_id, t3_id], script, [len(cb4), len(t3)])

    cb5, cb5_id, script, _ = coinbase(5)
    add(5, [cb5], [cb5_id], script, [len(cb5)])
    return blocks, model


def emit(tmp, blocks, name="headers", end=None, host=ra):
    """The chain through a real host scanner's --headers plug. `host` is
    the module: both scanners must be able to grow the same archive, and
    one of the tests below proves they produce the same bytes."""
    hdir = os.path.join(tmp, name)
    server, url = trs.serve(blocks)
    try:
        if host is ra:
            ra.run_scan(url, "user:pass", end or max(blocks),
                        os.path.join(tmp, name + "_host"),
                        batch_size=2, checkpoint_every=2, headers_dir=hdir)
        else:
            locks = os.path.join(tmp, name + "_l")
            os.makedirs(locks, exist_ok=True)
            rs.run_scan(trs.test_prepare(locks),
                        url, "user:pass", end or max(blocks),
                        os.path.join(tmp, name + "_host"),
                        batch_size=2, checkpoint_every=2, headers_dir=hdir)
    finally:
        server.shutdown()
    return hdir


def read_files(hdir):
    """The three files' bytes, by logical name."""
    return {name: open(os.path.join(hdir, fn), "rb").read()
            for name, fn in hd.FILES}


@pytest.fixture
def chain():
    return headers_chain()


@pytest.fixture
def archive(tmp, chain):
    blocks, _model = chain
    return emit(tmp, blocks)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_records_match_model(archive, chain):
    """Every field of every record, against the writers' own model."""
    _blocks, model = chain
    got = dict(hd.iter_records(archive))
    check(sorted(got) == sorted(model),
          f"heights archived: {sorted(got)}, expected {sorted(model)}")

    raw = read_files(archive)["headers"]
    check(len(raw) == len(model) * hd.HDR_REC,
          f"headers.bin is {len(raw)} bytes, expected "
          f"{len(model) * hd.HDR_REC}")
    check(raw[:80] == model[0]["header"],
          "index 0 must hold the genesis header, verbatim")

    for h, want in model.items():
        rec = got[h]
        check(rec["raw"] == want["header"],
              f"height {h}: the 80 bytes are not the ones the chain wrote")
        check(rec["hash"] == want["hash"], f"height {h}: block id")
        check(rec["time"] == want["time"], f"height {h}: time")
        check(rec["size"] == want["size"],
              f"height {h}: size {rec['size']}, expected {want['size']}")
        check(rec["weight"] == want["weight"],
              f"height {h}: weight {rec['weight']}, expected {want['weight']}")
    # The SegWit block is the one where the weight is not a restatement
    # of the size: if it were, the field would be worth nothing.
    check(model[3]["weight"] != 4 * model[3]["size"],
          "the SegWit block must weigh less than 4× its size, or the "
          "test is not testing the weight")
    check(model[5]["weight"] == 4 * model[5]["size"],
          "a witness-free block weighs exactly 4× its size")
    print("ok  records: 80 bytes verbatim, size and weight, genesis at 0")


def test_coinbase_scripts(archive, chain):
    """The variable-length side: every scriptSig read back through the
    offsets, and the BIP 34 tally."""
    _blocks, model = chain
    got = dict(hd.coinbase_scripts(archive))
    for h, want in model.items():
        check(got[h] == want["coinbase"],
              f"height {h}: coinbase script {got[h].hex()}, expected "
              f"{want['coinbase'].hex()}")
    check(hd.bip34_height(got[4]) == 4, "height 4 must declare itself")
    check(hd.bip34_height(GENESIS_SCRIPT) == 486604799,
          "the genesis-style script declares a number that is not a height")

    _records, _last, _id, tally = hd.audit_chain(archive)
    check(tally == {"declared": 6, "agreed": 5},
          f"BIP 34 tally: {tally}, expected 6 declared and 5 agreeing")
    print("ok  coinbase scripts: read back through the offsets, BIP 34 "
          "tally reports the one disagreement instead of raising")


# The canonical fingerprint of this chain's header archive. Pinned so a
# refactor that changes a byte of the format has to say so out loud.
GOLDEN = "250b2137e95f61e44ce24b6afa5d5452cc7ed3d384b2c201193a359f641e2eed"


def test_seal_and_verify(archive, capsys):
    fp = hd.run_fingerprint(archive)
    manifest = json.load(open(os.path.join(archive, hd.MANIFEST_NAME)))
    check(manifest["identity"]["coverage"] == {"from": 0, "to": 5},
          f"coverage {manifest['identity']['coverage']}, expected 0..5")
    check("parent" not in manifest["identity"],
          "the identity carries no parent: it says what an artifact is")
    check(manifest["build"].get("parent") is None,
          "a header archive is a root artifact: no parent to declare")
    check([f["name"] for f in manifest["identity"]["files"]]
          == [name for name, _ in hd.FILES],
          "the identity must list the files in the format's order")
    check(fp == GOLDEN, f"fingerprint {fp}, pinned {GOLDEN}")

    hd.run_verify(archive)
    out = capsys.readouterr().out if capsys else ""
    if capsys:
        check("coverage 0..5 (rebuilt from the data)" in out,
              f"verify must state the range it rebuilt, got:\n{out}")
        check("each linking to the one before it (from genesis)" in out,
              f"verify must state the chain it rebuilt, got:\n{out}")
    print("ok  seal and verify: fingerprint pinned, coverage rebuilt from "
          "the data, chain rebuilt from the bytes")


def test_resume_equals_oneshot(tmp, chain):
    """Stopped and resumed must equal one-shot, byte for byte — and a
    tail past the committed sizes must be cut, not kept, whether the
    stop was a crash or a wanted TERM."""
    blocks, _model = chain
    one = emit(tmp, blocks, "one")
    part = emit(tmp, blocks, "part", end=3)

    # The crash window: bytes appended after the last checkpoint, which
    # no state names. The next load must truncate them away.
    with open(os.path.join(tmp, "part", "headers.bin"), "ab") as f:
        f.write(b"\x00" * hd.HDR_REC)
    with open(os.path.join(tmp, "part", "coinbase.bin"), "ab") as f:
        f.write(b"\xff" * 9)

    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 5, os.path.join(tmp, "part_host"),
                    batch_size=2, checkpoint_every=2,
                    headers_dir=os.path.join(tmp, "part"))
    finally:
        server.shutdown()

    a, b = read_files(one), read_files(tmp + "/part")
    for name, _fn in hd.FILES:
        check(a[name] == b[name],
              f"{name}: resumed emission differs from the one-shot one")
    check(hd.run_fingerprint(one) == hd.run_fingerprint(tmp + "/part"),
          "resumed archive must carry the one-shot fingerprint")
    print("ok  resume: same bytes and same fingerprint as one shot, crash "
          "leftovers truncated")


def test_hosts_agree(tmp, chain):
    """Either scanner may host the plug; the archive must not remember
    which one did."""
    blocks, _model = chain
    from_ra = read_files(emit(tmp, blocks, "from_ra", host=ra))
    from_rs = read_files(emit(tmp, blocks, "from_rs", host=rs))
    for name, _fn in hd.FILES:
        check(from_ra[name] == from_rs[name],
              f"{name}: the two hosts emitted different bytes")
    print("ok  hosts: reuse and archive scans emit the same archive")


def test_refuses_to_start_midway(tmp, chain):
    """An archive that begins above genesis could never be completed:
    the missing headers are behind a pass that is already over."""
    blocks, _model = chain
    emitter = hd.HeaderEmitter(os.path.join(tmp, "late"))
    try:
        emitter.load(4)
    except hd.HeaderError as e:
        check("turned on midway" in str(e), f"wrong refusal: {e}")
    else:
        fail("a fresh archive accepted a resume height above genesis")

    grown = hd.HeaderEmitter(emit(tmp, blocks, "grown"))
    try:
        grown.load(99)
    except hd.HeaderError as e:
        check("SAME scan" in str(e), f"wrong refusal: {e}")
    else:
        fail("an archive accepted a scan resuming past its watermark")
    print("ok  refusals: no archive that starts, or continues, in the "
          "wrong place")


def test_show_pays_for_the_range_and_answers_it_exactly(tmp, chain):
    """`show` reads by record — the coinbase through its offsets file —
    so a three-height window costs three seeks, not a pass over the
    archive. What it prints over ANY window must equal what the
    full-pass readers say about the same heights, edges included:
    genesis, and the watermark whose script runs to the end of the
    data file."""
    import io
    from nodsig import blockparse
    blocks, model = chain
    archive = emit(tmp, blocks)
    scripts = dict(hd.coinbase_scripts(archive))

    out = io.StringIO()
    hd.run_show(archive, 2, 4, out=out)
    text = out.getvalue()
    def head_line(h):
        return f"height {h:,}  {blockparse.hash_hex(model[h]['hash'])}"

    for h in (2, 3, 4):
        check(head_line(h) in text, f"height {h} missing from show 2..4")
        check(f"coinbase {scripts[h].hex()}" in text,
              f"height {h}: coinbase script wrong or missing in show")
    for h in (0, 1, 5):
        check(head_line(h) not in text,
              f"height {h} shown outside the asked range")

    for h in (0, 5):                       # the two edges, one at a time
        out = io.StringIO()
        hd.run_show(archive, h, h, out=out)
        check(f"coinbase {scripts[h].hex()}" in out.getvalue(),
              f"edge height {h}: coinbase script wrong in show")

    out = io.StringIO()
    hd.run_show(archive, 42, 50, out=out)
    check("no headers in that range" in out.getvalue(),
          "an empty range must be answered, not silent")
    print("ok  show: the window is read by record and matches the "
          "full-pass readers, edges and empty range included")


def test_an_archive_ahead_of_its_host_is_cut_to_the_resume_point(tmp, chain):
    """The crash window this emitter creates on purpose: it checkpoints
    BEFORE the host writes its own state, so a kill between the two
    leaves the archive ahead. load() must cut back to the host's resume
    point, landing on the very bytes of an archive that stopped there —
    state included, because the next checkpoint builds on it."""
    blocks, _model = chain
    stopped = emit(tmp, blocks, "stopped", end=3)      # the reference 0..3
    ahead = emit(tmp, blocks, "ahead", end=5)          # knows 0..5

    emitter = hd.HeaderEmitter(ahead)
    check(emitter.load(4) == 4,
          "an archive ahead of its host must heal, not refuse")
    a, b = read_files(stopped), read_files(ahead)
    for name, _fn in hd.FILES:
        check(a[name] == b[name],
              f"{name}: the cut archive differs from one that stopped "
              "at the same height")
    with open(os.path.join(stopped, hd.STATE_NAME)) as f:
        want = json.load(f)
    with open(os.path.join(ahead, hd.STATE_NAME)) as f:
        got = json.load(f)
    # `seconds` is compared apart, on purpose. It is the one field that
    # SHOULD differ between two archives that reached the same height by
    # different roads: one was fed straight through, the other was fed
    # too far and healed back, and they did not cost the same. What must
    # match is everything that describes WHAT the archive holds.
    check(got.pop("seconds", None) is not None,
          "a healed archive must still carry the scan's seconds")
    want.pop("seconds", None)
    check(got == want, f"cut state {got}, expected {want}")
    print("ok  ahead: the archive is cut to the resume point, byte for "
          "byte the one a stopped scan would have left")


def test_an_archive_ahead_of_its_host_regrows_the_same_bytes(tmp, chain):
    """The whole heal, end to end: a host with no state of its own
    rescans from the start against an archive that already knows the
    whole chain. The re-fed blocks must regrow it to the very bytes and
    fingerprint of a one-shot emission."""
    blocks, _model = chain
    one = emit(tmp, blocks, "one")
    ahead = emit(tmp, blocks, "ahead_regrow", end=5)
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 5, os.path.join(tmp, "fresh_host"),
                    batch_size=2, checkpoint_every=2, headers_dir=ahead)
    finally:
        server.shutdown()
    a, b = read_files(one), read_files(ahead)
    for name, _fn in hd.FILES:
        check(a[name] == b[name],
              f"{name}: the regrown archive differs from the one-shot one")
    check(hd.run_fingerprint(one) == hd.run_fingerprint(ahead),
          "the regrown archive must carry the one-shot fingerprint")
    print("ok  ahead: dropped records are re-fed and the archive lands "
          "on the one-shot bytes")


def test_refuses_a_foreign_block(tmp, chain):
    """A block from another chain, fed at the right height: the heights
    line up and everything else does not."""
    blocks, _model = chain
    emitter = hd.HeaderEmitter(emit(tmp, blocks, "foreign"))
    height = emitter.load(6)
    check(height == 6, f"resume height {height}, expected 6")
    other_blocks, _txids = toi.index_chain()
    from nodsig import blockparse
    foreign = blockparse.parse_block(bytes.fromhex(other_blocks[2][1]))
    try:
        emitter.add_block(6, foreign)
    except hd.HeaderError as e:
        check("stop being a chain" in str(e), f"wrong refusal: {e}")
    else:
        fail("the emitter appended a block from another chain")
    print("ok  refusal: a block that does not continue this chain is "
          "refused when it is written, not at the seal")


def test_verify_catches_a_broken_link(tmp, chain):
    """One byte of one prev_hash: the chain stops being a chain, and the
    audit says which link broke before any digest is even consulted."""
    blocks, _model = chain
    victim = emit(tmp, blocks, "broken")
    hd.run_fingerprint(victim)
    path = os.path.join(victim, "headers.bin")
    data = bytearray(open(path, "rb").read())
    data[3 * hd.HDR_REC + 4] ^= 0x01              # height 3's prev_hash
    open(path, "wb").write(data)
    try:
        hd.run_verify(victim)
    except hd.HeaderError as e:
        check("does not link to" in str(e) and "3" in str(e),
              f"wrong error: {e}")
    else:
        fail("verify accepted a header chain with a broken link")
    print("ok  verify: a broken link is named, with the heights it "
          "should have joined")


def test_verify_catches_corruption(tmp, chain):
    """A flipped byte in the variable-length file, which no link check
    would notice: the digests are the road that catches it."""
    blocks, _model = chain
    victim = emit(tmp, blocks, "rotten")
    hd.run_fingerprint(victim)
    path = os.path.join(victim, "coinbase.bin")
    data = bytearray(open(path, "rb").read())
    data[-1] ^= 0xFF
    open(path, "wb").write(data)
    try:
        hd.run_verify(victim)
    except hd.HeaderError as e:
        check("sha256 mismatch" in str(e), f"wrong error: {e}")
    else:
        fail("verify accepted a corrupted coinbase file")
    print("ok  verify: corruption in the coinbase file is caught by the "
          "digests")


def test_crosscheck_against_index(tmp, chain, capsys):
    """The third of the scan's four checks, repeated offline: every
    Merkle root recomputed from the index's txids."""
    blocks, _model = chain
    archive = emit(tmp, blocks, "cross")
    graph = toi.emit_graph(tmp, blocks, "cross_graph")
    index = os.path.join(tmp, "cross_index")
    oi.run_build(graph, index)

    checked = hd.run_crosscheck(archive, index)
    check(checked == 5, f"{checked} roots confronted, expected 5 (genesis "
                        "is not in the index)")

    # An index built over a DIFFERENT chain: same shape, other history.
    other_blocks, _txids = toi.index_chain()
    other = os.path.join(tmp, "other_index")
    oi.run_build(toi.emit_graph(tmp, other_blocks, "other_graph"), other)
    try:
        hd.run_crosscheck(archive, other)
    except hd.HeaderError as e:
        check("different chain" in str(e), f"wrong error: {e}")
    else:
        fail("crosscheck accepted an index built over another chain")
    print("ok  crosscheck: every Merkle root recomputed from the index, "
          "and an index of another chain refused")


def test_dates_without_a_node(tmp, chain):
    """`curve dates` off the archive must answer exactly what a node
    would: the header's time, and the median of the eleven timestamps
    ending at that height."""
    blocks, model = chain
    archive = emit(tmp, blocks, "dates")
    heights = [0, 3, 5]

    # The model's own road to the same two numbers. The median is the
    # UPPER middle when the count is even — which happens only near
    # genesis, where fewer than eleven blocks exist — because that is
    # the element a node picks, not the mean of the two middles that a
    # statistics library would return.
    def mtp(h):
        window = sorted(model[k]["time"]
                        for k in range(max(0, h - 10), h + 1))
        return window[len(window) // 2]

    want = [(h, model[h]["time"], mtp(h)) for h in heights]
    got = bd.read_dates(archive, heights)
    check(got == want, f"dates from the archive: {got}, expected {want}")

    # And the node's road, through the fake client the dates suite uses.
    table = {h: (t, mt) for h, t, mt in want}
    check(bd.fetch_dates(bd_fake(table), heights) == want,
          "the node road must agree with the archive road")
    print("ok  dates: time and median-time-past read locally, equal to "
          "what the node would answer")


def bd_fake(table):
    """The dates suite's fake client, imported lazily so this file does
    not depend on its module layout beyond the class it exposes."""
    import test_block_dates as tbd
    return tbd.FakeClient(table)


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def main():
    with tempfile.TemporaryDirectory() as tmp:
        blocks, model = headers_chain()
        chain = (blocks, model)
        archive = emit(tmp, blocks)
        test_records_match_model(archive, chain)
        test_coinbase_scripts(archive, chain)
        test_seal_and_verify(archive, None)
        test_resume_equals_oneshot(os.path.join(tmp, "a"), chain)
        test_hosts_agree(os.path.join(tmp, "b"), chain)
        test_refuses_to_start_midway(os.path.join(tmp, "c"), chain)
        test_refuses_a_foreign_block(os.path.join(tmp, "h"), chain)
        test_verify_catches_a_broken_link(os.path.join(tmp, "d"), chain)
        test_verify_catches_corruption(os.path.join(tmp, "e"), chain)
        test_crosscheck_against_index(os.path.join(tmp, "f"), chain, None)
        test_dates_without_a_node(os.path.join(tmp, "g"), chain)
    print("PASS")


if __name__ == "__main__":
    main()


def test_the_scan_leaves_its_seconds_in_the_header_state(tmp):
    """The fourth artifact of the co-emission check that lives in
    test_reveal_archive.py. It is here because a fresh header archive
    asks to be fed from GENESIS, and only this suite's chain starts
    there."""
    blocks, _model = headers_chain()
    hdir = emit(tmp, blocks, name="hdr_seconds")
    with open(os.path.join(hdir, hd.STATE_NAME)) as f:
        st = json.load(f)
    check("seconds" in st and "scan" in st["seconds"],
          f"the scan left no seconds in the header state: {list(st)}")
    print("ok  scan seconds: the header archive records them too")
