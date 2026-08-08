#!/usr/bin/env python3
"""
test_blockparse.py — self-test for blockparse.py, no node needed.

Two lines of attack, because they catch different mistakes:

1. MIRROR TEST. This file contains its own, independent serializers for
   Bitcoin's formats (the inverse of the readers under test: written from
   the specification, not by calling the parser). It builds a synthetic
   block — SegWit coinbase with witness commitment, a legacy transaction
   with an OP_PUSHDATA1 push, a SegWit transaction with mixed witness —
   computes every expected value on the writer's side (txids, wtxids,
   Merkle root, witness commitment, header hash) and checks that the
   parser recovers all of it, field by field. If the writer and the
   reader agree, a bug would have to be present in BOTH, in mirrored
   form, to slip through.

2. REAL FIXTURES. Two famous, public pieces of the chain are embedded as
   hex (chain data is public by construction: nothing private here):
   the genesis block, and the first SegWit transaction ever confirmed
   (block 481,824). These are self-certifying: the parser must recompute
   their well-known hashes from the raw bytes, so the fixtures do not
   even require trusting where they were downloaded from.

Plus the failure paths: truncated bytes, corrupted bytes (both a byte
the txid Merkle tree covers AND a witness byte only the witness
commitment covers — the case a first version of the parser missed),
trailing garbage, a missing commitment and malformed script pushes must
all raise ParseError — an integrity check that never fires is
indistinguishable from no check at all.

Usage:
    python3 test_blockparse.py        # prints PASS or fails loudly
"""

import hashlib
import sys

from nodsig import blockparse as bp


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


# ---------------------------------------------------------------------------
# Independent writers (the mirror image of the readers under test)
# ---------------------------------------------------------------------------
# Everything below is written from the serialization rules directly and
# shares no code with blockparse.py — that separation is the whole point.

def w_sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def w_compactsize(n):
    """Writer for the variable-length integer (inverse of read_compactsize)."""
    if n < 253:
        return bytes([n])
    if n < 2**16:
        return b"\xfd" + n.to_bytes(2, "little")
    if n < 2**32:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def w_input(prev_txid, prev_vout, script_sig, sequence):
    """One serialized input: outpoint, scriptSig with its length, sequence."""
    return (prev_txid + prev_vout.to_bytes(4, "little")
            + w_compactsize(len(script_sig)) + script_sig
            + sequence.to_bytes(4, "little"))


def w_output(value, script_pubkey):
    """One serialized output: 8-byte value, scriptPubKey with its length."""
    return (value.to_bytes(8, "little")
            + w_compactsize(len(script_pubkey)) + script_pubkey)


def w_tx(version, inputs, outputs, locktime, witnesses=None):
    """Serialize a transaction; SegWit layout if witnesses is given.

    Returns (raw_bytes, txid, wtxid): both ids are computed HERE — the
    txid over the stripped serialization, the wtxid over the full one —
    so the expectations are independent of the parser's own hashing.
    """
    body = w_compactsize(len(inputs)) + b"".join(inputs)
    body += w_compactsize(len(outputs)) + b"".join(outputs)
    head = version.to_bytes(4, "little")
    tail = locktime.to_bytes(4, "little")

    stripped = head + body + tail          # what the txid covers
    txid = w_sha256d(stripped)

    if witnesses is None:
        return stripped, txid, txid        # legacy: wtxid == txid

    wit = b""
    for stack in witnesses:                # one stack per input, in order
        wit += w_compactsize(len(stack))
        for item in stack:
            wit += w_compactsize(len(item)) + item
    raw = head + b"\x00\x01" + body + wit + tail
    return raw, txid, w_sha256d(raw)


def w_merkle(txids):
    """Independent Merkle root: same rule, separate implementation."""
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [w_sha256d(level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
    return level[0]


def w_block(version, prev_hash, time, bits, nonce, raw_txs, txids):
    """Serialize a block; the Merkle root comes from the writer's txids.

    Returns (raw_bytes, header_hash).
    """
    header = (version.to_bytes(4, "little") + prev_hash + w_merkle(txids)
              + time.to_bytes(4, "little") + bits.to_bytes(4, "little")
              + nonce.to_bytes(4, "little"))
    raw = header + w_compactsize(len(raw_txs)) + b"".join(raw_txs)
    return raw, w_sha256d(header)


# ---------------------------------------------------------------------------
# The synthetic block (all invented, nothing real)
# ---------------------------------------------------------------------------

FAKE_SIG = b"\x30" + bytes(70)             # 71 bytes, DER-ish shape
FAKE_PUB = b"\x02" + bytes(32)             # 33 bytes, compressed-key shape
FAKE_H20 = bytes(range(20))                # a fake 20-byte hash
P2PKH_SPK = bytes([0x76, 0xA9, 0x14]) + FAKE_H20 + bytes([0x88, 0xAC])


def w_commitment_spk(wtxids, reserved):
    """The coinbase output that commits to the witness data (BIP 141):
    OP_RETURN PUSH36( 0xaa21a9ed || sha256d(witness_root || reserved) ),
    where the witness root is the Merkle root over the wtxids with the
    coinbase's own slot set to 32 zero bytes."""
    witness_root = w_merkle([bytes(32)] + list(wtxids))
    return b"\x6a\x24\xaa\x21\xa9\xed" + w_sha256d(witness_root + reserved)


def build_synthetic(with_commitment=True):
    """Three transactions that among them exercise every branch:

    tx0 — the coinbase, itself SegWit as in every real post-2017 block
          with witness data: all-zero outpoint, arbitrary scriptSig, the
          32-byte reserved value as its only witness item, and three
          outputs (subsidy, a zero-value OP_RETURN, and — last, as the
          rule demands — the witness commitment);
    tx1 — legacy, TWO inputs (one scriptSig using OP_PUSHDATA1, which
          direct pushes never produce) and one output;
    tx2 — SegWit, MIXED inputs: native (empty scriptSig, two witness
          items), P2SH-wrapped style (redeem-script push in the
          scriptSig AND witness items), and one with an EMPTY witness
          stack — all three shapes occur on chain.

    `with_commitment=False` builds the same block WITHOUT the commitment
    output: an invalid block, used to prove the parser refuses it.
    """
    # tx1: legacy, two inputs; the second scriptSig pushes 80 bytes via
    # OP_PUSHDATA1 (0x4c 0x50), then a direct push of the fake key.
    pushdata_script = b"\x4c\x50" + bytes(80) + bytes([33]) + FAKE_PUB
    raw1, txid1, wtxid1 = w_tx(
        2,
        [w_input(b"\x11" * 32, 0, bytes([71]) + FAKE_SIG + bytes([33]) + FAKE_PUB, 0xFFFFFFFE),
         w_input(b"\x22" * 32, 5, pushdata_script, 0)],
        [w_output(123_456_789, P2PKH_SPK)],
        500_000)

    # tx2: SegWit, the three input shapes described above.
    redeem_push = bytes([22, 0x00, 0x14]) + FAKE_H20   # push of "0014<h20>"
    raw2, txid2, wtxid2 = w_tx(
        2,
        [w_input(b"\x33" * 32, 1, b"", 0xFFFFFFFF),
         w_input(b"\x44" * 32, 0, redeem_push, 0xFFFFFFFF),
         w_input(b"\x55" * 32, 2, bytes([71]) + FAKE_SIG + bytes([33]) + FAKE_PUB, 0)],
        [w_output(999, bytes([0x00, 0x20]) + bytes(32))],
        0,
        witnesses=[[FAKE_SIG, FAKE_PUB], [FAKE_SIG, FAKE_PUB], []])

    # tx0: the coinbase, built LAST because the commitment in its
    # outputs depends on the other transactions' wtxids.
    reserved = bytes(32)
    outputs = [w_output(5_000_000_000, P2PKH_SPK),
               w_output(0, b"\x6a\x04test")]
    if with_commitment:
        outputs.append(w_output(0, w_commitment_spk([wtxid1, wtxid2],
                                                    reserved)))
    raw0, txid0, _ = w_tx(
        1,
        [w_input(bytes(32), 0xFFFFFFFF, b"\x03\x40\x42\x0f hello", 0xFFFFFFFF)],
        outputs,
        0,
        witnesses=[[reserved]])

    txs = [raw0, raw1, raw2]
    txids = [txid0, txid1, txid2]
    raw_block, block_hash = w_block(
        4, b"\xaa" * 32, 1_700_000_000, 0x1701_2345, 42, txs, txids)
    return raw_block, block_hash, txids


def test_synthetic():
    raw, expect_hash, expect_txids = build_synthetic()
    blk = bp.parse_block(raw)

    # Header: every field must round-trip, and the recomputed hash must
    # equal the one the independent writer computed.
    h = blk.header
    check(h.version == 4, "header version")
    check(h.prev_hash == b"\xaa" * 32, "header prev_hash")
    check(h.time == 1_700_000_000 and h.bits == 0x1701_2345 and h.nonce == 42,
          "header time/bits/nonce")
    check(h.hash == expect_hash, "header hash != writer's header hash")

    # Txids: the crux of the mirror test (legacy AND stripped-SegWit).
    got_txids = [t.txid for t in blk.transactions]
    check(got_txids == expect_txids,
          "txids differ from the writer's independent computation")

    tx0, tx1, tx2 = blk.transactions
    check(bp.is_coinbase(tx0), "tx0 not recognized as coinbase")
    check(not bp.is_coinbase(tx1) and not bp.is_coinbase(tx2),
          "false coinbase detection")
    check(tx0.is_segwit and not tx1.is_segwit and tx2.is_segwit,
          "SegWit layout detection")
    check(tx1.wtxid == tx1.txid, "legacy tx must have wtxid == txid")
    check(tx2.wtxid != tx2.txid, "SegWit tx must have wtxid != txid")

    check(tx0.outputs[0].value == 5_000_000_000
          and tx0.outputs[0].script_pubkey == P2PKH_SPK
          and tx0.outputs[1].value == 0, "tx0 outputs")

    check(tx1.version == 2 and tx1.locktime == 500_000, "tx1 version/locktime")
    check(tx1.inputs[0].prev_txid == b"\x11" * 32
          and tx1.inputs[1].prev_vout == 5
          and tx1.inputs[0].sequence == 0xFFFFFFFE, "tx1 inputs")
    # The OP_PUSHDATA1 scriptSig must yield exactly its two pushes.
    check(bp.script_pushes(tx1.inputs[1].script_sig) == [bytes(80), FAKE_PUB],
          "OP_PUSHDATA1 pushes")

    check(tx2.inputs[0].script_sig == b"" and
          tx2.inputs[0].witness == [FAKE_SIG, FAKE_PUB],
          "tx2 native SegWit input")
    check(bp.script_pushes(tx2.inputs[1].script_sig) ==
          [bytes([0x00, 0x14]) + FAKE_H20],
          "tx2 wrapped input: redeem script push")
    check(tx2.inputs[1].witness == [FAKE_SIG, FAKE_PUB]
          and tx2.inputs[2].witness == [],
          "tx2 witness stacks")

    print("ok  synthetic block: header, txids, fields, witness, pushes")


def test_failure_paths():
    raw, _, _ = build_synthetic()

    # Truncation anywhere must raise, never return half a block.
    for cut in (10, 79, 100, len(raw) - 1):
        try:
            bp.parse_block(raw[:cut])
            fail(f"truncated block (at {cut}) parsed without error")
        except bp.ParseError:
            pass

    # Trailing garbage: a well-formed block plus one byte is not a block.
    try:
        bp.parse_block(raw + b"\x00")
        fail("trailing byte not detected")
    except bp.ParseError:
        pass

    # Corruption, case 1: flip a byte covered by the txid — an output
    # value (tx1's 123,456,789 satoshis, unique in the block). The block
    # still parses structurally, so only the Merkle check can catch it —
    # this proves the check actually fires.
    offset = raw.find((123_456_789).to_bytes(8, "little"))
    check(offset > 0, "could not locate tx1's output value in the raw block")
    corrupt = bytearray(raw)
    corrupt[offset] ^= 0xFF
    try:
        bp.parse_block(bytes(corrupt))
        fail("corrupted output value not caught by the Merkle check")
    except bp.ParseError as e:
        check("Merkle" in str(e), f"unexpected error for tx corruption: {e}")

    # Corruption, case 2: flip a byte inside tx2's WITNESS. The txid
    # excludes the witness, so the header's Merkle root cannot see this
    # — the first version of this parser let it through, and this very
    # test caught it. Only the witness commitment covers those bytes.
    # (raw[-30] sits inside the last witness stack that has items:
    # the block ends with tx2 = …witness stacks | 4-byte locktime.)
    corrupt = bytearray(raw)
    corrupt[-30] ^= 0xFF
    try:
        bp.parse_block(bytes(corrupt))
        fail("corrupted witness byte not caught by the witness commitment")
    except bp.ParseError as e:
        check("witness commitment" in str(e),
              f"unexpected error for witness corruption: {e}")

    # A SegWit block whose coinbase LACKS the commitment output is
    # invalid by consensus: the parser must refuse it, not shrug.
    raw_nc, _, _ = build_synthetic(with_commitment=False)
    try:
        bp.parse_block(raw_nc)
        fail("missing witness commitment not detected")
    except bp.ParseError as e:
        check("no witness commitment" in str(e),
              f"unexpected error for missing commitment: {e}")

    # A malformed script: push claims 5 bytes, only 2 remain.
    try:
        bp.script_pushes(b"\x05\x01\x02")
        fail("malformed push not detected")
    except bp.ParseError:
        pass

    print("ok  failure paths: truncation, trailing bytes, tx corruption "
          "(Merkle), witness corruption (commitment), missing commitment, "
          "malformed push")


def test_compactsize():
    # Each boundary of the encoding, against hand-written bytes.
    cases = [
        (b"\x00", 0), (b"\xfc", 252),
        (b"\xfd\xfd\x00", 253), (b"\xfd\xff\xff", 65535),
        (b"\xfe\x00\x00\x01\x00", 65536),
        (b"\xff\x00\x00\x00\x00\x01\x00\x00\x00", 2**32),
    ]
    for raw, expect in cases:
        value, pos = bp.read_compactsize(raw, 0)
        check(value == expect and pos == len(raw),
              f"compactsize {raw.hex()} -> {value}, expected {expect}")
    try:
        bp.read_compactsize(b"\xfd\x01", 0)
        fail("truncated compactsize not detected")
    except bp.ParseError:
        pass
    print("ok  compactsize: all encodings and the truncated case")


# ---------------------------------------------------------------------------
# Real fixtures (public chain data, self-certifying via their hashes)
# ---------------------------------------------------------------------------

# The genesis block, all 285 bytes of it: one coinbase paying 50 BTC to a
# bare public key (P2PK), with the famous newspaper headline in the
# scriptSig. Its hash is hardcoded in every Bitcoin node on earth.
GENESIS_HEX = (
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c01010000000100000000000000000000"
    "00000000000000000000000000000000000000000000ffffffff4d04ffff001d"
    "0104455468652054696d65732030332f4a616e2f32303039204368616e63656c"
    "6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066"
    "6f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe554827"
    "1967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4"
    "f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
GENESIS_MERKLE = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

# The first SegWit transaction ever confirmed (block 481,824, 2017-08-24),
# celebrating BIP 141 in an OP_RETURN. One P2SH-wrapped P2WPKH input:
# scriptSig = one push of the 22-byte redeem script, witness =
# [signature, public key]. Self-certifying: the parser must recompute its
# txid from the stripped serialization.
FIRST_SEGWIT_TXID = \
    "8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1c"
FIRST_SEGWIT_HEX = (
    "010000000001015836964079411659db5a4cfddd70e3f0de0261268f86c998a6"
    "9a143f47c6c83800000000171600149445e8b825f1a17d5e091948545c906540"
    "96db68ffffffff02d8be04000000000017a91422c17a06117b40516f98268048"
    "00003562e834c98700000000000000004d6a4b424950313431205c6f2f204865"
    "6c6c6f20536567576974203a2d29206b656570206974207374726f6e6721204c"
    "4c415020426974636f696e20747769747465722e636f6d2f6b6873396e650248"
    "3045022100aaa281e0611ba0b5a2cd055f77e5594709d611ad1233e7096394f6"
    "4ffe16f5b202207e2dcc9ef3a54c24471799ab99f6615847b21be2a6b4e02859"
    "18fd025597c5740121021ec0613f21c4e81c4b300426e5e5d30fa651f41e9993"
    "223adbe74dbe603c74fb00000000"
)


def test_genesis():
    blk = bp.parse_block(bytes.fromhex(GENESIS_HEX))
    check(bp.hash_hex(blk.header.hash) == GENESIS_HASH,
          "genesis block hash mismatch")
    check(bp.hash_hex(blk.header.merkle_root) == GENESIS_MERKLE,
          "genesis merkle root mismatch")
    check(len(blk.transactions) == 1, "genesis has exactly one transaction")

    cb = blk.transactions[0]
    check(bp.is_coinbase(cb) and not cb.is_segwit, "genesis coinbase shape")
    # With a single transaction, the txid IS the Merkle root.
    check(cb.txid == blk.header.merkle_root, "genesis txid == merkle root")
    check(b"The Times 03/Jan/2009 Chancellor on brink of second bailout "
          b"for banks" in cb.inputs[0].script_sig,
          "the headline is missing from the genesis scriptSig")
    # 50 BTC to a bare 65-byte public key followed by OP_CHECKSIG (P2PK):
    # the oldest exposed-by-construction lock — the very class the census
    # counts.
    out = cb.outputs[0]
    check(out.value == 5_000_000_000, "genesis subsidy value")
    pushes = bp.script_pushes(out.script_pubkey)
    check(len(out.script_pubkey) == 67 and out.script_pubkey[-1] == 0xAC
          and len(pushes) == 1 and len(pushes[0]) == 65
          and pushes[0][0] == 0x04,
          "genesis output is not the expected uncompressed P2PK")
    print("ok  genesis block: hash, merkle, headline, P2PK output")


def test_block_id_settles_the_question_before_the_parser_sees_anything():
    """The identity of a block is in its 80 header bytes, so a fetch
    loop can hash first and parse afterwards. That order is what keeps
    a parser from walking bytes nobody has authenticated yet."""
    raw = bytes.fromhex(GENESIS_HEX)
    check(bp.hash_hex(bp.block_id(raw)) == GENESIS_HASH,
          "block_id must agree with the hash the full parse reports")
    check(bp.block_id(raw) == bp.parse_block(raw).header.hash,
          "block_id and parse_block must not disagree about identity")

    # It reads the header and nothing else: a body mangled past byte 80
    # still has the same identity, and it is the identity that decides
    # whether parsing it is worth doing at all.
    check(bp.block_id(raw[:80] + b"\xff" * 40) == bp.block_id(raw),
          "block_id must depend on the header alone")
    try:
        bp.block_id(raw[:60])
        fail("a truncated header must be refused, not hashed")
    except bp.ParseError:
        pass
    print("ok  block_id: identity from the header alone, before the parse")


def test_first_segwit_tx():
    raw = bytes.fromhex(FIRST_SEGWIT_HEX)
    tx, pos = bp.parse_tx(raw)
    check(pos == len(raw), "first SegWit tx: bytes left over")
    check(tx.is_segwit, "first SegWit tx not detected as SegWit")
    check(bp.hash_hex(tx.txid) == FIRST_SEGWIT_TXID,
          "first SegWit tx: txid mismatch (stripped serialization wrong?)")

    # The single input is P2SH-wrapped P2WPKH: exactly the shape the
    # reveal extraction cares about — the scriptSig's one push is the
    # redeem script "0014<hash160>", and the witness holds the actual
    # [signature, public key].
    vin = tx.inputs[0]
    pushes = bp.script_pushes(vin.script_sig)
    check(len(pushes) == 1 and len(pushes[0]) == 22
          and pushes[0][:2] == b"\x00\x14",
          "redeem script push not found in scriptSig")
    check(len(vin.witness) == 2
          and vin.witness[0][0] == 0x30            # DER signature
          and len(vin.witness[1]) == 33
          and vin.witness[1][0] in (2, 3),         # compressed pubkey
          "witness is not [signature, compressed pubkey]")
    check(b"Hello SegWit" in tx.outputs[1].script_pubkey,
          "the BIP141 greeting is missing from the OP_RETURN")
    print("ok  first SegWit tx (block 481,824): txid, redeem script, witness")


def test_every_field_is_bytes_whatever_the_buffer_was():
    """The hot loops slice `buf` directly instead of copying each field,
    which is only safe because the buffer is normalized once on the way
    in. Hand the parser something that is not `bytes` and every field must
    still come out `bytes`.

    Why this is a test and not a comment: a `memoryview` over the right
    bytes compares EQUAL to those bytes, so every other assertion in this
    file would keep passing while the parser quietly handed out views into
    a buffer the caller may reuse or mutate. The type is the whole check,
    and it was a real regression during the profiling work.
    """
    raw, _, _ = build_synthetic()

    for wrap, name in ((memoryview, "memoryview"), (bytearray, "bytearray")):
        blk = bp.parse_block(wrap(raw))
        plain = bp.parse_block(raw)
        check(blk == plain, f"{name} gave a different block than bytes")
        check(type(blk.header.prev_hash) is bytes
              and type(blk.header.merkle_root) is bytes,
              f"{name}: header fields are not bytes")
        for tx in blk.transactions:
            check(type(tx.txid) is bytes and type(tx.wtxid) is bytes,
                  f"{name}: txid/wtxid are not bytes")
            for vin in tx.inputs:
                check(type(vin.prev_txid) is bytes
                      and type(vin.script_sig) is bytes,
                      f"{name}: input fields are not bytes")
                for item in vin.witness:
                    check(type(item) is bytes,
                          f"{name}: a witness item is not bytes")
            for vout in tx.outputs:
                check(type(vout.script_pubkey) is bytes,
                      f"{name}: scriptPubKey is not bytes")

    print("ok  every parsed field is bytes, whatever buffer came in")


def test_truncation_is_named_field_by_field():
    """Cutting the bytes at EVERY position must raise, and the message
    must say what was being read.

    The bounds checks in the input and output loops are inline now, one
    per field, instead of going through `_take`. Inline checks are exactly
    the kind that get forgotten one branch at a time, and a forgotten one
    does not crash: it slices short and hands back a truncated field that
    every downstream digest would then certify. So this walks every cut
    rather than sampling a few.
    """
    raw, _, _ = build_synthetic()
    for cut in range(1, len(raw)):
        try:
            bp.parse_block(raw[:cut])
        except bp.ParseError as e:
            check(str(e) != "", f"empty error message at cut {cut}")
        else:
            fail(f"a block cut at {cut} parsed without error")

    # And the naming itself, on the two loops that were rewritten: the
    # message must still identify the field, not merely report a failure.
    seen = set()
    for cut in range(80, len(raw)):
        try:
            bp.parse_block(raw[:cut])
        except bp.ParseError as e:
            seen.add(str(e))
    check(any("scriptSig" in m for m in seen),
          "no truncation message names a scriptSig")
    check(any("scriptPubKey" in m for m in seen),
          "no truncation message names a scriptPubKey")
    check(any("witness item" in m for m in seen),
          "no truncation message names a witness item")
    check(any("previous txid" in m for m in seen),
          "no truncation message names a previous txid")

    print(f"ok  every one of {len(raw) - 1} truncations refused, and named")


def main():
    test_compactsize()
    test_synthetic()
    test_failure_paths()
    test_every_field_is_bytes_whatever_the_buffer_was()
    test_truncation_is_named_field_by_field()
    test_genesis()
    test_first_segwit_tx()
    test_block_id_settles_the_question_before_the_parser_sees_anything()
    print("PASS: blockparse agrees with the mirror writer and the chain.")


if __name__ == "__main__":
    main()
