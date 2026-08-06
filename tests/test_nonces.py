"""Tests for nonces.py: the shape rules that decide what counts as a
signature, and the canonicalization that decides when two nonces are the
same one.

The discipline here is the one blockparse's tests use: the DER encoder
below is written independently of the parser it feeds, so a test failure
means the two disagree and not that one typo was copied twice.

What is worth pinning, and why each case exists:

- a repeated nonce must produce the SAME prefix from two DIFFERENT
  signatures. That is the entire purpose of the artifact, so it is the
  first test;
- `r` encoded with padding, or shorter than 32 bytes, is the same
  scalar. Pre-BIP 66 history contains both, and a canonicalization that
  missed this would split a real repeated-nonce group in two and report
  nothing;
- a 65-byte public key must never be read as a Schnorr signature: keys
  recur identically across inputs, so that single confusion would
  manufacture repeated-nonce groups out of ordinary wallets;
- a control block and a witness script must stay out of the Schnorr
  slots, for the same reason at a different length.
"""

import hashlib
import io
import json

import pytest

from nodsig.blockparse import TxIn
from nodsig.nonces import (FLAG_ECDSA, FLAG_SCHNORR, R_PREFIX, REC,
                           SIGHASH_ABSENT, SIGHASH_ALL, SIGHASH_OTHER,
                           SIGHASH_SINGLE_ACP, extract_nonces, new_stats,
                           record, rec_sighash, sighash_bits, signature_r,
                           taproot_r)

# The scheme bit plus the sighash bits of the signatures these tests
# build: SIG and SIG2 carry 0x01, a bare 64-byte Schnorr carries none.
ECDSA_ALL = FLAG_ECDSA | sighash_bits(0x01)
SCHNORR_DEFAULT = FLAG_SCHNORR | sighash_bits(None)


# ---------------------------------------------------------------------------
# An independent DER encoder, for the mirror discipline
# ---------------------------------------------------------------------------

def der(r_bytes, s_bytes, sighash=0x01):
    """A DER ECDSA signature carrying exactly these integer bodies.

    Takes the bodies verbatim, padding included, so a test can build the
    non-canonical encodings history actually contains.
    """
    body = (bytes([0x02, len(r_bytes)]) + r_bytes
            + bytes([0x02, len(s_bytes)]) + s_bytes)
    return bytes([0x30, len(body)]) + body + bytes([sighash])


def minimal(n):
    """The minimal DER body of integer n: big-endian, no leading zeros,
    prefixed with 0x00 when the top bit would make it negative."""
    raw = n.to_bytes((max(n.bit_length(), 1) + 7) // 8, "big")
    return b"\x00" + raw if raw[0] & 0x80 else raw


R = 0x9ff1c4b0e5d3a27681f0c5d4e3b2a1908f7e6d5c4b3a29180716253443526170
S1 = 0x00c0ffee00000000000000000000000000000000000000000000000000000001
S2 = 0x00beef0000000000000000000000000000000000000000000000000000000002


def test_same_nonce_two_signatures_one_prefix():
    """The point of the whole artifact: one k, two messages, one group."""
    a = signature_r(der(minimal(R), minimal(S1)))
    b = signature_r(der(minimal(R), minimal(S2)))
    assert a == b is not None
    assert a[:R_PREFIX] == R.to_bytes(32, "big")[:R_PREFIX]


def test_r_is_canonicalized_before_truncation():
    """Padding and short values are the same scalar.

    Three encodings of one r: minimal, with an extra zero byte of
    padding, and a genuinely short scalar. The first two must agree; the
    third must be left-padded to 32 bytes rather than truncated from its
    own first byte.
    """
    padded = signature_r(der(b"\x00" + minimal(R), minimal(S1)))
    assert padded == signature_r(der(minimal(R), minimal(S1)))

    small = signature_r(der(minimal(0x1234), minimal(S1)))
    assert small == bytes(30) + b"\x12\x34"
    assert small[:R_PREFIX] == bytes(R_PREFIX)


def test_der_refusals_are_counted_not_guessed():
    stats = new_stats()
    # A sequence length that does not cover the body.
    assert signature_r(bytes([0x30, 0x09, 0x02, 0x01, 0x01,
                              0x02, 0x01, 0x01, 0x01]), stats) is None
    # The s marker missing where the lengths say it must be.
    good = der(minimal(R), minimal(S1))
    broken = good[:4 + 33] + b"\x03" + good[4 + 34:]
    assert signature_r(broken, stats) is None
    # An r wider than a curve scalar cannot be one.
    assert signature_r(der(b"\x00" * 2 + b"\x11" * 33, minimal(S1)),
                       stats) is None
    assert stats["malformed_der"] == 2
    assert stats["oversize_r"] == 1

    # A Schnorr signature whose R.x happens to start with 0x30 is not a
    # broken DER signature, and must not be counted as one: at 64 and 65
    # bytes the two are indistinguishable, and real blocks produce this
    # constantly (one taproot signature in 256).
    schnorr = new_stats()
    for n in (64, 65):
        assert signature_r(b"\x30" + b"\xd4" * (n - 1), schnorr) is None
    assert schnorr["malformed_der"] == 0
    # Still parsed at those lengths, because a short r and s can reach
    # them honestly.
    # Total length is 7 + rlen + slen, so 29 and 29 land on 65 exactly.
    reachable = der(b"\x12" + bytes(28), b"\x56" + bytes(28))
    assert len(reachable) == 65
    assert signature_r(reachable) == bytes(3) + b"\x12" + bytes(28)

    # Things that do not even claim to be signatures are silent.
    quiet = new_stats()
    for item in (b"", b"\x02" + b"\x11" * 32, b"\x04" + b"\x11" * 64,
                 b"\x30", bytes(9)):
        assert signature_r(item, quiet) is None
    assert quiet["malformed_der"] == 0


def test_schnorr_shapes_and_the_public_key_trap():
    r32 = bytes(range(32))
    assert taproot_r(r32 + bytes(32)) == r32          # 64-byte form
    assert taproot_r(r32 + bytes(32) + b"\x81") == r32  # 65-byte, sighash ok

    # 65 bytes with an illegal sighash byte: not a signature.
    assert taproot_r(r32 + bytes(32) + b"\x00") is None
    # An uncompressed public key is 65 bytes and 0x04 leads it. Its last
    # byte is a coordinate byte, so 6 times in 256 it lands on a legal
    # sighash value: this is the case that must never pass where a key
    # could be what was pushed.
    key = b"\x04" + b"\x11" * 63 + b"\x02"
    assert taproot_r(key) is None
    for lead in (0x06, 0x07):                 # hybrid keys, early history
        assert taproot_r(bytes([lead]) + b"\x11" * 63 + b"\x02") is None
    # Not the right length at all.
    assert taproot_r(bytes(63)) is None
    assert taproot_r(bytes(66)) is None


def test_a_key_path_signature_may_start_like_a_key():
    """The guard above must NOT fire on a lone witness item.

    A witness holding one item cannot be holding a pushed public key, so
    refusing a signature whose R.x starts with 0x04 there would drop
    1.17% of the 65-byte form for nothing. Measured on real blocks
    before it was fixed: 169 signatures lost in 150 recent blocks.
    """
    r32 = b"\x04" + bytes(range(1, 32))
    sig = r32 + bytes(32) + b"\x01"
    assert taproot_r(sig) is None                    # not a lone item
    assert taproot_r(sig, key_path=True) == r32      # a lone item

    stats = new_stats()
    assert extract_nonces(_txin(witness=(sig,)), stats) == [
        (FLAG_SCHNORR | sighash_bits(0x01), r32[:R_PREFIX])]
    # In a script-path spend the same bytes sit next to a script and a
    # control block, where a pushed key is conceivable, so the guard
    # still applies.
    control = b"\xc0" + b"\x22" * 32
    assert extract_nonces(_txin(witness=(sig, b"\x51", control)),
                          stats) == []


def _txin(script_sig=b"", witness=()):
    return TxIn(bytes(32), 0, script_sig, 0xFFFFFFFF, list(witness))


def push(data):
    """A single data push, in the one encoding this length needs."""
    if len(data) < 76:
        return bytes([len(data)]) + data
    return b"\x4c" + bytes([len(data)]) + data


PUBKEY = b"\x02" + b"\x33" * 32
SIG = der(minimal(R), minimal(S1))
# A different nonce, and different in its TOP bytes: two scalars that
# differ only low down would share a 12-byte prefix, which is the
# truncation working as designed and would make this a bad test vector.
R2 = 0x1122334455667788990a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
SIG2 = der(minimal(R2), minimal(S2))


def test_p2pkh_and_p2wpkh_yield_one_ecdsa_nonce():
    stats = new_stats()
    out = extract_nonces(_txin(push(SIG) + push(PUBKEY)), stats)
    assert out == [(ECDSA_ALL, R.to_bytes(32, "big")[:R_PREFIX])]

    out = extract_nonces(_txin(witness=(SIG, PUBKEY)), stats)
    assert out == [(ECDSA_ALL, R.to_bytes(32, "big")[:R_PREFIX])]
    assert stats["nonces_ecdsa"] == 2
    assert stats["nonces_schnorr"] == 0
    assert stats["inputs_without_nonce"] == 0


def test_multisig_yields_every_signature_and_not_the_script():
    """A 2-of-3 P2WSH spend: two signatures, and a witness script that
    holds three public keys and no nonce."""
    script = (b"\x52" + push(PUBKEY) + push(PUBKEY) + push(PUBKEY)
              + b"\x53\xae")
    stats = new_stats()
    out = extract_nonces(_txin(witness=(b"", SIG, SIG2, script)), stats)
    assert [k for k, _ in out] == [ECDSA_ALL, ECDSA_ALL]
    assert out[0][1] != out[1][1]
    assert stats["nonces_schnorr"] == 0


def test_taproot_key_path_and_script_path():
    r32 = bytes(range(32))
    stats = new_stats()
    # Key path: the single item is the signature.
    assert extract_nonces(_txin(witness=(r32 + bytes(32),)), stats) == [
        (SCHNORR_DEFAULT, r32[:R_PREFIX])]
    # Key path with an annex, which is the last item and starts 0x50.
    assert extract_nonces(_txin(witness=(r32 + bytes(32),
                                         b"\x50\x01")), stats) == [
        (SCHNORR_DEFAULT, r32[:R_PREFIX])]
    # Script path: signature, leaf script, control block. The control
    # block here is 65 bytes and its last byte is a legal sighash value,
    # which is exactly the accident the slot rule exists to survive.
    control = b"\xc0" + b"\x22" * 63 + b"\x01"
    out = extract_nonces(_txin(witness=(r32 + bytes(32),
                                        b"\x20" + b"\x44" * 32 + b"\xac",
                                        control)), stats)
    assert out == [(SCHNORR_DEFAULT, r32[:R_PREFIX])]
    assert stats["nonces_schnorr"] == 3


def test_a_64_byte_witness_script_is_not_a_nonce():
    """The other half of the slot rule: the last two items are never
    read as signatures, so a 64-byte script cannot become a group."""
    stats = new_stats()
    script64 = bytes(64)
    assert extract_nonces(_txin(witness=(b"", script64)), stats) == []
    assert stats["inputs_without_nonce"] == 1


def test_inputs_that_reveal_no_nonce_are_counted():
    stats = new_stats()
    assert extract_nonces(_txin(), stats) == []
    assert extract_nonces(_txin(script_sig=push(PUBKEY)), stats) == []
    assert stats["inputs_without_nonce"] == 2

    # A malformed scriptSig is counted, exactly as the archive counts it,
    # and does not raise.
    bad = new_stats()
    assert extract_nonces(_txin(script_sig=b"\x4b\x01"), bad) == []
    assert bad["malformed_scriptsig"] == 1


def test_shared_pushes_give_the_same_answer_as_parsing_again():
    """The integration door the bench measures must not change the
    result: handing over already-parsed pushes is an optimization, not a
    second behaviour."""
    from nodsig.blockparse import script_pushes
    tx_in = _txin(push(SIG) + push(PUBKEY), witness=(SIG2, PUBKEY))
    alone = extract_nonces(tx_in, new_stats())
    shared = extract_nonces(tx_in, new_stats(),
                            sig_pushes=script_pushes(tx_in.script_sig))
    assert alone == shared
    assert len(alone) == 2


def test_record_layout_sorts_by_point_then_height_then_scheme():
    """The layout IS the grouping: sorting raw records puts a nonce
    point's sightings together and in chain order, which is what the
    fusion and every reader depend on."""
    a = record(b"\x01" * R_PREFIX, 100, FLAG_ECDSA)
    b = record(b"\x01" * R_PREFIX, 7, FLAG_ECDSA)
    c = record(b"\x02" * R_PREFIX, 1, FLAG_ECDSA)
    d = record(b"\x01" * R_PREFIX, 100, FLAG_SCHNORR)
    assert len(a) == REC == 16
    assert sorted([a, b, c, d]) == [b, a, d, c]
    assert a[:R_PREFIX] == b"\x01" * R_PREFIX
    assert int.from_bytes(a[R_PREFIX:R_PREFIX + 3], "big") == 100
    assert a[-1] == FLAG_ECDSA


def test_the_sighash_mode_rides_the_idle_bits():
    """The three bits carry WHAT the signature committed to: the six
    standard bytes get a code each, the 64-byte Schnorr form gets
    `absent` (it publishes none), and everything else collapses into
    `nonstandard`, because an ECDSA sighash byte is not constrained by
    consensus and inventing a code per oddity would invent meaning."""
    r32 = bytes(range(32))
    for byte, code in ((0x01, SIGHASH_ALL), (0x83, SIGHASH_SINGLE_ACP)):
        out = extract_nonces(_txin(push(der(minimal(R), minimal(S1), byte))
                                   + push(PUBKEY)), new_stats())
        assert rec_sighash(out[0][0]) == code
        assert out[0][0] & FLAG_ECDSA

    # Bytes no rule describes: 0x00, and the 0x85 that early history
    # contains. Both are `nonstandard`, and neither is guessed at.
    for byte in (0x00, 0x85):
        out = extract_nonces(_txin(push(der(minimal(R), minimal(S1), byte))
                                   + push(PUBKEY)), new_stats())
        assert rec_sighash(out[0][0]) == SIGHASH_OTHER

    # The two BIP 340 forms: 64 bytes publishes no byte, 65 publishes one.
    out = extract_nonces(_txin(witness=(r32 + bytes(32),)), new_stats())
    assert rec_sighash(out[0][0]) == SIGHASH_ABSENT
    out = extract_nonces(_txin(witness=(r32 + bytes(32) + b"\x83",)),
                         new_stats())
    assert rec_sighash(out[0][0]) == SIGHASH_SINGLE_ACP

    # The bits live above the scheme bits and below nothing else.
    assert nn.SIGHASH_MASK == 0b11100
    assert nn.FLAGS_DEFINED == 0b11111


def test_prefix_width_is_the_documented_one():
    """A change here changes the artifact's collision budget, so it is
    pinned rather than assumed."""
    assert R_PREFIX == 12
    with pytest.raises(AssertionError):
        assert R_PREFIX == 32       # guards against a silent widening


# ===========================================================================
# The artifact: emission, fusion, seal, rewind, and the answers
# ===========================================================================
# The chain below is synthetic but the signatures are real DER and real
# BIP 340 shapes, because the whole artifact turns on telling those apart.
# It is built so that every claim the format makes has a case:
#
#   nonce A     an ECDSA sighting at h2 and a SCHNORR one at h4 — the
#               cross-scheme reuse that having ONE keyspace is for;
#   nonce B     h3 and h5, so a group straddles a run boundary AND a
#               fusion;
#   tiny nonce  h2 and h5, the deliberate construction that must be
#               labelled rather than reported as a break;
#   nonce C     h3 only: a singleton, which must never become a group.

import os
import shutil

import pytest

from nodsig import nonces as nn
from nodsig import reveal_archive as ra
from nodsig.artifact import WallClock
import test_blockparse as tbw
import test_reuse_scan as trs

NONCE_A = 0x77f1c4b0e5d3a27681f0c5d4e3b2a1908f7e6d5c4b3a291807162534435261a0
NONCE_B = 0x2233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011
NONCE_C = 0x5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344
NONCE_TINY = 0x3b

PUB = b"\x02" + bytes(range(32))
MULTI = (bytes([0x52, 33]) + PUB + bytes([33]) + PUB
         + bytes([33]) + PUB + bytes([0x53, 0xAE]))       # 2-of-3


def _schnorr(r_int, s_byte=0x11):
    """A 64-byte BIP 340 signature carrying this nonce point."""
    return r_int.to_bytes(32, "big") + bytes([s_byte]) * 32


def point_of(r_int):
    return r_int.to_bytes(32, "big")[:nn.R_PREFIX]


def nonce_chain():
    """Five blocks; see the plan above for what each height carries."""
    blocks = {}
    prev = bytes(32)

    def add(height, raw_txs, txids):
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_600_000_000 + height,
                                      0x1700_0000, height, raw_txs, txids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())

    def coinbase(tag, witness=False, commit_wtxids=None):
        outs = [tbw.w_output(50 * trs.rs.SAT, tbw.P2PKH_SPK)]
        if witness:
            outs.append(tbw.w_output(
                0, tbw.w_commitment_spk(commit_wtxids, bytes(32))))
        return tbw.w_tx(
            1, [tbw.w_input(bytes(32), 0xFFFFFFFF, tag, 0xFFFFFFFF)],
            outs, 0, witnesses=[[bytes(32)]] if witness else None)

    cb, cbid, _ = coinbase(b"\x01a")
    add(1, [cb], [cbid])

    # h2: two P2PKH spends, nonce A and the tiny one.
    cb, cbid, _ = coinbase(b"\x01b")
    tx, txid, _ = tbw.w_tx(
        2,
        [tbw.w_input(b"\xB1" * 32, 0,
                     push(der(minimal(NONCE_A), minimal(S1)))
                     + push(PUB), 0xFFFFFFFF),
         tbw.w_input(b"\xB1" * 32, 1,
                     push(der(minimal(NONCE_TINY), minimal(S1)))
                     + push(PUB), 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0)
    add(2, [cb, txid and tx], [cbid, txid])

    # h3: one P2SH 2-of-3 spend, nonces B and C in one scriptSig.
    cb, cbid, _ = coinbase(b"\x01c")
    sig_script = (b"\x00" + push(der(minimal(NONCE_B), minimal(S1)))
                  + push(der(minimal(NONCE_C), minimal(S2)))
                  + b"\x4c" + bytes([len(MULTI)]) + MULTI)
    tx, txid, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xB2" * 32, 0, sig_script, 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0)
    add(3, [cb, tx], [cbid, txid])

    # h4: a taproot key-path spend whose R.x IS nonce A.
    tx, txid, wtxid = tbw.w_tx(
        2, [tbw.w_input(b"\xB3" * 32, 0, b"", 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0,
        witnesses=[[_schnorr(NONCE_A)]])
    cb, cbid, _ = coinbase(b"\x01d", witness=True, commit_wtxids=[wtxid])
    add(4, [cb, tx], [cbid, txid])

    # h5: nonce B again (different s), and the tiny one again.
    cb, cbid, _ = coinbase(b"\x01e")
    tx, txid, _ = tbw.w_tx(
        2,
        [tbw.w_input(b"\xB4" * 32, 0,
                     push(der(minimal(NONCE_B), minimal(S2)))
                     + push(PUB), 0xFFFFFFFF),
         tbw.w_input(b"\xB4" * 32, 1,
                     push(der(minimal(NONCE_TINY), minimal(S2)))
                     + push(PUB), 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0)
    add(5, [cb, tx], [cbid, txid])
    return blocks


@pytest.fixture
def tiny_flush(monkeypatch):
    """Flush a run at almost every window, so the fusion always has
    several runs to fold: single-run fusions would never exercise the
    path the append property lives on."""
    original = nn.NonceEmitter.__init__

    def small(self, nonces_dir, flush_records=2):
        original(self, nonces_dir, flush_records=flush_records)

    monkeypatch.setattr(nn.NonceEmitter, "__init__", small)


def _scan(tmp, name, end=5, nonces_dir=None, checkpoint_every=2,
          archive_dir=None):
    """Run the real host (the archive scan) with the nonce plug on."""
    blocks = nonce_chain()
    server, url = trs.serve(blocks)
    nd = nonces_dir or os.path.join(tmp, name + "_nonces")
    ad = archive_dir or os.path.join(tmp, name + "_archive")
    try:
        ra.run_scan(url, "user:pass", end, ad, batch_size=2,
                    checkpoint_every=checkpoint_every, nonces_dir=nd)
    finally:
        server.shutdown()
    return nd


def _records(nonces_dir):
    return list(nn.iter_records(nonces_dir))


def _records_of_runs(nonces_dir):
    """Every record sitting in the pending runs, in file order."""
    state = nn._load_state(nonces_dir)
    out = []
    for run in state["runs"]:
        path = os.path.join(nonces_dir, nn.RUNS_DIR, run["name"])
        with open(path, "rb") as f:
            raw = f.read()
        out += [raw[i:i + nn.REC] for i in range(0, len(raw), nn.REC)]
    return out


def _merged_bytes(nonces_dir):
    state = nn._load_state(nonces_dir)
    entry = state["files"][nn.LOGICAL]
    with open(os.path.join(nonces_dir, entry["file"]), "rb") as f:
        return f.read()


def test_the_scan_emits_exactly_the_signatures_it_walked(tmp, tiny_flush):
    nd = _scan(tmp, "content")
    nn.run_merge(nd)
    got = [(rec_point_hex(r), nn.rec_height(r), nn.rec_flags(r))
           for r in _records(nd)]
    # Every DER signature in the chain carries 0x01, and the Schnorr one
    # is the 64-byte form, which publishes no sighash byte at all.
    expect = {
        (point_of(NONCE_A).hex(), 2, ECDSA_ALL),
        (point_of(NONCE_A).hex(), 4, SCHNORR_DEFAULT),
        (point_of(NONCE_B).hex(), 3, ECDSA_ALL),
        (point_of(NONCE_B).hex(), 5, ECDSA_ALL),
        (point_of(NONCE_C).hex(), 3, ECDSA_ALL),
        (point_of(NONCE_TINY).hex(), 2, ECDSA_ALL),
        (point_of(NONCE_TINY).hex(), 5, ECDSA_ALL),
    }
    assert set(got) == expect
    assert len(got) == len(expect)
    # Sorted by the whole record, so a group comes out in chain order.
    assert got == sorted(got, key=lambda g: (g[0], g[1], g[2]))


def rec_point_hex(rec):
    return nn.rec_point(rec).hex()


def test_one_keyspace_catches_reuse_across_the_two_schemes(tmp, tiny_flush):
    """Nonce A is used by an ECDSA signature at h2 and a Schnorr one at
    h4. No honest signer does that, and it is only visible because the
    two schemes are NOT partitioned."""
    nd = _scan(tmp, "cross")
    nn.run_merge(nd)
    groups = {g.point: g for g in nn.run_groups(nd, out=io.StringIO())}
    a = groups[point_of(NONCE_A)]
    assert a.count == 2
    assert a.flags & nn.SCHEME_MASK == nn.SCHEME_MASK
    assert (a.first, a.last) == (2, 4)


def test_groups_are_the_answer_and_tiny_r_is_labelled(tmp, tiny_flush):
    nd = _scan(tmp, "groups")
    nn.run_merge(nd)
    report = io.StringIO()
    groups = nn.run_groups(nd, out=report)
    by_point = {g.point: g for g in groups}
    assert set(by_point) == {point_of(NONCE_A), point_of(NONCE_B),
                             point_of(NONCE_TINY)}
    assert point_of(NONCE_C) not in by_point       # a singleton is not a group
    assert nn.is_tiny(point_of(NONCE_TINY))
    assert not nn.is_tiny(point_of(NONCE_A))
    text = report.getvalue()
    assert "3 points sighted at least 2 times" in text
    assert "1 have a tiny r" in text
    assert "1 span BOTH schemes" in text
    # The two quantities the measurement said never to conflate.
    assert "3 sightings beyond the first" in text


def test_the_height_column_can_be_read_by_a_person():
    """Joining heights with a comma made the separator the same character
    as the thousands separator, so eight sightings in one block printed as
    `364,767,364,767,364,767,…` and nobody could see where a height ended.

    Runs collapse instead, which is shorter and says more: how many times
    a point appeared inside a single block is the interesting part of that
    row, and the chain's largest group is exactly that case.
    """
    assert nn._height_sample([364_767] * 8, more=True) == "364,767 x8 …"
    assert nn._height_sample([296_149, 298_481, 298_481, 298_505]) \
        == "296,149 298,481 x2 298,505"
    assert nn._height_sample([2, 3]) == "2 3"
    assert nn._height_sample([]) == ""


def test_append_equals_rebuild(tmp, tiny_flush):
    """Scanned in two takes, fused once: the same bytes and the same
    fingerprint as a single pass to the same height. This is the promise
    the whole appendable shape rests on."""
    one = _scan(tmp, "oneshot")
    fp_one = nn.run_merge(one)

    two = os.path.join(tmp, "twotakes_nonces")
    ad = os.path.join(tmp, "twotakes_archive")
    _scan(tmp, "twotakes", end=3, nonces_dir=two, archive_dir=ad)
    _scan(tmp, "twotakes", end=5, nonces_dir=two, archive_dir=ad,
          checkpoint_every=1)
    fp_two = nn.run_merge(two)

    assert fp_two == fp_one
    assert _merged_bytes(two) == _merged_bytes(one)


def test_rewind_equals_rebuild(tmp, tiny_flush):
    """Rewinding a sealed artifact to a height it covers must give the
    bytes a build stopped there would have written. Only the generation
    number and the scan counters may differ, and the identity covers
    neither."""
    full = _scan(tmp, "full")
    nn.run_merge(full)
    short = _scan(tmp, "short", end=3)
    fp_short = nn.run_merge(short)

    fp_rewound = nn.run_rewind(full, 3)
    assert fp_rewound == fp_short
    assert _merged_bytes(full) == _merged_bytes(short)

    # What survived is exactly the sightings at or below the cut.
    assert [nn.rec_height(r) for r in _records(full)] == [2, 3, 3, 2]

    state = nn._load_state(full)
    assert state["last_height"] == 3
    assert state["rewound_from"] == 5
    assert state["scan_stats"] is None          # a taller pass's counters


def test_rewind_refuses_to_move_forward_or_to_skip_the_fusion(tmp,
                                                              tiny_flush):
    nd = _scan(tmp, "refuse", end=3)
    # Never sealed: rewind works on the fused file, so it says so.
    with pytest.raises(nn.NonceError, match="has not been sealed yet"):
        nn.run_rewind(nd, 2)
    nn.run_merge(nd)
    # Sealed, then grown: the pending runs must be fused before a rewind
    # can mean anything, because they hold heights the file does not.
    _scan(tmp, "refuse", end=5, nonces_dir=nd,
          archive_dir=os.path.join(tmp, "refuse_archive"))
    with pytest.raises(nn.NonceError, match="run `nonces merge` first"):
        nn.run_rewind(nd, 2)
    nn.run_merge(nd)
    with pytest.raises(nn.NonceError, match="move it forward"):
        nn.run_rewind(nd, 5)
    with pytest.raises(nn.NonceError, match="move it forward"):
        nn.run_rewind(nd, 9)
    with pytest.raises(nn.NonceError, match="at least 1"):
        nn.run_rewind(nd, 0)


def test_verify_accepts_what_merge_sealed_and_rebuilds_the_ladder(
        tmp, tiny_flush, capsys):
    nd = _scan(tmp, "verify")
    nn.run_merge(nd)
    nn.run_verify(nd, deep=True)
    out = capsys.readouterr().out
    assert "records, non-decreasing" in out
    assert "cache, rebuilt from" in out          # the ladder, not itself
    assert "coverage 1..5" in out
    assert "fingerprint verified" in out


def test_verify_says_when_the_coverage_was_taken_on_trust(tmp, tiny_flush,
                                                          capsys):
    nd = _scan(tmp, "trust")
    nn.run_merge(nd)
    nn.run_verify(nd, deep=False)
    out = capsys.readouterr().out
    assert "taken on trust" in out and "--deep" in out


def test_verify_catches_a_flipped_byte(tmp, tiny_flush):
    nd = _scan(tmp, "rot")
    nn.run_merge(nd)
    state = nn._load_state(nd)
    path = os.path.join(nd, state["files"][nn.LOGICAL]["file"])
    with open(path, "r+b") as f:
        f.seek(3)
        f.write(bytes([f.read(1)[0] ^ 0x01]))
    with pytest.raises(nn.NonceError):
        nn.run_verify(nd, deep=False)


def test_open_sorted_refuses_a_corrupted_ladder(tmp, tiny_flush):
    """The ladder blob is checked against the sha the fusion recorded,
    like every other artifact's ladder: a rotted rung would otherwise
    steer the bisect wrong and make lookups answer short, silently."""
    nd = _scan(tmp, "lad")
    nn.run_merge(nd)
    state = nn._load_state(nd)
    path = os.path.join(nd, state["caches"][nn.LOGICAL]["file"])
    with open(path, "ab") as f:
        f.write(b"\x00")
    with pytest.raises(nn.NonceError, match="corrupted ladder"):
        nn.open_sorted(nd)


def test_verify_catches_a_moved_coverage_claim(tmp, tiny_flush):
    """The coverage is inside the identity, so inflating the watermark
    breaks the fingerprint. And with --deep the records contradict it
    from the other side."""
    nd = _scan(tmp, "cov")
    nn.run_merge(nd)
    path = os.path.join(nd, nn.MANIFEST_NAME)
    with open(path) as f:
        manifest = json.load(f)
    manifest["identity"]["coverage"]["to"] = 99
    with open(path, "w") as f:
        json.dump(manifest, f)
    with pytest.raises(nn.NonceError, match="fingerprint"):
        nn.run_verify(nd, deep=False)


def test_the_archive_is_unchanged_by_co_emitting_nonces(tmp, tiny_flush):
    """The plug shares the scriptSig pushes with the archive walk. That
    is an optimization, so the archive it produces must be the same
    artifact, to the fingerprint."""
    blocks = nonce_chain()
    fps = []
    for name, nonces_dir in (("with", os.path.join(tmp, "n")),
                             ("without", None)):
        ad = os.path.join(tmp, name + "_archive")
        server, url = trs.serve(blocks)
        try:
            ra.run_scan(url, "user:pass", 5, ad, batch_size=2,
                        checkpoint_every=2, nonces_dir=nonces_dir)
        finally:
            server.shutdown()
        fps.append(ra.run_merge(ad))
    assert fps[0] == fps[1]


def test_an_archive_ahead_of_its_host_re_emits_what_it_drops(tmp,
                                                              tiny_flush):
    """The crash window: this artifact checkpoints BEFORE the host, so a
    kill in between leaves it ahead. The host re-feeds those blocks, so
    the runs past its resume point must be dropped and rebuilt, landing
    on the very bytes of a clean pass."""
    reference = _scan(tmp, "ref")
    fp_ref = nn.run_merge(reference)

    ahead = os.path.join(tmp, "ahead_nonces")
    _scan(tmp, "ahead", end=4, nonces_dir=ahead)
    assert nn._load_state(ahead)["runs"], "expected unfused runs"
    # The host's own state is gone, so it rescans from height 1 while the
    # nonce archive still knows 1..4.
    _scan(tmp, "ahead2", end=5, nonces_dir=ahead,
          archive_dir=os.path.join(tmp, "ahead2_archive"))
    assert nn.run_merge(ahead) == fp_ref
    assert _merged_bytes(ahead) == _merged_bytes(reference)


def test_a_kill_between_the_fusion_and_its_seal_leaves_no_stale_seal(
        tmp, tiny_flush):
    """merge and rewind seal BEFORE they commit, so until the state is
    written the old generation is still the artifact and a kill costs
    only the work. And should a seal ever be missing anyway, `merge`
    reseals what the state commits instead of handing back a
    fingerprint whose file was deleted."""
    reference = _scan(tmp, "sealref")
    fp_ref = nn.run_merge(reference)

    nd = _scan(tmp, "sealkill")
    real_seal = nn._seal

    def flaky_seal(*a, **kw):
        raise RuntimeError("simulated kill before the seal")

    nn._seal = flaky_seal
    try:
        nn.run_merge(nd)
        pytest.fail("the simulated kill did not fire")
    except RuntimeError:
        pass
    finally:
        nn._seal = real_seal
    # Nothing was committed: no manifest, and the runs are all still
    # there to be fused again.
    assert nn._load_manifest(nd, required=False) is None
    assert nn._load_state(nd)["runs"]
    assert nn.run_merge(nd) == fp_ref
    assert _merged_bytes(nd) == _merged_bytes(reference)

    # The other half: a state that commits a fusion the manifest does
    # not describe (a crash in the old order, or a hand-edited seal).
    # merge must reseal rather than return the stale number.
    stale = json.load(open(os.path.join(nd, nn.MANIFEST_NAME)))
    stale["fingerprint"] = "de" * 32
    stale["build"]["files"][nn.LOGICAL]["sha256"] = "ad" * 32
    with open(os.path.join(nd, nn.MANIFEST_NAME), "w") as f:
        json.dump(stale, f)
    assert nn.run_merge(nd) == fp_ref
    nn.run_verify(nd, deep=True)


def test_an_archive_ahead_of_its_host_does_not_count_twice(tmp,
                                                           tiny_flush):
    """The heal drops the ahead runs' records, so the counters that
    described them must step back too: the host is about to feed those
    blocks again. The sealed scan_stats of a healed archive must equal
    the one an uninterrupted pass writes."""
    reference = _scan(tmp, "statsref")
    nn.run_merge(reference)
    ref_stats = nn._load_manifest(reference)["build"]["scan_stats"]

    ahead = os.path.join(tmp, "ahead_stats_nonces")
    _scan(tmp, "ahead_stats", end=4, nonces_dir=ahead)
    # The host's state is gone, so it rescans from 1 while this archive
    # knows 1..4: the ahead case, with counters to match.
    assert nn._load_state(ahead)["scan_stats"]["nonces_ecdsa"] > 0
    _scan(tmp, "ahead_stats2", end=5, nonces_dir=ahead,
          archive_dir=os.path.join(tmp, "ahead_stats2_archive"))
    nn.run_merge(ahead)
    assert nn._load_manifest(ahead)["build"]["scan_stats"] == ref_stats
    assert _merged_bytes(ahead) == _merged_bytes(reference)


def test_the_step_back_reads_a_snapshot_and_not_the_live_counters(tmp,
                                                                  tiny_flush):
    """The heal above resumes from 1, so it zeroes the counters outright.
    A real crash lands on the other branch: the host resumes one block
    past its own checkpoint, and the step-back reads `scan_stats_prev`.

    That snapshot has to be a COPY. Held as a reference to the live
    counter dict, it would keep growing with it, the step-back would
    restore the very numbers it means to undo, and the re-fed interval
    would be counted twice in a state that looks perfectly consistent.
    """
    reference = _scan(tmp, "stepref")
    nn.run_merge(reference)
    ref_stats = nn._load_manifest(reference)["build"]["scan_stats"]

    nd = os.path.join(tmp, "stepback_nonces")
    ad = os.path.join(tmp, "stepback_archive")
    snap = os.path.join(tmp, "stepback_host_at_2")
    _scan(tmp, "stepback", end=2, nonces_dir=nd, archive_dir=ad)
    shutil.copytree(ad, snap)
    _scan(tmp, "stepback", end=4, nonces_dir=nd, archive_dir=ad)
    # The crash: this archive's checkpoint at 4 landed, the host's did
    # not, so the host is back at 2 and about to feed 3 and 4 again.
    shutil.rmtree(ad)
    shutil.copytree(snap, ad)
    assert ra._load_state(ad)["last_height"] == 2
    assert nn._load_state(nd)["last_height"] == 4

    _scan(tmp, "stepback", end=5, nonces_dir=nd, archive_dir=ad)
    nn.run_merge(nd)
    assert nn._load_manifest(nd)["build"]["scan_stats"] == ref_stats
    assert _merged_bytes(nd) == _merged_bytes(reference)


def test_emission_cannot_start_midway_and_a_fusion_cannot_be_undone(tmp,
                                                                    tiny_flush):
    fresh = os.path.join(tmp, "fresh_nonces")
    with pytest.raises(nn.NonceError, match="cannot be turned on midway"):
        nn.NonceEmitter(fresh).load(7)

    nd = _scan(tmp, "sealed")
    nn.run_merge(nd)
    with pytest.raises(nn.NonceError, match="rewind --to-height 2"):
        nn.NonceEmitter(nd).load(3)


def test_lookup_answers_from_the_ladder(tmp, tiny_flush):
    nd = _scan(tmp, "lookup")
    nn.run_merge(nd)
    # A full 32-byte r is accepted and truncated: what a reader pastes.
    sink = io.StringIO()
    nn.run_lookup(nd, [NONCE_B.to_bytes(32, "big").hex(),
                       point_of(NONCE_C).hex(),
                       "ff" * nn.R_PREFIX], out=sink)
    out = sink.getvalue()
    assert "height         3" in out and "height         5" in out
    assert "REPEATED: 2 sightings" in out
    assert "not published in confirmed blocks 1..5" in out
    assert "candidate" in out


def test_lookup_refuses_a_value_too_short_to_be_a_key(tmp, tiny_flush):
    nd = _scan(tmp, "short_key")
    nn.run_merge(nd)
    with pytest.raises(nn.NonceError, match="at least 12 bytes"):
        nn.run_lookup(nd, ["aabb"])


def test_lookup_and_groups_include_the_unfused_runs(tmp, tiny_flush):
    """Both readers claim coverage up to the state's watermark, and the
    scan advances that watermark past the last merge — so a point that
    lives only in a pending run must be FOUND, not reported as never
    published over a range that was never searched."""
    nd = _scan(tmp, "pending", end=3)
    nn.run_merge(nd)
    # The SAME host archive, so the scan resumes at 4 and the nonce
    # archive grows runs on top of the fusion.
    _scan(tmp, "pending", end=5, nonces_dir=nd,
          archive_dir=os.path.join(tmp, "pending_archive"))
    state = nn._load_state(nd)
    assert state["runs"], "the second leg must leave unfused runs"
    assert state["last_height"] > state["merged_height"]

    # A point whose SECOND sighting lives only in a pending run: to a
    # fused-only reader it is a singleton, and the repetition — the one
    # thing this artifact exists to report — disappears.
    fused = [nn.rec_point(r) for r in nn.iter_records(nd)]
    in_runs = [nn.rec_point(r) for r in _records_of_runs(nd)]
    repeated = [p for p in in_runs if p in fused and not nn.is_tiny(p)]
    assert repeated, "the pending runs must repeat a fused point"
    point = repeated[0]

    sink = io.StringIO()
    nn.run_lookup(nd, [point.hex()], out=sink)
    out = sink.getvalue()
    assert "unfused run(s) included" in out
    assert "REPEATED: 2 sightings" in out, out
    assert f"height {state['last_height']:>9,}" in out, out

    sink = io.StringIO()
    nn.run_groups(nd, out=sink)
    text = sink.getvalue()
    scanned = len(list(nn.iter_records(nd))) + len(_records_of_runs(nd))
    assert f"({scanned:,} signatures)" in text, text
    assert "unfused run(s) included" in text

    # And after the fusion the two readers say the same thing, minus
    # the note: the runs were never a different answer.
    nn.run_merge(nd)
    sink = io.StringIO()
    nn.run_groups(nd, out=sink)
    after = sink.getvalue()
    assert f"({scanned:,} signatures)" in after
    assert "unfused run(s)" not in after


def test_lookup_skips_a_value_that_is_not_hex(tmp, tiny_flush):
    """A list of pasted values must not die on its one typo: the bad
    value is named and skipped, and the ones after it are still
    answered — same manners as the archive's lookup."""
    nd = _scan(tmp, "not_hex")
    nn.run_merge(nd)
    sink = io.StringIO()
    nn.run_lookup(nd, ["not-hex-at-all", point_of(NONCE_C).hex()],
                  out=sink)
    out = sink.getvalue()
    assert "not-hex-at-all: not hex, skipped" in out
    assert point_of(NONCE_C).hex() in out


def test_merge_is_a_no_op_with_nothing_new(tmp, tiny_flush, capsys):
    nd = _scan(tmp, "noop")
    first = nn.run_merge(nd)
    assert nn.run_merge(nd) == first
    assert "nothing to fuse" in capsys.readouterr().out


def test_a_chain_with_no_signature_still_seals(tmp, tiny_flush):
    """An honestly empty artifact is a valid one: the fixture chain of the
    other tests has no real DER signature in it at all."""
    blocks = trs.build_chain()
    nd = os.path.join(tmp, "empty_nonces")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, os.path.join(tmp, "empty_archive"),
                    batch_size=2, checkpoint_every=2, nonces_dir=nd)
    finally:
        server.shutdown()
    fp = nn.run_merge(nd)
    assert fp and _records(nd) == []
    nn.run_verify(nd, deep=True)


# --- the deep audit, on files built by hand -------------------------------

def _handmade(tmp, records, last_height, name="hand"):
    """A sealed artifact whose bytes the test chose. The seal is real
    (same code path as `merge`), so what the audit then refuses is the
    content and not a broken manifest."""
    d = os.path.join(tmp, name)
    os.makedirs(d, exist_ok=True)
    state = {"format": nn.FORMAT_TAG, "last_height": last_height,
             "merged_height": last_height, "last_block_hash": None,
             "scan_stats": None, "rewound_from": None}
    state.update(nn.new_state_fields())
    blob = b"".join(records)
    file_name = "nonces_g0001.bin"
    with open(os.path.join(d, file_name), "wb") as f:
        f.write(blob)
    state["generation"] = 1
    state["files"][nn.LOGICAL] = {
        "file": file_name, "records": len(records),
        "sha256": hashlib.sha256(blob).hexdigest()}
    with open(os.path.join(d, nn.STATE_NAME), "w") as f:
        json.dump(state, f)
    manifest = nn._seal(d, state, nn._tallies(d, state),
                        WallClock("merge", state))
    return d, state, manifest


def test_the_deep_audit_refuses_broken_content(tmp):
    good = sorted([nn.record(point_of(NONCE_A), 2, nn.FLAG_ECDSA),
                   nn.record(point_of(NONCE_B), 3, nn.FLAG_ECDSA)])
    d, state, manifest = _handmade(tmp, good, 5, "hand_ok")
    assert nn._audit_records(d, manifest, state) == 3      # the floor

    # Out of order: every lookup and every fusion depends on the order.
    d, state, manifest = _handmade(tmp, list(reversed(good)), 5, "hand_order")
    with pytest.raises(nn.NonceError, match="breaks the order"):
        nn._audit_records(d, manifest, state)

    # No scheme at all, a sighash code with no scheme under it, both
    # schemes at once (a record is ONE signature), and a bit outside the
    # five the format defines.
    for flags in (0, sighash_bits(0x01), nn.SCHEME_MASK,
                  FLAG_ECDSA | 0x20):
        d, state, manifest = _handmade(
            tmp, [nn.record(point_of(NONCE_A), 2, flags)], 5,
            f"hand_flags{flags}")
        with pytest.raises(nn.NonceError, match="defined schemes"):
            nn._audit_records(d, manifest, state)

    # Schnorr with a nonstandard sighash code: taproot's byte is
    # consensus-constrained to the six standard values, so this is a
    # claim the chain cannot produce.
    d, state, manifest = _handmade(
        tmp, [nn.record(point_of(NONCE_A), 2,
                        FLAG_SCHNORR | (SIGHASH_OTHER << nn.SIGHASH_SHIFT))],
        5, "hand_schnorr_other")
    with pytest.raises(nn.NonceError, match="nonstandard sighash"):
        nn._audit_records(d, manifest, state)

    # A height above the declared coverage.
    d, state, manifest = _handmade(
        tmp, [nn.record(point_of(NONCE_A), 9, nn.FLAG_ECDSA)], 5,
        "hand_height")
    with pytest.raises(nn.NonceError, match="outside the declared coverage"):
        nn._audit_records(d, manifest, state)


def test_equal_records_are_legal(tmp):
    """Two signatures can share a nonce inside ONE block, so an audit
    that demanded strictly increasing records would refuse exactly the
    finding this artifact exists to record."""
    twice = [nn.record(point_of(NONCE_TINY), 2, nn.FLAG_ECDSA)] * 2
    d, state, manifest = _handmade(tmp, twice, 5, "hand_equal")
    assert nn._audit_records(d, manifest, state) == 2
    assert manifest["build"]["tallies"]["repeated_points"] == 1
    assert manifest["build"]["tallies"]["repeat_sightings"] == 1


# ===========================================================================
# `nonces address`: the owner's question instead of the chain's
# ===========================================================================
# This needs a chain where the addresses really own their outputs, because
# the whole point of the command is the join: the derivatives say which of a
# lock's outputs were spent and by which transaction, the index turns that
# into a height and a txid, and the node hands back the block so the
# signature can be read. An outpoint names ONE input of ONE transaction, so
# nothing here guesses which signature belongs to the address being asked
# about.
#
# The chain below gives every branch of the answer a case:
#
#   ADDR_KEY    a single-key lock that signs twice with ONE nonce, in two
#               different blocks: the conclusive finding;
#   ADDR_SCRIPT a script lock that signs twice with one nonce: real
#               collision, but attribution needs verifying signatures, so
#               the report must refuse to conclude;
#   ADDR_ONCE   a lock that signed exactly once: nothing can repeat with
#               itself, and the report says so rather than staying silent;
#   ADDR_QUIET  a lock that received and never spent: it has never signed;
#   ADDR_COPY   a single-key lock whose two spends carry the SAME signature
#               byte for byte. The point repeats, so the census counts it
#               and must, but one `s` means one signed message and no key
#               follows: the case that separates a repeated nonce from a
#               copied signature, which the chain really does contain
#               (the SIGHASH_SINGLE bug lets one signature satisfy every
#               input of a transaction);
#   ADDR_NEG    a single-key lock whose two spends carry s and n-s: the
#               SAME signature in its two legal forms, from nonces k and
#               -k over one message. The bytes differ, the information
#               does not, and comparing raw `s` would call it exposed.

from nodsig import derivatives as dv
from nodsig import outpoint_index as oi
import test_outpoint_index as toi

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(version, payload):
    """An independent base58check encoder, so the test builds the address
    string and `check_addresses` decodes it: two directions written apart,
    which is the mirror discipline the parser tests use."""
    from nodsig.hashing import sha256d
    raw = bytes([version]) + payload
    raw += sha256d(raw)[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


H_KEY = bytes(range(20))                       # hash160 of a single key
H_SCRIPT = bytes(range(20, 40))                # hash160 of a redeem script
H_ONCE = bytes(range(40, 60))
H_QUIET = bytes(range(60, 80))
H_COPY = bytes(range(100, 120))
H_NEG = bytes(range(120, 140))

ADDR_KEY = b58check(0x00, H_KEY)
ADDR_SCRIPT = b58check(0x05, H_SCRIPT)
ADDR_ONCE = b58check(0x00, H_ONCE)
ADDR_QUIET = b58check(0x00, H_QUIET)
ADDR_COPY = b58check(0x00, H_COPY)
ADDR_NEG = b58check(0x00, H_NEG)

SPK_KEY = b"\x76\xa9\x14" + H_KEY + b"\x88\xac"
SPK_SCRIPT = b"\xa9\x14" + H_SCRIPT + b"\x87"
SPK_ONCE = b"\x76\xa9\x14" + H_ONCE + b"\x88\xac"
SPK_QUIET = b"\x76\xa9\x14" + H_QUIET + b"\x88\xac"
SPK_COPY = b"\x76\xa9\x14" + H_COPY + b"\x88\xac"
SPK_NEG = b"\x76\xa9\x14" + H_NEG + b"\x88\xac"

N_REUSED = 0x66f1c4b0e5d3a27681f0c5d4e3b2a1908f7e6d5c4b3a291807162534435261a0
N_SCRIPT = 0x1199aabbccddeeff00112233445566778899aabbccddeeff0011223344556677
N_COPY = 0x2a7b3c4d5e6f70819202a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8
N_NEG = 0x5f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a697887a6b5c4d3e2f100
# s and n-s: the two legal forms of ONE signature. Found on the real
# chain (one pair in ~1,600) while auditing the exposure criterion.
S_NEG = nn.CURVE_ORDER - S1
REDEEM = (bytes([0x52, 33]) + PUB + bytes([33]) + PUB
          + bytes([33]) + PUB + bytes([0x53, 0xAE]))       # 2-of-3


def address_chain():
    """Five blocks in which four locks receive, and three of them spend.

    h1  cb1 pays KEY 50, ONCE 50, QUIET 50
    h2  t1 spends KEY (nonce N_REUSED) and pays KEY 20, SCRIPT 20
    h3  t2 spends KEY again (nonce N_REUSED once more) and pays SCRIPT 10
    h4  t3 spends SCRIPT with two signatures sharing N_SCRIPT
        t3b spends COPY (nonce N_COPY, s S1)
        t3c spends NEG  (nonce N_NEG,  s S1)
    h5  t4 spends ONCE with the SAME nonce KEY reused, which is how a
        point in the census comes to belong to another lock
        t4b spends COPY again with the SAME signature bytes as t3b
        t4c spends NEG again with s = n-S1: one signature, two forms
    """
    blocks, txids = {}, {}
    prev = bytes(32)

    def add(height, raw_txs, ids):
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_700_000_000 + height,
                                      0x1700_0000, height, raw_txs, ids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())

    def p2pkh_sig(nonce, s):
        return push(der(minimal(nonce), minimal(s))) + push(PUB)

    cb1, cb1_id, _ = toi._coinbase(
        b"\x01a", [tbw.w_output(50, SPK_KEY), tbw.w_output(50, SPK_ONCE),
                   tbw.w_output(50, SPK_QUIET), tbw.w_output(50, SPK_COPY),
                   tbw.w_output(50, SPK_NEG)])
    add(1, [cb1], [cb1_id])
    txids["cb1"] = cb1_id

    cb2, cb2_id, _ = toi._coinbase(b"\x01b", [tbw.w_output(50, SPK_QUIET)])
    t1, t1_id, _ = tbw.w_tx(
        1, [tbw.w_input(cb1_id, 0, p2pkh_sig(N_REUSED, S1), 0xFFFFFFFF)],
        [tbw.w_output(20, SPK_KEY), tbw.w_output(20, SPK_SCRIPT)], 0)
    add(2, [cb2, t1], [cb2_id, t1_id])
    txids["t1"] = t1_id

    cb3, cb3_id, _ = toi._coinbase(b"\x01c", [tbw.w_output(50, SPK_QUIET)])
    t2, t2_id, _ = tbw.w_tx(
        1, [tbw.w_input(t1_id, 0, p2pkh_sig(N_REUSED, S2), 0xFFFFFFFF)],
        [tbw.w_output(10, SPK_SCRIPT)], 0)
    add(3, [cb3, t2], [cb3_id, t2_id])
    txids["t2"] = t2_id

    cb4, cb4_id, _ = toi._coinbase(b"\x01d", [tbw.w_output(50, SPK_QUIET)])
    script_sig = (b"\x00" + push(der(minimal(N_SCRIPT), minimal(S1)))
                  + push(der(minimal(N_SCRIPT), minimal(S2)))
                  + b"\x4c" + bytes([len(REDEEM)]) + REDEEM)
    t3, t3_id, _ = tbw.w_tx(
        1, [tbw.w_input(t1_id, 1, script_sig, 0xFFFFFFFF)],
        [tbw.w_output(15, SPK_QUIET)], 0)
    # The copied signature: built ONCE and spent into COPY again, so the
    # very same bytes appear in the next block.
    copy_sig = p2pkh_sig(N_COPY, S1)
    t3b, t3b_id, _ = tbw.w_tx(
        1, [tbw.w_input(cb1_id, 3, copy_sig, 0xFFFFFFFF)],
        [tbw.w_output(40, SPK_COPY)], 0)
    t3c, t3c_id, _ = tbw.w_tx(
        1, [tbw.w_input(cb1_id, 4, p2pkh_sig(N_NEG, S1), 0xFFFFFFFF)],
        [tbw.w_output(40, SPK_NEG)], 0)
    add(4, [cb4, t3, t3b, t3c], [cb4_id, t3_id, t3b_id, t3c_id])
    txids["t3"] = t3_id
    txids["t3b"] = t3b_id

    cb5, cb5_id, _ = toi._coinbase(b"\x01e", [tbw.w_output(50, SPK_QUIET)])
    t4, t4_id, _ = tbw.w_tx(
        1, [tbw.w_input(cb1_id, 1, p2pkh_sig(N_REUSED, S1), 0xFFFFFFFF)],
        [tbw.w_output(45, SPK_QUIET)], 0)
    t4b, t4b_id, _ = tbw.w_tx(
        1, [tbw.w_input(t3b_id, 0, copy_sig, 0xFFFFFFFF)],
        [tbw.w_output(35, SPK_QUIET)], 0)
    t4c, t4c_id, _ = tbw.w_tx(
        1, [tbw.w_input(t3c_id, 0, p2pkh_sig(N_NEG, S_NEG), 0xFFFFFFFF)],
        [tbw.w_output(35, SPK_QUIET)], 0)
    add(5, [cb5, t4, t4b, t4c], [cb5_id, t4_id, t4b_id, t4c_id])
    txids["t4"] = t4_id
    txids["t4b"] = t4b_id
    return blocks, txids


@pytest.fixture
def owner_setup(tmp):
    """(index, derived, nonces, client) over `address_chain`, built through
    the real host paths: a graph for the index, a census for the
    cross-check, and a fake node that serves the same chain again because
    the signatures live only in the blocks."""
    blocks, _txids = address_chain()
    graph = toi.emit_graph(tmp, blocks, "owner_graph")
    index = os.path.join(tmp, "owner_index")
    oi.run_build(graph, index)
    derived = os.path.join(tmp, "owner_derived")
    dv.run_build(index, derived)

    census = os.path.join(tmp, "owner_nonces")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 5, os.path.join(tmp, "owner_archive"),
                    batch_size=2, checkpoint_every=2, nonces_dir=census)
    finally:
        server.shutdown()
    nn.run_merge(census)

    server, url = trs.serve(blocks)
    client = trs.rs.RpcClient(url, "user:pass")
    yield index, derived, census, client, server
    server.shutdown()


def _ask(owner_setup, address, with_census=True):
    index, derived, census, client, _server = owner_setup
    sink = io.StringIO()
    findings = nn.run_address([address], index, derived, client,
                              nonces_dir=census if with_census else None,
                              out=sink)
    return sink.getvalue(), findings


def test_a_single_key_lock_that_repeated_a_nonce_is_told_plainly(owner_setup):
    text, findings = _ask(owner_setup, ADDR_KEY)
    assert findings == 1
    assert "2 signature(s) read from 2 block(s)" in text
    assert f"REPEATED NONCE {point_of(N_REUSED).hex()}" in text
    assert "at heights 2, 3" in text
    assert "opened by ONE key" in text
    assert "the private key follows" in text


def test_a_script_lock_collision_is_reported_without_a_conclusion(
        owner_setup):
    """Two signatures in one P2SH input share a nonce. The collision is
    real; which cosigner signed is not knowable without verifying
    signatures, and the report must say so instead of implying a key."""
    text, findings = _ask(owner_setup, ADDR_SCRIPT)
    assert findings == 1
    assert f"REPEATED NONCE {point_of(N_SCRIPT).hex()}" in text
    assert "can be opened by several keys" in text
    assert "the conclusion is not automatic" in text
    assert "opened by ONE key" not in text


def test_a_copied_signature_is_not_a_key_recovery(owner_setup):
    """The lock is single-key and its nonce point repeats, which is every
    condition the old report checked before announcing that the private
    key follows. It does not: both spends carry the SAME signature, so
    they signed ONE message, and two equations that are the same equation
    solve nothing.

    This is not a contrived case. It is what the chain's largest repeated
    point actually is: the SIGHASH_SINGLE bug fixes the signed message to
    a constant, so one signature satisfies every input, and a single
    2015 block carries thousands of copies of three signatures.
    """
    text, findings = _ask(owner_setup, ADDR_COPY)
    assert findings == 1                       # the point DOES repeat
    assert f"REPEATED NONCE {point_of(N_COPY).hex()}" in text
    assert "at heights 4, 5" in text
    assert "IDENTICAL each time" in text
    assert "Nothing follows from it" in text
    # The claim that would be false here, in either of its wordings.
    assert "the private key follows" not in text
    assert "opened by ONE key" not in text


def test_s_and_its_negation_are_one_signature_not_two(owner_setup):
    """The hole the copied-signature fix still left open.

    Nonces k and -k give points R and -R, which share an x-coordinate and
    therefore publish the SAME r. Over one message they yield s and n-s:
    two different `s` values, one signed message, and no key. Comparing
    raw `s` would call this exposed and announce a recovery that does not
    exist, so the comparison folds s with n-s first.

    Not hypothetical: over the chain's own repeated points this occurs
    about once in 1,600 (point, key) pairs. Low-s is relay policy, not
    consensus, so the high-s form is on the chain and always may be.
    """
    text, findings = _ask(owner_setup, ADDR_NEG)
    assert findings == 1                       # the point DOES repeat
    assert f"REPEATED NONCE {point_of(N_NEG).hex()}" in text
    assert "at heights 4, 5" in text
    assert "s and n-s" in text
    assert "Nothing follows from it" in text
    assert "the private key follows" not in text
    assert "opened by ONE key" not in text
    # And it is NOT the byte-identical case: the report must not say so.
    assert "IDENTICAL each time" not in text


def test_the_conclusive_finding_says_the_signatures_differ(owner_setup):
    """The other side of the same coin: KEY's two spends carry DIFFERENT
    signatures, and the report must now say so, because that difference
    is the whole reason a key follows."""
    text, _ = _ask(owner_setup, ADDR_KEY)
    assert "the signatures differ" in text
    assert "different messages" in text
    assert "IDENTICAL each time" not in text


def test_one_signature_cannot_repeat_with_itself(owner_setup):
    text, findings = _ask(owner_setup, ADDR_ONCE)
    assert findings == 0
    assert "1 signature(s) read from 1 block(s)" in text
    assert "one signature only" in text


def test_a_lock_that_never_spent_has_never_signed(owner_setup):
    text, findings = _ask(owner_setup, ADDR_QUIET)
    assert findings == 0
    assert "has never signed" in text
    assert "REPEATED" not in text


def test_the_report_names_the_index_watermark_and_the_lock(owner_setup):
    """Source, as everywhere else here: the answer is as of the
    index's height, and the lock is the honest boundary (one script, not
    a wallet)."""
    from nodsig.check_addresses import script_pubkey, decode_address
    from nodsig.hashing import hash160
    text, _ = _ask(owner_setup, ADDR_KEY)
    lock = hash160(script_pubkey(decode_address(ADDR_KEY)))
    assert lock.hex() in text
    assert "index through height 5" in text


def test_the_census_names_sightings_that_are_not_this_lock_s(owner_setup):
    """The census answers the other half: the same point published by
    somebody else's signature. Two DIFFERENT keys sharing a nonce hands
    neither one over, and the line has to say exactly that instead of
    letting it read like a second finding."""
    # ONCE signed once, so it has no repeat of its own, and the very point
    # it used was published twice more by KEY.
    text, findings = _ask(owner_setup, ADDR_ONCE)
    assert findings == 0
    assert "one signature only" in text
    assert f"census: {point_of(N_REUSED).hex()} was also published 2 time" \
        in text
    assert "does not hand either one over" in text

    # The script lock's nonce is its own alone: the line must stay silent
    # rather than count the lock's own signatures as strangers.
    assert "census:" not in _ask(owner_setup, ADDR_SCRIPT)[0]

    # And with no census plugged in, no such line either way.
    assert "census:" not in _ask(owner_setup, ADDR_ONCE,
                                 with_census=False)[0]


def test_max_blocks_refuses_instead_of_fetching_a_chain(owner_setup):
    index, derived, census, client, _server = owner_setup
    with pytest.raises(nn.NonceError, match="--max-blocks"):
        nn.run_address([ADDR_KEY], index, derived, client, max_blocks=1,
                       out=io.StringIO())


def test_an_address_this_chain_never_saw_is_answered_not_guessed(
        owner_setup):
    index, derived, census, client, _server = owner_setup
    stranger = b58check(0x00, bytes(range(80, 100)))
    sink = io.StringIO()
    assert nn.run_address([stranger], index, derived, client,
                          out=sink) == 0
    assert "has never signed" in sink.getvalue()
