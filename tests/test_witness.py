"""Tests for witness.py: the evidence that resolves a repeated point.

What is worth pinning here, and why each case exists:

- every resolution and every attribution class must come out of the SAME
  synthetic chain, because a resolution is only useful if it separates
  cases that look identical to the census. The chain below repeats ten
  points; four expose a key, and each exposure is attributed a different
  way (a key beside the signature, the key in a spent P2PK output, a
  position in an m-of-m redeem script, a slot of a tapscript template);
- `exposed` must require all four conditions, and each one has its own
  test, because each was a real defect once: the full `r` (not the
  truncated point), the same `x` (not the same lock type, and not the
  same serialization), a different (scheme, s) with the ECDSA `s`
  canonical and the Schnorr `s` as published, and attributed rows only;
- a table must re-derive its own resolutions on `verify`, so a file that
  rots into a different meaning is caught by more than a checksum;
- the declared parent must be confronted, because a witness table beside
  a different census answers about something else entirely; and the
  index must cover the census, or the bytes would depend on which index
  was given.
"""

import csv as csvmod
import io
import json
import os

import pytest

from nodsig import blockparse as bp
from nodsig import nonces as nn
from nodsig import outpoint_index as oi
from nodsig import reveal_archive as ra
from nodsig import witness as wt
from nodsig.hashing import hash160

import test_blockparse as tbw
import test_nonces as tn
import test_outpoint_index as toi
import test_reuse_scan as trs

R_A = bytes(range(32))
R_B = bytes(range(1, 33))
X_1 = bytes(range(32, 64))
X_2 = bytes(range(64, 96))
S_1 = bytes(31) + b"\x01"
S_2 = bytes(31) + b"\x02"


def row(r=R_A, x=X_1, s=S_1, count=2, height=7, flags=0, key_seen=b""):
    """An attributed BESIDE row unless the flags say otherwise."""
    return wt.record(r, x, key_seen, s, count, height, flags)


def none_row(r=R_A, s=S_1, ambiguous=False, height=7, count=1):
    flags = wt.NONE << wt.ATTR_SHIFT
    if ambiguous:
        flags |= wt.FLAG_AMBIGUOUS
    return wt.record(r, b"", b"", s, count, height, flags)


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

def test_a_row_round_trips_every_field():
    seen = bytes(range(20))
    rec = row(count=38_718, height=364_773, key_seen=seen,
              flags=wt.FLAG_HIGH_S | wt.FLAG_UNCOMPRESSED | wt.FLAG_ODD_Y)
    assert wt.rec_r(rec) == R_A
    assert wt.rec_x(rec) == X_1
    assert wt.rec_key_seen(rec) == seen
    assert wt.rec_s(rec) == S_1
    assert wt.rec_count(rec) == 38_718
    assert wt.rec_height(rec) == 364_773
    assert wt.rec_flags(rec) == (wt.FLAG_HIGH_S | wt.FLAG_UNCOMPRESSED
                                 | wt.FLAG_ODD_Y)
    assert wt.rec_class(rec) == wt.BESIDE
    assert len(rec) == wt.REC == 124
    # The join key back to the census is the truncation, not a stored field.
    assert wt.rec_point(rec) == R_A[:nn.R_PREFIX]
    # And the digest every other artifact keys the point by is derived:
    # the parity bit picks the lead byte.
    assert wt.rec_key_canon(rec) == hash160(b"\x03" + X_1)
    assert wt.rec_key_canon(row()) == hash160(b"\x02" + X_1)
    assert wt.rec_key_canon(row(flags=wt.FLAG_XONLY)) == hash160(b"\x02" + X_1)
    assert wt.rec_form(rec) == "uncompressed"
    assert wt.rec_form(row(flags=wt.FLAG_XONLY)) == "xonly"


def test_a_row_refuses_what_it_cannot_mean():
    """Every rule the page lists for `witness-verify`, refused at the
    writer too, so a row that means nothing is never written."""
    with pytest.raises(wt.WitnessError):
        wt.record(R_A[:16], X_1, b"", S_1, 2, 7, 0)       # r must be whole
    with pytest.raises(wt.WitnessError, match="if and only if the class"):
        wt.record(R_A, X_1, b"", S_1, 2, 7, wt.NONE << wt.ATTR_SHIFT)
    with pytest.raises(wt.WitnessError, match="if and only if the class"):
        wt.record(R_A, b"", b"", S_1, 2, 7, 0)             # BESIDE without x
    with pytest.raises(wt.WitnessError, match="UNCOMPRESSED"):
        wt.record(R_A, X_1, bytes(range(20)), S_1, 2, 7, 0)
    with pytest.raises(wt.WitnessError, match="UNCOMPRESSED"):
        row(flags=wt.FLAG_UNCOMPRESSED)                    # no key_seen
    with pytest.raises(wt.WitnessError, match="never together"):
        row(flags=wt.FLAG_UNCOMPRESSED | wt.FLAG_XONLY,
            key_seen=bytes(range(20)))
    with pytest.raises(wt.WitnessError, match="HIGH_S"):
        row(flags=wt.FLAG_HIGH_S | wt.FLAG_SCHNORR)
    with pytest.raises(wt.WitnessError, match="ODD_Y"):
        row(flags=wt.FLAG_ODD_Y | wt.FLAG_XONLY)
    with pytest.raises(wt.WitnessError, match="AMBIGUOUS"):
        row(flags=wt.FLAG_AMBIGUOUS)                       # not a NONE row


def test_an_absent_key_is_stored_as_absence_not_as_zero_the_value():
    rec = none_row()
    assert wt.rec_x(rec) == bytes(wt.X_LEN)
    assert not wt.has_key(rec)
    assert wt.rec_key_canon(rec) is None


def test_r_outside_its_range_is_refused_per_scheme():
    """`r` is the x-coordinate of k*G taken mod n for ECDSA, so
    0 < r < n. A BIP 340 R.x is a field element and may sit between n
    and p (see `nonces.taproot_r`), so the Schnorr rule is r < p."""
    zero = bytes(32)
    at_n = nn.CURVE_ORDER.to_bytes(32, "big")
    with pytest.raises(wt.WitnessError, match="range"):
        row(r=zero)
    with pytest.raises(wt.WitnessError, match="range"):
        row(r=at_n)
    assert wt.rec_r(row(r=(nn.CURVE_ORDER - 1).to_bytes(32, "big")))
    # Between n and p: a legal Schnorr R.x, and never an ECDSA r.
    assert wt.rec_flags(row(r=at_n, flags=wt.FLAG_SCHNORR)) == wt.FLAG_SCHNORR
    with pytest.raises(wt.WitnessError, match="range"):
        row(r=b"\xff" * 32, flags=wt.FLAG_SCHNORR)
    # And no threshold on SIZE: r = 1 is legal, absurd, and kept.
    assert wt.rec_r(row(r=bytes(31) + b"\x01")) == bytes(31) + b"\x01"


# ---------------------------------------------------------------------------
# The resolution: the four conditions, one test each
# ---------------------------------------------------------------------------

def test_exposed_needs_two_different_scheme_s_pairs():
    res = wt.resolution_of([row(s=S_1), row(s=S_2)])
    assert res.kind == wt.EXPOSED and res.exposed == (X_1,)
    # One `s`, twice: the same signature published again. Nothing follows,
    # and this is what the chain's largest group actually is.
    assert wt.resolution_of([row(s=S_1), row(s=S_1)]).kind == wt.COPIED
    # An ECDSA s and a Schnorr s that are numerically equal are still two
    # signatures: the scheme travels in the pair.
    res = wt.resolution_of([row(s=S_1), row(s=S_1, flags=wt.FLAG_SCHNORR)])
    assert res.kind == wt.EXPOSED


def test_s_and_its_negation_never_reach_the_resolution_as_two():
    """The rows carry min(s, n-s) for ECDSA, so the pair folds before it
    is compared. Nonces k and -k publish the same r over one message and
    give s and n-s; comparing the serialized values would call that
    exposed and announce a recovery that does not exist."""
    s = 0x00c0ffee00000000000000000000000000000000000000000000000000000001
    high = (nn.CURVE_ORDER - s).to_bytes(32, "big")
    low = s.to_bytes(32, "big")
    assert nn.canonical_s(high) == nn.canonical_s(low)
    canon = nn.canonical_s(low)
    assert wt.resolution_of([row(s=canon), row(s=canon)]).kind == wt.COPIED


def test_exposed_needs_the_same_x_not_merely_one_point():
    res = wt.resolution_of([row(x=X_1, s=S_1), row(x=X_2, s=S_2)])
    assert res.kind == wt.DISTINCT_KEYS
    assert res.exposed == ()
    # And the resolution is per (r, x): one point can carry a key that
    # is exposed beside keys that are not, which is what the chain does.
    res = wt.resolution_of([row(x=X_1, s=S_1), row(x=X_1, s=S_2),
                            row(x=X_2, s=S_1)])
    assert res.kind == wt.EXPOSED
    assert res.exposed == (X_1,)
    # The serialization is not the identity: a key seen at 65 bytes and
    # at 33 is ONE x, and two different s under it expose it.
    seen65 = row(x=X_1, s=S_2, key_seen=bytes(range(20)),
                 flags=wt.FLAG_UNCOMPRESSED)
    res = wt.resolution_of([row(x=X_1, s=S_1), seen65])
    assert res.kind == wt.EXPOSED and res.exposed == (X_1,)


def test_a_resolution_is_over_one_scalar_never_over_the_census_prefix():
    """The census truncates to 12 bytes; the table keeps the whole
    scalar precisely so two scalars under one prefix are two
    resolutions, not one `prefix-collision` swallowing an exposure."""
    other = R_A[:nn.R_PREFIX] + bytes(32 - nn.R_PREFIX) + b""
    other = other[:-1] + b"\x01"
    assert other[:nn.R_PREFIX] == R_A[:nn.R_PREFIX] and other != R_A
    with pytest.raises(wt.WitnessError, match="ONE full r"):
        wt.resolution_of([row(r=R_A, s=S_1), row(r=other, s=S_2)])
    assert wt.resolution_of([row(r=R_A, s=S_1), row(r=R_A, s=S_2)]).kind \
        == wt.EXPOSED


def test_a_none_row_with_the_same_signature_does_not_block_one_signature():
    """The same (r, s) from a second key would need a targeted preimage,
    so a NONE row carrying the attributed row's own (scheme, s) is that
    signature copied into an input that does not name its signer."""
    assert wt.resolution_of([row(s=S_1), none_row(s=S_1)]).kind == wt.COPIED
    # A NONE row with ANOTHER s might be another key: not a conclusion.
    res = wt.resolution_of([row(s=S_1), none_row(s=S_2)])
    assert res.kind == wt.UNDETERMINED
    assert (res.rows_ambiguous, res.rows_absent) == (0, 1)
    # A NONE row under another scheme is another signature too.
    res = wt.resolution_of([row(s=S_1),
                            wt.record(R_A, b"", b"", S_1, 1, 8,
                                      (wt.NONE << wt.ATTR_SHIFT)
                                      | wt.FLAG_SCHNORR)])
    assert res.kind == wt.UNDETERMINED


def test_an_unattributable_signer_gets_no_resolution_rather_than_a_guess():
    res = wt.resolution_of([none_row(s=S_1), none_row(s=S_2, ambiguous=True)])
    assert res.kind == wt.UNDETERMINED
    assert (res.rows_ambiguous, res.rows_absent) == (1, 1)
    assert res.exposed == ()


def test_every_resolution_has_words_to_go_with_it():
    for v in wt.RESOLUTIONS:
        assert wt.RESOLUTION_TEXT[v]
    assert "coupled" in wt.RESOLUTION_TEXT[wt.DISTINCT_KEYS]


# ---------------------------------------------------------------------------
# Reading one input: the attribution, shape by shape
# ---------------------------------------------------------------------------

def ckey(i, odd=False):
    return bytes([0x03 if odd else 0x02]) + bytes([i]) * 32


def der(r, s, sighash=0x01):
    return tn.der(tn.minimal(r), tn.minimal(s), sighash)


def schnorr(r, s):
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def p2pkh(key):
    return b"\x76\xa9\x14" + hash160(key) + b"\x88\xac"


def p2sh(script):
    return b"\xa9\x14" + hash160(script) + b"\x87"


def multisig(m, keys):
    return (bytes([0x50 + m]) + b"".join(bytes([len(k)]) + k for k in keys)
            + bytes([0x50 + len(keys), 0xae]))


def leaf_single(x):
    return bytes([32]) + x + b"\xac"


def leaf_add(xs, k):
    body = bytes([32]) + xs[0] + b"\xac"
    for x in xs[1:]:
        body += bytes([32]) + x + b"\xba"
    return body + bytes([0x50 + k, 0x9c])


CTRL = b"\xc0" + bytes([0xee]) * 32           # a control block's shape

N1 = 0x66f1c4b0e5d3a27681f0c5d4e3b2a1908f7e6d5c4b3a291807162534435261a0
N2 = 0x1199aabbccddeeff00112233445566778899aabbccddeeff0011223344556677
S1 = 0x00c0ffee00000000000000000000000000000000000000000000000000000001
S2 = 0x00beef0000000000000000000000000000000000000000000000000000000002
S_BIG = nn.CURVE_ORDER - S1                  # above n/2


def tx_in(script_sig, witness=(), prev=b"\x11" * 32, vout=0):
    return bp.TxIn(prev, vout, script_sig, 0xFFFFFFFF, list(witness))


def one(sightings):
    assert len(sightings) == 1, sightings
    return sightings[0]


def test_a_key_beside_the_signature_is_attributed_when_it_links_to_the_lock():
    key = ckey(1)
    lock = hash160(p2pkh(key))
    sg = one(wt.signatures_of_input(
        tx_in(tn.push(der(N1, S1)) + tn.push(key)), None, nn.new_stats(),
        lambda txid, vout: lock))
    assert sg.cls == wt.BESIDE and sg.x == key[1:] and not sg.odd_y
    assert sg.key_canon == hash160(key) and sg.key_seen is None
    assert not sg.schnorr and not sg.high_s and sg.sighash == 0x01
    # The same shape whose key does NOT hash to the lock it spends is a
    # shape, not an attribution: counted, and NONE without AMBIGUOUS.
    sg = one(wt.signatures_of_input(
        tx_in(tn.push(der(N1, S1)) + tn.push(key)), None, nn.new_stats(),
        lambda txid, vout: bytes(range(20))))
    assert sg.cls == wt.NONE and not sg.ambiguous and sg.link_failed
    assert sg.x is None
    # All three single-key locks link: P2WPKH and the P2SH wrapper too.
    for spk in (b"\x00\x14" + hash160(key),
                p2sh(b"\x00\x14" + hash160(key))):
        sg = one(wt.signatures_of_input(
            tx_in(b"", [der(N1, S1), key]), None, nn.new_stats(),
            lambda txid, vout, spk=spk: hash160(spk)))
        assert sg.cls == wt.BESIDE, spk.hex()


def test_a_65_byte_key_carries_its_own_digest_and_the_same_x():
    key33 = ckey(1, odd=True)
    key65 = b"\x04" + key33[1:] + bytes(31) + b"\x01"       # odd y
    lock = hash160(p2pkh(key65))
    sg = one(wt.signatures_of_input(
        tx_in(tn.push(der(N1, S1)) + tn.push(key65)), None, nn.new_stats(),
        lambda txid, vout: lock))
    assert sg.cls == wt.BESIDE and sg.uncompressed and sg.odd_y
    assert sg.x == key33[1:] and sg.key_seen == hash160(key65)
    assert sg.key_canon == hash160(key33)
    assert sg.flags & wt.FLAG_UNCOMPRESSED and sg.flags & wt.FLAG_ODD_Y


def test_the_position_in_an_m_of_m_multisig_names_the_signer():
    k4, k5, k6 = ckey(4), ckey(5), ckey(6)
    redeem = multisig(2, [k4, k5])
    script_sig = (b"\x00" + tn.push(der(N1, S1)) + tn.push(der(N2, S2))
                  + tn.push(redeem))
    got = wt.signatures_of_input(tx_in(script_sig), None, nn.new_stats(),
                                 lambda t, v: None)
    assert [(s.cls, s.x) for s in got] == [(wt.POSITION, k4[1:]),
                                           (wt.POSITION, k5[1:])]
    # Asking for one point still reads the whole input: the position of
    # the second signature is the second key's.
    sg = one(wt.signatures_of_input(
        tx_in(script_sig), {N2.to_bytes(32, "big")[:nn.R_PREFIX]},
        nn.new_stats(), lambda t, v: None))
    assert sg.cls == wt.POSITION and sg.x == k5[1:]
    # m < n: several candidates, no key is guessed.
    redeem23 = multisig(2, [k4, k5, k6])
    script_sig = (b"\x00" + tn.push(der(N1, S1)) + tn.push(der(N2, S2))
                  + tn.push(redeem23))
    got = wt.signatures_of_input(tx_in(script_sig), None, nn.new_stats(),
                                 lambda t, v: None)
    assert all(s.cls == wt.NONE and s.ambiguous and s.m_lt_n for s in got)
    # The same rule reads a witness script (P2WSH).
    got = wt.signatures_of_input(
        tx_in(b"", [b"", der(N1, S1), der(N2, S2), redeem]), None,
        nn.new_stats(), lambda t, v: None)
    assert [(s.cls, s.x) for s in got] == [(wt.POSITION, k4[1:]),
                                           (wt.POSITION, k5[1:])]


def test_a_tapscript_template_names_the_signer_by_its_slot():
    x9, xa, xb = bytes([9]) * 32, bytes([0xa]) * 32, bytes([0xb]) * 32
    sig = schnorr(N1, S1)
    sg = one(wt.signatures_of_input(
        tx_in(b"", [sig, leaf_single(x9), CTRL]), None, nn.new_stats(),
        lambda t, v: None))
    assert sg.cls == wt.POSITION and sg.xonly and sg.x == x9
    assert sg.schnorr and sg.key_canon == hash160(b"\x02" + x9)
    assert sg.flags & wt.FLAG_XONLY and not sg.flags & wt.FLAG_ODD_Y
    # BIP 342 multisig: every key has its own stack slot, read from the
    # top down. Stack [sig, empty] means the FIRST key's slot is empty
    # and the signature is the second key's.
    sg = one(wt.signatures_of_input(
        tx_in(b"", [sig, b"", leaf_add([xa, xb], 1), CTRL]), None,
        nn.new_stats(), lambda t, v: None))
    assert sg.cls == wt.POSITION and sg.x == xb
    sg = one(wt.signatures_of_input(
        tx_in(b"", [b"", sig, leaf_add([xa, xb], 1), CTRL]), None,
        nn.new_stats(), lambda t, v: None))
    assert sg.x == xa
    # A leaf outside the two templates names nobody; with two keys in it
    # the signer is one of several.
    other = bytes([32]) + xa + b"\xad" + bytes([32]) + xb + b"\xac"
    sg = one(wt.signatures_of_input(
        tx_in(b"", [sig, other, CTRL]), None, nn.new_stats(),
        lambda t, v: None))
    assert sg.cls == wt.NONE and sg.ambiguous
    # The leaf and the control block are never read as keys beside.
    leaf33 = b"\x02" + bytes(32)                # 33 bytes with a key's lead
    sg = one(wt.signatures_of_input(
        tx_in(b"", [sig, leaf33, CTRL]), None, nn.new_stats(),
        lambda t, v: bytes(20)))
    assert sg.cls == wt.NONE and not sg.link_failed


def test_the_spent_output_names_the_key_of_a_p2pk_or_a_key_path_spend():
    k2 = ckey(2)
    sg = one(wt.signatures_of_input(
        tx_in(tn.push(der(N1, S1))), None, nn.new_stats(),
        lambda t, v: None))
    assert sg.pending and sg.cls == wt.NONE
    wt.attribute_output(sg, bytes([33]) + k2 + b"\xac")
    assert sg.cls == wt.OUTPUT and sg.x == k2[1:] and not sg.pending
    # A taproot key-path spend: the witness is the signature alone, and
    # the key is the output's program.
    q = bytes([3]) * 32
    sg = one(wt.signatures_of_input(
        tx_in(b"", [schnorr(N1, S_BIG)]), None, nn.new_stats(),
        lambda t, v: None))
    assert sg.pending and sg.schnorr
    wt.attribute_output(sg, b"\x51\x20" + q)
    assert sg.cls == wt.OUTPUT and sg.xonly and sg.x == q
    # Schnorr s is stored as published: above n/2, and never HIGH_S.
    assert sg.s == S_BIG.to_bytes(32, "big") and not sg.high_s
    # Any other spent output leaves the sighting without a candidate.
    sg = one(wt.signatures_of_input(
        tx_in(tn.push(der(N1, S1))), None, nn.new_stats(),
        lambda t, v: None))
    wt.attribute_output(sg, p2pkh(k2))
    assert sg.cls == wt.NONE and not sg.ambiguous and not sg.pending


def test_a_signature_in_a_taproot_slot_is_never_read_as_the_key():
    """A 65-byte BIP 340 signature whose R.x happens to start with
    0x02, 0x03 or 0x04 has the shape of a 65-byte key. For a key-path
    spend the witness is that one item, and the old rule attributed
    hash160(signature) as the signer's key."""
    r = bytes([0x02]) + bytes(range(1, 32))
    sig = r + bytes(range(32)) + bytes([0x01])          # R.x | s | sighash
    wanted = {r[:nn.R_PREFIX]}
    sg = one(wt.signatures_of_input(tx_in(b"", [sig]), wanted, nn.new_stats(),
                                    lambda t, v: bytes(20)))
    assert sg.pending and sg.x is None and sg.schnorr
    # And a key pushed where a key can be pushed is still attributed.
    key33 = bytes([0x02]) + bytes(range(32))
    d = (bytes([0x30, 4 + 32 + 32, 0x02, 32]) + r + bytes([0x02, 32])
         + bytes(range(1, 33)) + bytes([0x01]))
    sg = one(wt.signatures_of_input(
        tx_in(b"", [d, key33]), wanted, nn.new_stats(),
        lambda t, v: hash160(b"\x00\x14" + hash160(key33))))
    assert sg.cls == wt.BESIDE and sg.key_canon == hash160(key33)


def test_ecdsa_high_s_is_folded_and_flagged():
    key = ckey(1)
    sg = one(wt.signatures_of_input(
        tx_in(tn.push(der(N1, S_BIG)) + tn.push(key)), None, nn.new_stats(),
        lambda t, v: hash160(p2pkh(key))))
    assert sg.s == S1.to_bytes(32, "big") and sg.high_s
    assert sg.s_raw == S_BIG.to_bytes(32, "big")
    assert sg.flags & wt.FLAG_HIGH_S


# ---------------------------------------------------------------------------
# End to end: a chain that gives every class and every resolution a case
# ---------------------------------------------------------------------------

K1 = ckey(1)
K1_65 = b"\x04" + K1[1:] + bytes(31) + b"\x00"           # even y, like 02
K2, K4, K5, K6, K7, K10, K12 = (ckey(i) for i in (2, 4, 5, 6, 7, 10, 12))
Q3, Q8, Q11 = bytes([3]) * 32, bytes([8]) * 32, bytes([11]) * 32
X9, XA, XB = bytes([9]) * 32, bytes([0xa]) * 32, bytes([0xb]) * 32
REDEEM22 = multisig(2, [K4, K5])
REDEEM23 = multisig(2, [K4, K5, K6])
LEAF9 = leaf_single(X9)
LEAF_AB = leaf_add([XA, XB], 1)
SPK_QUIET = p2pkh(ckey(0x77))

N3 = 0x2a7b3c4d5e6f70819202a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8
N4 = 0x5f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a697887a6b5c4d3e2f100
N5 = 0x3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c
N6 = 0x4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d
N7 = 0x5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e
N8 = 0x6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f
N9 = 0x7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a
N10A = 0x8b8b8b8b8b8b8b8b8b8b8b8b00000000000000000000000000000000000000a1
N10B = 0x8b8b8b8b8b8b8b8b8b8b8b8b00000000000000000000000000000000000000b2
N_X1 = 0x9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c01
N_X2 = 0x9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d02
S3 = 0x00dead0000000000000000000000000000000000000000000000000000000003

# The funding outputs of the first coinbase, by vout.
FUNDING = [p2pkh(K1), p2pkh(K1), p2pkh(K1_65),               # 0 1 2
           bytes([33]) + K2 + b"\xac", bytes([33]) + K2 + b"\xac",  # 3 4
           b"\x51\x20" + Q3, b"\x51\x20" + Q3,                # 5 6
           p2sh(REDEEM22), p2sh(REDEEM22),                    # 7 8
           p2sh(REDEEM23), p2sh(REDEEM23),                    # 9 10
           b"\x00\x14" + hash160(K7), b"\x00\x14" + hash160(K7),  # 11 12
           b"\x51\x20" + Q8, b"\x51\x20" + Q8,                # 13 14
           p2pkh(ckey(0x55)), p2pkh(ckey(0x55)),              # 15 16 (unlinked)
           b"\x51\x20" + Q11, b"\x51\x20" + Q11,              # 17 18
           p2pkh(K12), p2pkh(K12)]                            # 19 20


def witness_chain():
    """Three blocks: one coinbase funds every lock twice, and the next
    two blocks spend each lock once, so every point below repeats.

      N1   K1 beside its signature, three times: at 33 bytes (h2), at
           65 bytes (h3, s as n-s) and at 33 again (h3): one x, exposed
      N2   a P2PK output spent twice: the key is in the output
      N3   a taproot key-path spend, the SAME Schnorr signature twice
      N4   2-of-2 redeem script: K4 signs both spends with one nonce
      N5   2-of-3 redeem script, both signatures under one nonce, twice
      N6   P2WPKH, the same signature bytes twice
      N7   a single-key tapscript leaf, two different s
      N8   a key beside the signature that does NOT hash to the lock
      N9   a BIP 342 two-key leaf, the second key's slot signed twice
      N10  two different scalars under one 12-byte census prefix
    """
    blocks, txids = {}, {}
    prev = bytes(32)

    def add(height, entries):
        nonlocal prev
        segwit = any(e[3] for e in entries)
        reserved = bytes(32)
        outputs = [tbw.w_output(50, SPK_QUIET)] if height > 1 \
            else [tbw.w_output(50, spk) for spk in FUNDING]
        if segwit:
            outputs.append(tbw.w_output(
                0, tbw.w_commitment_spk([e[2] for e in entries], reserved)))
        cb, cb_id, _ = tbw.w_tx(
            1, [tbw.w_input(bytes(32), 0xFFFFFFFF, bytes([1, height]),
                            0xFFFFFFFF)],
            outputs, 0, witnesses=[[reserved]] if segwit else None)
        raw, block_hash = tbw.w_block(
            4, prev, 1_700_000_000 + height, 0x1700_0000, height,
            [cb] + [e[0] for e in entries], [cb_id] + [e[1] for e in entries])
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())
        return cb_id

    def spend(fund_id, vout, script_sig, witness=None):
        raw, txid, wtxid = tbw.w_tx(
            1, [tbw.w_input(fund_id, vout, script_sig, 0xFFFFFFFF)],
            [tbw.w_output(40, SPK_QUIET)], 0,
            witnesses=[witness] if witness is not None else None)
        return raw, txid, wtxid, witness is not None

    fund = add(1, [])
    txids["fund"] = fund

    def beside(nonce, s, key):
        return tn.push(der(nonce, s)) + tn.push(key)

    def sh(nonces_s, redeem):
        return (b"\x00" + b"".join(tn.push(der(n, s)) for n, s in nonces_s)
                + tn.push(redeem))

    h2 = [
        spend(fund, 0, beside(N1, S1, K1)),
        spend(fund, 3, tn.push(der(N2, S1))),
        spend(fund, 5, b"", [schnorr(N3, S_BIG)]),
        spend(fund, 7, sh([(N4, S1), (N_X1, S1)], REDEEM22)),
        spend(fund, 9, sh([(N5, S1), (N5, S2)], REDEEM23)),
        spend(fund, 11, b"", [der(N6, S1), K7]),
        spend(fund, 13, b"", [schnorr(N7, S1), LEAF9, CTRL]),
        spend(fund, 15, beside(N8, S1, K10)),
        spend(fund, 17, b"", [schnorr(N9, S1), b"", LEAF_AB, CTRL]),
        spend(fund, 19, beside(N10A, S1, K12)),
    ]
    add(2, h2)
    h3 = [
        spend(fund, 2, beside(N1, nn.CURVE_ORDER - S3, K1_65)),
        spend(fund, 1, beside(N1, S2, K1)),
        spend(fund, 4, tn.push(der(N2, S2))),
        spend(fund, 6, b"", [schnorr(N3, S_BIG)]),
        spend(fund, 8, sh([(N4, S2), (N_X2, S1)], REDEEM22)),
        spend(fund, 10, sh([(N5, S1), (N5, S2)], REDEEM23)),
        spend(fund, 12, b"", [der(N6, S1), K7]),
        spend(fund, 14, b"", [schnorr(N7, S2), LEAF9, CTRL]),
        spend(fund, 16, beside(N8, S2, K10)),
        spend(fund, 18, b"", [schnorr(N9, S2), b"", LEAF_AB, CTRL]),
        spend(fund, 20, beside(N10B, S2, K12)),
    ]
    add(3, h3)
    return blocks, txids


def build_census(tmp, blocks, name):
    census = os.path.join(tmp, name)
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", max(blocks),
                    os.path.join(tmp, name + "_archive"),
                    batch_size=2, checkpoint_every=2, nonces_dir=census)
    finally:
        server.shutdown()
    nn.run_merge(census)
    return census


def build_index(tmp, blocks, name, end_height=None):
    graph = toi.emit_graph(tmp, blocks, name + "_graph")
    index = os.path.join(tmp, name)
    oi.run_build(graph, index, end_height=end_height)
    return index


@pytest.fixture(scope="module")
def chain_dirs(tmp_path_factory):
    """The census and the index over `witness_chain`, built once for the
    module: both are pure functions of the chain, and the table is what
    the tests here are about."""
    tmp = str(tmp_path_factory.mktemp("witness"))
    blocks, _ = witness_chain()
    census = build_census(tmp, blocks, "census")
    index = build_index(tmp, blocks, "index")
    return blocks, census, index


@pytest.fixture
def resolved(chain_dirs, tmp):
    blocks, census, index = chain_dirs
    server, url = trs.serve(blocks)
    client = trs.rs.RpcClient(url, "user:pass")
    table = os.path.join(tmp, "witness")
    try:
        fp = wt.run_resolve(census, table, client, index, out=io.StringIO())
    finally:
        server.shutdown()
    return census, table, fp, index


def rp(n):
    return n.to_bytes(32, "big")


def test_resolve_refuses_a_census_with_pending_runs(tmp):
    """The groups would come from the sealed file AND the runs, the
    heights to re-read from the sealed file alone: an exposure that
    straddled the last merge came out as `one-signature`. Refused
    until `nonces merge` has run, like `nonces rewind` already did."""
    blocks, _ = tn.address_chain()
    census = os.path.join(tmp, "census_pending")
    archive = os.path.join(tmp, "archive_pending")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 2, archive, batch_size=2,
                    checkpoint_every=2, nonces_dir=census)
        nn.run_merge(census)
        ra.run_scan(url, "user:pass", 5, archive, batch_size=2,
                    checkpoint_every=2, nonces_dir=census)
        assert nn._load_state(census)["runs"], "the fixture needs runs"
        client = trs.rs.RpcClient(url, "user:pass")
        with pytest.raises(wt.WitnessError, match="pending run"):
            wt.run_resolve(census, os.path.join(tmp, "witness_pending"),
                           client, None, out=io.StringIO())
    finally:
        server.shutdown()


def test_resolve_refuses_a_census_of_an_earlier_format(chain_dirs, tmp):
    """A v2 census names sightings whose r is 0 or >= n, which the
    extraction since v3 refuses: re-reading them either aborts or drops
    them, and the table would say something the census does not. This
    release reads no earlier census at all."""
    import shutil
    _blocks, census, index = chain_dirs
    old = os.path.join(tmp, "census_v2")
    shutil.copytree(census, old)
    for name in (nn.MANIFEST_NAME, "state.json"):
        path = os.path.join(old, name)
        doc = json.load(open(path))
        doc["format"] = "nonces-v2"
        with open(path, "w") as f:
            json.dump(doc, f)
    with pytest.raises(wt.WitnessError, match="nonces-v3"):
        wt.run_resolve(old, os.path.join(tmp, "witness_v2"), None, index,
                       out=io.StringIO())


def test_resolve_refuses_an_index_that_stops_below_the_census(chain_dirs, tmp):
    """The bytes of the table must not depend on which index it was
    given: an index that stops early would answer NONE for a lock it
    cannot see."""
    blocks, census, _index = chain_dirs
    short = build_index(tmp, blocks, "short_index", end_height=2)
    server, url = trs.serve(blocks)
    try:
        client = trs.rs.RpcClient(url, "user:pass")
        with pytest.raises(wt.WitnessError, match="cover"):
            wt.run_resolve(census, os.path.join(tmp, "witness_short"),
                           client, short, out=io.StringIO())
    finally:
        server.shutdown()


def test_the_chain_gives_every_resolution_and_every_class_a_case(resolved):
    _census, table, _fp, _index = resolved
    by_r = wt.rows_by_r(table)
    got = {r: wt.resolution_of(rows) for r, rows in by_r.items()}
    kinds = {r: res.kind for r, res in got.items()}
    assert kinds == {
        rp(N1): wt.EXPOSED, rp(N2): wt.EXPOSED, rp(N3): wt.COPIED,
        rp(N4): wt.EXPOSED, rp(N5): wt.UNDETERMINED, rp(N6): wt.COPIED,
        rp(N7): wt.EXPOSED, rp(N8): wt.UNDETERMINED, rp(N9): wt.EXPOSED,
        rp(N10A): wt.COPIED, rp(N10B): wt.COPIED}
    classes = {r: {wt.rec_class(x) for x in rows} for r, rows in by_r.items()}
    assert classes[rp(N1)] == {wt.BESIDE}
    assert classes[rp(N2)] == {wt.OUTPUT}
    assert classes[rp(N3)] == {wt.OUTPUT}
    assert classes[rp(N4)] == {wt.POSITION}
    assert classes[rp(N5)] == {wt.NONE}
    assert classes[rp(N6)] == {wt.BESIDE}
    assert classes[rp(N7)] == {wt.POSITION}
    assert classes[rp(N8)] == {wt.NONE}
    assert classes[rp(N9)] == {wt.POSITION}
    # The exposed keys, as x: one per road.
    assert got[rp(N1)].exposed == (K1[1:],)
    assert got[rp(N2)].exposed == (K2[1:],)
    assert got[rp(N4)].exposed == (K4[1:],)
    assert got[rp(N7)].exposed == (X9,)
    assert got[rp(N9)].exposed == (XB,)
    # The two ways of being undetermined are told apart.
    assert (got[rp(N5)].rows_ambiguous, got[rp(N5)].rows_absent) == (2, 0)
    assert (got[rp(N8)].rows_ambiguous, got[rp(N8)].rows_absent) == (0, 2)
    assert all(wt.rec_flags(x) & wt.FLAG_AMBIGUOUS for x in by_r[rp(N5)])
    assert not any(wt.rec_flags(x) & wt.FLAG_AMBIGUOUS for x in by_r[rp(N8)])


def test_one_point_two_serializations_is_one_key(resolved):
    """K1 signed at 33 bytes and at 65: the rows share x, one of them
    carries the 65-byte digest, both derive the compressed digest, and
    the triple's count says three signatures were seen."""
    _census, table, _fp, _index = resolved
    rows = wt.rows_by_r(table)[rp(N1)]
    assert len(rows) == 2
    assert {wt.rec_x(r) for r in rows} == {K1[1:]}
    assert {wt.rec_key_canon(r) for r in rows} == {hash160(K1)}
    assert {wt.rec_count(r) for r in rows} == {3}
    forms = {wt.rec_form(r): r for r in rows}
    assert set(forms) == {"compressed", "uncompressed"}
    u = forms["uncompressed"]
    assert wt.rec_key_seen(u) == hash160(K1_65)
    assert wt.rec_flags(u) & wt.FLAG_HIGH_S       # s was published as n-s
    assert wt.rec_s(u) == S3.to_bytes(32, "big")  # and stored canonical
    assert wt.rec_key_seen(forms["compressed"]) == bytes(20)


def test_schnorr_s_is_stored_as_published(resolved):
    _census, table, _fp, _index = resolved
    rows = wt.rows_by_r(table)[rp(N3)]
    assert len(rows) == 1 and wt.rec_count(rows[0]) == 1
    rec = rows[0]
    assert wt.rec_flags(rec) & wt.FLAG_SCHNORR
    assert not wt.rec_flags(rec) & wt.FLAG_HIGH_S
    assert wt.rec_s(rec) == S_BIG.to_bytes(32, "big")
    assert wt.rec_flags(rec) & wt.FLAG_XONLY and wt.rec_x(rec) == Q3
    assert wt.rec_key_canon(rec) == hash160(b"\x02" + Q3)


def test_at_most_two_witnesses_are_kept_and_the_count_says_how_many(resolved):
    _census, table, _fp, _index = resolved
    for _r, rows in wt.rows_by_r(table).items():
        by_triple = {}
        for r in rows:
            by_triple.setdefault((wt.rec_x(r), wt.rec_class(r)), []).append(r)
        for group in by_triple.values():
            assert len(group) <= 2, "two witnesses settle it; more is weight"
            assert all(wt.rec_count(r) >= len(group) for r in group)
    # And the rows are sorted by their raw bytes: one r contiguous, and
    # inside it one key contiguous.
    raw = list(wt.iter_records(table))
    assert raw == sorted(raw)


def test_the_manifest_declares_the_index_and_counts_the_classes(resolved):
    _census, table, _fp, index = resolved
    build = wt._load_manifest(table)["build"]
    assert build["parent"]["format"] == nn.FORMAT_TAG
    assert build["index"] == {
        "format": oi.FORMAT_TAG,
        "fingerprint": json.load(open(os.path.join(
            index, oi.MANIFEST_NAME)))["fingerprint"],
        "coverage": {"from": 1, "to": 3}}
    assert build["parent"]["coverage"] == {"from": 1, "to": 3}
    assert build["points_resolved"] == 10        # the census counts prefixes
    assert build["rows"] == 18
    assert build["attributed_beside"] == 5       # N1 x2, N6, N10A, N10B
    assert build["attributed_position"] == 6     # N4, N7, N9, two each
    assert build["attributed_output"] == 3       # N2 x2, N3
    assert build["none"] == 4                    # N5 x2, N8 x2
    assert build["shape_without_link"] == 2
    assert build["ambiguous_multisig_m_lt_n"] == 4
    assert wt._load_state(table)["output_blocks_read"] == 1


def test_verify_rederives_the_resolutions_and_confronts_the_parent(
        resolved, capsys):
    census, table, fp, _index = resolved
    wt.run_verify(table, nonces_dir=census)
    text = capsys.readouterr().out
    assert "re-resolved from the rows themselves" in text
    assert f"parent {nn.FORMAT_TAG}" in text
    assert fp in text
    assert "1  census prefix(es) covering more than one scalar" in text


def test_the_csv_carries_what_the_audit_re_derived(resolved, tmp, capsys):
    """The export hangs off the audit on purpose: a resolution leaves this
    project only after the table it came from has been verified, and
    there is no second road to these numbers as data."""
    census, table, _fp, _index = resolved
    out = os.path.join(tmp, "resolutions.csv")
    keys = os.path.join(tmp, "keys.csv")
    wt.run_verify(table, nonces_dir=census, csv_path=out, keys_csv=keys)
    rows = {r["r"]: r for r in csvmod.DictReader(open(out))}
    assert len(rows) == 11                      # one row per SCALAR
    r1 = rows[rp(N1).hex()]
    assert r1["resolution"] == wt.EXPOSED
    assert r1["point"] == rp(N1)[:nn.R_PREFIX].hex()
    assert (r1["keys"], r1["exposed_keys"], r1["max_distinct_s"]) == ("1", "1", "3")
    assert (r1["first_height"], r1["last_height"]) == ("2", "3")
    assert r1["attribution"] == "beside" and r1["schemes"] == "ecdsa"
    # Two scalars under one census prefix: two rows, each saying so.
    for n in (N10A, N10B):
        assert rows[rp(n).hex()]["scalars_under_prefix"] == "2"
        assert rows[rp(n).hex()]["resolution"] == wt.COPIED
    assert rows[rp(N1).hex()]["scalars_under_prefix"] == "1"
    r5 = rows[rp(N5).hex()]
    assert (r5["rows_ambiguous"], r5["rows_absent"]) == ("2", "0")
    assert r5["attribution"] == "none"
    assert rows[rp(N7).hex()]["schemes"] == "schnorr"
    assert rows[rp(N9).hex()]["attribution"] == "position"
    # The keys: one row per attributed key, the two forms of K1 folded.
    krows = {r["key_canon"]: r for r in csvmod.DictReader(open(keys))}
    k1 = krows[hash160(K1).hex()]
    assert k1["key_seen"] == hash160(K1_65).hex()
    assert k1["form"] == "compressed+uncompressed" and k1["exposed"] == "1"
    assert krows[hash160(b"\x02" + Q3).hex()]["exposed"] == "0"
    assert krows[hash160(b"\x02" + XB).hex()]["form"] == "xonly"
    assert hash160(b"\x02" + XA).hex() not in krows
    assert hash160(K5).hex() not in krows      # K5 never repeated a nonce
    text = capsys.readouterr().out
    assert "wrote 11 scalar(s)" in text


def test_the_csv_is_not_written_when_the_audit_fails(resolved, tmp):
    """The point of hanging the export off the audit: a table that does
    not verify must not be able to emit numbers."""
    census, table, _fp, _index = resolved
    path = os.path.join(table, wt.FILE_NAME)
    raw = bytearray(open(path, "rb").read())
    raw[0] ^= 0xFF
    open(path, "wb").write(bytes(raw))
    out = os.path.join(tmp, "should-not-exist.csv")
    with pytest.raises(wt.WitnessError):
        wt.run_verify(table, csv_path=out)
    assert not os.path.exists(out)


def test_a_table_beside_another_census_is_refused(resolved, tmp):
    """The strongest thing this table says is about the points ITS census
    found. Beside a different one the resolutions are about other points, and
    a fingerprint check is the only thing that notices."""
    census, table, _fp, _index = resolved
    other = os.path.join(tmp, "other-census")
    os.makedirs(other)
    manifest = json.load(open(os.path.join(census, nn.MANIFEST_NAME)))
    manifest["fingerprint"] = "0" * 64
    json.dump(manifest, open(os.path.join(other, nn.MANIFEST_NAME), "w"))
    with pytest.raises(wt.WitnessError, match="not the same"):
        wt.run_verify(table, nonces_dir=other)


def test_a_rotted_row_is_caught_before_the_fingerprint(resolved):
    """A flipped bit that turns a row into one the writer would refuse
    (here: a key digest under a compressed key) is named as such, and a
    flipped bit that keeps the row legal is caught by the digest."""
    _census, table, _fp, _index = resolved
    path = os.path.join(table, wt.FILE_NAME)
    raw = bytearray(open(path, "rb").read())
    raw[wt._OFF_KEY] ^= 0xFF                    # key_seen of row 0
    open(path, "wb").write(bytes(raw))
    with pytest.raises(wt.WitnessError, match="UNCOMPRESSED"):
        wt.run_verify(table)
    raw[wt._OFF_KEY] ^= 0xFF
    raw[wt._OFF_S] ^= 0xFF                      # a bit of an `s`
    open(path, "wb").write(bytes(raw))
    with pytest.raises(wt.WitnessError):
        wt.run_verify(table)


def test_resolve_is_a_pure_function_of_its_three_inputs(resolved, tmp):
    census, table, fp, index = resolved
    blocks, _ = witness_chain()
    server, url = trs.serve(blocks)
    try:
        again = os.path.join(tmp, "witness_again")
        fp2 = wt.run_resolve(census, again, trs.rs.RpcClient(url, "user:pass"),
                             index, out=io.StringIO())
    finally:
        server.shutdown()
    assert fp2 == fp
    assert open(os.path.join(table, wt.FILE_NAME), "rb").read() == \
        open(os.path.join(again, wt.FILE_NAME), "rb").read()
