"""Tests for witness.py: the evidence that resolves a repeated point.

What is worth pinning here, and why each case exists:

- the four resolutions must come out of the SAME synthetic chain, because a
  resolution is only useful if it separates cases that look identical to the
  census. All four points below have a repeat; only one exposes a key;
- `exposed` must require all three conditions, and each one has its own
  test, because each was a real defect once: the full `r` (not the
  truncated point), the same key (not the same lock type), and the
  canonical `s` (not the serialized one);
- a table must re-derive its own resolutions on `verify`, so a file that
  rots into a different meaning is caught by more than a checksum;
- the declared parent must be confronted, because a witness table beside
  a different census answers about something else entirely.
"""

import io
import os

import pytest

from nodsig import nonces as nn
from nodsig import witness as wt

R_A = bytes(range(32))
R_B = bytes(range(1, 33))
KEY_1 = bytes(range(20))
KEY_2 = bytes(range(20, 40))
S_1 = bytes(31) + b"\x01"
S_2 = bytes(31) + b"\x02"


def row(r=R_A, key=KEY_1, s=S_1, count=2, height=7, flags=0):
    return wt.record(r, key, s, count, height, flags)


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

def test_a_row_round_trips_every_field():
    rec = row(count=38_718, height=364_773, flags=wt.FLAG_HIGH_S)
    assert wt.rec_r(rec) == R_A
    assert wt.rec_key(rec) == KEY_1
    assert wt.rec_s(rec) == S_1
    assert wt.rec_count(rec) == 38_718
    assert wt.rec_height(rec) == 364_773
    assert wt.rec_flags(rec) == wt.FLAG_HIGH_S
    assert len(rec) == wt.REC
    # The join key back to the census is the truncation, not a stored field.
    assert wt.rec_point(rec) == R_A[:nn.R_PREFIX]


def test_a_row_refuses_what_it_cannot_mean():
    with pytest.raises(wt.WitnessError):
        wt.record(R_A[:16], KEY_1, S_1, 2, 7, 0)      # r must be whole
    with pytest.raises(wt.WitnessError):
        wt.record(R_A, KEY_1[:10], S_1, 2, 7, 0)      # the key is a hash160
    with pytest.raises(wt.WitnessError):
        wt.record(R_A, KEY_1, S_1, 2, 7, 0x80)        # undefined flag bit


def test_an_absent_key_is_stored_as_absence_not_as_zero_the_value():
    rec = wt.record(R_A, b"", S_1, 1, 7, wt.FLAG_KEY_ABSENT)
    assert wt.rec_key(rec) == bytes(wt.KEY_LEN)
    assert not wt.has_key(rec)


# ---------------------------------------------------------------------------
# The resolution: the three conditions, one test each
# ---------------------------------------------------------------------------

def test_exposed_needs_two_different_canonical_s():
    assert wt.resolution_of([row(s=S_1), row(s=S_2)])[0] == wt.EXPOSED
    # One `s`, twice: the same signature published again. Nothing follows,
    # and this is what the chain's largest group actually is.
    assert wt.resolution_of([row(s=S_1), row(s=S_1)])[0] == wt.COPIED


def test_s_and_its_negation_never_reach_the_resolution_as_two():
    """The rows carry min(s, n-s), so the pair folds before it is compared.

    Nonces k and -k publish the same r over one message and give s and
    n-s. Comparing the serialized values would call that exposed and
    announce a recovery that does not exist.
    """
    s = 0x00c0ffee00000000000000000000000000000000000000000000000000000001
    high = (nn.CURVE_ORDER - s).to_bytes(32, "big")
    low = s.to_bytes(32, "big")
    assert nn.canonical_s(high) == nn.canonical_s(low)
    canon = nn.canonical_s(low)
    assert wt.resolution_of([row(s=canon), row(s=canon)])[0] == wt.COPIED


def test_exposed_needs_the_same_key_not_merely_one_point():
    v, keys = wt.resolution_of([row(key=KEY_1, s=S_1), row(key=KEY_2, s=S_2)])
    assert v == wt.DISTINCT_KEYS
    assert keys == ()
    # And the resolution is per (point, key): one point can carry a key that
    # is exposed beside keys that are not, which is what the chain does.
    v, keys = wt.resolution_of([row(key=KEY_1, s=S_1), row(key=KEY_1, s=S_2),
                             row(key=KEY_2, s=S_1)])
    assert v == wt.EXPOSED
    assert keys == (KEY_1,)


def test_two_scalars_under_one_prefix_are_not_a_repeat():
    """The census truncates to 12 bytes; the table keeps the whole scalar
    precisely so this case can be named instead of counted as a repeat."""
    other = R_A[:nn.R_PREFIX] + bytes(32 - nn.R_PREFIX)
    assert other[:nn.R_PREFIX] == R_A[:nn.R_PREFIX] and other != R_A
    assert wt.resolution_of([row(r=R_A, s=S_1), row(r=other, s=S_2)])[0] \
        == wt.PREFIX_COLLISION


def test_bytes_that_cannot_be_a_nonce_point_are_named_as_such():
    """`r` is the x-coordinate of k*G mod n, so 0 < r < n always. Zero and
    anything at or above the order are impossible, not merely odd: the
    bytes had a signature's shape without being one.

    This is on the chain. At height 957,301 one group's 12 zero bytes
    covered three scalars: 0, 1 and 82. Saying `not-a-signature` explains
    why they differ; `prefix-collision` only reports that they do.
    """
    zero = bytes(32)
    over = nn.CURVE_ORDER.to_bytes(32, "big")
    assert wt.resolution_of([row(r=zero, s=S_1),
                          row(r=zero, s=S_2)])[0] == wt.NOT_A_SIGNATURE
    assert wt.resolution_of([row(r=over, s=S_1)])[0] == wt.NOT_A_SIGNATURE
    # Just below the order is a legal scalar and must not be swept up.
    legal = (nn.CURVE_ORDER - 1).to_bytes(32, "big")
    assert wt.resolution_of([row(r=legal, s=S_1),
                          row(r=legal, s=S_2)])[0] == wt.EXPOSED


def test_a_small_r_is_not_treated_as_impossible():
    """The rule that would be WRONG, pinned so nobody adds it later.

    The chain carries consensus-validated signatures whose `r` is 166 and
    223 bits. Any "too small to be genuine" threshold would reject real
    data, so only 0 and n are lines this code draws.
    """
    tiny = (1).to_bytes(32, "big")                      # r = 1: legal, absurd
    assert not wt._impossible_scalar(tiny)
    r166 = int("3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63", 16)
    assert r166.bit_length() == 166
    assert not wt._impossible_scalar(r166.to_bytes(32, "big"))
    assert wt.resolution_of([row(r=r166.to_bytes(32, "big"), s=S_1),
                          row(r=r166.to_bytes(32, "big"),
                              s=S_2)])[0] == wt.EXPOSED


def test_an_unattributable_signer_gets_no_resolution_rather_than_a_guess():
    absent = wt.record(R_A, b"", S_1, 1, 7, wt.FLAG_KEY_ABSENT)
    ambiguous = wt.record(R_A, b"", S_2, 1, 8, wt.FLAG_AMBIGUOUS)
    assert wt.resolution_of([absent, ambiguous])[0] == wt.UNDETERMINED
    # One attributable row beside an opaque one is still not a conclusion:
    # the opaque signature could be the same key or another.
    assert wt.resolution_of([row(s=S_1), absent])[0] == wt.UNDETERMINED


def test_every_resolution_has_words_to_go_with_it():
    for v in (wt.EXPOSED, wt.COPIED, wt.DISTINCT_KEYS, wt.PREFIX_COLLISION,
              wt.NOT_A_SIGNATURE, wt.UNDETERMINED):
        assert wt.RESOLUTION_TEXT[v]


# ---------------------------------------------------------------------------
# End to end, over the address chain: build, read, verify
# ---------------------------------------------------------------------------

@pytest.fixture
def resolved(tmp):
    """A census and the witness table resolved from it, over the chain of
    `test_nonces.address_chain`, whose four repeated points were built to
    give every resolution a case."""
    import test_nonces as tn
    import test_reuse_scan as trs
    from nodsig import reveal_archive as ra

    blocks, _ = tn.address_chain()
    census = os.path.join(tmp, "census")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 5, os.path.join(tmp, "archive"),
                    batch_size=2, checkpoint_every=2, nonces_dir=census)
    finally:
        server.shutdown()
    nn.run_merge(census)

    server, url = trs.serve(blocks)
    client = trs.rs.RpcClient(url, "user:pass")
    table = os.path.join(tmp, "witness")
    try:
        fp = wt.run_resolve(census, table, client, out=io.StringIO())
    finally:
        server.shutdown()
    return census, table, fp


def test_the_chain_gives_every_resolution_a_case(resolved):
    census, table, _fp = resolved
    got = {}
    for point, rows in wt.rows_by_point(table).items():
        got[point.hex()] = wt.resolution_of(rows)[0]
    assert sorted(got.values()) == sorted(
        [wt.EXPOSED, wt.COPIED, wt.COPIED, wt.UNDETERMINED])

    # KEY signed twice with one nonce and two different messages.
    from test_nonces import N_REUSED, N_COPY, N_NEG, N_SCRIPT, point_of
    assert got[point_of(N_REUSED).hex()] == wt.EXPOSED
    # COPY published one signature twice; NEG published s and n-s. Both
    # repeat the point, and neither hands over anything.
    assert got[point_of(N_COPY).hex()] == wt.COPIED
    assert got[point_of(N_NEG).hex()] == wt.COPIED
    # The 2-of-3 input carries two signatures: nothing is attributable.
    assert got[point_of(N_SCRIPT).hex()] == wt.UNDETERMINED


def test_at_most_two_witnesses_are_kept_and_the_count_says_how_many(resolved):
    _census, table, _fp = resolved
    for _point, rows in wt.rows_by_point(table).items():
        by_key = {}
        for r in rows:
            by_key.setdefault(wt.rec_key(r), []).append(r)
        for key, group in by_key.items():
            assert len(group) <= 2, "two witnesses settle it; more is weight"
            assert all(wt.rec_count(r) >= len(group) for r in group)


def test_verify_rederives_the_resolutions_and_confronts_the_parent(
        resolved, capsys):
    census, table, fp = resolved
    wt.run_verify(table, nonces_dir=census)
    text = capsys.readouterr().out
    assert "re-resolved from the rows themselves" in text
    assert f"parent {nn.FORMAT_TAG}" in text
    assert fp in text


def test_the_csv_carries_what_the_audit_re_derived(resolved, tmp, capsys):
    """The export hangs off the audit on purpose: a resolution leaves this
    project only after the table it came from has been verified, and
    there is no second road to these numbers as data."""
    import csv as csvmod
    census, table, _fp = resolved
    out = os.path.join(tmp, "resolutions.csv")
    wt.run_verify(table, nonces_dir=census, csv_path=out)
    rows = list(csvmod.DictReader(open(out)))
    assert len(rows) == 4                       # one row per point
    assert {r["resolution"] for r in rows} == {wt.EXPOSED, wt.COPIED,
                                            wt.UNDETERMINED}
    by_v = {r["resolution"]: r for r in rows}
    # The exposed point names one key, and the row says so as a number
    # rather than naming it: an aggregate is publishable, a list is not.
    assert by_v[wt.EXPOSED]["exposed_keys"] == "1"
    assert by_v[wt.EXPOSED]["keys"] == "1"
    assert int(by_v[wt.EXPOSED]["first_height"]) == 2
    assert int(by_v[wt.EXPOSED]["last_height"]) == 3
    assert all(r["schemes"] == "ecdsa" for r in rows)
    # No scalar on this chain is impossible, and the column says so with a
    # number rather than by being absent.
    assert all(r["impossible_scalars"] == "0" for r in rows)
    assert capsys.readouterr().out.count("wrote 4 point(s)") == 1


def test_the_csv_is_not_written_when_the_audit_fails(resolved, tmp):
    """The point of hanging the export off the audit: a table that does
    not verify must not be able to emit numbers."""
    census, table, _fp = resolved
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
    import json
    census, table, _fp = resolved
    other = os.path.join(tmp, "other-census")
    os.makedirs(other)
    manifest = json.load(open(os.path.join(census, nn.MANIFEST_NAME)))
    manifest["fingerprint"] = "0" * 64
    json.dump(manifest, open(os.path.join(other, nn.MANIFEST_NAME), "w"))
    with pytest.raises(wt.WitnessError, match="not the same"):
        wt.run_verify(table, nonces_dir=other)


def test_a_rotted_row_is_caught_by_the_fingerprint(resolved):
    _census, table, _fp = resolved
    path = os.path.join(table, wt.FILE_NAME)
    raw = bytearray(open(path, "rb").read())
    raw[wt.R_LEN + wt.KEY_LEN] ^= 0xFF          # flip a bit of an `s`
    open(path, "wb").write(bytes(raw))
    with pytest.raises(wt.WitnessError):
        wt.run_verify(table)
