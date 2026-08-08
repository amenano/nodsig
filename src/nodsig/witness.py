#!/usr/bin/env python3
"""
witness.py — Nonces-witness-v1: the evidence that resolves a repeated point.

WHAT THIS IS FOR
================
The nonce census records, for every signature, the first 12 bytes of its
nonce point and the height. That is enough to say WHICH points
repeat and never enough to say WHAT a repeat means, because the meaning
lives in `s`, which a 16-byte record does not hold. So `nonces groups`
emits candidates it cannot resolve, and a reader has to go back to the
chain with a node to find out.

This artifact does that once and keeps the answer. It re-reads only the
blocks the groups name, and stores, per (nonce point, public key) pair,
the WITNESSES: the signatures that decide the resolution.

WHY WITNESSES AND NOT EVERY SIGHTING
====================================
Keeping every sighting of every repeated point would be 2.5 million rows
over the chain, dominated by one 2015 construction. Nothing needs them.
Exposure is decided by a pair of signatures that DISAGREE, so two rows per
(point, key) settle it: two distinct canonical `s` prove the key is
recoverable, and one proves it is not. Measured over the whole chain that
is 11,766 rows and 1.03 MB, against 2,508,137 sightings: 213 times
smaller for the same answers, with the sighting counts kept as numbers
beside them.

WHY VALUES AND NOT HASHES
=========================
The rows carry `r`, the key's hash160 and `s` in full, not digests of
them. Eight-byte hints would be a third the size and would answer the same
question, but only if you trust this code to have hashed correctly. Full
values make the resolution CHECKABLE BY A STRANGER against the chain, without
re-running the resolve and without trusting us — which is the property
this whole project exists for. Nothing here is secret: `r` and `s` are
published in the block, in the clear, by the transaction that spent.

WHAT IT DOES NOT DO
===================
It does not recover keys, and it holds nothing that would help more than
the chain already does. "Exposed" here means a proof obligation was met:
two signatures, one nonce, one key, two different messages. Computing the
key from that is arithmetic anyone can do and this project does not do it:
there is no curve arithmetic in nodsig, and `CURVE_ORDER` in `nonces.py`
is used only to fold `s` with `n-s` and to refuse an `r` the definition of
ECDSA excludes. Both are comparisons against a constant; neither
multiplies a point.

THE THREE CONDITIONS, AND WHY EACH ONE IS THERE
===============================================
A resolution of `exposed` requires all three, and each was a defect once:

  1. the SAME FULL r. The census truncates the point to 12 bytes, and two
     scalars can share that prefix (measured: 1 group in 5,149).
  2. the SAME PUBLIC KEY. Not the same lock type: a single-key lock says
     the signatures came from one key, which is true and not enough.
  3. DIFFERENT CANONICAL s. Nonces k and -k give points R and -R, which
     share an x-coordinate and so publish the same r; over ONE message
     they give s and n-s. Two different `s`, one message, no key
     (measured: 1 pair in 1,581). `nonces.canonical_s` folds them.
"""

import argparse
import json
import os
import sys

from nodsig import blockparse
from nodsig import nonces as nn
from nodsig.artifact import (WallClock, identity_fingerprint, make_identity,
                             producer, seal_manifest, verify_sealed,
                             declared_parent)
from nodsig.hashing import hash160
from nodsig.recio import atomic_json, read_fixed, sha_file

STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
FORMAT_TAG = "nonces-witness-v1"
LOGICAL = "witness"
FILE_NAME = "witness.bin"

# One row, 92 bytes, big-endian throughout:
#
#     r        32   the nonce point in full, left-padded. NOT truncated:
#                   condition 1 above needs the whole scalar.
#     key      20   hash160 of the public key beside the signature. The
#                   same identity the reveal archive uses, so the two join.
#     s        32   the CANONICAL s (min(s, n-s)): condition 3.
#     count     4   how many distinct canonical s this (r, key) pair has
#                   over the whole chain, of which this row is a witness.
#     height    3   where this witness was read.
#     flags     1   see below.
R_LEN, KEY_LEN, S_LEN = 32, 20, 32
REC = R_LEN + KEY_LEN + S_LEN + 4 + 3 + 1

FLAG_SCHNORR = 1        # the signature was BIP 340, not DER
FLAG_KEY_ABSENT = 2     # no public key in the input (p2pk, taproot, bare)
FLAG_AMBIGUOUS = 4      # more than one signature or key: cannot attribute
FLAG_HIGH_S = 8         # the serialized s was n-s, not the canonical one
FLAGS_DEFINED = FLAG_SCHNORR | FLAG_KEY_ABSENT | FLAG_AMBIGUOUS | FLAG_HIGH_S

# The resolutions. `capability.py` insists a definite negative is not an
# "I don't know", and that distinction is the whole point of this list.
EXPOSED = "exposed"
COPIED = "one-signature"
DISTINCT_KEYS = "distinct-keys"
PREFIX_COLLISION = "prefix-collision"
NOT_A_SIGNATURE = "not-a-signature"
UNDETERMINED = "undetermined"


class WitnessError(RuntimeError):
    """A witness table that cannot be trusted to mean what it says."""


def record(r_full, key_h160, s_canon, count, height, flags):
    """One row, packed. `key_h160` may be empty when the key is absent."""
    if len(r_full) != R_LEN or len(s_canon) != S_LEN:
        raise WitnessError("r and s are stored in full, 32 bytes each")
    key = key_h160 or bytes(KEY_LEN)
    if len(key) != KEY_LEN:
        raise WitnessError("the key identity is a 20-byte hash160")
    if flags & ~FLAGS_DEFINED:
        raise WitnessError(f"undefined flag bits set: {flags:#x}")
    return (bytes(r_full) + bytes(key) + bytes(s_canon)
            + count.to_bytes(4, "big") + height.to_bytes(3, "big")
            + bytes([flags]))


def rec_r(rec):
    return bytes(rec[:R_LEN])


def rec_key(rec):
    return bytes(rec[R_LEN:R_LEN + KEY_LEN])


def rec_s(rec):
    return bytes(rec[R_LEN + KEY_LEN:R_LEN + KEY_LEN + S_LEN])


def rec_count(rec):
    off = R_LEN + KEY_LEN + S_LEN
    return int.from_bytes(rec[off:off + 4], "big")


def rec_height(rec):
    off = R_LEN + KEY_LEN + S_LEN + 4
    return int.from_bytes(rec[off:off + 3], "big")


def rec_flags(rec):
    return rec[REC - 1]


def rec_point(rec):
    """The 12-byte point the census would have stored: the join key."""
    return bytes(rec[:nn.R_PREFIX])


def has_key(rec):
    return (rec_flags(rec) & (FLAG_KEY_ABSENT | FLAG_AMBIGUOUS)) == 0


# ---------------------------------------------------------------------------
# Reading one input: the extraction the resolve pass and the reader share
# ---------------------------------------------------------------------------

def signatures_of_input(tx_in, wanted, stats):
    """Every signature in one input whose point is in `wanted`.

    Yields `(full r, canonical s, flags)`. `wanted` holds 12-byte points,
    because that is what the census names; the full `r` comes back out so
    the caller can tell two scalars that share a prefix apart.

    The key is attributed only when the input holds exactly one signature
    and exactly one key-shaped push. Anything else is `AMBIGUOUS`, and
    saying so is the honest move: pairing a signature with one of several
    cosigners means verifying signatures, which this project does not do.
    """
    pushes = blockparse.scriptsig_pushes(tx_in, stats)
    items = pushes + list(tx_in.witness)
    hits = []
    for item in items:
        r = nn.signature_r(item, stats)
        if r is not None and r[:nn.R_PREFIX] in wanted:
            hits.append((item, r, False))
    slots, key_path = nn._taproot_slots(tx_in.witness)
    for item in slots:
        r = nn.taproot_r(item, key_path)
        if r is not None and r[:nn.R_PREFIX] in wanted:
            hits.append((item, r, True))
    if not hits:
        return []

    keys = [it for it in items
            if len(it) in (33, 65) and it[0] in (0x02, 0x03, 0x04)]
    out = []
    for item, r, schnorr in hits:
        flags = FLAG_SCHNORR if schnorr else 0
        if len(hits) > 1 or len(keys) > 1:
            flags |= FLAG_AMBIGUOUS
            key = b""
        elif len(keys) == 1:
            key = hash160(keys[0])
        else:
            flags |= FLAG_KEY_ABSENT
            key = b""
        raw = nn.signature_s(item, schnorr=schnorr)
        canon = nn.canonical_s(raw)
        if int.from_bytes(raw, "big") != int.from_bytes(canon, "big"):
            flags |= FLAG_HIGH_S
        out.append((r, key, canon, flags))
    return out


# ---------------------------------------------------------------------------
# The resolution: what a set of rows about one point means
# ---------------------------------------------------------------------------

def _impossible_scalar(r):
    """A value that cannot be a nonce point, by ECDSA's own definition.

    `r` is the x-coordinate of k*G taken mod n, so `0 < r < n` always.
    Zero and anything at or above the group order are therefore not
    small or unlikely, they are impossible: bytes that had a signature's
    SHAPE without being one.

    The census applies the same rule at extraction now, so a `nonces-v3`
    parent brings none of these through and this branch reports nothing.
    It stays for the censuses that predate the rule, which this tool
    still reads and resolves: there, the stored point is 12 truncated
    bytes and the value cannot be judged, while here the whole scalar is
    on hand and the test is two comparisons.

    Note which rule this is NOT. There is no threshold on SIZE, because
    the chain carries consensus-validated signatures whose `r` is 166
    and 223 bits: "too small to be genuine" would reject genuine data.
    Only 0 and n are lines the arithmetic itself draws.
    """
    v = int.from_bytes(r, "big")
    return v == 0 or v >= nn.CURVE_ORDER


def resolution_of(rows):
    """The resolution for one 12-byte point, from its witness rows.

    Returns `(resolution, exposed keys)`. The unit is the (point, key) pair
    and not the point: one nonce point can carry several keys with
    different outcomes, which is exactly what the chain's largest group
    does.
    """
    if all(_impossible_scalar(rec_r(r)) for r in rows):
        # Said before the prefix test, because it is the stronger
        # statement: "these are not signatures" explains why the scalars
        # under one prefix differ, where "they differ" only reports it.
        return NOT_A_SIGNATURE, ()
    if len({rec_r(r) for r in rows}) > 1:
        # Two different scalars under one 12-byte prefix. Not a repeat at
        # all, and the census cannot see it: that is what full r is for.
        return PREFIX_COLLISION, ()

    by_key = {}
    opaque = 0
    for r in rows:
        if has_key(r):
            by_key.setdefault(rec_key(r), set()).add(rec_s(r))
        else:
            opaque += 1

    exposed = tuple(sorted(k for k, ss in by_key.items() if len(ss) >= 2))
    if exposed:
        return EXPOSED, exposed
    if len(by_key) > 1:
        return DISTINCT_KEYS, ()
    if len(by_key) == 1 and opaque == 0:
        return COPIED, ()
    return UNDETERMINED, ()


RESOLUTION_TEXT = {
    EXPOSED: ("two signatures, one nonce, one key, two messages: the "
              "private key follows by arithmetic anybody can do"),
    COPIED: ("one signature, published more than once (copied, or as s "
             "and n-s): it signs one message and exposes nothing"),
    DISTINCT_KEYS: ("different keys on one nonce point: neither key "
                    "follows, and the point was not drawn at random"),
    PREFIX_COLLISION: ("two different scalars sharing the census's 12-byte "
                       "prefix: not a repeated nonce at all"),
    NOT_A_SIGNATURE: ("r is 0 or at least the group order, which no nonce "
                      "point can be: bytes with a signature's shape that "
                      "are not one"),
    UNDETERMINED: ("the signer is not identifiable from the input (the key "
                   "is in the output being spent, or several could have "
                   "signed): no resolution, and none is guessed"),
}


# ---------------------------------------------------------------------------
# resolve: the build, against the node, over the blocks the groups name
# ---------------------------------------------------------------------------

def _path(witness_dir, name=FILE_NAME):
    return os.path.join(witness_dir, name)


def _load_state(witness_dir):
    path = os.path.join(witness_dir, STATE_NAME)
    if not os.path.exists(path):
        raise WitnessError(f"no {STATE_NAME} in {witness_dir}: not a witness "
                           "table (or `resolve` never checkpointed)")
    with open(path) as f:
        state = json.load(f)
    if state.get("format") != FORMAT_TAG:
        raise WitnessError("unknown witness table format")
    return state


def _load_manifest(witness_dir):
    path = os.path.join(witness_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        raise WitnessError(f"no {MANIFEST_NAME} in {witness_dir}: this table "
                           "was never sealed, so it cannot be verified")
    with open(path) as f:
        return json.load(f)


def _heights_of_groups(nonces_dir, min_count, keep):
    """Which heights to re-read, and which points to look for there.

    Read out of the sealed census through its ladder, one lookup per
    group, so this costs a few thousand bucket reads and not a pass over
    the whole file.
    """
    groups = nn.run_groups(nonces_dir, min_count=min_count, limit=0,
                           keep_heights=0, out=open(os.devnull, "w"))
    census = nn.open_sorted(nonces_dir)
    try:
        wanted = {}
        for g in groups:
            for rec in census.find(g.point):
                wanted.setdefault(nn.rec_height(rec), set()).add(g.point)
    finally:
        census.close()
    return groups, wanted


def run_resolve(nonces_dir, witness_dir, client, min_count=2,
                batch_size=25, out=sys.stdout):
    """Re-read the blocks the repeated points name, and keep the witnesses.

    Resumable in the only way that matters here: the pass is a pure read
    of the chain, so an interruption loses time and nothing else, and a
    re-run starts from the height cursor in `state.json`.
    """
    t = WallClock("resolve")
    p = lambda *a: print(*a, file=out)

    parent = nn._load_manifest(nonces_dir, required=True)
    groups, wanted = _heights_of_groups(nonces_dir, min_count, 0)
    heights = sorted(wanted)
    p(f"{len(groups):,} repeated points name {len(heights):,} block(s)")
    if not groups:
        p("nothing repeats: the table will be sealed empty, which is an "
          "answer and not a failure")

    os.makedirs(witness_dir, exist_ok=True)
    # (r, key) -> {canonical s: (height, flags)}; the witnesses, kept in
    # memory because there are thousands of them and not millions.
    seen = {}
    counts = {}
    done = 0
    for i in range(0, len(heights), batch_size):
        window = heights[i:i + batch_size]
        hashes, raws = client.fetch_blocks(window)
        for h, want_hash, raw in zip(window, hashes, raws):
            block = blockparse.parse_block(raw)
            if block.header.hash != want_hash:
                raise WitnessError(
                    f"height {h}: the bytes do not hash to the block hash "
                    "asked for")
            stats = nn.new_stats()
            found = set()
            for tx in block.transactions:
                if blockparse.is_coinbase(tx):
                    continue
                for tx_in in tx.inputs:
                    for r, key, s, flags in signatures_of_input(
                            tx_in, wanted[h], stats):
                        found.add(r[:nn.R_PREFIX])
                        k = (r, key, flags & (FLAG_KEY_ABSENT
                                              | FLAG_AMBIGUOUS
                                              | FLAG_SCHNORR))
                        counts.setdefault(k, set()).add(s)
                        # Two witnesses settle it; a third adds nothing a
                        # resolution can use, so it is counted and dropped.
                        w = seen.setdefault(k, {})
                        if s not in w and len(w) < 2:
                            w[s] = (h, flags)
            missing = wanted[h] - found
            if missing:
                raise WitnessError(
                    f"height {h}: {len(missing)} point(s) the census names "
                    "are not in this block. The census and the node "
                    "disagree; nothing is written")
            done += 1
        atomic_json(os.path.join(witness_dir, STATE_NAME),
                    {"format": FORMAT_TAG, "cursor": window[-1],
                     "heights": len(heights), "done": done})

    rows = []
    for (r, key, _f), witnesses in seen.items():
        n = len(counts[(r, key, _f)])
        for s, (h, flags) in witnesses.items():
            rows.append(record(r, key, s, n, h, flags))
    rows.sort()
    with open(_path(witness_dir), "wb") as f:
        f.write(b"".join(rows))

    p(f"{len(rows):,} witness row(s) from {done:,} block(s)")
    return _seal(witness_dir, parent, groups, rows, t, out)


def _seal(witness_dir, parent, groups, rows, clock, out):
    """Write the manifest: the identity, the fingerprint, and the parent.

    The parent is the census this table resolved, declared the way every
    child artifact here declares one. It matters more than usual: a
    witness table is only about the points ITS census found, so a table
    beside a different census is answering about something else.
    """
    path = _path(witness_dir)
    files = {LOGICAL: {"file": FILE_NAME, "sha256": sha_file(path)}}
    heights = [rec_height(r) for r in _iter_rows(rows)]
    identity = make_identity(FORMAT_TAG,
                             min(heights) if heights else 0,
                             max(heights) if heights else 0,
                             [(LOGICAL, files[LOGICAL]["sha256"])])
    fingerprint = identity_fingerprint(identity)
    manifest = seal_manifest(FORMAT_TAG, identity, {
        "producer": producer(),
        "seconds": clock.stamp(),
        # The parent's OWN tag, read from its manifest, never this code's
        # constant: a table can be resolved over a census in the previous
        # format, and writing the tag we happen to emit would file it
        # under an artifact that does not exist.
        "parent": declared_parent(parent["format"], parent["fingerprint"]),
        "points_resolved": len(groups),
        "rows": len(rows),
        "files": files,
        "caches": {},
        "reconstruction": (
            "for every point the parent census reports as repeated, the "
            "blocks it names are re-read and each matching signature is "
            "reduced to (full r, hash160 of the public key beside it, "
            "canonical s = min(s, n-s), flags). At most TWO rows are kept "
            "per (r, key, flags) triple, being the first two distinct "
            "canonical s seen in ascending height order, with `count` "
            "holding how many distinct canonical s that triple has in "
            "total. Rows are sorted by their raw bytes; the identity is "
            "then sealed by the shared recipe in docs/contracts/Artifact.md"),
    })
    atomic_json(os.path.join(witness_dir, MANIFEST_NAME), manifest)
    print(f"witness table over {len(groups):,} repeated point(s)", file=out)
    print(f"  parent {parent['format']}: {parent['fingerprint']}  (declared)",
          file=out)
    print(f"fingerprint: {fingerprint}", file=out)
    return fingerprint


def _iter_rows(rows):
    return rows


def iter_records(witness_dir, expect_sha=None):
    """Every row of a sealed table, in order."""
    return read_fixed(_path(witness_dir), REC, expect_sha=expect_sha,
                      error=WitnessError)


def rows_by_point(witness_dir):
    """The rows grouped by the 12-byte point, which is how a reader asks."""
    out = {}
    for rec in iter_records(witness_dir):
        out.setdefault(rec_point(rec), []).append(rec)
    return out


# ---------------------------------------------------------------------------
# verify — the audit of a sealed table
# ---------------------------------------------------------------------------

def run_verify(witness_dir, nonces_dir=None, csv_path=None):
    """Re-read every byte against the manifest, and re-derive the resolutions.

    The digests prove the file has not rotted. Re-deriving the resolutions
    from the rows proves the file still MEANS what it meant, which is the
    part a checksum cannot say. Passing `--nonces` confirms the declared
    parent instead of taking it on trust.

    `--csv` writes what the audit just re-derived, and it hangs off the
    audit ON PURPOSE rather than off a reader of its own: exporting a
    resolution then requires having verified the table it came from, so a
    number that leaves this project has been checked by construction. It
    is also the only road to these numbers as data, which keeps one
    result from having two.
    """
    manifest = _load_manifest(witness_dir)
    p = print

    tally = {}
    rows_out = []
    for point, rows in sorted(rows_by_point(witness_dir).items()):
        v, keys = resolution_of(rows)
        tally[v] = tally.get(v, 0) + 1
        if csv_path:
            heights = [rec_height(r) for r in rows]
            attributed = {rec_key(r) for r in rows if has_key(r)}
            rows_out.append((
                point.hex(), v, len(attributed), len(keys),
                max((rec_count(r) for r in rows), default=0),
                # How many of this point's scalars cannot be a nonce point
                # at all. Usually 0; when it is not, it explains a resolution
                # the resolution alone only reports. Kept as a count rather
                # than folded into the resolution, because a point can mix
                # impossible scalars with legal ones and calling the whole
                # group "not a signature" would then be wrong.
                sum(1 for r in {rec_r(x) for x in rows}
                    if _impossible_scalar(r)),
                min(heights), max(heights),
                _schemes_of(rows)))
    total = sum(tally.values())
    p(f"ok  {total:,} point(s) re-resolved from the rows themselves")
    for v in (EXPOSED, DISTINCT_KEYS, COPIED, PREFIX_COLLISION,
              NOT_A_SIGNATURE, UNDETERMINED):
        if tally.get(v):
            p(f"      {tally[v]:>7,}  {v}")

    parent_confirmed = None
    if nonces_dir:
        declared = manifest.get("build", {}).get("parent", {})
        census = nn._load_manifest(nonces_dir, required=True)
        actual = census["fingerprint"]
        if declared.get("fingerprint") != actual:
            raise WitnessError(
                f"this table declares the census {declared.get('fingerprint')}"
                f" but the one given is {actual}: they are not the same "
                "artifact, and the resolutions are about the other one")
        # The census's own tag: the fingerprint match above already
        # covers it (the format is inside the hashed identity), so this
        # line reports what was confirmed rather than what we emit.
        parent_confirmed = f"ok parent {census['format']} {actual}"

    verify_sealed(witness_dir, manifest, FORMAT_TAG, WitnessError,
                  fp_order=[LOGICAL], parent_confirmed=parent_confirmed)

    # Written only after the audit above has passed: `verify_sealed`
    # raises on any mismatch, so a CSV existing means the table it came
    # from was whole.
    if csv_path:
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            f.write("point,resolution,keys,exposed_keys,max_distinct_s,"
                    "impossible_scalars,first_height,last_height,"
                    "schemes\n")
            for row in rows_out:
                f.write(",".join(str(c) for c in row) + "\n")
        p(f"\nwrote {len(rows_out):,} point(s) to {csv_path}")


def _schemes_of(rows):
    """Which signature schemes this point was published under."""
    names = []
    if any(not (rec_flags(r) & FLAG_SCHNORR) for r in rows):
        names.append("ecdsa")
    if any(rec_flags(r) & FLAG_SCHNORR for r in rows):
        names.append("schnorr")
    return "+".join(names) or "none"
