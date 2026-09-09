#!/usr/bin/env python3
"""
witness.py — Nonces-witness-v2: the evidence that resolves a repeated point.

WHAT THIS IS FOR
================
The nonce census records, for every signature, the first 12 bytes of its
nonce point and the height. That is enough to say WHICH points repeat
and never enough to say WHAT a repeat means, because the meaning lives
in `s` and in the key that signed, and a 16-byte record holds neither.
So `nonces groups` emits candidates it cannot resolve, and a reader has
to go back to the chain with a node to find out.

This artifact does that once and keeps the answer. It re-reads only the
blocks the groups name, and stores, per (nonce point, key, attribution
class), the WITNESSES: the signatures that decide the resolution, and
the key each one belongs to.

THE IDENTITY OF A KEY, FOR A RESOLUTION
=======================================
A signature is attributed to a POINT, not to the bytes a key was
serialized in. The equation of the signature fixes the nonce up to sign
(`R` and `-R` share an x coordinate) and the private key up to sign
(`P` and `-P` share `x`), so the identity a resolution works with is
`x`, and the row stores it as a value: 32 bytes anybody can compare with
the push in the block, without hashing. The digest every other artifact
of this project keys a point by is derived on read from `x` and the
parity bit, never stored beside the value it is computed from.

HOW A SIGNATURE IS ATTRIBUTED
=============================
Three classes, in rising strength, and two ways of saying "no key":

  BESIDE    one signature, one key-shaped item beside it (the shape of
            P2PKH, P2WPKH, P2SH-P2WPKH), AND the key hashes to the lock
            the input spends, read from the outpoint index: shape tied
            to consensus by the lock. A shape whose key does not link is
            counted and NOT attributed.
  POSITION  the script names the signer by position, by consensus: an
            m-of-m CHECKMULTISIG (the interpreter consumes keys in order
            and fails when signatures outrun keys, so with m == n the
            i-th signature is the i-th key's), a single-key tapscript
            leaf, or the BIP 342 multisig template where every key has
            its own stack slot.
  OUTPUT    one signature, no key in the input, and the spent
            scriptPubKey names the key: P2PK, or a taproot key-path
            program. Consensus, read from the index and the block that
            created the output.
  NONE      no key is guessed. AMBIGUOUS when several candidates exist
            (an m-of-n multisig with m < n, a leaf outside the two
            templates), plain when there is none.

Attributing by kind of address, which the previous format did, was a
special case of BESIDE (without the link) plus the key-path case, and
answered "several keys" for every m-of-m and for P2SH-P2WPKH.

WHY VALUES AND NOT HASHES
=========================
The rows carry `r`, `x` and `s` in full. Eight-byte hints would be a
third the size and would answer the same question, but only if you trust
this code to have hashed correctly. Full values make the resolution
CHECKABLE BY A STRANGER against the chain, without re-running the
resolve and without trusting us. Nothing here is secret: `r`, `s` and
the key were published in the block, in the clear, by the transaction
that spent.

WHAT IT DOES NOT DO
===================
It does not recover keys. "Exposed" here means a proof obligation was
met: two signatures, one nonce, one key, two different messages.
Computing the key from that is arithmetic anyone can do and this project
does not do it: there is no curve arithmetic in nodsig, and
`CURVE_ORDER` is used only to fold `s` with `n-s` and to refuse an `r`
the definition of ECDSA excludes. Both are comparisons against a
constant; neither multiplies a point.

THE CONDITIONS OF `exposed`, AND WHY EACH ONE IS THERE
======================================================
A resolution of `exposed` requires all four, and each was a defect once:

  1. the SAME FULL r. The census truncates the point to 12 bytes, and
     two scalars can share that prefix (measured: 1 prefix in 5,149).
     The unit of a resolution is the whole scalar; the prefix is a
     column of the export, never a resolution.
  2. the SAME x. Not the same lock type, not the same serialization: a
     key seen at 65 bytes and at 33 is one key, and a key used as
     `03||x` in an ECDSA input and as an x-only leaf key is one private
     key up to sign.
  3. DIFFERENT (scheme, s). For ECDSA the canonical s, min(s, n-s):
     nonces k and -k give points R and -R, which share an x-coordinate
     and so publish the same r; over ONE message they give s and n-s
     (measured: 1 pair in 1,581). For Schnorr, s as published: BIP 340
     fixes R to the even-y point, so n-s is another signature and not a
     second form of this one. The scheme travels in the pair, because an
     ECDSA s and a Schnorr s that happen to be numerically equal are
     still two signatures.
  4. attributed rows only. A NONE row says nothing about which key
     signed, and is never paired.
"""

import csv
import os
import sys
from collections import namedtuple

from nodsig import blockparse
from nodsig import nonces as nn
from nodsig.artifact import (WallClock, identity_fingerprint, make_identity,
                             producer, seal_manifest, verify_sealed,
                             declared_parent)
from nodsig.hashing import hash160
from nodsig.keyforms import P as FIELD_PRIME, canonical_key, compressed_of
from nodsig.recio import atomic_json, read_fixed, sha_file, read_json
from nodsig.sightings import is_control_block, taproot_body, leaf_xonly_keys

STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
FORMAT_TAG = "nonces-witness-v2"
PARENT_TAGS = (nn.FORMAT_TAG,)         # nonces-v3 only: no legacy census
LOGICAL = "witness"
FILE_NAME = "witness.bin"

# One row, 124 bytes, big-endian throughout:
#
#     r        32   the nonce point in full, left-padded. NOT truncated:
#                   condition 1 above needs the whole scalar.
#     x        32   the x coordinate of the key the signature is
#                   attributed to; 32 zero bytes when the class is NONE.
#     key_seen 20   hash160 of the 65-byte serialization the chain
#                   showed, when UNCOMPRESSED is set; zero otherwise
#                   (a compressed form's digest is derived from x).
#     s        32   ECDSA: the CANONICAL s, min(s, n-s). Schnorr: as
#                   published.
#     count     4   how many distinct (scheme, s) the triple (r, x, class)
#                   has over the whole pass, of which this row is one.
#     height    3   where this witness was read.
#     flags     1   see below.
R_LEN, X_LEN, KEY_LEN, S_LEN = 32, 32, 20, 32
_OFF_X = R_LEN
_OFF_KEY = _OFF_X + X_LEN
_OFF_S = _OFF_KEY + KEY_LEN
_OFF_COUNT = _OFF_S + S_LEN
_OFF_HEIGHT = _OFF_COUNT + 4
REC = _OFF_HEIGHT + 3 + 1

FLAG_SCHNORR = 1        # the signature is BIP 340, not DER
FLAG_HIGH_S = 2         # ECDSA: the serialized s was n-s; never with SCHNORR
ATTR_SHIFT = 2
ATTR_MASK = 0b11 << ATTR_SHIFT      # the two attribution bits
FLAG_AMBIGUOUS = 16     # only with NONE: several candidates, none named
FLAG_ODD_Y = 32         # the point seen has odd y (03, or 04/06/07 with odd y)
FLAG_UNCOMPRESSED = 64  # seen as 65 bytes: key_seen carries its hash160
FLAG_XONLY = 128        # seen as 32 bytes: parity unknown, digest 02||x
FLAGS_DEFINED = 255

# The attribution classes, two bits of the flags byte.
BESIDE, POSITION, OUTPUT, NONE = 0, 1, 2, 3
CLASS_NAMES = {BESIDE: "beside", POSITION: "position", OUTPUT: "output",
               NONE: "none"}

# The resolutions. `capability.py` insists a definite negative is not an
# "I don't know", and that distinction is the whole point of this list.
EXPOSED = "exposed"
COPIED = "one-signature"
DISTINCT_KEYS = "distinct-keys"
UNDETERMINED = "undetermined"
RESOLUTIONS = (EXPOSED, DISTINCT_KEYS, COPIED, UNDETERMINED)

RESOLUTION_TEXT = {
    EXPOSED: ("two signatures, one nonce, one key, two messages: the "
              "private key follows by arithmetic anybody can do"),
    COPIED: ("one signature, published more than once (copied, or as s "
             "and n-s): it signs one message and exposes nothing"),
    DISTINCT_KEYS: ("different keys on one nonce point: neither key "
                    "follows from the two signatures alone, the keys are "
                    "coupled (either private key gives the other), and "
                    "the point was not drawn at random"),
    UNDETERMINED: ("the signer is not named by the unlocking data or the "
                   "spent output (several could have signed, or no "
                   "candidate is known): no resolution, and none is "
                   "guessed"),
}


class WitnessError(RuntimeError):
    """A witness table that cannot be trusted to mean what it says."""


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

def _r_in_range(r, schnorr):
    """What the arithmetic excludes, and nothing more: an ECDSA r is a
    scalar mod n, so 0 < r < n; a BIP 340 R.x is a field element, so
    r < p, and p is larger than n (see `nonces.taproot_r` on why the
    two rules do not transfer)."""
    v = int.from_bytes(r, "big")
    if schnorr:
        return v < FIELD_PRIME
    return 0 < v < nn.CURVE_ORDER


def record(r_full, x, key_seen, s, count, height, flags):
    """One row, packed, refused when its fields cannot mean what the
    flags say. `x` and `key_seen` may be empty for "absent"."""
    if len(r_full) != R_LEN or len(s) != S_LEN:
        raise WitnessError("r and s are stored in full, 32 bytes each")
    if flags & ~FLAGS_DEFINED:
        raise WitnessError(f"undefined flag bits set: {flags:#x}")
    cls = (flags & ATTR_MASK) >> ATTR_SHIFT
    x = bytes(x or bytes(X_LEN))
    key = bytes(key_seen or bytes(KEY_LEN))
    if len(x) != X_LEN or len(key) != KEY_LEN:
        raise WitnessError("x is 32 bytes and key_seen a 20-byte hash160")
    if (cls == NONE) != (x == bytes(X_LEN)):
        raise WitnessError("x is zero if and only if the class is NONE")
    if bool(flags & FLAG_UNCOMPRESSED) != (key != bytes(KEY_LEN)):
        raise WitnessError("key_seen is set if and only if UNCOMPRESSED is")
    if flags & FLAG_UNCOMPRESSED and flags & FLAG_XONLY:
        raise WitnessError("UNCOMPRESSED and XONLY are never together")
    if flags & FLAG_HIGH_S and flags & FLAG_SCHNORR:
        raise WitnessError("HIGH_S is an ECDSA fact: never with SCHNORR")
    if flags & FLAG_ODD_Y and flags & FLAG_XONLY:
        raise WitnessError("ODD_Y is unknown for an x-only key: never set")
    if flags & FLAG_AMBIGUOUS and cls != NONE:
        raise WitnessError("AMBIGUOUS only qualifies a NONE row")
    if not _r_in_range(r_full, flags & FLAG_SCHNORR):
        raise WitnessError("r is outside the range a nonce point can have")
    return (bytes(r_full) + x + key + bytes(s)
            + count.to_bytes(4, "big") + height.to_bytes(3, "big")
            + bytes([flags]))


def rec_r(rec):
    return bytes(rec[:R_LEN])


def rec_x(rec):
    return bytes(rec[_OFF_X:_OFF_KEY])


def rec_key_seen(rec):
    return bytes(rec[_OFF_KEY:_OFF_S])


def rec_s(rec):
    return bytes(rec[_OFF_S:_OFF_COUNT])


def rec_count(rec):
    return int.from_bytes(rec[_OFF_COUNT:_OFF_HEIGHT], "big")


def rec_height(rec):
    return int.from_bytes(rec[_OFF_HEIGHT:_OFF_HEIGHT + 3], "big")


def rec_flags(rec):
    return rec[REC - 1]


def rec_class(rec):
    return (rec_flags(rec) & ATTR_MASK) >> ATTR_SHIFT


def rec_point(rec):
    """The 12-byte point the census would have stored: the join key."""
    return bytes(rec[:nn.R_PREFIX])


def has_key(rec):
    return rec_class(rec) != NONE


def rec_scheme_s(rec):
    """The pair a resolution compares: (scheme, s). The scheme travels
    with the value because two schemes can publish equal bytes."""
    return (rec_flags(rec) & FLAG_SCHNORR, rec_s(rec))


def rec_key_canon(rec):
    """The digest of the compressed form, the identity every other
    artifact keys a point by: hash160((02 | ODD_Y) || x), and
    hash160(02 || x) for an x-only key by BIP 340's definition. None
    for a NONE row."""
    if not has_key(rec):
        return None
    lead = 0x02 | (1 if rec_flags(rec) & FLAG_ODD_Y else 0)
    return hash160(bytes([lead]) + rec_x(rec))


def rec_form(rec):
    f = rec_flags(rec)
    if f & FLAG_XONLY:
        return "xonly"
    if f & FLAG_UNCOMPRESSED:
        return "uncompressed"
    return "compressed"


# ---------------------------------------------------------------------------
# Reading one input: the road `resolve` and `nonces address` share
# ---------------------------------------------------------------------------

class Sighting:
    """One signature read from one input, with the key it is attributed
    to and how. `pending` says the class is OUTPUT-or-NONE and the
    spent scriptPubKey decides: `attribute_output` settles it."""

    __slots__ = ("r", "s", "s_raw", "schnorr", "high_s", "sighash", "cls",
                 "ambiguous", "x", "odd_y", "uncompressed", "key_seen",
                 "xonly", "outpoint", "pending", "link_failed", "m_lt_n")

    def __init__(self, r, item, schnorr, outpoint):
        self.r = r
        raw = nn.signature_s(item, schnorr=schnorr)
        if schnorr:
            # BIP 340 fixes R to the even-y point: n-s is another
            # signature, not this one in a second form. Stored as
            # published, and HIGH_S is never set.
            self.s = bytes(raw)
            self.high_s = False
            self.sighash = item[64] if len(item) == 65 else None
        else:
            canon = nn.canonical_s(raw)
            self.s = canon
            self.high_s = (int.from_bytes(raw, "big")
                           != int.from_bytes(canon, "big"))
            self.sighash = item[-1]
        self.s_raw = int.from_bytes(raw, "big").to_bytes(32, "big")
        self.schnorr = schnorr
        self.outpoint = outpoint
        self.cls = NONE
        self.ambiguous = False
        self.x = None
        self.odd_y = False
        self.uncompressed = False
        self.key_seen = None
        self.xonly = False
        self.pending = False
        self.link_failed = False
        self.m_lt_n = False

    def attribute(self, cls, key, xonly=False):
        """Name the key: a 33- or 65-byte serialization, or a 32-byte
        x-only key when `xonly` says the place makes it one."""
        self.cls = cls
        self.ambiguous = False
        if xonly:
            self.x, self.odd_y, self.xonly = bytes(key), False, True
            self.uncompressed, self.key_seen = False, None
            return
        comp = compressed_of(key)
        self.x = comp[1:]
        self.odd_y = bool(comp[0] & 1)
        self.xonly = False
        self.uncompressed = len(key) == 65
        self.key_seen = hash160(bytes(key)) if self.uncompressed else None

    @property
    def flags(self):
        f = (FLAG_SCHNORR if self.schnorr else 0) | (self.cls << ATTR_SHIFT)
        f |= FLAG_HIGH_S if self.high_s else 0
        f |= FLAG_AMBIGUOUS if self.ambiguous else 0
        f |= FLAG_ODD_Y if self.odd_y else 0
        f |= FLAG_UNCOMPRESSED if self.uncompressed else 0
        f |= FLAG_XONLY if self.xonly else 0
        return f

    @property
    def scheme_s(self):
        return (FLAG_SCHNORR if self.schnorr else 0, self.s)

    @property
    def key_canon(self):
        if self.x is None:
            return None
        return hash160(bytes([0x02 | int(self.odd_y)]) + self.x)

    def triple(self):
        return (self.r, self.x or bytes(X_LEN), self.cls)

    def as_record(self, count, height):
        return record(self.r, self.x, self.key_seen, self.s, count, height,
                      self.flags)


def _multisig_template(script):
    """`OP_m <keys> OP_n OP_CHECKMULTISIG` with every key a direct push
    of a serialized key → (m, keys, n), or None. Walked strictly: an
    opcode that is not one of those makes it a script outside the
    template, which is what the attribution must not guess about."""
    n = len(script)
    if n < 4 or script[-1] != 0xae:
        return None
    if not (0x51 <= script[0] <= 0x60 and 0x51 <= script[-2] <= 0x60):
        return None
    m, k = script[0] - 0x50, script[-2] - 0x50
    keys = []
    i = 1
    while i < n - 2:
        ln = script[i]
        if ln not in (33, 65):
            return None
        item = script[i + 1:i + 1 + ln]
        if len(item) != ln or canonical_key(item) is None:
            return None
        keys.append(bytes(item))
        i += 1 + ln
    if len(keys) != k or m < 1 or m > k:
        return None
    return m, keys, k


def _leaf_template(leaf):
    """The two tapscript templates whose keys have positions:
    `<x> OP_CHECKSIG` alone, and the BIP 342 multisig
    `<x1> OP_CHECKSIG <x2> OP_CHECKSIGADD … OP_k OP_NUMEQUAL`. Returns
    the keys in script order, or None for any other leaf."""
    n = len(leaf)
    keys = []
    i = 0
    while True:
        if i + 33 > n or leaf[i] != 32:
            return None
        keys.append(bytes(leaf[i + 1:i + 33]))
        i += 33
        if i >= n:
            return None
        op = leaf[i]
        i += 1
        want = 0xac if len(keys) == 1 else 0xba
        if op != want:
            return None
        if i == n:
            return keys if len(keys) == 1 else None
        if leaf[i] == 32:
            continue                       # another key follows
        break
    # The threshold: OP_1..OP_16 or a one-byte push, then OP_NUMEQUAL.
    if 0x51 <= leaf[i] <= 0x60:
        i += 1
    elif leaf[i] == 1 and i + 1 < n:
        i += 2
    else:
        return None
    if i + 1 != n or leaf[i] != 0x9c:
        return None
    return keys


def _locks_of_key(item):
    """The three single-key locks a serialized key can stand behind, as
    hash160 of the scriptPubKey (the index's identity of a lock)."""
    h = hash160(bytes(item))
    return {hash160(b"\x76\xa9\x14" + h + b"\x88\xac"),
            hash160(b"\x00\x14" + h),
            hash160(b"\xa9\x14" + hash160(b"\x00\x14" + h) + b"\x87")}


def signatures_of_input(tx_in, wanted, stats, lock_of):
    """Every signature in one input whose point is in `wanted` (12-byte
    points, as the census names them; None for all of them), each
    attributed to a key and a class. Returns a list of `Sighting`.

    `lock_of(prev_txid, vout)` gives hash160 of the scriptPubKey the
    input spends, or None when it is not known: it ties a BESIDE shape
    to consensus. A sighting that comes back `pending` needs the spent
    scriptPubKey itself (`attribute_output`), which costs a block read
    and is the caller's to batch.
    """
    pushes = blockparse.scriptsig_pushes(tx_in, stats)
    witness = list(tx_in.witness)
    slots, key_path = nn._taproot_slots(witness)
    outpoint = (tx_in.prev_txid, tx_in.prev_vout)

    # Every signature the input carries, not only the wanted ones: "one
    # signature" is a fact about the input.
    sigs = []
    for item in pushes + witness:
        r = nn.signature_r(item, stats)
        if r is not None:
            sigs.append((item, r, False))
    for item in slots:
        r = nn.taproot_r(item, key_path)
        if r is not None:
            sigs.append((item, r, True))
    hits = [(i, s) for i, s in enumerate(sigs)
            if wanted is None or s[1][:nn.R_PREFIX] in wanted]
    if not hits:
        return []

    # Where a script that names its signers can be: a tapscript leaf, a
    # witness script, a redeem script.
    body = taproot_body(witness)
    leaf = stack = None
    legacy = None
    if len(body) >= 2 and is_control_block(body[-1]):
        leaf, stack = body[-2], body[:-2]
    elif witness and _multisig_template(witness[-1]):
        legacy, stack = _multisig_template(witness[-1]), witness[:-1]
    elif pushes and _multisig_template(pushes[-1]):
        legacy, stack = _multisig_template(pushes[-1]), pushes[:-1]

    # A key can be pushed in the scriptSig, or sit in the witness
    # outside the taproot slots and outside the script slots. A 65-byte
    # Schnorr signature is never one (F179): the slots are excluded.
    outside = pushes + [it for it in witness if not any(it is s for s in slots)]
    if leaf is not None:
        outside = [it for it in outside if it is not leaf
                   and it is not body[-1]]
    keys = [it for it in outside if canonical_key(it) is not None]

    out = []
    for idx, (item, r, schnorr) in hits:
        sg = Sighting(r, item, schnorr, outpoint)
        if leaf is not None:
            _attribute_in_leaf(sg, leaf, stack, sigs, idx)
        elif legacy is not None:
            _attribute_in_multisig(sg, legacy, stack, sigs, idx)
        elif len(sigs) == 1 and len(keys) == 1:
            lock = lock_of(*outpoint)
            if lock is not None and lock in _locks_of_key(keys[0]):
                sg.attribute(BESIDE, keys[0])
            else:
                sg.link_failed = True
        elif len(sigs) == 1 and not keys:
            sg.pending = True
        else:
            sg.ambiguous = len(keys) >= 2
        out.append(sg)
    return out


def _attribute_in_multisig(sg, template, stack, sigs, idx):
    m, keys, n = template
    if m < n:
        sg.ambiguous, sg.m_lt_n = True, True
        return
    # The i-th signature of the stack is the i-th key's, by consensus.
    stack_sigs = [s for s in sigs if any(s[0] is it for it in stack)]
    pos = next((i for i, s in enumerate(stack_sigs) if s is sigs[idx]), None)
    if pos is None or len(stack_sigs) != n:
        sg.ambiguous = n >= 2
        return
    sg.attribute(POSITION, keys[pos])


def _attribute_in_leaf(sg, leaf, stack, sigs, idx):
    keys = _leaf_template(leaf)
    if keys is None:
        sg.ambiguous = len(leaf_xonly_keys(leaf)) >= 2
        return
    k = len(keys)
    if len(stack) != k:
        sg.ambiguous = k >= 2
        return
    # Key i (script order) reads its slot from the top of the stack
    # down: the last witness item before the leaf is the first key's.
    slot = next((j for j, it in enumerate(stack) if it is sigs[idx][0]),
                None)
    if slot is None:
        sg.ambiguous = k >= 2
        return
    sg.attribute(POSITION, keys[k - 1 - slot], xonly=True)


def attribute_output(sg, spk):
    """Settle a pending sighting from the scriptPubKey it spends: the key
    of a P2PK output, or the output key of a taproot program; anything
    else leaves it NONE without a candidate."""
    sg.pending = False
    n = len(spk)
    if n in (35, 67) and spk[0] == n - 2 and spk[-1] == 0xac \
            and canonical_key(spk[1:-1]) is not None:
        sg.attribute(OUTPUT, spk[1:-1])
    elif n == 34 and spk[:2] == b"\x51\x20":
        sg.attribute(OUTPUT, spk[2:], xonly=True)


# ---------------------------------------------------------------------------
# The resolution: what a set of rows about one full r means
# ---------------------------------------------------------------------------

Resolution = namedtuple("Resolution", "kind exposed rows_ambiguous rows_absent")


def resolution_of(rows):
    """The resolution for one full `r`, from its witness rows.

    Returns `Resolution(kind, exposed x's, rows_ambiguous, rows_absent)`.
    The unit is the (r, x) pair and not the point: one nonce point can
    carry several keys with different outcomes, which is exactly what
    the chain's largest group does.
    """
    rs = {rec_r(r) for r in rows}
    if len(rs) != 1:
        raise WitnessError("a resolution is over the rows of ONE full r; "
                           "group by rec_r, not by the census's prefix")
    by_x = {}
    absent = ambiguous = 0
    opaque = set()
    for r in rows:
        if has_key(r):
            by_x.setdefault(rec_x(r), set()).add(rec_scheme_s(r))
        else:
            opaque.add(rec_scheme_s(r))
            if rec_flags(r) & FLAG_AMBIGUOUS:
                ambiguous += 1
            else:
                absent += 1

    exposed = tuple(sorted(x for x, ss in by_x.items() if len(ss) >= 2))
    if exposed:
        return Resolution(EXPOSED, exposed, ambiguous, absent)
    if len(by_x) > 1:
        return Resolution(DISTINCT_KEYS, (), ambiguous, absent)
    if len(by_x) == 1:
        # One key, one signature. A NONE row carrying the SAME (scheme,
        # s) is that signature copied into an input that does not name
        # its signer: the same (r, s) from a second key would need a
        # targeted preimage, so it is the same key's, and it does not
        # block the answer. A NONE row with another s might be another
        # key, and does.
        (ss,) = by_x.values()
        if opaque <= ss:
            return Resolution(COPIED, (), ambiguous, absent)
    return Resolution(UNDETERMINED, (), ambiguous, absent)


# ---------------------------------------------------------------------------
# resolve: the build, against the node and the index, over the blocks
# the groups name
# ---------------------------------------------------------------------------

def _path(witness_dir, name=FILE_NAME):
    return os.path.join(witness_dir, name)


def _load_state(witness_dir):
    path = os.path.join(witness_dir, STATE_NAME)
    if not os.path.exists(path):
        raise WitnessError(f"no {STATE_NAME} in {witness_dir}: not a witness "
                           "table (or `resolve` never finished)")
    state = read_json(path, WitnessError)
    if state.get("format") != FORMAT_TAG:
        raise WitnessError(f"witness state says {state.get('format')!r}, "
                           f"this build reads {FORMAT_TAG!r}")
    return state


def _load_manifest(witness_dir):
    path = os.path.join(witness_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        raise WitnessError(f"no {MANIFEST_NAME} in {witness_dir}: this table "
                           "was never sealed, so it cannot be verified")
    return read_json(path, WitnessError)


def _heights_of_groups(nonces_dir, min_count):
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


class _Prevouts:
    """The index, asked the two things the attribution needs about a
    spent output: its lock (cheap, positional) and the block that
    created it (for the scriptPubKey itself, read from the node)."""

    def __init__(self, index):
        self.index = index
        self._tx = {}

    def _resolve(self, txid):
        if txid not in self._tx:
            self._tx[txid] = self.index.resolve(txid)
        return self._tx[txid]

    def out_ord(self, txid, vout):
        hit = self._resolve(txid)
        if hit is None:
            raise WitnessError(
                f"the index does not know tx {blockparse.hash_hex(txid)}, "
                "which an input in the census's range spends: the index "
                "and the chain do not describe the same history")
        first_out, n_out = hit
        if vout >= n_out:
            raise WitnessError(
                f"tx {blockparse.hash_hex(txid)} has {n_out} output(s) in "
                f"the index and an input spends vout {vout}")
        return first_out + vout

    def lock(self, txid, vout):
        return self.index.output(self.out_ord(txid, vout))[1]

    def height(self, txid, vout):
        return self.index.height_of_tx(
            self.index.tx_of_output(self.out_ord(txid, vout)))


def _fetch_parsed(client, heights, batch_size, error):
    """Blocks by height, in windows, each checked against the hash the
    node named for it."""
    for i in range(0, len(heights), batch_size):
        window = heights[i:i + batch_size]
        hashes, raws = client.fetch_blocks(window)
        for h, want_hash, raw in zip(window, hashes, raws):
            block = blockparse.parse_block(raw)
            if block.header.hash != want_hash:
                raise error(f"height {h}: the bytes do not hash to the "
                            "block hash asked for")
            yield h, block


def run_resolve(nonces_dir, witness_dir, client, index_dir, min_count=2,
                batch_size=25, out=sys.stdout):
    """Re-read the blocks the repeated points name, and keep the witnesses.

    Not resumable, and not pretending to be: the pass is a pure read of
    the chain and the index, so an interruption loses time and nothing
    else, and a re-run starts over. `count` and the choice of the first
    two rows depend on the whole pass, which is also why the table is
    never appended: a census that grew is resolved again.
    """
    # Imported here, not at module scope: outpoint_index reaches the
    # scan, which reaches the census, which this module imports.
    from nodsig import outpoint_index as oi

    t = WallClock("resolve")
    p = lambda *a: print(*a, file=out)

    parent = nn._load_manifest(nonces_dir, required=True)
    if parent["format"] not in PARENT_TAGS:
        # A v2 census names sightings whose r is 0 or >= n, which the
        # extraction since v3 refuses: re-reading their blocks either
        # aborts ("the census and the node disagree") or drops them,
        # and the table then says something the census does not.
        raise WitnessError(
            f"resolve needs a {nn.FORMAT_TAG} census; this one is "
            f"{parent['format']}: rebuild the census with the current "
            "code, or resolve it with the release that wrote it")
    census_state = nn._load_state(nonces_dir)
    if census_state["runs"]:
        # The groups would come from the fused file AND the runs, the
        # heights to re-read from the fused file alone: a repeat that
        # straddles the last merge would be witnessed once and filed as
        # "exposes nothing". Same rule as `nonces rewind`.
        raise WitnessError(
            f"the census has {len(census_state['runs'])} pending run(s): "
            "run `nonces merge` first, then resolve — a resolution reads "
            "the sealed file its groups came from, and a run is not in it "
            "yet")
    index = oi.Index(index_dir)
    try:
        census_to = census_state["last_height"]
        if index.watermark < census_to:
            # Every spent output the pass asks about was created below
            # the census's height; an index that stops earlier would
            # answer NONE for a lock it cannot see, and the bytes of the
            # table would then depend on which index was given.
            raise WitnessError(
                f"the index covers heights 1..{index.watermark:,} and the "
                f"census reaches {census_to:,}: the table must not depend "
                "on which index it was given, so the index has to cover "
                "the census")
        prevouts = _Prevouts(index)
        groups, wanted = _heights_of_groups(nonces_dir, min_count)
        heights = sorted(wanted)
        p(f"{len(groups):,} repeated points name {len(heights):,} block(s)")
        if not groups:
            p("nothing repeats: the table will be sealed empty, which is an "
              "answer and not a failure")

        os.makedirs(witness_dir, exist_ok=True)
        sightings = []             # (height, Sighting), in chain order
        pending = {}               # creating height -> [Sighting]
        stats = nn.new_stats()
        tallies = {"shape_without_link": 0, "ambiguous_multisig_m_lt_n": 0}
        done = 0
        for h, block in _fetch_parsed(client, heights, batch_size,
                                      WitnessError):
            found = set()
            for tx in block.transactions:
                if blockparse.is_coinbase(tx):
                    continue
                for tx_in in tx.inputs:
                    for sg in signatures_of_input(tx_in, wanted[h], stats,
                                                  prevouts.lock):
                        found.add(sg.r[:nn.R_PREFIX])
                        sightings.append((h, sg))
                        tallies["shape_without_link"] += sg.link_failed
                        tallies["ambiguous_multisig_m_lt_n"] += sg.m_lt_n
                        if sg.pending:
                            pending.setdefault(
                                prevouts.height(*sg.outpoint), []).append(sg)
            missing = wanted[h] - found
            if missing:
                raise WitnessError(
                    f"height {h}: {len(missing)} point(s) the census names "
                    "are not in this block. The census and the node "
                    "disagree; nothing is written")
            done += 1

        # The spent outputs the attribution needs to see: one read per
        # creating block, batched like the pass above.
        read = 0
        for h, block in _fetch_parsed(client, sorted(pending), batch_size,
                                      WitnessError):
            by_txid = {tx.txid: tx for tx in block.transactions}
            for sg in pending[h]:
                txid, vout = sg.outpoint
                tx = by_txid.get(txid)
                if tx is None or vout >= len(tx.outputs):
                    raise WitnessError(
                        f"height {h}: the index puts output "
                        f"{blockparse.hash_hex(txid)}:{vout} here and the "
                        "block does not hold it: the index and the node "
                        "disagree")
                spk = tx.outputs[vout].script_pubkey
                if hash160(spk) != prevouts.lock(txid, vout):
                    raise WitnessError(
                        f"height {h}: the scriptPubKey of "
                        f"{blockparse.hash_hex(txid)}:{vout} does not hash "
                        "to the lock the index holds for it")
                attribute_output(sg, spk)
            read += 1

        rows, counters = _reduce(sightings)
        counters.update(tallies)
        atomic_json(os.path.join(witness_dir, STATE_NAME),
                    {"format": FORMAT_TAG, "heights": len(heights),
                     "done": done, "output_blocks_read": read})
        with open(_path(witness_dir), "wb") as f:
            f.write(b"".join(rows))
        p(f"{len(rows):,} witness row(s) from {done:,} block(s), "
          f"{read:,} more read for spent outputs")
        return _seal(witness_dir, parent, index, groups, rows, counters, t,
                     out)
    finally:
        index.close()


def _reduce(sightings):
    """Two witnesses per triple settle it; a third adds nothing a
    resolution can use, so it is counted and dropped. The first two
    distinct (scheme, s) in chain order are kept, and `count` holds how
    many the triple has over the whole pass."""
    seen = {}
    counts = {}
    for h, sg in sightings:
        k = sg.triple()
        counts.setdefault(k, set()).add(sg.scheme_s)
        w = seen.setdefault(k, {})
        if sg.scheme_s not in w and len(w) < 2:
            w[sg.scheme_s] = (h, sg)
    rows = []
    counters = {c: 0 for c in ("attributed_beside", "attributed_position",
                               "attributed_output", "none")}
    names = {BESIDE: "attributed_beside", POSITION: "attributed_position",
             OUTPUT: "attributed_output", NONE: "none"}
    for k, witnesses in seen.items():
        n = len(counts[k])
        for h, sg in witnesses.values():
            rows.append(sg.as_record(n, h))
            counters[names[sg.cls]] += 1
    rows.sort()
    return rows, counters


def _seal(witness_dir, parent, index, groups, rows, counters, clock, out):
    """Write the manifest: the identity, the fingerprint, the parent and
    the index that was read.

    The parent is the census this table resolved, declared the way every
    child artifact here declares one. It matters more than usual: a
    witness table is only about the points ITS census found, so a table
    beside a different census is answering about something else. The
    index is declared beside it: the table is a pure function of the
    census, the chain and the index, and a stranger reproducing an
    OUTPUT row needs the third.
    """
    path = _path(witness_dir)
    files = {LOGICAL: {"file": FILE_NAME, "sha256": sha_file(path)}}
    heights = [rec_height(r) for r in rows]
    identity = make_identity(FORMAT_TAG,
                             min(heights) if heights else 0,
                             max(heights) if heights else 0,
                             [(LOGICAL, files[LOGICAL]["sha256"])])
    fingerprint = identity_fingerprint(identity)
    build = {
        "producer": producer(),
        "seconds": clock.stamp(),
        "wall": clock.wall(),
        # The parent's OWN tag, read from its manifest, never this code's
        # constant.
        "parent": declared_parent(parent["format"], parent["fingerprint"]),
        "index": declared_parent(index.format,
                                 index.manifest["fingerprint"]),
        "points_resolved": len(groups),
        "rows": len(rows),
    }
    build.update(counters)
    build.update({
        "files": files,
        "caches": {},
        "reconstruction": (
            "for every point the parent census reports as repeated, the "
            "blocks it names are re-read and each matching signature is "
            "attributed to a key (x, up to sign) and a class: BESIDE when "
            "one signature sits beside one key that hashes to the lock "
            "the input spends (the index says which), POSITION when an "
            "m-of-m CHECKMULTISIG or a tapscript template names the "
            "signer's slot, OUTPUT when the spent scriptPubKey is P2PK or "
            "a taproot key-path program, NONE otherwise. s is min(s, n-s) "
            "for ECDSA and as published for Schnorr. At most TWO rows are "
            "kept per (r, x, class) triple, the first two distinct "
            "(scheme, s) in ascending height order, with `count` holding "
            "how many the triple has in total. Rows are sorted by their "
            "raw bytes; the identity is then sealed by the shared recipe "
            "in docs/contracts/Artifact.md. attributed_* and none count "
            "rows; shape_without_link and ambiguous_multisig_m_lt_n count "
            "signatures the pass saw"),
    })
    manifest = seal_manifest(FORMAT_TAG, identity, build)
    atomic_json(os.path.join(witness_dir, MANIFEST_NAME), manifest)
    print(f"witness table over {len(groups):,} repeated point(s)", file=out)
    print(f"  parent {parent['format']}: {parent['fingerprint']}  (declared)",
          file=out)
    print(f"  index  {index.format}: {index.manifest['fingerprint']}  "
          "(declared)", file=out)
    print(f"fingerprint: {fingerprint}", file=out)
    return fingerprint


def iter_records(witness_dir, expect_sha=None):
    """Every row of a sealed table, in order."""
    return read_fixed(_path(witness_dir), REC, expect_sha=expect_sha,
                      error=WitnessError)


def rows_by_r(witness_dir):
    """The rows grouped by the full scalar, which is the unit of a
    resolution."""
    out = {}
    for rec in iter_records(witness_dir):
        out.setdefault(rec_r(rec), []).append(rec)
    return out


def rows_by_point(witness_dir):
    """The rows grouped by the census's 12-byte point, which is how the
    census asks; the rows of one prefix can hold several scalars."""
    out = {}
    for rec in iter_records(witness_dir):
        out.setdefault(rec_point(rec), []).append(rec)
    return out


# ---------------------------------------------------------------------------
# verify — the audit of a sealed table
# ---------------------------------------------------------------------------

def _check_row(rec):
    """Every rule `record` enforces, re-applied to a row read back: a
    file that rotted into a row the writer would refuse is caught here
    before the digest even runs."""
    record(rec_r(rec), rec_x(rec), rec_key_seen(rec), rec_s(rec),
           rec_count(rec), rec_height(rec), rec_flags(rec))


def run_verify(witness_dir, nonces_dir=None, csv_path=None, keys_csv=None):
    """Re-read every byte against the manifest, and re-derive the resolutions.

    The digests prove the file has not rotted. Re-deriving the resolutions
    from the rows proves the file still MEANS what it meant, which is the
    part a checksum cannot say. Passing `--nonces` confirms the declared
    parent instead of taking it on trust.

    `--csv` and `--keys-csv` write what the audit just re-derived, and
    they hang off the audit ON PURPOSE rather than off a reader of their
    own: exporting a resolution then requires having verified the table
    it came from, so a number that leaves this project has been checked
    by construction. It is also the only road to these numbers as data,
    which keeps one result from having two.
    """
    manifest = _load_manifest(witness_dir)
    p = print

    # The order is part of the format: one r contiguous, and inside it
    # one key contiguous. A file whose rows wandered still hashes to
    # something, so the digest alone would not say.
    prev = None
    for rec in iter_records(witness_dir):
        _check_row(rec)
        if prev is not None and rec < prev:
            raise WitnessError("rows are not sorted by their raw bytes: "
                               "this is not the file `resolve` writes")
        prev = rec
    by_r = rows_by_r(witness_dir)
    scalars_under = {}
    for r in by_r:
        scalars_under[r[:nn.R_PREFIX]] = scalars_under.get(r[:nn.R_PREFIX],
                                                           0) + 1
    tally = {}
    rows_out = []
    keys_out = {}
    for r, rows in sorted(by_r.items()):
        per_triple = {}
        for rec in rows:
            per_triple.setdefault((rec_x(rec), rec_class(rec)), []).append(rec)
        for group in per_triple.values():
            if any(rec_count(x) < len(group) for x in group):
                raise WitnessError(
                    f"r {r.hex()[:16]}…: a triple holds {len(group)} rows "
                    "and its count says fewer")
        res = resolution_of(rows)
        tally[res.kind] = tally.get(res.kind, 0) + 1
        for rec in rows:
            if has_key(rec):
                entry = keys_out.setdefault(rec_key_canon(rec),
                                            ["", set(), False])
                if rec_flags(rec) & FLAG_UNCOMPRESSED:
                    entry[0] = rec_key_seen(rec).hex()
                entry[1].add(rec_form(rec))
                if rec_x(rec) in res.exposed:
                    entry[2] = True
        if csv_path:
            heights = [rec_height(x) for x in rows]
            attributed = {rec_x(x) for x in rows if has_key(x)}
            classes = sorted({CLASS_NAMES[rec_class(x)] for x in rows})
            rows_out.append((
                r.hex(), r[:nn.R_PREFIX].hex(), res.kind,
                scalars_under[r[:nn.R_PREFIX]],
                len(attributed), len(res.exposed),
                max((rec_count(x) for x in rows), default=0),
                res.rows_ambiguous, res.rows_absent, "+".join(classes),
                min(heights), max(heights), _schemes_of(rows)))
    total = sum(tally.values())
    p(f"ok  {total:,} scalar(s) re-resolved from the rows themselves")
    for v in RESOLUTIONS:
        if tally.get(v):
            p(f"      {tally[v]:>7,}  {v}")
    collided = sum(1 for n in scalars_under.values() if n > 1)
    if collided:
        p(f"      {collided:>7,}  census prefix(es) covering more than one "
          "scalar (a column, not a resolution)")

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
        parent_confirmed = f"ok parent {census['format']} {actual}"

    verify_sealed(witness_dir, manifest, FORMAT_TAG, WitnessError,
                  fp_order=[LOGICAL], parent_confirmed=parent_confirmed)

    # Written only after the audit above has passed: `verify_sealed`
    # raises on any mismatch, so a CSV existing means the table it came
    # from was whole.
    if csv_path:
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(("r", "point", "resolution", "scalars_under_prefix",
                        "keys", "exposed_keys", "max_distinct_s",
                        "rows_ambiguous", "rows_absent", "attribution",
                        "first_height", "last_height", "schemes"))
            for row in rows_out:
                w.writerow(row)
        p(f"\nwrote {len(rows_out):,} scalar(s) to {csv_path}")
    if keys_csv:
        with open(keys_csv, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(("key_canon", "key_seen", "form", "exposed"))
            for canon, (seen, forms, exposed) in sorted(keys_out.items()):
                w.writerow((canon.hex(), seen, "+".join(sorted(forms)),
                            int(exposed)))
        p(f"wrote {len(keys_out):,} attributed key(s) to {keys_csv}")


def _schemes_of(rows):
    """Which signature schemes this scalar was published under."""
    names = []
    if any(not (rec_flags(r) & FLAG_SCHNORR) for r in rows):
        names.append("ecdsa")
    if any(rec_flags(r) & FLAG_SCHNORR for r in rows):
        names.append("schnorr")
    return "+".join(names) or "none"
