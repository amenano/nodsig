#!/usr/bin/env python3
"""
sightings.py — what a key sighting is, decided once for both roads.

Two extraction pipelines read the chain for revealed keys: the reveal
archive (`reveal_archive.extract_revelations`) and the direct reuse scan
(`reuse_scan.extract_reveals`). They are written twice on purpose, in
the WALK (which pushes, which witness items, which candidates, which
outputs), so that a mistake in one is caught by the other at the
cross-check. What they must NOT decide twice is what a key looks like,
which candidate can be a script, and what a sighting burns under a
read-time perimeter: a rule written twice is a rule that drifts, and
the cross-check would then measure the drift as agreement. This module
holds those three decisions, and the eight provenance and form bits
the archive's `keys` record carries.

A kernel: no I/O, no flag; the byte rules of `keyforms`, the signature
readers of `nonces` and the push parser of `blockparse` are all it uses.
"""

import hashlib

from nodsig import nonces
from nodsig.blockparse import ParseError, script_pushes
from nodsig.hashing import hash160
from nodsig.keyforms import UNCOMPRESSED, XONLY, canonical_key

# Provenance bits of a key sighting. "Direct" = pushed as itself in the
# unlocking data; "inner" = found inside a revealed candidate script (a
# multisig cosigner whose script just went public).
FLAG_SIG = 1          # direct, in a scriptSig
FLAG_WIT = 2          # direct, in a witness (the control block's internal
                      # key included)
FLAG_INNER_SIG = 4    # inside the last scriptSig push (redeem script)
FLAG_INNER_WIT = 8    # inside the last witness item (witness script), or
                      # a revealed taproot leaf
# Form bit, not provenance: the key's serialized form was the 65-byte
# one (lead 04, 06 or 07). The form is a function of the digest's
# preimage, so every sighting of one digest agrees on this bit and the
# OR merge cannot change it: append == rebuild is untouched.
FLAG_UNCOMPRESSED = 16
# OUT: the key sat in a scriptPubKey (pay-to-pubkey, bare multisig), so
# it was public from the block that created the output. OTHER_FACE: the
# chain showed this point in another serialization; this digest is its
# compressed form, written so that a point revealed at 65 bytes marks
# the address of its 33-byte form (one identity per point: keyforms.py).
# XONLY: the key was seen as the 32-byte x-only form of taproot; the
# digest is hash160(02 || x), by BIP 340's definition.
FLAG_OUT = 32
FLAG_OTHER_FACE = 64
FLAG_XONLY = 128
FLAGS_DEFINED = 255
# The provenances that count only under the full read-time perimeter:
# no perimeter flag was added for them (decided with the format).
FLAGS_FULL_ONLY = FLAG_OUT | FLAG_OTHER_FACE | FLAG_XONLY

# Opcodes that consume the key pushed just before them in a taproot
# leaf: CHECKSIG, CHECKSIGVERIFY, CHECKSIGADD.
_LEAF_SIG_OPS = frozenset((0xac, 0xad, 0xba))

MAX_INNER_KEYS = 255


def key_records(out, item, provenance, xonly=False):
    """Append the `keys` record(s) one key-shaped item yields, as
    (category, digest, flags): the digest of the form seen with its
    provenance and form bits, and, when the form seen is not the
    compressed one, the compressed digest under OTHER_FACE. Returns True
    when `item` was a key."""
    ck = canonical_key(item, xonly=xonly)
    if ck is None:
        return False
    canon, seen, form = ck
    if form == XONLY:
        out.append(("keys", canon, provenance | FLAG_XONLY))
    elif form == UNCOMPRESSED:
        out.append(("keys", seen, provenance | FLAG_UNCOMPRESSED))
        out.append(("keys", canon, FLAG_OTHER_FACE))
    else:
        out.append(("keys", canon, provenance))
    return True


def is_control_block(item):
    return (len(item) >= 33 and (len(item) - 33) % 32 == 0
            and item[0] & 0xfe == 0xc0)


def taproot_body(witness):
    """The witness without its annex, when it carries one."""
    if len(witness) >= 2 and witness[-1][:1] == b"\x50":
        return witness[:-1]
    return witness


def leaf_xonly_keys(leaf):
    """The 32-byte pushes of a taproot leaf that an opcode consuming a
    key follows: `<x> OP_CHECKSIG`, `<x> OP_CHECKSIGVERIFY`, and the
    `<x> OP_CHECKSIGADD` chain of the multisig template. A 32-byte push
    followed by anything else (a hashlock's preimage hash) is not a key.
    Walked by opcode, so a push is never mistaken for one inside the
    data of another."""
    out = []
    i, n = 0, len(leaf)
    while i < n:
        op = leaf[i]
        if 1 <= op <= 75:
            data, i = leaf[i + 1:i + 1 + op], i + 1 + op
        elif op == 0x4c and i + 1 < n:
            ln = leaf[i + 1]
            data, i = leaf[i + 2:i + 2 + ln], i + 2 + ln
        elif op == 0x4d and i + 2 < n:
            ln = int.from_bytes(leaf[i + 1:i + 3], "little")
            data, i = leaf[i + 3:i + 3 + ln], i + 3 + ln
        elif op == 0x4e and i + 4 < n:
            ln = int.from_bytes(leaf[i + 1:i + 5], "little")
            data, i = leaf[i + 5:i + 5 + ln], i + 5 + ln
        else:
            i += 1
            continue
        if len(data) == 32 and i < n and leaf[i] in _LEAF_SIG_OPS:
            out.append(data)
    return out


def candidate_shape(item, stats, in_slot=False, key_path=False,
                    witness_len=0):
    """The shape that keeps an item out of the script partitions, or
    None when it may be a script. A key or a signature CAN be a script
    (`02` is a push of two bytes, `30` a push of 48), which is why the
    exception is counted and published; a control block or an annex
    cannot (their first byte executes and fails), which is exact."""
    if canonical_key(item) is not None:
        stats["filtered_key_shaped"] += 1
        return "key"
    if nonces.signature_r(item) is not None or (
            in_slot and nonces.taproot_r(item, key_path) is not None):
        stats["filtered_signature_shaped"] += 1
        return "signature"
    if is_control_block(item) or (witness_len >= 2 and item[:1] == b"\x50"):
        stats["filtered_control_or_annex"] += 1
        return "control_or_annex"
    return None


def script_records(out, script, cat, inner_flag, stats):
    """The record of a kept candidate script and of the keys inside it."""
    try:
        inner = script_pushes(script)
    except ParseError:
        stats["malformed_inner_script"] += 1
        inner = []
    keys = [p for p in inner if canonical_key(p) is not None]
    n = min(len(keys), MAX_INNER_KEYS)
    if cat == "scripts20":
        out.append((cat, hash160(script), n))
    else:
        out.append((cat, hashlib.sha256(script).digest(), n))
    for p in keys:
        key_records(out, p, inner_flag)


def output_keys(spk):
    """The key pushes of a pay-to-pubkey or bare multisig scriptPubKey,
    or none: `<key> OP_CHECKSIG`, `OP_m <keys> OP_n OP_CHECKMULTISIG`."""
    n = len(spk)
    if n in (35, 67) and spk[0] == n - 2 and spk[-1] == 0xac:
        return [spk[1:-1]]
    if (n >= 37 and spk[-1] == 0xae and 0x51 <= spk[-2] <= 0x60
            and 0x51 <= spk[0] <= 0x60):
        try:
            return script_pushes(spk[1:-2])
        except ParseError:
            return []
    return []


def new_filter_stats():
    return {"out_keys": 0, "filtered_key_shaped": 0,
            "filtered_signature_shaped": 0, "filtered_control_or_annex": 0}


def burns_for(cat, digest, flags, faces, cosigners):
    """What one archived record burns in the four lock sets under the
    chosen perimeter: a list of (lock type, lock digest), empty when the
    record is out of the perimeter.

    The archive itself has no perimeter: it stores every sighting with
    its bits. This map restates the reuse scan's declared rules, once
    for both roads: a revealed key burns all its faces (both hash160
    forms plus the P2SH-wrapped one) under the full perimeter, or only
    the exact form it was seen in under --no-faces; inner (cosigner)
    sightings count only with cosigners on; a key published in an
    output, the other face of a point and an x-only key of a taproot
    script path count under the full reading only; candidate redeem and
    witness scripts burn their own hash always, that being the base
    criterion, not an extension."""
    if cat == "scripts20":
        return [("p2sh", digest)]
    if cat == "scripts32":
        return [("p2wsh", digest)]
    effective = flags & (FLAG_SIG | FLAG_WIT)
    if cosigners:
        effective |= flags & (FLAG_INNER_SIG | FLAG_INNER_WIT)
    if faces and cosigners:
        effective |= flags & FLAGS_FULL_ONLY
    if not effective:
        return []
    if faces:
        return [("p2pkh", digest), ("p2wpkh", digest),
                ("p2sh", hash160(b"\x00\x14" + digest))]
    out = []
    if flags & FLAG_SIG or (cosigners and flags & FLAG_INNER_SIG):
        out.append(("p2pkh", digest))
    if flags & FLAG_WIT or (cosigners and flags & FLAG_INNER_WIT):
        out.append(("p2wpkh", digest))
    return out
