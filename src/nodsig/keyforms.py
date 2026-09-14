#!/usr/bin/env python3
"""
keyforms.py — the identity of a public key, decided once.

A public key is a point on secp256k1. The chain serializes it three ways:
33 bytes (`02` or `03`, the parity of y, then x), 65 bytes (`04` then x
then y; the hybrid leads `06`/`07` repeat the parity and name the same
point), and 32 bytes (x alone: the x-only form of taproot, defined by
BIP 340 as the point with even y). The private key is the same behind
all of them, so "has this key been revealed" is a question about the
point, and every artifact that keys a point by a digest keys it by the
digest of the COMPRESSED form.

Three of those forms convert without curve arithmetic:

  - 65 -> 33: the parity of y is the last bit of its last byte; the lead
    byte is ignored, so a hybrid whose lead disagrees with y (which the
    reference node refuses) cannot produce a wrong face;
  - 32 -> 33: `02 || x`, by the definition of x-only;
  - 33 -> 65 is the one direction that needs the curve: y from x is a
    square root modulo p, which for secp256k1 (p = 3 mod 4) is one
    modular exponentiation. It is FIELD arithmetic: no point is
    multiplied, no signature verified, no key recovered. It lives in
    `uncompressed_of`, is called only where a person typed a key (`check
    --key`, `nonces address --key`), never in a scan, and every command
    that used it says so in its output.

This module is a kernel of pure functions of bytes, like hashing.py: no
I/O, no other module of the project but hashing.
"""

from nodsig.hashing import hash160

# The field prime of secp256k1. p = 3 (mod 4), which is what makes the
# square root below a single exponentiation.
P = 2**256 - 2**32 - 977

COMPRESSED = "compressed"
UNCOMPRESSED = "uncompressed"
XONLY = "xonly"

_LEADS_33 = (0x02, 0x03)
_LEADS_65 = (0x04, 0x06, 0x07)


class KeyFormError(ValueError):
    """Bytes that are not a serialized public key, or an x that is not
    on the curve: the caller asked about something that is not a key."""


def looks_like_key(item):
    """Shape only: 33 bytes with lead 02/03, or 65 with lead 04/06/07.

    A false positive is harmless by construction wherever this decides
    what to archive: a digest can only match a lock that is its exact
    preimage. The hybrid leads are accepted because they are consensus
    valid and present on the chain in small numbers, and a key revealed
    only in that form was invisible to the readers that refused them."""
    n = len(item)
    return ((n == 33 and item[0] in _LEADS_33)
            or (n == 65 and item[0] in _LEADS_65))


def compressed_of(item):
    """The 33-byte form of a 33- or 65-byte key, without arithmetic."""
    n = len(item)
    if n == 33 and item[0] in _LEADS_33:
        return bytes(item)
    if n == 65 and item[0] in _LEADS_65:
        return bytes([0x02 | (item[64] & 1)]) + bytes(item[1:33])
    raise KeyFormError(f"{n} bytes with lead {item[:1].hex() or '-'} is "
                       "not a serialized public key")


def canonical_key(item, xonly=False):
    """(digest of the compressed form, digest of the form seen, form),
    or None when the bytes are not a key.

    `xonly=True` says the caller is in a place where a 32-byte item IS
    a key (a taproot leaf after a push of 32 bytes, the internal key of a
    control block); anywhere else 32 bytes are a hash or a nonce and are
    refused. For an x-only key the compressed form is `02 || x` and the
    digest seen is None: nothing on the chain hashes that form."""
    n = len(item)
    if xonly and n == 32:
        return hash160(b"\x02" + bytes(item)), None, XONLY
    if not looks_like_key(item):
        return None
    if n == 33:
        # The compressed form IS the form seen: one digest, hashed once.
        # Hashing it twice cost 3.8 µs per compressed key sighting, on the
        # most frequent item of every scan.
        digest = hash160(bytes(item))
        return digest, digest, COMPRESSED
    return hash160(compressed_of(item)), hash160(bytes(item)), UNCOMPRESSED


def uncompressed_of(item33):
    """The 65-byte form of a 33-byte key: y from x by one square root
    modulo p, the parity chosen by the lead byte. Refuses an x that is
    not on the curve. Field arithmetic, and the only piece of it in the
    project: call it where a person typed a key, and say so."""
    if len(item33) != 33 or item33[0] not in _LEADS_33:
        raise KeyFormError("uncompressed_of wants a 33-byte key with lead "
                           "02 or 03")
    x = int.from_bytes(item33[1:], "big")
    if x >= P:
        raise KeyFormError("x is not a field element of secp256k1")
    rhs = (pow(x, 3, P) + 7) % P
    y = pow(rhs, (P + 1) // 4, P)
    if (y * y) % P != rhs:
        raise KeyFormError("not a point on secp256k1: no y has this x")
    if (y & 1) != (item33[0] & 1):
        y = P - y
    return b"\x04" + item33[1:] + y.to_bytes(32, "big")


def faces_of(item):
    """Every digest a person asking about this key may hold: the digest
    of the compressed form, and of the uncompressed form, the second
    derived by the root when only the first was given. Returns
    (digest_compressed, digest_uncompressed, derived), `derived` saying
    whether the root was used."""
    n = len(item)
    if n == 65:
        comp = compressed_of(item)
        return hash160(comp), hash160(bytes(item)), False
    if n == 33:
        return (hash160(bytes(item)), hash160(uncompressed_of(item)),
                True)
    raise KeyFormError(f"{n} bytes is not a serialized public key")
