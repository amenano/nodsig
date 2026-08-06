#!/usr/bin/env python3
"""
hashing.py — the hash primitives every other module builds on.

This is the deepest, smallest kernel: pure functions of bytes, no I/O, no
dependency on any other module here. Three primitives cover the whole
codebase:

  - `sha256d`  — SHA-256 applied twice. Block hashes, txids and the Merkle
                 tree all use it; it is the only cryptography a parser needs.
  - `ripemd160`— RIPEMD-160, with a pure-Python fallback (see below).
  - `hash160`  — RIPEMD-160 of SHA-256: the 20-byte digest that turns a
                 public key (or a redeem script) into the value a lock stores.

Why a fallback for RIPEMD-160: OpenSSL 3 moved it to the "legacy" provider,
so on many modern systems `hashlib.new("ripemd160")` raises. Bitcoin needs
it (every classic address is RIPEMD-160 of SHA-256), so `_ripemd160_pure`
implements it from the specification and is used only when hashlib cannot.
Speed is not required here — the scan hashes candidates, not the whole
chain — correctness is: the suite checks it against the published test
vectors AND against real chain data (the first SegWit redeem script).
"""

import hashlib
import sys


def sha256d(data):
    """Bitcoin's workhorse: SHA-256 applied twice.

    Block hashes, txids and the Merkle tree all use this same function;
    it is the only piece of cryptography a parser needs.
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _ripemd160_pure(data):
    """RIPEMD-160 in pure Python, straight from the specification.

    Why it exists: OpenSSL 3 moved RIPEMD-160 to its "legacy" provider,
    so on many modern systems `hashlib.new("ripemd160")` simply fails —
    and Bitcoin needs it (every classic address is RIPEMD-160 of
    SHA-256). Fast is not required here (the scan hashes candidates,
    not the whole chain), correct is: the self-test checks this
    implementation against published test vectors AND against real
    chain data. Used only when hashlib cannot help.
    """
    K1 = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
    K2 = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
    # Message-word order and per-round rotation amounts, both lines.
    R1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    R2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    S1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    S2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    # Standard Merkle-Damgård padding, like MD4/MD5: a 0x80 byte, zeros,
    # then the bit length in 64 bits little-endian.
    msg = bytes(data)
    msg += b"\x80" + b"\x00" * ((55 - len(data)) % 64)
    msg += (len(data) * 8).to_bytes(8, "little")

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little")
             for i in range(16)]
        a, b, c, d, e = h            # left line
        A, B, C, D, E = h            # right line (mirrored schedule)
        for j in range(80):
            a, e, d, c, b = e, d, rol(c, 10), b, (
                rol((a + f(j, b, c, d) + x[R1[j]] + K1[j // 16])
                    & 0xFFFFFFFF, S1[j]) + e) & 0xFFFFFFFF
            A, E, D, C, B = E, D, rol(C, 10), B, (
                rol((A + f(79 - j, B, C, D) + x[R2[j]] + K2[j // 16])
                    & 0xFFFFFFFF, S2[j]) + E) & 0xFFFFFFFF
        h = [(h[1] + c + D) & 0xFFFFFFFF, (h[2] + d + E) & 0xFFFFFFFF,
             (h[3] + e + A) & 0xFFFFFFFF, (h[4] + a + B) & 0xFFFFFFFF,
             (h[0] + b + C) & 0xFFFFFFFF]
    return b"".join(v.to_bytes(4, "little") for v in h)


try:
    hashlib.new("ripemd160", b"")
    def ripemd160(data):
        return hashlib.new("ripemd160", data).digest()
    RIPEMD160_IS_PURE_PYTHON = False
except ValueError:                       # OpenSSL without legacy provider
    ripemd160 = _ripemd160_pure
    RIPEMD160_IS_PURE_PYTHON = True


def warn_if_slow_ripemd160(what):
    """Say it once, out loud, before a chain-scale command starts.

    The fallback keeps the tools RUNNING everywhere, which is why it
    exists — but it is ~50x slower per digest, and hash160 sits on the
    per-record path of every scan and every index build (billions of
    calls). Silently, that turns a two-day run into a two-month one
    with nothing on screen to explain it, and an operator cannot fix
    what nobody named. On most systems the cure is one line: enable
    OpenSSL's legacy provider."""
    if RIPEMD160_IS_PURE_PYTHON:
        print(f"warning: this OpenSSL has no ripemd160, so {what} will "
              "use the pure-Python fallback — correct, but roughly 50x "
              "slower per digest, on a path that runs billions of "
              "times. Enable OpenSSL's legacy provider before a "
              "chain-scale run.", file=sys.stderr)


def hash160(data):
    """Bitcoin's address digest: RIPEMD-160 of SHA-256. This is the
    function that turns a public key (or a redeem script) into the
    20-byte hash the lock stores."""
    return ripemd160(hashlib.sha256(data).digest())
