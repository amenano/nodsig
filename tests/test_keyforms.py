#!/usr/bin/env python3
"""test_keyforms.py — the identity of a public key, pinned.

Three things a reader must be able to rely on: a 65-byte key and its
33-byte form give ONE canonical digest, however the lead byte spells the
parity; the x-only form of taproot is `02 || x` and nothing else; and
the one direction that needs the curve, 33 to 65, is a square root that
refuses an x with no point behind it. The public vector is the key of
the genesis coinbase, so a stranger reproduces every line with a hash
function and one modular exponentiation.

Usage:
    python3 test_keyforms.py    # prints PASS or fails loudly
"""

import json
import os
import sys

from nodsig import keyforms as kf
from nodsig.hashing import hash160

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "keyforms", "vectors.json")


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


def _vectors():
    with open(FIXTURE) as f:
        return json.load(f)


def test_the_genesis_key_has_one_canonical_digest():
    v = _vectors()
    genesis = bytes.fromhex(v["genesis_key_65"])
    comp = kf.compressed_of(genesis)
    check(comp[0] == 0x03 and comp[1:] == genesis[1:33],
          "the compressed face of the genesis key has lead 03 (y is odd)")
    check(hash160(genesis).hex() == "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
          "hash160 of the 65-byte genesis key is the published one")
    check(hash160(comp).hex() == "9f81322cc88622ca4ccb2a52a21e2888727aa535",
          "hash160 of the compressed genesis key is the one the page prints")
    for case in v["compressed_of"]:
        check(kf.compressed_of(bytes.fromhex(case["input"])).hex()
              == case["output"], f"compressed_of({case['input'][:8]}…)")
    print("ok  genesis: 65 bytes, 03||x, and two hybrid spellings give one "
          "compressed face")


def test_canonical_key_decides_once():
    for case in _vectors()["canonical_key"]:
        got = kf.canonical_key(bytes.fromhex(case["input"]),
                               xonly=case["xonly"])
        if case["form"] is None:
            check(got is None, f"{case['input'][:8]}… is not a key")
            continue
        d, seen, form = got
        check(d.hex() == case["digest_canon"], f"canonical digest of "
              f"{case['input'][:8]}…")
        check((seen.hex() if seen else None) == case["digest_seen"],
              f"seen digest of {case['input'][:8]}…")
        check(form == case["form"], f"form of {case['input'][:8]}…")
    print("ok  canonical_key: compressed, uncompressed, hybrid, x-only, and "
          "the refusals")


def test_the_root_names_the_other_face_and_refuses_a_non_point():
    v = _vectors()
    for case in v["uncompressed_of"]:
        check(kf.uncompressed_of(bytes.fromhex(case["input"])).hex()
              == case["output"], "uncompressed_of(03||x) gives the 65 bytes")
    for bad in v["not_on_curve"]:
        try:
            kf.uncompressed_of(bytes.fromhex(bad))
            fail("an x with no point on the curve was accepted")
        except kf.KeyFormError:
            pass
    d_c, d_u, derived = kf.faces_of(bytes.fromhex(v["genesis_key_65"]))
    check(not derived, "from 65 bytes nothing is derived")
    comp = kf.compressed_of(bytes.fromhex(v["genesis_key_65"]))
    d_c2, d_u2, derived2 = kf.faces_of(comp)
    check(derived2 and (d_c, d_u) == (d_c2, d_u2),
          "from 33 bytes the other face is derived, and the digests agree")
    print("ok  root: 33 -> 65 by one square root, refused off the curve")


def main():
    test_the_genesis_key_has_one_canonical_digest()
    test_canonical_key_decides_once()
    test_the_root_names_the_other_face_and_refuses_a_non_point()
    print("PASS: a key is one point under every serialization")


if __name__ == "__main__":
    main()
