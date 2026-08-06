#!/usr/bin/env python3
"""
test_conformance.py — the neutral conformance vectors, run against the
reference implementation.

The vectors under tests/fixtures/<name>/vectors.json are language-neutral:
inputs and expected outputs as hex/decimal/JSON, with no dependency on this
Python runtime. A port in another language (or a native kernel) proves it is
identical by running the SAME files and comparing. Here they double as
anti-drift tests of the reference: the docs promise these vectors, so the
reference must keep meeting them.

The values are authoritative, not circular: the hashing outputs are the
published RIPEMD-160 vectors and real Bitcoin digests, the compact-size
encodings are fixed by the protocol, and the fingerprint recipe is stated in
full in the fixture and in docs/formats.
"""

import json
import os

from nodsig.artifact import (canonical_identity, canonical_statement,
                             identity_fingerprint, statement_digest)
from nodsig.blockparse import read_compactsize, write_compactsize
from nodsig.check_addresses import AddressError, decode_address, script_pubkey
from nodsig.hashing import hash160, ripemd160, sha256d

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES, name, "vectors.json")) as f:
        return json.load(f)


def test_hashing_vectors():
    data = _load("hashing")
    funcs = {"sha256d": sha256d, "ripemd160": ripemd160, "hash160": hash160}
    for fname, func in funcs.items():
        for v in data[fname]:
            got = func(bytes.fromhex(v["input"])).hex()
            assert got == v["output"], (
                f"{fname}({v['input'][:16]}…): {got} != {v['output']}")


def test_compactsize_vectors():
    for v in _load("compactsize")["vectors"]:
        value, hexbytes = v["value"], v["hex"]
        assert write_compactsize(value).hex() == hexbytes, (
            f"write_compactsize({value}) != {hexbytes}")
        decoded, pos = read_compactsize(bytes.fromhex(hexbytes), 0)
        assert decoded == value and pos == len(hexbytes) // 2, (
            f"read_compactsize({hexbytes}) != ({value}, len)")


def test_fingerprint_vectors():
    """Both halves of the recipe: the identity serializes to exactly those
    bytes, and those bytes hash to exactly that fingerprint. A porter can
    fail the first and pass the second only by luck."""
    for v in _load("fingerprint")["vectors"]:
        got_bytes = canonical_identity(v["identity"]).hex()
        assert got_bytes == v["canonical_bytes_hex"], (
            f"canonical bytes ({v['note']}): {got_bytes}")
        got = identity_fingerprint(v["identity"])
        assert got == v["fingerprint"], (
            f"fingerprint ({v['note']}): {got} != {v['fingerprint']}")


def test_statement_vectors():
    """The target a signature layer aims at. Pinned here rather than left to
    each signer to invent, because two signers who serialize differently
    produce signatures neither can check."""
    for v in _load("statement")["vectors"]:
        got_bytes = canonical_statement(v["manifest"]).hex()
        assert got_bytes == v["canonical_bytes_hex"], (
            f"canonical bytes ({v['note']}): {got_bytes}")
        got = statement_digest(v["manifest"])
        assert got == v["statement"], (
            f"statement ({v['note']}): {got} != {v['statement']}")


def test_addresscodec_vectors():
    data = _load("addresscodec")
    for v in data["valid"]:
        ad = decode_address(v["address"])
        assert ad.kind == v["kind"], f"{v['address']}: kind {ad.kind}"
        assert ad.digest.hex() == v["digest"], f"{v['address']}: digest"
        spk = script_pubkey(ad)
        assert spk.hex() == v["script_pubkey"], f"{v['address']}: script_pubkey"
        assert hash160(spk).hex() == v["lock"], f"{v['address']}: lock"
        # exposure routes by (digest, category), distinct from the lock
        exp = v["exposure_query"]
        if "by_construction" in exp:
            assert ad.category is None, f"{v['address']}: expected by-construction"
        else:
            assert ad.category == exp["category"], f"{v['address']}: category"
            assert ad.digest.hex() == exp["digest"], f"{v['address']}: exp digest"
    for s in data["invalid"]:
        try:
            decode_address(s)
            raise AssertionError(f"{s!r} should have been rejected")
        except AddressError:
            pass
