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


# ---------------------------------------------------------------------------
# The format matrix in the docs, pinned to the code
# ---------------------------------------------------------------------------
#
# A hand-maintained "which version do we emit / read" table drifts exactly the
# way scattered fingerprints do, and drifts silently: nothing breaks, a reader
# is just told something that stopped being true. So the table lives in
# docs/ARTIFACTS.md and this test rebuilds it from each module's FORMAT_TAG and
# READ_TAGS. A format that moves without the documentation moving fails here.

FORMAT_MATRIX = [
    ("nodsig.graphemit", "graph"),
    ("nodsig.headers", "headers"),
    ("nodsig.reveal_archive", "revelation archive"),
    ("nodsig.nonces", "nonce census"),
    ("nodsig.witness", "nonce witness table"),
    ("nodsig.outpoint_index", "outpoint index"),
    ("nodsig.derivatives", "outpoint derivatives"),
    ("nodsig.block_stats", "block stats"),
    ("nodsig.address_book", "address book (input)"),
    ("nodsig.check_report", "check report (output)"),
]

ARTIFACTS_DOC = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "docs", "ARTIFACTS.md")


def test_the_format_matrix_matches_the_code():
    import importlib
    rows = {}
    for module, label in FORMAT_MATRIX:
        mod = importlib.import_module(module)
        tag = mod.FORMAT_TAG
        also = [t for t in getattr(mod, "READ_TAGS", ()) if t != tag]
        rows[label] = (tag, also)

    with open(ARTIFACTS_DOC) as f:
        doc = f.read()
    for label, (tag, also) in rows.items():
        want = (f"| {label} | `{tag}` | "
                + (" ".join(f"`{t}`" for t in also) if also else "—")
                + " |")
        assert want in doc, (
            f"docs/ARTIFACTS.md is missing or has a stale row for {label}.\n"
            f"  expected: {want}\n"
            "  The code is the authority: fix the table, not the constant.")

    # And the other direction, which is the one that actually rots: a row in
    # the table for a format nothing emits any more.
    import re
    section = doc.split("## What this version emits, and what it still reads")[1]
    section = section.split("\n## ")[0]
    for line in section.splitlines():
        m = re.match(r"\|\s*([^|]+?)\s*\|\s*`([^`]+)`", line)
        if m and m.group(1) not in ("artifact", "---"):
            assert m.group(1) in rows, (
                f"docs/ARTIFACTS.md lists '{m.group(1)}', which no module in "
                "FORMAT_MATRIX emits: either the artifact went away or this "
                "test needs the new module added")
            assert rows[m.group(1)][0] == m.group(2), (
                f"'{m.group(1)}' is documented as {m.group(2)} but the code "
                f"emits {rows[m.group(1)][0]}")
