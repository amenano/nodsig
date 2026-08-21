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
    ("nodsig.firstspend", "first-spend table"),
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


# ---------------------------------------------------------------------------
# Release gates: what a machine can hold about the public documentation
# ---------------------------------------------------------------------------
#
# These two catch the mechanical half of a release sweep. They do NOT catch the
# half that actually bit us — a sentence that quietly became false, like a
# gallery telling readers to rebuild and find the same bytes after a format
# change. Nothing cheap detects that, which is why AGENTS.md carries a
# documentation sweep as a written step and names what to look for.

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_the_changelog_documents_the_current_version():
    """A release whose notes were never written is a release nobody can
    decide whether to take."""
    from nodsig import __version__
    with open(os.path.join(ROOT, "CHANGELOG.md")) as f:
        text = f.read()
    heading = f"\n## {__version__} "
    assert heading in text, (
        f"CHANGELOG.md has no section for {__version__}. Either the version "
        "was bumped without notes, or the notes are still under "
        "'## Unreleased' and the heading needs closing.")
    section = text.split(heading, 1)[1].split("\n## ", 1)[0]
    assert "Do your artifacts still work?" in section, (
        f"the {__version__} section does not answer 'do your artifacts still "
        "work?'. It is the question a reader holding 596 GB actually has, and "
        "the changelog promises it under every release.")


# Tags that appear in the documentation without being emitted or read by a
# module, each for a stated reason. Anything NOT on this list and not in the
# format matrix is a name the documentation invented or forgot to retire.
DOCUMENTED_ELSEWHERE = {
    "locks-v1": "reuse_scan writes it into the locks manifest (a literal)",
    "reuse-scan-v1": "reuse_scan writes it into the checkpoint state",
    "nodsig-identity-v3": "artifact.IDENTITY_TAG, the fingerprint recipe",
    "nodsig-statement-v1": "artifact.STATEMENT_TAG",
    "graph-v1": "historical: the earlier seal, which still decodes",
    "address-book-v1": "historical: superseded by v2, named in the changelog",
    "check-report-v1": "historical: superseded by v2",
    "address-book-v3": "forward reference: what a breaking change would be called",
    "check-report-v3": "forward reference: same",
}


def test_docs_name_no_format_that_does_not_exist():
    import importlib
    import re
    import subprocess
    known = set(DOCUMENTED_ELSEWHERE)
    for module, _label in FORMAT_MATRIX:
        mod = importlib.import_module(module)
        known.add(mod.FORMAT_TAG)
        known.update(getattr(mod, "READ_TAGS", ()))

    files = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT,
                           capture_output=True, text=True).stdout.split()
    pattern = re.compile(r"(?<![\w-])([a-z][a-z0-9]*(?:-[a-z0-9]+)*-v\d+)(?![\w-])")
    seen = {}
    for rel in files:
        with open(os.path.join(ROOT, rel)) as f:
            for n, line in enumerate(f, 1):
                for tag in pattern.findall(line):
                    seen.setdefault(tag, f"{rel}:{n}")
    unknown = {t: where for t, where in seen.items() if t not in known}
    assert not unknown, (
        "the documentation names formats no module emits, reads, or has an "
        "entry for in DOCUMENTED_ELSEWHERE:\n  "
        + "\n  ".join(f"{t}  ({where})" for t, where in sorted(unknown.items()))
        + "\nEither the tag is stale, or it is deliberate and belongs on the "
          "list with the reason it is there.")
