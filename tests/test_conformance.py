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

import hashlib
import json
import os

import pytest

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


def test_keyforms_vectors():
    """The identity of a public key, on public data: the genesis key in
    its three spellings and its x-only form give the digests the format
    pages print."""
    from nodsig import keyforms as kf
    data = _load("keyforms")
    for v in data["compressed_of"]:
        assert kf.compressed_of(bytes.fromhex(v["input"])).hex() == v["output"]
    for v in data["uncompressed_of"]:
        assert kf.uncompressed_of(bytes.fromhex(v["input"])).hex() == v["output"]
    for v in data["canonical_key"]:
        got = kf.canonical_key(bytes.fromhex(v["input"]), xonly=v["xonly"])
        if v["form"] is None:
            assert got is None
        else:
            d, seen, form = got
            assert (d.hex(), seen.hex() if seen else None, form) == \
                (v["digest_canon"], v["digest_seen"], v["form"])


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
    ("nodsig.firstreveal", "first-reveal table"),
    ("nodsig.block_stats", "block stats"),
    ("nodsig.priceseries", "price series (external input)"),
    ("nodsig.blockprice", "block price (external input, derived)"),
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
    "locks-v2": "reuse_scan.LOCKS_TAG, the sealed lock set",
    "reuse-scan-v2": "reuse_scan.STATE_TAG, the checkpoint state",
    "reuse-hits-v2": "reuse_scan.HITS_TAG, the identity of a burnt set",
    "reuse-stats-v2": "reuse_scan.STATS_TAG, the JSON of `reuse stats`",
    "reuse-curve-v2": "curve.REUSE_TAG, the sidecar of the reuse curve",
    "archive-curve-v2": "curve.ARCHIVE_TAG, the sidecar of the archive's curve",
    "locks-v1": "historical: superseded by v2, named in the changelog",
    "reuse-scan-v1": "historical: superseded by v2, named in the changelog",
    "reuse-stats-v1": "historical: superseded by v2, named in the changelog",
    "nodsig-identity-v3": "artifact.IDENTITY_TAG, the fingerprint recipe",
    "nodsig-statement-v1": "historical: superseded by v2, named in the changelog",
    "graph-v1": "historical: the earlier seal, read with the release that wrote it",
    "nonces-v2": "historical: superseded by v3, read with the release that wrote it",
    "outpoint-index-v2": "historical: superseded by v3, read with the release that wrote it",
    "outpoint-derived-v2": "historical: superseded by v3, read with the release that wrote it",
    "reveal-archive-v1": "historical: the first published archive, named "
                         "by the archive's page among the formats refused",
    "reveal-archive-v3": "historical: the 2.x archive, read by the release "
                         "that wrote it",
    "reveal-proof-v1": "reveal_archive.PROOF_TAG: the proof sealed beside the "
                       "archive, documented on the archive's page",
    "reuse-hits-v1": "historical: the v1 identity of a burnt set, a literal "
                     "in reuse_scan until 2.0.0",
    "address-book-v1": "historical: superseded by v2, named in the changelog",
    "check-report-v1": "historical: superseded by v2",
    "check-report-v2": "historical: superseded by v3, whose page is a delta on it",
    "address-book-v3": "forward reference: what a breaking change would be called",
    "check-report-v3": "forward reference: the 2.0.0 report, page written "
                       "before the code",
    "reveal-archive-v2": "historical: the 1.x archive, read by the release "
                         "that wrote it",
    "nonces-witness-v1": "historical: superseded by v2, named in the changelog",
    "firstreveal-v1": "historical: the 1.x table, read by the release that "
                      "wrote it",
    "locks-v2": "forward reference: same",
    "reuse-scan-v2": "forward reference: same",
    "reuse-hits-v2": "forward reference: same",
    "reuse-stats-v2": "forward reference: same",
    "price-series-v1": "historical: superseded by v2, named in the changelog",
    "blockprice-v1": "historical: superseded by v2, named in the changelog",
    "block-stats-v2": "historical: superseded by v3, named in the changelog",
    "nodsig-statement-v2": "artifact.STATEMENT_TAG",
    "derived-timeline-v2": "derivatives.TIMELINE_TAG: the sealed meta "
                           "`derived timeline` writes beside its two CSVs "
                           "(the module's FORMAT_TAG names the record files)",
    "derived-timeline-v1": "historical: superseded by v2, named in the changelog",
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


# ---------------------------------------------------------------------------
# The format pages pin their constants: "Constants, for a porter and for the
# test that pins this page" is read back and confronted with the code
# ---------------------------------------------------------------------------

def _constants_table(page):
    """The `name -> value` rows of a page's constants table, as text."""
    path = os.path.join(ROOT, "docs", "formats", page)
    with open(path) as f:
        text = f.read()
    start = text.index("## Constants, for a porter")
    rows = {}
    for line in text[start:].splitlines()[1:]:
        if line.startswith("## "):
            break
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) == 2 and cells[0] != "name":
            rows[cells[0].replace("`", "")] = cells[1]
    return rows


def _ints(text):
    import re
    return [int(x.replace(",", "")) for x in re.findall(r"\d[\d,]*", text)]


def _ticks(text):
    import re
    return re.findall(r"`([^`]+)`", text)


def test_the_format_pages_pin_their_constants():
    """Each 2.0.0 page ends with the numbers a porter needs; this reads
    them back off the page and confronts the module, so a constant that
    moves without the page moving fails here."""
    from nodsig import block_stats as bs
    from nodsig import curve as cv
    from nodsig import derivatives as dv
    from nodsig import firstreveal as fr
    from nodsig import graphemit as ge
    from nodsig import nonces as nn
    from nodsig import reuse_scan as rs
    from nodsig import reveal_archive as ra
    from nodsig import sightings as sg
    from nodsig import witness as wt

    t = _constants_table("BlockStats-v3.md")
    assert _ticks(t["columns"]) == [",".join(bs.COLUMNS)]
    assert _ticks(t["unspendable rule"])[0] == f"0x{bs.OP_RETURN:02x}"
    assert _ints(t["unspendable rule"])[-1] == bs.MAX_SCRIPT_SIZE
    assert _ticks(t["identity tag"]) == [bs.FORMAT_TAG]
    assert _ticks(t["parent tag accepted"]) == [ge.FORMAT_TAG]

    t = _constants_table("Nonces-witness-v2.md")
    assert _ints(t["record width"]) == [wt.REC]
    assert _ticks(t["fields"]) == ["r", "x", "key_seen", "s", "count",
                                   "height", "flags"]
    assert _ints(t["fields"])[:4] == [wt.R_LEN, wt.X_LEN, wt.KEY_LEN, wt.S_LEN]
    assert _ints(t["flags"]) == [wt.FLAG_SCHNORR, wt.FLAG_HIGH_S, 4, 8,
                                 wt.FLAG_AMBIGUOUS, wt.FLAG_ODD_Y,
                                 wt.FLAG_UNCOMPRESSED, wt.FLAG_XONLY]
    assert wt.ATTR_MASK == 4 | 8
    assert _ints(t["rows per triple"]) == [wt.ROWS_PER_TRIPLE]
    assert _ticks(t["identity tag"]) == [wt.FORMAT_TAG]
    assert _ticks(t["parent tag accepted"]) == list(wt.PARENT_TAGS) == [nn.FORMAT_TAG]

    t = _constants_table("DerivedTimeline-v2.md")
    assert _ticks(t["identity files"]) == list(dv.TIMELINE_FILES)
    assert _ticks(t["bands columns"]) == [",".join(dv.BANDS_COLUMNS)]
    assert _ticks(t["windows columns"]) == [",".join(dv.WINDOWS_COLUMNS)]
    assert _ticks(t["priced columns"]) == [
        ",".join(dv.PRICED_COLUMNS) + ",cost_at_creation_<currency>"]
    assert _ticks(t["identity tag"]) == [dv.TIMELINE_TAG]
    assert _ticks(t["parent tag accepted"]) == [dv.FORMAT_TAG]

    t = _constants_table("ReuseScan-v2.md")
    assert _ticks(t["TYPE_ORDER"]) == list(rs.TYPE_ORDER)
    widths = _ints(t["lock record"])
    assert widths[:2] == [rs.LOCK_TYPES["p2pkh"], rs.LOCK_TYPES["p2wsh"]]
    assert widths[-1] == 64                 # the satoshis, u64
    assert set(_ticks(t["tags"])) == {rs.LOCKS_TAG, rs.STATE_TAG, rs.HITS_TAG,
                                      rs.STATS_TAG, cv.REUSE_TAG,
                                      cv.ARCHIVE_TAG}
    header = cv.reuse_header(rs.TYPE_ORDER).strip().split(",")
    assert header[0] == "height" and header[-1] == "fingerprint"
    assert _ticks(t["curve columns"])[0] == "height"

    t = _constants_table("RevealArchive-v4.md")
    assert _ticks(t["CAT_ORDER"]) == list(ra.CAT_ORDER)
    assert _ints(t["record widths"]) == [ra.rec_width(c) for c in ra.CAT_ORDER]
    assert _ints(t["digest widths"]) == [ra.CATEGORIES[c] for c in ra.CAT_ORDER]
    assert _ints(t["ARCHIVE_LADDER_EVERY"]) == [ra.ARCHIVE_LADDER_EVERY]
    assert _ints(t["keys flags"])[:8] == [
        sg.FLAG_SIG, sg.FLAG_WIT, sg.FLAG_INNER_SIG, sg.FLAG_INNER_WIT,
        sg.FLAG_UNCOMPRESSED, sg.FLAG_OUT, sg.FLAG_OTHER_FACE, sg.FLAG_XONLY]
    assert _ints(t["scripts* payload"]) == [sg.MAX_INNER_KEYS]
    assert _ticks(t["identity tag"]) == [ra.FORMAT_TAG]
    assert _ticks(t["proof tag"]) == [ra.PROOF_TAG]
    assert _ticks(t["PROOF_ORDER"]) == list(ra.PROOF_ORDER)
    assert _ints(t["program carrier"])[:2] == [ra.PROGRAM_OUTPUT,
                                               ra.PROGRAM_NESTED]

    t = _constants_table("FirstReveal-v2.md")
    assert _ints(t["keys row"])[0] == fr.KEY
    assert _ints(t["first_off entry"])[0] == fr.OFF * 8
    assert _ticks(t["identity files"]) == list(fr.FP_ORDER)
    assert _ticks(t["identity tag"]) == [fr.FORMAT_TAG]
    assert _ticks(t["parent tag accepted"]) == [ra.FORMAT_TAG]


def test_the_docs_claim_only_what_the_book_accepts():
    """Every `"claim": "<word>"` and every "claimed as `<word>`" a page
    prints must be a claim `address_book` accepts: the word the pages
    used before (`mine`) was a claim of ownership the tool never made,
    and a reader who copies the example must not be refused."""
    import re
    from nodsig.address_book import CLAIMS
    pages = [os.path.join(ROOT, "README.md")] + [
        os.path.join(ROOT, "docs", n) for n in os.listdir(
            os.path.join(ROOT, "docs")) if n.endswith(".md")]
    found = set()
    for page in pages:
        with open(page, encoding="utf-8") as f:
            text = f.read()
        found |= set(re.findall(r'"claim": "([a-z]+)"', text))
        found |= set(re.findall(r"claimed as `([a-z]+)`", text))
    assert found and found <= set(CLAIMS), found


def test_the_fee_formula_for_porters_has_the_record_width():
    """Two pages hand a porter the one-line read of `fees.bin`; the
    stride and the width in it must be the record's, or a port reads
    fees shifted over the whole file."""
    import re
    from nodsig import derivatives as dv
    for page in ("contracts/FeeBackend.md", "formats/OutpointDerived-v3.md"):
        with open(os.path.join(ROOT, "docs", page), encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"u(\d+)_be\(fees\.bin\[tx_ordinal\*(\d+) : \+(\d+)\]\)",
                      text)
        assert m, page
        assert [int(x) for x in m.groups()] == [dv.FEE_REC * 8, dv.FEE_REC,
                                                dv.FEE_REC], page


def test_scan_vectors():
    """One block in, the archive's records out: the scan's own per-block
    body (`reveal_archive.block_records`) must give every synthetic
    vector its runs, its counters and its header facts. The chain
    vectors need a node: set NODSIG_VECTOR_NODE to a REST base URL to
    run them too, otherwise they are skipped and said so."""
    import tempfile
    from nodsig import blockparse
    from nodsig import reveal_archive as ra
    from nodsig.sightings import new_filter_stats
    data = _load("scan")
    assert data["format"] == ra.FORMAT_TAG
    assert data["categories"] == list(ra.RUN_CATS)

    def confront(v, raw, tmp):
        assert hashlib.sha256(raw).hexdigest() == v["raw_sha256"]
        assert blockparse.block_id(raw)[::-1].hex() == v["hash"]
        block = blockparse.parse_block(raw)
        stats = {"transactions": 0, "inputs": 0, "malformed_scriptsig": 0,
                 "revelations": 0, "program_outputs": 0,
                 "nested_programs": 0, **new_filter_stats()}
        buffers = {cat: [] for cat in ra.RUN_CATS}
        n = ra.block_records(block, v["height"], stats, buffers)
        assert n == sum(len(b) for b in buffers.values())
        assert stats == v["stats"], (v["height"], stats, v["stats"])
        for cat in ra.RUN_CATS:
            count, sha = ra._write_run(os.path.join(tmp, cat + ".bin"),
                                       cat, buffers[cat])
            assert {"records": count, "sha256": sha} == v["runs"][cat], \
                (v["height"], cat)
        h = block.header
        assert v["header"] == {
            "prev_hash": h.prev_hash[::-1].hex(),
            "merkle_root": h.merkle_root[::-1].hex(),
            "tx_count": len(block.transactions),
            "weight": block.weight,
            "txids_sha256": hashlib.sha256(
                b"".join(tx.txid for tx in block.transactions)).hexdigest(),
            "wtxids_sha256": hashlib.sha256(
                b"".join(tx.wtxid for tx in block.transactions)).hexdigest(),
        }, v["height"]

    with tempfile.TemporaryDirectory() as tmp:
        for v in data["synthetic"]:
            confront(v, bytes.fromhex(v["raw"]), tmp)
        node = os.environ.get("NODSIG_VECTOR_NODE")
        if not node:
            pytest.skip(f"{len(data['chain'])} chain vectors need a node: "
                        "set NODSIG_VECTOR_NODE to its REST base URL")
        from nodsig.reuse_scan import RestClient
        client = RestClient(node)
        vectors = data["chain"]
        for i in range(0, len(vectors), 25):
            window = vectors[i:i + 25]
            _hashes, raws = client.fetch_blocks([v["height"] for v in window])
            for v, raw in zip(window, raws):
                confront(v, raw, tmp)
