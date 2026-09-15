#!/usr/bin/env python3
"""
test_native.py — the native kernel against the reference, piece by piece.

The C under src/nodsig/native is an accelerator of the Python reference
and is answerable for one thing: the same bytes. Each piece is compiled
here into a throwaway shared library (a C compiler is needed; without one
these tests are skipped and say so) and driven through ctypes against the
reference's own functions and the conformance vectors. Nothing in the
package imports the C yet: the extension module comes when the kernel is
whole, and these tests stay as the piece-by-piece audit behind it.
"""

import ctypes
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE = os.path.join(ROOT, "src", "nodsig", "native")
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

_lib = None


def native():
    """The compiled kernel, built once per session into a temp dir."""
    global _lib
    if _lib is not None:
        return _lib
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.skip("no C compiler: the native kernel is not tested here")
    d = tempfile.mkdtemp(prefix="nodsig-native-")
    so = os.path.join(d, "libnodsig.so")
    # The kernel alone: nodsig_native.c is the CPython face, built and
    # tested apart (see `extension`).
    sources = [os.path.join(NATIVE, f) for f in sorted(os.listdir(NATIVE))
               if f.endswith(".c") and f != "nodsig_native.c"]
    subprocess.run([cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-fPIC", "-shared", "-o", so] + sources, check=True)
    _lib = ctypes.CDLL(so)
    return _lib


_ext = None


def extension():
    """`nodsig._native` built by its own builder into a temp dir and
    loaded from there: the package directory is not touched, and the
    test covers the extension whether or not a checkout built it."""
    global _ext
    if _ext is not None:
        return _ext
    import importlib.machinery
    import importlib.util
    from nodsig.native import build as nb
    if nb.compiler() is None:
        pytest.skip("no C compiler: the native kernel is not tested here")
    d = tempfile.mkdtemp(prefix="nodsig-ext-")
    try:
        so = nb.build(d, quiet=True)
    except RuntimeError as e:
        pytest.skip(f"the extension cannot be built here: {e}")
    loader = importlib.machinery.ExtensionFileLoader("_native", so)
    spec = importlib.util.spec_from_file_location("_native", so,
                                                  loader=loader)
    _ext = importlib.util.module_from_spec(spec)
    loader.exec_module(_ext)
    return _ext


def _digest(fn, data, n):
    out = ctypes.create_string_buffer(n)
    fn(data, ctypes.c_size_t(len(data)), out)
    return out.raw


def test_native_hashes_match_the_vectors_and_the_reference():
    """sha256d, ripemd160 and hash160: the published vectors first, then
    random inputs of every length around the block boundaries against
    hashlib and the reference's ripemd160 (the pure-Python one when
    OpenSSL has no legacy provider, the same bytes either way)."""
    from nodsig.hashing import hash160, ripemd160, sha256d
    lib = native()
    with open(os.path.join(FIXTURES, "hashing", "vectors.json")) as f:
        data = json.load(f)
    funcs = {"sha256d": (lib.nodsig_sha256d, 32),
             "ripemd160": (lib.nodsig_ripemd160, 20),
             "hash160": (lib.nodsig_hash160, 20)}
    for name, (fn, n) in funcs.items():
        for v in data[name]:
            assert _digest(fn, bytes.fromhex(v["input"]), n).hex() == v["output"]
    rng = random.Random(20260915)
    lengths = list(range(0, 130)) + [255, 256, 1000, 4096, 65537]
    for length in lengths:
        for _ in range(3):
            m = bytes(rng.randrange(256) for _ in range(length))
            assert _digest(lib.nodsig_sha256, m, 32) == hashlib.sha256(m).digest()
            assert _digest(lib.nodsig_sha256d, m, 32) == sha256d(m)
            assert _digest(lib.nodsig_ripemd160, m, 20) == ripemd160(m)
            assert _digest(lib.nodsig_hash160, m, 20) == hash160(m)


def test_native_sha256_incremental_is_one_shot():
    """The parser hashes a transaction's stripped serialization as three
    regions and the Merkle tree as pairs: the incremental context must
    give the one-shot digest whatever the cuts."""
    lib = native()

    class Ctx(ctypes.Structure):
        _fields_ = [("state", ctypes.c_uint32 * 8), ("length", ctypes.c_uint64),
                    ("buf", ctypes.c_uint8 * 64), ("fill", ctypes.c_size_t)]

    rng = random.Random(7)
    for _ in range(200):
        m = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        cuts = sorted(rng.randrange(0, len(m) + 1) for _ in range(rng.randrange(0, 5)))
        parts, prev = [], 0
        for c in cuts + [len(m)]:
            parts.append(m[prev:c])
            prev = c
        ctx = Ctx()
        lib.nodsig_sha256_init(ctypes.byref(ctx))
        for p in parts:
            lib.nodsig_sha256_update(ctypes.byref(ctx), p, ctypes.c_size_t(len(p)))
        out = ctypes.create_string_buffer(32)
        lib.nodsig_sha256_final(ctypes.byref(ctx), out)
        assert out.raw == hashlib.sha256(m).digest(), (len(m), cuts)


class _Buf(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)),
                ("len", ctypes.c_size_t), ("cap", ctypes.c_size_t)]


class _Stats(ctypes.Structure):
    _fields_ = [(k, ctypes.c_uint64) for k in (
        "transactions", "inputs", "malformed_scriptsig", "revelations",
        "program_outputs", "nested_programs", "out_keys", "control_or_annex",
        "unparsed_candidates")]


class _Facts(ctypes.Structure):
    _fields_ = [("hash", ctypes.c_uint8 * 32), ("prev_hash", ctypes.c_uint8 * 32),
                ("merkle_root", ctypes.c_uint8 * 32),
                ("version", ctypes.c_uint32), ("time", ctypes.c_uint32),
                ("bits", ctypes.c_uint32), ("nonce", ctypes.c_uint32),
                ("tx_count", ctypes.c_uint64), ("size", ctypes.c_uint64),
                ("weight", ctypes.c_uint64),
                ("txids_sha256", ctypes.c_uint8 * 32),
                ("wtxids_sha256", ctypes.c_uint8 * 32),
                ("coinbase_script", ctypes.c_void_p),
                ("coinbase_len", ctypes.c_size_t),
                ("coinbase_is_coinbase", ctypes.c_int)]


CATS = ["keys", "scripts20", "scripts32", "programs20", "programs32"]


def scan_block(raw, height, expect=None, extract=True):
    """Drive nodsig_scan_block; returns (code, message, facts, records
    by category as a list of whole records, stats as a dict)."""
    lib = native()
    lib.nodsig_scan_new.restype = ctypes.c_void_p
    lib.nodsig_scan_records.restype = ctypes.POINTER(_Buf)
    lib.nodsig_scan_stats.restype = ctypes.POINTER(_Stats)
    s = lib.nodsig_scan_new()
    try:
        facts = _Facts()
        err = ctypes.create_string_buffer(256)
        code = lib.nodsig_scan_block(
            ctypes.c_void_p(s), raw, ctypes.c_size_t(len(raw)),
            ctypes.c_uint32(height), expect, ctypes.c_int(1 if extract else 0),
            ctypes.byref(facts), err, ctypes.c_size_t(256))
        records = {}
        for i, cat in enumerate(CATS):
            b = lib.nodsig_scan_records(ctypes.c_void_p(s), i).contents
            blob = ctypes.string_at(b.data, b.len) if b.len else b""
            w = (32 if cat.endswith("32") else 20) + 4
            records[cat] = [blob[k:k + w] for k in range(0, len(blob), w)]
        st = lib.nodsig_scan_stats(ctypes.c_void_p(s)).contents
        stats = {k: getattr(st, k) for k, _ in _Stats._fields_}
        return code, err.value.decode(), facts, records, stats
    finally:
        lib.nodsig_scan_free(ctypes.c_void_p(s))


def _reference(raw, height):
    from nodsig import blockparse
    from nodsig import reveal_archive as ra
    from nodsig.sightings import new_filter_stats
    block = blockparse.parse_block(raw)
    stats = {"transactions": 0, "inputs": 0, "malformed_scriptsig": 0,
             "revelations": 0, "program_outputs": 0, "nested_programs": 0,
             **new_filter_stats()}
    buffers = {cat: [] for cat in ra.RUN_CATS}
    ra.block_records(block, height, stats, buffers)
    return block, stats, buffers


def _confront(raw, height, expect_hash_hex=None):
    """The kernel against the reference on one block: the facts, the
    counters, and the records as multisets."""
    from nodsig import blockparse
    block, stats, buffers = _reference(raw, height)
    expect = bytes.fromhex(expect_hash_hex)[::-1] if expect_hash_hex else None
    code, msg, facts, records, kstats = scan_block(raw, height, expect)
    assert code == 0, msg
    h = block.header
    assert bytes(facts.hash) == h.hash and bytes(facts.prev_hash) == h.prev_hash
    assert bytes(facts.merkle_root) == h.merkle_root
    assert (facts.version, facts.time, facts.bits, facts.nonce) == \
        (h.version, h.time, h.bits, h.nonce)
    assert facts.tx_count == len(block.transactions)
    assert facts.size == len(raw) and facts.weight == block.weight
    assert bytes(facts.txids_sha256) == hashlib.sha256(
        b"".join(tx.txid for tx in block.transactions)).digest()
    assert bytes(facts.wtxids_sha256) == hashlib.sha256(
        b"".join(tx.wtxid for tx in block.transactions)).digest()
    assert kstats == stats, (height, kstats, stats)
    tx0 = block.transactions[0]
    assert bool(facts.coinbase_is_coinbase) == blockparse.is_coinbase(tx0)
    assert ctypes.string_at(facts.coinbase_script, facts.coinbase_len) == \
        tx0.inputs[0].script_sig
    for cat in CATS:
        assert sorted(records[cat]) == sorted(buffers[cat]), (height, cat)


def _scan_vectors():
    with open(os.path.join(FIXTURES, "scan", "vectors.json")) as f:
        return json.load(f)


def test_native_scan_matches_the_reference_on_the_synthetic_vectors():
    for v in _scan_vectors()["synthetic"]:
        _confront(bytes.fromhex(v["raw"]), v["height"], v["hash"])


def test_native_scan_refuses_what_the_reference_refuses():
    """The same conditions, the reference's own words: a wrong hash, a
    truncation at every byte of a small block, trailing bytes, a broken
    Merkle root, a stripped witness, an unknown SegWit flag."""
    from nodsig import blockparse
    v = _scan_vectors()["synthetic"][6]              # the proof chain's h2
    raw = bytes.fromhex(v["raw"])
    code, msg, *_ = scan_block(raw, 2, bytes(32))
    assert code == 2

    def refusal(bytes_):
        # The scan's own order: block_id first, then the parser.
        try:
            blockparse.block_id(bytes_)
            blockparse.parse_block(bytes_)
            return None
        except blockparse.ParseError as e:
            return str(e)

    for cut in range(0, len(raw)):
        part = raw[:cut]
        code, msg, *_ = scan_block(part, 2)
        assert (code, msg) == (1, refusal(part)), (cut, code, msg)
    for bad in (raw + b"\x00", raw[:100] + bytes([raw[100] ^ 1]) + raw[101:],
                raw[:40] + bytes([raw[40] ^ 1]) + raw[41:]):
        code, msg, *_ = scan_block(bad, 2)
        assert (code, msg) == (1, refusal(bad)), (code, msg)
    # A block delivered without its witnesses: the same refusal.
    import test_blockparse as tbw
    stripped = tbw.build_synthetic(with_commitment=True, stripped=True)[0]
    code, msg, *_ = scan_block(stripped, 1)
    assert code == 1 and msg == refusal(stripped)


def test_native_scan_matches_the_reference_on_the_chain_vectors():
    node = os.environ.get("NODSIG_VECTOR_NODE")
    if not node:
        pytest.skip("set NODSIG_VECTOR_NODE to run the kernel on the 200 "
                    "chain vectors")
    from nodsig.reuse_scan import RestClient
    client = RestClient(node)
    vectors = _scan_vectors()["chain"]
    for i in range(0, len(vectors), 25):
        window = vectors[i:i + 25]
        _hashes, raws = client.fetch_blocks([v["height"] for v in window])
        for v, raw in zip(window, raws):
            _confront(raw, v["height"], v["hash"])


def test_the_extension_answers_as_the_kernel_and_as_the_reference():
    """`nodsig._native.scan_block` through `nodsig.kernel`'s reading of
    its codes: the records, the counters and the facts of every
    synthetic vector as the reference gives them; a wrong hash and a
    truncated block as the scan's own refusals."""
    from nodsig import blockparse, kernel
    from nodsig import reveal_archive as ra
    ext = extension()
    real = kernel._native
    kernel._native = ext
    try:
        for v in _scan_vectors()["synthetic"]:
            raw = bytes.fromhex(v["raw"])
            block, stats, buffers = _reference(raw, v["height"])
            recs, kstats, facts = kernel.scan_block(
                raw, v["height"], bytes.fromhex(v["hash"])[::-1])
            for i, cat in enumerate(ra.RUN_CATS):
                w = ra.rec_width(cat)
                got = [recs[i][k:k + w] for k in range(0, len(recs[i]), w)]
                assert sorted(got) == sorted(buffers[cat]), (v["height"], cat)
            assert kstats == stats
            h = block.header
            assert (facts["hash"], facts["prev_hash"], facts["merkle_root"],
                    facts["version"], facts["time"], facts["bits"],
                    facts["nonce"]) == (h.hash, h.prev_hash, h.merkle_root,
                                        h.version, h.time, h.bits, h.nonce)
            assert (facts["tx_count"], facts["size"], facts["weight"]) == \
                (len(block.transactions), len(raw), block.weight)
            tx0 = block.transactions[0]
            assert facts["coinbase_is_coinbase"] == blockparse.is_coinbase(tx0)
            assert facts["coinbase_script"] == tx0.inputs[0].script_sig
        with pytest.raises(kernel.HashMismatch):
            kernel.scan_block(raw, 1, bytes(32))
        with pytest.raises(blockparse.ParseError) as e:
            kernel.scan_block(raw[:100], 1)
        try:
            blockparse.parse_block(raw[:100])
        except blockparse.ParseError as want:
            assert str(e.value) == str(want)
    finally:
        kernel._native = real
