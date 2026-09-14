#!/usr/bin/env python3
"""
test_reuse_scan.py — self-test for reuse_scan.py, no node and no real
data needed.

What is exercised, end to end:

- the pure-Python RIPEMD-160 fallback, against the published test
  vectors AND against real chain data (the first SegWit transaction:
  hash160 of the public key in its witness must equal the 20 bytes
  inside its redeem script — the chain itself is the test vector);
- `prepare`: a synthetic dumptxoutset snapshot (built with the census
  test's mirror writer) is distilled into sorted lock files; checked:
  ordering, deduplication with summed amounts, exclusion of the
  exposed-by-construction types, the manifest;
- revelation extraction: crafted inputs of every standard shape;
- `scan`: a small synthetic CHAIN (built with the block test's mirror
  writer) is served by a fake JSON-RPC server over real HTTP on
  localhost, and the scan runs against it exactly as it would against
  the node: batches, integrity checks, checkpoints, curve;
- resume and determinism: scanning in two runs (stop at height 2,
  resume to 4) must produce byte-identical fingerprints to the
  one-shot scan — the property that makes every checkpoint publishable;
- the narrow perimeter flags (--no-faces / --no-cosigners) must
  subtract exactly the hits the extensions added;
- corrupted block bytes from the server must abort the scan;
- the two transports: the same fake node also answers the binary REST
  endpoints, and a scan fetched that way must land on the same
  fingerprint as one fetched over JSON-RPC, at prefetch depth 1 and 3,
  refuse the same corrupted bytes, and ask for no credential at all.

Usage:
    python3 test_reuse_scan.py        # prints PASS or fails loudly
"""

import hashlib
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nodsig import blockparse as bp
from nodsig import hashing as ha
from nodsig import reuse_scan as rs

# The mirror writers live in the other test files on purpose: they are
# independent implementations of the serializations, and reusing them
# here keeps one mirror per format.
import test_blockparse as tbw           # block/tx writers
import test_utxo_census as tsw          # snapshot writers


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


# ---------------------------------------------------------------------------
# RIPEMD-160: vectors, hashlib agreement, and the chain as a witness
# ---------------------------------------------------------------------------

def test_ripemd160():
    vectors = {
        b"": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        b"abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        b"message digest": "5d0689ef49d2fae572b881b123a85ffa21595f36",
        b"a" * 1000000: "52783243c1697bdbe16d37f97f68f08325dc1528",
    }
    for msg, want in vectors.items():
        got = ha._ripemd160_pure(msg).hex()
        check(got == want, f"ripemd160 vector {msg[:10]}…: {got}")

    # The real-world check: in the first SegWit transaction the redeem
    # script is 0x0014 + hash160(pubkey), and the pubkey sits in the
    # witness. If our hash160 is right, the two must meet.
    tx, _ = bp.parse_tx(bytes.fromhex(tbw.FIRST_SEGWIT_HEX))
    redeem = bp.script_pushes(tx.inputs[0].script_sig)[0]
    pubkey = tx.inputs[0].witness[1]
    check(ha._ripemd160_pure(hashlib.sha256(pubkey).digest())
          == redeem[2:22],
          "hash160(witness pubkey) != redeem script payload")
    check(ha.hash160(pubkey) == redeem[2:22], "hash160 wrapper disagrees")
    print("ok  ripemd160: vectors, and the chain agrees")


def test_recount_from_bitmap_matches_the_naive_walk():
    """The resume path counts by set bit (whole words at a time)
    instead of testing all ~100 million locks one by one. It must
    answer exactly what the bit-by-bit walk answered, tail bits and
    all — the totals it rebuilds are what the published table prints.
    Sizes chosen around the byte boundary, where a tail is easiest to
    get wrong."""
    from array import array

    class Fake(rs.LockSet):
        def __init__(self, count, hits, sats):
            self.count, self.hits, self.sats = count, hits, sats

    for count in (0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 100):
        n_bytes = (count + 7) // 8
        for pattern in (0x00, 0xFF, 0xA5, 0x01, 0x80):
            hits = bytearray([pattern]) * n_bytes
            sats = array("q", range(1, count + 1))
            naive_count = sum(
                1 for i in range(count) if hits[i >> 3] & (1 << (i & 7)))
            naive_sats = sum(
                sats[i] for i in range(count)
                if hits[i >> 3] & (1 << (i & 7)))
            ls = Fake(count, hits, sats)
            ls.recount_from_bitmap()
            check((ls.hit_count, ls.hit_sats) == (naive_count, naive_sats),
                  f"count={count} pattern={pattern:#04x}: "
                  f"({ls.hit_count},{ls.hit_sats}) != "
                  f"({naive_count},{naive_sats})")
    print("ok  recount: the word-at-a-time walk equals the bit-by-bit "
          "one, tails included")


def test_the_pure_python_fallback_says_so_before_a_long_run():
    """The fallback keeps the tools running everywhere, at ~50x the
    cost per digest on a path that runs billions of times. Silently,
    that turns a two-day run into a two-month one with nothing on
    screen to explain it — so the chain-scale commands say it once,
    and say nothing when the fast road is available."""
    import contextlib
    import io
    real = ha.RIPEMD160_IS_PURE_PYTHON
    try:
        for pure, expect in ((True, True), (False, False)):
            ha.RIPEMD160_IS_PURE_PYTHON = pure
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                ha.warn_if_slow_ripemd160("this scan")
            said = "pure-Python fallback" in err.getvalue()
            check(said == expect,
                  f"pure={pure}: warning {'missing' if expect else 'wrong'}")
            if expect:
                check("legacy provider" in err.getvalue(),
                      "the warning must name the cure")
    finally:
        ha.RIPEMD160_IS_PURE_PYTHON = real
    print("ok  ripemd160: the slow fallback is announced, the fast "
          "road is silent")


# ---------------------------------------------------------------------------
# The cast: keys, scripts, and the locks they map to
# ---------------------------------------------------------------------------

PUB1 = b"\x02" + bytes(range(32))            # revealed in a scriptSig
PUB2 = b"\x03" + bytes(range(1, 33))         # cosigner inside a redeem
PUB3 = b"\x02" + bytes(range(2, 34))         # revealed in a witness
PUB4 = b"\x03" + bytes(range(3, 35))         # cosigner inside a wscript
PUB5 = b"\x02" + bytes(range(4, 36))         # never revealed anywhere
FAKE_SIG = b"\x30" + bytes(70)

REDEEM = bytes([0x51, 33]) + PUB2 + bytes([0x51, 0xAE])   # 1-of-1 multisig
WSCRIPT = bytes([0x51, 33]) + PUB4 + bytes([0x51, 0xAE])

# The forms the v3 archive learned to see, all at height 5 (the tests
# that scan to 4 never meet them): a pay-to-pubkey output with a 65-byte
# key, a bare 1-of-2 multisig output, a hybrid-form key pushed in a
# scriptSig, a taproot script-path spend whose leaf names an x-only key,
# and a pay-to-pubkey spend whose scriptSig is one well-formed DER
# signature (a candidate script by position, filtered by shape).
PUBU5 = b"\x04" + bytes(range(10, 74))          # y ends in 0x49: odd
PUB6 = b"\x02" + bytes(range(5, 37))
PUB7 = b"\x03" + bytes(range(6, 38))
PUBH = b"\x06" + bytes(range(11, 75))   # hybrid lead, y ends 0x4a: even
XLEAF = bytes(range(40, 72))                    # an x-only leaf key
XINT = bytes(range(41, 73))                     # an x-only internal key
DER_SIG = (b"\x30\x44\x02\x20" + bytes([1] + [0] * 31) + b"\x02\x20"
           + bytes([1] + [0] * 31) + b"\x01")           # strict DER, 71 bytes
SCHNORR_SIG = bytes(range(64))
P2PK_SPK = bytes([65]) + PUBU5 + b"\xac"
BARE_MS_SPK = b"\x51" + bytes([33]) + PUB6 + bytes([33]) + PUB7 + b"\x52\xae"
TAP_LEAF = bytes([32]) + XLEAF + b"\xac"
TAP_CONTROL = b"\xc0" + XINT

H1 = rs.hash160(PUB1)
H2 = rs.hash160(REDEEM)
S1 = hashlib.sha256(WSCRIPT).digest()
WRAP3 = rs.hash160(b"\x00\x14" + rs.hash160(PUB3))   # P2SH-wrapped face

# The synthetic UTXO set: (type, lock hash, satoshis). Two coins share
# the p2pkh lock H1 on purpose: prepare must merge them into one record
# of 3000 sats (one revelation burns them together).
SNAPSHOT_LOCKS = [
    ("p2pkh", H1, 1000),
    ("p2pkh", H1, 2000),
    ("p2pkh", rs.hash160(PUB2), 250),        # burnt via cosigners
    ("p2pkh", rs.hash160(PUB5), 10_000),     # must survive untouched
    ("p2sh", H2, 700),                       # burnt by the redeem reveal
    ("p2sh", WRAP3, 900),                    # burnt via the wrapped face
    ("p2wpkh", H1, 500),                     # burnt via the h160 face
    ("p2wsh", S1, 1500),                     # burnt by the wscript reveal
]

EXPECT_MANIFEST = {           # type: (records after dedupe, satoshis)
    "p2pkh": (3, 13_250),
    "p2sh": (2, 1_600),
    "p2wpkh": (1, 500),
    "p2wsh": (1, 1_500),
}
EXPECT_FULL = {               # full perimeter: (hits, burnt satoshis)
    "p2pkh": (2, 3_250),
    "p2sh": (2, 1_600),
    "p2wpkh": (1, 500),
    "p2wsh": (1, 1_500),
}
EXPECT_NARROW = {             # --no-faces --no-cosigners
    "p2pkh": (1, 3_000),      # only the scriptSig key, exact form
    "p2sh": (1, 700),         # base criterion still counts the redeem
    "p2wpkh": (0, 0),         # the face is gone
    "p2wsh": (1, 1_500),      # base criterion still counts the wscript
}


def build_snapshot_file(path, base_hash_hex=None):
    """A dumptxoutset v2 snapshot holding SNAPSHOT_LOCKS plus two coins
    of exposed types (P2PK, P2TR) that prepare must skip.

    `base_hash_hex` is the display hash of the block the snapshot
    claims to photograph; the default is a fake one, which is fine for
    prepare's own mechanics but NOT for derive, which refuses locks
    photographed at a block the archive does not end on."""
    out = bytearray()
    out += b"utxo\xff" + (2).to_bytes(2, "little")
    out += bytes.fromhex("f9beb4d9")
    if base_hash_hex is None:
        out += bytes.fromhex("ab" * 32)                # fake base hash
    else:
        out += bytes.fromhex(base_hash_hex)[::-1]      # display -> file order
    coins = []
    for i, (kind, lock, sat) in enumerate(SNAPSHOT_LOCKS):
        txid = bytes([i + 1]) * 32
        if kind == "p2pkh":
            coins.append((txid, 0, sat, 0, lock))
        elif kind == "p2sh":
            coins.append((txid, 1, sat, 1, lock))
        elif kind == "p2wpkh":
            spk = b"\x00\x14" + lock
            coins.append((txid, 2, sat, 6 + len(spk), spk))
        else:                                          # p2wsh
            spk = b"\x00\x20" + lock
            coins.append((txid, 3, sat, 6 + len(spk), spk))
    coins.append((b"\xEE" * 32, 4, 5_000, 2, bytes(32)))          # P2PK
    coins.append((b"\xEF" * 32, 5, 123, 6 + 34,
                  bytes([0x51, 0x20]) + bytes(32)))               # P2TR
    out += len(coins).to_bytes(8, "little")
    for txid, vout, sat, code, payload in coins:
        out += txid + tsw.write_compactsize(1)
        out += tsw.coin(vout, 100, 0, sat, code, payload)
    with open(path, "wb") as f:
        f.write(out)


def test_prepare(tmp, base_hash_hex=None, height=None, headers_dir=None):
    """`height` is the snapshot's height as `dumptxoutset` would print
    it; a fixture with a fake base hash gets a fake height too, since
    the manifest refuses to exist without one."""
    snapshot = os.path.join(tmp, "test_utxos.dat")
    locks_dir = os.path.join(tmp, "locks")
    build_snapshot_file(snapshot, base_hash_hex=base_hash_hex)
    if headers_dir is None and height is None:
        height = 9
    # chunk_records=3 forces several sorted runs: the external merge
    # (and its duplicate-summing) is what gets exercised, not bypassed.
    rs.run_prepare(snapshot, locks_dir, chunk_records=3,
                   headers_dir=headers_dir, height=height)

    with open(os.path.join(locks_dir, rs.MANIFEST_NAME)) as f:
        manifest = json.load(f)
    check(manifest["format"] == rs.LOCKS_TAG
          and manifest["identity"]["coverage"]["from"]
          == manifest["identity"]["coverage"]["to"],
          f"a lock set is sealed over one moment: {manifest['identity']}")
    for t, (records, sats) in EXPECT_MANIFEST.items():
        got = rs.locks_types(manifest)[t]
        check((got["records"], got["satoshis"]) == (records, sats),
              f"prepare {t}: {got} != {(records, sats)}")

    # The record files must be sorted and hold the summed amounts.
    ls = rs.LockSet(os.path.join(locks_dir, "locks_p2pkh.bin"), 20)
    idx = ls.find(H1)
    check(idx >= 0 and ls.sats[idx] == 3000,
          "H1 not merged into a single 3000-sat record")
    check(ls.find(rs.hash160(PUB5)) >= 0, "PUB5 lock missing")
    check(ls.find(bytes(20)) == -1, "phantom lock found")
    print("ok  prepare: dedupe+sum, sorting, exclusions, manifest")
    return locks_dir


def test_locks_are_verified_against_their_manifest(tmp):
    """The LockSet load refuses a locks file that is not the one the
    manifest describes: truncated on a record boundary (the count
    catches it) or rotted in place at the same size (the sha catches
    it). Every number downstream of a LockSet is a published one, and
    the cross-check builds its LockSet from the SAME files: unverified,
    a broken file would make both roads agree on garbage."""
    locks_dir = test_prepare(tmp)
    with open(os.path.join(locks_dir, rs.MANIFEST_NAME)) as f:
        manifest = json.load(f)
    entry = rs.locks_types(manifest)["p2pkh"]
    path = os.path.join(locks_dir, "locks_p2pkh.bin")
    with open(path, "rb") as f:
        whole = f.read()

    # The honest file first: expectations met, load succeeds.
    rs.LockSet(path, 20, expect_records=entry["records"],
               expect_sha=entry["sha256"])

    # One record shorter: still a multiple of the width, but not the
    # set the manifest counted.
    with open(path, "wb") as f:
        f.write(whole[:-28])
    try:
        rs.LockSet(path, 20, expect_records=entry["records"],
                   expect_sha=entry["sha256"])
        fail("a truncated locks file was loaded")
    except rs.ScanError:
        pass

    # Same size, one bit off: only the sha can see it.
    rotted = bytearray(whole)
    rotted[20] ^= 0x01
    with open(path, "wb") as f:
        f.write(bytes(rotted))
    try:
        rs.LockSet(path, 20, expect_records=entry["records"],
                   expect_sha=entry["sha256"])
        fail("a rotted locks file was loaded")
    except rs.ScanError:
        pass
    print("ok  locks: manifest record count and sha enforced at load")


# ---------------------------------------------------------------------------
# Extraction on crafted inputs
# ---------------------------------------------------------------------------

def test_extraction():
    stats = {"malformed_scriptsig": 0, "malformed_inner_script": 0,
             **rs.new_filter_stats()}

    def tx_in(script_sig, witness):
        return bp.TxIn(bytes(32), 0, script_sig, 0, witness)

    # P2PKH shape: [sig, pubkey] in the scriptSig.
    got = set(rs.extract_reveals(
        tx_in(bytes([71]) + FAKE_SIG + bytes([33]) + PUB1, []),
        faces=True, cosigners=True, stats=stats))
    for want in [("p2pkh", H1), ("p2wpkh", H1),
                 ("p2sh", rs.hash160(b"\x00\x14" + H1))]:
        check(want in got, f"P2PKH spend: missing {want[0]} face")

    # Narrow perimeter: the same input burns only the exact form.
    got = set(rs.extract_reveals(
        tx_in(bytes([71]) + FAKE_SIG + bytes([33]) + PUB1, []),
        faces=False, cosigners=True, stats=stats))
    check(("p2pkh", H1) in got and ("p2wpkh", H1) not in got,
          "--no-faces did not narrow the P2PKH spend")

    # P2SH shape: the LAST push is the redeem; PUB2 inside it is a
    # cosigner and must appear only when cosigners=True.
    sig_script = b"\x00" + bytes([71]) + FAKE_SIG \
        + bytes([len(REDEEM)]) + REDEEM
    got = set(rs.extract_reveals(tx_in(sig_script, []),
                                 faces=True, cosigners=True, stats=stats))
    check(("p2sh", H2) in got, "P2SH spend: redeem hash missing")
    check(("p2pkh", rs.hash160(PUB2)) in got, "cosigner face missing")
    got = set(rs.extract_reveals(tx_in(sig_script, []),
                                 faces=True, cosigners=False, stats=stats))
    check(("p2pkh", rs.hash160(PUB2)) not in got,
          "--no-cosigners still extracted the cosigner")

    # P2WSH shape: last witness item is the script.
    got = set(rs.extract_reveals(tx_in(b"", [FAKE_SIG, WSCRIPT]),
                                 faces=True, cosigners=True, stats=stats))
    check(("p2wsh", S1) in got, "P2WSH spend: wscript hash missing")

    # Malformed scriptSig: counted, not guessed at.
    before = stats["malformed_scriptsig"]
    rs.extract_reveals(tx_in(b"\x4c", []), True, True, stats)
    check(stats["malformed_scriptsig"] == before + 1,
          "malformed scriptSig not counted")
    print("ok  extraction: shapes, faces, cosigners, malformed")


# ---------------------------------------------------------------------------
# The synthetic chain and its fake RPC server
# ---------------------------------------------------------------------------

def build_chain():
    """Four linked blocks whose spends hit exactly EXPECT_FULL:

    height 2: legacy [sig, PUB1]        → p2pkh H1 + p2wpkh H1 (face);
              its outputs create the P2SH H2 and P2WSH S1 locks
    height 3: SegWit [sig, PUB3]        → p2sh WRAP3 (wrapped face)
              SegWit [sig, WSCRIPT]     → p2wsh S1
    height 4: legacy P2SH redeem spend  → p2sh H2 + p2pkh(PUB2) (cosigner)
              plus one malformed scriptSig (counted, harmless)
    """
    blocks = {}          # height → (hash_display_hex, raw_hex)
    prev = bytes(32)

    def add(height, raw_txs, txids):
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_600_000_000 + height,
                                      0x1700_0000, height, raw_txs, txids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())

    def coinbase(tag, witness=False, commit_wtxids=None):
        outs = [tbw.w_output(50 * rs.SAT, tbw.P2PKH_SPK)]
        if witness:
            outs.append(tbw.w_output(
                0, tbw.w_commitment_spk(commit_wtxids, bytes(32))))
        return tbw.w_tx(
            1, [tbw.w_input(bytes(32), 0xFFFFFFFF, tag, 0xFFFFFFFF)],
            outs, 0, witnesses=[[bytes(32)]] if witness else None)

    # height 1: just a coinbase (reveals nothing, warms the chain).
    cb, cbid, _ = coinbase(b"\x01h1")
    add(1, [cb], [cbid])

    # height 2: the P2PKH spend of PUB1. Its outputs CREATE the P2SH lock
    # of REDEEM and the P2WSH lock of WSCRIPT that heights 3 and 4 open:
    # a lock in the snapshot is an output the chain made, and the archive
    # keeps a script only when the chain shows its program was created.
    cb, cbid, _ = coinbase(b"\x01h2")
    spend = bytes([71]) + FAKE_SIG + bytes([33]) + PUB1
    tx, txid, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xA1" * 32, 0, spend, 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK),
         tbw.w_output(700, b"\xa9\x14" + H2 + b"\x87"),
         tbw.w_output(1500, b"\x00\x20" + S1)], 0)
    add(2, [cb, tx], [cbid, txid])

    # height 3: SegWit spends (P2WPKH of PUB3, P2WSH of WSCRIPT); the
    # coinbase must carry the witness commitment or the parser refuses.
    tx, txid, wtxid = tbw.w_tx(
        2, [tbw.w_input(b"\xA2" * 32, 0, b"", 0xFFFFFFFF),
            tbw.w_input(b"\xA3" * 32, 1, b"", 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0,
        witnesses=[[FAKE_SIG, PUB3], [FAKE_SIG, WSCRIPT]])
    cb, cbid, _ = coinbase(b"\x01h3", witness=True, commit_wtxids=[wtxid])
    add(3, [cb, tx], [cbid, txid])

    # height 4: the P2SH multisig spend, plus a malformed scriptSig.
    cb, cbid, _ = coinbase(b"\x01h4")
    sig_script = b"\x00" + bytes([71]) + FAKE_SIG \
        + bytes([len(REDEEM)]) + REDEEM
    tx, txid, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xA4" * 32, 0, sig_script, 0xFFFFFFFF),
            tbw.w_input(b"\xA5" * 32, 0, b"\x4c", 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0)
    add(4, [cb, tx], [cbid, txid])

    # height 5: what only the v3 archive sees. Scans to 4 never meet it.
    hybrid_spend = bytes([71]) + FAKE_SIG + bytes([65]) + PUBH
    tx, txid, wtxid = tbw.w_tx(
        2, [tbw.w_input(b"\xA6" * 32, 0, hybrid_spend, 0xFFFFFFFF),
            tbw.w_input(b"\xA7" * 32, 0, bytes([len(DER_SIG)]) + DER_SIG,
                        0xFFFFFFFF),
            tbw.w_input(b"\xA8" * 32, 0, b"", 0xFFFFFFFF)],
        [tbw.w_output(10, P2PK_SPK), tbw.w_output(10, BARE_MS_SPK)], 0,
        witnesses=[[], [], [SCHNORR_SIG, TAP_LEAF, TAP_CONTROL]])
    cb, cbid, _ = coinbase(b"\x01h5", witness=True, commit_wtxids=[wtxid])
    add(5, [cb, tx], [cbid, txid])
    return blocks


class FakeRpc(BaseHTTPRequestHandler):
    """Answers like the node would, on both of its interfaces and on one
    port, as the node does.

    JSON-RPC (POST): getblockhash/getblock, hashes in display order and
    blocks as hex. REST (GET): `/rest/blockhashbyheight/<H>.bin`, which
    answers the 32 bytes in SERIALIZED order (the opposite convention
    of the JSON side, and the node's own), and
    `/rest/block/<display-hex>.bin`, which answers the block verbatim.
    Everything else the scan needs to trust, it re-derives from the
    bytes, which is the property under test, on either interface."""
    blocks = {}          # set by serve(): height → (hash_hex, raw_hex)
    by_hash = {}

    def _send(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path
        if path.startswith("/rest/blockhashbyheight/") \
                and path.endswith(".bin"):
            height = path[len("/rest/blockhashbyheight/"):-len(".bin")]
            entry = self.blocks.get(int(height)) if height.isdigit() else None
            if entry is None:
                self.send_error(404)
                return
            self._send(bytes.fromhex(entry[0])[::-1],
                       "application/octet-stream")
        elif path.startswith("/rest/block/") and path.endswith(".bin"):
            hash_hex = path[len("/rest/block/"):-len(".bin")]
            raw_hex = self.by_hash.get(hash_hex)
            if raw_hex is None:
                self.send_error(404)
                return
            self._send(bytes.fromhex(raw_hex), "application/octet-stream")
        else:
            self.send_error(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(
            int(self.headers["Content-Length"])))
        replies = []
        for call in body:
            if call["method"] == "getblockhash":
                result = self.blocks[call["params"][0]][0]
            elif call["method"] == "getblock":
                result = self.by_hash[call["params"][0]]
            else:
                self.send_error(400)
                return
            replies.append({"id": call["id"], "result": result,
                            "error": None})
        self._send(json.dumps(replies).encode(), "application/json")

    def log_message(self, *args):
        pass                      # keep the test output readable


def serve(blocks):
    FakeRpc.blocks = blocks
    FakeRpc.by_hash = {h: raw for h, raw in blocks.values()}
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeRpc)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def read_totals(checkpoint_dir):
    with open(os.path.join(checkpoint_dir, rs.STATE_NAME)) as f:
        state = json.load(f)
    return {t: (v["hits"], v["satoshis"])
            for t, v in state["totals"].items()}, state


def test_scan(tmp, locks_dir):
    blocks = build_chain()
    server, url = serve(blocks)
    try:
        # One-shot scan of the whole chain, full perimeter.
        dir_full = os.path.join(tmp, "cp_full")
        fp_full = rs.run_scan(locks_dir, url, "user:pass", 4, dir_full,
                              batch_size=2, checkpoint_every=2)
        totals, state = read_totals(dir_full)
        check(totals == EXPECT_FULL, f"full scan totals: {totals}")
        check(state["stats"]["malformed_scriptsig"] == 1,
              "malformed scriptSig not counted in the scan")
        with open(os.path.join(dir_full, rs.CURVE_NAME)) as f:
            rows = f.read().strip().splitlines()
        check(len(rows) == 1 + 2 and rows[1].startswith("2,")
              and rows[2].startswith("4,"),
              f"curve rows: {rows}")
        print("ok  scan: hits, sums, malformed counter, curve")

        # Interrupted + resumed run: byte-identical result. This is the
        # determinism the published fingerprint stands on.
        dir_resume = os.path.join(tmp, "cp_resume")
        rs.run_scan(locks_dir, url, "user:pass", 2, dir_resume,
                    batch_size=2, checkpoint_every=2)
        fp_resumed = rs.run_scan(locks_dir, url, "user:pass", 4,
                                 dir_resume, batch_size=2,
                                 checkpoint_every=2)
        check(fp_resumed == fp_full,
              "resumed fingerprint differs from the one-shot scan")
        totals, _ = read_totals(dir_resume)
        check(totals == EXPECT_FULL, f"resumed totals: {totals}")
        print("ok  resume: interrupted run converges to the same "
              "fingerprint")

        # Narrow perimeter: exactly the extension hits disappear.
        dir_narrow = os.path.join(tmp, "cp_narrow")
        rs.run_scan(locks_dir, url, "user:pass", 4, dir_narrow,
                    batch_size=2, checkpoint_every=2,
                    faces=False, cosigners=False)
        totals, _ = read_totals(dir_narrow)
        check(totals == EXPECT_NARROW, f"narrow totals: {totals}")
        print("ok  perimeter flags: narrow reading subtracts the "
              "extensions only")
    finally:
        server.shutdown()

    # Corruption: flip one byte of a served block; the scan must abort,
    # whatever stage catches it (parse, Merkle, or the hash check).
    corrupt = dict(blocks)
    h_hex, raw_hex = corrupt[2]
    pos = len(raw_hex) - 40
    flipped = ("0" if raw_hex[pos] != "0" else "f")
    corrupt[2] = (h_hex, raw_hex[:pos] + flipped + raw_hex[pos + 1:])
    server, url = serve(corrupt)
    try:
        rs.run_scan(locks_dir, url, "user:pass", 4,
                    os.path.join(tmp, "cp_corrupt"),
                    batch_size=2, checkpoint_every=2)
        fail("corrupted block accepted by the scan")
    except (rs.ScanError, bp.ParseError):
        print("ok  corruption: altered block bytes abort the scan")
    finally:
        server.shutdown()


def test_checkpoint_survives_a_crash_between_its_writes(tmp, locks_dir):
    """checkpoint() promotes the bitmaps only after the state that
    fingerprints them is on disk, so a kill anywhere inside it leaves
    ONE full set the state still matches. Both halves of the window are
    reproduced here: a crash BEFORE the state write leaves pending
    bitmaps the resume must discard, one AFTER it leaves a promotion
    the resume must finish. Either way the run continues to the
    one-shot fingerprint — replacing the bitmaps in place used to turn
    the first half into a mismatch with nothing left to resume from."""
    blocks = build_chain()
    server, url = serve(blocks)
    try:
        full = os.path.join(tmp, "cp_ref")
        fp_full = rs.run_scan(locks_dir, url, "user:pass", 4, full,
                              batch_size=2, checkpoint_every=2)

        cp = os.path.join(tmp, "cp_crash")
        rs.run_scan(locks_dir, url, "user:pass", 2, cp,
                    batch_size=2, checkpoint_every=2)
        halfway = {t: open(os.path.join(cp, f"hits_{t}.bin"), "rb").read()
                   for t in rs.TYPE_ORDER}

        # Before the state write: pendings hold work the state does not
        # fingerprint yet (a flipped bit stands in for it).
        for t in rs.TYPE_ORDER:
            data = bytearray(halfway[t])
            data[0] ^= 0x01
            with open(os.path.join(cp, f"hits_{t}.bin.new"), "wb") as f:
                f.write(bytes(data))
        fp_resumed = rs.run_scan(locks_dir, url, "user:pass", 4, cp,
                                 batch_size=2, checkpoint_every=2)
        check(fp_resumed == fp_full,
              "resume over discarded pendings missed the one-shot "
              "fingerprint")

        # After the state write: the state and the pendings say 4, the
        # promoted files still say 2. The resume must finish the swap.
        for t in rs.TYPE_ORDER:
            final = os.path.join(cp, f"hits_{t}.bin")
            os.replace(final, final + ".new")
            with open(final, "wb") as f:
                f.write(halfway[t])
        fp_promoted = rs.run_scan(locks_dir, url, "user:pass", 4, cp,
                                  batch_size=2, checkpoint_every=2)
        check(fp_promoted == fp_full,
              "resume over an unfinished promotion missed the one-shot "
              "fingerprint")
        for t in rs.TYPE_ORDER:
            check(not os.path.exists(os.path.join(cp,
                                                  f"hits_{t}.bin.new")),
                  f"{t}: pending bitmap left behind after the resume")
            got = open(os.path.join(cp, f"hits_{t}.bin"), "rb").read()
            want = open(os.path.join(full, f"hits_{t}.bin"), "rb").read()
            check(got == want,
                  f"{t}: resumed bitmap differs from the one-shot one")
        print("ok  checkpoint: a kill in either commit window resumes "
              "and lands on the one-shot bytes")

        # And the guard still guards: a bitmap that matches NEITHER set
        # the state could name is corruption, not a crash window.
        data = bytearray(open(os.path.join(cp, "hits_p2pkh.bin"),
                              "rb").read())
        data[0] ^= 0x01
        with open(os.path.join(cp, "hits_p2pkh.bin"), "wb") as f:
            f.write(bytes(data))
        try:
            rs.run_scan(locks_dir, url, "user:pass", 4, cp,
                        batch_size=2, checkpoint_every=2)
            fail("a corrupted bitmap resumed instead of refusing")
        except rs.ScanError as e:
            check("mismatch" in str(e), f"corruption reported as: {e}")
        print("ok  checkpoint: a bitmap matching no recorded state is "
              "still refused")
    finally:
        server.shutdown()


def test_rest_transport(tmp, locks_dir):
    """The REST interface is a different conversation with the node, not
    a different result.

    The two transports disagree about everything on the wire (verbatim
    bytes against hex inside JSON, two GETs a block against two batched
    POSTs a window, no credential against a credential) and must agree
    on the fingerprint, which is the only thing published. Depth is
    checked here too: with several windows in the air the fetches come
    back in whatever order the network decides, and the scan must still
    see them in height order or the prev_hash link would refuse them."""
    blocks = build_chain()
    server, url = serve(blocks)
    try:
        dir_rpc = os.path.join(tmp, "cp_rpc")
        fp_rpc = rs.run_scan(locks_dir, url, "user:pass", 4, dir_rpc,
                             batch_size=2, checkpoint_every=2)

        dir_rest = os.path.join(tmp, "cp_rest")
        fp_rest = rs.run_scan(locks_dir, url, None, 4, dir_rest,
                              batch_size=2, checkpoint_every=2,
                              client=rs.RestClient(url))
        check(fp_rest == fp_rpc,
              "REST scan fingerprint differs from the RPC scan")
        totals_rest, _ = read_totals(dir_rest)
        check(totals_rest == EXPECT_FULL, f"REST totals: {totals_rest}")

        dir_deep = os.path.join(tmp, "cp_rest_deep")
        fp_deep = rs.run_scan(locks_dir, url, None, 4, dir_deep,
                              batch_size=1, checkpoint_every=2,
                              client=rs.RestClient(url), prefetch_depth=3)
        check(fp_deep == fp_rpc,
              "REST scan at prefetch depth 3 differs from depth 1")
        print("ok  rest: same fingerprint as RPC, at depth 1 and 3")

        # A hash the node does not have is an answer, not a hiccup: it
        # must be named at once and not retried into a stall.
        try:
            rs.RestClient(url).fetch_blocks([99])
            fail("REST fetch of an unknown height did not raise")
        except rs.ScanError as e:
            check("404" in str(e), f"REST 404 not reported as such: {e}")
        print("ok  rest: an unknown height is a named error, not a retry")
    finally:
        server.shutdown()

    # The transport is chosen for bytes on the wire, never for trust:
    # the integrity checks must bite on this one exactly as they do on
    # the other.
    corrupt = dict(blocks)
    h_hex, raw_hex = corrupt[2]
    pos = len(raw_hex) - 40
    flipped = ("0" if raw_hex[pos] != "0" else "f")
    corrupt[2] = (h_hex, raw_hex[:pos] + flipped + raw_hex[pos + 1:])
    server, url = serve(corrupt)
    try:
        rs.run_scan(locks_dir, url, None, 4,
                    os.path.join(tmp, "cp_rest_corrupt"),
                    batch_size=2, checkpoint_every=2,
                    client=rs.RestClient(url))
        fail("corrupted block accepted by the scan over REST")
    except (rs.ScanError, bp.ParseError):
        print("ok  rest: altered block bytes abort the scan")
    finally:
        server.shutdown()


def test_resume_refuses_a_different_perimeter(tmp, locks_dir):
    """A burn made under the wide reading and one made under the
    narrow one are different claims, and a bit records neither: mixing
    them gives a bitmap — and a published fingerprint — that belongs to
    no perimeter, and nothing downstream can say so. The resume must
    refuse instead, and keep accepting the perimeter it started with."""
    blocks = build_chain()
    server, url = serve(blocks)
    try:
        cp = os.path.join(tmp, "cp_perimeter")
        rs.run_scan(locks_dir, url, "user:pass", 2, cp,
                    batch_size=2, checkpoint_every=2,
                    faces=False, cosigners=False)
        state = read_totals(cp)[1]
        check(state["perimeter"] == {"faces": False, "cosigners": False},
              f"the perimeter must be recorded: {state.get('perimeter')}")
        try:
            rs.run_scan(locks_dir, url, "user:pass", 4, cp,
                        batch_size=2, checkpoint_every=2)
            fail("a resume under a different perimeter was allowed")
        except rs.ScanError as e:
            check("perimeter" in str(e) or "different" in str(e),
                  f"the refusal must name the perimeter: {e}")
        # The same flags still resume, and reach the narrow totals.
        rs.run_scan(locks_dir, url, "user:pass", 4, cp,
                    batch_size=2, checkpoint_every=2,
                    faces=False, cosigners=False)
        totals, _ = read_totals(cp)
        check(totals == EXPECT_NARROW,
              f"resumed narrow scan totals: {totals}")

        # A state of an earlier format (the one that could lack the
        # field) is refused by its tag, never read as a default: a
        # perimeter guessed is a perimeter the fingerprint does not
        # name.
        old = os.path.join(tmp, "cp_legacy")
        rs.run_scan(locks_dir, url, "user:pass", 2, old,
                    batch_size=2, checkpoint_every=2)
        path = os.path.join(old, rs.STATE_NAME)
        with open(path) as f:
            st = json.load(f)
        st["format"] = "reuse-scan-v1"
        del st["perimeter"]
        with open(path, "w") as f:
            json.dump(st, f)
        try:
            rs.run_scan(locks_dir, url, "user:pass", 4, old,
                        batch_size=2, checkpoint_every=2)
            fail("a checkpoint of an earlier format was resumed")
        except rs.ScanError as e:
            check("reuse-scan-v1" in str(e), f"the refusal names the tag: {e}")
        print("ok  perimeter: a resume under other flags is refused, "
              "the same flags continue, and a checkpoint of an earlier "
              "format is refused by its tag")
    finally:
        server.shutdown()


def test_rest_rides_out_a_transient_5xx(tmp, locks_dir):
    """A 5xx is the node's moment, not its answer: warming up after a
    restart, or shedding load. The REST path must retry through it the
    way the RPC path already does, or a restart of the node costs a
    days-long run. The definite answers keep their old behaviour: the
    404 of an unknown height is named at once (tested with the
    transport suite above)."""
    class Flaky(FakeRpc):
        hiccups = 2

        def do_GET(self):
            if Flaky.hiccups:
                Flaky.hiccups -= 1
                self.send_error(503, "Service Unavailable")
                return
            super().do_GET()

    blocks = build_chain()
    Flaky.blocks = blocks
    Flaky.by_hash = {h: raw for h, raw in blocks.values()}
    server = ThreadingHTTPServer(("127.0.0.1", 0), Flaky)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    real_sleep = rs.time.sleep
    rs.time.sleep = lambda _s: None       # the backoff, not the retries
    try:
        rs.run_scan(locks_dir, url, None, 4,
                    os.path.join(tmp, "cp_flaky"),
                    batch_size=2, checkpoint_every=2,
                    client=rs.RestClient(url))
    finally:
        rs.time.sleep = real_sleep
        server.shutdown()
    check(Flaky.hiccups == 0, "the 503s were never actually served")
    totals, _ = read_totals(os.path.join(tmp, "cp_flaky"))
    check(totals == EXPECT_FULL,
          f"scan through a transient 503 mis-counted: {totals}")
    print("ok  rest: a transient 5xx is retried through, and the run "
          "completes on the full totals")


def test_rest_needs_no_credential():
    """Choosing REST must not ask for a secret it cannot use.

    The REST interface authenticates nobody, so `--rest` resolves no
    cookie and reads no environment: with neither available, the RPC
    path exits and the REST path builds a client anyway. A credential
    that is never resolved is a credential that cannot leak."""
    saved = os.environ.pop(rs.RPC_AUTH_ENV, None)
    try:
        client, auth = rs.build_client("http://127.0.0.1:8332", True, None)
        check(isinstance(client, rs.RestClient), "--rest did not pick REST")
        check(auth is None, "--rest resolved a credential anyway")
        try:
            rs.build_client("http://127.0.0.1:8332", False, None)
            fail("the RPC path started with no credential at all")
        except rs.AuthError:
            pass
    finally:
        if saved is not None:
            os.environ[rs.RPC_AUTH_ENV] = saved
    print("ok  rest: no credential asked for, and the RPC path still "
          "demands one")


class _Definite(BaseHTTPRequestHandler):
    """A node that answers with a status code: 401 unless the request
    carries `accept` as its credential, 503 when `flaky` says so."""
    accept = None
    flaky = 0
    seen = []

    def do_POST(self):
        self.seen.append(self.headers.get("Authorization"))
        if _Definite.flaky:
            _Definite.flaky -= 1
            self.send_response(503)
            self.end_headers()
            return
        if self.headers.get("Authorization") != _Definite.accept:
            self.send_response(401)
            self.end_headers()
            return
        n = len(json.loads(self.rfile.read(
            int(self.headers["Content-Length"]))))
        body = json.dumps([{"id": i, "result": i} for i in range(n)])
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def _basic(auth):
    import base64
    return "Basic " + base64.b64encode(auth.encode()).decode()


def test_a_definite_answer_is_not_retried_and_a_cookie_is_reread(tmp):
    """A 401 used to ride the same backoff as a socket error (8 tries,
    three minutes) and end in "RPC unreachable", pointing at the tunnel
    instead of the credential. A 5xx IS transient and is retried. And
    a 401 with a cookie file behind it gets one re-read: Core rotates
    the cookie at every restart, and a scan of days meets restarts."""
    import time as _time
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Definite)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/"
    sleeps = []
    real_sleep, _time.sleep = _time.sleep, lambda s: sleeps.append(s)
    try:
        _Definite.accept = _basic("u:new")
        _Definite.seen.clear()
        try:
            rs.RpcClient(url, "u:old", retries=4).batch(
                [("getblockhash", [1])])
            fail("a 401 was not raised")
        except rs.ScanError as e:
            assert "401" in str(e) and "credentials" in str(e), str(e)
        assert sleeps == [], f"a definite answer must not back off: {sleeps}"
        assert len(_Definite.seen) == 1, "a 401 must be asked once"

        cookie = os.path.join(tmp, "cookie")
        with open(cookie, "w") as f:
            f.write("u:old")
        client, _auth = rs.build_client(url, False, cookie)
        with open(cookie, "w") as f:
            f.write("u:new")             # the node restarted meanwhile
        _Definite.seen.clear()
        assert client.batch([("getblockhash", [1])]) == [0]
        assert _Definite.seen == [_basic("u:old"), _basic("u:new")], \
            "the rotated cookie must be re-read once, after the 401"
        assert sleeps == [], "the re-read is immediate, not a backoff"

        _Definite.flaky = 2
        _Definite.seen.clear()
        assert rs.RpcClient(url, "u:new", retries=4).batch(
            [("getblockhash", [1])]) == [0]
        assert sleeps == [2, 4], f"a 5xx is retried with backoff: {sleeps}"
    finally:
        _time.sleep = real_sleep
        server.shutdown()
    print("ok  rpc: 401 is an answer (no retry, the credential is named), "
          "a rotated cookie is re-read once, a 5xx is retried")


def test_the_scan_confronts_its_last_block_with_the_snapshot(tmp):
    """The locks were photographed at block 3. Scanning to 4 burns
    locks the snapshot no longer holds and counts their coins as
    reused: refused, unless asked for by name. Scanning to 3 is
    aligned; stopping short is a floor and says so."""
    blocks = build_chain()
    base3 = os.path.join(tmp, "base3")
    os.makedirs(base3)
    locks = test_prepare(base3, base_hash_hex=blocks[3][0], height=3)
    server, url = serve(blocks)
    try:
        try:
            rs.run_scan(locks, url, "user:pass", 4, os.path.join(tmp, "over"),
                        batch_size=2, checkpoint_every=2)
            fail("a scan past the snapshot's block was accepted")
        except rs.ScanError as e:
            check("photographed" in str(e), f"unexpected: {e}")
        rs.run_scan(locks, url, "user:pass", 3, os.path.join(tmp, "on"),
                    batch_size=2, checkpoint_every=2)
        with open(os.path.join(tmp, "on", "state.json")) as f:
            st = json.load(f)
        check(st["base_seen_at"] == 3 and st["base_hash"] == blocks[3][0],
              f"the state must record where the snapshot's block was: {st}")
        rs.run_scan(locks, url, "user:pass", 4, os.path.join(tmp, "over2"),
                    batch_size=2, checkpoint_every=2,
                    allow_base_mismatch=True)
        with open(os.path.join(tmp, "over2", "state.json")) as f:
            st = json.load(f)
        check(st["base_seen_at"] == 3 and st["last_height"] == 4,
              "an allowed overshoot still records the crossing")
    finally:
        server.shutdown()
    print("ok  base: past the snapshot's block is refused, on it is "
          "aligned, short of it is a floor")


def test_stats_finishes_a_checkpoint_caught_mid_promotion(tmp, locks_dir):
    """A kill between the state write and the promotion leaves the
    bitmaps the state names under `.new` and a stale set under the
    final names. The scan's resume knew which set to take; `stats`
    read the final set alone and called it corruption, healable only
    by a scan with a node behind it. One function decides now."""
    server, url = serve(build_chain())
    cp = os.path.join(tmp, "cp_midway")
    try:
        rs.run_scan(locks_dir, url, "user:pass", 4, cp, batch_size=2,
                    checkpoint_every=2)
    finally:
        server.shutdown()
    for t in rs.TYPE_ORDER:
        final = os.path.join(cp, f"hits_{t}.bin")
        os.replace(final, final + ".new")
        with open(final, "wb") as f:
            f.write(bytes(os.path.getsize(final + ".new")))
    rs.run_stats(locks_dir, cp, thresholds=(0, 10))
    check(not any(n.endswith(".new") for n in os.listdir(cp)),
          "stats must finish the promotion it found half done")
    print("ok  stats: a checkpoint caught mid-promotion is finished, not "
          "called corrupt")


def test_a_lost_curve_row_comes_back_from_the_state(tmp, locks_dir):
    """The curve row is the last write of a checkpoint: a kill after
    the state and before the row left a hole `curve deltas` folded
    into the next interval without a word. The resume writes the row
    back from the state."""
    blocks = build_chain()
    server, url = serve(blocks)
    cp = os.path.join(tmp, "cp_hole")
    try:
        rs.run_scan(locks_dir, url, "user:pass", 4, cp, batch_size=2,
                    checkpoint_every=2)
        curve = os.path.join(cp, rs.CURVE_NAME)
        with open(curve) as f:
            lines = f.read().splitlines(keepends=True)
        with open(curve, "w") as f:
            f.writelines(lines[:-1])                # the row for 4 is gone
        rs.run_scan(locks_dir, url, "user:pass", 4, cp, batch_size=2,
                    checkpoint_every=2)             # nothing to scan
        with open(curve) as f:
            healed = f.read().splitlines(keepends=True)
    finally:
        server.shutdown()
    check(healed == lines, f"the row must come back byte for byte:\n"
                           f"{healed}\n{lines}")
    print("ok  curve: a lost row is written back from the state on resume")


def test_a_truncated_locks_manifest_is_a_named_refusal(tmp):
    """`prepare` wrote its manifest with a plain open+dump after the
    runs were gone; a kill there left a truncated manifest that made the
    next scan die in a JSON traceback. Written atomically now, runs
    removed after it, and a broken one is refused by name."""
    locks = os.path.join(tmp, "locks_broken")
    os.makedirs(locks)
    with open(os.path.join(locks, rs.MANIFEST_NAME), "w") as f:
        f.write('{"format": "locks-v1", "types": {')
    try:
        rs._load_manifest(locks)
        fail("a truncated manifest was read")
    except rs.ScanError as e:
        check("prepare" in str(e), f"the refusal must say what to do: {e}")
    print("ok  locks: a truncated manifest is refused with the remedy")


def test_end_below_the_checkpoint_is_refused_by_name(tmp, locks_dir):
    """A resume with --end below the watermark ran zero windows and then
    tripped over the snapshot comparison with a message about the wrong
    thing; a bitmap cannot un-burn, so it is refused as what it is."""
    server, url = serve(build_chain())
    cp = os.path.join(tmp, "cp_shorter")
    try:
        rs.run_scan(locks_dir, url, "user:pass", 4, cp, batch_size=2,
                    checkpoint_every=2)
        try:
            rs.run_scan(locks_dir, url, "user:pass", 2, cp, batch_size=2,
                        checkpoint_every=2)
            fail("--end below the checkpoint was accepted")
        except rs.ScanError as e:
            check("already covers" in str(e), f"unexpected: {e}")
    finally:
        server.shutdown()
    print("ok  resume: --end below the checkpoint is refused by name")


def test_stats(tmp, locks_dir):
    """`stats` reads a locks dir + a scan checkpoint and reports the
    value distribution of the exposed locks. Checked against the scan's
    own totals: per-type value and count must match to the satoshi; the
    histogram and a zero threshold must fold back to the same totals;
    the fingerprint guard must reject a tampered bitmap."""
    blocks = build_chain()
    server, url = serve(blocks)
    try:
        cp = os.path.join(tmp, "cp_stats")
        rs.run_scan(locks_dir, url, "user:pass", 4, cp,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()

    totals, state = read_totals(cp)          # {type: (hits, satoshis)}
    out = os.path.join(tmp, "stats.json")
    # thresholds include 0: everything is >= 0, a clean total invariant.
    rs.run_stats(locks_dir, cp, thresholds=(0, 10), json_out=out)
    with open(out) as f:
        obj = json.load(f)

    check(obj["fingerprint"] == state["fingerprint"],
          "stats fingerprint does not match the checkpoint")
    check(obj["format"] == rs.STATS_TAG and obj["locks"] == state["locks"]
          and obj["height"] == state["last_height"]
          and obj["perimeter"] == state["perimeter"]
          and obj["locks_height"] == 4,
          f"the stats JSON names what its fingerprint is of: {obj.keys()}")
    grand = 0
    for t in rs.TYPE_ORDER:
        d = obj["types"][t]
        hits, sats = totals[t]
        check(d["count"] == hits and d["total_sat"] == sats,
              f"{t}: stats ({d['count']},{d['total_sat']}) != scan "
              f"({hits},{sats})")
        # zero threshold carries every lock and all the value
        z = d["concentration"]["0"]
        check(z["count"] == hits and z["value_sat"] == sats,
              f"{t}: zero-threshold tail is not the whole set")
        # histogram folds back to the totals
        hc = sum(b["count"] for b in d["histogram"])
        hv = sum(b["value_sat"] for b in d["histogram"])
        check(hc == hits and hv == sats,
              f"{t}: histogram ({hc},{hv}) != totals ({hits},{sats})")
        grand += sats
    allt = obj["types"]["all"]
    check(allt["total_sat"] == grand,
          f"ALL total {allt['total_sat']} != sum of types {grand}")
    check(allt["median_sat"] <= allt["max_sat"],
          "median above max: order statistics inconsistent")
    # Lorenz: non-decreasing in p, ends at (1.0 -> 1.0), never above 1.
    lz = allt["lorenz"]
    check(lz[-1][0] == 1.0 and abs(lz[-1][1] - 1.0) < 1e-9,
          f"Lorenz does not close at (1,1): {lz[-1]}")
    prev = -1.0
    for p, v in lz:
        check(v + 1e-9 >= prev and v <= 1.0 + 1e-9,
              f"Lorenz not monotone/in-range at p={p}: {v}")
        prev = v
    # top-N: the N largest never exceed the total, and grow with N.
    v100 = allt["top_n"]["100"]["value_sat"]
    v1000 = allt["top_n"]["1000"]["value_sat"]
    check(v100 <= v1000 <= grand,
          f"top-N monotonicity/total broken: {v100},{v1000},{grand}")
    print("ok  stats: per-type value/count, histogram and threshold "
          "fold back to the scan totals")

    # Guard: a tampered bitmap must be rejected, not silently mis-counted.
    with open(os.path.join(cp, "hits_p2pkh.bin"), "r+b") as f:
        f.write(b"\xff")
    try:
        rs.run_stats(locks_dir, cp)
        fail("stats accepted a checkpoint whose bitmap was altered")
    except rs.ScanError:
        print("ok  stats: altered bitmap rejected by the fingerprint guard")



def test_prepare_needs_the_snapshot_height(tmp):
    """The snapshot names its block by hash only, and every reuse figure
    is defined by that height: no height, no lock set."""
    snapshot = os.path.join(tmp, "no_height.dat")
    build_snapshot_file(snapshot)
    try:
        rs.run_prepare(snapshot, os.path.join(tmp, "locks_no_height"),
                       chunk_records=3)
        fail("a lock set without a height was written")
    except rs.ScanError as e:
        check("--headers" in str(e) and "--height" in str(e),
              f"the refusal names both roads: {e}")
    try:
        rs.run_prepare(snapshot, os.path.join(tmp, "locks_two"),
                       chunk_records=3, height=3, headers_dir=tmp)
        fail("two sources for one height were accepted")
    except rs.ScanError:
        pass
    print("ok  prepare: the height comes from exactly one of --headers and "
          "--height")


def test_prepare_reads_the_height_off_the_header_archive(tmp):
    """A sealed header archive holds every block id: the snapshot's
    height is the record whose id is the base hash, verified by the
    archive's own chain of links, and a hash the archive does not hold
    is a refusal."""
    import test_headers as th
    blocks, _model = th.headers_chain()  # a chain with a genesis, as headers need
    hdir = th.emit(tmp, blocks, "hdr_for_prepare")
    base3 = os.path.join(tmp, "base3_headers")
    os.makedirs(base3)
    locks = test_prepare(base3, base_hash_hex=blocks[3][0], headers_dir=hdir)
    manifest = rs._load_manifest(locks)
    check(rs.locks_height(manifest) == 3
          and manifest["build"]["height_source"] == "headers"
          and rs.locks_base_hash(manifest) == blocks[3][0],
          f"the height is read off the headers: {manifest['identity']}, "
          f"{manifest['build']['height_source']}")
    # The same snapshot with the height declared seals the same set:
    # the source is in `build`, the identity is the moment and the files.
    base3b = os.path.join(tmp, "base3_declared")
    os.makedirs(base3b)
    declared = rs._load_manifest(
        test_prepare(base3b, base_hash_hex=blocks[3][0], height=3))
    check(declared["fingerprint"] == manifest["fingerprint"],
          "the height's source must not change the lock set's name")
    snapshot = os.path.join(tmp, "foreign.dat")
    build_snapshot_file(snapshot)                     # a hash no chain has
    try:
        rs.run_prepare(snapshot, os.path.join(tmp, "locks_foreign"),
                       chunk_records=3, headers_dir=hdir)
        fail("a base hash the headers do not hold was accepted")
    except rs.ScanError as e:
        check("does not hold" in str(e), f"unexpected: {e}")
    print("ok  prepare: the height comes off the header archive, and a "
          "foreign hash is refused")


def test_a_wrong_declared_height_is_caught_by_the_scan(tmp):
    """`--height` is a claim. The scan meets the snapshot's block at its
    real height and refuses to write a figure under the wrong one."""
    blocks = build_chain()
    wrong = os.path.join(tmp, "base3_wrong")
    os.makedirs(wrong)
    locks = test_prepare(wrong, base_hash_hex=blocks[3][0], height=2)
    server, url = serve(blocks)
    try:
        rs.run_scan(locks, url, "user:pass", 3, os.path.join(tmp, "cp_wrong"),
                    batch_size=2, checkpoint_every=2)
        fail("a scan against a lock set with a wrong height was accepted")
    except rs.ScanError as e:
        check("was wrong" in str(e) and "3" in str(e) and "2" in str(e),
              f"the refusal names both heights: {e}")
    finally:
        server.shutdown()
    print("ok  scan: a declared height the chain contradicts is refused")


def test_verify_locks_is_the_shared_audit(tmp, locks_dir):
    fp = rs.run_verify_locks(locks_dir)
    check(fp == rs._load_manifest(locks_dir)["fingerprint"],
          "verify returns the fingerprint it recomputed")
    path = os.path.join(locks_dir, rs._lock_file("p2pkh"))
    raw = bytearray(open(path, "rb").read())
    raw[3] ^= 0xFF
    open(path, "wb").write(bytes(raw))
    try:
        rs.run_verify_locks(locks_dir)
        fail("a rotted lock file passed the audit")
    except rs.ScanError:
        pass
    print("ok  verify --locks: the four files against the manifest")


def test_the_identity_of_a_burnt_set_names_its_moment():
    """The same bitmaps at another height, against other locks, or under
    another perimeter are another answer, and the fingerprint says so:
    the previous identity let one hex string name all four."""
    bitmaps = {t: bytearray(b"\x01\x00") for t in rs.TYPE_ORDER}
    full = {"faces": True, "cosigners": True}
    a = rs.fingerprint_of_bitmaps(bitmaps, "aa" * 32, 100, full)
    check(a == rs.fingerprint_of_bitmaps(bitmaps, "aa" * 32, 100, full),
          "the identity is a function of its inputs")
    check(a != rs.fingerprint_of_bitmaps(bitmaps, "bb" * 32, 100, full),
          "other locks, other name")
    check(a != rs.fingerprint_of_bitmaps(bitmaps, "aa" * 32, 101, full),
          "another height, another name")
    check(a != rs.fingerprint_of_bitmaps(bitmaps, "aa" * 32, 100,
                                         {"faces": False, "cosigners": True}),
          "another perimeter, another name")
    # The perimeter enters as the digest of one canonical line, which a
    # porter recomputes from the recipe alone.
    check(rs.perimeter_digest(full) == hashlib.sha256(
        b"faces=1,cosigners=1").hexdigest(), "the perimeter's digest")
    print("ok  identity: locks, height and perimeter are in the name")


def test_the_scan_seals_its_curve_at_every_checkpoint(tmp, locks_dir):
    """The sidecar beside curve.csv is a sealed manifest the shared
    audit reads; it is rewritten with the state, and a lost row comes
    back with its sidecar."""
    from nodsig import curve as cv
    blocks = build_chain()
    server, url = serve(blocks)
    cp = os.path.join(tmp, "cp_sealed")
    try:
        rs.run_scan(locks_dir, url, "user:pass", 4, cp, batch_size=2,
                    checkpoint_every=2)
        curve = os.path.join(cp, rs.CURVE_NAME)
        meta = cv.verify(curve, cv.REUSE_TAG)
        state = read_totals(cp)[1]
        check(meta["build"]["road"] == "scan"
              and meta["build"]["parent"] == {"format": rs.STATE_TAG,
                                              "fingerprint": state["fingerprint"],
                                              "coverage": {"from": 1, "to": 4}}
              and meta["build"]["grid"] == 2 and meta["build"]["rows"] == 2
              and meta["build"]["locks"] == state["locks"]
              and meta["build"]["perimeter"] == state["perimeter"]
              and meta["identity"]["coverage"] == {"from": 1, "to": 4},
              f"the sidecar says what the CSV cannot: {meta}")
        rows = cv.read_reuse(curve, rs.TYPE_ORDER, every=2)
        check([h for h, _, _ in rows] == [2, 4]
              and rows[-1][2] == state["fingerprint"],
              f"the last row's fingerprint is the table's: {rows}")
        # A lost last row: healed from the state, and re-sealed.
        with open(curve) as f:
            lines = f.read().splitlines(keepends=True)
        with open(curve, "w") as f:
            f.writelines(lines[:-1])
        try:
            cv.verify(curve, cv.REUSE_TAG)
            fail("a curve that lost a row passed the audit")
        except cv.CurveError:
            pass
        rs.run_scan(locks_dir, url, "user:pass", 4, cp, batch_size=2,
                    checkpoint_every=2)
        check(open(curve).read() == "".join(lines), "the row is back")
        check(cv.verify(curve, cv.REUSE_TAG)["fingerprint"]
              == meta["fingerprint"], "and the sidecar with it")
    finally:
        server.shutdown()
    print("ok  curve: sealed at every checkpoint, healed with its sidecar")


def main():
    test_ripemd160()
    test_recount_from_bitmap_matches_the_naive_walk()
    test_the_pure_python_fallback_says_so_before_a_long_run()
    test_extraction()
    test_rest_needs_no_credential()
    with tempfile.TemporaryDirectory() as tmp:
        test_locks_are_verified_against_their_manifest(tmp)
    with tempfile.TemporaryDirectory() as tmp:
        locks_dir = test_prepare(tmp)
        test_scan(tmp, locks_dir)
        test_checkpoint_survives_a_crash_between_its_writes(tmp, locks_dir)
        test_resume_refuses_a_different_perimeter(tmp, locks_dir)
        test_rest_transport(tmp, locks_dir)
        test_rest_rides_out_a_transient_5xx(tmp, locks_dir)
        test_stats(tmp, locks_dir)
        test_a_definite_answer_is_not_retried_and_a_cookie_is_reread(tmp)
        test_the_scan_confronts_its_last_block_with_the_snapshot(tmp)
        test_stats_finishes_a_checkpoint_caught_mid_promotion(tmp, locks_dir)
        test_a_lost_curve_row_comes_back_from_the_state(tmp, locks_dir)
        test_a_truncated_locks_manifest_is_a_named_refusal(tmp)
        test_end_below_the_checkpoint_is_refused_by_name(tmp, locks_dir)
    print("PASS: reuse_scan agrees with the mirror chain, resumes "
          "deterministically, and refuses bad bytes.")


if __name__ == "__main__":
    main()
