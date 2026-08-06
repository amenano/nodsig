#!/usr/bin/env python3
"""
reuse_scan.py — count how many CURRENT coins sit behind locks that were
already opened in the past (address/key reuse), by scanning the whole
block history against the UTXO set.

Why this exists: the census (utxo_census.py) counts the coins whose
public key is exposed *by construction* — a hard lower bound that needs
no history. But most of the publicly quoted exposure (the ">34%" class
of estimates) comes from REUSE: a lock whose key was revealed by some
past spend, and which still guards coins today. Reuse cannot be read
from a snapshot; it requires rewinding history. This tool does exactly
that, as an exact count with a declared perimeter, reproducible bit for
bit by anyone at the same block height.

The three ideas it rests on (see the manual for the full story):

1. INVERTED COMPARISON. Instead of archiving every key ever revealed
   (billions), keep in memory only the ~100M hashes of the CURRENT
   locks that hide a key ("behind hash" types), and stream the history
   checking every revelation against that set. Small memory, one pass.

2. THE SPENT LOCK IS RECOMPUTED FROM THE UNLOCKING DATA. An input names
   the coin it spends as (txid, index), not the lock; but for the
   standard types the unlocking data contains what is needed to
   RECOMPUTE the lock: hash160 of the revealed public key (P2PKH,
   P2WPKH), hash160 of the redeem script (P2SH), sha256 of the witness
   script (P2WSH). No index over history is needed.

3. EVERY PARTIAL SCAN IS A VALID LOWER BOUND. A lock is burnt by its
   FIRST spend: reading more blocks can only add burnt locks, never
   remove them. An interrupted run is an honest result ("history read
   up to height H, reuse is AT LEAST X BTC"), and the sequence of
   checkpoints IS the published curve.

Two subcommands:

    prepare  — one-time: distill the current "behind hash" locks (with
               their coin amounts) from a dumptxoutset snapshot into
               sorted binary files. Runs offline, no node needed.

    scan     — the long run: fetch raw blocks from the node (batched
               JSON-RPC, or the binary REST interface with `--rest`,
               which halves the bytes on the wire), verify their
               integrity, extract revelations, match them against the
               prepared locks, checkpoint and resume. Read-only towards
               the node, days of runtime, survives interruption.

Declared perimeter (what a hit means): a current lock is counted as
burnt when the scan finds, in confirmed history, either the identical
lock hash being opened, or (faces extension, ON by default) another
face of the same revealed key — same hash160 as `1…`/`bc1q…`, or the
P2SH-wrapped face — or (cosigners extension, ON by default) a public
key revealed inside a redeem/witness script. What NO scan of blocks
can see, and is therefore excluded by declaration: keys shared only
off-chain (xpub given to services), keys seen only in mempool, and
P2SH/P2WSH locks never spent (their content is invisible). The count
errs on the side of LESS exposure, never more.

Everything is standard library; the node is only asked for public
chain data, read-only (getblockhash and getblock verbosity 0 over
JSON-RPC, or the two `.bin` endpoints that answer the same two
questions over REST). No wallet, no addresses of ours, aggregates only
in the outputs.
"""

import argparse
import base64
import hashlib
import heapq
import http.client
import json
import os
import queue
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from array import array

from nodsig import blockparse
from nodsig.blockparse import ParseError, script_pushes

# The hash primitives (sha256d / ripemd160 / hash160) live in their own
# leaf kernel; the scan recomputes hash160 of revealed keys and scripts.
from nodsig.hashing import hash160, warn_if_slow_ripemd160

# Atomic state/checkpoint writes (tmp + rename) come from the I/O kernel.
from nodsig.recio import (IO_CHUNK, atomic_json, budgeted_slab,
                          read_slabs)

# Distribution statistics (order stats, Gini, Lorenz, histogram) shared
# with reveal_archive and curve_deltas: one implementation, so a median
# or a Gini means the same thing wherever it is reported.
from nodsig import diststats as ds

# The graph co-emission plug (--graph): the scan already fetches and
# verifies every block, so it can grow the raw transaction-graph
# archive on the side. graphemit is self-contained (stdlib +
# blockparse) precisely so both scanners can host it without cycles.
from nodsig import graphemit

# The header co-emission plug (--headers), hosted the same way and for
# the same reason: 88 bytes a block keep the chain the scan verified,
# so its checks can be repeated later without another pass.
from nodsig import headers

# The snapshot format readers live in the census tool; importing them is
# deliberate: ONE implementation of that format in the project, checked
# against Core's own converter.
from nodsig import utxo_census as census


class ScanError(RuntimeError):
    """Anything that must stop the run: bad data, broken chain, RPC
    failure after retries. The message says what and where."""


# ---------------------------------------------------------------------------
# The lock types this scan is about
# ---------------------------------------------------------------------------
# Only the "behind hash" types matter here: the exposed-by-construction
# types (P2PK, P2TR, bare multisig) are already counted by the census
# and a scan can add nothing to them. For each type: the byte width of
# the lock hash as it appears in the scriptPubKey.

LOCK_TYPES = {
    "p2pkh":  20,   # hash160(pubkey)
    "p2sh":   20,   # hash160(redeem script)
    "p2wpkh": 20,   # hash160(pubkey) — same digest as p2pkh, other face
    "p2wsh":  32,   # sha256(witness script)
}
TYPE_ORDER = ["p2pkh", "p2sh", "p2wpkh", "p2wsh"]   # canonical order

MANIFEST_NAME = "manifest.json"
STATE_NAME = "state.json"
CURVE_NAME = "curve.csv"
SAT = 100_000_000


def looks_like_pubkey(item):
    """True for byte strings shaped like a Bitcoin public key: 33 bytes
    starting 0x02/0x03 (compressed) or 65 starting 0x04 (uncompressed).

    Shape is all we can check without context — but a false positive is
    harmless by construction: hashing a non-key can only match a real
    lock if that exact byte string IS what the lock was built from,
    which is the definition of a true hit (see the note in
    extract_reveals)."""
    n = len(item)
    return ((n == 33 and item[0] in (2, 3))
            or (n == 65 and item[0] == 4))


# ---------------------------------------------------------------------------
# prepare — distill the current locks from the snapshot
# ---------------------------------------------------------------------------

def _snapshot_locks(path):
    """Stream the dumptxoutset snapshot and yield, for every UTXO of a
    "behind hash" type, (type, lock_hash, satoshis).

    The walk over the file is the same as the census's; only what is
    kept differs: the census keeps counts, this keeps the lock hashes
    themselves (they are the memory-resident set the scan matches
    against). Everything about the format lives in utxo_census.py.
    """
    with open(path, "rb", buffering=1024 * 1024) as f:
        if census.read_exact(f, 5) != census.MAGIC:
            raise ScanError("not a dumptxoutset snapshot (v2)")
        version = int.from_bytes(census.read_exact(f, 2), "little")
        if version != census.EXPECTED_VERSION:
            raise ScanError(f"snapshot format v{version}, expected "
                            f"v{census.EXPECTED_VERSION}")
        if census.read_exact(f, 4) != census.MAINNET_MAGIC:
            raise ScanError("snapshot is not from mainnet")
        base_hash = census.read_exact(f, 32)[::-1].hex()
        declared = int.from_bytes(census.read_exact(f, 8), "little")
        yield ("__base__", base_hash, declared)   # header info, once

        left_in_group = 0
        for _ in range(declared):
            if left_in_group == 0:
                census.read_exact(f, 32)                 # txid: unused
                left_in_group = census.read_compactsize(f)
            left_in_group -= 1
            census.read_compactsize(f)                   # vout: unused
            census.read_varint(f)                        # height: unused
            sat = census.decompress_amount(census.read_varint(f))
            type_code = census.read_varint(f)
            if type_code == 0:                           # p2pkh, 20-byte hash
                yield ("p2pkh", census.read_exact(f, 20), sat)
            elif type_code == 1:                         # p2sh, 20-byte hash
                yield ("p2sh", census.read_exact(f, 20), sat)
            elif type_code < 6:                          # p2pk: exposed, skip
                census.read_exact(f, 32)
            else:
                script = census.read_exact(f, type_code - 6)
                kind = census.classify(type_code, script)
                if kind == "p2wpkh":
                    yield ("p2wpkh", script[2:22], sat)
                elif kind == "p2wsh":
                    yield ("p2wsh", script[2:34], sat)
                # p2tr/multisig/other: exposed or out of scope, skip


def run_prepare(snapshot_path, out_dir, chunk_records=8_000_000):
    """Build, per lock type, a sorted deduplicated binary file of
    records [lock_hash | 8-byte little-endian satoshi total].

    Deduplication matters and is not an optimization: several UTXOs can
    sit behind the SAME lock (that is address reuse seen from the other
    side), and the scan wants one entry per lock with the summed coins,
    because one revelation burns them all together.

    The sort is external (sorted runs on disk + streaming merge): the
    full list would not fit comfortably in memory as Python objects.
    `chunk_records` bounds how many records are held before flushing a
    sorted run.
    """
    os.makedirs(out_dir, exist_ok=True)
    buffers = {t: [] for t in LOCK_TYPES}
    run_files = {t: [] for t in LOCK_TYPES}
    buffered = 0
    base_hash, declared = None, None
    start = time.monotonic()

    def flush(t):
        # One write, not one per record. The run is already whole in
        # memory, so joining it costs a copy and saves millions of
        # 8 KiB trips: on a network mount that is the difference
        # between minutes and hours, and this is the only writer here
        # that was still going record by record.
        buffers[t].sort()
        run_path = os.path.join(out_dir, f"run_{t}_{len(run_files[t])}.tmp")
        with open(run_path, "wb") as out:
            out.write(b"".join(h + sat.to_bytes(8, "little")
                               for h, sat in buffers[t]))
        run_files[t].append(run_path)
        buffers[t].clear()

    seen = 0
    for kind, payload, sat in _snapshot_locks(snapshot_path):
        if kind == "__base__":
            base_hash, declared = payload, sat
            print(f"snapshot base block: {base_hash}")
            print(f"declared entries:    {declared:,}")
            continue
        buffers[kind].append((bytes(payload), sat))
        buffered += 1
        seen += 1
        if buffered >= chunk_records:
            for t in LOCK_TYPES:
                if buffers[t]:
                    flush(t)
            buffered = 0
        if seen % 10_000_000 == 0:
            print(f"  …{seen // 1_000_000}M locks collected "
                  f"({(time.monotonic() - start) / 60:.1f} min)",
                  file=sys.stderr)
    for t in LOCK_TYPES:
        if buffers[t]:
            flush(t)

    # Merge the sorted runs per type, summing the amounts of equal
    # hashes: heapq.merge streams them in order, so equal hashes arrive
    # adjacent and the group sum is a simple look-behind.
    manifest = {"format": "locks-v1", "base_hash": base_hash, "types": {}}
    for t in TYPE_ORDER:
        width = LOCK_TYPES[t]
        rec = width + 8

        # The runs are read back in slabs and split in memory, sized by
        # how many of them the merge holds open at once (budgeted_slab):
        # a per-record read here would issue one trip per 28-40 bytes.
        slab = budgeted_slab(len(run_files[t])) if run_files[t] else IO_CHUNK

        def read_run(path, width=width, rec=rec, slab=slab):
            for buf in read_slabs(path, rec, slab):
                for off in range(0, len(buf), rec):
                    yield (bytes(buf[off:off + width]),
                           int.from_bytes(buf[off + width:off + rec],
                                          "little"))

        out_path = os.path.join(out_dir, f"locks_{t}.bin")
        digest = hashlib.sha256()
        records, total_sat = 0, 0
        with open(out_path, "wb") as out:
            buf = bytearray()              # rows leave in slabs, see IO_CHUNK
            last_hash, last_sat = None, 0

            def emit(row):
                buf.extend(row)
                digest.update(row)
                if len(buf) >= IO_CHUNK:
                    out.write(buf)
                    buf.clear()

            for h, sat in heapq.merge(*(read_run(p) for p in run_files[t])):
                if h == last_hash:
                    last_sat += sat            # same lock, sum the coins
                    continue
                if last_hash is not None:
                    emit(last_hash + last_sat.to_bytes(8, "little"))
                    records += 1
                    total_sat += last_sat
                last_hash, last_sat = h, sat
            if last_hash is not None:
                emit(last_hash + last_sat.to_bytes(8, "little"))
                records += 1
                total_sat += last_sat
            if buf:
                out.write(buf)
        for p in run_files[t]:
            os.remove(p)
        manifest["types"][t] = {"records": records, "satoshis": total_sat,
                                "sha256": digest.hexdigest()}
        print(f"{t:<8} {records:>12,} locks  "
              f"{total_sat / SAT:>20,.8f} BTC")

    with open(os.path.join(out_dir, MANIFEST_NAME), "w") as f:
        json.dump(manifest, f, indent=1)
    print(f"locks written to {out_dir} "
          f"({(time.monotonic() - start) / 60:.1f} min). "
          "The manifest pins the snapshot's base block: scan only up to "
          "that same height. It also pins each file's record count and "
          "sha256, which every reader checks before burning a single "
          "lock: move or truncate one of these files and the next run "
          "refuses it instead of scanning against a shorter set.")


# ---------------------------------------------------------------------------
# The in-memory lock set: sorted blob + first-bytes index + bitmap
# ---------------------------------------------------------------------------

class LockSet:
    """One lock type held in memory, ready for millions of lookups.

    Layout: `hashes` is one contiguous bytes blob of the sorted lock
    hashes (fixed width); `sats` the parallel array of satoshi totals;
    `hits` a bitmap with one bit per lock (the burnt ones). A bitmap
    over the SORTED lock file is also the canonical form of the result:
    same snapshot + same scanned range = byte-identical bitmap, which
    is what the published fingerprint hashes.

    Lookup: like a phone book: a small index of the first three bytes
    (16.7M buckets) jumps straight to the right page, and a short
    binary search finishes inside it. Pure Python needs the help: the
    scan does billions of these.

    With `expect_records`/`expect_sha` (from the locks manifest that
    `prepare` wrote) the load refuses a file that is not the one the
    manifest describes. Every number downstream of a LockSet is a
    published one, and a truncated-on-a-record-boundary or bit-rotted
    locks file would otherwise burn against a wrong set with no error;
    worse, the cross-check builds its LockSet from the SAME files, so
    both roads would agree on the garbage. The sha is streamed inside
    the chunked read the load already does, so the check costs no
    extra pass.
    """

    def __init__(self, path, width, expect_records=None, expect_sha=None):
        self.width = width
        size = os.path.getsize(path)
        rec = width + 8
        if size % rec:
            raise ScanError(f"{path}: size {size} not a multiple of "
                            f"record width {rec}")
        self.count = size // rec
        if expect_records is not None and self.count != expect_records:
            raise ScanError(f"{path}: {self.count} records disagree with "
                            "the manifest: wrong or truncated locks file")
        digest = hashlib.sha256() if expect_sha is not None else None
        hashes = bytearray(self.count * width)
        sats = array("q", bytes(8 * self.count))
        # In chunks, not one read() per lock: this runs ~100M times on
        # the real set, at the start of a multi-day scan, and the same
        # chunked walk is what `stats` already uses to stream the
        # amounts (_load_exposed_sats).
        with open(path, "rb", buffering=1 << 20) as f:
            base = 0
            while base < self.count:
                n = min(1 << 16, self.count - base)
                buf = f.read(rec * n)
                if len(buf) != rec * n:
                    raise ScanError(f"{path}: file ended after "
                                    f"{base} of {self.count} records")
                if digest is not None:
                    digest.update(buf)
                for k in range(n):
                    i, o = base + k, k * rec
                    hashes[i * width:(i + 1) * width] = buf[o:o + width]
                    sats[i] = int.from_bytes(buf[o + width:o + rec],
                                             "little")
                base += n
        if digest is not None and digest.hexdigest() != expect_sha:
            raise ScanError(f"{path}: content does not match the sha256 "
                            "the locks manifest recorded at prepare: "
                            "corrupted locks file")
        self.hashes = bytes(hashes)
        self.sats = sats
        self.hits = bytearray((self.count + 7) // 8)
        self.hit_count = 0
        self.hit_sats = 0
        self.burn_height = None      # see track_burn_heights

        # First-three-bytes index: bucket_start[p] = index of the first
        # record whose hash begins with prefix p. Like the thumb index
        # of a dictionary: jump to the right page, then search only
        # there — it cuts the binary search from ~27 steps to ~3, which
        # matters when the scan does billions of lookups in Python.
        # Built with a counting pass + running sum (the hashes are
        # already sorted). Small sets (tests, partial data) skip it:
        # 16.7M buckets would cost more than they save.
        if self.count >= 1_000_000:
            counts = array("I", bytes(4 * (1 << 24)))
            h, w = self.hashes, width
            for i in range(self.count):
                j = i * w
                counts[(h[j] << 16) | (h[j + 1] << 8) | h[j + 2]] += 1
            starts = array("I", bytes(4 * ((1 << 24) + 1)))
            total = 0
            for p in range(1 << 24):
                starts[p] = total
                total += counts[p]
            starts[1 << 24] = total
            self.bucket_start = starts
        else:
            self.bucket_start = None

    def find(self, key):
        """Index of `key` in the sorted hashes, or -1."""
        if self.bucket_start is not None:
            p = (key[0] << 16) | (key[1] << 8) | key[2]
            lo, hi = self.bucket_start[p], self.bucket_start[p + 1]
        else:
            lo, hi = 0, self.count
        w, h = self.width, self.hashes
        while lo < hi:
            mid = (lo + hi) // 2
            row = h[mid * w:(mid + 1) * w]
            if row < key:
                lo = mid + 1
            elif row > key:
                hi = mid
            else:
                return mid
        return -1

    def track_burn_heights(self):
        """Start remembering, per lock, the height that burnt it.

        Off by default: it costs four bytes per lock and the scan does
        not need it, because it walks the chain in order and its own
        checkpoints already say when. The archive is read in DIGEST
        order instead, so a reader that wants the curve cannot learn
        the height from the order it sees, and has to be told."""
        self.burn_height = array("I", b"\xff\xff\xff\xff" * self.count)

    def burn(self, key, height=None):
        """Mark the lock as burnt if present. Returns True on a NEW hit.

        First spend is what burns a lock: re-marking an already burnt
        one changes nothing, which is exactly the monotonicity the
        lower bound rests on.

        `height` is kept as a MINIMUM, not as the first one seen, and
        the two differ: read in digest order a lock can be burnt by a
        later record before an earlier one. One lock genuinely takes
        two: a P2SH lock is burnt both by the key inside a wrapped
        P2WPKH and by the redeem script that spells the same twenty
        bytes, and those two records carry their own heights."""
        i = self.find(key)
        if i < 0:
            return False
        if height is not None and self.burn_height is not None:
            if height < self.burn_height[i]:
                self.burn_height[i] = height
        byte, bit = divmod(i, 8)
        if self.hits[byte] & (1 << bit):
            return False
        self.hits[byte] |= (1 << bit)
        self.hit_count += 1
        self.hit_sats += self.sats[i]
        return True

    def recount_from_bitmap(self):
        """Rebuild the running totals from the bitmap (used on resume).

        Walked by SET BIT, not by lock: the count comes from
        `int.bit_count` over whole machine words, and the amounts are
        summed only for the bits that are actually on. Testing every
        one of ~100 million locks in a Python loop cost minutes at the
        start of every resume of a days-long run, and a resume is what
        a crash makes frequent."""
        whole = self.count >> 3
        tail = self.count & 7
        blob = bytes(self.hits[:whole])
        self.hit_count = int.from_bytes(blob, "big").bit_count()
        if tail:
            last = self.hits[whole] & ((1 << tail) - 1)
            self.hit_count += last.bit_count()
        self.hit_sats = 0
        sats = self.sats
        for byte_i in range(whole + (1 if tail else 0)):
            byte = self.hits[byte_i]
            if not byte:
                continue
            base = byte_i << 3
            for bit in range(8):
                if byte & (1 << bit) and base + bit < self.count:
                    self.hit_sats += sats[base + bit]


# ---------------------------------------------------------------------------
# Extracting the revelations from an input
# ---------------------------------------------------------------------------

def extract_reveals(tx_in, faces, cosigners, stats):
    """All the (type, lock_hash) candidates revealed by one input.

    Rather than guessing what KIND of spend an input is (which would
    need the previous output), the extraction collects everything the
    unlocking data plausibly reveals and lets the lock set decide:

      - every pubkey-shaped item in the scriptSig pushes and in the
        witness items is treated as a revealed public key;
      - the LAST scriptSig push is a candidate redeem script (that is
        where P2SH keeps it), so its hash160 is a candidate p2sh lock;
      - the LAST witness item is a candidate witness script (that is
        where P2WSH keeps it), so its sha256 is a candidate p2wsh lock;
      - with `cosigners`, pubkey-shaped pushes INSIDE those candidate
        scripts are revealed keys too (the co-signers of a multisig
        whose script just went public);
      - with `faces`, a revealed key burns all its faces: hash160 in
        BOTH p2pkh and p2wpkh (same digest, two address forms), plus
        the P2SH-wrapped face hash160(0x0014||hash160(key)). Without
        `faces`, a scriptSig key burns only p2pkh and a witness key
        only p2wpkh — the narrow reading, kept as a flag so others can
        measure what each choice adds.

    Why over-collecting cannot inflate the count: a candidate only
    counts if its hash equals a CURRENT lock, and a hash matches only
    if the candidate bytes are the exact preimage that lock was built
    from — at which point the revelation is real, whatever kind of
    spend carried it. Collecting too much costs a few wasted lookups;
    collecting too little would silently weaken the bound. Malformed
    scripts are counted in `stats` and skipped, never guessed at.
    """
    pubkeys = []
    scripts = []      # (candidate script bytes, revealed-as-witness?)

    try:
        sig_pushes = script_pushes(tx_in.script_sig)
    except ParseError:
        stats["malformed_scriptsig"] += 1
        sig_pushes = []
    if sig_pushes:
        scripts.append((sig_pushes[-1], False))
        pubkeys.extend((p, False) for p in sig_pushes
                       if looks_like_pubkey(p))
    if tx_in.witness:
        scripts.append((tx_in.witness[-1], True))
        pubkeys.extend((p, True) for p in tx_in.witness
                       if looks_like_pubkey(p))

    out = []
    for script, from_witness in scripts:
        if from_witness:
            out.append(("p2wsh", hashlib.sha256(script).digest()))
        else:
            out.append(("p2sh", hash160(script)))
        if cosigners:
            try:
                inner = script_pushes(script)
            except ParseError:
                stats["malformed_inner_script"] += 1
                inner = []
            pubkeys.extend((p, from_witness) for p in inner
                           if looks_like_pubkey(p))

    for key, from_witness in pubkeys:
        h = hash160(key)
        if faces:
            out.append(("p2pkh", h))
            out.append(("p2wpkh", h))
            out.append(("p2sh", hash160(b"\x00\x14" + h)))
        elif from_witness:
            out.append(("p2wpkh", h))
        else:
            out.append(("p2pkh", h))
    return out


# ---------------------------------------------------------------------------
# The node transports: batches, retries, no trust in either of them
#
# Two clients, one method that matters to a scan: fetch_blocks(heights).
# JSON-RPC is the default and answers every question the project ever
# asks a node; REST answers exactly one, the bulk one, and answers it in
# half the bytes. Neither is trusted: the scanner hashes what arrives.
# ---------------------------------------------------------------------------

class RpcClient:
    """Minimal JSON-RPC client for Bitcoin Core, standard library only.

    Calls are sent in batches (one HTTP round-trip for many blocks) to
    amortize latency over the tunnel. Transient network failures are
    retried with growing pauses: on a run of days a WiFi hiccup must
    not cost the run (the checkpoint would save it anyway, but there is
    no reason to die for a hiccup). What is NOT retried is a JSON-RPC
    error from the node itself: that means the request is wrong (bad
    auth, unknown block) and retrying would not change it.

    The client deliberately verifies nothing about content: integrity
    of the blocks is the scanner's job (hashes recomputed from bytes),
    which is why the transport needs no trust.
    """

    def __init__(self, url, auth, retries=8):
        self.url = url
        self.retries = retries
        token = base64.b64encode(auth.encode()).decode()
        self.headers = {"Authorization": f"Basic {token}",
                        "Content-Type": "application/json"}

    def batch(self, calls):
        """calls = [(method, params), …] → list of results, in order."""
        payload = json.dumps([
            {"jsonrpc": "2.0", "id": i, "method": m, "params": p}
            for i, (m, p) in enumerate(calls)
        ]).encode()
        last_err = None
        for attempt in range(self.retries):
            if attempt:
                pause = min(2 ** attempt, 60)
                print(f"  RPC retry {attempt}/{self.retries} in {pause}s "
                      f"({last_err})", file=sys.stderr)
                time.sleep(pause)
            try:
                req = urllib.request.Request(self.url, data=payload,
                                             headers=self.headers)
                with urllib.request.urlopen(req, timeout=120) as resp:
                    replies = json.load(resp)
                break
            except (urllib.error.URLError, TimeoutError, OSError,
                    json.JSONDecodeError) as e:
                last_err = e
        else:
            raise ScanError(f"RPC unreachable after {self.retries} "
                            f"attempts: {last_err}")

        if not isinstance(replies, list) or len(replies) != len(calls):
            raise ScanError("RPC batch reply has the wrong shape")
        results = [None] * len(calls)
        for reply in replies:           # replies may arrive out of order
            if reply.get("error") is not None:
                raise ScanError(f"RPC error: {reply['error']} "
                                "(wrong credentials? cookie rotated at a "
                                "bitcoind restart?)")
            # The id routes the reply to the call that asked. It comes
            # from the far end, which this client trusts for nothing:
            # an id out of range must be a named failure, not an
            # IndexError from somewhere deep in the scan.
            i = reply.get("id")
            if not isinstance(i, int) or not 0 <= i < len(calls):
                raise ScanError(f"RPC batch reply carries id {i!r}, "
                                f"outside the {len(calls)} calls sent")
            results[i] = reply["result"]
        return results

    def fetch_blocks(self, heights):
        """heights → (hashes, raws), in the order asked.

        Two batched round-trips: heights to hashes, then hashes to
        blocks. This is where hex stops. The node speaks it in both
        directions (a block costs twice its size on the wire, plus the
        JSON around it), while everything above works on bytes and
        compares hashes in SERIALIZED order, so the conversion belongs
        here, in the transport that imposed it.
        """
        hex_hashes = self.batch([("getblockhash", [h]) for h in heights])
        hex_raws = self.batch([("getblock", [h, 0]) for h in hex_hashes])
        try:
            # RPC prints hashes byte-reversed for humans; serialized
            # order is what a header actually carries and what the
            # scan compares.
            hashes = [bytes.fromhex(h)[::-1] for h in hex_hashes]
            raws = [bytes.fromhex(r) for r in hex_raws]
        except (TypeError, ValueError) as e:
            raise ScanError(f"RPC returned something that is not block "
                            f"hex: {e}")
        for h, digest in zip(heights, hashes):
            if len(digest) != 32:
                raise ScanError(f"RPC returned a {len(digest)}-byte hash "
                                f"for height {h}, not 32")
        return hashes, raws


class RestClient:
    """The same fetch over the node's binary REST interface.

    It exists for one reason, and it is the reason a full scan takes
    days: `getblock` hands over a block as hex inside JSON, so the wire
    carries twice the bytes plus the escaping, and on a chain-scale run
    the wire is the ceiling. `/rest/block/<hash>.bin` carries the block
    verbatim.

    What the REST interface does not have, and what follows from it:

    - **no batching.** Two GETs per block (the hash by height, then the
      block), so latency is paid per block instead of per window. That
      makes the connection matter: `urllib` opens a new one per
      request, which over millions of requests is millions of
      handshakes, so this uses `http.client` and keeps one open **per
      thread**, which is also what lets several windows be in flight
      at once (see BlockFetcher's depth).
    - **no credential.** REST is unauthenticated by design (`-rest=1`,
      same port as the RPC), so this path holds no secret at all. The
      same property is why a node must keep that port on localhost or
      behind a tunnel, exactly as for the RPC port.

    None of it changes what the caller may believe: every block is
    still checked against the hash it was asked for, upstream, so the
    transport deserves no trust in either shape.
    """

    def __init__(self, url, retries=8):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ScanError(f"REST needs an http:// or https:// address, "
                            f"got {url!r}")
        self.scheme = parts.scheme
        self.host = parts.hostname or "127.0.0.1"
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.retries = retries
        self._per_thread = threading.local()

    def _connection(self):
        conn = getattr(self._per_thread, "conn", None)
        if conn is None:
            cls = (http.client.HTTPSConnection if self.scheme == "https"
                   else http.client.HTTPConnection)
            conn = cls(self.host, self.port, timeout=120)
            self._per_thread.conn = conn
        return conn

    def _drop(self):
        """Throw away this thread's connection: after a network error
        its state is unknown, and a reused half-broken connection is a
        much worse failure than a fresh handshake."""
        conn = getattr(self._per_thread, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
            self._per_thread.conn = None

    def _get(self, path, what):
        """One GET, retried on the same policy as an RPC batch: a WiFi
        hiccup on a run of days must not cost the run. A DEFINITE answer
        from the node (a 404 for an unknown block, or the interface not
        being enabled) is NOT retried: asking again gives the same
        answer. A 5xx is not that answer — it is the node warming up
        after a restart or shedding load ("work queue depth exceeded"),
        the very moments the JSON-RPC path already rides out through its
        retries, and a days-long run meets both."""
        last_err = None
        for attempt in range(self.retries):
            if attempt:
                pause = min(2 ** attempt, 60)
                print(f"  REST retry {attempt}/{self.retries} in {pause}s "
                      f"({last_err})", file=sys.stderr)
                time.sleep(pause)
            try:
                conn = self._connection()
                conn.request("GET", path)
                resp = conn.getresponse()
                body = resp.read()      # drained: the connection is reused
                status, reason = resp.status, resp.reason
            except (OSError, http.client.HTTPException) as e:
                last_err = e
                self._drop()
                continue
            if 500 <= status < 600:
                last_err = f"HTTP {status} {reason}"
                self._drop()    # a server mid-restart may close it anyway
                continue
            if status != 200:
                raise ScanError(
                    f"REST {path} answered {status} {reason} ({what}). "
                    f"Is the node running with -rest=1?")
            return body
        raise ScanError(f"REST unreachable after {self.retries} attempts "
                        f"({what}): {last_err}")

    def fetch_blocks(self, heights):
        """heights → (hashes, raws), in the order asked."""
        hashes, raws = [], []
        for h in heights:
            digest = self._get(f"/rest/blockhashbyheight/{h}.bin",
                               f"hash of height {h}")
            if len(digest) != 32:
                raise ScanError(f"REST returned {len(digest)} bytes for the "
                                f"hash of height {h}, not 32")
            # `.bin` gives the hash in serialized order, which is the
            # form the scan compares; the URL of a block wants the
            # display form, which is the same bytes read backwards.
            raws.append(self._get(f"/rest/block/{digest[::-1].hex()}.bin",
                                  f"block at height {h}"))
            hashes.append(digest)
        return hashes, raws


class _Slot:
    """One window's place in line: the payload, or what went wrong."""

    __slots__ = ("ready", "payload", "error")

    def __init__(self):
        self.ready = threading.Event()
        self.payload = None
        self.error = None


class BlockFetcher:
    """Yields (window, hashes, raws) over a height range, keeping up to
    `depth` windows in flight ahead of the caller.

    Fetch and parse used to run in series: the pipe sat idle while the
    CPU parsed, and the CPU sat idle while the pipe filled. Measured on
    the real tunnel, that ceiling was ~6.7 MB/s out of ~11 the fetch
    alone can do. Now background threads fetch ahead while the caller
    digests the window it has (the socket wait releases the GIL, so the
    overlap is real), and results are handed over strictly in height
    order, whatever order they arrive in.

    **Depth 1, the default, is the old behaviour exactly**: one window
    in the air, one request at a time, so a single-threaded fake server
    in the tests sees the same conversation it always saw, and at most
    two windows of raw blocks live in memory.

    Depth above 1 is there for REST, which pays latency per block
    instead of per window and cannot batch: N windows in flight means N
    connections working at once, and N+1 windows of raw blocks in
    memory. It buys nothing that JSON-RPC batching does not already
    buy, so it is not the default. Either way the caller verifies every
    byte by hash, so the transport keeps deserving no trust.

    `prefetch=False` (flag `--no-prefetch`) restores the strictly
    serial behaviour with no thread at all: the prudent fallback if the
    overlap ever misbehaves on an exotic setup.
    """

    def __init__(self, client, start_height, end_height, batch_size,
                 prefetch=True, depth=1):
        self.client = client
        self.start = start_height
        self.end = end_height
        self.batch = batch_size
        self.depth = max(1, depth) if prefetch else 0

    def _windows(self):
        height = self.start
        while height <= self.end:
            window = list(range(height, min(height + self.batch,
                                            self.end + 1)))
            yield window
            height = window[-1] + 1

    def _fetch(self, window):
        hashes, raws = self.client.fetch_blocks(window)
        return window, hashes, raws

    def _window_count(self):
        span = self.end - self.start + 1
        return max(0, -(-span // self.batch))     # ceil, without floats

    def __iter__(self):
        windows = self._windows()
        if not self.depth:
            for window in windows:
                yield self._fetch(window)
            return

        # One slot per window, taken in height order. A worker claims
        # the next window and puts its (empty) slot in the queue under
        # the SAME lock, so the queue is ordered by height even though
        # the fetches finish in whatever order the network decides.
        # The queue's bound IS the depth: a worker that finds it full
        # waits there instead of running further ahead.
        lock = threading.Lock()
        slots = queue.Queue(maxsize=self.depth)
        stopping = threading.Event()

        def worker():
            while not stopping.is_set():
                with lock:
                    window = next(windows, None)
                    if window is None:
                        return
                    slot = _Slot()
                    slots.put(slot)
                try:
                    slot.payload = self._fetch(window)
                except BaseException as e:      # re-raised in the caller
                    slot.error = e
                finally:
                    slot.ready.set()

        # Daemon threads on purpose: an aborted run (a block that did
        # not hash to what was asked, a Ctrl-C) must not wait for a
        # fetch that is halfway through its retries. The windows in the
        # air are cheap to fetch again; the exit is not.
        for i in range(self.depth):
            threading.Thread(target=worker, daemon=True,
                             name=f"block-prefetch-{i}").start()
        try:
            for _ in range(self._window_count()):
                slot = slots.get()
                slot.ready.wait()
                if slot.error is not None:
                    raise slot.error
                yield slot.payload
        finally:
            stopping.set()


# ---------------------------------------------------------------------------
# scan — the long run
# ---------------------------------------------------------------------------

def _fingerprint(locks):
    """Canonical fingerprint of the current result.

    sha256 over: a format tag, then for each type in fixed order its
    name and the sha256 of its hit bitmap. The bitmap is defined over
    the sorted locks file, so: same snapshot + same scanned range ⇒
    same fingerprint, on anyone's machine. Publishing it at every
    checkpoint lets a third party compare with us at ANY intermediate
    height, not only at the end — the level-3 twin of muhash.
    """
    return fingerprint_of_bitmaps({t: locks[t].hits for t in TYPE_ORDER})


def fingerprint_of_bitmaps(bitmaps):
    """The rule above, over bare bitmaps.

    A curve row has to fingerprint the state as it was at ITS height,
    which is a bitmap nobody holds in a LockSet: it is replayed. The
    definition lives here once so the replayed rows and the final one
    cannot drift apart."""
    d = hashlib.sha256(b"reuse-hits-v1")
    for t in TYPE_ORDER:
        d.update(t.encode())
        d.update(hashlib.sha256(bytes(bitmaps[t])).digest())
    return d.hexdigest()


def _load_manifest(locks_dir):
    with open(os.path.join(locks_dir, MANIFEST_NAME)) as f:
        manifest = json.load(f)
    if manifest.get("format") != "locks-v1":
        raise ScanError("unknown locks manifest format")
    return manifest


def run_scan(locks_dir, rpc_url, auth, end_height, checkpoint_dir,
             batch_size=25, checkpoint_every=10_000,
             faces=True, cosigners=True, client=None, graph_dir=None,
             headers_dir=None, prefetch=True, prefetch_depth=1,
             graph_digest_dir=None):
    """The run. Sequential over heights, batch by batch:

        fetch raw blocks → verify (header hash, prev link, Merkle,
        witness commitment) → extract revelations → burn matching
        locks → checkpoint every `checkpoint_every` blocks.

    Resumable: state.json in `checkpoint_dir` records the last height
    whose work is safely on disk; a rerun with the same arguments
    continues from there. The curve CSV grows one row per checkpoint —
    every row is a valid lower bound on its own.
    """
    manifest = _load_manifest(locks_dir)
    warn_if_slow_ripemd160("this scan")
    client = client or RpcClient(rpc_url, auth)
    os.makedirs(checkpoint_dir, exist_ok=True)
    state_path = os.path.join(checkpoint_dir, STATE_NAME)
    curve_path = os.path.join(checkpoint_dir, CURVE_NAME)

    print("loading locks into memory "
          "(blob + first-bytes index; a few minutes)…", file=sys.stderr)
    locks = {}
    for t in TYPE_ORDER:
        locks[t] = LockSet(os.path.join(locks_dir, f"locks_{t}.bin"),
                           LOCK_TYPES[t],
                           expect_records=manifest["types"][t]["records"],
                           expect_sha=manifest["types"][t]["sha256"])
        print(f"  {t:<8} {locks[t].count:>12,} locks", file=sys.stderr)

    stats = {"malformed_scriptsig": 0, "malformed_inner_script": 0,
             "inputs": 0, "transactions": 0}

    # --- Resume, or start fresh ---
    start_height = 1                      # genesis coinbase reveals nothing
    prev_hash = None                      # serialized order, None = unchecked
    if os.path.exists(state_path):
        with open(state_path) as f:
            state = json.load(f)
        if state["locks_manifest"] != manifest["types"]:
            raise ScanError("checkpoint was made against DIFFERENT locks "
                            "files: refusing to mix results")
        # The perimeter is part of what a bitmap MEANS: a burn made
        # under the wide reading and one made under the narrow one are
        # different claims, and a bit carries no record of which rule
        # set it. Mixing them irreversibly is the failure this refuses,
        # because the fingerprint would then describe no perimeter at
        # all — and nothing downstream could say so. A checkpoint from
        # before this field is read as the default perimeter, which is
        # what those runs used.
        was = state.get("perimeter") or {"faces": True, "cosigners": True}
        if was != {"faces": bool(faces), "cosigners": bool(cosigners)}:
            raise ScanError(
                f"this checkpoint was made with faces="
                f"{'on' if was['faces'] else 'off'}, cosigners="
                f"{'on' if was['cosigners'] else 'off'}, but this run "
                f"asks for faces={'on' if faces else 'off'}, cosigners="
                f"{'on' if cosigners else 'off'}: the two readings burn "
                "different locks, and a bitmap holding both belongs to "
                "neither. Resume with the same flags, or scan into a "
                "fresh directory")

        # checkpoint() commits in two phases: bitmaps under a pending
        # `.new` name, then the state that fingerprints them, then the
        # promotion to the final names. A crash can stop between any
        # two, so a `.new` beside a state is not corruption, it is a
        # checkpoint caught mid-commit — and WHICH set the state names
        # is what the fingerprint says. Try the pending set first: a
        # match means the state was written and only the promotion was
        # cut short, so finish it. A mismatch means the crash came
        # before the state write, the pending set is uncommitted work,
        # and the promoted set must still match — discard the leftovers
        # and resume from it. Only when neither set matches is the
        # directory actually broken.
        def read_hits(prefer_pending):
            for t in TYPE_ORDER:
                final = os.path.join(checkpoint_dir, f"hits_{t}.bin")
                pending = final + ".new"
                path = (pending if prefer_pending and os.path.exists(pending)
                        else final)
                with open(path, "rb") as f:
                    locks[t].hits = bytearray(f.read())
                locks[t].recount_from_bitmap()

        pendings = [os.path.join(checkpoint_dir, f"hits_{t}.bin.new")
                    for t in TYPE_ORDER]
        read_hits(prefer_pending=True)
        if _fingerprint(locks) == state["fingerprint"]:
            for pending in pendings:
                if os.path.exists(pending):
                    os.replace(pending, pending[:-len(".new")])
        else:
            if not any(os.path.exists(p) for p in pendings):
                raise ScanError("checkpoint fingerprint mismatch: bitmaps "
                                "on disk do not match the recorded state")
            read_hits(prefer_pending=False)
            if _fingerprint(locks) != state["fingerprint"]:
                raise ScanError("checkpoint fingerprint mismatch: neither "
                                "the committed bitmaps nor the pending ones "
                                "match the recorded state")
            for pending in pendings:
                if os.path.exists(pending):
                    os.remove(pending)
        stats.update(state["stats"])
        start_height = state["last_height"] + 1
        prev_hash = bytes.fromhex(state["last_block_hash"])[::-1]
        print(f"resuming from height {start_height} "
              f"(fingerprint verified)", file=sys.stderr)

    # Graph co-emission (OFF by default: the lean pass stays the
    # default for anyone rerunning the count). When on, the emitter
    # grows its own archive in lockstep with this scan — load() checks
    # the two agree on where to resume, or refuses.
    # --graph-digest is the same plug measuring instead of writing:
    # it checks that this code still emits the graph a reference
    # archive already holds, without spending the disk to prove it.
    # The two are answers to one question, so asking both is a mistake
    # worth naming.
    emitter = None
    if graph_dir and graph_digest_dir:
        raise graphemit.GraphError(
            "--graph and --graph-digest do the same work with and "
            "without the disk: pick one (fingerprint the archive "
            "afterwards if you wrote it)")
    if graph_dir:
        emitter = graphemit.GraphEmitter(graph_dir)
        emitter.load(start_height)
    elif graph_digest_dir:
        emitter = graphemit.GraphDigest(graph_digest_dir, checkpoint_dir)
        emitter.load(start_height)

    # The header archive (also OFF by default). It is the one plug that
    # can move the scan's own starting point: a chain of headers has to
    # reach genesis to check its first link, so a fresh archive asks for
    # height 0 and the loop below feeds that block to it and to nothing
    # else — every other artifact here starts at 1 on purpose.
    header_emitter = None
    feed_from = start_height
    if headers_dir:
        header_emitter = headers.HeaderEmitter(headers_dir)
        feed_from = header_emitter.load(start_height)

    def checkpoint(height, block_hash_display):
        # The co-emitted artifacts checkpoint first, on purpose: if a
        # crash lands between the writes they are AHEAD of this state,
        # the one direction their load() can heal (see GraphEmitter).
        if emitter:
            emitter.checkpoint(height, block_hash_display)
        if header_emitter:
            header_emitter.checkpoint(height, block_hash_display)
        # Two-phase commit, because the state's fingerprint covers the
        # bitmaps: replacing them in place and THEN writing the state
        # would leave a crash in between with new bitmaps against an old
        # state — a mismatch with nothing left to fall back on, and the
        # whole run to redo. So the new bitmaps land under a pending
        # `.new` name (complete or absent: they go through a `.tmp` and
        # a rename), the state commits against them, and only then are
        # they promoted over the old set. Whichever write the crash
        # cuts, one full set still matches the state on disk; the
        # resume path above knows how to pick it.
        for t in TYPE_ORDER:
            tmp = os.path.join(checkpoint_dir, f"hits_{t}.bin.tmp")
            with open(tmp, "wb") as f:
                f.write(bytes(locks[t].hits))
            os.replace(tmp, os.path.join(checkpoint_dir,
                                         f"hits_{t}.bin.new"))
        fp = _fingerprint(locks)
        atomic_json(state_path, {
            "format": "reuse-scan-v1",
            "locks_manifest": manifest["types"],
            "perimeter": {"faces": bool(faces),
                          "cosigners": bool(cosigners)},
            "last_height": height,
            "last_block_hash": block_hash_display,
            "stats": stats,
            "totals": {t: {"hits": locks[t].hit_count,
                           "satoshis": locks[t].hit_sats}
                       for t in TYPE_ORDER},
            "fingerprint": fp,
        })
        for t in TYPE_ORDER:
            os.replace(os.path.join(checkpoint_dir, f"hits_{t}.bin.new"),
                       os.path.join(checkpoint_dir, f"hits_{t}.bin"))
        new_curve = not os.path.exists(curve_path)
        with open(curve_path, "a") as f:
            if new_curve:
                f.write("height," + ",".join(
                    f"{t}_hits,{t}_satoshis" for t in TYPE_ORDER)
                    + ",fingerprint\n")
            f.write(f"{height},"
                    + ",".join(f"{locks[t].hit_count},{locks[t].hit_sats}"
                               for t in TYPE_ORDER)
                    + f",{fp}\n")
        return fp

    # --- The loop ---
    started = time.monotonic()
    done_since_start = 0
    fetcher = BlockFetcher(client, feed_from, end_height, batch_size,
                           prefetch=prefetch, depth=prefetch_depth)
    for window, hashes, raws in fetcher:
        for h, want, raw in zip(window, hashes, raws):
            # The transport hands over hashes in serialized order,
            # whichever transport it was. This closes the integrity
            # loop: the bytes must BE the block we asked for, and the
            # 80-byte hash settles that BEFORE the parser walks a single
            # byte of what a wire delivered (see blockparse.block_id)…
            if blockparse.block_id(raw) != want:
                raise ScanError(f"height {h}: block bytes do not hash to "
                                "the requested block hash")
            block = blockparse.parse_block(raw)   # Merkle + witness commit
            # …and each block must extend the previous one: the chain
            # certifies itself while we read it.
            if prev_hash is not None and block.header.prev_hash != prev_hash:
                raise ScanError(f"height {h}: prev_hash does not link to "
                                f"height {h - 1} (reorg? wrong node?)")
            prev_hash = block.header.hash
            if header_emitter:
                header_emitter.add_block(h, block)
            if h < start_height:
                # Genesis, fetched only for the header chain's first
                # link: its coinbase is unspendable by consensus, so it
                # burns no lock and creates no edge anywhere else.
                continue
            if emitter:
                emitter.add_block(h, block)

            for tx in block.transactions:
                stats["transactions"] += 1
                if blockparse.is_coinbase(tx):
                    continue              # creates coins, spends none
                for tx_in in tx.inputs:
                    stats["inputs"] += 1
                    for t, key in extract_reveals(tx_in, faces,
                                                  cosigners, stats):
                        locks[t].burn(key)

        done_since_start += len(window)

        if (window[-1] % checkpoint_every < batch_size
                or window[-1] == end_height):
            fp = checkpoint(window[-1], blockparse.hash_hex(prev_hash))
            rate = done_since_start / (time.monotonic() - started)
            eta_h = (end_height - window[-1]) / rate / 3600 if rate else 0
            burnt = sum(locks[t].hit_sats for t in TYPE_ORDER)
            print(f"checkpoint @ {window[-1]:>7,}: "
                    f"reuse ≥ {burnt / SAT:,.2f} BTC "
                    f"({sum(locks[t].hit_count for t in TYPE_ORDER):,} locks) "
                    f"| {rate:.1f} blk/s, ~{eta_h:.1f} h left "
                    f"| {fp[:16]}…", file=sys.stderr)

    # --- Final summary: the numbers AND the declared blind spots ---
    print(f"\n=== Reuse scan up to height {end_height} "
          f"(locks from snapshot {manifest['base_hash'][:16]}…) ===")
    print(f"{'type':<8} {'locks':>13} {'burnt':>12} "
          f"{'burnt BTC':>20}")
    for t in TYPE_ORDER:
        ls = locks[t]
        print(f"{t:<8} {ls.count:>13,} {ls.hit_count:>12,} "
              f"{ls.hit_sats / SAT:>20,.8f}")
    total = sum(locks[t].hit_sats for t in TYPE_ORDER)
    print(f"{'TOTAL':<8} {'':>13} "
          f"{sum(locks[t].hit_count for t in TYPE_ORDER):>12,} "
          f"{total / SAT:>20,.8f}")
    print(f"\nfingerprint: {_fingerprint(locks)}")
    print(f"perimeter: faces={'on' if faces else 'off'}, "
          f"cosigners={'on' if cosigners else 'off'}; "
          f"malformed scriptSigs: {stats['malformed_scriptsig']}, "
          f"malformed inner scripts: {stats['malformed_inner_script']}")
    print("NOT visible to this or any block scan, by declaration: "
          "keys shared off-chain (xpub), keys seen only in mempool, "
          "P2SH/P2WSH locks never spent. The true exposure can only be "
          "HIGHER than this count, never lower.")
    if graph_digest_dir:
        emitter.report()
    return _fingerprint(locks)


# ---------------------------------------------------------------------------
# stats: how the exposed value is spread across the locks
# ---------------------------------------------------------------------------
#
# The scan answers "how much exposed value?"; stats answers "how is that
# value spread across locks?". The mean alone (exposed BTC / exposed
# locks) hides everything: a few whales on a long tail of dust give the
# same mean as a broad band of mid-sized holders, yet the two say very
# different things about WHO reuses. So this reads the amount of every
# exposed lock and reports the shape — median and high percentiles, how
# much value sits above a threshold, a concentration index, and a
# per-decade histogram (the data a treemap draws).
#
# It needs only the per-lock amounts (the locks files) and which locks
# were burnt (the checkpoint bitmaps): a read-side computation, no node,
# no rescan, safe to run after the fact. Caveat baked into the wording of
# the output: a "lock" is one unique scriptPubKey with the TOTAL it
# guards, so these are per-address/script figures, NOT a headcount of
# entities — one actor can hold many locks, and good hygiene fragments a
# holder across many. The distribution supports a reading; it never
# proves one.

# Powers-of-ten BTC band edges: the levels of the histogram / treemap.
# Each band is [low, high) BTC; the last is open-ended.
STATS_LEVELS = [0.001, 0.01, 0.1, 1, 10, 100, 1000]


def _num(x):
    """Compact BTC label: '10', '0.001', without trailing noise."""
    return str(int(x)) if x == int(x) else ("%g" % x)


def _band_labels(levels):
    """Human labels for the histogram bands defined by `levels`."""
    labels, prev = [], 0
    for x in levels:
        labels.append(f"{_num(prev)}–{_num(x)}")
        prev = x
    labels.append(f"≥{_num(prev)}")
    return labels


def _load_exposed_sats(locks_dir, checkpoint_dir):
    """Amount (satoshis) of every EXPOSED lock, per type, index-free.

    Reads only what stats needs, the per-lock amounts and the hit
    bitmap: not the hashes nor the lookup index the scan builds. Before
    trusting a byte it repeats the scan's own resume guards: the
    checkpoint must be against THESE locks (same manifest), the locks
    bytes must hash to what the manifest recorded at prepare, and the
    bitmaps must hash to the recorded fingerprint. Stats over mismatched
    inputs would be quietly wrong, which is worse than a loud failure.

    Returns (exposed, state, manifest) where exposed[type] is an
    unsorted array('q') of the satoshi totals of that type's burnt locks.
    """
    manifest = _load_manifest(locks_dir)
    with open(os.path.join(checkpoint_dir, STATE_NAME)) as f:
        state = json.load(f)
    if state["locks_manifest"] != manifest["types"]:
        raise ScanError("checkpoint was made against DIFFERENT locks "
                        "files: refusing to compute stats on a mix")

    # Load the bitmaps and verify the fingerprint FIRST: fail fast,
    # before reading gigabytes of amounts off disk.
    hits = {}
    fp = hashlib.sha256(b"reuse-hits-v1")
    for t in TYPE_ORDER:
        with open(os.path.join(checkpoint_dir, f"hits_{t}.bin"), "rb") as f:
            hits[t] = bytearray(f.read())
        fp.update(t.encode())
        fp.update(hashlib.sha256(bytes(hits[t])).digest())
    if fp.hexdigest() != state["fingerprint"]:
        raise ScanError("checkpoint fingerprint mismatch: bitmaps on disk "
                        "do not match the recorded state")

    exposed = {}
    for t in TYPE_ORDER:
        width = LOCK_TYPES[t]
        rec = width + 8
        path = os.path.join(locks_dir, f"locks_{t}.bin")
        size = os.path.getsize(path)
        if size % rec:
            raise ScanError(f"{path}: size {size} not a multiple of "
                            f"record width {rec}")
        count = size // rec
        if count != manifest["types"][t]["records"]:
            raise ScanError(f"{path}: {count} records disagree with the "
                            "manifest — wrong or truncated locks file")
        h = hits[t]
        sats = array("q")
        append = sats.append
        # Stream in big chunks; keep a lock's amount only when its bit is
        # set. Bytes [k*rec + width : +8] are the little-endian satoshi
        # total of the k-th record in the chunk. The sha rides the same
        # pass: the count check above cannot see a rotted byte, and
        # amounts from a rotted file would be quietly wrong.
        digest = hashlib.sha256()
        with open(path, "rb", buffering=1 << 20) as f:
            base = 0
            while base < count:
                n = min(1 << 16, count - base)
                buf = f.read(rec * n)
                digest.update(buf)
                for k in range(n):
                    idx = base + k
                    if h[idx >> 3] & (1 << (idx & 7)):
                        o = k * rec + width
                        append(int.from_bytes(buf[o:o + 8], "little"))
                base += n
        if digest.hexdigest() != manifest["types"][t]["sha256"]:
            raise ScanError(f"{path}: content does not match the sha256 "
                            "the manifest recorded at prepare: corrupted "
                            "locks file")
        exposed[t] = sats
    return exposed, state, manifest


# The distribution maths live in diststats (shared with reveal_archive
# and curve_deltas). Here we only adapt the generic order-statistics
# bundle to this tool's satoshi-named schema, so the printed table and
# the reuse-stats-v1 JSON keep their field names.
def _stat_sat(asc):
    d = ds.order_stats(asc)
    return {
        "count": d["count"],
        "total_sat": d["total"],
        "mean_sat": d["mean"],
        "median_sat": d["median"],
        "p90_sat": d["p90"],
        "p99_sat": d["p99"],
        "max_sat": d["max"],
        "gini": d["gini"],
    }


# Population fractions for the Lorenz curve: the bottom p of locks by
# value, and the value they hold. Denser at the top, where the reuse of
# the big locks lives.
LORENZ_POP = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 0.999, 1.0]


def run_stats(locks_dir, checkpoint_dir, thresholds=(10, 100),
              top_n=(100, 1000), levels=None, json_out=None):
    """Read the exposed locks and report the shape of their value.

    Printed views — order statistics per type, a concentration table
    (value above each threshold, plus the top-1% share), the same read
    the other way (Lorenz headline shares and the value of the N largest
    locks), and a per-decade histogram (the treemap's data). With --json
    the same numbers are written out, pinned to the result's
    fingerprint, so a reader can check them against ours. Read-only and
    offline; on the full chain it streams ~50M locks once, a couple of
    minutes.
    """
    if levels is None:
        levels = STATS_LEVELS
    exposed, state, manifest = _load_exposed_sats(locks_dir, checkpoint_dir)

    # Sort once per type; ALL is the concatenation, sorted.
    seq = {t: sorted(exposed[t]) for t in TYPE_ORDER}
    seq["ALL"] = sorted(x for t in TYPE_ORDER for x in exposed[t])
    groups = TYPE_ORDER + ["ALL"]

    def btc(s):
        return s / SAT

    print(f"=== Exposed-lock value distribution "
          f"(snapshot {manifest['base_hash'][:16]}…, "
          f"height ≤ {state['last_height']:,}) ===")
    print(f"fingerprint: {state['fingerprint']}")
    print("a lock = one unique scriptPubKey with the total it guards "
          "(per address/script, NOT per entity)\n")

    # --- order statistics ---
    print(f"{'type':<6} {'locks':>10} {'BTC':>15} {'mean':>9} "
          f"{'median':>11} {'p90':>9} {'p99':>9} {'max':>13} {'Gini':>6}")
    od = {}
    for g in groups:
        d = _stat_sat(seq[g])
        od[g] = d
        print(f"{g:<6} {d['count']:>10,} {btc(d['total_sat']):>15,.2f} "
              f"{btc(d['mean_sat']):>9,.4f} {btc(d['median_sat']):>11,.6f} "
              f"{btc(d['p90_sat']):>9,.3f} {btc(d['p99_sat']):>9,.2f} "
              f"{btc(d['max_sat']):>13,.2f} {d['gini']:>6.3f}")

    # --- concentration: value above thresholds + top 1% ---
    print("\nconcentration (share of exposed VALUE, and how few locks "
          "carry it)")
    hdr = f"{'type':<6}"
    for thr in thresholds:
        lbl = _num(thr)
        hdr += f" {('≥'+lbl+' locks'):>15} {('≥'+lbl+' val%'):>10}"
    hdr += f" {'top1% val%':>11}"
    print(hdr)
    conc = {}
    for g in groups:
        d = od[g]
        tot = d["total_sat"] or 1
        row, cg = f"{g:<6}", {}
        for thr in thresholds:
            c, v = ds.tail_from(seq[g], int(round(thr * SAT)))
            cg[_num(thr)] = {"count": c, "value_sat": v}
            row += f" {c:>15,} {100 * v / tot:>10.2f}"
        tk, tv = ds.top_fraction(seq[g], 0.01)
        cg["top_0.01"] = {"count": tk, "value_sat": tv}
        row += f" {100 * tv / tot:>11.2f}"
        conc[g] = cg
        print(row)

    # --- the same read the other way: Lorenz shares + the N largest ---
    lz = {g: ds.lorenz(seq[g], LORENZ_POP) for g in groups}
    tn = {}
    for g in groups:
        tn[g] = {str(nc): dict(zip(("count", "value_sat"),
                                   ds.top_n(seq[g], nc))) for nc in top_n}
    # Headline shares for ALL: bottom-50%, and the top-10% / top-1% as the
    # complement of the Lorenz value at 90% / 99% of the population.
    lz_all = dict((round(p, 3), v) for p, v in lz["ALL"])
    tot_all_btc = od["ALL"]["total_sat"] or 1
    print("\nconcentration, another way (ALL exposed locks):")
    print(f"  bottom 50% hold {100 * lz_all.get(0.5, 0):.1f}% of value; "
          f"top 10% hold {100 * (1 - lz_all.get(0.9, 1)):.1f}%; "
          f"top 1% hold {100 * (1 - lz_all.get(0.99, 1)):.1f}%")
    for nc in top_n:
        c, v = ds.top_n(seq["ALL"], nc)
        print(f"  the {c:,} largest exposed locks hold {btc(v):,.2f} BTC "
              f"({100 * v / tot_all_btc:.1f}%)")

    # --- histogram / treemap levels ---
    print("\nvalue-level histogram (ALL types; exposed locks per BTC band "
          "— treemap data)")
    labels = _band_labels(levels)
    edges = [int(round(x * SAT)) for x in levels]
    hist = {g: ds.level_histogram(seq[g], edges) for g in groups}
    tot_all = od["ALL"]["total_sat"] or 1
    print(f"{'band (BTC)':<16} {'locks':>12} {'BTC':>15} {'val%':>7}")
    for lab, (cnt, val) in zip(labels, hist["ALL"]):
        print(f"{lab:<16} {cnt:>12,} {btc(val):>15,.2f} "
              f"{100 * val / tot_all:>7.1f}")

    if json_out:
        obj = {
            "format": "reuse-stats-v1",
            "base_hash": manifest["base_hash"],
            "last_height": state["last_height"],
            "fingerprint": state["fingerprint"],
            "note": "a lock = one unique scriptPubKey with its total; "
                    "lock != entity",
            "thresholds_btc": list(thresholds),
            "top_n_counts": list(top_n),
            "lorenz_pop": list(LORENZ_POP),
            "levels_btc": list(levels),
            "band_labels": labels,
            "types": {},
        }
        for g in groups:
            obj["types"]["all" if g == "ALL" else g] = {
                **od[g],
                "concentration": conc[g],
                "top_n": tn[g],
                "lorenz": lz[g],
                "histogram": [{"band": lab, "count": c, "value_sat": v}
                              for lab, (c, v) in zip(labels, hist[g])],
            }
        atomic_json(json_out, obj)
        print(f"\nstats written to {json_out}")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

RPC_AUTH_ENV = "NODSIG_RPC_AUTH"


def resolve_auth(cookie_file):
    """Return the `user:password` string for the node's RPC.

    The secret NEVER travels on the command line. A process's argv is
    readable by anyone on the machine (`ps`, `pgrep -af`,
    `/proc/<pid>/cmdline`) and it stays there for the whole length of a
    run that lasts days: an `--auth` flag once leaked a cookie exactly
    that way, which is why it no longer exists.

    Two ways are left, in order of preference:

    - `--cookie-file`: the secret is READ from the `.cookie` file that
      Bitcoin Core rewrites at every restart. It stays out of the argv
      and it is always the current one, with nothing to update by hand.
      This is the recommended path.
    - the ``NODSIG_RPC_AUTH`` environment variable, for a node
      configured with an explicit user and password instead of the
      cookie. A process's environment is less exposed than its argv,
      but it is not secret either: prefer the cookie when there is one.
    """
    if cookie_file:
        path = os.path.expanduser(cookie_file)
        try:
            content = open(path, encoding="utf-8").read().strip()
        except OSError as e:
            raise SystemExit(f"--cookie-file is not readable: {path}: {e}")
        if not content:
            raise SystemExit(f"--cookie-file is empty: {path}")
        return content
    env = os.environ.get(RPC_AUTH_ENV, "").strip()
    if env:
        return env
    raise SystemExit(
        f"this command needs --cookie-file (recommended) or the "
        f"{RPC_AUTH_ENV}=user:password environment variable. Credentials "
        f"are not accepted on the command line: they would end up in the "
        f"process argv, readable by anyone on the machine.")


def build_client(url, rest, cookie_file):
    """The block transport a scan will use, and the credential it took.

    Shared by both scanners so `--rest` means the same thing in each.
    The REST interface authenticates nobody, so this asks for no
    secret when it is chosen: the credential a run never resolves is
    the credential it cannot leak. The returned `auth` is None in that
    case, and the scanners carry it only to keep one signature.
    """
    if rest:
        return RestClient(url), None
    auth = resolve_auth(cookie_file)
    return RpcClient(url, auth), auth


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Count current coins behind already-opened locks "
                    "(reuse), by scanning block history against a "
                    "prepared UTXO lock set.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("prepare", help="distill the current locks from "
                        "a dumptxoutset snapshot")
    pp.add_argument("snapshot", help="file produced by dumptxoutset")
    pp.add_argument("--out", required=True, help="output directory")
    pp.add_argument("--chunk-records", type=int, default=8_000_000,
                    help="records per sorted run (memory knob)")

    ps = sub.add_parser("scan", help="run the history scan over RPC")
    ps.add_argument("--locks", required=True,
                    help="directory produced by prepare")
    ps.add_argument("--rpc", default="http://127.0.0.1:8332",
                    help="node address (default: %(default)s; a remote node "
                        "is reached through a local tunnel). Also the "
                        "address --rest uses: the node serves both on the "
                        "same port")
    ps.add_argument("--rest", action="store_true",
                    help="fetch the blocks over the node's binary REST "
                         "interface (needs bitcoind -rest=1) instead of "
                         "JSON-RPC: the blocks arrive verbatim rather than "
                         "as hex inside JSON, which is about half the bytes "
                         "on the wire, and this path needs no credential at "
                         "all. Recommended for a full scan; REST has no "
                         "batching, so pair it with --prefetch-depth")
    ps.add_argument("--cookie-file",
                    help="path to the node's .cookie file (e.g. "
                         "~/.bitcoin/.cookie): the secret is read from the "
                         "file, stays OUT of the argv and is always the "
                         "current one when the node rotates it. Without a "
                         "cookie: NODSIG_RPC_AUTH=user:password in the "
                         "environment.")
    ps.add_argument("--end", type=int, required=True,
                    help="last height to scan: the snapshot's height, "
                         "so the two sides of the comparison match")
    ps.add_argument("--checkpoint", required=True,
                    help="directory for state, bitmaps and the curve")
    ps.add_argument("--batch", type=int, default=25,
                    help="blocks per fetch window: one JSON-RPC batch, "
                         "or that many blocks asked for over REST")
    ps.add_argument("--checkpoint-every", type=int, default=10_000,
                    help="blocks between checkpoints")
    ps.add_argument("--no-faces", action="store_true",
                    help="narrow perimeter: a key burns only the exact "
                         "address form it was revealed in")
    ps.add_argument("--no-cosigners", action="store_true",
                    help="narrow perimeter: ignore keys revealed inside "
                         "redeem/witness scripts")
    ps.add_argument("--graph",
                    help="ALSO co-emit the raw transaction graph "
                         "(graph-v2) into this directory while "
                         "scanning — the blocks are fetched and parsed "
                         "anyway; off by default (~300-400 GB on the "
                         "full chain, see graphemit.py)")
    ps.add_argument("--graph-digest", metavar="GRAPH",
                    help="INSTEAD of --graph: serialize the same graph "
                         "records and hash them without writing them, "
                         "checking interval by interval that this code "
                         "still emits the bytes the graph archive in "
                         "this directory already holds. Costs no disk "
                         "and no extra pass; fingerprint that archive "
                         "first, since the check trusts the per-run "
                         "digests its state records")
    ps.add_argument("--headers",
                    help="ALSO co-emit the header archive (headers-v2) "
                         "into this directory: 88 B per block plus the "
                         "coinbase scripts, ~150 MB for the whole chain, "
                         "and the scan's integrity checks become "
                         "repeatable offline (see headers.py). A fresh "
                         "archive starts at genesis, so the scan fetches "
                         "height 0 for it")
    ps.add_argument("--no-prefetch", action="store_true",
                    help="fetch and parse strictly in series (the "
                         "prudent fallback; by default the next batch "
                         "downloads while this one is parsed)")
    ps.add_argument("--prefetch-depth", type=int, default=1,
                    help="batches in flight at once (default: "
                         "%(default)s, one ahead of the parser). Above 1 "
                         "means that many connections fetching at the "
                         "same time, which pays off over --rest, where "
                         "latency is per block; over JSON-RPC the batch "
                         "already amortizes it")

    pt = sub.add_parser("stats", help="distribution of value across the "
                        "exposed locks (median, concentration, treemap "
                        "levels) from a locks dir + a scan checkpoint; "
                        "read-only, offline, no rescan")
    pt.add_argument("--locks", required=True,
                    help="directory produced by prepare")
    pt.add_argument("--checkpoint", required=True,
                    help="scan checkpoint dir (hits bitmaps + state.json)")
    pt.add_argument("--thresholds", default="10,100",
                    help="comma-separated BTC thresholds for the "
                         "concentration table (default: 10,100)")
    pt.add_argument("--top-n", default="100,1000",
                    help="comma-separated lock counts for the "
                         "'N largest locks' shares (default: 100,1000)")
    pt.add_argument("--levels", default=None,
                    help="comma-separated BTC band edges for the "
                         "histogram/treemap (default: powers of ten "
                         "0.001…1000)")
    pt.add_argument("--json",
                    help="also write the numbers to this file "
                         "(reuse-stats-v1, pinned to the fingerprint)")

    args = p.parse_args(argv)
    try:
        if args.cmd == "prepare":
            run_prepare(args.snapshot, args.out, args.chunk_records)
        elif args.cmd == "stats":
            thr = tuple(float(x) for x in args.thresholds.split(",")
                        if x.strip())
            tn = tuple(int(x) for x in args.top_n.split(",") if x.strip())
            lv = ([float(x) for x in args.levels.split(",") if x.strip()]
                  if args.levels else None)
            run_stats(args.locks, args.checkpoint, thresholds=thr,
                      top_n=tn, levels=lv, json_out=args.json)
        else:
            client, auth = build_client(args.rpc, args.rest,
                                        args.cookie_file)
            run_scan(args.locks, args.rpc, auth, args.end,
                     args.checkpoint, batch_size=args.batch,
                     checkpoint_every=args.checkpoint_every,
                     faces=not args.no_faces,
                     cosigners=not args.no_cosigners,
                     client=client,
                     graph_dir=args.graph,
                     graph_digest_dir=args.graph_digest,
                     headers_dir=args.headers,
                     prefetch=not args.no_prefetch,
                     prefetch_depth=args.prefetch_depth)
    except (ScanError, ParseError, graphemit.GraphError,
            headers.HeaderError, census.CensusError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
