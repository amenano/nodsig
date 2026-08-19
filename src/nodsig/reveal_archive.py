#!/usr/bin/env python3
"""
reveal_archive.py — build the COMPLETE archive of every key and script
ever revealed in confirmed block history, and use it to cross-check
the reuse scan.

Why a second tool for the same question: reuse_scan.py answers "which
current locks were already opened?" with an inverted comparison — the
current locks stay in memory, history streams past, only the hits are
kept. It is fast and small, but its result is one bitmap, produced by
one pipeline. The project's rule for numbers that end up published is
the double method: two INDEPENDENT roads that must meet on the same
answer. This tool is the other road: it keeps EVERYTHING history
reveals (tens of GB on disk — disk is cheap, the scan is paid anyway),
and derives the hits afterwards, by reading the archive against the
lock files. If the two bitmaps do not match bit for bit, one of the
two pipelines is wrong: that is the cross-check of level 3, as the
19×3.125 delta was for levels 1-2.

What the independence covers, exactly, because a check that claims
more than it verifies is worse than none: the two EXTRACTION pipelines
are written separately and that is what the comparison tests. Both
roads then burn the same lock files through the same LockSet code, so
a broken locks directory would make them agree on garbage rather than
disagree. That shared input is guarded instead of assumed: the files
are verified against the sha256 their manifest recorded at prepare,
and `crosscheck --reuse-state` refuses a checkpoint made against a
different locks manifest.

The archive is not only a check. It is designed to REMAIN:

- it answers the full question of check_addresses.py ("was this lock's
  key ever revealed?") with a local lookup, no third-party index;
- it answers future questions without rescanning the chain;
- its on-disk format is APPENDABLE from day one — sorted runs plus a
  height watermark, fused periodically — so the one-shot scan of
  level 3 is already the seed of the incremental card index, not
  work to redo.

What one record means. The archive stores revelations, not conclusions.
Every record is `digest | byte | first_height u24`:

    keys       hash160 of every public-key-shaped item found in an
               unlocking context (scriptSig push, witness item, or a
               push inside a revealed script), 20 bytes. Its byte is
               the FLAGS below: where it was seen, and in which form;
    scripts20  hash160 of every candidate redeem script (the last
               scriptSig push, where P2SH keeps it), 20 bytes. Its
               byte COUNTS the pubkeys found inside that script;
    scripts32  sha256 of every candidate witness script (the last
               witness item, where P2WSH keeps it), 32 bytes. Same
               count.

FIRST_HEIGHT is the lowest height the digest was ever seen at, so the
archive answers WHEN a key became public and not only whether. It is
three bytes on every record, about 12% of the file, and it is the one
piece of this format that no later pass could recover: a digest says
nothing about its own date, and the graph deliberately keeps no
unlocking data to re-derive it from. It also turns "what appeared
since height H" from an impossible question into a filter.

The key count on a script is free: the extraction has just walked
that script looking for pubkeys, and the byte it fills was reserved
and always zero. It buys a census of multisig shapes over the whole
chain, from an archive that stores hashes and never scripts.

The flags byte on a key records WHERE it was seen (directly in a
scriptSig, directly in a witness, or inside a revealed script, the
cosigner case), with the bits of every sighting OR-ed together, and in
one more bit WHICH FORM the key was serialized in. The form is not a
place: it is a property of the key itself, constant across sightings
because the two serializations hash to different digests, which is why
OR leaves it alone. This
is what lets the perimeter be chosen at READ time: the same archive
reproduces the full perimeter and the narrow readings of reuse_scan's
--no-faces / --no-cosigners, so the cross-check is exact for every
flag combination. Over-collection is as harmless here as it is there:
a stored hash can only match a lock if it is that lock's exact
preimage, so junk records cost bytes, never correctness.

Subcommands:

    scan        the long run: fetch raw blocks from the node (batched
                JSON-RPC, or the binary REST interface with `--rest`,
                which halves the bytes on the wire), verify integrity
                (header hash, prev link, Merkle, witness commitment),
                extract revelations, flush them as sorted deduplicated
                runs, checkpoint and resume.
    merge       fuse all runs (and the previous merged files) into
                one sorted deduplicated file per category, and write
                the manifest with the archive's canonical fingerprint.
                This is the periodic fusion of the card index.
    crosscheck  derive the burnt-locks bitmaps from the archive and
                the lock files of `reuse_scan.py prepare`, and print
                the fingerprint in reuse_scan's exact format — or
                compare it directly against a reuse_scan state file.
    verify      re-read a sealed archive against its manifest: the
                bytes, the ladders rebuilt from the files they index,
                the fingerprint, and with --deep every record.
    derive      the reuse table and curve as a READ of the archive,
                without a second pass over the chain.
    lookup      is this 20/32-byte digest in the archive? The seed of
                check_addresses.py's complete answer.
    v1-digests  one sha256 per category over the records projected to
                the published v1 layout, which is what confronts this
                code with the historical artifact.

Everything is standard library; the node is only asked for public
chain data, read-only, over either of its interfaces. No addresses of
ours anywhere: the archive holds hashes of PUBLIC chain data only.
"""

import argparse
import hashlib
import heapq
import json
import os
import sys
import time
from array import array

from nodsig import blockparse
from nodsig.artifact import (WallClock, make_identity, producer,
                             seal_manifest, verify_sealed)
from nodsig.blockparse import ParseError, script_pushes, scriptsig_pushes

# Slab I/O for the fixed-width record files (runs, merged archive): the
# read/write budget, the sha-verifying reader, atomic writes — shared with
# the outpoint index, one implementation of the mechanics for both.
from nodsig.recio import (IO_CHUNK, atomic_json, budgeted_slab, checked_name,
                          read_fixed)

# The ladder-backed search over the merged files: same primitive the index
# uses, so a lookup is one bucket read, not a blind on-disk binary search.
from nodsig.recsort import SortedFile

# The graph co-emission plug (--graph), same contract as in
# reuse_scan.py: either long pass can host it, since both fetch and
# verify every block anyway.
from nodsig import graphemit

# The header co-emission plug (--headers): the same contract again, and
# the same reason — the checks this scan performs on every block are
# worth keeping, and 88 bytes a block keeps them.
from nodsig import headers

# The nonce census (--nonces): the third plug, and the only one fed from
# what this scan has already parsed instead of from the block. Every
# signature publishes the x-coordinate of its nonce point, a repeated one
# is a key waiting to be recovered, and no artifact we keep holds the
# unlocking data to re-derive it later.
from nodsig import nonces

# Shared primitives come from the sibling tools ON PURPOSE: one
# implementation of each in the project, so the node transports (both
# of them), the credential rules and the hash helpers come from
# reuse_scan and the parser from blockparse. What is NOT shared is the
# pipeline: the per-input walk, the storage, and the matching are
# written here again, because they are what the cross-check is meant to
# check.
from nodsig.reuse_scan import (LOCK_TYPES, TYPE_ORDER, SAT, BlockFetcher, LockSet,
                        RpcClient, ScanError, _fingerprint, build_client,
                        fingerprint_of_bitmaps, hash160, looks_like_pubkey,
                        warn_if_slow_ripemd160,
                        _load_manifest as _load_locks_manifest)

STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
FORMAT_TAG = "reveal-archive-v2"
RUNS_DIR = "runs"

# Provenance bits of a key sighting. "Direct" = pushed as itself in
# the unlocking data; "inner" = found inside a revealed candidate
# script (a multisig cosigner whose script just went public).
FLAG_SIG = 1          # direct, in a scriptSig
FLAG_WIT = 2          # direct, in a witness
FLAG_INNER_SIG = 4    # inside the last scriptSig push (redeem script)
FLAG_INNER_WIT = 8    # inside the last witness item (witness script)
# Form bit, not provenance: the key's serialized form was the 65-byte
# uncompressed one. The form is a function of the digest's preimage
# (hash160 of the 33-byte string and of the 65-byte one are different
# digests), so every sighting of one digest agrees on this bit and the
# OR merge cannot change it: append == rebuild is untouched. It rides
# a bit that was idle, on information the extraction already holds
# (the length test in looks_like_pubkey) and that the archive cannot
# recover later, because it stores the hash and never the key.
FLAG_UNCOMPRESSED = 16
# The four bits the published v1 archive defined: what the v1
# projection (run_v1_digests) masks a keys byte down to.
V1_KEY_FLAGS = FLAG_SIG | FLAG_WIT | FLAG_INNER_SIG | FLAG_INNER_WIT
FLAGS_DEFINED = V1_KEY_FLAGS | FLAG_UNCOMPRESSED

# category → width of the stored digest. A record is
#
#     digest | byte | first_height u24 (big-endian)
#
# The BYTE means different things per category, which is why the
# reduction below is per category and not one rule for all:
#
#   keys       the FLAGS above (provenance, plus the form bit), a
#              bitfield: two sightings of one key are merged with OR;
#   scripts*   the NUMBER of pubkey-shaped pushes found inside that
#              script, saturating at 255. It is a function of the script
#              bytes, so every sighting of one script agrees; `max`
#              merges them and is a no-op that a test pins.
#
# FIRST_HEIGHT is the LOWEST height at which the digest was ever seen, so
# the merge takes `min`. Both `or` and `min` are associative and
# commutative, which is exactly what keeps the fusion order-independent
# and the append equal to a rebuild.
CATEGORIES = {"keys": 20, "scripts20": 20, "scripts32": 32}
CAT_ORDER = ["keys", "scripts20", "scripts32"]
HEIGHT_BYTES = 3            # 16.7M heights, ~318 years of chain
MAX_INNER_KEYS = 255


def rec_width(cat):
    """Bytes of one record of `cat`: 24, 24 and 36."""
    return CATEGORIES[cat] + 1 + HEIGHT_BYTES


def _reduce(cat, byte_a, height_a, byte_b, height_b):
    """Merge two sightings of the same digest."""
    byte = (byte_a | byte_b) if cat == "keys" else max(byte_a, byte_b)
    return byte, min(height_a, height_b)

# Every K-th key of a merged file is sampled into a `.lad` sidecar at merge
# time, so a lookup bisects the resident ladder and reads ONE bucket (here
# ~49-74 KB, 24-36 B per record) instead of ~35 seeks on a multi-GB file.
# The ladder is a cache: it is NOT part of the canonical fingerprint (which
# is over the merged files' bytes alone), so its step can change freely and
# an archive without one still answers, by a blind bisect.
ARCHIVE_LADDER_EVERY = 2048

# What `verify` needs to rebuild each ladder from the file it indexes:
# logical name → (record width, key length, step). The same triple the
# merge sampled by, declared once so the seal and the audit cannot drift
# apart and raise a false alarm at each other.
ARCHIVE_LADDERS = {cat: (rec_width(cat), CATEGORIES[cat],
                         ARCHIVE_LADDER_EVERY)
                   for cat in CAT_ORDER}


# ---------------------------------------------------------------------------
# Extraction: one input → its revelations, with provenance
# ---------------------------------------------------------------------------

# One scriptSig parse per input, shared with every other walk: see
# blockparse.scriptsig_pushes, imported above, for why it is one function.


def extract_revelations(tx_in, stats, sig_pushes=None):
    """Everything one input reveals, as (category, digest, flags).

    The walk mirrors the shapes of the standard spends (and is the
    same over-collecting strategy as reuse_scan's, restated here
    independently): every pubkey-shaped push or witness item is a
    revealed key; the LAST scriptSig push is a candidate redeem
    script and the LAST witness item a candidate witness script;
    pubkey-shaped pushes inside those candidates are revealed keys
    too, tagged as inner. Malformed scripts are counted and skipped,
    never guessed at.

    `sig_pushes` lets the caller pass the scriptSig pushes it has
    already parsed (see `scriptsig_pushes`). Passing them must not
    change the answer, only the cost.
    """
    out = []

    if sig_pushes is None:
        sig_pushes = scriptsig_pushes(tx_in, stats)

    for p in sig_pushes:
        if looks_like_pubkey(p):
            out.append(("keys", hash160(p), _key_flags(p, FLAG_SIG)))
    for item in tx_in.witness:
        if looks_like_pubkey(item):
            out.append(("keys", hash160(item), _key_flags(item, FLAG_WIT)))

    # (candidate script, category of its hash, inner-key flag)
    candidates = []
    if sig_pushes:
        candidates.append((sig_pushes[-1], "scripts20", FLAG_INNER_SIG))
    if tx_in.witness:
        candidates.append((tx_in.witness[-1], "scripts32", FLAG_INNER_WIT))

    for script, cat, inner_flag in candidates:
        try:
            inner = script_pushes(script)
        except ParseError:
            stats["malformed_inner_script"] += 1
            inner = []
        keys = [p for p in inner if looks_like_pubkey(p)]
        # The script's own record carries HOW MANY keys were found inside
        # it, in the byte that used to be reserved and zero. The count is
        # already in hand here and costs nothing to keep; recovering it
        # later would mean another pass over the chain, because the
        # archive stores the script's hash and never the script.
        n = min(len(keys), MAX_INNER_KEYS)
        if cat == "scripts20":
            out.append((cat, hash160(script), n))
        else:
            out.append((cat, hashlib.sha256(script).digest(), n))
        for p in keys:
            out.append(("keys", hash160(p), _key_flags(p, inner_flag)))
    return out


def _key_flags(pubkey, provenance):
    """The record byte of one key sighting: the provenance bit the
    caller found it under, plus the form bit when the key came in the
    65-byte uncompressed serialization."""
    return provenance | (FLAG_UNCOMPRESSED if len(pubkey) == 65 else 0)


# ---------------------------------------------------------------------------
# The on-disk format: sorted runs, fused periodically
# ---------------------------------------------------------------------------
# A run is an immutable file of fixed-width records [digest | flags],
# sorted by digest, deduplicated within itself (flags OR-ed). The
# archive at any moment is the union of the merged files and the runs
# written since the last fusion; because deduplication is an OR of
# bits, fusion is associative and the result does not depend on when
# it happens — which is exactly what makes the format appendable: new
# blocks only ever ADD runs on top.


def _write_run(path, cat, records):
    """Sort, dedupe and write one run. Returns (records written,
    sha256). Atomic: tmp file + rename, so a crash never leaves a
    half-run behind under the final name. Rows leave in slabs (see
    IO_CHUNK): same bytes, same sha256, fewer calls."""
    records.sort()
    digest = hashlib.sha256()
    written = 0
    buf = bytearray()
    tmp = path + ".tmp"

    def emit(h, fl, ht):
        nonlocal written
        buf.extend(h)
        buf.append(fl)
        buf.extend(ht.to_bytes(HEIGHT_BYTES, "big"))
        written += 1

    with open(tmp, "wb") as f:
        last = None
        for h, fl, ht in records:
            if last is not None and h == last[0]:
                last = (h,) + _reduce(cat, last[1], last[2], fl, ht)
                continue
            if last is not None:
                emit(*last)
                if len(buf) >= IO_CHUNK:
                    f.write(buf)
                    digest.update(buf)
                    buf.clear()
            last = (h, fl, ht)
        if last is not None:
            emit(*last)
        if buf:
            f.write(buf)
            digest.update(buf)
    os.replace(tmp, path)
    return written, digest.hexdigest()


def _read_records(path, cat, expect_sha=None, slab_bytes=IO_CHUNK,
                  digest_into=None):
    """Stream (digest, byte, first_height) from a run or merged file.
    The slab reading and sha verification are recio.read_fixed; this
    only splits each record into its three fields and raises the
    archive's own ScanError on corruption.

    `digest_into` is a hashlib object fed the raw records as they pass:
    a caller that must walk every byte anyway gets the file's sha256
    without a second read (see `_audit_records`)."""
    width = CATEGORIES[cat]
    for r in read_fixed(path, rec_width(cat), expect_sha=expect_sha,
                        slab_bytes=slab_bytes, error=ScanError):
        if digest_into is not None:
            digest_into.update(r)
        yield r[:width], r[width], int.from_bytes(r[width + 1:], "big")


def _merged_stream(sources, cat):
    """One deduplicated (digest, byte, first_height) stream out of many
    sorted sources: heapq.merge keeps the global order, so equal digests
    arrive adjacent and the reduction is a look-behind."""
    last = None
    for h, fl, ht in heapq.merge(*sources):
        if last is not None and h == last[0]:
            last = (h,) + _reduce(cat, last[1], last[2], fl, ht)
            continue
        if last is not None:
            yield last
        last = (h, fl, ht)
    if last is not None:
        yield last


def _load_state(archive_dir, required=True):
    path = os.path.join(archive_dir, STATE_NAME)
    if not os.path.exists(path):
        if required:
            raise ScanError(f"no {STATE_NAME} in {archive_dir}: "
                            "run `scan` first")
        return None
    with open(path) as f:
        state = json.load(f)
    if state.get("format") != FORMAT_TAG:
        raise ScanError("unknown archive state format")
    return state


def _load_manifest(archive_dir):
    path = os.path.join(archive_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        manifest = json.load(f)
    if manifest.get("format") != FORMAT_TAG:
        raise ScanError("unknown archive manifest format")
    return manifest


def _cat_file(manifest, cat):
    """The file name holding a merged category.

    Merged files carry a GENERATION because the fusion is crash-safe
    (see run_merge): the manifest names the file, it is not derived
    from the category. The name lives in `build` and the digest in
    `identity`, which is the split itself: a generation number is how
    this copy was made, a digest is what it holds.

    Checked on the way out: an archive is a thing people hand each
    other, so a manifest this process did not write is untrusted input
    and its names must stay inside the directory (recio.checked_name)."""
    return checked_name(manifest["build"]["files"][cat]["file"], ScanError)


def _run_path(archive_dir, name):
    """A pending run's path. The name comes from the state file, which
    is untrusted whenever this process did not write it, and these paths
    are both read and removed: see recio.checked_name."""
    return os.path.join(archive_dir, RUNS_DIR,
                        checked_name(name, ScanError, "run"))


def _cat_sha(manifest, cat):
    """The digest the identity records for a merged category."""
    for entry in manifest["identity"]["files"]:
        if entry["name"] == cat:
            return entry["sha256"]
    raise ScanError(f"the identity names no category {cat!r}")


def _sweep_unnamed(archive_dir, manifest, why):
    """What the manifest does not name does not exist: delete it.

    One rule, two moments. BEFORE a fusion it clears what a crashed
    fusion left — a generation written but never committed, a `.tmp`
    stub; the manifest still describes a whole, readable archive and
    the fusion simply runs again. AFTER a fusion it clears the
    generation the new manifest has just superseded. Both are the same
    question ("is this file named?"), so they are the same code."""
    named = set()
    if manifest is not None:
        named = ({_cat_file(manifest, c) for c in CAT_ORDER}
                 | {e["file"]
                    for e in manifest["build"]["caches"].values()})
    for name in sorted(os.listdir(archive_dir)):
        if not name.startswith("archive_"):
            continue
        if name.endswith(".tmp") or name not in named:
            os.remove(os.path.join(archive_dir, name))
            print(f"  removed {name} ({why})", file=sys.stderr)


def _archive_sources(archive_dir, cat, state, manifest):
    """All the sorted sources holding one category right now: the
    merged file (if a fusion happened) plus every run written since.
    Each is streamed with its recorded sha256 checked."""
    todo = []
    if manifest is not None:
        todo.append((os.path.join(archive_dir, _cat_file(manifest, cat)),
                     _cat_sha(manifest, cat)))
    for run in state["runs"]:
        if run["category"] == cat:
            todo.append((_run_path(archive_dir, run["name"]),
                         run["sha256"]))
    # All these sources feed one heapq.merge, so their read buffers must
    # share a memory budget — otherwise a fragmented archive (hundreds of
    # runs) blows past RAM before the merge yields anything.
    slab = budgeted_slab(len(todo))
    return [_read_records(path, cat, sha, slab) for path, sha in todo]


# ---------------------------------------------------------------------------
# scan — the long run
# ---------------------------------------------------------------------------

def run_scan(rpc_url, auth, end_height, archive_dir,
             batch_size=25, checkpoint_every=10_000,
             flush_records=8_000_000, client=None, graph_dir=None,
             headers_dir=None, nonces_dir=None, prefetch=True,
             prefetch_depth=1, graph_digest_dir=None):
    """Stream the chain and archive every revelation.

    The loop is the same discipline as reuse_scan's (and is written
    out again on purpose — it is part of what the cross-check checks):
    fetch a batch of raw blocks, refuse any byte that does not hash
    back to the block we asked for or does not link to its
    predecessor, extract, and checkpoint. The state file records the
    last height whose revelations are safely on disk; a rerun with
    the same arguments resumes from there. Runs that a crash left
    unrecorded are deleted on resume: what the state does not name
    does not exist.
    """
    warn_if_slow_ripemd160("this scan")
    client = client or RpcClient(rpc_url, auth)
    os.makedirs(os.path.join(archive_dir, RUNS_DIR), exist_ok=True)
    state_path = os.path.join(archive_dir, STATE_NAME)

    stats = {"transactions": 0, "inputs": 0,
             "malformed_scriptsig": 0, "malformed_inner_script": 0,
             "revelations": 0}
    runs = []                      # [{name, category, records, sha256}]
    start_height = 1               # the genesis coinbase reveals nothing
    prev_hash = None

    state = _load_state(archive_dir, required=False)
    # Built from the state so a resumed scan continues its own total.
    clock = WallClock("scan", state)
    if state is not None:
        stats.update(state["stats"])
        runs = state["runs"]
        start_height = state["last_height"] + 1
        prev_hash = bytes.fromhex(state["last_block_hash"])[::-1]
        known = {r["name"] for r in runs}
        for name in os.listdir(os.path.join(archive_dir, RUNS_DIR)):
            if name not in known:
                os.remove(os.path.join(archive_dir, RUNS_DIR, name))
                print(f"  removed stale run {name} (not named by the "
                      "state)", file=sys.stderr)
        print(f"resuming from height {start_height}", file=sys.stderr)

    # Graph co-emission (OFF by default), same contract as in
    # reuse_scan.py: load() lines the graph archive up with this
    # scan's resume point, or refuses.
    #
    # --graph-digest is the same plug measuring instead of writing: it
    # checks that this code still emits the graph a reference archive
    # already holds, without spending the disk to prove it. The two are
    # answers to one question, so asking both is a mistake worth naming.
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
        emitter = graphemit.GraphDigest(graph_digest_dir, archive_dir)
        emitter.load(start_height)

    # The header archive (--headers), the one plug that can move this
    # scan's starting point: a fresh archive begins at genesis, because
    # a chain of headers that starts at 1 cannot check its first link.
    # That block is fed to it and to nothing else.
    header_emitter = None
    feed_from = start_height
    if headers_dir:
        header_emitter = headers.HeaderEmitter(headers_dir)
        feed_from = header_emitter.load(start_height)

    # The nonce census (--nonces): the one plug that consumes what this
    # scan has ALREADY parsed rather than the block. It is fed per input,
    # with the scriptSig pushes handed over, so the chain's scriptSigs
    # are parsed once for both artifacts.
    nonce_emitter = None
    if nonces_dir:
        nonce_emitter = nonces.NonceEmitter(nonces_dir)
        nonce_emitter.load(start_height)

    if start_height > end_height:
        print(f"nothing to do: archive already covers height "
              f"{start_height - 1}", file=sys.stderr)
        return

    buffers = {cat: [] for cat in CAT_ORDER}
    buffered = 0
    seg_start = start_height       # first height the open buffers cover

    def flush(through_height):
        """Close the open buffers into runs named by the exact height
        interval they cover. Runs do NOT tile the chain: an interval
        with nothing to keep produces no run (empty buffers are
        skipped below while seg_start advances past them), so a gap
        between run names is legal and silent. Coverage is declared
        by the watermark at seal time, never deduced from the names;
        that is why a missing tile is invisible to merge and verify
        by design, not by luck."""
        nonlocal buffered, seg_start
        for cat in CAT_ORDER:
            if not buffers[cat]:
                continue
            name = (f"run_{seg_start:08d}-{through_height:08d}_"
                    f"{cat}.bin")
            path = os.path.join(archive_dir, RUNS_DIR, name)
            records, sha = _write_run(path, cat, buffers[cat])
            runs.append({"name": name, "category": cat,
                         "records": records, "sha256": sha})
            buffers[cat] = []
        buffered = 0
        seg_start = through_height + 1

    def checkpoint(height, block_hash_display):
        # The co-emitted artifacts first, on purpose: a crash between
        # the writes leaves them AHEAD, the one direction their load()
        # heals.
        if emitter:
            emitter.checkpoint(height, block_hash_display)
        if header_emitter:
            header_emitter.checkpoint(height, block_hash_display)
        if nonce_emitter:
            nonce_emitter.checkpoint(height, block_hash_display)
        flush(height)
        st = {
            "format": FORMAT_TAG,
            "last_height": height,
            "last_block_hash": block_hash_display,
            "stats": stats,
            "runs": runs,
        }
        # The pass's own seconds, accumulated across resumes because the
        # total lives in the state and the state is what survives a kill.
        # A run split over several sessions therefore reports what it
        # really cost, not what its last stretch cost; what is lost is
        # the stretch between this checkpoint and a kill, which makes the
        # number a FLOOR, and the contract says so.
        clock.stamp(st)
        atomic_json(state_path, st)

    started = time.monotonic()
    done_since_start = 0
    # Two rates on purpose. The stretch average restarts from zero at
    # every resume and, on a chain whose per-block cost only grows, an
    # average seeded by light blocks stays permanently above the true
    # pace: two stretches of different length printing one "blk/s" are
    # not comparable. The last checkpoint interval is what "now" means.
    mark_t, mark_done = started, 0
    fetcher = BlockFetcher(client, feed_from, end_height, batch_size,
                           prefetch=prefetch, depth=prefetch_depth)
    for window, hashes, raws in fetcher:
        for h, want, raw in zip(window, hashes, raws):
            # The hash BEFORE the parse: until these bytes are known to
            # be the block that was asked for, they are input from the
            # other end of a wire, and there is no reason to walk them
            # with a parser first. See blockparse.block_id.
            if blockparse.block_id(raw) != want:
                raise ScanError(f"height {h}: block bytes do not hash to "
                                "the requested block hash")
            block = blockparse.parse_block(raw)   # Merkle + witness commit
            if prev_hash is not None and block.header.prev_hash != prev_hash:
                raise ScanError(f"height {h}: prev_hash does not link to "
                                f"height {h - 1} (reorg? wrong node?)")
            prev_hash = block.header.hash
            if header_emitter:
                header_emitter.add_block(h, block)
            if h < start_height:
                # Genesis, fetched for the header chain's first link
                # only: its coinbase is unspendable and reveals nothing.
                continue
            if emitter:
                emitter.add_block(h, block)

            for tx in block.transactions:
                stats["transactions"] += 1
                if blockparse.is_coinbase(tx):
                    continue
                for tx_in in tx.inputs:
                    stats["inputs"] += 1
                    # Parsed once, walked twice: the scriptSig pushes are
                    # what both artifacts start from, and parsing them
                    # here is the whole saving of co-emission.
                    pushes = scriptsig_pushes(tx_in, stats)
                    for cat, digest, byte in extract_revelations(
                            tx_in, stats, pushes):
                        buffers[cat].append((digest, byte, h))
                        buffered += 1
                        stats["revelations"] += 1
                    if nonce_emitter:
                        nonce_emitter.add_input(h, tx_in, pushes)

        done_since_start += len(window)
        if buffered >= flush_records:
            flush(window[-1])
        if nonce_emitter:
            nonce_emitter.flush_if_full(window[-1])

        if (window[-1] % checkpoint_every < batch_size
                or window[-1] == end_height):
            checkpoint(window[-1], blockparse.hash_hex(prev_hash))
            now = time.monotonic()
            step = ((done_since_start - mark_done) / (now - mark_t)
                    if now > mark_t else 0.0)
            avg = (done_since_start / (now - started)
                   if now > started else 0.0)
            mark_t, mark_done = now, done_since_start
            # The ETA extrapolates at constant per-block cost, which on
            # this chain is optimistic by construction; the tag says so
            # rather than letting the number claim more than it checked.
            eta_h = ((end_height - window[-1]) / step / 3600
                     if step else 0)
            print(f"checkpoint @ {window[-1]:>7,}: "
                  f"{stats['revelations']:,} revelations in "
                  f"{len(runs)} runs "
                  f"| {step:.1f} blk/s now, {avg:.1f} avg, "
                  f"~{eta_h:.1f} h left (flat-cost extrapolation)",
                  file=sys.stderr)

    print(f"\narchive covers heights 1..{end_height} "
          f"({stats['revelations']:,} revelations, {len(runs)} runs; "
          f"malformed scriptSigs: {stats['malformed_scriptsig']}, "
          f"malformed inner scripts: {stats['malformed_inner_script']})")
    if graph_digest_dir:
        emitter.report()
    print("run `merge` to fuse the runs and fingerprint the archive.")


# ---------------------------------------------------------------------------
# merge — the periodic fusion
# ---------------------------------------------------------------------------

def run_merge(archive_dir):
    """Fuse the merged files and all runs into one sorted deduplicated
    file per category, then fingerprint the result.

    The fingerprint is the archive's canonical form: after a full
    fusion the archive at height H is one well-defined set of bytes,
    whatever the run boundaries were — an interrupted-and-resumed scan
    fuses to the SAME files as a one-shot scan. That is the
    determinism rule of the card index: the incremental state must
    equal a rebuild from zero, and this is where it is enforced and
    measured.

    WHY THE MERGED FILES CARRY A GENERATION
    =======================================
    The fusion writes generation N+1 beside generation N and commits
    the manifest only when all three categories are on disk; the old
    generation and the consumed runs are deleted after the state that
    stopped naming them. Overwriting `archive_keys.bin` in place, as
    this did before, left a window with no way out: a kill between the
    rename and the manifest write left the manifest describing bytes
    that no longer existed, and since every reader — merge included —
    verifies that sha256 before yielding a byte, the archive could not
    even be re-fused. Nothing about the FORMAT changes: the
    fingerprint is over the category names and the file digests, never
    over a file name, so a generation number cannot move it.
    """
    state = _load_state(archive_dir)
    manifest = _load_manifest(archive_dir)
    _sweep_unnamed(archive_dir, manifest, "not named by the manifest")
    if not state["runs"] and manifest is not None:
        print("nothing to fuse: no runs since the last merge.")
        return manifest["fingerprint"]

    generation = ((manifest["build"]["generation"] + 1)
                  if manifest else 1)
    # The clock reads what the archive's state already carries, so an
    # entry the scan left under `scan` rides into the manifest here
    # instead of being lost when the runs are consumed. Stamped at the
    # END of the fusion, below: a build dict is assembled before the
    # work it describes.
    clock = WallClock("merge", state)
    build = {"producer": producer(), "generation": generation,
             "files": {}, "caches": {}}
    digests = {}
    for cat in CAT_ORDER:
        sources = _archive_sources(archive_dir, cat, state, manifest)
        out_name = f"archive_{cat}_g{generation:04d}.bin"
        out_path = os.path.join(archive_dir, out_name)
        tmp = out_path + ".tmp"
        digest = hashlib.sha256()
        records = 0
        buf = bytearray()          # rows leave in slabs, see IO_CHUNK
        ladder = bytearray()       # every K-th key, sampled on the way
        with open(tmp, "wb") as f:
            for h, fl, ht in _merged_stream(sources, cat):
                if records % ARCHIVE_LADDER_EVERY == 0:
                    ladder += h
                buf += h
                buf.append(fl)
                buf += ht.to_bytes(HEIGHT_BYTES, "big")
                records += 1
                if len(buf) >= IO_CHUNK:
                    f.write(buf)
                    digest.update(buf)
                    buf.clear()
            if buf:
                f.write(buf)
                digest.update(buf)
        os.replace(tmp, out_path)
        build["files"][cat] = {"file": out_name, "records": records}
        digests[cat] = digest.hexdigest()

        # The ladder sidecar: written next to the file, recorded in the
        # manifest, and deliberately OUT of the fingerprint (it is a cache).
        lad_name = f"archive_{cat}_g{generation:04d}.lad"
        lad_path = os.path.join(archive_dir, lad_name)
        tmp_lad = lad_path + ".tmp"
        with open(tmp_lad, "wb") as f:
            f.write(ladder)
        os.replace(tmp_lad, lad_path)
        build["caches"][cat] = {
            "file": lad_name,
            "every": ARCHIVE_LADDER_EVERY,
            "sha256": hashlib.sha256(ladder).hexdigest()}
        print(f"{cat:<10} {records:>14,} records")

    # The identity: the three category digests in fixed order, plus the
    # coverage, which for THIS format is the field that matters most.
    # The records carry a first_height each, so `verify --deep` can hold
    # the watermark to a floor, but only a floor: a stretch of chain that
    # reveals nothing new leaves no record, and nothing in the bytes
    # contradicts a manifest claiming a taller watermark than the scan
    # reached, while every "not revealed up to H" would inherit the lie.
    # Inside the identity, the claim cannot move without moving the
    # fingerprint. Same chain + same height, same number on anyone's
    # machine: the archive's twin of muhash.
    identity = make_identity(FORMAT_TAG, 1, state["last_height"],
                             ((cat, digests[cat]) for cat in CAT_ORDER))
    build["seconds"] = clock.stamp(state)
    build["wall"] = clock.wall()
    new_manifest = seal_manifest(FORMAT_TAG, identity, build)

    # THE COMMIT POINT. Up to here the old generation is still the
    # archive and a crash costs nothing but the work; from here the new
    # one is, and what is deleted below is only what neither the
    # manifest nor the state names any more. Between the two writes a
    # reader sees the new base AND the runs it already contains, which
    # is harmless: fusion dedups by OR, so reading a record twice is
    # the same as reading it once.
    atomic_json(os.path.join(archive_dir, MANIFEST_NAME), new_manifest)
    # Checked BEFORE the state is rewritten, so a state naming a run
    # outside the archive is refused instead of removing it.
    consumed = [_run_path(archive_dir, run["name"]) for run in state["runs"]]
    state["runs"] = []
    atomic_json(os.path.join(archive_dir, STATE_NAME), state)
    for path in consumed:
        os.remove(path)
    _sweep_unnamed(archive_dir, new_manifest, "superseded generation")
    print(f"merged through height {state['last_height']:,}")
    print(f"fingerprint: {new_manifest['fingerprint']}")
    return new_manifest["fingerprint"]


# ---------------------------------------------------------------------------
# verify — the audit of a sealed archive
# ---------------------------------------------------------------------------

def _audit_records(archive_dir, manifest):
    """Read every record of every merged category and check what the
    bytes alone cannot say. Returns (highest first_height, prepared),
    where `prepared` is name → (sha256, ladder) for the files this pass
    streamed — the digest and the ladder samples come free with the
    bytes, and handing them to `verify_sealed` is what keeps the deep
    audit to ONE read of the archive instead of two.

    The digests prove the files did not rot; they say nothing about
    whether the fusion did its job, because a wrongly built archive is
    sealed just as faithfully as a right one. What a pass over the
    records adds, per category:

    - **digests strictly ascending.** One statement covering both the
      order the search depends on and the deduplication the format
      promises: the fusion emits each digest exactly once, so equal
      adjacent digests are as wrong as inverted ones;
    - **the record count** the manifest's build block claims;
    - **the flags byte** of `keys` with no bit outside the five
      defined ones, since nothing else can set one;
    - **`first_height` within 1..watermark.** A record above the
      watermark would mean the archive holds a revelation the coverage
      claims not to cover, which is the one lie that would poison
      every "never revealed up to H".

    The cost is a full read of the archive (tens of GB at chain
    scale), which is why `verify` asks for it instead of assuming it.
    """
    watermark = manifest["identity"]["coverage"]["to"]
    highest = 0
    prepared = {}
    for cat in CAT_ORDER:
        name = _cat_file(manifest, cat)
        path = os.path.join(archive_dir, name)
        declared = manifest["build"]["files"][cat]["records"]
        previous = None
        records = 0
        top = 0
        rec_w, key_len, every = ARCHIVE_LADDERS[cat]
        digest_of_file = hashlib.sha256()
        ladder = bytearray()
        for digest, byte, height in _read_records(
                path, cat, _cat_sha(manifest, cat),
                digest_into=digest_of_file):
            if records % every == 0:
                ladder += digest[:key_len]
            if previous is not None and digest <= previous:
                where = "repeats" if digest == previous else "goes back to"
                raise ScanError(
                    f"{name}: record {records:,} {where} "
                    f"{digest.hex()}, after {previous.hex()}. A merged "
                    f"file is sorted and deduplicated by construction, so "
                    f"a search through it can stop above a digest that is "
                    f"in there and report it absent")
            if cat == "keys" and byte & ~FLAGS_DEFINED:
                raise ScanError(
                    f"{name}: record {records:,} ({digest.hex()}) carries "
                    f"flag bits {byte:#04x}, outside the five this "
                    f"format defines")
            if not 1 <= height <= watermark:
                raise ScanError(
                    f"{name}: record {records:,} ({digest.hex()}) was "
                    f"first seen at height {height:,}, outside the "
                    f"coverage 1..{watermark:,} this archive claims")
            previous = digest
            records += 1
            top = max(top, height)
        if records != declared:
            raise ScanError(f"{name}: {records:,} records on disk, "
                            f"{declared:,} in the manifest")
        # Same two rules `sha_and_ladder` applies, on bytes already
        # read: the digest of the whole file, and every `every`-th
        # record's key. The audit that follows checks the manifest
        # against these instead of streaming the file again.
        prepared[cat] = (digest_of_file.hexdigest(), bytes(ladder))
        highest = max(highest, top)
        if not records:
            print(f"ok  {name} is empty, as its manifest says")
            continue
        print(f"ok  {records:,} records in {name}, ordered and unique, "
              f"first seen up to height {top:,}")
    return highest, prepared


def run_verify(archive_dir, deep=False):
    """Re-read a sealed archive against its manifest.

    Without `--deep`: the three merged files against the digests in the
    identity, the three ladders rebuilt from the files they index, and
    the fingerprint recomputed from what is on disk. One read.

    With `--deep`: a pass over the records first (see `_audit_records`),
    whose highest `first_height` then confronts the declared coverage as
    a FLOOR. It can only be a floor: a stretch of chain revealing
    nothing new leaves no record, so the tail of the coverage is
    unprovable by construction. Said out loud either way, because an
    audit silent about what it did not check reads as one that checked
    everything.
    """
    manifest = _load_manifest(archive_dir)
    if manifest is None:
        raise ScanError(f"no {MANIFEST_NAME} in {archive_dir}: an archive "
                        "is sealed by `merge`, and only a sealed archive "
                        "has something to verify against")
    state = _load_state(archive_dir, required=False)
    floor, prepared = ((None, None) if not deep
                       else _audit_records(archive_dir, manifest))
    verify_sealed(
        archive_dir, manifest, FORMAT_TAG, ScanError,
        fp_order=CAT_ORDER,
        coverage_from_data=(None if floor is None
                            else lambda: ("floor", floor)),
        trust_hint="--deep",
        ladder_hint=" (rebuildable: re-run merge after deleting it)",
        ladders=ARCHIVE_LADDERS,
        # With --deep the record pass has just streamed every byte, so
        # the digests and ladders it produced stand in for a second
        # read of tens of GB. Without it, nothing is prepared and the
        # audit reads the files itself, exactly as before.
        prepared=prepared)

    # The fingerprint above covers the merged base. Runs written since
    # are part of every answer the archive gives and part of no
    # fingerprint at all, so a report that ended here would let a
    # queryable archive pass for a sealed one.
    if state and state["runs"]:
        covered = manifest["identity"]["coverage"]["to"]
        print(f"..  NOT SEALED at its watermark: {len(state['runs'])} run"
              f"{'s' if len(state['runs']) > 1 else ''} hold revelations "
              f"from heights {covered + 1:,}..{state['last_height']:,}, "
              f"which no fingerprint covers yet. Run `merge` to fuse them.")


# ---------------------------------------------------------------------------
# Applying the perimeter at read time (shared by crosscheck and derive)
# ---------------------------------------------------------------------------

def _apply_revelation(locks, cat, h, fl, faces, cosigners, height=None):
    """Burn into the lock sets what one archived record implies under
    the chosen perimeter, and say whether the record made the cut.

    `height` is the record's `first_height`, passed through to the
    LockSets only when a caller has asked them to remember it (see
    `LockSet.track_burn_heights`). Nothing else here depends on it: the
    burn rules are about provenance bits, not about when.

    The archive itself has no perimeter: it stores every sighting with
    its provenance bits. The mapping below restates reuse_scan's
    declared rules — a revealed key burns all its faces (both hash160
    forms plus the P2SH-wrapped one) under the full perimeter, or only
    the exact form it was seen in under --no-faces; inner (cosigner)
    sightings count only with cosigners on; candidate redeem and
    witness scripts burn their own hash always, that being the base
    criterion, not an extension. Burning is idempotent, so applying
    the same record twice (a digest sighted in many intervals) cannot
    inflate anything.
    """
    if cat == "keys":
        effective = fl & (FLAG_SIG | FLAG_WIT)
        if cosigners:
            effective |= fl & (FLAG_INNER_SIG | FLAG_INNER_WIT)
        if not effective:
            return False           # revealed only as a cosigner, excluded
        if faces:
            locks["p2pkh"].burn(h, height)
            locks["p2wpkh"].burn(h, height)
            locks["p2sh"].burn(hash160(b"\x00\x14" + h), height)
        else:
            # Narrow reading: the exact form only. Inner keys count as
            # the form of the script that revealed them, like
            # reuse_scan does: a redeem cosigner is a `1…` sighting,
            # a witness-script cosigner a `bc1q…` one.
            sig = fl & FLAG_SIG or (cosigners and fl & FLAG_INNER_SIG)
            wit = fl & FLAG_WIT or (cosigners and fl & FLAG_INNER_WIT)
            if sig:
                locks["p2pkh"].burn(h, height)
            if wit:
                locks["p2wpkh"].burn(h, height)
        return True
    if cat == "scripts20":
        locks["p2sh"].burn(h, height)
    else:
        locks["p2wsh"].burn(h, height)
    return True


def _load_locksets(locks_dir):
    """The four LockSets, verified against the locks manifest.

    Returns (locks, manifest). The verification is what keeps the
    cross-check honest: both roads burn the same locks files, so a
    corrupt file unchecked here would make the two fingerprints agree
    on garbage.
    """
    manifest = _load_locks_manifest(locks_dir)
    locks = {}
    for t in TYPE_ORDER:
        entry = manifest["types"][t]
        locks[t] = LockSet(os.path.join(locks_dir, f"locks_{t}.bin"),
                           LOCK_TYPES[t],
                           expect_records=entry["records"],
                           expect_sha=entry["sha256"])
    return locks, manifest


def _print_lock_table(locks, faces, cosigners, fp):
    print(f"{'type':<8} {'locks':>13} {'burnt':>12} {'burnt BTC':>20}")
    for t in TYPE_ORDER:
        ls = locks[t]
        print(f"{t:<8} {ls.count:>13,} {ls.hit_count:>12,} "
              f"{ls.hit_sats / SAT:>20,.8f}")
    total = sum(locks[t].hit_sats for t in TYPE_ORDER)
    print(f"{'TOTAL':<8} {'':>13} "
          f"{sum(locks[t].hit_count for t in TYPE_ORDER):>12,} "
          f"{total / SAT:>20,.8f}")
    print(f"perimeter: faces={'on' if faces else 'off'}, "
          f"cosigners={'on' if cosigners else 'off'}")
    print(f"fingerprint: {fp}")


# ---------------------------------------------------------------------------
# crosscheck — the cross-check
# ---------------------------------------------------------------------------

def run_crosscheck(archive_dir, locks_dir, faces=True, cosigners=True,
                   reuse_state_path=None):
    """Derive the burnt-locks bitmaps from the archive and compare
    them with reuse_scan's.

    The perimeter is applied HERE, at read time, from the provenance
    bits — the archive itself has no perimeter; the mapping is
    _apply_revelation, shared with `derive` so the two read-side
    views cannot drift apart.

    The fingerprint printed is byte-compatible with reuse_scan's
    (same bitmap definition over the same sorted lock files), so the
    two roads meet on one hex string. With --reuse-state, the meeting
    is checked right here and a mismatch is a hard failure: a cross-check
    that "almost passes" does not exist.

    What "independent" covers, honestly: the two EXTRACTION pipelines
    are written twice on purpose, but both roads share the locks files
    and the LockSet lookup code. That is why the load verifies the
    files against the manifest's shas, and why --reuse-state refuses a
    checkpoint made against different locks: without those guards the
    shared input could make both roads agree on garbage.
    """
    state = _load_state(archive_dir)
    manifest = _load_manifest(archive_dir)
    locks, locks_manifest = _load_locksets(locks_dir)

    keys_seen = 0
    for cat in CAT_ORDER:
        for h, fl, _ht in _merged_stream(
                _archive_sources(archive_dir, cat, state, manifest), cat):
            if (_apply_revelation(locks, cat, h, fl, faces, cosigners)
                    and cat == "keys"):
                keys_seen += 1

    fp = _fingerprint(locks)
    print(f"=== Cross-check from archive (heights 1..{state['last_height']:,}"
          f", {keys_seen:,} keys in perimeter) ===")
    _print_lock_table(locks, faces, cosigners, fp)

    if reuse_state_path:
        with open(reuse_state_path) as f:
            reuse_state = json.load(f)
        if reuse_state.get("locks_manifest") != locks_manifest["types"]:
            raise ScanError(
                "the scan's checkpoint was made against DIFFERENT locks "
                "files: the two roads must burn the same locks to be "
                "comparable")
        if reuse_state["last_height"] != state["last_height"]:
            raise ScanError(
                f"heights differ: archive at {state['last_height']}, "
                f"reuse scan at {reuse_state['last_height']} — the two "
                "roads must be compared at the SAME height")
        if reuse_state["fingerprint"] != fp:
            raise ScanError(
                "CHECK FAILED: the archive-derived bitmaps do "
                f"not match the scan's\n  scan:    "
                f"{reuse_state['fingerprint']}\n  archive: {fp}\n"
                "one of the two pipelines is wrong — do not publish "
                "either number")
        print("CHECK PASSED: the two independent roads meet "
              "on the same fingerprint.")
    return fp


# ---------------------------------------------------------------------------
# v1-digests — the archive projected back to the published v1 form
# ---------------------------------------------------------------------------

def run_v1_digests(archive_dir):
    """One sha256 per category, over the records projected to the v1
    layout: `digest | byte` with no height, the keys byte masked to
    the four provenance bits v1 defined, the scripts byte zeroed (it
    was reserved then).

    This is the check that ties the new code to the historical
    artifact: an archive rebuilt from the chain by THIS code, projected
    here, must reproduce the per-category digests the sealed v1 archive
    published. Same chain, same digests, with everything the format
    gained since (the height, the inner-key count, the form bit) taken
    out of the comparison by construction. The masks are pinned by a
    test: widening a flag without teaching this projection would break
    the confrontation, and the test says so before the chain does.

    Defined on the FUSED base only. A pending run would make the
    digests describe neither the v1 artifact nor this archive, so the
    presence of any is a refusal, not a warning.

    Returns {category: hex digest}, and prints them.
    """
    state = _load_state(archive_dir)
    manifest = _load_manifest(archive_dir)
    if manifest is None:
        raise ScanError("no manifest: run `archive merge` first, the "
                        "v1 projection is defined on the fused base")
    if state["runs"]:
        raise ScanError(f"{len(state['runs'])} unfused runs beyond the "
                        "fused base: run `archive merge` first")
    print(f"=== v1 projection "
          f"(heights 1..{state['last_height']:,}) ===")
    out = {}
    for cat in CAT_ORDER:
        mask = V1_KEY_FLAGS if cat == "keys" else 0
        digest = hashlib.sha256()
        buf = bytearray()
        n = 0
        path = os.path.join(archive_dir, _cat_file(manifest, cat))
        for h, byte, _ht in _read_records(path, cat,
                                          expect_sha=_cat_sha(manifest,
                                                              cat)):
            buf += h
            buf.append(byte & mask)
            n += 1
            if len(buf) >= IO_CHUNK:
                digest.update(buf)
                buf.clear()
        digest.update(buf)
        out[cat] = digest.hexdigest()
        print(f"{cat:<10} {n:>13,} records  {out[cat]}")
    print("confront these with the per-category digests the sealed v1 "
          "archive recorded")
    return out


# ---------------------------------------------------------------------------
# derive — the reuse count and curve as a READ of the archive
# ---------------------------------------------------------------------------

def _tiles(state):
    """The archive's runs grouped by the exact height interval they
    cover, in chain order. Run names carry their interval
    (`run_START-END_category.bin`), and the intervals tile the chain:
    that tiling is what makes the curve derivable — each tile is
    'every revelation of blocks START..END', so burning tiles in
    order replays the scan's cumulative state at every boundary."""
    groups = {}
    for run in state["runs"]:
        interval = run["name"].split("_")[1]
        start, end = (int(x) for x in interval.split("-"))
        groups.setdefault((start, end), []).append(run)
    tiles = sorted(groups.items())
    prev_end = None
    for (start, end), _ in tiles:
        if prev_end is not None and start != prev_end + 1:
            raise ScanError(f"runs do not tile the chain: gap or overlap "
                            f"at {prev_end}..{start}")
        prev_end = end
    return tiles


def _coverage_to(state, manifest):
    """The last height the archive speaks for. The manifest is the
    authority once a merge has sealed one; before that, the state."""
    if manifest is not None:
        return manifest["identity"]["coverage"]["to"]
    return state["last_height"]


def _grid(every, coverage_to):
    """The heights a curve carries rows for: the multiples of `every`
    inside the coverage, and the coverage's own last height, which is
    the one row that is always worth having and rarely a multiple."""
    if every < 1:
        raise ScanError("the curve grid must be at least 1 block wide")
    points = list(range(every, coverage_to + 1, every))
    if not points or points[-1] != coverage_to:
        points.append(coverage_to)
    return points


def _write_curve(locks, curve_path, every, coverage_to):
    """Replay the burns in height order and write one row per grid
    point: cumulative counts, satoshis, and the bitmap fingerprint the
    state had exactly there.

    Replayed on fresh bitmaps rather than sampled during the read: the
    archive arrives in digest order, so at no moment during the pass do
    the LockSets hold the state of any particular height. Cost is small
    and bounded by the BURNT locks, not by the records: a few million
    entries sorted once, and a bitmap rehashed per row.
    """
    events = {}
    for t in TYPE_ORDER:
        ls = locks[t]
        if ls.burn_height is None:
            raise ScanError("curve asked for without tracking the heights "
                            "(track_burn_heights was not called)")
        # height in the high bits, lock index in the low ones: one
        # sort over a plain integer array puts the burns in chain
        # order without materialising a tuple per lock.
        packed = array("Q", (h << 32 | i
                             for i, h in enumerate(ls.burn_height)
                             if h != 0xFFFFFFFF))
        packed = array("Q", sorted(packed))
        events[t] = packed

    bitmaps = {t: bytearray(len(locks[t].hits)) for t in TYPE_ORDER}
    counts = {t: 0 for t in TYPE_ORDER}
    sats = {t: 0 for t in TYPE_ORDER}
    pos = {t: 0 for t in TYPE_ORDER}

    tmp = curve_path + ".tmp"
    rows = 0
    with open(tmp, "w") as f:
        f.write("height," + ",".join(
            f"{t}_hits,{t}_satoshis" for t in TYPE_ORDER) + ",fingerprint\n")
        for point in _grid(every, coverage_to):
            for t in TYPE_ORDER:
                ev, p = events[t], pos[t]
                while p < len(ev) and (ev[p] >> 32) <= point:
                    i = ev[p] & 0xFFFFFFFF
                    bitmaps[t][i >> 3] |= 1 << (i & 7)
                    counts[t] += 1
                    sats[t] += locks[t].sats[i]
                    p += 1
                pos[t] = p
            f.write(f"{point},"
                    + ",".join(f"{counts[t]},{sats[t]}" for t in TYPE_ORDER)
                    + f",{fingerprint_of_bitmaps(bitmaps)}\n")
            rows += 1
    os.replace(tmp, curve_path)
    print(f"curve: {rows} rows on the {every:,} grid → {curve_path}",
          file=sys.stderr)


def run_archive_curve(archive_dir, out_path, every=10_000):
    """When the chain first revealed each thing, by window of heights.

    The archive's own curve, and the one artefact here that needs
    NOTHING else: no locks, no UTXO snapshot, no node. That is the
    reason it is its own verb rather than a column on `derive` — the
    reuse curve has to join a lock set that comes from a snapshot, and
    hanging this on the same command would make "how much was revealed,
    and when" depend on a snapshot it has no use for.

    It has no perimeter either, for the same reason the archive has
    none: the perimeter is a reading of the provenance bits, and this
    counts records, not readings.

    One row per window: the digests whose FIRST revelation falls in
    `height - every + 1 .. height`. First, not every sighting: a digest
    seen again at a later height was already revealed, and the fused
    archive keeps the earliest height precisely so this question has an
    exact answer. The stream is deduplicated, so the count is the same
    whether the archive has been merged or is still in runs.
    """
    state = _load_state(archive_dir)
    manifest = _load_manifest(archive_dir)
    coverage_to = _coverage_to(state, manifest)
    points = _grid(every, coverage_to)
    last = len(points) - 1
    counts = {cat: [0] * len(points) for cat in CAT_ORDER}

    for cat in CAT_ORDER:
        col = counts[cat]
        for _h, _fl, ht in _merged_stream(
                _archive_sources(archive_dir, cat, state, manifest), cat):
            # The grid is regular, so the window is arithmetic rather
            # than a search: this runs once per record.
            i = (ht - 1) // every
            col[i if i < last else last] += 1

    tmp = out_path + ".tmp"
    with open(tmp, "w") as f:
        f.write("height," + ",".join(CAT_ORDER) + ",total\n")
        for n, point in enumerate(points):
            row = [counts[cat][n] for cat in CAT_ORDER]
            f.write(f"{point}," + ",".join(str(v) for v in row)
                    + f",{sum(row)}\n")
    os.replace(tmp, out_path)
    total = sum(sum(counts[cat]) for cat in CAT_ORDER)
    print(f"archive curve: {len(points)} windows of {every:,} blocks "
          f"through height {coverage_to:,}, {total:,} first revelations "
          f"→ {out_path}", file=sys.stderr)
    return total


def run_derive(archive_dir, locks_dir, faces=True, cosigners=True,
               curve_path=None, curve_every=10_000,
               allow_base_mismatch=False):
    """Derive from the archive everything the reuse scan measures:
    the final table AND the per-checkpoint curve, with a fingerprint
    per row.

    This is the read side of the single-pass pipeline: one scan
    archives the revelations (and can co-emit the graph); the reuse
    numbers are then a READ of the archive against any snapshot's
    locks — no second pass over the chain.

    The curve comes from the `first_height` each record carries, which
    is the height that burnt the lock. That makes it independent of the
    order the archive is read in and of how the scan buffered: it can
    be asked for on ANY grid, it reads the same on a fused base as on
    loose runs, and a third party gets the same rows. The rows are
    replayed, not sampled: the burns are collected with their heights,
    sorted, and the bitmap is rebuilt point by point, so each row's
    fingerprint is the one the state genuinely had at that height.

    It used to be sampled at run-tile boundaries instead, which put a
    grid meant to be chosen in the hands of the download batch size and
    the flush knob: on the published chain not one boundary landed on
    the 10,000 grid and the file came out with a single row.

    Same LockSet, same burn rules (_apply_revelation, shared with the
    cross-check), same fingerprint definition: on the same inputs the
    two roads cannot disagree by construction of this function — the
    cross-check stays `crosscheck --reuse-state`, which compares
    against an INDEPENDENT scan's state instead.
    """
    state = _load_state(archive_dir)
    manifest = _load_manifest(archive_dir)
    locks, locks_manifest = _load_locksets(locks_dir)
    # The table is defined by TWO heights: the archive's coverage and
    # the block the snapshot's locks were photographed at. The manifest
    # names that block by hash, and the archive checkpoints the hash at
    # its watermark, so the two can be confronted offline and exactly:
    # same hash, same block, same height. Deriving an archive against
    # locks from another block produces a table indistinguishable from
    # a right one, which is why a mismatch is a refusal and not a note.
    base_hash = locks_manifest["base_hash"]
    tip_hash = state["last_block_hash"]
    if base_hash != tip_hash and not allow_base_mismatch:
        raise ScanError(
            f"the locks were photographed at block {base_hash}, but "
            f"the archive covers through {tip_hash}: these are "
            "different moments of the chain, and the reuse table "
            "would silently mix them — pass --allow-base-mismatch "
            "only if crossing two moments is what you want")
    if curve_path:
        for t in TYPE_ORDER:
            locks[t].track_burn_heights()

    def apply_stream(cat, stream):
        n = 0
        for h, fl, ht in stream:
            if (_apply_revelation(locks, cat, h, fl, faces, cosigners, ht)
                    and cat == "keys"):
                n += 1
        return n

    keys_seen = 0
    if manifest is not None:
        for cat in CAT_ORDER:
            path = os.path.join(archive_dir, _cat_file(manifest, cat))
            keys_seen += apply_stream(cat, _read_records(
                path, cat, _cat_sha(manifest, cat)))

    for (start, end), runs in _tiles(state):
        for run in sorted(runs, key=lambda r: CAT_ORDER.index(r["category"])):
            path = _run_path(archive_dir, run["name"])
            keys_seen += apply_stream(run["category"], _read_records(
                path, run["category"], run["sha256"]))

    if curve_path:
        _write_curve(locks, curve_path, curve_every,
                     _coverage_to(state, manifest))

    fp = _fingerprint(locks)
    # "sightings", not "keys": tiles are read one by one, so a key
    # revealed in several intervals is counted at each sighting (the
    # burns stay idempotent; only this informational counter differs
    # from crosscheck's, which walks the deduplicated stream).
    aligned = ("the same block" if base_hash == tip_hash
               else "A DIFFERENT BLOCK, crossed on purpose")
    print(f"=== Derived from archive (heights 1..{state['last_height']:,}"
          f", {keys_seen:,} key sightings in perimeter) ===")
    print(f"    archive tip {tip_hash}")
    print(f"    locks base  {base_hash} ({aligned})")
    _print_lock_table(locks, faces, cosigners, fp)
    return fp


# ---------------------------------------------------------------------------
# lookup — the seed of check_addresses
# ---------------------------------------------------------------------------

def _bisect_file(path, cat, key):
    """Binary search for `key` in a sorted fixed-width record file,
    without loading it: seek arithmetic on record boundaries. Returns
    (byte, first_height), or None. This is what makes the archive usable
    as an index: one lookup costs ~35 seeks even on a 60 GB file."""
    width = CATEGORIES[cat]
    rec = rec_width(cat)
    size = os.path.getsize(path)
    if size % rec:
        raise ScanError(f"{path}: size {size} not a multiple of {rec}")
    with open(path, "rb") as f:
        lo, hi = 0, size // rec
        while lo < hi:
            mid = (lo + hi) // 2
            f.seek(mid * rec)
            row = f.read(rec)
            if row[:width] < key:
                lo = mid + 1
            elif row[:width] > key:
                hi = mid
            else:
                return row[width], int.from_bytes(row[width + 1:], "big")
    return None


def _open_merged(archive_dir, manifest, cat):
    """Open the merged file of `cat` as a ladder-backed SortedFile, the
    ladder loaded and verified ONCE. Returns None when the archive has no
    ladder for the category (a merge from before ladders existed) — the
    caller then falls back to the blind on-disk bisect. The reader is
    reusable across many keys, so a batch lookup pays the ladder load and
    its sha check a single time, like the outpoint index does."""
    cache = manifest["build"]["caches"].get(cat)
    if cache is None:
        return None
    path = os.path.join(archive_dir, _cat_file(manifest, cat))
    with open(os.path.join(archive_dir, cache["file"]), "rb") as f:
        blob = f.read()
    if hashlib.sha256(blob).hexdigest() != cache["sha256"]:
        raise ScanError(f"{cache['file']}: corrupted ladder")
    return SortedFile(path, rec_width(cat), CATEGORIES[cat],
                      manifest["build"]["files"][cat]["records"],
                      blob, cache["every"], error=ScanError)


def _merged_sighting(archive_dir, manifest, cat, key, reader):
    """(byte, first_height) for `key` in the merged file of `cat`, or
    None. Uses the resident-ladder `reader` (one bucket read) when there
    is one, else a blind on-disk bisect. Both roads return the same
    record: the ladder only decides WHERE to read."""
    if reader is None:
        path = os.path.join(archive_dir, _cat_file(manifest, cat))
        return _bisect_file(path, cat, key)
    width = CATEGORIES[cat]
    for rec in reader.scan(key):      # merged keys are unique: 0 or 1 match
        return rec[width], int.from_bytes(rec[width + 1:], "big")
    return None


def _lookup_merged(archive_dir, manifest, cat, key):
    """Single-key convenience: open the merged reader, query it, close it.
    `run_lookup` opens the reader once and reuses it across keys instead."""
    reader = _open_merged(archive_dir, manifest, cat)
    try:
        return _merged_sighting(archive_dir, manifest, cat, key, reader)
    finally:
        if reader is not None:
            reader.close()


def run_lookup(archive_dir, hex_digests):
    """Membership check of raw digests (hex, 20 or 32 bytes) against
    the archive. Deliberately low-level: it takes digests, not
    addresses — decoding addresses (and explaining what a hit means
    for each type) is check_addresses.py's job. Absence is reported
    for what it is: not revealed in confirmed blocks up to the
    watermark, within what a block scan can see.
    """
    state = _load_state(archive_dir)
    manifest = _load_manifest(archive_dir)
    print(f"archive covers heights 1..{state['last_height']:,}"
          + ("" if not state["runs"] else
             f" ({len(state['runs'])} unfused runs included)"))

    # One merged reader per category, opened lazily and reused across every
    # queried digest: the ladder is loaded and sha-checked once, not per key.
    readers = {}

    def reader_for(cat):
        if cat not in readers:
            readers[cat] = (None if manifest is None
                            else _open_merged(archive_dir, manifest, cat))
        return readers[cat]

    try:
        for hx in hex_digests:
            try:
                key = bytes.fromhex(hx)
            except ValueError:
                print(f"{hx}: not hex, skipped")
                continue
            cats = [c for c in CAT_ORDER if CATEGORIES[c] == len(key)]
            if not cats:
                print(f"{hx}: not a 20- or 32-byte digest, skipped")
                continue
            found = {}
            for cat in cats:
                hit = None
                if manifest is not None:
                    hit = _merged_sighting(archive_dir, manifest, cat,
                                           key, reader_for(cat))
                for run in state["runs"]:
                    if run["category"] != cat:
                        continue
                    got = _bisect_file(
                        _run_path(archive_dir, run["name"]), cat, key)
                    if got is not None:
                        hit = got if hit is None else (
                            _reduce(cat, hit[0], hit[1], got[0], got[1]))
                if hit is not None:
                    found[cat] = hit
            if not found:
                print(f"{hx}: NOT in the archive (never revealed on-chain "
                      "up to the watermark; off-chain exposure is invisible "
                      "here by declaration)")
                continue
            for cat, (fl, first_height) in sorted(found.items()):
                where = []
                if cat == "keys":
                    if fl & FLAG_SIG:
                        where.append("scriptSig")
                    if fl & FLAG_WIT:
                        where.append("witness")
                    if fl & FLAG_INNER_SIG:
                        where.append("inside a redeem script")
                    if fl & FLAG_INNER_WIT:
                        where.append("inside a witness script")
                    if fl & FLAG_UNCOMPRESSED:
                        where.append("uncompressed form")
                if cat != "keys" and fl:
                    where.append(f"{fl} key{'s' if fl > 1 else ''} inside")
                print(f"{hx}: REVEALED at height {first_height:,}, {cat}"
                      + (f" ({', '.join(where)})" if where else ""))
    finally:
        for r in readers.values():
            if r is not None:
                r.close()


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Archive every key/script revelation in block "
                    "history (appendable, fingerprinted) and "
                    "cross-check the reuse scan against it.")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="stream the chain into the archive")
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
                    help="path to the node's .cookie file (e.g. ~/.bitcoin/"
                         ".cookie): read from the file, stays out of the "
                         "argv and is always current. Without a cookie: "
                         "NODSIG_RPC_AUTH=user:password in the environment.")
    ps.add_argument("--end", type=int, required=True,
                    help="last height to archive (the snapshot's height, "
                         "so the cross-check compares like with like)")
    ps.add_argument("--archive", required=True, help="archive directory")
    ps.add_argument("--batch", type=int, default=25,
                    help="blocks per fetch window: one JSON-RPC batch, "
                         "or that many blocks asked for over REST")
    ps.add_argument("--checkpoint-every", type=int, default=10_000,
                    help="blocks between checkpoints")
    ps.add_argument("--flush-records", type=int, default=8_000_000,
                    help="buffered revelations before a run is flushed "
                         "(memory knob)")
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
    ps.add_argument("--nonces",
                    help="ALSO co-emit the nonce census (nonces-v3) into "
                         "this directory: one 16-byte record per "
                         "signature, ~55 GB for the whole chain, and the "
                         "repeated nonce points it sorts together are "
                         "keys recoverable from public data (see "
                         "nonces.py). Costs about +10%% of this scan's "
                         "per-input CPU, measured")
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

    pv = sub.add_parser("verify", help="re-read a sealed archive "
                                       "against its manifest (full audit)")
    pv.add_argument("--archive", required=True)
    pv.add_argument("--deep", action="store_true",
                    help="also read every record: order, uniqueness, the "
                         "record counts, the flag bits, and every "
                         "first-seen height inside the coverage, whose "
                         "highest value then confronts the declared "
                         "watermark as a floor. Costs a second read of "
                         "the archive; without it the coverage is taken "
                         "on trust and the report says so")

    pm = sub.add_parser("merge", help="fuse runs, fingerprint the archive")
    pm.add_argument("--archive", required=True)

    pc = sub.add_parser("crosscheck",
                        help="derive the burnt locks from the archive "
                             "and compare with reuse_scan")
    pc.add_argument("--archive", required=True)
    pc.add_argument("--locks", required=True,
                    help="directory produced by reuse_scan.py prepare")
    pc.add_argument("--reuse-state",
                    help="reuse_scan state.json to compare against "
                         "(the cross-check proper)")
    pc.add_argument("--no-faces", action="store_true",
                    help="narrow perimeter, must mirror the scan's flag")
    pc.add_argument("--no-cosigners", action="store_true",
                    help="narrow perimeter, must mirror the scan's flag")

    pd = sub.add_parser("derive",
                        help="derive the reuse table AND its curve from "
                             "the archive (the single-pass pipeline's "
                             "read side)")
    pd.add_argument("--archive", required=True)
    pd.add_argument("--locks", required=True,
                    help="directory produced by reuse_scan.py prepare")
    pd.add_argument("--curve",
                    help="write the reuse curve CSV here "
                         "(same columns as reuse_scan's curve.csv)")
    pd.add_argument("--curve-every", type=int, default=10_000,
                    help="height grid for curve rows")
    pd.add_argument("--allow-base-mismatch", action="store_true",
                    help="derive even when the locks' snapshot block "
                         "differs from the archive's tip: the table "
                         "then mixes two moments of the chain, which "
                         "is refused by default")

    pv = sub.add_parser("curve",
                        help="when the chain first revealed each thing, "
                             "by window of heights: the archive's own "
                             "curve, no locks and no snapshot needed")
    pv.add_argument("--archive", required=True)
    pv.add_argument("--out", required=True,
                    help="write the CSV here")
    pv.add_argument("--every", type=int, default=10_000,
                    help="width of each window, in blocks")
    pd.add_argument("--no-faces", action="store_true",
                    help="narrow perimeter, as in crosscheck")
    pd.add_argument("--no-cosigners", action="store_true",
                    help="narrow perimeter, as in crosscheck")

    pl = sub.add_parser("lookup", help="membership check of hex digests")
    pl.add_argument("--archive", required=True)
    pl.add_argument("digests", nargs="+",
                    help="hex digests, 20 bytes (hash160) or 32 (sha256)")

    p1 = sub.add_parser("v1-digests",
                        help="per-category sha256 of the records "
                             "projected to the v1 layout (no height, "
                             "v1 flag bits only): the confrontation "
                             "with a sealed v1 archive's digests")
    p1.add_argument("--archive", required=True)

    args = p.parse_args(argv)
    try:
        if args.cmd == "scan":
            client, auth = build_client(args.rpc, args.rest,
                                        args.cookie_file)
            run_scan(args.rpc, auth, args.end, args.archive,
                     batch_size=args.batch,
                     checkpoint_every=args.checkpoint_every,
                     flush_records=args.flush_records,
                     client=client,
                     graph_dir=args.graph,
                     graph_digest_dir=args.graph_digest,
                     headers_dir=args.headers,
                     nonces_dir=args.nonces,
                     prefetch=not args.no_prefetch,
                     prefetch_depth=args.prefetch_depth)
        elif args.cmd == "merge":
            run_merge(args.archive)
        elif args.cmd == "verify":
            run_verify(args.archive, deep=args.deep)
        elif args.cmd == "crosscheck":
            run_crosscheck(args.archive, args.locks,
                           faces=not args.no_faces,
                           cosigners=not args.no_cosigners,
                           reuse_state_path=args.reuse_state)
        elif args.cmd == "derive":
            run_derive(args.archive, args.locks,
                       faces=not args.no_faces,
                       cosigners=not args.no_cosigners,
                       curve_path=args.curve,
                       curve_every=args.curve_every,
                       allow_base_mismatch=args.allow_base_mismatch)
        elif args.cmd == "curve":
            run_archive_curve(args.archive, args.out, every=args.every)
        elif args.cmd == "v1-digests":
            run_v1_digests(args.archive)
        else:
            run_lookup(args.archive, args.digests)
    except (ScanError, ParseError, graphemit.GraphError,
            headers.HeaderError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
