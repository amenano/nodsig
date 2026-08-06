#!/usr/bin/env python3
"""
outpoint_index.py — the OUTPOINT INDEX: the one expensive derivative
that resolves any input reference (txid, vout) to the output it spends,
and with it unlocks the address history, the fees and the co-spend
questions — built from a graph-v2 archive in ONE pass.

Why build this from scratch instead of pointing an existing indexer at
the node: the ready-made indexes (Electrum-style servers) answer an
ONLINE query model — one scripthash, one list of txids, a server that
must stay up. Our questions are OFFLINE and analytical: streaming
joins over the whole chain, numbers that must be replicable byte for
byte by a stranger (the contract of replica), artifacts that live on a
NAS and are read by tools, not sockets. Optimizing for that model is
exactly why writing it ourselves is worth it: we get to choose the
coordinates.

THE DESIGN IN ONE IDEA: ORDINAL COORDINATES
===========================================
A naive outpoint index repeats the (txid, vout) key — 36 bytes — in
every record of every file: measured against the 2026 chain (~1.3G
transactions, ~3.5G inputs, ~3.7G outputs) that is ~500 GB for the
index plus its spend side. Instead, this format numbers the chain ONCE:

    tx ordinal      = position of the transaction in chain order
                      (block by block, tx by tx), starting at 0 with
                      the first transaction of block 1;
    output ordinal  = position of the output in chain order (block,
                      tx, vout), same origin.

Ordinals are dense, so a file whose records are IN ordinal order needs
no key at all: record i lives at byte offset i × width, and reading it
is one seek — no search. The order is the first index, taken to its
conclusion: here the order IS the address. Everything that can be
positional is positional; the only sorted (searchable) files are the
two that answer by-key questions. Every future
derivative that references an output spends 5 bytes on it, not 36 —
efficiency paid once, repaid every time a new question grafts on.

The genesis block is excluded, like in graph-v2 (its coinbase is
unspendable by consensus): ordinals start counting at block height 1.

FROZEN FORMAT — outpoint-index-v2
=================================
An index is a directory of fixed-width record files. ALL integers are
big-endian — the opposite of graph-v2, and on purpose: graph-v2 echoes
Bitcoin's little-endian serialization because its job is fidelity to
the block; this format's job is to BE sorted and searched, and with
big-endian fields the lexicographic byte order IS the numeric order,
so sorting, merging and binary search run on raw memcmp and never
decode a field. (That is also the honest answer to "use bit tricks":
the fastest bit-level comparison available to us is the one the C
runtime already does on aligned bytes. Sub-byte packing was evaluated
and rejected: <8% space for broken slab arithmetic; likewise varints:
they would break the fixed width that makes records addressable, and
txid truncation: a 2^64 birthday grind could forge a collision.)

Ordinals are 40-bit (5 bytes): the chain has ~3.7G outputs and grows
by ~0.2G/year, so 32 bits would overflow within a few years while 2^40
≈ 1.1e12 lasts generations. Output counts per tx are 24-bit (the
consensus block size caps them far below that).

Positional files (record i = ordinal i; no keys stored):

    blocks.bin        14 B/block: first_tx u40 | first_out u40 | time u32
                      (record 0 = height 1; ~13 MB, loaded to RAM)
    txids.bin         32 B/tx: the txid, serialized order
    tx_first_out.bin   5 B/tx: first output ordinal (strictly
                      increasing — every tx has ≥1 output — so it can
                      also be binary-searched by VALUE to answer
                      "which tx created output ordinal k?")
    outputs.bin       28 B/output: value u64 | lock hash160 20 B
                      (the lock fingerprint is hash160 of the FULL
                      scriptPubKey — "address" here means identical
                      lock, the honest boundary: not a wallet, not
                      a key under its other faces)

Sorted files (searchable by key, deduplicated where stated):

    txid_index.bin    40 B: txid 32 | first_out u40 | n_out u24,
                      sorted by txid — the RESOLVER: (txid, vout) →
                      output ordinal = first_out + vout, refusing
                      vout ≥ n_out loudly. A tx's own ordinal is NOT
                      stored: it is recoverable by binary-searching
                      tx_first_out.bin for first_out (stored once,
                      not repeated — the positional twin answers it).
    spends.bin        10 B: spent_out u40 | spender_tx u40, sorted —
                      the whole spend side of the graph in 10 bytes
                      per edge. Spend height = the spender's block
                      (blocks.bin); spender txid = txids.bin[spender].

Sidecar caches (deterministic, rebuilt with their file, NOT part of
the canonical fingerprint): for each searchable file a LADDER `.lad` —
every K-th key, sampled while the file is written. A lookup loads the
ladder once (a few tens of MB, RAM), bisects it in memory, and reads
ONE K-record bucket (~40 KB) from disk: on a network mount that is a
single round-trip where a blind on-disk binary search would pay ~35.
tx_first_out.bin gets the same treatment at seal time. This is the
whole cache story: small resident summaries, one targeted read,
sequential consumers use large shared-budget slabs (recio's).

Size, measured against the 2026 chain: blocks 13 MB + txids 42 GB +
tx_first_out 6.5 GB + txid_index 52 GB + outputs 104 GB + spends
35 GB ≈ 240 GB — half the naive keyed layout, with faster reads.

DUPLICATE TXIDS (BIP30) — the one dedup decision
================================================
Bitcoin's early history contains two duplicated coinbase txids (block
91842 repeats 91812's, 91880 repeats 91722's; BIP34 made this
impossible later). The duplicate OVERWROTE the earlier output in the
UTXO set, so the resolver keeps, for a duplicated txid, the LATEST
instance (highest first_out — exactly the record that sorts last, so
"keep the last of an equal-key run" implements consensus). The
positional files keep BOTH instances honestly: they existed. The
dropped-duplicate count is recorded and its expected value on the full
chain is exactly 2 — a built-in historical cross-check. Equal keys in
spends.bin (one output spent twice) cannot happen under consensus;
they are counted, kept, and expected to be 0.

BUILD = ONE GRAPH PASS + TWO SORTS, in five resumable phases
============================================================
    scan          read graph-v2 once (verified stream). The four
                  positional files are APPENDED in ordinal order —
                  born sorted, no sort needed. Resolver records and
                  raw spend records (prev_txid 32 | vout u32 |
                  spender u40 = 41 B) are buffered, sorted in memory,
                  and flushed as run files that tile the chain by
                  height — checkpoint/resume exactly like the scans.
    merge-txids   fuse resolver runs (and, on an append, the previous
                  txid_index) into the new txid_index + ladder.
    resolve       merge the raw spend runs (one stream sorted by
                  prevout) against txid_index (sorted by txid): a
                  streaming MERGE-JOIN — "sort in pieces, then fuse"
                  applied to the join, linear, no random access.
                  Rewrites each edge to 10 bytes; sorted 10-B runs out.
    merge-spends  fuse them (and any previous spends.bin) → spends.bin.
    seal          stream every file once more: sha256 each, check the
                  arithmetic invariants, write manifest.json with the
                  canonical fingerprint. Doubles as the integrity
                  audit, like graphemit's fingerprint pass.

`build` drives the phases from state.json and is safe to re-run: it
continues where it stopped (crash, Ctrl-C) and, called again after the
graph has grown, APPENDS — new blocks extend the positional files and
add runs, the merges fuse old + new: by construction (merging sorted
sources is associative) the appended index is byte-identical to a
rebuild from zero. Merged files carry a generation number in their
name (txid_index_g0001.bin): a fusion writes generation N+1, commits
it in the state, then deletes N — so no crash window can leave the
state describing bytes that were already replaced. What the state does
not name is deleted on load; the logical names (without generation)
are what the canonical fingerprint covers.

Canonical fingerprint: the shared identity recipe of artifact.py
(nodsig-identity-v3: the format tag, the coverage, then each logical
file name and its content sha256, in the fixed order). Same graph +
same end height ⇒ same fingerprint on anyone's machine — the index's
twin of the graph's and the archive's.

An input whose prevout is not in the resolver means a graph that does
not contain the whole history below the end height: with real chain
data that is corruption, and the join fails LOUDLY. --tolerate-
unresolved downgrades it to a counted statistic, for synthetic or
deliberately partial graphs — never for numbers meant to be published.

Subcommands:
    build    drive the five phases (resumable, appendable)
    rewind   back to a height already covered, into the same bytes a
             build that stopped there would have written
    stats    watermark, phase, per-file records and sizes (instant)
    verify   re-read everything against the manifest (full audit)
    lookup   the didactic window: TXID:VOUT → its whole story
             (created where, worth what, under which lock, spent by
             whom or still unspent)

Standard library only. graphemit is imported for its verified reader,
reuse_scan for hash160, reveal_archive for the shared slab budget —
one implementation of each in the project. The append-and-fuse
bookkeeping (sorted runs, merged generations, the crash-safe commit
order) is not this format's invention and does not live here: it is
genstore's, and this module is one of its two users.
"""

import argparse
import bisect
import hashlib
import heapq
import json
import os
import sys
import time
from array import array
from datetime import datetime, timezone

from nodsig import graphemit as ge
from nodsig.artifact import (WallClock, declared_parent,
                             identity_fingerprint, make_identity, producer,
                             seal_manifest, sha_and_ladder, verify_sealed)
from nodsig.hashing import hash160, warn_if_slow_ripemd160
from nodsig.genstore import GenStore, new_state_fields
from nodsig.recio import (IO_CHUNK, atomic_json, budgeted_slab, read_fixed,
                          sha_file)
from nodsig.recsort import SortedFile, bisect_blob
from nodsig.reuse_scan import SAT

FORMAT_TAG = "outpoint-index-v2"
STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
RUNS_DIR = "runs"

# Record widths, from the format above. ORD is the 40-bit ordinal.
ORD = 5
BLOCK_REC = ORD + ORD + 4            # blocks.bin
TXID_REC = 32                        # txids.bin
TFO_REC = ORD                        # tx_first_out.bin
OUT_REC = 8 + 20                     # outputs.bin
RESOLVER_REC = 32 + ORD + 3          # txid_index.bin (and its runs)
RAWSPEND_REC = 32 + 4 + ORD          # scan-phase spend runs
SPEND_REC = ORD + ORD                # spends.bin (and its sorted runs)

# Positional files: logical name → record width. Their bytes are
# defined by chain order alone, so they are append-only and never
# rewritten; their sha256 is computed at seal.
POSITIONAL = {"blocks": BLOCK_REC, "txids": TXID_REC,
              "tx_first_out": TFO_REC, "outputs": OUT_REC}

# Merged (searchable) files: logical name → (record width, key width,
# ladder sampling step). Key width is the sorted prefix a search
# compares; the step is chosen so one bucket is ~40 KB — one network
# round-trip on a NAS-mounted index.
MERGED = {"txid_index": (RESOLVER_REC, 32, 1024),
          "spends": (SPEND_REC, ORD, 4096)}

# tx_first_out is positional but ALSO binary-searched by value (output
# ordinal → its tx), so it gets a ladder too, sampled at seal. Its
# samples are whole records: the value searched IS the record.
TFO_LADDER_EVERY = 8192

# Every ladder this artifact carries, as the same triple: what `verify`
# needs to rebuild each one from the file it indexes instead of taking
# the seal's word for it.
LADDERS = dict(MERGED, tx_first_out=(TFO_REC, TFO_REC, TFO_LADDER_EVERY))

# The canonical fingerprint covers the logical data files in this
# fixed order. Ladders are caches: rebuilt with their file, excluded.
FP_ORDER = ("blocks", "txids", "tx_first_out", "txid_index",
            "outputs", "spends")

PHASES = ("scan", "merge-txids", "resolve", "merge-spends", "seal",
          "sealed")


class OutpointError(RuntimeError):
    """Corruption, a mismatch, or a join that cannot be trusted must
    stop the build — never leak into data that could be published."""


# ---------------------------------------------------------------------------
# Small shared pieces: fixed-record streaming, runs, ladders
# ---------------------------------------------------------------------------

def _read_fixed(path, rec, expect_sha=None, slab_bytes=IO_CHUNK,
                start_record=0):
    """Stream whole `rec`-byte records from a file (recio.read_fixed),
    raising the index's own OutpointError on a truncated file or a sha
    mismatch. Kept as a named wrapper so the many call sites read the same
    and the error type stays the index's."""
    yield from read_fixed(path, rec, expect_sha=expect_sha,
                          slab_bytes=slab_bytes, start_record=start_record,
                          error=OutpointError)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def _new_state():
    return {
        "format": FORMAT_TAG,
        "phase": "scan",
        "last_height": 0,          # watermark: heights fully scanned
        "last_block_hash": None,   # display hex, for resume alignment
        "n_tx": 0,                 # next tx ordinal
        "n_out": 0,                # next output ordinal
        "n_spends": 0,             # raw spend records emitted by scan
        "sizes": {name: 0 for name in POSITIONAL},   # committed bytes
        # runs / files / caches / generation: the store's four keys.
        **new_state_fields(),
        "totals": {"overwritten_txids": 0, "duplicate_spends": 0,
                   "unresolved_spends": 0},
    }


def _store(index_dir, state, clock=None):
    """This index's append-and-fuse store. The projections it fuses are
    MERGED (record width, key length, ladder step) — declared once at
    the top of this file, handed to the store at each fusion."""
    return GenStore(index_dir, state, label="index",
                    error=OutpointError, runs_dir=RUNS_DIR,
                    state_name=STATE_NAME, clock=clock)


def _load_state(index_dir, required=True):
    path = os.path.join(index_dir, STATE_NAME)
    if not os.path.exists(path):
        if required:
            raise OutpointError(f"no {STATE_NAME} in {index_dir}: "
                                "run `build` first")
        return None
    with open(path) as f:
        state = json.load(f)
    if state.get("format") != FORMAT_TAG:
        raise OutpointError("unknown index state format")
    return state


def _positional_path(index_dir, name):
    return os.path.join(index_dir, f"{name}.bin")


# The top-level inventory the orphan sweep must not touch: everything
# this format owns beside the merged generations and their ladders.
KEEP_TOP = (set(POSITIONAL) | {f"{n}.bin" for n in POSITIONAL}
            | {"tx_first_out.lad", STATE_NAME, MANIFEST_NAME, RUNS_DIR})


# ---------------------------------------------------------------------------
# Phase 1: scan — one pass over the graph
# ---------------------------------------------------------------------------

def _verify_resume_point(graph_dir, state):
    """The index must keep growing from the SAME chain: the graph's
    block at our watermark must be the block we checkpointed. One
    record is read back to prove it."""
    w = state["last_height"]
    if w == 0:
        return
    for rec in ge.iter_blocks(graph_dir, from_height=w, to_height=w):
        got = rec["hash"][::-1].hex()
        if got != state["last_block_hash"]:
            raise OutpointError(
                f"graph block at height {w} is {got}, but this index "
                f"was built through {state['last_block_hash']}: not the "
                "same chain — use a fresh directory")
        return
    raise OutpointError(f"graph does not contain height {w}, the "
                        "index watermark: wrong or truncated graph")


def _phase_scan(graph_dir, store, end_height, flush_records,
                checkpoint_every):
    index_dir, state = store.dir, store.state
    graph_state = ge._load_state(graph_dir)
    if end_height is None:
        end_height = graph_state["last_height"]
    if end_height > graph_state["last_height"]:
        raise OutpointError(
            f"--end {end_height} is past the graph's watermark "
            f"{graph_state['last_height']}")
    # Before anything else, including the no-op path: an index that has
    # nothing new to read still has to be reading the SAME chain, or
    # "nothing to do" would be a lie told about a different history.
    _verify_resume_point(graph_dir, state)
    start = state["last_height"] + 1
    if start > end_height:
        return end_height                    # nothing new to scan

    store.make_runs_dir()

    n_tx, n_out = state["n_tx"], state["n_out"]
    pos_buf = {name: bytearray() for name in POSITIONAL}
    resolver_buf = []
    spend_buf = []
    seg_start = start
    last_hash = None

    def flush_positional():
        # Safe at ANY moment, not only at checkpoints: bytes past the
        # state's committed sizes are truncated away on resume, so an
        # early flush risks nothing and keeps the buffers bounded (a
        # mainnet checkpoint interval alone would buffer ~1 GB).
        for name, buf in pos_buf.items():
            if buf:
                with open(_positional_path(index_dir, name), "ab") as f:
                    f.write(buf)
                state["sizes"][name] += len(buf)
                buf.clear()

    def flush_runs(through):
        nonlocal seg_start
        for cat, buf, in (("txids", resolver_buf),
                          ("rawspends", spend_buf)):
            if not buf:
                continue
            name = f"run_{seg_start:08d}-{through:08d}_{cat}.bin"
            store.write_run(name, cat, buf)
            buf.clear()
        seg_start = through + 1

    def checkpoint(height):
        # Order matters: runs and positional bytes reach the disk
        # BEFORE the state that names them; a crash in between leaves
        # extras that the next load truncates or deletes.
        flush_runs(height)
        flush_positional()
        state["last_height"] = height
        state["last_block_hash"] = last_hash
        state["n_tx"], state["n_out"] = n_tx, n_out
        store.write_state()

    started = time.monotonic()
    done = 0
    for rec in ge.iter_blocks(graph_dir, from_height=start,
                              to_height=end_height):
        h = rec["height"]
        last_hash = rec["hash"][::-1].hex()
        pos_buf["blocks"] += (n_tx.to_bytes(ORD, "big")
                              + n_out.to_bytes(ORD, "big")
                              + rec["time"].to_bytes(4, "big"))
        for tx in rec["txs"]:
            txid = tx["txid"]
            outs = tx["outputs"]
            if len(outs) >= 1 << 24:
                raise OutpointError(f"height {h}: a tx with "
                                    f"{len(outs)} outputs cannot be "
                                    "real — corrupt graph")
            first_out5 = n_out.to_bytes(ORD, "big")
            pos_buf["txids"] += txid
            pos_buf["tx_first_out"] += first_out5
            resolver_buf.append(txid + first_out5
                                + len(outs).to_bytes(3, "big"))
            for value, script in outs:
                pos_buf["outputs"] += (value.to_bytes(8, "big")
                                       + hash160(script))
            spender5 = n_tx.to_bytes(ORD, "big")
            for prev_txid, prev_vout in tx["inputs"]:
                spend_buf.append(prev_txid
                                 + prev_vout.to_bytes(4, "big")
                                 + spender5)
            n_tx += 1
            n_out += len(outs)
        state["n_spends"] += sum(len(t["inputs"]) for t in rec["txs"])

        if len(resolver_buf) + len(spend_buf) >= flush_records:
            flush_runs(h)
        if sum(map(len, pos_buf.values())) >= 64 * 2**20:
            flush_positional()
        done += 1
        if h % checkpoint_every == 0 or h == end_height:
            checkpoint(h)
            rate = done / (time.monotonic() - started)
            eta_h = (end_height - h) / rate / 3600 if rate else 0
            print(f"scan @ {h:>9,}: {n_tx:,} tx, {n_out:,} outputs "
                  f"| {rate:.1f} blk/s, ~{eta_h:.1f} h left",
                  file=sys.stderr)
    return end_height


# ---------------------------------------------------------------------------
# Phase 3: resolve — the streaming merge-join
# ---------------------------------------------------------------------------

def resolve_join(spends, resolver, tolerate_unresolved, totals):
    """The join that unlocks the three questions, as a pure generator:
    two streams sorted on the same key — raw spends by (prev_txid,
    vout), the resolver by txid — fused by looking at the front card
    of each. Linear, no random access: this is "sort in pieces, then
    fuse" applied to a join.

    Yields 10-byte spend records (spent ordinal, spender ordinal), in
    prevout order — the caller re-sorts them by spent ordinal, which
    is the second and last sort of the whole build.

    A prevout with no resolver entry, or a vout past the tx's output
    count, cannot happen in a complete honest graph: both stop the
    build unless explicitly tolerated (and even then the vout
    overflow, which can only be corruption, still stops it)."""
    r_iter = iter(resolver)
    r = next(r_iter, None)
    cached_txid = None
    first_out = n_out = 0
    for s in spends:
        ptxid = s[:32]
        if ptxid != cached_txid:
            while r is not None and r[:32] < ptxid:
                r = next(r_iter, None)
            if r is None or r[:32] > ptxid:
                totals["unresolved_spends"] += 1
                if tolerate_unresolved:
                    continue
                raise OutpointError(
                    f"input spends unknown txid "
                    f"{ptxid[::-1].hex()} — the graph does not "
                    "contain the whole history below this height "
                    "(corrupt or partial graph); --tolerate-"
                    "unresolved only for deliberately partial data")
            cached_txid = ptxid
            first_out = int.from_bytes(r[32:37], "big")
            n_out = int.from_bytes(r[37:40], "big")
        vout = int.from_bytes(s[32:36], "big")
        if vout >= n_out:
            raise OutpointError(
                f"input spends {ptxid[::-1].hex()}:{vout} but that tx "
                f"has {n_out} outputs — corrupt graph")
        yield (first_out + vout).to_bytes(ORD, "big") + s[36:41]


def _phase_resolve(store, flush_records, tolerate_unresolved):
    state = store.state
    entry = state["files"]["txid_index"]
    raw = store.run_sources("rawspends")
    slab = budgeted_slab(len(raw) + 1)
    spends = heapq.merge(*[store.read(p, RAWSPEND_REC, sha, slab)
                           for p, sha in raw])
    resolver = store.read(store.path(entry["file"]),
                          RESOLVER_REC, entry["sha256"], slab)

    totals = {"unresolved_spends": 0}
    new_runs = []
    buf = []
    seq = 0

    def flush():
        nonlocal seq
        if not buf:
            return
        name = f"sort_{seq:05d}_spends.bin"
        # `into` holds the new runs OUT of the state until the whole
        # rawspends category is swapped: a spends run named before the
        # swap would be fused twice.
        store.write_run(name, "spends", buf, into=new_runs)
        buf.clear()
        seq += 1

    for rec in resolve_join(spends, resolver, tolerate_unresolved,
                            totals):
        buf.append(rec)
        if len(buf) >= flush_records:
            flush()
    flush()

    delete = store.drop_runs("rawspends")
    state["runs"] += new_runs
    state["totals"]["unresolved_spends"] += totals["unresolved_spends"]
    if totals["unresolved_spends"]:
        print(f"  resolve: {totals['unresolved_spends']:,} unresolved "
              "spends TOLERATED — this index is not for publication",
              file=sys.stderr)
    return delete


# ---------------------------------------------------------------------------
# Phase 5: seal — audit, invariants, manifest
# ---------------------------------------------------------------------------

def _phase_seal(index_dir, state, graph_dir, clock):
    n_tx, n_out = state["n_tx"], state["n_out"]
    sizes = state["sizes"]
    # The arithmetic invariants: the positional files must agree with
    # the counters to the byte, or something lied.
    expect = {"blocks": state["last_height"] * BLOCK_REC,
              "txids": n_tx * TXID_REC,
              "tx_first_out": n_tx * TFO_REC,
              "outputs": n_out * OUT_REC}
    for name, want in expect.items():
        if sizes[name] != want:
            raise OutpointError(f"{name}.bin holds {sizes[name]} bytes "
                                f"but the counters expect {want}")

    files = {}
    ladder = None                # tx_first_out's, filled by the loop
    for name in POSITIONAL:
        path = _positional_path(index_dir, name)
        if os.path.getsize(path) != sizes[name]:
            raise OutpointError(f"{name}.bin changed size since the "
                                "last checkpoint")
        if name == "tx_first_out":
            # Its ladder is sampled during the audit read, by the same
            # function `verify` will use to rebuild it: one rule, one
            # implementation, so the two can never disagree.
            sha, ladder = sha_and_ladder(path, *LADDERS[name], OutpointError)
        else:
            sha = sha_file(path)
        files[name] = {"file": f"{name}.bin",
                       "records": sizes[name] // POSITIONAL[name],
                       "sha256": sha}

    # The ladder sampled above, written next to its file.
    lad_path = os.path.join(index_dir, "tx_first_out.lad")
    tmp = lad_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(ladder)
    os.replace(tmp, lad_path)
    state["caches"]["tx_first_out"] = {
        "file": "tx_first_out.lad", "every": TFO_LADDER_EVERY,
        "sha256": hashlib.sha256(ladder).hexdigest()}

    # Merged files: re-read against their recorded sha (the audit),
    # and the spend count must match what the join produced.
    for name in MERGED:
        entry = state["files"][name]
        path = os.path.join(index_dir, entry["file"])
        if sha_file(path) != entry["sha256"]:
            raise OutpointError(f"{entry['file']}: sha256 changed "
                                "since its fusion")
        files[name] = entry
    resolved = state["n_spends"] - state["totals"]["unresolved_spends"]
    if files["spends"]["records"] != resolved:
        raise OutpointError(
            f"spends.bin holds {files['spends']['records']} records "
            f"but the scan emitted {resolved} resolvable inputs")

    source_fp = None
    gpath = os.path.join(graph_dir, ge.MANIFEST_NAME)
    if os.path.exists(gpath):
        with open(gpath) as f:
            graph_manifest = json.load(f)
        # A seal from an earlier major is readable but cannot be a
        # parent: its fingerprint comes from a recipe this code does not
        # compute, so adopting it would put a number inside this
        # artifact's identity that nobody can rederive from these
        # formats. Silently taking it would be the worst outcome, since
        # the wrong ancestry would be sealed and published.
        if graph_manifest.get("format") != ge.FORMAT_TAG:
            raise OutpointError(
                f"the graph is sealed as {graph_manifest.get('format')}, "
                f"not {ge.FORMAT_TAG}: its fingerprint comes from a "
                "recipe this major does not compute and cannot be named "
                "as a parent. Re-seal the graph first with "
                "`graph fingerprint --reseal` (the bytes do not change).")
        source_fp = graph_manifest.get("fingerprint")

    # The parent is DECLARED, not sealed: it says where this index came
    # from, not what it is, so it rides in `build`. Two indexes built from
    # the same chain to the same height are the same artifact and take the
    # same name, whether or not their builders had sealed their graph.
    identity = make_identity(
        FORMAT_TAG, 1, state["last_height"],
        ((name, files[name]["sha256"]) for name in FP_ORDER))
    fingerprint = identity_fingerprint(identity)

    manifest = seal_manifest(FORMAT_TAG, identity, {
            "producer": producer(),
            "seconds": clock.stamp(state),
            "parent": (None if source_fp is None
                       else declared_parent(ge.FORMAT_TAG, source_fp)),
            "last_block_hash": state["last_block_hash"],
            "transactions": n_tx,
            "outputs": n_out,
            "spends": files["spends"]["records"],
            "totals": state["totals"],
            "files": files,
            "caches": state["caches"],
            "reconstruction": (
                "one pass over the graph's heights 1..H emits the positional "
                "files in ordinal order plus sorted resolver/spend runs; "
                "fuse resolver runs (equal txids: highest first_out wins, "
                "BIP30); merge-join raw spends against the resolver; fuse "
                "the rewritten spends; the identity is then sealed by the "
                "shared recipe in docs/contracts/Artifact.md"),
    })
    atomic_json(os.path.join(index_dir, MANIFEST_NAME), manifest)
    if source_fp is None:
        print("note: the source graph is not sealed, so this index records "
              "no parent and cannot attest its ancestry. Run `graph "
              "fingerprint` and re-run this build to give it one.",
              file=sys.stderr)
    return manifest


# ---------------------------------------------------------------------------
# build — driving the phases
# ---------------------------------------------------------------------------

def run_build(graph_dir, index_dir, end_height=None,
              flush_records=8_000_000, checkpoint_every=10_000,
              tolerate_unresolved=False):
    """Drive the five phases from wherever the state says we are.
    Safe to re-run after a crash (continues) and after the graph has
    grown (appends): both are the same code path."""
    warn_if_slow_ripemd160("this build")
    os.makedirs(index_dir, exist_ok=True)
    state = _load_state(index_dir, required=False)
    if state is None:
        state = _new_state()
        for name in POSITIONAL:
            open(_positional_path(index_dir, name), "ab").close()
    # One code path, two verbs: an index that was already sealed when
    # this command started is being APPENDED to, and the cost of adding
    # blocks is not the cost of building from nothing. The distinction
    # has to be taken here, before the phase below is flipped back to
    # `scan` and the two become indistinguishable.
    clock = WallClock("append" if state["phase"] == "sealed" else "build",
                      state)
    store = _store(index_dir, state, clock=clock)
    store.clean_orphans(keep=KEEP_TOP)
    store.truncate_appended([(f"{name}.bin", committed)
                             for name, committed
                             in state["sizes"].items()])
    if state["phase"] == "rewind":
        raise OutpointError(
            f"a rewind to height {state['rewind']['height']:,} was "
            "interrupted: finish it with `rewind` before building "
            "again, or this build would extend a half-cut index")
    if state["phase"] == "sealed":
        state["phase"] = "scan"          # append: scan decides if
                                         # anything new exists

    while state["phase"] != "sealed":
        phase = state["phase"]
        if phase == "scan":
            covered = _phase_scan(graph_dir, store, end_height,
                                  flush_records, checkpoint_every)
            if (state["last_height"] == covered
                    and "txid_index" in state["files"]
                    and not state["runs"]):
                # Append with nothing new: the sealed artifacts stand.
                state["phase"] = "sealed"
                store.write_state()
                print("nothing to do: index already covers height "
                      f"{covered:,}")
                return
            state["phase"] = "merge-txids"
            store.write_state()
        elif phase == "merge-txids":
            dup_log = []
            dups, delete = store.fuse("txid_index",
                                      MERGED["txid_index"],
                                      "txids", dedup="last",
                                      dup_log=dup_log)
            state["totals"]["overwritten_txids"] += dups
            # The colliding records themselves, kept verbatim: a rewind
            # must ask whether a duplicate straddles its cut, and with
            # the records in the state that question costs nothing
            # instead of a pass over txids.bin (see
            # _refuse_straddling_duplicate).
            state["totals"].setdefault("overwritten_txid_records", [])
            state["totals"]["overwritten_txid_records"] += [
                (d + k).hex() for d, k in dup_log]
            state["phase"] = "resolve"
            store.commit(delete)
            print(f"txid_index: {state['files']['txid_index']['records']:,} "
                  f"txids ({dups} duplicate overwritten — BIP30 expects "
                  "2 on the full chain)", file=sys.stderr)
        elif phase == "resolve":
            delete = _phase_resolve(store, flush_records,
                                    tolerate_unresolved)
            state["phase"] = "merge-spends"
            store.commit(delete)
        elif phase == "merge-spends":
            dups, delete = store.fuse("spends", MERGED["spends"],
                                      "spends", dedup=None)
            state["totals"]["duplicate_spends"] += dups
            state["phase"] = "seal"
            store.commit(delete)
        elif phase == "seal":
            manifest = _phase_seal(index_dir, state, graph_dir, clock)
            state["phase"] = "sealed"
            store.write_state()
            _print_manifest(index_dir, manifest)
    return _load_manifest(index_dir)["fingerprint"]


def _cut_at(index_dir, height):
    """(transactions, outputs) through `height`, read from the index's
    own blocks.bin.

    A block record holds the ordinals its block STARTS at, so the
    record of height+1 is the count of everything before it, which is
    exactly the total through `height`. No manifest to keep, no
    counting: the artifact already knows where every height ends."""
    with open(_positional_path(index_dir, "blocks"), "rb") as f:
        f.seek(height * BLOCK_REC)
        rec = f.read(BLOCK_REC)
    if len(rec) != BLOCK_REC:
        raise OutpointError(f"blocks.bin has no record for height "
                            f"{height + 1}: the index does not reach "
                            "past the target")
    return (int.from_bytes(rec[:ORD], "big"),
            int.from_bytes(rec[ORD:2 * ORD], "big"))


def run_rewind(index_dir, graph_dir, to_height):
    """Take a sealed index back to a height it already covers, so that
    its bytes equal those of a build that had stopped there.

    Cheap where a rebuild is not, because REMOVING RECORDS FROM A
    SORTED FILE LEAVES IT SORTED: the positional files are truncated to
    the counts blocks.bin already holds, and the two merged files are
    re-fused through a sift that drops what lies above the cut. It is
    the ordinary fusion, so the ladder, the generation numbering and
    the crash-safe commit order are the same code that built them.

    The graph is read for one thing only — the hash of the block at the
    target height, which the index stores but cannot recompute."""
    state = _load_state(index_dir)
    if state["phase"] == "rewind":
        pass                       # a crashed rewind resumes below
    elif state["phase"] != "sealed":
        raise OutpointError(f"the index is in phase {state['phase']}, "
                            "not sealed: finish `build` before "
                            "rewinding it")
    clock = WallClock("rewind", state)
    store = _store(index_dir, state, clock=clock)
    store.clean_orphans(keep=KEEP_TOP)
    store.truncate_appended([(f"{name}.bin", committed)
                             for name, committed
                             in state["sizes"].items()])

    if state["phase"] != "rewind":
        _rewind_plan(index_dir, graph_dir, state, store, to_height)
    plan = state["rewind"]
    if to_height is not None and to_height != plan["height"]:
        raise OutpointError(
            f"a rewind to height {plan['height']:,} was interrupted "
            "and must be finished first: re-run with that height")
    n_tx_cut, n_out_cut = plan["n_tx"], plan["n_out"]

    # The resolver keeps an output ordinal, not a transaction's: a txid
    # is dropped when the outputs it created are above the cut.
    if "txid_index" not in plan["done"]:
        cut5 = n_out_cut.to_bytes(ORD, "big")
        dups, delete = store.fuse(
            "txid_index", MERGED["txid_index"], "txids", dedup="last",
            sift=lambda r: r if r[32:32 + ORD] < cut5 else None)
        state["totals"]["overwritten_txids"] = (
            n_tx_cut - state["files"]["txid_index"]["records"])
        plan["done"].append("txid_index")
        store.commit(delete)

    if "spends" not in plan["done"]:
        cut5 = n_tx_cut.to_bytes(ORD, "big")
        dups, delete = store.fuse(
            "spends", MERGED["spends"], "spends", dedup=None,
            sift=lambda r: r if r[ORD:2 * ORD] < cut5 else None)
        state["totals"]["duplicate_spends"] = dups
        state["n_spends"] = state["files"]["spends"]["records"]
        plan["done"].append("spends")
        store.commit(delete)

    if "positional" not in plan["done"]:
        cuts = (("blocks", plan["height"]),
                ("txids", n_tx_cut),
                ("tx_first_out", n_tx_cut),
                ("outputs", n_out_cut))
        for name, count in cuts:
            state["sizes"][name] = count * POSITIONAL[name]
        state["last_height"] = plan["height"]
        state["last_block_hash"] = plan["last_block_hash"]
        state["n_tx"], state["n_out"] = n_tx_cut, n_out_cut
        plan["done"].append("positional")
        # The state first, the truncations after — the store's own
        # rule, and here it is what makes this step killable: a crash
        # after the write leaves the files LONGER than the committed
        # sizes, which is the one direction truncate_appended heals on
        # the next load. The old order turned the same crash into a
        # false "tampered with or lost data" refusal.
        store.write_state()
        for name, count in cuts:
            with open(_positional_path(index_dir, name), "ab") as f:
                f.truncate(count * POSITIONAL[name])

    del state["rewind"]
    state["phase"] = "seal"
    store.write_state()
    manifest = _phase_seal(index_dir, state, graph_dir, clock)
    state["phase"] = "sealed"
    store.write_state()
    _print_manifest(index_dir, manifest)
    return manifest["fingerprint"]


def _refuse_straddling_duplicate(index_dir, state, n_tx_cut, n_out_cut,
                                 to_height):
    """The one hazard a sift cannot see, and the only place a rewind
    can be wrong instead of merely refused.

    The resolver keeps the LAST of two equal txids (the BIP30 rule), so
    the earlier record is already gone from the file. If the survivor
    lies above the cut, the sift drops it and the txid disappears —
    while a rebuild to that height would still hold the earlier
    instance. Counting cannot see it: the survivor is one record and it
    is legitimately dropped, so the totals come out right and the
    artifact comes out wrong.

    Asked only when the index says duplicates exist at all — which
    after BIP34 no chain produces any more, so on a modern range this
    costs nothing. When they do exist, the first road is the state
    itself: the fusion keeps the colliding records verbatim, each
    carrying its first_out, and a cut lands at a block boundary, so
    "instance below the cut" is exactly "first_out below the output
    cut" — the whole question costs a few hex decodes. The second road,
    for an index sealed before the collisions were kept, asks the
    txids themselves: the removed range held as sorted contiguous
    blobs (the bytes and nothing else, not a set of per-record
    objects, whose overhead once put a chain-scale rewind out of
    memory), a prefix bitmap in front, and one pass below the cut."""
    total = state["totals"]["overwritten_txids"]
    if not total:
        return

    def refuse(txid):
        raise OutpointError(
            f"txid {txid[::-1].hex()} appears both at or "
            f"below height {to_height:,} and above it: the "
            "resolver kept only the later instance (BIP30) and the "
            "earlier one cannot be brought back — rebuild instead")

    recorded = state["totals"].get("overwritten_txid_records") or []
    if len(recorded) == total:
        instances = {}
        for hx in recorded:
            raw = bytes.fromhex(hx)
            half = len(raw) // 2
            for rec in (raw[:half], raw[half:]):
                instances.setdefault(rec[:32], set()).add(
                    int.from_bytes(rec[32:32 + ORD], "big"))
        for txid, first_outs in instances.items():
            if min(first_outs) < n_out_cut <= max(first_outs):
                refuse(txid)
        return

    path = _positional_path(index_dir, "txids")
    blobs = []
    batch = []
    removed = 0
    for r in _read_fixed(path, TXID_REC, start_record=n_tx_cut):
        batch.append(bytes(r))
        removed += 1
        if len(batch) >= 8_000_000:
            batch.sort()
            blobs.append(b"".join(batch))
            batch.clear()
    if batch:
        batch.sort()
        blobs.append(b"".join(batch))
        batch.clear()
    if not removed:
        return
    # The bitmap is sized to the removed count (at ~1/16 occupancy) and
    # capped at 512 MB: a miss skips the bisects, and on a chain where
    # duplicates are two, essentially everything misses.
    bits = 1 << min(32, max(20, (removed * 16).bit_length()))
    mask = bits - 1
    bitmap = bytearray(bits // 8)
    for blob in blobs:
        for i in range(0, len(blob), TXID_REC):
            p = int.from_bytes(blob[i:i + 4], "big") & mask
            bitmap[p >> 3] |= 1 << (p & 7)
    for i, rec in enumerate(_read_fixed(path, TXID_REC)):
        if i >= n_tx_cut:
            break
        p = int.from_bytes(rec[:4], "big") & mask
        if not bitmap[p >> 3] & (1 << (p & 7)):
            continue
        key = bytes(rec)
        for blob in blobs:
            j = bisect_blob(blob, TXID_REC, key)
            if j >= 0 and blob[j * TXID_REC:(j + 1) * TXID_REC] == key:
                refuse(key)


def _rewind_plan(index_dir, graph_dir, state, store, to_height):
    """Check that this rewind is possible, then write it into the state
    before a single byte moves. Everything that can refuse refuses
    here, while the artifact is still whole."""
    if to_height is None:
        raise OutpointError("a rewind needs a target height")
    if not 1 <= to_height < state["last_height"]:
        raise OutpointError(
            f"target height {to_height:,} is not below the index's "
            f"{state['last_height']:,}: a rewind only ever removes")
    if state["totals"]["unresolved_spends"]:
        raise OutpointError(
            "this index tolerated unresolved spends: how many of them "
            "lay below the target is not recoverable from the files, "
            "so the count would become a lie — rebuild instead")

    n_tx_cut, n_out_cut = _cut_at(index_dir, to_height)

    _refuse_straddling_duplicate(index_dir, state, n_tx_cut, n_out_cut,
                                 to_height)

    for rec in ge.iter_blocks(graph_dir, from_height=to_height,
                              to_height=to_height):
        last_hash = rec["hash"][::-1].hex()
        break
    else:
        raise OutpointError(f"the graph has no block at height "
                            f"{to_height:,}")

    state["rewind"] = {"height": to_height, "n_tx": n_tx_cut,
                       "n_out": n_out_cut, "last_block_hash": last_hash,
                       "done": []}
    state["phase"] = "rewind"
    store.write_state()
    print(f"rewinding to height {to_height:,}: "
          f"{state['n_tx'] - n_tx_cut:,} transactions and "
          f"{state['n_out'] - n_out_cut:,} outputs go", file=sys.stderr)


def _load_manifest(index_dir):
    path = os.path.join(index_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        raise OutpointError(f"no {MANIFEST_NAME} in {index_dir}: the "
                            "index is not sealed — run `build`")
    with open(path) as f:
        manifest = json.load(f)
    if manifest.get("format") != FORMAT_TAG:
        raise OutpointError("unknown index manifest format")
    return manifest


def _print_manifest(index_dir, manifest):
    build = manifest["build"]
    print(f"outpoint index sealed: heights "
          f"1..{manifest['identity']['coverage']['to']:,}")
    print(f"  transactions {build['transactions']:>16,}")
    print(f"  outputs      {build['outputs']:>16,}")
    print(f"  spends       {build['spends']:>16,}")
    t = build["totals"]
    print(f"  overwritten txids (BIP30): {t['overwritten_txids']}, "
          f"duplicate spends: {t['duplicate_spends']}, "
          f"unresolved: {t['unresolved_spends']}")
    total = sum(os.path.getsize(os.path.join(index_dir, e["file"]))
                for e in build["files"].values())
    print(f"  on disk      {total / 2**30:>13.2f} GiB "
          "(+ ladder caches)")
    parent = build.get("parent")
    if parent is None:
        print("  source graph: not sealed, so this index declares no parent")
    else:
        print(f"  source graph: {parent['fingerprint']}  (declared)")
    print(f"fingerprint: {manifest['fingerprint']}")


# ---------------------------------------------------------------------------
# Reading: the Index object (SortedFile, the shared search primitive, and
# bisect_blob live in recsort)
# ---------------------------------------------------------------------------

class Index:
    """Read side of a sealed index. This object is the module's reuse
    point: `lookup` below is one consumer, the address-history and
    co-spend backends of check_addresses.py will be the next ones —
    they all ask the same few questions, answered with at most one
    targeted bucket read each (ladders in RAM, blocks.bin in RAM)."""

    def __init__(self, index_dir):
        self.dir = index_dir
        self.manifest = _load_manifest(index_dir)
        self.build = self.manifest["build"]
        self._fd = {}
        self._ladders = {}
        self._sorted = {}
        # blocks.bin resident: three parallel u64 arrays, ~24 bytes per
        # thousand blocks — the price of answering every "which height
        # / what time" question without touching the disk.
        self.first_tx = array("q")
        self.first_out = array("q")
        self.times = array("q")
        for rec in _read_fixed(_positional_path(index_dir, "blocks"),
                               BLOCK_REC,
                               self.build["files"]["blocks"]["sha256"]):
            self.first_tx.append(int.from_bytes(rec[0:5], "big"))
            self.first_out.append(int.from_bytes(rec[5:10], "big"))
            self.times.append(int.from_bytes(rec[10:14], "big"))
        self.n_tx = self.build["transactions"]
        self.n_out = self.build["outputs"]
        self.watermark = self.manifest["identity"]["coverage"]["to"]

    # -- plumbing ----------------------------------------------------------

    def _fdesc(self, fname):
        if fname not in self._fd:
            self._fd[fname] = os.open(os.path.join(self.dir, fname),
                                      os.O_RDONLY)
        return self._fd[fname]

    def close(self):
        for fd in self._fd.values():
            os.close(fd)
        self._fd = {}
        for sf in self._sorted.values():
            sf.close()
        self._sorted = {}

    def _pread(self, fname, offset, length):
        data = os.pread(self._fdesc(fname), length, offset)
        if len(data) != length:
            raise OutpointError(f"{fname}: short read at {offset} — "
                                "truncated file")
        return data

    def _ladder(self, name):
        if name not in self._ladders:
            entry = self.build["caches"][name]
            with open(os.path.join(self.dir, entry["file"]), "rb") as f:
                blob = f.read()
            if hashlib.sha256(blob).hexdigest() != entry["sha256"]:
                raise OutpointError(f"{entry['file']}: corrupted ladder")
            self._ladders[name] = (blob, entry["every"])
        return self._ladders[name]

    def sorted_file(self, logical):
        """The SortedFile for one of the searchable artifacts, opened
        lazily with its ladder verified and resident."""
        if logical not in self._sorted:
            rec, key_len, _ = MERGED[logical]
            entry = self.build["files"][logical]
            blob, every = self._ladder(logical)
            self._sorted[logical] = SortedFile(
                os.path.join(self.dir, entry["file"]), rec, key_len,
                entry["records"], blob, every, error=OutpointError)
        return self._sorted[logical]

    # -- the questions -----------------------------------------------------

    def resolve(self, txid):
        """txid (serialized order) → (first_out, n_out), or None if
        that txid never appeared in confirmed history up to the
        watermark."""
        hits = self.sorted_file("txid_index").find(txid)
        if not hits:
            return None
        r = hits[0]
        return (int.from_bytes(r[32:37], "big"),
                int.from_bytes(r[37:40], "big"))

    def output(self, out_ord):
        """output ordinal → (value_sats, lock hash160)."""
        rec = self._pread("outputs.bin", out_ord * OUT_REC, OUT_REC)
        return int.from_bytes(rec[0:8], "big"), rec[8:28]

    def spenders(self, out_ord):
        """tx ordinals that spent this output: [] if unspent, one
        entry under consensus (more would echo a duplicate_spends
        anomaly, reported as found)."""
        key = out_ord.to_bytes(ORD, "big")
        return [int.from_bytes(r[ORD:2 * ORD], "big")
                for r in self.sorted_file("spends").find(key)]

    def txid_of(self, tx_ord):
        return self._pread("txids.bin", tx_ord * TXID_REC, TXID_REC)

    def tx_of_output(self, out_ord):
        """Which tx created output ordinal k: binary search by VALUE
        over tx_first_out.bin, narrowed to one bucket by its ladder —
        the positional file doubling as a sorted one."""
        blob, every = self._ladder("tx_first_out")
        key = out_ord.to_bytes(ORD, "big")
        i = max(bisect_blob(blob, TFO_REC, key), 0)
        start = i * every
        count = min(every, self.n_tx - start)
        bucket = self._pread("tx_first_out.bin", start * TFO_REC,
                             count * TFO_REC)
        lo, hi = 0, count                 # last entry <= out_ord
        while lo < hi:
            mid = (lo + hi) // 2
            if bucket[mid * TFO_REC:(mid + 1) * TFO_REC] <= key:
                lo = mid + 1
            else:
                hi = mid
        return start + lo - 1

    def outpoint_of(self, out_ord):
        """The (txid, vout, tx_ord) an output ordinal came from — the
        reverse walk the co-spend display needs."""
        tx_ord = self.tx_of_output(out_ord)
        first = int.from_bytes(
            self._pread("tx_first_out.bin", tx_ord * TFO_REC, TFO_REC),
            "big")
        return self.txid_of(tx_ord), out_ord - first, tx_ord

    def height_of_tx(self, tx_ord):
        return bisect.bisect_right(self.first_tx, tx_ord)

    def height_of_output(self, out_ord):
        return bisect.bisect_right(self.first_out, out_ord)

    def time_of_height(self, height):
        return self.times[height - 1]


# ---------------------------------------------------------------------------
# stats / verify / lookup
# ---------------------------------------------------------------------------

def run_stats(index_dir, out=sys.stdout):
    state = _load_state(index_dir)
    print(f"phase: {state['phase']}   heights 1..{state['last_height']:,}",
          file=out)
    print(f"  transactions {state['n_tx']:>16,}", file=out)
    print(f"  outputs      {state['n_out']:>16,}", file=out)
    print(f"  inputs seen  {state['n_spends']:>16,}", file=out)
    for name, entry in sorted(state["files"].items()):
        print(f"  {entry['file']:<24} {entry['records']:>14,} records",
              file=out)
    if state["runs"]:
        print(f"  {len(state['runs'])} unfused runs", file=out)
    t = state["totals"]
    print(f"  overwritten txids: {t['overwritten_txids']}, duplicate "
          f"spends: {t['duplicate_spends']}, unresolved: "
          f"{t['unresolved_spends']}", file=out)
    if state["phase"] == "sealed":
        print(f"fingerprint: {_load_manifest(index_dir)['fingerprint']}",
              file=out)


def run_verify(index_dir, graph_dir=None):
    """Re-read every byte against the manifest: data files, ladders
    rebuilt from the files they index, and the fingerprint recomputed
    from what is actually on disk.

    With `--graph`, the PARENT gets its second road, exactly as
    `derived verify --index` gives one to the derivatives: the parent
    rides in `build` and is a declaration until the graph it names is
    handed over to confront it with. The coverage needs no help here
    (blocks.bin states it), and it is legitimate for it to stop below
    the graph's: `--end` builds a comparable prefix on purpose."""
    manifest = _load_manifest(index_dir)
    parent_confirmed = None
    if graph_dir is not None:
        gpath = os.path.join(graph_dir, ge.MANIFEST_NAME)
        if not os.path.exists(gpath):
            raise OutpointError(
                "that graph is not sealed (no manifest): there is no "
                "fingerprint to confront the declared parent with")
        with open(gpath) as f:
            gmanifest = json.load(f)
        # The graph's manifest must first agree with itself: comparing
        # two stored fingerprint strings confirms nothing if the one in
        # the graph was left behind by an edit of its identity block.
        if gmanifest.get("format") != ge.FORMAT_TAG:
            raise OutpointError(
                f"the graph is sealed as {gmanifest.get('format')}, not "
                f"{ge.FORMAT_TAG}: no parent declared by this major can "
                "name it")
        if identity_fingerprint(gmanifest["identity"]) != \
                gmanifest["fingerprint"]:
            raise OutpointError(
                "the given graph's manifest does not match its own "
                "identity block: nothing can be confirmed against it "
                "(run `graph fingerprint` on it)")
        parent = manifest["build"].get("parent")
        if parent is None or \
                parent["fingerprint"] != gmanifest["fingerprint"]:
            raise OutpointError(
                "that graph is not this index's parent (fingerprints "
                "differ)")
        parent_confirmed = True
    verify_sealed(
        index_dir, manifest, FORMAT_TAG, OutpointError,
        fp_order=FP_ORDER,
        coverage_from_data=lambda: (
            "exact",
            os.path.getsize(_positional_path(index_dir, "blocks")) // BLOCK_REC),
        ladder_hint=" (rebuildable: re-run build after deleting it)",
        ladders=LADDERS,
        trust_hint="--graph",
        parent_confirmed=parent_confirmed)


def _fmt_time(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC")


def run_lookup(index_dir, outpoints, out=sys.stdout):
    """The didactic window: one outpoint, its whole story — where the
    coin was born, what it is worth, under which lock, and whether
    history has already consumed it. Takes txids in DISPLAY order
    (what explorers show), reverses them at the door like everything
    else does."""
    idx = Index(index_dir)
    print(f"index covers heights 1..{idx.watermark:,}", file=out)
    try:
        for op in outpoints:
            try:
                txid_hex, vout_str = op.split(":")
                txid = bytes.fromhex(txid_hex)[::-1]
                vout = int(vout_str)
                if len(txid) != 32 or vout < 0:
                    raise ValueError
            except ValueError:
                print(f"{op}: not TXID:VOUT (64 hex chars, colon, "
                      "a number)", file=out)
                continue
            hit = idx.resolve(txid)
            if hit is None:
                print(f"{op}: txid NOT in confirmed history up to the "
                      "watermark", file=out)
                continue
            first_out, n_out = hit
            if vout >= n_out:
                print(f"{op}: tx exists but has only {n_out} outputs",
                      file=out)
                continue
            out_ord = first_out + vout
            value, lock = idx.output(out_ord)
            h = idx.height_of_output(out_ord)
            print(f"{op}", file=out)
            print(f"  created  height {h:,} "
                  f"({_fmt_time(idx.time_of_height(h))})", file=out)
            print(f"  value    {value / SAT:,.8f} BTC ({value:,} sat)",
                  file=out)
            print(f"  lock     hash160(scriptPubKey) {lock.hex()}",
                  file=out)
            spenders = idx.spenders(out_ord)
            if not spenders:
                print(f"  spent    no — UNSPENT as of height "
                      f"{idx.watermark:,}", file=out)
            for tx_ord in spenders:
                sh = idx.height_of_tx(tx_ord)
                print(f"  spent    height {sh:,} "
                      f"({_fmt_time(idx.time_of_height(sh))}) by "
                      f"{idx.txid_of(tx_ord)[::-1].hex()}", file=out)
    finally:
        idx.close()


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Build and query the outpoint index (ordinal "
                    "coordinates over a graph-v2 archive): the one "
                    "expensive derivative behind address history, "
                    "fees and co-spends.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pb = sub.add_parser("build", help="drive the five build phases "
                                      "(resumable, appendable)")
    pb.add_argument("--graph", required=True,
                    help="a graph-v2 archive directory")
    pb.add_argument("--index", required=True,
                    help="the index directory to create or grow")
    pb.add_argument("--end", type=int,
                    help="last height to index (default: the graph's "
                         "watermark; a fixed height makes runs "
                         "comparable across machines)")
    pb.add_argument("--flush-records", type=int, default=8_000_000,
                    help="buffered run records before a flush "
                         "(memory knob)")
    pb.add_argument("--checkpoint-every", type=int, default=10_000,
                    help="blocks between checkpoints in the scan")
    pb.add_argument("--tolerate-unresolved", action="store_true",
                    help="count inputs whose prevout is missing "
                         "instead of failing (partial/synthetic "
                         "graphs ONLY — never for published numbers)")

    pr = sub.add_parser("rewind", help="take a sealed index back to a "
                                       "height it already covers")
    pr.add_argument("--index", required=True)
    pr.add_argument("--graph", required=True,
                    help="the graph this index was built from (read "
                         "for one block hash)")
    pr.add_argument("--to-height", type=int, required=True,
                    help="the height to come back to; the result holds "
                         "the same bytes as a build that stopped there")

    pt = sub.add_parser("stats", help="phase, watermark and counts "
                                      "(instant)")
    pt.add_argument("--index", required=True)

    pv = sub.add_parser("verify", help="re-read everything against "
                                       "the manifest (full audit)")
    pv.add_argument("--index", required=True)
    pv.add_argument("--graph",
                    help="the sealed graph this index declares as its "
                         "parent: confirms the ancestry instead of "
                         "taking it on trust")

    pl = sub.add_parser("lookup", help="TXID:VOUT → its whole story")
    pl.add_argument("--index", required=True)
    pl.add_argument("outpoints", nargs="+", metavar="TXID:VOUT",
                    help="txid in display order, colon, output number")

    args = p.parse_args(argv)
    try:
        if args.cmd == "build":
            run_build(args.graph, args.index, end_height=args.end,
                      flush_records=args.flush_records,
                      checkpoint_every=args.checkpoint_every,
                      tolerate_unresolved=args.tolerate_unresolved)
        elif args.cmd == "rewind":
            run_rewind(args.index, args.graph, args.to_height)
        elif args.cmd == "stats":
            run_stats(args.index)
        elif args.cmd == "verify":
            run_verify(args.index, graph_dir=args.graph)
        else:
            run_lookup(args.index, args.outpoints)
    except (OutpointError, ge.GraphError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
