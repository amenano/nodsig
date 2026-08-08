#!/usr/bin/env python3
"""
derivatives.py — the three spend-side DERIVATIVES of the outpoint
index: the payment history of a lock (Q3), the fee of every
transaction, and the co-spend reading (the common-input hint of Q2).
One build, one directory, one fingerprint — everything derived from
`outpoint-index-v3` alone, no node and no graph needed.

Why these three together: the design promise of the outpoint index
was that ONE expensive derivative unlocks three questions at once.
This module is that promise kept — and because the index already
speaks ordinal coordinates, each answer is a small projection of it,
built with streams and at most one external sort per side, and
readable afterwards with one targeted bucket read.

FROZEN FORMAT — outpoint-derived-v2
===================================
A derivatives directory holds three record files (all integers
big-endian, same rule and same reason as the index: byte order IS
numeric order, so sorting and searching never decode a field):

    history.bin    38 B, sorted by (lock, out_ord):
                       lock 20 | out_ord u40 | spender_tx u40 | value u64
                   One row per output EVER created: who received it
                   (the lock, hash160 of the full scriptPubKey), when
                   (the ordinal, which is chain time), whether and by
                   whom it was spent, and its value. History could be
                   kept as two event rows (a receive and a spend);
                   one row per output CARRIES both events — the reader
                   emits them — at half the records and with the spend
                   attached to its coin for free. Receive height =
                   height_of_output(out_ord); spend height =
                   height_of_tx(spender): both answered from RAM.
    tx_inputs.bin  10 B, sorted by (spender_tx, out_ord):
                       spender_tx u40 | out_ord u40
                   The spend side re-sorted by the SPENDER: every
                   transaction's inputs, adjacent. This is the
                   co-spend reader — outputs consumed together by one
                   transaction, the common-input hint — and the
                   inverse of the index's spender_of.bin.
    fees.bin        8 B per transaction, POSITIONAL by tx ordinal:
                       fee u64 (satoshis)
                   fee = sum of input values − sum of output values;
                   0 for a transaction with no inputs (a coinbase —
                   under consensus the only no-input case). The join
                   that is impossible without the index, now a
                   subtraction and an O(1) read.

UNSPENT sentinel: spender_tx = 0. Transaction ordinal 0 is the first
transaction of block 1 — a coinbase, which can never spend anything —
so 0 is unambiguous, and it SORTS BELOW every real spender: when an
append updates a row from unspent to spent, the spent row wins the
"keep the last of an equal key" rule by construction, the same
mechanism that settles BIP30 in the index. No special cases.

Size, measured against the 2026 chain (~1.3G tx, ~3.5G spends, ~3.7G
outputs): history ~141 GB, tx_inputs ~35 GB, fees ~10 GB ≈ 186 GB.
The value is stored in the history row on purpose (it is also in
outputs.bin): statistical scans over locks — balances, dormancy,
concentration — read one file sequentially instead of paying billions
of random lookups; +30 GB buys every future per-lock analysis.

Ladders (`.lad` sidecars, resident in RAM) give point queries one
~40 KB bucket read, as in the index; history's ladder samples the
20-byte lock, so one lock's whole story is one contiguous scan.

HONEST BOUNDARIES, stated once
==============================
- A lock is an identical scriptPubKey (its hash160): NOT a wallet
  (that is Q2's heuristic, and this module only provides its HINT —
  outputs co-spent by one transaction usually share an owner, with
  known exceptions: CoinJoin and collaborative spends break the
  assumption), and NOT a key under its other faces.
- Fees are in satoshis, absolute: fee RATES need transaction sizes,
  which graph-v2 deliberately excludes — a future derived scan, not a
  silent estimate here.
- The build REFUSES an index with unresolved spends (a tolerated,
  partial graph): fees and histories computed on holes would be
  numbers that look true. Publication-grade sources only.

BUILD = one sequential pass over the index + one sort per side
==============================================================
    scan           outputs.bin, spender_of.bin and tx_first_out.bin
                   are all ordinal-ordered, so ONE aligned pass zips
                   them (spender_of even shares the output's index):
                   each output meets its (at most one) spend in
                   lockstep, emits a history row and, if spent, a
                   spender-side record (spender | out | value, 17 B);
                   per-transaction output sums stream into a temp
                   file for the fee subtraction. Sorted runs flush at
                   checkpoints; the pass resumes from exact record
                   positions (they are all just counters).

                   The two sides resume DIFFERENTLY, and the asymmetry
                   is the format's, not an accident. Outputs and
                   transactions are append-only in the index — an
                   ordinal is theirs forever — so their cursors mean
                   the same thing across generations. spender_of.bin
                   is positional too and its slots never move — and
                   that is exactly the trap, because the obvious
                   conclusion ("so the cursor can be kept") is wrong:
                   a new block spending an OLD output mutates a slot
                   BELOW the cursor. Each cycle therefore re-reads
                   spender_of.bin whole and keeps the edges whose
                   SPENDER is one of its own transactions: an exact
                   partition (an old transaction cannot gain inputs),
                   at the cost of one sequential pass per append.
                   Under v2 the reason was different (the file was
                   re-sorted at every fusion); the reason changed, the
                   rule did not.
    merge-history  fuse history runs → history.bin (+ ladder), the
                   same generation-committed fusion the index uses.
    merge-inputs   fuse spender runs: the stream arrives grouped by
                   spender, so tx_inputs.bin, the fee of every new
                   transaction (group sum − its output sum, read in
                   step from the temp) and fees.bin are all written in
                   the same single walk. Appends in place; committed
                   sizes make a crash truncate-and-redo, like the
                   index's positional files.
    seal           re-read everything (sha256, the audit), check the
                   arithmetic: one history row per output, one
                   tx_inputs row per spend, fees for every tx, and
                   the cross-file identity Σ(spent values in
                   history.bin) == Σ(input values consumed by the fee
                   computation) — two roads to the same satoshis.
                   Then manifest + canonical fingerprint.

`build` drives the phases from state.json, is safe to re-run after a
crash, and APPENDS when the source index has grown: new outputs add
rows, spends of OLD outputs become update rows (same key, spent
spender, value fetched back from the index) that win the dedup, and
fees/tx_inputs only ever extend — appending derivatives equals
rebuilding them, byte for byte. Growing with the chain is therefore a
cadence choice, not a design problem: the practical cost of a sync is
the fusion (the sorted files are rewritten), so frequent syncs would
batch runs and fuse periodically — that mechanism lives with the
scan-side tools, not here.

Ancestry: the manifest records the SOURCE INDEX fingerprint
(which itself records the graph's): graph → index → derivatives, each
sealed artifact naming its parent. Same chain + same height ⇒ same
three files and the same fingerprint on anyone's machine.

Subcommands:
    build     drive the phases (resumable, appendable)
    rewind    back to the height the index now covers, into the same
              bytes a build that stopped there would have written
    stats     phase and counts (instant)
    verify    re-read everything against the manifest (full audit)
    history   one lock's whole story: events in time order + balance
    fee       TXID → its fee (or "coinbase")
    cospends  TXID or TXID:VOUT → what was spent together, with locks

Standard library only; the shared machinery is one implementation each:
record I/O and the slab budget in recio, the run writer and the
ladder-backed SortedFile in recsort, the fingerprint and the verify audit
in artifact, the append-and-fuse store (runs, merged generations, the
crash-safe commit order) in genstore, and the Index reader in
outpoint_index — from which this module now borrows nothing private.
"""

import argparse
import hashlib
import heapq
import json
import os
import sys
import time
from datetime import datetime, timezone

from nodsig import outpoint_index as oi
from nodsig.artifact import (WallClock, declared_parent,
                             identity_fingerprint, make_identity, producer,
                             seal_manifest, sha_and_ladder, verify_sealed)
from nodsig.genstore import GenStore, new_state_fields
from nodsig.outpoint_index import ORD, OutpointError
from nodsig.hashing import hash160
from nodsig.recio import (IO_CHUNK, atomic_json, budgeted_slab,
                          read_fixed, read_slabs)
from nodsig.recsort import SortedFile
from nodsig.reuse_scan import SAT

FORMAT_TAG = "outpoint-derived-v3"

# Sealed derivatives this code can READ. v2 is the same three files in
# the same order, with satoshis as u64 instead of u56, so the widths are
# carried on the reader and `verify_sealed` can take the pair directly —
# unlike the index, where a file was replaced and the file LIST changed.
# Builders stay strict: extending a v2 artifact would fuse 38-byte rows
# into a 37-byte file, which is not a format question but a corruption.
READ_TAGS = (FORMAT_TAG, "outpoint-derived-v2")
LEGACY_VAL = 8
STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
RUNS_DIR = "runs"

# Satoshi fields follow the index: u56, not u64 (see the comment on
# VALUE_REC there — a consensus bound carrying a layout, declared, with
# a loud refusal at every write site instead of a quiet truncation).
VAL = oi.VALUE_REC
HIST_VAL = 20 + ORD + ORD            # where the value starts in a row

HIST_REC = 20 + ORD + ORD + VAL      # lock | out_ord | spender | value
HIST_KEY = 20                        # searched by lock…
HIST_DEDUP = 25                      # …deduplicated by (lock, out_ord)
HIST_EVERY = 1024                    # ~40 KB bucket
SPRUN_REC = ORD + ORD + VAL          # spender | out_ord | value (runs)
TXIN_REC = ORD + ORD                 # spender | out_ord (final)
TXIN_EVERY = 4096                    # ~40 KB bucket
FEE_REC = VAL

UNSPENT = bytes(ORD)                 # spender 0 = tx 0 = a coinbase

FP_ORDER = ("history", "tx_inputs", "fees")

# Every ladder these derivatives carry, logical name → (record width,
# key length, sampling step): what `verify` needs to rebuild each one
# from the file it indexes instead of taking the seal's word for it.
# fees.bin is read positionally and has none.
LADDERS = {"history": (HIST_REC, HIST_KEY, HIST_EVERY),
           "tx_inputs": (TXIN_REC, ORD, TXIN_EVERY)}

# The same table for a v2 artifact, whose history row is one byte wider.
# The file LIST is identical across the two versions — which is what lets
# `verify_sealed` take the tag pair — but a ladder is rebuilt FROM its
# file, so its spec has to carry that file's actual record width.
LEGACY_LADDERS = {"history": (HIST_VAL + LEGACY_VAL, HIST_KEY, HIST_EVERY),
                  "tx_inputs": (TXIN_REC, ORD, TXIN_EVERY)}
PHASES = ("scan", "merge-history", "merge-inputs", "seal", "sealed")


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def _new_state():
    return {
        "format": FORMAT_TAG,
        "phase": "scan",
        # Cursors into the source index, all plain record counts: the
        # whole resume story is "reopen the streams here".
        "out_pos": 0,
        "spend_pos": 0,
        "tx_pos": 0,
        "out_sums_base": None,       # first tx of the open cycle
        "out_sums_records": 0,
        "source_fingerprint": None,  # binds an OPEN cycle to its index
        "run_seq": 0,
        # runs / files / caches / generation: the store's four keys.
        **new_state_fields(),
        "totals": {"updated_rows": 0, "total_fees_sats": 0,
                   "input_sats": 0},
    }


def _store(derived_dir, state, clock=None):
    """These derivatives' append-and-fuse store. Same machinery as the
    index's, a different directory and a different projection: history
    rows are searched by lock but deduplicated on (lock, ordinal), so
    `fuse` gets HIST_KEY and HIST_DEDUP separately."""
    return GenStore(derived_dir, state, label="derived",
                    error=OutpointError, runs_dir=RUNS_DIR,
                    state_name=STATE_NAME, clock=clock)


def _load_state(derived_dir, required=True, accept=(FORMAT_TAG,)):
    path = os.path.join(derived_dir, STATE_NAME)
    if not os.path.exists(path):
        if required:
            raise OutpointError(f"no {STATE_NAME} in {derived_dir}: "
                                "run `build` first")
        return None
    with open(path) as f:
        state = json.load(f)
    found = state.get("format")
    if found not in accept:
        if found in READ_TAGS:
            raise OutpointError(
                f"these derivatives are {found} and this build emits "
                f"{FORMAT_TAG}: satoshi fields are one byte narrower "
                "now, so extending or rewinding them as the new format "
                "would fuse records of two widths into one file. Read "
                "them, or build a fresh directory")
        raise OutpointError("unknown derivatives state format")
    return state


def _load_manifest(derived_dir, accept=(FORMAT_TAG,)):
    path = os.path.join(derived_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        raise OutpointError(f"no {MANIFEST_NAME} in {derived_dir}: "
                            "the derivatives are not sealed — run "
                            "`build`")
    with open(path) as f:
        manifest = json.load(f)
    if manifest.get("format") not in accept:
        raise OutpointError("unknown derivatives manifest format")
    return manifest


def _appended_sizes(state):
    """tx_inputs.bin, fees.bin and the out_sums temp grow in place, so
    the store must cut whatever sits past their committed size. Their
    record counts live in different corners of the state, which is why
    the list is built here and not there."""
    return [("tx_inputs.bin",
             state["files"].get("tx_inputs", {}).get("records", 0)
             * TXIN_REC),
            ("fees.bin",
             state["files"].get("fees", {}).get("records", 0)
             * FEE_REC),
            ("out_sums.tmp.bin", state["out_sums_records"] * 8)]


# ---------------------------------------------------------------------------
# Phase 1: scan — the aligned pass over the index
# ---------------------------------------------------------------------------

def _index_stream(index, logical, rec, start):
    """One of the index's files as a record stream, sha-verified when
    read whole; a resumed (offset) stream cannot be — the derivative
    seal is the audit that closes that honesty gap."""
    entry = index.build["files"][logical]
    return read_fixed(os.path.join(index.dir, entry["file"]), rec,
                      expect_sha=entry["sha256"] if start == 0 else None,
                      start_record=start, error=OutpointError)


class _ForwardOutputs:
    """A sliding window over the index's outputs.bin, for an ASCENDING
    stream of ordinals.

    The append path asks for the (value, lock) of every OLD output its
    new blocks spend, in the order the spend walk yields them — which is
    ascending, because spender_of.bin is indexed by it. One
    positioned read per ordinal pays a network round-trip for 28 bytes,
    up to hundreds of millions of times per append; a window slid only
    forward turns a dense update stream into one sequential pass over
    the file and a sparse one into far fewer, far larger reads."""

    WINDOW = 4 * 2**20

    def __init__(self, index):
        self.f = open(oi._positional_path(index.dir, "outputs"), "rb")
        self.base = 0
        self.buf = b""

    def close(self):
        self.f.close()

    def fetch(self, out_ord):
        """→ (value_sats, lock). `out_ord` must not decrease between
        calls; the window only ever moves forward."""
        off = out_ord * oi.OUT_REC
        if not (self.base <= off
                and off + oi.OUT_REC <= self.base + len(self.buf)):
            self.f.seek(off)
            self.buf = self.f.read(self.WINDOW)
            self.base = off
            if len(self.buf) < oi.OUT_REC:
                raise OutpointError(
                    f"outputs.bin: short read at ordinal {out_ord}")
        i = off - self.base
        rec = self.buf[i:i + oi.OUT_REC]
        return (int.from_bytes(rec[0:oi.VALUE_REC], "big"),
                rec[oi.VALUE_REC:])


def _phase_scan(index, store, flush_records, checkpoint_every):
    derived_dir, state = store.dir, store.state
    man = index.build
    n_out_t, n_tx_t = man["outputs"], man["transactions"]
    n_sp_t = man["spends"]
    out_pos, spend_pos = state["out_pos"], state["spend_pos"]
    tx_pos = state["tx_pos"]
    if out_pos > n_out_t or spend_pos > n_out_t or tx_pos > n_tx_t:
        raise OutpointError("state cursors are past the index: this "
                            "is not the index the build started on")
    # Whether the index has grown is read on the APPEND-ONLY files: an
    # output and a transaction keep their ordinal forever, so these two
    # cursors mean the same thing across generations. The spend cursor
    # does not (see below) and must not be asked.
    if out_pos == n_out_t and tx_pos == n_tx_t:
        return False                       # nothing new to scan

    store.make_runs_dir()
    if state["out_sums_base"] is None:
        # A NEW CYCLE OPENS. outputs.bin and tx_first_out.bin only ever
        # grow at the tail, so their cursors survive an index append
        # untouched. The SLOT CURSOR does not, and the reason is not
        # the one v2 had. spender_of.bin is positional and its slots
        # never move, so it is tempting to keep the cursor across an
        # append — and wrong: a new block almost always spends outputs
        # older than the newest one, and each such spend MUTATES A SLOT
        # BELOW THE CURSOR. The cycle therefore re-reads
        # spender_of.bin from the start and keeps the edges whose SPENDER
        # is one of its own transactions. That is an exact partition of
        # the file: every edge belongs to the cycle that scanned its
        # spender, an old transaction can never gain an input, and a
        # transaction's inputs never change.
        state["out_sums_base"] = tx_pos
        spend_pos = state["spend_pos"] = 0

    outs = _index_stream(index, "outputs", oi.OUT_REC, out_pos)
    slots = _index_stream(index, "spender_of", oi.SPENDER_REC, spend_pos)
    tfo = _index_stream(index, "tx_first_out", oi.TFO_REC, tx_pos)
    cycle_base5 = state["out_sums_base"].to_bytes(ORD, "big")

    # Checkpoints sit on transaction boundaries, so the resumed tx's
    # first output must be exactly where the output cursor stands.
    first = next(tfo, None)
    if first is None or int.from_bytes(first, "big") != out_pos:
        raise OutpointError("scan cursors do not sit on a tx boundary "
                            "— state does not match the index")
    nb = next(tfo, None)
    boundary = int.from_bytes(nb, "big") if nb is not None else n_out_t

    hist_buf, sprun_buf = [], []
    osums_buf = bytearray()
    cur_sum = 0
    last_cp_out = out_pos
    last_cp_time = time.monotonic()
    checkpoint_due = False

    def next_spend():
        """The next edge THIS cycle owns, as (output | spender), from
        the slot cursor on.

        The cursor is now simply an OUTPUT ORDINAL: spender_of.bin has
        one slot per output, in output order, so the position and the
        key are the same number and the old bookkeeping (a cursor that
        counted stepped-over records because it was a position in a
        file that got re-sorted) is gone with the file it described.
        Slots owned by an earlier cycle are still stepped over, and the
        record returned is the one buffered next and never one already
        digested, so a checkpoint resumes exactly here.

        The marker is refused, not represented: an output with more
        than one spender is an anomaly the INDEX records and counts,
        and derivatives are built on publication-grade sources only
        (INVARIANTS). This is the same refusal the v2 code made when it
        saw two rows with one key — the same rule, at the same layer,
        reading a different shape."""
        nonlocal spend_pos
        for slot in slots:
            if slot == oi.SLOT_MANY:
                raise OutpointError(
                    f"output ordinal {spend_pos} has MORE THAN ONE "
                    "spender: this index records a duplicate_spends "
                    "anomaly, and derivatives computed over one would "
                    "be numbers that look true. Fix the source, do not "
                    "derive from it")
            if slot != UNSPENT and slot >= cycle_base5:
                return spend_pos.to_bytes(ORD, "big") + slot
            spend_pos += 1              # unspent, or an earlier cycle's
        return None

    def flush_run(cat, records):
        state["run_seq"] += 1
        name = f"run_{state['run_seq']:06d}_{cat}.bin"
        store.write_run(name, cat, records)

    def checkpoint():
        nonlocal last_cp_out, last_cp_time
        if hist_buf:
            flush_run("history", hist_buf)
            hist_buf.clear()
        if sprun_buf:
            flush_run("spends", sprun_buf)
            sprun_buf.clear()
        if osums_buf:
            with open(os.path.join(derived_dir, "out_sums.tmp.bin"),
                      "ab") as f:
                f.write(osums_buf)
            state["out_sums_records"] += len(osums_buf) // 8
            osums_buf.clear()
        state["out_pos"], state["spend_pos"] = out_pos, spend_pos
        state["tx_pos"] = tx_pos
        store.write_state()
        # The rate of THIS interval: outputs since the last checkpoint
        # over the time since the last checkpoint. Dividing an interval
        # numerator by the time since the phase began (which is what a
        # never-reset `started` gives) understates the rate by orders
        # of magnitude as the run goes on.
        now = time.monotonic()
        rate = (out_pos - last_cp_out) / max(now - last_cp_time, 1e-9)
        print(f"scan @ output {out_pos:>13,}/{n_out_t:,} "
              f"| {rate:,.0f} out/s", file=sys.stderr)
        last_cp_out, last_cp_time = out_pos, now

    old_outputs = _ForwardOutputs(index)

    def emit_update(sp_rec):
        """A NEW spend of an output from a previous cycle: re-emit its
        row with the spender set. Same key, and the spent row sorts
        above the old unspent one (spender 0), so the fusion's
        keep-last quietly replaces it — append equals rebuild."""
        nonlocal spend_pos
        so = int.from_bytes(sp_rec[:ORD], "big")
        value, lock = old_outputs.fetch(so)
        hist_buf.append(lock + sp_rec[:ORD] + sp_rec[ORD:2 * ORD]
                        + value.to_bytes(VAL, "big"))
        sprun_buf.append(sp_rec[ORD:2 * ORD] + sp_rec[:ORD]
                         + value.to_bytes(VAL, "big"))
        spend_pos += 1

    spend_rec = next_spend()
    for out_rec in outs:
        while out_pos == boundary:        # crossed into the next tx
            osums_buf += cur_sum.to_bytes(8, "big")
            cur_sum = 0
            tx_pos += 1
            nb = next(tfo, None)
            boundary = (int.from_bytes(nb, "big") if nb is not None
                        else n_out_t)
            if checkpoint_due:            # boundaries are safe points
                checkpoint()
                checkpoint_due = False
        # One conversion per output: the two loop conditions and the
        # row below all want the same five bytes, and this loop runs
        # once per output of the chain.
        out5 = out_pos.to_bytes(ORD, "big")
        while spend_rec is not None and spend_rec[:ORD] < out5:
            emit_update(spend_rec)
            spend_rec = next_spend()
        spender = UNSPENT
        # One slot per output, so at most one edge can name this
        # ordinal: the "spent twice" case cannot reach here any more,
        # because the shape cannot express it. It is caught upstream by
        # next_spend, on the marker, which is where the index put it.
        if spend_rec is not None and spend_rec[:ORD] == out5:
            spender = spend_rec[ORD:2 * ORD]
            spend_pos += 1
            spend_rec = next_spend()
        value = out_rec[:oi.VALUE_REC]
        lock = out_rec[oi.VALUE_REC:]
        hist_buf.append(lock + out5 + spender + value)
        if spender != UNSPENT:
            sprun_buf.append(spender + out5 + value)
        cur_sum += int.from_bytes(value, "big")
        out_pos += 1
        if (len(hist_buf) + len(sprun_buf) >= flush_records
                or out_pos - last_cp_out >= checkpoint_every):
            checkpoint_due = True

    # Trailing spends can only be updates of old outputs (an append
    # whose new blocks spend more than they create cannot happen —
    # every block has a coinbase — but the drain is still written). A
    # slot past the watermark is no longer possible to express: the
    # file has exactly n_out slots, and the length check below is what
    # says so.
    while spend_rec is not None:
        emit_update(spend_rec)
        spend_rec = next_spend()

    osums_buf += cur_sum.to_bytes(8, "big")    # the last open tx
    tx_pos += 1
    if tx_pos != n_tx_t or next(tfo, None) is not None:
        raise OutpointError("transaction walk did not end on the "
                            "index totals — corrupt index")
    # The cycle walked spender_of.bin to its last SLOT: the cursor is a
    # file position, so this closes the partition — every edge was
    # either kept by this cycle or recognised as an earlier one's. The
    # total is now the output count, because the file holds one slot
    # per output and not one record per edge.
    if spend_pos != n_out_t:
        raise OutpointError(
            f"the spend walk stopped at slot {spend_pos} of "
            f"{n_out_t} — corrupt index")
    old_outputs.close()
    checkpoint()
    return True


# ---------------------------------------------------------------------------
# Phase 3: merge-inputs — tx_inputs, fees and the fee arithmetic
# ---------------------------------------------------------------------------

def _phase_merge_inputs(store):
    derived_dir, state = store.dir, store.state
    base = state["out_sums_base"]
    if base is None:
        raise OutpointError("no open cycle: scan must run first")
    end_tx = base + state["out_sums_records"]

    todo = store.run_sources("spends")
    slab = budgeted_slab(max(len(todo), 1))
    stream = heapq.merge(*[store.read(p, SPRUN_REC, sha, slab)
                           for p, sha in todo])

    txin_prev = state["files"].get(
        "tx_inputs", {"file": "tx_inputs.bin", "records": 0})
    fees_prev = state["files"].get(
        "fees", {"file": "fees.bin", "records": 0})
    if fees_prev["records"] != base:
        raise OutpointError("fees.bin does not end where this cycle "
                            "begins — state corrupted")

    txin_buf, fee_buf = bytearray(), bytearray()
    txin_records = 0
    input_sats = 0
    fee_sats = 0
    t = base
    base5 = base.to_bytes(ORD, "big")
    end5 = end_tx.to_bytes(ORD, "big")

    with open(os.path.join(derived_dir, "out_sums.tmp.bin"), "rb") as \
            osums, \
            open(os.path.join(derived_dir, "tx_inputs.bin"), "ab") as \
            txin_f, \
            open(os.path.join(derived_dir, "fees.bin"), "ab") as fee_f:

        def out_sum_next():
            data = osums.read(8)
            if len(data) != 8:
                raise OutpointError("out_sums temp shorter than the "
                                    "transaction walk — corrupt state")
            return int.from_bytes(data, "big")

        def fee_row(fee):
            nonlocal t, fee_sats
            if fee > oi.MAX_VALUE:
                raise OutpointError(
                    f"a fee of {fee} satoshis is past the "
                    f"{oi.MAX_VALUE} a u56 field holds — more than the "
                    "whole supply, so the source is not consensus data")
            fee_buf.extend(fee.to_bytes(VAL, "big"))
            fee_sats += fee
            t += 1
            if len(fee_buf) >= IO_CHUNK:
                fee_f.write(fee_buf)
                fee_buf.clear()

        cur, in_sum, prev10 = None, 0, None
        for rec in stream:
            sp5 = rec[:ORD]
            if not base5 <= sp5 < end5:
                raise OutpointError(
                    "a spender outside this cycle's transactions — an "
                    "old tx cannot gain inputs, this is corruption")
            if sp5 != cur:
                if cur is not None:
                    fee = in_sum - out_sum_next()
                    if fee < 0:
                        raise OutpointError(
                            f"negative fee at tx ordinal {t}: inputs "
                            "worth less than outputs — corrupt data")
                    fee_row(fee)
                while t < int.from_bytes(sp5, "big"):
                    out_sum_next()          # keep the temp in step
                    fee_row(0)              # no inputs: a coinbase
                cur, in_sum = sp5, 0
            if rec[:TXIN_REC] == prev10:
                raise OutpointError("duplicate (spender, output) edge "
                                    "— corrupt runs")
            prev10 = rec[:TXIN_REC]
            txin_buf.extend(rec[:TXIN_REC])
            txin_records += 1
            in_sum += int.from_bytes(rec[ORD + ORD:], "big")
            input_sats += int.from_bytes(rec[ORD + ORD:], "big")
            if len(txin_buf) >= IO_CHUNK:
                txin_f.write(txin_buf)
                txin_buf.clear()
        if cur is not None:
            fee = in_sum - out_sum_next()
            if fee < 0:
                raise OutpointError(f"negative fee at tx ordinal {t}")
            fee_row(fee)
        while t < end_tx:
            out_sum_next()
            fee_row(0)
        txin_f.write(txin_buf)
        fee_f.write(fee_buf)

    delete = store.drop_runs("spends")
    state["files"]["tx_inputs"] = {
        "file": "tx_inputs.bin",
        "records": txin_prev["records"] + txin_records}
    state["files"]["fees"] = {"file": "fees.bin", "records": end_tx}
    state["totals"]["input_sats"] += input_sats
    state["totals"]["total_fees_sats"] += fee_sats
    return delete


# ---------------------------------------------------------------------------
# Phase 4: seal — audit, invariants, manifest
# ---------------------------------------------------------------------------

def _phase_seal(store, index):
    derived_dir, state = store.dir, store.state
    man = index.manifest
    ibuild = index.build
    files = {}

    # history: sha audit + the per-lock statistics in the same read.
    entry = state["files"]["history"]
    if entry["records"] != ibuild["outputs"]:
        raise OutpointError(
            f"history.bin holds {entry['records']} rows but the index "
            f"has {ibuild['outputs']} outputs: exactly one row per output "
            "is the format's first invariant")
    spent_sats = 0
    spent_rows = 0
    locks = 0
    prev_lock = None
    for rec in store.read(store.path(entry["file"]),
                              HIST_REC, entry["sha256"]):
        if rec[:HIST_KEY] != prev_lock:
            locks += 1
            prev_lock = rec[:HIST_KEY]
        if rec[25:30] != UNSPENT:
            spent_rows += 1
            spent_sats += int.from_bytes(rec[HIST_VAL:], "big")
    files["history"] = dict(entry)

    # The cross-file identity: the satoshis history says were spent
    # must equal the satoshis the fee arithmetic consumed — two
    # independent walks meeting on one number.
    if spent_sats != state["totals"]["input_sats"]:
        raise OutpointError(
            f"history says {spent_sats} sats were spent but the fee "
            f"walk consumed {state['totals']['input_sats']} — the two "
            "roads MUST meet; do not use this build")
    if spent_rows != ibuild["spends"]:
        raise OutpointError("spent-row count does not match the "
                            "index's spend count")

    # tx_inputs: sha + ladder sampled in the same audit read.
    entry = state["files"]["tx_inputs"]
    if entry["records"] != ibuild["spends"]:
        raise OutpointError("tx_inputs.bin does not hold one row per "
                            "spend")
    # Hashed by slab and sampled by record in one read, by the same
    # function `verify` will use to rebuild this ladder: one rule, one
    # implementation, so the two can never disagree.
    sha, ladder = sha_and_ladder(store.path(entry["file"]),
                                 *LADDERS["tx_inputs"], OutpointError)
    files["tx_inputs"] = dict(entry, sha256=sha)
    lad_path = os.path.join(derived_dir, "tx_inputs.lad")
    tmp = lad_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(ladder)
    os.replace(tmp, lad_path)
    state["caches"]["tx_inputs"] = {
        "file": "tx_inputs.lad", "every": TXIN_EVERY,
        "sha256": hashlib.sha256(ladder).hexdigest()}

    # fees: sha + the totals must re-add to the committed number.
    entry = state["files"]["fees"]
    if entry["records"] != ibuild["transactions"]:
        raise OutpointError("fees.bin does not hold one row per "
                            "transaction")
    digest = hashlib.sha256()
    fee_sum = 0
    for slab in read_slabs(store.path(entry["file"]), FEE_REC,
                           error=OutpointError):
        digest.update(slab)              # once per slab, not per fee
        for i in range(0, len(slab), FEE_REC):
            fee_sum += int.from_bytes(slab[i:i + FEE_REC], "big")
    if fee_sum != state["totals"]["total_fees_sats"]:
        raise OutpointError("fees.bin does not re-add to the committed "
                            "fee total")
    files["fees"] = dict(entry, sha256=digest.hexdigest())

    identity = make_identity(
        FORMAT_TAG, 1, man["identity"]["coverage"]["to"],
        ((name, files[name]["sha256"]) for name in FP_ORDER))

    manifest = seal_manifest(FORMAT_TAG, identity, {
            "producer": producer(),
            "seconds": store.clock.stamp(state),
            "parent": declared_parent(oi.FORMAT_TAG, man["fingerprint"]),
            "transactions": ibuild["transactions"],
            "outputs": ibuild["outputs"],
            "spends": ibuild["spends"],
            "totals": {
                "total_fees_sats": state["totals"]["total_fees_sats"],
                "input_sats": state["totals"]["input_sats"],
                "spent_outputs": spent_rows,
                "unspent_outputs": ibuild["outputs"] - spent_rows,
                "distinct_locks": locks,
                "updated_rows": state["totals"]["updated_rows"],
            },
            "files": files,
            "caches": state["caches"],
            "reconstruction": (
                "zip outputs.bin+spender_of.bin+tx_first_out.bin of the source "
                "index in ordinal order; one history row per output "
                "(spender 0 = unspent, appends re-emit spent rows and "
                "keep-last wins); spender-side records fused by (spender, "
                "out_ord) give tx_inputs and, against the per-tx output "
                "sums, fees; the identity is then sealed by the shared "
                "recipe in docs/contracts/Artifact.md"),
    })
    atomic_json(os.path.join(derived_dir, MANIFEST_NAME), manifest)

    # The state first, the deletion after — the store's own rule. The
    # old order removed the tmp with the zeroed counter only in memory,
    # so a kill before the caller's write_state left a state claiming
    # bytes of a file that was gone, and the next load refused it as
    # corruption.
    state["out_sums_records"] = 0
    state["out_sums_base"] = None
    state["source_fingerprint"] = None      # the cycle is closed
    store.write_state()
    tmp_path = os.path.join(derived_dir, "out_sums.tmp.bin")
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
    return manifest


# ---------------------------------------------------------------------------
# build — driving the phases
# ---------------------------------------------------------------------------

def run_build(index_dir, derived_dir, flush_records=8_000_000,
              checkpoint_every=5_000_000):
    """Drive the four phases from wherever the state says we are.
    Re-run after a crash (continues) or after the index has grown
    (appends): same code path, same bytes as a rebuild."""
    index = oi.Index(index_dir)
    try:
        # The reader accepts a v2 index, on purpose: the published
        # artifacts must stay readable. A BUILD is a different promise.
        # This walk needs the spend side laid out per output, which a v2
        # index does not have, and there is no honest way to fake it —
        # so the refusal is stated here, where the source is named,
        # rather than as a KeyError three frames down on a file that
        # simply is not there.
        if index.format != oi.FORMAT_TAG:
            raise OutpointError(
                f"that index is {index.format} and this tool builds "
                f"derivatives from {oi.FORMAT_TAG}: its spend side is a "
                "sorted (output, spender) file, not one slot per "
                "output. Rebuild the index with this version, or read "
                "the old pair with the version that wrote it")
        if index.build["totals"]["unresolved_spends"]:
            raise OutpointError(
                "the source index tolerates unresolved spends: fees "
                "and histories built on holes would be plausible lies "
                "— derivatives require a strict index")
        os.makedirs(derived_dir, exist_ok=True)
        state = _load_state(derived_dir, required=False)
        if state is None:
            state = _new_state()
        # Sealed already means this run is an APPEND, and the phase is
        # about to be reset to make the two paths one: read the verb off
        # it while the difference is still visible.
        clock = WallClock(
            "append" if state["phase"] == "sealed" else "build", state)
        store = _store(derived_dir, state, clock=clock)
        store.clean_orphans()
        store.truncate_appended(_appended_sizes(state))
        if state["phase"] == "rewind":
            raise OutpointError(
                f"a rewind to height {state['rewind']['height']:,} was "
                "interrupted: finish it with `rewind` before building "
                "again, or this build would extend half-cut files")
        if state["phase"] == "sealed":
            state["phase"] = "scan"
        if state["source_fingerprint"] is None:
            state["source_fingerprint"] = index.manifest["fingerprint"]
        elif (state["source_fingerprint"]
              != index.manifest["fingerprint"]):
            raise OutpointError(
                "the index changed while a derivatives build was open "
                "— finish that build against its original index, or "
                "start a fresh directory")

        while state["phase"] != "sealed":
            phase = state["phase"]
            if phase == "scan":
                grew = _phase_scan(index, store, flush_records,
                                   checkpoint_every)
                if not grew and "history" in state["files"] \
                        and not state["runs"]:
                    state["phase"] = "sealed"
                    state["source_fingerprint"] = None
                    store.write_state()
                    print("nothing to do: derivatives already cover "
                          f"the index at height "
                          f"{index.watermark:,}")
                    return
                state["phase"] = "merge-history"
                store.write_state()
            elif phase == "merge-history":
                dups, delete = store.fuse(
                    "history", (HIST_REC, HIST_KEY, HIST_EVERY),
                    "history", dedup="last", dedup_len=HIST_DEDUP)
                state["totals"]["updated_rows"] += dups
                state["phase"] = "merge-inputs"
                store.commit(delete)
                print(f"history: "
                      f"{state['files']['history']['records']:,} rows "
                      f"({dups:,} updated by this append)",
                      file=sys.stderr)
            elif phase == "merge-inputs":
                delete = _phase_merge_inputs(store)
                state["phase"] = "seal"
                store.commit(delete)
            elif phase == "seal":
                manifest = _phase_seal(store, index)
                state["phase"] = "sealed"
                store.write_state()
                _print_manifest(manifest)
        return _load_manifest(derived_dir)["fingerprint"]
    finally:
        index.close()


def run_rewind(index_dir, derived_dir):
    """Take sealed derivatives back to the height their index now
    covers, so that their bytes equal those of a build that had
    stopped there.

    There is no height argument on purpose: the derivatives have never
    chosen their own coverage, they follow the index. Rewind the index
    first (`index rewind`), then this brings its three files back to
    meet it — the same order in which a build extends them.

    history is the only file with something to undo rather than drop: a
    row whose spender lies above the cut was spent by a transaction
    that, at the target height, had not happened yet. Its five spender
    bytes go back to UNSPENT and its value stays where it is, which
    changes neither its key nor its place in the order."""
    index = oi.Index(index_dir)
    try:
        state = _load_state(derived_dir)
        if state["phase"] not in ("sealed", "rewind"):
            raise OutpointError(
                f"the derivatives are in phase {state['phase']}, not "
                "sealed: finish `build` before rewinding them")
        store = _store(derived_dir, state, clock=WallClock("rewind", state))
        store.clean_orphans()
        store.truncate_appended(_appended_sizes(state))
        man = index.manifest
        if state["phase"] != "rewind":
            _rewind_plan_derived(derived_dir, state, store, man)
        plan = state["rewind"]
        n_out_cut, n_tx_cut = plan["outputs"], plan["transactions"]
        n_sp_cut = plan["spends"]

        if "history" not in plan["done"]:
            out_cut = n_out_cut.to_bytes(ORD, "big")
            tx_cut = n_tx_cut.to_bytes(ORD, "big")
            spent = 0

            def sift(rec):
                nonlocal spent
                if rec[HIST_KEY:HIST_DEDUP] >= out_cut:
                    return None                  # the output is not there yet
                if rec[HIST_DEDUP:HIST_DEDUP + ORD] >= tx_cut:
                    rec = rec[:HIST_DEDUP] + UNSPENT + rec[30:]
                elif rec[HIST_DEDUP:HIST_DEDUP + ORD] != UNSPENT:
                    spent += int.from_bytes(rec[HIST_VAL:], "big")
                return bytes(rec)

            dups, delete = store.fuse(
                "history", (HIST_REC, HIST_KEY, HIST_EVERY), "history",
                dedup="last", dedup_len=HIST_DEDUP, sift=sift)
            # The satoshis the fee walk must agree with at seal, counted
            # on the rows that survive: the identity is recomputed, not
            # carried over from a coverage that no longer exists.
            state["totals"]["input_sats"] = spent
            plan["done"].append("history")
            store.commit(delete)

        if "positional" not in plan["done"]:
            # The dropped fee tail is read BEFORE anything moves: it is
            # a few records against re-reading the whole surviving file,
            # and the seal repeats the full re-add anyway, so the one
            # independent road is kept where it was.
            dropped = 0
            with open(store.path("fees.bin"), "rb") as f:
                f.seek(n_tx_cut * FEE_REC)
                while True:
                    tail = f.read(8 * 2**20)
                    if not tail:
                        break
                    for i in range(0, len(tail), FEE_REC):
                        dropped += int.from_bytes(tail[i:i + FEE_REC],
                                                  "big")
            state["totals"]["total_fees_sats"] -= dropped
            for name, _rec, count in (("tx_inputs", TXIN_REC, n_sp_cut),
                                      ("fees", FEE_REC, n_tx_cut)):
                state["files"][name] = dict(state["files"][name],
                                            records=count)
            state["out_pos"], state["tx_pos"] = n_out_cut, n_tx_cut
            state["spend_pos"] = n_sp_cut
            state["out_sums_base"] = None
            state["out_sums_records"] = 0
            plan["done"].append("positional")
            # The state first, the truncations after: a kill in between
            # leaves the files LONGER than the committed sizes, which is
            # the direction truncate_appended heals on the next load.
            # The old order (truncate, then commit) turned the same kill
            # into a false "tampered with or lost data" refusal.
            store.write_state()
            for name, rec, count in (("tx_inputs", TXIN_REC, n_sp_cut),
                                     ("fees", FEE_REC, n_tx_cut)):
                with open(store.path(f"{name}.bin"), "ab") as f:
                    f.truncate(count * rec)

        del state["rewind"]
        state["phase"] = "seal"
        state["source_fingerprint"] = man["fingerprint"]
        store.write_state()
        manifest = _phase_seal(store, index)
        state["phase"] = "sealed"
        store.write_state()
        _print_manifest(manifest)
        return manifest["fingerprint"]
    finally:
        index.close()


def _rewind_plan_derived(derived_dir, state, store, man):
    """Refuse before moving a byte, then write the target into the
    state so a crash resumes instead of guessing."""
    ibuild = man["build"]
    index_height = man["identity"]["coverage"]["to"]
    if ibuild["totals"]["unresolved_spends"]:
        raise OutpointError(
            "the source index tolerates unresolved spends: derivatives "
            "over holes would be plausible lies")
    covered = _load_manifest(derived_dir)["identity"]["coverage"]["to"]
    if index_height >= covered:
        raise OutpointError(
            f"the index covers height {index_height:,} "
            f"and the derivatives {covered:,}: a rewind only ever "
            "removes, so rewind the index first, then these")
    if state["files"]["fees"]["records"] < ibuild["transactions"]:
        raise OutpointError(
            "the derivatives hold fewer transactions than the index: "
            "these two were never built together")
    state["rewind"] = {"height": index_height,
                       "outputs": ibuild["outputs"],
                       "transactions": ibuild["transactions"],
                       "spends": ibuild["spends"], "done": []}
    state["phase"] = "rewind"
    store.write_state()
    print(f"rewinding derivatives to height "
          f"{index_height:,}: "
          f"{state['files']['history']['records'] - ibuild['outputs']:,} "
          "history rows go", file=sys.stderr)


def _print_manifest(manifest):
    b = manifest["build"]
    t = b["totals"]
    print(f"derivatives sealed: heights "
          f"1..{manifest['identity']['coverage']['to']:,}")
    print(f"  history rows  {b['outputs']:>16,} "
          f"({t['spent_outputs']:,} spent, "
          f"{t['unspent_outputs']:,} unspent)")
    print(f"  distinct locks{t['distinct_locks']:>16,}")
    print(f"  tx inputs     {b['spends']:>16,}")
    print(f"  fees          {b['transactions']:>16,} txs, "
          f"{t['total_fees_sats'] / SAT:,.8f} BTC total")
    print(f"  source index: {manifest['build']['parent']['fingerprint']}"
          "  (declared)")
    print(f"fingerprint: {manifest['fingerprint']}")


# ---------------------------------------------------------------------------
# Reading: the Derived object (CLI here, address-check backends next)
# ---------------------------------------------------------------------------

class Derived:
    """Read side of sealed derivatives, bound to the Index they came
    from — the binding is CHECKED (fingerprints must match), because a
    history read against a different index would mix coordinate
    systems and answer nonsense with confidence."""

    def __init__(self, derived_dir, index):
        self.dir = derived_dir
        self.index = index
        self.manifest = _load_manifest(derived_dir, accept=READ_TAGS)
        self.format = self.manifest["format"]
        self.build = self.manifest["build"]
        # Declared by the format, never inferred from the file size: v2
        # stored satoshis as u64, v3 as u56, and the value is the tail
        # of the record either way.
        self.val = VAL if self.format == FORMAT_TAG else LEGACY_VAL
        self.hist_rec = HIST_VAL + self.val
        self.fee_rec = self.val
        parent = self.manifest["build"].get("parent")
        if (parent is None
                or parent["fingerprint"] != index.manifest["fingerprint"]):
            raise OutpointError(
                "these derivatives were built on a different index "
                "(fingerprints differ): append/rebuild them first")
        self._sorted = {}
        self._fees_fd = None

    def _sorted_file(self, name, rec, key_len):
        if name not in self._sorted:
            entry = self.build["files"][name]
            cache = self.build["caches"][name]
            with open(os.path.join(self.dir, cache["file"]), "rb") as f:
                blob = f.read()
            if hashlib.sha256(blob).hexdigest() != cache["sha256"]:
                raise OutpointError(f"{cache['file']}: corrupted ladder")
            self._sorted[name] = SortedFile(
                os.path.join(self.dir, entry["file"]), rec, key_len,
                entry["records"], blob, cache["every"], error=OutpointError)
        return self._sorted[name]

    def close(self):
        for sf in self._sorted.values():
            sf.close()
        self._sorted = {}
        if self._fees_fd is not None:
            os.close(self._fees_fd)
            self._fees_fd = None

    # -- the questions -----------------------------------------------------

    def rows(self, lock):
        """One lock's history rows, streamed in ordinal (= time)
        order: (out_ord, spender_tx | None, value_sats)."""
        sf = self._sorted_file("history", self.hist_rec, HIST_KEY)
        for rec in sf.scan(lock):
            spender = rec[25:30]
            yield (int.from_bytes(rec[20:25], "big"),
                   None if spender == UNSPENT
                   else int.from_bytes(spender, "big"),
                   int.from_bytes(rec[HIST_VAL:], "big"))

    def balance(self, lock):
        """(unspent outputs, satoshis) — the offline balance, no node
        asked."""
        n = sats = 0
        for _out, spender, value in self.rows(lock):
            if spender is None:
                n += 1
                sats += value
        return n, sats

    def fee(self, tx_ord):
        if self._fees_fd is None:
            self._fees_fd = os.open(
                os.path.join(self.dir, "fees.bin"), os.O_RDONLY)
        data = os.pread(self._fees_fd, self.fee_rec,
                        tx_ord * self.fee_rec)
        if len(data) != self.fee_rec:
            raise OutpointError("fees.bin: short read")
        return int.from_bytes(data, "big")

    def inputs_of(self, tx_ord):
        """The output ordinals a transaction consumed — [] for a
        coinbase."""
        sf = self._sorted_file("tx_inputs", TXIN_REC, ORD)
        return [int.from_bytes(r[ORD:], "big")
                for r in sf.scan(tx_ord.to_bytes(ORD, "big"))]


# ---------------------------------------------------------------------------
# stats / verify
# ---------------------------------------------------------------------------

def run_stats(derived_dir, out=sys.stdout):
    state = _load_state(derived_dir, accept=READ_TAGS)
    print(f"phase: {state['phase']}   cursors: "
          f"{state['out_pos']:,} outputs, {state['spend_pos']:,} "
          f"spends, {state['tx_pos']:,} txs", file=out)
    for name, entry in sorted(state["files"].items()):
        print(f"  {entry['file']:<22} {entry['records']:>14,} records",
              file=out)
    if state["runs"]:
        print(f"  {len(state['runs'])} unfused runs", file=out)
    t = state["totals"]
    print(f"  fees total {t['total_fees_sats']:,} sats, updated rows "
          f"{t['updated_rows']:,}", file=out)
    if state["phase"] == "sealed":
        print("fingerprint: "
              f"{_load_manifest(derived_dir, accept=READ_TAGS)['fingerprint']}",
              file=out)


def run_verify(derived_dir, index_dir=None):
    """Re-read every byte against the manifest: data files, ladders
    rebuilt from the files they index, and the fingerprint recomputed
    from what is actually on disk.

    With `--index`, two things get their second road at once. The
    coverage: these files hold ordinals, not heights, so nothing in them
    states the watermark, but the parent index writes one blocks.bin
    record per height. And the PARENT itself, which rides in `build` and
    is therefore a declaration until an index is handed over to confront
    it with. Without the flag the audit says both were taken on trust,
    and points at the flag that would settle them."""
    manifest = _load_manifest(derived_dir, accept=READ_TAGS)
    coverage = None
    if index_dir is not None:
        imanifest = oi._load_manifest(index_dir)
        # The parent's manifest must first agree with itself: comparing
        # two stored fingerprint strings confirms nothing if the one in
        # the parent was left behind by an edit of its identity block.
        if identity_fingerprint(imanifest["identity"]) != \
                imanifest["fingerprint"]:
            raise OutpointError(
                "the given index's manifest does not match its own "
                "identity block: nothing can be confirmed against it "
                "(run `index verify` on it)")
        parent = manifest["build"].get("parent")
        if parent is None or parent["fingerprint"] != imanifest["fingerprint"]:
            raise OutpointError(
                "that index is not this artifact's parent (fingerprints "
                "differ): the coverage cannot be checked against it")
        coverage = lambda: (                              # noqa: E731
            "exact", imanifest["identity"]["coverage"]["to"])
    # The comparison above already refused a mismatched parent, so
    # reaching this call with an index means the declaration WAS
    # confronted — and the report has to say so, or it tells the
    # operator to pass the very flag they passed.
    # The tag PAIR is legitimate here and was not for the index: both
    # versions are the same three files in the same order, which is the
    # condition verify_sealed states for a sequence. The LADDERS are a
    # different matter — they are rebuilt from their file, so their spec
    # must carry that file's real record width — and getting that wrong
    # showed up as "truncated record", not as a wrong digest.
    verify_sealed(derived_dir, manifest, READ_TAGS, OutpointError,
                  fp_order=FP_ORDER,
                  ladders=(LADDERS if manifest["format"] == FORMAT_TAG
                           else LEGACY_LADDERS),
                  coverage_from_data=coverage,
                  trust_hint="--index",
                  parent_confirmed=(True if index_dir is not None
                                    else None))


# ---------------------------------------------------------------------------
# The didactic windows: history, fee, cospends
# ---------------------------------------------------------------------------

def _open_pair(derived_dir, index_dir):
    index = oi.Index(index_dir)
    return Derived(derived_dir, index), index


def _lock_from_args(args):
    """The CLI takes a lock fingerprint or a raw scriptPubKey, NOT an
    address: decoding addresses (and explaining what each type means)
    is check_addresses.py's job — same boundary as the archive's
    lookup. Everything here is public chain data."""
    try:
        if args.lock:
            lock = bytes.fromhex(args.lock)
            if len(lock) != 20:
                raise OutpointError("--lock must be 20 hex bytes "
                                    "(hash160 of the scriptPubKey)")
            return lock
        return hash160(bytes.fromhex(args.spk))
    except ValueError:
        raise OutpointError("--lock/--spk take hex, and this is not hex")


def run_history(derived_dir, index_dir, lock, limit=100,
                out=sys.stdout):
    """One lock's story, as a reader sees it: events in time order —
    each row of history.bin unfolds into its receive and, when spent,
    its spend."""
    derived, index = _open_pair(derived_dir, index_dir)
    try:
        events = []              # (height, order, text)
        received = spent = n_rows = 0
        for out_ord, spender, value in derived.rows(lock):
            n_rows += 1
            h = index.height_of_output(out_ord)
            txid, vout, _ = index.outpoint_of(out_ord)
            op = f"{txid[::-1].hex()}:{vout}"
            received += value
            events.append((h, out_ord, 0,
                           f"IN   +{value / SAT:,.8f}  {op}"))
            if spender is not None:
                sh = index.height_of_tx(spender)
                spent += value
                events.append(
                    (sh, out_ord, 1,
                     f"OUT  -{value / SAT:,.8f}  {op} spent by "
                     f"{index.txid_of(spender)[::-1].hex()}"))
        if not n_rows:
            print(f"lock {lock.hex()}: never seen in confirmed "
                  f"history up to height {index.watermark:,}",
                  file=out)
            return
        events.sort(key=lambda e: e[:3])
        print(f"lock {lock.hex()} — {n_rows:,} outputs, "
              f"{len(events):,} events, index through height "
              f"{index.watermark:,}", file=out)
        shown = events if len(events) <= limit else events[-limit:]
        if len(events) > limit:
            print(f"  … {len(events) - limit:,} earlier events "
                  "omitted (--limit)", file=out)
        for h, _o, _k, text in shown:
            print(f"  height {h:>9,}  "
                  f"{_fmt_time(index.time_of_height(h))}  {text}",
                  file=out)
        n_utxo, sats = derived.balance(lock)
        print(f"received {received / SAT:,.8f}  spent "
              f"{spent / SAT:,.8f}  balance {sats / SAT:,.8f} BTC "
              f"in {n_utxo} unspent output(s)", file=out)
    finally:
        derived.close()
        index.close()


def _fmt_time(t):
    """A height's block time as a date. Shorter than the index's own
    (which prints the hour): a history line is about the day."""
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d")


def _txid_from_hex(hx):
    """A display-order txid string → serialized-order bytes, or None
    when it is not one. The CLI takes text from a human: a typo is an
    answerable question ("that is not a txid"), not a traceback —
    `nodsig index lookup` has always treated it that way."""
    try:
        raw = bytes.fromhex(hx)
    except ValueError:
        return None
    return raw[::-1] if len(raw) == 32 else None


def _tx_ord_of(index, txid):
    hit = index.resolve(txid)
    if hit is None:
        return None
    first_out, _n = hit
    return index.tx_of_output(first_out)


def run_fee(derived_dir, index_dir, txid_hexes, out=sys.stdout):
    derived, index = _open_pair(derived_dir, index_dir)
    try:
        for hx in txid_hexes:
            txid = _txid_from_hex(hx)
            if txid is None:
                print(f"{hx}: not a TXID (64 hex characters)", file=out)
                continue
            tx_ord = _tx_ord_of(index, txid)
            if tx_ord is None:
                print(f"{hx}: txid NOT in confirmed history up to the "
                      "watermark", file=out)
                continue
            if not derived.inputs_of(tx_ord):
                print(f"{hx}: coinbase — creates coins, pays no fee",
                      file=out)
                continue
            fee = derived.fee(tx_ord)
            print(f"{hx}: fee {fee:,} sat ({fee / SAT:,.8f} BTC)",
                  file=out)
    finally:
        derived.close()
        index.close()


def run_cospends(derived_dir, index_dir, arg, out=sys.stdout):
    """What was spent TOGETHER: the common-input hint, read from
    tx_inputs.bin. Takes a spending TXID, or TXID:VOUT to first find
    the transaction that spent that outpoint."""
    derived, index = _open_pair(derived_dir, index_dir)
    try:
        if ":" in arg:
            txid_hex, _, vout_s = arg.partition(":")
            txid = _txid_from_hex(txid_hex)
            vout = int(vout_s) if vout_s.isdigit() else None
            if txid is None or vout is None:
                print(f"{arg}: not TXID:VOUT (64 hex chars, colon, a "
                      "number)", file=out)
                return
            hit = index.resolve(txid)
            if hit is None:
                print(f"{arg}: txid NOT in confirmed history", file=out)
                return
            first_out, n_out = hit
            if vout >= n_out:
                print(f"{arg}: tx has only {n_out} outputs", file=out)
                return
            spenders = index.spenders(first_out + vout)
            if not spenders:
                print(f"{arg}: UNSPENT as of height "
                      f"{index.watermark:,} — nothing was co-spent "
                      "with it", file=out)
                return
            tx_ords = spenders
        else:
            txid = _txid_from_hex(arg)
            if txid is None:
                print(f"{arg}: not a TXID (64 hex characters)", file=out)
                return
            tx_ord = _tx_ord_of(index, txid)
            if tx_ord is None:
                print(f"{arg}: txid NOT in confirmed history", file=out)
                return
            tx_ords = [tx_ord]
        for tx_ord in tx_ords:
            ins = derived.inputs_of(tx_ord)
            h = index.height_of_tx(tx_ord)
            if not ins:
                print(f"{index.txid_of(tx_ord)[::-1].hex()} "
                      f"(height {h:,}): coinbase — spends nothing",
                      file=out)
                continue
            print(f"{index.txid_of(tx_ord)[::-1].hex()} "
                  f"(height {h:,}) spends {len(ins)} output(s) "
                  "together:", file=out)
            total = 0
            for so in ins:
                value, lock = index.output(so)
                txid, vout, _ = index.outpoint_of(so)
                total += value
                print(f"  {txid[::-1].hex()}:{vout}  "
                      f"{value / SAT:,.8f} BTC  lock {lock.hex()}",
                      file=out)
            fee = derived.fee(tx_ord)
            print(f"  in {total / SAT:,.8f} BTC, fee {fee:,} sat — "
                  "co-spent locks are a common-input HINT (Q2): same "
                  "spender, not proof of same owner (CoinJoin breaks "
                  "the assumption)", file=out)
    finally:
        derived.close()
        index.close()


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="History per lock, fee per transaction and "
                    "co-spends — the three derivatives of the "
                    "outpoint index.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pb = sub.add_parser("build", help="build or append the three "
                                      "derivatives from a sealed "
                                      "strict index")
    pb.add_argument("--index", required=True,
                    help="a sealed outpoint-index-v3 directory")
    pb.add_argument("--out", required=True,
                    help="the derivatives directory to create or grow")
    pb.add_argument("--flush-records", type=int, default=8_000_000,
                    help="buffered run records before a flush "
                         "(memory knob)")
    pb.add_argument("--checkpoint-every", type=int, default=5_000_000,
                    help="outputs between checkpoints in the scan")

    pr = sub.add_parser("rewind", help="bring sealed derivatives back "
                                       "to the height their index now "
                                       "covers")
    pr.add_argument("--index", required=True,
                    help="the source index, already rewound: it is the "
                         "one that names the target height")
    pr.add_argument("--derived", required=True)

    pt = sub.add_parser("stats", help="phase and counts (instant)")
    pt.add_argument("--derived", required=True)

    pv = sub.add_parser("verify", help="re-read everything against "
                                       "the manifest (full audit)")
    pv.add_argument("--derived", required=True)
    pv.add_argument("--index", help="the parent index, so the declared "
                                    "coverage can be confronted with the "
                                    "heights it actually holds")

    ph = sub.add_parser("history", help="one lock's whole story")
    ph.add_argument("--derived", required=True)
    ph.add_argument("--index", required=True)
    g = ph.add_mutually_exclusive_group(required=True)
    g.add_argument("--lock", help="hash160 of the scriptPubKey, hex")
    g.add_argument("--spk", help="raw scriptPubKey, hex (hashed here)")
    ph.add_argument("--limit", type=int, default=100,
                    help="most recent events to print (summary is "
                         "always complete)")

    pf = sub.add_parser("fee", help="TXID → its fee")
    pf.add_argument("--derived", required=True)
    pf.add_argument("--index", required=True)
    pf.add_argument("txids", nargs="+", metavar="TXID",
                    help="txid in display order")

    pc = sub.add_parser("cospends", help="TXID or TXID:VOUT → what "
                                         "was spent together")
    pc.add_argument("--derived", required=True)
    pc.add_argument("--index", required=True)
    pc.add_argument("target", metavar="TXID[:VOUT]")

    args = p.parse_args(argv)
    try:
        if args.cmd == "build":
            run_build(args.index, args.out,
                      flush_records=args.flush_records,
                      checkpoint_every=args.checkpoint_every)
        elif args.cmd == "rewind":
            run_rewind(args.index, args.derived)
        elif args.cmd == "stats":
            run_stats(args.derived)
        elif args.cmd == "verify":
            run_verify(args.derived, args.index)
        elif args.cmd == "history":
            run_history(args.derived, args.index,
                        _lock_from_args(args), limit=args.limit)
        elif args.cmd == "fee":
            run_fee(args.derived, args.index, args.txids)
        else:
            run_cospends(args.derived, args.index, args.target)
    except OutpointError as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
