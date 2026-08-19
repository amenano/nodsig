#!/usr/bin/env python3
"""
graphemit.py — co-emit the raw TRANSACTION GRAPH while a scan is
already streaming the chain, and read it back later.

Why this exists: the reuse scan pays the expensive part of reading
history — fetching every block and parsing every byte with full
integrity checks — and then keeps almost nothing (reuse_scan keeps one
bitmap, reveal_archive keeps the revelations). But the SAME parsed
bytes contain the whole transaction graph: which outputs every
transaction created (value + lock), and which previous outputs it
consumed. That graph is the raw material of every future on-chain
question — the payment history of an address, common-input clustering,
statistical watch on spends from keyless locks — and none of those
questions can be answered by an Electrum-style index, whose query
model is "one scripthash, one list of txids, online". Emitting the raw
records DURING a pass that is happening anyway costs local sequential
writes; rebuilding them later costs another multi-day pass over the
chain. So the choice was made (2026-07-11) to co-emit now.

What this module deliberately is NOT: an index. The records are kept
as faithful to the block as possible, in block order, with minimal
transformation — because a dumb emitter has a small surface for bugs,
and because every future index (by address, by cluster, by script
class) is a DERIVED artifact, rebuilt from these records with its own
one-page rule and its own fingerprint, per the card-index design that
grows in width. The emitter is a plug: any scanner that already
fetches and verifies blocks can host it (reuse_scan.py and
reveal_archive.py both accept --graph). Emission is OFF by default —
the lean pass stays possible for anyone who clones the tools and does
not want to spend the disk.

FROZEN FORMAT — graph-v2
========================
A graph archive is a directory: run files under `runs/`, a `state.json`
naming them, and (after `fingerprint`) a `manifest.json`. The archive's
CANONICAL FORM is the concatenation of the run files in height order:
one byte stream, defined by the chain and the height range alone. Run
boundaries are an artifact of buffering and checkpoints and are NOT
part of the format: an interrupted-and-resumed emission produces the
same stream, byte for byte, as a one-shot one.

The stream is a sequence of BLOCK RECORDS, one per block, ascending
heights starting at 1 (the genesis block is not emitted: its coinbase
is unspendable by consensus and creates no edge). All integers are
little-endian; all hashes are in SERIALIZED order (explorers display
the same bytes reversed); all counts and variable lengths use Bitcoin's
own compactsize encoding — the format echoes the block serialization
it distills.

    block record:
        height      u32
        block_hash  32 bytes   (sha256d of the header, serialized order)
        time        u32        (the header's timestamp, miner-declared)
        n_tx        compactsize
        n_tx × transaction record

    transaction record:
        txid        32 bytes   (serialized order)
        flags       1 byte     (bit 0 = coinbase; bits 1-7 reserved, 0)
        n_in        compactsize   — 0 for the coinbase: its "input" is
                    a null reference by construction, not an edge
        n_in × input record
        n_out       compactsize
        n_out × output record

    input record  (an EDGE of the graph: this tx consumes that output)
        prev_txid   32 bytes   (serialized order)
        prev_vout   u32

    output record  (a TILE of the graph: a coin is born)
        value       u64        (satoshis)
        script_len  compactsize
        script      script_len bytes   (the scriptPubKey, verbatim)

Excluded on purpose, with the reason on record: scriptSig and witness
(they are the REVELATIONS, archived by reveal_archive.py — the graph
is who pays whom, under which lock); version, locktime, sequence
(consensus bookkeeping, not flow; a future question that needs them is
a new derived scan, not a format change); fees (a JOIN of these very
records — input edges resolved against output tiles — so storing them
would be transformation, not fidelity). The records are uncompressed:
the canonical fingerprint is defined over these exact bytes, and
compression is the filesystem's business, not the format's.

Canonical fingerprint: the shared identity block of every artifact
here (format tag, covered heights, parent, and the digests of the
logical files in a fixed order, length-prefixed), where the graph
declares ONE logical file, `stream`, whose digest is the sha256 of the
whole record stream in height order with no tag of its own. Same chain
+ same end height ⇒ same fingerprint on anyone's machine — the graph's
twin of muhash, of the reuse bitmaps' fingerprint and of the reveal
archive's one. See artifact.py, which is the source of the recipe.

Size, measured against the 2026 chain (~1.3G transactions, ~3.5G
inputs, ~3.7G outputs): roughly 300-400 GB. The archive can live on a
NAS mount: writes are large sequential appends (the flush buffer,
hundreds of MB) at a rate far below LAN speed, and every file is
written tmp-then-rename in its final directory.

Subcommands:

    fingerprint   stream the whole archive (verifying every run's
                  recorded sha256), compute the canonical fingerprint,
                  write manifest.json. Doubles as an integrity audit.
    stats         watermark and record totals, from the state alone.
    show          decode a height range in human-readable form — the
                  didactic window on what one record really says.
    digest        the result of a --graph-digest check: whether a
                  rescan re-emitted the bytes this archive holds,
                  interval by interval.

Everything is standard library; blockparse is imported only for the
compactsize reader. The emitter never talks to the network: blocks
arrive already fetched and integrity-checked by the host scanner.
"""

import argparse
import hashlib
import json
import os
import sys

from nodsig.artifact import (WallClock, identity_fingerprint,
                             make_identity, producer, seal_manifest)
from nodsig.blockparse import read_compactsize, write_compactsize
from nodsig.recio import atomic_json

STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
DIGEST_STATE_NAME = "graph-digest.json"
RUNS_DIR = "runs"
FORMAT_TAG = "graph-v2"

# Emissions this reader accepts. The v1 → v2 break changed the SEAL (the
# identity block and the manifest built from it) and not one byte of the
# record stream, so a v1 emission is still exactly what it claims to be:
# it decodes, its per-run digests hold, and it can serve as the reference
# a --graph-digest check measures against. What it cannot do is act as a
# PARENT, because a v1 manifest's fingerprint comes from a recipe this
# major does not compute; `fingerprint --reseal` is what gives those same
# bytes a v2 identity. Only FORMAT_TAG is ever written.
READABLE_TAGS = ("graph-v1", "graph-v2")

FLAG_COINBASE = 1

# The null outpoint a coinbase names as its input. Built once: the
# comparison sits on the per-input path of every block of the chain,
# and allocating 32 fresh bytes to compare against is the kind of
# waste that only shows up at three billion inputs.
NULL_TXID = bytes(32)


class GraphError(RuntimeError):
    """Raised when the archive on disk cannot be trusted or cannot
    line up with the scan that wants to grow it. Like everywhere else
    in these tools: corruption or a mismatch must stop the run, never
    leak into data that could end up published."""


# ---------------------------------------------------------------------------
# Writing one record
# ---------------------------------------------------------------------------

def serialize_block_record(height, block):
    """One parsed block → its graph-v2 record, exactly as specified in
    the module docstring. Deliberately dumb: field for field, no
    decisions taken beyond dropping what the spec excludes — the
    format's whole bug surface is this one function."""
    out = bytearray()
    out += height.to_bytes(4, "little")
    out += block.header.hash
    out += block.header.time.to_bytes(4, "little")
    out += write_compactsize(len(block.transactions))
    for tx in block.transactions:
        coinbase = (len(tx.inputs) == 1
                    and tx.inputs[0].prev_txid == NULL_TXID
                    and tx.inputs[0].prev_vout == 0xFFFFFFFF)
        out += tx.txid
        out += bytes([FLAG_COINBASE if coinbase else 0])
        if coinbase:
            out += write_compactsize(0)
        else:
            out += write_compactsize(len(tx.inputs))
            for tx_in in tx.inputs:
                out += tx_in.prev_txid
                out += tx_in.prev_vout.to_bytes(4, "little")
        out += write_compactsize(len(tx.outputs))
        for tx_out in tx.outputs:
            out += tx_out.value.to_bytes(8, "little")
            out += write_compactsize(len(tx_out.script_pubkey))
            out += tx_out.script_pubkey
    return bytes(out)


# ---------------------------------------------------------------------------
# The emitter: the plug a scanner hosts
# ---------------------------------------------------------------------------

class GraphEmitter:
    """Grows a graph archive alongside a host scan.

    The contract with the host, in three calls:

        emitter = GraphEmitter(graph_dir)
        emitter.load(start_height)      # after the host resolved its
                                        # own resume point
        emitter.add_block(h, block)     # every verified block, in order
        emitter.checkpoint(h, hash_hex) # at the host's checkpoint, just
                                        # BEFORE the host writes its own
                                        # state

    Why "just before": if the process dies between the two writes, the
    graph state is AHEAD of the host's. load() heals every ahead case
    by dropping the runs past the host's resume point — a clean
    suffix, because checkpoint() always closes the open buffer, so
    every host checkpoint height is a run boundary; and no data is
    lost, because the host re-feeds every block from its resume point
    anyway (keeping the runs would emit those blocks TWICE). Dropping
    a run must also drop its counts, which is why the stats live PER
    RUN in the state and the totals are only ever a sum: there is no
    global counter to unwind. The opposite order (host first) would
    leave the graph BEHIND, missing blocks the host will never feed
    again — a hole no cleanup can heal, and the one misalignment
    load() refuses.

    Runs are flushed when the buffer passes `flush_bytes` (large, so a
    NAS-mounted archive sees few, big, sequential writes) and at every
    checkpoint. A run file the state does not name (a crash between
    flush and checkpoint) is deleted on load: what the state does not
    name does not exist, and its blocks will be emitted again.
    """

    # The clock of the pass that FEEDS this archive. A scan co-emits the
    # archive, the headers, the nonce census and this graph, and each one
    # records the same seconds under `scan` in its own state: four views of
    # one walk, which is exactly why WallClock's docstring says they must
    # never be added together. Carried per artifact, because an emission
    # can be switched on later than the others and then honestly owes less.
    clock = None

    def __init__(self, graph_dir, flush_bytes=256 * 2**20):
        self.dir = graph_dir
        self.flush_bytes = flush_bytes
        self.runs = []           # state entries, see _flush()
        self.buffer = []         # serialized records not yet in a run
        self.buffered_bytes = 0
        self.pending = None      # per-buffer counts, becomes the run's
        self.seg_start = None    # first height the open buffer covers
        self.watermark = 0       # last height in a CLOSED run
        self.last_hash = None    # display hex of the watermark's block

    # -- lifecycle ---------------------------------------------------------

    def load(self, start_height):
        """Open (or create) the archive and line it up with a scan that
        will feed blocks from `start_height` on."""
        os.makedirs(os.path.join(self.dir, RUNS_DIR), exist_ok=True)
        state_path = os.path.join(self.dir, STATE_NAME)
        # Built unconditionally: a FRESH archive has no state to carry a
        # total from, and it is exactly the first stretch of a long scan.
        # Building the clock only on the resume path would have left the
        # first session unmeasured, which is the session that matters most.
        self.clock = WallClock("scan")
        if os.path.exists(state_path):
            with open(state_path) as f:
                state = json.load(f)
            self.clock = WallClock("scan", state)
            if state.get("format") != FORMAT_TAG:
                # A readable earlier major is not an unknown format, and
                # saying "unknown" to the owner of a 300 GB archive
                # would hide the one command that opens the road.
                raise GraphError(
                    f"graph archive state says "
                    f"{state.get('format')!r}, not {FORMAT_TAG!r}"
                    + (": re-seal it first with `graph fingerprint "
                       "--reseal` (the bytes do not change, and the "
                       "state is relabelled with them)"
                       if state.get("format") in READABLE_TAGS
                       else ""))
            self.runs = state["runs"]
            self.watermark = state["last_height"]
            self.last_hash = state["last_block_hash"]

        # Crash leftovers: run files the state does not name.
        known = {r["name"] for r in self.runs}
        for name in os.listdir(os.path.join(self.dir, RUNS_DIR)):
            if name not in known:
                os.remove(os.path.join(self.dir, RUNS_DIR, name))
                print(f"  graph: removed stale run {name} "
                      "(not named by the state)", file=sys.stderr)

        # The ahead case: the graph knows heights the host's state does
        # not (the crash window between the two checkpoint writes, or
        # an archive paired with an older host state). The host will
        # re-feed every block from its resume point, so keeping these
        # runs would emit their blocks twice: dropping the suffix is
        # not data loss, it is the only state that can converge.
        keep, drop = [], []
        for run in self.runs:
            if run["start"] >= start_height:
                drop.append(run)
            elif run["end"] >= start_height:
                # Cannot happen if checkpoints were shared with the
                # host; refusing beats guessing where to cut a file.
                raise GraphError(
                    f"run {run['name']} straddles the resume height "
                    f"{start_height}: this archive did not grow with "
                    "this scan")
            else:
                keep.append(run)
        if drop:
            self.runs = keep
            self.watermark = keep[-1]["end"] if keep else 0
            # The recorded hash belonged to the dropped watermark; the
            # new one is unknown until the next checkpoint. Honest null
            # beats a stale value.
            self.last_hash = None
            # The state first, the deletions after: a kill in between
            # leaves files the state no longer names, which the stale
            # sweep above removes on the next load. The other order
            # left the state naming files that were already gone, and
            # every later start died on the missing one.
            self._write_state()
            for run in drop:
                path = os.path.join(self.dir, RUNS_DIR, run["name"])
                if os.path.exists(path):
                    os.remove(path)
                print(f"  graph: dropped run {run['name']} — past the "
                      "scan's resume point, will be re-emitted",
                      file=sys.stderr)

        self._check_tiling()
        if self.watermark != start_height - 1:
            raise GraphError(
                f"graph archive covers 1..{self.watermark} but the scan "
                f"resumes from {start_height}: the graph must grow with "
                "the SAME scan from the SAME height — use a fresh "
                "directory for a fresh scan (the flag cannot be turned "
                "on midway: the missed blocks would never come back)")
        self.seg_start = start_height
        self.pending = self._zero_counts()

    def _check_tiling(self):
        """The recorded runs must tile 1..watermark with no gap and no
        overlap — the property every reader relies on."""
        expect = 1
        for run in self.runs:
            if run["start"] != expect:
                raise GraphError(
                    f"graph runs do not tile the chain: expected a run "
                    f"starting at {expect}, found {run['name']}")
            expect = run["end"] + 1
        if self.runs and self.runs[-1]["end"] != self.watermark:
            raise GraphError("graph state watermark does not match "
                             "the last run")

    @staticmethod
    def _zero_counts():
        return {"blocks": 0, "transactions": 0, "inputs": 0,
                "outputs": 0, "bytes": 0}

    # -- feeding -----------------------------------------------------------

    def add_block(self, height, block):
        """Serialize one verified block into the open buffer. The host
        guarantees order and integrity; the emitter only refuses to
        write a hole."""
        expect = (self.seg_start + self.pending["blocks"]
                  if self.pending else None)
        if expect is None or height != expect:
            raise GraphError(f"graph emitter fed height {height}, "
                             f"expected {expect} (host bug)")
        record = serialize_block_record(height, block)
        self.buffer.append(record)
        self.buffered_bytes += len(record)
        self.pending["blocks"] += 1
        self.pending["transactions"] += len(block.transactions)
        for tx in block.transactions:
            # Only a coinbase names the null outpoint, and it has
            # exactly one input, so "inputs that are not coinbase
            # inputs" is the input count minus that one — no per-input
            # comparison, on a path that runs three billion times.
            ins = len(tx.inputs)
            if (ins == 1 and tx.inputs[0].prev_txid == NULL_TXID
                    and tx.inputs[0].prev_vout == 0xFFFFFFFF):
                ins = 0
            self.pending["inputs"] += ins
            self.pending["outputs"] += len(tx.outputs)
        self.pending["bytes"] += len(record)
        if self.buffered_bytes >= self.flush_bytes:
            self._flush(height)

    def _flush(self, through_height):
        """Close the open buffer into a run file named by the exact
        interval it covers — like the reveal archive, the name IS the
        append story: runs tile the chain. Atomic (tmp + rename), and
        the sha256 of the bytes goes into the state: the file is
        trusted for nothing when read back."""
        if not self.buffer:
            return
        name = f"run_{self.seg_start:08d}-{through_height:08d}.bin"
        path = os.path.join(self.dir, RUNS_DIR, name)
        digest = hashlib.sha256()
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            for record in self.buffer:
                f.write(record)
                digest.update(record)
        os.replace(tmp, path)
        entry = {"name": name, "start": self.seg_start,
                 "end": through_height, "sha256": digest.hexdigest()}
        entry.update(self.pending)
        self.runs.append(entry)
        self.buffer = []
        self.buffered_bytes = 0
        self.pending = self._zero_counts()
        self.seg_start = through_height + 1
        self.watermark = through_height

    def checkpoint(self, height, block_hash_display):
        """Everything emitted so far becomes durable and named. Called
        by the host right before it writes its own state (see the class
        docstring for why that order)."""
        self._flush(height)
        self.last_hash = block_hash_display
        self._write_state()

    def _write_state(self):
        tmp = os.path.join(self.dir, STATE_NAME + ".tmp")
        with open(tmp, "w") as f:
            st = {"format": FORMAT_TAG,
                  "last_height": self.watermark,
                  "last_block_hash": self.last_hash,
                  "runs": self.runs}
            if self.clock is not None:
                self.clock.stamp(st)
            json.dump(st, f, indent=1)
        os.replace(tmp, os.path.join(self.dir, STATE_NAME))

    def totals(self):
        """The archive's counts — always a sum over runs, never a
        stored global (see load() for why)."""
        totals = self._zero_counts()
        for run in self.runs:
            for k in totals:
                totals[k] += run[k]
        return totals


# ---------------------------------------------------------------------------
# The digest: the same plug, measuring instead of writing
# ---------------------------------------------------------------------------

class GraphDigest:
    """Grows nothing. Serializes exactly what GraphEmitter would have
    written and hashes it, to answer one question: would today's code
    emit the graph we already have?

    Why it exists. A rescan of the chain does not need to write the
    graph again — the data format did not change, so the archive on
    disk stays valid and is only re-sealed. But then nothing checks
    that the emitter still produces those bytes, and 301 GB is a lot
    of disk to spend on a non-regression test. This plug spends none:
    it rides the same scan, serializes each block, and throws the
    bytes away once they are in a hash.

    What it compares against, and why that is free. The reference
    archive's `state.json` already records a sha256 PER RUN, so the
    comparison needs no read of the reference at all: close an interval
    exactly where the reference closed a run, and the two digests are
    directly comparable. A mismatch is therefore reported the moment
    the scan crosses that boundary, and it names the interval, which is
    a great deal more useful than one number at the end of three days.
    Those recorded digests are worth exactly what the last
    `graph fingerprint` is worth: that pass re-reads every byte and
    checks each one against the file it names. Run it on the reference
    before trusting this. (It is the same pass that re-seals a v1
    archive into a v2 one, so it is on the path anyway.)

    Interruptions cost one interval, not the run. A scan resumes at its
    host's checkpoint, which almost never falls on a reference run
    boundary, so the interval straddling the restart cannot be
    completed. It is reported as SKIPPED and the check continues at the
    next boundary: an interrupted three-day scan still verifies all but
    a handful of intervals, and says which ones it did not.

    The whole-stream digest is also accumulated, and is comparable with
    `stream_digest()` and hence with the fingerprint, but only when the
    pass ran from height 1 in one go: sha256 keeps no state anyone can
    write down, so a resume voids that one number while leaving every
    interval intact. That asymmetry is the reason the intervals are the
    primary answer and the single digest is the bonus.

    Host contract, identical to GraphEmitter's, so a scanner hosts
    either without knowing which it holds.
    """

    def __init__(self, reference_dir, state_dir):
        self.reference_dir = reference_dir
        self.state_dir = state_dir
        self.ref = [dict(start=r["start"], end=r["end"], sha256=r["sha256"])
                    for r in _load_state(reference_dir)["runs"]]
        if not self.ref:
            raise GraphError(f"{reference_dir}: empty reference archive, "
                             "nothing to compare against")
        expect = 1
        for run in self.ref:
            if run["start"] != expect:
                raise GraphError("reference runs do not tile the chain: "
                                 f"expected a run starting at {expect}")
            expect = run["end"] + 1
        self.ref_watermark = self.ref[-1]["end"]

        self.results = []        # [{start, end, ok}] closed intervals
        self.skipped = []        # [[start, end]] straddled by a restart
        self.contiguous = True   # the whole-stream digest is meaningful
        self.whole = hashlib.sha256()
        self.beyond = 0          # heights past the reference watermark
        self.last_height = 0
        self.last_hash = None
        self._open = None        # the interval being accumulated
        self._next = 0           # index into self.ref
        self._expect = 1         # the only height add_block will accept

    # -- lifecycle ---------------------------------------------------------

    def _state_path(self):
        return os.path.join(self.state_dir, DIGEST_STATE_NAME)

    def load(self, start_height):
        """Line up with a scan that will feed blocks from
        `start_height` on."""
        path = self._state_path()
        if os.path.exists(path):
            with open(path) as f:
                state = json.load(f)
            if state.get("format") != FORMAT_TAG:
                raise GraphError("unknown graph digest state format")
            # The digest can only be AHEAD of the host, never behind,
            # because it is checkpointed first. Drop what the host is
            # about to feed again.
            self.results = [r for r in state["intervals"]
                            if r["end"] < start_height]
            self.skipped = [s for s in state["skipped"]
                            if s[1] < start_height]
            self.contiguous = False
        elif start_height > 1:
            # A digest measures the stream from height 1. Asked to join
            # one it never saw, it would look like this check while
            # measuring something else.
            raise GraphError(
                f"a graph digest cannot start at height {start_height}: "
                "it measures the stream from 1, so it has to see it from "
                "1 (scan into a fresh archive, or drop --graph-digest)")

        # Heights already past the reference need no digest and are
        # counted, not stored: the arithmetic is exact and survives any
        # number of restarts.
        self.beyond = max(0, (start_height - 1) - self.ref_watermark)

        # The reference run straddling a restart can never be completed,
        # so retire it by name and pick up at the next boundary.
        self._next = 0
        while (self._next < len(self.ref)
               and self.ref[self._next]["end"] < start_height):
            self._next += 1
        if (self._next < len(self.ref)
                and self.ref[self._next]["start"] < start_height):
            run = self.ref[self._next]
            self.skipped.append([run["start"], run["end"]])
            self._next += 1

        self._expect = start_height
        self.last_height = start_height - 1
        self._open = None
        return start_height

    # -- feeding -----------------------------------------------------------

    def add_block(self, height, block):
        """Serialize one verified block and fold it into the digests.
        Same refusal as the emitter: a hole is a host bug, not
        something to hash over."""
        if height != self._expect:
            raise GraphError(f"graph digest fed height {height}, expected "
                             f"{self._expect} (host bug)")
        self._expect = height + 1
        record = serialize_block_record(height, block)
        if self.contiguous:
            self.whole.update(record)

        if height > self.ref_watermark:
            self.beyond += 1
        else:
            if self._open is None and self._next < len(self.ref) \
                    and self.ref[self._next]["start"] == height:
                self._open = {"run": self.ref[self._next],
                              "digest": hashlib.sha256()}
            if self._open is not None:
                self._open["digest"].update(record)
                if height == self._open["run"]["end"]:
                    self._close_interval()
        self.last_height = height

    def _close_interval(self):
        run = self._open["run"]
        ok = self._open["digest"].hexdigest() == run["sha256"]
        self.results.append({"start": run["start"], "end": run["end"],
                             "ok": ok})
        self._open = None
        self._next += 1
        if not ok:
            print(f"  graph digest MISMATCH over heights "
                  f"{run['start']:,}..{run['end']:,}: this code does not "
                  "emit the bytes the reference archive holds",
                  file=sys.stderr)

    def checkpoint(self, height, block_hash_display):
        """Everything measured so far becomes durable, written before
        the host writes its own state (see GraphEmitter for why that
        order is the only safe one)."""
        self.last_hash = block_hash_display
        # No path here, and the absence is deliberate. This file lives
        # INSIDE an artifact directory, and an artifact is meant to be
        # handed to somebody: an absolute path names the disk it was
        # built on, which is exactly what `capability.Source` already
        # refuses to carry ("identity, not local topology"). Nothing
        # read this field back, so what a reader loses is nothing at
        # all; what the reference was is a question its own fingerprint
        # answers, and a fingerprint travels.
        atomic_json(self._state_path(),
                    {"format": FORMAT_TAG,
                     "last_height": self.last_height,
                     "last_block_hash": self.last_hash,
                     "contiguous": self.contiguous,
                     "stream_sha256": self.stream_fingerprint(),
                     "beyond": self.beyond,
                     "skipped": self.skipped,
                     "intervals": self.results})

    def totals(self):
        """What the check covered, as counts rather than as a result."""
        return {"intervals": len(self.results),
                "matched": sum(1 for r in self.results if r["ok"]),
                "mismatched": sum(1 for r in self.results if not r["ok"]),
                "skipped": len(self.skipped),
                "beyond_reference": self.beyond}

    def stream_fingerprint(self):
        """The whole-stream digest, or None if a resume voided it."""
        return self.whole.hexdigest() if self.contiguous else None

    def report(self):
        """Print the result. Every number it prints is a count of
        something that was measured, and the parts that were NOT
        measured are named rather than rounded away."""
        return _digest_report({"intervals": self.results,
                               "skipped": self.skipped,
                               "beyond": self.beyond,
                               "last_height": self.last_height,
                               "contiguous": self.contiguous},
                              self.stream_fingerprint())


def _digest_report(state, stream_fingerprint=None):
    """The shared printer, so a live run and a re-read of the state
    file cannot describe the same check differently."""
    intervals = state["intervals"]
    bad = [r for r in intervals if not r["ok"]]
    covered = sum(r["end"] - r["start"] + 1 for r in intervals)
    print(f"graph digest through height {state['last_height']:,}")
    print(f"  intervals verified   {len(intervals) - len(bad):>10,}"
          f"  ({covered:,} heights)")
    if bad:
        print(f"  intervals MISMATCHED {len(bad):>10,}")
        for r in bad:
            print(f"    heights {r['start']:,}..{r['end']:,}")
    for start, end in state["skipped"]:
        print(f"  not verified: heights {start:,}..{end:,} "
              "(a restart fell inside this interval)")
    if state["beyond"]:
        print(f"  not verified: {state['beyond']:,} heights past the "
              "reference archive's watermark (the chain grew)")
    if stream_fingerprint:
        print(f"  whole-stream sha256: {stream_fingerprint}")
        print("  (comparable with `graph fingerprint` on the reference)")
    elif not state["contiguous"]:
        print("  whole-stream sha256: not available (the pass was "
              "resumed; the intervals above are unaffected)")
    result = "MISMATCH" if bad else ("ok" if intervals else "nothing verified")
    print(f"  result: {result}")
    return not bad and bool(intervals)


def read_digest_report(state_dir):
    """Re-print the result from the state file, for a check that is
    still running or that was interrupted."""
    path = os.path.join(state_dir, DIGEST_STATE_NAME)
    if not os.path.exists(path):
        raise GraphError(f"no {DIGEST_STATE_NAME} in {state_dir}: no graph "
                         "digest was run against this scan")
    with open(path) as f:
        state = json.load(f)
    if state.get("format") != FORMAT_TAG:
        raise GraphError("unknown graph digest state format")
    return _digest_report(state, state.get("stream_sha256"))


# ---------------------------------------------------------------------------
# Reading back: the canonical stream
# ---------------------------------------------------------------------------

def _load_state(graph_dir):
    path = os.path.join(graph_dir, STATE_NAME)
    if not os.path.exists(path):
        raise GraphError(f"no {STATE_NAME} in {graph_dir}: not a graph "
                         "archive (or the scan never checkpointed)")
    with open(path) as f:
        state = json.load(f)
    if state.get("format") not in READABLE_TAGS:
        raise GraphError(f"unknown graph archive format "
                         f"{state.get('format')!r}")
    return state


def _run_bytes(graph_dir, run, chunk=8 * 2**20):
    """Stream one run's bytes, verifying its recorded sha256 on the
    way: a graph that feeds derived indices (and published numbers
    downstream) is trusted exactly as much as the blocks were — not
    at all."""
    digest = hashlib.sha256()
    with open(os.path.join(graph_dir, RUNS_DIR, run["name"]), "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            digest.update(data)
            yield data
    if digest.hexdigest() != run["sha256"]:
        raise GraphError(f"{run['name']}: sha256 mismatch — file "
                         "corrupted or not the one the state describes")


def decode_block_record(buf, pos):
    """One graph-v2 block record → a plain dict. Returns (dict,
    new_pos). The reading twin of serialize_block_record, used by
    `show` and by the tests — and by nothing on the emission path, so
    the two directions stay independent."""
    height = int.from_bytes(buf[pos:pos + 4], "little")
    block_hash = bytes(buf[pos + 4:pos + 36])
    time_ = int.from_bytes(buf[pos + 36:pos + 40], "little")
    pos += 40
    n_tx, pos = read_compactsize(buf, pos)
    txs = []
    for _ in range(n_tx):
        txid = bytes(buf[pos:pos + 32])
        flags = buf[pos + 32]
        pos += 33
        n_in, pos = read_compactsize(buf, pos)
        inputs = []
        for _ in range(n_in):
            prev_txid = bytes(buf[pos:pos + 32])
            prev_vout = int.from_bytes(buf[pos + 32:pos + 36], "little")
            pos += 36
            inputs.append((prev_txid, prev_vout))
        n_out, pos = read_compactsize(buf, pos)
        outputs = []
        for _ in range(n_out):
            value = int.from_bytes(buf[pos:pos + 8], "little")
            pos += 8
            script_len, pos = read_compactsize(buf, pos)
            outputs.append((value, bytes(buf[pos:pos + script_len])))
            pos += script_len
        txs.append({"txid": txid, "coinbase": bool(flags & FLAG_COINBASE),
                    "inputs": inputs, "outputs": outputs})
    return {"height": height, "hash": block_hash, "time": time_,
            "txs": txs}, pos


def iter_blocks(graph_dir, from_height=1, to_height=None):
    """Decoded block records in height order, runs verified as they
    stream. Whole runs outside the range are skipped without a read —
    the run names carry their interval for exactly this."""
    state = _load_state(graph_dir)
    for run in state["runs"]:
        if run["end"] < from_height:
            continue
        if to_height is not None and run["start"] > to_height:
            break
        buf = b"".join(_run_bytes(graph_dir, run))
        pos = 0
        while pos < len(buf):
            rec, pos = decode_block_record(buf, pos)
            if rec["height"] < from_height:
                continue
            if to_height is not None and rec["height"] > to_height:
                return
            yield rec


# ---------------------------------------------------------------------------
# fingerprint — the canonical form, measured
# ---------------------------------------------------------------------------

def stream_digest(graph_dir):
    """sha256 of the canonical form: the record stream in height order,
    deliberately blind to where one run ends and the next begins,
    because the boundaries are buffering accidents and not data. An
    interrupted-and-resumed emission therefore digests the same as a
    one-shot one, and anyone who re-emits at the same height must land
    on the same hex string.

    No format tag goes in here, unlike the seal that wraps it: this is
    the digest of what the chain dictated, so it is the number to
    compare across format versions when the question is whether the
    BYTES changed. The pass re-reads everything and re-checks every
    run's sha256, so it doubles as the integrity audit.
    """
    state = _load_state(graph_dir)
    if not state["runs"]:
        raise GraphError("empty archive: nothing to fingerprint")
    digest = hashlib.sha256()
    for run in state["runs"]:
        for data in _run_bytes(graph_dir, run):
            digest.update(data)
    return digest.hexdigest(), state


def run_fingerprint(graph_dir, reseal=False):
    """Seal the graph: stream it, digest its canonical form, write the
    identity.

    The graph declares ONE logical file, `stream`, because its data
    live in runs whose boundaries carry no meaning: what it is made of
    is the concatenation, not the pieces. Everything else is the shared
    identity of every artifact, so a graph is fingerprinted by the same
    recipe as an index and binds to a child the same way.

    Superseding a seal from an earlier major is a deliberate act, so it
    asks: an archive emitted under v1 holds a manifest whose fingerprint
    came from a recipe this code does not compute, and that number may
    be published somewhere no rerun can reach. With `reseal` the old
    manifest is kept beside the new one under its own format's name, so
    re-sealing adds an identity and destroys none.
    """
    existing = None
    mpath = os.path.join(graph_dir, MANIFEST_NAME)
    if os.path.exists(mpath):
        with open(mpath) as f:
            existing = json.load(f)
    if existing and existing.get("format") != FORMAT_TAG:
        old = existing.get("format")
        if not reseal:
            raise GraphError(
                f"this archive is sealed as {old}, whose fingerprint "
                f"({existing.get('fingerprint')}) comes from a recipe "
                f"{FORMAT_TAG} does not compute. The bytes are readable "
                "either way; re-sealing is what gives them an identity a "
                "child can name. Pass --reseal to do it (the old manifest "
                "is kept).")
        keep = os.path.join(graph_dir, f"manifest.{old}.json")
        if not os.path.exists(keep):
            atomic_json(keep, existing)
            print(f"kept the {old} seal as manifest.{old}.json "
                  f"({existing.get('fingerprint')})")

    fingerprint_of_bytes, state = stream_digest(graph_dir)
    identity = make_identity(FORMAT_TAG, 1, state["last_height"],
                             [("stream", fingerprint_of_bytes)])
    fingerprint = identity_fingerprint(identity)

    totals = {k: sum(r[k] for r in state["runs"])
              for k in ("blocks", "transactions", "inputs", "outputs",
                        "bytes")}
    clock = WallClock("fingerprint", state)
    manifest = seal_manifest(
        FORMAT_TAG, identity,
        {"producer": producer(),
         "seconds": clock.stamp(),
         "wall": clock.wall(),
         "totals": totals, "runs": len(state["runs"]),
         "files": {"stream": {"file": RUNS_DIR}}, "caches": {}})
    atomic_json(os.path.join(graph_dir, MANIFEST_NAME), manifest)

    if state.get("format") != FORMAT_TAG:
        # The state file is bookkeeping, not data: the v1 → v2 break
        # changed the seal recipe and not one byte of the stream, so an
        # archive this command just sealed is v2 in every respect —
        # including the label its own emitter checks. Leaving the old
        # one would make `--graph` refuse to grow the very archive the
        # reseal promised was current.
        atomic_json(os.path.join(graph_dir, STATE_NAME),
                    {**state, "format": FORMAT_TAG})
        print(f"state relabelled {FORMAT_TAG} (bookkeeping only: the "
              "bytes did not change)")

    print(f"graph archive covers heights 1..{state['last_height']:,}")
    for k in ("blocks", "transactions", "inputs", "outputs"):
        print(f"  {k:<13} {totals[k]:>16,}")
    print(f"  {'bytes':<13} {totals['bytes']:>16,}")
    print(f"fingerprint: {fingerprint}")
    return fingerprint


def run_stats(graph_dir):
    """Watermark and totals from the state alone — no bytes read, so
    it answers instantly even on a NAS-hosted archive."""
    state = _load_state(graph_dir)
    totals = {k: sum(r[k] for r in state["runs"])
              for k in ("blocks", "transactions", "inputs", "outputs",
                        "bytes")}
    print(f"graph archive covers heights 1..{state['last_height']:,} "
          f"in {len(state['runs'])} runs")
    for k, v in totals.items():
        print(f"  {k:<13} {v:>16,}")


def run_show(graph_dir, from_height, to_height):
    """A height range, decoded and printed — what the bytes actually
    say, for a human. This is the didactic window: one look at a block
    here and the format needs no further explaining."""
    shown = 0
    for rec in iter_blocks(graph_dir, from_height, to_height):
        print(f"block {rec['height']:,}  hash {rec['hash'][::-1].hex()}  "
              f"time {rec['time']}")
        for tx in rec["txs"]:
            kind = "coinbase" if tx["coinbase"] else \
                f"{len(tx['inputs'])} in"
            print(f"  tx {tx['txid'][::-1].hex()}  "
                  f"({kind}, {len(tx['outputs'])} out)")
            for prev_txid, prev_vout in tx["inputs"]:
                print(f"    spends {prev_txid[::-1].hex()}:{prev_vout}")
            for value, script in tx["outputs"]:
                print(f"    creates {value:,} sat  lock {script.hex()}")
        shown += 1
    if not shown:
        print("no blocks in that range (check the archive's watermark "
              "with `stats`)")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Read back a graph-v2 archive co-emitted during a "
                    "chain scan (the emission itself is the --graph "
                    "flag of reuse_scan.py / reveal_archive.py scan).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pf = sub.add_parser("fingerprint",
                        help="canonical fingerprint + integrity audit "
                             "(reads every byte)")
    pf.add_argument("--graph", required=True, help="archive directory")
    pf.add_argument("--reseal", action="store_true",
                    help="supersede a seal written by an earlier major "
                         "(the old manifest is kept beside the new one)")

    pt = sub.add_parser("stats", help="watermark and totals (instant)")
    pt.add_argument("--graph", required=True)

    ps = sub.add_parser("show", help="decode a height range, human-readable")
    ps.add_argument("--graph", required=True)
    ps.add_argument("--from", dest="from_height", type=int, required=True)
    ps.add_argument("--to", dest="to_height", type=int, required=True)

    pd = sub.add_parser("digest",
                        help="the result of a --graph-digest check, "
                             "re-read from the scan it rode along with")
    pd.add_argument("--scan", required=True,
                    help="the scan's own directory (--archive of "
                         "`archive scan`), where the check keeps state")

    args = p.parse_args(argv)
    try:
        if args.cmd == "fingerprint":
            run_fingerprint(args.graph, reseal=args.reseal)
        elif args.cmd == "stats":
            run_stats(args.graph)
        elif args.cmd == "digest":
            if not read_digest_report(args.scan):
                sys.exit(1)
        else:
            run_show(args.graph, args.from_height, args.to_height)
    except GraphError as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
