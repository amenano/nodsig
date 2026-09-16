#!/usr/bin/env python3
"""
genstore.py — the APPEND-AND-FUSE STORE shared by every artifact that
grows by generations: sorted runs pile up, a fusion folds them into the
next generation of a merged file, and the state file is the only truth
about what exists on disk.

Two artifacts are built this way (outpoint-index-v3 and
outpoint-derived-v3) and a third one, reveal-archive-v4, is the same
idea written earlier by hand. What they share is not a data format —
their records differ in width, key and meaning — but a WAY OF GROWING,
and that is what lives here.

WHY A STORE AND NOT A BASE CLASS
================================
The two artifacts do not have an is-a relationship: the derivatives are
not a kind of index. What they have is the same bookkeeping problem, so
this is a component they each own an instance of, declaring the two
things that actually differ:

    the directory   — where its files live;
    the projection  — for each merged file, the (record width, key
                      length, ladder step) triple that says how its
                      bytes are laid out and searched.

Everything else (run naming, generation numbering, the crash-safe
commit order, the ladder sampled while writing) is identical, and a
single copy of it means a fix lands once. The state dict stays owned by
the caller and is passed in by reference: the store writes into the
four keys it is responsible for, the artifact keeps the rest.

THE STATE KEYS THIS OWNS
========================
    runs        [{name, category, records, sha256}] — sorted runs
                waiting to be fused, each with the sha that proves it
                was read whole;
    files       name → {file, records, sha256} — the merged files, one
                entry per logical name, always the CURRENT generation;
    caches      name → {file, every, sha256} — the ladders. Caches, not
                data: excluded from the canonical fingerprint, so a
                lost ladder costs a slower search and never an
                invalid artifact;
    generation  a counter, so a new fusion never writes over the file a
                reader might be holding open.

WHY THE FUSION GALLOPS
======================
A fusion re-reads and re-writes the whole of the previous generation
even when the new blocks touch a handful of its records — that is what
makes `append ≡ rebuild` true, and it is not negotiable. What IS
negotiable is paying Python's per-record price for the >99.9% of
records that arrive already in place and already in order. So the
previous generation comes in as a cursor rather than as one more
stream, and whenever its next stretch is entirely below the next
pending record of the runs, that stretch is settled in one piece. The
rules do not change with the road: see `merge_to_file`.

WHY THE RUNS ARE SORTED, NOT MERGED
===================================
The gallop has nothing to bite on in the FIRST fusion of a scan: no
previous generation, a few thousand runs of random digests, every
record the runs' turn. There the per-record price was paid three times
over (the run's generator, the heap's step, the writer's loop). So the
runs come in as slab cursors too, and a k-way stage (`_BulkFusion`)
gathers, round by round, every record below a key all sources are
known to have reached, sorts them in one list (timsort finds the runs
and merges them in C) and reduces the equal keys by column instead of
by record. The stage yields sorted, reduced blobs: the output itself
when nothing else is fused, one more source for the loop when a base
gallops over them. Same rules, same bytes, same ladder, same count,
which the suite pins against a reference written the obvious way.

WHY THE COMMIT ORDER IS WHAT IT IS
==================================
A fusion writes generation N+1 beside generation N and only then
rewrites the state; the old generation and the consumed runs are
deleted after the state that stopped naming them is on disk. There is
therefore no instant at which the state points at bytes that are being
replaced — the flaw a plain overwrite would have. The rule the whole
design leans on: WHAT THE STATE DOES NOT NAME DOES NOT EXIST, which is
what makes `clean_orphans` a safe sweep rather than a guess.
"""

import hashlib
import heapq
import os
import re
import struct
import sys

from nodsig import kernel
from nodsig.recio import (IO_CHUNK, atomic_json, budgeted_slab, checked_name,
                          preflight_space, durable_replace,
                          read_fixed, read_slabs)
from nodsig.recsort import write_run

# How many (dropped, kept) collision pairs merge_to_file keeps for a
# caller that asked: enough for every real duplicate the chain has
# (BIP30 produced two), small enough that a caller whose collisions are
# routine (an append's updated rows) cannot hoard memory by mistake.
DUP_LOG_CAP = 64

# How many consecutive records the previous generation must win before
# the fusion stops walking it one at a time — and how many it must then
# have clear before their bytes are moved in one piece. Both are the
# same judgement: a stretch shorter than this does not repay the fixed
# cost of measuring it (the galloping search) or of moving it (the
# equality scan, the ladder arithmetic).
#
# The STREAK is what makes the slow case slow-proof. A fusion whose
# runs are as big as its base interleaves record by record: there, a
# search per record would cost more than the walk it replaces, so it is
# never started — the counter resets at every record the runs win, and
# the fusion stays exactly the loop it was. Timsort takes the same
# precaution, for the same reason and with the same order of magnitude.
MIN_BULK = 8


def new_state_fields():
    """The four keys a store owns, for an artifact's `_new_state()` to
    splice into its own. Kept here so the schema has one author."""
    return {"runs": [], "files": {}, "caches": {}, "generation": 0}


def _pair_mask(slab, off, count, rec, dedup_len):
    """For the `count` records at `slab[off:]`, one byte per ADJACENT
    PAIR: zero where the pair may share its dedup prefix, non-zero
    where it certainly does not. Returns (mask, exact): with `exact`
    the zeros ARE the equal pairs; without it they are candidates a
    caller settles by comparing the whole prefix.

    Counted a COLUMN at a time instead of a record at a time. The j-th
    byte of every record is one strided slice, so one XOR of two such
    slices, read as big integers, answers the question for every pair
    at once: a zero byte in the result is a pair that agrees on that
    column. Columns are OR-ed from the LAST byte of the prefix
    backwards — the byte that differs first in a dense key like an
    ordinal — until the surviving candidates are rare enough to be
    worth checking one by one, or until every column has spoken, at
    which point the mask is exact. The narrowing is a heuristic; the
    answer is not, because every candidate is settled either by the
    whole prefix having been compared here or by the caller comparing
    it."""
    span = (count - 1) * rec
    acc = None
    j = dedup_len - 1
    while True:
        a = int.from_bytes(slab[off + j:off + j + span:rec], "big")
        b = int.from_bytes(slab[off + rec + j:off + rec + j + span:rec],
                           "big")
        acc = (a ^ b) if acc is None else acc | (a ^ b)
        mask = acc.to_bytes(count - 1, "big")
        candidates = mask.count(0)
        if candidates == 0 or j == 0 or candidates * 64 <= count:
            return mask, j == 0 or candidates == 0
        j -= 1


def _adjacent_equal(slab, off, count, rec, dedup_len):
    """How many of the `count` records at `slab[off:]` share their
    dedup prefix with the record BEFORE them — i.e. how many duplicate
    pairs a stretch of already-sorted records contains.

    This is the one thing a bulk copy must not skip: the fusion's dup
    count is an OUTPUT, checked against a second road (the nonces
    archive compares it with a full pass over the file it wrote), so a
    faster path that copied bytes without counting would return a
    different number for the same input. The pairs are found by
    column (`_pair_mask`); the candidates it leaves unsettled are
    compared in full here."""
    if count < 2:
        return 0
    mask, exact = _pair_mask(slab, off, count, rec, dedup_len)
    if exact:
        return mask.count(0)
    found = 0
    i = mask.find(0)
    while i >= 0:
        o = off + i * rec
        if slab[o:o + dedup_len] == slab[o + rec:o + rec + dedup_len]:
            found += 1
        i = mask.find(0, i + 1)
    return found


class LadderWriter:
    """A sorted record file written with its sha256 and its ladder taken
    on the way, by record or by whole sorted blob. The one writer every
    fusion output goes through, so the ladder's sampling rule (every
    `every`-th record, counted from the first) and the slab writing are
    stated once: a blob of n records sampled by arithmetic must land on
    the same ladder n records added one at a time would, and the suite
    pins that. Atomic like every writer here: tmp file + rename, ladder
    beside it; `close` returns (records, sha256, ladder sha256)."""

    def __init__(self, path, rec, key_len, ladder_path, every):
        self.path = path
        self.rec = rec
        self.key_len = key_len
        self.ladder_path = ladder_path
        self.every = every
        self.digest = hashlib.sha256()
        self.ladder = bytearray()
        self.buf = bytearray()
        self.records = 0
        self.f = open(path + ".tmp", "wb")

    def add(self, r):
        if self.records % self.every == 0:
            self.ladder.extend(r[:self.key_len])
        self.buf.extend(r)
        self.records += 1
        if len(self.buf) >= IO_CHUNK:
            self._flush()

    def add_blob(self, blob, n=None):
        """`n` whole sorted records at once (n defaults to the blob's
        length): sampled into the ladder by position, appended whole."""
        rec, key_len = self.rec, self.key_len
        if n is None:
            n = len(blob) // rec
        step = (-self.records) % self.every
        for j in range(step, n, self.every):
            o = j * rec
            self.ladder.extend(blob[o:o + key_len])
        self.buf.extend(blob)
        self.records += n
        if len(self.buf) >= IO_CHUNK:
            self._flush()

    def _flush(self):
        self.f.write(self.buf)
        self.digest.update(self.buf)
        self.buf.clear()

    def close(self):
        """Returns (records, sha256, ladder sha256)."""
        if self.buf:
            self._flush()
        self.f.close()
        durable_replace(self.path + ".tmp", self.path)
        ladder_sha = hashlib.sha256(self.ladder).hexdigest()
        with open(self.ladder_path + ".tmp", "wb") as f:
            f.write(self.ladder)
        durable_replace(self.ladder_path + ".tmp", self.ladder_path)
        return self.records, self.digest.hexdigest(), ladder_sha


# The one shape a merged generation or its ladder can have; see
# GenStore.clean_orphans for why the sweep matches nothing looser.
_GENERATION = re.compile(r".+_g\d{4}\.(bin|lad)")


class _BaseCursor:
    """The previous generation, read as SLABS rather than as records.

    A fusion's base is the one source that is overwhelmingly already in
    place: an append inserts a few million records into billions, so
    the base's records mostly arrive in long stretches with nothing to
    interleave. This cursor is what lets those stretches be measured
    (`below`) and then moved in one piece, while the ordinary
    per-record path still handles the boundaries. It verifies the
    sealed sha256 as it goes, exactly as `read_fixed` would, so the
    faster road trusts the bytes no more than the slow one.
    """

    def __init__(self, path, rec, expect_sha, slab_bytes, error):
        self._slabs = read_slabs(path, rec, slab_bytes, error=error)
        self._digest = hashlib.sha256() if expect_sha is not None else None
        self._expect = expect_sha
        self._path = path
        self._error = error
        self._eof = False
        self.rec = rec
        self.slab = b""
        self.off = 0
        self.end = 0
        # Byte offset up to which the bulk path is refused: a stretch
        # whose duplicates it cannot express is consumed record by
        # record instead of being re-measured at every step.
        self.plain_until = 0
        # What the last `below` found, kept because a stretch too short
        # to move whole is walked record by record and asking again for
        # each of them would cost more than the walk it is trying to
        # avoid: the count simply decreases as the records go by. -1 is
        # "unknown", which a new slab restores.
        self.clear = -1

    def _fill(self):
        buf = next(self._slabs, None)
        self.clear = -1
        if buf is None:
            self._eof = True
            self.slab, self.off, self.end, self.plain_until = b"", 0, 0, 0
            if (self._digest is not None
                    and self._digest.hexdigest() != self._expect):
                raise self._error(
                    f"{self._path}: sha256 mismatch — file corrupted or "
                    "not the one the state describes")
            return False
        if self._digest is not None:
            self._digest.update(buf)
        self.slab, self.off, self.end, self.plain_until = buf, 0, len(buf), 0
        return True

    def peek(self):
        """The next record, or None at end of file — where the sealed
        sha256 is settled."""
        while self.off >= self.end:
            if self._eof or not self._fill():
                return None
        return self.slab[self.off:self.off + self.rec]

    def below(self, threshold, dedup_len):
        """How many of the current slab's remaining records have a
        dedup prefix strictly below `threshold` (all of them when there
        is no threshold left to respect, the runs being exhausted).

        Galloping, not bisecting: a dense boundary answers in a couple
        of comparisons, and a long clear stretch costs the logarithm of
        its length. The count stops at the end of the slab, which only
        means the next stretch is measured again after the refill."""
        slab, rec, off = self.slab, self.rec, self.off
        n = (self.end - off) // rec
        if threshold is None:
            return n
        if n == 0 or slab[off:off + dedup_len] >= threshold:
            return 0
        lo, hi = 0, 1
        while hi < n and (slab[off + hi * rec:off + hi * rec + dedup_len]
                          < threshold):
            lo, hi = hi, hi * 2
        if hi > n:
            hi = n
        while lo + 1 < hi:                    # first record NOT below
            mid = (lo + hi) // 2
            if slab[off + mid * rec:off + mid * rec + dedup_len] < threshold:
                lo = mid
            else:
                hi = mid
        return hi

    @property
    def eof(self):
        """True once the file has no slab left to give: what is still
        in `slab` (a tail kept by `refill`) is all there is."""
        return self._eof

    def last_key(self, dedup_len):
        """The dedup prefix of the LAST record of the current slab: the
        key up to which every record of this source is in memory."""
        return self.slab[self.end - self.rec:self.end - self.rec + dedup_len]

    def key_ahead(self, ahead, dedup_len):
        """The dedup prefix of the record `ahead` bytes (whole records)
        past the head of the current slab, or of the slab's last record
        when that is nearer: a key up to which every record of this
        source is in memory, like `last_key`, but one the k-way stage
        can use to bound a round. When the head's own key reaches that
        far, the last record's key instead: a threshold equal to the
        head would consume nothing and refill nothing."""
        slab, off, dl = self.slab, self.off, dedup_len
        last = self.end - self.rec
        at = min(off + ahead, last)
        key = slab[at:at + dl]
        if at < last and key == slab[off:off + dl]:
            return slab[last:last + dl]
        return key

    def refill(self):
        """The next slab, with the unconsumed tail of this one kept in
        front of it. The k-way stage consumes each slab up to a
        threshold that is strictly below its last key, so the records
        it leaves behind (those equal to that key, one as a rule) must
        meet their equals in the next slab: they are carried, not
        re-read. At end of file the tail alone stays, and `eof` says so."""
        tail = self.slab[self.off:self.end]
        if self._fill():
            if tail:
                self.slab = tail + self.slab
                self.end = len(self.slab)
        elif tail:
            self.slab, self.off, self.end = tail, 0, len(tail)

    def records(self):
        """The per-record road over the same slabs, sha settled at the
        end exactly as `read_fixed` settles it."""
        rec = self.rec
        while True:
            r = self.peek()
            if r is None:
                return
            slab, off, end = self.slab, self.off, self.end
            self.off = end
            for i in range(off, end, rec):
                yield slab[i:i + rec]

# Records leave a blob as bytes objects through struct. One compiled
# format per (record shape, count) is cheaper than slicing by hand (0.14
# against 0.36 µs per record, measured), but a format per count is a
# cache that grows with every length a piece happens to have: 4,096 of
# them cost 295 MB per shape, measured. So a piece is split by the
# powers of two of its length: at most _SPLIT_BITS formats per shape,
# ever, and at most _SPLIT_BITS calls per piece. (The 4.2 GB the first
# real fusion peaked at were mostly the round itself, unbounded then:
# see _BulkFusion, THE BOUND.)
_SPLIT_BITS = 13                      # chunks of up to 4,096 records
_unpackers = {}

# About how many records the k-way stage gathers in one round, over all
# its sources (_BulkFusion, THE BOUND): 64 k records of 24 bytes are
# 1.5 MB of pieces and a few MB of Python objects, and a walk over 1,200
# sources per round is then paid once per 64 k records, not once per 3.
_ROUND_RECORDS = 1 << 16


def _split(blob, rec, n=None, unit=None):
    """The `n` fixed-width records of `blob` (n defaults to its whole
    length), as a list, in C. `unit` is the struct format of ONE
    record, default the whole record as bytes; a caller wanting only
    a prefix passes e.g. "20s4x"."""
    if n is None:
        n = len(blob) // rec
    if unit is None:
        unit = f"{rec}s"
    out = []
    off = 0
    bit = _SPLIT_BITS - 1
    while n:
        count = 1 << bit
        if n >= count:
            out += _unpacker(unit, count)(blob, off)
            off += count * rec
            n -= count
        else:
            bit -= 1
    return out


def _unpacker(unit, count):
    u = _unpackers.get((unit, count))
    if u is None:
        u = _unpackers[(unit, count)] = struct.Struct(unit * count).unpack_from
    return u


class _BulkFusion:
    """The k-way stage of a fusion, by slabs: every run comes in as a
    cursor, and the records leave as SORTED, REDUCED BLOBS, one per
    round, in key order and with no key straddling two of them.

    WHY NOT heapq.merge
    -------------------
    The first fusion of a scan is the one with no previous generation
    to gallop over: a few thousand runs of random digests, every record
    the runs' turn, so the gallop's insight (a stretch nothing
    interleaves moves whole) has nothing to bite on. What is left is a
    k-way merge that pays Python per record three times — the source's
    generator, the heap's step, the writer's loop — 3.25 µs a record on
    the real pile, measured. Sorting does better: timsort finds the
    runs on its own and merges them in C, and the equal keys of a
    sorted blob are found by column (`_pair_mask`) rather than by
    record. So each round gathers, from every source, the records below
    a threshold every source is known to have reached, sorts them in
    one list, reduces the equal keys by the fusion's rule, and yields
    one blob.

    THE THRESHOLD is the smallest, among the sources that still have
    a slab to read, of the key a bounded number of records past the
    source's head (its slab's last key when that is nearer): every
    record below it, from every source, is in memory (a source's slab
    reaches at least that key, or the source has no more slabs).
    Strictly below, so a key shared by a slab's last records and its
    successor's first is never split across rounds: what a source
    keeps is carried into its next slab by `refill`. A round therefore
    holds every record of every key it emits, which is what lets it
    reduce them.

    THE BOUND on the round is what keeps the stage's memory at the
    size of a round rather than of the read budget. With the last key
    as the threshold, every slab of every source covers the same
    stretch of keys at the start, and again each time every source
    has refilled: such a round gathers the whole budget (22 M records
    for 512 MB, measured) into one Python list, 4 GB resident on the
    first real 3.0.x fusion and an out-of-memory on a machine with
    less. Looking `_ROUND_RECORDS // k` records ahead of each head
    instead bounds a round at about `_ROUND_RECORDS` records, and the
    sources then advance in step: the rounds are of one size, where
    before one huge round was followed by a thousand of a few records
    each, every one paying the walk over every source.

    THE RULES are `merge_to_file`'s, applied once per equal-key group:
    `combine` folds the group left to right (the fold is associative
    and commutative, so the order two equal records meet in still does
    not matter), "last" keeps its last record, None keeps every record
    and counts the pairs, and `dup_log` receives (kept so far, next)
    per pair as the per-record road logs it. `dups` is the number of
    reductions, readable once the blobs are exhausted.

    THE NATIVE ROAD. The sort and the reduction of a round are the
    stage's whole cost, and with ~1,200 sources the pieces are ~15
    records each: below timsort's minrun, so the sort degenerates
    (measured ~3 µs a record on the first real 3.0.x fusion). When the
    kernel is built (`nodsig.kernel`) and knows the rule, a round goes
    to `fuse_pieces`: a k-way merge over the sorted pieces with the
    reduction on the way out, log2(k) memcmp's a record. Same blobs,
    same count; the suite holds the two roads to it."""

    def __init__(self, cursors, rec, dedup_len, dedup, combine, dup_log):
        self.cursors = list(cursors)
        self.rec = rec
        self.dedup_len = dedup_len
        self.keep_last = dedup == "last"
        self.combine = combine
        self.dup_log = dup_log
        self.dups = 0
        # The native road for the sort-and-reduce of a round, when the
        # kernel is built and knows the rule; the pairs a caller logs
        # are the reference's business, so a log keeps the round here.
        self.native_rule = (kernel.fuse_rule(dedup, combine)
                            if dup_log is None and kernel.available()
                            else None)

    def _round(self):
        """(pieces, threshold) for the next round, or None when every
        source is spent; the cursors that reached the threshold are
        refilled here, so the caller only sorts."""
        rec, dl = self.rec, self.dedup_len
        active = [c for c in self.cursors if c.peek() is not None]
        if not active:
            return None
        ahead = max(1, _ROUND_RECORDS // len(active)) * rec
        threshold = None
        for c in active:
            if not c.eof:
                k = c.key_ahead(ahead, dl)
                if threshold is None or k < threshold:
                    threshold = k
        pieces = []
        for c in active:
            n = c.below(threshold, dl)
            if n:
                pieces.append(c.slab[c.off:c.off + n * rec])
                c.off += n * rec
            if threshold is not None and not c.eof and c.last_key(dl) == threshold:
                c.refill()
        return pieces

    def blobs(self):
        rec, dl = self.rec, self.dedup_len
        combine, keep_last, log = self.combine, self.keep_last, self.dup_log
        rule = self.native_rule
        while True:
            pieces = self._round()
            if pieces is None:
                return
            if not pieces:
                continue
            if rule is not None:
                # The kernel merges the sorted pieces and reduces on the
                # way out (nodsig_kway.h); it declines a piece that is
                # not sorted, and the round then takes the road below.
                got = kernel.fuse_pieces(pieces, rec, dl, rule)
                if got is not None:
                    blob, d = got
                    self.dups += d
                    if blob:
                        yield blob
                    continue
            if len(pieces) == 1:
                records = _split(pieces[0], rec)
            else:
                records = []
                for piece in pieces:
                    records += _split(piece, rec)
                records.sort()
            n = len(records)
            if n < 2:
                if n:
                    yield records[0]
                continue
            blob = b"".join(records)
            mask, exact = _pair_mask(blob, 0, n, rec, dl)
            if not mask.count(0):
                yield blob
                continue
            # The groups: maximal runs of zero bytes in the mask, each
            # a stretch of records sharing the prefix (settled here when
            # the mask is not exact). The output is the blob with each
            # group replaced by what the rule keeps of it.
            out = []
            start = 0
            view = memoryview(blob)
            for m in re.finditer(rb"\x00+", mask):
                first, last = m.start(), m.end()   # records first..last
                if not exact:
                    # Settle pair by pair; a false candidate splits the
                    # group, so walk it as sub-groups.
                    i = first
                    while i < last:
                        if records[i][:dl] != records[i + 1][:dl]:
                            i += 1
                            continue
                        j = i + 1
                        while j < last and records[j][:dl] == records[j + 1][:dl]:
                            j += 1
                        start = self._reduce(records, i, j, view, out, start)
                        i = j + 1
                    continue
                start = self._reduce(records, first, last, view, out, start)
            out.append(view[start * rec:])
            yield b"".join(out)

    def _reduce(self, records, i, j, view, out, start):
        """Records i..j (inclusive) share the prefix: append what comes
        before them and what the rule keeps of them; return the index
        the untouched stretch resumes from."""
        rec = self.rec
        n_pairs = j - i
        self.dups += n_pairs
        if self.combine is None and not self.keep_last:
            if self.dup_log is not None:
                for k in range(i, j):
                    if len(self.dup_log) >= DUP_LOG_CAP:
                        break
                    self.dup_log.append((bytes(records[k]),
                                         bytes(records[k + 1])))
            return start                    # nothing dropped: counted only
        out.append(view[start * rec:i * rec])
        kept = records[i]
        for k in range(i + 1, j + 1):
            r = records[k]
            if self.dup_log is not None and len(self.dup_log) < DUP_LOG_CAP:
                self.dup_log.append((bytes(kept), bytes(r)))
            kept = self.combine(kept, r) if self.combine is not None else r
        out.append(kept)
        return j + 1

    def records(self):
        """The blobs as records, for the road that must walk them."""
        rec = self.rec
        for blob in self.blobs():
            yield from _split(blob, rec)


def merge_to_file(sources, out_path, rec, key_len, ladder_path,
                  ladder_every, dedup, dedup_len=None, dup_log=None,
                  base=None, combine=None, cursors=(), blobs=None):
    """Fuse sorted record streams into one file, sampling the ladder
    while writing — the cache costs no extra pass.

    dedup="last": equal keys collapse to the LAST record of the run —
    which, keys and payloads being big-endian, is the numerically
    greatest payload: for the resolver that is the highest first_out,
    i.e. the BIP30 rule "the later duplicate overwrote the earlier".
    dedup=None: nothing is dropped, but equal keys are still counted
    (the index's spend side expects that count to be 0 under consensus).

    `dedup_len` is the prefix equality is judged on (default: the
    ladder's key_len). The derivatives need them distinct: history
    rows dedup on (lock, ordinal) but are SEARCHED by lock alone.

    `dup_log`, when a list, receives up to DUP_LOG_CAP (dropped, kept)
    record pairs, one per collision. It exists for the caller whose
    collisions are RARE and PRECIOUS — the index keeps its BIP30
    overwrites so a later rewind can ask about them without re-reading
    the file — and the cap is what keeps a caller with millions of
    collisions from hoarding them; such a caller reads fewer pairs than
    the count and knows the log is partial.

    `base`, when given, is a `_BaseCursor` over the previous generation
    instead of one more stream in `sources` — the GALLOP. It is one
    loop and one set of rules either way: whenever the base's next
    stretch is entirely below the next pending record of the runs,
    those records are settled TOGETHER, because a stretch that nothing
    interleaves cannot be reordered, cannot collide with what comes
    after it, and is sampled into the ladder by position — which is
    arithmetic on the stretch instead of a test per record. Everything
    else (the boundaries, the collisions, the runs) walks the ordinary
    per-record path, and the bulk form is refused whenever it could not
    say the same thing: a stretch with duplicates to DROP, or one whose
    pairs a caller asked to see, is consumed record by record. What the
    fusion writes, the ladder it samples and the number of duplicates
    it counts are therefore the same with the gallop and without it.

    `combine`, when given, is the third rule for equal keys: two records
    sharing the dedup prefix are REDUCED to one, `combine(kept, next)`,
    and the reduction must be associative and commutative (the reveal
    archive ORs its flags and keeps the lowest height), because the
    order two equal records meet in depends on run boundaries and the
    fusion must not. It counts a duplicate per reduction, like the
    other two rules, and it sends a base stretch holding an equal pair
    back to the per-record road, like `dedup="last"` does: a stretch
    moved whole can neither drop nor reduce.

    `cursors` are the runs as `_BaseCursor`s instead of record streams:
    they go through the k-way stage by slabs (`_BulkFusion`), which
    sorts and reduces them into blobs. `blobs`, alternatively, is such
    a stream already made (a caller that joined or filtered it on the
    way, like the archive's proof). With no `base` and no `sources`
    the blobs are the output and are written whole; otherwise they join
    the per-record loop as one more sorted source, so the base still
    gallops over them. The log of pairs is the same on either road
    when the runs are all there is (their order is total); with a base
    or other streams beside them a logged pair could meet in another
    order, so a caller who asked for the log keeps the runs on the
    per-record road there.

    Returns (records, sha256, ladder_sha256, dup_count)."""
    if dedup_len is None:
        dedup_len = key_len
    if combine is not None and dedup is not None:
        raise ValueError("combine replaces dedup: pass dedup=None with it")
    if cursors and blobs is not None:
        raise ValueError("cursors and blobs are two forms of one stage")
    if dedup_len > rec:
        dedup_len = rec      # a prefix longer than the record IS the
                             # record, and saying so once keeps the
                             # per-column scan and the slicing agreed
    keep_last = dedup == "last"
    sources = list(sources)
    bulk = None
    if cursors:
        if dup_log is not None and (base is not None or sources):
            sources += [c.records() for c in cursors]
        else:
            bulk = _BulkFusion(cursors, rec, dedup_len, dedup, combine,
                               dup_log)
            blobs = bulk.blobs()
    writer = LadderWriter(out_path, rec, key_len, ladder_path, ladder_every)
    dups = 0

    if blobs is not None and base is None and not sources:
        for blob in blobs:
            writer.add_blob(blob)
        records, sha, ladder_sha = writer.close()
        return records, sha, ladder_sha, (bulk.dups if bulk else 0)
    if blobs is not None:
        sources.append(_records_of(blobs, rec))

    runs = heapq.merge(*sources)
    nxt = next(runs, None)
    head = base.peek() if base is not None else None
    pending = None
    streak = 0
    while True:
        if head is not None and (nxt is None or head <= nxt):
            # The base's turn — ties go to it, as they did when it
            # was heapq.merge's first source.
            r = head
            off0 = base.off
            streak += 1
            clear = 0
            if streak >= MIN_BULK:
                # The count is measured once per stretch and then
                # counted down. What makes that safe is the streak
                # itself: it resets at every record the runs win,
                # which is the only thing that can move the record
                # the count was measured against.
                clear = base.clear
                if streak == MIN_BULK or clear < 0:
                    clear = base.below(None if nxt is None
                                       else nxt[:dedup_len], dedup_len)
                base.clear = clear - 1 if clear else 0
            base.off = off0 + rec
            from_base = True
        elif nxt is not None:
            r = nxt
            nxt = next(runs, None)
            streak = 0
            from_base = False
        else:
            break

        if pending is not None:
            if r[:dedup_len] == pending[:dedup_len]:
                dups += 1
                if dup_log is not None and len(dup_log) < DUP_LOG_CAP:
                    dup_log.append((bytes(pending), bytes(r)))
                if combine is not None:
                    pending = combine(pending, r)
                    if from_base:
                        head = base.peek()
                    continue             # one bulk missed, no more
                if keep_last:
                    pending = r          # the later record wins
                    if from_base:
                        head = base.peek()
                    continue             # one bulk missed, no more
            writer.add(pending)
        pending = r

        if from_base:
            # `r` is the first of `clear` base records that nothing
            # interleaves. Settle them all here, holding the last
            # back as `pending` so the record after it can still be
            # compared against it.
            if clear >= MIN_BULK and off0 >= base.plain_until:
                slab = base.slab
                d = _adjacent_equal(slab, off0, clear, rec, dedup_len)
                if d == 0 or (not keep_last and combine is None
                              and dup_log is None):
                    dups += d
                    moved = clear - 1
                    writer.add_blob(slab[off0:off0 + moved * rec], moved)
                    base.off = off0 + clear * rec
                    base.clear = 0   # the next one is not below it
                    pending = slab[base.off - rec:base.off]
                else:
                    base.plain_until = off0 + clear * rec
            head = base.peek()
    if pending is not None:
        writer.add(pending)
    records, sha, ladder_sha = writer.close()
    if bulk is not None:
        dups += bulk.dups
    return records, sha, ladder_sha, dups


def _records_of(blobs, rec):
    for blob in blobs:
        yield from _split(blob, rec)


def _sifted(source, sift):
    """A record stream with the sift applied: a record it answers None
    for is dropped, anything else is emitted in its place.

    It sits between the read (which verifies the source's sha as it
    streams) and the merge, so a sift can never hide a corrupt input,
    and the merge sees exactly what will be written."""
    for rec in source:
        out = sift(rec)
        if out is not None:
            yield out


class GenStore:
    """One artifact directory's runs, merged generations and state.

    `state` is the caller's dict, held by reference: the store mutates
    the four keys of `new_state_fields()` and reads nothing else, so
    the artifact remains the author of its own schema.

    `label` prefixes the housekeeping messages ("index", "derived") and
    `error` is the artifact's own exception class, so a corrupt file
    raises what the tool's callers already catch.

    `clock` is the caller's `artifact.WallClock`, or None. The store
    does not own it and does not read it: at every state write it asks
    the clock to stamp the caller's dict, so a resumable job keeps its
    running cost in the one file that survives a kill. Passed in rather
    than built here because the verb being timed is the artifact's
    business, not the store's."""

    def __init__(self, directory, state, *, label, error=RuntimeError,
                 runs_dir="runs", state_name="state.json", clock=None):
        self.dir = directory
        self.state = state
        self.label = label
        self.error = error
        self.runs_dir = runs_dir
        self.state_name = state_name
        self.clock = clock

    # -- paths and reading --------------------------------------------

    # Every path this store builds goes through one of these two, and
    # both check the name first: a state file this process did not write
    # is untrusted input, and these names are opened and, for runs,
    # removed. See recio.checked_name.
    def path(self, name):
        return os.path.join(self.dir, checked_name(name, self.error))

    def run_path(self, name):
        return os.path.join(self.dir, self.runs_dir,
                            checked_name(name, self.error, "run"))

    def read(self, path, rec, expect_sha=None, slab_bytes=IO_CHUNK,
             start_record=0):
        """Stream whole `rec`-byte records, raising the artifact's own
        error on a truncated file or a sha mismatch."""
        yield from read_fixed(path, rec, expect_sha=expect_sha,
                              slab_bytes=slab_bytes,
                              start_record=start_record,
                              error=self.error)

    # -- runs ---------------------------------------------------------

    def make_runs_dir(self):
        os.makedirs(os.path.join(self.dir, self.runs_dir), exist_ok=True)

    def write_run(self, name, category, records, into=None):
        """Sort and write one run, then name it in the state with the
        sha that will later prove it was read whole.

        `into` takes a different list when the entries must not join
        the state yet: the resolve phase swaps a whole category at
        once, and a run named before that swap would be fused twice."""
        count, sha = write_run(self.run_path(name), records)
        # `bytes` lets the next load see a run the disk lost (a power
        # loss after the rename) before a day of work is built on it.
        entry = {"name": name, "category": category,
                 "records": count, "sha256": sha,
                 "bytes": count * (len(records[0]) if records else 0)}
        (self.state["runs"] if into is None else into).append(entry)
        return count

    def run_sources(self, category):
        """The (path, sha) pairs of every pending run in a category."""
        return [(self.run_path(r["name"]), r["sha256"])
                for r in self.state["runs"]
                if r["category"] == category]

    def run_paths(self, category):
        return [self.run_path(r["name"]) for r in self.state["runs"]
                if r["category"] == category]

    def drop_runs(self, category):
        """Forget a category and hand back its files to delete. The
        caller commits the state first: deleting before that would
        leave the state naming bytes that are gone."""
        delete = self.run_paths(category)
        self.state["runs"] = [r for r in self.state["runs"]
                              if r["category"] != category]
        return delete

    # -- fusion -------------------------------------------------------

    def fuse(self, logical, spec, category, dedup, dedup_len=None,
             sift=None, dup_log=None):
        """One fusion: previous generation (if any) + this category's
        runs → generation N+1 of the merged file, ladder sampled on the
        way. `spec` = (record width, key length, ladder step) is the
        projection the artifact declares for this file.

        The new generation is committed in the state BEFORE the old one
        and the runs are deleted, so no crash window can leave the
        state pointing at replaced bytes. Returns (dups, delete): the
        caller writes the state, then removes what it got back.

        `sift` (record → record or None) filters and may rewrite the
        stream on the way through. It is what makes a REWIND a fusion
        rather than a second builder: the current generation becomes
        its own only source and the records above a cut are dropped, so
        the ladder, the generation numbering and the commit order stay
        this one implementation. A sift MUST NOT change a record's key
        or its order — removing records from a sorted file leaves it
        sorted, rewriting one past its neighbour does not."""
        needed = sum(os.path.getsize(p) for p in self.run_paths(category))
        current = self.state["files"].get(logical)
        if current is not None:
            needed += os.path.getsize(self.path(current["file"]))
        preflight_space(self.dir, needed, self.error,
                        f"{self.label} fusion of {logical}")
        rec, key_len, every = spec
        old = self.state["files"].get(logical)
        todo = []
        if old is not None:
            todo.append((self.path(old["file"]), old["sha256"]))
        todo += self.run_sources(category)
        # Zero sources is legitimate: a chain slice with no resolvable
        # spends still seals, with an honestly empty file.

        gen = self.state["generation"] + 1
        out_name = f"{logical}_g{gen:04d}.bin"
        lad_name = f"{logical}_g{gen:04d}.lad"
        slab = budgeted_slab(len(todo))
        # The previous generation goes in as a CURSOR rather than as one
        # more stream, so its long untouched stretches move in one piece
        # (see merge_to_file). Not when a sift is in play: a sift may
        # rewrite or drop any record, which is exactly what a stretch
        # moved whole cannot express, so a rewind keeps the plain road.
        base = None
        sources, cursors = [], ()
        if sift is not None:
            sources = [_sifted(self.read(p, rec, sha, slab), sift)
                       for p, sha in todo]
        else:
            if old is not None:
                path, base_sha = todo.pop(0)
                base = _BaseCursor(path, rec, base_sha, slab, self.error)
            # The runs by slabs, through the k-way stage: sorted and
            # reduced in blobs before the base gallops over them.
            cursors = [_BaseCursor(p, rec, sha, slab, self.error)
                       for p, sha in todo]
        records, sha, lad_sha, dups = merge_to_file(
            sources, self.path(out_name), rec, key_len,
            self.path(lad_name), every, dedup, dedup_len,
            dup_log=dup_log, base=base, cursors=cursors)

        delete = ([self.path(old["file"]),
                   self.path(self.state["caches"][logical]["file"])]
                  if old is not None else [])
        delete += self.run_paths(category)

        self.state["files"][logical] = {"file": out_name,
                                        "records": records,
                                        "sha256": sha}
        self.state["caches"][logical] = {"file": lad_name,
                                         "every": every,
                                         "sha256": lad_sha}
        self.state["runs"] = [r for r in self.state["runs"]
                              if r["category"] != category]
        self.state["generation"] = gen
        return dups, delete

    # -- state --------------------------------------------------------

    def write_state(self):
        if self.clock is not None:
            self.clock.stamp(self.state)
        atomic_json(self.path(self.state_name), self.state)

    def commit(self, delete):
        """The state first, the deletions after: the order IS the
        crash safety."""
        self.write_state()
        for path in delete:
            if os.path.exists(path):
                os.remove(path)

    # -- housekeeping -------------------------------------------------

    def clean_orphans(self, keep=()):
        """What the state does not name does not exist: runs from a
        crashed flush, merged generations from a crashed fusion, stray
        tmp files — all deleted on load, and their records will be
        produced again by the phase that re-runs.

        `keep` is the artifact's own top-level inventory (positional
        files and the like), which this sweep must not touch.

        The sweep is only a sweep when there IS a state on disk to
        measure the leftovers against. A directory holding runs or
        generations and no state is not a crash — a crash leaves a run
        or two unnamed, not everything — it is an artifact whose state
        was lost, or an `--out` pointed at the wrong place, and either
        way the files are somebody's hours. Refused, with everything
        left where it was. The same goes for the shape of a name: a
        generation is exactly `<logical>_g<4 digits>.bin|.lad`, and
        nothing else with `_g` in it is this store's to remove."""
        runs_dir = os.path.join(self.dir, self.runs_dir)
        fresh = not os.path.exists(self.path(self.state_name))
        stale_runs = []
        if os.path.isdir(runs_dir):
            known_runs = {r["name"] for r in self.state["runs"]}
            stale_runs = [name for name in sorted(os.listdir(runs_dir))
                          if name not in known_runs
                          and not os.path.isdir(os.path.join(runs_dir, name))]
        known_top = ({e["file"] for e in self.state["files"].values()}
                     | {e["file"] for e in self.state["caches"].values()}
                     | set(keep))
        stale_top = [name for name in sorted(os.listdir(self.dir))
                     if not os.path.isdir(self.path(name))
                     and (name.endswith(".tmp")
                          or (_GENERATION.fullmatch(name)
                              and name not in known_top))]
        if fresh and (stale_runs or stale_top):
            raise self.error(
                f"{self.dir}: no {self.state_name}, but the directory "
                f"holds {len(stale_runs)} run(s) and {len(stale_top)} "
                "generation or tmp file(s) — not a crash to sweep but a "
                "lost state or the wrong directory; restore the state, "
                "or start in an empty directory")
        for name in stale_runs:
            os.remove(os.path.join(runs_dir, name))
            print(f"  {self.label}: removed stale run {name} "
                  "(not named by the state)", file=sys.stderr)
        # A run the state names with a size the disk does not hold is
        # not a crash leftover: the state was written, the run's bytes
        # never reached the disk (a power loss, a mount that lied). No
        # phase re-produces those records, so the only honest answer is
        # to stop here, where the loss is one run, not at a fusion days
        # later with "sha256 mismatch".
        for run in self.state["runs"]:
            if "bytes" not in run:
                continue            # written before the field existed
            path = self.run_path(run["name"])
            actual = os.path.getsize(path) if os.path.exists(path) else -1
            if actual != run["bytes"]:
                raise self.error(
                    f"{path}: the state names this run with "
                    f"{run['bytes']:,} bytes but the disk holds "
                    f"{actual:,} — the run was lost after the state "
                    "was written (power loss?); the heights it covered "
                    "have to be scanned again")
        for name in stale_top:
            os.remove(self.path(name))
            print(f"  {self.label}: removed stale file {name} "
                  "(not named by the state)", file=sys.stderr)

    def truncate_appended(self, todo):
        """Files that grow in place are not committed atomically: a
        crash can leave a tail past the last checkpoint. The state's
        committed sizes are the truth — anything beyond them is cut,
        anything short of them is corruption.

        `todo` is a list of (filename, committed bytes)."""
        for name, committed in todo:
            path = self.path(name)
            actual = os.path.getsize(path) if os.path.exists(path) else 0
            if actual < committed:
                raise self.error(
                    f"{path}: {actual} bytes on disk but the state "
                    f"committed {committed} — the file was tampered "
                    "with or lost data")
            if actual > committed:
                with open(path, "ab") as f:
                    f.truncate(committed)
                    os.fsync(f.fileno())
                print(f"  {self.label}: truncated {name} to its "
                      f"committed {committed} bytes (tail past the "
                      "last checkpoint)", file=sys.stderr)
