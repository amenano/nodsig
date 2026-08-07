#!/usr/bin/env python3
"""
genstore.py — the APPEND-AND-FUSE STORE shared by every artifact that
grows by generations: sorted runs pile up, a fusion folds them into the
next generation of a merged file, and the state file is the only truth
about what exists on disk.

Two artifacts are built this way (outpoint-index-v2 and
outpoint-derived-v2) and a third one, reveal-archive-v2, is the same
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
import sys

from nodsig.recio import (IO_CHUNK, atomic_json, budgeted_slab, checked_name,
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


def _adjacent_equal(slab, off, count, rec, dedup_len):
    """How many of the `count` records at `slab[off:]` share their
    dedup prefix with the record BEFORE them — i.e. how many duplicate
    pairs a stretch of already-sorted records contains.

    This is the one thing a bulk copy must not skip: the fusion's dup
    count is an OUTPUT, checked against a second road (the nonces
    archive compares it with a full pass over the file it wrote), so a
    faster path that copied bytes without counting would return a
    different number for the same input.

    Counted a COLUMN at a time instead of a record at a time. The j-th
    byte of every record is one strided slice, so one XOR of two such
    slices, read as big integers, answers the question for every pair
    at once: a zero byte in the result is a pair that agrees on that
    column. Columns are OR-ed from the LAST byte of the prefix
    backwards — the byte that differs first in a dense key like an
    ordinal — until the surviving candidates are rare enough to be
    worth checking one by one, and those few are then compared in full.
    The narrowing is a heuristic; the answer is not, because every
    candidate is settled by comparing the whole prefix.
    """
    if count < 2:
        return 0
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
            break
        j -= 1
    found = 0
    i = mask.find(0)
    while i >= 0:
        o = off + i * rec
        if slab[o:o + dedup_len] == slab[o + rec:o + rec + dedup_len]:
            found += 1
        i = mask.find(0, i + 1)
    return found


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


def merge_to_file(sources, out_path, rec, key_len, ladder_path,
                  ladder_every, dedup, dedup_len=None, dup_log=None,
                  base=None):
    """Fuse sorted record streams into one file, sampling the ladder
    while writing — the cache costs no extra pass.

    dedup="last": equal keys collapse to the LAST record of the run —
    which, keys and payloads being big-endian, is the numerically
    greatest payload: for the resolver that is the highest first_out,
    i.e. the BIP30 rule "the later duplicate overwrote the earlier".
    dedup=None: nothing is dropped, but equal keys are still counted
    (spends.bin expects that count to be 0 under consensus).

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

    Returns (records, sha256, ladder_sha256, dup_count)."""
    if dedup_len is None:
        dedup_len = key_len
    if dedup_len > rec:
        dedup_len = rec      # a prefix longer than the record IS the
                             # record, and saying so once keeps the
                             # per-column scan and the slicing agreed
    keep_last = dedup == "last"
    digest = hashlib.sha256()
    ladder = bytearray()
    buf = bytearray()
    records = 0
    dups = 0

    def emit(r):
        nonlocal records
        if records % ladder_every == 0:
            ladder.extend(r[:key_len])
        buf.extend(r)
        records += 1

    tmp = out_path + ".tmp"
    with open(tmp, "wb") as f:
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
                    if keep_last:
                        pending = r          # the later record wins
                        if from_base:
                            head = base.peek()
                        continue             # one bulk missed, no more
                emit(pending)
                if len(buf) >= IO_CHUNK:
                    f.write(buf)
                    digest.update(buf)
                    buf.clear()
            pending = r

            if from_base:
                # `r` is the first of `clear` base records that nothing
                # interleaves. Settle them all here, holding the last
                # back as `pending` so the record after it can still be
                # compared against it.
                if clear >= MIN_BULK and off0 >= base.plain_until:
                    slab = base.slab
                    d = _adjacent_equal(slab, off0, clear, rec, dedup_len)
                    if d == 0 or (not keep_last and dup_log is None):
                        dups += d
                        moved = clear - 1
                        step = (-records) % ladder_every
                        for j in range(step, moved, ladder_every):
                            o = off0 + j * rec
                            ladder.extend(slab[o:o + key_len])
                        buf.extend(slab[off0:off0 + moved * rec])
                        records += moved
                        if len(buf) >= IO_CHUNK:
                            f.write(buf)
                            digest.update(buf)
                            buf.clear()
                        base.off = off0 + clear * rec
                        base.clear = 0   # the next one is not below it
                        pending = slab[base.off - rec:base.off]
                    else:
                        base.plain_until = off0 + clear * rec
                head = base.peek()
        if pending is not None:
            emit(pending)
        if buf:
            f.write(buf)
            digest.update(buf)
    os.replace(tmp, out_path)

    ladder_sha = hashlib.sha256(ladder).hexdigest()
    tmp = ladder_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(ladder)
    os.replace(tmp, ladder_path)
    return records, digest.hexdigest(), ladder_sha, dups


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
        entry = {"name": name, "category": category,
                 "records": count, "sha256": sha}
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
        if old is not None and sift is None:
            path, base_sha = todo.pop(0)
            base = _BaseCursor(path, rec, base_sha, slab, self.error)
        sources = [self.read(p, rec, sha, slab) for p, sha in todo]
        if sift is not None:
            sources = [_sifted(s, sift) for s in sources]
        records, sha, lad_sha, dups = merge_to_file(
            sources, self.path(out_name), rec, key_len,
            self.path(lad_name), every, dedup, dedup_len,
            dup_log=dup_log, base=base)

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
        files and the like), which this sweep must not touch."""
        known_runs = {r["name"] for r in self.state["runs"]}
        runs_dir = os.path.join(self.dir, self.runs_dir)
        if os.path.isdir(runs_dir):
            for name in os.listdir(runs_dir):
                if name not in known_runs:
                    os.remove(os.path.join(runs_dir, name))
                    print(f"  {self.label}: removed stale run {name} "
                          "(crash leftover)", file=sys.stderr)
        known_top = ({e["file"] for e in self.state["files"].values()}
                     | {e["file"] for e in self.state["caches"].values()}
                     | set(keep))
        for name in os.listdir(self.dir):
            if name.endswith(".tmp") or ("_g" in name
                                         and name not in known_top):
                os.remove(self.path(name))
                print(f"  {self.label}: removed stale file {name} "
                      "(crash leftover)", file=sys.stderr)

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
                print(f"  {self.label}: truncated {name} to its "
                      f"committed {committed} bytes (crash leftover)",
                      file=sys.stderr)
