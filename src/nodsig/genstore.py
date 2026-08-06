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
                          read_fixed)
from nodsig.recsort import write_run

# How many (dropped, kept) collision pairs merge_to_file keeps for a
# caller that asked: enough for every real duplicate the chain has
# (BIP30 produced two), small enough that a caller whose collisions are
# routine (an append's updated rows) cannot hoard memory by mistake.
DUP_LOG_CAP = 64


def new_state_fields():
    """The four keys a store owns, for an artifact's `_new_state()` to
    splice into its own. Kept here so the schema has one author."""
    return {"runs": [], "files": {}, "caches": {}, "generation": 0}


def merge_to_file(sources, out_path, rec, key_len, ladder_path,
                  ladder_every, dedup, dedup_len=None, dup_log=None):
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

    Returns (records, sha256, ladder_sha256, dup_count)."""
    if dedup_len is None:
        dedup_len = key_len
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
        pending = None
        for r in heapq.merge(*sources):
            if pending is not None:
                if r[:dedup_len] == pending[:dedup_len]:
                    dups += 1
                    if dup_log is not None and len(dup_log) < DUP_LOG_CAP:
                        dup_log.append((bytes(pending), bytes(r)))
                    if dedup == "last":
                        pending = r      # the later record wins
                        continue
                emit(pending)
                if len(buf) >= IO_CHUNK:
                    f.write(buf)
                    digest.update(buf)
                    buf.clear()
            pending = r
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
        sources = [self.read(p, rec, sha, slab) for p, sha in todo]
        if sift is not None:
            sources = [_sifted(s, sift) for s in sources]
        records, sha, lad_sha, dups = merge_to_file(
            sources, self.path(out_name), rec, key_len,
            self.path(lad_name), every, dedup, dedup_len,
            dup_log=dup_log)

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
