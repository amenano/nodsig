#!/usr/bin/env python3
"""FirstSpend-v1: when a lock was first spent from, ordered by that moment.

The derivatives answer "when was THIS lock first spent" one lock at a time;
they cannot enumerate WHICH locks were first spent inside a height range,
because history.bin is ordered by lock, not by time. This artifact
materialises that one missing order, as a read of the derivatives alone: no
node, no graph, no index at build time.

    firstspend.bin   25 B, big-endian, sorted by (spender_tx, lock):
        spender_tx:u40 | lock:hash160(20)

One row per lock EVER spent from, carrying the ordinal of the transaction
that first spent an output of it. A lock spent many times keeps only the
first; a lock never spent from has no row. The perimeter is history's:
"first spent from", not "first exposed" (the co-signer case is out).

The format is in docs/formats/FirstSpend-v1.md; the reconstruction, the
scale rule and the perimeter are stated there and pinned by the tests.
"""

import hashlib
import os
import sys
import time

from nodsig import derivatives as dv
from nodsig.artifact import (WallClock, declared_parent, identity_fingerprint,
                             make_identity, producer, seal_manifest,
                             verify_sealed)
from nodsig.genstore import GenStore, new_state_fields
from nodsig.recio import atomic_json, read_fixed, sha_file
from nodsig.recsort import SortedFile

FORMAT_TAG = "firstspend-v1"
STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
RUNS_DIR = "runs"
LOGICAL = "firstspend"

ORD = 5                              # a tx or output ordinal, u40
FS_REC = ORD + 20                    # spender_tx | lock  = 25
FS_KEY = ORD                         # searched by spender_tx
FS_EVERY = 2048                      # ~51 KB bucket, in line with the others
UNSPENT = 0                          # history's sentinel: never a real spender


class FirstSpendError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------

def _new_state():
    return {
        "format": FORMAT_TAG,
        "phase": "scan",
        # Records of the parent's history consumed up to the START of the
        # currently open lock group: a checkpoint sits on a lock boundary,
        # so a resume re-reads the open group and never a closed one.
        "hist_pos": 0,
        "coverage": None,               # the parent's, copied at open
        "source_fingerprint": None,     # binds an OPEN build to its parent
        "run_seq": 0,
        **new_state_fields(),
    }


def _store(out_dir, state, clock=None):
    return GenStore(out_dir, state, label="firstspend",
                    error=FirstSpendError, runs_dir=RUNS_DIR,
                    state_name=STATE_NAME, clock=clock)


def _load_state(out_dir, required=True):
    path = os.path.join(out_dir, STATE_NAME)
    if not os.path.exists(path):
        if required:
            raise FirstSpendError(f"no {STATE_NAME} in {out_dir}: run "
                                  "`build` first")
        return None
    import json
    with open(path) as f:
        state = json.load(f)
    if state.get("format") != FORMAT_TAG:
        raise FirstSpendError(f"not a {FORMAT_TAG} state: {out_dir}")
    return state


def _load_manifest(out_dir):
    path = os.path.join(out_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        raise FirstSpendError(f"no {MANIFEST_NAME} in {out_dir}: the table "
                              "is not sealed — run `build`")
    import json
    with open(path) as f:
        manifest = json.load(f)
    if manifest.get("format") != FORMAT_TAG:
        raise FirstSpendError("unknown firstspend manifest format")
    return manifest


# ---------------------------------------------------------------------------
# build — one pass over the parent's history, then a fusion, then a seal
# ---------------------------------------------------------------------------

def _history_source(derived_dir):
    """The sealed parent's history file, as everything a build reads off
    it. The parent must be `outpoint-derived-v3` and sealed: a BUILD is a
    stricter promise than a read, exactly as the derivatives refuse to be
    built from a v2 index. Its history row is 37 B
    (lock | out_ord | spender | value); only the lock and the spender are
    read here, but the whole record is streamed to keep the sha check."""
    man = dv._load_manifest(derived_dir, accept=(dv.FORMAT_TAG,))
    entry = man["build"]["files"]["history"]
    path = os.path.join(derived_dir, entry["file"])
    return (path, entry["sha256"], man["build"]["transactions"],
            man["fingerprint"], man["identity"]["coverage"],
            man["format"], dv.HIST_REC)


def run_build(derived_dir, out_dir, flush_records=8_000_000):
    """Build (or grow, or resume) the table from the sealed derivatives.

    Re-run after a crash (continues from the history cursor) or after the
    derivatives have grown (rebuilds from the grown history): one code
    path, and the same bytes a from-scratch build would seal.
    """
    (hist_path, hist_sha, n_tx, parent_fp, coverage,
     parent_fmt, hist_rec) = _history_source(derived_dir)

    os.makedirs(out_dir, exist_ok=True)
    state = _load_state(out_dir, required=False) or _new_state()
    clock = WallClock("append" if state["phase"] == "sealed" else "build",
                      state)
    store = _store(out_dir, state, clock=clock)
    store.clean_orphans()

    if state["phase"] == "sealed":
        # An APPEND: the derivatives grew, so the pass reopens from the
        # start of history against the new parent. A first spend never
        # moves, so a lock already placed re-emits the same row and the
        # merge's equal-key handling keeps one; but re-reading is the
        # honest road and it is cheap next to the fusion.
        if parent_fp == state["source_fingerprint"]:
            print("nothing to do: the table already covers this "
                  "derivatives seal", file=sys.stderr)
            return _load_manifest(out_dir)["fingerprint"]
        state["phase"] = "scan"
        state["hist_pos"] = 0
        state["source_fingerprint"] = None

    if state["source_fingerprint"] is None:
        state["source_fingerprint"] = parent_fp
        state["coverage"] = coverage
    elif state["source_fingerprint"] != parent_fp:
        raise FirstSpendError(
            "the derivatives changed while a firstspend build was open "
            "— finish that build against their original seal, or start "
            "a fresh directory")

    if state["phase"] == "scan":
        _phase_scan(store, hist_path, hist_sha, hist_rec, flush_records)
        state["phase"] = "merge"
        store.write_state()
    if state["phase"] == "merge":
        # dedup="last" over the WHOLE record: only exact duplicates
        # collapse. The append path relies on it — the pass re-emits
        # every row the previous generation already holds — and
        # dedup=None would keep both copies (it counts equal keys, it
        # does not collapse them), which the structural verify would
        # then refuse as an out-of-order file.
        _, delete = store.fuse(LOGICAL, (FS_REC, FS_KEY, FS_EVERY),
                               LOGICAL, dedup="last", dedup_len=FS_REC)
        state["phase"] = "seal"
        store.commit(delete)
    if state["phase"] == "seal":
        manifest = _seal(store, n_tx, parent_fmt, parent_fp)
        state["phase"] = "sealed"
        store.write_state()
        _print_manifest(manifest, out=sys.stdout)
    return _load_manifest(out_dir)["fingerprint"]


def _phase_scan(store, hist_path, hist_sha, hist_rec, flush_records):
    """One sequential pass over history.bin (sorted by (lock, out_ord)).

    Rows arrive grouped by lock. The minimum non-zero spender in a group
    is the lock's first spend; it is emitted when the group closes, or
    nothing if every spend in it is the unspent sentinel. Checkpoints sit
    on lock boundaries: `hist_pos` is the count of history records BEFORE
    the open group, so a resume re-reads that group and never a closed one.
    """
    state = store.state
    store.make_runs_dir()
    buf = []
    consumed = state["hist_pos"]         # records before the open group
    seen_in_group = 0                    # records of the open group so far
    cur_lock = None
    cur_first = None

    def flush():
        if not buf:
            return
        state["run_seq"] += 1
        name = f"run_{state['run_seq']:06d}_{LOGICAL}.bin"
        store.write_run(name, LOGICAL, buf)
        buf.clear()

    def checkpoint():
        # Everything up to the open group is in a run and named by the
        # state; the open group is not emitted, so the cursor points at
        # its first record and a resume redoes only it.
        flush()
        state["hist_pos"] = consumed
        store.write_state()

    # The sha is verified only on a full pass from the start; a resume
    # seeks into the file, and read_fixed refuses to claim a whole-file
    # sha over a partial stream. The parent is sealed and immutable, so a
    # resumed cursor reads bytes that were checked when they were written.
    start = state["hist_pos"]
    expect = hist_sha if start == 0 else None
    last_cp = time.monotonic()
    for rec in read_fixed(hist_path, hist_rec, expect_sha=expect,
                          start_record=start, error=FirstSpendError):
        lock = rec[:20]
        spender = int.from_bytes(rec[20 + ORD:20 + ORD + ORD], "big")
        if lock != cur_lock:
            if cur_lock is not None and cur_first is not None:
                buf.append(cur_first.to_bytes(ORD, "big") + cur_lock)
            # the group that just closed is now accounted for
            consumed += seen_in_group
            seen_in_group = 0
            cur_lock, cur_first = lock, None
            if len(buf) >= flush_records \
                    or time.monotonic() - last_cp > 300:
                checkpoint()
                last_cp = time.monotonic()
        seen_in_group += 1
        if spender != UNSPENT and (cur_first is None or spender < cur_first):
            cur_first = spender
    # close the last open group
    if cur_lock is not None and cur_first is not None:
        buf.append(cur_first.to_bytes(ORD, "big") + cur_lock)
    consumed += seen_in_group
    flush()
    state["hist_pos"] = consumed
    store.write_state()


def _seal(store, n_tx, parent_fmt, parent_fp):
    state = store.state
    entry = state["files"][LOGICAL]
    path = store.path(entry["file"])
    files = {LOGICAL: {"file": entry["file"], "records": entry["records"],
                       "sha256": entry["sha256"]}}
    frm, to = state["coverage"]["from"], state["coverage"]["to"]
    identity = make_identity(FORMAT_TAG, frm, to,
                             [(LOGICAL, entry["sha256"])])
    fingerprint = identity_fingerprint(identity)
    manifest = seal_manifest(FORMAT_TAG, identity, {
        "producer": producer(),
        "seconds": store.clock.stamp(),
        "wall": store.clock.wall(),
        # The parent's OWN tag from its manifest, never this code's
        # constant: a table can be built over a derivatives directory in
        # the previous format, and the identity binds the ordinals it is
        # keyed by.
        "parent": declared_parent(parent_fmt, parent_fp),
        "rows": entry["records"],
        "transactions": n_tx,
        "files": files,
        "caches": {LOGICAL: state["caches"][LOGICAL]},
        "generation": state["generation"],
        "reconstruction": (
            "one pass over the parent derivatives' history.bin (sorted by "
            "(lock, output_ordinal)): for each lock, the minimum non-zero "
            "spender ordinal in its group is emitted as (spender_tx, lock); "
            "a lock with only unspent rows emits nothing. Rows are sorted "
            "by (spender_tx, lock) and the identity is sealed by the shared "
            "recipe in docs/contracts/Artifact.md, over the one logical "
            "file `firstspend`, keyed by spender_tx"),
    })
    atomic_json(store.path(MANIFEST_NAME), manifest)
    return manifest


def _print_manifest(manifest, out):
    cov = manifest["identity"]["coverage"]
    print(f"firstspend table sealed: heights "
          f"{cov['from']:,}..{cov['to']:,}", file=out)
    print(f"  rows             {manifest['build']['rows']:,} "
          f"(locks ever spent from)", file=out)
    p = manifest["build"]["parent"]
    print(f"  parent {p['format']}: {p['fingerprint']}  (declared)", file=out)
    print(f"fingerprint: {manifest['fingerprint']}", file=out)


# ---------------------------------------------------------------------------
# rewind — follow the derivatives back to a lower coverage
# ---------------------------------------------------------------------------

def run_rewind(out_dir, derived_dir):
    """Take the sealed table back to the coverage its derivatives now
    hold, so its bytes equal those of a build that had stopped there.

    There is no height argument, and that is deliberate: this table has
    never chosen its own coverage, it follows the derivatives (which
    follow the index). Rewind the index, then the derivatives, then run
    this: it drops every row whose spender is at or above the parent's
    (now lower) transaction count. A first spend is the MINIMUM spender
    of a lock, so if it is above the cut every spend of that lock is, and
    the lock is simply not spent yet at the target: the row is dropped,
    never rewritten. That is why this is the cleanest rewind here.
    """
    (_hp, _hs, n_tx, parent_fp, coverage,
     parent_fmt, _hr) = _history_source(derived_dir)
    state = _load_state(out_dir)
    clock = WallClock("rewind", state)
    store = _store(out_dir, state, clock=clock)
    store.clean_orphans()

    if state["phase"] == "sealed":
        old_to = state["coverage"]["to"]
        if coverage["to"] > old_to:
            raise FirstSpendError(
                f"the derivatives cover height {coverage['to']}, ABOVE this "
                f"table's {old_to}: that is a build/append, not a rewind")
        if coverage["to"] == old_to and parent_fp == \
                state["source_fingerprint"]:
            print("nothing to do: the table already sits at the "
                  "derivatives' coverage", file=sys.stderr)
            return _load_manifest(out_dir)["fingerprint"]
        state["phase"] = "rewind"
        state["rewind"] = {"transactions": n_tx, "coverage": coverage}
        store.write_state()
    elif state["phase"] != "rewind":
        raise FirstSpendError(
            f"the table is in phase {state['phase']}, not sealed: finish "
            "`build` before rewinding")

    tx_cut = state["rewind"]["transactions"].to_bytes(ORD, "big")

    def sift(rec):
        # rec = spender(5) | lock(20); drop what the target has not reached.
        return None if rec[:ORD] >= tx_cut else bytes(rec)

    _, delete = store.fuse(LOGICAL, (FS_REC, FS_KEY, FS_EVERY), LOGICAL,
                           dedup=None, dedup_len=FS_REC, sift=sift)
    state["coverage"] = state["rewind"]["coverage"]
    state["source_fingerprint"] = parent_fp
    state["hist_pos"] = 0
    store.commit(delete)

    manifest = _seal(store, n_tx, parent_fmt, parent_fp)
    state["phase"] = "sealed"
    del state["rewind"]
    store.write_state()
    _print_manifest(manifest, out=sys.stdout)
    return manifest["fingerprint"]


# ---------------------------------------------------------------------------
# stats — read the sealed table back
# ---------------------------------------------------------------------------

def run_stats(out_dir, out=sys.stdout):
    manifest = _load_manifest(out_dir)
    cov = manifest["identity"]["coverage"]
    print(f"phase: sealed   heights {cov['from']:,}..{cov['to']:,}", file=out)
    print(f"  rows (locks first-spent)  {manifest['build']['rows']:,}",
          file=out)
    print(f"  parent transactions       {manifest['build']['transactions']:,}",
          file=out)
    print(f"fingerprint: {manifest['fingerprint']}", file=out)
    return manifest["fingerprint"]


# ---------------------------------------------------------------------------
# verify — the audit of a sealed table
# ---------------------------------------------------------------------------

FP_ORDER = (LOGICAL,)
LADDERS = {LOGICAL: (FS_REC, FS_KEY, FS_EVERY)}
_SAMPLE = 512                        # locks confronted against the parent


def run_verify(out_dir, derived_dir=None, out=sys.stdout):
    """Re-read every byte against the manifest, then run the two checks a
    checksum cannot make.

    `verify_sealed` does the shared audit: the data file and its ladder
    (rebuilt from the file it indexes, not trusted), and the fingerprint
    recomputed from what is on disk. On top of it, two checks specific to
    this table:

    - **structural**, over the whole file: rows strictly increasing by
      (spender_tx, lock), and every spender below the transaction count
      the manifest declares. This is the pass the seal made anyway.
    - **sampled, against the other road** (only with `--derived`): for a
      spread of locks drawn from the file, the first spend it records must
      equal the minimum non-unspent spender the parent's history.bin
      reports for that lock, read the long way through its ladder. It is
      the only check that confronts this artifact with something it did
      not build itself, and it needs the parent to make it.

    Without `--derived` the audit says the parent and that second road
    were taken on trust, and names the flag that would supply them."""
    manifest = _load_manifest(out_dir)
    parent_confirmed = None
    hist = None
    if derived_dir is not None:
        (hist_path, hist_sha, _n_tx, parent_fp, _cov,
         _fmt, hist_rec) = _history_source(derived_dir)
        declared = manifest["build"]["parent"]
        if declared is None or declared["fingerprint"] != parent_fp:
            raise FirstSpendError(
                "those derivatives are not this table's parent "
                "(fingerprints differ): the sampled check would compare "
                "against the wrong history")
        parent_confirmed = True
        hist = (derived_dir, hist_path, hist_sha, hist_rec)

    verify_sealed(out_dir, manifest, FORMAT_TAG, FirstSpendError,
                  fp_order=FP_ORDER, ladders=LADDERS,
                  coverage_from_data=None, trust_hint="--derived",
                  parent_confirmed=parent_confirmed)

    _verify_structural(out_dir, manifest, out)
    if hist is not None:
        _verify_against_parent(out_dir, manifest, hist, out)
    else:
        print("  parent and first-spend values taken on trust "
              "(pass --derived to confront them)", file=out)
    return manifest["fingerprint"]


def _verify_structural(out_dir, manifest, out):
    """One pass over firstspend.bin: strictly increasing, and every
    spender below the parent's transaction count."""
    entry = manifest["build"]["files"][LOGICAL]
    n_tx = manifest["build"]["transactions"]
    path = os.path.join(out_dir, entry["file"])
    prev = None
    rows = 0
    for rec in read_fixed(path, FS_REC, expect_sha=entry["sha256"],
                          error=FirstSpendError):
        if prev is not None and rec <= prev:
            raise FirstSpendError(
                f"row {rows} is not strictly after the one before it: "
                "the file is out of order or holds a duplicate")
        spender = int.from_bytes(rec[:ORD], "big")
        if spender == UNSPENT:
            raise FirstSpendError(
                f"row {rows} carries spender 0, the unspent sentinel, "
                "which is never a first spend")
        if spender >= n_tx:
            raise FirstSpendError(
                f"row {rows} names spender {spender}, but the parent has "
                f"only {n_tx} transactions: this file does not belong to "
                "that parent")
        prev = rec
        rows += 1
    print(f"  ok  {rows:,} rows strictly increasing, every spender < "
          f"{n_tx:,}", file=out)


def _verify_against_parent(out_dir, manifest, hist, out):
    """Sampled second road: for a spread of locks in the table, the first
    spend recorded must equal what the parent's history says, read
    independently through its ladder."""
    derived_dir, hist_path, hist_sha, hist_rec = hist
    dman = dv._load_manifest(derived_dir, accept=(dv.FORMAT_TAG,))
    hentry = dman["build"]["files"]["history"]
    hcache = dman["build"]["caches"]["history"]
    with open(os.path.join(derived_dir, hcache["file"]), "rb") as f:
        blob = f.read()
    if hashlib.sha256(blob).hexdigest() != hcache["sha256"]:
        raise FirstSpendError("the parent's history ladder is corrupt")
    sf = SortedFile(hist_path, hist_rec, dv.HIST_KEY, hentry["records"],
                    blob, hcache["every"], error=FirstSpendError)
    try:
        entry = manifest["build"]["files"][LOGICAL]
        rows = manifest["build"]["rows"]
        step = max(1, rows // _SAMPLE)
        path = os.path.join(out_dir, entry["file"])
        checked = 0
        with open(path, "rb") as f:
            for i in range(0, rows, step):
                f.seek(i * FS_REC)
                rec = f.read(FS_REC)
                spender = int.from_bytes(rec[:ORD], "big")
                lock = rec[ORD:]
                # The other road: read this lock's history and take the
                # minimum non-unspent spender, the same rule the build used.
                first = None
                for hrec in sf.scan(lock):
                    sp = int.from_bytes(hrec[25:30], "big")
                    if sp != UNSPENT and (first is None or sp < first):
                        first = sp
                if first != spender:
                    raise FirstSpendError(
                        f"lock {lock.hex()}: the table says first spend "
                        f"{spender}, the parent's history says {first}")
                checked += 1
        print(f"  ok  {checked:,} sampled locks agree with the parent's "
              "history (first spend re-derived the long way)", file=out)
    finally:
        sf.close()


# ---------------------------------------------------------------------------
# between — the locks first spent inside a height window
# ---------------------------------------------------------------------------

def _sorted_firstspend(out_dir, manifest):
    """A SortedFile over the sealed table, its ladder verified."""
    entry = manifest["build"]["files"][LOGICAL]
    cache = manifest["build"]["caches"][LOGICAL]
    with open(os.path.join(out_dir, cache["file"]), "rb") as f:
        blob = f.read()
    if hashlib.sha256(blob).hexdigest() != cache["sha256"]:
        raise FirstSpendError(f"{cache['file']}: corrupted ladder")
    return SortedFile(os.path.join(out_dir, entry["file"]), FS_REC, FS_KEY,
                      manifest["build"]["rows"], blob, cache["every"],
                      error=FirstSpendError)


def run_between(out_dir, index_dir, from_h, to_h, out=sys.stdout):
    """The locks whose FIRST spend falls in heights [from_h, to_h].

    This is the read the artifact exists for: history answers it one lock
    at a time, this answers it one WINDOW at a time, as a contiguous scan.
    The index turns the height window into an ordinal window (blocks.bin
    holds the first transaction ordinal of each height), and the table,
    sorted by that ordinal, is then read as a half-open range.

    The index must be this table's ancestor: firstspend is built on the
    derivatives, the derivatives on the index, and the spender ordinals
    are the index's. The binding by fingerprint is `verify --derived`'s
    job (this table declares the derivatives, not the index); here the
    index is asked only to cover the window, and passing an index of a
    different chain would answer with the wrong heights.
    """
    from nodsig import outpoint_index as oi
    if from_h < 1:
        raise FirstSpendError(f"--from {from_h} is below height 1")
    if from_h > to_h:
        raise FirstSpendError(f"--from {from_h} is above --to {to_h}")
    index = oi.Index(index_dir)
    try:
        manifest = _load_manifest(out_dir)
        if to_h > index.watermark:
            raise FirstSpendError(
                f"--to {to_h} is past the index watermark "
                f"{index.watermark}")
        # first_tx[h-1] is the first tx ordinal of height h; the window is
        # [first_tx of from_h, first_tx of to_h+1), the second being the
        # tx count when to_h is the last height.
        lo = index.first_tx[from_h - 1]
        hi = (index.first_tx[to_h] if to_h < index.watermark
              else index.n_tx)
        sf = _sorted_firstspend(out_dir, manifest)
        try:
            n = 0
            for rec in sf.scan_range(lo.to_bytes(ORD, "big"),
                                     hi.to_bytes(ORD, "big")):
                spender = int.from_bytes(rec[:ORD], "big")
                lock = rec[ORD:]
                print(f"{lock.hex()}  first spent at height "
                      f"{index.height_of_tx(spender):,} (tx {spender:,})",
                      file=out)
                n += 1
            print(f"# {n:,} lock(s) first spent in heights "
                  f"{from_h:,}..{to_h:,}", file=out)
            return n
        finally:
            sf.close()
    finally:
        index.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog="nodsig firstspend",
        description="when each lock was first spent from, ordered by that "
                    "moment (a read of the derivatives)")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build/grow the table from sealed "
                                     "derivatives")
    b.add_argument("--derived", required=True,
                   help="a sealed outpoint-derived directory")
    b.add_argument("--out", required=True,
                   help="the firstspend directory to create or grow")
    b.add_argument("--flush-records", type=int, default=8_000_000,
                   help="buffered rows before a run flush (memory knob)")

    s = sub.add_parser("stats", help="read a sealed table's manifest")
    s.add_argument("--firstspend", required=True)

    v = sub.add_parser("verify", help="audit a sealed table; --derived adds "
                                      "the second road")
    v.add_argument("--firstspend", required=True)
    v.add_argument("--derived",
                   help="the parent derivatives, to confront the declared "
                        "parent and re-derive a sample of first spends")

    bt = sub.add_parser("between", help="locks first spent in a height "
                                        "window (a contiguous read)")
    bt.add_argument("--firstspend", required=True)
    bt.add_argument("--index", required=True,
                    help="the parent index, to turn heights into ordinals")
    bt.add_argument("--from", dest="from_h", type=int, required=True)
    bt.add_argument("--to", dest="to_h", type=int, required=True)

    rw = sub.add_parser("rewind", help="follow the derivatives back to a "
                                       "lower coverage (no height argument)")
    rw.add_argument("--firstspend", required=True)
    rw.add_argument("--derived", required=True,
                    help="the derivatives, already rewound to the target")

    args = p.parse_args(argv)
    if args.cmd == "build":
        run_build(args.derived, args.out, flush_records=args.flush_records)
    elif args.cmd == "stats":
        run_stats(args.firstspend)
    elif args.cmd == "verify":
        run_verify(args.firstspend, derived_dir=args.derived)
    elif args.cmd == "between":
        run_between(args.firstspend, args.index, args.from_h, args.to_h)
    elif args.cmd == "rewind":
        run_rewind(args.firstspend, args.derived)
    return 0


if __name__ == "__main__":
    sys.exit(main())
