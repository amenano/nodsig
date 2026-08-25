#!/usr/bin/env python3
"""FirstReveal-v1: when each public key was first revealed, by that moment.

The reveal archive answers "was THIS key ever revealed, and when" one
digest at a time; it cannot enumerate WHICH keys were first revealed
inside a height range, because its records are ordered by digest, not by
time. This artifact materialises that one missing order, as a read of the
archive's `keys` partition alone: no node, no graph, no index at build
time.

    firstreveal.bin   23 B, big-endian, sorted by (first_height, key):
        first_height:u24 | key:hash160(20)

One row per revealed key — the archive's `keys` partition verbatim, one
record in, one row out — carrying the height its digest was first seen
at. The perimeter is the archive's: serialized public keys (33 or 65
bytes), where the two serializations of one point are two digests;
revealed scripts live in the archive's other partitions and stay out;
taproot x-only keys are not collected (there the key IS the output). The
sighting flags stay in the archive on purpose: they are OR-ed across ALL
sightings and an append can add bits to them, while a first height can
only be joined by later, higher ones — this table carries exactly the
field that never moves. This format has no rewind because its parent has
none: a first sighting cannot be un-seen.

The format is in docs/formats/FirstReveal-v1.md; the reconstruction, the
scale rule and the perimeter are stated there and pinned by the tests.
"""

import hashlib
import os
import sys
import time

from nodsig import reveal_archive as ra
from nodsig.artifact import (WallClock, declared_parent, identity_fingerprint,
                             make_identity, producer, seal_manifest,
                             verify_sealed)
from nodsig.genstore import GenStore, new_state_fields
from nodsig.recio import atomic_json, read_fixed
from nodsig.recsort import SortedFile

FORMAT_TAG = "firstreveal-v1"
STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
RUNS_DIR = "runs"
LOGICAL = "firstreveal"
CAT = "keys"                         # the one archive partition read

H = 3                                # a height, u24 — the archive's own width
FR_REC = H + 20                      # first_height | key  = 23
FR_KEY = H                           # searched by height
FR_EVERY = 2048                      # ~47 KB bucket, in line with the others
KEYS_REC = ra.rec_width(CAT)         # the parent record: digest | flags | h


class FirstRevealError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------

def _new_state():
    return {
        "format": FORMAT_TAG,
        "phase": "scan",
        # Records of the parent's keys file consumed so far: each one is
        # exactly one emitted row, so the cursor needs no group logic.
        "keys_pos": 0,
        "coverage": None,               # the parent's, copied at open
        "source_fingerprint": None,     # binds an OPEN build to its parent
        "run_seq": 0,
        **new_state_fields(),
    }


def _store(out_dir, state, clock=None):
    return GenStore(out_dir, state, label="firstreveal",
                    error=FirstRevealError, runs_dir=RUNS_DIR,
                    state_name=STATE_NAME, clock=clock)


def _load_state(out_dir, required=True):
    path = os.path.join(out_dir, STATE_NAME)
    if not os.path.exists(path):
        if required:
            raise FirstRevealError(f"no {STATE_NAME} in {out_dir}: run "
                                   "`build` first")
        return None
    import json
    with open(path) as f:
        state = json.load(f)
    if state.get("format") != FORMAT_TAG:
        raise FirstRevealError(f"not a {FORMAT_TAG} state: {out_dir}")
    return state


def _load_manifest(out_dir):
    path = os.path.join(out_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        raise FirstRevealError(f"no {MANIFEST_NAME} in {out_dir}: the table "
                               "is not sealed — run `build`")
    import json
    with open(path) as f:
        manifest = json.load(f)
    if manifest.get("format") != FORMAT_TAG:
        raise FirstRevealError("unknown firstreveal manifest format")
    return manifest


# ---------------------------------------------------------------------------
# build — one pass over the parent's keys partition, a fusion, a seal
# ---------------------------------------------------------------------------

def _archive_source(archive_dir):
    """The sealed parent's keys file, as everything a build reads off it.

    The parent must be MERGED and have no pending runs: a run not yet
    fused holds sightings the merged file does not, so a table built
    beside it would claim the archive's coverage while missing keys. A
    BUILD is a stricter promise than a read (the exposure checker is
    happy to OR runs in; this refuses them), exactly as firstspend
    refuses an unsealed derivatives directory."""
    state = ra._load_state(archive_dir)
    manifest = ra._load_manifest(archive_dir)
    if manifest is None:
        raise FirstRevealError(
            f"no sealed archive in {archive_dir}: run `archive merge` first")
    if state["runs"]:
        raise FirstRevealError(
            "the archive has unfused runs: their sightings are not in the "
            "merged keys file yet — run `archive merge`, then build")
    entry = manifest["build"]["files"][CAT]
    path = os.path.join(archive_dir, ra._cat_file(manifest, CAT))
    return (path, ra._cat_sha(manifest, CAT), entry["records"],
            manifest["fingerprint"], manifest["identity"]["coverage"],
            manifest["format"])


def run_build(archive_dir, out_dir, flush_records=8_000_000):
    """Build (or grow, or resume) the table from the sealed archive.

    Re-run after a crash (continues from the keys cursor) or after the
    archive has grown (rebuilds from the grown keys file): one code
    path, and the same bytes a from-scratch build would seal.
    """
    (keys_path, keys_sha, keys_records, parent_fp,
     coverage, parent_fmt) = _archive_source(archive_dir)

    os.makedirs(out_dir, exist_ok=True)
    state = _load_state(out_dir, required=False) or _new_state()
    clock = WallClock("append" if state["phase"] == "sealed" else "build",
                      state)
    store = _store(out_dir, state, clock=clock)
    store.clean_orphans()

    if state["phase"] == "sealed":
        # An APPEND: the archive grew, so the pass reopens from the start
        # of the keys file against the new seal. A first height never
        # moves (later sightings are higher by construction), so a key
        # already placed re-emits the same row and the merge's duplicate
        # handling keeps one; re-reading is the honest road and it is
        # cheap next to the fusion.
        if parent_fp == state["source_fingerprint"]:
            print("nothing to do: the table already covers this "
                  "archive seal", file=sys.stderr)
            return _load_manifest(out_dir)["fingerprint"]
        state["phase"] = "scan"
        state["keys_pos"] = 0
        state["source_fingerprint"] = None

    if state["source_fingerprint"] is None:
        state["source_fingerprint"] = parent_fp
        state["coverage"] = coverage
    elif state["source_fingerprint"] != parent_fp:
        raise FirstRevealError(
            "the archive changed while a firstreveal build was open — "
            "finish that build against its original seal, or start a "
            "fresh directory")

    if state["phase"] == "scan":
        _phase_scan(store, keys_path, keys_sha, flush_records)
        state["phase"] = "merge"
        store.write_state()
    if state["phase"] == "merge":
        # dedup="last" over the WHOLE record: only exact duplicates
        # collapse — which is precisely the append case, where the pass
        # re-emits every row the previous generation already holds. Two
        # rows that differ anywhere both survive, and the structural
        # verify would then refuse the file: nothing is ever dropped
        # silently. (dedup=None would keep both copies: it counts equal
        # keys, it does not collapse them.)
        _, delete = store.fuse(LOGICAL, (FR_REC, FR_KEY, FR_EVERY),
                               LOGICAL, dedup="last", dedup_len=FR_REC)
        state["phase"] = "seal"
        store.commit(delete)
    if state["phase"] == "seal":
        manifest = _seal(store, keys_records, parent_fmt, parent_fp)
        state["phase"] = "sealed"
        store.write_state()
        _print_manifest(manifest, out=sys.stdout)
    return _load_manifest(out_dir)["fingerprint"]


def _phase_scan(store, keys_path, keys_sha, flush_records):
    """One sequential pass over the archive's keys file (sorted by
    digest). Each 24-byte record is one row: the trailing height moves
    to the front and the digest follows, so the run sort puts time
    first. The cursor is a plain record count — every parent record
    emits exactly one row, so a checkpoint can sit anywhere."""
    state = store.state
    store.make_runs_dir()
    buf = []

    def flush():
        if not buf:
            return
        state["run_seq"] += 1
        name = f"run_{state['run_seq']:06d}_{LOGICAL}.bin"
        store.write_run(name, LOGICAL, buf)
        buf.clear()

    def checkpoint():
        flush()
        state["keys_pos"] = consumed
        store.write_state()

    # The sha is verified only on a full pass from the start; a resume
    # seeks into the file, and read_fixed refuses to claim a whole-file
    # sha over a partial stream. The parent is sealed and immutable, so a
    # resumed cursor reads bytes that were checked when they were written.
    start = state["keys_pos"]
    consumed = start
    expect = keys_sha if start == 0 else None
    last_cp = time.monotonic()
    for rec in read_fixed(keys_path, KEYS_REC, expect_sha=expect,
                          start_record=start, error=FirstRevealError):
        buf.append(bytes(rec[KEYS_REC - H:]) + bytes(rec[:20]))
        consumed += 1
        if len(buf) >= flush_records or time.monotonic() - last_cp > 300:
            checkpoint()
            last_cp = time.monotonic()
    flush()
    state["keys_pos"] = consumed
    store.write_state()


def _seal(store, keys_records, parent_fmt, parent_fp):
    state = store.state
    entry = state["files"][LOGICAL]
    files = {LOGICAL: {"file": entry["file"], "records": entry["records"],
                       "sha256": entry["sha256"]}}
    frm, to = state["coverage"]["from"], state["coverage"]["to"]
    identity = make_identity(FORMAT_TAG, frm, to,
                             [(LOGICAL, entry["sha256"])])
    manifest = seal_manifest(FORMAT_TAG, identity, {
        "producer": producer(),
        "seconds": store.clock.stamp(),
        "wall": store.clock.wall(),
        # The parent's OWN tag from its manifest, never this code's
        # constant: a table can be built over an archive in an earlier
        # format, and the identity binds the heights it is keyed by.
        "parent": declared_parent(parent_fmt, parent_fp),
        "rows": entry["records"],
        "parent_keys": keys_records,
        "files": files,
        "caches": {LOGICAL: state["caches"][LOGICAL]},
        "generation": state["generation"],
        "reconstruction": (
            "one pass over the parent archive's merged keys partition "
            "(sorted by digest, 24-byte records digest20|flags|height): "
            "each record emits (first_height, digest) with the flags "
            "dropped; nothing else is read and nothing is filtered, so "
            "rows equal the parent's keys records. Rows are sorted by "
            "(first_height, key) and the identity is sealed by the shared "
            "recipe in docs/contracts/Artifact.md, over the one logical "
            "file `firstreveal`, keyed by first_height"),
    })
    atomic_json(store.path(MANIFEST_NAME), manifest)
    return manifest


def _print_manifest(manifest, out):
    cov = manifest["identity"]["coverage"]
    print(f"firstreveal table sealed: heights "
          f"{cov['from']:,}..{cov['to']:,}", file=out)
    print(f"  rows             {manifest['build']['rows']:,} "
          f"(keys ever revealed)", file=out)
    p = manifest["build"]["parent"]
    print(f"  parent {p['format']}: {p['fingerprint']}  (declared)", file=out)
    print(f"fingerprint: {manifest['fingerprint']}", file=out)


# ---------------------------------------------------------------------------
# stats — read the sealed table back
# ---------------------------------------------------------------------------

def run_stats(out_dir, out=sys.stdout):
    manifest = _load_manifest(out_dir)
    cov = manifest["identity"]["coverage"]
    print(f"phase: sealed   heights {cov['from']:,}..{cov['to']:,}", file=out)
    print(f"  rows (keys first-revealed)  {manifest['build']['rows']:,}",
          file=out)
    p = manifest["build"]["parent"]
    print(f"  parent {p['format']}          {p['fingerprint']}", file=out)
    print(f"fingerprint: {manifest['fingerprint']}", file=out)
    return manifest["fingerprint"]


# ---------------------------------------------------------------------------
# verify — the audit of a sealed table
# ---------------------------------------------------------------------------

FP_ORDER = (LOGICAL,)
LADDERS = {LOGICAL: (FR_REC, FR_KEY, FR_EVERY)}
_SAMPLE = 512                        # keys confronted against the parent


def _floor_from_data(out_dir, manifest):
    """The highest first_height in the file — its last record, since the
    file is sorted by height. A FLOOR for the declared coverage: a
    stretch of chain with no new revelation leaves no trace above it."""
    entry = manifest["build"]["files"][LOGICAL]
    if entry["records"] == 0:
        return None
    path = os.path.join(out_dir, entry["file"])
    with open(path, "rb") as f:
        f.seek((entry["records"] - 1) * FR_REC)
        rec = f.read(FR_REC)
    return ("floor", int.from_bytes(rec[:H], "big"))


def run_verify(out_dir, archive_dir=None, out=sys.stdout):
    """Re-read every byte against the manifest, then run the checks a
    checksum cannot make.

    `verify_sealed` does the shared audit: the data file and its ladder
    (rebuilt from the file it indexes, not trusted), the fingerprint
    recomputed from what is on disk, and the declared coverage confronted
    with the highest height the rows actually carry (a floor). On top of
    it, two checks specific to this table:

    - **structural**, over the whole file: rows strictly increasing by
      (first_height, key), and every height inside the declared coverage.
    - **against the other road** (only with `--archive`): the row count
      must equal the keys records the parent seals — the build is a
      1:1 map, so a single missing or invented row breaks it — and, for
      a spread of keys drawn from the file, the height recorded must
      equal what the archive's own ladder-backed lookup reports for that
      digest. It is the only check that confronts this artifact with
      something it did not build itself.

    Without `--archive` the audit says the parent and that second road
    were taken on trust, and names the flag that would supply them."""
    manifest = _load_manifest(out_dir)
    parent_confirmed = None
    if archive_dir is not None:
        (_kp, _ks, keys_records, parent_fp,
         _cov, _fmt) = _archive_source(archive_dir)
        declared = manifest["build"]["parent"]
        if declared is None or declared["fingerprint"] != parent_fp:
            raise FirstRevealError(
                "that archive is not this table's parent (fingerprints "
                "differ): the sampled check would compare against the "
                "wrong sightings")
        parent_confirmed = True

    floor = _floor_from_data(out_dir, manifest)
    verify_sealed(out_dir, manifest, FORMAT_TAG, FirstRevealError,
                  fp_order=FP_ORDER, ladders=LADDERS,
                  coverage_from_data=(None if floor is None
                                      else lambda: floor),
                  trust_hint="--archive",
                  parent_confirmed=parent_confirmed)

    _verify_structural(out_dir, manifest, out)
    if archive_dir is not None:
        _verify_against_parent(out_dir, manifest, archive_dir,
                               keys_records, out)
    else:
        print("  parent and first-reveal heights taken on trust "
              "(pass --archive to confront them)", file=out)
    return manifest["fingerprint"]


def _verify_structural(out_dir, manifest, out):
    """One pass over firstreveal.bin: strictly increasing, every height
    inside the declared coverage."""
    entry = manifest["build"]["files"][LOGICAL]
    cov = manifest["identity"]["coverage"]
    path = os.path.join(out_dir, entry["file"])
    prev = None
    rows = 0
    for rec in read_fixed(path, FR_REC, expect_sha=entry["sha256"],
                          error=FirstRevealError):
        if prev is not None and rec <= prev:
            raise FirstRevealError(
                f"row {rows} is not strictly after the one before it: "
                "the file is out of order or holds a duplicate")
        h = int.from_bytes(rec[:H], "big")
        if not cov["from"] <= h <= cov["to"]:
            raise FirstRevealError(
                f"row {rows} carries height {h}, outside the declared "
                f"coverage {cov['from']}..{cov['to']}: this file does not "
                "belong to that coverage")
        prev = rec
        rows += 1
    print(f"  ok  {rows:,} rows strictly increasing, every height inside "
          f"{cov['from']:,}..{cov['to']:,}", file=out)


def _verify_against_parent(out_dir, manifest, archive_dir, keys_records,
                           out):
    """The second road: the 1:1 row count, then a sampled confrontation
    of heights with the archive's own reader."""
    rows = manifest["build"]["rows"]
    if rows != keys_records:
        raise FirstRevealError(
            f"the table holds {rows} rows but the parent seals "
            f"{keys_records} keys records: the build is a 1:1 map, so "
            "one of the two is not what it claims")
    am = ra._load_manifest(archive_dir)
    reader = ra._open_merged(archive_dir, am, CAT)
    try:
        entry = manifest["build"]["files"][LOGICAL]
        step = max(1, rows // _SAMPLE)
        path = os.path.join(out_dir, entry["file"])
        checked = 0
        with open(path, "rb") as f:
            for i in range(0, rows, step):
                f.seek(i * FR_REC)
                rec = f.read(FR_REC)
                h = int.from_bytes(rec[:H], "big")
                digest = rec[H:]
                # The other road: the archive's ladder-backed lookup,
                # the same answer `check` gives for this digest.
                got = ra._merged_sighting(archive_dir, am, CAT, digest,
                                          reader)
                if got is None or got[1] != h:
                    raise FirstRevealError(
                        f"key {digest.hex()}: the table says first reveal "
                        f"at height {h}, the archive says "
                        f"{None if got is None else got[1]}")
                checked += 1
        print(f"  ok  rows equal the parent's {keys_records:,} keys "
              f"records, and {checked:,} sampled keys agree with the "
              "archive's own lookup", file=out)
    finally:
        if reader is not None:
            reader.close()


# ---------------------------------------------------------------------------
# between — the keys first revealed inside a height window
# ---------------------------------------------------------------------------

def _sorted_firstreveal(out_dir, manifest):
    """A SortedFile over the sealed table, its ladder verified."""
    entry = manifest["build"]["files"][LOGICAL]
    cache = manifest["build"]["caches"][LOGICAL]
    with open(os.path.join(out_dir, cache["file"]), "rb") as f:
        blob = f.read()
    if hashlib.sha256(blob).hexdigest() != cache["sha256"]:
        raise FirstRevealError(f"{cache['file']}: corrupted ladder")
    return SortedFile(os.path.join(out_dir, entry["file"]), FR_REC, FR_KEY,
                      manifest["build"]["rows"], blob, cache["every"],
                      error=FirstRevealError)


def run_between(out_dir, from_h, to_h, out=sys.stdout):
    """The keys whose FIRST revelation falls in heights [from_h, to_h].

    This is the read the artifact exists for: the archive answers it one
    digest at a time, this answers it one WINDOW at a time, as a
    contiguous scan. The rows are keyed by the height itself, so unlike
    firstspend's window there is no index in the loop: the range is two
    3-byte keys."""
    if from_h < 1:
        raise FirstRevealError(f"--from {from_h} is below height 1")
    if from_h > to_h:
        raise FirstRevealError(f"--from {from_h} is above --to {to_h}")
    manifest = _load_manifest(out_dir)
    cov_to = manifest["identity"]["coverage"]["to"]
    if to_h > cov_to:
        raise FirstRevealError(
            f"--to {to_h} is past the table's coverage {cov_to}")
    sf = _sorted_firstreveal(out_dir, manifest)
    try:
        n = 0
        for rec in sf.scan_range(from_h.to_bytes(H, "big"),
                                 (to_h + 1).to_bytes(H, "big")):
            h = int.from_bytes(rec[:H], "big")
            print(f"{rec[H:].hex()}  first revealed at height {h:,}",
                  file=out)
            n += 1
        print(f"# {n:,} key(s) first revealed in heights "
              f"{from_h:,}..{to_h:,}", file=out)
        return n
    finally:
        sf.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog="nodsig firstreveal",
        description="when each public key was first revealed, ordered by "
                    "that moment (a read of the archive's keys partition)")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build/grow the table from a sealed, "
                                     "merged archive")
    b.add_argument("--archive", required=True,
                   help="a merged reveal-archive directory (no pending runs)")
    b.add_argument("--out", required=True,
                   help="the firstreveal directory to create or grow")
    b.add_argument("--flush-records", type=int, default=8_000_000,
                   help="buffered rows before a run flush (memory knob)")

    s = sub.add_parser("stats", help="read a sealed table's manifest")
    s.add_argument("--firstreveal", required=True)

    v = sub.add_parser("verify", help="audit a sealed table; --archive adds "
                                      "the second road")
    v.add_argument("--firstreveal", required=True)
    v.add_argument("--archive",
                   help="the parent archive, to confront the declared "
                        "parent, the 1:1 row count and a sample of heights")

    bt = sub.add_parser("between", help="keys first revealed in a height "
                                        "window (a contiguous read)")
    bt.add_argument("--firstreveal", required=True)
    bt.add_argument("--from", dest="from_h", type=int, required=True)
    bt.add_argument("--to", dest="to_h", type=int, required=True)

    args = p.parse_args(argv)
    if args.cmd == "build":
        run_build(args.archive, args.out, flush_records=args.flush_records)
    elif args.cmd == "stats":
        run_stats(args.firstreveal)
    elif args.cmd == "verify":
        run_verify(args.firstreveal, archive_dir=args.archive)
    elif args.cmd == "between":
        run_between(args.firstreveal, args.from_h, args.to_h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
