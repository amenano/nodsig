#!/usr/bin/env python3
"""
firstreveal.py — when each public key was first revealed, ordered by that
moment (the format is docs/formats/FirstReveal-v2.md).

The reveal archive answers "was this key revealed" one digest at a time,
and its records carry the first height; what it cannot do is enumerate
which keys were first revealed inside a height range, because it is
ordered by digest. This table is the archive's keys partition restated
in time order, and nothing else: one row per keys record, the flags
dropped, the height turned into a POSITION.

Two files. `keys.bin` holds the 20-byte digests in (first_height, digest)
order; `first_off.bin` holds one u40 per height from 1 to the coverage,
plus a closing entry, each the index of the first row of that height.
The rows first revealed at height h are keys.bin[off[h-1]:off[h]], one
contiguous slice. No ladder: the height column IS the offset table.

An append is an append. When the archive grows and re-seals, every row it
adds has a first height above the old coverage (a first height is a
minimum, and later sightings are higher by construction), so the new
rows sort after every existing one: they go to the end of keys.bin, the
new heights to the end of first_off.bin. Appending equals rebuilding
because the file is the concatenation of per-height slices in height
order whichever pass wrote them.
"""

import heapq
import os
import sys
import time

from nodsig import reveal_archive as ra
from nodsig.artifact import (WallClock, declared_parent, identity_fingerprint,
                             make_identity, producer, seal_manifest,
                             verify_sealed)
from nodsig.genstore import GenStore, new_state_fields
from nodsig.recio import (IO_CHUNK, atomic_json, budgeted_slab, checked_name,
                          durable_replace, read_fixed, read_json, sha_file)

FORMAT_TAG = "firstreveal-v2"
STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
RUNS_DIR = "runs"
LOGICAL = "firstreveal"
CAT = "keys"                         # the one archive partition read

H = 3                                # a height, u24 — the archive's width
KEY = 20                             # the digest, as the archive keys it
RUN_REC = H + KEY                    # a run row: first_height | key
OFF = 5                              # a row index, u40
KEYS_FILE = "keys.bin"
OFF_FILE = "first_off.bin"
KEYS_REC = ra.rec_width(CAT)         # the parent record: digest | flags | h
FP_ORDER = ("keys", "first_off")
KEEP_TOP = (KEYS_FILE, OFF_FILE)


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
        # exactly one emitted row (or none, on an append, when its
        # height is already in the table), so the cursor needs no group
        # logic.
        "keys_pos": 0,
        "coverage": None,               # the parent's, copied at open
        "sealed_to": 0,                 # the height the table holds
        "rows": 0,                      # rows in keys.bin, committed
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
    state = read_json(path, FirstRevealError)
    if state.get("format") != FORMAT_TAG:
        raise FirstRevealError(
            f"firstreveal state says {state.get('format')!r}, not "
            f"{FORMAT_TAG!r}: an earlier table is read by the release that "
            "wrote it, and a fresh build writes this one")
    return state


def _load_manifest(out_dir):
    path = os.path.join(out_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        raise FirstRevealError(f"no {MANIFEST_NAME} in {out_dir}: the table "
                               "is not sealed — run `build`")
    manifest = read_json(path, FirstRevealError)
    if manifest.get("format") != FORMAT_TAG:
        raise FirstRevealError(
            f"firstreveal manifest says {manifest.get('format')!r}, not "
            f"{FORMAT_TAG!r}: an earlier table is read by the release that "
            "wrote it")
    return manifest


# ---------------------------------------------------------------------------
# build — one pass over the parent's keys partition, a fusion, a seal
# ---------------------------------------------------------------------------

def _archive_source(archive_dir):
    """The sealed parent's keys file, as everything a build reads off it.

    The parent must be MERGED and have no pending runs: a run not yet
    fused holds sightings the merged file does not, so a table built
    beside it would claim the archive's coverage while missing keys."""
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
    archive has grown (appends the rows above the old coverage): one
    code path, and the same bytes a from-scratch build would seal.
    """
    (keys_path, keys_sha, keys_records, parent_fp,
     coverage, parent_fmt) = _archive_source(archive_dir)

    os.makedirs(out_dir, exist_ok=True)
    state = _load_state(out_dir, required=False) or _new_state()
    clock = WallClock("append" if state["phase"] == "sealed" else "build",
                      state)
    store = _store(out_dir, state, clock=clock)
    store.clean_orphans(keep=KEEP_TOP)

    if state["phase"] == "sealed":
        if parent_fp == state["source_fingerprint"]:
            print("nothing to do: the table already covers this "
                  "archive seal", file=sys.stderr)
            return _load_manifest(out_dir)["fingerprint"]
        # An APPEND: only the rows above the sealed height are new; a
        # parent that does not extend the table is a rebuild.
        if coverage["to"] <= state["coverage"]["to"]:
            raise FirstRevealError(
                f"the archive given covers heights up to "
                f"{coverage['to']:,}, not above the table's "
                f"{state['coverage']['to']:,}: that is a rebuild (a fresh "
                "directory), not an append")
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
        _phase_merge(store)
        state["phase"] = "seal"
        store.write_state()
    if state["phase"] == "seal":
        manifest = _seal(store, keys_records, parent_fmt, parent_fp)
        state["phase"] = "sealed"
        store.write_state()
        _print_manifest(manifest, out=sys.stdout)
    return _load_manifest(out_dir)["fingerprint"]


def _phase_scan(store, keys_path, keys_sha, flush_records):
    """One sequential pass over the archive's keys file (sorted by
    digest). Each 24-byte record whose height is above the table's
    sealed height is one row: the trailing height moves to the front and
    the digest follows, so the run sort puts time first. On a fresh
    build every record qualifies; on an append only the new heights do,
    and that filter is what makes the append an append."""
    state = store.state
    store.make_runs_dir()
    buf = []
    sealed_to = state["sealed_to"]

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

    start = state["keys_pos"]
    consumed = start
    expect = keys_sha if start == 0 else None
    last_cp = time.monotonic()
    for rec in read_fixed(keys_path, KEYS_REC, expect_sha=expect,
                          start_record=start, error=FirstRevealError):
        if int.from_bytes(rec[KEYS_REC - H:], "big") > sealed_to:
            buf.append(bytes(rec[KEYS_REC - H:]) + bytes(rec[:KEY]))
        consumed += 1
        if len(buf) >= flush_records or time.monotonic() - last_cp > 300:
            checkpoint()
            last_cp = time.monotonic()
    flush()
    state["keys_pos"] = consumed
    store.write_state()


def _phase_merge(store):
    """Fuse the runs into the end of keys.bin, and extend first_off.bin
    from the sealed height to the parent's coverage. The two files grow
    in place, so their committed sizes are the truth: what a kill left
    past them is cut at the next start, and this phase re-runs whole."""
    state = store.state
    rows_before = state["rows"]
    sealed_to = state["sealed_to"]
    cov_to = state["coverage"]["to"]
    keys_path = store.path(KEYS_FILE)
    off_path = store.path(OFF_FILE)
    # A re-run after a kill starts from the committed sizes.
    for path, size in ((keys_path, rows_before * KEY),
                       (off_path, (sealed_to + 1) * OFF if sealed_to else 0)):
        if os.path.exists(path):
            with open(path, "ab") as f:
                f.truncate(size)
        else:
            open(path, "wb").close()

    sources = store.run_sources(LOGICAL)
    slab = budgeted_slab(len(sources) + 1)
    streams = [store.read(p, RUN_REC, sha, slab) for p, sha in sources]
    rows = rows_before
    height = sealed_to
    offsets = bytearray()
    if not sealed_to:
        offsets += (0).to_bytes(OFF, "big")     # height 1 starts at row 0
    buf = bytearray()
    prev = None
    with open(keys_path, "ab") as kf, open(off_path, "r+b") as of:
        # The closing entry of the previous seal is overwritten: it was
        # the row count, and the appended heights take its place.
        of.seek((sealed_to) * OFF if sealed_to else 0)
        for rec in heapq.merge(*streams):
            if rec == prev:
                continue                        # an exact duplicate row
            prev = rec
            h = int.from_bytes(rec[:H], "big")
            if h <= sealed_to or h > cov_to:
                raise FirstRevealError(
                    f"a run row carries height {h}, outside "
                    f"{sealed_to + 1}..{cov_to}: the runs do not belong "
                    "to this append")
            while height < h:
                # every height from the last one to this one starts here
                height += 1
                if height > 1 or sealed_to:
                    offsets += rows.to_bytes(OFF, "big")
                if len(offsets) >= IO_CHUNK:
                    of.write(offsets)
                    offsets.clear()
            buf += rec[H:]
            rows += 1
            if len(buf) >= IO_CHUNK:
                kf.write(buf)
                buf.clear()
        while height < cov_to:
            height += 1
            offsets += rows.to_bytes(OFF, "big")
        offsets += rows.to_bytes(OFF, "big")    # the closing entry
        kf.write(buf)
        of.write(offsets)
        kf.flush()
        os.fsync(kf.fileno())
        of.flush()
        os.fsync(of.fileno())
    delete = store.drop_runs(LOGICAL)
    state["rows"] = rows
    state["sealed_to"] = cov_to
    store.commit(delete)


def _seal(store, keys_records, parent_fmt, parent_fp):
    state = store.state
    keys_path, off_path = store.path(KEYS_FILE), store.path(OFF_FILE)
    rows, cov = state["rows"], state["coverage"]
    if os.path.getsize(keys_path) != rows * KEY:
        raise FirstRevealError(f"{KEYS_FILE} holds "
                               f"{os.path.getsize(keys_path)} bytes, the "
                               f"state committed {rows * KEY}")
    if os.path.getsize(off_path) != (cov["to"] + 1) * OFF:
        raise FirstRevealError(f"{OFF_FILE} holds "
                               f"{os.path.getsize(off_path)} bytes, the "
                               f"coverage wants {(cov['to'] + 1) * OFF}")
    keys_sha = sha_file(keys_path)
    off_sha = sha_file(off_path)
    files = {"keys": {"file": KEYS_FILE, "records": rows,
                      "sha256": keys_sha},
             "first_off": {"file": OFF_FILE, "records": cov["to"] + 1,
                           "sha256": off_sha}}
    identity = make_identity(FORMAT_TAG, cov["from"], cov["to"],
                             [("keys", keys_sha), ("first_off", off_sha)])
    manifest = seal_manifest(FORMAT_TAG, identity, {
        "producer": producer(),
        "seconds": store.clock.stamp(),
        "wall": store.clock.wall(),
        "parent": declared_parent(parent_fmt, parent_fp),
        "rows": rows,
        "parent_keys": keys_records,
        "files": files,
        "caches": {},
        "reconstruction": (
            "one pass over the parent archive's merged keys partition "
            "(sorted by digest, 24-byte records digest20|flags|height): "
            "each record emits (first_height, digest) with the flags "
            "dropped; nothing else is read and nothing is filtered, so "
            "rows equal the parent's keys records. Rows are sorted by "
            "(first_height, digest); keys.bin holds the digests in that "
            "order and first_off.bin one u40 per height, the index of the "
            "first row of that height, plus a closing entry equal to the "
            "row count. The identity is sealed by the shared recipe in "
            "docs/contracts/Artifact.md over the two files keys, first_off"),
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
# reading — the offsets, and the slice of a height window
# ---------------------------------------------------------------------------

class Table:
    """A sealed table, its offsets resident (5 bytes a height: 4.8 MB on
    the whole chain), its keys read by slice."""

    def __init__(self, out_dir, manifest=None):
        self.dir = out_dir
        self.manifest = manifest or _load_manifest(out_dir)
        build = self.manifest["build"]
        self.rows = build["rows"]
        self.cov_to = self.manifest["identity"]["coverage"]["to"]
        with open(os.path.join(out_dir, checked_name(
                build["files"]["first_off"]["file"], FirstRevealError)),
                "rb") as f:
            self.offsets = f.read()
        if len(self.offsets) != (self.cov_to + 1) * OFF:
            raise FirstRevealError(f"{OFF_FILE}: {len(self.offsets)} bytes, "
                                   f"the coverage wants "
                                   f"{(self.cov_to + 1) * OFF}")
        self.keys_path = os.path.join(out_dir, checked_name(
            build["files"]["keys"]["file"], FirstRevealError))
        self._fd = None

    def off(self, i):
        return int.from_bytes(self.offsets[i * OFF:(i + 1) * OFF], "big")

    def slice(self, from_h, to_h):
        """The digests first revealed in heights [from_h, to_h], one
        contiguous read."""
        lo, hi = self.off(from_h - 1), self.off(to_h)
        if self._fd is None:
            self._fd = os.open(self.keys_path, os.O_RDONLY)
        data = os.pread(self._fd, (hi - lo) * KEY, lo * KEY)
        if len(data) != (hi - lo) * KEY:
            raise FirstRevealError(f"{KEYS_FILE}: short read at row {lo}")
        return [data[i:i + KEY] for i in range(0, len(data), KEY)]

    def height_of_row(self, row):
        """The height a row sits in: bisect the offsets."""
        lo, hi = 0, self.cov_to
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.off(mid) <= row:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def run_between(out_dir, from_h, to_h, out=sys.stdout):
    """The keys whose FIRST revelation falls in heights [from_h, to_h]:
    two 5-byte reads give the row range, one contiguous read the keys."""
    if from_h < 1:
        raise FirstRevealError(f"--from {from_h} is below height 1")
    if from_h > to_h:
        raise FirstRevealError(f"--from {from_h} is above --to {to_h}")
    table = Table(out_dir)
    if to_h > table.cov_to:
        raise FirstRevealError(
            f"--to {to_h} is past the table's coverage {table.cov_to}")
    try:
        n = 0
        for h in range(from_h, to_h + 1):
            for digest in table.slice(h, h):
                print(f"{digest.hex()}  first revealed at height {h:,}",
                      file=out)
                n += 1
        print(f"# {n:,} key(s) first revealed in heights "
              f"{from_h:,}..{to_h:,} (table sealed through "
              f"{table.cov_to:,})", file=out)
        return n
    finally:
        table.close()


# ---------------------------------------------------------------------------
# verify — the audit of a sealed table
# ---------------------------------------------------------------------------

_SAMPLE = 512                        # keys confronted against the parent


def run_verify(out_dir, archive_dir=None, out=sys.stdout):
    """Re-read every byte against the manifest, then run the checks a
    checksum cannot make: the offsets non-decreasing and closing on the
    row count, every height slice strictly increasing; and, with
    `--archive`, the 1:1 row count against the parent's keys records
    and a sample of rows whose slice height must equal the archive's own
    lookup for that digest."""
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

    verify_sealed(out_dir, manifest, FORMAT_TAG, FirstRevealError,
                  fp_order=FP_ORDER, trust_hint="--archive",
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
    table = Table(out_dir, manifest)
    try:
        rows = manifest["build"]["rows"]
        if table.off(0) != 0 or table.off(table.cov_to) != rows:
            raise FirstRevealError(
                "first_off.bin does not start at row 0 and close on the "
                f"row count {rows:,}")
        prev = -1
        for h in range(1, table.cov_to + 1):
            o = table.off(h)
            if o < prev:
                raise FirstRevealError(f"first_off.bin decreases at height "
                                       f"{h}: the offsets are not a "
                                       "cumulative count")
            prev = o
        walked = 0
        for h in range(1, table.cov_to + 1):
            last = None
            for digest in table.slice(h, h):
                if last is not None and digest <= last:
                    raise FirstRevealError(
                        f"height {h}: rows are not strictly increasing "
                        "inside the slice: out of order or a duplicate")
                last = digest
                walked += 1
        if walked != rows:
            raise FirstRevealError(f"walked {walked} rows, the seal names "
                                   f"{rows}")
        print(f"  ok  {rows:,} rows in {table.cov_to:,} height slices, "
              "offsets cumulative, every slice strictly increasing",
              file=out)
    finally:
        table.close()


def _verify_against_parent(out_dir, manifest, archive_dir, keys_records,
                           out):
    rows = manifest["build"]["rows"]
    if rows != keys_records:
        raise FirstRevealError(
            f"the table holds {rows} rows but the parent seals "
            f"{keys_records} keys records: the build is a 1:1 map, so "
            "one of the two is not what it claims")
    am = ra._load_manifest(archive_dir)
    reader = ra._open_merged(archive_dir, am, CAT)
    table = Table(out_dir, manifest)
    try:
        step = max(1, rows // _SAMPLE)
        checked = 0
        with open(table.keys_path, "rb") as f:
            for i in range(0, rows, step):
                f.seek(i * KEY)
                digest = f.read(KEY)
                h = table.height_of_row(i)
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
        table.close()
        if reader is not None:
            reader.close()


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
