#!/usr/bin/env python3
"""
curve.py — the text and the meta of a curve, written once for three verbs.

Two commands write the reuse curve (`reuse scan` at every checkpoint,
`archive derive --curve` in one replay) and one writes the archive's own
curve (`archive curve`); two read them (`curve deltas`, `curve dates`).
The two roads to the reuse curve must meet byte for byte, which is why
the grid, the header, the row and the sidecar are defined here and not
in either writer: a text written twice is a text that drifts, and the
cross-check would then measure the drift as agreement.

The sidecar `<csv>.meta.json` is what the CSV cannot say about itself:
it is sealed like every other artifact here (`docs/contracts/Artifact.md`),
with the CSV as its one logical file, so the shared audit reads it and a
curve has a fingerprint a caption can cite. The parent, the road that
wrote it, the grid, the locks and the perimeter it was burnt under live
in `build`: the two roads produce the same CSV and therefore the same
meta fingerprint, which is the comparison the cross-check makes; and
every row of the reuse curve already carries the `reuse-hits-v2`
fingerprint of its own height, which names the locks and the perimeter,
so the CSV digest commits to them transitively.

A kernel: no I/O beyond the two files it is about, no command line.
"""

import csv
import hashlib
import json
import os

from nodsig.artifact import (make_identity, producer,
                             seal_manifest, verify_sealed)
from nodsig.recio import durable_replace, read_json

REUSE_TAG = "reuse-curve-v2"
ARCHIVE_TAG = "archive-curve-v2"
META_SUFFIX = ".meta.json"
# The logical name of the one file each sidecar seals. Logical, not the
# file's: `derive --curve here.csv` and the scan's `curve.csv` are the
# same artifact when their rows are, and the name a caller chose is in
# `build.files`, outside the identity.
LOGICAL = {REUSE_TAG: "curve.csv", ARCHIVE_TAG: "revelations.csv"}


class CurveError(RuntimeError):
    """A CSV that is not the curve it claims to be: wrong columns, a
    height out of order, a hole in the grid, a meta that does not
    describe the file beside it."""


def grid(every, to):
    """The heights a curve carries rows for: the multiples of `every`
    inside the coverage, and the coverage's own last height, which is
    the one row that is always worth having and rarely a multiple."""
    if every < 1:
        raise CurveError("the curve grid must be at least 1 block wide")
    points = list(range(every, to + 1, every))
    if not points or points[-1] != to:
        points.append(to)
    return points


def reuse_header(types):
    return ("height," + ",".join(f"{t}_hits,{t}_satoshis" for t in types)
            + ",fingerprint\n")


def reuse_row(height, totals, fingerprint, types):
    """One line of the reuse curve, from what a state carries for a
    height: the same text whether written at the checkpoint, replayed
    from the archive, or written back from the state on a resume."""
    return (f"{height},"
            + ",".join(f"{totals[t]['hits']},{totals[t]['satoshis']}"
                       for t in types)
            + f",{fingerprint}\n")


def write(path, header, rows):
    """The whole file at once, atomically: tmp, then rename. Returns
    the sha256 of the bytes written, born with the file."""
    digest = hashlib.sha256()
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as f:
        f.write(header)
        digest.update(header.encode())
        for row in rows:
            f.write(row)
            digest.update(row.encode())
    durable_replace(tmp, path)
    return digest.hexdigest()


def append_row(path, header, row):
    """The scan's road: one row per checkpoint, the header first when
    the file is new."""
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        if new:
            f.write(header)
        f.write(row)


def last_height(path):
    """The height of the last row, or None for a file with no row."""
    last = None
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                head = line.split(",", 1)[0]
                if head.isdigit():
                    last = int(head)
    return last


def sha_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_reuse(path, types, every=None):
    """The reuse curve as [(height, {type: (hits, satoshis)}, fingerprint)],
    in height order. Refuses other columns, a height out of order, and,
    when `every` is given, a hole in the grid: a missing row is an
    error with a name, never an interval folded into the next one. A
    height written twice (a kill between the row and the state, before
    the resume wrote it back) keeps the LAST row, the resumed run's."""
    expected = reuse_header(types).rstrip("\n").split(",")
    rows = {}
    order = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != expected:
            raise CurveError(
                f"unexpected curve columns {reader.fieldnames!r}; a reuse "
                f"curve has exactly {expected!r}")
        for row in reader:
            h = int(row["height"])
            if h not in rows:
                order.append(h)
            rows[h] = ({t: (int(row[f"{t}_hits"]), int(row[f"{t}_satoshis"]))
                        for t in types}, row["fingerprint"])
    if order != sorted(order):
        raise CurveError("curve heights are not in ascending order: this "
                         "is not the file a scan or a derive writes")
    if every is not None and order:
        want = grid(every, order[-1])
        missing = [h for h in want if h not in rows]
        if missing:
            raise CurveError(
                f"the curve is on a {every:,} grid and lacks the row(s) for "
                f"height(s) {', '.join(f'{h:,}' for h in missing[:5])}"
                f"{'…' if len(missing) > 5 else ''}: a hole, not an "
                "interval")
        extra = [h for h in order if h not in set(want)]
        if extra:
            raise CurveError(
                f"the curve carries row(s) off its {every:,} grid at "
                f"height(s) {', '.join(f'{h:,}' for h in extra[:5])}")
    return [(h, rows[h][0], rows[h][1]) for h in order]


def seal(path, tag, coverage_to, build, sha=None):
    """Write `<path>.meta.json`: the identity over the one logical file
    (named after the CSV), the fingerprint, and `build` as given plus
    the file entry the shared audit needs. Returns the meta."""
    sha = sha or sha_of(path)
    name = LOGICAL[tag]
    identity = make_identity(tag, 1, coverage_to, [(name, sha)])
    build = dict(build)
    build.setdefault("producer", producer())
    build["files"] = {name: {"file": os.path.basename(path), "sha256": sha}}
    build["caches"] = {}
    meta = seal_manifest(tag, identity, build)
    meta_path = path + META_SUFFIX
    tmp = meta_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(meta, f, indent=1)
    durable_replace(tmp, meta_path)
    return meta


def read_meta(path):
    """The sealed meta beside a CSV, or None when there is none."""
    meta_path = path + META_SUFFIX
    if not os.path.exists(meta_path):
        return None
    return read_json(meta_path, CurveError)


def verify(path, tag):
    """The shared audit over the sidecar: the CSV's bytes against the
    identity, the fingerprint recomputed. Returns the meta."""
    meta = read_meta(path)
    if meta is None:
        raise CurveError(f"no {os.path.basename(path)}{META_SUFFIX} beside "
                         f"{path}: this curve was never sealed")
    # The bytes are the file given, whatever name the meta remembers
    # for it: a curve copied under another name is the same curve.
    verify_sealed(os.path.dirname(os.path.abspath(path)), meta, tag,
                  CurveError, fp_order=[LOGICAL[tag]],
                  prepared={LOGICAL[tag]: (sha_of(path), None)})
    return meta
