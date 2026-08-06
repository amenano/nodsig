#!/usr/bin/env python3
"""
recio.py — slab I/O for fixed-width record files.

The archive and the outpoint index both store their data the same way: long
files of equal-width records, each sealed by a sha256 recorded in a state or
manifest. Reading and writing them well is the same problem in both places,
so the mechanics live here once:

  - `IO_CHUNK` / `budgeted_slab` — how big a read/write buffer to use. I/O and
    hashing go by big slabs, never by record: on a full archive these paths
    are walked billions of times, and one read()/update() per 21-33-byte
    record would spend more time calling than reading, especially over a
    network mount. When many sorted files are merged at once, every open
    source holds a buffer, so the sources of one merge SHARE a fixed budget
    (`budgeted_slab`) — otherwise a fragmented archive is un-mergeable.
  - `read_slabs` / `read_fixed` — stream a fixed-width file, by slab or by
    record. `read_fixed` verifies the sealed sha256 on the way; the files are
    trusted for nothing (like the blocks): a truncated file or a sha mismatch
    stops the tool, it never leaks into a published number. The caller passes
    the exception class to raise, so the error keeps the caller's own type
    (OutpointError / ScanError). `read_slabs` is the same walk without the
    per-record split, for the consumers that hash or sample a file rather
    than read every record — hashing a billion-record file one 10-byte
    update at a time is the very cost the slab exists to avoid.
  - `sha_file` / `atomic_json` — the whole-file digest, and the tmp-file +
    rename every writer uses so a crash never leaves a half-written file
    under its final name.

The slab size is a memory knob only: it is always rounded down to a whole
number of records, so a partial record can only ever mean a truncated file,
and the sha256 of the slabs is the sha256 of the same bytes — no slab choice
touches any fingerprint.
"""

import hashlib
import json
import os

# One read/write buffer. 8 MiB amortises syscalls without holding much.
IO_CHUNK = 8 * 2**20

# A many-way merge primes every source before yielding a byte (heapq.merge),
# so giving each the full IO_CHUNK is what blows a fragmented archive up
# front: 997 runs × 8 MiB ≈ 8 GB, out-of-memory with zero output. The sources
# of one merge therefore share this budget — per-source slab = budget /
# n_sources, floored to whole records and never below _MIN_SLAB so reads stay
# large enough to amortise syscalls on a network mount. A lone source keeps
# the full slab (the common read path after a merge, nothing to share with).
_MERGE_READ_BUDGET = 512 * 2**20
_MIN_SLAB = 256 * 2**10


class RecordError(RuntimeError):
    """Default type raised on a corrupt or truncated record file. Callers
    normally pass their own class to `read_fixed` so the error carries the
    module's type; this is the fallback when none is given."""


def checked_name(name, error=RecordError, what="file"):
    """A file name read out of a manifest or a state file, refused
    unless it names something INSIDE the artifact directory.

    An artifact is meant to be handed to somebody: the README says so,
    and the whole design is built on two strangers comparing one. That
    makes every manifest and every state file the project reads
    UNTRUSTED INPUT the moment it did not write it itself. Their names
    are joined to a directory and then opened, and in a few places
    removed, so a name of `../../something`, or an absolute path (which
    os.path.join takes as the whole answer, discarding the directory it
    was given), reaches outside the artifact.

    Nothing legitimate needs it: every name this project writes is a
    plain file name in the artifact's own directory, produced by a
    format string. So the rule is the narrow one, refusing anything
    that is not exactly that, and it is applied where the name comes
    IN rather than at each of the dozen places that use one.
    """
    if not isinstance(name, str) or not name:
        raise error(f"{what} name missing from the manifest")
    if (os.path.basename(name) != name or name in (".", "..")
            or os.path.isabs(name) or "\\" in name):
        raise error(
            f"{what} name {name!r} is not a plain name inside the "
            "artifact: a manifest that reaches outside its own "
            "directory is not describing an artifact")
    return name


def budgeted_slab(n_sources):
    """Per-source read-buffer size when n_sources are merged together,
    sharing _MERGE_READ_BUDGET so total buffering stays bounded however
    fragmented the archive is. One source keeps the full slab."""
    if n_sources <= 1:
        return IO_CHUNK
    return max(_MIN_SLAB, min(IO_CHUNK, _MERGE_READ_BUDGET // n_sources))


def read_slabs(path, rec, slab_bytes=IO_CHUNK, start_record=0,
               error=RecordError):
    """Stream a `rec`-byte record file in whole-record slabs.

    The record walk without the per-record split: for a consumer that hashes
    a file, or samples every K-th record, one `update()` per slab replaces
    billions per record. Each yielded slab holds a whole number of records,
    so a partial one can only mean a truncated file. `start_record` seeks
    into the file; `error` is the class raised on truncation."""
    slab = max(rec, (slab_bytes // rec) * rec)   # whole records, >= 1
    with open(path, "rb") as f:
        if start_record:
            f.seek(start_record * rec)
        while True:
            buf = f.read(slab)
            if not buf:
                break
            if len(buf) % rec:
                raise error(f"{path}: truncated record at end of file")
            yield buf


def read_fixed(path, rec, expect_sha=None, slab_bytes=IO_CHUNK,
               start_record=0, error=RecordError):
    """Stream whole `rec`-byte records from a file in big slabs, verifying
    the recorded sha256 on the way when one is expected.

    The slab size is a memory knob only: rounded down to whole records, so a
    partial record can only mean a truncated file. `start_record` seeks into
    the file (a resumed or appending consumer): a partial stream cannot be
    checked against a whole-file sha, so the two are mutually exclusive.
    `error` is the exception class raised on truncation or mismatch, so the
    caller keeps its own error type."""
    if start_record and expect_sha is not None:
        raise ValueError("cannot verify a sha256 over a partial stream")
    digest = hashlib.sha256() if expect_sha is not None else None
    for buf in read_slabs(path, rec, slab_bytes, start_record, error):
        if digest is not None:
            digest.update(buf)
        for i in range(0, len(buf), rec):
            yield buf[i:i + rec]
    if digest is not None and digest.hexdigest() != expect_sha:
        raise error(f"{path}: sha256 mismatch — file corrupted or not the "
                    "one the state describes")


def sha_file(path):
    """The sha256 of a whole file, read in slabs."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(IO_CHUNK)
            if not data:
                break
            digest.update(data)
    return digest.hexdigest()


def atomic_json(path, obj):
    """Write JSON to a tmp file and rename it into place, so a crash never
    leaves a half-written state or manifest under its final name."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)
