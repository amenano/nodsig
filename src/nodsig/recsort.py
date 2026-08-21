#!/usr/bin/env python3
"""
recsort.py — writing and searching sorted fixed-width record files.

The sorted artifacts of this project (the index's resolver and spends, the
derivatives' history and co-spend files, the reveal archive's key files) are
all the same shape: a file of equal-width records, sorted on a key prefix,
big-endian so byte order IS key order. What they do to those files is shared
here once:

  - `write_run` — sort a batch of opaque records and write them as one sealed
    run (atomic, slab I/O, sha256); the shared run writer for the index and
    the derivatives.
  - `bisect_blob` — a binary search over a contiguous blob of fixed-width
    keys, slicing ~log2(n) keys instead of materializing a list.
  - `SortedFile` — the read-side primitive: a resident LADDER (every K-th key,
    sampled when the file was written and excluded from the fingerprint)
    bisected in RAM, then ONE K-record bucket read from disk and scanned for
    the key. On a network mount that is a single round-trip where a blind
    on-disk binary search would pay ~log2(records) seeks.

The ladder is a cache, never a source of truth: it only decides WHERE to read;
the bytes returned come from the file and are the file's. A short read (a
truncated file) raises the caller's own exception class, passed in so the
error keeps the index's or the archive's type.
"""

import hashlib
import os

from nodsig.recio import IO_CHUNK, RecordError


def write_run(path, records):
    """Sort a list of equal-width records and write them as one run.
    Atomic (tmp + rename); rows leave in slabs; returns (count, sha256).

    No dedup here on purpose: deduplication is a GLOBAL property (an equal
    key can sit in another run), so it happens once, at merge time. The
    records are opaque bytes — the caller decides the width and the key —
    which is why this is the shared run writer for the index and the
    derivatives. (The reveal archive writes its runs with an OR-dedup
    interleaved, so it keeps its own writer.)"""
    records.sort()
    digest = hashlib.sha256()
    buf = bytearray()
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        for r in records:
            buf += r
            if len(buf) >= IO_CHUNK:
                f.write(buf)
                digest.update(buf)
                buf.clear()
        if buf:
            f.write(buf)
            digest.update(buf)
    os.replace(tmp, path)
    return len(records), digest.hexdigest()


def bisect_blob(blob, k, key, strict=False):
    """Rightmost i with blob[i*k:(i+1)*k] <= key, or -1. The ladder
    stays one contiguous bytes object: bisecting it slices ~log2(n)
    keys instead of materializing a million-element list.

    With `strict`, the test becomes `< key`: the rightmost sample
    STRICTLY BELOW the key. The two questions look alike and are not,
    so both live here:

      - a POSITION lookup ("which record covers this ordinal?" — the
        tx_first_out ladder) wants `<=`: its keys are unique, and the
        answer is the record at or before the key;
      - an EQUALITY scan (`SortedFile.scan`) wants `<`: a group longer
        than `every` records is sampled by SEVERAL consecutive ladder
        entries, all equal to the key, and `<=` lands on the LAST of
        them — every row before it would be skipped. The rightmost
        sample below the key is the only one guaranteed to sit at or
        before the head of the group."""
    lo, hi = 0, len(blob) // k
    while lo < hi:
        mid = (lo + hi) // 2
        sample = blob[mid * k:(mid + 1) * k]
        if (sample < key) if strict else (sample <= key):
            lo = mid + 1
        else:
            hi = mid
    return lo - 1


class SortedFile:
    """A sorted fixed-width record file searched through its resident
    ladder: bisect the in-RAM samples, read ONE bucket, scan it. This
    is the read-side primitive every sorted artifact shares — the
    index uses it for the resolver and the spends, the derivatives
    reuse it for the history and the co-spend files, the reveal archive
    for its key lookup. `error` is the exception class raised on a short
    read, so the failure keeps the caller's own type."""

    def __init__(self, path, rec, key_len, records, ladder_blob, every,
                 error=RecordError):
        self.path = path
        self.rec = rec
        self.key_len = key_len
        self.records = records
        self.blob = ladder_blob
        self.every = every
        self.error = error
        self._fd = None

    def _fdesc(self):
        if self._fd is None:
            self._fd = os.open(self.path, os.O_RDONLY)
        return self._fd

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def scan(self, key):
        """Yield every record whose key_len-prefix equals `key`, in
        file order. One bucket read in the overwhelming case; groups
        that straddle a bucket boundary (a lock with many outputs)
        keep reading forward — the consumer streams, never holds the
        whole group unless it wants to.

        The entry point is the rightmost sample STRICTLY below the key
        (`strict=True`): a group of more than `every` records owns
        several ladder samples, and starting at the last of them would
        drop its head without a word. Below the first sample the walk
        starts at record 0 — one bucket read that finds nothing when
        the key is genuinely absent, which is the price of never
        answering with a truncated group."""
        if len(key) != self.key_len:
            raise ValueError(f"key must be {self.key_len} bytes")
        i = bisect_blob(self.blob, self.key_len, key, strict=True)
        start = max(i, 0) * self.every
        while start < self.records:
            count = min(self.every, self.records - start)
            data = os.pread(self._fdesc(), count * self.rec,
                            start * self.rec)
            if len(data) != count * self.rec:
                raise self.error(f"{self.path}: short read — "
                                 "truncated file")
            lo, hi = 0, count            # first record >= key
            while lo < hi:
                mid = (lo + hi) // 2
                if data[mid * self.rec:mid * self.rec
                        + self.key_len] < key:
                    lo = mid + 1
                else:
                    hi = mid
            while (lo < count and data[lo * self.rec:lo * self.rec
                                       + self.key_len] == key):
                yield data[lo * self.rec:(lo + 1) * self.rec]
                lo += 1
            if lo < count:               # the group ended inside
                return
            start += count               # ran off the bucket: read on

    def find(self, key):
        return list(self.scan(key))

    def scan_range(self, lo_key, hi_key):
        """Yield every record whose key is in [lo_key, hi_key), in file
        order: the half-open range read a contiguous artifact wants (a
        window of heights turned into a window of ordinals). Same entry
        rule as `scan` (rightmost sample strictly below `lo_key`), then a
        forward walk that skips below `lo_key` and stops at `hi_key`."""
        if len(lo_key) != self.key_len or len(hi_key) != self.key_len:
            raise ValueError(f"keys must be {self.key_len} bytes")
        i = bisect_blob(self.blob, self.key_len, lo_key, strict=True)
        start = max(i, 0) * self.every
        while start < self.records:
            count = min(self.every, self.records - start)
            data = os.pread(self._fdesc(), count * self.rec,
                            start * self.rec)
            if len(data) != count * self.rec:
                raise self.error(f"{self.path}: short read — "
                                 "truncated file")
            for off in range(0, count * self.rec, self.rec):
                key = data[off:off + self.key_len]
                if key < lo_key:
                    continue
                if key >= hi_key:
                    return
                yield data[off:off + self.rec]
            start += count
