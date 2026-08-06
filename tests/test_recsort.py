#!/usr/bin/env python3
"""
test_recsort.py — self-test for the shared read-side primitive.

`SortedFile` is the one piece of code every sorted artifact reads
through (the index's resolver and spends, the derivatives' history and
co-spend files, the reveal archive's key files), so a silent hole here
is a silent hole everywhere. The hole this suite was written for was a
real one, found on the full-chain derivatives and not by the fixtures:

    a group longer than the ladder step owns SEVERAL consecutive ladder
    samples, all equal to its key. Entering at the rightmost sample
    `<= key` lands on the LAST of them, and every row before it is
    dropped — no error, just a smaller answer. On the real history file
    the genesis-block address came back with 12 outputs instead of
    75,454.

The fixtures of the other suites cannot see it: none of their groups
reaches 1024 rows, so no sample ever equals a key. Here the ladder step
is deliberately tiny (`EVERY = 8`) and groups are built ACROSS it — the
same shape at a size a test can hold.

What is checked:

- every distinct key of a model file comes back complete and in file
  order — groups of 1, groups that end inside a bucket, groups that
  span many buckets, the first group of the file and the last;
- the boundary sizes around the step (every-1, every, every+1, and a
  group whose head sits exactly on a sample);
- absent keys yield nothing: below the first record, between two
  groups, past the last record;
- `bisect_blob` answers its two questions distinctly (`<=` for a
  position lookup, `<` for the entry point of an equality scan), since
  one caller depends on each;
- `read_slabs` (recio) is the same walk as the per-record one: the
  seal hashes and samples billion-record files by slab, and the ladder
  it builds must not depend on where a slab happens to end. Checked at
  step/slab alignments a real file would take years to hit.

Usage:
    python3 test_recsort.py         # prints PASS or fails loudly
    (also runs under pytest)
"""

import os
import sys
import tempfile

from nodsig.recio import read_slabs
from nodsig.recsort import SortedFile, bisect_blob

KEY = 3                              # key width, bytes
REC = KEY + 2                        # key | 2 bytes of payload
EVERY = 8                            # ladder step: one sample per 8 records


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def key_of(n):
    """Keys are big-endian so byte order IS key order, like the real
    formats; leaving gaps (10, 20, 30…) keeps absent keys available
    between the groups."""
    return n.to_bytes(KEY, "big")


def build(path, groups):
    """Write a sorted file from [(key_number, multiplicity), …] and
    sample its ladder exactly as `_merge_to_file` does: the key of
    every EVERY-th record, starting at record 0.

    Returns (ladder_blob, records, model) where model maps key → the
    list of records the file holds for it, in file order."""
    ladder = bytearray()
    model = {}
    records = 0
    with open(path, "wb") as f:
        for n, mult in groups:
            k = key_of(n)
            rows = []
            for j in range(mult):
                rec = k + j.to_bytes(2, "big")
                if records % EVERY == 0:
                    ladder.extend(k)
                f.write(rec)
                rows.append(rec)
                records += 1
            model[k] = rows
    return bytes(ladder), records, model


def opened(path, ladder, records):
    return SortedFile(path, REC, KEY, records, ladder, EVERY)


# ---------------------------------------------------------------------------
# The groups: sizes chosen around the ladder step, not at random
# ---------------------------------------------------------------------------

GROUPS = [
    (10, 3),                 # opens the file: a group starting at record 0
    (20, 1),                 # the ordinary case: one row, inside a bucket
    (30, EVERY - 1),         # just short of a step
    (40, EVERY),             # exactly a step: its head lands on a sample
    (50, EVERY + 1),         # just over: two samples, one of them equal
    (60, 5 * EVERY + 3),     # many buckets: the case the real chain hit
    (70, 2),                 # a small group AFTER a long one
    (80, 4 * EVERY),         # long, and it closes the file at EOF
]


def test_every_group_comes_back_whole(tmp):
    """The property that matters: for every key in the file, scan
    returns exactly the rows the model holds, in file order."""
    path = os.path.join(tmp, "sorted.bin")
    ladder, records, model = build(path, GROUPS)
    sf = opened(path, ladder, records)
    try:
        for k, rows in model.items():
            got = sf.find(k)
            if got != rows:
                fail(f"key {k.hex()}: {len(got)} rows instead of "
                     f"{len(rows)}"
                     + (" (a truncated group — the ladder entry point "
                        "skipped its head)" if got == rows[-len(got):]
                        else ""))
        print(f"ok  {len(model)} groups, {records} records: every "
              "group whole and in order")
    finally:
        sf.close()


def test_absent_keys_yield_nothing(tmp):
    """Nothing found must mean nothing found — including below the
    first record, where the entry point now starts at record 0 instead
    of refusing to look."""
    path = os.path.join(tmp, "absent.bin")
    ladder, records, _ = build(path, GROUPS)
    sf = opened(path, ladder, records)
    try:
        for n, where in ((5, "below the first record"),
                         (35, "between two groups"),
                         (45, "between two groups spanning samples"),
                         (99, "past the last record")):
            got = sf.find(key_of(n))
            if got:
                fail(f"key {n} ({where}): {len(got)} rows out of "
                     "nowhere")
        print("ok  absent keys yield nothing (below, between, past)")
    finally:
        sf.close()


def test_group_that_fills_the_whole_file(tmp):
    """One key, many buckets, no neighbours: the walk must stop at the
    end of the file and not read past it."""
    path = os.path.join(tmp, "single.bin")
    ladder, records, model = build(path, [(10, 3 * EVERY)])
    sf = opened(path, ladder, records)
    try:
        got = sf.find(key_of(10))
        if got != model[key_of(10)]:
            fail(f"single-group file: {len(got)} rows instead of "
                 f"{records}")
        print("ok  a file that is one long group reads to EOF")
    finally:
        sf.close()


def test_bisect_blob_answers_two_questions(tmp):
    """The position lookup and the equality scan need different
    answers on the same blob; both callers exist in the tree
    (tx_first_out wants `<=`, SortedFile.scan wants `<`)."""
    blob = b"".join(key_of(n) for n in (10, 20, 20, 20, 30))
    cases = [
        (key_of(20), 3, 0, "a key repeated across samples"),
        (key_of(10), 0, -1, "the first sample"),
        (key_of(5), -1, -1, "below every sample"),
        (key_of(25), 3, 3, "between two samples"),
        (key_of(30), 4, 3, "the last sample"),
        (key_of(99), 4, 4, "above every sample"),
    ]
    for key, want_le, want_lt, what in cases:
        got_le = bisect_blob(blob, KEY, key)
        got_lt = bisect_blob(blob, KEY, key, strict=True)
        if got_le != want_le:
            fail(f"bisect_blob <= on {what}: {got_le} != {want_le}")
        if got_lt != want_lt:
            fail(f"bisect_blob < on {what}: {got_lt} != {want_lt}")
    print("ok  bisect_blob: `<=` for a position, `<` for a scan entry")


# ---------------------------------------------------------------------------
# Standalone runner (pytest collects the same functions via the fixture)
# ---------------------------------------------------------------------------

def test_slab_walk_equals_record_walk(tmp):
    """Hashing and ladder-sampling by slab must give exactly what the
    per-record walk gave.

    The derivatives' seal walks tx_inputs.bin and fees.bin by slab —
    one sha256 update per slab instead of one per 10-byte row, which
    on the full chain is billions of calls saved. The sampling index
    then has to be carried ACROSS slabs (`-n % every`), and getting
    that wrong shifts the ladder without any file being wrong: a
    lookup would just start at the wrong bucket. So it is pinned here,
    at slab sizes that fall on, before and after a step boundary.
    """
    import hashlib
    rec, every, key_len = 10, 7, 5
    data = b"".join(bytes([i % 251]) * rec for i in range(1000))
    path = os.path.join(tmp, "slabwalk.bin")
    with open(path, "wb") as f:
        f.write(data)

    want_ladder = b"".join(data[i * rec:i * rec + key_len]
                           for i in range(len(data) // rec)
                           if i % every == 0)
    want_sha = hashlib.sha256(data).hexdigest()

    for slab_bytes in (rec, rec * 3, rec * 7, rec * 13, 8 * 2**20):
        ladder, n, digest = bytearray(), 0, hashlib.sha256()
        for slab in read_slabs(path, rec, slab_bytes=slab_bytes):
            digest.update(slab)
            rows = len(slab) // rec
            for i in range(-n % every, rows, every):
                ladder.extend(slab[i * rec:i * rec + key_len])
            n += rows
        if bytes(ladder) != want_ladder:
            fail(f"slab {slab_bytes}: the ladder differs from the "
                 "per-record walk — the sampling index was not carried "
                 "across the slab boundary")
        if digest.hexdigest() != want_sha:
            fail(f"slab {slab_bytes}: the digest differs from the "
                 "per-record walk")
    print("ok  slabs: hashing and ladder sampling do not depend on "
          "where a slab ends")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        test_every_group_comes_back_whole(tmp)
        test_absent_keys_yield_nothing(tmp)
        test_group_that_fills_the_whole_file(tmp)
        test_bisect_blob_answers_two_questions(tmp)
        test_slab_walk_equals_record_walk(tmp)
    print("PASS: groups longer than the ladder step come back whole, "
          "absent keys stay absent.")


if __name__ == "__main__":
    main()
