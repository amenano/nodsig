#!/usr/bin/env python3
"""
test_genstore.py — self-test for the append-and-fuse store.

`GenStore` is the bookkeeping both big artifacts grow through: the
outpoint index and its derivatives accumulate sorted runs, fold them
into the next generation of a merged file, and trust the state file to
be the only truth about what exists on disk. Their own suites check
the BYTES they produce (golden fingerprints included); this one checks
the machinery underneath, at a size a test can hold and with the
failure modes it was written to prevent.

What is checked:

- a fusion numbers the next generation and names it in the state, with
  the ladder sampled at the declared step;
- the COMMIT ORDER: after `fuse` and before `commit`, the previous
  generation is still on disk and the state on disk still names it.
  This is the whole crash-safety argument — an overwrite in place
  would leave a window where the state points at bytes being
  replaced — and it is invisible to a test that only reads the end
  result;
- `dedup="last"` collapses equal keys onto the later record (the BIP30
  rule and the derivatives' unspent→spent update) while `dedup=None`
  keeps everything and still counts;
- `dedup_len` may be LONGER than the ladder key: the derivatives
  deduplicate history rows on (lock, ordinal) but search them by lock
  alone, so the two lengths must not be confused;
- the orphan sweep deletes what the state does not name, and spares
  the inventory the artifact declares with `keep` — deleting a
  positional file of the index would cost 34 hours of rebuild;
- `drop_runs` hands back paths WITHOUT deleting them, so the caller
  can write the state first;
- the GALLOP: a fusion that moves whole stretches of the previous
  generation instead of walking them record by record must produce the
  same bytes, the same ladder, the same duplicate count and the same
  duplicate log as one that walks them. It is checked against an
  independent reference — sort, group, keep — over a randomized matrix
  of widths, dedup rules, slab sizes and source counts, and the check
  is only allowed to pass if the bulk path was actually taken: a
  fixture too small to reach it would otherwise report success for
  code it never ran.

Usage:
    python3 test_genstore.py        # prints PASS or fails loudly
    (also runs under pytest)
"""

import hashlib
import json
import os
import random
import sys
import tempfile

from nodsig import genstore
from nodsig.genstore import (DUP_LOG_CAP, GenStore, _BaseCursor,
                             merge_to_file, new_state_fields)
from nodsig.recio import read_fixed
from nodsig.recsort import write_run

KEY = 3                      # key width, bytes
REC = KEY + 2                # key | 2 bytes of payload
EVERY = 4                    # ladder step, deliberately tiny
SPEC = (REC, KEY, EVERY)


class StoreError(RuntimeError):
    """Stands in for an artifact's own exception class."""


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


def rec(key, payload):
    return key.to_bytes(KEY, "big") + payload.to_bytes(2, "big")


def fresh(tmp, name="art"):
    directory = os.path.join(tmp, name)
    os.makedirs(directory, exist_ok=True)
    state = {"format": "test-v1", **new_state_fields()}
    store = GenStore(directory, state, label="test", error=StoreError)
    store.make_runs_dir()
    return store


def merged_bytes(store, logical):
    entry = store.state["files"][logical]
    with open(store.path(entry["file"]), "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------

def test_fusion_generations_and_ladder(tmp):
    """Two fusions in a row: the generation counter advances, the state
    names only the current one, and the ladder holds one key every
    EVERY records."""
    store = fresh(tmp, "gens")
    store.write_run("run_a.bin", "cat", [rec(10, 1), rec(30, 3)])
    dups, delete = store.fuse("m", SPEC, "cat", dedup=None)
    store.commit(delete)

    check(store.state["generation"] == 1, "first fusion must be gen 1")
    check(store.state["files"]["m"]["file"] == "m_g0001.bin",
          "the merged file must carry its generation in its name")
    check(dups == 0, "distinct keys are not duplicates")
    check(store.state["runs"] == [],
          "a fused category must leave no runs behind")

    # Enough records to sample the ladder more than once.
    store.write_run("run_b.bin", "cat",
                    [rec(k, k) for k in (20, 40, 50, 60, 70)])
    _dups, delete = store.fuse("m", SPEC, "cat", dedup=None)
    store.commit(delete)

    check(store.state["generation"] == 2, "second fusion must be gen 2")
    body = merged_bytes(store, "m")
    keys = [int.from_bytes(body[i:i + KEY], "big")
            for i in range(0, len(body), REC)]
    check(keys == [10, 20, 30, 40, 50, 60, 70],
          f"the fusion must keep everything in key order, got {keys}")

    cache = store.state["caches"]["m"]
    with open(store.path(cache["file"]), "rb") as f:
        ladder = f.read()
    sampled = [int.from_bytes(ladder[i:i + KEY], "big")
               for i in range(0, len(ladder), KEY)]
    check(sampled == [10, 50],
          f"the ladder must sample every {EVERY} records, got {sampled}")
    check(not os.path.exists(store.path("m_g0001.bin")),
          "the superseded generation must be gone after the commit")
    print("ok  fusion: generations advance, the ladder samples at the "
          "declared step, the old generation is removed")


def test_commit_order_is_the_crash_safety(tmp):
    """The window a crash could fall into: between the fusion and the
    commit, the state ON DISK must still describe the OLD generation,
    and the old bytes must still be there. Otherwise a crash in that
    instant would leave a state naming files that no longer exist."""
    store = fresh(tmp, "order")
    store.write_run("run_a.bin", "cat", [rec(10, 1)])
    _dups, delete = store.fuse("m", SPEC, "cat", dedup=None)
    store.commit(delete)
    first_gen = store.path("m_g0001.bin")

    store.write_run("run_b.bin", "cat", [rec(20, 2)])
    _dups, delete = store.fuse("m", SPEC, "cat", dedup=None)

    on_disk = json.load(open(store.path("state.json")))
    check(on_disk["files"]["m"]["file"] == "m_g0001.bin",
          "before the commit the state on disk must still name the "
          "previous generation")
    check(os.path.exists(first_gen),
          "before the commit the previous generation must still exist")
    check(os.path.exists(store.path("m_g0002.bin")),
          "the new generation is written beside the old one, never "
          "over it")

    store.commit(delete)
    on_disk = json.load(open(store.path("state.json")))
    check(on_disk["files"]["m"]["file"] == "m_g0002.bin",
          "after the commit the state must name the new generation")
    check(not os.path.exists(first_gen),
          "the old generation is deleted only after the state stopped "
          "naming it")
    print("ok  commit: the new generation is committed BEFORE the old "
          "one is deleted — no crash window on replaced bytes")


def test_dedup_last_and_none(tmp):
    """Equal keys: kept-last (consensus rules and append updates) or
    kept-all, and counted either way."""
    store = fresh(tmp, "dedup_last")
    store.write_run("r.bin", "cat",
                    [rec(10, 1), rec(10, 2), rec(10, 3), rec(20, 9)])
    dups, delete = store.fuse("m", SPEC, "cat", dedup="last")
    store.commit(delete)
    body = merged_bytes(store, "m")
    check(dups == 2, f"three equal keys are two duplicates, got {dups}")
    check(body == rec(10, 3) + rec(20, 9),
          "keep-last must leave the greatest payload of the run")

    store = fresh(tmp, "dedup_none")
    store.write_run("r.bin", "cat", [rec(10, 1), rec(10, 2)])
    dups, delete = store.fuse("m", SPEC, "cat", dedup=None)
    store.commit(delete)
    check(dups == 1, "duplicates are counted even when nothing is dropped")
    check(len(merged_bytes(store, "m")) == 2 * REC,
          "dedup=None must drop nothing")
    print("ok  dedup: keep-last takes the later record, dedup=None "
          "drops nothing, both count")


def test_dedup_len_longer_than_key(tmp):
    """The derivatives' shape: rows are SEARCHED by a short key and
    DEDUPLICATED on a longer prefix. Confusing the two would silently
    collapse rows that must all survive."""
    store = fresh(tmp, "dlen")
    # Same key (10), different second field: distinct under the long
    # prefix, identical under the short one.
    store.write_run("r.bin", "cat",
                    [rec(10, 1), rec(10, 2), rec(10, 2)])
    dups, delete = store.fuse("m", SPEC, "cat", dedup="last",
                              dedup_len=REC)
    store.commit(delete)
    body = merged_bytes(store, "m")
    check(dups == 1,
          f"only the fully equal pair is a duplicate, got {dups}")
    check(body == rec(10, 1) + rec(10, 2),
          "rows sharing the search key must survive the fusion")
    print("ok  dedup_len: a longer equality prefix keeps rows that "
          "share the search key")


def test_orphan_sweep_spares_the_declared_inventory(tmp):
    """What the state does not name does not exist — except what the
    artifact declares it owns."""
    store = fresh(tmp, "sweep")
    store.write_run("run_a.bin", "cat", [rec(10, 1)])
    _dups, delete = store.fuse("m", SPEC, "cat", dedup=None)
    store.commit(delete)

    # A crashed fusion's leftovers and an unnamed run.
    open(store.path("m_g0009.bin"), "wb").close()
    open(store.path("half_written.tmp"), "wb").close()
    open(store.run_path("run_ghost.bin"), "wb").close()
    # And the artifact's own inventory, which must survive.
    open(store.path("outputs.bin"), "wb").close()
    open(store.path("tx_first_out_g.bin"), "wb").close()

    store.clean_orphans(keep={"tx_first_out_g.bin"})

    check(not os.path.exists(store.path("m_g0009.bin")),
          "a generation the state does not name must go")
    check(not os.path.exists(store.path("half_written.tmp")),
          "a tmp file must go")
    check(not os.path.exists(store.run_path("run_ghost.bin")),
          "a run the state does not name must go")
    check(os.path.exists(store.path("outputs.bin")),
          "a file with no generation marker must be left alone")
    check(os.path.exists(store.path("tx_first_out_g.bin")),
          "a declared file must survive even with '_g' in its name")
    check(os.path.exists(store.path(
        store.state["files"]["m"]["file"])),
        "the current generation must survive its own sweep")
    print("ok  sweep: unnamed generations, runs and tmp files go; the "
          "declared inventory stays")


def test_orphan_sweep_refuses_a_directory_without_a_state(tmp):
    """A crash leaves a run or two the state did not get to name; a
    directory full of runs and generations with NO state is a lost
    state or a wrong `--out`, and the old sweep deleted all of it
    (`*_g*`, `*.tmp`, everything under runs/) before any check could
    speak. Now: refused, files intact; and an empty directory, which
    is what a fresh build starts in, is still fine."""
    store = fresh(tmp, "nostate")
    open(store.path("m_g0001.bin"), "wb").close()
    open(store.run_path("run_a.bin"), "wb").close()
    try:
        store.clean_orphans()
        fail("runs and generations without a state were swept")
    except StoreError as e:
        check("state" in str(e), f"the refusal must name the state: {e}")
    check(os.path.exists(store.path("m_g0001.bin"))
          and os.path.exists(store.run_path("run_a.bin")),
          "a refusal must leave every file where it was")
    empty = fresh(tmp, "empty")
    empty.clean_orphans()
    print("ok  sweep: no state and files to sweep is refused; no state "
          "and nothing to sweep is a fresh start")


def test_orphan_sweep_matches_the_generation_shape_exactly(tmp):
    """`_g` as a substring is not a generation: `notes_graph.txt` and
    `history_g0003.bin.bak` are somebody's files, and a subdirectory is
    never this store's to remove (the old sweep died on one with
    IsADirectoryError, after deleting what came before it)."""
    store = fresh(tmp, "shape")
    store.write_run("run_a.bin", "cat", [rec(10, 1)])
    _dups, delete = store.fuse("m", SPEC, "cat", dedup=None)
    store.commit(delete)
    spare = ["notes_graph.txt", "history_g0003.bin.bak", "m_g01.bin"]
    for name in spare:
        open(store.path(name), "wb").close()
    os.makedirs(store.path("sub_g0001.bin"))
    os.makedirs(store.run_path("nested"))
    open(store.path("m_g0007.lad"), "wb").close()
    store.clean_orphans()
    for name in spare:
        check(os.path.exists(store.path(name)),
              f"{name} is not a generation and must survive")
    check(os.path.isdir(store.path("sub_g0001.bin"))
          and os.path.isdir(store.run_path("nested")),
          "directories are never swept")
    check(not os.path.exists(store.path("m_g0007.lad")),
          "an unnamed ladder of the exact shape must go")
    print("ok  sweep: only `<logical>_g<4 digits>.bin|.lad` and `.tmp` "
          "files go; look-alikes and directories stay")


def test_a_run_the_disk_lost_is_refused_on_load(tmp):
    """The state names a run with its size; a power loss after the
    rename can leave that run empty on disk with the state intact,
    and nothing would re-produce its records. The next load compares
    sizes and stops there, not days later at a fusion."""
    store = fresh(tmp, "lost")
    store.write_run("run_a.bin", "cat", [rec(10, 1), rec(11, 2)])
    store.write_state()
    check(store.state["runs"][0]["bytes"] == 2 * REC,
          "a run entry must record its bytes")
    with open(store.run_path("run_a.bin"), "wb") as f:
        f.truncate(0)
    try:
        store.clean_orphans()
        fail("an empty run the state names was accepted")
    except StoreError as e:
        check("lost" in str(e), f"the refusal must say what happened: {e}")
    print("ok  sizes: a named run the disk lost is refused on load")


def test_a_fusion_refuses_without_the_space(tmp):
    """The fusion writes a whole generation before deleting anything;
    on a network mount a full disk shows up hours in, as EIO. The
    upper bound (runs plus the current generation) is checked first."""
    from nodsig import recio
    store = fresh(tmp, "space")
    store.write_run("run_a.bin", "cat", [rec(10, 1)])
    real = recio.shutil.disk_usage
    class _Usage:
        total = used = 0
        free = 1
    recio.shutil.disk_usage = lambda _p: _Usage
    try:
        store.fuse("m", SPEC, "cat", dedup=None)
        fail("a fusion started without the space for it")
    except StoreError as e:
        check("free" in str(e), f"the refusal must name the space: {e}")
    finally:
        recio.shutil.disk_usage = real
    check(not any(n.startswith("m_g") for n in os.listdir(store.dir)),
          "the refusal must come before the first byte")
    _dups, delete = store.fuse("m", SPEC, "cat", dedup=None)
    store.commit(delete)
    print("ok  preflight: a fusion without the space is refused before "
          "writing, and runs once the space is there")


def test_drop_runs_defers_deletion(tmp):
    """`drop_runs` forgets a category and hands back its paths; the
    files stay until the caller has committed the state that stopped
    naming them."""
    store = fresh(tmp, "drop")
    store.write_run("run_a.bin", "keep_me", [rec(10, 1)])
    store.write_run("run_b.bin", "drop_me", [rec(20, 2)])

    delete = store.drop_runs("drop_me")
    check([os.path.basename(p) for p in delete] == ["run_b.bin"],
          "only the dropped category comes back")
    check(all(os.path.exists(p) for p in delete),
          "drop_runs must NOT delete: the state is committed first")
    check([r["category"] for r in store.state["runs"]] == ["keep_me"],
          "the other category must stay in the state")

    store.commit(delete)
    check(not os.path.exists(store.run_path("run_b.bin")),
          "the commit deletes what the state stopped naming")
    print("ok  drop_runs: paths handed back, deletion deferred to the "
          "commit")


def test_truncate_appended(tmp):
    """Files that grow in place: a tail past the committed size is
    not accounted by any state and is cut; a file SHORTER than
    committed is corruption and must stop everything. The message
    states the fact (past the committed size), not a guessed cause:
    a wanted TERM and a crash leave the same tail, and the code
    cannot tell them apart."""
    store = fresh(tmp, "trunc")
    path = store.path("grows.bin")
    with open(path, "wb") as f:
        f.write(b"\x00" * 30)
    store.truncate_appended([("grows.bin", 20)])
    check(os.path.getsize(path) == 20,
          "the tail past the committed size must be cut")

    try:
        store.truncate_appended([("grows.bin", 40)])
        fail("a file shorter than its committed size must raise")
    except StoreError:
        pass
    print("ok  truncate: a long tail is cut, a short file raises the "
          "artifact's own error")


# ---------------------------------------------------------------------------
# The gallop: same answer, arrived at in stretches.

def reference(streams, rec, key_len, dedup_len, every, dedup, combine=None):
    """What a fusion must produce, worked out the obvious way: put every
    record in order, group the ones sharing the dedup prefix, keep what
    the rule says to keep, sample every `every`-th survivor.

    Deliberately NOT the shape of the code under test — no merge, no
    ladder written while writing, no cursor. A fast path checked against
    a slow path written the same way would only prove they were edited
    together."""
    rows = sorted(r for stream in streams for r in stream)
    out, dups, log = [], 0, []
    i, n = 0, len(rows)
    while i < n:
        j = i
        while j + 1 < n and rows[j + 1][:dedup_len] == rows[i][:dedup_len]:
            j += 1
        dups += j - i
        log += [(rows[k], rows[k + 1]) for k in range(i, j)]
        if combine is not None:
            kept = rows[i]
            for k in range(i + 1, j + 1):
                kept = combine(kept, rows[k])
            out.append(kept)
        else:
            out += rows[j:j + 1] if dedup == "last" else rows[i:j + 1]
        i = j + 1
    ladder = b"".join(r[:key_len] for k, r in enumerate(out)
                      if k % every == 0)
    return b"".join(out), ladder, dups, log[:DUP_LOG_CAP]


def fuse_one_way(tmp, gallop, base_rows, runs_rows, rec, key_len,
                 dedup_len, every, dedup, slab, want_log, combine=None,
                 runs_as="streams"):
    """One fusion, with the previous generation as a cursor (the gallop)
    or as one more stream (the plain road), and the runs as record
    streams or, with `runs_as="cursors"`, as slab cursors through the
    k-way stage. Returns everything the fusion is answerable for."""
    d = os.path.join(tmp, "gallop")
    os.makedirs(d, exist_ok=True)
    files = []
    for i, rows in enumerate([base_rows] + list(runs_rows)):
        p = os.path.join(d, f"src{i}.bin")
        _, sha = write_run(p, list(rows))
        files.append((p, sha))
    out = os.path.join(d, "out.bin")
    lad = os.path.join(d, "out.lad")

    base, todo = None, files
    if gallop:
        p, sha = files[0]
        base = _BaseCursor(p, rec, sha, slab, StoreError)
        todo = files[1:]
    sources, cursors = [], ()
    if runs_as == "cursors":
        cursors = [_BaseCursor(p, rec, sha, slab, StoreError)
                   for p, sha in todo]
    else:
        sources = [read_fixed(p, rec, sha, slab) for p, sha in todo]
    log = [] if want_log else None
    records, sha, lad_sha, dups = merge_to_file(
        sources, out, rec, key_len, lad, every, dedup, dedup_len,
        dup_log=log, base=base, combine=combine, cursors=cursors)

    with open(out, "rb") as f:
        body = f.read()
    with open(lad, "rb") as f:
        ladder = f.read()
    check(records * rec == len(body), "the record count must match the file")
    check(sha == hashlib.sha256(body).hexdigest(),
          "the returned sha must be the sha of the file written")
    check(lad_sha == hashlib.sha256(ladder).hexdigest(),
          "the returned ladder sha must be the sha of the ladder written")
    return body, ladder, dups, log


def test_gallop_answers_exactly_as_the_plain_fusion(tmp):
    """The property is not «faster», it is «the same bytes»: over a
    matrix of record widths, dedup rules, ladder steps, slab sizes and
    source counts, the fusion that moves stretches whole must equal the
    fusion that walks them, and both must equal the reference.

    The slab sizes matter: a stretch is measured inside one slab, so
    the small ones make stretches END at a boundary and the large ones
    let them run for hundreds of records. The key alphabets matter for
    the same reason — a narrow one makes collisions the rule, which is
    what forbids the bulk form and sends the fusion back to the
    per-record road."""
    rng = random.Random(20260807)
    taken = []
    real = genstore._adjacent_equal

    def counting(*args):
        taken.append(1)
        return real(*args)

    genstore._adjacent_equal = counting
    try:
        for case in range(160):
            rec = rng.choice((4, 6, 12, 33))
            key_len = rng.randint(1, rec)
            dedup_len = rng.randint(key_len, rec)
            every = rng.choice((1, 2, 4, 16, 1024))
            dedup = rng.choice(("last", None))
            span = rng.choice((2, 5, 256))     # how often keys collide
            slab = rng.choice((rec, rec * 3, rec * 17, 8 << 20))
            want_log = rng.random() < 0.5

            def rows(n):
                out = []
                for _ in range(n):
                    key = bytes(rng.randrange(span) for _ in range(key_len))
                    tail = bytes(rng.randrange(256)
                                 for _ in range(rec - key_len))
                    out.append(key + tail)
                return sorted(out)

            base_rows = rows(rng.choice((0, 1, 5, 40, 300, 700)))
            runs_rows = [rows(rng.choice((0, 1, 3, 30)))
                         for _ in range(rng.randint(0, 3))]

            want = reference([base_rows] + runs_rows, rec, key_len,
                             dedup_len, every, dedup)
            for gallop in (False, True):
                got = fuse_one_way(tmp, gallop, base_rows, runs_rows, rec,
                                   key_len, dedup_len, every, dedup, slab,
                                   want_log)
                names = ("bytes", "ladder", "dups", "dup_log")
                for name, a, b in zip(names, want, got):
                    if b is None:              # no log asked for
                        continue
                    check(a == b,
                          f"case {case} ({'gallop' if gallop else 'plain'}, "
                          f"rec={rec} key={key_len} dedup_len={dedup_len} "
                          f"every={every} dedup={dedup} span={span} "
                          f"slab={slab}): {name} differs\n"
                          f"   want {a!r}\n   got  {b!r}")
    finally:
        genstore._adjacent_equal = real

    check(len(taken) > 50,
          f"the bulk path ran only {len(taken)} times: a matrix that never "
          "reaches it proves nothing about it")
    print(f"ok  gallop: 160 randomized fusions match the reference on both "
          f"roads ({len(taken)} bulk stretches taken)")


def _archive_like(a, b):
    """The reveal archive's rule on two sightings of one digest: flags
    OR-ed, the lowest first height kept. Associative and commutative,
    which is what lets the fusion meet the pair in any order."""
    return a[:4] + bytes([a[4] | b[4]]) + min(a[5:], b[5:])


# The same slicing as the archive's `_combine_or` on an 8-byte record, so
# the k-way stage may hand it to the native kernel when one is built: the
# matrix below then exercises that road as well as the reference's.
_archive_like.native = "or_min"


def test_gallop_combines_equal_keys_as_the_archive_does(tmp):
    """The third rule for equal keys: reduce them. The reveal archive
    used to fuse by hand, record by record through three generator
    layers, because the shared fusion knew only "keep last" and "keep
    both"; with `combine` it gallops like the index does, and the bytes,
    the ladder and the count must be the reference's on both roads."""
    rng = random.Random(20260908)
    taken = []
    real = genstore._adjacent_equal

    def counting(*args):
        taken.append(1)
        return real(*args)

    rec, key_len = 8, 4                     # digest | flags | height:u24

    def rows(n, span):
        out = []
        for _ in range(n):
            key = bytes(rng.randrange(span) for _ in range(key_len))
            out.append(key + bytes([1 << rng.randrange(5)])
                       + rng.randrange(1, 1 << 24).to_bytes(3, "big"))
        return sorted(out)

    genstore._adjacent_equal = counting
    try:
        for case in range(80):
            span = rng.choice((2, 5, 256))
            slab = rng.choice((rec, rec * 3, rec * 17, 8 << 20))
            every = rng.choice((1, 4, 1024))
            base_rows = rows(rng.choice((0, 5, 40, 700)), span)
            # A previous generation holds unique keys, as the archive's
            # does; the runs may repeat them and each other.
            seen, unique = set(), []
            for r in base_rows:
                if r[:key_len] not in seen:
                    seen.add(r[:key_len])
                    unique.append(r)
            runs_rows = [rows(rng.choice((0, 3, 30)), span)
                         for _ in range(rng.randint(0, 3))]
            want = reference([unique] + runs_rows, rec, key_len, key_len,
                             every, None, combine=_archive_like)
            for gallop in (False, True):
                got = fuse_one_way(tmp, gallop, unique, runs_rows, rec,
                                   key_len, key_len, every, None, slab,
                                   False, combine=_archive_like)
                for name, a, b in zip(("bytes", "ladder", "dups"), want, got):
                    check(a == b, f"case {case} "
                          f"({'gallop' if gallop else 'plain'}, span={span} "
                          f"slab={slab} every={every}): {name} differs")
    finally:
        genstore._adjacent_equal = real
    check(len(taken) > 20, f"the bulk path ran only {len(taken)} times")
    try:
        merge_to_file([], os.path.join(tmp, "x.bin"), rec, key_len,
                      os.path.join(tmp, "x.lad"), 4, "last",
                      combine=_archive_like)
        fail("combine together with dedup was accepted")
    except ValueError:
        pass
    print(f"ok  gallop: reduced equal keys match the reference on both "
          f"roads ({len(taken)} bulk stretches taken)")


def test_gallop_refuses_a_stretch_it_cannot_express(tmp):
    """The one thing a stretch moved whole cannot do is DROP a record.
    A long clear stretch that happens to contain two records sharing
    the dedup prefix, under `dedup="last"`, must therefore go back to
    the per-record road and collapse them — and the fusion must notice
    it once, not at every record it walks after that.

    Deterministic on purpose: the randomized matrix reaches this branch
    by chance, and a branch that decides what gets DROPPED should not
    be covered by chance."""
    rows = sorted({(k * 7 % 997).to_bytes(KEY, "big") + b"\x00\x01"
                   for k in range(300)})
    rows.append(rows[150][:KEY] + b"\x00\x09")     # same key, later row
    rows.sort()
    runs = [[(998).to_bytes(KEY, "big") + b"\x00\x02"]]

    seen = []
    real = genstore._adjacent_equal

    def counting(*args):
        d = real(*args)
        seen.append(d)
        return d

    genstore._adjacent_equal = counting
    try:
        want = reference([rows] + runs, REC, KEY, REC - 2, 4, "last")
        got = fuse_one_way(tmp, True, rows, runs, REC, KEY, REC - 2, 4,
                           "last", 8 << 20, True)
    finally:
        genstore._adjacent_equal = real

    check(any(d > 0 for d in seen),
          f"the stretch with the collision was never measured: {seen}")
    for name, a, b in zip(("bytes", "ladder", "dups", "dup_log"), want, got):
        check(a == b, f"a refused stretch changed the {name}")
    check(got[2] == 1, f"the collision must be counted once, got {got[2]}")
    print("ok  gallop: a stretch holding a record to drop goes back to "
          "the per-record road")


def test_gallop_still_verifies_the_base(tmp):
    """The stretch moved whole is read, hashed and checked exactly like
    the record walk it replaces: a previous generation that does not
    match the sha the state sealed stops the fusion, it does not get
    copied faster."""
    store = fresh(tmp, "basesha")
    store.write_run("r0.bin", "cat", [rec(k, k) for k in range(0, 400, 2)])
    _dups, delete = store.fuse("m", SPEC, "cat", dedup=None)
    store.commit(delete)

    path = store.path(store.state["files"]["m"]["file"])
    with open(path, "r+b") as f:
        f.seek(80)
        f.write(b"\xff")

    store.write_run("r1.bin", "cat", [rec(1001, 1)])
    try:
        store.fuse("m", SPEC, "cat", dedup=None)
        fail("a base that does not match its sealed sha must stop the "
             "fusion")
    except StoreError:
        pass
    print("ok  gallop: a previous generation whose sha does not match "
          "stops the fusion")


def test_sift_keeps_the_plain_road(tmp):
    """A rewind rewrites and drops records as they pass, which is
    exactly what a stretch moved whole cannot express — so a sift never
    gets the cursor, and still cuts what it is told to cut."""
    store = fresh(tmp, "sift")
    store.write_run("r0.bin", "cat", [rec(k, k) for k in range(200)])
    _dups, delete = store.fuse("m", SPEC, "cat", dedup=None)
    store.commit(delete)

    cut = 100
    _dups, delete = store.fuse(
        "m", SPEC, "cat", dedup=None,
        sift=lambda r: r if int.from_bytes(r[:KEY], "big") < cut else None)
    store.commit(delete)
    body = merged_bytes(store, "m")
    keys = [int.from_bytes(body[i:i + KEY], "big")
            for i in range(0, len(body), REC)]
    check(keys == list(range(cut)),
          f"the sift must drop everything at or above the cut, got {keys}")
    print("ok  sift: a rewind keeps the per-record road and cuts what it "
          "must")


# ---------------------------------------------------------------------------

def test_a_name_that_leaves_the_directory_is_refused(tmp):
    """A state file this process did not write is untrusted input, and
    these names are opened and, for runs, removed. Nothing legitimate
    is anything but a plain name in the artifact's own directory, so
    everything else is refused rather than joined and used."""
    store = fresh(tmp, "hostile")
    outside = os.path.join(tmp, "not-ours.bin")
    with open(outside, "wb") as f:
        f.write(b"a file that belongs to somebody else")

    for bad in ("../not-ours.bin", "../../etc/passwd", outside,
                "runs/../../escape", "..", "", None):
        for build in (store.path, store.run_path):
            try:
                build(bad)
                fail(f"{build.__name__} accepted {bad!r}")
            except StoreError:
                pass

    # And the ordinary case still works, or the guard would be a wall.
    check(store.path("archive_g0001.bin").startswith(store.dir),
          "a plain name must still resolve inside the directory")
    check(os.path.exists(outside),
          "the guard must refuse the name, never touch the file")
    print("ok  names: a manifest that reaches outside its own directory "
          "is refused")


TESTS = (test_fusion_generations_and_ladder,
         test_commit_order_is_the_crash_safety,
         test_dedup_last_and_none,
         test_dedup_len_longer_than_key,
         test_orphan_sweep_spares_the_declared_inventory,
         test_orphan_sweep_refuses_a_directory_without_a_state,
         test_orphan_sweep_matches_the_generation_shape_exactly,
         test_a_run_the_disk_lost_is_refused_on_load,
         test_a_fusion_refuses_without_the_space,
         test_drop_runs_defers_deletion,
         test_truncate_appended,
         test_gallop_answers_exactly_as_the_plain_fusion,
         test_gallop_combines_equal_keys_as_the_archive_does,
         test_gallop_refuses_a_stretch_it_cannot_express,
         test_gallop_still_verifies_the_base,
         test_sift_keeps_the_plain_road,
         test_a_name_that_leaves_the_directory_is_refused)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        for t in TESTS:
            t(tmp)
    print("PASS: genstore")


if __name__ == "__main__":
    main()


def test_bulk_stage_answers_exactly_as_the_per_record_roads(tmp):
    """The k-way stage by slabs (`_BulkFusion`): runs handed in as
    cursors must fuse to the reference's bytes, ladder, count and log,
    with and without a base to gallop over, under every rule. The
    slabs are tiny on purpose: a threshold then falls inside almost
    every slab, keys straddle slab ends and are carried by `refill`,
    and a round often holds one record or none. The narrow alphabets
    make equal keys the rule, so groups of three and more are reduced
    in one blob; the wide one makes the mask inexact and settles the
    candidates the slow way. The stage is counted, so a matrix that
    never entered it cannot pass."""
    rng = random.Random(20260914)
    rounds = []
    real = genstore._BulkFusion._round

    def counting(self):
        got = real(self)
        if got:
            rounds.append(len(got))
        return got

    genstore._BulkFusion._round = counting
    try:
        for case in range(200):
            rec = rng.choice((4, 6, 12, 24, 33))
            key_len = rng.randint(1, rec)
            dedup_len = rng.randint(key_len, rec)
            every = rng.choice((1, 2, 4, 16, 1024))
            rule = rng.choice(("last", None, "combine"))
            span = rng.choice((2, 3, 5, 256))
            slab = rng.choice((rec, rec * 2, rec * 7, rec * 64, 8 << 20))
            want_log = rng.random() < 0.5
            with_base = rng.random() < 0.5

            def rows(n):
                out = []
                for _ in range(n):
                    key = bytes(rng.randrange(span) for _ in range(key_len))
                    tail = bytes(rng.randrange(256)
                                 for _ in range(rec - key_len))
                    out.append(key + tail)
                return sorted(out)

            base_rows = rows(rng.choice((0, 1, 5, 40, 300))) if with_base \
                else []
            runs_rows = [rows(rng.choice((0, 1, 3, 30, 200)))
                         for _ in range(rng.randint(0, 12))]
            if rule == "combine":
                dedup, combine = None, _archive_like
                # No caller logs pairs under `combine`, and the two
                # roads log the running reduction where the reference
                # logs the rows: not asked for, as the gallop's test
                # does not ask for it.
                want_log = False
                # The archive's combine slices at fixed offsets: give
                # it the shape it expects when the rule is in play.
                rec, key_len, dedup_len = 8, 4, 4
                base_rows = [r[:4] + r[4:5] + r[5:8] for r in
                             (rows(len(base_rows)) if base_rows else [])]
                runs_rows = [rows(len(rr)) for rr in runs_rows]
            else:
                dedup, combine = rule, None
            want = reference([base_rows] + runs_rows, rec, key_len,
                             dedup_len, every, dedup, combine=combine)
            for road in ("streams", "cursors"):
                got = fuse_one_way(tmp, with_base, base_rows, runs_rows,
                                   rec, key_len, dedup_len, every, dedup,
                                   slab, want_log, combine=combine,
                                   runs_as=road)
                names = ("bytes", "ladder", "dups", "dup_log")
                for name, a, b in zip(names, want, got):
                    if b is None:
                        continue
                    check(a == b,
                          f"case {case} ({road}, base={with_base} rec={rec} "
                          f"key={key_len} dedup_len={dedup_len} "
                          f"every={every} rule={rule} span={span} "
                          f"slab={slab} log={want_log}): {name} differs\n"
                          f"   want {a!r}\n   got  {b!r}")
    finally:
        genstore._BulkFusion._round = real
    check(len(rounds) > 500 and max(rounds) > 3,
          f"the k-way stage ran {len(rounds)} rounds, widest {max(rounds or [0])}"
          ": a matrix that never reaches it proves nothing about it")
    print(f"ok  bulk stage: 200 randomized fusions match the reference "
          f"({len(rounds)} rounds, up to {max(rounds)} sources in one)")


def test_bulk_stage_rounds_are_bounded_when_the_sources_are_in_step(tmp):
    """Sources whose slabs all cover the same stretch of keys (every
    first fusion: random digests, one slab each at the start) must not
    be gathered into one round of the whole read budget. With the
    bound set low, no round may hold much more than it, the answer is
    the per-record road's, and the rounds are many where the last-key
    threshold made one."""
    rng = random.Random(20260916)
    rec, key_len = 24, 20
    d = os.path.join(tmp, "instep")
    os.makedirs(d, exist_ok=True)
    files, everything = [], []
    for i in range(8):
        rows = [bytes(rng.randrange(256) for _ in range(rec)) for _ in range(3000)]
        everything += rows
        p = os.path.join(d, f"src{i}.bin")
        _, sha = write_run(p, rows)
        files.append((p, sha))
    bound = genstore._ROUND_RECORDS
    genstore._ROUND_RECORDS = 256
    try:
        stage = genstore._BulkFusion(
            [_BaseCursor(p, rec, sha, 8 << 20, StoreError) for p, sha in files],
            rec, key_len, None, None, None)
        sizes = []
        while True:
            pieces = stage._round()
            if pieces is None:
                break
            sizes.append(sum(len(p) for p in pieces) // rec)
        check(sum(sizes) == 24000, f"the rounds gathered {sum(sizes)} records")
        check(max(sizes) <= 2 * 256,
              f"a round held {max(sizes)} records against a bound of 256")
        check(len(sizes) > 50, f"only {len(sizes)} rounds: the bound did not bite")
        stage = genstore._BulkFusion(
            [_BaseCursor(p, rec, sha, 8 << 20, StoreError) for p, sha in files],
            rec, key_len, None, None, None)
        check(b"".join(stage.blobs()) == b"".join(sorted(everything)),
              "the bounded rounds do not give the sorted whole")
    finally:
        genstore._ROUND_RECORDS = bound
    print(f"ok  bounded rounds: {len(sizes)} rounds, the largest {max(sizes)} "
          f"records, for 24,000 in step")


def test_bulk_stage_native_road_answers_as_the_reference_road(tmp):
    """The k-way stage with the kernel's `fuse_pieces` and without it,
    in one process, on the same random matrix under every rule the
    kernel knows: the same blobs and the same count, and the native
    road must actually have been taken. Skipped, and said so, where
    the kernel is not built."""
    import pytest
    from nodsig import kernel
    if not kernel.available():
        pytest.skip("the native kernel is not built: one road only")
    calls = []
    real = kernel.fuse_pieces

    def counting(pieces, rec, dl, rule):
        got = real(pieces, rec, dl, rule)
        calls.append(got is not None)
        return got

    rng = random.Random(20260916)
    d = os.path.join(tmp, "native")
    os.makedirs(d, exist_ok=True)
    kernel.fuse_pieces = counting
    try:
        for case in range(120):
            rule = rng.choice(("last", None, "or", "max"))
            if rule in ("or", "max"):
                rec, key_len = 8, rng.choice((3, 4))
                combine = _archive_like if rule == "or" else _scripts_like
                dedup = None
            else:
                rec = rng.choice((4, 6, 12, 24))
                key_len = rng.randint(1, rec)
                combine, dedup = None, rule
            span = rng.choice((2, 3, 5, 256))
            slab = rng.choice((rec, rec * 7, rec * 64, 8 << 20))
            files = []
            for i in range(rng.randint(0, 12)):
                rows = []
                for _ in range(rng.choice((0, 1, 3, 30, 200))):
                    key = bytes(rng.randrange(span) for _ in range(key_len))
                    rows.append(key + bytes(rng.randrange(256)
                                            for _ in range(rec - key_len)))
                p = os.path.join(d, f"src{i}.bin")
                _, sha = write_run(p, rows)
                files.append((p, sha))
            answers = []
            for road in ("native", "python"):
                saved = kernel._native
                if road == "python":
                    kernel._native = None
                try:
                    stage = genstore._BulkFusion(
                        [_BaseCursor(p, rec, sha, slab, StoreError)
                         for p, sha in files], rec, key_len, dedup, combine,
                        None)
                    check((stage.native_rule is not None) == (road == "native"),
                          f"case {case}: the {road} road was not the one taken")
                    answers.append((b"".join(stage.blobs()), stage.dups))
                finally:
                    kernel._native = saved
            check(answers[0] == answers[1],
                  f"case {case} (rule={rule} rec={rec} key={key_len} "
                  f"span={span} slab={slab}): the two roads differ")
    finally:
        kernel.fuse_pieces = real
    check(len(calls) > 200 and all(calls),
          f"the kernel took {len(calls)} rounds and declined "
          f"{calls.count(False)}: sorted pieces are never declined")
    print(f"ok  native road: 120 randomized stages match the reference road "
          f"({len(calls)} kernel rounds)")


def _scripts_like(a, b):
    """The archive's `_combine_scripts` on an 8-byte record: the larger
    byte, the lowest height."""
    return a[:4] + bytes([max(a[4], b[4])]) + min(a[5:], b[5:])


_scripts_like.native = "max_min"


def test_ladder_writer_samples_a_blob_as_it_samples_records(tmp):
    """`LadderWriter.add_blob` is arithmetic on a stretch; `add` is a
    test per record. Interleaving the two in every shape must leave
    the ladder, the sha and the count the per-record writer leaves."""
    rng = random.Random(7)
    for case in range(60):
        rec = rng.choice((3, 8, 24))
        key_len = rng.randint(1, rec)
        every = rng.choice((1, 2, 3, 16))
        rows = [bytes(rng.randrange(256) for _ in range(rec))
                for _ in range(rng.randint(0, 120))]
        rows.sort()
        want_ladder = b"".join(r[:key_len] for k, r in enumerate(rows)
                               if k % every == 0)
        path = os.path.join(tmp, f"lw{case}.bin")
        w = genstore.LadderWriter(path, rec, key_len, path + ".lad", every)
        i = 0
        while i < len(rows):
            if rng.random() < 0.5:
                w.add(rows[i])
                i += 1
            else:
                n = rng.randint(0, 9)
                w.add_blob(b"".join(rows[i:i + n]))
                i += n
        records, sha, lad_sha = w.close()
        with open(path, "rb") as f:
            body = f.read()
        with open(path + ".lad", "rb") as f:
            ladder = f.read()
        check(records == len(rows) and body == b"".join(rows)
              and sha == hashlib.sha256(body).hexdigest()
              and ladder == want_ladder
              and lad_sha == hashlib.sha256(ladder).hexdigest(),
              f"case {case}: the blob road and the record road disagree")
    print("ok  ladder writer: blobs and records sample the same ladder")


def test_split_is_slicing_and_keeps_a_bounded_cache():
    """`_split` must give exactly the records slicing gives, for every
    length around the chunk sizes and with a prefix format, and its
    cache of compiled formats must stay at a handful per shape whatever
    lengths it saw: a format per length was 295 MB per shape."""
    rng = random.Random(3)
    before = len(genstore._unpackers)
    for rec, unit in ((24, None), (36, None), (24, "20s4x"), (36, "32s4x")):
        width = rec if unit is None else int(unit.split("s")[0])
        for n in list(range(0, 70)) + [4095, 4096, 4097, 8191, 8192, 8193,
                                       12345, 20000]:
            blob = bytes(rng.randrange(256) for _ in range(n * rec))
            want = [blob[i:i + width] for i in range(0, n * rec, rec)]
            check(genstore._split(blob, rec, unit=unit) == want,
                  f"_split differs from slicing at n={n}, rec={rec}, "
                  f"unit={unit}")
            check(genstore._split(blob, rec, n, unit) == want,
                  f"_split with n given differs at n={n}")
    grown = len(genstore._unpackers) - before
    check(grown <= 4 * genstore._SPLIT_BITS,
          f"the cache grew by {grown} formats: it must stay bounded")
    print(f"ok  _split: slicing's answers, {grown} formats cached for 4 shapes")
