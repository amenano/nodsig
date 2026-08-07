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
    """Files that grow in place: a tail past the committed size is a
    crash leftover and is cut; a file SHORTER than committed is
    corruption and must stop everything."""
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

def reference(streams, rec, key_len, dedup_len, every, dedup):
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
        out += rows[j:j + 1] if dedup == "last" else rows[i:j + 1]
        i = j + 1
    ladder = b"".join(r[:key_len] for k, r in enumerate(out)
                      if k % every == 0)
    return b"".join(out), ladder, dups, log[:DUP_LOG_CAP]


def fuse_one_way(tmp, gallop, base_rows, runs_rows, rec, key_len,
                 dedup_len, every, dedup, slab, want_log):
    """One fusion, with the previous generation as a cursor (the gallop)
    or as one more stream (the plain road). Returns everything the
    fusion is answerable for."""
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
    sources = [read_fixed(p, rec, sha, slab) for p, sha in todo]
    log = [] if want_log else None
    records, sha, lad_sha, dups = merge_to_file(
        sources, out, rec, key_len, lad, every, dedup, dedup_len,
        dup_log=log, base=base)

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
         test_drop_runs_defers_deletion,
         test_truncate_appended,
         test_gallop_answers_exactly_as_the_plain_fusion,
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
