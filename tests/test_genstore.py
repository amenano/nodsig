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
  can write the state first.

Usage:
    python3 test_genstore.py        # prints PASS or fails loudly
    (also runs under pytest)
"""

import json
import os
import sys
import tempfile

from nodsig.genstore import GenStore, new_state_fields

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
         test_a_name_that_leaves_the_directory_is_refused)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        for t in TESTS:
            t(tmp)
    print("PASS: genstore")


if __name__ == "__main__":
    main()
