#!/usr/bin/env python3
"""FirstReveal-v1: the sixth artifact, when a key was first revealed.

Built from the archive's keys partition alone. The tests reuse the reuse
suite's synthetic chain, whose reveals are known by hand (they are the
same expectations test_reveal_archive pins on the archive itself):

    PUB1 revealed at height 2 (scriptSig)
    PUB3 revealed at height 3 (witness)
    PUB4 revealed at height 3 (inside WSCRIPT, a cosigner)
    PUB2 revealed at height 4 (inside REDEEM, a cosigner)
    PUB5 never revealed -> no row

Covered:
- build matches that model, byte for byte, sorted by (height, key), the
  row count equals the parent's keys records, and the parent is declared;
- an interrupted-and-resumed build equals the one-shot build;
- an append after the archive grows equals a fresh build, and a re-run
  against the same seal does nothing;
- the build refuses an archive that is not merged (pending runs);
- verify passes a clean table, catches a flipped byte, refuses a foreign
  parent;
- between returns the window's keys and refuses bad ranges.

Usage:
    python3 test_firstreveal.py    # prints PASS or fails loudly
    (also runs under pytest via the shared conftest fixtures)
"""

import io
import os
import sys
import tempfile

import pytest

from nodsig import firstreveal as fr
from nodsig import reveal_archive as ra
from nodsig.hashing import hash160
import test_reuse_scan as trs


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


REVEALS = {2: (trs.PUB1,), 3: (trs.PUB3, trs.PUB4), 4: (trs.PUB2,)}


def _expected_rows():
    """The model's first reveals, as sorted 23-byte records."""
    recs = [h.to_bytes(3, "big") + hash160(pub)
            for h, pubs in REVEALS.items() for pub in pubs]
    recs.sort()
    return recs


def _read_firstreveal(out_dir):
    manifest = fr._load_manifest(out_dir)
    entry = manifest["build"]["files"]["firstreveal"]
    with open(os.path.join(out_dir, entry["file"]), "rb") as f:
        return manifest, f.read()


def _merged_archive(tmp, blocks, name, end=4):
    """A scanned and merged archive, like the conftest fixture but with
    a choosable end height (a shorter chain seals a different parent)."""
    d = os.path.join(tmp, name)
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", end, d,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()
    ra.run_merge(d)
    return d


def test_build_matches_model(tmp, archive):
    out = os.path.join(tmp, "firstreveal")
    fp = fr.run_build(archive, out)

    manifest, data = _read_firstreveal(out)
    want = b"".join(_expected_rows())
    check(data == want,
          f"firstreveal bytes differ from the model: got {data.hex()}, "
          f"want {want.hex()}")
    rows = manifest["build"]["rows"]
    check(rows == len(_expected_rows()),
          f"row count {rows} != {len(_expected_rows())} revealed keys")
    am = ra._load_manifest(archive)
    check(rows == am["build"]["files"]["keys"]["records"],
          "rows differ from the parent's keys records: not a 1:1 map")
    check(hash160(trs.PUB5) not in data,
          "a never-revealed key grew a row")
    check(fp == manifest["fingerprint"], "run_build returned a stray fp")
    # provenance: the parent is the archive, declared and not sealed in.
    check(manifest["build"]["parent"]["fingerprint"] == am["fingerprint"],
          "firstreveal does not declare its archive parent")
    print("ok  firstreveal: bytes match the model, 1:1 with the keys "
          "partition, parent declared")


def test_resume_equals_oneshot(tmp, archive):
    one = os.path.join(tmp, "fr_one")
    fp_one = fr.run_build(archive, one)

    # Interrupt: flush one row at a time so the scan checkpoints mid-file,
    # then resume from the state on disk.
    part = os.path.join(tmp, "fr_part")
    st = fr._new_state()
    os.makedirs(part, exist_ok=True)
    (keys_path, keys_sha, _n, parent_fp, cov, _fmt) = \
        fr._archive_source(archive)
    st["source_fingerprint"] = parent_fp
    st["coverage"] = cov
    store = fr._store(part, st, clock=fr.WallClock("build", st))
    fr._phase_scan(store, keys_path, keys_sha, flush_records=1)
    st["phase"] = "merge"
    store.write_state()
    fp_part = fr.run_build(archive, part)

    check(fp_one == fp_part,
          f"resumed build {fp_part} != one-shot {fp_one}")
    _, a = _read_firstreveal(one)
    _, b = _read_firstreveal(part)
    check(a == b, "resumed bytes differ from one-shot")
    print("ok  firstreveal: an interrupted-and-resumed build equals "
          "one-shot")


def test_append_equals_rebuild(tmp, blocks):
    # An archive sealed at height 2, a table over it; the archive then
    # grows to 4 and re-seals; re-running build must equal a fresh build
    # over the grown archive, byte for byte.
    d = _merged_archive(tmp, blocks, "fr_grow", end=2)
    out = os.path.join(tmp, "fr_grown_table")
    fr.run_build(d, out)
    _, before = _read_firstreveal(out)
    check(before == b"".join(r for r in _expected_rows()
                             if int.from_bytes(r[:3], "big") <= 2),
          "the height-2 table is not the model's height-2 prefix")

    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, d,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()
    ra.run_merge(d)
    fp_append = fr.run_build(d, out)

    fresh = os.path.join(tmp, "fr_fresh")
    fp_fresh = fr.run_build(d, fresh)
    check(fp_append == fp_fresh,
          f"append fp {fp_append} != fresh-build fp {fp_fresh}")
    _, a = _read_firstreveal(out)
    _, b = _read_firstreveal(fresh)
    check(a == b, "appended bytes differ from a fresh build")

    # Same seal again: nothing to do, and the seal is untouched.
    fp_again = fr.run_build(d, out)
    check(fp_again == fp_append, "a no-op re-run moved the fingerprint")
    print("ok  firstreveal: append equals a fresh build over the grown "
          "archive, and a same-seal re-run is a no-op")


def test_refuses_an_unmerged_archive(tmp, archive_oneshot):
    try:
        fr.run_build(archive_oneshot, os.path.join(tmp, "x"))
        fail("build accepted an archive with unfused runs")
    except fr.FirstRevealError:
        pass
    print("ok  firstreveal: refuses an archive that is not merged")


def test_verify_passes_and_catches_corruption(tmp, archive):
    out = os.path.join(tmp, "fr_verify")
    fr.run_build(archive, out)

    devnull = open(os.devnull, "w")
    fr.run_verify(out, archive_dir=archive, out=devnull)
    fr.run_verify(out, out=devnull)          # trust-mode still audits

    manifest = fr._load_manifest(out)
    data_file = os.path.join(
        out, manifest["build"]["files"]["firstreveal"]["file"])
    with open(data_file, "r+b") as f:
        f.seek(0)
        b = f.read(1)
        f.seek(0)
        f.write(bytes([b[0] ^ 0xFF]))
    try:
        fr.run_verify(out, archive_dir=archive, out=devnull)
        fail("verify passed a table with a flipped byte")
    except fr.FirstRevealError:
        pass
    print("ok  firstreveal: verify passes a clean table and catches a "
          "flipped byte")


def test_verify_refuses_a_foreign_parent(tmp, blocks, archive):
    out = os.path.join(tmp, "fr_foreign")
    fr.run_build(archive, out)
    other = _merged_archive(tmp, blocks, "fr_other", end=2)
    try:
        fr.run_verify(out, archive_dir=other, out=open(os.devnull, "w"))
        fail("verify accepted a foreign parent")
    except fr.FirstRevealError:
        pass
    print("ok  firstreveal: verify refuses an archive that is not the "
          "parent")


def _between_keys(out_dir, from_h, to_h):
    buf = io.StringIO()
    fr.run_between(out_dir, from_h, to_h, out=buf)
    return {line.split()[0] for line in buf.getvalue().splitlines()
            if not line.startswith("#")}


def test_between_window(tmp, archive):
    out = os.path.join(tmp, "fr_bt")
    fr.run_build(archive, out)

    allset = _between_keys(out, 1, 4)
    want = {hash160(p).hex() for pubs in REVEALS.values() for p in pubs}
    check(allset == want, f"between(whole chain) = {allset}, want {want}")

    got = _between_keys(out, 3, 3)
    same = {hash160(p).hex() for p in REVEALS[3]}
    check(got == same, f"between(3,3) = {got}, want {same}")

    check(_between_keys(out, 1, 1) == set(),
          "height 1 reveals nothing in the model, between disagrees")
    print("ok  firstreveal: between returns the keys first revealed in a "
          "window, whole-chain and one-height")


def test_between_refuses_bad_range(tmp, archive):
    out = os.path.join(tmp, "fr_bt2")
    fr.run_build(archive, out)
    for lo, hi, why in [(3, 2, "from > to"),
                        (0, 3, "from below 1"),
                        (1, 5, "to past the coverage")]:
        try:
            fr.run_between(out, lo, hi, out=io.StringIO())
            fail(f"between accepted {why}")
        except fr.FirstRevealError:
            pass
    print("ok  firstreveal: between refuses a backwards range, height 0, "
          "and a window past the coverage")


def main():
    blocks = trs.build_chain()
    with tempfile.TemporaryDirectory() as tmp:
        archive = _merged_archive(tmp, blocks, "archive")
        test_build_matches_model(tmp, archive)
        test_resume_equals_oneshot(tmp, archive)
        test_verify_passes_and_catches_corruption(tmp, archive)
        test_verify_refuses_a_foreign_parent(tmp, blocks, archive)
        test_between_window(tmp, archive)
        test_between_refuses_bad_range(tmp, archive)
    with tempfile.TemporaryDirectory() as tmp:
        test_append_equals_rebuild(tmp, blocks)
    with tempfile.TemporaryDirectory() as tmp:
        d = os.path.join(tmp, "oneshot")
        server, url = trs.serve(blocks)
        try:
            ra.run_scan(url, "user:pass", 4, d,
                        batch_size=2, checkpoint_every=2)
        finally:
            server.shutdown()
        test_refuses_an_unmerged_archive(tmp, d)
    print("PASS: firstreveal builds the model, resumes and appends to the "
          "same bytes, and declares its parent.")


if __name__ == "__main__":
    main()
