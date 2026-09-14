#!/usr/bin/env python3
"""
test_reveal_archive.py — self-test for reveal_archive.py, no node and
no real data needed.

The test reuses the cast of test_reuse_scan.py on purpose: the same
synthetic snapshot (locks), the same four-block synthetic chain served
by the same fake node (JSON-RPC and REST). That is what makes the
cross-check testable end to end: both roads run here, on the same
data, and the test demands that they meet.

What is exercised:

- `scan`: the chain goes into sorted runs; the archive must contain
  exactly the digests the crafted spends reveal, with the right
  provenance bits, and none of the never-revealed ones;
- checkpoint hygiene: a run file not recorded in the state (a crash
  leftover) is removed on resume;
- `merge` and the appendable format: scanning in two takes
  (1..3 then 4) with a different flush threshold must fuse to the
  BYTE-IDENTICAL archive of a one-shot scan — the determinism rule
  the card index stands on; a second merge is a no-op;
- `crosscheck`, the cross-check proper: the archive-derived bitmaps
  must reproduce reuse_scan's fingerprint for the full perimeter AND
  for the narrow flag combinations; against a real reuse_scan
  state.json the check must pass — and it must FAIL loudly when the
  perimeters differ (a check that cannot fail checks nothing);
- crash safety of the fusion: a merge killed after the new
  generation reaches the disk but before the manifest names it
  leaves a readable archive, and the next merge completes it on
  the very fingerprint the uninterrupted one produced;
- corruption: a flipped byte in a run file must abort the merge, and
  corrupted block bytes from the server must abort the scan;
- the two transports: the same chain fetched over the node's binary
  REST endpoints, with three windows in flight, must merge to the
  byte-identical archive of a scan fetched over JSON-RPC;
- `derive`, the single-pass pipeline's read side: table, fingerprint
  AND per-checkpoint curve reproduced from the archive alone must
  equal reuse_scan's, on all three perimeters, with the curve CSV
  byte-identical; after a merge the fused base must land on the same
  final state (the curve's tiling is spent, by design); the archive
  it reads comes from a `--no-prefetch` scan, so the serial fetch path
  is covered too;
- `lookup`: revealed digests are found (with provenance), absent ones
  are reported absent.

Usage:
    python3 test_reveal_archive.py    # prints PASS or fails loudly
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile

from nodsig import blockparse as bp
from nodsig.artifact import (identity_fingerprint, sha_and_ladder,
                             statement_digest)
from nodsig import reuse_scan as rs
from nodsig import curve as cv
from nodsig import reveal_archive as ra
import test_blockparse as tbw           # block/tx writers
import test_reuse_scan as trs


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


def read_state(archive_dir):
    with open(os.path.join(archive_dir, ra.STATE_NAME)) as f:
        return json.load(f)


def archive_records(archive_dir, cat, with_height=False):
    """Every digest in the archive for one category, from the merged file
    and any runs, deduplicated: the test's own reader. By default it maps
    digest → byte, so the long-standing perimeter assertions read as they
    always did; `with_height` asks for the whole (byte, first_height).
    It reads through `ArchiveView`, so the proof is applied to the
    candidates of the runs exactly as every reader applies it."""
    view = ra.ArchiveView(archive_dir)
    try:
        rows = list(view.stream(cat))
    finally:
        view.close()
    if with_height:
        return {h: (fl, ht) for h, fl, ht in rows}
    return {h: fl for h, fl, _ht in rows}


# ---------------------------------------------------------------------------
# scan + content
# ---------------------------------------------------------------------------

def test_scan_content(tmp, blocks):
    server, url = trs.serve(blocks)
    archive = os.path.join(tmp, "archive_a")
    try:
        ra.run_scan(url, "user:pass", 4, archive,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()

    state = read_state(archive)
    check(state["last_height"] == 4, "watermark is not the end height")
    check(state["stats"]["malformed_scriptsig"] == 1,
          "malformed scriptSig not counted")

    # The keys the chain reveals, each with its provenance; PUB5 is
    # never revealed and must be absent.
    keys = archive_records(archive, "keys")
    expect = {
        rs.hash160(trs.PUB1): ra.FLAG_SIG,         # direct, scriptSig
        rs.hash160(trs.PUB3): ra.FLAG_WIT,         # direct, witness
        rs.hash160(trs.PUB2): ra.FLAG_INNER_SIG,   # redeem cosigner
        rs.hash160(trs.PUB4): ra.FLAG_INNER_WIT,   # wscript cosigner
    }
    check(keys == expect,
          f"keys archive: {{h.hex(): f for h, f in keys.items()}} != "
          f"expected provenance map")
    check(rs.hash160(trs.PUB5) not in keys, "unrevealed key archived")

    # Scripts: the real redeem/witness scripts, and nothing else. PUB1
    # (the last scriptSig push of the P2PKH spend) and PUB3 (the last
    # witness item of the P2WPKH spend) are candidates too, and no
    # program the chain created opens them, so the proof leaves them
    # out; the programs of REDEEM and WSCRIPT were created at height 2.
    s20 = archive_records(archive, "scripts20")
    check(set(s20) == {rs.hash160(trs.REDEEM)},
          "scripts20 content differs from the crafted spends")
    s32 = archive_records(archive, "scripts32")
    check(set(s32) == {hashlib.sha256(trs.WSCRIPT).digest()},
          "scripts32 content differs from the crafted spends")
    check(state["stats"]["program_outputs"] == 2,
          f"the two programs created at height 2 are counted: "
          f"{state['stats']}")
    print("ok  scan: watermark, provenance bits, exact content")
    return archive


def test_scan_content_v3(tmp, blocks):
    """Height 5 holds what only the v3 archive sees: a key published in
    a pay-to-pubkey output and two in a bare multisig (OUT), a 65-byte
    key whose compressed face is recorded under OTHER_FACE, a hybrid
    lead accepted, a taproot script path revealing its internal key and
    its leaf key (XONLY), and a scriptSig that is one well-formed DER
    signature: a candidate script by position, kept out of `scripts20`
    because no program opens it, not because of its shape."""
    from nodsig import keyforms as kf
    server, url = trs.serve(blocks)
    archive = os.path.join(tmp, "archive_v3")
    try:
        ra.run_scan(url, "user:pass", 5, archive,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()
    keys = archive_records(archive, "keys", with_height=True)
    comp_u5 = kf.compressed_of(trs.PUBU5)
    comp_h = kf.compressed_of(trs.PUBH)
    expect = {
        rs.hash160(trs.PUBU5): (ra.FLAG_OUT | ra.FLAG_UNCOMPRESSED, 5),
        rs.hash160(comp_u5): (ra.FLAG_OTHER_FACE, 5),
        rs.hash160(trs.PUB6): (ra.FLAG_OUT, 5),
        rs.hash160(trs.PUB7): (ra.FLAG_OUT, 5),
        rs.hash160(trs.PUBH): (ra.FLAG_SIG | ra.FLAG_UNCOMPRESSED, 5),
        rs.hash160(comp_h): (ra.FLAG_OTHER_FACE, 5),
        rs.hash160(b"\x02" + trs.XINT): (ra.FLAG_WIT | ra.FLAG_XONLY, 5),
        rs.hash160(b"\x02" + trs.XLEAF): (ra.FLAG_INNER_WIT | ra.FLAG_XONLY,
                                          5),
    }
    for digest, want in expect.items():
        check(keys.get(digest) == want,
              f"key {digest.hex()[:12]}…: {keys.get(digest)} != {want}")
    check(rs.hash160(trs.PUB5) not in keys, "unrevealed key archived")
    s20 = archive_records(archive, "scripts20")
    check(set(s20) == {rs.hash160(trs.REDEEM)},
          "a DER signature or a hybrid key reached scripts20")
    s32 = archive_records(archive, "scripts32")
    check(set(s32) == {hashlib.sha256(trs.WSCRIPT).digest()},
          "a control block or a leaf reached scripts32")
    st = read_state(archive)["stats"]
    check(st["out_keys"] == 3 and st["control_or_annex"] == 1,
          f"the counters must say what the bytes excluded: {st}")
    ra.run_merge(archive)
    ra.run_verify(archive, deep=True)
    pile = archive_records(archive, "unproven20")
    check(rs.hash160(trs.DER_SIG) in pile and rs.hash160(trs.PUB1) in pile,
          "the candidates no program opens wait in the proof")
    print("ok  scan v3: outputs, other face, hybrid, x-only, and the "
          "candidates the proof sets aside")


def test_stale_run_cleanup(tmp, blocks):
    """A run file the state does not know about (crash between flush
    and checkpoint) must be deleted on resume, not silently fused."""
    archive = os.path.join(tmp, "archive_stale")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 2, archive,
                    batch_size=2, checkpoint_every=2)
        stale = os.path.join(archive, ra.RUNS_DIR,
                             "run_00000003-00000003_keys.bin")
        with open(stale, "wb") as f:
            f.write(bytes(21))
        ra.run_scan(url, "user:pass", 4, archive,
                    batch_size=2, checkpoint_every=2)
        check(not os.path.exists(stale), "stale run survived the resume")
    finally:
        server.shutdown()
    print("ok  resume: stale run files are removed, not fused")


# ---------------------------------------------------------------------------
# merge: determinism, appendability, idempotence
# ---------------------------------------------------------------------------

def test_merge_determinism(tmp, blocks, archive_oneshot):
    fp_oneshot = ra.run_merge(archive_oneshot)

    # Two takes (1..3, then 4), tiny flushes → many small runs; two
    # fusions along the way. The final archive must be byte-identical.
    archive_b = os.path.join(tmp, "archive_b")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 3, archive_b,
                    batch_size=2, checkpoint_every=2, flush_records=1)
        ra.run_merge(archive_b)
        ra.run_scan(url, "user:pass", 4, archive_b,
                    batch_size=2, checkpoint_every=2, flush_records=1)
    finally:
        server.shutdown()
    fp_b = ra.run_merge(archive_b)
    check(fp_b == fp_oneshot,
          "append-and-fuse archive differs from the one-shot archive")
    # The merged files carry a generation, and the two archives reached
    # this state by a different number of fusions — so the NAMES differ
    # while the bytes must not. Resolve each through its own manifest:
    # that is the whole point of the name living in the manifest.
    man_a = ra._load_manifest(archive_oneshot)
    man_b = ra._load_manifest(archive_b)
    for cat in ra.CAT_ORDER:
        with open(os.path.join(archive_oneshot,
                               ra._cat_file(man_a, cat)), "rb") as f:
            a = f.read()
        with open(os.path.join(archive_b, ra._cat_file(man_b, cat)),
                  "rb") as f:
            b = f.read()
        check(a == b, f"merged {cat} files differ byte for byte")

    check(ra.run_merge(archive_oneshot) == fp_oneshot,
          "re-merge with no new runs changed the fingerprint")
    print("ok  merge: appended+fused == one-shot, byte for byte; "
          "re-merge is a no-op")
    return archive_b


def test_merge_crash_recovery(tmp, blocks):
    """A fusion killed after the new generation is on disk but before
    the manifest names it must leave the archive READABLE and the next
    merge must complete it.

    The old shape overwrote `archive_<cat>.bin` in place, so that kill
    left the manifest describing bytes that no longer existed — and
    every reader, `merge` included, verifies that sha256 before
    yielding a byte, so the archive could not even be re-fused. The
    generation makes the write additive: nothing the manifest names is
    ever touched until the manifest itself has moved.
    """
    archive = os.path.join(tmp, "archive_crash_merge")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 2, archive,
                    batch_size=2, checkpoint_every=2)
        ra.run_merge(archive)                  # generation 1 is the base
        ra.run_scan(url, "user:pass", 4, archive,
                    batch_size=2, checkpoint_every=2)   # runs pile up
    finally:
        server.shutdown()

    # The crash, faithfully: fuse in a clone, copy the generation files
    # it produced back, and leave the manifest and the runs untouched.
    clone = os.path.join(tmp, "crash_merge_clone")
    shutil.copytree(archive, clone)
    want = ra.run_merge(clone)
    for name in os.listdir(clone):
        if name.startswith("archive_") and "_g0002" in name:
            shutil.copyfile(os.path.join(clone, name),
                            os.path.join(archive, name))

    # Still readable: the manifest names generation 1, which is intact.
    # (Under the old shape this raised "sha256 mismatch" and there was
    # no way back.)
    man = ra._load_manifest(archive)
    check(ra._merged_sighting(archive, man, "keys", rs.hash160(trs.PUB1),
                              None) is not None,
          "a half-committed fusion must not stop the readers")

    got = ra.run_merge(archive)
    check(got == want,
          "the completed fusion must land on the fingerprint the "
          f"uninterrupted one produced: {got} != {want}")
    left = sorted(n for n in os.listdir(archive)
                  if n.startswith("archive_"))
    check(all("_g0002" in n for n in left),
          f"the superseded generation was not swept: {left}")
    print("ok  merge: a fusion killed before its manifest leaves a "
          "readable archive, and the next merge completes it")


def test_run_corruption(tmp, blocks):
    """One flipped byte in a run must stop the fusion."""
    archive = os.path.join(tmp, "archive_corrupt")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, archive,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()
    state = read_state(archive)
    victim = os.path.join(archive, ra.RUNS_DIR, state["runs"][0]["name"])
    data = bytearray(open(victim, "rb").read())
    data[0] ^= 0xFF
    with open(victim, "wb") as f:
        f.write(data)
    try:
        ra.run_merge(archive)
        fail("corrupted run accepted by merge")
    except rs.ScanError:
        print("ok  corruption: a flipped byte in a run aborts the merge")


def test_verify(tmp, blocks):
    """The audit of a sealed archive, and everything it must refuse.

    `verify` is what someone who did NOT build an archive runs on it,
    so every check is tested by breaking exactly one thing and leaving
    the rest whole: a check that cannot fail checks nothing. Two of the
    breakages are RE-SEALED afterwards, digest and ladder and
    fingerprint recomputed, because that is the honest shape of the
    danger: not a corrupted archive, a wrong one sealed faithfully."""
    archive = os.path.join(tmp, "archive_verify")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, archive,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()

    # Before the fusion there is no fingerprint to verify against, and
    # saying so is the answer, not a crash.
    try:
        ra.run_verify(archive)
        fail("verify accepted an archive that was never merged")
    except ra.ScanError:
        pass

    ra.run_merge(archive)
    ra.run_verify(archive)                     # bytes, ladders, fingerprint
    ra.run_verify(archive, deep=True)          # and every record

    # The case the audit exists for: an archive someone else built,
    # arriving as the merged files and their manifest, with no state
    # and no runs. Everything verify needs is inside what was shipped.
    inherited = os.path.join(tmp, "archive_inherited")
    os.makedirs(inherited)
    for name in os.listdir(archive):
        if name.startswith("archive_") or name == ra.MANIFEST_NAME:
            shutil.copyfile(os.path.join(archive, name),
                            os.path.join(inherited, name))
    ra.run_verify(inherited, deep=True)
    print("ok  verify: a sealed archive passes both roads, inherited "
          "without its state too")

    # What follows breaks the ARCHIVE one way at a time and re-seals it;
    # each re-seal moves the fingerprint the proof names as its parent,
    # and the proof's own audit has tests of its own. Set it aside, so
    # every refusal below is the archive's.
    shutil.rmtree(os.path.join(archive, ra.PROOF_DIR))

    man_path = os.path.join(archive, ra.MANIFEST_NAME)
    man = ra._load_manifest(archive)
    keys_path = os.path.join(archive, ra._cat_file(man, "keys"))
    lad_path = os.path.join(archive, man["build"]["caches"]["keys"]["file"])
    pristine = {p: open(p, "rb").read()
                for p in (man_path, keys_path, lad_path)}

    def restore():
        for path, data in pristine.items():
            with open(path, "wb") as f:
                f.write(data)

    def write_manifest(manifest):
        with open(man_path, "w") as f:
            json.dump(manifest, f)

    def reseal(cat):
        """Record the digest, the ladder and the fingerprint the files
        now imply: what a build that went wrong would have sealed."""
        manifest = ra._load_manifest(archive)
        rec, key_len, every = ra.ARCHIVE_LADDERS[cat]
        sha, ladder = sha_and_ladder(
            os.path.join(archive, ra._cat_file(manifest, cat)),
            rec, key_len, every, ra.ScanError)
        for entry in manifest["identity"]["files"]:
            if entry["name"] == cat:
                entry["sha256"] = sha
        cache = manifest["build"]["caches"][cat]
        with open(os.path.join(archive, cache["file"]), "wb") as f:
            f.write(ladder)
        cache["sha256"] = hashlib.sha256(ladder).hexdigest()
        manifest["fingerprint"] = identity_fingerprint(manifest["identity"])
        manifest["statement"] = statement_digest(manifest)
        write_manifest(manifest)

    # 1. A flipped byte: the digest catches it, no --deep needed.
    data = bytearray(pristine[keys_path])
    data[0] ^= 0xFF
    with open(keys_path, "wb") as f:
        f.write(data)
    try:
        ra.run_verify(archive)
        fail("verify accepted a merged file with a flipped byte")
    except ra.ScanError:
        pass
    restore()

    # 2. Two records swapped, then re-sealed: the bytes are exactly the
    #    ones the fingerprint names, so the fast road has nothing to say
    #    and MUST pass. Only the record pass can see that the file is
    #    not sorted, which is the whole reason --deep exists.
    width = ra.rec_width("keys")
    data = bytearray(pristine[keys_path])
    data[0:width] = pristine[keys_path][width:2 * width]
    data[width:2 * width] = pristine[keys_path][0:width]
    with open(keys_path, "wb") as f:
        f.write(data)
    reseal("keys")
    ra.run_verify(archive)
    try:
        ra.run_verify(archive, deep=True)
        fail("the record audit accepted a file out of order")
    except ra.ScanError as e:
        check("goes back to" in str(e),
              f"out-of-order file reported as: {e}")
    restore()

    # 3. A ladder that is intact and WRONG: its own digest updated so
    #    the intact-only check passes. This is the failure a verify
    #    comparing a ladder with a digest of itself can never see.
    bad = bytearray(pristine[lad_path])
    bad[0] ^= 0xFF
    with open(lad_path, "wb") as f:
        f.write(bad)
    man = ra._load_manifest(archive)
    man["build"]["caches"]["keys"]["sha256"] = \
        hashlib.sha256(bytes(bad)).hexdigest()
    write_manifest(man)
    try:
        ra.run_verify(archive)
        fail("verify accepted a ladder that its file does not imply")
    except ra.ScanError as e:
        check("not the ladder" in str(e), f"wrong ladder reported as: {e}")
    restore()

    # 4. A watermark raised by hand. The coverage lives INSIDE the
    #    identity, so the fingerprint moves and the manifest stops
    #    matching itself: this is the check that makes the archive's
    #    "never revealed up to H" worth anything.
    man = ra._load_manifest(archive)
    man["identity"]["coverage"]["to"] = 400_000
    write_manifest(man)
    try:
        ra.run_verify(archive)
        fail("verify accepted a manifest whose coverage was edited")
    except ra.ScanError as e:
        check("fingerprint" in str(e), f"edited coverage reported as: {e}")
    print("ok  verify: flipped byte, a file out of order, a ladder its "
          "file does not imply and an edited coverage are all refused")

    # 5. The same lie with the fingerprint recomputed to match it. Now
    #    only the data can object, and about the tail they cannot: no
    #    revelation between height 5 and 400,000 is exactly what an
    #    archive that stopped at 4 looks like. It passes, and the
    #    report says the coverage is a floor.
    man["fingerprint"] = identity_fingerprint(man["identity"])
    man["statement"] = statement_digest(man)
    write_manifest(man)
    ra.run_verify(archive, deep=True)

    # 6. A watermark LOWERED below records the archive holds is the one
    #    coverage lie the floor does catch.
    man["identity"]["coverage"]["to"] = 2
    man["fingerprint"] = identity_fingerprint(man["identity"])
    man["statement"] = statement_digest(man)
    write_manifest(man)
    try:
        ra.run_verify(archive, deep=True)
        fail("the deep pass accepted a record above the watermark")
    except ra.ScanError as e:
        check("outside the coverage" in str(e),
              f"record above the watermark reported as: {e}")
    restore()
    print("ok  verify: the coverage is a floor, and a revelation above "
          "the claimed watermark is refused")


def test_scan_and_merge_exclude_each_other(archive):
    """A merge started while a scan checkpoints into the same directory
    used to win or lose a race hours later: the state loaded before the
    fusion was written back over the scan's, naming runs the merge had
    deleted or moving the watermark back. The directory's `.lock` makes
    the second command refuse at once. The lock is held by the process,
    so a crash cannot leave it behind."""
    from nodsig.recio import exclusive
    with exclusive(archive, ra.ScanError, "test"):
        try:
            ra.run_merge(archive)
            fail("a merge ran on a directory another command holds")
        except ra.ScanError as e:
            check(".lock" in str(e), f"the refusal must name the lock: {e}")
    ra.run_merge(archive)          # free again: nothing to fuse, no error
    print("ok  exclusion: a held directory refuses a second command, "
          "and is free once the first is done")


def test_merge_refuses_without_the_space_and_a_lost_run(tmp, blocks):
    """Two guards on the scan path. The first fusion of a scan reads
    the whole run pile, about twice what it seals, and used to find a
    full disk hours in; it now names the bytes and refuses first. And
    a run the state names with a size the disk does not hold was lost
    after the state was written: refused at the next resume, not at
    the fusion with "sha256 mismatch"."""
    from nodsig import recio
    archive = os.path.join(tmp, "archive_guards")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, archive, batch_size=2,
                    checkpoint_every=2)
        real = recio.shutil.disk_usage
        class _Usage:
            total = used = 0
            free = 1
        recio.shutil.disk_usage = lambda _p: _Usage
        try:
            ra.run_merge(archive)
            fail("a merge started without the space for it")
        except ra.ScanError as e:
            check("free" in str(e), f"the refusal must name the space: {e}")
        finally:
            recio.shutil.disk_usage = real
        check(not any(n.startswith("archive_") for n in os.listdir(archive)),
              "the refusal must come before the first byte")

        run = ra._load_state(archive)["runs"][0]
        with open(ra._run_path(archive, run["name"]), "ab") as f:
            f.truncate(0)
        try:
            ra.run_scan(url, "user:pass", 4, archive, batch_size=2,
                        checkpoint_every=2)
            fail("a resume accepted a run the disk lost")
        except ra.ScanError as e:
            check("lost" in str(e), f"the refusal must say what happened: {e}")
    finally:
        server.shutdown()
    print("ok  guards: no space is refused before writing; a lost run is "
          "refused at resume")


def test_a_broken_state_file_is_a_named_refusal(tmp):
    """Twenty loaders opened and parsed by hand; a truncated state.json
    (a kill during a write, a bad copy) died in a json traceback in
    some of them and in a bare FileNotFoundError in one. One reader
    now, and the failure keeps the artifact's own type."""
    d = os.path.join(tmp, "broken_archive")
    os.makedirs(d)
    with open(os.path.join(d, ra.STATE_NAME), "w") as f:
        f.write('{"format": "reveal-archive-v2", "runs": [')
    try:
        ra._load_state(d)
        fail("a truncated state was read")
    except ra.ScanError as e:
        check("truncated" in str(e), f"the refusal must say why: {e}")
    print("ok  loaders: a broken JSON is the artifact's own refusal")


def test_verify_reports_unfused_runs(tmp, blocks):
    """An archive with runs beyond its merged base is queryable and NOT
    sealed. The audit must say so: the fingerprint it just verified
    covers less history than the archive answers from."""
    archive = os.path.join(tmp, "archive_verify_runs")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 2, archive,
                    batch_size=2, checkpoint_every=2)
        ra.run_merge(archive)
        ra.run_scan(url, "user:pass", 4, archive,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ra.run_verify(archive, deep=True)
    text = out.getvalue()
    check("NOT SEALED" in text, f"unfused runs not reported: {text}")
    check("3..4" in text, f"the uncovered heights are not named: {text}")
    ra.run_merge(archive)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ra.run_verify(archive, deep=True)
    check("NOT SEALED" not in out.getvalue(),
          "a fused archive is still reported as unsealed")
    print("ok  verify: unfused runs are named, and stop being named "
          "once fused")


def test_deep_verify_reads_the_archive_once_and_checks_the_same_things(
        archive):
    """--deep hands the record pass's digests and ladders to the audit
    instead of streaming tens of GB a second time. What it checks must
    not change: a ladder that is intact but does not index its file is
    still refused, and the file is still read exactly once."""
    man = ra._load_manifest(archive)
    lad_path = os.path.join(archive, man["build"]["caches"]["keys"]["file"])
    keys_name = ra._cat_file(man, "keys")
    pristine = open(lad_path, "rb").read()

    reads = []
    real_slabs = ra.read_fixed

    def counting(path, *a, **kw):
        if os.path.basename(path) == keys_name:
            reads.append(path)
        return real_slabs(path, *a, **kw)

    ra.read_fixed = counting
    try:
        ra.run_verify(archive, deep=True)
    finally:
        ra.read_fixed = real_slabs
    check(len(reads) == 1,
          f"the merged keys file was streamed {len(reads)} times, "
          "expected once")

    # The wrong-ladder check must survive the shortcut: its own digest
    # is updated so only a rebuild from the data can object.
    bad = bytearray(pristine)
    bad[0] ^= 0xFF
    with open(lad_path, "wb") as f:
        f.write(bytes(bad))
    man["build"]["caches"]["keys"]["sha256"] = \
        hashlib.sha256(bytes(bad)).hexdigest()
    with open(os.path.join(archive, ra.MANIFEST_NAME), "w") as f:
        json.dump(man, f)
    try:
        ra.run_verify(archive, deep=True)
        fail("the deep audit accepted a ladder its file does not imply")
    except ra.ScanError as e:
        check("not the ladder" in str(e), f"wrong ladder reported as: {e}")
    print("ok  deep verify: one read of the archive, and the ladder is "
          "still confronted with the file")


def test_verify_refuses_a_manifest_missing_a_mandated_file(archive):
    """A manifest whose identity lost a file entry, RE-SEALED so the
    fingerprint covers the shortened list, is consistent with itself in
    every digest: each listed file checks out and the fingerprint
    recomputes to the same number. The audit still has to refuse it,
    because the file list is the format's, not the manifest's — a
    fingerprint over two categories does not name a revelation archive,
    whatever it verifies against."""
    man_path = os.path.join(archive, ra.MANIFEST_NAME)
    man = ra._load_manifest(archive)
    dropped = man["identity"]["files"].pop()
    del man["build"]["caches"][dropped["name"]]
    man["fingerprint"] = identity_fingerprint(man["identity"])
    man["statement"] = statement_digest(man)
    with open(man_path, "w") as f:
        json.dump(man, f)
    try:
        ra.run_verify(archive)
        fail("verify accepted a manifest that lists fewer files than "
             "the format is made of")
    except ra.ScanError as e:
        check("is made of" in str(e),
              f"missing mandated file reported as: {e}")
    print("ok  verify: a self-consistent manifest missing a mandated "
          "file is refused")


def test_rest_transport(tmp, blocks):
    """Fetched over REST, the same chain must produce the same archive
    down to the byte.

    The archive is the artifact whose fingerprint gets published, so
    "the transport is a detail" is not an opinion here, it is something
    to show: one scan over JSON-RPC, one over REST at depth 3 (windows
    coming back out of order, handed to the scan in height order), then
    both merged and compared file by file."""
    a_rpc = os.path.join(tmp, "archive_rpc")
    a_rest = os.path.join(tmp, "archive_rest")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, a_rpc,
                    batch_size=2, checkpoint_every=2)
        ra.run_scan(url, None, 4, a_rest,
                    batch_size=1, checkpoint_every=2,
                    client=rs.RestClient(url), prefetch_depth=3)
    finally:
        server.shutdown()

    fp_rpc = ra.run_merge(a_rpc)
    fp_rest = ra.run_merge(a_rest)
    check(fp_rest == fp_rpc,
          "the archive fetched over REST has a different fingerprint")
    man_rpc = ra._load_manifest(a_rpc)
    man_rest = ra._load_manifest(a_rest)
    for cat in ra.CAT_ORDER:
        with open(os.path.join(a_rpc, ra._cat_file(man_rpc, cat)),
                  "rb") as f:
            over_rpc = f.read()
        with open(os.path.join(a_rest, ra._cat_file(man_rest, cat)),
                  "rb") as f:
            over_rest = f.read()
        check(over_rpc == over_rest,
              f"merged {cat} differs between the two transports")
    print("ok  rest: byte-identical archive, RPC against REST at depth 3")


def test_block_corruption(tmp, blocks):
    """Corrupted block bytes from the server must abort the scan —
    this road re-derives integrity from the bytes exactly like the
    other one."""
    corrupt = dict(blocks)
    h_hex, raw_hex = corrupt[3]
    pos = len(raw_hex) - 40
    flipped = ("0" if raw_hex[pos] != "0" else "f")
    corrupt[3] = (h_hex, raw_hex[:pos] + flipped + raw_hex[pos + 1:])
    server, url = trs.serve(corrupt)
    try:
        ra.run_scan(url, "user:pass", 4,
                    os.path.join(tmp, "archive_badblock"),
                    batch_size=2, checkpoint_every=2)
        fail("corrupted block accepted by the archive scan")
    except (rs.ScanError, bp.ParseError):
        print("ok  corruption: altered block bytes abort the scan")
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# crosscheck: the cross-check, on every perimeter
# ---------------------------------------------------------------------------

def test_crosscheck(tmp, blocks, locks_dir, archive):
    server, url = trs.serve(blocks)
    try:
        for label, faces, cosigners in [("full", True, True),
                                        ("narrow", False, False),
                                        ("no-cosigners", True, False)]:
            cp = os.path.join(tmp, f"cp_{label}")
            fp_scan = rs.run_scan(locks_dir, url, "user:pass", 4, cp,
                                  batch_size=2, checkpoint_every=2,
                                  faces=faces, cosigners=cosigners)
            fp_arch = ra.run_crosscheck(
                archive, locks_dir, faces=faces, cosigners=cosigners,
                reuse_state_path=os.path.join(cp, rs.STATE_NAME))
            check(fp_arch == fp_scan,
                  f"cross-check ({label}): fingerprints differ")
    finally:
        server.shutdown()
    print("ok  cross-check: both roads meet, on all three perimeters")

    # A check that cannot fail checks nothing: comparing the narrow
    # archive reading against the FULL scan state must be refused.
    try:
        ra.run_crosscheck(archive, locks_dir, faces=False,
                          cosigners=False,
                          reuse_state_path=os.path.join(
                              tmp, "cp_full", rs.STATE_NAME))
        fail("mismatched perimeters passed the cross-check")
    except rs.ScanError:
        print("ok  cross-check: a real mismatch fails loudly")

    # The two roads must burn the SAME locks: a checkpoint whose
    # recorded locks manifest differs from the locks directory's is
    # refused before any fingerprint is compared.
    with open(os.path.join(tmp, "cp_full", rs.STATE_NAME)) as f:
        state = json.load(f)
    state["locks"] = "0" * 64
    tampered = os.path.join(tmp, "state_other_locks.json")
    with open(tampered, "w") as f:
        json.dump(state, f)
    try:
        ra.run_crosscheck(archive, locks_dir, reuse_state_path=tampered)
        fail("a checkpoint against different locks passed the cross-check")
    except rs.ScanError:
        print("ok  cross-check: a checkpoint against different locks "
              "is refused")


# ---------------------------------------------------------------------------
# derive — the single-pass pipeline's read side
# ---------------------------------------------------------------------------

def test_crosscheck_refuses_a_perimeter_other_than_the_scans(tmp, blocks,
                                                             locks_dir, archive):
    """The scan records the perimeter its bitmaps were burnt under; the
    cross-check read with other flags gave another fingerprint and
    said "one of the two pipelines is wrong" about a correct pair."""
    server, url = trs.serve(blocks)
    cp = os.path.join(tmp, "cp_narrow_scan")
    try:
        rs.run_scan(locks_dir, url, "user:pass", 4, cp, batch_size=2,
                    checkpoint_every=2, cosigners=False)
    finally:
        server.shutdown()
    try:
        ra.run_crosscheck(archive, locks_dir,
                          reuse_state_path=os.path.join(cp, rs.STATE_NAME))
        fail("a cross-check under another perimeter was compared")
    except ra.ScanError as e:
        check("flags" in str(e) and "pipelines" not in str(e),
              f"the refusal must name the perimeter, not a defect: {e}")
    print("ok  cross-check: a perimeter other than the scan's is refused "
          "by name")


def test_the_curve_is_refused_under_a_narrow_perimeter(tmp, locks_dir,
                                                       archive):
    """A keys record carries one first_height, the minimum over every
    sighting: under --no-cosigners the final table is right but every
    intermediate curve row dated a burn by a sighting the perimeter
    excluded. The combination is refused rather than printed."""
    curve = os.path.join(tmp, "narrow_curve.csv")
    try:
        ra.run_derive(archive, locks_dir, cosigners=False, curve_path=curve,
                      curve_every=1)
        fail("a curve under a narrow perimeter was written")
    except ra.ScanError as e:
        check("full perimeter" in str(e), f"unexpected: {e}")
    check(not os.path.exists(curve), "nothing must be written")
    ra.run_derive(archive, locks_dir, cosigners=False)     # the table: fine
    print("ok  curve: refused under a narrow perimeter, the table is not")


def test_the_two_roads_meet_on_the_forms_v3_sees(tmp, blocks):
    """Height 5 holds the sightings the 2.0.0 extraction added (keys in
    outputs, the other face, a hybrid, x-only taproot keys) and the
    candidates the shape filter drops. The reuse scan and the archive
    walk the chain separately and must still meet on one fingerprint,
    under every perimeter."""
    base5 = os.path.join(tmp, "base5")
    os.makedirs(base5)
    locks5 = trs.test_prepare(base5, base_hash_hex=blocks[5][0], height=5)
    server, url = trs.serve(blocks)
    archive = os.path.join(tmp, "archive_roads5")
    try:
        ra.run_scan(url, "user:pass", 5, archive, batch_size=2,
                    checkpoint_every=2)
        for label, faces, cosigners in [("full", True, True),
                                        ("narrow", False, False),
                                        ("no-cosigners", True, False)]:
            cp = os.path.join(tmp, f"cp5_{label}")
            fp_scan = rs.run_scan(locks5, url, "user:pass", 5, cp,
                                  batch_size=2, checkpoint_every=2,
                                  faces=faces, cosigners=cosigners)
            fp_arch = ra.run_crosscheck(
                archive, locks5, faces=faces, cosigners=cosigners,
                reuse_state_path=os.path.join(cp, rs.STATE_NAME))
            check(fp_arch == fp_scan,
                  f"cross-check at 5 ({label}): fingerprints differ")
    finally:
        server.shutdown()
    st = read_state(archive)["stats"]
    check(st["out_keys"] == 3 and st["control_or_annex"] == 1,
          f"the archive must have seen height 5: {st}")
    print("ok  cross-check at 5: both roads meet on the v3 sightings, on "
          "all three perimeters")


def test_derive(tmp, blocks, locks_dir):
    server, url = trs.serve(blocks)
    archive = os.path.join(tmp, "arch_derive")
    try:
        ra.run_scan(url, "user:pass", 4, archive,
                    batch_size=2, checkpoint_every=2,
                    prefetch=False)          # the serial fallback path
        for label, faces, cosigners in [("full", True, True),
                                        ("narrow", False, False),
                                        ("no-cosigners", True, False)]:
            cp = os.path.join(tmp, f"cpd_{label}")
            fp_scan = rs.run_scan(locks_dir, url, "user:pass", 4, cp,
                                  batch_size=2, checkpoint_every=2,
                                  faces=faces, cosigners=cosigners)
            # The curve is exact only under the full perimeter (a keys
            # record carries one first_height, whatever the provenance
            # of the sighting that set it), so derive refuses it under
            # a narrow one; the table is derived on every perimeter.
            full = faces and cosigners
            curve = os.path.join(tmp, f"curve_{label}.csv") if full else None
            fp_der = ra.run_derive(archive, locks_dir, faces=faces,
                                   cosigners=cosigners,
                                   curve_path=curve, curve_every=2)
            check(fp_der == fp_scan,
                  f"derive ({label}): fingerprint differs from the scan")
            if full:
                scan_curve = os.path.join(cp, rs.CURVE_NAME)
                with open(curve) as f_a, open(scan_curve) as f_b:
                    check(f_a.read() == f_b.read(),
                          f"derive ({label}): curve differs from the scan's")
                # The same bytes, the same sidecar fingerprint, whatever
                # road wrote it; and the cross-check compares them too.
                check(cv.read_meta(curve)["fingerprint"]
                      == cv.read_meta(scan_curve)["fingerprint"],
                      "the two roads must seal the same curve fingerprint")
                check(cv.read_meta(curve)["build"]["road"] == "derive"
                      and cv.read_meta(curve)["build"]["parent"] is None,
                      "a live archive is no parent, and the road is named")
                ra.run_crosscheck(archive, locks_dir,
                                  reuse_state_path=os.path.join(
                                      cp, rs.STATE_NAME),
                                  curve_path=scan_curve)
                tampered = os.path.join(tmp, "curve_tampered.csv")
                shutil.copy(scan_curve, tampered)
                shutil.copy(scan_curve + cv.META_SUFFIX,
                            tampered + cv.META_SUFFIX)
                with open(tampered, "a") as f:
                    f.write("5,9,9,9,9,9,9,9,9,ff\n")
                try:
                    ra.run_crosscheck(archive, locks_dir,
                                      reuse_state_path=os.path.join(
                                          cp, rs.STATE_NAME),
                                      curve_path=tampered)
                    fail("a curve that changed beside its sidecar passed")
                except (ra.ScanError, cv.CurveError):
                    pass
        print("ok  derive: the table equals the scan's on all three "
              "perimeters, and the curve on the full one, sidecar and "
              "cross-check included")

        # The twin the scan writes, from this road: bitmaps and a state
        # `reuse stats` reads, with the scan's fingerprint.
        cpd = os.path.join(tmp, "cp_from_derive")
        fp_cp = ra.run_derive(archive, locks_dir, checkpoint_dir=cpd)
        st = json.load(open(os.path.join(cpd, rs.STATE_NAME)))
        check(st["format"] == rs.STATE_TAG and st["road"] == "derive"
              and st["fingerprint"] == fp_cp
              and st["fingerprint"] == json.load(open(os.path.join(
                  tmp, "cpd_full", rs.STATE_NAME)))["fingerprint"]
              and st["base_seen_at"] == 4,
              f"derive --checkpoint writes the scan's twin: {st}")
        rs.run_stats(locks_dir, cpd, thresholds=(0, 10))
        print("ok  derive: --checkpoint writes what `reuse stats` reads")

        # After a merge the tiling is spent: derive burns the fused
        # base silently and must land on the same final state.
        ra.run_merge(archive)
        fp_der = ra.run_derive(archive, locks_dir)
        with open(os.path.join(tmp, "cpd_full", rs.STATE_NAME)) as f:
            check(fp_der == json.load(f)["fingerprint"],
                  "derive after merge: fingerprint differs")
        print("ok  derive: a merged archive lands on the same state")
    finally:
        server.shutdown()


def test_derive_refuses_locks_from_another_block(tmp, blocks):
    """The reuse table is defined by TWO moments: the archive's tip
    and the block the snapshot's locks were photographed at. Locks
    whose base hash is not the archive's tip must be refused, because
    a table mixing two moments is indistinguishable from a right one;
    the explicit flag is the only door through."""
    server, url = trs.serve(blocks)
    archive = os.path.join(tmp, "arch_base_mismatch")
    try:
        ra.run_scan(url, "user:pass", 4, archive,
                    batch_size=2, checkpoint_every=2, prefetch=False)
    finally:
        server.shutdown()
    snapshot = os.path.join(tmp, "other_moment.dat")
    foreign = os.path.join(tmp, "locks_other_moment")
    trs.build_snapshot_file(snapshot)       # default fake base hash
    rs.run_prepare(snapshot, foreign, chunk_records=3, height=9)
    try:
        ra.run_derive(archive, foreign)
        fail("derive accepted locks photographed at another block")
    except rs.ScanError:
        print("ok  derive: locks from another block are refused")
    fp = ra.run_derive(archive, foreign, allow_base_mismatch=True)
    check(fp is not None, "derive with the explicit flag did not run")
    print("ok  derive: the explicit flag crosses the two moments, "
          "and says so in the header")


def _curve_rows(path):
    with open(path) as f:
        head, *body = [line.rstrip("\n").split(",") for line in f]
    return head, [(int(r[0]), r[1:]) for r in body]


def test_the_curve_covers_the_runs_it_reads(tmp, blocks):
    """`archive curve` reads the sealed generation AND the pending runs,
    but labelled its rows with the manifest's coverage: after a merge at
    3 and a resume to 4, the row for height 3 held height 4's first
    revelations too. The curve of a merged-then-resumed archive must
    equal the curve of a one-shot scan to the same height."""
    server, url = trs.serve(blocks)
    split = os.path.join(tmp, "curve_split")
    whole = os.path.join(tmp, "curve_whole")
    try:
        ra.run_scan(url, "user:pass", 3, split, batch_size=2,
                    checkpoint_every=1, prefetch=False)
        ra.run_merge(split)
        ra.run_scan(url, "user:pass", 4, split, batch_size=2,
                    checkpoint_every=1, prefetch=False)
        ra.run_scan(url, "user:pass", 4, whole, batch_size=2,
                    checkpoint_every=1, prefetch=False)
    finally:
        server.shutdown()
    check(ra._load_state(split)["runs"], "the fixture needs pending runs")
    rows = {}
    for name, archive in (("split", split), ("whole", whole)):
        path = os.path.join(tmp, f"curve_{name}.csv")
        ra.run_archive_curve(archive, path, every=1)
        rows[name] = _curve_rows(path)
    check(rows["split"] == rows["whole"],
          f"merge-then-resume curve {rows['split']} differs from the "
          f"one-shot curve {rows['whole']}")
    check([h for h, _ in rows["split"][1]][-1] == 4,
          "the last row must be the archive's watermark, not the seal's")
    print("ok  curve: a merged-then-resumed archive curves like a one-shot "
          "scan, up to its own watermark")


def test_the_curve_lands_on_the_grid_it_was_asked_for(tmp, blocks, locks_dir):
    """The rows must sit where the caller asked, not where the scan
    happened to close a run.

    This is the case the mirror test above cannot see: it runs with the
    grid equal to the checkpoint interval, so a row falls due at every
    boundary whatever the code does. On the published chain the two
    never coincided — the download batch offsets every boundary by 24,
    no boundary was a multiple of 10,000, and the file came out with
    one row. Asserting the heights against the grid, and the count
    against an expectation computed from the coverage rather than from
    the code under test, is what closes that.
    """
    server, url = trs.serve(blocks)
    archive = os.path.join(tmp, "arch_grid")
    try:
        ra.run_scan(url, "user:pass", 4, archive, batch_size=2,
                    checkpoint_every=2, prefetch=False)
        end = ra._load_state(archive)["last_height"]

        # 3 is the discriminating one: no run boundary is a multiple of
        # it, which is the shape the published chain had for 10,000.
        for every in (1, 2, 3):
            curve = os.path.join(tmp, f"grid_{every}.csv")
            ra.run_derive(archive, locks_dir, curve_path=curve,
                          curve_every=every)
            _, rows = _curve_rows(curve)
            expected = list(range(every, end + 1, every))
            if not expected or expected[-1] != end:
                expected.append(end)
            check([h for h, _ in rows] == expected,
                  f"curve on the {every} grid: heights "
                  f"{[h for h, _ in rows]} are not the grid {expected}")
        print("ok  curve: the rows land on the grid, on three of them")

        # The property that removes the ordering rule: first_height
        # survives the fusion, so the curve does not care whether the
        # tiling is still there.
        before = os.path.join(tmp, "grid_before.csv")
        after = os.path.join(tmp, "grid_after.csv")
        ra.run_derive(archive, locks_dir, curve_path=before, curve_every=1)
        ra.run_merge(archive)
        ra.run_derive(archive, locks_dir, curve_path=after, curve_every=1)
        with open(before) as a, open(after) as b:
            check(a.read() == b.read(),
                  "the curve changed across the merge: the tiling is "
                  "still leaking into it")
        print("ok  curve: identical before and after the merge")
    finally:
        server.shutdown()


def test_the_archive_curve_needs_nothing_but_the_archive(tmp, blocks):
    """`archive curve` answers when each thing was first revealed, and
    it takes no locks, no snapshot and no perimeter: note that this
    test never builds a lock set.

    The count is checked against the manifest's own per-category record
    counts, which the fusion wrote and this code does not read: an
    expectation from the other side. And it must not move across the
    merge, because a window is defined by first_height and not by where
    the runs happen to be cut.
    """
    server, url = trs.serve(blocks)
    archive = os.path.join(tmp, "arch_curve")
    try:
        ra.run_scan(url, "user:pass", 4, archive, batch_size=2,
                    checkpoint_every=2, prefetch=False)
        loose = os.path.join(tmp, "acurve_loose.csv")
        total_loose = ra.run_archive_curve(archive, loose, every=1)

        ra.run_merge(archive)
        fused = os.path.join(tmp, "acurve_fused.csv")
        total_fused = ra.run_archive_curve(archive, fused, every=1)

        with open(loose) as a, open(fused) as b:
            check(a.read() == b.read(),
                  "the archive curve moved across the merge")
        check(total_loose == total_fused, "the totals moved across the merge")

        manifest = ra._load_manifest(archive)
        # `points` counts points and not serializations: a keys record
        # carrying UNCOMPRESSED is the 65-byte form of a point whose
        # canonical record is counted once.
        keys_path = os.path.join(archive, ra._cat_file(manifest, "keys"))
        uncompressed = sum(
            1 for _h, fl, _ht in ra._read_records(
                keys_path, "keys", ra._cat_sha(manifest, "keys"))
            if fl & ra.FLAG_UNCOMPRESSED)
        expected = sum(entry["records"]
                       for entry in manifest["build"]["files"].values()
                       ) - uncompressed
        check(total_fused == expected,
              f"archive curve counted {total_fused} first revelations, "
              f"the manifest holds {expected} points and scripts")
        head, _rows = _curve_rows(fused)
        check(head == ["height", "points", "scripts20", "scripts32", "total"],
              f"the archive curve names what it counts: {head}")
        meta = cv.verify(fused, cv.ARCHIVE_TAG)
        check(meta["build"]["parent"]["fingerprint"] == manifest["fingerprint"]
              and meta["build"]["grid"] == 1,
              f"the sidecar declares the archive and the grid: {meta['build']}")

        # Every record falls in exactly one window, so widening the grid
        # to a single window must land on the same total.
        one = os.path.join(tmp, "acurve_one.csv")
        check(ra.run_archive_curve(archive, one, every=4) == expected,
              "a one-window curve disagrees with the per-height one")
        print("ok  archive curve: totals match the manifest, and the "
              "merge does not move them")
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------

def test_lookup(archive):
    merged = os.path.join(archive,
                          ra._cat_file(ra._load_manifest(archive), "keys"))
    hit = ra._bisect_file(merged, "keys", rs.hash160(trs.PUB1))
    check(hit == (ra.FLAG_SIG, 2),
          f"lookup: PUB1 sighting wrong: {hit}")
    check(ra._bisect_file(merged, "keys", rs.hash160(trs.PUB5)) is None,
          "lookup: unrevealed key found")

    # C1: merge writes a ladder sidecar per category, recorded in the
    # manifest OUTSIDE the fingerprint, and the ladder-backed lookup must
    # meet the blind on-disk bisect on the same byte for every key — the
    # ladder only decides WHERE to read.
    manifest = ra._load_manifest(archive)
    check("keys" in manifest["build"]["caches"],
          "merge did not record a ladder cache")
    lad = os.path.join(archive, manifest["build"]["caches"]["keys"]["file"])
    check(os.path.exists(lad), "ladder sidecar missing on disk")
    for pub in (trs.PUB1, trs.PUB5, trs.PUB2):
        key = rs.hash160(pub)
        check(ra._lookup_merged(archive, manifest, "keys", key)
              == ra._bisect_file(merged, "keys", key),
              "ladder lookup disagrees with the blind bisect")

    # The CLI path, as a user would drive it (smoke: must not raise).
    ra.run_lookup(archive, [rs.hash160(trs.PUB1).hex(),
                            rs.hash160(trs.PUB5).hex(),
                            hashlib.sha256(trs.WSCRIPT).digest().hex()])
    print("ok  lookup: found with provenance, ladder meets blind bisect")


# The frozen reveal-archive-v4 fingerprint of the synthetic chain. Unlike the
# determinism tests (which check that two builds AGREE), this pins the absolute
# value, so a format change that alters every build identically is still
# caught. Update deliberately if the format or the fixture chain changes.
GOLDEN_ARCHIVE_FINGERPRINT = \
    "b920ff746bc92a933f0dc1161b68319280409fe76ce766c56dcbe2b74fd4c379"


def test_golden_fingerprint(archive):
    fp = ra._load_manifest(archive)["fingerprint"]
    check(fp == GOLDEN_ARCHIVE_FINGERPRINT,
          f"reveal-archive-v4 fingerprint drifted from the frozen value: {fp}")
    print("ok  golden: the synthetic archive fingerprint is unchanged")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        blocks = trs.build_chain()
        locks_dir = trs.test_prepare(tmp, base_hash_hex=blocks[4][0], height=4)
        archive = test_scan_content(tmp, blocks)
        test_scan_content_v3(tmp, blocks)
        test_stale_run_cleanup(tmp, blocks)
        test_merge_determinism(tmp, blocks, archive)
        test_merge_crash_recovery(tmp, blocks)
        test_run_corruption(tmp, blocks)
        test_verify(tmp, blocks)
        test_verify_reports_unfused_runs(tmp, blocks)
        test_rest_transport(tmp, blocks)
        test_block_corruption(tmp, blocks)
        test_crosscheck(tmp, blocks, locks_dir, archive)
        test_derive(tmp, blocks, locks_dir)
        test_derive_refuses_locks_from_another_block(tmp, blocks)
        test_lookup(archive)
        test_golden_fingerprint(archive)
    print("PASS: the archive matches the crafted chain, fuses "
          "deterministically, and the two roads meet on the same "
          "fingerprint.")


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# the two fields the record gained: first_height and the inner-key count
# ---------------------------------------------------------------------------
# A chain of its own, deliberately not `build_chain`: that one carries the
# perimeter assertions of half this suite, and stretching it to cover two
# more fields would ripple through counts that are asserted elsewhere for
# unrelated reasons. Same choice test_outpoint_index made with index_chain.

MULTI = (bytes([0x52, 33]) + trs.PUB2 + bytes([33]) + trs.PUB3
         + bytes([33]) + trs.PUB4 + bytes([0x53, 0xAE]))   # 2-of-3


def heights_chain():
    """Five blocks built so that the same key is revealed TWICE, on
    either side of a run boundary and of a fusion:

        h2  PUB1 in a scriptSig            ← the first sighting
        h3  a P2SH spend revealing MULTI, which holds three pubkeys
        h5  PUB1 again, in a witness       ← later, and must not win
    """
    blocks = {}
    prev = bytes(32)

    def add(height, raw_txs, txids):
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_600_000_000 + height,
                                      0x1700_0000, height, raw_txs, txids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())

    def coinbase(tag, witness=False, commit_wtxids=None):
        outs = [tbw.w_output(50 * rs.SAT, tbw.P2PKH_SPK)]
        if witness:
            outs.append(tbw.w_output(
                0, tbw.w_commitment_spk(commit_wtxids, bytes(32))))
        return tbw.w_tx(
            1, [tbw.w_input(bytes(32), 0xFFFFFFFF, tag, 0xFFFFFFFF)],
            outs, 0, witnesses=[[bytes(32)]] if witness else None)

    cb, cbid, _ = coinbase(b"\x01a")
    add(1, [cb], [cbid])

    cb, cbid, _ = coinbase(b"\x01b")
    spend = bytes([71]) + trs.FAKE_SIG + bytes([33]) + trs.PUB1
    # The same transaction creates the P2SH output MULTI opens at h3.
    tx, txid, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xB1" * 32, 0, spend, 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK),
         tbw.w_output(10, b"\xa9\x14" + rs.hash160(MULTI) + b"\x87")], 0)
    add(2, [cb, tx], [cbid, txid])

    cb, cbid, _ = coinbase(b"\x01c")
    # 105 bytes needs OP_PUSHDATA1: a bare length byte only pushes 1..75,
    # and a redeem script that big is exactly the realistic case.
    sig_script = (b"\x00" + bytes([71]) + trs.FAKE_SIG
                  + b"\x4c" + bytes([len(MULTI)]) + MULTI)
    tx, txid, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xB2" * 32, 0, sig_script, 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0)
    add(3, [cb, tx], [cbid, txid])

    cb, cbid, _ = coinbase(b"\x01d")
    add(4, [cb], [cbid])

    tx, txid, wtxid = tbw.w_tx(
        2, [tbw.w_input(b"\xB3" * 32, 0, b"", 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0,
        witnesses=[[trs.FAKE_SIG, trs.PUB1]])
    cb, cbid, _ = coinbase(b"\x01e", witness=True, commit_wtxids=[wtxid])
    add(5, [cb, tx], [cbid, txid])
    return blocks


def _scan_heights(tmp, name, end=5, checkpoint_every=2):
    server, url = trs.serve(heights_chain())
    d = os.path.join(tmp, name)
    try:
        ra.run_scan(url, "user:pass", end, d, batch_size=2,
                    checkpoint_every=checkpoint_every)
    finally:
        server.shutdown()
    return d


def test_first_height_is_the_lowest_sighting(tmp):
    """PUB1 is revealed at height 2 and again at height 5, in different
    runs and across a fusion. The record must carry 2: the archive
    answers WHEN a key became public, and becoming public happens once."""
    archive = _scan_heights(tmp, "heights")
    key = rs.hash160(trs.PUB1)

    before = archive_records(archive, "keys", with_height=True)
    check(before[key][1] == 2,
          f"across runs, first_height should be 2, got {before[key][1]}")
    check(before[key][0] == ra.FLAG_SIG | ra.FLAG_WIT,
          "the flags of both sightings must still be OR-ed together")

    ra.run_merge(archive)
    after = archive_records(archive, "keys", with_height=True)
    check(after[key] == before[key],
          f"the fusion changed the sighting: {before[key]} -> {after[key]}")

    # And the reader agrees with the stream, on both roads.
    manifest = ra._load_manifest(archive)
    merged = os.path.join(archive, ra._cat_file(manifest, "keys"))
    check(ra._bisect_file(merged, "keys", key) == after[key],
          "the blind bisect disagrees with the merged stream")
    check(ra._lookup_merged(archive, manifest, "keys", key) == after[key],
          "the ladder-backed lookup disagrees with the blind bisect")


def test_a_watermark_past_the_seal_withholds_the_fingerprint(tmp):
    """Height 4 of this chain reveals nothing and creates no program, so a
    scan from a seal at 3 to 4 moves the watermark and writes no run. The
    answers are right up to 4; the fingerprint speaks for 3, and a reader
    must not hand it out as if it covered both."""
    archive = _scan_heights(tmp, "past_seal", end=3)
    ra.run_merge(archive)
    server, url = trs.serve(heights_chain())
    try:
        ra.run_scan(url, "user:pass", 4, archive, batch_size=1,
                    checkpoint_every=1)
    finally:
        server.shutdown()
    view = ra.ArchiveView(archive)
    check(not view.runs and view.watermark == 4,
          "the fixture needs a watermark past the seal and no run")
    check(not view.sealed, "a fingerprint sealed at 3 was offered for 4")


def test_a_never_revealed_key_stays_absent(tmp):
    archive = _scan_heights(tmp, "absent")
    check(rs.hash160(trs.PUB5) not in archive_records(archive, "keys"),
          "a key nobody revealed must not appear because records grew")


def test_scripts_carry_how_many_keys_are_inside(tmp):
    """The byte that used to be reserved and zero now counts the pubkeys
    found inside the revealed script: three, for a 2-of-3."""
    archive = _scan_heights(tmp, "counted")
    ra.run_merge(archive)
    scripts = archive_records(archive, "scripts20", with_height=True)
    byte, height = scripts[rs.hash160(MULTI)]
    check(byte == 3, f"the 2-of-3 should count 3 keys inside, got {byte}")
    check(height == 3, f"the script was revealed at height 3, got {height}")

    keys = archive_records(archive, "keys")
    for pub in (trs.PUB2, trs.PUB3, trs.PUB4):
        check(rs.hash160(pub) in keys,
              "every key inside the revealed script must be archived too")


def test_append_and_rebuild_agree_on_both_new_fields(tmp):
    """The reduction is `or` on the flags and `min` on the height, and
    both are associative and commutative: scanning in two takes with a
    different checkpoint rhythm must land on the same bytes as one shot.
    This is where a `max` slipped in by accident would show."""
    one = _scan_heights(tmp, "oneshot", end=5, checkpoint_every=2)
    ra.run_merge(one)

    two = os.path.join(tmp, "twotakes")
    blocks = heights_chain()
    for end, every in ((3, 3), (5, 1)):
        server, url = trs.serve(blocks)
        try:
            ra.run_scan(url, "user:pass", end, two, batch_size=1,
                        checkpoint_every=every)
        finally:
            server.shutdown()
    ra.run_merge(two)

    for cat in ra.CAT_ORDER:
        a = os.path.join(one, ra._cat_file(ra._load_manifest(one), cat))
        b = os.path.join(two, ra._cat_file(ra._load_manifest(two), cat))
        check(open(a, "rb").read() == open(b, "rb").read(),
              f"{cat}: appending in two takes did not rebuild the same bytes")
    check(ra._load_manifest(one)["fingerprint"]
          == ra._load_manifest(two)["fingerprint"],
          "append != rebuild on the fingerprint")


# ---------------------------------------------------------------------------
# the form bit, and the projection back to the published v1 bytes
# ---------------------------------------------------------------------------

PUBU = b"\x04" + bytes(range(1, 65))     # uncompressed, 65 bytes


def form_chain():
    """Two spends at height 2: PUB1 (33 bytes) and PUBU (65 bytes),
    the two serializations side by side."""
    blocks = {}
    prev = bytes(32)

    def add(height, raw_txs, txids):
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_600_000_000 + height,
                                      0x1700_0000, height, raw_txs, txids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())

    def coinbase(tag):
        return tbw.w_tx(
            1, [tbw.w_input(bytes(32), 0xFFFFFFFF, tag, 0xFFFFFFFF)],
            [tbw.w_output(50 * rs.SAT, tbw.P2PKH_SPK)], 0)

    cb, cbid, _ = coinbase(b"\x01u")
    add(1, [cb], [cbid])

    cb, cbid, _ = coinbase(b"\x01v")
    s1 = bytes([71]) + trs.FAKE_SIG + bytes([33]) + trs.PUB1
    t1, id1, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xC1" * 32, 0, s1, 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0)
    s2 = bytes([71]) + trs.FAKE_SIG + bytes([65]) + PUBU
    t2, id2, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xC2" * 32, 0, s2, 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0)
    add(2, [cb, t1, t2], [cbid, id1, id2])
    return blocks


def test_the_form_bit_and_the_other_face(tmp):
    """A 65-byte sighting carries FLAG_UNCOMPRESSED and its compressed
    face is recorded beside it under OTHER_FACE, at the same height; a
    33-byte one carries neither; the deep audit accepts every bit of
    the eight and refuses the one pairing that cannot exist."""
    from nodsig import keyforms as kf
    server, url = trs.serve(form_chain())
    archive = os.path.join(tmp, "form")
    try:
        ra.run_scan(url, "user:pass", 2, archive, batch_size=1,
                    checkpoint_every=1)
    finally:
        server.shutdown()

    recs = archive_records(archive, "keys", with_height=True)
    check(recs[rs.hash160(PUBU)] == (ra.FLAG_SIG | ra.FLAG_UNCOMPRESSED, 2),
          "the 65-byte sighting must carry the form bit")
    check(recs[rs.hash160(kf.compressed_of(PUBU))] == (ra.FLAG_OTHER_FACE, 2),
          "the compressed face must be recorded at the same height")
    check(recs[rs.hash160(trs.PUB1)] == (ra.FLAG_SIG, 2),
          "a compressed sighting must carry neither form bit")

    ra.run_merge(archive)
    ra.run_verify(archive, deep=True)
    manifest = ra._load_manifest(archive)
    path = os.path.join(archive, ra._cat_file(manifest, "keys"))
    with open(path, "r+b") as f:
        f.seek(20)
        f.write(bytes([ra.FLAG_UNCOMPRESSED | ra.FLAG_XONLY]))
    try:
        ra.run_verify(archive, deep=True)
        fail("a record both 65-byte and x-only passed the deep audit")
    except rs.ScanError:
        pass
    print("ok  forms: the form bit, the other face, and the audit's rule")


# ---------------------------------------------------------------------------
# The scan's own seconds, in all four artifacts it co-emits
# ---------------------------------------------------------------------------

def test_the_scan_records_its_seconds_in_every_artifact_it_emits(tmp, blocks):
    """One walk of the chain writes four artifacts, and each records the
    SAME seconds under `scan` in its own state.

    Why this is a test and not a hope: the number is the only measured
    cost a reader ever gets for the longest phase of the pipeline, and it
    is the one that has to survive a run split over several sessions. It
    is wired in four different writers, so nothing but a test keeps the
    four in step.

    What it must NOT tempt anyone into: adding those four numbers. They
    are one pass seen four times. WallClock's docstring says so, and the
    assertion below pins the equality that makes the sum wrong."""
    server, url = trs.serve(blocks)
    archive = os.path.join(tmp, "sec_archive")
    graph = os.path.join(tmp, "sec_graph")
    nonces = os.path.join(tmp, "sec_nonces")
    try:
        ra.run_scan(url, "user:pass", 2, archive, batch_size=2,
                    checkpoint_every=2, graph_dir=graph,
                    nonces_dir=nonces)
        first = {}
        for name, d in (("archive", archive), ("graph", graph),
                        ("nonces", nonces)):
            with open(os.path.join(d, "state.json")) as f:
                st = json.load(f)
            check("seconds" in st and "scan" in st["seconds"],
                  f"{name}: the scan left no seconds in its state: {st.keys()}")
            first[name] = st["seconds"]["scan"]
            stretches = st.get("wall", {}).get("scan")
            check(stretches and len(stretches) == 1,
                  f"{name}: expected one wall stretch, got {stretches}")
            check(stretches[0][0] <= stretches[0][1]
                  and stretches[0][1].endswith("Z"),
                  f"{name}: malformed wall stretch {stretches[0]}")

        # RESUME. The total lives in the state, so a second stretch adds
        # to the first instead of replacing it. This is the property the
        # whole thing exists for: a run split over sessions still reports
        # what it really cost.
        ra.run_scan(url, "user:pass", 4, archive, batch_size=2,
                    checkpoint_every=2, graph_dir=graph,
                    nonces_dir=nonces)
        for name, d in (("archive", archive), ("graph", graph),
                        ("nonces", nonces)):
            with open(os.path.join(d, "state.json")) as f:
                st = json.load(f)
            check(st["seconds"]["scan"] >= first[name],
                  f"{name}: seconds went BACKWARDS across a resume "
                  f"({st['seconds']['scan']} < {first[name]}): the total "
                  "restarted instead of accumulating")
            # An IN-PROCESS resume continues its own wall stretch: one
            # pair still, not a duplicate twin per run_scan call.
            check(len(st["wall"]["scan"]) == 1,
                  f"{name}: an in-process resume duplicated the wall "
                  f"stretch: {st['wall']['scan']}")
    finally:
        server.shutdown()
    print("ok  scan seconds: recorded in all four artifacts, and they "
          "accumulate across a resume")


# ---------------------------------------------------------------------------
# The rule with no exceptions: exclude only on proof
# ---------------------------------------------------------------------------

def _witness_shapes(key33, key65):
    """Witness layouts that between them put a key in every position a
    real spend does, including the ones a taproot slot rule calls
    "somewhere a signature could sit"."""
    sig71 = b"\x30" * 71
    script97 = b"\x63" + b"\x51" * 96          # OP_IF …: a conditional script
    return {
        "p2wpkh": [sig71, key33],
        # A Lightning HTLC on the chain: signature, KEY, preimage,
        # branch, script. The key is the second item of five.
        "htlc": [sig71, key33, b"\xAB" * 32, b"\x01", script97],
        "p2wsh multisig": [b"", sig71, sig71, key33, script97],
        "uncompressed in the middle": [sig71, key65, b"\x01", script97],
    }


def test_the_archive_excludes_a_key_only_on_proof_never_on_position():
    """The invariant, not a list of cases: wherever a key-shaped item
    sits in a witness, the archive holds its digest.

    A false positive here is a record that can only match its own
    preimage, so it is inert; a false negative makes the archive answer
    "protected" about something the chain published. 2.0.0 excluded by
    position and lost 804 keys on the real chain."""
    from nodsig.blockparse import TxIn
    from nodsig.keyforms import canonical_key
    key33 = b"\x02" + bytes(range(1, 33))
    key65 = b"\x04" + bytes(range(1, 65))
    for name, wit in _witness_shapes(key33, key65).items():
        txin = TxIn(bytes(32), 0, b"", 0xFFFFFFFF, list(wit))
        got = ra.extract_revelations(txin, ra.new_filter_stats())
        keys = {d for cat, d, _f in got if cat == "keys"}
        for item in wit:
            ck = canonical_key(item)
            if ck is None:
                continue
            canon, seen, _form = ck
            with_ = f"{name}: the key at that position is missing"
            check(canon in keys, with_)
            if seen is not None:
                check(seen in keys, with_ + " (form seen)")
    print("ok  keys: no position is excluded, in any witness shape")


def test_what_the_archive_does_exclude_is_proved_impossible():
    """The other half of the same rule. A control block and an annex
    cannot be scripts — their first byte executes and fails — so they
    are kept out of the script partitions, and that exclusion is a
    proof rather than a shape. A key and a signature are not excluded:
    they CAN be scripts, and the fusion asks the chain."""
    from nodsig.sightings import cannot_be_script, is_control_block
    stats = ra.new_filter_stats()
    control = b"\xc0" + b"\x11" * 32
    check(is_control_block(control), "the fixture must be a control block")
    check(cannot_be_script(control, 2, stats),
          "a control block must be excluded from the script partitions")
    annex = b"\x50" + b"\x22" * 10
    check(cannot_be_script(annex, 2, stats), "an annex must be excluded too")
    for shaped in (trs.PUB1, trs.PUBU5, trs.DER_SIG, trs.SCHNORR_SIG):
        check(not cannot_be_script(shaped, 2, stats)
              and not cannot_be_script(shaped, 0, stats),
              f"a {len(shaped)}-byte item was excluded by its shape")
    check(stats["control_or_annex"] == 2, f"counted: {stats}")


def test_the_two_roads_read_a_witness_the_same_way():
    """The loop lived twice, in `reveal_archive` and in `reuse_scan`,
    which is how both roads came to share the defect instead of the
    cross-check catching it. One function now, and this pins it."""
    from nodsig.blockparse import TxIn
    key33 = b"\x03" + bytes(range(2, 34))
    key65 = b"\x04" + bytes(range(2, 66))
    for name, wit in _witness_shapes(key33, key65).items():
        txin = TxIn(bytes(32), 0, b"", 0xFFFFFFFF, list(wit))
        recs = ra.extract_revelations(txin, ra.new_filter_stats())
        from nodsig.sightings import burns_for
        a = set()
        for cat, digest, flags in recs:
            a.update(burns_for(cat, digest, flags, True, True))
        b = set(rs.extract_reveals(txin, True, True, rs.new_filter_stats()))
        check(a == b, f"{name}: the two roads disagree: {a ^ b}")
    print("ok  the two roads extract the same records from a witness")


# ---------------------------------------------------------------------------
# The proof: a candidate is a script when the chain created its program
# ---------------------------------------------------------------------------
# A chain of its own again, built around the cases the proof has to get
# right and the shape filter of 2.0.0 got wrong.

def _push(data):
    if len(data) <= 75:
        return bytes([len(data)]) + data
    return b"\x4c" + bytes([len(data)]) + data


def _p2sh(script):
    return b"\xa9\x14" + rs.hash160(script) + b"\x87"


def _p2wsh(script):
    return b"\x00\x20" + hashlib.sha256(script).digest()


# A redeem script with the shape of a key and a witness script with the
# shape of a DER signature: real scripts here, because outputs were
# created with their programs, and exactly what 2.0.0 dropped by shape.
KEY_SHAPED_REDEEM = b"\x02" + bytes(range(100, 132))
SIG_SHAPED_WSCRIPT = trs.DER_SIG
# A witness script nested in P2SH: no output carries its program, the
# redeem script its spend pushes does.
NESTED_WSCRIPT = bytes([0x51, 33]) + trs.PUB6 + bytes([0x51, 0xAE])
NESTED_REDEEM = b"\x00\x20" + hashlib.sha256(NESTED_WSCRIPT).digest()
# Revealed at height 2; its P2SH output is created only at height 4.
LATE_SCRIPT = bytes([0x51, 33]) + trs.PUB7 + bytes([0x51, 0xAE])

PROVEN20 = {rs.hash160(KEY_SHAPED_REDEEM), rs.hash160(NESTED_REDEEM),
            rs.hash160(LATE_SCRIPT)}
PROVEN32 = {hashlib.sha256(SIG_SHAPED_WSCRIPT).digest(),
            hashlib.sha256(NESTED_WSCRIPT).digest()}
UNPROVEN20 = {rs.hash160(trs.PUB1)}
UNPROVEN32 = {hashlib.sha256(trs.PUB3).digest()}


def proof_chain():
    """Five blocks:

        h1  outputs create the P2SH of KEY_SHAPED_REDEEM and of
            NESTED_REDEEM, and the P2WSH of SIG_SHAPED_WSCRIPT
        h2  one transaction spending all three, plus LATE_SCRIPT (no
            program yet), a P2PKH spend of PUB1 and a P2WPKH spend of
            PUB3, whose last items are candidates nothing opens
        h3  a coinbase
        h4  an output creates the P2SH of LATE_SCRIPT
        h5  a coinbase
    """
    blocks = {}
    prev = bytes(32)

    def add(height, raw_txs, txids):
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_600_000_000 + height,
                                      0x1700_0000, height, raw_txs, txids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())

    def coinbase(tag, commit_wtxids=None):
        outs = [tbw.w_output(50 * rs.SAT, tbw.P2PKH_SPK)]
        if commit_wtxids is not None:
            outs.append(tbw.w_output(
                0, tbw.w_commitment_spk(commit_wtxids, bytes(32))))
        return tbw.w_tx(
            1, [tbw.w_input(bytes(32), 0xFFFFFFFF, tag, 0xFFFFFFFF)],
            outs, 0,
            witnesses=[[bytes(32)]] if commit_wtxids is not None else None)

    cb, cbid, _ = coinbase(b"\x01p1")
    tx, txid, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xD1" * 32, 0, b"", 0xFFFFFFFF)],
        [tbw.w_output(10, _p2sh(KEY_SHAPED_REDEEM)),
         tbw.w_output(10, _p2sh(NESTED_REDEEM)),
         tbw.w_output(10, _p2wsh(SIG_SHAPED_WSCRIPT))], 0)
    add(1, [cb, tx], [cbid, txid])

    inputs = [
        (_push(KEY_SHAPED_REDEEM), []),
        (b"\x00" + _push(trs.FAKE_SIG) + _push(LATE_SCRIPT), []),
        (_push(trs.FAKE_SIG) + _push(trs.PUB1), []),
        (b"", [trs.FAKE_SIG, SIG_SHAPED_WSCRIPT]),
        (_push(NESTED_REDEEM), [trs.FAKE_SIG, NESTED_WSCRIPT]),
        (b"", [trs.FAKE_SIG, trs.PUB3]),
    ]
    tx, txid, wtxid = tbw.w_tx(
        2, [tbw.w_input(bytes([0xE0 + i]) * 32, 0, sig, 0xFFFFFFFF)
            for i, (sig, _w) in enumerate(inputs)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0,
        witnesses=[w for _sig, w in inputs])
    cb, cbid, _ = coinbase(b"\x01p2", commit_wtxids=[wtxid])
    add(2, [cb, tx], [cbid, txid])

    cb, cbid, _ = coinbase(b"\x01p3")
    add(3, [cb], [cbid])

    cb, cbid, _ = coinbase(b"\x01p4")
    tx, txid, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xD2" * 32, 0, b"", 0xFFFFFFFF)],
        [tbw.w_output(10, _p2sh(LATE_SCRIPT))], 0)
    add(4, [cb, tx], [cbid, txid])

    cb, cbid, _ = coinbase(b"\x01p5")
    add(5, [cb], [cbid])
    return blocks


def _proof_scan(tmp, name, end, archive=None):
    d = archive or os.path.join(tmp, name)
    server, url = trs.serve(proof_chain())
    try:
        ra.run_scan(url, "user:pass", end, d, batch_size=1,
                    checkpoint_every=1)
    finally:
        server.shutdown()
    return d


def _sealed_bytes(archive):
    """Every sealed file of the archive and of its proof, by category,
    with the two fingerprints: what 'the same archive' means."""
    man = ra._load_manifest(archive)
    proof = ra._load_proof(archive)
    files = {}
    for cat in ra.CAT_ORDER:
        with open(os.path.join(archive, ra._cat_file(man, cat)), "rb") as f:
            files[cat] = f.read()
    for cat in ra.PROOF_ORDER:
        with open(os.path.join(archive, ra.PROOF_DIR,
                               ra._cat_file(proof, cat)), "rb") as f:
            files[cat] = f.read()
    return files, man["fingerprint"], proof["fingerprint"]


def test_a_candidate_is_kept_exactly_when_the_chain_created_its_program(tmp):
    """The invariant, on every kind of candidate at once: the scripts are
    the candidates whose program the chain created, the proof holds the
    others, and nothing else decides. A key-shaped redeem script and a
    signature-shaped witness script are scripts; a witness script nested
    in P2SH is proven by the redeem script its spend pushes; the keys that
    ended a P2PKH and a P2WPKH spend are not scripts."""
    archive = _proof_scan(tmp, "proof_oneshot", 5)
    ra.run_merge(archive)
    s20 = archive_records(archive, "scripts20", with_height=True)
    s32 = archive_records(archive, "scripts32", with_height=True)
    check(set(s20) == PROVEN20,
          f"scripts20 must be the proven candidates: {sorted(s20)}")
    check(set(s32) == PROVEN32,
          f"scripts32 must be the proven candidates: {sorted(s32)}")
    check(set(archive_records(archive, "unproven20")) == UNPROVEN20
          and set(archive_records(archive, "unproven32")) == UNPROVEN32,
          "the proof must hold exactly the candidates nothing opens")
    check(s20[rs.hash160(LATE_SCRIPT)] == (1, 2),
          "a script is revealed when its bytes appear (height 2), not when "
          "its program does (height 4)")
    programs32 = archive_records(archive, "programs32")
    check(programs32 == {
        hashlib.sha256(SIG_SHAPED_WSCRIPT).digest(): ra.PROGRAM_OUTPUT,
        hashlib.sha256(NESTED_WSCRIPT).digest(): ra.PROGRAM_NESTED},
          f"each program says where the chain committed to it: {programs32}")
    keys = archive_records(archive, "keys")
    for pub in (trs.PUB6, trs.PUB7):
        check(rs.hash160(pub) in keys, "the keys inside a script are archived")
    man = ra._load_manifest(archive)
    check(man["build"]["unproven"] == {"scripts20": 1, "scripts32": 1},
          f"the archive says what the proof left out: {man['build']}")
    proof = ra._load_proof(archive)
    check(proof["build"]["parent"]["fingerprint"] == man["fingerprint"]
          and man["build"]["proof"]["fingerprint"] == proof["fingerprint"],
          "the archive and its proof name each other")
    ra.run_verify(archive, deep=True)
    print("ok  proof: key- and signature-shaped scripts kept, nested "
          "witness scripts proven, keys set aside, and nothing else decides")


def test_appending_promotes_a_candidate_whose_program_came_later(tmp):
    """Why the proof keeps what it has not proven. LATE_SCRIPT is revealed
    at height 2 and its program is created at 4: an archive sealed at 3
    cannot keep it, and the same archive grown to 5 must hold exactly the
    bytes of one built to 5 at once. Before the second fusion, with the
    program still in a run, every reader already sees it."""
    one = _proof_scan(tmp, "late_one", 5)
    ra.run_merge(one)

    two = _proof_scan(tmp, "late_two", 3)
    ra.run_merge(two)
    late = rs.hash160(LATE_SCRIPT)
    check(late not in archive_records(two, "scripts20")
          and late in archive_records(two, "unproven20"),
          "at 3 no program opens LATE_SCRIPT: the proof holds it")
    check(rs.hash160(trs.PUB7) in archive_records(two, "keys"),
          "the keys inside a candidate are archived whether or not it is "
          "proven")

    _proof_scan(tmp, None, 5, archive=two)
    view = ra.ArchiveView(two)
    try:
        check(view.sighting("scripts20", late) == (1, 2),
              "a program still in a run promotes the candidate for a lookup")
    finally:
        view.close()
    check(archive_records(two, "scripts20", with_height=True).get(late)
          == (1, 2), "and for a stream")

    ra.run_merge(two)
    check(_sealed_bytes(two) == _sealed_bytes(one),
          "appending in two takes did not seal the bytes of one build")
    print("ok  proof: a candidate waits in the proof and is promoted when "
          "its program appears; append == rebuild")


def test_a_fusion_killed_between_its_manifests_completes_on_the_same_bytes(
        tmp):
    """The fusion commits three writes: the archive's manifest, the
    proof's, the state. Killed after the first, the new archive stands
    beside the previous proof; killed after the second, both are new and
    the state still names the runs. Either way a scan must refuse to run
    on top, and the next merge must land on the uninterrupted bytes."""
    ref = _proof_scan(tmp, "kill_ref", 5)
    ra.run_merge(ref)
    want = _sealed_bytes(ref)
    for with_proof in (False, True):
        d = _proof_scan(tmp, f"kill_{with_proof}", 3)
        ra.run_merge(d)
        _proof_scan(tmp, None, 5, archive=d)
        clone = os.path.join(tmp, f"kill_clone_{with_proof}")
        shutil.copytree(d, clone)
        ra.run_merge(clone)
        for name in os.listdir(clone):
            if name.startswith("archive_") or name == ra.MANIFEST_NAME:
                shutil.copyfile(os.path.join(clone, name),
                                os.path.join(d, name))
        if with_proof:
            for name in os.listdir(os.path.join(clone, ra.PROOF_DIR)):
                shutil.copyfile(os.path.join(clone, ra.PROOF_DIR, name),
                                os.path.join(d, ra.PROOF_DIR, name))
        check(read_state(d)["runs"], "the fixture needs the runs still named")
        try:
            _proof_scan(tmp, None, 5, archive=d)
            fail("a scan ran on top of an interrupted fusion")
        except ra.ScanError as e:
            check("merge" in str(e), f"the refusal must name the way out: {e}")
        ra.run_merge(d)
        check(_sealed_bytes(d) == want,
              f"the completed fusion (proof committed: {with_proof}) "
              "differs from the uninterrupted one")
        ra.run_verify(d, deep=True)
    print("ok  proof: a fusion killed between its manifests completes on "
          "the same bytes, and nothing scans on top of it")


def test_an_archive_grows_only_beside_the_proof_it_was_sealed_with(tmp):
    """Without its proof an archive answers everything up to its
    watermark, and must refuse to grow: a candidate set aside at the last
    fusion would never be promoted. Beside another archive's proof it
    must refuse too."""
    d = _proof_scan(tmp, "no_proof", 3)
    ra.run_merge(d)
    other = _proof_scan(tmp, "other_proof", 2)
    ra.run_merge(other)
    saved = os.path.join(tmp, "saved_proof")
    shutil.move(os.path.join(d, ra.PROOF_DIR), saved)

    check(rs.hash160(KEY_SHAPED_REDEEM) in archive_records(d, "scripts20"),
          "a sealed archive answers without its proof")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ra.run_verify(d, deep=True)
    check("cannot grow" in out.getvalue(),
          f"verify must say what a missing proof costs: {out.getvalue()}")
    try:
        _proof_scan(tmp, None, 5, archive=d)
        fail("an archive grew without its proof")
    except ra.ScanError as e:
        check("no proof" in str(e), f"unexpected: {e}")

    shutil.copytree(os.path.join(other, ra.PROOF_DIR),
                    os.path.join(d, ra.PROOF_DIR))
    try:
        _proof_scan(tmp, None, 5, archive=d)
        fail("an archive grew beside another archive's proof")
    except ra.ScanError as e:
        check("not the one it was sealed with" in str(e), f"unexpected: {e}")

    shutil.rmtree(os.path.join(d, ra.PROOF_DIR))
    shutil.move(saved, os.path.join(d, ra.PROOF_DIR))
    _proof_scan(tmp, None, 5, archive=d)
    ra.run_merge(d)
    print("ok  proof: no proof or a foreign one refuses to grow; the "
          "archive still answers")


def test_a_received_archive_answers_and_grows_from_its_seal(tmp):
    """An archive handed over as its sealed files, its manifest and its
    proof, with no state and no runs: every reader answers from the
    manifest, and a scan grows it from the watermark and the block hash
    the manifest names, to the bytes of an archive built at once."""
    ref = _proof_scan(tmp, "recv_ref", 5)
    ra.run_merge(ref)
    built = _proof_scan(tmp, "recv_built", 3)
    ra.run_merge(built)

    received = os.path.join(tmp, "received")
    os.makedirs(received)
    for name in os.listdir(built):
        if name.startswith("archive_") or name == ra.MANIFEST_NAME:
            shutil.copyfile(os.path.join(built, name),
                            os.path.join(received, name))
    shutil.copytree(os.path.join(built, ra.PROOF_DIR),
                    os.path.join(received, ra.PROOF_DIR))

    view = ra.ArchiveView(received)
    try:
        check(view.sealed and view.watermark == 3
              and view.last_block_hash == read_state(built)["last_block_hash"],
              "the manifest stands in for the state")
        check(view.sighting("scripts20", rs.hash160(KEY_SHAPED_REDEEM))
              == (0, 2), "a received archive answers a lookup")
    finally:
        view.close()
    ra.run_lookup(received, [rs.hash160(KEY_SHAPED_REDEEM).hex()])
    ra.run_verify(received, deep=True)

    _proof_scan(tmp, None, 5, archive=received)
    ra.run_merge(received)
    check(_sealed_bytes(received) == _sealed_bytes(ref),
          "a received archive grown to 5 differs from one built to 5")
    print("ok  proof: a received archive answers from its manifest and "
          "grows from its seal")


def test_deep_verify_refuses_a_script_the_chain_never_proved(tmp):
    """The digests say the files are the ones sealed; only the deep audit
    can say the fusion kept by the rule. A candidate slipped into
    `scripts20` and RE-SEALED, with the proof's parent moved to match, is
    a wrong archive sealed faithfully: the fast road passes, the deep one
    must not."""
    d = _proof_scan(tmp, "tampered", 5)
    ra.run_merge(d)
    man = ra._load_manifest(d)
    proof = ra._load_proof(d)
    path = os.path.join(d, ra._cat_file(man, "scripts20"))
    width = ra.rec_width("scripts20")
    with open(path, "rb") as f:
        data = f.read()
    records = [data[i:i + width] for i in range(0, len(data), width)]
    records.append(rs.hash160(trs.PUB1) + b"\x00" + (2).to_bytes(3, "big"))
    with open(path, "wb") as f:
        f.write(b"".join(sorted(records)))

    rec, key_len, every = ra.LADDERS["scripts20"]
    sha, ladder = sha_and_ladder(path, rec, key_len, every, ra.ScanError)
    for entry in man["identity"]["files"]:
        if entry["name"] == "scripts20":
            entry["sha256"] = sha
    cache = man["build"]["caches"]["scripts20"]
    with open(os.path.join(d, cache["file"]), "wb") as f:
        f.write(ladder)
    cache["sha256"] = hashlib.sha256(ladder).hexdigest()
    man["build"]["files"]["scripts20"]["records"] += 1
    man["fingerprint"] = identity_fingerprint(man["identity"])
    man["statement"] = statement_digest(man)
    with open(os.path.join(d, ra.MANIFEST_NAME), "w") as f:
        json.dump(man, f)
    proof["build"]["parent"]["fingerprint"] = man["fingerprint"]
    proof["statement"] = statement_digest(proof)
    with open(os.path.join(d, ra.PROOF_DIR, ra.MANIFEST_NAME), "w") as f:
        json.dump(proof, f)

    ra.run_verify(d)
    try:
        ra.run_verify(d, deep=True)
        fail("the deep audit accepted a script no program opens")
    except ra.ScanError as e:
        check("never proved" in str(e), f"unexpected: {e}")
    print("ok  proof: the deep audit refuses a re-sealed archive holding a "
          "candidate the chain never proved")
