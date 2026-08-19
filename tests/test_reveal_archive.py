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
    always did; `with_height` asks for the whole (byte, first_height)."""
    state = read_state(archive_dir)
    manifest = ra._load_manifest(archive_dir)
    rows = ra._merged_stream(
        ra._archive_sources(archive_dir, cat, state, manifest), cat)
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

    # Candidate scripts: the real redeem/witness scripts must be
    # there; so are the over-collected candidates (PUB1/PUB3 pushed
    # last), harmless by construction — asserted to pin the behavior.
    s20 = archive_records(archive, "scripts20")
    check(set(s20) == {rs.hash160(trs.REDEEM), rs.hash160(trs.PUB1)},
          "scripts20 content differs from the crafted spends")
    s32 = archive_records(archive, "scripts32")
    check(set(s32) == {hashlib.sha256(trs.WSCRIPT).digest(),
                       hashlib.sha256(trs.PUB3).digest()},
          "scripts32 content differs from the crafted spends")
    print("ok  scan: watermark, provenance bits, exact content")
    return archive


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
    state["locks_manifest"]["p2pkh"]["records"] += 1
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
            curve = os.path.join(tmp, f"curve_{label}.csv")
            fp_der = ra.run_derive(archive, locks_dir, faces=faces,
                                   cosigners=cosigners,
                                   curve_path=curve, curve_every=2)
            check(fp_der == fp_scan,
                  f"derive ({label}): fingerprint differs from the scan")
            with open(curve) as f_a, \
                 open(os.path.join(cp, rs.CURVE_NAME)) as f_b:
                check(f_a.read() == f_b.read(),
                      f"derive ({label}): curve differs from the scan's")
        print("ok  derive: table and curve equal the scan's, "
              "on all three perimeters")

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
    rs.run_prepare(snapshot, foreign, chunk_records=3)
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
        expected = sum(entry["records"]
                       for entry in manifest["build"]["files"].values())
        check(total_fused == expected,
              f"archive curve counted {total_fused} first revelations, "
              f"the manifest holds {expected} records")

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


# The frozen reveal-archive-v2 fingerprint of the synthetic chain. Unlike the
# determinism tests (which check that two builds AGREE), this pins the absolute
# value, so a format change that alters every build identically is still
# caught. Update deliberately if the format or the fixture chain changes.
GOLDEN_ARCHIVE_FINGERPRINT = \
    "6bcd01817bdceec9f80dd275c127f6ad263e754aeaf2bb4032c06bc647997019"


def test_golden_fingerprint(archive):
    fp = ra._load_manifest(archive)["fingerprint"]
    check(fp == GOLDEN_ARCHIVE_FINGERPRINT,
          f"reveal-archive-v2 fingerprint drifted from the frozen value: {fp}")
    print("ok  golden: the synthetic archive fingerprint is unchanged")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        blocks = trs.build_chain()
        locks_dir = trs.test_prepare(tmp, base_hash_hex=blocks[4][0])
        archive = test_scan_content(tmp, blocks)
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
    tx, txid, _ = tbw.w_tx(
        2, [tbw.w_input(b"\xB1" * 32, 0, spend, 0xFFFFFFFF)],
        [tbw.w_output(10, tbw.P2PKH_SPK)], 0)
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


def test_the_form_bit_and_the_v1_projection(tmp):
    """A 65-byte sighting carries FLAG_UNCOMPRESSED and a 33-byte one
    does not; the deep audit accepts the fifth bit; and `v1-digests`
    projects the records back to the published v1 bytes, matched here
    against a mirror that re-reads the merged files raw. The masks are
    pinned HERE: a flag added without teaching the projection fails in
    this test, not in the confrontation with the sealed v1 artifact."""
    server, url = trs.serve(form_chain())
    archive = os.path.join(tmp, "form")
    try:
        ra.run_scan(url, "user:pass", 2, archive, batch_size=1,
                    checkpoint_every=1)
    finally:
        server.shutdown()

    recs = archive_records(archive, "keys")
    check(recs[rs.hash160(PUBU)] == ra.FLAG_SIG | ra.FLAG_UNCOMPRESSED,
          "the 65-byte sighting must carry the form bit")
    check(recs[rs.hash160(trs.PUB1)] == ra.FLAG_SIG,
          "a compressed sighting must not carry the form bit")

    try:
        ra.run_v1_digests(archive)
        fail("the v1 projection accepted an unfused archive")
    except rs.ScanError:
        pass

    ra.run_merge(archive)
    ra.run_verify(archive, deep=True)

    got = ra.run_v1_digests(archive)
    manifest = ra._load_manifest(archive)
    for cat in ra.CAT_ORDER:
        width = ra.CATEGORIES[cat]
        rw = ra.rec_width(cat)
        with open(os.path.join(archive, ra._cat_file(manifest, cat)),
                  "rb") as f:
            raw = f.read()
        mirror = hashlib.sha256()
        for off in range(0, len(raw), rw):
            mirror.update(raw[off:off + width])
            mirror.update(bytes((raw[off + width]
                                 & (15 if cat == "keys" else 0),)))
        check(got[cat] == mirror.hexdigest(),
              f"{cat}: the v1 projection drifted from the raw mirror")


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
    finally:
        server.shutdown()
    print("ok  scan seconds: recorded in all four artifacts, and they "
          "accumulate across a resume")
