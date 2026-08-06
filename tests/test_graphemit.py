#!/usr/bin/env python3
"""
test_graphemit.py — self-test for graphemit.py, no node and no real
data needed.

The cast is the usual one: the synthetic four-block chain and the fake
JSON-RPC server of test_reuse_scan.py, so the graph is emitted through
the REAL host path (the --graph plug of both scanners), not through a
shortcut.

What is exercised:

- the compactsize writer against the independent mirror of
  test_blockparse.py, on every width boundary;
- emission content: the records decoded back must say exactly what
  blockparse says about the same raw blocks — heights, hashes, times,
  txids, the coinbase flag (and its zero input records), every edge
  (prev_txid, prev_vout), every tile (value, scriptPubKey);
- host independence, both directions: the host's own fingerprint must
  not move when --graph is on (the emitter only observes), and the
  graph emitted by reuse_scan must be byte-identical to the one
  emitted by reveal_archive (the emitter does not care who hosts it);
- determinism: an interrupted-and-resumed emission (tiny flushes, many
  runs) must fingerprint — and concatenate — byte-identical to the
  one-shot one: run boundaries are not data;
- the crash window: a graph checkpointed AHEAD of the host's state
  (the one ordering the design allows) must heal on load by dropping
  the suffix runs, and still end byte-identical;
- refusals: a graph directory that cannot line up with the scan's
  resume point is refused; a flipped byte in a run aborts the
  fingerprint; a run file the state does not name is removed on load;
- `show` and `stats`, as a user would drive them (smoke);
- --graph-digest, the plug that measures instead of writing: a rescan
  of the same chain agrees with the archive it did not write, interval
  by interval, and its whole-stream digest is the one `fingerprint`
  computes; one changed byte in the records is caught and localised; a
  restart costs the straddled interval and nothing else, and the
  heights it could not speak for are named rather than dropped.

Usage:
    python3 test_graphemit.py    # prints PASS or fails loudly
"""

import json
import os
import sys
import tempfile

from nodsig import blockparse as bp
from nodsig import graphemit as ge
from nodsig import reuse_scan as rs
from nodsig import reveal_archive as ra
import test_blockparse as tbw
import test_reuse_scan as trs


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


def canonical_bytes(graph_dir):
    """The archive's canonical form, as the fingerprint sees it: every
    run's bytes, in height order — the test's own reader."""
    state = ge._load_state(graph_dir)
    return b"".join(b"".join(ge._run_bytes(graph_dir, run))
                    for run in state["runs"])


def parsed_chain(blocks):
    """height → parsed Block, straight from the raw hex the fake
    server serves: the reference the decoded records are held to."""
    return {h: bp.parse_block(bytes.fromhex(raw))
            for h, (_, raw) in blocks.items()}


# ---------------------------------------------------------------------------
# compactsize writer vs the independent mirror
# ---------------------------------------------------------------------------

def test_compactsize():
    for n in (0, 1, 252, 253, 65_535, 65_536, 2**32 - 1, 2**32,
              2**64 - 1):
        check(ge.write_compactsize(n) == tbw.w_compactsize(n),
              f"compactsize writer differs from the mirror at {n}")
        # And the production READER (blockparse) must round-trip it.
        value, pos = bp.read_compactsize(ge.write_compactsize(n), 0)
        check(value == n and pos == len(ge.write_compactsize(n)),
              f"compactsize round-trip failed at {n}")
    print("ok  compactsize: writer == mirror, round-trips")


# ---------------------------------------------------------------------------
# emission through the real host path + content
# ---------------------------------------------------------------------------

def test_emission_content(tmp, blocks):
    server, url = trs.serve(blocks)
    graph = os.path.join(tmp, "graph_a")
    try:
        ra.run_scan(url, "user:pass", 4,
                    os.path.join(tmp, "archive_host_a"),
                    batch_size=2, checkpoint_every=2, graph_dir=graph)
    finally:
        server.shutdown()

    reference = parsed_chain(blocks)
    heights = []
    for rec in ge.iter_blocks(graph):
        h = rec["height"]
        heights.append(h)
        block = reference[h]
        check(rec["hash"] == block.header.hash, f"h{h}: block hash")
        check(rec["time"] == block.header.time, f"h{h}: time")
        check(len(rec["txs"]) == len(block.transactions), f"h{h}: n_tx")
        for got, tx in zip(rec["txs"], block.transactions):
            check(got["txid"] == tx.txid, f"h{h}: txid")
            check(got["coinbase"] == bp.is_coinbase(tx),
                  f"h{h}: coinbase flag")
            if got["coinbase"]:
                check(got["inputs"] == [],
                      f"h{h}: coinbase must emit no edge")
            else:
                check(got["inputs"] == [(i.prev_txid, i.prev_vout)
                                        for i in tx.inputs],
                      f"h{h}: input edges")
            check(got["outputs"] == [(o.value, o.script_pubkey)
                                     for o in tx.outputs],
                  f"h{h}: output tiles")
    check(heights == [1, 2, 3, 4], "heights emitted out of order or missing")

    state = ge._load_state(graph)
    check(state["last_height"] == 4, "graph watermark is not the end height")
    totals = {k: sum(r[k] for r in state["runs"])
              for k in ("blocks", "transactions", "inputs", "outputs")}
    want = {"blocks": 4,
            "transactions": sum(len(b.transactions)
                                for b in reference.values()),
            "inputs": sum(1 for b in reference.values()
                          for t in b.transactions if not bp.is_coinbase(t)
                          for _ in t.inputs),
            "outputs": sum(len(t.outputs) for b in reference.values()
                           for t in b.transactions)}
    check(totals == want, f"per-run totals {totals} != {want}")
    print("ok  emission: decoded records == parsed blocks, exact totals")
    return graph


# ---------------------------------------------------------------------------
# host independence, both directions
# ---------------------------------------------------------------------------

def test_host_independence(tmp, blocks, locks_dir, graph_from_ra):
    # The reuse fingerprint must not move when the emitter rides along.
    server, url = trs.serve(blocks)
    try:
        fp_plain = rs.run_scan(locks_dir, url, "user:pass", 4,
                               os.path.join(tmp, "cp_plain"),
                               batch_size=2, checkpoint_every=2)
        graph_from_rs = os.path.join(tmp, "graph_rs")
        fp_graph = rs.run_scan(locks_dir, url, "user:pass", 4,
                               os.path.join(tmp, "cp_graph"),
                               batch_size=2, checkpoint_every=2,
                               graph_dir=graph_from_rs)
    finally:
        server.shutdown()
    check(fp_plain == fp_graph,
          "--graph changed the host's fingerprint: the emitter must "
          "only observe")

    # And the graph must not care who hosted it.
    check(canonical_bytes(graph_from_rs) == canonical_bytes(graph_from_ra),
          "graph emitted via reuse_scan differs from the one via "
          "reveal_archive")
    check(ge.run_fingerprint(graph_from_rs)
          == ge.run_fingerprint(graph_from_ra),
          "fingerprints differ between hosts")
    print("ok  hosts: fingerprint untouched by --graph; both hosts emit "
          "the identical graph")


# ---------------------------------------------------------------------------
# determinism: interrupted+resumed == one-shot, byte for byte
# ---------------------------------------------------------------------------

def test_determinism(tmp, blocks, graph_oneshot):
    graph_b = os.path.join(tmp, "graph_b")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 2, os.path.join(tmp, "host_b"),
                    batch_size=2, checkpoint_every=2, graph_dir=graph_b)
        ra.run_scan(url, "user:pass", 4, os.path.join(tmp, "host_b"),
                    batch_size=2, checkpoint_every=2, graph_dir=graph_b)
    finally:
        server.shutdown()
    state = ge._load_state(graph_b)
    check(len(state["runs"]) > 1,
          "test did not force multiple runs: nothing was exercised")
    check(canonical_bytes(graph_b) == canonical_bytes(graph_oneshot),
          "interrupted+resumed graph differs from the one-shot graph")
    check(ge.run_fingerprint(graph_b) == ge.run_fingerprint(graph_oneshot),
          "fingerprints differ between interrupted and one-shot")
    print("ok  determinism: two takes == one shot, byte for byte "
          f"({len(state['runs'])} runs vs "
          f"{len(ge._load_state(graph_oneshot)['runs'])})")


# ---------------------------------------------------------------------------
# the crash window: graph ahead of the host, healed on load
# ---------------------------------------------------------------------------

def test_crash_window(tmp, blocks, graph_oneshot):
    reference = parsed_chain(blocks)
    graph = os.path.join(tmp, "graph_crash")

    # The graph checkpoints at 2 (host about to write its state at 2)…
    em = ge.GraphEmitter(graph, flush_bytes=1)
    em.load(1)
    em.add_block(1, reference[1])
    em.checkpoint(1, blocks[1][0])
    em.add_block(2, reference[2])
    em.checkpoint(2, blocks[2][0])
    # …and the crash lands before the host does: on restart the host
    # resumes from ITS last state, height 1, so it feeds from 2 again.
    em = ge.GraphEmitter(graph, flush_bytes=1)
    em.load(2)                     # must drop the run(s) covering 2
    check(em.watermark == 1, "ahead runs not dropped down to the "
                             "host's resume point")
    em.add_block(2, reference[2])
    em.add_block(3, reference[3])
    em.add_block(4, reference[4])
    em.checkpoint(4, blocks[4][0])
    check(canonical_bytes(graph) == canonical_bytes(graph_oneshot),
          "healed crash-window graph differs from the one-shot graph")
    print("ok  crash window: ahead runs dropped, re-emission lands on "
          "the identical bytes")


# ---------------------------------------------------------------------------
# refusals
# ---------------------------------------------------------------------------

def test_refusals(tmp, blocks, graph_oneshot):
    # A fresh directory cannot serve a scan resuming past height 1
    # (the missed blocks would never come back)…
    try:
        em = ge.GraphEmitter(os.path.join(tmp, "graph_fresh"))
        em.load(3)
        fail("fresh graph dir accepted a mid-chain resume")
    except ge.GraphError:
        pass
    # …and neither can an archive BEHIND the resume point, for the
    # same reason: being behind is the one misalignment that cannot
    # heal (ahead heals by dropping, see test_crash_window).
    reference = parsed_chain(blocks)
    behind = os.path.join(tmp, "graph_behind")
    em = ge.GraphEmitter(behind)
    em.load(1)
    em.add_block(1, reference[1])
    em.checkpoint(1, blocks[1][0])
    try:
        em = ge.GraphEmitter(behind)
        em.load(3)
        fail("archive behind the resume point accepted (gap)")
    except ge.GraphError:
        pass
    print("ok  refusals: fresh-dir mid-resume and a gap are refused")

    # A run file the state does not name is a crash leftover: removed.
    stale = os.path.join(graph_oneshot, ge.RUNS_DIR, "run_zz_stale.bin")
    with open(stale, "wb") as f:
        f.write(b"junk")
    em = ge.GraphEmitter(graph_oneshot)
    em.load(5)                     # aligned: watermark 4, resume 5
    check(not os.path.exists(stale), "stale run survived load()")
    print("ok  hygiene: stale run files are removed on load")

    # One flipped byte in a run must abort the fingerprint.
    graph = os.path.join(tmp, "graph_corrupt")
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, os.path.join(tmp, "host_c"),
                    batch_size=2, checkpoint_every=2, graph_dir=graph)
    finally:
        server.shutdown()
    victim = os.path.join(graph, ge.RUNS_DIR,
                          ge._load_state(graph)["runs"][0]["name"])
    data = bytearray(open(victim, "rb").read())
    data[0] ^= 0xFF
    with open(victim, "wb") as f:
        f.write(data)
    try:
        ge.run_fingerprint(graph)
        fail("corrupted run accepted by fingerprint")
    except ge.GraphError:
        print("ok  corruption: a flipped byte in a run aborts the "
              "fingerprint")


def test_cli_readers(graph):
    """stats and show, as a user would drive them (must not raise)."""
    ge.run_stats(graph)
    ge.run_show(graph, 1, 2)
    print("ok  stats/show: smoke")


# ---------------------------------------------------------------------------
# --graph-digest: the same plug, measuring instead of writing
# ---------------------------------------------------------------------------

def _digest_scan(tmp, blocks, reference, name, end=4, resume_at=None):
    """Run the digest plug through the real host path. With `resume_at`
    the scan is stopped there and re-run, which is how an interruption
    is reproduced without killing a process."""
    host = os.path.join(tmp, name)
    server, url = trs.serve(blocks)
    try:
        if resume_at:
            ra.run_scan(url, "user:pass", resume_at, host, batch_size=2,
                        checkpoint_every=2, graph_digest_dir=reference)
        ra.run_scan(url, "user:pass", end, host, batch_size=2,
                    checkpoint_every=2, graph_digest_dir=reference)
    finally:
        server.shutdown()
    return host


def test_digest_agrees(tmp, blocks, graph_oneshot):
    """The digest of a rescan must match the archive that rescan did
    not write — and it must reach that result interval by interval,
    against the per-run digests the reference already recorded."""
    host = _digest_scan(tmp, blocks, graph_oneshot, "digest_host")
    state = ge._load_state(graph_oneshot)
    with open(os.path.join(host, ge.DIGEST_STATE_NAME)) as f:
        got = json.load(f)

    check(len(got["intervals"]) == len(state["runs"]),
          f"digest checked {len(got['intervals'])} intervals, the "
          f"reference has {len(state['runs'])} runs: the check must "
          "close where the reference closed")
    check(all(r["ok"] for r in got["intervals"]),
          "a rescan of the same chain disagreed with the graph it did "
          "not write")
    check(not got["skipped"] and not got["beyond"],
          "an uninterrupted scan to the reference's watermark left "
          "something unverified")
    check(ge.read_digest_report(host) is True,
          "report said the check failed when every interval matched")

    # This file lives inside an artifact directory, and an artifact is a
    # thing people hand each other: nothing in it may name the disk it
    # was built on. The reference is identified by what it holds, not by
    # where it sat.
    blob = json.dumps(got)
    for path in (graph_oneshot, host, tmp, os.path.expanduser("~")):
        check(path not in blob,
              f"the digest state names a local path: {path}")

    # The whole-stream digest of an uninterrupted pass is the number
    # `fingerprint` computes, which is what makes the check comparable
    # with a published one rather than only with itself. It has to
    # survive in the state file: a three-day run must not keep its one
    # citable number only on a terminal that scrolled away.
    expected, _ = ge.stream_digest(graph_oneshot)
    check(got["contiguous"], "an uninterrupted pass reported itself "
                             "as resumed")
    check(got["stream_sha256"] == expected,
          "the whole-stream digest is not the one `fingerprint` computes")
    print(f"ok  digest: {len(got['intervals'])} intervals matched the "
          "reference, whole-stream digest == fingerprint's")
    return host


def test_digest_host_independence(tmp, blocks, locks_dir, graph_oneshot):
    """The measuring plug does not care who hosts it either: the other
    scanner has to reach the same result over the same chain."""
    cp = os.path.join(tmp, "cp_digest")
    server, url = trs.serve(blocks)
    try:
        rs.run_scan(locks_dir, url, "user:pass", 4, cp, batch_size=2,
                    checkpoint_every=2, graph_digest_dir=graph_oneshot)
    finally:
        server.shutdown()
    with open(os.path.join(cp, ge.DIGEST_STATE_NAME)) as f:
        got = json.load(f)
    expected, _ = ge.stream_digest(graph_oneshot)
    check(all(r["ok"] for r in got["intervals"]) and got["intervals"],
          "the digest hosted by reuse_scan disagreed with the reference")
    check(got["stream_sha256"] == expected,
          "the two hosts measured different streams")
    print("ok  digest: both scanners reach the same result")


def test_digest_catches_a_change(tmp, blocks, graph_oneshot):
    """The point of the check: if the emitter's bytes move, it says so,
    and it names the interval rather than one number for the chain."""
    original = ge.serialize_block_record

    def altered(height, block):
        rec = bytearray(original(height, block))
        rec[-1] ^= 0xFF            # one byte of the last scriptPubKey
        return bytes(rec)

    ge.serialize_block_record = altered
    try:
        host = _digest_scan(tmp, blocks, graph_oneshot, "digest_bad")
    finally:
        ge.serialize_block_record = original
    with open(os.path.join(host, ge.DIGEST_STATE_NAME)) as f:
        got = json.load(f)
    bad = [r for r in got["intervals"] if not r["ok"]]
    check(bad, "the digest accepted records that are not the reference's")
    check(ge.read_digest_report(host) is False,
          "report called a mismatched check ok")
    print(f"ok  digest: a changed byte is caught, in "
          f"{len(bad)}/{len(got['intervals'])} intervals")


def test_digest_resume(tmp, blocks, graph_oneshot):
    """An interruption costs the straddled interval and nothing else:
    the check continues at the next boundary and says which heights it
    could not speak for.

    The reference is built by hand with wide runs, because the fixtures
    flush every 64 bytes: with one run per block every restart lands on
    a boundary and the straddling path is never reached. Runs 1..3 and
    4..4, a restart at 3, so one interval is lost and the other still
    has to verify.
    """
    reference = os.path.join(tmp, "graph_wide")
    parsed = parsed_chain(blocks)
    em = ge.GraphEmitter(reference, flush_bytes=10**9)
    em.load(1)
    for h in (1, 2, 3):
        em.add_block(h, parsed[h])
    em.checkpoint(3, blocks[3][0])
    em.add_block(4, parsed[4])
    em.checkpoint(4, blocks[4][0])
    check([(r["start"], r["end"]) for r in ge._load_state(reference)["runs"]]
          == [(1, 3), (4, 4)], "the hand-built reference is not two wide runs")

    host = _digest_scan(tmp, blocks, reference, "digest_resume",
                        resume_at=2)
    with open(os.path.join(host, ge.DIGEST_STATE_NAME)) as f:
        got = json.load(f)
    check(all(r["ok"] for r in got["intervals"]),
          "a resumed digest reported a mismatch on the same chain")
    check(not got["contiguous"],
          "a resumed pass still claims a whole-stream digest, which "
          "sha256 cannot give it")
    covered = {h for r in got["intervals"]
               for h in range(r["start"], r["end"] + 1)}
    unverified = {h for s in got["skipped"]
                  for h in range(s[0], s[1] + 1)}
    check(covered & unverified == set(),
          "an interval was reported both verified and skipped")
    check(covered | unverified == set(range(1, 5)),
          f"heights {set(range(1, 5)) - covered - unverified} are in "
          "neither column: the check lost track of them silently")
    check(unverified and covered,
          "the test proved nothing: the restart neither cost an "
          "interval nor left one to verify")
    check(got["stream_sha256"] is None,
          "a resumed pass published a whole-stream digest anyway")
    print(f"ok  digest: a restart costs {len(unverified)} height(s), "
          f"named, and the other {len(covered)} still verify")


def test_digest_refusals(tmp, blocks, graph_oneshot):
    # A digest measures the stream from 1; it cannot join one midway.
    try:
        ge.GraphDigest(graph_oneshot, os.path.join(tmp)).load(3)
        fail("a digest accepted a start past height 1 with no state")
    except ge.GraphError:
        pass
    # Writing the graph and measuring it are one question asked twice.
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, os.path.join(tmp, "host_both"),
                    batch_size=2, checkpoint_every=2,
                    graph_dir=os.path.join(tmp, "graph_both"),
                    graph_digest_dir=graph_oneshot)
        fail("--graph and --graph-digest accepted together")
    except ge.GraphError:
        pass
    finally:
        server.shutdown()
    print("ok  digest refusals: no mid-stream start, no --graph with "
          "--graph-digest")


# ---------------------------------------------------------------------------
# an emission sealed by an earlier major: readable, but not a parent
# ---------------------------------------------------------------------------

def test_earlier_major(tmp, blocks, graph_oneshot):
    """The v1 → v2 break moved the seal and not the stream, so a v1
    emission still has to be readable — and re-sealing it must not
    destroy the number it was published under."""
    import shutil
    from nodsig import outpoint_index as oi

    old = os.path.join(tmp, "graph_v1")
    shutil.copytree(graph_oneshot, old)
    state = ge._load_state(old)
    v1_fingerprint = "0" * 64
    with open(os.path.join(old, ge.STATE_NAME), "w") as f:
        json.dump({**state, "format": "graph-v1"}, f)
    ge.atomic_json(os.path.join(old, ge.MANIFEST_NAME),
                   {"format": "graph-v1", "covered_through": 4,
                    "fingerprint": v1_fingerprint})

    # Readable: the stream is the stream.
    check(len(list(ge.iter_blocks(old))) == 4,
          "a v1 emission did not decode with today's reader")
    check(ge.stream_digest(old)[0] == ge.stream_digest(graph_oneshot)[0],
          "the same bytes digested differently under the two tags")

    # Not re-sealed silently…
    try:
        ge.run_fingerprint(old)
        fail("an earlier major's seal was superseded without asking")
    except ge.GraphError:
        pass
    # …not grown while the state still wears the old label — but the
    # refusal must name the way out, not call a readable major unknown…
    try:
        ge.GraphEmitter(old).load(5)
        fail("the emitter grew an archive still labelled graph-v1")
    except ge.GraphError as e:
        check("--reseal" in str(e), f"v1 state refused as: {e}")
    # …and when asked, the superseded seal survives beside the new one.
    fp = ge.run_fingerprint(old, reseal=True)
    kept = os.path.join(old, "manifest.graph-v1.json")
    check(os.path.exists(kept), "the superseded manifest was destroyed")
    with open(kept) as f:
        check(json.load(f)["fingerprint"] == v1_fingerprint,
              "the kept manifest is not the one that was superseded")
    check(fp == ge.run_fingerprint(graph_oneshot),
          "re-sealing produced a different identity for the same bytes")

    # The reseal makes the archive current in EVERY respect: the state
    # label travels with the new seal, so the emitter now agrees to grow
    # the very archive the reseal just certified — the append run the
    # whole exercise exists for.
    check(ge._load_state(old)["format"] == ge.FORMAT_TAG,
          "reseal left the state labelled graph-v1")
    ge.GraphEmitter(old).load(5)
    print("ok  earlier major: readable, re-seal is asked for, old seal "
          "kept, and the resealed archive can grow again")

    # An index must refuse a parent it cannot rederive.
    unsealed = os.path.join(tmp, "graph_v1_unsealed")
    shutil.copytree(graph_oneshot, unsealed)
    ge.atomic_json(os.path.join(unsealed, ge.MANIFEST_NAME),
                   {"format": "graph-v1", "covered_through": 4,
                    "fingerprint": v1_fingerprint})
    try:
        oi.run_build(unsealed, os.path.join(tmp, "index_v1"))
        fail("an index adopted a parent fingerprint from another recipe")
    except oi.OutpointError:
        print("ok  earlier major: an index refuses it as a parent")


def main():
    test_compactsize()
    # Tiny flushes everywhere: every temporary directory below ends up
    # with several small runs, so the multi-run paths (tiling checks,
    # canonical stream across boundaries) are what gets exercised.
    original = ge.GraphEmitter.__init__

    def tiny_init(self, graph_dir, flush_bytes=64):
        original(self, graph_dir, flush_bytes=flush_bytes)

    ge.GraphEmitter.__init__ = tiny_init
    try:
        with tempfile.TemporaryDirectory() as tmp:
            locks_dir = trs.test_prepare(tmp)
            blocks = trs.build_chain()
            graph = test_emission_content(tmp, blocks)
            test_host_independence(tmp, blocks, locks_dir, graph)
            test_determinism(tmp, blocks, graph)
            test_crash_window(tmp, blocks, graph)
            test_refusals(tmp, blocks, graph)
            test_cli_readers(graph)
            test_digest_agrees(tmp, blocks, graph)
            test_digest_host_independence(tmp, blocks, locks_dir, graph)
            test_digest_catches_a_change(tmp, blocks, graph)
            test_digest_resume(tmp, blocks, graph)
            test_digest_refusals(tmp, blocks, graph)
            test_earlier_major(tmp, blocks, graph)
    finally:
        ge.GraphEmitter.__init__ = original
    print("PASS: the co-emitted graph says exactly what the blocks say, "
          "whoever hosts it, however often it is interrupted.")


if __name__ == "__main__":
    main()
