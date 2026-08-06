#!/usr/bin/env python3
"""
test_block_stats.py — self-test for block_stats.py. No node, no real
chain: the shared synthetic chain is emitted into a real graph-v2
archive, and the derivative is checked against aggregates computed
INDEPENDENTLY from the parsed blocks.

Two roads meet, as everywhere here: block_stats reads the graph stream
and aggregates; the test aggregates the parsed reference blocks by
hand. They must agree row for row. On top of that:

- the fingerprint is deterministic and born-with-the-file (a rebuild
  lands on the same hex string and the same bytes);
- meta.json carries the contract of replica: watermark, rows, and the
  source graph fingerprint once the graph is sealed (None before);
- summary reads the CSV back, totals match, buckets partition cleanly;
- a CSV that is not block-stats-v2 is refused.

Usage:
    python3 test_block_stats.py    # prints PASS or fails loudly
"""

import hashlib
import io
import json
import os
import sys
import tempfile

from nodsig import blockparse as bp
from nodsig import block_stats as bs
from nodsig import graphemit as ge
from nodsig import reveal_archive as ra
import test_graphemit as tge
import test_reuse_scan as trs


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


def build_graph(tmp):
    """Emit the shared 4-block chain into a real graph-v2 archive."""
    server, url = trs.serve(trs.build_chain())
    graph = os.path.join(tmp, "graph")
    try:
        ra.run_scan(url, "user:pass", 4,
                    os.path.join(tmp, "archive_host"),
                    batch_size=2, checkpoint_every=2, graph_dir=graph)
    finally:
        server.shutdown()
    return graph


def expected_rows(blocks):
    """The block-stats-v2 rows computed straight from the parsed blocks
    — the independent road. graph-v2 emits no edge for a coinbase, so
    the edge count excludes coinbase inputs; tiles and value count all
    outputs."""
    ref = tge.parsed_chain(blocks)
    rows = []
    for h in sorted(ref):
        block = ref[h]
        n_tx = len(block.transactions)
        n_in = sum(len(t.inputs) for t in block.transactions
                   if not bp.is_coinbase(t))
        n_out = sum(len(t.outputs) for t in block.transactions)
        value = sum(o.value for t in block.transactions
                    for o in t.outputs)
        rows.append((h, block.header.time, n_tx, n_in, n_out, value))
    return rows


def test_build_matches_parsed(tmp, blocks, graph):
    out = os.path.join(tmp, "stats.csv")
    bs.run_build(graph, out)
    got = list(bs.read_series(out))
    want = expected_rows(blocks)
    check(got == want, f"per-block rows differ:\n got {got}\n want {want}")

    meta = json.load(open(out + bs.META_NAME_SUFFIX))
    check(meta["identity"]["coverage"]["to"] == 4, "meta watermark wrong")
    check(meta["build"]["rows"] == len(want), "meta row count wrong")
    check(meta["build"]["parent"] is None,
          "unsealed graph must be recorded as unknown source")
    # totals in meta must equal the sum of the rows we verified
    check(meta["build"]["totals"]["n_tx"] == sum(r[2] for r in want),
          "meta n_tx total wrong")
    check(meta["build"]["totals"]["value_created_sats"] == sum(r[5] for r in want),
          "meta value total wrong")
    print("ok  build: rows == independently parsed aggregates, meta exact")
    return out


def test_fingerprint_deterministic(tmp, graph):
    a = os.path.join(tmp, "a.csv")
    b = os.path.join(tmp, "b.csv")
    fa = bs.run_build(graph, a)
    fb = bs.run_build(graph, b)
    check(fa == fb, "rebuild produced a different fingerprint")
    check(open(a, "rb").read() == open(b, "rb").read(),
          "rebuild produced different bytes")
    # the recorded fingerprint must match the file it describes
    meta = json.load(open(a + bs.META_NAME_SUFFIX))
    check(meta["fingerprint"] == fa, "meta fingerprint != printed one")
    print("ok  fingerprint: rebuild is byte-identical and self-consistent")


def test_meta_carries_sealed_graph(tmp, graph):
    """Once the graph is fingerprinted, the derivative records which
    graph it came from — the contract of replica made concrete."""
    graph_fp = ge.run_fingerprint(graph)
    out = os.path.join(tmp, "sealed.csv")
    bs.run_build(graph, out)
    meta = json.load(open(out + bs.META_NAME_SUFFIX))
    check(meta["build"]["parent"]["fingerprint"] == graph_fp,
          "sealed graph fingerprint not carried into the derivative")
    check(meta["build"]["parent"]["format"] == ge.FORMAT_TAG,
          "the parent must name its format, not only its fingerprint")
    check("parent" not in meta["identity"],
          "the parent must not reach the identity: two derivatives of the "
          "same graph bytes have to take the same name")
    print("ok  ancestry: sealed graph's fingerprint carried in meta")


def test_the_recorded_digest_is_the_files_own_sha256(tmp, graph):
    """The Artifact contract says a files[].sha256 is the content digest
    of the named file, and every other artifact seals exactly that. So
    `sha256sum` on the CSV must agree with the manifest — a digest
    seeded with anything else would read as corruption to whoever
    audits the file by the shared recipe, and would give byte-identical
    CSVs two different numbers across re-implementations."""
    out = os.path.join(tmp, "digest.csv")
    bs.run_build(graph, out)
    meta = json.load(open(out + bs.META_NAME_SUFFIX))
    plain = hashlib.sha256(open(out, "rb").read()).hexdigest()
    check(meta["identity"]["files"] == [{"name": "csv", "sha256": plain}],
          f"identity files {meta['identity']['files']}, expected the "
          f"plain sha256 {plain}")
    check(meta["build"]["csv_sha256"] == plain,
          "build.csv_sha256 is not the plain digest of the file")
    print("ok  digest: the sealed sha256 is the one sha256sum prints")


def test_a_graph_sealed_by_an_earlier_major_is_refused_as_parent(tmp,
                                                                 graph):
    """graphemit reads a graph-v1 emission on purpose, so one can reach
    this builder — but its seal cannot become the parent: that
    fingerprint comes from a recipe this major does not compute, and
    declaring it under the v2 tag would publish an ancestry claim no
    seal of any graph can ever confirm. The index already refuses this
    at its own seal; the derivative must too."""
    with open(os.path.join(graph, ge.MANIFEST_NAME), "w") as f:
        json.dump({"format": "graph-v1", "fingerprint": "ab" * 32}, f)
    try:
        bs.run_build(graph, os.path.join(tmp, "v1parent.csv"))
        fail("a graph-v1 seal was adopted as a graph-v2 parent")
    except bs.StatsError as e:
        check("--reseal" in str(e), f"v1 seal refused as: {e}")
    print("ok  ancestry: a seal from an earlier major is refused, with "
          "the way out named")


def test_summary(tmp, blocks, out_csv):
    want = expected_rows(blocks)
    buf = io.StringIO()
    bs.run_summary(out_csv, epoch_blocks=2, out=buf)
    text = buf.getvalue()
    check(f"blocks: {len(want)}" in text, "summary block count wrong")
    check(f"transactions: {sum(r[2] for r in want)}" in text,
          "summary tx total wrong")
    busiest = max(want, key=lambda r: r[2])
    check(f"busiest block: {busiest[0]}" in text,
          "summary busiest block wrong")
    # epoch=2 over heights 1..4 → buckets {0:h1, 1:h2,h3, 2:h4}: 3 lines
    bucket_lines = [l for l in text.splitlines() if "tx/blk" in l]
    check(len(bucket_lines) == 3,
          f"expected 3 epoch buckets, got {len(bucket_lines)}")
    print("ok  summary: totals, busiest block and buckets all check out")


def test_rejects_foreign_csv(tmp):
    bad = os.path.join(tmp, "bad.csv")
    with open(bad, "w") as f:
        f.write("height,foo\n1,2\n")
    try:
        list(bs.read_series(bad))
    except bs.StatsError:
        print("ok  guard: a non block-stats-v2 CSV is refused")
        return
    fail("read_series accepted a foreign CSV")


def main():
    blocks = trs.build_chain()
    with tempfile.TemporaryDirectory() as tmp:
        graph = build_graph(tmp)
        out = test_build_matches_parsed(tmp, blocks, graph)
        test_fingerprint_deterministic(tmp, graph)
        test_the_recorded_digest_is_the_files_own_sha256(tmp, graph)
        test_summary(tmp, blocks, out)
        test_rejects_foreign_csv(tmp)
        # do these last: they write the graph manifest, changing later
        # builds (and the second leaves a v1 seal behind on purpose)
        test_meta_carries_sealed_graph(tmp, graph)
        test_a_graph_sealed_by_an_earlier_major_is_refused_as_parent(
            tmp, graph)
    print("PASS: the per-block derivative equals the independently "
          "parsed chain, rebuilds byte-identically, and carries its "
          "contract of replica.")


if __name__ == "__main__":
    main()
