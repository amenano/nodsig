#!/usr/bin/env python3
"""
block_stats.py — the first DERIVATIVE of the graph: per-block
statistics read out of a graph-v2 archive.

Why this exists: the graph archive (graphemit.py) is the raw material —
who pays whom, under which lock, in block order. Questions are answered
by DERIVATIVES built from it, each with its own reconstruction rule and
its own fingerprint. The design grows in WIDTH: every question is a
derivative, the graph is the source of truth, and the derivative can
be deleted and rebuilt. This is the easy one: aggregate each block's
records into a small per-block time series — transactions, edges,
tiles, value created — a single pass over the canonical stream,
no join required. It demonstrates the derivative discipline in a form
simpler than the reveal archive, and it answers a question the write-up
actually wants: how the chain's shape (transactions per block, value
moved) changes over the eras.

WHAT A ROW MEANS (and, honestly, what it does NOT)
==================================================
Per block, in ascending height:
    height              the block's height
    time                header timestamp (miner-declared, from graph-v2)
    n_tx                transactions in the block
    n_inputs            total inputs across non-coinbase txs = graph
                        EDGES (graph-v2 emits no edge for a coinbase)
    n_outputs           total outputs = graph TILES (coins created)
    value_created_sats  sum of all output values in the block

value_created is output value, NOT net issuance and NOT fees: a block's
outputs re-spend value that already existed, so this figure double-
counts money in motion by design — it is "how many satoshis were placed
into new outputs here", a movement gauge, not new supply. FEES are
deliberately absent: a fee is a JOIN (each input edge resolved against
the output tile it spends, to get value-in minus value-out), which
needs an index of every output's value — a bigger, separate derivative,
not this one-pass easy case (the honest boundary of the format).

FORMAT — block-stats-v2
=======================
The canonical form is a CSV, height-ordered, integer fields, LF line
endings, no locale: readable by any spreadsheet, `sort`, or `sqlite3
.import`, and — because it is ordered by height — already an index
(the order is the first index, and the file stays one a standard tool
can read, not a database). Its fingerprint is
sha256(b"block-stats-v2\\n" + the exact file bytes), the twin of the
graph's fingerprint and of muhash. A sidecar meta.json records the
source graph's fingerprint (when the graph has been fingerprinted), the
height covered, the row count, the reconstruction rule, and this
fingerprint — so the derivative carries its own contract of replica:
rebuild from the same graph at the same height ⇒ the same CSV, byte
for byte.

Rebuild, don't mutate: `build` reads the whole graph once and writes
the CSV fresh. At full-chain scale that is the hour-scale read of the
graph; the derivative itself is tiny (~1M blocks × a short line ≈ tens
of MB). Incremental append by height is a natural future option (the
CSV is height-ordered), left out here to keep the easy case's bug
surface at zero.

Subcommands:
    build GRAPH_DIR --out STATS.csv   read the graph, write the series,
                                      print totals + fingerprint
    summary STATS.csv [--epoch N]     read a built series back, print
                                      overall totals and per-era buckets

Standard library only; graphemit is imported for its verified canonical
reader (runs are checked against their recorded sha256 as they stream —
a derivative trusts the graph exactly as much as the graph trusted the
blocks: not at all).
"""

import argparse
import csv as csv_module
import hashlib
import json
import os
import sys

from nodsig import graphemit as ge
from nodsig.artifact import (WallClock, declared_parent, make_identity,
                             producer, seal_manifest)

FORMAT_TAG = "block-stats-v2"
META_NAME_SUFFIX = ".meta.json"

# The canonical column order. Kept as data so a written file and a read
# file cannot silently disagree, and so `summary` fails loudly on a CSV
# that is not one of ours.
COLUMNS = ("height", "time", "n_tx", "n_inputs", "n_outputs",
           "value_created_sats")

HALVING = 210_000          # blocks per epoch, the natural Bitcoin era
SATS_PER_BTC = 100_000_000


class StatsError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# build — graph-v2 → the per-block series
# ---------------------------------------------------------------------------

def block_row(rec):
    """One decoded graph-v2 block record → the six integers of a
    block-stats-v2 row. Pure aggregation, no decisions: sum what the
    block already says."""
    n_tx = len(rec["txs"])
    n_inputs = sum(len(tx["inputs"]) for tx in rec["txs"])
    n_outputs = sum(len(tx["outputs"]) for tx in rec["txs"])
    value = sum(v for tx in rec["txs"] for v, _script in tx["outputs"])
    return (rec["height"], rec["time"], n_tx, n_inputs, n_outputs, value)


def run_build(graph_dir, out_path):
    """Read the graph's canonical stream once, write block-stats-v2.

    The CSV bytes are written and digested at once: the digest is born
    with the file, never from a re-read, so it cannot drift from what is
    on disk. It is the PLAIN sha256 of the file, exactly what the
    Artifact contract says a files[].sha256 is and what `sha256sum`
    prints — the format tag is not folded in here, because the identity
    block already carries it and a digest a stranger cannot reproduce
    from the file alone would read as corruption. Atomic tmp-then-rename,
    like every other artifact here — a crash never leaves a half series
    under the final name."""
    digest = hashlib.sha256()
    header = (",".join(COLUMNS) + "\n").encode()
    digest.update(header)

    rows = 0
    covered = 0
    totals = {"n_tx": 0, "n_inputs": 0, "n_outputs": 0,
              "value_created_sats": 0}
    tmp = out_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(header)
        for rec in ge.iter_blocks(graph_dir):
            row = block_row(rec)
            line = (",".join(str(x) for x in row) + "\n").encode()
            f.write(line)
            digest.update(line)
            rows += 1
            covered = row[0]
            totals["n_tx"] += row[2]
            totals["n_inputs"] += row[3]
            totals["n_outputs"] += row[4]
            totals["value_created_sats"] += row[5]
    os.replace(tmp, out_path)
    csv_sha256 = digest.hexdigest()

    # Tie the derivative to the graph it came from, INSIDE the identity:
    # a parent that only sits beside the fingerprint is a claim, a parent
    # the fingerprint commits to is a link. A live, still-growing graph
    # has no manifest yet, so this artifact records no parent and says as
    # much: it is genuinely a weaker object, one that cannot state where
    # it came from.
    source_fp = None
    manifest_path = os.path.join(graph_dir, ge.MANIFEST_NAME)
    if os.path.exists(manifest_path):
        with open(manifest_path) as mf:
            graph_manifest = json.load(mf)
        # The same refusal the index makes at its own seal: a graph still
        # sealed by an earlier major has a fingerprint this code does not
        # compute, and declaring it under ge.FORMAT_TAG would seal an
        # ancestry claim no seal of any graph can ever confirm.
        if graph_manifest.get("format") != ge.FORMAT_TAG:
            raise StatsError(
                f"the graph is sealed as {graph_manifest.get('format')}, "
                f"not {ge.FORMAT_TAG}: its fingerprint comes from a "
                "recipe this major does not compute and cannot be named "
                "as a parent. Re-seal the graph first with "
                "`graph fingerprint --reseal` (the bytes do not change).")
        source_fp = graph_manifest.get("fingerprint")

    identity = make_identity(FORMAT_TAG, 1, covered, [("csv", csv_sha256)])
    meta = seal_manifest(FORMAT_TAG, identity, {
            "producer": producer(),
            "seconds": WallClock("build").stamp(),
            "parent": (None if source_fp is None
                       else declared_parent(ge.FORMAT_TAG, source_fp)),
            "rows": rows,
            "totals": totals,
            "csv_sha256": csv_sha256,
            "reconstruction": ("aggregate each graph block record into "
                               "one row: " + ", ".join(COLUMNS)),
    })
    meta_path = out_path + META_NAME_SUFFIX
    meta_tmp = meta_path + ".tmp"
    with open(meta_tmp, "w") as f:
        json.dump(meta, f, indent=1)
    os.replace(meta_tmp, meta_path)

    print(f"{FORMAT_TAG} written: {out_path}")
    print(f"  covers heights 1..{covered:,}  ({rows:,} blocks)")
    print(f"  transactions {totals['n_tx']:>16,}")
    print(f"  edges        {totals['n_inputs']:>16,}")
    print(f"  tiles        {totals['n_outputs']:>16,}")
    print(f"  value moved  {totals['value_created_sats'] / SATS_PER_BTC:>16,.2f} BTC")
    if source_fp is None:
        print("  source graph: not sealed, so this series records no parent "
              "and cannot attest its ancestry")
    print(f"fingerprint: {meta['fingerprint']}")
    return meta["fingerprint"]


# ---------------------------------------------------------------------------
# summary — read a built series back
# ---------------------------------------------------------------------------

def read_series(path):
    """Stream (height, time, n_tx, n_inputs, n_outputs, value) tuples
    from a block-stats-v2 CSV, failing loudly on any other columns."""
    with open(path, newline="") as f:
        reader = csv_module.reader(f)
        head = next(reader, None)
        if head != list(COLUMNS):
            raise StatsError(
                f"{path}: columns {head!r} are not block-stats-v2 "
                f"{list(COLUMNS)!r}")
        for r in reader:
            yield tuple(int(x) for x in r)


def run_summary(path, epoch_blocks, out=sys.stdout):
    """Overall totals plus per-era buckets: the shape of the chain over
    time. Buckets default to the halving epoch (210k blocks) — the
    natural Bitcoin era — but any interval works for a finer look."""
    n_blocks = 0
    busiest = (None, -1)       # (height, n_tx)
    richest = (None, -1)       # (height, value)
    grand = {"n_tx": 0, "n_inputs": 0, "n_outputs": 0, "value": 0}
    buckets = {}               # bucket index -> aggregates

    for height, _time, n_tx, n_in, n_out, value in read_series(path):
        n_blocks += 1
        grand["n_tx"] += n_tx
        grand["n_inputs"] += n_in
        grand["n_outputs"] += n_out
        grand["value"] += value
        if n_tx > busiest[1]:
            busiest = (height, n_tx)
        if value > richest[1]:
            richest = (height, value)
        b = height // epoch_blocks
        agg = buckets.setdefault(b, {"blocks": 0, "n_tx": 0, "value": 0})
        agg["blocks"] += 1
        agg["n_tx"] += n_tx
        agg["value"] += value

    if n_blocks == 0:
        print("empty series: nothing to summarize", file=out)
        return

    print(f"blocks: {n_blocks:,}", file=out)
    print(f"transactions: {grand['n_tx']:,}   "
          f"edges: {grand['n_inputs']:,}   "
          f"tiles: {grand['n_outputs']:,}", file=out)
    print(f"value moved: {grand['value'] / SATS_PER_BTC:,.2f} BTC", file=out)
    print(f"avg tx/block: {grand['n_tx'] / n_blocks:.1f}", file=out)
    print(f"busiest block: {busiest[0]:,} with {busiest[1]:,} tx", file=out)
    print(f"most value moved: block {richest[0]:,} with "
          f"{richest[1] / SATS_PER_BTC:,.2f} BTC", file=out)

    label = ("halving epoch" if epoch_blocks == HALVING
             else f"{epoch_blocks:,}-block bucket")
    print(f"\nper {label} (avg tx/block, value moved):", file=out)
    for b in sorted(buckets):
        agg = buckets[b]
        lo, hi = b * epoch_blocks, (b + 1) * epoch_blocks - 1
        avg = agg["n_tx"] / agg["blocks"]
        print(f"  {lo:>9,}–{hi:<9,}  {agg['blocks']:>7,} blk   "
              f"{avg:>8.1f} tx/blk   "
              f"{agg['value'] / SATS_PER_BTC:>16,.2f} BTC", file=out)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="per-block statistics derived from a graph-v2 archive")
    sub = p.add_subparsers(dest="cmd", required=True)

    pb = sub.add_parser("build", help="graph-v2 archive → block-stats CSV")
    pb.add_argument("graph_dir", help="a graph-v2 archive directory")
    pb.add_argument("--out", required=True, help="output CSV path")

    ps = sub.add_parser("summary", help="read a built block-stats CSV back")
    ps.add_argument("stats_csv", help="a block-stats-v2 CSV")
    ps.add_argument("--epoch", type=int, default=HALVING,
                    help="bucket size in blocks (default: halving 210000)")

    args = p.parse_args(argv)
    try:
        if args.cmd == "build":
            run_build(args.graph_dir, args.out)
        elif args.cmd == "summary":
            if args.epoch < 1:
                p.error("--epoch must be at least 1 block")
            run_summary(args.stats_csv, args.epoch)
    except (StatsError, ge.GraphError, OSError) as e:
        # A CSV that is not one of ours, an unreadable graph: expected
        # failures get the suite's one-line ERROR, not a traceback.
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
