#!/usr/bin/env python3
"""
curve_deltas.py — turn the reuse scan's cumulative curve into a TIME
SERIES of newly revealed reuse, per height interval and per lock type.

Why this exists: reuse_scan.py appends one row to `curve.csv` at every
checkpoint — cumulative hits and satoshis for each of the four
behind-a-hash lock types, plus the canonical fingerprint at that
height. Each row is a publishable lower bound (the curve IS the
published result), but the cumulative shape hides the story over time.
The DIFFERENCES between consecutive rows tell it: how much reuse was
REVEALED in each slice of chain history. Because the scanner counts at
the revelation, not at the lock's first appearance, each delta reads
as behaviour: "during these blocks, keys guarding this much value
were exposed".

Two curves, two stories — keep them apart when reading the output:
  - delta HITS  (locks newly revealed): diffuse behaviour, how many
    locks the habit of reuse burned in that slice;
  - delta SATOSHIS: economic exposure, stepwise and whale-dominated —
    a single custody sweep can dwarf years of retail reuse.

One honest caveat, worth repeating wherever these numbers are shown:
a delta says WHEN keys were exposed, not how much value still sits
behind exposed keys today (coins revealed long ago may have moved on).
The behavioural question ("are people reusing less?") reads on this
series; the present-day exposure question reads on the scan's final
totals. They are different numbers on purpose.

This tool is read-only, stdlib-only, and deliberately does NOT map
heights to calendar dates: the curve knows heights, the block header
times live in the graph archive (graph-v2). A date column would smuggle
in a second data source; the join belongs to a later, declared step.

Robustness note (why heights are deduplicated keeping the LAST row):
the scanner writes the curve row and then saves its checkpoint state.
A kill landing between the two leaves a row whose height the resumed
run will reach — and append — again. Same height, recomputed numbers,
later row wins: "last pass wins", the same rule stats_data.json uses.

Usage:
    python3 curve_deltas.py CURVE.csv                # summary to stdout
    python3 curve_deltas.py CURVE.csv --csv OUT.csv  # deltas as CSV too

The input is a snapshot copy of curve.csv if the scan is still running
(the file is append-only, so copying it mid-run is safe).
"""

import argparse
import csv
import sys


class CurveError(RuntimeError):
    """A CSV that is not a reuse-scan curve, or one whose cumulative
    counters go backwards. Raised rather than exited on: read_curve and
    deltas are readers other code can call, and a reader that kills the
    process is not one."""

# Distribution statistics shared with reuse_scan/reveal_archive: here we
# use the Gini and the top-N shares to say how lumpy the curve is.
from nodsig import diststats as ds

# The four behind-a-hash lock types, in the scanner's own column order.
# Kept as data, not discovered from the header: a curve.csv with other
# columns is a different format and should fail loudly, not be guessed.
TYPE_ORDER = ("p2pkh", "p2sh", "p2wpkh", "p2wsh")

SATS_PER_BTC = 100_000_000


def read_curve(path):
    """Read curve.csv into a list of rows sorted by height.

    Returns [(height, {type: (hits, satoshis)}), ...] with duplicate
    heights collapsed to the LAST occurrence (see robustness note in
    the module docstring). The fingerprint column is ignored here: it
    certifies the bitmaps, it plays no role in the arithmetic.
    """
    expected = ["height"] + [f"{t}_{f}" for t in TYPE_ORDER
                             for f in ("hits", "satoshis")] + ["fingerprint"]
    by_height = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != expected:
            raise CurveError(
                f"unexpected curve columns {reader.fieldnames!r}; "
                f"this tool understands exactly {expected!r}")
        for row in reader:
            h = int(row["height"])
            by_height[h] = {t: (int(row[f"{t}_hits"]),
                                int(row[f"{t}_satoshis"]))
                            for t in TYPE_ORDER}
    return sorted(by_height.items())


def deltas(rows):
    """Differences between consecutive checkpoints.

    Yields (h_from, h_to, {type: (d_hits, d_sats)}) where the interval
    covers blocks h_from+1 .. h_to. The first row has no predecessor:
    its cumulative values ARE its delta (blocks start_height .. h), and
    h_from is reported as 0 for want of a better anchor — callers that
    resumed a scan mid-chain should read the first interval knowing it
    absorbs everything before the first checkpoint.

    Cumulative counters never decrease (a hit bitmap only gains bits),
    so negative deltas mean a malformed or hand-edited curve: fail.
    """
    prev_h, prev = 0, {t: (0, 0) for t in TYPE_ORDER}
    for h, cur in rows:
        d = {}
        for t in TYPE_ORDER:
            # Not `ds`: that name is the diststats module at the top of
            # this file, and shadowing it here would arm a trap for the
            # next function that needs it in this scope.
            d_hits = cur[t][0] - prev[t][0]
            d_sats = cur[t][1] - prev[t][1]
            if d_hits < 0 or d_sats < 0:
                raise CurveError(
                    f"cumulative counter decreased for {t} at height {h}: "
                    "curve rows are not from one monotone scan")
            d[t] = (d_hits, d_sats)
        yield prev_h, h, d
        prev_h, prev = h, cur


def totals(d):
    """Sum a delta dict across types → (hits, satoshis)."""
    return (sum(v[0] for v in d.values()), sum(v[1] for v in d.values()))


def write_csv(intervals, out):
    """Write the delta table: one row per interval, columns per type."""
    w = csv.writer(out)
    w.writerow(["from_height", "to_height"]
               + [f"{t}_d{f}" for t in TYPE_ORDER for f in ("hits", "sats")]
               + ["total_dhits", "total_dsats"])
    for h0, h1, d in intervals:
        th, ts = totals(d)
        w.writerow([h0, h1]
                   + [d[t][i] for t in TYPE_ORDER for i in (0, 1)]
                   + [th, ts])


def summarize(intervals, top, out):
    """Human summary: the whole series, then the loudest intervals.

    The two rankings are printed separately (by locks, by BTC) because
    they answer different questions — see the module docstring. BTC
    figures are printed with the "≥" the scan's own claim carries: every
    number is a lower bound at a declared perimeter.
    """
    if not intervals:
        print("empty curve: nothing to summarize", file=out)
        return
    th = sum(totals(d)[0] for _, _, d in intervals)
    ts = sum(totals(d)[1] for _, _, d in intervals)
    h_last = intervals[-1][1]
    print(f"checkpoints: {len(intervals)}  span: ..{h_last:,}", file=out)
    print(f"cumulative:  reuse >= {ts / SATS_PER_BTC:,.2f} BTC "
          f"({th:,} locks)", file=out)
    by_type = {t: (sum(d[t][0] for _, _, d in intervals),
                   sum(d[t][1] for _, _, d in intervals))
               for t in TYPE_ORDER}
    for t in TYPE_ORDER:
        hh, ss = by_type[t]
        print(f"  {t:7s} {hh:>12,} locks   "
              f">= {ss / SATS_PER_BTC:>16,.2f} BTC", file=out)

    def show(title, key):
        print(f"\ntop {top} intervals {title}:", file=out)
        ranked = sorted(intervals, key=key, reverse=True)[:top]
        for h0, h1, d in ranked:
            hh, ss = totals(d)
            print(f"  {h0:>9,} → {h1:>9,}   {hh:>10,} locks   "
                  f">= {ss / SATS_PER_BTC:>14,.2f} BTC", file=out)

    show("by newly revealed locks (diffuse behaviour)",
         lambda x: totals(x[2])[0])
    show("by newly revealed BTC (whale steps)",
         lambda x: totals(x[2])[1])


def concentration(intervals, tops=(5, 20), out=sys.stdout):
    """How LUMPY the curve is across intervals — SKETCH (workstream C).

    The reuse curve does not rise smoothly: a few intervals (custody
    sweeps, migrations) carry most of the newly revealed value. This
    puts a number on that, generalizing the hand-picked "top-5 = a
    third, top-20 = three quarters" into a measured Gini of the
    per-interval deltas plus the cumulative share the largest intervals
    carry. Two series, two readings (module docstring): BTC deltas are
    whale-dominated, lock-count deltas are diffuse behaviour.

    Caveat unchanged: a delta says WHEN keys were exposed, so this
    measures the lumpiness of the TIMELINE of revelation, not of the
    present-day exposure. TODO(presentation): pick the final headline
    (Gini vs a single "top-N carries X%") once the real curve is in;
    the interval width (10k blocks) is the unit here and should be
    stated wherever the number is shown.
    """
    if not intervals:
        return
    sats = sorted(totals(d)[1] for _, _, d in intervals)
    hits = sorted(totals(d)[0] for _, _, d in intervals)
    tot_s, tot_h = sum(sats) or 1, sum(hits) or 1
    print(f"\nconcentration across {len(intervals)} intervals "
          "(how lumpy the timeline of revelation is):", file=out)
    print(f"  Gini   BTC deltas {ds.gini(sats):.3f}    "
          f"lock deltas {ds.gini(hits):.3f}", file=out)
    for k in tops:
        if k > len(intervals):
            continue
        _, vs = ds.top_n(sats, k)
        _, vh = ds.top_n(hits, k)
        print(f"  top {k:>2} intervals carry {100 * vs / tot_s:5.1f}% of "
              f"revealed BTC, {100 * vh / tot_h:5.1f}% of revealed locks",
              file=out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="per-interval deltas of the reuse scan curve")
    ap.add_argument("curve", help="path to curve.csv (or a copy of it)")
    ap.add_argument("--csv", metavar="OUT",
                    help="also write the full delta table as CSV")
    ap.add_argument("--top", type=int, default=5,
                    help="rows in each ranking (default 5)")
    args = ap.parse_args(argv)

    try:
        intervals = list(deltas(read_curve(args.curve)))
    except (CurveError, OSError) as e:
        sys.exit(f"ERROR: {e}")
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            write_csv(intervals, f)
        print(f"delta table written: {args.csv}\n", file=sys.stderr)
    summarize(intervals, args.top, sys.stdout)
    concentration(intervals, out=sys.stdout)


if __name__ == "__main__":
    main()
