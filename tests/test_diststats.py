#!/usr/bin/env python3
"""
test_diststats.py — self-test for diststats.py.

Small, exact fixtures with hand-computed answers: order statistics,
Gini at its two extremes, Lorenz shape, thresholds and the histogram.
No I/O, no data files.

Usage:
    python3 test_diststats.py        # prints PASS or fails loudly
"""

import sys

from nodsig import diststats as ds


def check(cond, msg):
    if not cond:
        print(f"FAIL: {msg}")
        sys.exit(1)


def test_gini():
    check(ds.gini([]) == 0.0, "gini of empty must be 0")
    check(ds.gini([5]) == 0.0, "gini of one amount must be 0")
    check(ds.gini([7, 7, 7, 7]) == 0.0, "gini of equal amounts must be 0")
    # one holder has everything: Gini approaches (n-1)/n
    n = 100
    g = ds.gini([0] * (n - 1) + [1])
    check(abs(g - (n - 1) / n) < 1e-9, f"max-inequality gini off: {g}")
    # a known intermediate case: [1,2,3,4] → Gini 0.25
    check(abs(ds.gini([1, 2, 3, 4]) - 0.25) < 1e-9,
          f"gini([1,2,3,4]) should be 0.25, got {ds.gini([1,2,3,4])}")
    print("ok  gini: extremes and a known intermediate value")


def test_percentile_and_order():
    asc = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]   # n=10
    # nearest-rank: q=0.5 -> ceil(5)=5 -> index 4 -> 50
    check(ds.percentile(asc, 0.5) == 50, "median nearest-rank")
    check(ds.percentile(asc, 0.9) == 90, "p90 nearest-rank")
    check(ds.percentile(asc, 0.99) == 100, "p99 nearest-rank")
    check(ds.percentile(asc, 0.0) == 10, "q=0 clamps to first")
    check(ds.percentile([], 0.5) == 0, "percentile of empty is 0")
    d = ds.order_stats(asc)
    check(d["count"] == 10 and d["total"] == 550, "order_stats totals")
    check(d["mean"] == 55 and d["max"] == 100, "order_stats mean/max")
    check(d["median"] == 50 and d["p90"] == 90, "order_stats percentiles")
    print("ok  percentile + order_stats on a known ramp")


def test_tails_and_top():
    asc = [1, 1, 2, 5, 10, 100]                       # total 119
    c, v = ds.tail_from(asc, 5)
    check(c == 3 and v == 115, f"tail_from(>=5): {(c, v)}")
    c, v = ds.tail_from(asc, 1000)
    check(c == 0 and v == 0, "tail above max is empty")
    check(ds.top_n(asc, 2) == (2, 110), "top_n=2 are 100+10")
    check(ds.top_n(asc, 999) == (6, 119), "top_n clamps to n")
    # top 50% of 6 = ceil(3) largest: 100+10+5 = 115
    check(ds.top_fraction(asc, 0.5) == (3, 115), "top_fraction 50%")
    print("ok  tail_from / top_n / top_fraction")


def test_lorenz():
    asc = list(range(1, 101))                          # 1..100
    pts = ds.lorenz(asc, [0.5, 0.9, 1.0])
    check(pts[-1][0] == 1.0 and abs(pts[-1][1] - 1.0) < 1e-9,
          f"lorenz must close at (1,1): {pts[-1]}")
    prev = -1.0
    for p, f in pts:
        check(f + 1e-12 >= prev and f <= 1.0 + 1e-9,
              f"lorenz not monotone/in-range at {p}: {f}")
        prev = f
    # bottom 50% (1..50) hold 1275 of 5050 → ~0.2525
    check(abs(pts[0][1] - 1275 / 5050) < 1e-9,
          f"lorenz bottom-50% share off: {pts[0][1]}")
    print("ok  lorenz: monotone, closes at (1,1), known share")


def test_histogram():
    asc = [0, 5, 15, 150, 1500]
    # edges 10,100,1000 → bands [0,10) [10,100) [100,1000) [1000,inf)
    h = ds.level_histogram(asc, [10, 100, 1000])
    check([c for c, _ in h] == [2, 1, 1, 1], f"histogram counts: {h}")
    check(sum(c for c, _ in h) == 5 and sum(v for _, v in h) == 1670,
          "histogram folds back to totals")
    print("ok  level_histogram: bands and totals")


def main():
    test_gini()
    test_percentile_and_order()
    test_tails_and_top()
    test_lorenz()
    test_histogram()
    print("PASS: diststats matches the hand-computed fixtures.")


if __name__ == "__main__":
    main()
