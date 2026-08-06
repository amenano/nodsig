#!/usr/bin/env python3
"""
diststats.py — distribution statistics over a list of non-negative
integer amounts.

Shared by the tools that ask the same question — "how is a quantity
spread out?" — so the numbers mean the same thing everywhere:

  - reuse_scan.py `stats`: value across the exposed locks (satoshis);
  - reveal_archive.py: the same, bucketed by reveal epoch (windowed);
  - curve_deltas.py: how lumpy the reuse curve is across intervals
    (satoshi deltas, or lock-count deltas).

Contract, deliberately narrow so it composes cleanly:

  - every function takes `asc`, an ASCENDING-sorted sequence of
    NON-NEGATIVE ints (sort once at the call site, reuse everywhere);
  - returns are in the SAME unit as the input (satoshis in, satoshis
    out) — the caller renders BTC or whatever the unit is;
  - no I/O, stdlib only, no notion of "money": it is pure arithmetic
    on a multiset of amounts, which is why three different tools can
    lean on it without dragging each other in.

Non-negativity matters: the Gini coefficient and the Lorenz curve are
only defined for it, and every caller here feeds counts or satoshi
totals, which cannot be negative.
"""

import math


def gini(asc):
    """Gini coefficient of an ascending-sorted list of amounts.

    0 = perfect equality (every amount equal), approaching 1 = one
    holder has everything. Computed with the order-statistics form,
    exact in integer arithmetic until the final division:

        G = Σ_i (2i − n − 1) · x_i / (n · Σ x),   i = 1..n, x ascending

    Undefined for fewer than two amounts or a zero sum → returns 0.0,
    the "no measurable inequality" reading.
    """
    n = len(asc)
    total = sum(asc)
    if n < 2 or total == 0:
        return 0.0
    weighted = sum((2 * i - n - 1) * x for i, x in enumerate(asc, 1))
    return weighted / (n * total)


def percentile(asc, q):
    """The q-quantile (0..1) by the nearest-rank method, clamped.

    Nearest-rank (not interpolated) on purpose: the result is always an
    actual amount from the data, which is what "the median lock holds X"
    should mean. Returns 0 on an empty input.
    """
    n = len(asc)
    if n == 0:
        return 0
    return asc[min(n - 1, max(0, math.ceil(q * n) - 1))]


def order_stats(asc):
    """The usual bundle from an ascending-sorted list: count, total,
    mean (integer, floor), median, p90, p99, max, and the Gini. Keys are
    unit-agnostic; the caller labels them (satoshis, BTC, locks)."""
    n = len(asc)
    total = sum(asc)
    return {
        "count": n,
        "total": total,
        "mean": total // n if n else 0,
        "median": percentile(asc, 0.5),
        "p90": percentile(asc, 0.9),
        "p99": percentile(asc, 0.99),
        "max": asc[-1] if n else 0,
        "gini": gini(asc),
    }


def lower_bound(asc, cut):
    """First index in ascending `asc` whose value is >= cut (bisect)."""
    lo, hi = 0, len(asc)
    while lo < hi:
        mid = (lo + hi) // 2
        if asc[mid] < cut:
            lo = mid + 1
        else:
            hi = mid
    return lo


def tail_from(asc, cut):
    """(count, sum) of the amounts >= cut. The tail is a suffix of the
    sorted list, so one binary search then a slice-sum."""
    i = lower_bound(asc, cut)
    return len(asc) - i, sum(asc[i:])


def top_fraction(asc, frac):
    """(count, sum) of the top `frac` (0..1) of amounts by size."""
    n = len(asc)
    if n == 0:
        return 0, 0
    k = max(1, math.ceil(frac * n))
    return k, sum(asc[n - k:])


def top_n(asc, k):
    """(count, sum) of the `k` largest amounts (k clamped to n)."""
    n = len(asc)
    k = min(k, n)
    if k == 0:
        return 0, 0
    return k, sum(asc[n - k:])


def lorenz(asc, pop_fractions):
    """Lorenz points [[p, value_fraction], …]: the share of the total
    held by the bottom p of amounts, for each requested population
    fraction p. One ascending pass; its scalar summary is the Gini."""
    n = len(asc)
    total = sum(asc)
    if n == 0 or total == 0:
        return [[p, 0.0] for p in pop_fractions]
    want = {p: max(1, min(n, round(p * n))) for p in pop_fractions}
    targets = sorted(set(want.values()))
    frac_at, cum, ti = {}, 0, 0
    for i, x in enumerate(asc, 1):
        cum += x
        while ti < len(targets) and targets[ti] == i:
            frac_at[targets[ti]] = cum / total
            ti += 1
    return [[p, frac_at[want[p]]] for p in pop_fractions]


def level_histogram(asc, edges):
    """[[count, sum], …] over the bands cut by `edges` (an ASCENDING
    list of amounts): [0, e0), [e0, e1), …, [e_last, ∞). One row per
    band — len(edges)+1 of them. This is a treemap's data. The caller
    owns the labels and the unit of `edges`."""
    cuts = [0] + [lower_bound(asc, e) for e in edges] + [len(asc)]
    return [[b - a, sum(asc[a:b])] for a, b in zip(cuts, cuts[1:])]
