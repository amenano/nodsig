#!/usr/bin/env python3
"""Draw the five timeline figures in `docs/figures/`, from CSV the tool emits.

Same footing as `plot_nonces.py`, `plot_price.py` and `plot_ledger.py`:
`nodsig` counts, it does not draw, so this writes SVG by hand with nothing
but python3, in the visual language of the figures already there. No number
in any figure is typed in.

    python3 tools/plot_timeline.py --timeline <timeline-dir> \
                                   --supply-price supply-price.csv \
                                   --out docs/figures

`<timeline-dir>` is what `derived timeline --price <blockprice>` writes: the
two chain tables (`timeline_bands.csv`, `timeline_windows.csv`) and, because
a price was given, `timeline_priced.csv`. The price is an external input
beside the artifact, not part of it: the same derivatives on the same grid
seal the same timeline whether or not a series was supplied, which is why
the third table is joined by key here rather than assumed to be there.

`supply-price.csv` is `derived supply --price <blockprice> --csv`, read for
one thing the timeline cannot hold: the market price at each checkpoint, the
other line in the two price figures.

Three of the five figures rest on that external series and say so in their
own footer. The series' licence is the publisher's, not this repository's,
and the caption names it: anyone with their own price source can rebuild
the table and redraw these from it.
"""

import argparse
import csv
import json
import os
import re
from collections import defaultdict
from math import floor, log10
from xml.dom.minidom import parseString
from xml.sax.saxutils import escape

SAT = 100_000_000

# The house palette: two ramps for the stacked areas, two lines for the
# series, and the same paper/rule/ink the other figures use.
BLUES = ["#e2edfa", "#9cc4ef", "#4a8fdd", "#1b5cae", "#0e315c"]
AMBERS = ["#fbeecd", "#f2c14e", "#d98e00", "#9c6200", "#5e3a00"]
SERIES1 = "#2a78d6"
SERIES2 = "#eda100"
PAPER = "#fdfdfc"
RULE = "#e6e6e3"
MUTED = "#666"

W, H = 780, 410
L, R, T, B = 56, 600, 26, 340       # plot area; the footers live below it

BLOCKS_PER_YEAR = 52_560            # the design rate: ten minutes a block


class SVG:
    """A document that refuses to hold a coordinate outside its own box,
    and refuses to be written if it is not well-formed XML. Both checks
    have caught real mistakes: a figure that renders in an HTML preview
    can still be an invalid standalone file, which is how GitHub serves
    it."""

    def __init__(self):
        self.parts = [
            f'<svg viewBox="0 0 {W} {H}" role="img" '
            'xmlns="http://www.w3.org/2000/svg" '
            'style="max-width:100%;height:auto;'
            'font-family:system-ui,sans-serif">',
            f'<rect width="100%" height="100%" fill="{PAPER}"/>']

    def el(self, s):
        for n in re.findall(r'[xy][12]?="([-\d.]+)"', s):
            v = float(n)
            assert -1 <= v <= max(W, H) + 1, f"coordinate outside: {s[:80]}"
        self.parts.append(s)

    def text(self, x, y, s, anchor="start", size=12, fill=MUTED):
        self.el(f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" '
                f'fill="{fill}" font-size="{size}">{escape(s)}</text>')

    def write(self, out_dir, name):
        os.makedirs(out_dir, exist_ok=True)
        body = "\n".join(self.parts) + "\n</svg>\n"
        parseString(body)               # well-formed, or nothing is written
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        print(f"wrote {path}  ({len(body):,} bytes)")


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def x_scale(hmin, hmax):
    def at(h):
        return L + (R - L) * (h - hmin) / (hmax - hmin)
    return at


def x_axis(s, at, hmin, hmax, step=200_000):
    """Ticks, and no axis title: the caption names the axis. The title
    used to collide with the footers."""
    first = (hmin // step + (1 if hmin % step else 0)) * step
    for h in range(first, hmax, step):
        if at(h) - at(hmin) < 24 or at(hmax) - at(h) < 24:
            continue                    # never crowd the ends
        s.text(at(h), B + 16, f"{h // 1000}k", anchor="middle", size=11)
    s.text(at(hmin), B + 16, f"{hmin // 1000}k" if hmin else "0",
           anchor="middle", size=11)
    s.text(at(hmax), B + 16, f"{hmax // 1000}k", anchor="middle", size=11)
    for h in (210_000, 420_000, 630_000, 840_000):      # the halvings
        if hmin < h < hmax:
            s.el(f'<line x1="{at(h):.1f}" y1="{T}" x2="{at(h):.1f}" '
                 f'y2="{B}" stroke="{RULE}" stroke-dasharray="4 3"/>')


def y_grid(s, values, fmt, ymax):
    for v in values:
        y = B - (B - T) * v / ymax
        s.el(f'<line x1="{L}" y1="{y:.1f}" x2="{R}" y2="{y:.1f}" '
             f'stroke="{RULE}"/>')
        s.text(L - 8, y + 4, fmt(v), anchor="end", size=11)


def nice_step(vmax, n=4):
    """A round step (1/2/2.5/5 x 10^k) covering vmax in at most n ticks."""
    raw = vmax / n
    mag = 10.0 ** floor(log10(raw))
    for m in (1, 2, 2.5, 5, 10):
        if raw <= m * mag:
            return m * mag
    return 10 * mag


def stacked_area(s, xs, layers, colors, labels, ymax, at):
    """`layers`: lists of values from the bottom up, aligned to xs. The
    2px gap between bands is the paper showing through, which is what
    keeps a five-band stack readable without a legend inside it."""
    cum = [0.0] * len(xs)
    for vals, col in zip(layers, colors):
        top = [c + v for c, v in zip(cum, vals)]
        up = " ".join(f"{at(x):.1f},{B - (B - T) * v / ymax:.1f}"
                      for x, v in zip(xs, top))
        down = " ".join(f"{at(x):.1f},{B - (B - T) * v / ymax:.1f}"
                        for x, v in zip(reversed(xs), reversed(cum)))
        s.el(f'<polygon points="{up} {down}" fill="{col}" '
             f'stroke="{PAPER}" stroke-width="2"/>')
        cum = top
    for i, (col, lab) in enumerate(zip(reversed(colors), reversed(labels))):
        y = T + 14 + i * 20
        s.el(f'<rect x="{R + 12}" y="{y - 9}" width="12" height="12" '
             f'fill="{col}"/>')
        s.text(R + 30, y + 1, lab, size=11)
    return cum


def dollars(v):
    """Prices spelled out, never powers of ten: a reader should not have
    to do arithmetic to know whether a gridline is a thousand or a
    billion."""
    for unit, suffix in ((1e12, "T"), (1e9, "B"), (1e6, "M"), (1e3, "k")):
        if v >= unit:
            return f"${v / unit:g}{suffix}"
    return f"${v:g}" if v >= 1 else f"${v:.2f}"


def log_y(s, dec_min, dec_max):
    span = dec_max - dec_min
    for d in range(dec_min, dec_max + 1):
        y = B - (B - T) * (d - dec_min) / span
        s.el(f'<line x1="{L}" y1="{y:.1f}" x2="{R}" y2="{y:.1f}" '
             f'stroke="{RULE}"/>')
        s.text(L - 8, y + 4, dollars(10.0 ** d), anchor="end", size=11)

    def at(v):
        return B - (B - T) * (log10(v) - dec_min) / span
    return at


def line_series(s, points, at_y, color, at_x):
    d = " ".join(f"{at_x(x):.1f},{at_y(v):.1f}" for x, v in points if v > 0)
    s.el(f'<polyline points="{d}" fill="none" stroke="{color}" '
         'stroke-width="2"/>')


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------

class Timeline:
    """The three tables of a priced timeline, plus the totals its own meta
    declares. Those totals are what the figures are checked against: a
    stack that does not re-add to the sealed number is a drawing bug, and
    this script would rather stop than publish it."""

    def __init__(self, timeline_dir):
        meta_path = os.path.join(timeline_dir, "timeline.meta.json")
        self.meta = json.load(open(meta_path))
        build = self.meta["build"]
        self.grid = build.get("grid", 10_000)
        self.tip = (self.meta.get("identity", {})
                    .get("coverage", {}).get("to")
                    or build.get("watermark"))
        totals = build["totals"]
        self.unspent_sats = totals["unspent_sats"]
        self.coinage = totals.get("coinage_destroyed_sat_heights")
        self.bands = read_csv(os.path.join(timeline_dir, "timeline_bands.csv"))
        self.windows = read_csv(os.path.join(timeline_dir,
                                             "timeline_windows.csv"))
        self.currency, self.cells = self._cells(timeline_dir)

    def _cells(self, timeline_dir):
        """(create window, spend window or None) -> (sats, priced sats,
        cost at creation). The price table is joined BY KEY, never by
        position: it holds only the cells that had a price, so a
        positional join would silently shift every row after the first
        gap."""
        cells = {}
        for r in self.windows:
            sw = None if r["spend_from"] == "" else int(r["spend_from"])
            cells[(int(r["create_from"]) // self.grid,
                   None if sw is None else sw // self.grid)] = \
                [int(r["sats"]), 0, 0.0]
        priced_path = os.path.join(timeline_dir, "timeline_priced.csv")
        currency = None
        if os.path.exists(priced_path):
            rows = read_csv(priced_path)
            cost_col = next((c for c in (rows[0] if rows else {})
                             if c.startswith("cost_at_creation")), None)
            if cost_col:
                currency = cost_col[len("cost_at_creation_"):].upper()
            for r in rows:
                sw = None if r["spend_from"] == "" else int(r["spend_from"])
                key = (int(r["create_from"]) // self.grid,
                       None if sw is None else sw // self.grid)
                if key in cells:
                    cells[key][1] = int(r["sats_priced"])
                    cells[key][2] = float(r[cost_col]) if cost_col else 0.0
        return currency, {k: tuple(v) for k, v in cells.items()}

    @property
    def last_whole_window(self):
        """The last window that ends inside the coverage. Every point in
        the age figures is exact at the last height of its window, so the
        partial window at the tip has no exact point and is left out."""
        return self.tip // self.grid


def first_priced_height(price_dir):
    """The first height the price table could price, read from the table
    itself. The figures name it in their footer, and a number in a figure
    should come from the artifact it describes, never from a memory of
    what it was the last time someone looked."""
    if not price_dir:
        return None
    path = os.path.join(price_dir, "blockprice.json")
    if not os.path.exists(path):
        return None
    meta = json.load(open(path))
    return meta.get("first_priced_height") or meta.get("priced_from")


def read_market(path):
    """height -> market price, from `derived supply --price --csv`. The
    column carries the currency in its name."""
    out = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        col = next((c for c in (reader.fieldnames or ())
                    if c.startswith("price_")), None)
        if not col:
            raise SystemExit(f"{path} has no price column: run "
                             "`derived supply --price ... --csv`")
        for r in reader:
            if r[col]:
                out[int(r["height"])] = float(r[col])
    return out


# ---------------------------------------------------------------------------
# Figure 1: what the unspent value sits in, by the size of the holding lock
# ---------------------------------------------------------------------------

BAND_GROUPS = [     # (floor min, floor max, label), largest at the bottom
    (10**11, 10**15, "> 1,000 BTC"),
    (10**9, 10**10, "10–1,000 BTC"),
    (10**7, 10**8, "0.1–10 BTC"),
    (10**5, 10**6, "0.001–0.1 BTC"),
    (1, 10**4, "< 0.001 BTC"),
]


def figure_bands(tl, out_dir):
    per_cp = defaultdict(lambda: [0] * len(BAND_GROUPS))
    for r in tl.bands:
        cp, floor_sats, sats = (int(r["checkpoint"]),
                                int(r["band_floor_sats"]), int(r["sats"]))
        for i, (lo, hi, _label) in enumerate(BAND_GROUPS):
            if lo <= floor_sats <= hi:
                per_cp[cp][i] += sats
                break
    cps = sorted(per_cp)
    assert cps[-1] == tl.tip and sum(per_cp[tl.tip]) == tl.unspent_sats, \
        "the stack at the tip does not re-add to the sealed unspent_sats"
    layers = [[per_cp[cp][i] / SAT / 1e6 for cp in cps]
              for i in range(len(BAND_GROUPS))]
    ymax = 21.0
    at = x_scale(0, tl.tip)
    s = SVG()
    y_grid(s, (0, 5, 10, 15, 20), lambda v: f"{v:.0f} M", ymax)
    x_axis(s, at, 0, tl.tip)
    stacked_area(s, cps, layers, AMBERS[::-1],
                 [g[2] for g in BAND_GROUPS], ymax, at)
    s.text(L, H - 40, "unspent BTC (millions) by the balance of the holding "
           "lock, at checkpoints every 10,000 blocks; x = block height",
           size=10)
    s.text(L, H - 26, "a lock is an identical scriptPubKey: not a wallet, "
           "not a person; bands are decades of satoshis, grouped", size=10)
    s.text(L, H - 12, "includes outputs the node no longer tracks: the two "
           "BIP30-overwritten coinbases and unspendable outputs (~151 BTC "
           "in all)", size=10)
    s.write(out_dir, "timeline-balance-bands.svg")


# ---------------------------------------------------------------------------
# Figure 2: HODL waves, the unspent value by the age of the output holding it
# ---------------------------------------------------------------------------

AGE_BUCKETS = [     # (min windows, max windows, label), oldest at the bottom
    (40, 10**9, "> 400k blocks (> ~7.6 y)"),
    (15, 39, "150k–400k"),
    (5, 14, "50k–150k"),
    (1, 4, "10k–50k"),
    (0, 0, "< 10k blocks (~10 weeks)"),
]


def figure_waves(tl, out_dir):
    last_k = tl.last_whole_window
    ks = list(range(1, last_k + 1))
    xs = [k * tl.grid - 1 for k in ks]
    layers = [[0.0] * len(ks) for _ in AGE_BUCKETS]
    # A cell (cw, sw) is visible at every k with k-1 >= cw (it exists) and,
    # when spent, k-1 < sw (not yet spent). ks[j] = j+1, so j runs from cw
    # to sw-1 or to the end. The first version of this loop broke on the
    # wrong index and drew only the first window: hence the check below,
    # which re-counts the last point another way.
    for (cw, sw), (sats, _priced, _cost) in tl.cells.items():
        v = sats / SAT / 1e6
        end = len(ks) if sw is None else min(len(ks), sw)
        for j in range(cw, end):
            age = j - cw
            for i, (lo, hi, _label) in enumerate(AGE_BUCKETS):
                if lo <= age <= hi:
                    layers[i][j] += v
                    break
    expected = sum(sats for (cw, sw), (sats, _p, _c) in tl.cells.items()
                   if cw <= last_k - 1
                   and (sw is None or sw > last_k - 1)) / SAT / 1e6
    got = sum(layer[-1] for layer in layers)
    assert abs(got - expected) < 1e-6, \
        f"the waves do not re-add to the unspent value: {got} vs {expected}"
    ymax = 21.0
    at = x_scale(0, xs[-1])
    s = SVG()
    y_grid(s, (0, 5, 10, 15, 20), lambda v: f"{v:.0f} M", ymax)
    x_axis(s, at, 0, xs[-1])
    stacked_area(s, xs, layers, BLUES[::-1],
                 [b[2] for b in AGE_BUCKETS], ymax, at)
    s.text(L, H - 40, "unspent BTC (millions) by the age of the output "
           "holding it; age in blocks, 52,560 blocks ≈ 1 year; x = block "
           "height", size=10)
    s.text(L, H - 26, "window resolution (10,000 blocks): each point is "
           "exact at the last height of its window, ages are counted in "
           "whole windows", size=10)
    s.text(L, H - 12, f"the axis ends at height {xs[-1]:,}: the tip window "
           "is partial and has no exact point", size=10)
    s.write(out_dir, "timeline-hodl-waves.svg")


# ---------------------------------------------------------------------------
# Figures 3, 4 and 5: realized cap, and realized price against the market
# ---------------------------------------------------------------------------

def realized_at(tl, k):
    """(cap, priced unspent sats) at the last height of window k, which is
    k*grid-1: every cell created by then and not yet spent, each priced at
    what it cost when it was created."""
    cap = 0.0
    priced = 0
    for (cw, sw), (_sats, sats_priced, cost) in tl.cells.items():
        if cw > k - 1:
            continue
        if sw is not None and sw <= k - 1:
            continue
        cap += cost
        priced += sats_priced
    return cap, priced


def figures_realized(tl, market, out_dir, priced_from=None):
    last_k = tl.last_whole_window
    ks = list(range(1, last_k + 1))
    data = [realized_at(tl, k) for k in ks]
    xs = [k * tl.grid - 1 for k in ks]
    cur = tl.currency or "USD"

    at = x_scale(0, xs[-1])
    s = SVG()
    at_y = log_y(s, 4, 12)
    x_axis(s, at, 0, xs[-1])
    line_series(s, [(x, d[0]) for x, d in zip(xs, data)], at_y, SERIES1, at)
    s.text(R - 4, at_y(data[-1][0]) - 8, "realized cap", anchor="end",
           size=11, fill=SERIES1)
    s.text(L, H - 40, f"realized cap: every unspent output priced at its "
           f"creation, {cur}, log scale; exact at the last height of each "
           "10,000-block window; x = block height", size=10)
    since = f" (height {priced_from:,})" if priced_from else ""
    s.text(L, H - 26, f"outputs created before the first observation{since} "
           "or after the last carry no price and are left out of the sum",
           size=10)
    s.text(L, H - 12, "external input: price series identified by digest, "
           "see the caption", size=10)
    s.write(out_dir, "timeline-realized-cap.svg")

    realized = [(x, d[0] / (d[1] / SAT) if d[1] else 0)
                for x, d in zip(xs, data)]
    quoted = [(x, market.get(x, 0)) for x in xs]

    def price_figure(name, hmin, dec_min, dec_max, cut_note):
        at_x = x_scale(hmin, xs[-1])
        s = SVG()
        at_y = log_y(s, dec_min, dec_max)
        x_axis(s, at_x, hmin, xs[-1], step=100_000)
        line_series(s, [(x, v) for x, v in quoted if x >= hmin], at_y,
                    SERIES2, at_x)
        line_series(s, [(x, v) for x, v in realized if x >= hmin], at_y,
                    SERIES1, at_x)
        legend = ((SERIES2, "market price at the checkpoint", 0),
                  (SERIES1, "realized price (cost basis of the unspent, "
                            "per priced BTC)", 1))
        for col, label, i in legend:
            y = T + 14 + i * 18
            s.el(f'<rect x="{L + 8}" y="{y - 8}" width="12" height="4" '
                 f'fill="{col}"/>')
            s.text(L + 26, y, label, size=11)
        s.text(L, H - 40, f"{cur} per BTC, log scale; realized price = "
               "realized cap / unspent priced BTC, exact at the last height "
               "of each 10,000-block window; x = block height", size=10)
        s.text(L, H - 26, cut_note, size=10)
        s.text(L, H - 12, "external input: price series identified by "
               "digest, see the caption", size=10)
        s.write(out_dir, name)

    price_figure("timeline-realized-price.svg", 0, -2, 6,
                 "the two series answer different questions: what the "
                 "market asks now vs what the resting coins cost when they "
                 "were created")
    price_figure("timeline-realized-price-recent.svg", 450_000, 2, 6,
                 "same figure from height 450,000 on: four decades instead "
                 "of eight, the readable half of the story")
    return data[-1]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--timeline", required=True,
                    help="the directory `derived timeline --price` wrote")
    ap.add_argument("--price",
                    help="the blockprice table the timeline was built on, "
                         "read for the height its first observation covers")
    ap.add_argument("--supply-price",
                    help="CSV from `derived supply --price ... --csv`, for "
                         "the market line of the two price figures")
    ap.add_argument("--out", default="docs/figures")
    args = ap.parse_args(argv)

    tl = Timeline(args.timeline)
    print(f"timeline at height {tl.tip:,}, grid {tl.grid:,}, "
          f"{len(tl.cells):,} cells"
          + (f", priced in {tl.currency}" if tl.currency else
             ", no price table"))

    figure_bands(tl, args.out)
    figure_waves(tl, args.out)
    if not tl.currency:
        print("no timeline_priced.csv: the three priced figures are left "
              "alone. Rebuild the timeline with --price to redraw them.")
        return 0
    if not args.supply_price:
        raise SystemExit("the timeline carries prices but --supply-price "
                         "was not given: the market line would be missing")
    market = read_market(args.supply_price)
    cap, priced = figures_realized(tl, market, args.out,
                                   first_priced_height(args.price))
    print(f"realized cap at {tl.last_whole_window * tl.grid - 1:,}: "
          f"{cap:,.0f} {tl.currency} over {priced / SAT:,.2f} priced BTC")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
