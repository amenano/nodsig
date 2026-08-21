#!/usr/bin/env python3
"""Draw the two price figures in `docs/figures/`, from CSV the tool emits.

Same footing as `plot_nonces.py`: `nodsig` counts, it does not draw, so
this writes SVG by hand with nothing but python3, in the visual language
of the figures already there. No number in either figure is typed in.

    python3 tools/plot_price.py --supply supply-price.csv \
                                --blockprice <blockprice> --out docs/figures

`supply-price.csv` is what `derived supply --price <blockprice> --csv`
writes: one row per height with the block's price and its fees in the
series' currency. `<blockprice>` is the table itself (`blockprice.bin`,
documented in docs/formats/BlockPrice-v1.md), read here for one thing
the CSV does not carry: WHICH series answered at each height, so the
figure can show where the daily series hands over to the hourly one.

Everything drawn rests on external inputs (the price series), so the
script also prints the series' publishers, licenses and digests, and the
figures name them. A figure built on a publisher's data is published
under that publisher's terms, not this repository's license.
"""

import argparse
import csv
import html
import json
import math
import os
from decimal import Decimal

INK = "#1a1a1a"
MUTED = "#666"
RULE = "#e6e6e3"
PAPER = "#fdfdfc"
HUES = ["#2a78d6", "#008300", "#eda100", "#e87ba4", "#8a8a8a"]
FONT = "font-family:system-ui,sans-serif"

HALVING = 210_000
PERIOD = 2_016            # one difficulty period: the x resolution


def _esc(s):
    return html.escape(str(s), quote=True)


def _svg(width, height, body):
    return (f'<svg viewBox="0 0 {width} {height}" role="img" '
            f'xmlns="http://www.w3.org/2000/svg" '
            f'style="max-width:100%;height:auto;{FONT}">\n'
            f'<rect width="100%" height="100%" fill="{PAPER}"/>\n'
            + body + "</svg>\n")


def _text(x, y, s, size=12, fill=MUTED, anchor="start", weight=None):
    w = f' font-weight="{weight}"' if weight else ""
    return (f'<text x="{x}" y="{y}" text-anchor="{anchor}" fill="{fill}" '
            f'font-size="{size}"{w}>{_esc(s)}</text>\n')


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------

def read_supply(path):
    """-> list of (height, fees_sats, price or None, fees_fiat or None)."""
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        col = [c for c in reader.fieldnames if c.startswith("price_")]
        if not col:
            raise SystemExit("this CSV has no price column: run "
                             "`derived supply --price ... --csv`")
        pcol = col[0]
        fcol = "fees_" + pcol[len("price_"):]
        currency = pcol[len("price_"):].upper()
        for r in reader:
            price = Decimal(r[pcol]) if r[pcol] else None
            fiat = Decimal(r[fcol]) if r[fcol] else None
            rows.append((int(r["height"]), int(r["fees_sats"]), price, fiat))
    return rows, currency


def read_blockprice(bp_dir):
    """The series byte per height (index h-1) and the table's metadata."""
    with open(os.path.join(bp_dir, "blockprice.json")) as f:
        meta = json.load(f)
    with open(os.path.join(bp_dir, meta["file"]), "rb") as f:
        data = f.read()
    series = [data[i * 9 + 8] for i in range(len(data) // 9)]
    return series, meta


# ---------------------------------------------------------------------------
# Figure 1: the price on the chain's own clock
# ---------------------------------------------------------------------------

def price_figure(rows, series, meta, currency):
    """One point per difficulty period: the mean of the priced blocks'
    prices, on a log scale, against HEIGHT. The x-axis is the point:
    the chain's clock is the height, the header time is only how a
    price was attached to it. The halvings are drawn because they are
    heights, not dates; the era before the first observation is shaded,
    because no price is invented there; and the hue says which series
    answered, because that is a fact about the input and not the chain."""
    n = len(rows)
    pts = []
    for start in range(0, n, PERIOD):
        chunk = rows[start:start + PERIOD]
        priced = [(h, p) for h, _f, p, _ in chunk if p is not None]
        if not priced:
            continue
        mean = sum(p for _h, p in priced) / len(priced)
        ks = [series[h - 1] for h, _p in priced]
        k = max(set(ks), key=ks.count)
        pts.append((chunk[0][0], float(mean), k))
    first_priced = next(h for h, _f, p, _ in rows if p is not None)

    left, right, top, base = 64, 744, 60, 350
    width, height = right + 36, base + 86
    x_of = lambda h: left + (right - left) * h / n
    lo, hi = 0.01, max(p for _h, p, _k in pts) * 1.3
    y_of = lambda p: base - (base - top) * (math.log10(p) - math.log10(lo)) \
        / (math.log10(hi) - math.log10(lo))

    names = [s["publisher"] for s in meta["parents"]["series"]]
    body = _text(left - 40, 30, f"The price of a block, in {currency}, "
                 "over the whole chain", size=14, fill=INK, weight="600")
    body += _text(left - 40, 46,
                  f"one point per {PERIOD:,} blocks (a difficulty period): "
                  "the mean of the priced blocks' prices; log scale",
                  size=11)
    # grid: one line per decade, up to the last one under the top
    d = lo
    while d <= hi:
        y = y_of(d)
        body += (f'<line x1="{left}" y1="{y:.1f}" x2="{right}" '
                 f'y2="{y:.1f}" stroke="{RULE}"/>\n')
        label = f"{d:,.0f}" if d >= 1 else f"{d:g}"
        body += _text(left - 8, y + 4, label, size=11, anchor="end")
        d *= 10
    # the era without a price
    body += (f'<rect x="{left}" y="{top}" width="{x_of(first_priced) - left:.1f}" '
             f'height="{base - top}" fill="{RULE}" opacity="0.6"/>\n')
    body += _text(x_of(first_priced) + 6, top + 14,
                  f"no price before height {first_priced:,}", size=10)
    # the halvings
    h = HALVING
    while h < n:
        x = x_of(h)
        body += (f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{base}" '
                 f'stroke="{MUTED}" stroke-dasharray="3 4"/>\n')
        body += _text(x, base + 30, f"{h // 1000:,}k", size=10,
                      anchor="middle")
        h += HALVING
    body += _text(left, base + 30, "height 1", size=10)
    body += _text(right, base + 30, f"{n:,}", size=10, anchor="end")
    body += _text((left + right) / 2, base + 46,
                  "height; the dashed lines are the halvings", size=11,
                  anchor="middle")
    # the points, by series
    for h0, p, k in pts:
        body += (f'<circle cx="{x_of(h0):.1f}" cy="{y_of(p):.1f}" r="1.8" '
                 f'fill="{HUES[(k - 1) % len(HUES)]}"/>\n')
    # legend
    x = left
    for k, name in enumerate(names, 1):
        s = meta["parents"]["series"][k - 1]
        body += (f'<rect x="{x}" y="{base + 58}" width="10" height="10" '
                 f'fill="{HUES[(k - 1) % len(HUES)]}"/>\n')
        label = f"{name} (step {s['step'] // 3600} h)" if s["step"] >= 3600 \
            else f"{name} (step {s['step']} s)"
        body += _text(x + 14, base + 67, label, size=11)
        x += 14 + 7 * len(label) + 24
    body += _text(left, base + 82,
                  "external input: price series identified by digest, "
                  "see the caption", size=10)
    return _svg(width, height, body)


# ---------------------------------------------------------------------------
# Figure 2: the fees of each epoch, in BTC and in the currency
# ---------------------------------------------------------------------------

def epochs(rows):
    """Per halving epoch: blocks, priced blocks, fees in sats, fees in
    the currency (over the priced blocks), and the two ways of getting
    a fiat total, which is the measurement behind the figure."""
    out = {}
    for h, fee, price, fiat in rows:
        e = out.setdefault(h // HALVING, {"blocks": 0, "priced": 0,
                                          "fees": 0, "fees_priced": 0,
                                          "fiat": Decimal(0),
                                          "price_sum": Decimal(0)})
        e["blocks"] += 1
        e["fees"] += fee
        if price is not None:
            e["priced"] += 1
            e["fees_priced"] += fee
            e["fiat"] += fiat
            e["price_sum"] += price
    for e in out.values():
        if e["priced"]:
            mean_price = e["price_sum"] / e["priced"]
            e["fiat_by_mean"] = Decimal(e["fees_priced"]) * mean_price \
                / Decimal(10 ** 8)
        else:
            e["fiat_by_mean"] = None
    return out


def fees_figure(per_epoch, currency):
    """Two panels, one bar per epoch: fees in BTC on the left, the same
    fees in the currency on the right, each computed block by block. The
    shapes differ, and that difference is the whole reason to price per
    block: the epoch that paid the most coins is not the one that paid
    the most money."""
    keys = sorted(per_epoch)
    panel_w, gap, left, top, base = 330, 60, 64, 70, 300
    width = left + 2 * panel_w + gap + 30
    body = _text(left - 40, 30, "What each halving epoch paid in fees",
                 size=14, fill=INK, weight="600")
    body += _text(left - 40, 46, "the same blocks, the same fees, in "
                  f"two units; {currency} computed block by block, then "
                  "summed", size=11)

    def panel(x0, title, values, fmt):
        b = _text(x0, top - 10, title, size=12, fill=INK, weight="600")
        b += (f'<line x1="{x0}" y1="{base}" x2="{x0 + panel_w}" y2="{base}" '
              f'stroke="{RULE}"/>\n')
        tallest = max(v for v in values if v is not None) or 1
        step = panel_w // len(keys)
        for i, k in enumerate(keys):
            v = values[i]
            x = x0 + i * step + 8
            if v is None:
                b += _text(x + (step - 16) / 2, base - 8, "no price", size=10,
                           anchor="middle")
            else:
                hgt = max(2, round((base - top) * float(v / tallest)))
                b += (f'<rect x="{x}" y="{base - hgt}" width="{step - 16}" '
                      f'height="{hgt}" fill="{HUES[i % len(HUES)]}"/>\n')
                b += _text(x + (step - 16) / 2, base - hgt - 6, fmt(v),
                           size=10, anchor="middle")
            lo = max(k * HALVING, 1)
            hi = (k + 1) * HALVING - 1
            b += _text(x + (step - 16) / 2, base + 16, f"epoch {k}", size=11,
                       anchor="middle")
            b += _text(x + (step - 16) / 2, base + 30,
                       f"{'1' if lo == 1 else f'{lo // 1000:,}k'}.."
                       f"{hi // 1000:,}k", size=9, anchor="middle")
        return b

    btc = [Decimal(per_epoch[k]["fees"]) / Decimal(10 ** 8) for k in keys]
    fiat = [per_epoch[k]["fiat"] if per_epoch[k]["priced"] else None
            for k in keys]
    body += panel(left, "fees, BTC", btc, lambda v: f"{v:,.0f}")
    body += panel(left + panel_w + gap, f"fees, {currency} (priced blocks)",
                  fiat, lambda v: f"{v / 10 ** 6:,.0f} M" if v >= 10 ** 7
                  else f"{v / 10 ** 6:,.2f} M")
    e0 = per_epoch[keys[0]]
    body += _text(left - 40, base + 56,
                  f"epoch 0: {e0['blocks'] - e0['priced']:,} of "
                  f"{e0['blocks']:,} blocks precede the first observation "
                  "and are not converted", size=10)
    body += _text(left - 40, base + 72,
                  "external input: price series identified by digest, "
                  "see the caption", size=10)
    return _svg(width, base + 88, body)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--supply", required=True,
                    help="CSV from `derived supply --price ... --csv`")
    ap.add_argument("--blockprice", required=True,
                    help="the blockprice directory the CSV was made with")
    ap.add_argument("--out", default="docs/figures")
    args = ap.parse_args(argv)

    rows, currency = read_supply(args.supply)
    series, meta = read_blockprice(args.blockprice)
    if len(series) < len(rows):
        raise SystemExit("the blockprice table is shorter than the CSV")

    per_epoch = epochs(rows)
    pairs = [("price-by-height.svg",
              price_figure(rows, series, meta, currency)),
             ("fees-by-epoch.svg", fees_figure(per_epoch, currency))]
    for name, svg in pairs:
        path = os.path.join(args.out, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(svg)
        print(f"wrote {path}  ({len(svg):,} bytes)")

    print(f"\nper halving epoch, fees in BTC and in {currency}, and what "
          "the total would be if the epoch's fees were multiplied by the "
          "epoch's mean price instead of being priced block by block:")
    print(f"  {'epoch':>5}  {'priced/blocks':>17}  {'fees BTC':>14}  "
          f"{'block by block':>16}  {'by mean price':>16}  {'difference':>10}")
    for k in sorted(per_epoch):
        e = per_epoch[k]
        if not e["priced"]:
            print(f"  {k:>5}  {e['priced']:>8,}/{e['blocks']:<8,}  "
                  f"{e['fees'] / 1e8:>14,.2f}  {'no price':>16}")
            continue
        diff = (e["fiat_by_mean"] - e["fiat"]) / e["fiat"] * 100 \
            if e["fiat"] else Decimal(0)
        print(f"  {k:>5}  {e['priced']:>8,}/{e['blocks']:<8,}  "
              f"{e['fees'] / 1e8:>14,.2f}  {e['fiat']:>16,.0f}  "
              f"{e['fiat_by_mean']:>16,.0f}  {diff:>+9.2f}%")
    print("\nexternal inputs these figures rest on:")
    for s in meta["parents"]["series"]:
        o = s["origin"]
        print(f"  series {s['order']}: {s['publisher']}, step {s['step']} s, "
              f"license: {o.get('license')}, fetched: {o.get('fetched_at')}")
        print(f"    digest {s['digest']}")
    print(f"  blockprice digest {meta['digest']}")
    print("  a series fetched later may differ where its publisher "
          "corrected the past")


if __name__ == "__main__":
    raise SystemExit(main())
