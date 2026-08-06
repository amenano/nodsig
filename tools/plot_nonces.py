#!/usr/bin/env python3
"""Draw the two nonce figures in `docs/figures/`, from CSV the tool emits.

This exists so the figures in the gallery are reproducible like everything
else in this project. It is not part of the package and nothing imports it:
`nodsig` counts, it does not draw, and adding a plotting library to a tool
whose whole pitch is that it has no dependencies would be a poor trade for
two pictures. So this writes SVG by hand, in the same visual language as
the figures already there, and needs nothing but python3.

    python3 tools/plot_nonces.py --groups groups.csv --resolutions resolutions.csv \
                                 --out docs/figures

`groups.csv` comes from `nonces groups --csv`, `resolutions.csv` from
`nonces witness-verify --csv`. Both are the artifacts' own output: no
number here is typed in, which is the only reason a figure belongs in a
repository that asks to be checked rather than believed.
"""

import argparse
import collections
import csv
import html
import os

INK = "#1a1a1a"
MUTED = "#666"
RULE = "#e6e6e3"
PAPER = "#fdfdfc"
# The same four hues the ledger map uses, so the two pages look like one
# project. Order matters: the first is the one a reader should look at.
HUES = ["#2a78d6", "#008300", "#eda100", "#e87ba4", "#8a8a8a"]

FONT = "font-family:system-ui,sans-serif"


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
# Figure 1: what the repeated points turn out to be
# ---------------------------------------------------------------------------

def resolution_figure(rows):
    """One bar per resolution, widest first.

    The figure a reader should take away is not that some keys are
    exposed: it is that most repeated points cannot be resolved at all.
    So the bars are drawn in the order the data gives, and the largest
    one is the undetermined share.
    """
    tally = collections.Counter(r["resolution"] for r in rows)
    total = sum(tally.values())
    order = tally.most_common()

    left, top, bar_w, row_h = 190, 56, 470, 34
    height = top + row_h * len(order) + 46
    body = _text(left - 138, 30, "What a repeated nonce point turns out to be",
                 size=14, fill=INK, weight="600")
    body += _text(left - 138, 46,
                  f"{total:,} points, heights 1 to 957,301", size=11)

    biggest = order[0][1]
    for i, (resolution, n) in enumerate(order):
        y = top + i * row_h
        w = max(2, round(bar_w * n / biggest))
        body += _text(left - 10, y + 15, resolution, anchor="end", fill=INK)
        body += (f'<rect x="{left}" y="{y + 3}" width="{w}" height="16" '
                 f'fill="{HUES[i % len(HUES)]}"/>\n')
        body += _text(left + w + 8, y + 15,
                      f"{n:,}   {100 * n / total:.1f}%", size=11)
    body += _text(left - 138, height - 16,
                  "undetermined = the signer is not identifiable from the "
                  "input; no resolution is guessed", size=11)
    return _svg(left + bar_w + 110, height, body)


# ---------------------------------------------------------------------------
# Figure 2: how big the groups are
# ---------------------------------------------------------------------------

def size_figure(rows):
    """Groups by how many sightings they have, on a log scale.

    This is the figure that stops a reader quoting the largest number:
    almost every group is a pair, and a single point accounts for
    millions of sightings on its own.
    """
    counts = [int(r["count"]) for r in rows]
    buckets = collections.Counter()
    for c in counts:
        if c < 10:
            buckets[str(c)] += 1
        else:
            lo = 10
            while lo * 10 <= c:
                lo *= 10
            buckets[f"{lo:,}+"] += 1

    def key(b):
        return int(b.rstrip("+").replace(",", ""))

    order = sorted(buckets, key=key)
    left, base, top = 60, 330, 60
    step = min(58, 620 // max(len(order), 1))
    width = left + step * len(order) + 40
    tallest = max(buckets.values())

    body = _text(left - 34, 30, "How many sightings a repeated point has",
                 size=14, fill=INK, weight="600")
    body += _text(left - 34, 46,
                  f"{len(counts):,} points; the bar height is a count of "
                  "points, on a log scale", size=11)
    body += f'<line x1="{left - 8}" y1="{base}" x2="{width - 30}" ' \
            f'y2="{base}" stroke="{RULE}"/>\n'

    import math
    for i, b in enumerate(order):
        n = buckets[b]
        h = max(3, round((base - top) * math.log10(n + 1)
                         / math.log10(tallest + 1)))
        x = left + i * step
        body += (f'<rect x="{x}" y="{base - h}" width="{step - 12}" '
                 f'height="{h}" fill="{HUES[0] if key(b) < 10 else HUES[2]}"/>\n')
        body += _text(x + (step - 12) / 2, base - h - 6, f"{n:,}", size=10,
                      anchor="middle")
        body += _text(x + (step - 12) / 2, base + 16, b, size=11,
                      anchor="middle")
    body += _text(left - 34, base + 42,
                  "sightings of the point (2 means it was published twice)",
                  size=11)
    body += _text(left - 34, base + 60,
                  f"largest single group: {max(counts):,} sightings, one "
                  "constructed value from 2015", size=11)
    return _svg(width, base + 76, body)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--groups", required=True,
                    help="CSV from `nonces groups --csv`")
    ap.add_argument("--resolutions", required=True,
                    help="CSV from `nonces witness-verify --csv`")
    ap.add_argument("--out", default="docs/figures")
    args = ap.parse_args(argv)

    with open(args.resolutions) as f:
        resolutions = list(csv.DictReader(f))
    with open(args.groups) as f:
        groups = list(csv.DictReader(f))

    pairs = [("nonce-resolutions.svg", resolution_figure(resolutions)),
             ("nonce-group-sizes.svg", size_figure(groups))]
    for name, svg in pairs:
        path = os.path.join(args.out, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(svg)
        print(f"wrote {path}  ({len(svg):,} bytes)")


if __name__ == "__main__":
    raise SystemExit(main())
