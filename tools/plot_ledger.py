#!/usr/bin/env python3
"""Draw the two ledger figures in `docs/figures/`, from CSV the tool emits.

Same footing as `plot_nonces.py` and `plot_price.py`: `nodsig` counts, it
does not draw, so this writes SVG by hand with nothing but python3, in the
visual language of the figures already there. No number in either figure is
typed in.

    python3 tools/plot_ledger.py --census census.csv --curve curve.csv \
                                 --dates dates.csv --out docs/figures

`census.csv` comes from `nodsig census --csv`: the value each lock type
holds at the snapshot. `curve.csv` comes from `archive derive --curve`
(`reuse scan` writes the same columns), and its LAST row is the value whose
key the chain has already shown, type by type, at the same height. The two
must be read at the same moment of the chain or the map compares two
different ledgers, which is why the script refuses a curve whose last height
is not the census tip unless you insist.

`dates.csv` is optional: it is what `curve dates --curve curve.csv --out`
writes (`height,unix,mediantime,utc`), and it buys the reuse curve an x axis
in calendar years instead of block heights. Without it the axis is heights,
which is what the files themselves know.

The two figures were the only ones in `docs/figures/` with no script behind
them, which meant they could not be redrawn when the artifacts were rebuilt.
This closes that hole.
"""

import argparse
import csv
import collections
import html
import os

INK = "#1a1a1a"
MUTED = "#666"
RULE = "#e6e6e3"
PAPER = "#fdfdfc"
FONT = "font-family:system-ui,sans-serif"

SAT = 100_000_000
MILLION = 1_000_000
# Spelled out rather than taken from strftime, which would name the month
# in whatever language the machine drawing the figure happens to speak.
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _month(stamp):
    """'2018-11' -> 'Nov 2018'."""
    year, month = stamp.split("-")[:2]
    return f"{MONTHS[int(month) - 1]} {year}"

# One hue per lock type, shared by both figures so the two pictures read as
# one ledger. The hues are `plot_nonces.HUES`, in the order the older
# figures used them.
COLOR = {"p2wpkh": "#2a78d6", "p2sh": "#008300",
         "p2wsh": "#eda100", "p2pkh": "#e87ba4"}
LABEL = {"p2wpkh": "P2WPKH", "p2sh": "P2SH",
         "p2wsh": "P2WSH", "p2pkh": "P2PKH"}

# The rows of the ledger map: a display name, the census types that feed it,
# and the curve type that says how much of it is already in view -- or None
# for the shapes that publish the key to be spent at all, which are exposed
# by construction and are drawn hatched, at their full length.
MAP_ROWS = (
    ("P2WPKH", ("p2wpkh",), "p2wpkh"),
    ("P2PKH", ("p2pkh",), "p2pkh"),
    ("P2SH", ("p2sh",), "p2sh"),
    ("P2PK", ("p2pk_c", "p2pk_u"), None),
    ("P2WSH", ("p2wsh",), "p2wsh"),
    ("Taproot", ("p2tr",), None),
)


def _esc(s):
    return html.escape(str(s), quote=True)


def _svg(width, height, body):
    return (f'<svg viewBox="0 0 {width} {height}" role="img" '
            f'xmlns="http://www.w3.org/2000/svg" '
            f'style="max-width:100%;height:auto;{FONT}">\n'
            f'<rect width="100%" height="100%" fill="{PAPER}"/>\n'
            + body + "</svg>\n")


def _text(x, y, s, size=12, fill=MUTED, anchor="start", weight=None,
          style=None):
    w = f' font-weight="{weight}"' if weight else ""
    st = f' font-style="{style}"' if style else ""
    return (f'<text x="{x}" y="{y}" text-anchor="{anchor}" fill="{fill}" '
            f'font-size="{size}"{w}{st}>{_esc(s)}</text>\n')


def _nice_step(span, want):
    """A round step that cuts `span` into about `want` intervals: 1, 2 or 5
    times a power of ten. Round numbers on an axis are not decoration, they
    are what lets a reader do the arithmetic the figure does not do."""
    raw = max(span, 1) / max(want, 1)
    mag = 10 ** int(len(str(int(raw))) - 1) if raw >= 1 else 1
    for mult in (1, 2, 5, 10):
        if mult * mag >= raw:
            return mult * mag
    return 10 * mag


def _unit_for(top):
    """The unit an axis reaching `top` BTC should be read in: millions on a
    whole chain, thousands or plain BTC on a shorter one. Taking the unit
    from the axis instead of assuming millions is what keeps a figure drawn
    from a short chain from labelling every gridline `0.0 M`."""
    for unit, suffix in ((MILLION, "M"), (1_000, "k"), (1, "")):
        if top >= unit:
            return unit, suffix
    return 1, ""


def _axis_label(btc, step, top):
    """A gridline's label, carrying a decimal only when the step needs one."""
    unit, suffix = _unit_for(top)
    places = 0 if step % unit == 0 else 1
    return f"{btc / unit:,.{places}f}" + (f" {suffix}" if suffix else "")


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------

def read_census(path):
    """-> {census type: satoshis}, summed over the height ranges."""
    total = collections.Counter()
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        need = {"type", "satoshis"}
        if not need <= set(reader.fieldnames or ()):
            raise SystemExit(f"{path} is not a census CSV: it has no "
                             f"{sorted(need)} columns")
        for row in reader:
            total[row["type"]] += int(row["satoshis"])
    return total


def read_curve(path):
    """-> (types, [(height, {type: (hits, satoshis)})]) in height order.

    The columns name the types, so a curve written with a different set of
    lock types draws without editing this file.
    """
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        cols = list(reader.fieldnames or ())
        if not cols or cols[0] != "height":
            raise SystemExit(f"{path} is not a curve CSV: the first column "
                             f"is {cols[:1]}, not 'height'")
        types = [c[:-len("_satoshis")]
                 for c in cols if c.endswith("_satoshis")]
        rows = []
        for row in reader:
            rows.append((int(row["height"]),
                         {t: (int(row[f"{t}_hits"]), int(row[f"{t}_satoshis"]))
                          for t in types}))
    if not rows:
        raise SystemExit(f"{path} has no rows")
    rows.sort(key=lambda r: r[0])
    return types, rows


def read_dates(path):
    """-> {height: 'YYYY-MM'}, from `curve dates --out`."""
    out = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            stamp = row.get("utc") or ""
            if len(stamp) >= 7:
                out[int(row["height"])] = stamp[:7]
    return out


# ---------------------------------------------------------------------------
# Figure 1: the ledger map -- what each type holds, and how much is in view
# ---------------------------------------------------------------------------

def ledger_map(census, exposed):
    """One bar per lock type: the length is what the type holds, the filled
    part what the chain has already shown the key for.

    The bars are ordered by what they hold, not by a fixed list, so the
    figure follows the ledger instead of a memory of it.
    """
    rows = []
    for name, sources, curve_type in MAP_ROWS:
        held = sum(census.get(s, 0) for s in sources)
        if not held:
            continue
        shown = held if curve_type is None else exposed.get(curve_type, 0)
        rows.append((name, held, shown, curve_type))
    if not rows:
        raise SystemExit("the census holds none of the types the map draws")
    rows.sort(key=lambda r: -r[1])
    left_over = sum(v for t, v in census.items()
                    if t not in {s for _, ss, _ in MAP_ROWS for s in ss})

    left, top, bar_w, row_h, bar_h = 84, 41, 426, 46, 16
    biggest = max(r[1] for r in rows)
    scale = bar_w / biggest
    base = top + row_h * (len(rows) - 1) + bar_h
    height = base + (67 if left_over else 49)
    width = 720

    body = ('<defs><pattern id="hatch" width="6" height="6" '
            'patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
            f'<rect width="6" height="6" fill="{MUTED}"/>'
            f'<line x1="0" y1="0" x2="0" y2="6" stroke="{PAPER}" '
            'stroke-width="2.5"/></pattern></defs>\n')

    step = _nice_step(biggest / SAT, 5)
    unit, suffix = _unit_for(biggest / SAT)
    grid = 0
    while grid * SAT * scale <= bar_w + 1:
        x = round(left + grid * SAT * scale, 1)
        body += (f'<line x1="{x}" y1="{top - 21}" x2="{x}" y2="{base + 15}" '
                 f'stroke="{RULE}"/>\n')
        body += _text(x, base + 31, _axis_label(grid, step, biggest / SAT),
                      anchor="middle")
        grid += step

    for i, (name, held, shown, curve_type) in enumerate(rows):
        y = top + i * row_h
        full = round(held * scale, 1)
        part = round(shown * scale, 1)
        fill = "url(#hatch)" if curve_type is None else COLOR.get(
            curve_type, MUTED)
        pct = 100 * shown / held
        body += _text(left - 10, y + 12, name, anchor="end", fill=INK,
                      weight="600")
        body += (f'<rect x="{left}" y="{y}" width="{full}" height="{bar_h}" '
                 f'rx="2" fill="{RULE}"/>\n')
        body += (f'<rect x="{left}" y="{y}" width="{max(part, 1.0)}" '
                 f'height="{bar_h}" rx="2" fill="{fill}">'
                 f'<title>{_esc(name)}: {shown // SAT:,} BTC exposed of '
                 f'{held // SAT:,}</title></rect>\n')
        note = (f"{held / SAT / unit:.2f}{suffix}, by construction (100%)"
                if curve_type is None else
                f"{shown / SAT / unit:.2f} of {held / SAT / unit:.2f}{suffix} "
                f"({pct:.0f}%)")
        body += _text(left + full + 8, y + 12, note)
    if left_over:
        body += _text(left - 74, height - 16,
                      f"left out: {left_over / SAT:,.0f} BTC in bare "
                      "multisig and other shapes, which no single key "
                      "stands behind", size=11)
    return _svg(width, height, body)


# ---------------------------------------------------------------------------
# Figure 2: the reuse curve -- value in view, by the height that showed it
# ---------------------------------------------------------------------------

def reuse_curve(types, rows, dates=None):
    """One line per lock type: BTC spendable at the snapshot whose key was
    already public by the block on the x axis.

    The line is cumulative by construction -- a key, once shown, stays
    shown -- so the interesting thing in it is where it steps, and the
    figure names its largest step rather than leaving a reader to find it.
    """
    left, right, base, top = 56, 610, 370.0, 26.0
    lo, hi = rows[0][0], rows[-1][0]
    span = max(hi - lo, 1)

    peak = max(v[1] for _, cols in rows for v in cols.values())
    step = _nice_step(peak / SAT, 4)
    ceiling = step
    while ceiling * SAT < peak:
        ceiling += step
    yscale = (base - top) / (ceiling * SAT)

    def px(height):
        return round(left + (height - lo) * (right - left) / span, 1)

    def py(sats):
        return round(base - sats * yscale, 1)

    body = ""
    grid = 0
    while grid <= ceiling:
        y = round(base - grid * SAT * yscale, 1)
        body += (f'<line x1="{left}" y1="{y}" x2="{right}" y2="{y}" '
                 f'stroke="{RULE}"/>\n')
        body += _text(left - 8, y + 4, _axis_label(grid, step, ceiling),
                      anchor="end")
        grid += step

    body += (f'<line x1="{left}" y1="{base}" x2="{right}" y2="{base}" '
             f'stroke="{MUTED}"/>\n')

    # The x axis: calendar years when a dates CSV was given, heights when
    # it was not. The years are the one thing here that a file cannot hold,
    # which is why `curve dates` has to ask a node or a header archive.
    ticks = []
    if dates:
        seen = {}
        for height, _ in rows:
            stamp = dates.get(height)
            if stamp:
                seen.setdefault(stamp[:4], height)
        every = max(1, -(-len(seen) // 10))
        ticks = [(h, y) for y, h in sorted(seen.items())
                 if int(y) % every == 0]
        # A span whose years are all off the step (a handful of years, none
        # a multiple) would leave the axis bare: then every year is a tick.
        ticks = ticks or [(h, y) for y, h in sorted(seen.items())]
    if not ticks:
        hstep = _nice_step(span, 6)
        h = ((lo + hstep - 1) // hstep) * hstep
        while h <= hi:
            ticks.append((h, f"{h / MILLION:.1f} M"))
            h += hstep
    for height, label in ticks:
        x = px(height)
        body += (f'<line x1="{x}" y1="{base}" x2="{x}" y2="{base + 4}" '
                 f'stroke="{MUTED}"/>\n')
        body += _text(x, base + 18, label, anchor="middle")

    order = sorted(types, key=lambda t: -rows[-1][1][t][1])
    mark_every = max(1, -(-len(rows) // 50))
    for t in order:
        points = " ".join(f"{px(h)},{py(cols[t][1])}" for h, cols in rows)
        body += (f'<polyline points="{points}" fill="none" '
                 f'stroke="{COLOR.get(t, MUTED)}" stroke-width="2"/>\n')
    for t in order:
        for i in range(0, len(rows), mark_every):
            h, cols = rows[i]
            body += (f'<circle cx="{px(h)}" cy="{py(cols[t][1])}" r="7" '
                     f'fill="transparent"><title>{_esc(LABEL.get(t, t))}: '
                     f'{cols[t][1] // SAT:,} BTC by height {h:,}'
                     f'</title></circle>\n')

    # End-of-line labels, nudged apart when two lines finish close together.
    unit, suffix = _unit_for(ceiling)
    taken = []
    for t in order:
        y = py(rows[-1][1][t][1])
        while any(abs(y - other) < 14 for other in taken):
            y -= 14
        taken.append(y)
        body += (f'<rect x="{right + 8}" y="{round(y - 4, 1)}" width="8" '
                 f'height="8" rx="2" fill="{COLOR.get(t, MUTED)}"/>\n')
        body += _text(right + 20, y + 4,
                      f"{LABEL.get(t, t)} "
                      f"{rows[-1][1][t][1] / SAT / unit:.2f}"
                      + (f" {suffix}" if suffix else ""),
                      size=12, fill=INK, weight="600")

    x = left
    for t in order:
        body += (f'<rect x="{x}" y="8" width="10" height="10" rx="2" '
                 f'fill="{COLOR.get(t, MUTED)}"/>\n')
        body += _text(x + 14, 17, LABEL.get(t, t))
        x += 24 + 8 * len(LABEL.get(t, t))

    body += _biggest_step(rows, px, py, dates)
    return _svg(right + 170, int(base) + 40, body)


def _biggest_step(rows, px, py, dates):
    """Name the largest single jump in the curve: which type, how much, over
    how many locks. It is always a batch of keys coming into view at once,
    and a reader who cannot see which step is the big one will quote the
    wrong one."""
    best = None
    for (prev_h, prev), (h, cur) in zip(rows, rows[1:]):
        for t in cur:
            delta = cur[t][1] - prev[t][1]
            if best is None or delta > best[0]:
                best = (delta, cur[t][0] - prev[t][0], t, h, prev_h)
    if not best or best[0] <= 0:
        return ""
    delta, dhits, t, h, _ = best
    stamp = (dates or {}).get(h)
    when = _month(stamp) if stamp else f"height {h:,}"
    at = next(cols[t][1] for height, cols in rows if height == h)
    x, y = px(h), py(at)
    # The note is centred on the step, but kept clear of both margins: a
    # jump in the first or last blocks would otherwise write off the plot.
    x = min(max(x, px(rows[0][0]) + 80), px(rows[-1][0]) - 80)
    above = y > 150
    ty = round(y - 40 if above else y + 46, 1)
    tip = round(ty + 20 if above else ty - 26, 1)
    body = (f'<line x1="{x}" y1="{tip}" x2="{px(h)}" y2="{y}" '
            f'stroke="{MUTED}" stroke-dasharray="2 3"/>\n')
    body += _text(x, ty, f"{when}: +{delta // SAT:,} BTC", size=11,
                 anchor="middle", style="italic")
    body += _text(x, ty + 14, f"across {dhits:,} {LABEL.get(t, t)} locks",
                  size=11, anchor="middle", style="italic")
    return body


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--census", required=True,
                    help="CSV from `nodsig census --csv`")
    ap.add_argument("--curve", required=True,
                    help="CSV from `archive derive --curve` or `reuse scan`")
    ap.add_argument("--dates",
                    help="CSV from `curve dates --out`: heights to years")
    ap.add_argument("--allow-height-mismatch", action="store_true",
                    help="draw even when the curve's last height is not the "
                         "census tip, which mixes two moments of the chain")
    ap.add_argument("--census-height", type=int,
                    help="the height the census was taken at, when it is not "
                         "the curve's last height")
    ap.add_argument("--out", default="docs/figures")
    args = ap.parse_args(argv)

    census = read_census(args.census)
    types, rows = read_curve(args.curve)
    tip = rows[-1][0]
    if args.census_height and args.census_height != tip \
            and not args.allow_height_mismatch:
        raise SystemExit(
            f"the census is at height {args.census_height:,} and the curve "
            f"ends at {tip:,}: the map would compare two ledgers. Pass "
            f"--allow-height-mismatch if that is what you want.")
    dates = read_dates(args.dates) if args.dates else None

    exposed = {t: rows[-1][1][t][1] for t in types}
    pairs = [("ledger-map.svg", ledger_map(census, exposed)),
             ("reuse-curve.svg", reuse_curve(types, rows, dates))]
    for name, svg in pairs:
        path = os.path.join(args.out, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(svg)
        print(f"wrote {path}  ({len(svg):,} bytes)")
    print(f"drawn at height {tip:,}, from {len(rows):,} curve rows")


if __name__ == "__main__":
    raise SystemExit(main())
