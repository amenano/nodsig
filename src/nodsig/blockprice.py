#!/usr/bin/env python3
"""BlockPrice-v1: one price per block, the bridge between the chain's clock
and an external price series.

The clock of every artifact here is the height. The only bridge the chain
CERTIFIES towards calendar time is the header timestamp: declared by the
miner, held by consensus only to within hours (above the median of the
previous eleven, not more than two hours into the future), and not
monotonic. So the chain does not know when a transaction happened; it
knows which block it sits in. Giving a transaction a price "at the
minute" would be inventing an instant nobody certified. The finest price
that can honestly be assigned is the price OF THE BLOCK, shared by every
transaction in it, and that is what this table materialises:

    blockprice.bin      9 B per height, big-endian, height h at record h-1
                        (the same positional rule as the index's blocks.bin):
                            price_micro:u64 | series:u8
                        price_micro = price * 1e6, rounded half-even;
                        series = 1-based order of the series that answered,
                        0 = no price (and then price_micro is 0)
    blockprice.json     the rule, the parents (the index by fingerprint,
                        each series by digest), what the rebuild found
                        when it compared its prefix with the previous
                        file, and this file's own digest

Rule: price(h) = the last observation with obs_ts <= header_time(h), from
the first series in the declared order that answers (a series that is
stale or not yet started does not answer). Every fiat figure in this
toolkit is computed block by block from this table and aggregated after;
the daily view below is one such aggregation, and not an exchange close.

This is an EXTERNAL INPUT, DERIVED: it depends on an index, which is a
function of the chain, and on series that are not. It therefore carries
a digest and not a fingerprint: two people can reproduce it only if they
hold the same series, and the parents block is where they check that.
Formats: docs/formats/BlockPrice-v1.md, docs/formats/PriceSeries-v1.md;
the reasoning: docs/external-inputs.md.
"""

import argparse
import json
import os
import sys
import time
from decimal import Decimal, ROUND_HALF_EVEN

from nodsig import outpoint_index as oi
from nodsig import priceseries as ps
from nodsig.artifact import producer
from nodsig.recio import atomic_json, sha_file

FORMAT_TAG = "blockprice-v1"
BIN_NAME = "blockprice.bin"
META_NAME = "blockprice.json"
REC = 9
MICRO = Decimal(1_000_000)
U64_MAX = (1 << 64) - 1
DAY = 86400

RULE = ("price(h) = last observation with obs_ts <= header time of h, "
        "from the first series in order that answers; series 0 = no price")


class BlockPriceError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# encoding
# ---------------------------------------------------------------------------

def encode(price, series):
    """price: Decimal or None. A price the 64-bit micro field cannot hold
    is refused rather than wrapped: it would not be a price any more."""
    if series == 0 or price is None:
        return bytes(REC)
    micro = int((price * MICRO).to_integral_value(ROUND_HALF_EVEN))
    if micro <= 0 or micro > U64_MAX:
        raise BlockPriceError(f"price {price} does not fit the record")
    return micro.to_bytes(8, "big") + bytes([series])


def decode(rec):
    """-> (price as Decimal, series order) or (None, 0)."""
    k = rec[8]
    if k == 0:
        return None, 0
    return Decimal(int.from_bytes(rec[:8], "big")) / MICRO, k


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def _open_index(index_dir):
    try:
        return oi.Index(index_dir)
    except oi.OutpointError as e:
        raise BlockPriceError(f"index: {e}")


def compute(times, series):
    """The table's bytes for a list of header times. Pure: a function of
    the times and of the series, which is what `verify` recomputes."""
    out = bytearray()
    priced = 0
    priced_from = None
    for i, ts in enumerate(times):
        k, q = ps.quote_first(series, ts)
        out += encode(q.price if q else None, k)
        if k:
            priced += 1
            if priced_from is None:
                priced_from = i + 1
    return bytes(out), priced, priced_from


def run_build(index_dir, out_dir, series_dirs, out=None):
    """Build `<out_dir>` from a sealed index and one or more series, in
    the order given. A rebuild over an existing table compares the
    prefix and REPORTS the heights whose price changed: a publisher that
    rewrote its past becomes a number in the metadata, never something
    silently absorbed."""
    out = out or sys.stdout
    if len(series_dirs) > 255:
        raise BlockPriceError("at most 255 series (the series byte)")
    try:
        series = ps.open_series(series_dirs)
    except ps.PriceSeriesError as e:
        raise BlockPriceError(str(e))
    index = _open_index(index_dir)
    try:
        times = list(index.times)
        fingerprint = index.manifest["fingerprint"]
        index_format = index.format
        watermark = index.watermark
    finally:
        index.close()

    data, priced, priced_from = compute(times, series)
    os.makedirs(out_dir, exist_ok=True)
    bin_path = os.path.join(out_dir, BIN_NAME)
    previous = b""
    if os.path.exists(bin_path):
        with open(bin_path, "rb") as f:
            previous = f.read()
    common = min(len(previous), len(data)) // REC
    changed = [i + 1 for i in range(common)
               if previous[i * REC:(i + 1) * REC] != data[i * REC:(i + 1) * REC]]
    tmp = bin_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, bin_path)
    meta = {
        "format": FORMAT_TAG,
        "kind": "external input, derived",
        "rule": RULE,
        "record": "price_micro:u64 | series:u8, 9 bytes, height h at "
                  "record h-1",
        "currency": series[0].currency,
        "heights": {"from": 1, "to": len(times)},
        "watermark": watermark,
        "priced": priced,
        "priced_from": priced_from,
        "parents": {
            "index": {"format": index_format, "fingerprint": fingerprint},
            "series": [s.declared(k) for k, s in enumerate(series, 1)],
        },
        "prefix": {"previous_heights": len(previous) // REC,
                   "changed": len(changed),
                   "changed_heights": changed[:10]},
        "file": BIN_NAME,
        "digest": sha_file(bin_path),
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "producer": producer(),
    }
    atomic_json(os.path.join(out_dir, META_NAME), meta)
    _print_meta(meta, out)
    return meta


def _print_meta(meta, out):
    h = meta["heights"]
    print(f"block price: heights {h['from']:,}..{h['to']:,}, "
          f"{meta['priced']:,} priced"
          + (f" from height {meta['priced_from']:,}" if meta["priced_from"]
             else ", none priced"), file=out)
    print(f"  currency {meta['currency']}; {meta['rule']}", file=out)
    print(f"  parent index  {meta['parents']['index']['fingerprint']}",
          file=out)
    for s in meta["parents"]["series"]:
        print(f"  series {s['order']}  {s['publisher']}  step {s['step']} s  "
              f"digest {s['digest']}", file=out)
    p = meta["prefix"]
    if p["previous_heights"]:
        print(f"  previous table: {p['previous_heights']:,} heights, "
              f"{p['changed']:,} changed"
              + (f" (the first at {p['changed_heights']})"
                 if p["changed"] else ""), file=out)
    print(f"digest: {meta['digest']}", file=out)
    print("(a digest identifies this file; fiat figures depend on external "
          "series, identified above by digest, and a series fetched later "
          "may differ where its publisher corrected the past)", file=out)


# ---------------------------------------------------------------------------
# reading
# ---------------------------------------------------------------------------

def load_meta(bp_dir):
    path = os.path.join(bp_dir, META_NAME)
    if not os.path.exists(path):
        raise BlockPriceError(f"no {META_NAME} in {bp_dir}: run "
                              "`price build`")
    with open(path) as f:
        meta = json.load(f)
    if meta.get("format") != FORMAT_TAG:
        raise BlockPriceError(f"not a {FORMAT_TAG} table: {bp_dir}")
    return meta


class BlockPrice:
    """Read side. The table is small (9 B per block) and is read whole."""

    def __init__(self, bp_dir, check_digest=True):
        self.dir = bp_dir
        self.meta = load_meta(bp_dir)
        path = os.path.join(bp_dir, self.meta["file"])
        if check_digest and sha_file(path) != self.meta["digest"]:
            raise BlockPriceError(f"{path}: digest differs from "
                                  f"{META_NAME}; the file changed after "
                                  "it was built")
        with open(path, "rb") as f:
            self.data = f.read()
        if len(self.data) % REC:
            raise BlockPriceError(f"{path}: not a whole number of records")
        self.n = len(self.data) // REC
        if self.n != self.meta["heights"]["to"]:
            raise BlockPriceError(f"{path}: {self.n} records, {META_NAME} "
                                  f"says {self.meta['heights']['to']}")
        self.names = [s["publisher"] for s in self.meta["parents"]["series"]]
        self.currency = self.meta["currency"]

    def at(self, height):
        """-> (price Decimal, publisher name) or None."""
        if height < 1 or height > self.n:
            return None
        price, k = decode(self.data[(height - 1) * REC: height * REC])
        if k == 0:
            return None
        if k > len(self.names):
            raise BlockPriceError(f"height {height}: series {k} is not "
                                  "declared in the metadata")
        return price, self.names[k - 1]

    def rows(self):
        """Every (price or None, series order), height 1 first."""
        for i in range(self.n):
            yield decode(self.data[i * REC:(i + 1) * REC])


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def run_verify(bp_dir, index_dir=None, series_dirs=(), out=None):
    """Structural first: digest, whole records, count, no series byte
    beyond the declared ones, no price without a series and no series
    without a price. Then, given the parents: the index fingerprint and
    each series digest against the declaration, and the whole table
    recomputed and compared byte for byte."""
    out = out or sys.stdout
    bp = BlockPrice(bp_dir)
    n_series = len(bp.names)
    for i in range(bp.n):
        rec = bp.data[i * REC:(i + 1) * REC]
        k = rec[8]
        if k > n_series:
            raise BlockPriceError(f"height {i + 1}: series byte {k} beyond "
                                  f"the {n_series} declared")
        if (k == 0) != (rec[:8] == bytes(8)):
            raise BlockPriceError(f"height {i + 1}: a price without a "
                                  "series, or a series without a price")
    print(f"block price ok: {bp.n:,} heights, digest matches, records "
          f"well formed", file=out)
    declared = bp.meta["parents"]
    if index_dir is None and not series_dirs:
        print("  parents declared, not confirmed: give --index and "
              "--series to recompute", file=out)
        return
    if index_dir is None or not series_dirs:
        raise BlockPriceError("recomputing needs both --index and every "
                              "--series, in the declared order")
    index = _open_index(index_dir)
    try:
        if index.manifest["fingerprint"] != declared["index"]["fingerprint"]:
            raise BlockPriceError("the index given is not the declared "
                                  "parent (fingerprint differs)")
        times = list(index.times)
    finally:
        index.close()
    try:
        series = ps.open_series(series_dirs)
    except ps.PriceSeriesError as e:
        raise BlockPriceError(str(e))
    if len(series) != len(declared["series"]):
        raise BlockPriceError(f"{len(series)} series given, "
                              f"{len(declared['series'])} declared")
    for s, d in zip(series, declared["series"]):
        if s.digest != d["digest"]:
            raise BlockPriceError(f"series {d['order']} ({d['publisher']}): "
                                  "digest differs from the declared parent")
    data, _priced, _from = compute(times, series)
    if data != bp.data:
        diff = next(i for i in range(min(len(data), len(bp.data)) // REC + 1)
                    if data[i * REC:(i + 1) * REC] != bp.data[i * REC:(i + 1) * REC])
        raise BlockPriceError(f"recomputed table differs, the first at "
                              f"height {diff + 1}")
    print("  parents confirmed: index fingerprint and series digests "
          "match, and the table recomputes byte for byte", file=out)


# ---------------------------------------------------------------------------
# daily: the aggregation that is not an exchange close
# ---------------------------------------------------------------------------

def daily_rows(bp, times):
    """Per UTC day of the header time, dense from the day of height 1 to
    the day of the last header. Each row carries a value AND its kind:

        measured  the simple mean of the priced blocks of the day, one
                  weight per block (value-weighted figures are computed
                  per block, never through a day price)
        carried   no priced block that day: the last measured day's
                  price, with how many days ago it was measured
        none      before the first priced block: no number is invented

    -> (date, blocks, price, kind, gap_days, price_min, price_max,
        series) with Decimal prices (or None)."""
    days = {}
    prices = list(bp.rows())
    n = min(len(prices), len(times))
    for i in range(n):
        d = times[i] // DAY
        g = days.setdefault(d, [0, Decimal(0), None, None, 0, set()])
        g[0] += 1
        price, k = prices[i]
        if k:
            g[1] += price
            g[4] += 1
            g[2] = price if g[2] is None or price < g[2] else g[2]
            g[3] = price if g[3] is None or price > g[3] else g[3]
            g[5].add(bp.names[k - 1])
    if not days:
        return []
    out = []
    last = None
    last_day = None
    for d in range(min(days), max(days) + 1):
        date = time.strftime("%Y-%m-%d", time.gmtime(d * DAY))
        g = days.get(d)
        blocks = g[0] if g else 0
        if g and g[4]:
            price = g[1] / g[4]
            last, last_day = price, d
            out.append((date, blocks, price, "measured", 0, g[2], g[3],
                        "+".join(sorted(g[5]))))
        elif last is not None:
            out.append((date, blocks, last, "carried", d - last_day, None,
                        None, ""))
        else:
            out.append((date, blocks, None, "none", None, None, None, ""))
    return out


def write_daily_csv(rows, meta, out, date_from=None, date_to=None):
    def fmt(x):
        if x is None:
            return ""
        if isinstance(x, Decimal):
            return f"{x.quantize(Decimal('0.000001')):f}"
        return str(x)
    out.write("# blockprice daily: simple mean of the block prices per UTC "
              "day of header time, one weight per block; not an exchange "
              "close\n")
    out.write("# kind: measured | carried (last measured price, gap_days "
              "ago) | none (before the first priced block)\n")
    out.write(f"# currency {meta['currency']}; blockprice digest "
              f"{meta['digest']}; index {meta['parents']['index']['fingerprint']}\n")
    for s in meta["parents"]["series"]:
        out.write(f"# series {s['order']} {s['publisher']} step {s['step']} "
                  f"digest {s['digest']}\n")
    out.write("# fiat figures depend on external series identified by "
              "digest; a series fetched later may differ where its "
              "publisher corrected the past\n")
    out.write("date,blocks,price,kind,gap_days,price_min,price_max,series\n")
    for r in rows:
        if date_from and r[0] < date_from:
            continue
        if date_to and r[0] > date_to:
            continue
        out.write(",".join(fmt(x) for x in r) + "\n")


def run_daily(bp_dir, index_dir, csv_path=None, date_from=None,
              date_to=None, out=None):
    out = out or sys.stdout
    bp = BlockPrice(bp_dir)
    index = _open_index(index_dir)
    try:
        if index.manifest["fingerprint"] != \
                bp.meta["parents"]["index"]["fingerprint"]:
            raise BlockPriceError("the index given is not the table's "
                                  "declared parent (fingerprint differs)")
        times = list(index.times)
    finally:
        index.close()
    rows = daily_rows(bp, times)
    if csv_path:
        with open(csv_path, "w") as f:
            write_daily_csv(rows, bp.meta, f, date_from, date_to)
        print(f"{len(rows):,} days written to {csv_path}", file=out)
    else:
        write_daily_csv(rows, bp.meta, out, date_from, date_to)
    return rows


# ---------------------------------------------------------------------------
# the other verbs
# ---------------------------------------------------------------------------

def run_at(bp_dir, height, out=None):
    out = out or sys.stdout
    bp = BlockPrice(bp_dir)
    if height < 1 or height > bp.n:
        raise BlockPriceError(f"height {height} is outside 1..{bp.n}")
    answer = bp.at(height)
    if answer is None:
        print(f"height {height:,}: no price (before the series, or the "
              "series was stale)", file=out)
    else:
        price, name = answer
        print(f"height {height:,}: {price:f} {bp.currency}  "
              f"(series {name}, price of the block, precision of hours)",
              file=out)
    return answer


def run_stats(bp_dir, out=None):
    _print_meta(load_meta(bp_dir), out or sys.stdout)


def _import_from_args(args):
    preset = dict(ps.PRESETS.get(args.preset, {})) if args.preset else {}
    def pick(name, default=None):
        v = getattr(args, name)
        return v if v is not None else preset.get(name, default)
    ts_field, price_field = pick("ts_field"), pick("price_field")
    if ts_field is None or price_field is None:
        raise BlockPriceError("--ts-field and --price-field are required "
                              "(or a --preset that sets them)")
    publisher = pick("publisher")
    if not publisher:
        raise BlockPriceError("--publisher is required: who published "
                              "the file")
    return ps.import_series(
        args.src, args.out, ts_field, price_field,
        pick("ts_format", "unix"), pick("step", 86400), publisher,
        url=pick("url", ""), license_=pick("license", "unknown"),
        note=args.note or "", currency=args.currency,
        stale_after=args.stale_after, records_path=args.records,
        fetched_at=args.fetched_at)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="nodsig price",
        description="an external price series in one canonical shape, and "
                    "one price per block derived from it (requires a "
                    "price series: nothing here is a function of the chain)")
    sub = p.add_subparsers(dest="cmd", required=True)

    im = sub.add_parser("import", help="convert a publisher's CSV or JSON "
                                       "into a sealed price series")
    im.add_argument("--from", dest="src", required=True,
                    help="the publisher's file, CSV or JSON")
    im.add_argument("--out", required=True, help="the series directory")
    im.add_argument("--preset", choices=sorted(ps.PRESETS),
                    help="a named field mapping; every flag below "
                         "overrides it")
    im.add_argument("--ts-field", help="column (or JSON key/index) of time")
    im.add_argument("--price-field", help="column (or JSON key/index) of "
                                          "the price")
    im.add_argument("--ts-format", help="unix, unix_ms, or a strptime "
                                        "pattern read as UTC")
    im.add_argument("--step", type=int, help="nominal seconds between "
                                             "observations (86400 daily)")
    im.add_argument("--stale-after", type=int,
                    help="seconds after which an observation no longer "
                         "answers (default 3 steps)")
    im.add_argument("--records", help="JSON only: dotted path to the list")
    im.add_argument("--publisher", help="who published the file")
    im.add_argument("--url", help="where it was fetched from")
    im.add_argument("--license", help="the publisher's license")
    im.add_argument("--fetched-at", help="when you fetched it (free text)")
    im.add_argument("--currency", default="USD")
    im.add_argument("--note")

    sv = sub.add_parser("series-verify", help="a series against its "
                                              "series.json")
    sv.add_argument("--series", required=True)

    b = sub.add_parser("build", help="one price per block from a sealed "
                                     "index and the series, in order")
    b.add_argument("--index", required=True, help="a sealed outpoint index")
    b.add_argument("--out", required=True, help="the blockprice directory")
    b.add_argument("--series", action="append", required=True,
                   help="a series directory; repeat, finest first")

    st = sub.add_parser("stats", help="read the table's metadata")
    st.add_argument("--blockprice", required=True)

    v = sub.add_parser("verify", help="audit the table; with --index and "
                                      "--series it recomputes it")
    v.add_argument("--blockprice", required=True)
    v.add_argument("--index")
    v.add_argument("--series", action="append", default=[])

    at = sub.add_parser("at", help="the price of one block")
    at.add_argument("--blockprice", required=True)
    at.add_argument("height", type=int)

    d = sub.add_parser("daily", help="the per-day aggregation, dense, "
                                     "each value with its kind")
    d.add_argument("--blockprice", required=True)
    d.add_argument("--index", required=True, help="the parent index, for "
                                                  "the header times")
    d.add_argument("--csv", help="write here instead of stdout")
    d.add_argument("--from", dest="date_from", help="YYYY-MM-DD")
    d.add_argument("--to", dest="date_to", help="YYYY-MM-DD")

    args = p.parse_args(argv)
    try:
        if args.cmd == "import":
            meta = _import_from_args(args)
            print(f"price series imported: {meta['rows']:,} rows, "
                  f"{meta['currency']}, step {meta['step']} s")
            print(f"digest: {meta['digest']}")
        elif args.cmd == "series-verify":
            ps.verify_series(args.series)
        elif args.cmd == "build":
            run_build(args.index, args.out, args.series)
        elif args.cmd == "stats":
            run_stats(args.blockprice)
        elif args.cmd == "verify":
            run_verify(args.blockprice, index_dir=args.index,
                       series_dirs=args.series)
        elif args.cmd == "at":
            run_at(args.blockprice, args.height)
        elif args.cmd == "daily":
            run_daily(args.blockprice, args.index, csv_path=args.csv,
                      date_from=args.date_from, date_to=args.date_to)
    except (BlockPriceError, ps.PriceSeriesError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
