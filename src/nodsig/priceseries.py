#!/usr/bin/env python3
"""PriceSeries-v1: an external price series, in one canonical shape.

A price is NOT a function of the chain. Nothing in the blocks says what a
coin was worth, so every figure in a fiat currency that this toolkit ever
prints comes from a file somebody else published, and that file is the
one thing a rebuild cannot reproduce. This module gives such a file one
canonical shape, a digest that identifies it, and a reading rule, so that
two people holding the same series get the same numbers and two people
holding different series can tell.

It is an EXTERNAL INPUT, like the address book: a format this project
promises stability on, never an artifact. Artifacts carry a fingerprint,
which says "anyone can rebuild these bytes from the chain". A series
carries a `digest`, which says only "this is the file I used". The two
words are kept apart on purpose; see docs/external-inputs.md.

    <series>/series.csv     "ts,price" then one row per observation,
                            strictly ascending unix seconds, the price as a
                            plain decimal string (no exponent), exactly
                            the value the publisher gave
    <series>/series.json    currency, step, stale_after, coverage, row
                            count, the publisher's `origin` block, and the
                            sha256 digest of series.csv

Reading rule, the same for every consumer: the price valid at `ts` is the
LAST observation with `obs_ts <= ts` (never a look into the future), and
only if it is not older than `stale_after` seconds; otherwise there is
no price, and "no price" is said, never filled. A daily series applies
the price of day D to the whole of D; that convention is what `step`
declares, and it is printed beside every number that rests on it.

The format is in docs/formats/PriceSeries-v1.md.
"""

import bisect
import calendar
import csv
import json
import os
import time
from decimal import Decimal, InvalidOperation

from nodsig.artifact import producer
from nodsig.recio import atomic_json, sha_file

FORMAT_TAG = "price-series-v1"
CSV_NAME = "series.csv"
META_NAME = "series.json"
DEFAULT_STALE_STEPS = 3      # a price older than 3 steps is no price

# Field mappings for publishers whose files are common enough to name.
# Each is exactly what a reader would type by hand with `--ts-field` and
# friends; naming it only saves the typing and pins the published shape.
PRESETS = {
    # github.com/coinmetrics/data, csv/btc.csv: one row per UTC day
    "coinmetrics": {"ts_field": "time", "price_field": "PriceUSD",
                    "ts_format": "%Y-%m-%d", "step": 86400,
                    "publisher": "coinmetrics-community",
                    "url": "https://github.com/coinmetrics/data",
                    "license": "CC BY-NC 4.0"},
}


class PriceSeriesError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# canonical numbers and times
# ---------------------------------------------------------------------------

def canonical_price(text):
    """The price as the canonical decimal string the CSV stores.

    Plain notation, no exponent, no sign, no surrounding blanks, the
    digits the publisher gave (trailing zeros included: they are the
    publisher's precision, not ours). A price that is not a positive
    finite decimal is refused: a zero or negative price is not an
    observation, and keeping it would let "no price" hide as a number."""
    try:
        d = Decimal(text.strip())
    except (InvalidOperation, AttributeError):
        raise PriceSeriesError(f"not a decimal price: {text!r}")
    if not d.is_finite() or d <= 0:
        raise PriceSeriesError(f"not a positive finite price: {text!r}")
    return f"{d:f}"


def parse_ts(value, ts_format):
    """`ts_format`: `unix`, `unix_ms`, or a strptime pattern read as UTC."""
    if ts_format == "unix":
        return int(Decimal(str(value).strip()))
    if ts_format == "unix_ms":
        return int(Decimal(str(value).strip())) // 1000
    return calendar.timegm(time.strptime(str(value).strip(), ts_format))


# ---------------------------------------------------------------------------
# import: any CSV or JSON file -> the canonical shape, sealed by digest
# ---------------------------------------------------------------------------

def _records(path, records_path):
    """The iterable of rows in an external file. CSV rows are dicts keyed
    by header; JSON rows are whatever the list holds (dicts, or lists
    addressed by index), found under the dotted `records_path`."""
    if path.lower().endswith(".json"):
        with open(path) as f:
            data = json.load(f)
        for key in (records_path.split(".") if records_path else []):
            data = data[key]
        if not isinstance(data, list):
            raise PriceSeriesError("the JSON records path does not lead "
                                   "to a list")
        return data
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _field(row, name):
    if isinstance(row, dict):
        return row.get(name)
    return row[int(name)]


def import_series(src_path, out_dir, ts_field, price_field, ts_format,
                  step, publisher, url="", license_="unknown", note="",
                  currency="USD", stale_after=None, records_path=None,
                  fetched_at=None):
    """Convert one external file into `<out_dir>/series.csv` + series.json.

    Rows with an empty price are skipped (a publisher's way of saying the
    market did not exist yet). Rows are sorted by time; two observations
    at the same second keep the first, so the output is strictly
    ascending and the file is a total order. Returns the metadata."""
    step = int(step)
    if step <= 0:
        raise PriceSeriesError("step must be a positive number of seconds")
    stale_after = int(stale_after) if stale_after is not None \
        else DEFAULT_STALE_STEPS * step
    rows = []
    for row in _records(src_path, records_path):
        raw_price = _field(row, price_field)
        if raw_price in (None, ""):
            continue
        rows.append((parse_ts(_field(row, ts_field), ts_format),
                     canonical_price(str(raw_price))))
    if not rows:
        raise PriceSeriesError(f"no priced rows in {os.path.basename(src_path)}")
    rows.sort(key=lambda r: r[0])
    dedup = [rows[0]]
    for r in rows[1:]:
        if r[0] > dedup[-1][0]:
            dedup.append(r)
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, CSV_NAME)
    tmp = csv_path + ".tmp"
    with open(tmp, "w", newline="") as f:
        f.write("ts,price\n")
        for ts, price in dedup:
            f.write(f"{ts},{price}\n")
    os.replace(tmp, csv_path)
    meta = {
        "format": FORMAT_TAG,
        "currency": currency,
        "step": step,
        "stale_after": stale_after,
        "rule": ("price at ts = last row with row.ts <= ts, and only if "
                 "ts - row.ts <= stale_after; otherwise no price"),
        "rows": len(dedup),
        "coverage": {"from": dedup[0][0], "to": dedup[-1][0]},
        "origin": {"publisher": publisher, "url": url, "license": license_,
                   "file": os.path.basename(src_path),
                   "fields": {"ts": ts_field, "price": price_field,
                              "ts_format": ts_format},
                   "fetched_at": fetched_at, "note": note},
        "file": CSV_NAME,
        "digest": sha_file(csv_path),
        "imported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "producer": producer(),
    }
    atomic_json(os.path.join(out_dir, META_NAME), meta)
    return meta


# ---------------------------------------------------------------------------
# reading
# ---------------------------------------------------------------------------

def load_meta(series_dir):
    path = os.path.join(series_dir, META_NAME)
    if not os.path.exists(path):
        raise PriceSeriesError(f"no {META_NAME} in {series_dir}: not a "
                               "price series (run `price import`)")
    with open(path) as f:
        meta = json.load(f)
    if meta.get("format") != FORMAT_TAG:
        raise PriceSeriesError(f"not a {FORMAT_TAG} series: {series_dir}")
    return meta


class Quote:
    """One answer of a series: the observation used, its price as a
    Decimal, and which series (by name) and step it came from."""
    __slots__ = ("ts_used", "price", "currency", "series", "step")

    def __init__(self, ts_used, price, currency, series, step):
        self.ts_used = ts_used
        self.price = price
        self.currency = currency
        self.series = series
        self.step = step

    def __repr__(self):
        return (f"Quote(ts_used={self.ts_used}, price={self.price}, "
                f"{self.currency}, series={self.series!r}, step={self.step})")


class Series:
    """A sealed series in memory. Opening it checks the digest: a series
    whose bytes moved under its metadata would otherwise answer with the
    authority of the name it no longer matches."""

    def __init__(self, series_dir, check_digest=True):
        self.dir = series_dir
        self.meta = load_meta(series_dir)
        csv_path = os.path.join(series_dir, self.meta["file"])
        if check_digest and sha_file(csv_path) != self.meta["digest"]:
            raise PriceSeriesError(
                f"{csv_path}: digest differs from {META_NAME}; the file "
                "changed after it was imported")
        self.ts = []
        self.price = []
        with open(csv_path, newline="") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header != ["ts", "price"]:
                raise PriceSeriesError(f"{csv_path}: header is not ts,price")
            last = None
            for n, row in enumerate(reader, 2):
                if len(row) != 2:
                    raise PriceSeriesError(f"{csv_path}:{n}: not two fields")
                ts = int(row[0])
                if last is not None and ts <= last:
                    raise PriceSeriesError(f"{csv_path}:{n}: ts not "
                                           "strictly ascending")
                last = ts
                self.ts.append(ts)
                self.price.append(Decimal(row[1]))
        if len(self.ts) != self.meta["rows"]:
            raise PriceSeriesError(f"{csv_path}: {len(self.ts)} rows, "
                                   f"{META_NAME} says {self.meta['rows']}")
        self.step = int(self.meta["step"])
        self.stale_after = int(self.meta["stale_after"])
        self.currency = self.meta["currency"]
        self.name = self.meta["origin"]["publisher"]
        self.digest = self.meta["digest"]

    def coverage(self):
        return self.ts[0], self.ts[-1]

    def at(self, ts):
        """The Quote valid at `ts`, or None (before the series, or stale)."""
        i = bisect.bisect_right(self.ts, ts) - 1
        if i < 0 or ts - self.ts[i] > self.stale_after:
            return None
        return Quote(self.ts[i], self.price[i], self.currency, self.name,
                     self.step)

    def declared(self, order):
        """What a consumer writes down about this series as a parent."""
        return {"order": order, "publisher": self.name,
                "digest": self.digest, "currency": self.currency,
                "step": self.step, "stale_after": self.stale_after,
                "rows": len(self.ts),
                "coverage": dict(self.meta["coverage"]),
                "origin": dict(self.meta["origin"])}


def open_series(dirs):
    """Open several series meant to be asked in order. They must agree on
    the currency: a table mixing two currencies under one column would be
    a number that looks like a price."""
    series = [Series(d) for d in dirs]
    if not series:
        raise PriceSeriesError("at least one series is required")
    currencies = {s.currency for s in series}
    if len(currencies) > 1:
        raise PriceSeriesError(f"the series disagree on the currency: "
                               f"{sorted(currencies)}")
    return series


def quote_first(series, ts):
    """The first series in order that answers at `ts`: (order 1-based,
    Quote), or (0, None). The order is the consumer's declared choice:
    a finer series placed before a coarser one, for example."""
    for k, s in enumerate(series, 1):
        q = s.at(ts)
        if q is not None:
            return k, q
    return 0, None


# ---------------------------------------------------------------------------
# verify: the file against its metadata
# ---------------------------------------------------------------------------

def verify_series(series_dir, out=None):
    """Digest, header, strict order, row count, positive prices: what
    `Series` checks on open, reported. Returns the Series."""
    import sys
    out = out or sys.stdout
    s = Series(series_dir)
    lo, hi = s.coverage()
    if (lo, hi) != (s.meta["coverage"]["from"], s.meta["coverage"]["to"]):
        raise PriceSeriesError("coverage in series.json does not match "
                               "the rows")
    bad = [i for i, p in enumerate(s.price) if p <= 0]
    if bad:
        raise PriceSeriesError(f"{len(bad)} non-positive price(s), the "
                               f"first at row {bad[0] + 2}")
    print(f"price series ok: {s.name}, {len(s.ts):,} rows, {s.currency}, "
          f"step {s.step} s, stale after {s.stale_after} s", file=out)
    print(f"  coverage {_iso(lo)} .. {_iso(hi)}", file=out)
    print(f"  digest   {s.digest}", file=out)
    print("  (a digest identifies this file; it is not a fingerprint and "
          "nothing on the chain can reproduce it)", file=out)
    return s


def _iso(ts):
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(ts))
