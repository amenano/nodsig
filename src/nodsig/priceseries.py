#!/usr/bin/env python3
"""PriceSeries-v2: an external price series, in one canonical shape.

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
                            count, what each observation IS and WHERE its
                            stamp falls (`observation`), the publisher's
                            `origin` block, and the sha256 digest of
                            series.csv

Reading rule, the same for every consumer: the price valid at `ts` is the
LAST observation with `obs_ts <= ts`, and only if it is not older than
`stale_after` seconds; otherwise there is no price, and "no price" is
said, never filled. A daily series applies the observation of day D to
the whole of D. That is never a look into the future of the STAMPS; it
can be one of the INFORMATION: a daily close stamped at the start of its
day is a number fixed up to 24 hours after the blocks it is applied to.
The v1 promised "never a look into the future" with no field that could
tell a close from an open. `observation` says what the number is and
where its stamp falls, and every table built from a series carries the
look-ahead that follows (`lookahead_s`), printed beside every fiat
figure. The number is not shifted: the literature applies the day's
price to the day, and a builder who wants a lag applies it to the series
and the digest says so.

The format is in docs/formats/PriceSeries-v2.md.
"""

import bisect
import calendar
import csv
import json
import os
import time
from decimal import Decimal, InvalidOperation

from nodsig.artifact import producer
from nodsig.recio import (atomic_json, checked_name, durable_replace,
                          read_json, sha_file)

FORMAT_TAG = "price-series-v2"
CSV_NAME = "series.csv"
META_NAME = "series.json"
DEFAULT_STALE_STEPS = 3      # a price older than 3 steps is no price

# What an observation is over its period, and where its stamp falls.
# Closed lists: a consumer that met a value outside them would have to
# guess, and a guess about the semantics of a price is the defect this
# field exists to retire.
OBSERVATION_KINDS = ("open", "close", "mean", "vwap", "spot", "unknown")
OBSERVATION_STAMPS = ("period_start", "period_end", "instant")

# Field mappings for publishers whose files are common enough to name.
# Each is exactly what a reader would type by hand with `--ts-field` and
# friends; naming it only saves the typing and pins the published shape.
# The observation a preset pins is a statement about the publisher's
# documentation, and `observation_source` says where to read it.
PRESETS = {
    # github.com/coinmetrics/data, csv/btc.csv: one row per UTC day,
    # `PriceUSD` documented as a reference rate fixed at the end of the
    # day and stamped with the day's date.
    "coinmetrics": {"ts_field": "time", "price_field": "PriceUSD",
                    "ts_format": "%Y-%m-%d", "step": 86400,
                    "publisher": "coinmetrics-community",
                    "url": "https://github.com/coinmetrics/data",
                    "license": "CC BY-NC 4.0",
                    "observation_kind": "close",
                    "observation_stamp": "period_start",
                    "observation_source": (
                        "the publisher's data dictionary for PriceUSD, "
                        "read at import; confirm it against the file "
                        "fetched")},
}


def lookahead_s(observation, step):
    """How far after a block the number applied to it may have been
    fixed: `step` for a close, mean or vwap stamped at the start of its
    period; 0 for an open, for a stamp at the end of the period, or for
    an instant; None when the kind is unknown."""
    kind, stamp = observation["kind"], observation["stamp"]
    if kind == "unknown":
        return None
    if kind == "open" or stamp in ("period_end", "instant"):
        return 0
    return int(step)


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
                  fetched_at=None, observation_kind=None,
                  observation_stamp=None, observation_source=""):
    """Convert one external file into `<out_dir>/series.csv` + series.json.

    Rows with an empty price are skipped (a publisher's way of saying the
    market did not exist yet). Rows are sorted by time; two observations
    at the same second keep the first, so the output is strictly
    ascending and the file is a total order. The observation's kind and
    stamp are required, like the publisher: a series that cannot say is
    imported as `unknown`, on purpose and in writing. Returns the
    metadata."""
    step = int(step)
    if step <= 0:
        raise PriceSeriesError("step must be a positive number of seconds")
    if observation_kind not in OBSERVATION_KINDS:
        raise PriceSeriesError(
            f"the observation kind is required, one of "
            f"{', '.join(OBSERVATION_KINDS)}: what the publisher's number "
            "is over its period (`unknown` if the publisher does not say)")
    if observation_stamp not in OBSERVATION_STAMPS:
        raise PriceSeriesError(
            f"the observation stamp is required, one of "
            f"{', '.join(OBSERVATION_STAMPS)}: where the timestamp falls "
            "relative to the period the number describes")
    observation = {"kind": observation_kind, "stamp": observation_stamp}
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
    durable_replace(tmp, csv_path)
    meta = {
        "format": FORMAT_TAG,
        "currency": currency,
        "step": step,
        "stale_after": stale_after,
        "observation": observation,
        "rule": ("price at ts = last row with row.ts <= ts, and only if "
                 "ts - row.ts <= stale_after; otherwise no price; a "
                 "number stamped at the start of its period may have "
                 "been fixed up to lookahead_s after ts"),
        "rows": len(dedup),
        "coverage": {"from": dedup[0][0], "to": dedup[-1][0]},
        "origin": {"publisher": publisher, "url": url, "license": license_,
                   "file": os.path.basename(src_path),
                   "fields": {"ts": ts_field, "price": price_field,
                              "ts_format": ts_format},
                   "fetched_at": fetched_at, "note": note,
                   "observation_source": observation_source},
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
    meta = read_json(path, PriceSeriesError)
    if meta.get("format") != FORMAT_TAG:
        raise PriceSeriesError(
            f"not a {FORMAT_TAG} series: {series_dir} says "
            f"{meta.get('format')!r}; a series of an earlier format is "
            "imported again from the publisher's file (seconds, same "
            "digest), with its observation kind and stamp")
    obs = meta.get("observation") or {}
    if (obs.get("kind") not in OBSERVATION_KINDS
            or obs.get("stamp") not in OBSERVATION_STAMPS):
        raise PriceSeriesError(
            f"{path}: the observation is missing or not one of the "
            "declared values; no default is taken, because a default on "
            "the semantics of a price is the defect the field retired")
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
        csv_path = os.path.join(
            series_dir, checked_name(self.meta["file"], PriceSeriesError))
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
        self.observation = dict(self.meta["observation"])
        self.lookahead_s = lookahead_s(self.observation, self.step)

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
                "observation": dict(self.observation),
                "lookahead_s": self.lookahead_s,
                "rows": len(self.ts),
                "coverage": dict(self.meta["coverage"]),
                "origin": dict(self.meta["origin"])}

    def lookahead_sentence(self, order=None):
        """What a consumer prints beside a fiat figure that rests on
        this series: what the number could not have known at the
        block, in words, never a number shifted."""
        who = (f"series {order} ({self.name})" if order is not None
               else f"series {self.name}")
        kind, stamp = self.observation["kind"], self.observation["stamp"]
        if self.lookahead_s is None:
            return (f"{who} does not say what its observation is "
                    f"(kind unknown, stamp {stamp}): how far after a block "
                    "its number was fixed is not known")
        if self.lookahead_s == 0:
            return (f"{who} stamps its {kind} where it was fixed "
                    f"({stamp}): a block's price was known at the block")
        return (f"{who} stamps a {kind} of {self.step:,} s at the start of "
                f"its period: a block's price may be a number fixed up to "
                f"{self.lookahead_s / 3600:g} hours after the block")


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
    print(f"  observation {s.observation['kind']} stamped "
          f"{s.observation['stamp']}: {s.lookahead_sentence()}", file=out)
    print(f"  coverage {_iso(lo)} .. {_iso(hi)}", file=out)
    print(f"  digest   {s.digest}", file=out)
    print("  (a digest identifies this file; it is not a fingerprint and "
          "nothing on the chain can reproduce it)", file=out)
    return s


def _iso(ts):
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(ts))
