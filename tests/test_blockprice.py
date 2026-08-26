#!/usr/bin/env python3
"""PriceSeries-v1 and BlockPrice-v1: the external inputs.

Synthetic throughout: a publisher's file written by the test, the
derived suite's five-block chain (header times 1_700_000_000 + h). The
block prices are worked out by hand from the reading rule and pinned as
bytes, so the test is a model and not a re-run of the code.

Covered:
- import: canonical decimal strings, empty prices skipped, duplicates at
  one second collapsed, JSON by dotted path, a preset's mapping, a zero
  price refused, the digest over the exact bytes;
- the reading rule: before the series, exact hit, last-before, stale;
- build matches the hand model, two series in order, and the `series`
  byte says which one answered;
- a rebuild over a rewritten past reports the changed heights;
- verify: structural, parents confirmed, a tampered table and a foreign
  index refused;
- daily: the three kinds, dense over the days;
- the command line, end to end.

Usage:
    python3 test_blockprice.py     # prints PASS or fails loudly
    (also runs under pytest via the shared conftest fixtures)
"""

import io
import json
import os
import sys
import tempfile
from decimal import Decimal

import pytest

from nodsig import blockprice as bp
from nodsig import outpoint_index as oi
from nodsig import priceseries as ps
import test_derivatives as td


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


T0 = 1_700_000_000          # header time of height h is T0 + h
DAY = 86400


def write_csv(path, rows, header="time,price"):
    with open(path, "w") as f:
        f.write(header + "\n")
        for r in rows:
            f.write(",".join(str(x) for x in r) + "\n")


def series_a(tmp, name="a", rows=None):
    """Hourly: 100.50 from T0-100, 200 from T0+3. Heights 1,2 -> 100.50;
    3,4,5 -> 200."""
    src = os.path.join(tmp, name + ".csv")
    write_csv(src, rows or [(T0 - 100, "100.50"), (T0 + 3, "200")])
    out = os.path.join(tmp, "series_" + name)
    ps.import_series(src, out, "time", "price", "unix", 3600, "pub-" + name,
                     license_="test")
    return out


def rec(price, k):
    return bp.encode(Decimal(price), k)


@pytest.fixture
def built(tmp):
    blocks, _ = td.derived_chain()
    _graph, index = td.build_index(tmp, blocks, name="bp_index")
    return tmp, index


# ---------------------------------------------------------------------------
# import and the reading rule
# ---------------------------------------------------------------------------

def test_import_canonical(tmp):
    src = os.path.join(tmp, "pub.csv")
    write_csv(src, [("2010-07-18", "0.0858"), ("2010-07-17", ""),
                    ("2010-07-19", " 8.5E-2 "), ("2010-07-19", "9"),
                    ("2010-07-20", "1.0")], header="time,PriceUSD")
    out = os.path.join(tmp, "s")
    meta = ps.import_series(src, out, "time", "PriceUSD", "%Y-%m-%d",
                            86400, "pub", license_="CC BY-NC 4.0")
    with open(os.path.join(out, ps.CSV_NAME)) as f:
        text = f.read()
    check(text == "ts,price\n1279411200,0.0858\n1279497600,0.085\n"
                  "1279584000,1.0\n",
          f"canonical csv differs:\n{text}")
    check(meta["rows"] == 3 and meta["stale_after"] == 3 * 86400,
          "rows or stale_after wrong")
    check(meta["origin"]["license"] == "CC BY-NC 4.0", "origin lost")
    # the digest is over the exact bytes, and verify agrees with it
    s = ps.verify_series(out, out=io.StringIO())
    check(s.digest == meta["digest"], "digest mismatch")
    # a zero price is refused, not stored
    write_csv(src, [("2010-07-18", "0")], header="time,PriceUSD")
    with pytest.raises(ps.PriceSeriesError):
        ps.import_series(src, os.path.join(tmp, "z"), "time", "PriceUSD",
                         "%Y-%m-%d", 86400, "pub")


def test_import_json_and_preset(tmp):
    src = os.path.join(tmp, "pub.json")
    with open(src, "w") as f:
        json.dump({"data": {"ohlc": [
            {"timestamp": "1313000000", "close": "10.5"},
            {"timestamp": "1313003600", "close": "11"}]}}, f)
    meta = ps.import_series(src, os.path.join(tmp, "j"), "timestamp",
                            "close", "unix", 3600, "pub-j",
                            records_path="data.ohlc")
    check(meta["rows"] == 2 and meta["coverage"]["to"] == 1313003600,
          "json import wrong")
    # lists addressed by index, milliseconds
    with open(src, "w") as f:
        json.dump([[1313000000000, 10.5], [1313003600000, 11]], f)
    meta = ps.import_series(src, os.path.join(tmp, "j2"), "0", "1",
                            "unix_ms", 3600, "pub-j")
    check(meta["coverage"] == {"from": 1313000000, "to": 1313003600},
          "unix_ms import wrong")
    # the preset maps the CoinMetrics community file
    src = os.path.join(tmp, "btc.csv")
    write_csv(src, [("2010-07-18", "0.0858")], header="time,PriceUSD")
    out = os.path.join(tmp, "cm")
    rc = bp.main(["import", "--from", src, "--out", out,
                  "--preset", "coinmetrics"])
    check(rc == 0, "preset import failed")
    meta = ps.load_meta(out)
    check(meta["origin"]["publisher"] == "coinmetrics-community"
          and meta["step"] == 86400, "preset mapping not applied")


def test_reading_rule(tmp):
    s = ps.Series(series_a(tmp))
    check(s.at(T0 - 101) is None, "before the series must be None")
    q = s.at(T0 - 100)
    check(q.price == Decimal("100.50") and q.ts_used == T0 - 100,
          "exact hit")
    check(s.at(T0 + 2).price == Decimal("100.50"), "last-before")
    check(s.at(T0 + 3).price == Decimal("200"), "new observation at ts")
    check(s.at(T0 + 3 + 3 * 3600).price == Decimal("200"), "edge of stale")
    check(s.at(T0 + 4 + 3 * 3600) is None, "stale must be None")
    # a file changed under its metadata is refused on open
    with open(os.path.join(s.dir, ps.CSV_NAME), "a") as f:
        f.write(f"{T0 + 10},300\n")
    with pytest.raises(ps.PriceSeriesError):
        ps.Series(s.dir)


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def test_build_matches_model(built):
    tmp, index = built
    a = series_a(tmp)
    out = os.path.join(tmp, "bp")
    meta = bp.run_build(index, out, [a], out=io.StringIO())
    with open(os.path.join(out, bp.BIN_NAME), "rb") as f:
        data = f.read()
    want = (rec("100.50", 1) * 2 + rec("200", 1) * 3)
    check(data == want, "table differs from the hand model")
    check(meta["priced"] == 5 and meta["priced_from"] == 1, "counts")
    check(meta["parents"]["index"]["fingerprint"]
          == oi._load_manifest(index)["fingerprint"], "parent index")
    check(meta["parents"]["series"][0]["digest"] == ps.load_meta(a)["digest"],
          "parent series digest")
    table = bp.BlockPrice(out)
    check(table.at(2) == (Decimal("100.5"), "pub-a"), "at(2)")
    check(table.at(5) == (Decimal("200"), "pub-a"), "at(5)")
    check(table.at(6) is None, "beyond the table")
    # the same inputs give the same digest on a second build elsewhere
    meta2 = bp.run_build(index, os.path.join(tmp, "bp2"), [a],
                         out=io.StringIO())
    check(meta2["digest"] == meta["digest"], "not deterministic")


def test_two_series_in_order(built):
    tmp, index = built
    fine = series_a(tmp, "fine", rows=[(T0 + 4, "400")])      # h4, h5 only
    coarse = series_a(tmp, "coarse")
    out = os.path.join(tmp, "bp")
    bp.run_build(index, out, [fine, coarse], out=io.StringIO())
    with open(os.path.join(out, bp.BIN_NAME), "rb") as f:
        data = f.read()
    want = rec("100.50", 2) * 2 + rec("200", 2) + rec("400", 1) * 2
    check(data == want, "the order of the series is not honoured")
    # a series in another currency is refused
    src = os.path.join(tmp, "eur.csv")
    write_csv(src, [(T0, "1")])
    eur = os.path.join(tmp, "series_eur")
    ps.import_series(src, eur, "time", "price", "unix", 3600, "pub-eur",
                     currency="EUR")
    with pytest.raises(bp.BlockPriceError):
        bp.run_build(index, os.path.join(tmp, "bp_mix"), [fine, eur],
                     out=io.StringIO())


def test_rebuild_reports_a_rewritten_past(built):
    tmp, index = built
    a = series_a(tmp)
    out = os.path.join(tmp, "bp")
    bp.run_build(index, out, [a], out=io.StringIO())
    # the publisher corrects the second observation
    series_a(tmp, rows=[(T0 - 100, "100.50"), (T0 + 3, "201")])
    meta = bp.run_build(index, out, [a], out=io.StringIO())
    check(meta["prefix"] == {"previous_heights": 5, "changed": 3,
                             "changed_heights": [3, 4, 5]},
          f"prefix report wrong: {meta['prefix']}")
    # and an unchanged rebuild reports nothing changed
    meta = bp.run_build(index, out, [a], out=io.StringIO())
    check(meta["prefix"]["changed"] == 0, "a same rebuild must change 0")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def test_verify(built):
    tmp, index = built
    a = series_a(tmp)
    out = os.path.join(tmp, "bp")
    bp.run_build(index, out, [a], out=io.StringIO())
    log = io.StringIO()
    bp.run_verify(out, out=log)
    check("declared, not confirmed" in log.getvalue(), "without parents")
    log = io.StringIO()
    bp.run_verify(out, index_dir=index, series_dirs=[a], out=log)
    check("parents confirmed" in log.getvalue(), "with parents")
    # a foreign index (a shorter build) is not the declared parent
    blocks, _ = td.derived_chain()
    _g, other = td.build_index(tmp, blocks, name="bp_other", end=4)
    with pytest.raises(bp.BlockPriceError):
        bp.run_verify(out, index_dir=other, series_dirs=[a],
                      out=io.StringIO())
    # a tampered record: digest check catches it on open
    path = os.path.join(out, bp.BIN_NAME)
    with open(path, "r+b") as f:
        f.seek(9 * 2 + 7)
        f.write(b"\x01")
    with pytest.raises(bp.BlockPriceError):
        bp.run_verify(out, out=io.StringIO())


# ---------------------------------------------------------------------------
# daily
# ---------------------------------------------------------------------------

def test_daily_kinds(built):
    tmp, index = built
    # only heights 3 and 5 priced: the series starts at T0+3 and is
    # stale by T0+4 (stale_after 0 is not allowed, so use 1 second)
    src = os.path.join(tmp, "p.csv")
    write_csv(src, [(T0 + 3, "10"), (T0 + 5, "30")])
    s = os.path.join(tmp, "series_p")
    ps.import_series(src, s, "time", "price", "unix", 1, "pub-p",
                     stale_after=0)
    out = os.path.join(tmp, "bp")
    bp.run_build(index, out, [s], out=io.StringIO())
    table = bp.BlockPrice(out)
    check([k for _p, k in table.rows()] == [0, 0, 1, 0, 1], "priced set")
    A = (T0 // DAY) * DAY
    times = [A, A + 2 * DAY, A + 2 * DAY + 1, A + 4 * DAY, A + 5 * DAY]
    rows = bp.daily_rows(table, times)
    got = [(r[0][-5:], r[1], r[2], r[3], r[4]) for r in rows]
    d = lambda i: __import__("time").strftime("%m-%d", __import__("time").gmtime(A + i * DAY))
    want = [(d(0), 1, None, "none", None),
            (d(1), 0, None, "none", None),
            (d(2), 2, Decimal(10), "measured", 0),
            (d(3), 0, Decimal(10), "carried", 1),
            (d(4), 1, Decimal(10), "carried", 2),
            (d(5), 1, Decimal(30), "measured", 0)]
    check(got == want, f"daily rows differ:\n{got}\n{want}")
    check(rows[2][7] == "pub-p" and rows[5][5] == Decimal(30), "extras")
    # through the command, against the real header times (one day)
    csv_path = os.path.join(tmp, "daily.csv")
    rc = bp.main(["daily", "--blockprice", out, "--index", index,
                  "--csv", csv_path])
    check(rc == 0, "daily command failed")
    with open(csv_path) as f:
        lines = f.read().splitlines()
    check(lines[-1].endswith(",5,20.000000,measured,0,10.000000,30.000000,pub-p"),
          f"csv last line: {lines[-1]}")
    check(any("corrected the past" in l for l in lines if l.startswith("#")),
          "the limit must be printed in the csv")


# ---------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------

def test_cli_end_to_end(built, capsys):
    tmp, index = built
    src = os.path.join(tmp, "pub.csv")
    write_csv(src, [(T0 - 100, "100.50"), (T0 + 3, "200")])
    s = os.path.join(tmp, "s")
    out = os.path.join(tmp, "bp")
    check(bp.main(["import", "--from", src, "--out", s, "--ts-field", "time",
                   "--price-field", "price", "--step", "3600",
                   "--publisher", "pub", "--license", "test"]) == 0, "import")
    check(bp.main(["series-verify", "--series", s]) == 0, "series-verify")
    check(bp.main(["build", "--index", index, "--out", out,
                   "--series", s]) == 0, "build")
    check(bp.main(["stats", "--blockprice", out]) == 0, "stats")
    check(bp.main(["verify", "--blockprice", out, "--index", index,
                   "--series", s]) == 0, "verify")
    check(bp.main(["at", "--blockprice", out, "4"]) == 0, "at")
    text = capsys.readouterr().out
    check("height 4: 200 USD" in text, f"at output: {text[-200:]}")
    check("digest" in text and "fingerprint: " not in text.replace(
        "parent index", ""), "a table prints digests, not a fingerprint")
    # an error is a message and exit 1, not a traceback
    check(bp.main(["at", "--blockprice", out, "9"]) == 1, "out of range")
    check(bp.main(["import", "--from", src, "--out", s + "2",
                   "--ts-field", "time", "--price-field", "price"]) == 1,
          "missing publisher must fail")


def test_supply_with_a_price(built):
    """The first consumer: fees in the series' currency, block by block.
    Model fees (td.FEES, by tx ordinal) per height: h3 has t2 (1 sat),
    h4 has t3 (1), h5 has t4 (3), h2 has t1 (S-10)."""
    from nodsig import derivatives as dv
    tmp, index = built
    derived = os.path.join(tmp, "derived")
    dv.run_build(index, derived)
    a = series_a(tmp)
    table = os.path.join(tmp, "bp")
    bp.run_build(index, table, [a], out=io.StringIO())
    log = io.StringIO()
    csv_path = os.path.join(tmp, "supply.csv")
    dv.run_supply(derived, index, csv_path=csv_path, price_dir=table,
                  out=log)
    text = log.getvalue()
    # h2: (S-10) sat at 100.50; h3: 1 sat at 200; h4: 1 at 200; h5: 3 at 200
    want = (Decimal(td.S - 10) * Decimal("100.50")
            + Decimal(5) * Decimal(200)) / Decimal(10 ** 8)
    check(f"{want:,.2f} USD over 5 priced block(s)" in text,
          f"fiat total missing or wrong:\n{text}")
    check("corrected the past" in text, "the limit must be printed")
    with open(csv_path) as f:
        lines = f.read().splitlines()
    check(lines[0].endswith(",price_usd,fees_usd"), lines[0])
    check(lines[5].endswith(",200,0.000006"), lines[5])
    # a table built on another index is refused
    blocks, _ = td.derived_chain()
    _g, other = td.build_index(tmp, blocks, name="bp_other", end=4)
    other_table = os.path.join(tmp, "bp_other_table")
    bp.run_build(other, other_table, [a], out=io.StringIO())
    with pytest.raises(dv.OutpointError):
        dv.run_supply(derived, index, price_dir=other_table,
                      out=io.StringIO())


def test_timeline_with_a_price(built):
    """The timeline's price channel against the hand model: every
    fixture height has a price (1,2 at 100.50; 3,4,5 at 200), so
    sats_priced equals sats in every cell and the at-creation cost is
    Σ value*price(create_height), spelled out per cell below. The
    price-free columns must be byte-identical to the unpriced run."""
    from nodsig import derivatives as dv
    tmp, index = built
    derived = os.path.join(tmp, "derived")
    dv.run_build(index, derived)
    a = series_a(tmp)
    table = os.path.join(tmp, "bp")
    bp.run_build(index, table, [a], out=io.StringIO())
    out_dir = os.path.join(tmp, "timeline_priced")
    log = io.StringIO()
    dv.run_timeline(derived, index, out_dir, grid=2, price_dir=table,
                    out=log)
    S = td.S
    windows = open(os.path.join(out_dir,
                                dv.WINDOWS_CSV)).read().splitlines()
    check(windows == [
        "create_from,spend_from,outputs,sats,"
        "sat_heights_created,sat_heights_spent,"
        "sats_priced,cost_at_creation",
        # 50 BTC at 100.50 = 5025; at 200 = 10000
        f"0,,1,{S},{S},0,{S},5025.000000",
        f"2,,1,{S},{3 * S},0,{S},10000.000000",
        # out1 (S) and out3 (3 sat) both created at h2, price 100.50
        f"2,2,2,{S + 3},{2 * S + 6},{2 * S + 9},{S + 3},5025.000003",
        # out2: 7 sat at 100.50, out5: 2 sat at 200
        "2,4,2,9,20,38,9,0.000011",
        # out6, out8 (50 BTC each) and out9 (5 sat), all at 200
        f"4,,3,{2 * S + 5},{9 * S + 25},0,{2 * S + 5},20000.000010",
        # out7: 6 sat at 200
        "4,4,1,6,24,30,6,0.000012",
    ], f"priced windows differ from the hand model:\n{windows}")
    meta = json.load(open(os.path.join(out_dir, dv.TIMELINE_META)))
    check(meta["build"]["price"]["currency"] == "USD"
          and meta["build"]["price"]["digest"],
          "the external input must be declared in the meta")
    check("external input" in log.getvalue(),
          "the summary must say what the cost figures rest on")
    # The price-free columns must not move: same pass, same folds.
    plain_dir = os.path.join(tmp, "timeline_plain")
    dv.run_timeline(derived, index, plain_dir, grid=2,
                    out=io.StringIO())
    plain = open(os.path.join(plain_dir,
                              dv.WINDOWS_CSV)).read().splitlines()
    stripped = [",".join(r.split(",")[:6]) for r in windows]
    check(stripped == plain,
          "the price channel must only append columns, never change one")
    check(open(os.path.join(plain_dir, dv.BANDS_CSV)).read()
          == open(os.path.join(out_dir, dv.BANDS_CSV)).read(),
          "bands do not depend on the price at all")
    # a table built on another index is refused, like supply's
    blocks, _ = td.derived_chain()
    _g, other = td.build_index(tmp, blocks, name="tl_other", end=4)
    other_table = os.path.join(tmp, "tl_other_table")
    bp.run_build(other, other_table, [a], out=io.StringIO())
    with pytest.raises(dv.OutpointError):
        dv.run_timeline(derived, index, os.path.join(tmp, "tl_x"),
                        grid=2, price_dir=other_table, out=io.StringIO())


def main():
    with tempfile.TemporaryDirectory() as tmp:
        test_import_canonical(tmp)
        test_import_json_and_preset(tmp)
        test_reading_rule(tmp)
    for t in (test_build_matches_model, test_two_series_in_order,
              test_rebuild_reports_a_rewritten_past, test_verify,
              test_daily_kinds, test_supply_with_a_price):
        with tempfile.TemporaryDirectory() as tmp:
            blocks, _ = td.derived_chain()
            _g, index = td.build_index(tmp, blocks, name="bp_index")
            t((tmp, index))
    print("PASS: price series and block price")


if __name__ == "__main__":
    main()
