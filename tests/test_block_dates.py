#!/usr/bin/env python3
"""
test_block_dates.py — self-test for block_dates.py, no node needed.

A fake client returns canned getblockhash/getblockheader replies; the
test checks the height→date mapping, the UTC formatting, and the guard
that refuses a header whose height is not the one asked for.

Usage:
    python3 test_block_dates.py        # prints PASS or fails loudly
"""

import sys

from nodsig import block_dates as bd
from nodsig import reuse_scan as rs


def check(cond, msg):
    if not cond:
        print(f"FAIL: {msg}")
        sys.exit(1)


class FakeClient:
    """Answers getblockhash/getblockheader from a fixed height→(time)
    table. `wrong_height` forces a header to report the wrong height, to
    exercise the mismatch guard."""

    def __init__(self, table, wrong_height=None):
        self.table = table                       # height -> (time, mediantime)
        self.wrong = wrong_height

    def batch(self, calls):
        out = []
        for method, params in calls:
            if method == "getblockhash":
                out.append(f"hash{params[0]}")
            elif method == "getblockheader":
                h = int(params[0].removeprefix("hash"))
                t, mt = self.table[h]
                reported = self.wrong if self.wrong is not None else h
                out.append({"height": reported, "time": t, "mediantime": mt})
            else:
                raise AssertionError(f"unexpected method {method}")
        return out


def test_mapping():
    # 1231006505 = 2009-01-03 (genesis); 1612962571 = 2021-02-10
    table = {0: (1231006505, 1231006505), 670000: (1612962571, 1612900000)}
    rows = bd.fetch_dates(FakeClient(table), [0, 670000])
    check(rows == [(0, 1231006505, 1231006505),
                   (670000, 1612962571, 1612900000)], f"rows: {rows}")
    check(bd.utc_date(1231006505) == "2009-01-03", "genesis date")
    check(bd.utc_date(1612962571) == "2021-02-10", "height 670000 date")
    print("ok  mapping: heights → header time → UTC date")


def test_height_guard():
    table = {800000: (1690168629, 1690100000)}
    try:
        bd.fetch_dates(FakeClient(table, wrong_height=799999), [800000])
        print("FAIL: mismatched height accepted")
        sys.exit(1)
    except rs.ScanError:
        print("ok  guard: header with the wrong height is rejected")


def main():
    test_mapping()
    test_height_guard()
    print("PASS: block_dates maps heights to confirmed dates and refuses "
          "a mismatched node.")


if __name__ == "__main__":
    main()
