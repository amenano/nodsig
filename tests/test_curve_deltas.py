#!/usr/bin/env python3
"""
test_curve_deltas.py — collaudo of the curve delta tool.

Mirror-implementation style, like the other test files here: the
expected numbers are computed by hand in the fixtures, not by calling
the code under test twice. The fixture curve is synthetic (no chain
data involved: this tool is pure arithmetic on a CSV).
"""

import io
import os
import subprocess
import sys
import tempfile
import unittest

from nodsig import curve_deltas  # noqa: E402

# The package is imported in-process via pytest's `pythonpath = ["src"]`; a
# subprocess is a fresh interpreter that does not inherit it, so the CLI
# end-to-end test below re-exports src/ on PYTHONPATH and runs the tool as a
# module (`-m nodsig.curve_deltas`).
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "src")
_ENV = {**os.environ,
        "PYTHONPATH": os.pathsep.join([_SRC, os.environ.get("PYTHONPATH", "")])}

HEADER = ("height,p2pkh_hits,p2pkh_satoshis,p2sh_hits,p2sh_satoshis,"
          "p2wpkh_hits,p2wpkh_satoshis,p2wsh_hits,p2wsh_satoshis,"
          "fingerprint\n")

# Three checkpoints; only p2pkh and p2wsh move, and by hand:
#   10k: p2pkh (2, 1000)                     → delta (2, 1000)
#   20k: p2pkh (5, 7000)                     → delta (3, 6000)
#   30k: p2pkh (5, 7000), p2wsh (1, 250)     → delta p2wsh (1, 250)
FIXTURE = (HEADER
           + "10000,2,1000,0,0,0,0,0,0,aa\n"
           + "20000,5,7000,0,0,0,0,0,0,bb\n"
           + "30000,5,7000,0,0,0,0,1,250,cc\n")


def write_tmp(text):
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


class TestReadCurve(unittest.TestCase):
    def test_rows_sorted_and_typed(self):
        path = write_tmp(FIXTURE)
        try:
            rows = curve_deltas.read_curve(path)
        finally:
            os.unlink(path)
        self.assertEqual([h for h, _ in rows], [10000, 20000, 30000])
        self.assertEqual(rows[1][1]["p2pkh"], (5, 7000))
        self.assertEqual(rows[2][1]["p2wsh"], (1, 250))

    def test_duplicate_height_last_wins(self):
        # The crash-between-curve-and-state case from the docstring:
        # height 20k appears twice, the resumed run's row must win.
        dup = (HEADER
               + "10000,2,1000,0,0,0,0,0,0,aa\n"
               + "20000,9,9999,0,0,0,0,0,0,STALE\n"
               + "20000,5,7000,0,0,0,0,0,0,bb\n")
        path = write_tmp(dup)
        try:
            rows = curve_deltas.read_curve(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][1]["p2pkh"], (5, 7000))

    def test_wrong_columns_fail_loudly(self):
        path = write_tmp("height,foo\n1,2\n")
        try:
            with self.assertRaises(curve_deltas.CurveError):
                curve_deltas.read_curve(path)
        finally:
            os.unlink(path)


class TestDeltas(unittest.TestCase):
    def rows(self, text=FIXTURE):
        path = write_tmp(text)
        try:
            return curve_deltas.read_curve(path)
        finally:
            os.unlink(path)

    def test_hand_computed_deltas(self):
        out = list(curve_deltas.deltas(self.rows()))
        self.assertEqual([(a, b) for a, b, _ in out],
                         [(0, 10000), (10000, 20000), (20000, 30000)])
        self.assertEqual(out[0][2]["p2pkh"], (2, 1000))
        self.assertEqual(out[1][2]["p2pkh"], (3, 6000))
        self.assertEqual(out[2][2]["p2pkh"], (0, 0))
        self.assertEqual(out[2][2]["p2wsh"], (1, 250))

    def test_monotonicity_enforced(self):
        shrinking = (HEADER
                     + "10000,5,7000,0,0,0,0,0,0,aa\n"
                     + "20000,2,1000,0,0,0,0,0,0,bb\n")
        with self.assertRaises(curve_deltas.CurveError):
            list(curve_deltas.deltas(self.rows(shrinking)))

    def test_totals(self):
        out = list(curve_deltas.deltas(self.rows()))
        self.assertEqual(curve_deltas.totals(out[1][2]), (3, 6000))


class TestOutputs(unittest.TestCase):
    def test_csv_roundtrip_by_hand(self):
        path = write_tmp(FIXTURE)
        try:
            intervals = list(curve_deltas.deltas(
                curve_deltas.read_curve(path)))
        finally:
            os.unlink(path)
        buf = io.StringIO()
        curve_deltas.write_csv(intervals, buf)
        # csv.writer ends rows with \r\n: strip each line before comparing
        lines = [l.strip() for l in buf.getvalue().strip().splitlines()]
        self.assertEqual(len(lines), 4)  # header + 3 intervals
        # second interval row, hand-checked: 3 new locks, 6000 sats
        self.assertIn("10000,20000,3,6000", lines[2])
        self.assertTrue(lines[2].endswith("3,6000"))  # totals columns

    def test_summary_mentions_lower_bound(self):
        path = write_tmp(FIXTURE)
        try:
            intervals = list(curve_deltas.deltas(
                curve_deltas.read_curve(path)))
        finally:
            os.unlink(path)
        buf = io.StringIO()
        curve_deltas.summarize(intervals, 2, buf)
        text = buf.getvalue()
        self.assertIn(">=", text)          # the claim stays a lower bound
        self.assertIn("p2pkh", text)
        self.assertIn("checkpoints: 3", text)

    def test_cli_end_to_end(self):
        src = write_tmp(FIXTURE)
        out = src + ".deltas"
        try:
            r = subprocess.run(
                [sys.executable, "-m", "nodsig.curve_deltas",
                 src, "--csv", out, "--top", "2"],
                capture_output=True, text=True, env=_ENV)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("cumulative:", r.stdout)
            with open(out) as f:
                self.assertEqual(len(f.read().strip().split("\n")), 4)
        finally:
            os.unlink(src)
            if os.path.exists(out):
                os.unlink(out)


if __name__ == "__main__":
    unittest.main()
