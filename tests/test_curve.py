"""Tests for curve.py: the text and the meta of a curve, written once.

What is pinned here, and why:

- the grid, the header and the row are the same function for the scan
  and for the derive, so the two roads meet byte for byte; the text is
  checked against hand-written strings, not against the code twice;
- a reader that knows the grid names a hole, never folds it into the
  next interval (the defect the previous reader had); a height written
  twice keeps the last row (a kill between the row and the state);
- the sidecar is a sealed manifest the shared audit reads: a changed
  CSV beside its meta is caught, and the fingerprint covers the bytes
  and nothing else, so two writers of the same rows seal the same
  fingerprint whatever they put in `build`.
"""

import os

import pytest

from nodsig import curve as cv

TYPES = ("p2pkh", "p2sh", "p2wpkh", "p2wsh")
HEADER = ("height,p2pkh_hits,p2pkh_satoshis,p2sh_hits,p2sh_satoshis,"
          "p2wpkh_hits,p2wpkh_satoshis,p2wsh_hits,p2wsh_satoshis,"
          "fingerprint\n")


def totals(**kw):
    return {t: {"hits": kw.get(t, (0, 0))[0], "satoshis": kw.get(t, (0, 0))[1]}
            for t in TYPES}


def test_the_grid_is_the_multiples_and_the_tip():
    assert cv.grid(10, 35) == [10, 20, 30, 35]
    assert cv.grid(10, 30) == [10, 20, 30]
    assert cv.grid(100, 7) == [7]
    with pytest.raises(cv.CurveError):
        cv.grid(0, 7)


def test_header_and_row_are_the_text_both_roads_write():
    assert cv.reuse_header(TYPES) == HEADER
    row = cv.reuse_row(10_000, totals(p2pkh=(2, 1000), p2wsh=(1, 250)), "aa",
                       TYPES)
    assert row == "10000,2,1000,0,0,0,0,1,250,aa\n"


def test_write_and_append_agree_on_the_bytes(tmp):
    rows = [cv.reuse_row(h, totals(p2pkh=(h, 10 * h)), f"f{h}", TYPES)
            for h in (2, 4)]
    whole = os.path.join(tmp, "whole.csv")
    sha = cv.write(whole, HEADER, rows)
    grown = os.path.join(tmp, "grown.csv")
    for row in rows:
        cv.append_row(grown, HEADER, row)
    assert open(whole).read() == open(grown).read()
    assert sha == cv.sha_of(grown)
    assert cv.last_height(grown) == 4
    assert cv.last_height(os.path.join(tmp, "absent.csv")) is None
    with open(os.path.join(tmp, "empty.csv"), "w") as f:
        f.write(HEADER)
    assert cv.last_height(os.path.join(tmp, "empty.csv")) is None


def test_the_reader_refuses_other_columns_and_disorder(tmp):
    path = os.path.join(tmp, "c.csv")
    with open(path, "w") as f:
        f.write("height,foo\n1,2\n")
    with pytest.raises(cv.CurveError, match="columns"):
        cv.read_reuse(path, TYPES)
    with open(path, "w") as f:
        f.write(HEADER + "20,1,1,0,0,0,0,0,0,b\n10,1,1,0,0,0,0,0,0,a\n")
    with pytest.raises(cv.CurveError, match="ascending"):
        cv.read_reuse(path, TYPES)


def test_a_hole_in_the_grid_is_named_not_folded(tmp):
    path = os.path.join(tmp, "c.csv")
    with open(path, "w") as f:
        f.write(HEADER + "10,1,1,0,0,0,0,0,0,a\n30,3,3,0,0,0,0,0,0,c\n")
    # Without the grid the reader cannot know: two rows, as written.
    assert [h for h, _, _ in cv.read_reuse(path, TYPES)] == [10, 30]
    with pytest.raises(cv.CurveError, match="lacks the row"):
        cv.read_reuse(path, TYPES, every=10)
    # A row off the grid is named too.
    with open(path, "w") as f:
        f.write(HEADER + "10,1,1,0,0,0,0,0,0,a\n15,2,2,0,0,0,0,0,0,b\n"
                "20,3,3,0,0,0,0,0,0,c\n")
    with pytest.raises(cv.CurveError, match="off its"):
        cv.read_reuse(path, TYPES, every=10)
    # The tip is on every grid.
    with open(path, "w") as f:
        f.write(HEADER + "10,1,1,0,0,0,0,0,0,a\n20,2,2,0,0,0,0,0,0,b\n"
                "23,3,3,0,0,0,0,0,0,c\n")
    rows = cv.read_reuse(path, TYPES, every=10)
    assert [h for h, _, _ in rows] == [10, 20, 23]
    assert rows[2][1]["p2pkh"] == (3, 3) and rows[2][2] == "c"


def test_a_height_written_twice_keeps_the_last_row(tmp):
    path = os.path.join(tmp, "c.csv")
    with open(path, "w") as f:
        f.write(HEADER + "10,1,1,0,0,0,0,0,0,a\n20,9,9,0,0,0,0,0,0,STALE\n"
                "20,2,2,0,0,0,0,0,0,b\n")
    rows = cv.read_reuse(path, TYPES, every=10)
    assert [(h, d["p2pkh"], fp) for h, d, fp in rows] == [
        (10, (1, 1), "a"), (20, (2, 2), "b")]


def test_the_sidecar_is_sealed_over_the_bytes_alone(tmp):
    path = os.path.join(tmp, "curve.csv")
    rows = [cv.reuse_row(h, totals(p2pkh=(h, 10 * h)), f"f{h}", TYPES)
            for h in (10, 20)]
    sha = cv.write(path, HEADER, rows)
    meta = cv.seal(path, cv.REUSE_TAG, 20, {"road": "scan", "grid": 10,
                                            "rows": 2, "parent": None})
    assert meta["identity"] == {
        "format": cv.REUSE_TAG, "coverage": {"from": 1, "to": 20},
        "files": [{"name": "curve.csv", "sha256": sha}]}
    assert meta["build"]["files"]["curve.csv"] == {"file": "curve.csv",
                                                    "sha256": sha}
    assert cv.read_meta(path) == meta
    assert cv.verify(path, cv.REUSE_TAG)["fingerprint"] == meta["fingerprint"]
    # Another writer, another build block, another file name, the same
    # rows: the same name.
    other = os.path.join(tmp, "elsewhere", "mine.csv")
    os.makedirs(os.path.dirname(other))
    cv.write(other, HEADER, rows)
    again = cv.seal(other, cv.REUSE_TAG, 20, {"road": "derive", "grid": 10,
                                              "rows": 2, "parent": None,
                                              "note": "not in the identity"})
    assert again["fingerprint"] == meta["fingerprint"]
    assert again["build"]["files"]["curve.csv"]["file"] == "mine.csv"
    assert cv.verify(other, cv.REUSE_TAG)["fingerprint"] == meta["fingerprint"]
    # A changed byte beside an unchanged meta is caught by the audit.
    with open(path, "a") as f:
        f.write("30,3,30,0,0,0,0,0,0,f30\n")
    with pytest.raises(cv.CurveError):
        cv.verify(path, cv.REUSE_TAG)
    with pytest.raises(cv.CurveError, match="never sealed"):
        cv.verify(os.path.join(tmp, "nothing.csv"), cv.REUSE_TAG)
    assert cv.read_meta(os.path.join(tmp, "nothing.csv")) is None
