#!/usr/bin/env python3
"""
test_report.py — the page that describes what you hold.

Two properties matter here and neither is about formatting. The first is
that the page cannot leak the machine it was written on: it is built to
be published, so a path, a home directory or a host name reaching the
output is the failure, not a cosmetic defect. The second is that it says
what it does not know instead of quietly leaving it out, which is the
same rule `verify` follows for a coverage it cannot derive.

The artifacts under test are real ones built from the synthetic chain,
so the durations, the ancestry and the producer are read out of
manifests a builder actually sealed rather than out of a fixture written
to match.
"""

import io
import os

import pytest

from nodsig import derivatives as dv
from nodsig import outpoint_index as oi
from nodsig import report as rp
import test_outpoint_index as toi


@pytest.fixture
def pair(tmp):
    """A sealed index and the derivatives built from it: enough to
    exercise identity, cost and a confirmed ancestry link."""
    blocks, _txids = toi.index_chain()
    graph = toi.emit_graph(tmp, blocks)
    index = os.path.join(tmp, "index")
    derived = os.path.join(tmp, "derived")
    oi.run_build(graph, index)
    dv.run_build(index, derived)
    return graph, index, derived


def _page(**dirs):
    out = io.StringIO()
    rp.run_report(dirs, out=out)
    return out.getvalue()


def test_the_page_names_no_path(pair, tmp):
    """The rule that makes this publishable. Directories go in as
    arguments and must not come out: an artifact is named by its role,
    which is what a reader elsewhere can use."""
    graph, index, derived = pair
    page = _page(graph=graph, index=index, derived=derived)
    for path in (tmp, graph, index, derived, os.path.expanduser("~")):
        assert path not in page
    assert os.sep + "tmp" not in page


def test_the_machine_block_asks_nothing_that_identifies_it():
    """Hardware and runtime, never whose. The host name is the obvious
    trap, so it is the one asserted against by value and not by
    hope."""
    import platform
    import socket
    facts = dict(rp.machine())
    assert set(facts) == {"CPU", "Cores", "Memory", "OS", "Python", "nodsig"}
    for forbidden in (platform.node(), socket.gethostname(),
                      os.path.expanduser("~")):
        if forbidden:
            assert forbidden not in " ".join(facts.values())


def test_it_reports_identity_cost_and_a_confirmed_ancestry(pair):
    """The three questions the page exists to answer, on artifacts a
    builder really sealed."""
    graph, index, derived = pair
    page = _page(graph=graph, index=index, derived=derived)

    imanifest = oi._load_manifest(index)
    assert imanifest["fingerprint"] in page
    assert "1..4" in page                      # the coverage, as printed

    # The cost: `index build` recorded its own seconds under its verb.
    assert imanifest["build"]["seconds"]["build"] >= 0
    assert "| index | build |" in page

    # The ancestry: the derivatives declare the index, and the index is
    # in the report, so the link is confirmed rather than merely stated.
    assert "confirmed" in page
    assert "declared and not confirmed" not in page


def test_an_unsealed_artifact_is_named_not_skipped(tmp, pair):
    """A report silent about what it could not read reads as a report
    that read everything."""
    graph, index, _derived = pair
    empty = os.path.join(tmp, "nothing-here")
    os.makedirs(empty)
    page = _page(graph=graph, index=index, derived=empty)
    assert "not sealed" in page


def test_the_shared_pass_is_flagged_where_it_appears(pair):
    """A `scan` writes several artifacts at once, so those rows are one
    run seen more than once and the page must say so. Nothing here was
    scanned, so the warning must be absent: a note that appears when it
    does not apply teaches a reader to ignore it."""
    graph, index, derived = pair
    assert "must not be added" not in _page(index=index, derived=derived)

    found = [("archive", graph, {"fingerprint": "f" * 64,
                                 "identity": {"format": "reveal-archive-v2",
                                              "coverage": {"from": 1,
                                                           "to": 4}},
                                 "build": {"seconds": {"scan": 187_000}}})]
    out = io.StringIO()
    rp.render(found, out=out)
    assert "must not be added" in out.getvalue()
    assert "51 h 56 min" in out.getvalue()


def test_naming_no_artifact_is_an_error():
    with pytest.raises(rp.ReportError):
        rp.run_report({})


def main():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        blocks, _txids = toi.index_chain()
        graph = toi.emit_graph(tmp, blocks)
        index = os.path.join(tmp, "index")
        derived = os.path.join(tmp, "derived")
        oi.run_build(graph, index)
        dv.run_build(index, derived)
        built = (graph, index, derived)
        test_the_page_names_no_path(built, tmp)
        test_the_machine_block_asks_nothing_that_identifies_it()
        test_it_reports_identity_cost_and_a_confirmed_ancestry(built)
        test_an_unsealed_artifact_is_named_not_skipped(tmp, built)
        test_the_shared_pass_is_flagged_where_it_appears(built)
        print("report: ok")


if __name__ == "__main__":
    main()
