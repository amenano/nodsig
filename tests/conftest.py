#!/usr/bin/env python3
"""
conftest.py — the shared fixtures of the test suite.

Why this exists, and why it is here. Every test file in this directory
can also run on its own: at the bottom it has a main() that builds by
hand what it needs (a temporary directory, the synthetic chain, the fake
node) and calls the test functions in order. Under pytest
that manual wiring becomes these fixtures, which pytest injects by
looking at the tests' parameter names. The content is the SAME as the
main()s, written once here, so the suite runs both ways without
duplicating the setup logic.

No node and no real data: a single synthetic four-block chain
(`test_reuse_scan.build_chain`), served on localhost by a fake node
that answers on both of its interfaces (`test_reuse_scan.serve`),
distilled into the artifacts the readers
consume — the locks (`locks_dir`), the revelation archive (`archive`),
the co-emitted graph (`graph`).
"""

import os
import tempfile

import pytest

from nodsig import block_stats as bs
from nodsig import graphemit as ge
from nodsig import reveal_archive as ra
import test_reuse_scan as trs


@pytest.fixture
def tmp():
    """The throwaway working directory, the same `with
    tempfile.TemporaryDirectory()` that opens every main()."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def blocks():
    """The synthetic chain: height -> (display hash, block hex). The
    spends inside it reveal exactly the keys the tests expect to find
    again."""
    return trs.build_chain()


@pytest.fixture
def locks_dir(tmp, blocks):
    """The synthetic snapshot distilled into sorted lock files.
    `trs.test_prepare` does the work (builds the snapshot, runs
    `run_prepare`, checks dedup/ordering/exclusions) and returns the
    directory: it is the same line that opens the main()s needing it.
    The snapshot claims the chain's tip as its base block, like a real
    `dumptxoutset` taken at the archive's target height: derive
    confronts the two hashes and refuses locks from another moment."""
    return trs.test_prepare(tmp, base_hash_hex=blocks[4][0])


def _scan_archive(tmp, blocks, name):
    """Scan the chain into a revelation archive and return its
    directory. It does not merge: whoever wants the merged archive
    merges it afterwards (see the `archive` fixture)."""
    d = os.path.join(tmp, name)
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, d,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()
    return d


@pytest.fixture
def archive_oneshot(tmp, blocks):
    """A freshly scanned archive, NOT merged: `test_merge_determinism`
    merges it itself and compares the fingerprints, so it must receive
    it raw."""
    return _scan_archive(tmp, blocks, "archive_oneshot")


@pytest.fixture
def archive(tmp, blocks):
    """A scanned and MERGED archive: the "finished" shape the readers
    query — `lookup` reads the merged key file, and the cross-check and
    the address check search inside the merged files."""
    d = _scan_archive(tmp, blocks, "archive")
    ra.run_merge(d)
    return d


@pytest.fixture
def _tiny_graph_flush(monkeypatch):
    """Lower the graph's flush threshold to 64 bytes (as the graphemit
    and block_stats main()s do with their own `tiny_init`), so every
    emission produces SEVERAL runs: that is what exercises the
    multi-run paths (determinism, canonical stream across run
    boundaries). The monkeypatch undoes itself when the test ends."""
    original = ge.GraphEmitter.__init__

    def tiny_init(self, graph_dir, flush_bytes=64):
        original(self, graph_dir, flush_bytes=flush_bytes)

    monkeypatch.setattr(ge.GraphEmitter, "__init__", tiny_init)


def _emit_graph(tmp, blocks, name):
    """Emit the chain's co-emitted graph through the real host path
    (reveal_archive's `--graph` plug) and return its directory. The
    incidental host archive lands in `<name>_host` and is of no interest
    to the graph tests."""
    graph = os.path.join(tmp, name)
    server, url = trs.serve(blocks)
    try:
        ra.run_scan(url, "user:pass", 4, os.path.join(tmp, name + "_host"),
                    batch_size=2, checkpoint_every=2, graph_dir=graph)
    finally:
        server.shutdown()
    return graph


@pytest.fixture
def graph(tmp, blocks, _tiny_graph_flush):
    """A co-emitted graph of the chain. Read by graphemit (stats/show)
    and by block_stats (which derives the per-block statistics from it).
    It is NOT sealed: `block_stats` checks precisely that the source
    fingerprint is None until the graph has been fingerprinted."""
    return _emit_graph(tmp, blocks, "graph")


@pytest.fixture
def graph_oneshot(tmp, blocks, _tiny_graph_flush):
    """The graph emitted in one pass: the reference for the determinism
    comparisons (against an interrupted-and-resumed emission) and for the
    crash window. The dependency on `_tiny_graph_flush` keeps the
    monkeypatch alive during the test body too, where the comparison
    graph is emitted in its turn."""
    return _emit_graph(tmp, blocks, "graph_oneshot")


@pytest.fixture
def graph_from_ra(tmp, blocks, _tiny_graph_flush):
    """The graph emitted with reveal_archive as its host. It serves the
    host-independence proof: it must be byte-identical to the one
    emitted by reuse_scan over the same chain."""
    return _emit_graph(tmp, blocks, "graph_from_ra")


@pytest.fixture
def out_csv(tmp, graph):
    """A block-stats-v2 CSV already built from the graph, like the `out`
    variable the main()s pass to `test_summary`."""
    out = os.path.join(tmp, "stats.csv")
    bs.run_build(graph, out)
    return out
