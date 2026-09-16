#!/usr/bin/env python3
"""
kernel.py — the native kernel of the scan, when there is one.

The reveal archive's scan has two roads to the same bytes: the Python
reference (`blockparse.parse_block` + `reveal_archive.block_records`),
which is the readable statement of what the scan does, and `nodsig._native`,
the same walk in C (src/nodsig/_native), a proven-identical accelerator
and nothing more. This module is the one place that decides which road
runs: the native one when it is built and not switched off, the Python one
otherwise, with no difference in what comes out — the conformance vectors
(tests/fixtures/scan) and the suite hold the two to the same records, the
same counters and the same refusals.

    NODSIG_NATIVE=0    forces the Python road (a benchmark, an audit)

Nothing is built at import time: `python3 -m nodsig.native.build` (or
the wheel build) makes the extension, and a package without it simply
answers `available() == False`. The manifest of an archive says which road
scanned it, outside the identity: the fingerprint does not depend on it.
"""

import os

from nodsig.blockparse import ParseError

try:
    from nodsig import _native
except ImportError:                      # not built: the Python road
    _native = None

if os.environ.get("NODSIG_NATIVE", "1") == "0":
    _native = None


def available():
    """True when the native road is built and switched on."""
    return _native is not None


def name():
    """What the manifest records: which road scanned."""
    return "native" if _native is not None else "python"


class HashMismatch(Exception):
    """The block's header does not hash to the hash it was asked for:
    the scan's own refusal, raised by the caller in its own words."""


def scan_block(raw, height, expect_hash=None):
    """One block in, the archive's records out, on the native road.

    Returns (records, stats, facts): `records` is a tuple of five bytes
    objects, the whole records of each category in RUN_CATS order, as
    `block_records` would have appended them (a multiset: the order is
    not promised); `stats` the counters the block moves, from zero;
    `facts` the header, the two sizes, the coinbase's scriptSig and what
    a header archive needs. Raises `ParseError` with the parser's own
    words where the parser would, `HashMismatch` when the header does
    not hash to `expect_hash`."""
    out = _native.scan_block(raw, height, expect_hash)
    if out[0] == 0:
        return out[1], out[2], out[3]
    if out[0] == 1:
        raise ParseError(out[1])
    raise HashMismatch()


# The rules of the fusion's k-way stage the kernel knows, by the name a
# combining function declares on itself (`native = "or_min"`) or by the
# stage's own dedup rule; nodsig_kway.h numbers them.
FUSE_COUNT, FUSE_LAST, FUSE_OR_MIN, FUSE_MAX_MIN = 0, 1, 2, 3
_FUSE_RULES = {"or_min": FUSE_OR_MIN, "max_min": FUSE_MAX_MIN}


def fuse_rule(dedup, combine):
    """The kernel's number for a fusion rule, or None when the kernel has
    no such rule (a combining function that declares nothing takes the
    reference road, as it must: the kernel cannot call it)."""
    if combine is not None:
        return _FUSE_RULES.get(getattr(combine, "native", None))
    return FUSE_LAST if dedup == "last" else FUSE_COUNT


def fuse_pieces(pieces, rec, dedup_len, rule):
    """One round of the k-way stage on the native road: the sorted
    `pieces` (bytes, whole records of `rec` bytes each) merged into one
    sorted blob with the equal dedup prefixes reduced by `rule`. Returns
    (blob, reductions), or None when a piece was not sorted and the
    reference road must take the round (`genstore._BulkFusion`)."""
    return _native.fuse_pieces(pieces, rec, dedup_len, rule)
