#!/usr/bin/env python3
"""
test_hotpath_equivalence.py — the faster roads through the scan's hot
path answer exactly what the roads they replaced answered.

Each speed-up here removed work, not meaning: a hash computed twice, an
exception raised to say "this is not a script", a tuple built and taken
apart for every record, a hash-function lookup by name on every call. The
property asserted is never "faster"; it is "the same answer, byte for
byte", against a REFERENCE written the old way inside this file, on
random inputs shaped like the chain's (keys, signatures, pushes that run
past their end, reused digests). A reference that imported the code under
test would compare that code with itself.
"""

import hashlib
import os
import random
import tempfile

from nodsig import blockparse as bp
from nodsig import hashing as ha
from nodsig import keyforms as kf
from nodsig import reveal_archive as ra
from nodsig import sightings as sg


def check(cond, msg):
    assert cond, msg


# ---------------------------------------------------------------------------
# the push walk: no exception, same answers and the same error text
# ---------------------------------------------------------------------------

def _reference_pushes(script):
    """The walk as it was written before, raising ParseError."""
    pushes, pos, n = [], 0, len(script)

    def take(k, what):
        nonlocal pos
        if pos + k > n:
            raise bp.ParseError(f"bytes ended while reading {what}")
        out = script[pos:pos + k]
        pos += k
        return out

    while pos < n:
        op = script[pos]
        pos += 1
        if 1 <= op <= 75:
            length = op
        elif op == 76:
            length = take(1, "an OP_PUSHDATA1 length")[0]
        elif op == 77:
            length = int.from_bytes(take(2, "an OP_PUSHDATA2 length"),
                                    "little")
        elif op == 78:
            length = int.from_bytes(take(4, "an OP_PUSHDATA4 length"),
                                    "little")
        else:
            continue
        pushes.append(bytes(take(length, "a script push")))
    return pushes


def _random_script(rnd):
    """Bytes that exercise every branch: direct pushes that fit or run
    over, the three PUSHDATA forms with short or oversized lengths,
    non-push opcodes, keys and signatures read as scripts."""
    kind = rnd.randrange(6)
    if kind == 0:
        return bytes([2 + rnd.getrandbits(1)]) + rnd.randbytes(32)
    if kind == 1:
        return b"\x30" + rnd.randbytes(rnd.randrange(60, 72))
    out = bytearray()
    for _ in range(rnd.randrange(0, 8)):
        op = rnd.choice((0, 1, 20, 33, 75, 76, 77, 78, 0x51, 0xAE,
                         rnd.randrange(256)))
        out.append(op)
        if 1 <= op <= 75:
            out += rnd.randbytes(max(0, op + rnd.randrange(-2, 2)))
        elif op == 76:
            ln = rnd.randrange(0, 90)
            out += bytes([ln]) + rnd.randbytes(max(0, ln + rnd.randrange(-2, 1)))
        elif op == 77:
            ln = rnd.randrange(0, 300)
            out += ln.to_bytes(2, "little")[:rnd.choice((1, 2, 2))]
            out += rnd.randbytes(rnd.randrange(0, 300))
        elif op == 78:
            out += rnd.randbytes(rnd.choice((0, 2, 4)))
    cut = rnd.randrange(len(out) + 1) if rnd.random() < 0.3 else len(out)
    return bytes(out[:cut])


def test_the_push_walk_answers_as_before_without_raising():
    rnd = random.Random(145)
    malformed = 0
    for _ in range(20_000):
        script = _random_script(rnd)
        try:
            want, error = _reference_pushes(script), None
        except bp.ParseError as e:
            want, error = None, str(e)
            malformed += 1
        check(bp.script_pushes_or_none(script) == want,
              f"script_pushes_or_none({script.hex()}) differs")
        try:
            got, got_error = bp.script_pushes(script), None
        except bp.ParseError as e:
            got, got_error = None, str(e)
        check((got, got_error) == (want, error),
              f"script_pushes({script.hex()}): {got_error!r} != {error!r}")
        check(bp.script_pushes_or_none(memoryview(script)) == want,
              "a memoryview must read like its bytes")
    check(1_000 < malformed < 19_000,
          f"the fuzz must reach both outcomes: {malformed} malformed")


# ---------------------------------------------------------------------------
# hashing and the identity of a key
# ---------------------------------------------------------------------------

def test_ripemd160_through_a_copied_context_is_ripemd160():
    rnd = random.Random(160)
    for _ in range(300):
        data = rnd.randbytes(rnd.randrange(0, 200))
        check(ha.ripemd160(data) == ha._ripemd160_pure(data),
              f"ripemd160 differs on {data.hex()}")
    # Copies are independent: hashing twice from the same template must
    # not leak state from the first call into the second.
    check(ha.ripemd160(b"abc") == ha.ripemd160(b"abc"), "state leaked")


def test_canonical_key_hashes_once_and_answers_the_same():
    rnd = random.Random(33)
    for _ in range(2_000):
        n = rnd.choice((33, 65, 32, 34))
        lead = rnd.choice((2, 3, 4, 6, 7, 5))
        item = bytes([lead]) + rnd.randbytes(n - 1)
        if n == 33 and lead in (2, 3):
            want = (ha.hash160(item), ha.hash160(item), kf.COMPRESSED)
        elif n == 65 and lead in (4, 6, 7):
            comp = bytes([2 | item[64] & 1]) + item[1:33]
            want = (ha.hash160(comp), ha.hash160(item), kf.UNCOMPRESSED)
        else:
            want = None
        check(kf.canonical_key(item) == want, f"canonical_key({item.hex()})")


def test_a_candidate_script_reuses_the_digest_its_key_already_had():
    """A P2PKH scriptSig ends with a key, which is also the candidate
    redeem script: the digest handed over must change nothing."""
    rnd = random.Random(20)
    for _ in range(2_000):
        item = _random_script(rnd)
        plain, reused = [], []
        stats_a, stats_b = sg.new_filter_stats(), sg.new_filter_stats()
        sg.script_records(plain, item, "scripts20", sg.FLAG_INNER_SIG,
                          stats_a)
        ck = sg.key_records([], item, sg.FLAG_SIG)
        sg.script_records(reused, item, "scripts20", sg.FLAG_INNER_SIG,
                          stats_b, None if ck is None else ck[1])
        check(plain == reused and stats_a == stats_b,
              f"the reused digest changed the records of {item.hex()}")
        check(plain[0] == ("scripts20", ha.hash160(item),
                           min(sum(1 for p in (_safe_pushes(item) or ())
                                   if kf.canonical_key(p) is not None),
                               sg.MAX_INNER_KEYS)),
              f"the script record of {item.hex()} is not its own")


def _safe_pushes(script):
    try:
        return _reference_pushes(script)
    except bp.ParseError:
        return None


# ---------------------------------------------------------------------------
# the run writer: whole records, the bytes the tuple road wrote
# ---------------------------------------------------------------------------

def _reference_run(cat, triples):
    """The tuple road: sort (digest, byte, height), reduce equal digests
    by the category's rule, serialise."""
    out = bytearray()
    last = None
    for h, fl, ht in sorted(triples):
        if last is not None and h == last[0]:
            last = (h,) + ra._reduce(cat, last[1], last[2], fl, ht)
            continue
        if last is not None:
            out += last[0] + bytes([last[1]]) + last[2].to_bytes(3, "big")
        last = (h, fl, ht)
    if last is not None:
        out += last[0] + bytes([last[1]]) + last[2].to_bytes(3, "big")
    return out


def test_the_run_writer_writes_what_the_tuple_road_wrote():
    rnd = random.Random(24)
    with tempfile.TemporaryDirectory() as tmp:
        for cat in ra.RUN_CATS:
            width = ra.CATEGORIES[cat]
            pool = [rnd.randbytes(width) for _ in range(300)]
            for size in (0, 1, 5, 4_000):
                triples = [(rnd.choice(pool) if rnd.random() < 0.5
                            else rnd.randbytes(width),
                            rnd.randrange(256), rnd.randrange(1, 2**24))
                           for _ in range(size)]
                records = [ra._record(h, fl, ht.to_bytes(3, "big"))
                           for h, fl, ht in triples]
                path = os.path.join(tmp, f"{cat}-{size}.bin")
                n, sha = ra._write_run(path, cat, records)
                want = _reference_run(cat, triples)
                with open(path, "rb") as f:
                    got = f.read()
                check(got == want, f"{cat}, {size} records: bytes differ")
                check(n * ra.rec_width(cat) == len(want)
                      and sha == hashlib.sha256(want).hexdigest(),
                      f"{cat}, {size} records: count or sha differs")
