#!/usr/bin/env python3
"""
test_linkage.py — self-test for linkage.py.

The chain here is built for ONE topology that no other suite has: two
addresses that were never spent together, but each of which was spent
together with the same third lock. That is the bridge, and it is the
whole reason `--linkage-depth 2` exists — and the reason it is not the
default.

    h1  cb  pays A, X, C, X (four outputs, three locks)
    h2  t1  spends A and X together   → pays D
    h3  t2  spends C and X together   → pays D

So: A—X and C—X are direct co-spends, A—C exists only through X. At
depth 1 the report must find the first two and NOT invent the third; at
depth 2 it must find A—C and say which bridge carried it and how wide
that bridge is.

What is checked beyond the finding itself is what makes it safe to
read:

    a class never becomes another one   `payment_arc` is reported and
                                        never breaks a separation
    an absence declares its bounds      depth, caps hit, hubs skipped
    a hub is refused and counted        never silently walked
    only claimed groups are separated   a `watching` group cannot be

Usage:
    python3 test_linkage.py     # prints PASS or fails loudly
"""

import io
import json
import os
import sys
import tempfile

import pytest

from nodsig import check_addresses as ca
from nodsig import derivatives as dvm
from nodsig import linkage as lk
from nodsig.capability import Status
from nodsig.hashing import hash160
from nodsig.reuse_scan import SAT
import test_blockparse as tbw
import test_check_addresses as tca
import test_derivatives as tdv
import test_outpoint_index as toi

H_A = b"\xA1" * 20
H_X = b"\xB2" * 20
H_C = b"\xC3" * 20
H_D = b"\xD4" * 20


def p2pkh(h20):
    return b"\x76\xa9\x14" + h20 + b"\x88\xac"


def address(h20):
    return tca.b58check_encode(0x00, h20)


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


def bridge_chain():
    """The three blocks described in the module docstring."""
    blocks = {}
    prev = bytes(32)

    def add(height, raw_txs, ids):
        nonlocal prev
        raw, block_hash = tbw.w_block(4, prev, 1_700_000_000 + height,
                                      0x1700_0000, height, raw_txs, ids)
        prev = block_hash
        blocks[height] = (block_hash[::-1].hex(), raw.hex())

    cb, cb_id, _ = toi._coinbase(
        b"\x01L", [tbw.w_output(50 * SAT, p2pkh(H_A)),
                   tbw.w_output(50 * SAT, p2pkh(H_X)),
                   tbw.w_output(50 * SAT, p2pkh(H_C)),
                   tbw.w_output(50 * SAT, p2pkh(H_X))])
    add(1, [cb], [cb_id])

    cb2, cb2_id, _ = toi._coinbase(b"\x01M",
                                   [tbw.w_output(50 * SAT, p2pkh(H_D))])
    t1, t1_id, _ = tbw.w_tx(
        1, [tbw.w_input(cb_id, 0, b"\x00", 0xFFFFFFFF),
            tbw.w_input(cb_id, 1, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(90 * SAT, p2pkh(H_D))], 0)
    add(2, [cb2, t1], [cb2_id, t1_id])

    cb3, cb3_id, _ = toi._coinbase(b"\x01N",
                                   [tbw.w_output(50 * SAT, p2pkh(H_D))])
    t2, t2_id, _ = tbw.w_tx(
        1, [tbw.w_input(cb_id, 2, b"\x00", 0xFFFFFFFF),
            tbw.w_input(cb_id, 3, b"\x00", 0xFFFFFFFF)],
        [tbw.w_output(90 * SAT, p2pkh(H_D))], 0)
    add(3, [cb3, t2], [cb3_id, t2_id])
    return blocks


def build_backend(tmp):
    blocks = bridge_chain()
    _graph, index = tdv.build_index(tmp, blocks, name="lk_index")
    derived = os.path.join(tmp, "lk_derived")
    dvm.run_build(index, derived)
    from nodsig import outpoint_index as oi
    idx = oi.Index(index)
    return lk.IndexLinkage(idx, dvm.Derived(derived, idx))


@pytest.fixture
def backend(tmp):
    b = build_backend(tmp)
    yield b
    b.close()


def entries_for(texts, backends=None, book=None):
    """The report entries for a list of addresses, which is what the
    linkage block is computed from. The book travels too: an entry that
    does not know its compartment cannot take part in a sentence about
    compartments."""
    return ca.build_report(texts, backends or {}, book).entries


# ---------------------------------------------------------------------------
# Class 1: no chain needed at all
# ---------------------------------------------------------------------------

def test_same_key_is_a_fact_of_the_encoding():
    """`1…` and `bc1q…` over the same 20 bytes are one key. It comes
    from no artifact, has no height, and cannot expire — while whether
    an outsider can SEE the tie is a different fact with a different
    source."""
    h20 = bytes(range(20))
    entries = entries_for([address(h20), tca.segwit_addr(h20, 0)])
    findings = lk.same_key(entries)
    check(len(findings) == 1, f"one pair expected: {findings}")
    f = findings[0]
    check(f["evidence"]["source"] == "address-codec",
          f"the identity comes from the codec: {f}")
    check(f["evidence"]["perishable"] is False,
          f"a fact of the encoding does not expire: {f}")
    check(f["positions"] == [0, 1],
          f"findings are ordered by input position: {f}")
    check(f["observable"]["value"] is None
          and f["observable"]["status"] == Status.UNDETERMINED,
          "with no exposure backend, whether it is VISIBLE is unknown "
          f"— and unknown is not 'no': {f}")
    print("ok  same key: identity from the codec, visibility asked "
          "separately")


def test_same_key_visibility_comes_from_the_archive(archive):
    """With an archive plugged in, the tie's visibility gets a height —
    and the height belongs to the visibility, never to the identity."""
    from nodsig import reuse_scan as rs
    import test_reuse_scan as trs

    h20 = rs.hash160(trs.PUB1)          # a key the archive has seen
    backends = {"exposure": ca.RevealArchiveExposure(archive)}
    entries = entries_for([address(h20), tca.segwit_addr(h20, 0)],
                          backends)
    f = lk.same_key(entries)[0]
    check(f["observable"]["value"] is True
          and f["observable"]["source"] == "exposure",
          f"a revealed key makes the tie visible: {f}")
    check(isinstance(f["observable"]["at_height"], int),
          f"and that half has a height: {f}")
    check("at_height" not in f["evidence"],
          "the identity must not borrow the visibility's height")
    print("ok  same key: visibility carries the archive's height, the "
          "identity carries none")


def test_two_different_keys_are_not_a_finding():
    entries = entries_for([address(bytes(range(20))),
                           address(bytes(range(1, 21)))])
    check(lk.same_key(entries) == [],
          "two different digests are not the same key")
    print("ok  same key: no finding where there is no identity")


# ---------------------------------------------------------------------------
# Classes 2 and 3: over the bridge chain
# ---------------------------------------------------------------------------

def _mine(entries):
    return {hash160(ca.script_pubkey(e.address)): (i, e)
            for i, e in enumerate(entries) if e.valid}


def test_depth_one_finds_the_direct_co_spend_only(backend):
    """A and X were spent together; A and C were not. At depth 1 the
    report must say the first and must NOT invent the second."""
    entries = entries_for([address(H_A), address(H_X), address(H_C)])
    findings, bounded = backend.common_input(_mine(entries), depth=1)
    pairs = {tuple(f["positions"]) for f in findings}
    check(pairs == {(0, 1), (1, 2)},
          f"A—X and C—X are direct, A—C is not: {pairs}")
    for f in findings:
        check(f["hops"][0]["bridge_lock"] is None,
              f"a direct co-spend has no bridge: {f}")
        check(f["hops"][0]["height"] in (2, 3),
              f"the height of the co-spending tx must travel: {f}")
    check(bounded == {"depth": 1, "caps_hit": 0,
                      "bridges_not_expanded": 0},
          f"what bounded the search is always declared: {bounded}")
    print("ok  common input: the direct co-spends, and nothing invented")


def test_depth_two_crosses_the_bridge_and_weighs_it(backend):
    """The pair that only a bridge connects, with the bridge named and
    its fanout beside it: a bridge shared by three locks is damning, one
    shared by 900,000 is an exchange."""
    entries = entries_for([address(H_A), address(H_C)])
    findings, bounded = backend.common_input(_mine(entries), depth=2)
    check([f["positions"] for f in findings] == [[0, 1]],
          f"A and C are tied through X: {findings}")
    hop = findings[0]["hops"][0]
    check(hop["bridge_lock"] == hash160(p2pkh(H_X)).hex(),
          f"the bridge must be named: {hop}")
    check(hop["bridge_fanout"] >= 2,
          f"the weight of the bridge travels with the finding: {hop}")
    check(bounded["depth"] == 2, f"the depth is declared: {bounded}")
    print("ok  common input: depth 2 crosses one bridge and reports its "
          "weight")


def test_a_hub_is_refused_and_counted(backend, monkeypatch):
    """A bridge that touches too many locks is not expanded — and the
    refusal is COUNTED, because a search that stopped must say where."""
    monkeypatch.setattr(lk, "HUB_FANOUT", 0)
    entries = entries_for([address(H_A), address(H_C)])
    findings, bounded = backend.common_input(_mine(entries), depth=2)
    check(findings == [], "a hub must not produce a finding")
    check(bounded["bridges_not_expanded"] >= 1,
          f"the skipped hub must be counted: {bounded}")
    print("ok  common input: a hub is skipped, and the skip is in the "
          "report")


def test_payment_arcs_are_reported_apart(backend):
    """A funded an output of D. That is a payment, not a merge."""
    entries = entries_for([address(H_A), address(H_D)])
    arcs = backend.payment_arcs(_mine(entries))
    check(any(a["from"] == address(H_A) and a["to"] == address(H_D)
              for a in arcs), f"the arc A→D is missing: {arcs}")
    check(all("NOT the claim" in a["means"] for a in arcs),
          f"every arc must carry what it does not mean: {arcs}")
    print("ok  payment arc: reported, with the claim it does not make")


# ---------------------------------------------------------------------------
# The block, and the separations it is allowed to speak about
# ---------------------------------------------------------------------------

def _book(tmp, groups):
    from nodsig import address_book as ab
    path = os.path.join(tmp, "book.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"format": ab.FORMAT_TAG, "groups": groups}, f)
    return ab.load(path)


def test_a_broken_separation_names_what_broke_it(tmp, backend):
    book = _book(tmp, [
        {"label": "group-a", "claim": "mine", "addresses": [address(H_A)]},
        {"label": "group-b", "claim": "mine", "addresses": [address(H_X)]}])
    entries = entries_for(book.addresses, book=book)
    block = lk.build(entries, backend, 1, book)
    sep = block["declared_separations"]
    check(len(sep) == 1 and sep[0]["held"] is False,
          f"A and X were spent together: {sep}")
    check(sep[0]["broken_by"] == lk.COMMON_INPUT
          and sep[0]["at_height"] == 2,
          f"what broke it, and when: {sep}")
    print("ok  separations: a broken one names the class and the height")


def test_a_held_separation_declares_what_bounded_the_search(tmp,
                                                            backend):
    """`held: true` is never an attestation: the depth, the caps and the
    hubs travel with it, and so does the asymmetry — a merge is
    permanent, a non-merge is one transaction away from ending."""
    book = _book(tmp, [
        {"label": "group-a", "claim": "mine", "addresses": [address(H_A)]},
        {"label": "group-c", "claim": "mine", "addresses": [address(H_C)]}])
    entries = entries_for(book.addresses, book=book)
    block = lk.build(entries, backend, 1, book)
    sep = block["declared_separations"][0]
    check(sep["held"] is True, f"A and C are not tied at depth 1: {sep}")
    check(sep["bounded_by"] == {"depth": 1, "caps_hit": 0,
                                "bridges_not_expanded": 0},
          f"the bounds of the search are part of the answer: {sep}")
    check("perishable" in sep["note"], f"the asymmetry must be said: {sep}")
    check(sep["as_of"] == backend.watermark,
          f"and the height it holds as of: {sep}")

    # At depth 2 the same pair IS tied: the sentence above was about
    # the search, exactly as it said.
    deeper = lk.build(entries, backend, 2, book)
    check(deeper["declared_separations"][0]["held"] is False,
          "depth 2 finds the bridge, which is why depth is declared")
    print("ok  separations: a held one is bounded, and depth 1 vs 2 "
          "proves the bound was real")


def test_only_claimed_groups_are_separated(tmp, backend):
    book = _book(tmp, [
        {"label": "group-a", "claim": "mine", "addresses": [address(H_A)]},
        {"label": "theirs", "claim": "watching",
         "addresses": [address(H_C)]}])
    entries = entries_for(book.addresses, book=book)
    block = lk.build(entries, backend, 2, book)
    check(block["declared_separations"] == [],
          "a group nobody claimed cannot be separated from anything: "
          f"{block['declared_separations']}")
    check(block["classes"][lk.COMMON_INPUT]["findings"],
          "but the LINK towards it is still reported: that is what a "
          "watching group is for")
    print("ok  separations: only claimed groups, links reported for all")


def test_a_payment_arc_never_breaks_a_separation(tmp, backend):
    """A funded an output of D and they were never spent together. "A
    paid D" must not read as "A and D are one entity"."""
    book = _book(tmp, [
        {"label": "group-a", "claim": "mine", "addresses": [address(H_A)]},
        {"label": "group-d", "claim": "mine", "addresses": [address(H_D)]}])
    entries = entries_for(book.addresses, book=book)
    block = lk.build(entries, backend, 1, book)
    check(block["classes"][lk.PAYMENT_ARC]["findings"],
          "the arc must be reported")
    sep = block["declared_separations"][0]
    check(sep["held"] is True,
          f"a payment is not a merge: {sep}")
    print("ok  separations: a payment arc is reported and merges "
          "nothing")


def test_without_an_index_each_class_answers_for_itself(tmp):
    """`same_key` needs no artifact; the other two do. One status over
    the whole block would erase an answer that exists."""
    h20 = bytes(range(20))
    entries = entries_for([address(h20), tca.segwit_addr(h20, 0)])
    block = lk.build(entries, None, 1, None)
    check(block["classes"][lk.SAME_KEY]["status"] == Status.OK
          and block["classes"][lk.SAME_KEY]["findings"],
          "the codec answers with no index at all")
    for cls in (lk.COMMON_INPUT, lk.PAYMENT_ARC):
        check(block["classes"][cls]["status"] == Status.UNSUPPORTED
              and "--index" in block["classes"][cls]["why"],
              f"{cls} must say what would answer it")
    print("ok  linkage: three classes, three statuses")


def test_no_third_party_lock_leaks_at_depth_one(backend):
    """The engine is asked membership, never enumeration: at depth 1
    nothing about a stranger appears at all."""
    entries = entries_for([address(H_A), address(H_X), address(H_C)])
    block = lk.build(entries, backend, 1, None)
    text = json.dumps(block)
    check(hash160(p2pkh(H_D)).hex() not in text,
          "a lock nobody listed must not appear in the block")
    for f in block["classes"][lk.COMMON_INPUT]["findings"]:
        check(all(h["bridge_lock"] is None for h in f["hops"]),
              f"no bridge is named at depth 1: {f}")
    print("ok  linkage: membership, not enumeration")


@pytest.fixture
def archive(tmp):
    return tca.build_archive(tmp)


def main():
    test_same_key_is_a_fact_of_the_encoding()
    test_two_different_keys_are_not_a_finding()
    with tempfile.TemporaryDirectory() as tmp:
        test_same_key_visibility_comes_from_the_archive(
            tca.build_archive(tmp))
        b = build_backend(tmp)
        try:
            test_depth_one_finds_the_direct_co_spend_only(b)
            test_depth_two_crosses_the_bridge_and_weighs_it(b)
            test_payment_arcs_are_reported_apart(b)
            test_a_broken_separation_names_what_broke_it(tmp, b)
            test_a_held_separation_declares_what_bounded_the_search(
                tmp, b)
            test_only_claimed_groups_are_separated(tmp, b)
            test_a_payment_arc_never_breaks_a_separation(tmp, b)
            test_no_third_party_lock_leaks_at_depth_one(b)
        finally:
            b.close()
        test_without_an_index_each_class_answers_for_itself(tmp)
    print("PASS: the three classes stay three claims, every absence "
          "declares what bounded it, and no stranger's lock leaves the "
          "machine.")


if __name__ == "__main__":
    main()
