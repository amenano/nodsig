#!/usr/bin/env python3
"""
test_address_book.py — self-test for address_book.py.

Most of this file is REFUSALS, and that is where its value is. The
reader's job is not to parse JSON — the stdlib does that — it is to
refuse a file that would produce a report which looks complete while
covering less than the user believes. Every rejection below stands for
one way that could happen:

    a mistyped key           half a wallet silently unchecked
    a missing/odd `claim`    the separation sentences licensed, or
                             dropped, without saying so
    a repeated label         two compartments that cannot be told apart
    an address in two groups a file that does not describe the
                             compartments it claims to describe

And the two cases that look like errors and must NOT be refused: the
same address twice inside one group (deduplicated and declared), and two
different addresses that are the same key under two encodings — a
finding, not a mistake, and the sharpest thing this whole feature can
report.

Addresses here are public fixtures (the genesis address, a BIP-173
vector) or synthetic, and the labels are neutral on purpose: a fixture
that says "savings" teaches whoever reads it that this is where such
things go.

Usage:
    python3 test_address_book.py    # prints PASS or fails loudly
"""

import json
import os
import sys
import tempfile

from nodsig import address_book as ab

GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BIP173 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
OTHER = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


def book(**over):
    """A minimal valid book, overridable field by field."""
    group = {"label": "group-a", "claim": "separate",
             "addresses": [GENESIS, BIP173]}
    group.update(over)
    return {"format": ab.FORMAT_TAG, "groups": [group]}


def refuses(raw, why, expect=None):
    """The book must be refused, and the reason must be readable."""
    try:
        ab.loads(json.dumps(raw))
    except ab.BookError as e:
        if expect and expect not in str(e):
            fail(f"{why}: refused, but the reason does not mention "
                 f"{expect!r}: {e}")
        return
    fail(f"accepted a book it must refuse ({why})")


def test_minimal():
    b = ab.loads(json.dumps(book()))
    check(len(b.groups) == 1, "one group expected")
    g = b.groups[0]
    check(g.label == "group-a" and g.claim == "separate", "group fields lost")
    check(g.addresses == [GENESIS, BIP173],
          f"the order of the list is meaning, not decoration: {g.addresses}")
    check(g.claims_separation, "'mine' must be the claimed case")
    check(b.addresses == [GENESIS, BIP173], "flat list wrong")
    check(b.group_of(BIP173) == "group-a", "group_of lost the label")
    check(b.group_of("never-listed") is None,
          "an address nobody listed has no group")
    print("ok  minimal book: order preserved, claim read, groups mapped")


def test_origin_is_read_and_typed():
    """Origin is the author's claim and nothing here verifies it —
    but the TYPES are checked, because the report renders these values
    verbatim and a mistyped `chain` would be read as a fact about how
    the list was derived."""
    p = {"method": "descriptor", "descriptor_checksum": "8rjyrgz9",
         "script_type": "wpkh", "chain": "both", "range": [0, 999],
         "gap_limit": 20, "derived_at_height": 957301,
         "derived_by": "bitcoin core 27.0, deriveaddresses"}
    b = ab.loads(json.dumps(book(origin=p)))
    check(b.groups[0].origin == p, "origin not carried through")
    check(ab.loads(json.dumps(book())).groups[0].origin is None,
          "origin is optional and absent must stay absent")

    refuses(book(origin={"sauce": "descriptor"}),
            "unknown origin key", "unknown key")
    refuses(book(origin={"method": "guesswork"}),
            "method outside the three", "method must be one of")
    refuses(book(origin={"chain": "recieve"}),
            "misspelled chain", "chain must be one of")
    refuses(book(origin={"range": [0]}), "range of one", "two integers")
    refuses(book(origin={"range": ["0", "999"]}),
            "range of strings", "two integers")
    refuses(book(origin={"gap_limit": "20"}),
            "gap limit as a string", "must be an integer")
    refuses(book(origin={"derived_at_height": True}),
            "a bool is not a height", "must be an integer")
    print("ok  origin: carried as given, refused when mistyped")


def test_unknown_keys_refused_at_every_level():
    """The rule that looks pedantic and matters most."""
    refuses({"format": ab.FORMAT_TAG, "groups": [], "extra": 1},
            "unknown top-level key", "unknown key")
    refuses(book(adresses=[GENESIS]), "the classic one-d typo",
            "unknown key")
    print("ok  refusal: an unknown key at any level is an error, never "
          "a silent skip")


def test_format_and_shape():
    refuses({"groups": []}, "no format", "format must be")
    refuses({"format": "address-book-v3", "groups": []},
            "a format from the future", "format must be")
    refuses({"format": ab.FORMAT_TAG}, "no groups", "non-empty list")
    refuses({"format": ab.FORMAT_TAG, "groups": []}, "empty groups",
            "non-empty list")
    refuses({"format": ab.FORMAT_TAG, "groups": [[]]}, "a group that is "
            "a list", "must be an object")
    try:
        ab.loads("{not json")
    except ab.BookError as e:
        check("JSON" in str(e), f"a broken file must say so: {e}")
    else:
        fail("accepted something that is not JSON")
    print("ok  refusal: format tag and overall shape")


def test_claim_is_required_and_exact():
    """A default would license the report's strongest sentence on a
    permission nobody gave; an unknown value must not be downgraded to
    the cautious case in silence."""
    g = {"label": "group-a", "addresses": [GENESIS]}
    refuses({"format": ab.FORMAT_TAG, "groups": [g]}, "claim missing",
            "claim must be exactly one of")
    refuses(book(claim="theirs"), "claim outside the two",
            "claim must be exactly one of")
    refuses(book(claim=True), "claim as a boolean",
            "claim must be exactly one of")
    watched = ab.loads(json.dumps(book(claim="watching")))
    check(not watched.groups[0].claims_separation,
          "'watching' must not count as claimed")
    print("ok  refusal: claim required, exact, never defaulted")


def test_labels_and_addresses():
    two = {"format": ab.FORMAT_TAG, "groups": [
        {"label": "group-a", "claim": "separate", "addresses": [GENESIS]},
        {"label": "group-a", "claim": "separate", "addresses": [BIP173]}]}
    refuses(two, "repeated label", "duplicate label")
    refuses(book(label=""), "empty label", "non-empty string")
    refuses(book(label="   "), "whitespace label", "non-empty string")
    refuses(book(addresses=[]), "group without addresses", "non-empty")
    refuses(book(addresses=GENESIS), "addresses as a bare string",
            "non-empty list")
    refuses(book(addresses=[GENESIS, 7]), "a number among the addresses",
            "list of strings")
    print("ok  refusal: labels distinct and non-empty, groups non-empty")


def test_same_address_in_two_groups_is_a_contradiction():
    raw = {"format": ab.FORMAT_TAG, "groups": [
        {"label": "group-a", "claim": "separate", "addresses": [GENESIS]},
        {"label": "group-b", "claim": "separate",
         "addresses": [BIP173, GENESIS]}]}
    refuses(raw, "one address in two compartments",
            "separate from itself")
    print("ok  refusal: an address cannot be meant to be separate from "
          "itself")


def test_repeat_inside_a_group_is_declared_not_refused():
    b = ab.loads(json.dumps(book(addresses=[GENESIS, BIP173, GENESIS])))
    g = b.groups[0]
    check(g.addresses == [GENESIS, BIP173],
          f"the duplicate must be dropped, keeping first position: "
          f"{g.addresses}")
    check(g.duplicates_removed == 1 and b.duplicates_removed == 1,
          "how many were dropped must be declared, not silently absorbed")
    print("ok  dedup: a repeat inside one group is declared, not an error")


def test_two_encodings_of_one_key_are_kept():
    """`1…` and `bc1q…` over the same 20 bytes are two different strings
    and stay two entries: refusing them would erase the sharpest finding
    the report can produce (same key across two compartments)."""
    raw = {"format": ab.FORMAT_TAG, "groups": [
        {"label": "group-a", "claim": "separate", "addresses": [GENESIS]},
        {"label": "group-b", "claim": "separate", "addresses": [BIP173]}]}
    b = ab.loads(json.dumps(raw))
    check(len(b.addresses) == 2, "both encodings must survive the reader")
    print("ok  kept: two encodings of one key are a finding, not a "
          "duplicate")


def test_load_from_disk(tmp):
    path = os.path.join(tmp, "book.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(book(), f)
    b = ab.load(path)
    check(b.addresses == [GENESIS, BIP173], "reading from disk lost the "
                                            "addresses")
    print("ok  load: the same reader from a file on disk")


def main():
    test_minimal()
    test_origin_is_read_and_typed()
    test_unknown_keys_refused_at_every_level()
    test_format_and_shape()
    test_claim_is_required_and_exact()
    test_labels_and_addresses()
    test_same_address_in_two_groups_is_a_contradiction()
    test_repeat_inside_a_group_is_declared_not_refused()
    test_two_encodings_of_one_key_are_kept()
    with tempfile.TemporaryDirectory() as tmp:
        test_load_from_disk(tmp)
    print("PASS: the address book reads what it promises and refuses "
          "every file that would shrink a report in silence.")


if __name__ == "__main__":
    main()
