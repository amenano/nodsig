#!/usr/bin/env python3
"""
address_book.py — the reader for `address-book-v2`, the input format of
the address check: a list of addresses plus the two things a bare list
cannot say.

WHY A FORMAT AT ALL
===================
`check` already takes addresses on the command line or one per line in a
text file, and for the per-address questions that is enough. Two answers
need more than a list:

    compartments   which addresses their owner MEANT to keep apart. It
                   is the left half of the report's most useful
                   comparison: intended separation against observed
                   separation. A flat list has no compartments, so the
                   comparison cannot even be stated;
    a claim        whether the compartment was MEANT to stay apart from
                   the others. "A and B are linked" asks the author
                   nothing — the evidence is on the chain. "A and B
                   still look separate" says nothing at all unless
                   somebody claimed they were meant to be: two random
                   addresses are trivially unlinked.

Hence `claim`, and hence it is REQUIRED. A default would license the
report's strongest sentence on a permission nobody gave. It is a string
and not a boolean because a third case arrives as a new value instead of
a new type.

WHAT THE CLAIM IS NOT: a statement of OWNERSHIP. It says these addresses
were meant to be kept apart from the other groups claimed the same way,
and nothing more. nodsig cannot know who controls an address — that
would take a signature — and a format that asked would be collecting an
answer it can neither use nor check. `separate` and `watching` therefore
name what the author INTENDED about the addresses, never a relationship
between the author and them.

`origin` is the third thing, and it is what lets the report say a
coverage sentence instead of admitting it knows nothing. Every field in
it is REPORTED AS THE AUTHOR'S CLAIM and verified by nothing here: the
report renders it attributed, never asserted.

WHY UNKNOWN KEYS ARE REFUSED
============================
The rule that looks pedantic and matters most: a key this reader does
not know is an error at every level. An `"adresses"` with one `d`,
skipped in silence, is half a wallet left unchecked inside a report that
looks complete — the falsely reassuring outcome, which is the worst
class of defect this project has. The output format goes the other way
on purpose (a reader there ignores keys it does not know): there it is
us adding keys, here it is the user mistyping them.

WHAT THIS FORMAT DELIBERATELY HAS NOT
=====================================
No field for an xpub or a descriptor: a field that exists gets filled,
and then the file gets pasted into an issue. The 8-digit checksum
identifies without containing. No file paths: nothing in the book makes
anything open. No scores, thresholds or words of judgement, in or out.
No per-address note in v1 — every free-text field is one more place for
something to end up that then leaves in the report.

A WARNING THAT BELONGS TO THE USER
==================================
The `label`s appear in the report. Somebody who names a group "my
mother's account" has just written that sentence into a file they might
share.
"""

import json

FORMAT_TAG = "address-book-v2"

CLAIMS = ("separate", "watching")

GROUP_KEYS = ("label", "claim", "addresses", "origin")

# Origin: every field optional, every field a claim. The types are
# checked even though the content is not verified — a `chain` of
# "recieve" would be rendered verbatim in the report and read as a fact
# about how the list was derived.
#
# The name is `origin` because the obvious alternative is a word this
# project reserves to one job elsewhere. See AGENTS.md, "Words reserved
# to ONE job": one word for one job is what keeps a format document
# readable, and `tests/test_layering.py` keeps this honest.
ORIGIN_KEYS = ("method", "descriptor_checksum", "script_type",
               "chain", "range", "gap_limit", "derived_at_height",
               "derived_by")
ORIGIN_METHODS = ("descriptor", "wallet-export", "manual")
ORIGIN_CHAINS = ("receive", "change", "both")


class BookError(ValueError):
    """The file is not a valid address book, with the reason. Never a
    warning: this reader refuses instead of guessing, because every
    guess it could make would shrink what the report checked without
    saying so."""


def _keys(obj, allowed, where):
    if not isinstance(obj, dict):
        raise BookError(f"{where} must be an object")
    unknown = [k for k in obj if k not in allowed]
    if unknown:
        raise BookError(
            f"{where}: unknown key(s) {', '.join(sorted(unknown))} — "
            f"known keys are {', '.join(allowed)}. Refused rather than "
            "ignored: a mistyped key would silently drop addresses from "
            "a report that still looks complete")


class Group:
    """One compartment: the addresses in the order they were written,
    what the author claims about them, and how they say they got them.

    THE ORDER IS PART OF THE MEANING. When the list comes from a
    descriptor the position IS the derivation index, so the report can
    say "the 17th receive address" without the format carrying one more
    field."""

    __slots__ = ("label", "claim", "addresses", "origin",
                 "duplicates_removed")

    def __init__(self, label, claim, addresses, origin=None,
                 duplicates_removed=0):
        self.label = label
        self.claim = claim
        self.addresses = addresses
        self.origin = origin
        self.duplicates_removed = duplicates_removed

    @property
    def claims_separation(self):
        """Only a group claimed `separate` takes part in the separation
        sentences (§the claim, above). A `watching` group is not second
        class: links TOWARDS it are searched and reported like any other.

        The claim says nothing about OWNERSHIP, and the name is careful
        about it: nodsig has no way to know who controls an address and
        does not ask. What is claimed is that these addresses were meant
        to be kept apart from the other groups claimed the same way, and
        that intent is the only thing the separation sentences need."""
        return self.claim == "separate"


class AddressBook:
    """The whole file, read and checked."""

    __slots__ = ("groups",)

    def __init__(self, groups):
        self.groups = groups

    @property
    def addresses(self):
        """Every address, groups in file order, addresses in group
        order. The same address cannot appear twice: two groups sharing
        one is refused, and within a group it is deduplicated."""
        return [a for g in self.groups for a in g.addresses]

    @property
    def duplicates_removed(self):
        return sum(g.duplicates_removed for g in self.groups)

    def group_of(self, address_text):
        """→ the label of the group that listed this address, or None
        for an address that came from the command line instead."""
        for g in self.groups:
            if address_text in g.addresses:
                return g.label
        return None


def _origin(raw, label):
    where = f"group {label!r}: origin"
    _keys(raw, ORIGIN_KEYS, where)
    p = dict(raw)
    if "method" in p and p["method"] not in ORIGIN_METHODS:
        raise BookError(f"{where}: method must be one of "
                        f"{', '.join(ORIGIN_METHODS)}")
    if "chain" in p and p["chain"] not in ORIGIN_CHAINS:
        raise BookError(f"{where}: chain must be one of "
                        f"{', '.join(ORIGIN_CHAINS)}")
    rng = p.get("range")
    if rng is not None and not (isinstance(rng, list) and len(rng) == 2
                                and all(isinstance(v, int)
                                        and not isinstance(v, bool)
                                        for v in rng)):
        raise BookError(f"{where}: range must be two integers")
    for k in ("gap_limit", "derived_at_height"):
        if k in p and (not isinstance(p[k], int)
                       or isinstance(p[k], bool)):
            raise BookError(f"{where}: {k} must be an integer")
    for k in ("descriptor_checksum", "script_type", "derived_by"):
        if k in p and not isinstance(p[k], str):
            raise BookError(f"{where}: {k} must be a string")
    return p


def _group(raw, index, seen_labels, seen_addresses):
    where = f"group #{index}"
    _keys(raw, GROUP_KEYS, where)

    label = raw.get("label")
    if not isinstance(label, str) or not label.strip():
        raise BookError(f"{where}: label must be a non-empty string")
    if label in seen_labels:
        raise BookError(f"duplicate label {label!r}: labels name the "
                        "compartments and must be distinct")
    seen_labels.add(label)

    claim = raw.get("claim")
    if claim not in CLAIMS:
        raise BookError(
            f"group {label!r}: claim must be exactly one of "
            f"{' or '.join(repr(c) for c in CLAIMS)} (got {claim!r}). "
            "An unknown value is not quietly downgraded to the cautious "
            "case: somebody who wrote it meaning 'watching' would get a "
            "report silent on half its sentences, with no reason given")

    raw_addresses = raw.get("addresses")
    if (not isinstance(raw_addresses, list) or not raw_addresses
            or not all(isinstance(a, str) and a.strip()
                       for a in raw_addresses)):
        raise BookError(f"group {label!r}: addresses must be a non-empty "
                        "list of strings")

    # Repeated inside one group is NOT an error: it is deduplicated and
    # declared. Repeated ACROSS groups is a contradiction — nobody can
    # have meant to keep an address apart from itself — so the file does
    # not describe the compartments it claims to describe.
    addresses, dropped = [], 0
    for a in raw_addresses:
        if a in addresses:
            dropped += 1
            continue
        if a in seen_addresses:
            raise BookError(
                f"address {a} is in group {label!r} and in group "
                f"{seen_addresses[a]!r}: an address cannot be meant to "
                "be separate from itself")
        seen_addresses[a] = label
        addresses.append(a)

    origin = raw.get("origin")
    if origin is not None:
        origin = _origin(origin, label)

    return Group(label, claim, addresses, origin, dropped)


def loads(text):
    """Parse an address book from JSON text → AddressBook."""
    try:
        raw = json.loads(text)
    except ValueError as e:
        raise BookError(f"not valid JSON: {e}")
    _keys(raw, ("format", "groups"), "the address book")
    if raw.get("format") != FORMAT_TAG:
        raise BookError(f"format must be {FORMAT_TAG!r}, got "
                        f"{raw.get('format')!r}")
    groups_raw = raw.get("groups")
    if not isinstance(groups_raw, list) or not groups_raw:
        raise BookError("groups must be a non-empty list")

    seen_labels, seen_addresses = set(), {}
    groups = [_group(g, i, seen_labels, seen_addresses)
              for i, g in enumerate(groups_raw)]
    return AddressBook(groups)


def load(path):
    """Read an address book from disk → AddressBook."""
    with open(path, encoding="utf-8") as f:
        return loads(f.read())
