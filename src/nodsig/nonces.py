#!/usr/bin/env python3
"""
nonces.py: every signature nonce point ever published in a confirmed
block, sorted, with the height that published it.

THE QUESTION. Every ECDSA signature carries a public value `r`, the
x-coordinate of the point k*G, where k is the one-time secret ("nonce")
the signer drew. Sign two different messages with the same key and the
same k, and both signatures show the same r: the two equations then have
two unknowns, and the private key falls out with school algebra. This is
not a theoretical weakness, it is the single most productive class of
real key recovery on the chain, and it is visible from public data
alone. Schnorr (BIP 340, taproot) publishes the same quantity even more
directly, as the leading 32 bytes of the signature, and on the same
curve: a broken generator that signs a legacy input and a taproot input
with one k is compromised across both, which is why this artifact keeps
the two schemes in ONE keyspace and records the scheme in a byte.

WHAT ONE RECORD IS: `point (12) | height (3) | flags (1)`, 16 bytes, one
record per signature, sorted by the whole record. Nothing is
deduplicated: two signatures sharing a nonce inside one block are two
records, and erasing that would erase the finding. The flags byte holds
the scheme in two bits and the SIGHASH MODE in three more: what a
signature committed to is half of what recovering a key from a repeated
nonce needs, the signature carries it already, and no artifact we keep
could give it back later. The format is `docs/formats/Nonces-v3.md`,
which is the source this module follows.

Because the fusion REDUCES NOTHING and every record carries its own
height, two properties come for free and are contractual:

    append ≡ rebuild     growing in two passes yields the bytes, and so
                         the fingerprint, of one pass to the same height;
    rewind ≡ rebuild     dropping the records above a cut leaves a sorted
                         file sorted, so a rewind is a fusion with a
                         filter (genstore's `sift`), not a second builder.

The reveal archive cannot have the second one: it folds many sightings
into one record, so it cannot restore what it folded. This artifact pays
16 bytes a signature and gets reversibility for it.

A GROUP IS A CANDIDATE, NOT A COMPROMISED KEY. Recovering a key needs
one key signing twice with one nonce, and a record holds no key; for a
taproot key-path spend the key is not even in the input, since it lives
in the output being spent. What closes the gap is the height: groups are
rare, so the keys are recovered by re-reading only the blocks a group
names. And only EXACT repetitions are covered: a biased or partially
leaked nonce is attacked with lattices over many signatures of one key,
which is different inputs and a different computation, and out of this
perimeter.

WHAT IT COST, AND HOW THAT WAS DECIDED. This module began as a gate: the
risk was never disk, it was CPU on a pass over 3.4 billion inputs, where
one microsecond per input is one hour. `bench` is that measurement and
stays here, because a cost that was measured once should be re-measurable
on someone else's node. Over 20,000 real blocks and 116.3 million
non-coinbase inputs (a recent window, and a stride-95 sample of the whole
chain), the extraction costs 1.97 to 2.00 microseconds per input when it
shares the scriptSig pushes with the archive walk, which is +9.5% to
+10.9% of the per-input CPU a scan already spends, about 1.9 hours over
the chain, plus 0.7 hours to sort the 55 GB of transient runs. The two
samples agree to within 2%, and that agreement is what makes the
projection worth quoting.

The same measurement taught the shape rules three things no fixture
would have shown, all of them in the code below: at 64 and 65 bytes a
leading 0x30 is usually a Schnorr R.x and not a broken DER sequence; the
"looks like a public key" guard must not apply to a lone witness item,
where it was discarding 169 real signatures per 150 blocks; and repeated
POINTS (4 in 4.25 million inputs) and repeated SIGHTINGS (4,491 of a
single deliberate tiny-r value) differ by three orders of magnitude, so
a report that quotes one number for both describes a handful of known
constructions as an epidemic.

Subcommands:

    merge    fuse the runs (and the previous generation) into the next
             one, and seal: manifest, identity, canonical fingerprint.
    verify   re-read every byte against the manifest, rebuild the ladder
             from the file it indexes, recompute the fingerprint;
             `--deep` adds a pass over every record.
    rewind   bring a sealed artifact back to a height it already covers,
             in the bytes a build stopped there would have written.
    groups   every point with two or more sightings, its count and
             span; tiny-r points flagged as a shape, never as a motive.
    lookup   was this nonce point ever published, and where?
    resolve  re-read the blocks the repeated points name and keep the
             evidence that decides them, as a sealed witness table.
    witness-verify  audit that table, re-derive its resolutions, and
             optionally write them as CSV (the export hangs off the audit,
             so a resolution that leaves here has been checked).
    address  the owner's question instead of the chain's: did THIS
             address's key ever repeat a nonce with itself? Joins the
             index, the derivatives and the node on the outpoint, so it
             reads a handful of blocks and knows exactly which signature
             is the one being asked about.
    bench    what the extraction costs, measured on real blocks.

The scan itself is not here: this artifact is co-emitted by the pass
that builds the reveal archive (`archive scan --nonces <dir>`), which
already fetches, verifies and walks every input, and hands over the
scriptSig pushes it has just parsed.
"""

import argparse
import hashlib
import heapq
import json
import os
import sys
import time
from collections import Counter

from nodsig import blockparse
from nodsig.artifact import (WallClock, make_identity, producer,
                             seal_manifest, verify_sealed)
from nodsig.blockparse import scriptsig_pushes
from nodsig.genstore import GenStore, new_state_fields
from nodsig.recio import atomic_json, read_fixed
from nodsig.recsort import SortedFile

FORMAT_TAG = "nonces-v3"

# The censuses this code READS. v3 differs from v2 in what was collected,
# not in how it is laid out: `signature_r` now refuses values ECDSA cannot
# produce, so a v3 census holds the same records minus a handful that were
# never signatures. Everything that reads one (lookup, groups, verify,
# resolve, check) works on either, which is why anyone who downloaded the
# published v2 artifact keeps a working tool.
#
# BUILDING is a different question and stays on FORMAT_TAG alone. A merge
# that extended a v2 base would write a file no v3 rebuild could reproduce,
# because the base carries records the new rules reject: `append ≡ rebuild`
# is contractual, and this is exactly where it would break. Same for a
# rewind, which promises the bytes a build stopped at that height would
# have written. So `_load_state` is strict unless a caller asks otherwise,
# and only the read paths ask.
READ_TAGS = (FORMAT_TAG, "nonces-v2")
STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
RUNS_DIR = "runs"
CATEGORY = "nonces"          # one logical file, so one run category
LOGICAL = "nonces"


class NonceError(RuntimeError):
    """Raised when the artifact on disk is not what it claims to be."""


# ---------------------------------------------------------------------------
# The extraction kernel
# ---------------------------------------------------------------------------

# Bytes of the nonce point kept per record. Top bytes, not bottom: the
# order of the truncated key is the order of the full one, so a sorted
# file of prefixes is a sorted file of nonce points.
R_PREFIX = 12
HEIGHT_BYTES = 3             # 16.7M heights, around 318 years of chain
REC = R_PREFIX + HEIGHT_BYTES + 1
POINT_LEN = R_PREFIX

# Which scheme carried the sighting. A bitfield rather than an enum so a
# group can be summarized by OR-ing its members, and so a future scheme
# costs a bit instead of a format.
FLAG_ECDSA = 1
FLAG_SCHNORR = 2
SCHEME_MASK = FLAG_ECDSA | FLAG_SCHNORR
# What a single record may carry in the SCHEME bits: one bit, because a
# record is one signature. Their OR is what a GROUP shows, which is a
# reader's summary and never a stored value.
SINGLE_FLAGS = frozenset((FLAG_ECDSA, FLAG_SCHNORR))

# Bits 2..4: WHAT the signature committed to, the sighash mode, in three
# bits that were idle. The signature carries the byte already (the DER
# trailer, or the 65th byte of the long BIP 340 form), the extraction
# has it in hand at zero cost, and no artifact we keep could give it
# back later: the graph holds no unlocking data and the archive holds
# hashes. It belongs here because it is what the artifact's own purpose
# needs — two signatures under one nonce are solvable only together with
# what each of them signed.
SIGHASH_SHIFT = 2
SIGHASH_MASK = 0b111 << SIGHASH_SHIFT
SIGHASH_ABSENT = 0      # no byte at all: the 64-byte BIP 340 form
SIGHASH_ALL = 1         # 0x01
SIGHASH_NONE = 2        # 0x02
SIGHASH_SINGLE = 3      # 0x03
SIGHASH_ALL_ACP = 4     # 0x81
SIGHASH_NONE_ACP = 5    # 0x82
SIGHASH_SINGLE_ACP = 6  # 0x83
SIGHASH_OTHER = 7       # any other byte
# The map is exact and closed: the six standard bytes get a code each,
# absence gets its own, and everything else collapses into OTHER. The
# collapse is not laziness, it is the honest floor: an ECDSA sighash
# byte is NOT constrained by consensus (BIP 66 validates the DER shape,
# strict encoding is policy), so early history holds bytes no rule
# describes, and inventing a code per oddity would be inventing meaning.
# Taproot's byte IS constrained, to the six, so a Schnorr record can
# never carry OTHER, and `verify --deep` says so.
SIGHASH_CODES = {0x01: SIGHASH_ALL, 0x02: SIGHASH_NONE,
                 0x03: SIGHASH_SINGLE, 0x81: SIGHASH_ALL_ACP,
                 0x82: SIGHASH_NONE_ACP, 0x83: SIGHASH_SINGLE_ACP}
SIGHASH_NAMES = {SIGHASH_ABSENT: "default", SIGHASH_ALL: "all",
                 SIGHASH_NONE: "none", SIGHASH_SINGLE: "single",
                 SIGHASH_ALL_ACP: "all|acp", SIGHASH_NONE_ACP: "none|acp",
                 SIGHASH_SINGLE_ACP: "single|acp",
                 SIGHASH_OTHER: "nonstandard"}

FLAGS_DEFINED = SCHEME_MASK | SIGHASH_MASK

# Every 4096th record's point is sampled into the ladder while the fusion
# writes: about 10 MB resident for a full chain, one 64 KB bucket per
# lookup. A cache, never in the fingerprint.
LADDER_EVERY = 4096

# What `verify` needs to rebuild the ladder from the file it indexes:
# logical name → (record width, key length, step). Declared once, so the
# seal and the audit cannot drift apart and raise a false alarm.
LADDERS = {LOGICAL: (REC, POINT_LEN, LADDER_EVERY)}

# The sighash byte a 65-byte BIP 340 signature may carry. The 64-byte
# form means "default" and carries none; 0x00 is explicitly forbidden in
# the long form, which is what makes this set a usable filter.
TAPROOT_SIGHASH = frozenset((0x01, 0x02, 0x03, 0x81, 0x82, 0x83))

# First bytes of a serialized public key that is 65 bytes long:
# uncompressed, and the two hybrid forms that early history contains.
# See taproot_r for where a 65-byte item starting with one of these is
# refused, and where it is not.
_KEY_LEAD = frozenset((0x04, 0x06, 0x07))


def new_stats():
    """The counters the extraction fills. Same idiom as the archive's:
    the caller owns the dict, so a scan can carry one across blocks."""
    return {
        "nonces_ecdsa": 0,
        "nonces_schnorr": 0,
        # Items that begin like a DER sequence but do not hold together
        # as one. Counted, never guessed at: this number is how a bench
        # tells a strict rule from a wrong one.
        "malformed_der": 0,
        # A DER integer wider than 32 bytes once its padding is gone.
        # Cannot be a curve scalar, so it is not a signature.
        "oversize_r": 0,
        # A DER integer that held together as one but names a value ECDSA
        # cannot produce: zero, or at/above the group order. See
        # signature_r for why these two lines and no others.
        "impossible_r": 0,
        "malformed_scriptsig": 0,
        "inputs_without_nonce": 0,
    }


# The order of the secp256k1 group, in both forms this module uses. It is
# here for TWO purposes, stated so that its presence is not mistaken for
# something this project does not do: `canonical_s` folds s and n-s
# together, and `signature_r` refuses a value at or above it. That is
# comparison and arithmetic on integers modulo a constant, NOT arithmetic
# on curve points; nothing in this project multiplies a point, derives a
# key, or verifies a signature.
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_ORDER_BE = CURVE_ORDER.to_bytes(32, "big")


def signature_r(item, stats=None):
    """The nonce point of a DER ECDSA signature, as 32 big-endian bytes.

    Returns None if the bytes are not one. Two things are checked, and
    it is worth keeping them apart. First the layout:

        0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s> <sighash byte>

    with `len` covering everything between itself and the sighash byte.
    The three markers, the two lengths and the total must agree exactly,
    which is a strong enough filter that a false positive would have to
    be data deliberately shaped like a signature. That matters more here
    than in the reveal archive, where over-collection is provably
    harmless: two inputs carrying the same non-signature bytes would
    look like a repeated nonce.

    Then the two VALIDITY rules on the value itself, `r != 0` and
    `r < n`. Shape alone accepts bytes that no signer could have
    produced, and the chain holds them: one 12-byte census point turned
    out to carry three different whole values, `0`, `1` and `82`. Those
    are not signatures, and until this rule existed the census collected
    them and a reader had to be told so afterwards. Nothing here
    verifies a signature, and these two comparisons do not begin to:
    they only refuse values the definition of ECDSA excludes.

    `r` is canonicalized before it is truncated, its leading zero
    padding removed and the value left-padded to 32 bytes, so the same
    scalar always yields the same point whether it was encoded minimally
    (BIP 66, consensus since 2015) or not. Without that, one repeated
    nonce would split into two singletons and report nothing.
    """
    n = len(item)
    if n < 9 or item[0] != 0x30:
        return None
    # From here on the item claims to be a signature, so a failure is
    # worth counting rather than ignoring. With one exception, found by
    # measuring: at exactly 64 or 65 bytes a leading 0x30 is far more
    # often the first byte of a Schnorr R.x than a broken DER sequence
    # (one taproot signature in 256 starts that way, and the chain has
    # billions). Those two lengths are still PARSED, since a short r and
    # s can genuinely produce them; they are just not counted as
    # malformed, because at that length nothing can tell the two apart
    # and a counter that cries wolf is worse than no counter.
    if stats is not None and n in (64, 65):
        stats = None
    if item[1] != n - 3 or item[2] != 0x02:
        if stats is not None:
            stats["malformed_der"] += 1
        return None
    rlen = item[3]
    if rlen == 0 or 6 + rlen > n or item[4 + rlen] != 0x02:
        if stats is not None:
            stats["malformed_der"] += 1
        return None
    slen = item[5 + rlen]
    if slen == 0 or 6 + rlen + slen != n - 1:
        if stats is not None:
            stats["malformed_der"] += 1
        return None
    r = bytes(item[4:4 + rlen]).lstrip(b"\x00")
    if len(r) > 32:
        if stats is not None:
            stats["oversize_r"] += 1
        return None
    # ECDSA's own definition: r is the x-coordinate of k*G taken mod n,
    # so 0 < r < n always. Zero and anything at or above the order are
    # not unlikely, they are IMPOSSIBLE: bytes that had a signature's
    # shape without being one. Both tests ride on the lstrip above: an
    # empty `r` is the value zero, and only a full 32 bytes can reach n,
    # so the comparison is big-endian bytes at C speed and never an
    # int conversion (50.3 ns per signature against 174.6 for the
    # int.from_bytes form: about 3 minutes against 11 over the chain).
    #
    # Note which rule this is NOT. There is no threshold on SIZE: the
    # chain carries consensus-validated signatures whose r is 166 and
    # 223 bits, so "too small to be genuine" would reject real data.
    # Only 0 and n are lines the arithmetic itself draws. The stronger
    # filter, checking that r is the x-coordinate of a real curve
    # point, would halve the false positives and costs one modular
    # exponentiation per signature: out of scale over 3.7 billion, and
    # across the line this project does not cross. It is declared in
    # the format instead of chased.
    if not r or (len(r) == 32 and r >= _ORDER_BE):
        if stats is not None:
            stats["impossible_r"] += 1
        return None
    return bytes(32 - len(r)) + r


def signature_s(item, schnorr=False):
    """The `s` of a signature whose `r` this module already accepted.

    Only ever called on an item `signature_r` or `taproot_r` returned a
    point for, so the shape is known good and nothing is re-validated:
    this reads the second integer of the DER sequence, or the second
    half of a BIP 340 signature. WHICH of the two is the caller's to
    say, never guessed here: at 64 and 65 bytes the two forms are not
    distinguishable from the bytes, which is the same ambiguity
    `signature_r` documents, and the extractor that accepted the item
    already knows which door it came through.

    `s` is what separates a REPEATED NONCE from a COPIED SIGNATURE, and
    the two mean opposite things. Two signatures sharing a nonce point
    expose the key only if they signed different messages, and since
    s = k⁻¹(z + r·d) with k and d fixed by the shared point and the
    shared key, a different message gives a different `s`. An identical
    `s` is the same signature serialized twice, which happens on purpose
    (the SIGHASH_SINGLE bug lets one signature satisfy every input of a
    transaction) and hands over nothing at all.

    The converse needs one more step, and `canonical_s` is where it is
    taken: different `s` does NOT by itself mean a different message.

    Canonicalized like `r`, leading zero padding removed, so that the
    comparison is between values and not between encodings.
    """
    if schnorr:
        return bytes(item[32:64])          # BIP 340: R.x ‖ s
    rlen = item[3]
    slen = item[5 + rlen]
    return bytes(item[6 + rlen:6 + rlen + slen]).lstrip(b"\x00")


def canonical_s(s_bytes):
    """`s` folded with its negation, as the value a comparison should use.

    Two signatures over the SAME message, made with nonces k and -k, are
    both valid and both publish the same `r`: the two nonce points are
    R and -R, which share an x-coordinate. Their s values are s and
    n-s, so they DIFFER while the signed message does not, and reading
    that difference as two messages would announce a key recovery that
    does not exist. Folding to min(s, n-s) makes the pair compare equal,
    which is what the caller means to ask.

    This is not hypothetical: over the chain's repeated points it happens
    (measured: one pair in about 1,600). Low-s is relay policy and not
    consensus, so the high-s form is on the chain and always may be.

    Schnorr is not affected. BIP 340 fixes R to the even-y point, so k is
    determined and there is no second form; passing a BIP 340 `s` through
    here is harmless, because n-s cannot also appear.
    """
    s = int.from_bytes(s_bytes, "big")
    other = CURVE_ORDER - s
    return min(s, other).to_bytes(32, "big")


def taproot_r(item, key_path=False):
    """The nonce point of a BIP 340 signature, as 32 big-endian bytes.

    A Schnorr signature is R.x (32 bytes) followed by s (32 bytes), with
    an optional sighash byte after it. There is no internal structure to
    check, so the shape rule has to earn its confidence elsewhere:

    - a 65-byte item must end in a legal sighash byte, which consensus
      guarantees for the long form and which no other 65-byte payload has
      a reason to satisfy;
    - the caller decides WHERE to apply this (see _taproot_slots), which
      is what keeps 64-byte witness scripts and control blocks out;
    - `key_path` says the item is the ONLY thing in the witness, so it
      can only be the signature of a key-path spend. Anywhere else, a
      65-byte item that begins like an uncompressed or hybrid public key
      is refused: keys are the one payload at this length that recurs
      identically across inputs, so reading one as a nonce would
      manufacture a repeated-nonce group out of an ordinary wallet.

    The `key_path` distinction is not a micro-optimization, it was
    measured: over 150 recent blocks the guard was rejecting 169 real
    signatures (1.17% of the 65-byte form, i.e. the 3 first bytes out of
    256 that a key can start with) and protecting nothing, because a
    witness holding a single item cannot be holding a pushed key.

    THE VALIDITY RULES OF `signature_r` DO NOT TRANSFER HERE, and the
    asymmetry is deliberate rather than an oversight. An ECDSA `r` is a
    scalar reduced mod n, so `r >= n` is impossible. A BIP 340 `R.x` is
    not reduced at all: it is a FIELD element, bounded by p, and p is
    larger than n. An x-coordinate between n and p is a perfectly valid
    point, so refusing one here would throw away a real signature. The
    gap is about 2^129 wide out of 2^256, which is why nobody has seen
    one, but "vanishingly rare" is the wrong reason to keep a rule, and
    the wrong reason to drop one. This module refuses only what the
    arithmetic excludes, and here the arithmetic excludes nothing.
    """
    n = len(item)
    if n == 64:
        return bytes(item[:32])
    if n == 65 and item[64] in TAPROOT_SIGHASH:
        if key_path or item[0] not in _KEY_LEAD:
            return bytes(item[:32])
    return None


def _taproot_slots(witness):
    """The witness items that a Schnorr signature could occupy.

    Taproot spends put their signatures in fixed places (BIP 341), and
    using that is the difference between a census and a pile of false
    positives: the LAST item of a script-path spend is the control
    block, and the one before it the leaf script, both of which repeat
    byte for byte every time the same tree is spent. A 64-byte one of
    those would look like the same nonce over and over.

    An annex, if present, is the last item and starts with 0x50; it is
    never a signature either.

    The rule is applied without knowing the input's type, so on a P2WSH
    spend it returns a couple of items that are simply not 64 or 65
    bytes long. Being wrong there is free; being wrong the other way is
    not.

    Returns the candidate items and whether this is a key-path spend,
    which is the one case where a lone 65-byte item cannot be a pushed
    public key (see taproot_r).
    """
    if not witness:
        return (), False
    items = witness
    if len(items) >= 2 and items[-1][:1] == b"\x50":
        items = items[:-1]
    if len(items) == 1:
        return items, True                # key path: the item IS the signature
    return items[:-2], False              # script path: script, control block


def extract_nonces(tx_in, stats, sig_pushes=None, detail_out=None):
    """Every nonce point one input reveals, as (flags, 12-byte point).

    Signatures live in exactly two places, and both are walked: the
    pushes of the scriptSig, and the witness items. Redeem and witness
    scripts are NOT walked for signatures the way the reveal archive
    walks them for keys, because a script holds the conditions, never
    the signature that satisfies them.

    `sig_pushes` is the door for sharing: the archive walk parses the
    scriptSig pushes for its own reasons, and handing them over here
    means the chain's scriptSigs are parsed once instead of twice. It is
    worth about half a microsecond per input, which is half an hour over
    the chain, and it must not change the answer (a test pins that).

    `detail_out`, when a list is passed, is filled with one
    `(full r, canonical s, s as serialized)` triple per point returned, in the same order,
    so a caller that needs to tell a repeated nonce from a copied
    signature gets both out of the walk it already paid for. The full
    `r` is there because the returned point is TRUNCATED to 12 bytes,
    and two different scalars can share that prefix: comparing the
    prefixes would merge two nonces into one apparent repeat (it happens
    about once in 5,000 groups over the chain).

    The chain scan passes nothing and so pays one `is None` test per
    signature: this function is 10% of the pass's CPU and the census
    itself has no use for either value (see Nonces-v3 on why the record
    is 16 bytes). Only the per-address question needs them, on the few
    blocks the index names.
    """
    if sig_pushes is None:
        sig_pushes = scriptsig_pushes(tx_in, stats)

    out = []
    ecdsa = 0
    for p in sig_pushes:
        r = signature_r(p, stats)
        if r is not None:
            out.append((FLAG_ECDSA | sighash_bits(p[-1]), r[:R_PREFIX]))
            ecdsa += 1
            if detail_out is not None:
                s = signature_s(p)
                detail_out.append((r, canonical_s(s), s))
    for item in tx_in.witness:
        r = signature_r(item, stats)
        if r is not None:
            out.append((FLAG_ECDSA | sighash_bits(item[-1]), r[:R_PREFIX]))
            ecdsa += 1
            if detail_out is not None:
                s = signature_s(item)
                detail_out.append((r, canonical_s(s), s))
    slots, key_path = _taproot_slots(tx_in.witness)
    for item in slots:
        r = taproot_r(item, key_path)
        if r is not None:
            # 64 bytes is the short form: it commits to ALL by consensus
            # and publishes no byte, which is a fact about the signature
            # and gets its own code rather than being folded into `all`.
            byte = item[64] if len(item) == 65 else None
            out.append((FLAG_SCHNORR | sighash_bits(byte), r[:R_PREFIX]))
            if detail_out is not None:
                s = signature_s(item, schnorr=True)
                detail_out.append((r, canonical_s(s), s))

    # Counted as they are found, not by walking `out` again: this
    # function is the thing being timed, and a second pass over its own
    # result would make a measurement report a cost the emitter would
    # not pay.
    stats["nonces_ecdsa"] += ecdsa
    stats["nonces_schnorr"] += len(out) - ecdsa
    if not out:
        stats["inputs_without_nonce"] += 1
    return out


def sighash_bits(byte):
    """The sighash bits of a record, from the signature's trailing byte
    (None when the form carries none)."""
    if byte is None:
        code = SIGHASH_ABSENT
    else:
        code = SIGHASH_CODES.get(byte, SIGHASH_OTHER)
    return code << SIGHASH_SHIFT


def rec_sighash(rec_or_flags):
    """The sighash code of a record's flags byte."""
    return (rec_or_flags & SIGHASH_MASK) >> SIGHASH_SHIFT


def record(point, height, flags):
    """One 16-byte record: point | height | flags, big-endian throughout.

    The point leads, so sorting the raw bytes groups the sightings of one
    nonce; the height comes next, so a group comes out in chain order;
    the flags trail, because they are what a group summarizes rather than
    what it is keyed by. A record is a single bytes object and not a
    tuple because sorting billions of them is half the cost of building
    this artifact.
    """
    return point + height.to_bytes(HEIGHT_BYTES, "big") + bytes((flags,))


def rec_point(rec):
    return rec[:POINT_LEN]


def rec_height(rec):
    return int.from_bytes(rec[POINT_LEN:POINT_LEN + HEIGHT_BYTES], "big")


def rec_flags(rec):
    return rec[REC - 1]


def is_tiny(point, zero_bytes=3):
    """True for a nonce point whose top `zero_bytes` bytes are zero.

    This is a SHAPE, not a motive. A drawn nonce lands here about once in
    2^(8·zero_bytes), i.e. once in 2^24 at the default, so at chain scale
    a few hundred ordinary points fall in with any that were constructed,
    and this predicate cannot tell the two apart: it reads the top bytes,
    it does not read intent. The report
    separates tiny points because they are the largest groups in the
    artifact and folding them in with the rest would read as an epidemic
    of one shape; naming the shape is not claiming a reason for it. What
    a tiny point means for a given group is a question for a block
    re-read, not for a byte test.
    """
    return point[:zero_bytes] == bytes(zero_bytes)


# ---------------------------------------------------------------------------
# Emission: grown alongside the scan that builds the reveal archive
# ---------------------------------------------------------------------------

class NonceEmitter:
    """Grows a nonce archive alongside a host scan.

    The contract with the host is the graph emitter's:

        emitter = NonceEmitter(nonces_dir)
        emitter.load(start_height)              # lines up, or refuses
        emitter.add_input(h, tx_in, pushes)     # every non-coinbase input
        emitter.flush_if_full(h)                # once per window
        emitter.checkpoint(h, hash_hex)         # at the host's checkpoint,
                                                # just BEFORE the host's
                                                # own state is written

    Checkpointing before the host leaves this archive AHEAD after a
    crash, which is the direction `load` can heal: the host re-feeds
    those blocks, so a run that starts past the resume point is dropped
    and re-emitted. The other order would leave a hole, which nothing
    can heal.

    The storage is `genstore`: sorted runs pile up, a fusion folds them
    into the next generation. That store is shared with the outpoint
    index and the derivatives, and it fits here unchanged for one
    reason: this format's fusion REDUCES NOTHING. The reveal archive
    could not use it precisely because its fusion ORs flags and takes
    minima, and widening the store to carry a reducer during a format
    break was two risks in one place.
    """

    def __init__(self, nonces_dir, flush_records=8_000_000):
        self.dir = nonces_dir
        self.flush_records = flush_records
        self.state = None
        self.store = None
        self.buffer = []
        self.stats = new_stats()
        self.stats_valid = True      # False: a heal had no snapshot to
                                     # step back to, the counters are
                                     # honest null from here on
        self.watermark = None        # last height fed OR committed
        self.seg_start = None        # first height the open buffer covers

    # -- lifecycle ---------------------------------------------------------

    def _stats_snapshot(self):
        """What the state records as the counters, and the one rule that
        keeps the history honest: a COPY, never `self.stats` itself.

        The extraction adds to that dict input by input. Stored by
        reference, what the state calls the counters "as of height H"
        would go on growing past H, and `scan_stats_prev`, which is only
        ever the value an earlier checkpoint left here, would hold the
        present instead of the past. The step-back in `_heal`
        would then restore the very numbers it means to undo, the
        re-fed interval would be counted twice, and nothing in the
        state would look wrong.
        """
        return dict(self.stats) if self.stats_valid else None

    def _new_state(self):
        state = {"format": FORMAT_TAG, "last_height": 0,
                 "merged_height": 0, "last_block_hash": None,
                 "scan_stats": new_stats(), "rewound_from": None}
        state.update(new_state_fields())
        return state

    def load(self, start_height):
        """Open (or create) the archive and line it up with a scan that
        will feed inputs from `start_height` on."""
        os.makedirs(self.dir, exist_ok=True)
        state_path = os.path.join(self.dir, STATE_NAME)
        if not os.path.exists(state_path):
            if start_height > 1:
                raise NonceError(
                    f"this scan resumes at height {start_height}, so a new "
                    "nonce archive would start there and could never be made "
                    "whole: the signatures below it would have to come from a "
                    "pass that is already over. Emission cannot be turned on "
                    "midway, use a fresh scan directory")
            self.state = self._new_state()
        else:
            with open(state_path) as f:
                self.state = json.load(f)
            found = self.state.get("format")
            if found != FORMAT_TAG:
                if found in READ_TAGS:
                    raise NonceError(
                        f"this archive is {found} and this scan emits "
                        f"{FORMAT_TAG}: the two collect different things, so "
                        "feeding one into the other would write a file no "
                        "rebuild reproduces. Use a fresh scan directory")
                raise NonceError("unknown nonce archive format")
            saved = self.state["scan_stats"]
            self.stats = dict(saved) if saved else new_stats()
            self.stats_valid = saved is not None

        # The scan's clock, carried in THIS census's state. See
        # GraphWriter.clock: one walk feeds four artifacts and each
        # records the same seconds under `scan`, which is why those four
        # numbers must never be added to each other.
        self.store = store_of(self.dir, self.state,
                              clock=WallClock("scan", self.state))
        self.store.make_runs_dir()
        self.store.clean_orphans()
        self._heal(start_height)

        self.watermark = self.state["last_height"]
        self.seg_start = start_height
        return start_height

    def _heal(self, start_height):
        """Reconcile an archive that knows more than the host's state.

        The crash window between the two checkpoint writes leaves this
        one ahead. The host will re-feed every block from its resume
        point, so a run that begins at or after that point would emit
        its blocks twice: dropping it is not data loss, it is the only
        state that can converge. A run that STRADDLES the resume height
        cannot happen when checkpoints are shared, and refusing beats
        guessing where to cut a file.
        """
        keep, drop = [], []
        for run in self.state["runs"]:
            if run.get("start", 0) >= start_height:
                drop.append(run)
            elif run.get("end", 0) >= start_height:
                raise NonceError(
                    f"run {run['name']} straddles the resume height "
                    f"{start_height}: this archive did not grow with this "
                    "scan")
            else:
                keep.append(run)
        self.state["runs"] = keep

        if self.state["merged_height"] >= start_height:
            raise NonceError(
                f"this archive is fused through height "
                f"{self.state['merged_height']:,} but the scan resumes from "
                f"{start_height:,}: a fusion cannot be undone by dropping "
                f"runs. Bring it back first with `nonces rewind --to-height "
                f"{start_height - 1}`")
        if drop:
            # The HOST is authoritative for the coverage, so the watermark
            # becomes the block before its resume point. It is not the
            # highest run end: a stretch of chain whose inputs carry no
            # signature writes no record, so run ends lag the heights that
            # were genuinely scanned, and reading the watermark off them
            # would silently shorten the coverage.
            self.state["last_height"] = start_height - 1
            # The recorded hash belonged to the dropped watermark, and
            # no record here carries one to read back: honest null
            # beats a stale value (the graph's rule).
            self.state["last_block_hash"] = None
            # The dropped blocks are about to be counted AGAIN by the
            # re-feed, so the counters must step back with the records.
            # The previous checkpoint's snapshot is exactly the resume
            # point when checkpoints were shared; an archive paired
            # with some older host state has no snapshot to step back
            # to, and null is the honest value — the same one a rewind
            # writes.
            prev = self.state.get("scan_stats_prev")
            if start_height <= 1:
                # Everything is about to be re-fed: the honest count of
                # what has been walked so far is zero.
                self.stats = new_stats()
            elif (prev and prev["stats"] is not None
                    and prev["height"] == start_height - 1):
                # Copied for the same reason the snapshot is: what is
                # walked from here on must not flow back into it.
                self.stats = dict(prev["stats"])
            else:
                self.stats = new_stats()
                self.stats_valid = False
            self.state["scan_stats"] = self._stats_snapshot()
            # The state first, the deletions after — the store's rule.
            self.store.write_state()
            for run in drop:
                path = self.store.run_path(run["name"])
                if os.path.exists(path):
                    os.remove(path)
                print(f"  nonces: dropped run {run['name']}, past the "
                      "scan's resume point, will be re-emitted",
                      file=sys.stderr)
        if self.state["last_height"] + 1 < start_height:
            raise NonceError(
                f"nonce archive covers 1..{self.state['last_height']:,} but "
                f"the scan resumes from {start_height:,}: the gap between "
                "them would never be filled. Emission cannot be turned on "
                "midway, use a fresh scan directory")

    # -- feeding -----------------------------------------------------------

    def add_input(self, height, tx_in, sig_pushes=None):
        """Emit the records of one non-coinbase input.

        The host passes the scriptSig pushes it has already parsed for
        the reveal archive, so the chain's scriptSigs are parsed once.
        """
        if height > (self.watermark or 0):
            self.watermark = height
        buf = self.buffer
        for flags, point in extract_nonces(tx_in, self.stats, sig_pushes):
            buf.append(record(point, height, flags))

    def flush_if_full(self, through_height):
        """Called once per fetch window: close the buffer into a run if
        it has grown past its cap. Only ever at a block boundary, so a
        run's name describes exactly the heights it holds."""
        if len(self.buffer) >= self.flush_records:
            self._flush(through_height)

    def _flush(self, through_height):
        if not self.buffer:
            self.seg_start = through_height + 1
            return
        name = f"run_{self.seg_start:08d}-{through_height:08d}.bin"
        self.store.write_run(name, CATEGORY, self.buffer)
        # The height interval the run covers, which `_heal` needs and the
        # store itself does not care about. Extra keys ride along in the
        # state's JSON, exactly as the graph archive's runs do.
        self.state["runs"][-1].update(start=self.seg_start,
                                      end=through_height)
        self.buffer = []
        self.seg_start = through_height + 1

    def checkpoint(self, height, block_hash_display):
        """Everything fed so far becomes durable and named. Called by
        the host right before it writes its own state."""
        if self.watermark is not None and height < self.watermark:
            raise NonceError(f"nonce checkpoint at {height} but blocks were "
                             f"fed up to {self.watermark} (host bug)")
        self._flush(height)
        # One checkpoint of history for the counters: it is what _heal
        # steps back to when a crash leaves this archive ahead and the
        # host re-feeds the last interval's blocks. The value moved here
        # is the snapshot the PREVIOUS checkpoint froze, and the line
        # below hands `scan_stats` a new one, so the two never share a
        # dict.
        self.state["scan_stats_prev"] = {
            "height": self.state["last_height"],
            "stats": self.state["scan_stats"]}
        self.state["last_height"] = height
        self.state["last_block_hash"] = block_hash_display
        self.state["scan_stats"] = self._stats_snapshot()
        self.store.write_state()


# ---------------------------------------------------------------------------
# Reading a built archive
# ---------------------------------------------------------------------------

def _load_state(nonces_dir, accept=(FORMAT_TAG,)):
    """The state file, refused unless its format is one of `accept`.

    The default is the tag this code EMITS, so a caller that says
    nothing gets the strict rule. Read-only commands pass `READ_TAGS`
    to also accept the previous census; a builder must not, and the
    comment on READ_TAGS says why.
    """
    path = os.path.join(nonces_dir, STATE_NAME)
    if not os.path.exists(path):
        raise NonceError(f"no {STATE_NAME} in {nonces_dir}: not a nonce "
                         "archive (build one with `archive scan --nonces`)")
    with open(path) as f:
        state = json.load(f)
    found = state.get("format")
    if found not in accept:
        if found in READ_TAGS:
            raise NonceError(
                f"this archive is {found} and the tool writes {FORMAT_TAG}: "
                "it can be read, but not extended or rewound. Growing it "
                "would write records the current rules refuse to collect, "
                "so the result would not be the file a rebuild produces. "
                "Build a fresh one with `archive scan --nonces`")
        raise NonceError("unknown nonce archive format")
    return state


def _load_manifest(nonces_dir, required=True):
    path = os.path.join(nonces_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        if required:
            raise NonceError(
                f"no {MANIFEST_NAME} in {nonces_dir}: the archive has not "
                "been sealed yet, run `nonces merge`")
        return None
    with open(path) as f:
        return json.load(f)


def _merged_entry(state):
    """The current generation's file entry, or None if never fused."""
    return state["files"].get(LOGICAL)


def iter_records(nonces_dir, state=None, verify_sha=True):
    """Stream every record of the fused file, in order.

    The sha is checked as the bytes go past (that is `read_fixed`'s
    job), so a corrupt file cannot be silently reported on.
    """
    state = state or _load_state(nonces_dir, READ_TAGS)
    entry = _merged_entry(state)
    if entry is None:
        return
    path = os.path.join(nonces_dir, entry["file"])
    yield from read_fixed(path, REC,
                          expect_sha=entry["sha256"] if verify_sha else None,
                          error=NonceError)


def open_sorted(nonces_dir, state=None):
    """The fused file as a ladder-backed searchable file."""
    state = state or _load_state(nonces_dir, READ_TAGS)
    entry = _merged_entry(state)
    if entry is None:
        raise NonceError("nothing fused yet: run `nonces merge` first")
    cache = state["caches"].get(LOGICAL)
    blob = b""
    every = LADDER_EVERY
    if cache is not None:
        with open(os.path.join(nonces_dir, cache["file"]), "rb") as f:
            blob = f.read()
        if hashlib.sha256(blob).hexdigest() != cache["sha256"]:
            raise NonceError(f"{cache['file']}: corrupted ladder")
        every = cache["every"]
    return SortedFile(os.path.join(nonces_dir, entry["file"]), REC,
                      POINT_LEN, entry["records"], blob, every,
                      error=NonceError)


# ---------------------------------------------------------------------------
# merge: the fusion, and the seal
# ---------------------------------------------------------------------------

def _tallies(nonces_dir, state):
    """One pass over the fused file: what `build` can recompute.

    Everything here is derivable from the bytes, which is exactly why it
    lives in `build` and not in the identity. Recomputing it at every
    seal is what makes a rewound artifact's manifest equal to a fresh
    build's, instead of carrying counters from a scan that covered more.
    """
    ecdsa = schnorr = records = 0
    groups = sightings = 0
    top = 0
    in_run = 0
    last = None
    for rec in iter_records(nonces_dir, state):
        records += 1
        flags = rec_flags(rec)
        if flags & FLAG_ECDSA:
            ecdsa += 1
        if flags & FLAG_SCHNORR:
            schnorr += 1
        h = rec_height(rec)
        if h > top:
            top = h
        point = rec_point(rec)
        if point == last:
            sightings += 1
            if in_run == 0:
                groups += 1
            in_run += 1
        else:
            in_run = 0
            last = point
    return {"records": records, "ecdsa": ecdsa, "schnorr": schnorr,
            "repeated_points": groups, "repeat_sightings": sightings,
            "highest_height": top}


def _seal(nonces_dir, state, tallies, clock):
    """Write the manifest: identity, fingerprint, and the build block.

    The coverage is the one identity field no digest can prove, so it
    goes INSIDE the identity: a claim about how far the scan reached
    cannot then be moved without moving the fingerprint. The records
    carry a height each, so `verify --deep` can hold that claim to a
    floor, but only a floor, because a stretch of chain whose signatures
    are all fresh nonces leaves nothing that contradicts a taller claim.
    """
    entry = _merged_entry(state)
    files = {LOGICAL: dict(entry)}
    identity = make_identity(FORMAT_TAG, 1, state["last_height"],
                             ((LOGICAL, entry["sha256"]),))
    manifest = seal_manifest(FORMAT_TAG, identity, {
            "producer": producer(),
            "seconds": clock.stamp(state),
            "generation": state["generation"],
            "last_block_hash": state["last_block_hash"],
            "files": files,
            "caches": state["caches"],
            "tallies": tallies,
            # The scan's own counters: history of HOW this copy was
            # built, not of what it contains, and not recomputable from
            # the records. A rewind sets them to null rather than
            # carrying numbers that describe a taller scan.
            "scan_stats": state["scan_stats"],
            "rewound_from": state["rewound_from"],
            "reconstruction": (
                "one record per signature, point | height | flags, sorted by "
                "the whole record with nothing deduplicated; runs are fused "
                "with the previous generation by a plain merge, so append and "
                "rewind both equal a rebuild; the identity is then sealed by "
                "the shared recipe in docs/contracts/Artifact.md"),
    })
    atomic_json(os.path.join(nonces_dir, MANIFEST_NAME), manifest)
    return manifest


def run_merge(nonces_dir):
    """Fuse the pending runs and the previous generation into the next
    one, then seal.

    After a full fusion the artifact at height H is one well-defined set
    of bytes whatever the run boundaries were: an interrupted-and-resumed
    scan fuses to the same file as a one-shot scan, and therefore to the
    same fingerprint. That is the determinism rule of an appendable
    artifact, and this is where it is enforced.
    """
    state = _load_state(nonces_dir)
    clock = WallClock("merge", state)
    store = store_of(nonces_dir, state, clock=clock)
    manifest = _load_manifest(nonces_dir, required=False)
    if not state["runs"] and manifest is not None:
        entry = _merged_entry(state)
        fresh = (entry is not None
                 and manifest["build"]["files"]
                     .get(LOGICAL, {}).get("sha256") == entry["sha256"]
                 and manifest["identity"]["coverage"]["to"]
                     == state["last_height"])
        if fresh:
            print("nothing to fuse: no runs since the last merge.")
            return manifest["fingerprint"]
        # The manifest does not describe the committed file: the mark of
        # a crash between a fusion's commit and its seal. The fused
        # bytes are whole (the commit is what made them the artifact),
        # only the seal is missing — so reseal what is on disk instead
        # of returning a fingerprint whose file no longer exists.
        tallies = _tallies(nonces_dir, state)
        manifest = _seal(nonces_dir, state, tallies, clock)
        print("the seal did not match the fused file (a crash between "
              "fusion and seal): resealed what the state commits")
        print(f"fingerprint: {manifest['fingerprint']}")
        return manifest["fingerprint"]

    # Fuse, tally and seal BEFORE the commit: until the state is
    # written the old generation is still the artifact, so a kill
    # anywhere in this stretch costs only the work. The old order
    # committed first and paid the tallies pass inside the crash
    # window, where a kill left a stale seal over deleted files.
    dups, delete = store.fuse(LOGICAL, LADDERS[LOGICAL], CATEGORY,
                              dedup=None, dedup_len=POINT_LEN)
    state["merged_height"] = state["last_height"]
    tallies = _tallies(nonces_dir, state)
    if tallies["repeat_sightings"] != dups:
        raise NonceError(
            f"the fusion counted {dups:,} equal points but a pass over the "
            f"file finds {tallies['repeat_sightings']:,}: the merged file is "
            "not what the fusion wrote")
    manifest = _seal(nonces_dir, state, tallies, clock)
    store.commit(delete)

    print(f"nonce archive covers heights 1..{state['last_height']:,}")
    print(f"  {tallies['records']:>16,} signatures "
          f"({tallies['ecdsa']:,} ecdsa, {tallies['schnorr']:,} schnorr)")
    print(f"  {tallies['repeated_points']:>16,} repeated points, over "
          f"{tallies['repeat_sightings']:,} extra sightings")
    print(f"fingerprint: {manifest['fingerprint']}")
    return manifest["fingerprint"]


# ---------------------------------------------------------------------------
# verify: the audit of a sealed artifact
# ---------------------------------------------------------------------------

def _audit_records(nonces_dir, manifest, state):
    """One pass over every record: order, flags, heights.

    The order check is `>=` and not `>`: equal records are LEGAL here,
    because two signatures can share a nonce inside one block, and an
    audit that refused them would refuse exactly the finding this
    artifact exists to record.
    """
    covered_to = manifest["identity"]["coverage"]["to"]
    covered_from = manifest["identity"]["coverage"]["from"]
    records = 0
    top = 0
    prev = None
    for rec in iter_records(nonces_dir, state):
        if prev is not None and rec < prev:
            raise NonceError(
                f"record {records:,} breaks the order: a sorted file is what "
                "every lookup and every fusion depends on")
        flags = rec_flags(rec)
        if flags & ~FLAGS_DEFINED or flags & SCHEME_MASK not in SINGLE_FLAGS:
            # Exactly one SCHEME bit, not merely a subset of the defined
            # ones: a record is ONE signature, and one signature has one
            # scheme. The OR of several schemes is what a GROUP has, and
            # a group is computed by a reader, never stored.
            raise NonceError(
                f"record {records:,} carries flags 0x{flags:02x}, which is "
                f"not one of the defined schemes")
        if (flags & SCHEME_MASK == FLAG_SCHNORR
                and rec_sighash(flags) == SIGHASH_OTHER):
            # Taproot's sighash byte is consensus-constrained to the six
            # standard values, so `nonstandard` on a Schnorr record is a
            # statement the chain cannot produce.
            raise NonceError(
                f"record {records:,} is Schnorr with a nonstandard sighash "
                "code, which consensus does not allow")
        h = rec_height(rec)
        if not covered_from <= h <= covered_to:
            raise NonceError(
                f"record {records:,} sits at height {h:,}, outside the "
                f"declared coverage {covered_from:,}..{covered_to:,}")
        if h > top:
            top = h
        prev = rec
        records += 1
    declared = manifest["build"]["files"][LOGICAL]["records"]
    if records != declared:
        raise NonceError(f"the file holds {records:,} records but the "
                         f"manifest says {declared:,}")
    print(f"ok  {records:,} records, non-decreasing, one scheme and a "
          f"defined sighash code each, every height in range")
    return top


def run_verify(nonces_dir, deep=False):
    """Re-read the sealed bytes against the manifest, rebuild the ladder
    from the file it indexes, recompute the fingerprint.

    `--deep` adds a pass over every record and, with it, the only road
    the bytes offer to the coverage: the highest height they hold is a
    floor under the watermark. Without it the report says the coverage
    was taken on trust, because an audit silent about what it did not
    check reads as an audit that checked everything.
    """
    state = _load_state(nonces_dir, READ_TAGS)
    manifest = _load_manifest(nonces_dir)
    if state["runs"]:
        print(f"note: {len(state['runs'])} run(s) written since the last "
              f"merge are NOT SEALED and not audited here", file=sys.stderr)

    top = _audit_records(nonces_dir, manifest, state) if deep else None
    verify_sealed(nonces_dir, manifest, READ_TAGS, NonceError,
                  fp_order=(LOGICAL,),
                  ladders=LADDERS,
                  coverage_from_data=(None if top is None
                                      else lambda: ("floor", top)),
                  trust_hint="--deep")


# ---------------------------------------------------------------------------
# rewind: back to a height already covered, in the bytes of a rebuild
# ---------------------------------------------------------------------------

def run_rewind(nonces_dir, to_height):
    """Bring a sealed artifact back to `to_height`.

    A fusion with a filter, not a second builder: dropping the records
    above the cut leaves a sorted file sorted, so the current generation
    becomes its own only source and the store's `sift` does the rest.
    Nothing has to be rebuilt because nothing in a record was derived
    from a record above the cut: no reduction to undo, no minimum to
    recompute, no folded flag.

    What the result is NOT byte-identical in, and the contract says so:
    the generation number and therefore the file names, and the scan
    counters, which describe a pass that covered more and are set to
    null rather than carried. The identity covers neither.
    """
    state = _load_state(nonces_dir)
    _load_manifest(nonces_dir)          # refuse an unsealed artifact
    if state["runs"]:
        raise NonceError(
            f"{len(state['runs'])} run(s) are waiting to be fused: rewind "
            "works on the fused file, so run `nonces merge` first")
    if _merged_entry(state) is None:
        raise NonceError("nothing fused yet: run `nonces merge` first")
    if to_height < 1:
        raise NonceError("--to-height must be at least 1")
    if to_height >= state["last_height"]:
        raise NonceError(
            f"this archive covers 1..{state['last_height']:,}: rewinding to "
            f"{to_height:,} would move it forward, which no filter can do")

    cut = to_height
    clock = WallClock("rewind", state)
    store = store_of(nonces_dir, state, clock=clock)

    def sift(rec):
        return rec if rec_height(rec) <= cut else None

    _dups, delete = store.fuse(LOGICAL, LADDERS[LOGICAL], CATEGORY,
                               dedup=None, dedup_len=POINT_LEN, sift=sift)
    # The highest height this artifact ever reached, recorded before the
    # watermark is moved down: it is what tells a later reader that the
    # missing scan counters belong to a longer pass.
    state["rewound_from"] = max(state.get("rewound_from") or 0,
                                state["last_height"])
    state["last_height"] = to_height
    state["merged_height"] = to_height
    state["scan_stats"] = None
    state["last_block_hash"] = None
    # Tally and seal BEFORE the commit, as in `merge`: a kill anywhere
    # up to the commit leaves the old sealed artifact untouched and the
    # same rewind can simply be run again. The old order committed
    # first, and a kill in the tallies pass left the artifact rewound
    # but unsealable: the same-height rewind was refused as moving
    # forward, and merge answered "nothing to fuse".
    tallies = _tallies(nonces_dir, state)
    manifest = _seal(nonces_dir, state, tallies, clock)
    store.commit(delete)
    print(f"rewound to height {to_height:,}: {tallies['records']:,} "
          f"signatures remain")
    print(f"fingerprint: {manifest['fingerprint']}")
    return manifest["fingerprint"]


def store_of(nonces_dir, state, clock=None):
    """A store bound to this state. Kept tiny and explicit: the state is
    held by reference, so two stores over one dict stay consistent."""
    return GenStore(nonces_dir, state, label="nonces", error=NonceError,
                    runs_dir=RUNS_DIR, state_name=STATE_NAME, clock=clock)


# ---------------------------------------------------------------------------
# groups: the answer a human reads
# ---------------------------------------------------------------------------

class _Group:
    """One nonce point's sightings, summarized instead of stored.

    The heights are capped: a deliberate tiny-r value can be sighted
    millions of times, and a report that held every height would fail on
    exactly the group it most needs to describe.
    """

    __slots__ = ("point", "count", "flags", "first", "last", "sample",
                 "_keep")

    def __init__(self, point, keep):
        self.point = point
        self.count = 0
        self.flags = 0
        self.first = None
        self.last = None
        self.sample = []
        self._keep = keep

    def add(self, height, flags):
        self.count += 1
        self.flags |= flags
        if self.first is None:
            self.first = height
        self.last = height
        if len(self.sample) < self._keep:
            self.sample.append(height)


def _schemes(flags):
    names = []
    if flags & FLAG_ECDSA:
        names.append("ecdsa")
    if flags & FLAG_SCHNORR:
        names.append("schnorr")
    return "+".join(names) or "none"


def _height_sample(heights, more=False):
    """The sampled heights of a group, in a column a person can read.

    Two problems with joining them by comma, both of which this fixes and
    both of which the chain produces constantly:

    - the separator was also the thousands separator, so eight sightings
      in one block printed as `364,767,364,767,364,767,…` and there was
      no way to see where one height ended;
    - a point published many times inside ONE block repeated that block
      until the column was full, spending the whole sample saying one
      thing. Runs collapse to `364,767 x8`, which is shorter AND says
      more, since how many times a point appeared in a single block is
      the interesting part of that row.
    """
    runs = []
    for h in heights:
        if runs and runs[-1][0] == h:
            runs[-1][1] += 1
        else:
            runs.append([h, 1])
    out = " ".join(f"{h:,}" + (f" x{n}" if n > 1 else "") for h, n in runs)
    return out + " …" if more else out


def run_groups(nonces_dir, min_count=2, limit=20, csv_path=None,
               keep_heights=8, out=sys.stdout):
    """Every nonce point sighted more than once: what the census counts.

    Streamed, not loaded: one pass over the fused file, holding only the
    groups. They are rare (a few thousand over the whole chain), so that
    fits, while the file does not.

    Two numbers are printed and never conflated, because measuring said
    they differ by three orders of magnitude: how many POINTS repeat, and
    how many extra SIGHTINGS those points account for. The tiny-r shapes
    are counted apart for the same reason: they are deliberate, they are
    the biggest groups, and a reader who ranks by size sees them first.
    """
    state = _load_state(nonces_dir, READ_TAGS)
    # Pending runs are part of the coverage the banner claims, and they
    # are sorted, so folding them in is one heap-merge — the same walk,
    # over everything the watermark stands for.
    sources = [iter_records(nonces_dir, state)]
    for run in state["runs"]:
        sources.append(read_fixed(
            os.path.join(nonces_dir, RUNS_DIR, run["name"]), REC,
            expect_sha=run["sha256"], error=NonceError))
    stream = sources[0] if len(sources) == 1 else heapq.merge(*sources)
    groups = []
    current = None
    scanned = 0
    for rec in stream:
        scanned += 1
        point = rec_point(rec)
        if current is None or current.point != point:
            if current is not None and current.count >= min_count:
                groups.append(current)
            current = _Group(point, keep_heights)
        current.add(rec_height(rec), rec_flags(rec))
    if current is not None and current.count >= min_count:
        groups.append(current)

    groups.sort(key=lambda g: (-g.count, g.point))
    tiny = [g for g in groups if is_tiny(g.point)]
    extra = sum(g.count - 1 for g in groups)
    tiny_extra = sum(g.count - 1 for g in tiny)
    mixed = [g for g in groups if g.flags & SCHEME_MASK == SCHEME_MASK]

    p = lambda *a: print(*a, file=out)
    p(f"\nnonce groups over heights 1..{state['last_height']:,} "
      f"({scanned:,} signatures)"
      + (f"  ({len(state['runs'])} unfused run(s) included)"
         if state["runs"] else ""))
    p(f"  {len(groups):,} points sighted at least {min_count} times, "
      f"accounting for {extra:,} sightings beyond the first")
    p(f"  of those, {len(tiny):,} have a tiny r ({tiny_extra:,} of those "
      f"sightings beyond the first): a point whose top bytes are zero, a "
      f"shape a drawn nonce lands on about once in 2^24. What that means "
      f"for a point is not decided here")
    p(f"  {len(mixed):,} span BOTH schemes: the same nonce point appears "
      f"under an ecdsa and a schnorr signature")
    p(f"  {len(groups) - len(tiny):,} are candidates only a block re-read "
      f"can resolve: compare the public keys of the signatures they name")

    if groups:
        p(f"\n{'point (12 B)':<26} {'count':>9}  {'schemes':<14} "
          f"{'heights':<24} tiny")
        for g in groups[:limit]:
            heights = _height_sample(g.sample,
                                     more=g.count > len(g.sample))
            p(f"{g.point.hex():<26} {g.count:>9,}  {_schemes(g.flags):<14} "
              f"{heights:<24} {'yes' if is_tiny(g.point) else ''}")
        if len(groups) > limit:
            p(f"… {len(groups) - limit:,} more "
              f"(raise --limit, or use --csv for all of them)")

    if csv_path:
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("point,count,schemes,first_height,last_height,tiny\n")
            for g in groups:
                f.write(f"{g.point.hex()},{g.count},{_schemes(g.flags)},"
                        f"{g.first},{g.last},"
                        f"{'yes' if is_tiny(g.point) else 'no'}\n")
        p(f"\nwrote {len(groups):,} groups to {csv_path}")
    return groups


# ---------------------------------------------------------------------------
# lookup: was this nonce point ever published?
# ---------------------------------------------------------------------------

def _run_hits(path, records, point):
    """Every record with this point in one SORTED run file: a blind
    bisect (a run carries no ladder), ~log2(n) seeks then one forward
    read. Runs are consulted so a lookup's answer covers everything the
    watermark claims, not only what a merge has fused."""
    with open(path, "rb") as f:
        lo, hi = 0, records
        while lo < hi:                       # first record >= point
            mid = (lo + hi) // 2
            f.seek(mid * REC)
            if f.read(REC)[:POINT_LEN] < point:
                lo = mid + 1
            else:
                hi = mid
        hits = []
        f.seek(lo * REC)
        while True:
            rec = f.read(REC)
            if len(rec) < REC or rec[:POINT_LEN] != point:
                break
            hits.append(rec)
    return hits


def run_lookup(nonces_dir, values, out=sys.stdout):
    """One ladder-backed search per value: one bucket read, not a scan,
    plus a blind bisect of every pending run — the coverage the answer
    claims is the state's watermark, so everything under it must be
    searched, fused or not.

    A value may be given as the 12-byte point, or as a full 32-byte r
    (or anything longer, a whole signature included): only the leading
    12 bytes are the key, and truncating here rather than making the
    caller do it is what keeps a copied-and-pasted r usable.
    """
    state = _load_state(nonces_dir, READ_TAGS)
    # Before the first merge the whole archive lives in runs; after it,
    # the runs are the not-yet-fused tail. Either way they are part of
    # every answer, so a missing fused file is a smaller archive, not a
    # refusal.
    sf = (open_sorted(nonces_dir, state)
          if _merged_entry(state) is not None else None)
    if state["runs"]:
        print(f"({len(state['runs'])} unfused run(s) included: the "
              "archive answers past its last merge)", file=out)
    try:
        for value in values:
            try:
                raw = bytes.fromhex(value.strip().lower().removeprefix("0x"))
            except ValueError:
                # The archive's lookup skips and says so; a list of
                # values must not die on its one typo.
                print(f"{value}: not hex, skipped", file=out)
                continue
            if len(raw) < POINT_LEN:
                raise NonceError(
                    f"{value}: a nonce point needs at least {POINT_LEN} "
                    f"bytes ({2 * POINT_LEN} hex characters), got {len(raw)}")
            point = raw[:POINT_LEN]
            hits = list(sf.find(point)) if sf is not None else []
            for run in state["runs"]:
                hits += _run_hits(os.path.join(nonces_dir, RUNS_DIR,
                                               run["name"]),
                                  run["records"], point)
            hits.sort()
            print(f"\n{point.hex()}", file=out)
            if not hits:
                print(f"  not published in confirmed blocks "
                      f"1..{state['last_height']:,}", file=out)
                continue
            for rec in hits:
                fl = rec_flags(rec)
                print(f"  height {rec_height(rec):>9,}  "
                      f"{_schemes(fl)}  "
                      f"sighash {SIGHASH_NAMES[rec_sighash(fl)]}", file=out)
            if len(hits) > 1:
                print(f"  REPEATED: {len(hits)} sightings of one nonce point"
                      + ("  (tiny r: top bytes zero, a shape a drawn nonce "
                         "lands on about once in 2^24)"
                         if is_tiny(point) else
                         "  (a candidate: compare the public keys of those "
                         "blocks)"), file=out)
    finally:
        if sf is not None:
            sf.close()


# ---------------------------------------------------------------------------
# address: the same question, asked from the owner's side
# ---------------------------------------------------------------------------
# The census answers a question about the CHAIN: which nonce points repeat.
# An owner has a different one: did MY key ever repeat a nonce with itself,
# which is the only shape that hands a private key over. That is a much
# smaller question, because every signature a key ever made is a spend of
# that lock's own outputs, and a lock has a handful of those and not
# billions.
#
# Why it takes the node. A record here holds no key, and no artifact kept
# afterwards holds unlocking data (the graph is flow, not unlocking; the
# archive keeps hashes). So the signatures have to be read again from the
# blocks that carry them. What makes that cheap is the index: it says
# exactly which heights to fetch, so this reads a handful of blocks rather
# than the chain.
#
# What makes it EXACT, and this is the part the census cannot do: an
# outpoint names one input of one transaction. There is no guessing about
# which signature belongs to the address being asked about, and it works
# even for a taproot key-path spend, whose public key is not in the input
# at all.

# Locks whose signature can only have come from one key. A script lock can
# be opened by several, and attributing one signature to one cosigner means
# verifying signatures, which this project does not do.
SINGLE_KEY_KINDS = frozenset(("p2pkh", "p2wpkh"))


def _spends_of(index, derived, lock):
    """Every confirmed spend of one lock, oldest first.

    Yields (height, spender txid, our txid, our vout). The heights come
    from the index, so nothing is fetched to discover what to fetch.
    """
    for out_ord, spender, _value in derived.rows(lock):
        if spender is None:
            continue                       # still unspent: never signed for
        txid, vout, _tx_ord = index.outpoint_of(out_ord)
        yield (index.height_of_tx(spender), index.txid_of(spender),
               txid, vout)


def _signatures_of_spend(block, spender_txid, prev_txid, vout, stats):
    """The nonce points of the one input that spends OUR outpoint.

    Returns (points, details, key_path), with `details` a list of
    `(full r, canonical s, raw s)` aligned to `points`, and `key_path` saying
    the witness held a single item, i.e. a taproot key-path spend, whose
    signature can only be the output key's.

    Refuses rather than guesses: if the transaction the index names is not
    in the block, or holds no input spending that outpoint, the two
    sources disagree and saying so is the only honest move.
    """
    for tx in block.transactions:
        if tx.txid != spender_txid:
            continue
        for tx_in in tx.inputs:
            if tx_in.prev_txid == prev_txid and tx_in.prev_vout == vout:
                _slots, key_path = _taproot_slots(tx_in.witness)
                details = []
                points = extract_nonces(tx_in, stats, detail_out=details)
                return points, details, key_path
        raise NonceError(
            f"tx {blockparse.hash_hex(spender_txid)} does not spend "
            f"{blockparse.hash_hex(prev_txid)}:{vout}: the index and the "
            "node disagree about this transaction")
    raise NonceError(
        f"tx {blockparse.hash_hex(spender_txid)} is not in the block the "
        "index puts it in: the index and the node disagree")


class _Sighting:
    """One signature this lock published, and where."""

    __slots__ = ("height", "point", "flags", "spender", "single_key",
                 "r_full", "s", "s_raw")

    def __init__(self, height, point, flags, spender, single_key,
                 r_full, s, s_raw):
        self.height = height
        self.point = point
        self.flags = flags
        self.spender = spender
        self.single_key = single_key
        self.r_full = r_full          # the untruncated nonce point
        self.s = s                    # canonical: s and n-s fold together
        self.s_raw = s_raw            # as serialized, to name which case


def _read_sightings(client, index, derived, address, lock, stats,
                    max_blocks, out):
    """Fetch the blocks this lock signed in, and read its signatures."""
    spends = sorted(_spends_of(index, derived, lock))
    if not spends:
        return [], 0
    heights = sorted({h for h, _s, _t, _v in spends})
    if len(heights) > max_blocks:
        raise NonceError(
            f"this lock was spent in {len(heights):,} different blocks, and "
            f"reading them all is {len(heights):,} block fetches. Raise "
            f"--max-blocks if that is what you want")

    blocks = {}
    for i in range(0, len(heights), 25):
        window = heights[i:i + 25]
        hashes, raws = client.fetch_blocks(window)
        for h, want, raw in zip(window, hashes, raws):
            block = blockparse.parse_block(raw)
            if block.header.hash != want:
                raise NonceError(f"height {h}: block bytes do not hash to "
                                 "the requested block hash")
            blocks[h] = block

    single = address.kind in SINGLE_KEY_KINDS
    sightings = []
    for height, spender, prev_txid, vout in spends:
        points, details, key_path = _signatures_of_spend(
            blocks[height], spender, prev_txid, vout, stats)
        for (flags, point), (r_full, s, s_raw) in zip(points, details):
            sightings.append(_Sighting(
                height, point, flags, spender,
                single or (address.kind == "p2tr" and key_path),
                r_full, s, s_raw))
    return sightings, len(heights)


def run_address(addresses, index_dir, derived_dir, client, nonces_dir=None,
                max_blocks=200, out=sys.stdout):
    """Did this address's own key ever repeat a nonce?

    Three sources, joined on the outpoint: the derivatives say which of
    this lock's outputs were spent and by which transaction, the index
    turns those into heights and txids, and the node hands back the blocks
    so the signatures can be read. The census is optional and answers a
    different half: whether the same point was also published by somebody
    else, which is a broken generator rather than a key recovery.
    """
    # Imported here, not at module scope: check_addresses reaches the
    # reveal archive, which reaches this module, so a top-level import
    # would close a cycle.
    from nodsig import derivatives as dvm
    from nodsig import outpoint_index as oi
    from nodsig.check_addresses import KINDS, decode_address, script_pubkey
    from nodsig.hashing import hash160

    index = oi.Index(index_dir)
    derived = dvm.Derived(derived_dir, index)
    census = None
    if nonces_dir:
        census = open_sorted(nonces_dir)
    stats = new_stats()
    p = lambda *a: print(*a, file=out)
    findings = 0

    try:
        for text in addresses:
            address = decode_address(text)
            lock = hash160(script_pubkey(address))
            p(f"\n{address.text}")
            p(f"  {KINDS[address.kind][1]}")
            p(f"  lock {lock.hex()}, index through height "
              f"{index.watermark:,}")

            sightings, n_blocks = _read_sightings(
                client, index, derived, address, lock, stats, max_blocks, out)
            if not sightings:
                p("  no signature to examine: this lock has no confirmed "
                  "spend up to that height, so it has never signed")
                continue

            p(f"  {len(sightings)} signature(s) read from {n_blocks} "
              f"block(s):")
            for s in sightings:
                p(f"    height {s.height:>9,}  {s.point.hex()}  "
                  f"{_schemes(s.flags):<8} "
                  f"{SIGHASH_NAMES[rec_sighash(s.flags)]:<11} in "
                  f"{blockparse.hash_hex(s.spender)[:16]}…")

            # Grouped by the FULL nonce point, not by the 12-byte one the
            # census stores: the truncation is a storage decision, and two
            # scalars sharing a prefix are two nonces, not a repeat. The
            # blocks are already in hand here, so the untruncated value
            # costs nothing and keeps the strongest claim on this page
            # from resting on a prefix.
            groups = {}
            for s in sightings:
                groups.setdefault(s.r_full, []).append(s)
            repeated = {pt: g for pt, g in groups.items() if len(g) > 1}

            if not repeated:
                if len(sightings) == 1:
                    p("  one signature only: a nonce cannot repeat with "
                      "itself, so there is nothing here to find")
                else:
                    p(f"  no repeated nonce among this lock's own "
                      f"{len(sightings)} signatures")
            for pt, g in repeated.items():
                findings += 1
                heights = ", ".join(f"{s.height:,}" for s in g)
                # Printed as the 12-byte point the census stores, so the
                # value can be pasted into `nonces lookup`; the grouping
                # above used the full one.
                p(f"  REPEATED NONCE {pt[:R_PREFIX].hex()} at heights "
                  f"{heights}")
                if len({s.s for s in g}) == 1:
                    # The point repeats because the SIGNATURE repeats, not
                    # because a generator did. One `s` means one `z` (with
                    # the nonce point and the key both fixed, s determines
                    # the message), so these are one signature serialized
                    # again, which consensus allows and which hands over
                    # nothing: the SIGHASH_SINGLE bug makes a single
                    # signature satisfy every input of a transaction, and
                    # the chain has inputs where it was used thousands of
                    # times over. Claiming a key recovery here would be
                    # claiming one that does not exist.
                    if len({s.s_raw for s in g}) == 1:
                        p("    the signature is IDENTICAL each time, not "
                          "merely its nonce: one signature reused, which "
                          "signs one message and exposes nothing. Nothing "
                          "follows from it")
                    else:
                        # s and n-s: one signature in its two legal forms,
                        # from nonces k and -k over the same message. The
                        # bytes differ, the information does not.
                        p("    the signatures differ only as s and n-s, "
                          "which is ONE signature in its two legal forms "
                          "over one message. Nothing follows from it")
                elif all(s.single_key for s in g):
                    p("    this lock is opened by ONE key, and the "
                      "signatures differ, so they signed different messages "
                      "with the same key and the same nonce: the private "
                      "key follows from the two of them, by arithmetic "
                      "anybody can do")
                else:
                    p("    this lock can be opened by several keys, and "
                      "telling which cosigner signed needs verifying "
                      "signatures, which this tool does not do. The "
                      "collision is real; the conclusion is not automatic")
                if is_tiny(pt):
                    p("    the nonce point is tiny: its top bytes are zero, "
                      "a shape a drawn nonce lands on about once in 2^24. "
                      "What that means here is not decided")

            if census is not None:
                for pt, g in groups.items():
                    pt = pt[:R_PREFIX]        # the census is keyed on those
                    elsewhere = len(census.find(pt)) - len(g)
                    if elsewhere > 0:
                        p(f"  census: {pt.hex()} was also published "
                          f"{elsewhere} time(s) by signatures that are not "
                          f"this lock's. Two DIFFERENT keys sharing a nonce "
                          f"does not hand either one over; it does show the "
                          f"point was not drawn at random, though not whether "
                          f"that was a fault or a choice")
    finally:
        if census is not None:
            census.close()
        derived.close()
        index.close()

    return findings


# ---------------------------------------------------------------------------
# bench: what the extraction costs, measured on real blocks
# ---------------------------------------------------------------------------
# Four timed passes over the same blocks, each one a real function that
# the real scan calls:
#
#   parse    parse_block, plus the hash check every scan does. The floor
#            no pass can avoid.
#   pushes   script_pushes over every input's scriptSig. Measured alone
#            because the archive walk ALREADY pays it, so subtracting it
#            from the nonce pass is what "integrated" costs.
#   archive  extract_revelations, i.e. today's per-input work.
#   nonces   extract_nonces plus building the records, i.e. this artifact.
#
# The passes run per block, so memory holds one parsed block at a time
# and the numbers are not a benchmark of the page cache.


def _walk(block, fn):
    """Apply fn(tx_in) to every non-coinbase input, as the scan does."""
    for tx in block.transactions:
        if blockparse.is_coinbase(tx):
            continue
        for tx_in in tx.inputs:
            fn(tx_in)


def run_bench(client, start, count, stride=1, batch_size=25,
              sort_batch=2_000_000, project_inputs=3_400_000_000,
              project_heights=957_301, out=sys.stdout):
    """Fetch `count` blocks from `start`, time the four passes, report.

    `stride` samples the chain instead of walking a window of it: the
    per-input cost is what the projection uses, but the MIX of input
    shapes changes a lot over the chain (no witnesses before 481,824, no
    taproot before 709,632), so a spread sample and a recent window
    answer slightly different questions. Both are worth running.
    """
    # Imported here, not at module scope: the archive imports this module
    # for its --nonces plug, so a top-level import would close a cycle.
    from nodsig.reveal_archive import extract_revelations
    from nodsig.reuse_scan import ScanError

    heights = list(range(start, start + count * stride, stride))
    windows = [heights[i:i + batch_size]
               for i in range(0, len(heights), batch_size)]

    t = dict.fromkeys(("fetch", "parse", "pushes", "archive", "nonces",
                       "sort"), 0.0)
    n_blocks = n_tx = n_inputs = n_bytes = 0
    sorted_records = 0
    sort_batches = 0
    arch_stats = {"malformed_scriptsig": 0, "malformed_inner_script": 0}
    nonce_stats = new_stats()
    unknown = Counter()          # (length, first byte) of unrecognized items
    pending = []
    clock = time.perf_counter
    started = clock()

    def measure_sort():
        """Sort one batch and count what repeats in it, two ways.

        Groups and sightings are counted separately because measuring
        showed they are nowhere near proportional: chain-wide, a single
        deliberate tiny-r value accounted for 99.9% of the repeated
        SIGHTINGS while the number of repeated POINTS stayed in the
        single digits. Reporting only the sightings makes a handful of
        known constructions look like an epidemic.
        """
        nonlocal sorted_records, sort_batches
        t0 = clock()
        pending.sort()
        groups = extras = 0
        in_run = 0
        last = None
        for rec in pending:
            key = rec[:POINT_LEN]
            if key == last:
                extras += 1
                if in_run == 0:
                    groups += 1
                in_run += 1
            else:
                in_run = 0
                last = key
        t["sort"] += clock() - t0
        sorted_records += len(pending)
        sort_batches += 1
        pending.clear()
        return groups, extras

    rep_groups = rep_sightings = 0
    for window in windows:
        t0 = clock()
        hashes, raws = client.fetch_blocks(window)
        t["fetch"] += clock() - t0

        for h, want, raw in zip(window, hashes, raws):
            n_bytes += len(raw)

            t0 = clock()
            block = blockparse.parse_block(raw)
            if block.header.hash != want:
                raise ScanError(f"height {h}: block bytes do not hash to "
                                "the requested block hash")
            t["parse"] += clock() - t0

            # pushes: the shared cost, timed on its own
            t0 = clock()
            _walk(block, lambda i: _parse_pushes(i, arch_stats))
            t["pushes"] += clock() - t0

            # archive: today's per-input work, appends included
            sink = []
            t0 = clock()
            _walk(block, lambda i: sink.extend(
                (cat, digest, byte, h)
                for cat, digest, byte in extract_revelations(i, arch_stats)))
            t["archive"] += clock() - t0
            sink.clear()

            # nonces: this artifact, record building included
            t0 = clock()
            _walk(block, lambda i: pending.extend(
                record(point, h, flags)
                for flags, point in extract_nonces(i, nonce_stats)))
            t["nonces"] += clock() - t0

            n_blocks += 1
            n_tx += len(block.transactions)
            n_inputs += sum(len(tx.inputs) for tx in block.transactions
                            if not blockparse.is_coinbase(tx))
            _census_unknown(block, unknown)

            if len(pending) >= sort_batch:
                g, e = measure_sort()
                rep_groups += g
                rep_sightings += e

        if n_blocks % 1000 < batch_size:
            print(f"  {n_blocks:>6,}/{len(heights):,} blocks, "
                  f"{n_inputs:,} inputs, "
                  f"{clock() - started:.0f}s elapsed", file=sys.stderr)

    total_records = sorted_records + len(pending)
    if pending:
        g, e = measure_sort()
        rep_groups += g
        rep_sightings += e

    _report(out, t, n_blocks, n_tx, n_inputs, n_bytes, total_records,
            sorted_records, sort_batches, rep_groups, rep_sightings,
            arch_stats, nonce_stats, unknown, project_inputs,
            project_heights, clock() - started)
    return {"blocks": n_blocks, "inputs": n_inputs,
            "records": total_records, "times": t,
            "nonce_stats": nonce_stats}


def _parse_pushes(tx_in, stats):
    """The shared parse, timed alone: the cost both walks split."""
    scriptsig_pushes(tx_in, stats)


def _census_unknown(block, unknown, keep=12):
    """Histogram of unlocking items that yielded no nonce.

    The reason this is in the bench and not a footnote: if the shape
    rules are missing a real signature family, the misses are not
    random, they cluster at one length with one first byte. A cheap
    histogram turns "89% recognized" into a name.
    """
    for tx in block.transactions:
        if blockparse.is_coinbase(tx):
            continue
        for tx_in in tx.inputs:
            for item in tx_in.witness:
                if len(item) >= 32 and taproot_r(item) is None \
                        and signature_r(item) is None:
                    unknown[(len(item), item[0])] += 1
    # Bounded: a runaway key space would otherwise grow with the chain.
    if len(unknown) > 4096:
        for key, _ in unknown.most_common()[keep:]:
            del unknown[key]


def _pct(part, whole):
    return f"{100.0 * part / whole:.1f}%" if whole else "n/a"


def _hours(per_input_us, inputs):
    return per_input_us * inputs / 1e6 / 3600.0


def _report(out, t, blocks, txs, inputs, nbytes, records, sorted_records,
            sort_batches, rep_groups, rep_sightings, arch_stats,
            nonce_stats, unknown, project_inputs, project_heights, wall):
    def us(seconds):
        return 1e6 * seconds / inputs if inputs else 0.0

    baseline = t["parse"] + t["archive"]
    integrated = max(0.0, t["nonces"] - t["pushes"])
    p = lambda *a: print(*a, file=out)

    p(f"\nnonce census gate: {blocks:,} blocks, {txs:,} transactions, "
      f"{inputs:,} non-coinbase inputs, {nbytes / 1e6:,.0f} MB")
    p(f"wall {wall:.1f}s, of which fetch {t['fetch']:.1f}s "
      f"({nbytes / 1e6 / t['fetch']:.1f} MB/s, serial) "
      f"and CPU {wall - t['fetch']:.1f}s")

    p("\nper pass (CPU, and per non-coinbase input):")
    for name in ("parse", "pushes", "archive", "nonces"):
        p(f"  {name:<8} {t[name]:8.2f}s  {us(t[name]):6.3f} us/input")
    p(f"  {'sort':<8} {t['sort']:8.2f}s  "
      f"{1e6 * t['sort'] / sorted_records if sorted_records else 0:6.3f} "
      f"us/record over {sorted_records:,} records in {sort_batches} "
      f"batch(es)")

    p(f"\nwhat the census adds to a scan that today costs "
      f"parse+archive = {baseline:.2f}s:")
    p(f"  integrated (scriptSig pushes shared): {integrated:.2f}s  "
      f"{us(integrated):.3f} us/input  "
      f"+{_pct(integrated, baseline)}")
    p(f"  standalone (its own pass):            {t['nonces']:.2f}s  "
      f"{us(t['nonces']):.3f} us/input  "
      f"+{_pct(t['nonces'], baseline)}")
    p(f"  sort of what it emits:                {t['sort']:.2f}s  "
      f"{us(t['sort']):.3f} us/input  "
      f"+{_pct(t['sort'], baseline)}")

    p(f"\nvolume: {records:,} records, "
      f"{records / inputs if inputs else 0:.2f} per input, "
      f"{records * REC / 1e6:,.1f} MB "
      f"({rep_groups:,} nonce points repeat within a sorted batch, over "
      f"{rep_sightings:,} extra sightings: the two differ because a few "
      f"deliberate values recur in bulk)")

    p("\nrecognition (the number that says whether the rules are right):")
    p(f"  ecdsa {nonce_stats['nonces_ecdsa']:,}, "
      f"schnorr {nonce_stats['nonces_schnorr']:,}")
    p(f"  inputs with no nonce found: "
      f"{nonce_stats['inputs_without_nonce']:,} "
      f"({_pct(nonce_stats['inputs_without_nonce'], inputs)})")
    p(f"  DER-shaped near misses: {nonce_stats['malformed_der']:,}, "
      f"oversize r: {nonce_stats['oversize_r']:,}, "
      f"impossible r (0 or >= n): {nonce_stats['impossible_r']:,}, "
      f"malformed scriptSigs: {arch_stats['malformed_scriptsig']:,}")
    if unknown:
        p("  unrecognized witness items >=32 B, most common "
          "(length, first byte):")
        for (length, lead), n in unknown.most_common(8):
            p(f"    {length:>4} B  0x{lead:02x}  {n:,}")

    p(f"\nprojected over {project_inputs:,} inputs "
      f"and {project_heights:,} heights:")
    for label, seconds in (("extraction, integrated", integrated),
                           ("extraction, standalone", t["nonces"]),
                           ("sort of the runs", t["sort"])):
        p(f"  {label:<24} {_hours(us(seconds), project_inputs):6.2f} h")
    if inputs:
        p(f"  {'artifact bytes':<24} "
          f"{records / inputs * project_inputs * REC / 1e9:6.1f} GB")
    p("\nThe projection scales the measured per-input cost. It assumes "
      "this sample's\nmix of input shapes; a window of recent blocks "
      "and a spread sample of the\nwhole chain will not agree, and the "
      "difference between them is the honest\nerror bar.")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="The archive of published signature nonce points: "
                    "seal it, audit it, and read the repetitions.")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("merge", help="fuse the runs and seal the artifact")
    m.add_argument("--nonces", required=True, help="the nonce archive")

    v = sub.add_parser("verify", help="audit a sealed artifact")
    v.add_argument("--nonces", required=True)
    v.add_argument("--deep", action="store_true",
                   help="also pass over every record (order, one scheme "
                        "bit each, no undefined flag bit, no Schnorr "
                        "record claiming a nonstandard sighash, heights) "
                        "and hold the coverage to a floor")

    r = sub.add_parser("rewind", help="back to a height already covered")
    r.add_argument("--nonces", required=True)
    r.add_argument("--to-height", type=int, required=True)

    g = sub.add_parser("groups", help="the points sighted more than once")
    g.add_argument("--nonces", required=True)
    g.add_argument("--min-count", type=int, default=2,
                   help="how many sightings make a group (default 2)")
    g.add_argument("--limit", type=int, default=20,
                   help="how many groups to print (default 20)")
    g.add_argument("--csv", help="write every group to this file")

    lk = sub.add_parser("lookup", help="was this nonce point published?")
    lk.add_argument("--nonces", required=True)
    lk.add_argument("points", nargs="+",
                    help="hex of the point, or of a whole r")

    a = sub.add_parser("address", help="did this address's own key ever "
                                       "repeat a nonce?")
    a.add_argument("addresses", nargs="+", help="mainnet address(es)")
    a.add_argument("--index", required=True,
                   help="outpoint index: which heights to read")
    a.add_argument("--derived", required=True,
                   help="its derivatives: which outputs were spent, by whom")
    a.add_argument("--rpc", default="http://127.0.0.1:8332",
                   help="the node, which is where the signatures still are: "
                        "no artifact keeps unlocking data")
    a.add_argument("--rest", action="store_true",
                   help="use the binary REST interface (needs -rest=1)")
    a.add_argument("--cookie-file",
                   help="Bitcoin Core .cookie file (the secret never "
                        "travels on the command line)")
    a.add_argument("--nonces",
                   help="a census, to also say whether the same point was "
                        "published by signatures that are not this lock's")
    a.add_argument("--max-blocks", type=int, default=200,
                   help="refuse to fetch more blocks than this (default "
                        "%(default)s)")

    rs = sub.add_parser("resolve", help="re-read the blocks the repeated "
                                        "points name, and keep the evidence")
    rs.add_argument("--nonces", required=True, help="the sealed census")
    rs.add_argument("--witness", required=True,
                    help="the witness table to build (a new directory)")
    rs.add_argument("--rpc", default="http://127.0.0.1:8332",
                    help="the node: the signatures live only in the blocks")
    rs.add_argument("--rest", action="store_true",
                    help="use the binary REST interface (needs -rest=1)")
    rs.add_argument("--cookie-file",
                    help="Bitcoin Core .cookie file (the secret never "
                         "travels on the command line)")
    rs.add_argument("--min-count", type=int, default=2,
                    help="resolve points sighted at least this many times "
                         "(default %(default)s)")

    wv = sub.add_parser("witness-verify",
                        help="audit a sealed witness table")
    wv.add_argument("--witness", required=True)
    wv.add_argument("--nonces",
                    help="the census it declares as its parent, to confirm "
                         "the ancestry instead of trusting it")
    wv.add_argument("--csv", metavar="OUT",
                    help="also write one row per point with its resolution, "
                         "from what this audit just re-derived")

    b = sub.add_parser("bench", help="time the extraction over real blocks")
    b.add_argument("--rpc-url", default="http://127.0.0.1:8332",
                   help="node RPC/REST endpoint")
    b.add_argument("--rest", action="store_true",
                   help="use the binary REST interface (needs -rest=1)")
    b.add_argument("--cookie-file",
                   help="Bitcoin Core .cookie file (RPC only; the secret "
                        "never travels on the command line)")
    b.add_argument("--start", type=int, required=True,
                   help="first height to measure")
    b.add_argument("--count", type=int, default=10_000,
                   help="how many blocks (default 10000)")
    b.add_argument("--stride", type=int, default=1,
                   help="sample every Nth height instead of a window")
    b.add_argument("--batch-size", type=int, default=25,
                   help="blocks per fetch (the scan's own default)")
    b.add_argument("--sort-batch", type=int, default=2_000_000,
                   help="records sorted per measured batch (memory knob)")
    b.add_argument("--project-inputs", type=int, default=3_400_000_000,
                   help="input count to project onto")
    b.add_argument("--project-heights", type=int, default=957_301,
                   help="height count to project onto")

    args = p.parse_args(argv)
    if args.cmd == "merge":
        run_merge(args.nonces)
    elif args.cmd == "verify":
        run_verify(args.nonces, deep=args.deep)
    elif args.cmd == "rewind":
        run_rewind(args.nonces, args.to_height)
    elif args.cmd == "groups":
        run_groups(args.nonces, min_count=args.min_count, limit=args.limit,
                   csv_path=args.csv)
    elif args.cmd == "lookup":
        run_lookup(args.nonces, args.points)
    elif args.cmd == "address":
        from nodsig.reuse_scan import build_client
        client, _ = build_client(args.rpc, args.rest, args.cookie_file)
        run_address(args.addresses, args.index, args.derived, client,
                    nonces_dir=args.nonces, max_blocks=args.max_blocks)
    elif args.cmd == "resolve":
        from nodsig import witness as wt
        from nodsig.reuse_scan import build_client
        client, _ = build_client(args.rpc, args.rest, args.cookie_file)
        wt.run_resolve(args.nonces, args.witness, client,
                       min_count=args.min_count)
    elif args.cmd == "witness-verify":
        from nodsig import witness as wt
        wt.run_verify(args.witness, nonces_dir=args.nonces,
                      csv_path=args.csv)
    elif args.cmd == "bench":
        if args.count < 1 or args.stride < 1:
            raise SystemExit("--count and --stride must be positive")
        from nodsig.reuse_scan import build_client
        client, _ = build_client(args.rpc_url, args.rest, args.cookie_file)
        run_bench(client, args.start, args.count, stride=args.stride,
                  batch_size=args.batch_size, sort_batch=args.sort_batch,
                  project_inputs=args.project_inputs,
                  project_heights=args.project_heights)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        # NonceError for this artifact, ScanError for the node transport
        # the bench borrows: both are expected failures, and both should
        # print one line instead of a traceback.
        sys.exit(f"error: {e}")
