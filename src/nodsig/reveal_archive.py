#!/usr/bin/env python3
"""
reveal_archive.py — build the COMPLETE archive of every key and script
ever revealed in confirmed block history, and use it to cross-check
the reuse scan.

Why a second tool for the same question: reuse_scan.py answers "which
current locks were already opened?" with an inverted comparison — the
current locks stay in memory, history streams past, only the hits are
kept. It is fast and small, but its result is one bitmap, produced by
one pipeline. The project's rule for numbers that end up published is
the double method: two INDEPENDENT roads that must meet on the same
answer. This tool is the other road: it keeps EVERYTHING history
reveals (tens of GB on disk — disk is cheap, the scan is paid anyway),
and derives the hits afterwards, by reading the archive against the
lock files. If the two bitmaps do not match bit for bit, one of the
two pipelines is wrong: that is the cross-check of level 3, as the
19×3.125 delta was for levels 1-2.

What the independence covers, exactly, because a check that claims
more than it verifies is worse than none: the two EXTRACTION pipelines
are written separately and that is what the comparison tests. Both
roads then burn the same lock files through the same LockSet code, so
a broken locks directory would make them agree on garbage rather than
disagree. That shared input is guarded instead of assumed: the files
are verified against the sha256 their manifest recorded at prepare,
and `crosscheck --reuse-state` refuses a checkpoint made against a
different locks manifest.

The archive is not only a check. It is designed to REMAIN:

- it answers the full question of check_addresses.py ("was this lock's
  key ever revealed?") with a local lookup, no third-party index;
- it answers future questions without rescanning the chain;
- its on-disk format is APPENDABLE from day one — sorted runs plus a
  height watermark, fused periodically — so the one-shot scan of
  level 3 is already the seed of the incremental card index, not
  work to redo.

What one record means. The archive stores revelations, not conclusions.
Every record is `digest | byte | first_height u24`:

    keys       hash160 of every public-key-shaped item found in an
               unlocking context (scriptSig push, witness item, or a
               push inside a candidate script), or published in an
               output, 20 bytes. Its byte is the FLAGS below: where it
               was seen, and in which form;
    scripts20  hash160 of every redeem script the chain revealed (the
               last scriptSig push, where P2SH keeps it), 20 bytes. Its
               byte COUNTS the pubkeys found inside that script;
    scripts32  sha256 of every witness script the chain revealed (the
               last witness item, where P2WSH keeps it), 32 bytes. Same
               count.

WHAT MAKES A CANDIDATE A SCRIPT, AND WHY IT IS DECIDED AT THE FUSION
===================================================================
The scan sees the input that spends, never the output spent, so it
cannot tell a redeem script from a public key: a 33-byte script that
starts with `02` and a compressed key are the same bytes. 2.0.0 decided
by the shape and dropped real scripts that looked like keys or
signatures; 1.x kept every candidate and filled half its script
partitions with keys and signatures. This format does neither. The rule
it follows has no exception:

    an item is excluded only when the chain itself proves it cannot be
    what it would be archived for. A shape is not a proof. A position
    is not a proof.

The proof is in the chain, only not in the input: a redeem script runs
only behind a P2SH output whose program is its hash160, a witness script
only behind a P2WSH program that is its sha256 (a native output, or the
`0020<32>` a P2SH-P2WSH spend pushes as its redeem script). So the scan
keeps every candidate and also records, in two more run categories,
every such program the chain created; the fusion keeps a candidate in
`scripts20`/`scripts32` exactly when its digest is among the programs,
and sets the others aside. What is set aside is not thrown away: a
program created LATER can make an old candidate a revealed script, and
appending must equal rebuilding. The programs and the candidates not
proven yet are therefore a second artifact, `reveal-proof-v1`, sealed in
the same fusion under `proof/`, with this archive as its declared
parent. The archive answers every question without it; it grows only
beside it.

The two exclusions that remain are proofs of the same kind, made by the
bytes: a control block and an annex cannot be scripts, because the first
byte of a script always executes and theirs fail it.

FIRST_HEIGHT is the lowest height the digest was ever seen at, so the
archive answers WHEN a key became public and not only whether. It is
three bytes on every record, about 12% of the file, and it is the one
piece of this format that no later pass could recover: a digest says
nothing about its own date, and the graph deliberately keeps no
unlocking data to re-derive it from. It also turns "what appeared
since height H" from an impossible question into a filter.

The key count on a script is free: the extraction has just walked
that script looking for pubkeys, and the byte it fills was reserved
and always zero. It buys a census of multisig shapes over the whole
chain, from an archive that stores hashes and never scripts: a census
that means something only because the partition holds scripts.

The flags byte on a key records WHERE it was seen (directly in a
scriptSig, directly in a witness, or inside a candidate script, the
cosigner case), with the bits of every sighting OR-ed together, and in
one more bit WHICH FORM the key was serialized in. The form is not a
place: it is a property of the key itself, constant across sightings
because the two serializations hash to different digests, which is why
OR leaves it alone. This
is what lets the perimeter be chosen at READ time: the same archive
reproduces the full perimeter and the narrow readings of reuse_scan's
--no-faces / --no-cosigners, so the cross-check is exact for every
flag combination. Over-collection is as harmless here as it is there:
a stored hash can only match a lock if it is that lock's exact
preimage, so junk records cost bytes, never correctness.

Subcommands:

    scan        the long run: fetch raw blocks from the node (batched
                JSON-RPC, or the binary REST interface with `--rest`,
                which halves the bytes on the wire), verify integrity
                (header hash, prev link, Merkle, witness commitment),
                extract revelations and programs, flush them as sorted
                deduplicated runs, checkpoint and resume.
    merge       fuse all runs (and the previous merged files) into
                one sorted deduplicated file per category, prove the
                candidates against the programs, and write the two
                manifests with their canonical fingerprints.
                This is the periodic fusion of the card index —
                periodic BETWEEN scans, never during one: scan and
                merge on one directory exclude each other (a `.lock`
                in the directory says so, see recio.exclusive).
    crosscheck  derive the burnt-locks bitmaps from the archive and
                the lock files of `reuse_scan.py prepare`, and print
                the fingerprint in reuse_scan's exact format — or
                compare it directly against a reuse_scan state file.
    verify      re-read a sealed archive (and its proof, when it has
                one) against the manifests: the bytes, the ladders
                rebuilt from the files they index, the fingerprints,
                and with --deep every record and the proof itself.
    derive      the reuse table and curve as a READ of the archive,
                without a second pass over the chain.
    lookup      is this 20/32-byte digest in the archive? The seed of
                check_addresses.py's complete answer.

Everything is standard library; the node is only asked for public
chain data, read-only, over either of its interfaces. No addresses of
ours anywhere: the archive holds hashes of PUBLIC chain data only.
"""

import argparse
import bisect
import hashlib
import heapq
import json
import os
import sys
import time
from array import array

from nodsig import blockparse
from nodsig.sightings import (FLAG_INNER_SIG, FLAG_INNER_WIT, FLAG_OTHER_FACE,
                              FLAG_OUT, FLAG_SIG, FLAG_UNCOMPRESSED, FLAG_WIT,
                              FLAG_XONLY, FLAGS_DEFINED, FLAGS_FULL_ONLY,
                              MAX_INNER_KEYS, MIN_KEY_OUTPUT, burns_for,
                              cannot_be_script,
                              is_control_block, key_records, leaf_xonly_keys,
                              new_filter_stats, output_keys, script_records,
                              taproot_body, witness_key_records)
from nodsig.progress import Pace
from nodsig.artifact import (WallClock, declared_parent, identity_fingerprint,
                             make_identity, producer, seal_manifest,
                             verify_sealed)
from nodsig import kernel
from nodsig.blockparse import ParseError, script_pushes, scriptsig_pushes

# Slab I/O for the fixed-width record files (runs, merged archive): the
# read/write budget, the sha-verifying reader, atomic writes — shared with
# the outpoint index, one implementation of the mechanics for both.
from nodsig.genstore import (LadderWriter, _BaseCursor, _BulkFusion,
                             _split, merge_to_file)
from nodsig.recio import (IO_CHUNK, atomic_json, budgeted_slab, checked_name,
                          read_json,
                          durable_replace, locked, preflight_space,
                          read_fixed)

# The ladder-backed search over the merged files: same primitive the index
# uses, so a lookup is one bucket read, not a blind on-disk binary search.
from nodsig.recsort import SortedFile

# The graph co-emission plug (--graph), same contract as in
# reuse_scan.py: either long pass can host it, since both fetch and
# verify every block anyway.
from nodsig import graphemit

# The header co-emission plug (--headers): the same contract again, and
# the same reason — the checks this scan performs on every block are
# worth keeping, and 88 bytes a block keeps them.
from nodsig import headers

# The nonce census (--nonces): the third plug, and the only one fed from
# what this scan has already parsed instead of from the block. Every
# signature publishes the x-coordinate of its nonce point, a repeated one
# is a key waiting to be recovered, and no artifact we keep holds the
# unlocking data to re-derive it later.
from nodsig import nonces

# Shared primitives come from the sibling tools ON PURPOSE: one
# implementation of each in the project, so the node transports (both
# of them), the credential rules and the hash helpers come from
# reuse_scan and the parser from blockparse. What is NOT shared is the
# pipeline: the per-input walk, the storage, and the matching are
# written here again, because they are what the cross-check is meant to
# check.
from nodsig import curve as cv
from nodsig import home
from nodsig.reuse_scan import (add_coemission_args, add_node_args,
                               add_window_args,
                               LOCK_TYPES, TYPE_ORDER, SAT, BlockFetcher, LockSet,
                        RpcClient, ScanError, _fingerprint, _lock_file,
                        _perimeter, build_client, fingerprint_of_bitmaps,
                        hash160, locks_base_hash, locks_height, locks_types,
                        warn_if_slow_ripemd160, write_checkpoint,
                        STATE_TAG as REUSE_STATE_TAG,
                        _load_manifest as _load_locks_manifest)

STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
FORMAT_TAG = "reveal-archive-v4"
RUNS_DIR = "runs"

# The sibling artifact the fusion seals beside the archive: the programs
# the chain created and the candidates they have not proven (see the
# module docstring). A directory of its own, so the archive can be handed
# over without it, and a tag of its own, so it can be handed over too.
PROOF_TAG = "reveal-proof-v1"
PROOF_DIR = "proof"

# The eight bits of a `keys` record, and the classifier both roads
# share, live in sightings.py; they are re-exported here by name.

# category → width of the stored digest. A record is
#
#     digest | byte | first_height u24 (big-endian)
#
# The BYTE means different things per category, which is why the
# reduction below is per category and not one rule for all:
#
#   keys       the FLAGS above (provenance, plus the form bit), a
#              bitfield: two sightings of one key are merged with OR;
#   scripts*   the NUMBER of pubkey-shaped pushes found inside that
#   unproven*  script, saturating at 255. It is a function of the script
#              bytes, so every sighting of one script agrees; `max`
#              merges them and is a no-op that a test pins;
#   programs*  where the chain committed to the program: PROGRAM_OUTPUT
#              (an output created with it) and PROGRAM_NESTED (a
#              P2SH-P2WSH spend pushing it as its redeem script), OR-ed.
#
# FIRST_HEIGHT is the LOWEST height at which the digest was ever seen, so
# the merge takes `min`. Both `or` and `min` are associative and
# commutative, which is exactly what keeps the fusion order-independent
# and the append equal to a rebuild.
CATEGORIES = {"keys": 20, "scripts20": 20, "scripts32": 32,
              "programs20": 20, "programs32": 32,
              "unproven20": 20, "unproven32": 32}
CAT_ORDER = ["keys", "scripts20", "scripts32"]
PROGRAM_CATS = ["programs20", "programs32"]
RUN_CATS = CAT_ORDER + PROGRAM_CATS
PROOF_ORDER = ["programs20", "programs32", "unproven20", "unproven32"]
# A script partition → the programs that prove its candidates, and the
# pile of the candidates they have not proven yet.
PROVED_BY = {"scripts20": ("programs20", "unproven20"),
             "scripts32": ("programs32", "unproven32")}
_OR_CATS = frozenset(("keys", "programs20", "programs32"))
HEIGHT_BYTES = 3            # 16.7M heights, ~318 years of chain

PROGRAM_OUTPUT = 1          # an output the chain created carries it
PROGRAM_NESTED = 2          # a P2SH-P2WSH spend pushed it as its redeem script
PROGRAM_BITS = PROGRAM_OUTPUT | PROGRAM_NESTED


def rec_width(cat):
    """Bytes of one record of `cat`: 24 for a 20-byte digest, 36 for 32."""
    return CATEGORIES[cat] + 1 + HEIGHT_BYTES


def _reduce(cat, byte_a, height_a, byte_b, height_b):
    """Merge two sightings of the same digest."""
    byte = (byte_a | byte_b) if cat in _OR_CATS else max(byte_a, byte_b)
    return byte, min(height_a, height_b)


def _combine_or(a, b):
    """`_reduce` on two whole records whose byte is a bitfield (`keys`,
    `programs*`): bits OR-ed, the lowest first height kept. The height
    is big-endian, so the byte minimum is the numeric one."""
    w = len(a) - 4
    return a[:w] + bytes([a[w] | b[w]]) + min(a[w + 1:], b[w + 1:])


def _combine_scripts(a, b):
    """`_reduce` on two whole script records (20- or 32-byte digest):
    the larger inner-keys count, the lowest first height."""
    w = len(a) - 4
    return a[:w] + bytes([max(a[w], b[w])]) + min(a[w + 1:], b[w + 1:])


# What the native kernel of the fusion's k-way stage knows the two rules
# as (nodsig_kway.h: the byte at rec-4 combined, the last three bytes the
# minimum, the group folded onto its first record — the same slicing as
# above). A rule without this name keeps the reference road.
_combine_or.native = "or_min"
_combine_scripts.native = "max_min"


def _combiner(cat):
    return _combine_or if cat in _OR_CATS else _combine_scripts

# Every K-th key of a merged file is sampled into a `.lad` sidecar at merge
# time, so a lookup bisects the resident ladder and reads ONE bucket (here
# ~49-74 KB, 24-36 B per record) instead of ~35 seeks on a multi-GB file.
# The ladder is a cache: it is NOT part of the canonical fingerprint (which
# is over the merged files' bytes alone), so its step can change freely and
# an archive without one still answers, by a blind bisect.
ARCHIVE_LADDER_EVERY = 2048

# What `verify` needs to rebuild each ladder from the file it indexes:
# logical name → (record width, key length, step). The same triple the
# merge sampled by, declared once so the seal and the audit cannot drift
# apart and raise a false alarm at each other. One table for both
# artifacts: their category names do not overlap.
LADDERS = {cat: (rec_width(cat), CATEGORIES[cat], ARCHIVE_LADDER_EVERY)
           for cat in CATEGORIES}
ARCHIVE_LADDERS = {cat: LADDERS[cat] for cat in CAT_ORDER}
PROOF_LADDERS = {cat: LADDERS[cat] for cat in PROOF_ORDER}


# ---------------------------------------------------------------------------
# Extraction: one input → its revelations, with provenance
# ---------------------------------------------------------------------------

# One scriptSig parse per input, shared with every other walk: see
# blockparse.scriptsig_pushes, imported above, for why it is one function.


def extract_revelations(tx_in, stats, sig_pushes=None):
    """Everything one input reveals, as (category, digest, flags).

    The walk mirrors the shapes of the standard spends (and is the
    same strategy as reuse_scan's, restated there independently): every
    key-shaped push of the scriptSig and every key-shaped witness item,
    wherever it sits, is a revealed key, keyed by the identity
    `keyforms` decides once (the compressed digest under OTHER_FACE
    when the form seen was another); the LAST scriptSig push is a
    candidate redeem script and the LAST witness item a candidate
    witness script, whatever they look like, unless their bytes prove
    they cannot be one (a control block, an annex); key-shaped pushes
    inside a candidate are revealed keys too, tagged as inner. Whether a
    candidate IS a script is not decided here: the fusion decides it
    against the programs the chain created. A taproot script path
    reveals its internal key (in the control block) and the keys its
    leaf names, both x-only. Malformed scripts are counted and skipped,
    never guessed at.

    `sig_pushes` lets the caller pass the scriptSig pushes it has
    already parsed. Passing them must not change the answer, only the
    cost.
    """
    out = []

    if sig_pushes is None:
        sig_pushes = scriptsig_pushes(tx_in, stats)

    ck = None
    for p in sig_pushes:
        ck = key_records(out, p, FLAG_SIG)

    witness = tx_in.witness
    witness_key_records(out, witness)

    # The script's own record carries HOW MANY keys were found inside
    # it. The count is already in hand and costs nothing to keep;
    # recovering it later would mean another pass over the chain,
    # because the archive stores the script's hash and never the script.
    if sig_pushes and not cannot_be_script(sig_pushes[-1], 0, stats):
        # `ck` is the last push's: when it was a key (a P2PKH spend), its
        # hash160 is the candidate's digest too, already computed.
        script_records(out, sig_pushes[-1], "scripts20", FLAG_INNER_SIG,
                       stats, None if ck is None else ck[1])
    if witness and not cannot_be_script(witness[-1], len(witness), stats):
        script_records(out, witness[-1], "scripts32", FLAG_INNER_WIT, stats)

    # A taproot script path: the internal key is bytes 1..33 of the
    # control block, the leaf names its own keys. Neither item is a
    # candidate script (the control block cannot be one, the leaf is
    # walked for keys instead of being hashed).
    body = taproot_body(witness)
    if len(body) >= 2 and is_control_block(body[-1]):
        key_records(out, body[-1][1:33], FLAG_WIT, xonly=True)
        for x in leaf_xonly_keys(body[-2]):
            key_records(out, x, FLAG_INNER_WIT, xonly=True)
    return out


def extract_output_revelations(tx_out, stats):
    """The keys one output publishes: pay-to-pubkey (`<key> OP_CHECKSIG`)
    and bare multisig (`OP_m <keys> OP_n OP_CHECKMULTISIG`). Such a key
    is public from the block that created the output, spent or not, and
    every lock built on it is exposed from that height. A taproot output
    publishes its key by construction and no lock hides behind it: it
    yields nothing here."""
    spk = tx_out.script_pubkey
    if len(spk) < MIN_KEY_OUTPUT:
        return ()
    out = []
    for push in output_keys(spk):
        if key_records(out, push, FLAG_OUT):
            stats["out_keys"] += 1
    return out


def output_program(spk):
    """(category, program) for a P2SH output (`a914 <20> 87`) or a P2WSH
    output (`0020 <32>`), else None. Both templates are exact and of
    fixed length: this is a byte comparison, not a guess."""
    n = len(spk)
    if n == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[22] == 0x87:
        return "programs20", bytes(spk[2:22])
    if n == 34 and spk[0] == 0x00 and spk[1] == 0x20:
        return "programs32", bytes(spk[2:34])
    return None


def _facts_block(facts):
    """The `Block` the header archive reads, out of what the native
    kernel reports: the header (re-serialized and re-hashed by the
    emitter, so it must be the block's), the two sizes, and a first
    transaction that is a coinbase exactly when the block's is, carrying
    its scriptSig. Nothing else is filled in, and nothing else is read."""
    coinbase = facts["coinbase_is_coinbase"]
    header = blockparse.BlockHeader(
        facts["version"], facts["prev_hash"], facts["merkle_root"],
        facts["time"], facts["bits"], facts["nonce"], facts["hash"])
    tx_in = blockparse.TxIn(bytes(32) if coinbase else b"\x01" * 32,
                            0xFFFFFFFF if coinbase else 0,
                            facts["coinbase_script"], 0, [])
    tx = blockparse.Tx(0, [tx_in], [], 0, None, None, False, 0, 0)
    return blockparse.Block(header, [tx], facts["size"], facts["weight"])


def block_records(block, height, stats, buffers, on_input=None):
    """What one block adds to the archive: the records, appended to
    `buffers` by category (whole records, see `_record`), and the
    counters it moves in `stats`. Returns how many records it appended.

    This is THE per-block body of the scan, stated once so that the scan,
    the conformance vectors (tests/fixtures/scan) and the differential
    test of a native kernel all call the same function: a kernel of the
    scan is answerable for exactly this — the multiset of records a block
    yields and the counters it moves — and for nothing else. The order
    of the records inside a buffer is the walk's and is not part of any
    contract: a run is sorted and reduced before it is written.

    `on_input(height, tx_in, pushes)`, when given, sees every non-coinbase
    input with its scriptSig pushes already parsed: the nonce census rides
    on the same walk (parsed once, walked twice), which is the whole
    saving of co-emission."""
    hb = height.to_bytes(HEIGHT_BYTES, "big")   # every record's height
    buffered = 0
    for tx in block.transactions:
        stats["transactions"] += 1
        # Outputs first, coinbase included: a key published in a
        # scriptPubKey is in view from this block, and a program created
        # here proves the scripts that open it.
        for tx_out in tx.outputs:
            recs = extract_output_revelations(tx_out, stats)
            for cat, digest, byte in recs:
                buffers[cat].append(_record(digest, byte, hb))
            buffered += len(recs)
            stats["revelations"] += len(recs)
            program = output_program(tx_out.script_pubkey)
            if program is not None:
                buffers[program[0]].append(
                    _record(program[1], PROGRAM_OUTPUT, hb))
                buffered += 1
                stats["program_outputs"] += 1
        if blockparse.is_coinbase(tx):
            continue
        for tx_in in tx.inputs:
            stats["inputs"] += 1
            pushes = scriptsig_pushes(tx_in, stats)
            recs = extract_revelations(tx_in, stats, pushes)
            for cat, digest, byte in recs:
                buffers[cat].append(_record(digest, byte, hb))
            buffered += len(recs)
            stats["revelations"] += len(recs)
            nested = nested_program(pushes, tx_in.witness)
            if nested is not None:
                buffers["programs32"].append(
                    _record(nested, PROGRAM_NESTED, hb))
                buffered += 1
                stats["nested_programs"] += 1
            if on_input is not None:
                on_input(height, tx_in, pushes)
    return buffered


def nested_program(sig_pushes, witness):
    """The 32-byte program of a P2SH-P2WSH spend, or None.

    A witness script nested in P2SH is proven by no output: the output
    holds hash160 of `0020 <32>`, and the `<32>` the witness script must
    hash to sits in the redeem script the scriptSig pushes. BIP 141 makes
    that push the scriptSig's only one, and a witness on any other spend
    of a non-witness output invalid. So an input with a witness whose
    last scriptSig push is `0020 <32>` names a program; the test is
    looser than the consensus rule (any last push, not the only one),
    which can only add programs, never miss one."""
    if witness and sig_pushes:
        last = sig_pushes[-1]
        if len(last) == 34 and last[0] == 0x00 and last[1] == 0x20:
            return bytes(last[2:34])
    return None


# ---------------------------------------------------------------------------
# The on-disk format: sorted runs, fused periodically
# ---------------------------------------------------------------------------
# A run is an immutable file of fixed-width records [digest | byte |
# height], sorted by digest, deduplicated within itself. The archive at
# any moment is the union of the merged files and the runs written since
# the last fusion, with the proof applied to the candidates; because
# deduplication is an OR of bits (or a max) and a min of heights, and the
# proof is membership in a set that only grows, fusion is associative and
# the result does not depend on when it happens, which is exactly what
# makes the format appendable: new blocks only ever ADD runs on top.


_BYTE = tuple(bytes((i,)) for i in range(256))


def _record(digest, byte, height_bytes):
    """One whole record, `digest | byte | first_height u24`, as the scan
    buffers it. Bytes and not a tuple: sorting whole records compares
    them in C with the order the tuple had (digest, then byte, then the
    big-endian height), and the run is written without taking them apart."""
    return digest + _BYTE[byte] + height_bytes


def _write_run(path, cat, records):
    """Sort, dedupe and write one run of whole records (see `_record`).
    Returns (records written, sha256). Atomic: tmp file + rename, so a
    crash never leaves a half-run behind under the final name. Rows
    leave in slabs (see IO_CHUNK): same bytes, same sha256, fewer calls.

    Equal digests reduce by the category's own rule (`_combiner`, the one
    the fusion applies), so a run holds exactly the bytes the tuple road
    it replaced wrote; a test compares the two. The road through tuples
    cost 7.53 µs per record against 3.73 for this one, measured."""
    records.sort()
    key_len = CATEGORIES[cat]
    combine = _combiner(cat)
    digest = hashlib.sha256()
    written = 0
    buf = bytearray()
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        last = key = None
        for r in records:
            if key is not None and r.startswith(key):
                last = combine(last, r)
                continue
            if last is not None:
                buf += last
                written += 1
                if len(buf) >= IO_CHUNK:
                    f.write(buf)
                    digest.update(buf)
                    buf.clear()
            last = r
            key = r[:key_len]
        if last is not None:
            buf += last
            written += 1
        if buf:
            f.write(buf)
            digest.update(buf)
    durable_replace(tmp, path)
    return written, digest.hexdigest()


def _read_records(path, cat, expect_sha=None, slab_bytes=IO_CHUNK,
                  digest_into=None):
    """Stream (digest, byte, first_height) from a run or merged file.
    The slab reading and sha verification are recio.read_fixed; this
    only splits each record into its three fields and raises the
    archive's own ScanError on corruption.

    `digest_into` is a hashlib object fed the raw records as they pass:
    a caller that must walk every byte anyway gets the file's sha256
    without a second read (see `_audit_records`)."""
    width = CATEGORIES[cat]
    for r in read_fixed(path, rec_width(cat), expect_sha=expect_sha,
                        slab_bytes=slab_bytes, error=ScanError):
        if digest_into is not None:
            digest_into.update(r)
        yield r[:width], r[width], int.from_bytes(r[width + 1:], "big")


def _reduced(records, cat):
    """One deduplicated stream of whole records out of a sorted one:
    equal digests arrive adjacent and are reduced by the category's
    rule, so the reduction is a look-behind."""
    key_len = CATEGORIES[cat]
    combine = _combiner(cat)
    pending = None
    for r in records:
        if pending is not None and r[:key_len] == pending[:key_len]:
            pending = combine(pending, r)
            continue
        if pending is not None:
            yield pending
        pending = r
    if pending is not None:
        yield pending


def _proven(candidates, programs, key_len, pile=None):
    """THE PROOF, in one place for the fusion and for every reader.

    `candidates` and `programs` are sorted streams of whole records. A
    candidate whose digest is among the programs is yielded: the chain
    created a program it opens, so it is a revealed script. Any other is
    handed to `pile.add` when a pile is given (the fusion keeps it for
    a program yet to come) and dropped otherwise (a reader answers at
    the watermark). A merge-join: both streams are read once, in order.

    The programs are read to their end even after the last candidate, so
    a sha-checked reader settles its digest instead of stopping short."""
    prog = next(programs, None)
    for r in candidates:
        key = r[:key_len]
        while prog is not None and prog[:key_len] < key:
            prog = next(programs, None)
        if prog is not None and prog[:key_len] == key:
            yield r
        elif pile is not None:
            pile.add(r)
    for _ in programs:
        pass


def _proven_blobs(candidates, programs, rec, key_len, pile):
    """THE PROOF by blobs, for the fusion: `_proven`'s rule (a
    candidate whose digest is among the programs is a revealed script;
    any other goes to the pile) applied to sorted reduced BLOBS of
    candidates against a `_BaseCursor` over the sealed programs.

    Each blob covers a key range no later blob revisits, so the programs
    up to its last key are gathered once, as a set of digests, and the
    blob is split by membership in one pass; the cursor never turns
    back. Yields the blobs of proven candidates; the pile receives the
    others through `pile.add_blob`. The programs are read to their end
    after the last candidate, so the cursor settles the sealed sha256
    instead of stopping short. The suite pins this road to `_proven`."""
    unit = f"{key_len}s{rec - key_len}x"      # the digest alone
    for blob in candidates:
        n = len(blob) // rec
        last = blob[-rec:-rec + key_len]
        # Every program with a digest <= last: strictly below the
        # digest one past it, and every remaining one past the top.
        above = None
        if last != b"\xff" * key_len:
            above = (int.from_bytes(last, "big") + 1).to_bytes(key_len, "big")
        digests = set()
        while programs.peek() is not None:
            m = programs.below(above, key_len)
            if m:
                piece = programs.slab[programs.off:programs.off + m * rec]
                programs.off += m * rec
                digests.update(_split(piece, rec, m, unit))
            if programs.off < programs.end:
                break                    # the next program is above
        # The hits, as a set operation in C; a blob without one goes to
        # the pile whole, and one with hits is cut around them — the
        # proven candidates are the rare ones, so the per-record work is
        # spent on those alone.
        keys = _split(blob, rec, n, unit)
        hits = digests.intersection(keys)
        if not hits:
            pile.add_blob(blob, n)
            continue
        kept, unproven, start = [], [], 0
        for i in sorted(bisect.bisect_left(keys, k) for k in hits):
            unproven.append(blob[start * rec:i * rec])
            kept.append(blob[i * rec:(i + 1) * rec])
            start = i + 1
        unproven.append(blob[start * rec:])
        if n > len(hits):
            pile.add_blob(b"".join(unproven), n - len(hits))
        yield b"".join(kept)
    while programs.peek() is not None:
        programs.off = programs.end


def _load_state(archive_dir, required=True):
    path = os.path.join(archive_dir, STATE_NAME)
    if not os.path.exists(path):
        if required:
            raise ScanError(f"no {STATE_NAME} in {archive_dir}: "
                            "run `scan` first")
        return None
    state = read_json(path, ScanError)
    if state.get("format") != FORMAT_TAG:
        raise ScanError(
            f"archive state says {state.get('format')!r}, not "
            f"{FORMAT_TAG!r}: an earlier format is read by the release "
            "that wrote it (v2.1.2 for reveal-archive-v3, v1.9.0 for "
            "reveal-archive-v2), and a fresh scan writes this one")
    return state


def _load_manifest(archive_dir):
    path = os.path.join(archive_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        return None
    manifest = read_json(path, ScanError)
    if manifest.get("format") != FORMAT_TAG:
        raise ScanError(
            f"archive manifest says {manifest.get('format')!r}, not "
            f"{FORMAT_TAG!r}: an earlier format is read by the release "
            "that wrote it")
    return manifest


def _proof_dir(archive_dir):
    return os.path.join(archive_dir, PROOF_DIR)


def _load_proof(archive_dir):
    """The sealed proof beside the archive, or None when there is none."""
    path = os.path.join(_proof_dir(archive_dir), MANIFEST_NAME)
    if not os.path.exists(path):
        return None
    proof = read_json(path, ScanError)
    if proof.get("format") != PROOF_TAG:
        raise ScanError(
            f"{path} says {proof.get('format')!r}, not {PROOF_TAG!r}")
    return proof


def _state_from_seal(manifest):
    """The state a sealed archive implies when it arrives without its
    own: nothing pending, the watermark and the block its seal names.

    What a state holds beyond that is how the archive was built (the
    runs not yet fused, the counters, the seconds), none of which a
    reader needs and none of which a copy carries. The block hash is the
    one fact that is not in the identity and that a reader does need:
    `derive` confronts it with the snapshot's block, and a scan growing
    the archive checks that the next block links to it."""
    return {"format": FORMAT_TAG,
            "last_height": manifest["identity"]["coverage"]["to"],
            "last_block_hash": manifest["build"]["last_block_hash"],
            "stats": {}, "runs": []}


def _cat_file(manifest, cat):
    """The file name holding a merged category.

    Merged files carry a GENERATION because the fusion is crash-safe
    (see run_merge): the manifest names the file, it is not derived
    from the category. The name lives in `build` and the digest in
    `identity`, which is the split itself: a generation number is how
    this copy was made, a digest is what it holds.

    Checked on the way out: an archive is a thing people hand each
    other, so a manifest this process did not write is untrusted input
    and its names must stay inside the directory (recio.checked_name)."""
    return checked_name(manifest["build"]["files"][cat]["file"], ScanError)


def _run_path(archive_dir, name):
    """A pending run's path. The name comes from the state file, which
    is untrusted whenever this process did not write it, and these paths
    are both read and removed: see recio.checked_name."""
    return os.path.join(archive_dir, RUNS_DIR,
                        checked_name(name, ScanError, "run"))


def _cat_sha(manifest, cat):
    """The digest the identity records for a merged category."""
    for entry in manifest["identity"]["files"]:
        if entry["name"] == cat:
            return entry["sha256"]
    raise ScanError(f"the identity names no category {cat!r}")


def _sweep_unnamed(directory, manifest, order, prefix, why):
    """What the manifest does not name does not exist: delete it.

    One rule, two moments. BEFORE a fusion it clears what a crashed
    fusion left — a generation written but never committed, a `.tmp`
    stub; the manifest still describes a whole, readable artifact and
    the fusion simply runs again. AFTER a fusion it clears the
    generation the new manifest has just superseded. Both are the same
    question ("is this file named?"), so they are the same code, for
    the archive and for its proof alike."""
    if not os.path.isdir(directory):
        return
    named = set()
    if manifest is not None:
        named = ({_cat_file(manifest, c) for c in order}
                 | {e["file"]
                    for e in manifest["build"]["caches"].values()})
    for name in sorted(os.listdir(directory)):
        if not name.startswith(prefix):
            continue
        if name.endswith(".tmp") or name not in named:
            os.remove(os.path.join(directory, name))
            print(f"  removed {name} ({why})", file=sys.stderr)


def _in_fusion_window(state, manifest):
    """True when a fusion sealed the archive and was killed before it
    rewrote the state: runs are still named, and the watermark they
    reach is the one the manifest already covers. Outside a crash this
    cannot happen: a scan that adds runs moves the watermark past the
    seal, and a completed fusion leaves no runs."""
    return (manifest is not None and bool(state["runs"])
            and state["last_height"] == manifest["identity"]["coverage"]["to"])


def _check_proof(state, manifest, proof):
    """Raise unless `proof` is the proof this archive can grow beside.

    The normal case is the proof sealed in the same fusion: the archive
    names its fingerprint, and it names the archive as its parent. The
    one other case accepted is the crash window (`_in_fusion_window`):
    the fusion commits the archive's manifest BEFORE the proof's, so a
    kill between the two leaves the previous proof beside the new
    archive, and re-fusing the same runs against it lands on the same
    bytes (every candidate it promotes is already in the archive, and
    merging a record twice is merging it once). The previous proof is
    recognized by its parent: the archive the new one was fused onto.
    The order is not negotiable: committed the other way round, the
    new proof would have dropped the candidates it promoted, and the
    archive holding them would have been swept."""
    if manifest is None:
        if proof is not None:
            raise ScanError(
                f"{PROOF_DIR}/ holds a sealed proof but the archive has no "
                "manifest: a proof is sealed in the same fusion as its "
                "archive, so this one belongs to another: remove it, or "
                "restore the archive's manifest")
        return
    sealed_with = manifest["build"]["proof"]["fingerprint"]
    if (proof is not None and proof["fingerprint"] == sealed_with
            and proof["build"]["parent"]["fingerprint"]
            == manifest["fingerprint"]):
        return
    if _in_fusion_window(state, manifest):
        before = None if proof is None else \
            proof["build"]["parent"]["fingerprint"]
        if before == manifest["build"]["fused_onto"]:
            return
    if proof is None:
        raise ScanError(
            f"this archive has no proof beside it ({PROOF_DIR}/"
            f"{MANIFEST_NAME}): it answers every question up to its "
            "watermark, but it can only grow beside the proof it was "
            "sealed with, which holds the programs that prove a candidate "
            "and the candidates not proven yet. Restore that directory, "
            "or build from zero")
    raise ScanError(
        f"the proof beside this archive ({proof['fingerprint'][:16]}…) is "
        f"not the one it was sealed with ({sealed_with[:16]}…): growing "
        "against another proof would keep or set aside candidates by "
        "programs this archive never saw")


# ---------------------------------------------------------------------------
# scan — the long run
# ---------------------------------------------------------------------------

@locked("archive_dir", ScanError, "scan")
@locked("nonces_dir", ScanError, "scan")
def run_scan(rpc_url, auth, end_height, archive_dir,
             batch_size=25, checkpoint_every=10_000,
             flush_records=8_000_000, client=None, graph_dir=None,
             headers_dir=None, nonces_dir=None, prefetch=True,
             prefetch_depth=1, graph_digest_dir=None):
    """Stream the chain and archive every revelation.

    The loop is the same discipline as reuse_scan's (and is written
    out again on purpose — it is part of what the cross-check checks):
    fetch a batch of raw blocks, refuse any byte that does not hash
    back to the block we asked for or does not link to its
    predecessor, extract, and checkpoint. The state file records the
    last height whose revelations are safely on disk; a rerun with
    the same arguments resumes from there. Runs that a crash left
    unrecorded are deleted on resume: what the state does not name
    does not exist.

    A sealed archive that arrived without its state grows from its
    seal: the watermark and the block hash the manifest names stand in
    for the state, and the first block fetched must link to that hash.
    Growing needs the proof it was sealed with, checked here and not
    after a day of scanning.
    """
    warn_if_slow_ripemd160("this scan")
    client = client or RpcClient(rpc_url, auth)
    os.makedirs(os.path.join(archive_dir, RUNS_DIR), exist_ok=True)
    state_path = os.path.join(archive_dir, STATE_NAME)

    stats = {"transactions": 0, "inputs": 0, "malformed_scriptsig": 0,
             "revelations": 0, "program_outputs": 0, "nested_programs": 0,
             **new_filter_stats()}
    runs = []                      # [{name, category, records, sha256}]
    start_height = 1               # the genesis coinbase reveals nothing
    prev_hash = None

    state = _load_state(archive_dir, required=False)
    manifest = _load_manifest(archive_dir)
    if state is None and manifest is not None:
        state = _state_from_seal(manifest)
        print(f"growing a sealed archive from its watermark "
              f"{state['last_height']:,}", file=sys.stderr)
    if manifest is not None:
        if _in_fusion_window(state, manifest):
            raise ScanError(
                "a fusion was interrupted after sealing the archive and "
                "before rewriting the state: run `merge` to finish it, "
                "then scan")
        _check_proof(state, manifest, _load_proof(archive_dir))
    # Built from the state so a resumed scan continues its own total.
    clock = WallClock("scan", state)
    if state is not None:
        zeros = dict(stats)
        stats.update(state["stats"])
        for name, zero in zeros.items():
            stats.setdefault(name, zero)
        runs = state["runs"]
        start_height = state["last_height"] + 1
        prev_hash = bytes.fromhex(state["last_block_hash"])[::-1]
        known = {r["name"] for r in runs}
        for name in os.listdir(os.path.join(archive_dir, RUNS_DIR)):
            if name not in known:
                os.remove(os.path.join(archive_dir, RUNS_DIR, name))
                print(f"  removed stale run {name} (not named by the "
                      "state)", file=sys.stderr)
        # A named run whose bytes the disk does not hold was lost after
        # the state was written (a power loss): nothing re-emits those
        # records, so stop here rather than at the fusion.
        for run in runs:
            path = _run_path(archive_dir, run["name"])
            expected = run["records"] * rec_width(run["category"])
            actual = os.path.getsize(path) if os.path.exists(path) else -1
            if actual != expected:
                raise ScanError(
                    f"{path}: the state names this run with "
                    f"{run['records']:,} records ({expected:,} bytes) but "
                    f"the disk holds {actual:,} bytes — lost after the "
                    "state was written (power loss?); the heights it "
                    "covers have to be scanned again")
        print(f"resuming from height {start_height}", file=sys.stderr)

    # Graph co-emission (OFF by default), same contract as in
    # reuse_scan.py: load() lines the graph archive up with this
    # scan's resume point, or refuses.
    #
    # --graph-digest is the same plug measuring instead of writing: it
    # checks that this code still emits the graph a reference archive
    # already holds, without spending the disk to prove it. The two are
    # answers to one question, so asking both is a mistake worth naming.
    emitter = None
    if graph_dir and graph_digest_dir:
        raise graphemit.GraphError(
            "--graph and --graph-digest do the same work with and "
            "without the disk: pick one (fingerprint the archive "
            "afterwards if you wrote it)")
    if graph_dir:
        emitter = graphemit.GraphEmitter(graph_dir)
        emitter.load(start_height)
    elif graph_digest_dir:
        emitter = graphemit.GraphDigest(graph_digest_dir, archive_dir)
        emitter.load(start_height)

    # The header archive (--headers), the one plug that can move this
    # scan's starting point: a fresh archive begins at genesis, because
    # a chain of headers that starts at 1 cannot check its first link.
    # That block is fed to it and to nothing else.
    header_emitter = None
    feed_from = start_height
    if headers_dir:
        header_emitter = headers.HeaderEmitter(headers_dir)
        feed_from = header_emitter.load(start_height)

    # The nonce census (--nonces): the one plug that consumes what this
    # scan has ALREADY parsed rather than the block. It is fed per input,
    # with the scriptSig pushes handed over, so the chain's scriptSigs
    # are parsed once for both artifacts.
    nonce_emitter = None
    if nonces_dir:
        nonce_emitter = nonces.NonceEmitter(nonces_dir)
        nonce_emitter.load(start_height)

    if start_height > end_height:
        print(f"nothing to do: archive already covers height "
              f"{start_height - 1}", file=sys.stderr)
        return

    buffers = {cat: [] for cat in RUN_CATS}
    buffered = 0
    seg_start = start_height       # first height the open buffers cover

    def flush(through_height):
        """Close the open buffers into runs named by the exact height
        interval they cover. Runs do NOT tile the chain: an interval
        with nothing to keep produces no run (empty buffers are
        skipped below while seg_start advances past them), so a gap
        between run names is legal and silent. Coverage is declared
        by the watermark at seal time, never deduced from the names;
        that is why a missing tile is invisible to merge and verify
        by design, not by luck."""
        nonlocal buffered, seg_start
        for cat in RUN_CATS:
            if not buffers[cat]:
                continue
            name = (f"run_{seg_start:08d}-{through_height:08d}_"
                    f"{cat}.bin")
            path = os.path.join(archive_dir, RUNS_DIR, name)
            records, sha = _write_run(path, cat, buffers[cat])
            runs.append({"name": name, "category": cat,
                         "records": records, "sha256": sha})
            buffers[cat] = []
        buffered = 0
        seg_start = through_height + 1

    def checkpoint(height, block_hash_display):
        # The co-emitted artifacts first, on purpose: a crash between
        # the writes leaves them AHEAD, the one direction their load()
        # heals.
        if emitter:
            emitter.checkpoint(height, block_hash_display)
        if header_emitter:
            header_emitter.checkpoint(height, block_hash_display)
        if nonce_emitter:
            nonce_emitter.checkpoint(height, block_hash_display)
        flush(height)
        st = {
            "format": FORMAT_TAG,
            "last_height": height,
            "last_block_hash": block_hash_display,
            "stats": stats,
            "runs": runs,
            # The roads that scanned this archive, across resumes: the
            # native kernel, the Python reference, or both. Information,
            # never identity: the two write the same bytes.
            "kernels": sorted(kernels | {"native" if native else "python"}),
        }
        # The pass's own seconds, accumulated across resumes because the
        # total lives in the state and the state is what survives a kill.
        # A run split over several sessions therefore reports what it
        # really cost, not what its last stretch cost; what is lost is
        # the stretch between this checkpoint and a kill, which makes the
        # number a FLOOR, and the contract says so.
        clock.stamp(st)
        atomic_json(state_path, st)

    pace = Pace(end_height)
    fetcher = BlockFetcher(client, feed_from, end_height, batch_size,
                           prefetch=prefetch, depth=prefetch_depth)
    # The native kernel takes the block whole (hash, parse, records) and
    # hands back no parsed block: the graph and the nonce census read
    # one, so a scan that co-emits them keeps the Python road. The header
    # archive needs only what the kernel reports (see `_facts_block`).
    native = kernel.available() and not emitter and not nonce_emitter
    kernels = set(state.get("kernels", ())) if state else set()
    for window, hashes, raws in fetcher:
        for h, want, raw in zip(window, hashes, raws):
            if native:
                try:
                    recs, moved, facts = kernel.scan_block(raw, h, want)
                except kernel.HashMismatch:
                    raise ScanError(f"height {h}: block bytes do not hash "
                                    "to the requested block hash") from None
                if prev_hash is not None and facts["prev_hash"] != prev_hash:
                    raise ScanError(f"height {h}: prev_hash does not link "
                                    f"to height {h - 1} (reorg? wrong node?)")
                prev_hash = facts["hash"]
                if header_emitter:
                    header_emitter.add_block(h, _facts_block(facts))
                if h < start_height:
                    continue
                for cat, blob in zip(RUN_CATS, recs):
                    if blob:
                        buffers[cat] += _split(blob, rec_width(cat))
                        buffered += len(blob) // rec_width(cat)
                for key, n in moved.items():
                    stats[key] += n
                continue
            # The hash BEFORE the parse: until these bytes are known to
            # be the block that was asked for, they are input from the
            # other end of a wire, and there is no reason to walk them
            # with a parser first. See blockparse.block_id.
            if blockparse.block_id(raw) != want:
                raise ScanError(f"height {h}: block bytes do not hash to "
                                "the requested block hash")
            block = blockparse.parse_block(raw)   # Merkle + witness commit
            if prev_hash is not None and block.header.prev_hash != prev_hash:
                raise ScanError(f"height {h}: prev_hash does not link to "
                                f"height {h - 1} (reorg? wrong node?)")
            prev_hash = block.header.hash
            if header_emitter:
                header_emitter.add_block(h, block)
            if h < start_height:
                # Genesis, fetched for the header chain's first link
                # only: its coinbase is unspendable and reveals nothing.
                continue
            if emitter:
                emitter.add_block(h, block)
            buffered += block_records(
                block, h, stats, buffers,
                on_input=nonce_emitter.add_input if nonce_emitter else None)

        pace.add(len(window))
        if buffered >= flush_records:
            flush(window[-1])
        if nonce_emitter:
            nonce_emitter.flush_if_full(window[-1])

        if (window[-1] % checkpoint_every < batch_size
                or window[-1] == end_height):
            checkpoint(window[-1], blockparse.hash_hex(prev_hash))
            print(f"checkpoint @ {window[-1]:>7,}: "
                  f"{stats['revelations']:,} revelations in "
                  f"{len(runs)} runs | {pace.text(window[-1])}",
                  file=sys.stderr)

    print(f"\narchive covers heights 1..{end_height} "
          f"({stats['revelations']:,} revelations, {len(runs)} runs; "
          f"malformed scriptSigs: {stats['malformed_scriptsig']}, "
          f"candidates that do not parse as a script: "
          f"{stats['unparsed_candidates']:,}; "
          f"keys in outputs: {stats['out_keys']:,}; programs: "
          f"{stats['program_outputs']:,} in outputs, "
          f"{stats['nested_programs']:,} nested in P2SH; "
          f"{stats['control_or_annex']:,} control blocks or annexes, "
          "which cannot be scripts)")
    if graph_digest_dir:
        emitter.report()
    print("run `merge` to fuse the runs, prove the candidates and "
          "fingerprint the archive.")


# ---------------------------------------------------------------------------
# merge — the periodic fusion
# ---------------------------------------------------------------------------

def _fuse(directory, prefix, cat, generation, sources, base_manifest, slab,
          cursors=(), blobs=None):
    """One merged file of the next generation: the previous one (named by
    `base_manifest`, when there is one) as the gallop's cursor, `sources`
    as sorted record streams, `cursors` as the runs by slabs (the k-way
    stage) or `blobs` as a stream that stage already produced (the
    proof's), the category's own reduction on equal digests.
    Returns (build.files entry, build.caches entry, sha256).

    The shared fusion, with the previous generation as a cursor: an
    append inserts a few million records into billions, and the
    stretches nothing interleaves move as slabs instead of passing one by
    one through three generator layers. The bytes, the ladder and the
    count are the ones a per-record walk produces, which the suite pins."""
    rec = rec_width(cat)
    stem = f"{prefix}{cat}_g{generation:04d}"
    cursor = None
    if base_manifest is not None:
        cursor = _BaseCursor(
            os.path.join(directory, _cat_file(base_manifest, cat)), rec,
            _cat_sha(base_manifest, cat), slab, ScanError)
    records, sha, lad_sha, _dups = merge_to_file(
        sources, os.path.join(directory, stem + ".bin"), rec,
        CATEGORIES[cat], os.path.join(directory, stem + ".lad"),
        ARCHIVE_LADDER_EVERY, None, base=cursor, combine=_combiner(cat),
        cursors=cursors, blobs=blobs)
    return ({"file": stem + ".bin", "records": records},
            {"file": stem + ".lad", "every": ARCHIVE_LADDER_EVERY,
             "sha256": lad_sha},
            sha)


@locked("archive_dir", ScanError, "merge")
def run_merge(archive_dir):
    """Fuse the merged files and all runs into one sorted deduplicated
    file per category, prove the candidates, then fingerprint the
    archive and its proof.

    The fingerprint is the archive's canonical form: after a full
    fusion the archive at height H is one well-defined set of bytes,
    whatever the run boundaries were — an interrupted-and-resumed scan
    fuses to the SAME files as a one-shot scan, and an archive grown in
    two takes to the same files as one built at once. That is the
    determinism rule of the card index: the incremental state must
    equal a rebuild from zero, and this is where it is enforced and
    measured.

    THE PROOF, PER SCRIPT PARTITION
    ===============================
    1. the programs: the previous generation of the proof's programs
       and the program runs, fused;
    2. the candidates: the proof's pile of candidates not proven yet and
       the candidate runs, reduced into one stream and joined with the
       programs just sealed. A candidate among them joins the archive's
       previous generation in the merge of the scripts; any other goes
       to the new pile, in the same pass.
    A candidate the pile has held for years is promoted the moment a
    program for it appears, which is what makes appending equal
    rebuilding: a rebuild sees the old candidate and the new program
    together, and so does the pile.

    WHY THE MERGED FILES CARRY A GENERATION, AND THE ORDER OF THE COMMIT
    ===================================================================
    The fusion writes generation N+1 beside generation N, for the
    archive and for the proof, and deletes nothing before the commit.
    The commit is three writes, in this order: the archive's manifest,
    the proof's manifest, the state that stops naming the runs. The
    consumed runs and the superseded generations are deleted after all
    three. A kill between any two leaves the runs named and a readable
    archive, and the next `merge` fuses them again onto what is sealed
    and lands on the same bytes (see `_check_proof` for the one window
    where the two manifests disagree, and why this order and not the
    other). Nothing about the FORMAT depends on the generation: the
    fingerprint is over the category names and the file digests, never
    over a file name.
    """
    state = _load_state(archive_dir)
    manifest = _load_manifest(archive_dir)
    proof = _load_proof(archive_dir)
    proof_dir = _proof_dir(archive_dir)
    # The sweep comes first, as it always did: a fusion killed while it
    # deleted the generation it had just superseded leaves files no
    # manifest names, and a merge with nothing to fuse is where they go.
    _sweep_unnamed(archive_dir, manifest, CAT_ORDER, "archive_",
                   "not named by the manifest")
    _sweep_unnamed(proof_dir, proof, PROOF_ORDER, "proof_",
                   "not named by the proof's manifest")
    if not state["runs"] and manifest is not None:
        print("nothing to fuse: no runs since the last merge.")
        return manifest["fingerprint"]
    _check_proof(state, manifest, proof)

    generation = ((manifest["build"]["generation"] + 1)
                  if manifest else 1)
    # The fusion writes the new generations beside the runs and the old
    # ones, and deletes nothing before the commit. Its upper bound is
    # every record it reads: the run pile plus both current generations
    # (the first fusion of a scan reads a pile about twice the size of
    # what it will seal: measured, and the reason this is checked here
    # rather than discovered as EIO hours in).
    pile = sum(run["records"] * rec_width(run["category"])
               for run in state["runs"])
    base = 0
    for m, d, order in ((manifest, archive_dir, CAT_ORDER),
                        (proof, proof_dir, PROOF_ORDER)):
        if m is not None:
            base += sum(os.path.getsize(os.path.join(d, _cat_file(m, c)))
                        for c in order)
    print(f"  fusing {pile / 1e9:,.1f} GB of runs"
          + (f" into {base / 1e9:,.1f} GB sealed" if base else ""),
          file=sys.stderr)
    preflight_space(archive_dir, pile + base, ScanError, "archive merge")
    os.makedirs(proof_dir, exist_ok=True)
    # The clock reads what the archive's state already carries, so an
    # entry the scan left under `scan` rides into the manifest here
    # instead of being lost when the runs are consumed. Stamped at the
    # END of the fusion, below: a build dict is assembled before the
    # work it describes.
    clock = WallClock("merge", state)
    build = {"producer": producer(), "generation": generation,
             "files": {}, "caches": {}}
    proof_build = {"producer": producer(), "generation": generation,
                   "files": {}, "caches": {}}
    digests = {}
    proof_digests = {}

    def runs_of(cat):
        return [(_run_path(archive_dir, run["name"]), run["sha256"])
                for run in state["runs"] if run["category"] == cat]

    def cursors(todo, rec, slab):
        return [_BaseCursor(path, rec, sha, slab, ScanError)
                for path, sha in todo]

    runs = runs_of("keys")
    slab = budgeted_slab(len(runs) + 1)
    (build["files"]["keys"], build["caches"]["keys"],
     digests["keys"]) = _fuse(archive_dir, "archive_", "keys", generation,
                              [], manifest, slab,
                              cursors=cursors(runs, rec_width("keys"), slab))
    print(f"{'keys':<10} {build['files']['keys']['records']:>14,} records")

    for cat in ("scripts20", "scripts32"):
        prog_cat, pile_cat = PROVED_BY[cat]
        rec = rec_width(cat)
        key_len = CATEGORIES[cat]

        runs = runs_of(prog_cat)
        slab = budgeted_slab(len(runs) + 1)
        entry, cache, prog_sha = _fuse(proof_dir, "proof_", prog_cat,
                                       generation, [], proof, slab,
                                       cursors=cursors(runs, rec, slab))
        proof_build["files"][prog_cat] = entry
        proof_build["caches"][prog_cat] = cache
        proof_digests[prog_cat] = prog_sha

        todo = runs_of(cat)
        if proof is not None:
            todo.insert(0, (os.path.join(proof_dir,
                                         _cat_file(proof, pile_cat)),
                            _cat_sha(proof, pile_cat)))
        slab = budgeted_slab(len(todo) + 2)
        # The candidates: the pile and the runs through the k-way stage,
        # as sorted reduced blobs; the programs just sealed, as a cursor.
        candidates = _BulkFusion(cursors(todo, rec, slab), rec, key_len,
                                 None, _combiner(cat), None).blobs()
        programs = _BaseCursor(os.path.join(proof_dir, checked_name(
                                   entry["file"], ScanError)), rec,
                               prog_sha, slab, ScanError)
        stem = f"proof_{pile_cat}_g{generation:04d}"
        pile_writer = LadderWriter(os.path.join(proof_dir, stem + ".bin"),
                                   rec, key_len,
                                   os.path.join(proof_dir, stem + ".lad"),
                                   ARCHIVE_LADDER_EVERY)
        kept = _proven_blobs(candidates, programs, rec, key_len, pile_writer)
        (build["files"][cat], build["caches"][cat],
         digests[cat]) = _fuse(archive_dir, "archive_", cat, generation,
                               [], manifest, slab, blobs=kept)
        n, pile_sha, pile_lad = pile_writer.close()
        proof_build["files"][pile_cat] = {"file": stem + ".bin",
                                          "records": n}
        proof_build["caches"][pile_cat] = {"file": stem + ".lad",
                                           "every": ARCHIVE_LADDER_EVERY,
                                           "sha256": pile_lad}
        proof_digests[pile_cat] = pile_sha
        print(f"{cat:<10} {build['files'][cat]['records']:>14,} records "
              f"proven by {entry['records']:,} programs; {n:,} candidates "
              "not proven")

    # The identities: the category digests in fixed order, plus the
    # coverage, which for THIS format is the field that matters most.
    # The records carry a first_height each, so `verify --deep` can hold
    # the watermark to a floor, but only a floor: a stretch of chain that
    # reveals nothing new leaves no record, and nothing in the bytes
    # contradicts a manifest claiming a taller watermark than the scan
    # reached, while every "not revealed up to H" would inherit the lie.
    # Inside the identity, the claim cannot move without moving the
    # fingerprint. Same chain + same height, same number on anyone's
    # machine: the archive's twin of muhash.
    last = state["last_height"]
    proof_identity = make_identity(
        PROOF_TAG, 1, last, ((c, proof_digests[c]) for c in PROOF_ORDER))
    identity = make_identity(FORMAT_TAG, 1, last,
                             ((cat, digests[cat]) for cat in CAT_ORDER))
    # Outside the identity, and each for a reader who has only this
    # manifest: the block the watermark stands on (a received archive
    # has no state to read it from), the proof sealed beside it, the
    # archive it was fused onto (how a fusion killed between its two
    # manifests is recognized), and how many candidates the proof has
    # not proven, which is the archive's answer to "what did you leave
    # out", for a reader who never received the proof.
    build["last_block_hash"] = state["last_block_hash"]
    build["fused_onto"] = manifest["fingerprint"] if manifest else None
    build["proof"] = {"format": PROOF_TAG,
                      "fingerprint": identity_fingerprint(proof_identity)}
    build["unproven"] = {cat: proof_build["files"][PROVED_BY[cat][1]]
                         ["records"] for cat in PROVED_BY}
    # The roads that scanned the runs fused here (nodsig.kernel): the
    # native kernel, the Python reference, or both across resumes.
    # Information about how the bytes were made, never about what they
    # are: the two roads write the same bytes, and the suite holds them
    # to it.
    build["kernels"] = state.get("kernels", ["python"])
    build["seconds"] = clock.stamp(state)
    build["wall"] = clock.wall()
    new_manifest = seal_manifest(FORMAT_TAG, identity, build)
    proof_build["parent"] = declared_parent(
        FORMAT_TAG, new_manifest["fingerprint"], identity["coverage"])
    new_proof = seal_manifest(PROOF_TAG, proof_identity, proof_build)

    # THE COMMIT. Up to the first write the old generations are still the
    # archive and a crash costs nothing but the work; see the docstring
    # for why these three writes come in this order. Between them a
    # reader sees the new base AND the runs it already contains, which is
    # harmless: fusion dedups by OR, so reading a record twice is the
    # same as reading it once.
    atomic_json(os.path.join(archive_dir, MANIFEST_NAME), new_manifest)
    atomic_json(os.path.join(proof_dir, MANIFEST_NAME), new_proof)
    # Checked BEFORE the state is rewritten, so a state naming a run
    # outside the archive is refused instead of removing it.
    consumed = [_run_path(archive_dir, run["name"]) for run in state["runs"]]
    state["runs"] = []
    atomic_json(os.path.join(archive_dir, STATE_NAME), state)
    for path in consumed:
        os.remove(path)
    _sweep_unnamed(archive_dir, new_manifest, CAT_ORDER, "archive_",
                   "superseded generation")
    _sweep_unnamed(proof_dir, new_proof, PROOF_ORDER, "proof_",
                   "superseded generation")
    print(f"merged through height {state['last_height']:,}")
    print(f"fingerprint: {new_manifest['fingerprint']}")
    print(f"proof:       {new_proof['fingerprint']}")
    return new_manifest["fingerprint"]


# ---------------------------------------------------------------------------
# verify — the audit of a sealed archive
# ---------------------------------------------------------------------------

def _audit_records(directory, manifest, order):
    """Read every record of every merged category in `order` and check
    what the bytes alone cannot say. Returns (highest first_height,
    prepared), where `prepared` is name → (sha256, ladder) for the files
    this pass streamed; the digest and the ladder samples come free with
    the bytes, and handing them to `verify_sealed` is what keeps the deep
    audit to ONE read of each file instead of two.

    The digests prove the files did not rot; they say nothing about
    whether the fusion did its job, because a wrongly built archive is
    sealed just as faithfully as a right one. What a pass over the
    records adds, per category:

    - **digests strictly ascending.** One statement covering both the
      order the search depends on and the deduplication the format
      promises: the fusion emits each digest exactly once, so equal
      adjacent digests are as wrong as inverted ones;
    - **the record count** the manifest's build block claims;
    - **the byte**: for `keys`, never the 65-byte form and the x-only
      form together; for a program, one or both of the two carriers and
      nothing else;
    - **`first_height` within 1..watermark.** A record above the
      watermark would mean the archive holds a revelation the coverage
      claims not to cover, which is the one lie that would poison
      every "never revealed up to H".

    The cost is a full read of every file (tens of GB at chain scale),
    which is why `verify` asks for it instead of assuming it.
    """
    watermark = manifest["identity"]["coverage"]["to"]
    highest = 0
    prepared = {}
    for cat in order:
        name = _cat_file(manifest, cat)
        path = os.path.join(directory, name)
        declared = manifest["build"]["files"][cat]["records"]
        previous = None
        records = 0
        top = 0
        rec_w, key_len, every = LADDERS[cat]
        digest_of_file = hashlib.sha256()
        ladder = bytearray()
        for digest, byte, height in _read_records(
                path, cat, _cat_sha(manifest, cat),
                digest_into=digest_of_file):
            if records % every == 0:
                ladder += digest[:key_len]
            if previous is not None and digest <= previous:
                where = "repeats" if digest == previous else "goes back to"
                raise ScanError(
                    f"{name}: record {records:,} {where} "
                    f"{digest.hex()}, after {previous.hex()}. A merged "
                    f"file is sorted and deduplicated by construction, so "
                    f"a search through it can stop above a digest that is "
                    f"in there and report it absent")
            if cat == "keys" and (byte & FLAG_UNCOMPRESSED
                                  and byte & FLAG_XONLY):
                raise ScanError(
                    f"{name}: record {records:,} ({digest.hex()}) carries "
                    f"flag bits {byte:#04x}, outside the five this "
                    f"format defines")
            if cat in PROGRAM_CATS and (not byte or byte & ~PROGRAM_BITS):
                raise ScanError(
                    f"{name}: record {records:,} ({digest.hex()}) says it "
                    f"came from {byte:#04x}, which is neither an output nor "
                    f"a nested redeem script")
            if not 1 <= height <= watermark:
                raise ScanError(
                    f"{name}: record {records:,} ({digest.hex()}) was "
                    f"first seen at height {height:,}, outside the "
                    f"coverage 1..{watermark:,} this archive claims")
            previous = digest
            records += 1
            top = max(top, height)
        if records != declared:
            raise ScanError(f"{name}: {records:,} records on disk, "
                            f"{declared:,} in the manifest")
        # Same two rules `sha_and_ladder` applies, on bytes already
        # read: the digest of the whole file, and every `every`-th
        # record's key. The audit that follows checks the manifest
        # against these instead of streaming the file again.
        prepared[cat] = (digest_of_file.hexdigest(), bytes(ladder))
        highest = max(highest, top)
        if not records:
            print(f"ok  {name} is empty, as its manifest says")
            continue
        print(f"ok  {records:,} records in {name}, ordered and unique, "
              f"first seen up to height {top:,}")
    return highest, prepared


def _common_digests(path_a, path_b, cat):
    """How many digests two sorted files of `cat`'s width share: a
    merge-join, both read once."""
    rec, key_len = rec_width(cat), CATEGORIES[cat]
    other = read_fixed(path_b, rec, error=ScanError)
    b = next(other, None)
    common = 0
    for r in read_fixed(path_a, rec, error=ScanError):
        key = r[:key_len]
        while b is not None and b[:key_len] < key:
            b = next(other, None)
        if b is not None and b[:key_len] == key:
            common += 1
    return common


def _audit_proof(archive_dir, manifest, proof):
    """The proof applied, checked from the sealed bytes of both artifacts:
    every script the archive holds is among the programs, and no candidate
    the proof set aside is. The digests say both sets were written
    faithfully; only this says the fusion kept and set aside by the rule.
    Two merge-joins per partition."""
    proof_dir = _proof_dir(archive_dir)
    for cat, (prog_cat, pile_cat) in PROVED_BY.items():
        programs = os.path.join(proof_dir, _cat_file(proof, prog_cat))
        held = manifest["build"]["files"][cat]["records"]
        proven = _common_digests(
            os.path.join(archive_dir, _cat_file(manifest, cat)), programs,
            prog_cat)
        if proven != held:
            raise ScanError(
                f"{held - proven:,} of the {held:,} records of {cat} are not "
                f"among the programs of the proof: the archive holds "
                "candidates the chain never proved to be scripts")
        wrong = _common_digests(
            os.path.join(proof_dir, _cat_file(proof, pile_cat)), programs,
            prog_cat)
        if wrong:
            raise ScanError(
                f"{wrong:,} candidates the proof set aside in {pile_cat} are "
                f"among its programs: they are revealed scripts the archive "
                "does not hold")
        print(f"ok  proof applied to {cat}: its {held:,} records are all "
              f"programs, none of the "
              f"{proof['build']['files'][pile_cat]['records']:,} set aside "
              "is")


def run_verify(archive_dir, deep=False):
    """Re-read a sealed archive, and its proof when it has one, against
    their manifests.

    Without `--deep`: the merged files against the digests in the
    identity, the ladders rebuilt from the files they index, and the
    fingerprints recomputed from what is on disk. One read.

    With `--deep`: a pass over the records first (see `_audit_records`),
    whose highest `first_height` then confronts the declared coverage as
    a FLOOR. It can only be a floor: a stretch of chain revealing
    nothing new leaves no record, so the tail of the coverage is
    unprovable by construction. Said out loud either way, because an
    audit silent about what it did not check reads as one that checked
    everything. And, when the proof is there, the proof itself: the
    archive's scripts are programs, the set-aside candidates are not.
    """
    manifest = _load_manifest(archive_dir)
    if manifest is None:
        raise ScanError(f"no {MANIFEST_NAME} in {archive_dir}: an archive "
                        "is sealed by `merge`, and only a sealed archive "
                        "has something to verify against")
    state = _load_state(archive_dir, required=False)
    floor, prepared = ((None, None) if not deep
                       else _audit_records(archive_dir, manifest, CAT_ORDER))
    verify_sealed(
        archive_dir, manifest, FORMAT_TAG, ScanError,
        fp_order=CAT_ORDER,
        coverage_from_data=(None if floor is None
                            else lambda: ("floor", floor)),
        trust_hint="--deep",
        ladder_hint=" (rebuildable: re-run merge after deleting it)",
        ladders=ARCHIVE_LADDERS,
        # With --deep the record pass has just streamed every byte, so
        # the digests and ladders it produced stand in for a second
        # read of tens of GB. Without it, nothing is prepared and the
        # audit reads the files itself, exactly as before.
        prepared=prepared)

    proof = _load_proof(archive_dir)
    if proof is None:
        print(f"..  no proof beside this archive ({PROOF_DIR}/): it answers "
              "up to its watermark, and it cannot grow")
    else:
        if proof["identity"]["coverage"] != manifest["identity"]["coverage"]:
            raise ScanError(
                f"the proof covers {proof['identity']['coverage']} and the "
                f"archive {manifest['identity']['coverage']}: a proof is "
                "sealed with its archive, at the same height")
        paired = (proof["build"]["parent"]["fingerprint"]
                  == manifest["fingerprint"]
                  and manifest["build"]["proof"]["fingerprint"]
                  == proof["fingerprint"])
        if not paired and state and _in_fusion_window(state, manifest):
            raise ScanError(
                "a fusion was interrupted between the archive's manifest "
                "and the proof's: run `merge` to finish it, then verify")
        pfloor, pprepared = ((None, None) if not deep else
                             _audit_records(_proof_dir(archive_dir), proof,
                                            PROOF_ORDER))
        verify_sealed(
            _proof_dir(archive_dir), proof, PROOF_TAG, ScanError,
            fp_order=PROOF_ORDER,
            coverage_from_data=(None if pfloor is None
                                else lambda: ("floor", pfloor)),
            trust_hint="--deep",
            ladder_hint=" (rebuildable: re-run merge after deleting it)",
            ladders=PROOF_LADDERS, parent_confirmed=paired,
            prepared=pprepared)
        if deep:
            _audit_proof(archive_dir, manifest, proof)

    # The fingerprint above covers the merged base. Runs written since
    # are part of every answer the archive gives and part of no
    # fingerprint at all, so a report that ended here would let a
    # queryable archive pass for a sealed one.
    if state and state["runs"]:
        covered = manifest["identity"]["coverage"]["to"]
        print(f"..  NOT SEALED at its watermark: {len(state['runs'])} run"
              f"{'s' if len(state['runs']) > 1 else ''} hold revelations "
              f"from heights {covered + 1:,}..{state['last_height']:,}, "
              f"which no fingerprint covers yet. Run `merge` to fuse them.")


# ---------------------------------------------------------------------------
# The archive as its readers see it
# ---------------------------------------------------------------------------

def _merged_sighting(directory, manifest, cat, key, reader):
    """(byte, first_height) for `key` in the merged file of `cat`, or
    None. Uses the resident-ladder `reader` (one bucket read) when there
    is one, else a blind on-disk bisect. Both roads return the same
    record: the ladder only decides WHERE to read."""
    if reader is None:
        path = os.path.join(directory, _cat_file(manifest, cat))
        return _bisect_file(path, cat, key)
    width = CATEGORIES[cat]
    for rec in reader.scan(key):      # merged keys are unique: 0 or 1 match
        return rec[width], int.from_bytes(rec[width + 1:], "big")
    return None


def _open_merged(directory, manifest, cat):
    """Open the merged file of `cat` as a ladder-backed SortedFile, the
    ladder loaded and verified ONCE. Returns None when the manifest has no
    ladder for the category; the caller then falls back to the blind
    on-disk bisect. The reader is reusable across many keys, so a batch
    lookup pays the ladder load and its sha check a single time, like the
    outpoint index does."""
    cache = manifest["build"]["caches"].get(cat)
    if cache is None:
        return None
    return SortedFile.open(directory, manifest["build"]["files"][cat],
                           cache, LADDERS[cat], error=ScanError)


def _bisect_file(path, cat, key):
    """Binary search for `key` in a sorted fixed-width record file,
    without loading it: seek arithmetic on record boundaries. Returns
    (byte, first_height), or None. This is what makes the archive usable
    as an index: one lookup costs ~35 seeks even on a 60 GB file."""
    width = CATEGORIES[cat]
    rec = rec_width(cat)
    size = os.path.getsize(path)
    if size % rec:
        raise ScanError(f"{path}: size {size} not a multiple of {rec}")
    with open(path, "rb") as f:
        lo, hi = 0, size // rec
        while lo < hi:
            mid = (lo + hi) // 2
            f.seek(mid * rec)
            row = f.read(rec)
            if row[:width] < key:
                lo = mid + 1
            elif row[:width] > key:
                hi = mid
            else:
                return row[width], int.from_bytes(row[width + 1:], "big")
    return None


def _either(cat, a, b):
    """Two (byte, first_height) sightings of one digest, either absent,
    reduced to one."""
    if a is None:
        return b
    if b is None:
        return a
    return _reduce(cat, a[0], a[1], b[0], b[1])


class ArchiveView:
    """The archive every reader asks, in one place: the sealed generation,
    the runs written since, and the proof applied to the candidates among
    them. Built from what is on disk: the state when there is one, the
    manifest alone when the archive arrived without it (see
    `_state_from_seal`).

    A reader of `scripts20`/`scripts32` with runs pending needs the proof:
    a candidate in a run is a script only if a program opens it, and a
    program in a run can promote a candidate the proof's pile has held
    for years. Asking for a script partition then checks the proof
    exactly as a fusion would, and refuses when it cannot apply it.
    Everything else reads without it.
    """

    def __init__(self, archive_dir):
        self.dir = archive_dir
        self.manifest = _load_manifest(archive_dir)
        state = _load_state(archive_dir, required=False)
        if state is None:
            if self.manifest is None:
                raise ScanError(f"no {STATE_NAME} and no {MANIFEST_NAME} in "
                                f"{archive_dir}: run `scan` first")
            state = _state_from_seal(self.manifest)
        self.state = state
        self.runs = state["runs"]
        self.watermark = state["last_height"]
        self.last_block_hash = state["last_block_hash"]
        self.proof = _load_proof(archive_dir)
        self.proof_dir = _proof_dir(archive_dir)
        self._readers = {}
        self._proof_checked = False

    @property
    def sealed(self):
        """True when one fingerprint covers every answer: nothing pending,
        and the watermark the answers reach is the one the seal names. A
        scan over blocks that revealed nothing and created no program
        moves the watermark and writes no run; its answers are right up to
        the new height, and the fingerprint still speaks for the old one."""
        return (self.manifest is not None and not self.runs
                and self.watermark
                == self.manifest["identity"]["coverage"]["to"])

    def coverage_to(self):
        """The last height the archive speaks for, as the readers here
        walk it: the sealed generation AND the pending runs, which is the
        state's watermark whenever runs are pending. The manifest's
        coverage is the authority only for what the manifest seals; a
        curve computed over the runs too and labelled with the
        manifest's height folded every revelation past that height into
        its last row."""
        if self.runs or self.manifest is None:
            return self.watermark
        return self.manifest["identity"]["coverage"]["to"]

    def close(self):
        for reader in self._readers.values():
            if reader is not None:
                reader.close()
        self._readers = {}

    # -- where each category lives --------------------------------------

    def _sealed(self, cat):
        """[(path, sha)] of the sealed file holding `cat`, or []."""
        if cat in PROOF_ORDER:
            m, d = self.proof, self.proof_dir
        else:
            m, d = self.manifest, self.dir
        if m is None:
            return []
        return [(os.path.join(d, _cat_file(m, cat)), _cat_sha(m, cat))]

    def _runs(self, cat):
        return [(_run_path(self.dir, run["name"]), run["sha256"])
                for run in self.runs if run["category"] == cat]

    def _pending_proof(self, cat):
        """True when the proof must be applied to answer `cat`: a script
        partition with candidates or programs still in runs."""
        if cat not in PROVED_BY:
            return False
        prog_cat, _pile = PROVED_BY[cat]
        if not (self._runs(cat) or self._runs(prog_cat)):
            return False
        if not self._proof_checked:
            _check_proof(self.state, self.manifest, self.proof)
            self._proof_checked = True
        return True

    def _reader(self, cat):
        if cat not in self._readers:
            if cat in PROOF_ORDER:
                m, d = self.proof, self.proof_dir
            else:
                m, d = self.manifest, self.dir
            self._readers[cat] = None if m is None else _open_merged(d, m,
                                                                     cat)
        return self._readers[cat]

    # -- streams ----------------------------------------------------------

    def raw(self, cat):
        """Every record of `cat` the archive answers from, as whole
        records, deduplicated and in digest order."""
        rec = rec_width(cat)

        def opened(todo, slab):
            return [read_fixed(path, rec, expect_sha=sha, slab_bytes=slab,
                               error=ScanError) for path, sha in todo]

        base = self._sealed(cat)
        if not self._pending_proof(cat):
            todo = base + self._runs(cat)
            return _reduced(heapq.merge(*opened(todo, budgeted_slab(
                len(todo)))), cat)
        prog_cat, pile_cat = PROVED_BY[cat]
        candidates = self._sealed(pile_cat) + self._runs(cat)
        programs = self._sealed(prog_cat) + self._runs(prog_cat)
        slab = budgeted_slab(len(base) + len(candidates) + len(programs))
        pending = _proven(
            _reduced(heapq.merge(*opened(candidates, slab)), cat),
            _reduced(heapq.merge(*opened(programs, slab)), prog_cat),
            CATEGORIES[cat])
        return _reduced(heapq.merge(*opened(base, slab), pending), cat)

    def stream(self, cat):
        """`raw`, split into (digest, byte, first_height)."""
        width = CATEGORIES[cat]
        for r in self.raw(cat):
            yield r[:width], r[width], int.from_bytes(r[width + 1:], "big")

    # -- one digest -------------------------------------------------------

    def _run_sighting(self, cat, key):
        hit = None
        for path, _sha in self._runs(cat):
            hit = _either(cat, hit, _bisect_file(path, cat, key))
        return hit

    def sighting(self, cat, key):
        """(byte, first_height) for one digest of `cat`, reduced across
        the sealed generation and the runs, with the proof applied; or
        None when the archive never saw it (up to its watermark)."""
        hit = None
        if self.manifest is not None:
            hit = _merged_sighting(self.dir, self.manifest, cat, key,
                                   self._reader(cat))
        if not self._pending_proof(cat):
            return _either(cat, hit, self._run_sighting(cat, key))
        prog_cat, pile_cat = PROVED_BY[cat]
        pending = self._run_sighting(cat, key)
        if self.proof is not None:
            pending = _either(cat, pending, _merged_sighting(
                self.proof_dir, self.proof, pile_cat, key,
                self._reader(pile_cat)))
        if pending is not None:
            program = self._run_sighting(prog_cat, key)
            if program is None and self.proof is not None:
                program = _merged_sighting(self.proof_dir, self.proof,
                                           prog_cat, key,
                                           self._reader(prog_cat))
            if program is None:
                pending = None
        return _either(cat, hit, pending)


# ---------------------------------------------------------------------------
# Applying the perimeter at read time (shared by crosscheck and derive)
# ---------------------------------------------------------------------------

def _apply_revelation(locks, cat, h, fl, faces, cosigners, height=None):
    """Burn into the lock sets what one archived record implies under
    the chosen perimeter, and say whether the record made the cut.

    `height` is the record's `first_height`, passed through to the
    LockSets only when a caller has asked them to remember it (see
    `LockSet.track_burn_heights`). The rules are `sightings.burns_for`,
    the one map both roads apply; burning is idempotent, so applying
    the same record twice cannot inflate anything.
    """
    burns = burns_for(cat, h, fl, faces, cosigners)
    for t, lock in burns:
        locks[t].burn(lock, height)
    return bool(burns)


def _load_locksets(locks_dir):
    """The four LockSets, verified against the locks manifest.

    Returns (locks, manifest). The verification is what keeps the
    cross-check honest: both roads burn the same locks files, so a
    corrupt file unchecked here would make the two fingerprints agree
    on garbage.
    """
    manifest = _load_locks_manifest(locks_dir)
    locks = {}
    for t in TYPE_ORDER:
        entry = locks_types(manifest)[t]
        locks[t] = LockSet(os.path.join(locks_dir, _lock_file(t)),
                           LOCK_TYPES[t],
                           expect_records=entry["records"],
                           expect_sha=entry["sha256"])
    return locks, manifest


def _print_lock_table(locks, faces, cosigners, fp):
    print(f"{'type':<8} {'locks':>13} {'burnt':>12} {'burnt BTC':>20}")
    for t in TYPE_ORDER:
        ls = locks[t]
        print(f"{t:<8} {ls.count:>13,} {ls.hit_count:>12,} "
              f"{ls.hit_sats / SAT:>20,.8f}")
    total = sum(locks[t].hit_sats for t in TYPE_ORDER)
    print(f"{'TOTAL':<8} {'':>13} "
          f"{sum(locks[t].hit_count for t in TYPE_ORDER):>12,} "
          f"{total / SAT:>20,.8f}")
    print(f"perimeter: faces={'on' if faces else 'off'}, "
          f"cosigners={'on' if cosigners else 'off'}")
    print(f"fingerprint: {fp}")


def _burn_archive(view, locks, faces, cosigners):
    """Every record of the archive through the perimeter map. Returns the
    number of `keys` records that made the cut."""
    keys_seen = 0
    for cat in CAT_ORDER:
        for h, fl, ht in view.stream(cat):
            if (_apply_revelation(locks, cat, h, fl, faces, cosigners, ht)
                    and cat == "keys"):
                keys_seen += 1
    return keys_seen


# ---------------------------------------------------------------------------
# crosscheck — the cross-check
# ---------------------------------------------------------------------------

def _base_note(locks_manifest, height):
    """Where the snapshot's block stands against a height: one phrase,
    the same in the scan's summary, in `derive` and in the cross-check."""
    base_h = locks_height(locks_manifest)
    if height == base_h:
        return f"aligned with height {height:,}"
    if height < base_h:
        return (f"{base_h - height:,} block(s) short of the snapshot's "
                f"height {base_h:,}: the figure is a floor for that moment")
    return (f"{height - base_h:,} block(s) past the snapshot's height "
            f"{base_h:,}: the figure counts spends the snapshot never saw")


def run_crosscheck(archive_dir, locks_dir, faces=True, cosigners=True,
                   reuse_state_path=None, curve_path=None):
    """Derive the burnt-locks bitmaps from the archive and compare
    them with reuse_scan's.

    The perimeter is applied HERE, at read time, from the provenance
    bits — the archive itself has no perimeter; the mapping is
    _apply_revelation, shared with `derive` so the two read-side
    views cannot drift apart.

    The fingerprint printed is byte-compatible with reuse_scan's
    (same identity over the same sorted lock files, the same height
    and the same perimeter), so the two roads meet on one hex string.
    With --reuse-state, the meeting is checked right here and a
    mismatch is a hard failure: a cross-check that "almost passes" does
    not exist. Five comparisons, in order, each with its own message:
    the locks, the height of the two states, the perimeter, the
    fingerprint of the bitmaps, and, with --curve, the scan's curve
    against one replayed from the archive on the same grid. The first
    three stay BEFORE the fingerprint even though the fingerprint now
    names all three: a mismatch is diagnosed by name, never as "one of
    the two pipelines is wrong".

    What "independent" covers, honestly: the two EXTRACTION pipelines
    are written twice on purpose, but both roads share the locks files,
    the LockSet lookup code, the classifier of what a key looks like
    and the read-time perimeter map. That is why the load verifies the
    files against the manifest's shas, and why --reuse-state refuses a
    checkpoint made against different locks: without those guards the
    shared input could make both roads agree on garbage. The proof is
    NOT shared: the reuse scan burns a candidate only against a lock,
    which the chain created, and the archive keeps a candidate only
    against a program the chain created: two roads to the same fact.
    """
    view = ArchiveView(archive_dir)
    locks, locks_manifest = _load_locksets(locks_dir)
    perimeter = _perimeter(faces, cosigners)
    height = view.watermark
    if curve_path:
        for t in TYPE_ORDER:
            locks[t].track_burn_heights()

    try:
        keys_seen = _burn_archive(view, locks, faces, cosigners)
    finally:
        view.close()

    fp = _fingerprint(locks, locks_manifest["fingerprint"], height, perimeter)
    print(f"=== Cross-check from archive (heights 1..{height:,}"
          f", {keys_seen:,} keys in perimeter) ===")
    print(f"    locks {locks_manifest['fingerprint']}")
    print(f"    snapshot block: {_base_note(locks_manifest, height)}")
    _print_lock_table(locks, faces, cosigners, fp)

    if reuse_state_path:
        reuse_state = read_json(reuse_state_path, ScanError)
        if reuse_state.get("format") != REUSE_STATE_TAG:
            raise ScanError(
                f"the scan's state says {reuse_state.get('format')!r}, "
                f"this build compares against {REUSE_STATE_TAG!r}")
        if reuse_state["locks"] != locks_manifest["fingerprint"]:
            raise ScanError(
                "the scan's checkpoint was made against DIFFERENT locks "
                f"(fingerprint {reuse_state['locks'][:16]}… against "
                f"{locks_manifest['fingerprint'][:16]}…): the two roads "
                "must burn the same locks to be comparable")
        if reuse_state["last_height"] != height:
            raise ScanError(
                f"heights differ: archive at {height:,}, reuse scan at "
                f"{reuse_state['last_height']:,} — the two roads must be "
                "compared at the SAME height")
        # The scan records the perimeter its bitmaps were burnt under;
        # this read applies its own flags. Two perimeters give two
        # fingerprints for one correct pair, and "one of the two
        # pipelines is wrong" would be a false diagnosis.
        was = reuse_state["perimeter"]
        if was != perimeter:
            raise ScanError(
                f"the scan's checkpoint was made with faces="
                f"{'on' if was['faces'] else 'off'}, cosigners="
                f"{'on' if was['cosigners'] else 'off'}, but this "
                f"cross-check reads with faces={'on' if faces else 'off'}, "
                f"cosigners={'on' if cosigners else 'off'}: the two "
                "readings burn different locks, so their fingerprints "
                "cannot meet — run the cross-check with the scan's flags")
        if reuse_state["fingerprint"] != fp:
            raise ScanError(
                "CHECK FAILED: the archive-derived bitmaps do "
                f"not match the scan's\n  scan:    "
                f"{reuse_state['fingerprint']}\n  archive: {fp}\n"
                "one of the two pipelines is wrong — do not publish "
                "either number")
        print("CHECK PASSED: the two independent roads meet "
              "on the same fingerprint.")
    if curve_path:
        _crosscheck_curve(locks, locks_manifest, perimeter, height,
                          curve_path)
    return fp


def _crosscheck_curve(locks, locks_manifest, perimeter, height, curve_path):
    """The scan's curve against one replayed from the archive on the
    grid its sidecar declares: the same CSV bytes, hence the same
    sidecar fingerprint. The sidecar is verified first, so a curve that
    changed beside its meta is named as such and not as a road that
    disagrees."""
    meta = cv.verify(curve_path, cv.REUSE_TAG)
    if meta["build"]["locks"] != locks_manifest["fingerprint"]:
        raise ScanError("the curve was burnt against DIFFERENT locks: "
                        "not comparable")
    if meta["build"]["perimeter"] != perimeter:
        raise ScanError("the curve was burnt under another perimeter: run "
                        "the cross-check with the scan's flags")
    if meta["identity"]["coverage"]["to"] != height:
        raise ScanError(
            f"the curve stops at {meta['identity']['coverage']['to']:,} and "
            f"the archive at {height:,}: not comparable")
    replay = curve_path + ".crosscheck"
    try:
        sha, _rows = _write_curve(locks, replay, meta["build"]["grid"],
                                  height, locks_manifest["fingerprint"],
                                  perimeter)
    finally:
        if os.path.exists(replay):
            os.remove(replay)
    if sha != meta["identity"]["files"][0]["sha256"]:
        raise ScanError(
            "CHECK FAILED: the curve replayed from the archive differs "
            "from the scan's — do not publish either curve")
    print(f"CHECK PASSED: the curve too ({meta['build']['rows']} rows on the "
          f"{meta['build']['grid']:,} grid, meta {meta['fingerprint'][:16]}…).")


# ---------------------------------------------------------------------------
# derive — the reuse count and curve as a READ of the archive
# ---------------------------------------------------------------------------

def _write_curve(locks, curve_path, every, coverage_to, locks_fp, perimeter):
    """Replay the burns in height order and write one row per grid
    point: cumulative counts, satoshis, and the fingerprint the burnt
    set had exactly there. Returns (sha256 of the file, rows).

    Replayed on fresh bitmaps rather than sampled during the read: the
    archive arrives in digest order, so at no moment during the pass do
    the LockSets hold the state of any particular height. Cost is small
    and bounded by the BURNT locks, not by the records: a few million
    entries sorted once, and a bitmap rehashed per row. The text of a
    row and the grid are `curve`'s, shared with the scan, which is what
    lets the two roads meet byte for byte on the file.
    """
    events = {}
    for t in TYPE_ORDER:
        ls = locks[t]
        if ls.burn_height is None:
            raise ScanError("curve asked for without tracking the heights "
                            "(track_burn_heights was not called)")
        # height in the high bits, lock index in the low ones: one
        # sort over a plain integer array puts the burns in chain
        # order without materialising a tuple per lock.
        packed = array("Q", (h << 32 | i
                             for i, h in enumerate(ls.burn_height)
                             if h != 0xFFFFFFFF))
        packed = array("Q", sorted(packed))
        events[t] = packed

    bitmaps = {t: bytearray(len(locks[t].hits)) for t in TYPE_ORDER}
    counts = {t: 0 for t in TYPE_ORDER}
    sats = {t: 0 for t in TYPE_ORDER}
    pos = {t: 0 for t in TYPE_ORDER}

    def rows():
        for point in cv.grid(every, coverage_to):
            for t in TYPE_ORDER:
                ev, p = events[t], pos[t]
                while p < len(ev) and (ev[p] >> 32) <= point:
                    i = ev[p] & 0xFFFFFFFF
                    bitmaps[t][i >> 3] |= 1 << (i & 7)
                    counts[t] += 1
                    sats[t] += locks[t].sats[i]
                    p += 1
                pos[t] = p
            yield cv.reuse_row(
                point, {t: {"hits": counts[t], "satoshis": sats[t]}
                        for t in TYPE_ORDER},
                fingerprint_of_bitmaps(bitmaps, locks_fp, point, perimeter),
                TYPE_ORDER)

    n = len(cv.grid(every, coverage_to))
    sha = cv.write(curve_path, cv.reuse_header(TYPE_ORDER), rows())
    print(f"curve: {n} rows on the {every:,} grid → {curve_path}",
          file=sys.stderr)
    return sha, n


def _archive_parent(manifest):
    """The archive as a declared parent, when it is sealed; None for a
    live archive, which has no fingerprint yet."""
    if manifest is None:
        return None
    return declared_parent(manifest["format"], manifest["fingerprint"],
                           manifest["identity"]["coverage"])


ARCHIVE_CURVE_COLUMNS = ("points", "scripts20", "scripts32")


def run_archive_curve(archive_dir, out_path, every=10_000):
    """When the chain first revealed each thing, by window of heights.

    The archive's own curve, and the one artefact here that needs
    NOTHING else: no locks, no UTXO snapshot, no node. That is the
    reason it is its own verb rather than a column on `derive` — the
    reuse curve has to join a lock set that comes from a snapshot, and
    hanging this on the same command would make "how much was revealed,
    and when" depend on a snapshot it has no use for.

    It has no perimeter either, for the same reason the archive has
    none: the perimeter is a reading of the provenance bits, and this
    counts records, not readings.

    One row per window: the digests whose FIRST revelation falls in
    `height - every + 1 .. height`. First, not every sighting: a digest
    seen again at a later height was already revealed, and the fused
    archive keeps the earliest height precisely so this question has an
    exact answer. The stream is deduplicated and proven, so the count is
    the same whether the archive has been merged or is still in runs.

    The `points` column counts KEYS records without the UNCOMPRESSED
    bit: a point seen at 65 bytes holds two records (the form seen and
    its compressed face under OTHER_FACE), and every point has exactly
    one canonical record, whose first height is the minimum over every
    form seen. So the column counts points, and says so. The script
    columns count the scripts the chain proved, by the archive's proof.
    """
    view = ArchiveView(archive_dir)
    coverage_to = view.coverage_to()
    points = cv.grid(every, coverage_to)
    last = len(points) - 1
    counts = {cat: [0] * len(points) for cat in CAT_ORDER}

    try:
        for cat in CAT_ORDER:
            col = counts[cat]
            for _h, fl, ht in view.stream(cat):
                if cat == "keys" and fl & FLAG_UNCOMPRESSED:
                    continue
                # The grid is regular, so the window is arithmetic rather
                # than a search: this runs once per record.
                i = (ht - 1) // every
                col[i if i < last else last] += 1
    finally:
        view.close()

    def rows():
        for n, point in enumerate(points):
            row = [counts[cat][n] for cat in CAT_ORDER]
            yield (f"{point}," + ",".join(str(v) for v in row)
                   + f",{sum(row)}\n")

    header = "height," + ",".join(ARCHIVE_CURVE_COLUMNS) + ",total\n"
    sha = cv.write(out_path, header, rows())
    total = sum(sum(counts[cat]) for cat in CAT_ORDER)
    cv.seal(out_path, cv.ARCHIVE_TAG, coverage_to, {
        "road": "archive",
        "parent": _archive_parent(view.manifest),
        "grid": every,
        "rows": len(points),
        "columns": ("height",) + ARCHIVE_CURVE_COLUMNS + ("total",),
        "reconstruction": (
            "one row per window of `grid` heights ending at the row's "
            "height (the last row ends at the coverage): per category, the "
            "records whose first_height falls in the window; keys records "
            "carrying UNCOMPRESSED are not counted, so `points` counts "
            "points and not serializations"),
    }, sha=sha)
    print(f"archive curve: {len(points)} windows of {every:,} blocks "
          f"through height {coverage_to:,}, {total:,} first revelations "
          f"→ {out_path}", file=sys.stderr)
    return total


def run_derive(archive_dir, locks_dir, faces=True, cosigners=True,
               curve_path=None, curve_every=10_000,
               allow_base_mismatch=False, checkpoint_dir=None):
    """Derive from the archive everything the reuse scan measures:
    the final table AND the per-checkpoint curve, with a fingerprint
    per row; and, with `checkpoint_dir`, the bitmaps and the state the
    scan would have written, so `reuse stats` reads this road too.

    This is the read side of the single-pass pipeline: one scan
    archives the revelations (and can co-emit the graph); the reuse
    numbers are then a READ of the archive against any snapshot's
    locks — no second pass over the chain.

    The curve comes from the `first_height` each record carries, which
    under the full perimeter is the height that burnt the lock. That
    makes it independent of the order the archive is read in and of
    how the scan buffered: it can be asked for on ANY grid, it reads the
    same on a fused base as on loose runs, and a third party gets the
    same rows. The rows are replayed, not sampled: the burns are
    collected with their heights, sorted, and the bitmap is rebuilt
    point by point, so each row's fingerprint is the one the state
    genuinely had at that height.

    Same LockSet, same burn rules (_apply_revelation, shared with the
    cross-check), same fingerprint definition: on the same inputs the
    two roads cannot disagree by construction of this function — the
    cross-check stays `crosscheck --reuse-state`, which compares
    against an INDEPENDENT scan's state instead.
    """
    view = ArchiveView(archive_dir)
    locks, locks_manifest = _load_locksets(locks_dir)
    perimeter = _perimeter(faces, cosigners)
    # The table is defined by TWO heights: the archive's coverage and
    # the block the snapshot's locks were photographed at. The manifest
    # names that block by hash and by height, and the archive
    # records the hash at its watermark, so the two can be
    # confronted offline and exactly: same hash, same block, same
    # height. Deriving an archive against locks from another block
    # produces a table indistinguishable from a right one, which is
    # why a mismatch is a refusal and not a note.
    if curve_path and not (faces and cosigners):
        # A keys record carries ONE first_height, the minimum over every
        # sighting whatever its provenance: under a narrowed perimeter
        # the final table is right (membership follows the surviving
        # bits) but every intermediate row would date a burn by a
        # sighting the perimeter excluded. A faithful narrow curve needs
        # one height per provenance bit, which this format does not
        # carry (six bits, +15 bytes per keys record, about 25 GB at
        # chain scale, for a series no published number uses); rather
        # than print upper bounds under the name of a curve, the
        # combination is refused, and the second road writes the exact
        # narrow curve because it burns as it reads.
        raise ScanError(
            "--curve is exact only under the full perimeter: with "
            "--no-faces or --no-cosigners the archive's first_height "
            "dates a burn by sightings the perimeter excludes, and the "
            "intermediate rows would over-count — derive the table with "
            "the narrow perimeter and the curve without it")
    base_hash = locks_base_hash(locks_manifest)
    tip_hash = view.last_block_hash
    tip = view.watermark
    if base_hash == tip_hash and tip != locks_height(locks_manifest):
        raise ScanError(
            f"the locks manifest puts the snapshot's block {base_hash[:16]}… "
            f"at height {locks_height(locks_manifest):,} and the archive's "
            f"tip, which is that block, is at {tip:,}: the height given to "
            "`prepare` was wrong; rebuild the locks with --headers, or with "
            "the right --height")
    if base_hash != tip_hash and not allow_base_mismatch:
        raise ScanError(
            f"the locks were photographed at block {base_hash}, but "
            f"the archive covers through {tip_hash}: these are "
            "different moments of the chain, and the reuse table "
            "would silently mix them — pass --allow-base-mismatch "
            "only if crossing two moments is what you want")
    if curve_path:
        for t in TYPE_ORDER:
            locks[t].track_burn_heights()

    try:
        keys_seen = _burn_archive(view, locks, faces, cosigners)
    finally:
        view.close()

    coverage_to = view.coverage_to()
    locks_fp = locks_manifest["fingerprint"]
    if curve_path:
        sha, rows = _write_curve(locks, curve_path, curve_every, coverage_to,
                                 locks_fp, perimeter)
        meta = cv.seal(curve_path, cv.REUSE_TAG, coverage_to, {
            "road": "derive",
            "parent": _archive_parent(view.manifest),
            "grid": curve_every,
            "locks": locks_fp,
            "perimeter": perimeter,
            "rows": rows,
        }, sha=sha)
        print(f"curve meta: {meta['fingerprint']}", file=sys.stderr)

    fp = _fingerprint(locks, locks_fp, tip, perimeter)
    if checkpoint_dir:
        # The twin the scan writes: `reuse stats` reads it, and the
        # cross-check can compare bitmap with bitmap. The snapshot's
        # block is "seen" at its height when the archive reaches it.
        base_h = locks_height(locks_manifest)
        write_checkpoint(checkpoint_dir, locks, locks_manifest, perimeter,
                         tip, tip_hash, base_h if base_h <= tip else None,
                         {}, road="derive")
        print(f"checkpoint: bitmaps and state written to {checkpoint_dir}",
              file=sys.stderr)
    print(f"=== Derived from archive (heights 1..{tip:,}"
          f", {keys_seen:,} keys in perimeter) ===")
    print(f"    archive tip {tip_hash}")
    print(f"    locks base  {base_hash} ("
          + ("the same block" if base_hash == tip_hash
             else "A DIFFERENT BLOCK, crossed on purpose: "
             + _base_note(locks_manifest, tip)) + ")")
    print(f"    locks       {locks_fp}")
    _print_lock_table(locks, faces, cosigners, fp)
    return fp


# ---------------------------------------------------------------------------
# lookup — the seed of check_addresses
# ---------------------------------------------------------------------------

def _lookup_merged(archive_dir, manifest, cat, key):
    """Single-key convenience: open the merged reader, query it, close it.
    `ArchiveView` opens the reader once and reuses it across keys instead."""
    reader = _open_merged(archive_dir, manifest, cat)
    try:
        return _merged_sighting(archive_dir, manifest, cat, key, reader)
    finally:
        if reader is not None:
            reader.close()


def run_lookup(archive_dir, hex_digests):
    """Membership check of raw digests (hex, 20 or 32 bytes) against
    the archive. Deliberately low-level: it takes digests, not
    addresses — decoding addresses (and explaining what a hit means
    for each type) is check_addresses.py's job. Absence is reported
    for what it is: not revealed in confirmed blocks up to the
    watermark, within what a block scan can see.
    """
    view = ArchiveView(archive_dir)
    print(f"archive covers heights 1..{view.watermark:,}"
          + ("" if not view.runs else
             f" ({len(view.runs)} unfused runs included)"))

    try:
        for hx in hex_digests:
            try:
                key = bytes.fromhex(hx)
            except ValueError:
                print(f"{hx}: not hex, skipped")
                continue
            cats = [c for c in CAT_ORDER if CATEGORIES[c] == len(key)]
            if not cats:
                print(f"{hx}: not a 20- or 32-byte digest, skipped")
                continue
            found = {}
            for cat in cats:
                hit = view.sighting(cat, key)
                if hit is not None:
                    found[cat] = hit
            if not found:
                print(f"{hx}: NOT in the archive (never revealed on-chain "
                      "up to the watermark; off-chain exposure is invisible "
                      "here by declaration)")
                continue
            for cat, (fl, first_height) in sorted(found.items()):
                where = []
                if cat == "keys":
                    if fl & FLAG_SIG:
                        where.append("scriptSig")
                    if fl & FLAG_WIT:
                        where.append("witness")
                    if fl & FLAG_INNER_SIG:
                        where.append("inside a redeem script")
                    if fl & FLAG_INNER_WIT:
                        where.append("inside a witness script")
                    if fl & FLAG_OUT:
                        where.append("published in an output")
                    if fl & FLAG_OTHER_FACE:
                        where.append("seen in its other serialization")
                    if fl & FLAG_XONLY:
                        where.append("seen as a taproot internal or leaf key")
                    if fl & FLAG_UNCOMPRESSED:
                        where.append("uncompressed form")
                if cat != "keys" and fl:
                    where.append(f"{fl} key{'s' if fl > 1 else ''} inside")
                print(f"{hx}: REVEALED at height {first_height:,}, {cat}"
                      + (f" ({', '.join(where)})" if where else ""))
    finally:
        view.close()


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Archive every key/script revelation in block "
                    "history (appendable, fingerprinted) and "
                    "cross-check the reuse scan against it.")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="stream the chain into the archive")
    add_node_args(ps)
    ps.add_argument("--end", type=int, required=True,
                    help="last height to archive (the snapshot's height, "
                         "so the cross-check compares like with like)")
    ps.add_argument("--archive", required=True, help="archive directory")
    ps.add_argument("--flush-records", type=int, default=8_000_000,
                    help="buffered revelations before a run is flushed "
                         "(memory knob)")
    add_window_args(ps)
    add_coemission_args(ps, nonces=True)

    pv = sub.add_parser("verify", help="re-read a sealed archive "
                                       "against its manifest (full audit)")
    pv.add_argument("--archive", **home.required("archive"))
    pv.add_argument("--deep", action="store_true",
                    help="also read every record: order, uniqueness, the "
                         "record counts, the flag bits, and every "
                         "first-seen height inside the coverage, whose "
                         "highest value then confronts the declared "
                         "watermark as a floor; and, with the proof beside "
                         "the archive, that every script is a program and "
                         "no candidate set aside is. Costs a second read of "
                         "the archive; without it the coverage is taken "
                         "on trust and the report says so")

    pm = sub.add_parser("merge", help="fuse runs, prove the candidates, "
                                      "fingerprint the archive")
    pm.add_argument("--archive", required=True)

    pc = sub.add_parser("crosscheck",
                        help="derive the burnt locks from the archive "
                             "and compare with reuse_scan")
    pc.add_argument("--archive", **home.required("archive"))
    pc.add_argument("--locks", **home.required(
        "locks", help="directory produced by reuse_scan.py prepare"))
    pc.add_argument("--reuse-state",
                    help="reuse_scan state.json to compare against "
                         "(the cross-check proper)")
    pc.add_argument("--curve",
                    help="the scan's curve.csv (its sidecar beside it): "
                         "replayed from the archive on the same grid and "
                         "compared byte for byte")
    pc.add_argument("--no-faces", action="store_true",
                    help="narrow perimeter, must mirror the scan's flag")
    pc.add_argument("--no-cosigners", action="store_true",
                    help="narrow perimeter, must mirror the scan's flag")

    pd = sub.add_parser("derive",
                        help="derive the reuse table AND its curve from "
                             "the archive (the single-pass pipeline's "
                             "read side)")
    pd.add_argument("--archive", required=True)
    pd.add_argument("--locks", required=True,
                    help="directory produced by reuse_scan.py prepare")
    pd.add_argument("--curve",
                    help="write the reuse curve CSV here "
                         "(same columns as reuse_scan's curve.csv)")
    pd.add_argument("--curve-every", type=int, default=10_000,
                    help="height grid for curve rows")
    pd.add_argument("--allow-base-mismatch", action="store_true",
                    help="derive even when the locks' snapshot block "
                         "differs from the archive's tip: the table "
                         "then mixes two moments of the chain, which "
                         "is refused by default")
    pd.add_argument("--checkpoint",
                    help="also write the bitmaps and the state the scan "
                         "would have written here, for `reuse stats`")

    pv = sub.add_parser("curve",
                        help="when the chain first revealed each thing, "
                             "by window of heights: the archive's own "
                             "curve, no locks and no snapshot needed")
    pv.add_argument("--archive", required=True)
    pv.add_argument("--out", required=True,
                    help="write the CSV here")
    pv.add_argument("--every", type=int, default=10_000,
                    help="width of each window, in blocks")
    pd.add_argument("--no-faces", action="store_true",
                    help="narrow perimeter, as in crosscheck")
    pd.add_argument("--no-cosigners", action="store_true",
                    help="narrow perimeter, as in crosscheck")

    pl = sub.add_parser("lookup", help="membership check of hex digests")
    pl.add_argument("--archive", **home.required("archive"))
    pl.add_argument("digests", nargs="+",
                    help="hex digests, 20 bytes (hash160) or 32 (sha256)")

    args = p.parse_args(argv)
    try:
        if args.cmd == "scan":
            client, auth = build_client(args.rpc, args.rest,
                                        args.cookie_file)
            run_scan(args.rpc, auth, args.end, args.archive,
                     batch_size=args.batch,
                     checkpoint_every=args.checkpoint_every,
                     flush_records=args.flush_records,
                     client=client,
                     graph_dir=args.graph,
                     graph_digest_dir=args.graph_digest,
                     headers_dir=args.headers,
                     nonces_dir=args.nonces,
                     prefetch=not args.no_prefetch,
                     prefetch_depth=args.prefetch_depth)
        elif args.cmd == "merge":
            run_merge(args.archive)
        elif args.cmd == "verify":
            run_verify(args.archive, deep=args.deep)
        elif args.cmd == "crosscheck":
            run_crosscheck(args.archive, args.locks,
                           faces=not args.no_faces,
                           cosigners=not args.no_cosigners,
                           reuse_state_path=args.reuse_state,
                           curve_path=args.curve)
        elif args.cmd == "derive":
            run_derive(args.archive, args.locks,
                       faces=not args.no_faces,
                       cosigners=not args.no_cosigners,
                       curve_path=args.curve,
                       curve_every=args.curve_every,
                       allow_base_mismatch=args.allow_base_mismatch,
                       checkpoint_dir=args.checkpoint)
        elif args.cmd == "curve":
            run_archive_curve(args.archive, args.out, every=args.every)
        else:
            run_lookup(args.archive, args.digests)
    except (ScanError, ParseError, graphemit.GraphError,
            headers.HeaderError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
