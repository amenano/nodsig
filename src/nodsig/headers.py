#!/usr/bin/env python3
"""
headers.py — co-emit the HEADER CHAIN while a scan is already streaming
the blocks, and read it back offline.

Why this exists: a scan verifies four things about every block it
touches — the bytes hash to the block id it asked for, that id links to
the previous block, the Merkle root commits to the transactions it
parsed, and the coinbase's witness commitment covers the witness bytes.
All four happen in memory and then evaporate: what the graph keeps is
who pays whom, and no artifact of this toolkit keeps the 80 bytes that
the checks were about. So the checks can never be REPEATED. Anyone
holding the artifacts — us included, a year later — can re-derive the
numbers but not re-derive the certainty, and the only way back to it is
another multi-day pass over the chain.

Eighty-eight bytes per height fixes that, and the whole chain fits in
under 150 MB: a rounding error next to the graph's 300+ GB, emitted by
the same pass that was happening anyway. Three of the four checks become
repeatable from local files (see below); the fourth cannot be, and the
reason is stated rather than glossed over.

It also takes the node out of a question that had no business needing
one. `curve dates` used to ask bitcoind for the timestamp of every
checkpoint height, because heights are what the scanner knows and dates
are what a figure caption needs. The timestamp is IN the header, and the
median-time-past is a median over eleven of them, so with this archive
both are a local read.

WHAT IT HOLDS, AND WHY EXACTLY THIS
===================================
Per height, ascending, GENESIS INCLUDED AT INDEX 0 — the one artifact
here that starts at 0, because a chain of headers that begins at 1 has
nothing to link its first record to, and the link is the point:

    headers.bin       88 B/height: the 80 header bytes VERBATIM,
                      then size u32, then weight u32
    coinbase.bin      the coinbase scriptSig of each block, verbatim,
                      concatenated
    coinbase_off.bin  5 B/height: the offset in coinbase.bin where this
                      height's scriptSig starts

The 80 bytes are quoted, not re-encoded: sha256d of exactly those bytes
IS the block id, so a re-serialization that differed in any bit would
break the one property that makes the file self-certifying. The emitter
rebuilds them from the parsed header and refuses to write unless they
hash back to the id the scan verified — a serializer checked against
the chain rather than against a test.

`size` and `weight` are the two figures a header does not carry and
nothing else here keeps: the graph records what a block MOVED, never
what it COST. Together they are the block-space series (how full blocks
have been since the weight limit replaced the size limit) at 8 bytes a
block, and they are by-products of a parse that already walked every
byte, so measuring them costs nothing.

The coinbase scriptSig is the one piece of every block that no other
artifact of this toolkit keeps and no derivation can bring back. The
graph excludes every scriptSig by design (they are unlocking data, and
for a coinbase they unlock nothing), the reveal archive finds no key in
it, and yet it carries the BIP34 height the block claims for itself, the
extranonce, and whatever the miner chose to write — the genesis
headline, the tags that make a mining-pool census possible. About 50
bytes a block on average. NOT the whole coinbase transaction: its
outputs are already tiles in the graph, and storing them again would
quadruple this archive to re-state what we have.

Offsets, not lengths, and the length of height h is the offset of h+1
minus its own — the positional idiom `tx_first_out.bin` already uses in
the index. It works for the same reason: every coinbase scriptSig is at
least two bytes by consensus, so the offsets strictly increase and the
last one's length falls out of the file size.

WHAT BECOMES REPEATABLE OFFLINE (AND WHAT DOES NOT)
===================================================
    1. every block id     `verify` — sha256d over the 80 bytes
    2. every prev link    `verify` — each record's prev_hash must be the
                          id of the record before it. Together with 1
                          this is the chain certifying itself, from
                          genesis, with no node and no network
    3. every Merkle root  `crosscheck --index` — the index holds the
                          txids of every block in block order, so the
                          root can be recomputed and confronted with the
                          header. This is also the strongest binding
                          between the two artifacts there is: it proves
                          the index's transactions ARE the ones the
                          chain committed to, not merely a list some
                          build produced
    4. the witness commitment CANNOT be repeated, ever, from anything we
       keep. It commits to the wtxids, which hash the witness bytes, and
       the witness is deliberately not archived (it is signatures; what
       matters in it — the revealed keys — is what the reveal archive
       distills). Verifying it requires the raw blocks, which is another
       full pass. Said here so that "three of four" is never read as
       four

Proof of work is not checked either, and that is a different kind of
absence: it would be easy (the id must be under the target `bits`
encodes) but it would be a consensus opinion, and this toolkit takes its
chain from a node it is run beside. What the archive attests is that
these headers are a chain and that they are the ones the scan saw.

THE FORMAT — headers-v2
=======================
A directory of three files, a `state.json` while it grows, a
`manifest.json` once sealed: the shape of every artifact here (see
`docs/contracts/Artifact.md` and `docs/formats/Headers-v2.md`). The
identity covers the three digests plus the coverage; the coverage is
`exact` for this format, because one record per height means the file's
own length states the watermark and `verify` refuses a manifest that
claims another.

Byte order, once: the 80 header bytes keep the chain's own (they are
quoted). Every field nodsig itself writes — size, weight, offset — is
BIG-endian, the convention of the sibling positional files, so that
"read a nodsig field" is one rule across the index and this.

Subcommands:
    fingerprint   seal: re-read everything, audit the chain, write the
                  manifest and the canonical fingerprint
    verify        the audit of a sealed archive: digests, coverage, and
                  the chain of links rebuilt from the bytes
    crosscheck    confront the Merkle roots with an outpoint index
    stats         watermark and totals, from the state alone
    show          decode a height range for a human

Standard library only. The emitter never talks to the network: blocks
arrive already fetched and integrity-checked by the host scanner.
"""

import argparse
import hashlib
import json
import os
import sys

from nodsig import blockparse
from nodsig.artifact import (WallClock, identity_fingerprint,
                             make_identity, producer, seal_manifest,
                             verify_sealed)
from nodsig.hashing import sha256d
from nodsig.recio import atomic_json, read_fixed, read_slabs, sha_file

STATE_NAME = "state.json"
MANIFEST_NAME = "manifest.json"
FORMAT_TAG = "headers-v2"

HDR_LEN = 80                     # the header itself, verbatim
HDR_REC = HDR_LEN + 4 + 4        # + size u32be + weight u32be
OFF_REC = 5                      # u40be, the ordinal width of the index

# Logical name → file name. The order is the identity's order.
FILES = (("headers", "headers.bin"),
         ("coinbase", "coinbase.bin"),
         ("coinbase_off", "coinbase_off.bin"))

# Fixed-width files only: coinbase.bin holds variable-length records and
# is addressed through coinbase_off.bin, never counted.
WIDTHS = {"headers": HDR_REC, "coinbase_off": OFF_REC}

GENESIS = 0                      # where a header archive always starts

# BIP34 made the coinbase scriptSig begin with a push of the block's own
# height. Before it, miners put arbitrary bytes there — which is why a
# disagreement is COUNTED and reported rather than raised: on the early
# chain an arbitrary scriptSig can decode as a plausible push of the
# wrong number, and refusing the archive over it would be a false alarm.
# Above the activation the declarations are continuous, and a real
# mismatch there would say the file's positions have slipped.


class HeaderError(RuntimeError):
    """Corruption, a mismatch, or an archive that cannot line up with
    the scan that wants to grow it. As everywhere here: it stops the
    run rather than leaking into something that could be published."""


# ---------------------------------------------------------------------------
# One record
# ---------------------------------------------------------------------------

def serialize_header(header):
    """The 80 bytes of a parsed header, as the chain wrote them.

    Deliberately dumb, field for field, in the fixed layout — and every
    caller checks the result by hashing it: sha256d of these bytes must
    be the id the parser recomputed. A serializer whose output is
    verified against the chain's own name for the block cannot silently
    drift, which is why this can be trusted to stand in for bytes the
    emitter no longer has.
    """
    return (header.version.to_bytes(4, "little")
            + header.prev_hash
            + header.merkle_root
            + header.time.to_bytes(4, "little")
            + header.bits.to_bytes(4, "little")
            + header.nonce.to_bytes(4, "little"))


def block_record(block):
    """One parsed block → its 88-byte headers-v2 record."""
    raw = serialize_header(block.header)
    if sha256d(raw) != block.header.hash:
        raise HeaderError(
            "the re-serialized header does not hash to the block id the "
            "parser recomputed: refusing to archive bytes that are not "
            "the ones the chain committed to")
    return raw + block.size.to_bytes(4, "big") + block.weight.to_bytes(4, "big")


def decode_record(rec):
    """One 88-byte record → a plain dict, the reading twin of
    `block_record`. The block id is recomputed here too: a reader is
    never handed an id it did not derive itself."""
    if len(rec) != HDR_REC:
        raise HeaderError(f"a headers record is {HDR_REC} bytes, got "
                          f"{len(rec)}")
    raw = rec[:HDR_LEN]
    header, _ = blockparse.parse_header(raw)
    return {"hash": header.hash, "prev_hash": header.prev_hash,
            "merkle_root": header.merkle_root, "version": header.version,
            "time": header.time, "bits": header.bits, "nonce": header.nonce,
            "size": int.from_bytes(rec[HDR_LEN:HDR_LEN + 4], "big"),
            "weight": int.from_bytes(rec[HDR_LEN + 4:], "big"),
            "raw": bytes(raw)}


def coinbase_script(block):
    """The coinbase input's scriptSig. The coinbase is the first
    transaction by consensus, and `is_coinbase` confirms it rather than
    assuming it: an archive that silently stored the wrong script would
    be worse than one that stops."""
    if not block.transactions:
        raise HeaderError("a block carries at least the coinbase")
    tx = block.transactions[0]
    if not blockparse.is_coinbase(tx):
        raise HeaderError("the first transaction of this block is not a "
                          "coinbase: refusing to guess which one is")
    return tx.inputs[0].script_sig


def bip34_height(script):
    """The height a coinbase scriptSig claims for its block (BIP 34), or
    None when its first item is not a plausible height push.

    The encoding is a minimally-encoded signed little-endian push of at
    most 4 bytes, which is exactly what the chain uses; anything else is
    reported as "no declaration" rather than as a wrong one.
    """
    if not script:
        return None
    n = script[0]
    if not 1 <= n <= 4 or len(script) < 1 + n:
        return None
    payload = script[1:1 + n]
    if payload[-1] & 0x80:              # negative in this encoding
        return None
    if n > 1 and payload[-1] == 0:      # not minimally encoded
        return None
    return int.from_bytes(payload, "little")


# ---------------------------------------------------------------------------
# The emitter: the plug a scanner hosts
# ---------------------------------------------------------------------------

def _path(headers_dir, name):
    return os.path.join(headers_dir, dict(FILES)[name])


class HeaderEmitter:
    """Grows a header archive alongside a host scan.

    The contract with the host is the graph emitter's, with one
    addition — the archive says where the feeding must START:

        emitter = HeaderEmitter(headers_dir)
        first = emitter.load(start_height)   # 0 on a fresh archive
        emitter.add_block(h, block)          # every verified block
        emitter.checkpoint(h, hash_hex)      # at the host's checkpoint,
                                             # just BEFORE the host's own
                                             # state is written

    Why it may ask for a height the host did not intend to fetch: a
    header chain that does not reach genesis cannot check its own first
    link, so a fresh archive returns 0 and the host prepends that one
    block. Genesis carries nothing else any artifact here wants (its
    coinbase is unspendable by consensus and spends nothing), so the
    host feeds it to this emitter and skips it everywhere else.

    Crash safety is the positional idiom of the index rather than the
    graph's runs: the three files only ever grow, the state records the
    COMMITTED size of each, and `load` cuts back to those sizes. Bytes
    past them belong to a checkpoint that never happened, and the host
    re-feeds those blocks anyway. Checkpointing before the host writes
    its own state leaves the archive AHEAD after a crash, which is the
    direction that heals; the other one would be a hole.
    """

    def __init__(self, headers_dir, flush_bytes=8 * 2**20):
        self.dir = headers_dir
        self.flush_bytes = flush_bytes
        self.from_height = GENESIS
        self.watermark = None        # last height committed OR buffered
        self.last_hash = None
        self.last_id = None          # block id of the last record, bytes
        self.sizes = {name: 0 for name, _ in FILES}
        self.buffers = {name: bytearray() for name, _ in FILES}

    # -- lifecycle ---------------------------------------------------------

    def load(self, start_height):
        """Open (or create) the archive, line it up with a scan that
        will feed blocks from `start_height` on, and return the height
        the host must actually start feeding from."""
        os.makedirs(self.dir, exist_ok=True)
        state_path = os.path.join(self.dir, STATE_NAME)
        if not os.path.exists(state_path):
            if start_height > 1:
                raise HeaderError(
                    f"this scan resumes at height {start_height}, so a new "
                    "header archive would start there and could never be "
                    "made whole: the headers below it would have to come "
                    "from a pass that is already over. Emission cannot be "
                    "turned on midway — use a fresh scan directory")
            for name, _ in FILES:
                open(_path(self.dir, name), "ab").close()
            self.watermark = None
            self._write_state()
            return GENESIS

        with open(state_path) as f:
            state = json.load(f)
        if state.get("format") != FORMAT_TAG:
            raise HeaderError("unknown header archive format")
        self.from_height = state["from_height"]
        self.watermark = state["last_height"]
        self.last_hash = state["last_block_hash"]
        self.sizes = state["sizes"]
        self._truncate_to_committed()

        if self.watermark is None:
            return GENESIS
        if self.watermark + 1 < start_height:
            raise HeaderError(
                f"header archive covers {self.from_height}..{self.watermark} "
                f"but the scan resumes from {start_height}: the archive must "
                "grow with the SAME scan from the SAME height — use a fresh "
                "directory for a fresh scan")
        if self.watermark + 1 > start_height:
            # The other misalignment is the crash window this emitter
            # creates on purpose: it checkpoints BEFORE the host writes
            # its own state, so a kill between the two leaves the
            # archive AHEAD. The host re-feeds every block from its
            # resume point, so the records up there are about to arrive
            # again: cutting them is the graph emitter's heal, in the
            # positional idiom, and the one state that can converge.
            self._cut_back(start_height - 1)
        # The id the next block must name as its parent, read back from
        # the archive itself rather than taken from the host: it is what
        # lets add_block refuse a block that does not continue THIS
        # chain, instead of leaving the discovery to the seal.
        self.last_id = decode_record(self._last_record())["hash"]
        return start_height

    def _last_record(self):
        """The 88 bytes of the highest record on disk."""
        with open(_path(self.dir, "headers"), "rb") as f:
            f.seek(self.sizes["headers"] - HDR_REC)
            return f.read(HDR_REC)

    def _truncate_to_committed(self):
        """The files grow in place, so a crash can leave a tail past the
        last checkpoint. The state's sizes are the truth: anything
        beyond them is cut, anything short of them is corruption."""
        for name, file_name in FILES:
            path = _path(self.dir, name)
            actual = os.path.getsize(path) if os.path.exists(path) else 0
            committed = self.sizes[name]
            if actual < committed:
                raise HeaderError(
                    f"{file_name}: {actual} bytes on disk but the state "
                    f"committed {committed} — the file lost data")
            if actual > committed:
                with open(path, "ab") as f:
                    f.truncate(committed)
                print(f"  headers: truncated {file_name} to its committed "
                      f"{committed} bytes (crash leftover)", file=sys.stderr)

    def _cut_back(self, to_height):
        """Drop every record above `to_height` and commit the shorter
        archive, leaving exactly the bytes a scan that checkpointed
        there would have written. The positional files cut by record
        count; coinbase.bin is variable-width, so its cut point is where
        the first dropped script begins, which coinbase_off.bin says."""
        records = to_height - self.from_height + 1
        if records < 1:
            raise HeaderError(
                f"cannot cut the archive back to height {to_height}: it "
                f"starts at {self.from_height}")
        with open(_path(self.dir, "coinbase_off"), "rb") as f:
            f.seek(records * OFF_REC)
            first_dropped = int.from_bytes(f.read(OFF_REC), "big")
        dropped = self.watermark - to_height
        self.sizes = {"headers": records * HDR_REC,
                      "coinbase_off": records * OFF_REC,
                      "coinbase": first_dropped}
        self.watermark = to_height
        # Both hashes are read back from the surviving record itself:
        # the archive is the authority on what it now ends with. Read
        # BEFORE the cut, which is only legal because the record is
        # below it.
        record = decode_record(self._last_record())
        self.last_id = record["hash"]
        self.last_hash = blockparse.hash_hex(record["hash"])
        # The state first, the truncations after: a kill in between
        # leaves the files LONGER than the committed sizes, which
        # _truncate_to_committed cuts on the next load. The other order
        # left them shorter, which that same check calls lost data —
        # and the heal would have wedged the run it exists to save.
        self._write_state()
        for name, _file_name in FILES:
            with open(_path(self.dir, name), "ab") as f:
                f.truncate(self.sizes[name])
        print(f"  headers: dropped {dropped} record(s) past the scan's "
              "resume point, will be re-fed", file=sys.stderr)

    # -- feeding -----------------------------------------------------------

    def add_block(self, height, block):
        """Archive one verified block's header. The host guarantees
        order and integrity; the emitter refuses to write a hole."""
        expect = GENESIS if self.watermark is None else self.watermark + 1
        if height != expect:
            raise HeaderError(f"header emitter fed height {height}, "
                              f"expected {expect} (host bug)")
        if self.last_id is not None and block.header.prev_hash != self.last_id:
            raise HeaderError(
                f"height {height}: this block names "
                f"{blockparse.hash_hex(block.header.prev_hash)} as its "
                f"parent, but the archive ends at "
                f"{blockparse.hash_hex(self.last_id)}. The archive would "
                "stop being a chain, which is the one thing it is for")
        script = coinbase_script(block)
        offset = self.sizes["coinbase"] + len(self.buffers["coinbase"])
        self.buffers["headers"] += block_record(block)
        self.buffers["coinbase_off"] += offset.to_bytes(OFF_REC, "big")
        self.buffers["coinbase"] += script
        self.watermark = height
        self.last_id = block.header.hash
        if sum(len(b) for b in self.buffers.values()) >= self.flush_bytes:
            self._flush()

    def _flush(self):
        """Append the buffers. Safe at any moment, not only at a
        checkpoint: what the state has not committed is truncated away
        on the next load, so an early flush risks nothing."""
        for name, _ in FILES:
            buf = self.buffers[name]
            if not buf:
                continue
            with open(_path(self.dir, name), "ab") as f:
                f.write(buf)
            self.sizes[name] += len(buf)
            buf.clear()

    def checkpoint(self, height, block_hash_display):
        """Everything fed so far becomes durable and named. Called by
        the host right before it writes its own state."""
        if self.watermark is not None and height != self.watermark:
            raise HeaderError(f"header checkpoint at {height} but the last "
                              f"block fed was {self.watermark} (host bug)")
        self._flush()
        self.last_hash = block_hash_display
        self._write_state()

    def _write_state(self):
        atomic_json(os.path.join(self.dir, STATE_NAME),
                    {"format": FORMAT_TAG,
                     "from_height": self.from_height,
                     "last_height": self.watermark,
                     "last_block_hash": self.last_hash,
                     "sizes": self.sizes})


# ---------------------------------------------------------------------------
# Reading back
# ---------------------------------------------------------------------------

def _load_state(headers_dir):
    path = os.path.join(headers_dir, STATE_NAME)
    if not os.path.exists(path):
        raise HeaderError(f"no {STATE_NAME} in {headers_dir}: not a header "
                          "archive (or the scan never checkpointed)")
    with open(path) as f:
        state = json.load(f)
    if state.get("format") != FORMAT_TAG:
        raise HeaderError("unknown header archive format")
    if state["last_height"] is None:
        raise HeaderError("empty header archive: nothing was ever "
                          "checkpointed into it")
    return state


def _load_manifest(headers_dir):
    path = os.path.join(headers_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        raise HeaderError(f"no {MANIFEST_NAME} in {headers_dir}: run "
                          "`headers fingerprint` first")
    with open(path) as f:
        return json.load(f)


class HeaderReader:
    """Random access by height, for the readers that need a few
    scattered ones (dates on a curve's checkpoints) rather than the
    whole file. One open file, one pread per record: at 88 bytes a
    height the cost of a lookup is the seek."""

    def __init__(self, headers_dir):
        state = _load_state(headers_dir)
        self.dir = headers_dir
        self.from_height = state["from_height"]
        self.last_height = state["last_height"]
        self._f = open(_path(headers_dir, "headers"), "rb")

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def record(self, height):
        """The decoded record of `height`, or a loud refusal."""
        if not self.from_height <= height <= self.last_height:
            raise HeaderError(
                f"height {height} is outside the archive's "
                f"{self.from_height:,}..{self.last_height:,}")
        self._f.seek((height - self.from_height) * HDR_REC)
        return decode_record(self._f.read(HDR_REC))

    def median_time(self, height):
        """The median-time-past of `height`: the median of the
        timestamps of the eleven blocks ending at it (fewer near the
        start of the archive, exactly as a node computes it near
        genesis). This is the monotone clock consensus uses, and the
        reason `curve dates` reported it in the first place.

        With an even count — only possible in the first ten blocks —
        the UPPER middle is taken, which is the element a node picks
        out of its sorted window. Averaging the two middles, as a
        statistics library would, is a different number.
        """
        first = max(self.from_height, height - 10)
        times = sorted(self.record(h)["time"]
                       for h in range(first, height + 1))
        return times[len(times) // 2]


def iter_records(headers_dir, from_height=None, to_height=None):
    """Decoded records in height order, streamed. The file is read in
    slabs, so a full pass over a chain-scale archive is sequential."""
    state = _load_state(headers_dir)
    height = state["from_height"]
    for slab in read_slabs(_path(headers_dir, "headers"), HDR_REC,
                           error=HeaderError):
        for i in range(0, len(slab), HDR_REC):
            if to_height is not None and height > to_height:
                return
            if from_height is None or height >= from_height:
                yield height, decode_record(slab[i:i + HDR_REC])
            height += 1


def coinbase_scripts(headers_dir):
    """(height, coinbase scriptSig) in height order.

    Two sequential reads, zipped: the offsets file says where each
    script starts, and the script of the last height runs to the end of
    the data file. The offsets must strictly increase — every coinbase
    scriptSig is at least two bytes by consensus — and a file that does
    not is corrupt in a way that would otherwise return silent garbage.
    """
    state = _load_state(headers_dir)
    height = state["from_height"]
    data_size = os.path.getsize(_path(headers_dir, "coinbase"))
    with open(_path(headers_dir, "coinbase"), "rb") as data:
        prev = None
        prev_height = None
        for slab in read_slabs(_path(headers_dir, "coinbase_off"), OFF_REC,
                               error=HeaderError):
            for i in range(0, len(slab), OFF_REC):
                offset = int.from_bytes(slab[i:i + OFF_REC], "big")
                if prev is not None:
                    if offset <= prev:
                        raise HeaderError(
                            f"coinbase_off.bin: height {height} starts at "
                            f"{offset}, not past the {prev} of height "
                            f"{prev_height} — the offsets must strictly "
                            "increase")
                    data.seek(prev)
                    yield prev_height, data.read(offset - prev)
                prev, prev_height = offset, height
                height += 1
        if prev is None:
            return
        if prev >= data_size:
            raise HeaderError(f"coinbase_off.bin: height {prev_height} "
                              f"starts at {prev}, past the end of "
                              f"coinbase.bin ({data_size} bytes)")
        data.seek(prev)
        yield prev_height, data.read(data_size - prev)


# ---------------------------------------------------------------------------
# The audit: the chain, rebuilt from the bytes
# ---------------------------------------------------------------------------

def audit_chain(headers_dir):
    """Re-derive from the file alone what the scan checked once: every
    block id, and every link.

    This is check 1 and check 2 of the four, and it is the reason the
    archive keeps the 80 bytes verbatim rather than the fields. Both the
    seal and `verify` call it, so the number they print is produced by
    one implementation and they cannot disagree.

    Returns (records, last height, last id, BIP 34 tally).
    """
    prev_id = None
    records = 0
    height = None
    for height, rec in iter_records(headers_dir):
        if prev_id is not None and rec["prev_hash"] != prev_id:
            raise HeaderError(
                f"height {height:,} does not link to {height - 1:,}: its "
                f"prev_hash is {blockparse.hash_hex(rec['prev_hash'])} but "
                f"the record before it hashes to "
                f"{blockparse.hash_hex(prev_id)}")
        prev_id = rec["hash"]
        records += 1
    if not records:
        raise HeaderError("empty header archive: nothing to audit")

    declared = agreed = 0
    for h, script in coinbase_scripts(headers_dir):
        claim = bip34_height(script)
        if claim is None:
            continue
        declared += 1
        agreed += (claim == h)
    return records, height, prev_id, {"declared": declared, "agreed": agreed}


def _print_bip34(tally):
    """The BIP 34 line. Reported, never raised: before the rule was
    enforced a scriptSig could hold anything, so a disagreement down
    there is chain history and not a defect (see the note at the top of
    this module)."""
    declared, agreed = tally["declared"], tally["agreed"]
    if not declared:
        print("..  no coinbase declares its height (BIP 34): nothing to "
              "confront the positions with")
        return
    print(f"ok  BIP 34: {agreed:,} of {declared:,} coinbases that declare a "
          f"height agree with the position they sit at"
          + ("" if agreed == declared else
             f" — {declared - agreed:,} disagree, expected only below the "
             "rule's activation"))


# ---------------------------------------------------------------------------
# fingerprint — the seal
# ---------------------------------------------------------------------------

def run_fingerprint(headers_dir):
    """Seal the archive: re-read every byte, audit the chain, write the
    identity and the canonical fingerprint.

    A root artifact: it records no parent because it has none. What it
    holds came from the blocks themselves, and the blocks are what every
    other artifact here descends from — a header archive is where a
    ancestry starts, not something that hangs off one.
    """
    state = _load_state(headers_dir)
    records, last, last_id, bip34 = audit_chain(headers_dir)

    covered_from = state["from_height"]
    if state["last_height"] != last:
        raise HeaderError(
            f"the state says the archive reaches {state['last_height']:,} "
            f"but the file holds {last:,} — a checkpoint that never finished")
    for name, file_name in FILES:
        size = os.path.getsize(_path(headers_dir, name))
        if size != state["sizes"][name]:
            raise HeaderError(f"{file_name} changed size since the last "
                              "checkpoint")
        if name in WIDTHS and size // WIDTHS[name] != records:
            raise HeaderError(
                f"{file_name} holds {size // WIDTHS[name]:,} records but "
                f"headers.bin holds {records:,}: the files do not describe "
                "the same heights")

    files = {name: {"file": file_name,
                    "sha256": sha_file(_path(headers_dir, name))}
             for name, file_name in FILES}
    identity = make_identity(FORMAT_TAG, covered_from, last,
                             ((name, files[name]["sha256"])
                              for name, _ in FILES))
    fingerprint = identity_fingerprint(identity)
    manifest = seal_manifest(FORMAT_TAG, identity, {
            "producer": producer(),
            "seconds": WallClock("fingerprint", state).stamp(),
            "last_block_hash": blockparse.hash_hex(last_id),
            "blocks": records,
            "coinbase_bytes": state["sizes"]["coinbase"],
            "bip34": bip34,
            "files": files,
            "caches": {},
            "reconstruction": (
                "one record per height in ascending order, genesis at index "
                "0: the 80 header bytes verbatim then size and weight, the "
                "coinbase scriptSig appended to coinbase.bin, and its start "
                "offset in coinbase_off.bin; the identity is then sealed by "
                "the shared recipe in docs/contracts/Artifact.md"),
    })
    atomic_json(os.path.join(headers_dir, MANIFEST_NAME), manifest)

    print(f"header archive covers heights {covered_from:,}..{last:,} "
          f"({records:,} blocks)")
    print(f"  coinbase scripts {state['sizes']['coinbase']:>16,} bytes")
    _print_bip34(bip34)
    print(f"fingerprint: {fingerprint}")
    return fingerprint


# ---------------------------------------------------------------------------
# verify — the audit of a sealed archive
# ---------------------------------------------------------------------------

def run_verify(headers_dir):
    """Re-read every byte against the manifest, then rebuild the chain
    from those bytes. The digests prove the files have not rotted; the
    chain proves they are a chain — two independent roads, and the
    second one is the whole reason this artifact exists."""
    manifest = _load_manifest(headers_dir)
    records, last, _id, bip34 = audit_chain(headers_dir)
    covered_from = manifest["identity"]["coverage"]["from"]
    print(f"ok  {records:,} headers, each linking to the one before it"
          + (" (from genesis)" if covered_from == GENESIS else ""))
    _print_bip34(bip34)
    verify_sealed(headers_dir, manifest, FORMAT_TAG, HeaderError,
                  fp_order=[name for name, _ in FILES],
                  coverage_from_data=lambda: ("exact", last))


# ---------------------------------------------------------------------------
# crosscheck — the Merkle roots, against an outpoint index
# ---------------------------------------------------------------------------

def run_crosscheck(headers_dir, index_dir):
    """Recompute every block's Merkle root from the index's txids and
    confront it with the header.

    The third of the scan's four checks, repeated offline — and the
    strongest statement anyone can make about the pair of artifacts:
    the index's transactions are exactly the ones the chain committed
    to, in the order it committed to them. A mismatch is not a rounding
    difference, it is one of the two files being about a different
    chain, so it stops at the first one.

    Both files are read sequentially, in step: blocks.bin gives the
    ordinal each height starts at, txids.bin the ids in that order.
    Nothing is held: one block's txids at a time, so the pass costs the
    two reads and no memory.
    """
    # Imported here, not at the top: the index imports the scanner, and
    # the scanner imports this module for the emission plug. A local
    # import is the honest way to say "this one command reaches across",
    # instead of a cycle that a reordering of imports could break.
    from nodsig import outpoint_index as oi

    imanifest = os.path.join(index_dir, oi.MANIFEST_NAME)
    if not os.path.exists(imanifest):
        raise HeaderError(f"no {oi.MANIFEST_NAME} in {index_dir}: this "
                          "crosscheck reads a SEALED index")
    with open(imanifest) as f:
        index_to = json.load(f)["identity"]["coverage"]["to"]

    state = _load_state(headers_dir)
    to_height = min(state["last_height"], index_to)
    if to_height < 1:
        raise HeaderError("the two artifacts do not overlap above genesis")
    print(f"confronting heights 1..{to_height:,} "
          f"(headers reach {state['last_height']:,}, index {index_to:,})",
          file=sys.stderr)

    # blocks.bin record i describes height i+1 and holds the ordinal its
    # block STARTS at, so a height's transaction count is the next
    # record's ordinal minus its own — and for the very last height, the
    # total number of txids. One record of lookahead, no list.
    txid_path = os.path.join(index_dir, "txids.bin")
    total_txids = os.path.getsize(txid_path) // oi.TXID_REC
    blocks = read_fixed(os.path.join(index_dir, "blocks.bin"), oi.BLOCK_REC,
                        error=HeaderError)
    txids = read_fixed(txid_path, oi.TXID_REC, error=HeaderError)

    def ordinal(rec):
        return int.from_bytes(rec[:oi.ORD], "big")

    start = ordinal(next(blocks))                    # height 1 starts here
    checked = 0
    for height, rec in iter_records(headers_dir, 1, to_height):
        nxt = next(blocks, None)
        end = total_txids if nxt is None else ordinal(nxt)
        n = end - start
        start = end
        block_txids = [bytes(next(txids)) for _ in range(n)]
        if blockparse.merkle_root(block_txids) != rec["merkle_root"]:
            raise HeaderError(
                f"height {height:,}: the {n:,} txids the index holds do not "
                f"give the Merkle root in the header "
                f"({blockparse.hash_hex(rec['merkle_root'])}). One of the "
                "two artifacts is about a different chain")
        checked += 1
        if checked % 100_000 == 0:
            print(f"  {checked:,} roots confronted", file=sys.stderr)
    print(f"ok  {checked:,} Merkle roots recomputed from the index and "
          f"confronted with the headers")
    return checked


# ---------------------------------------------------------------------------
# stats and show
# ---------------------------------------------------------------------------

def run_stats(headers_dir, out=sys.stdout):
    """Watermark and totals from the state alone — no bytes read."""
    state = _load_state(headers_dir)
    records = state["sizes"]["headers"] // HDR_REC
    print(f"header archive covers heights {state['from_height']:,}.."
          f"{state['last_height']:,} ({records:,} blocks)", file=out)
    print(f"  {'coinbase bytes':<16} {state['sizes']['coinbase']:>16,}",
          file=out)
    if records:
        print(f"  {'bytes/block':<16} "
              f"{sum(state['sizes'].values()) / records:>16.1f}", file=out)
    path = os.path.join(headers_dir, MANIFEST_NAME)
    if os.path.exists(path):
        with open(path) as f:
            print(f"fingerprint: {json.load(f)['fingerprint']}", file=out)
    else:
        print("not sealed: run `headers fingerprint`", file=out)


def _coinbase_range(headers_dir, state, lo, hi):
    """height → coinbase scriptSig for lo..hi, by three positional
    reads: the offsets slice, then one contiguous slice of the data
    file. The full-pass twin, with the corruption checks a whole-file
    read deserves, is `coinbase_scripts`; this one exists so that
    showing three heights of a chain-scale archive costs three seeks,
    not a pass over gigabytes of coinbase scripts."""
    first = state["from_height"]
    records = state["sizes"]["coinbase_off"] // OFF_REC
    with open(_path(headers_dir, "coinbase_off"), "rb") as f:
        f.seek((lo - first) * OFF_REC)
        raw = f.read((hi - lo + 2) * OFF_REC)
    offs = [int.from_bytes(raw[i:i + OFF_REC], "big")
            for i in range(0, len(raw), OFF_REC)]
    if hi - first + 1 == records:      # the last record runs to the end
        offs.append(state["sizes"]["coinbase"])
    if offs != sorted(set(offs)):
        raise HeaderError("coinbase_off.bin: the offsets must strictly "
                          "increase")
    with open(_path(headers_dir, "coinbase"), "rb") as f:
        f.seek(offs[0])
        blob = f.read(offs[-1] - offs[0])
    base = offs[0]
    return {h: blob[offs[k] - base:offs[k + 1] - base]
            for k, h in enumerate(range(lo, hi + 1))}


def run_show(headers_dir, from_height, to_height, out=sys.stdout):
    """A height range, decoded — what the 88 bytes actually say.

    Reads exactly the range it shows: both files are addressed by
    record, the variable-width coinbase through its offsets file, so
    the cost is the range's, never the archive's."""
    state = _load_state(headers_dir)
    first = state["from_height"]
    records = state["sizes"]["headers"] // HDR_REC
    lo = max(from_height, first)
    hi = min(to_height, first + records - 1)
    if hi < lo:
        print("no headers in that range (check the watermark with `stats`)",
              file=out)
        return
    with open(_path(headers_dir, "headers"), "rb") as f:
        f.seek((lo - first) * HDR_REC)
        raw = f.read((hi - lo + 1) * HDR_REC)
    scripts = _coinbase_range(headers_dir, state, lo, hi)
    for k, height in enumerate(range(lo, hi + 1)):
        rec = decode_record(raw[k * HDR_REC:(k + 1) * HDR_REC])
        script = scripts.get(height, b"")
        claim = bip34_height(script)
        print(f"height {height:,}  {blockparse.hash_hex(rec['hash'])}",
              file=out)
        print(f"  prev {blockparse.hash_hex(rec['prev_hash'])}", file=out)
        print(f"  merkle {blockparse.hash_hex(rec['merkle_root'])}", file=out)
        print(f"  time {rec['time']}  bits 0x{rec['bits']:08x}  "
              f"nonce {rec['nonce']}", file=out)
        print(f"  size {rec['size']:,} B  weight {rec['weight']:,} WU",
              file=out)
        print(f"  coinbase {script.hex()}"
              + (f"  (declares height {claim:,})" if claim is not None
                 else ""), file=out)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Read back a headers-v2 archive co-emitted during a "
                    "chain scan (the emission itself is the --headers flag "
                    "of `nodsig reuse scan` / `nodsig archive scan`).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pf = sub.add_parser("fingerprint",
                        help="seal: audit the chain, write the manifest")
    pf.add_argument("--headers", required=True, help="archive directory")

    pv = sub.add_parser("verify", help="audit a sealed archive (every byte)")
    pv.add_argument("--headers", required=True)

    pc = sub.add_parser("crosscheck",
                        help="recompute the Merkle roots from an index")
    pc.add_argument("--headers", required=True)
    pc.add_argument("--index", required=True, help="a sealed outpoint index")

    pt = sub.add_parser("stats", help="watermark and totals (instant)")
    pt.add_argument("--headers", required=True)

    ps = sub.add_parser("show", help="decode a height range, human-readable")
    ps.add_argument("--headers", required=True)
    ps.add_argument("--from", dest="from_height", type=int, required=True)
    ps.add_argument("--to", dest="to_height", type=int, required=True)

    args = p.parse_args(argv)
    try:
        if args.cmd == "fingerprint":
            run_fingerprint(args.headers)
        elif args.cmd == "verify":
            run_verify(args.headers)
        elif args.cmd == "crosscheck":
            run_crosscheck(args.headers, args.index)
        elif args.cmd == "stats":
            run_stats(args.headers)
        else:
            run_show(args.headers, args.from_height, args.to_height)
    except (HeaderError, blockparse.ParseError, OSError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
