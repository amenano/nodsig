#!/usr/bin/env python3
"""
blockparse.py — parser for raw Bitcoin blocks and transactions.

What it does: turns the raw bytes of a block (what `bitcoin-cli getblock
<hash> 0` returns, hex-decoded) into plain Python structures: the header
fields, and every transaction with its inputs (scriptSig, witness) and
outputs (value, scriptPubKey). Both serialization formats are handled,
legacy and SegWit.

Why it exists: the reuse scan (level 3 of the census) must read every
input ever confirmed, because for the standard script types the
*unlocking* data carries everything needed to recompute the lock being
opened. This module only parses; interpreting the data is the caller's
job.

Integrity is not an extra step, it is built into the format and this
parser recomputes it: the block hash is the double SHA-256 of the header,
each txid is the double SHA-256 of the transaction (witness excluded),
and the Merkle root in the header commits to all txids. `parse_block`
recomputes the Merkle root and refuses bytes that do not match their own
header, so corruption cannot pass silently.

One subtlety deserves the spotlight, because a first version of this
parser missed it and the self-test caught it: since the txid EXCLUDES
the witness, the header's Merkle root does not cover witness bytes at
all — and the witness is where most of the revealed keys live. The
protocol closes that hole elsewhere: SegWit blocks carry a *witness
commitment* in the coinbase (BIP 141), a second Merkle root over the
wtxids (hashes of the FULL serializations). `parse_block` verifies that
commitment too, so every byte this module hands to the census, witness
included, is certified by the block hash.

Hash convention, once and for all: inside the serialization every hash
sits in "little-endian" byte order; block explorers and RPC print the
SAME hash byte-reversed. This module keeps digests as they appear in the
bytes and offers `hash_hex` for the human-facing form. Mixing the two
orders is the classic first bug of every Bitcoin parser — keeping the
rule in one place is the cure.

It is a library (reuse_scan.py imports it) and talks to no one: no
network, no RPC, just bytes in, structures out.
"""

from collections import namedtuple

from nodsig.hashing import sha256d


class ParseError(ValueError):
    """Raised when the bytes do not form a well-formed block/transaction.

    Every message says WHAT was being read when the bytes ran out or made
    no sense: with gigabytes streaming past, an error that just says
    "bad data" would be useless.
    """


# ---------------------------------------------------------------------------
# The parsed structures: plain named tuples, nothing hidden
# ---------------------------------------------------------------------------
# A named tuple is just a tuple with field names: cheap (millions will be
# created during a scan), immutable, and it prints itself readably. No
# methods, no magic: what the parser found is all there is.

BlockHeader = namedtuple("BlockHeader", [
    "version",      # int: signalling field (BIP 9 uses its bits)
    "prev_hash",    # bytes(32), serialized order: hash of the PARENT block
                    # header — this single field is what makes the chain a
                    # chain, and checking it is how a reader verifies that
                    # block N+1 really extends block N
    "merkle_root",  # bytes(32), serialized order: root of the Merkle tree
                    # over the txids — the header's commitment to the full
                    # transaction list (see merkle_root() below)
    "time",         # int, unix seconds, declared by the miner (consensus
                    # only bounds it loosely: median-of-11 past blocks and
                    # at most ~2h in the future)
    "bits",         # int: the difficulty target in compact form
    "nonce",        # int: the field miners grind in search of a low hash
    "hash",         # bytes(32) = sha256d(the 80 header bytes): the block's
                    # own name, recomputed here from the bytes themselves
])

TxIn = namedtuple("TxIn", [
    "prev_txid",    # bytes(32), serialized order: the transaction that
                    # created the coin being spent…
    "prev_vout",    # int: …and which of its outputs is that coin
    "script_sig",   # bytes: the legacy unlocking data. For P2PKH it holds
                    # [signature, public key]; for P2SH its last push is
                    # the redeem script; for native SegWit spends it is
                    # EMPTY (the unlocking data moved to the witness)
    "sequence",     # int: relative-timelock / RBF signalling field
    "witness",      # list[bytes]: the SegWit unlocking data, one stack of
                    # items for this input ([] if the tx has no witness or
                    # this input contributes none). For P2WPKH it holds
                    # [signature, public key]; for P2WSH the LAST item is
                    # the witness script
])

TxOut = namedtuple("TxOut", [
    "value",         # int, satoshis (1 BTC = 100,000,000)
    "script_pubkey", # bytes: the lock placed on this coin — the script
                     # a future spender will have to satisfy
])

Tx = namedtuple("Tx", [
    "version",    # int (unsigned 32-bit little-endian field)
    "inputs",     # list[TxIn]
    "outputs",    # list[TxOut]
    "locktime",   # int: earliest block/time the tx may confirm
    "txid",       # bytes(32) = sha256d(serialization WITHOUT witness):
                  # the id the header's Merkle tree commits to
    "wtxid",      # bytes(32) = sha256d(FULL serialization): the id the
                  # witness commitment covers (equals txid for legacy txs)
    "is_segwit",  # bool: True if serialized with marker+flag and witness
    "size",       # int: bytes this transaction occupies in the block
    "base_size",  # int: bytes of the serialization WITHOUT marker, flag
                  # and witness — the one weight is computed from. Taken
                  # from the parser's own byte positions, not rebuilt by
                  # re-serializing: a size that is measured cannot drift
                  # from the bytes it describes
])

Block = namedtuple("Block", [
    "header",        # BlockHeader
    "transactions",  # list[Tx]
    "size",          # int: the raw block's length in bytes
    "weight",        # int: BIP 141 weight = 3 × base size + total size,
                     # where the base size excludes every witness byte.
                     # A block with no witness data weighs exactly 4×
                     # its size, which is what makes the old 1 MB limit
                     # and the 4M weight unit the same rule
])


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def hash_hex(digest):
    """From serialized order to the hex that explorers display.

    The two forms are the same 32 bytes read in opposite directions;
    reversing is all there is to it.
    """
    return digest[::-1].hex()


def read_compactsize(buf, pos):
    """Bitcoin's classic variable-length integer. Returns (value, new_pos).

    Counts (of transactions, inputs, outputs, script bytes, witness
    items…) are stored in a format that spends one byte on small numbers
    and more only when needed:

        value < 253        → 1 byte, the value itself
        fits in 16 bits    → 0xfd + 2 bytes little-endian
        fits in 32 bits    → 0xfe + 4 bytes little-endian
        fits in 64 bits    → 0xff + 8 bytes little-endian

    (Not to be confused with the snapshot VARINT of utxo_census.py:
    Bitcoin serializes integers in several unrelated ways, and this is
    the one used inside transactions and blocks.)
    """
    if pos >= len(buf):
        raise ParseError("bytes ended where a compact size was expected")
    n = buf[pos]
    pos += 1
    if n < 253:
        return n, pos
    width = {253: 2, 254: 4, 255: 8}[n]
    if pos + width > len(buf):
        raise ParseError("bytes ended inside a compact size")
    return int.from_bytes(buf[pos:pos + width], "little"), pos + width


def write_compactsize(n):
    """The inverse of read_compactsize: an integer → its compact-size bytes.

    Kept beside the reader so the wire format has one home. Only the graph
    co-emission serializes blocks, so this is its only production caller;
    the tests check it against an independent mirror, same discipline as
    for the block serialization itself.
    """
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _take(buf, pos, n, what):
    """Slice n bytes or fail saying WHAT was being read (see ParseError)."""
    end = pos + n
    if end > len(buf):
        raise ParseError(f"bytes ended while reading {what}")
    return buf[pos:end], end


def is_coinbase(tx):
    """True for the one transaction per block that creates new coins.

    The coinbase spends nothing, but the serialization still requires an
    input, so the protocol fills it with an impossible reference: an
    all-zero txid and output index 0xffffffff. Its scriptSig is not a
    real script — miners put arbitrary data there (the genesis block
    famously carries a newspaper headline).
    """
    return (len(tx.inputs) == 1
            and tx.inputs[0].prev_txid == bytes(32)
            and tx.inputs[0].prev_vout == 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def block_id(raw):
    """The block's own hash, out of the 80 header bytes and nothing else.

    Why this exists next to `parse_header`, which computes the same
    value: a caller holding bytes that arrived from somewhere has no
    reason to hand them to a PARSER before knowing whether they are the
    block it asked for. Hashing 80 bytes is free, and it settles the
    only question that makes parsing the rest worth doing. So the order
    a fetch loop follows is: hash, compare with the hash requested, and
    parse afterwards. Until that comparison is made, every byte here is
    input from a machine on the other end of a wire, however much that
    machine is trusted.

    Reversing those two lines costs nothing and removes a whole class of
    question about what a hostile node could feed the parser.
    """
    if len(raw) < 80:
        raise ParseError(f"a block is at least 80 bytes of header, "
                         f"got {len(raw)}")
    return sha256d(raw[:80])


def parse_header(buf, pos=0):
    """Parse the 80-byte block header. Returns (BlockHeader, new_pos).

    The layout, fixed since the genesis block:

        bytes  0- 3  version        (little-endian)
        bytes  4-35  prev_hash      (hash of the parent header)
        bytes 36-67  merkle_root    (commitment to the txids)
        bytes 68-71  time           (little-endian)
        bytes 72-75  bits           (little-endian)
        bytes 76-79  nonce          (little-endian)

    The returned .hash is recomputed from the bytes themselves. This is
    the cornerstone of reading blocks WITHOUT trusting the transport:
    ask for block hash H, hash the 80 bytes you received, and if the two
    match, nothing between the node's disk and your parser could have
    altered a single bit of the header. Chain the prev_hash fields and
    the guarantee extends to the whole sequence of headers.
    """
    raw, end = _take(buf, pos, 80, "the block header")
    return BlockHeader(
        version=int.from_bytes(raw[0:4], "little"),
        prev_hash=bytes(raw[4:36]),
        merkle_root=bytes(raw[36:68]),
        time=int.from_bytes(raw[68:72], "little"),
        bits=int.from_bytes(raw[72:76], "little"),
        nonce=int.from_bytes(raw[76:80], "little"),
        hash=sha256d(raw),
    ), end


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------

def parse_tx(buf, pos=0):
    """Parse one transaction. Returns (Tx, new_pos).

    The two serialization layouts:

        legacy:  version | n_in inputs | n_out outputs | locktime
        SegWit:  version | 0x00 0x01 | n_in inputs | n_out outputs
                 | witness (one stack per input) | locktime

    How they are told apart: the byte right after the version. In a
    legacy transaction that byte starts the input count, and a count of
    zero would mean a transaction with no inputs, which is not valid; so
    when 0x00 appears there it can only be the SegWit *marker*, followed
    by the *flag* 0x01 (BIP 144).

    Why the txid excludes the witness (BIP 141): signatures cannot sign
    themselves, so unlocking data is malleable — a third party could
    tweak a signature's encoding without invalidating it, changing the
    hash of the full serialization while the transaction stays the same.
    SegWit's fix is to define the txid over the serialization WITHOUT
    marker, flag and witness: what identifies the transaction is what it
    does (which coins in, which locks out), not how it was authorized.
    That is why this function tracks the byte regions between version and
    locktime: to rebuild that stripped serialization and hash it.
    """
    start = pos
    _, pos = _take(buf, pos, 4, "the transaction version")
    version = int.from_bytes(buf[start:pos], "little")

    if pos >= len(buf):
        raise ParseError("bytes ended after the transaction version")
    segwit = buf[pos] == 0x00
    if segwit:
        marker_flag, pos = _take(buf, pos, 2, "the SegWit marker and flag")
        if marker_flag[1] != 0x01:
            # 0x01 is the only flag ever defined; anything else means we
            # are reading a format this parser does not know.
            raise ParseError(f"unknown SegWit flag 0x{marker_flag[1]:02x}")

    # Everything from here to the end of the outputs is covered by the
    # txid in both layouts; remember where it starts.
    body_start = pos

    n_in, pos = read_compactsize(buf, pos)
    if n_in == 0:
        raise ParseError("transaction with zero inputs")
    inputs = []
    for i in range(n_in):
        # Each input: which coin it spends (txid + output index), the
        # legacy unlocking data, and the sequence field.
        prev_txid, pos = _take(buf, pos, 32, f"input {i}: previous txid")
        raw4, pos = _take(buf, pos, 4, f"input {i}: previous output index")
        prev_vout = int.from_bytes(raw4, "little")
        script_len, pos = read_compactsize(buf, pos)
        script_sig, pos = _take(buf, pos, script_len, f"input {i}: scriptSig")
        raw4, pos = _take(buf, pos, 4, f"input {i}: sequence")
        inputs.append(TxIn(bytes(prev_txid), prev_vout, bytes(script_sig),
                           int.from_bytes(raw4, "little"), []))

    n_out, pos = read_compactsize(buf, pos)
    outputs = []
    for i in range(n_out):
        # Each output: an amount and the lock placed on it. (Zero outputs
        # would also be invalid, but nothing downstream depends on it, so
        # the parser does not enforce what it does not need.)
        raw8, pos = _take(buf, pos, 8, f"output {i}: value")
        value = int.from_bytes(raw8, "little")
        script_len, pos = read_compactsize(buf, pos)
        script, pos = _take(buf, pos, script_len, f"output {i}: scriptPubKey")
        outputs.append(TxOut(value, bytes(script)))

    body_end = pos

    if segwit:
        # The witness section: one stack of items per input, in input
        # order, each item a plain length-prefixed byte string. Note the
        # asymmetry with scriptSig: a witness is NOT a script, it is only
        # data — the items are consumed by the script that gets executed.
        for i in range(n_in):
            n_items, pos = read_compactsize(buf, pos)
            items = []
            for j in range(n_items):
                item_len, pos = read_compactsize(buf, pos)
                item, pos = _take(buf, pos, item_len,
                                  f"input {i}: witness item {j}")
                items.append(bytes(item))
            inputs[i] = inputs[i]._replace(witness=items)

    raw4, pos = _take(buf, pos, 4, "the transaction locktime")
    locktime = int.from_bytes(raw4, "little")

    # The txid: hash of [version | inputs | outputs | locktime], i.e. the
    # full serialization for legacy, the stripped one for SegWit. The
    # wtxid hashes the FULL serialization either way (for legacy the two
    # coincide, exactly as BIP 141 defines it).
    full = bytes(buf[start:pos])
    if segwit:
        stripped = (bytes(buf[start:start + 4])
                    + bytes(buf[body_start:body_end])
                    + bytes(raw4))
        txid = sha256d(stripped)
        wtxid = sha256d(full)
    else:
        stripped = full
        txid = wtxid = sha256d(full)

    return Tx(version, inputs, outputs, locktime, txid, wtxid, segwit,
              pos - start, len(stripped)), pos


# ---------------------------------------------------------------------------
# Merkle root and the whole block
# ---------------------------------------------------------------------------

def merkle_root(txids):
    """Bitcoin's Merkle tree over the txids, computed bottom-up.

    Pair the digests, hash each pair with sha256d, repeat on the results
    until one digest is left; a level with an odd count duplicates its
    last element to complete the final pair. A single txid is its own
    root — the genesis block, with only the coinbase, is the example.

    This is how an 80-byte header commits to megabytes of transactions:
    change any byte of any transaction and its txid changes, so the pair
    hashes change all the way up, and the root no longer matches.

    Note for the curious: the duplication rule makes some DIFFERENT tx
    lists share a root (CVE-2012-2459), which matters to consensus code
    accepting blocks from strangers. Here the root is only compared
    against a header whose own hash was already verified, so the check
    detects corruption — and that it does perfectly well.
    """
    if not txids:
        raise ParseError("a block carries at least the coinbase")
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
    return level[0]


def parse_block(raw):
    """Parse a whole raw block and verify its internal consistency.

    A block is simply: header | transaction count | the transactions,
    back to back. Three checks are built in and not optional:

      1. every byte must be consumed — trailing bytes mean the input was
         not a single well-formed block;
      2. the Merkle root recomputed from the parsed txids must equal the
         one in the header — the transactions must be exactly those the
         header commits to;
      3. if the block carries witness data, the witness commitment in
         the coinbase must match — because check 2 alone does NOT cover
         witness bytes (see _verify_witness_commitment).

    The returned Block also carries the two sizes the bytes define: its
    length, and its BIP 141 weight. Both are by-products of a parse that
    has already walked every byte, so a caller who wants them (the header
    archive stores both per height) never has to serialize anything back.

    What this does NOT check is that the header is the one the caller
    wanted: compare header.hash with the hash the block was requested by.
    With that comparison done, the loop is closed: requested hash →
    header (verified by hashing it) → txids (verified by the Merkle
    root) → every parsed byte, witness included (verified by the witness
    commitment). Nothing rests on trusting the transport.
    """
    header, pos = parse_header(raw, 0)
    n_tx, pos = read_compactsize(raw, pos)
    prologue = pos                      # header + the transaction count
    transactions = []
    for _ in range(n_tx):
        tx, pos = parse_tx(raw, pos)
        transactions.append(tx)
    if pos != len(raw):
        raise ParseError(f"{len(raw) - pos} trailing bytes after the last "
                         "transaction")
    if merkle_root([tx.txid for tx in transactions]) != header.merkle_root:
        raise ParseError("Merkle root mismatch: the transactions do not "
                         "match the header (corrupted bytes?)")
    _verify_witness_commitment(transactions)
    # The block's two sizes, both measured rather than reconstructed: the
    # total is the bytes received, the base is the same block with every
    # witness byte (and the marker and flag that announce them) left out.
    base = prologue + sum(tx.base_size for tx in transactions)
    return Block(header, transactions, len(raw), 3 * base + len(raw))


# The 4 bytes that mark a witness commitment output in the coinbase:
# OP_RETURN outputs whose payload starts with this header (BIP 141).
_WITNESS_COMMITMENT_MARK = bytes.fromhex("aa21a9ed")


def _verify_witness_commitment(transactions):
    """Verify the coinbase's commitment to all witness data (BIP 141).

    Why this exists: txids exclude the witness, so the header's Merkle
    root certifies everything EXCEPT the unlocking data of SegWit spends
    — which for this project is precisely the payload (public keys are
    revealed there). SegWit therefore added a second commitment: the
    coinbase carries an output of the form

        OP_RETURN PUSH36( 0xaa21a9ed || sha256d(witness_root || reserved) )

    where witness_root is the Merkle root over the WTXIDs (with the
    coinbase's own slot set to 32 zero bytes, since the commitment cannot
    contain its own hash), and `reserved` is a 32-byte value carried as
    the coinbase's only witness item. Consensus rules require this output
    in every block that has witness data; if several outputs match the
    pattern, the last one wins (also per BIP 141).

    Blocks with no SegWit transaction (everything before block 481,824,
    and the occasional all-legacy block after) have nothing to commit to:
    the function returns without checking anything, and the header's
    Merkle root alone already covers every byte of those blocks.
    """
    if not any(tx.is_segwit for tx in transactions):
        return
    coinbase = transactions[0]
    if not is_coinbase(coinbase):
        raise ParseError("block with witness data whose first transaction "
                         "is not the coinbase")

    commitment = None
    for out in coinbase.outputs:           # the LAST matching output wins
        spk = out.script_pubkey
        if (len(spk) >= 38 and spk[0] == 0x6A and spk[1] == 0x24
                and spk[2:6] == _WITNESS_COMMITMENT_MARK):
            commitment = spk[6:38]
    if commitment is None:
        raise ParseError("block with witness data but no witness "
                         "commitment in the coinbase")

    witness = coinbase.inputs[0].witness
    if len(witness) != 1 or len(witness[0]) != 32:
        raise ParseError("coinbase witness is not the single 32-byte "
                         "reserved value required by BIP 141")

    witness_root = merkle_root([bytes(32)]
                               + [tx.wtxid for tx in transactions[1:]])
    if sha256d(witness_root + witness[0]) != commitment:
        raise ParseError("witness commitment mismatch: the witness bytes "
                         "do not match the coinbase (corrupted bytes?)")


# ---------------------------------------------------------------------------
# Scripts: extracting the data pushes
# ---------------------------------------------------------------------------

def script_pushes(script):
    """The data pushes of a script, in order, as a list of bytes.

    A script is a sequence of one-byte opcodes; some opcodes carry data
    (the "pushes") and encode its length in one of four ways:

        0x01-0x4b        → the opcode itself is the length (1 to 75)
        0x4c PUSHDATA1   → next 1 byte is the length
        0x4d PUSHDATA2   → next 2 bytes (little-endian) are the length
        0x4e PUSHDATA4   → next 4 bytes (little-endian) are the length

    This is how the reveal extraction reads unlocking data: in a P2PKH
    scriptSig the pushes are [signature, public key]; in a P2SH scriptSig
    the LAST push is the redeem script. All other opcodes (OP_DUP,
    OP_1…OP_16, OP_CHECKSIG…) push no data from the serialization and are
    skipped: they matter to the script interpreter, not to a census of
    revealed keys.

    Raises ParseError if a push claims more bytes than the script has:
    such a script is malformed, and the caller should count it in the
    declared "unknown" bucket, not guess (no silent heuristics).
    """
    pushes = []
    pos, n = 0, len(script)
    while pos < n:
        op = script[pos]
        pos += 1
        if 1 <= op <= 75:                 # direct push: opcode is the length
            length = op
        elif op == 76:                    # OP_PUSHDATA1
            raw, pos = _take(script, pos, 1, "an OP_PUSHDATA1 length")
            length = raw[0]
        elif op == 77:                    # OP_PUSHDATA2
            raw, pos = _take(script, pos, 2, "an OP_PUSHDATA2 length")
            length = int.from_bytes(raw, "little")
        elif op == 78:                    # OP_PUSHDATA4
            raw, pos = _take(script, pos, 4, "an OP_PUSHDATA4 length")
            length = int.from_bytes(raw, "little")
        else:                             # not a data push: skip
            continue
        data, pos = _take(script, pos, length, "a script push")
        pushes.append(bytes(data))
    return pushes


def scriptsig_pushes(tx_in, stats):
    """The data pushes of one input's scriptSig, malformed ones counted.

    Lives here, beside `script_pushes`, because every walk that reads an
    input's unlocking data — the reveal extraction, the nonce census, a
    benchmark of either — needs the same two lines: parse, and count the
    failure. One implementation keeps the accounting one rule (a count
    of scripts, not of readers), and lets a host that walks an input for
    more than one artifact parse its scriptSig ONCE and hand the list
    around — worth about half a microsecond per input, half an hour over
    the chain."""
    try:
        return script_pushes(tx_in.script_sig)
    except ParseError:
        stats["malformed_scriptsig"] += 1
        return []
