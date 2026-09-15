#!/usr/bin/env python3
"""Write the scan's conformance vectors, `tests/fixtures/scan/vectors.json`.

A vector is one block and what the reveal archive's scan makes of it: the
records it adds to each category, as the sorted and reduced run of that
single block (its record count and sha256), the counters it moves, and the
header facts a parser must agree on. The recipe is spelled out in the
file's `note`, so a port needs the block, a JSON reader and the format
page — never this runtime. Two families:

  - `synthetic`: the suite's own chains, block bytes INCLUDED as hex, so
    the vectors run anywhere; they cover every spend shape the tests
    know (P2PK and bare multisig outputs, P2PKH, P2SH, P2WPKH, P2WSH,
    P2SH-P2WSH, taproot key and script paths, hybrid and uncompressed
    keys, a malformed scriptSig, a program created after its script);
  - `chain`: real blocks, referenced by height and hash (their bytes are
    public and anyone with a node fetches them over REST), forty from
    each of five eras, so a port meets the chain as it is.

    python3 tools/make_scan_vectors.py --node http://127.0.0.1:8332 \\
        [--eras 100000,300000,480000,650000,830000] [--per-era 40] \\
        [--out tests/fixtures/scan/vectors.json] [--no-chain]

Not part of the package and nothing imports it; the reference is what it
runs (`reveal_archive.block_records`, the scan's own per-block body), so
what it writes is what the scan does, not a restatement of it.
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from nodsig import blockparse                      # noqa: E402
from nodsig import reveal_archive as ra           # noqa: E402
from nodsig.sightings import new_filter_stats     # noqa: E402

NOTE = """\
One vector = one block and what the reveal-archive-v4 scan makes of it.

Recipe. Parse the block (the header's hash must be `hash`; the Merkle root
and the witness commitment must verify). Walk every transaction as the
format page docs/formats/RevealArchive-v4.md describes: the keys an output
publishes and the programs it creates (P2SH, P2WSH), then, for every
non-coinbase input, the keys its scriptSig pushes and witness items
reveal, the candidate scripts (last scriptSig push, last witness item),
the keys inside them, the taproot internal key and leaf keys, and the
program a P2SH-P2WSH spend names. Every sighting is one record
`digest | byte | height`: a 20- or 32-byte digest (per category), one
byte of flags or inner-key count, the height as 3 bytes big-endian. For
each category sort the block's records, reduce equal digests (bitwise OR
of the byte and the lowest height for `keys`, `programs20`,
`programs32`; the highest byte and the lowest height for `scripts20`,
`scripts32`), concatenate: `runs.<category>.sha256` is the sha256 of
those bytes and `records` their count; an empty category is the sha256
of nothing. `stats` are the counters the block moves, from zero.
`header` is what a parser must agree on: `txids_sha256` and
`wtxids_sha256` are the sha256 over the transaction ids, in block order,
each in internal (little-endian) byte order.

Bytes are lowercase hex; hashes are shown as everyone shows them
(big-endian display order) except inside `txids_sha256`/`wtxids_sha256`.
`synthetic` vectors carry their block in `raw`; `chain` vectors carry
`height`, `hash` and `raw_sha256`, and the block is fetched from any
Bitcoin node (`/rest/block/<hash>.bin`)."""


def stats_fresh():
    return {"transactions": 0, "inputs": 0, "malformed_scriptsig": 0,
            "revelations": 0, "program_outputs": 0, "nested_programs": 0,
            **new_filter_stats()}


def vector_of(raw, height, tmp):
    block = blockparse.parse_block(raw)
    stats = stats_fresh()
    buffers = {cat: [] for cat in ra.RUN_CATS}
    ra.block_records(block, height, stats, buffers)
    runs = {}
    for cat in ra.RUN_CATS:
        path = os.path.join(tmp, f"{cat}.bin")
        n, sha = ra._write_run(path, cat, buffers[cat])
        runs[cat] = {"records": n, "sha256": sha}
    h = block.header
    txids = hashlib.sha256(b"".join(tx.txid for tx in block.transactions))
    wtxids = hashlib.sha256(b"".join(tx.wtxid for tx in block.transactions))
    return {
        "height": height,
        "hash": h.hash[::-1].hex(),
        "size": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "header": {
            "prev_hash": h.prev_hash[::-1].hex(),
            "merkle_root": h.merkle_root[::-1].hex(),
            "tx_count": len(block.transactions),
            "weight": block.weight,
            "txids_sha256": txids.hexdigest(),
            "wtxids_sha256": wtxids.hexdigest(),
        },
        "stats": stats,
        "runs": runs,
    }


def synthetic_chains():
    import test_reuse_scan as trs
    import test_reveal_archive as tra
    return [("reuse_scan.build_chain", trs.build_chain()),
            ("reveal_archive.proof_chain", tra.proof_chain())]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--node", help="REST base URL of a Bitcoin node")
    ap.add_argument("--eras", default="100000,300000,480000,650000,830000")
    ap.add_argument("--per-era", type=int, default=40)
    ap.add_argument("--out", default=os.path.join(
        ROOT, "tests", "fixtures", "scan", "vectors.json"))
    ap.add_argument("--no-chain", action="store_true",
                    help="synthetic vectors only")
    args = ap.parse_args(argv)

    out = {"note": NOTE, "format": ra.FORMAT_TAG,
           "record": {"height_bytes": ra.HEIGHT_BYTES,
                      "digest_bytes": dict(ra.CATEGORIES)},
           "categories": list(ra.RUN_CATS), "synthetic": [], "chain": []}
    with tempfile.TemporaryDirectory() as tmp:
        for name, chain in synthetic_chains():
            for height in sorted(chain):
                if height < 1:
                    continue
                hash_hex, raw_hex = chain[height]
                raw = bytes.fromhex(raw_hex)
                v = vector_of(raw, height, tmp)
                assert v["hash"] == hash_hex, (name, height)
                v = {"chain": name, **v, "raw": raw_hex}
                out["synthetic"].append(v)
        if not args.no_chain:
            if not args.node:
                sys.exit("--node is needed for the chain vectors "
                         "(or pass --no-chain)")
            from nodsig.reuse_scan import RestClient
            client = RestClient(args.node)
            heights = [e + i for e in map(int, args.eras.split(","))
                       for i in range(args.per_era)]
            for i in range(0, len(heights), 25):
                window = heights[i:i + 25]
                hashes, raws = client.fetch_blocks(window)
                for h, want, raw in zip(window, hashes, raws):
                    if blockparse.block_id(raw) != want:
                        sys.exit(f"height {h}: bytes do not hash to the hash")
                    out["chain"].append(vector_of(raw, h, tmp))
                print(f"  {window[-1]:>9,}", file=sys.stderr)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print(f"{len(out['synthetic'])} synthetic and {len(out['chain'])} chain "
          f"vectors -> {os.path.relpath(args.out, ROOT)}")


if __name__ == "__main__":
    main()
