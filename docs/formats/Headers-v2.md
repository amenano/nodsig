# Headers-v2: format (L0)

The **header chain** the scan verified, kept: 88 bytes per height plus each
block's coinbase scriptSig, co-emitted while a pass over the blocks is already
happening. It is what turns the scan's integrity checks from an event into a
property (they can be **repeated**, locally, forever), and it is what lets
`curve dates` answer without a node.

- **Directory:** `headers.bin`, `coinbase.bin`, `coinbase_off.bin`, a
  `state.json` while it grows, a `manifest.json` after `headers fingerprint`.
- **Coverage:** `0..H`. The only artifact here that starts at **genesis**: a
  chain of headers whose first record has nothing before it cannot check its own
  first link, and the link is the point.
- **Defined over:** nothing. It comes from the blocks themselves, so it is where a
  ancestry starts.
- **Size:** ~93 B/height fixed plus the coinbase scripts (~50 B on average, no
  consensus bound below 100 B), so **under 150 MB** for a chain of ~1M blocks:
  a rounding error beside [Graph-v2](./Graph-v2.md)'s 300+ GB.

## Endianness & conventions

The 80 header bytes are **quoted, not encoded**: they are stored exactly as the
chain wrote them (little-endian inside), because `sha256d` over those bytes *is*
the block id, and a re-serialization that differed in one bit would break the
one property that makes the file self-certifying. Every field nodsig itself
writes (size, weight, offset) is **big-endian**, the convention of the sibling
positional files, so "read a nodsig field" is one rule across the artifacts.

## The files

### `headers.bin`: 88 B per height, ascending, genesis at index 0

```
header record:
    header       80 bytes     // the block header, verbatim
    size         u32          // the raw block's length in bytes
    weight       u32          // BIP 141: 3 × base size + total size
```

The record of height *h* is at offset `(h - coverage.from) × 88`, and
`coverage.from` is 0 for any archive built by a full scan, so **index = height**.

`size` and `weight` are the two figures a header does not carry and no other
artifact here keeps: the graph records what a block *moved*, never what it
*cost*. Together they are the block-space series at 8 bytes a block, and both
are by-products of a parse that already walked every byte: the base size is
**measured** from the parser's own byte positions, never rebuilt by
re-serializing.

### `coinbase.bin` + `coinbase_off.bin`: the one thing nothing else keeps

`coinbase.bin` holds each block's **coinbase scriptSig**, verbatim,
concatenated; `coinbase_off.bin` holds one `u40` per height, the offset where
that height's script starts. The length of height *h* is the offset of *h+1*
minus its own, and the last one runs to the end of the file. It is the
positional idiom `tx_first_out.bin` already uses in
[OutpointIndex-v3](./OutpointIndex-v3.md), valid here for the same reason: every
coinbase scriptSig is at least two bytes by consensus, so the offsets **strictly
increase**.

Why this and not the whole coinbase transaction: its outputs are already tiles
in the graph, so storing them again would quadruple this archive to re-state
what we have. The **scriptSig** is the piece no artifact keeps and no derivation
brings back, since the graph excludes every scriptSig by design and the reveal
archive finds no key in a coinbase. It carries the BIP 34 height the block
claims for itself, the extranonce, and whatever the miner chose to write: the
genesis headline, the pool tags a mining census would need.

## What becomes repeatable offline

A scan checks four things about every block. This archive makes three of them
repeatable with no node and no network:

| | check | how |
|---|---|---|
| 1 | the bytes are the block they claim to be | `headers verify`: `sha256d` over the 80 bytes |
| 2 | each block extends the previous one | `headers verify`: every record's `prev_hash` must be the id of the record before it |
| 3 | the header commits to those transactions | `headers crosscheck --index`: recompute each Merkle root from the index's txids |
| 4 | the coinbase commits to the witness data | **not repeatable, ever**, from anything kept |

Check 4 commits to the wtxids, which hash the witness bytes, and the witness is
deliberately not archived (it is signatures; what matters in it, the revealed
keys, is what [RevealArchive-v2](./RevealArchive-v2.md) distills). Verifying it
again needs the raw blocks, which is another full pass. Stated here so that
"three of four" is never read as four.

Check 3 is also the strongest **binding** between two artifacts in this project:
it proves the index's transactions are exactly the ones the chain committed to,
in the order it committed to them.

**Proof of work is not checked**, and that absence is a different kind: it would
be easy (the id must be under the target `bits` encodes) but it would be a
consensus opinion, and this toolkit takes its chain from a node it runs beside.
What the archive attests is that these headers are a chain, and that they are
the ones the scan saw.

### The BIP 34 tally

`verify` and `fingerprint` also decode each coinbase scriptSig's leading push
and count how many declare the height they sit at. It is **reported, never
raised**: before BIP 34 was enforced a scriptSig could hold anything, and an
arbitrary one can decode as a plausible push of the wrong number. The real
genesis script does exactly that. Above the activation the declarations are
continuous, so a disagreement up there would say the file's positions have
slipped. The figure lands in `build.bip34` and in both reports.

## Watermark & manifest

`manifest.json` follows the shared shape in
[Artifact](../contracts/Artifact.md): an `identity` the fingerprint covers (the
tag `headers-v2`, the coverage `0..H`, the three file digests in the
order `headers, coinbase, coinbase_off`) and a `build` block that does not
(record counts, the last block id, the BIP 34 tally, the file names).

The coverage is **exact** for this format: one record per height means the
file's own length states the watermark, so `verify` derives it and refuses a
manifest claiming another. No ladders: every file is addressed by height, so
there is nothing to search and nothing to cache.

## Growth

Emitted by the `--headers` flag of `nodsig reuse scan` / `nodsig archive scan`,
hosted exactly like the graph plug: the archive it produces is the same bytes
whichever scanner hosted it. Two rules the emitter enforces rather than assumes:

- **it starts at genesis or not at all.** A fresh archive asks its host to feed
  height 0 first; an archive that would begin above genesis is refused, because
  the headers below it lie behind a pass that is already over. Genesis is fed to
  this emitter and to nothing else (its coinbase is unspendable by consensus, so
  it burns no lock, creates no edge, and reveals nothing);
- **append ≡ rebuild.** The three files only ever grow; `state.json` records the
  **committed** size of each and a resume cuts back to those sizes, so bytes
  written after the last checkpoint (the crash window) are truncated away and
  re-emitted. A scan stopped and resumed produces the same bytes, and therefore
  the same fingerprint, as a scan that ran through.

There is **no `rewind`**, and it would be trivial to add (truncate three files at
the right offsets); it is absent only because nothing has asked for one.

## Notes for porters

- A reader needs no other artifact: seek `height × 88`, and the 80 leading bytes
  are a header any Bitcoin library will parse.
- The block id is **recomputed**, never stored: a reader is not handed an id it
  did not derive itself.
- The median-time-past of a height is the median of the eleven timestamps ending
  at it. With an even count, which is only possible in the first ten blocks,
  take the **upper** middle, which is the element a node picks out of its sorted window,
  not the mean of the two middles.
