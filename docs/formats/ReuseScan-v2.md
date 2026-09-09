# ReuseScan-v2: the lock set, the reuse bitmaps and the curve (L0)

The direct road to the reuse figure: `reuse prepare` distils the locks of a
UTXO snapshot into four sorted files, `reuse scan` walks the chain and burns
every lock whose key or script it sees revealed, and the burnt set, read
against the snapshot's amounts, is the table and the curve. The lock set
serves both roads; the scan is the second one, kept as the audit of the
archive's road (`ARTIFACTS.md`, "The second road"), and it reads the chain
with the archive's own classifier of revelations. This page holds
the five small formats of that road, each with its own tag: `locks-v2`,
`reuse-scan-v2` (the checkpoint state), `reuse-hits-v2` (the identity of a
burnt set), `reuse-stats-v2` (the JSON of `reuse stats`), and the sidecars
`reuse-curve-v2` and `archive-curve-v2` of the two curve CSVs.

- **Directories** `<locks>/` (prepare), `<checkpoint>/` (scan)
- **Defined over** one `dumptxoutset` snapshot, photographed at one block
- **Read by** `reuse scan`, `reuse verify`, `reuse stats`, `archive derive`,
  `archive crosscheck`, `curve deltas`, `curve dates`
- **Supersedes** `locks-v1`, `reuse-scan-v1`, `reuse-hits-v1`, which this
  release neither reads nor reproduces; the July checkpoint stays a
  historical number, reproducible with the release that wrote it

What changed, in one paragraph: the lock set knows the **height** of its
snapshot, the identity of a burnt set names the locks, the height and the
perimeter it was burnt under (so the one hex string that used to name two
incomparable answers cannot any more), the curve carries a sealed sidecar,
and the extraction follows the archive's v3 rules for what a revealed key is.

## `locks-v2`: the snapshot's locks

Four files, unchanged from v1 in their bytes: `locks_<type>.bin` for
`p2pkh`, `p2sh`, `p2wpkh`, `p2wsh` (`TYPE_ORDER`), each a sorted list of
records `hash | satoshis:u64 LE`, one per distinct lock, amounts summed over
the lock's unspent outputs; 28 bytes for the 20-byte types, 40 for `p2wsh`.
Locks of exposed-by-construction types (P2PK, P2TR) are not in the set.

The manifest changes:

```
identity:  { format: "locks-v2",
             coverage: { from: S, to: S },       // the set AFTER block S
             files: [ {name: "locks_p2pkh.bin", sha256}, ... in TYPE_ORDER ] }
fingerprint: the shared recipe
build:     { producer, seconds, wall, height_source: "headers" | "argument",
             base_hash: <display hex of block S>, snapshot_entries,
             types: { t: {records, satoshis} }, files, caches: {} }
```

The identity holds exactly what the shared recipe hashes: the tag, the
moment and the four digests. The base hash is declared in `build`, like the
parent of every other artifact: it is a claim the block confirms (the height
in the identity and the hash describe one block, and the first consumer that
sees the block checks the pair), and two lock sets distilled from the same
moment of the same chain hold the same bytes whatever hash was written beside
them.

The snapshot file carries the base block's hash and not its height; `prepare`
takes the height from one of two places, and refuses without one: `--headers
<dir>`, a scan of a sealed header archive for the record whose hash is
`base_hash` (seconds, offline, verified); or `--height S`, the number
`dumptxoutset` prints, taken as a claim and verified by the first consumer
that sees the block: `reuse scan` when it meets the snapshot's block, `derive`
when the archive's tip is that block. `prepare` never asks a node.

`reuse verify --locks` re-reads the four files against the manifest. Coverage
`S..S` keeps the manifest inside the shared audit without a special case.

## `reuse-scan-v2`: the checkpoint

`<checkpoint>/state.json`, written at every checkpoint after the four
bitmaps `hits_<type>.bin` (one bit per lock, in the lock file's order): the
`road` that wrote it (`scan`, or `derive` for the twin `archive derive
--checkpoint` writes), the locks it was made against (`locks`, by
fingerprint, and `locks_height`), the perimeter (`faces`, `cosigners`),
`last_height`, `last_block_hash`, `base_hash` and `base_seen_at` (the height
at which the snapshot's block was met, or null), the extraction counters, the
totals per type and the `reuse-hits-v2` fingerprint of the bitmaps. The scan
checkpoints on the grid exactly, block by block, so its rows land where
`derive --curve` lands them whatever the download batch size. The commit is two-phase (bitmaps under a pending
name, then the state, then the promotion), and one function decides which
set the state names when a kill fell between the phases, for the resume and
for `stats` alike. A checkpoint against other locks, another perimeter or a
shorter `--end` is refused by name.

The scan stops **at** the snapshot's block: past it, it would burn locks the
snapshot no longer holds and count coins that were never in it; short of it,
the figure is a floor, and the summary says which of the three it is.

## `reuse-hits-v2`: the identity of a burnt set

```
{ format: "reuse-hits-v2",
  locks: <locks-v2 fingerprint>,
  height: H,
  perimeter: { faces: bool, cosigners: bool },
  bitmaps: [ {type: t, sha256: sha256(hits_t)} for t in TYPE_ORDER ] }
```

hashed with the shared recipe, into which it maps as coverage `{H, H}` and six
logical files in this order: `locks` (its digest is the locks-v2 fingerprint),
`perimeter` (its digest is `sha256("faces=F,cosigners=C")` with `F` and `C`
as `0` or `1`), then `hits_p2pkh`, `hits_p2sh`, `hits_p2wpkh`, `hits_p2wsh`
(the sha256 of each bitmap). A logical file need not be a file; a porter
recomputes the hex from the recipe alone. The v1 hashed a tag and the four bitmap
digests: the same hex string then named the same answer at another height,
against another lock file by coincidence, and two incomparable answers under
two perimeters. A reader holding only the hex now holds the moment, the locks
and the reading it describes. The explicit comparisons of locks, height and
perimeter stay **before** the fingerprint comparison in `crosscheck`, so a
mismatch is diagnosed by name and never as "one of the two pipelines is
wrong".

The extraction of what burns a lock follows [`RevealArchive-v3`](RevealArchive-v3.md):
keys published in outputs, the other face of a point, x-only keys of a
taproot script path, hybrid forms, and the shape filter on script
candidates. The two roads share the classifier and the read-time perimeter
map and are written twice only in the walk, which is what the cross-check
checks; `OUT`, `OTHER_FACE` and `XONLY` count under the full perimeter and
add no perimeter flag.

## `reuse-stats-v2`: the JSON of `reuse stats`

The numbers `reuse stats` prints (order statistics per type, concentration,
Lorenz shares, the histogram bands), pinned to the `reuse-hits-v2`
fingerprint they were computed from, with the locks fingerprint, the
snapshot's height, the scanned height and the perimeter repeated beside it.

## The curve sidecars: `reuse-curve-v2`, `archive-curve-v2`

`curve.csv` (from `reuse scan` at every checkpoint, or from `derive --curve`)
keeps its columns: `height`, then `<type>_hits,<type>_satoshis` per type, then
the row's `reuse-hits-v2` fingerprint. What the CSV cannot say sits in
`curve.csv.meta.json`, sealed like blockstats and the timeline:

```
identity:  { format: "reuse-curve-v2", coverage: {from: 1, to: H},
             files: [ {name: "curve.csv", sha256} ] }
fingerprint
build:     { producer, road: "scan" | "derive",
             parent: {format: "reuse-scan-v2", fingerprint} or
                     {format: "reveal-archive-v3", fingerprint} or null,
             grid: every, locks: <locks-v2 fingerprint>,
             perimeter: {faces, cosigners}, rows, files, caches: {} }
```

The parent, the road, the grid, the locks and the perimeter are in `build`,
outside the identity: the two roads produce the **same** `curve.csv` and
therefore the same sidecar fingerprint, which the cross-check compares too
(`crosscheck --curve`), and every row of the CSV already carries the
`reuse-hits-v2` fingerprint of its own height, which names the locks and the
perimeter, so the CSV's digest commits to them. `reuse scan` rewrites the sidecar at every
checkpoint beside the state; a row the state named and a kill lost is
written back from the state on resume.

The same shape, without locks and without perimeter, seals `revelations.csv`
from `archive curve` under `archive-curve-v2`, with the archive as parent.
Its `points` column counts records without `UNCOMPRESSED` (so a point seen at
65 bytes, which holds two records, counts once) and its script columns count
scripts only, by the archive's filter.

## What the curve is, and is not

The rows of the reuse curve are a **survivorship** series on the snapshot: row
`H` counts, per type, the locks of the UTXO set at block `S` whose key was
already public at height `H`, with the satoshis those locks hold at `S`. The
last row is the reuse table. It supports "at `S`, at least X BTC sat behind
locks whose key was public", and "of today's spendable coins, this much was
behind a key public by height `H`". It does **not** say how reuse grew over
time: a lock reused and then emptied before `S` is in no row. The series of
first revelations per window, without a snapshot and without a perimeter, is
`archive curve`; the two answer different questions and both exist.

The curve is exact under the full perimeter only: a keys record carries one
first height, the minimum over every sighting, so under `--no-faces` or
`--no-cosigners` the intermediate rows of `derive` would date a burn by a
sighting the perimeter excludes. `derive --curve` refuses the combination;
`reuse scan` under a narrow perimeter produces the exact narrow curve, because
it burns as it reads.

## Constants, for a porter and for the test that pins this page

| name | value |
|---|---|
| `TYPE_ORDER` | `p2pkh`, `p2sh`, `p2wpkh`, `p2wsh` |
| lock record | `hash` (20, or 32 for `p2wsh`) then `satoshis` u64 little-endian |
| bitmap | one bit per lock, in the lock file's order, little-endian bytes |
| tags | `locks-v2`, `reuse-scan-v2`, `reuse-hits-v2`, `reuse-stats-v2`, `reuse-curve-v2`, `archive-curve-v2` |
| curve columns | `height`, `<t>_hits`, `<t>_satoshis` per type, `fingerprint` |
