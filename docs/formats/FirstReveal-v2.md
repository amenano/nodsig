# FirstReveal-v2: format (L0)

When a public key was first revealed, ordered by that moment. The reveal
archive ([`RevealArchive-v4`](RevealArchive-v4.md)) answers it one digest at
a time (a key's record carries its first height), but it cannot enumerate
*which* keys were first revealed inside a height range, because its records
are ordered by digest, not by time. This table materialises that one missing
order.

- **Directory** `<firstreveal>/`: `keys.bin`, `first_off.bin`, `state.json`,
  `manifest.json`
- **Defined over** one sealed, merged `reveal-archive-v4` `keys` partition,
  and no other
- **Read by** `firstreveal between` (and `stats`, `verify`)
- **Built by** `firstreveal build`, a read of the archive alone: no node, no
  graph, no index at build time
- **Parent** the archive it was built from (`reveal-archive-v4`), declared in
  the manifest under its own tag
- **Supersedes** `firstreveal-v1`, which this release neither reads nor
  reproduces

What changed from v1, in one paragraph: the height is no longer written on
every row. Rows are sorted by height, so the height of a row is a property of
its **position**, and a table of one offset per height replaces 3 bytes on
1.6 billion rows (13% of the file), the ladder, and the fusion an append
used to pay; the perimeter follows the archive's, so keys published in
outputs, the other face of a point and the x-only keys of a taproot script
path now have a row each.

## What the two files are

`keys.bin`: 20 bytes per row, one row per `keys` record of the parent
archive, the record's digest as the archive keys it, in ascending
`(first_height, digest)` order. No height field: the height is where the row
sits.

`first_off.bin`: one `u40` big-endian per height from 1 to the coverage `H`,
plus one closing entry, `H + 1` entries in all. Entry `i` (zero-based) is the
index of the first row whose first height is `i + 1`; entry `H` is the row
count. The rows first revealed at height `h` are `keys.bin[off[h-1] :
off[h]]`, a contiguous slice, empty when that height revealed nothing.

| file | record | entries | at height 957,301 |
|---|---|---|---|
| `keys.bin` | 20 B | one per revealed key | measured at the 2.0.0 run (v1 had 1,613,342,055 rows) |
| `first_off.bin` | 5 B | `H + 1` | 4.8 MB |

## A 1:1 map of the keys partition, and why the flags are dropped

Each 24-byte record of the archive's merged `keys` file emits exactly one
row: the digest kept, the height turned into a position, the flags byte
dropped. Nothing is filtered, so **rows always equal the parent's keys
records**, and `verify --archive` refuses a table where they do not.

The flags are dropped on purpose. They are OR-ed across **all** sightings, so
an append can add bits to them while the first height can only be joined by
later, higher ones: a table carrying the flags would have rows an append must
rewrite. This table carries exactly the field that never moves; a reader that
wants the modes asks the archive for that digest, the one road that already
answers it.

## What "first revealed" covers, and what it does not

The perimeter is the archive's `keys` partition, inherited whole:

- one row per **digest**, and the archive keys a point by the digest of its
  compressed form, adding the digest of another form the chain showed under
  `FLAG_OTHER_FACE`: a point seen at 65 bytes holds two rows, the compressed
  one at the same height. Which form a digest is, the archive's flags record;
  an address commits to one form, so address-driven readers never straddle
  the two;
- keys **published in outputs** (P2PK, bare multisig) have a row at the
  height of the output; keys seen **x-only** in a taproot leaf or control
  block have a row for `hash160(02 || x)`; a taproot key-path spend reveals
  nothing the output had not already published, and has no row;
- revealed **scripts are out**: they live in the archive's script partitions,
  which this table does not read;
- a key found inside a candidate script has a row whether or not the chain
  proved the candidate a script: the archive walks every candidate for keys,
  and a key pushed inside bytes that were not a script is still a key the
  chain published.

## Building it

One sequential pass over the archive's merged `keys` file (sorted by digest,
24-byte records). Each record emits `(first_height, digest)`; runs sort and
fuse into `(first_height, digest)` order with the shared run machinery, and
the offsets are written from the fused stream in one pass, counting rows per
height. The archive must be **merged with no pending runs**: a run not yet
fused holds sightings the merged file does not, and a table built beside it
would claim the archive's coverage while missing keys; the build refuses.

## Appendability

When the archive grows and re-seals, every row it adds has a first height
above the old coverage (a first height is a minimum, and an append only adds
higher heights; a key already in the table keeps its row). So the new rows
sort **after** every existing row, and an append is an append: the new rows
go to the end of `keys.bin`, the new heights to the end of `first_off.bin`
after its closing entry is moved. No fusion, no re-emission of the old rows.
**Appending equals rebuilding**, byte for byte, because the file is the
concatenation of per-height slices in height order whichever pass wrote
them. The parent's coverage must extend the table's; a parent that went back
or changed at the same height is refused as a rebuild.

## No rewind, and why

The parent has none: the archive's records OR their sighting flags across
the whole scan, and un-seeing a sighting is not expressible there. A table
that follows a parent which can only move forward has nothing to rewind to.

## Canonical fingerprint

The shared recipe of [`Artifact.md`](../contracts/Artifact.md), over the two
logical files `keys` and `first_off`, in that order, with the tag
`firstreveal-v2`. Coverage is `1..H`, the parent archive's coverage; the
parent fingerprint is declared in `build`, outside the identity, and `verify
--archive` **refuses** a mismatched parent. Both files are in the identity:
the offsets are not a cache, they are the height column in another shape,
and a reader with the wrong offsets reads the wrong keys.

## Reading it

`firstreveal between --from A --to B`: two reads of 5 bytes give
`off[A-1]` and `off[B]`, then one contiguous read of `(off[B] - off[A-1])`
rows. No bisect, no ladder, no walk past the window. A window past the
coverage is refused, and the footer names the coverage.

## Verifying a sealed table

```sh
nodsig firstreveal verify --firstreveal <firstreveal> [--archive <archive>]
```

The shared audit compares each file's size with what the seal names, re-reads
every byte against the manifest, recomputes the fingerprint; then two checks
specific to this table:

- **structural**, over the whole file: `first_off` non-decreasing with its
  closing entry equal to the row count and its length equal to `H + 1`;
  inside every height slice the digests strictly increasing;
- **against the other road** (with `--archive`): the row count must equal the
  keys records the parent seals, and, for `k` rows drawn from the file, the
  height of the slice each row sits in must equal what the archive's own
  lookup reports for that digest. It is the only check that confronts this
  artifact with something it did not build itself.

## Constants, for a porter and for the test that pins this page

| name | value |
|---|---|
| `keys` row | 20 B, the archive's key digest |
| `first_off` entry | u40, big-endian, `H + 1` entries |
| order | `(first_height, digest)` ascending, heights from 1 |
| identity files | `keys`, `first_off`, in that order |
| identity tag | `firstreveal-v2` |
| parent tag accepted | `reveal-archive-v4` only |

## Notes for porters

- a height's slice is `[off[h-1], off[h])`; heights start at 1, so entry 0
  is height 1 and the table has no row for the genesis block;
- rows equal the parent's keys records, always: any filtering you are
  tempted to add belongs in a reader, not here, or the 1:1 audit is lost;
- a row means "this digest's first sighting", not "this lock was spent"
  (that is [`FirstSpend-v1`](FirstSpend-v1.md)) and not "these are all the
  exposure modes" (that is the archive's flags).
