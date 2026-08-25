# FirstReveal-v1: format (L0)

When a public key was first revealed, ordered by that moment. The reveal
archive ([`RevealArchive-v2`](RevealArchive-v2.md)) answers it one digest at
a time (`archive lookup` reads a key's sighting and the first height is in
it), but it cannot enumerate *which* keys were first revealed inside a
height range, because its records are ordered by digest, not by time. This
table materialises that one missing order.

- **Directory** `<firstreveal>/`: `firstreveal.bin`, its ladder,
  `state.json`, `manifest.json`
- **Defined over** one sealed, merged `reveal-archive-v2` `keys` partition,
  and no other
- **Read by** `firstreveal between` (and `stats`, `verify`)
- **Built by** `firstreveal build`, a read of the archive alone: no node,
  no graph, no index at build time
- **Parent** the archive it was built from (`reveal-archive-v2`), declared
  in the manifest under its own tag, never under the one the building code
  happens to emit

## What one record is

23 bytes, big-endian throughout, one row per **revealed key**:

| field | bytes | meaning |
|---|---|---|
| `first_height` | 3 | the lowest height the key's digest was ever seen at, exactly the archive's own field |
| `key` | 20 | `hash160` of the serialized public key, exactly as the archive keys it |

Rows are sorted by `(first_height, key)`. The search key is `first_height`
alone (3 bytes); `key` orders ties so the file is a total order and two
builds cannot disagree.

## A 1:1 map of the keys partition, and why the flags are dropped

The build is deliberately the simplest in the project: each 24-byte record
of the archive's merged `keys` file emits exactly one row — the trailing
height moved to the front, the digest kept, the flags byte dropped. Nothing
is filtered, so **rows always equal the parent's keys records**, and
`verify --archive` refuses a table where they do not.

The flags are dropped on purpose, not for the byte. They are OR-ed across
**all** sightings, so an append can add bits to them while the first height
can only be joined by later, higher ones: a table carrying the flags would
have rows an append must rewrite, and appending would stop equalling
rebuilding. This table carries exactly the field that never moves; a reader
that wants the modes asks the archive for that digest, the one road that
already answers it.

## What "first revealed" covers, and what it does not

The perimeter is the archive's `keys` partition, inherited whole:

- a **key in its serialized form**: the 33-byte and the 65-byte
  serializations of one secp256k1 point hash to *different* digests, so one
  point can hold two rows. Which form a digest is, the archive's
  `FLAG_UNCOMPRESSED` records; an address commits to one form, so
  address-driven readers never straddle the two;
- revealed **scripts are out**: they live in the archive's `scripts20` and
  `scripts32` partitions, which this table does not read. A P2SH/P2WSH
  address's revelation is a script revelation, not covered here;
- **taproot is out**: the extraction collects 33- and 65-byte key shapes;
  an x-only key is not a record, because in taproot the key is the output
  itself and "revelation by spending" is not its exposure model;
- the archive **over-collects harmlessly** (a byte string shaped like a key
  is stored by digest, and a stored digest can only match a lock that is
  its exact preimage), and this table inherits those records too: rows are
  the archive's records, not a judgement about them.

## Size

One row per revealed key, at 23 bytes. On the chain through height 957,301
that is **1,613,342,055 keys**, so **~37.1 GB**, measured on the sealed
archive rather than projected. A porter sizing a disk should scale by the
keys records, which the archive's manifest reports.

## Building it

One sequential pass over the archive's merged `keys` file (sorted by
digest, 24-byte records `digest20 | flags | first_height`). Each record
emits `(first_height, key)`; runs then fuse into the sorted file with the
shared run/merge machinery, and the seal is taken over it. The archive must
be **merged with no pending runs**: a run not yet fused holds sightings the
merged file does not, and a table built beside it would claim the archive's
coverage while missing keys — the build refuses, exactly as firstspend
refuses an unsealed derivatives directory.

## Appendability

When the archive grows and re-seals, the table is rebuilt from the grown
`keys` file. A key already in the table keeps its row unchanged (a first
height is a minimum, and an append only adds higher heights) and a key new
to the archive enters with its genuine first height, always above the old
coverage. Rows are a function of `(first_height, key)` alone, so the pass
re-emits every old row byte-identically and the fusion collapses the exact
duplicates: **appending equals rebuilding**, byte for byte.

## No rewind, and why

The parent has none: the archive's records OR their sighting flags across
the whole scan, and un-seeing a sighting is not expressible there — its
format documents this as a measurement, not an omission. A table that
follows a parent which can only move forward has nothing to rewind to;
giving it a rewind verb would promise a parent state that cannot exist.

## Canonical fingerprint

The shared recipe of [`Artifact.md`](../contracts/Artifact.md), over the
one logical file `firstreveal`. Coverage is `1..H`, the parent archive's
coverage; the parent fingerprint is declared in `build`, outside the
identity, and `verify --archive` **refuses** a mismatched parent, because
these rows restate the parent's sightings and pairing them with another
archive answers nonsense with confidence.

## Verifying a sealed table

```sh
nodsig firstreveal verify --firstreveal <firstreveal> [--archive <archive>]
```

The shared audit re-reads every byte against the manifest, rebuilds the
ladder from the file, recomputes the fingerprint, and confronts the
declared coverage with the highest height the rows carry (a **floor**: a
stretch of chain with no new revelation leaves no trace above it). Then two
checks specific to this table, the second being the one a checksum cannot
make:

- **structural**, over the whole file: rows strictly increasing by
  `(first_height, key)`, and every height inside the declared coverage;
- **against the other road** (with `--archive`): the row count must equal
  the keys records the parent seals — the build is a 1:1 map, so a single
  missing or invented row breaks the equality — and, for `k` keys drawn
  from the file, the height recorded must equal what the archive's own
  ladder-backed lookup reports for that digest. It is the only check that
  confronts this artifact with something it did not build itself.

Passing `--archive` confronts the declared parent instead of trusting it.

## Notes for porters

- everything is big-endian, including the 3-byte `first_height` — the
  archive's own height width, good through height 16,777,215;
- the sort key is `first_height`; `key` breaks ties but is not part of the
  ladder's search. The ladder entry point is the rightmost sample strictly
  below the key, because many keys share one height (a heavy block first
  reveals thousands), so a group can exceed the ladder stride and the walk
  must start below it and read the whole run;
- rows equal the parent's keys records, always: any filtering you are
  tempted to add (drop the over-collected shapes, drop a form) belongs in a
  reader, not here, or the 1:1 audit is lost;
- a row means "this digest's first sighting", not "this lock was spent"
  (that is [`FirstSpend-v1`](FirstSpend-v1.md)) and not "these are all the
  exposure modes" (that is the archive's flags).
