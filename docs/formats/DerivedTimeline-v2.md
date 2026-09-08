# DerivedTimeline-v2: format (L1)

One pass over the derivatives' history, folded into two small tables: the
balance bands at every checkpoint, and the creation/spend windows on a height
grid. It answers "how were the coins distributed at height H" and "coins
created in this window, when were they spent" without reading the index at
query time. Built by `derived timeline`, verified by `derived
timeline-verify`.

- **Directory** `<timeline>/`: `timeline_bands.csv`, `timeline_windows.csv`,
  `timeline.meta.json`; and, when a price table was given,
  `timeline_priced.csv`
- **Defined over** one sealed `outpoint-derived-v3` (the parent), read whole
- **Parent** the derivatives, declared in the meta under their own tag
- **Supersedes** `derived-timeline-v1`, whose identity depended on whether a
  price series was given: two runs over the same chain sealed two
  fingerprints. This release neither reads nor reproduces it.

What changed from v1, in one paragraph: the price is **outside the identity**.
The two chain tables are the same bytes with or without `--price`, and the
priced figures go to a third CSV that the meta describes under `build.price`
with the digest of the price table it came from; the meta is sealed like the
other artifacts, so the shared audit reads it; and the conventions the numbers
rest on are written in the meta, not only in prose.

## The two tables of chain data

`timeline_bands.csv`: `checkpoint,band_floor_sats,locks,sats`. At every
checkpoint of the grid, the locks holding a balance at or above each band
floor, and the satoshis they hold. A checkpoint counts balances **through**
its height, inclusive.

`timeline_windows.csv`:
`create_from,spend_from,outputs,sats,sat_heights_created,sat_heights_spent`.
Outputs created in the window `[create_from, create_from + grid)` and spent in
the window `[spend_from, spend_from + grid)`; a `spend_from` of zero holds
the outputs still unspent at the coverage height. The two `sat_heights`
columns are the coin-age created and destroyed, in satoshi-heights.

`unspent` is one row per output ever created and not spent by the coverage
height: it **includes** the two coinbases BIP30 overwrote (100 BTC that no key
can spend) and every provably unspendable output (`OP_RETURN`, and scripts no
key can satisfy), because the index records outputs and not their
spendability. The meta says so, and the summary prints the sentence beside
the number.

## The price table, outside the identity

`timeline_priced.csv`: `create_from,spend_from,sats_priced,cost_at_creation_usd`,
one row per cell of `windows`, in the same order, with the same two keys (the
join is by key, not by position), zeros where nothing had a price. Written in
the same pass when `--price <blockprice>` is given; absent otherwise. The
currency suffix on the column names says what the figures are expressed in.

It is an external input beside the artifact, not a part of it: the same
chain with another series is the same timeline with another third file.
`build.price` records the file, its digest, the block-price table's digest,
the series the table declares, and each series' `lookahead_s` (see
[`BlockPrice-v2`](BlockPrice-v2.md)): a reader of the priced figures is told,
in the meta and in every caption that quotes them, that a daily close applied
to its day is a number fixed up to 24 hours after the block.

## The meta

```
identity:  { format: "derived-timeline-v2", coverage: {from: 1, to: W},
             files: [ {name: "bands", sha256}, {name: "windows", sha256} ] }
fingerprint: the shared recipe
build:     { producer, seconds, wall,
             parent: { format: "outpoint-derived-v3", fingerprint },
             grid, checkpoints, rows,
             files: { bands: {file, sha256, rows}, windows: {file, sha256, rows} },
             totals: { distinct_locks, spent_outputs, unspent_outputs,
                       unspent_sats, coinage_destroyed_sat_heights },
             conventions: { checkpoint: "balances through the height, inclusive",
                            window: "[from, from + grid)",
                            unspent: "one row per output ever created; includes the
                                      two BIP30-overwritten coinbases and provably
                                      unspendable outputs" },
             price: null | { file, sha256, rows, digest, currency,
                             series: [ ...as the block-price table declares them,
                                       each with lookahead_s ],
                             sentence } }
```

`grid` is in `build`: a different grid produces different rows, so the
identity already covers it through the files' digests.

## Canonical fingerprint

The shared recipe of [`Artifact.md`](../contracts/Artifact.md), over the two
logical files `bands` and `windows`, in that order, with the tag
`derived-timeline-v2`. Same derivatives, same grid, same bytes, same
fingerprint, whether or not a price was given. The v1 fingerprints stay
historical numbers, reproducible with the release that wrote them.

## Building and rebuilding

One sequential pass over `history.bin` (about four hours on the whole chain
over a network mount: the pass is bound by the read, not by the arithmetic);
the pass writes all three tables at once. There is no append: the tables are
a function of the whole history, and the derivatives that grew are read
again. No rewind: rebuild from the derivatives, which have one.

## Verifying a sealed timeline

```sh
nodsig derived timeline-verify --timeline <dir> [--derived <dir>] [--price <blockprice>]
```

Sizes and digests of the two chain tables against the identity, the
fingerprint recomputed; the parent is declared until `--derived` confronts
it by fingerprint; with `--price`, the block-price table's digest against
`build.price.digest` and the third file's digest against
`build.price.sha256`. The pass itself checks that the spent rows it walked
equal the `spent_outputs` it declares.

## Constants, for a porter and for the test that pins this page

| name | value |
|---|---|
| identity files | `bands`, `windows`, in that order |
| `bands` columns | `checkpoint,band_floor_sats,locks,sats` |
| `windows` columns | `create_from,spend_from,outputs,sats,sat_heights_created,sat_heights_spent` |
| `priced` columns | `create_from,spend_from,sats_priced,cost_at_creation_<currency>` |
| window | `[from, from + grid)`; checkpoint inclusive |
| identity tag | `derived-timeline-v2` |
| parent tag accepted | `outpoint-derived-v3` |
