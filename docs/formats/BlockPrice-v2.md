# BlockPrice-v2: format (L0, external input, derived)

**Not an artifact.** One price per block, derived from a sealed outpoint
index (a function of the chain) and one or more price series (which are
not). It carries a **digest** and declares its parents: the index by
fingerprint, each series by digest. The reasoning is in
[`external-inputs.md`](../external-inputs.md).

- **Directory** `<blockprice>/`: `blockprice.bin`, `blockprice.json`
- **Defined over** one sealed `outpoint-index-v3` (its `blocks.bin` header
  times) and an ordered list of `price-series-v2`
- **Read by** `price at`, `price daily`, `price verify`, `derived supply
  --price`, `derived timeline --price`; nothing in the artifacts reads it
- **Built by** `price build`, a read of the index's block table and of the
  series: seconds, no node
- **Supersedes** `blockprice-v1`: same `blockprice.bin`, same digest for the
  same inputs; the metadata now carries each series' look-ahead, and the
  parent index is confirmed by its identity, not by a string

## The record

Unchanged from v1: 9 bytes, big-endian, height `h` at record `h-1`:

| field | bytes | meaning |
|---|---|---|
| `price_micro` | 8 | the price times 1 000 000, rounded half-even, as `u64` |
| `series` | 1 | 1-based order of the series that answered; `0` = no price |

A record with `series = 0` has `price_micro = 0`, and one with `series > 0`
has `price_micro > 0`; `verify` refuses any other pairing.

## The rule

> price(h) = the last observation with `obs_ts <= header_time(h)`, from the
> first series in the declared order that answers.

Each series answers under its own reading rule
([`PriceSeries-v2`](PriceSeries-v2.md)). All series of one table share the
`currency`.

## `lookahead_s`: what the number could not have known at the block

For every series, from its `observation`:

| `stamp` | `kind` | `lookahead_s` |
|---|---|---|
| `period_start` | `close`, `mean`, `vwap` | `step` |
| `period_end`, or `instant` | any | 0 |
| any | `open` | 0 |
| any | `unknown` | null, printed as "unknown" |

A daily close stamped at midnight gives every block of that day a number
fixed up to 86,400 seconds later. The table records it; `price daily`,
`derived supply --price` and `derived timeline --price` print the sentence
beside their figures: *series N stamps a daily close at the start of its day;
a block's price may be a number fixed up to 24 hours after the block*. The
number is not shifted: shifting would move every published fiat figure away
from the literature's convention; a builder who wants a lag applies it to
the series and the digest says so.

## `blockprice.json`

| field | meaning |
|---|---|
| `format` | `blockprice-v2` |
| `kind` | `external input, derived` |
| `rule`, `record` | the sentences above |
| `currency` | the common currency of the series |
| `heights.from`, `heights.to`, `watermark` | 1, the index's height count, the index's watermark |
| `priced`, `priced_from` | how many heights have a price, and the lowest that does |
| `parents.index` | `{format, fingerprint, coverage}` of the index |
| `parents.series[]` | per series, in order: `order`, `publisher`, `digest`, `currency`, `step`, `stale_after`, `observation`, `lookahead_s`, `rows`, `coverage`, `origin` |
| `prefix` | `previous_heights`, `changed`, `changed_heights` (the first ten) |
| `file`, `digest` | `blockprice.bin` and its sha256 |
| `built_at`, `producer` | when, and by which tool version |

## Verifying

`price verify --blockprice <dir>` checks the digest, the record count, the
pairing rule, and that no `series` byte exceeds the declared list. With
`--index` and every `--series` in the declared order, it confirms the parent
index by **recomputing its identity** from its manifest (a manifest whose
`fingerprint` field was edited or copied does not pass), confronts each
series' digest and observation with the parents block, and recomputes the
whole table, which must match byte for byte. Without the parents it says
they are declared, not confirmed.

## The daily view

`price daily` is recomputed from the table and the index's header times,
per UTC day of the header time: `date,blocks,price,kind,gap_days,price_min,
price_max,series`, with `kind` in `measured`, `carried`, `none`, as in v1.
The CSV opens with comment lines naming the rule, the currency, the table's
digest, the index fingerprint, each series' digest and `lookahead_s`, and
the limit: *fiat figures depend on external series identified by digest; a
series fetched later may differ where its publisher corrected the past.*
