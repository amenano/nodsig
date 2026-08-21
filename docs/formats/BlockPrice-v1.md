# BlockPrice-v1: format (L0, external input, derived)

**Not an artifact.** One price per block, derived from a sealed outpoint
index (a function of the chain) and one or more price series (which are
not). It carries a **digest** and declares its parents: the index by
fingerprint, each series by digest. Two people reproduce it only if they
hold the same series, and the parents block is where they check that.
The reasoning, and the one design choice it rests on, is in
[`external-inputs.md`](../external-inputs.md).

- **Directory** `<blockprice>/`: `blockprice.bin`, `blockprice.json`
- **Defined over** one sealed `outpoint-index-v3` (its `blocks.bin`
  header times) and an ordered list of `price-series-v1`
- **Read by** `price at`, `price daily`, `price verify`, and any consumer
  that wants a fiat figure; nothing in the artifacts reads it
- **Built by** `price build`, a read of the index's block table and of the
  series: seconds, no node

## The record

9 bytes, big-endian, **height h at record h-1**, the positional rule of
the index's `blocks.bin` (genesis is not in the index, so the table
starts at height 1):

| field | bytes | meaning |
|---|---|---|
| `price_micro` | 8 | the price times 1 000 000, rounded half-even, as `u64` |
| `series` | 1 | 1-based order of the series that answered; `0` = no price |

A record with `series = 0` has `price_micro = 0`, and a record with
`series > 0` has `price_micro > 0`; `verify` refuses any other pairing.
Micro-units of the quote currency are exact for every price a publisher
realistically gives (six decimals), and an integer field keeps the
arithmetic of every consumer identical on every platform: the
conversion from the series' decimal string goes through `Decimal`, never
through a binary float.

## The rule

> price(h) = the last observation with `obs_ts <= header_time(h)`, from
> the first series in the declared order that answers.

Each series answers under its own reading rule (last observation not
older than its `stale_after`, see
[`PriceSeries-v1`](PriceSeries-v1.md)). The order is the builder's
declared choice, written in the metadata: a finer series before a
coarser one lets the hourly data answer where it exists and the daily
data fill the years before. The `series` byte records which one did, so
a consumer can separate the two regimes.

All series of one table must share the `currency`; the build refuses a
mix.

## `blockprice.json`

| field | meaning |
|---|---|
| `format` | `blockprice-v1` |
| `kind` | `external input, derived` |
| `rule`, `record` | the sentences above |
| `currency` | the common currency of the series |
| `heights.from`, `heights.to`, `watermark` | 1, the index's height count, the index's watermark |
| `priced`, `priced_from` | how many heights have a price, and the lowest that does |
| `parents.index` | `{format, fingerprint}` of the index |
| `parents.series[]` | per series, in order: `order`, `publisher`, `digest`, `currency`, `step`, `stale_after`, `rows`, `coverage`, `origin` |
| `prefix` | `previous_heights`, `changed`, `changed_heights` (the first ten): what a rebuild found when it compared itself with the file it replaced |
| `file`, `digest` | `blockprice.bin` and its sha256 |
| `built_at`, `producer` | when, and by which tool version |

## Rebuilding, and the prefix comparison

A table is rebuilt whole: it is 9 bytes per block and takes seconds, so
there is nothing to append. What a rebuild **must not** do is silently
absorb a change in its inputs. Before replacing the previous
`blockprice.bin`, `build` compares the common prefix record by record
and writes the number of heights whose record changed, and the first ten
of them, into `prefix`. A longer index with the same series changes
nothing below the old height; a series whose publisher corrected its
past changes the records of that past, and the metadata says so.

## Verifying

`price verify --blockprice <dir>` checks the digest, the record count
against the metadata, the pairing rule, and that no `series` byte
exceeds the declared list. With `--index` and every `--series` in the
declared order, it also confirms the index fingerprint and each series
digest against the parents block and **recomputes the whole table**,
which must match byte for byte. Without the parents it says they are
declared, not confirmed, the same sentence the artifacts use.

## The daily view

`price daily` is not stored: it is recomputed from the table and the
index's header times in well under a minute, and exists as a definition.
Per UTC day of the header time, dense from the day of height 1 to the
day of the last header:

    date,blocks,price,kind,gap_days,price_min,price_max,series

- `measured`: the simple mean of the priced blocks of the day, one
  weight per block, with the day's minimum and maximum and the series
  that answered;
- `carried`: no priced block that day; the last measured price, and how
  many days ago it was measured;
- `none`: before the first priced block. No number.

The CSV opens with comment lines that name the rule, the currency, the
table's digest, the index fingerprint, each series' digest, and the
limit: *fiat figures depend on external series identified by digest; a
series fetched later may differ where its publisher corrected the past.*
