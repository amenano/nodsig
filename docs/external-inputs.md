# External inputs: files the chain cannot reproduce

Everything else in this repository is a function of the chain. Give two
people the same blocks and the same height and they build the same bytes,
which is what a fingerprint states and what `verify` recomputes. This page
is about the one family of files for which that sentence is false, why
the toolkit admits them anyway, and what it promises about them instead.

## What an external input is

An **external input** is a file with a format this project promises
stability on, which **nobody here can rebuild from the chain**. There are
already two in [`formats/`](formats/): the address book, which `check`
reads and a person writes, and the check report, which `check` writes and
nothing reads back. The format matrix in [`ARTIFACTS.md`](ARTIFACTS.md)
labels them `(input)` and `(output)` for that reason.

A **price series** is the third, labelled `(external input)`: a file a
publisher made available, converted into one canonical shape so that every
consumer reads it the same way. And the **block price** table built from
it is labelled `(external input, derived)`: it depends on the outpoint
index, which is a function of the chain, and on the series, which is not.

The rule that follows is short. **An artifact carries a fingerprint; an
external input carries a digest.** The two words are never exchanged:

| | artifact | external input |
|---|---|---|
| what it is a function of | the chain up to a height | a file somebody published |
| who can rebuild it | anyone with a node | only someone holding the same file |
| how it is identified | `fingerprint`, recomputed by `verify` | `digest`, the sha256 of the file |
| what two matching values mean | the same history | the same file |
| what a mismatch means | different chain, height or format | a different file; the cause is not knowable from here |

A digest is still worth having. Two readers holding series with the same
digest will get the same fiat figures to the last micro-unit, and two
readers whose figures differ can check the digests first and know in one
line whether they are even comparing the same input.

## The limit, printed beside the numbers

The sealed series is **not redistributed** with this repository: the
publishers' licenses (the one preset here is CC BY-NC 4.0) do not allow
it, and a copy would only move the problem. So a reader who wants to
check a fiat figure fetches the series themselves, imports it, and
compares. Two outcomes are possible and both are informative:

- the digests match, and every figure reproduces;
- the digests differ, and some figures do not. The publisher may have
  corrected its past, changed its methodology, or filled a gap; or the
  conversion may differ. **Nothing in this toolkit can tell which**,
  because it never saw the other file.

That second case is not a defect to hide. It is the limit, and it is
printed where the numbers are: every `blockprice` table and every daily
CSV carries the digest of each series it rests on and this sentence:
*fiat figures depend on external series identified by digest; a series
fetched later may differ where its publisher corrected the past.* A
rebuild over an existing table also compares its prefix with the previous
bytes and writes the count of changed heights into the metadata
(`prefix.changed`), so a rewritten past is a number a reader sees, never
something silently absorbed.

## One price per block

This is the one design choice of the price layer, and it follows from how
the rest of the toolkit keeps time.

**The clock of every artifact is the height.** A transaction is placed by
its ordinal, a lock's history by the heights of its events, a series by
the block it falls in. The only bridge the chain certifies towards
calendar time is the **header timestamp**: declared by the miner, held by
consensus only to within hours (it must exceed the median of the previous
eleven and may not run more than two hours ahead of the network), and not
monotonic from one block to the next.

So **the chain does not know when a transaction happened**. It knows which
block it sits in, and roughly when that block was made. Pricing a
transaction "at the minute it was broadcast" invents an instant nobody
certified, and pricing it at an exchange's daily close picks one venue's
bookkeeping over the chain's. The finest price that can be assigned
honestly is the **price of the block**, and every transaction in the block
shares it:

> price(h) = the last observation with `obs_ts <= header_time(h)`, from
> the first series in the declared order that answers.

Never a look into the future (an observation after the header time is not
used even if it is closer), never an interpolation, and "no price" when no
series answers, written as such. The precision is **hours**, because that
is the precision of the timestamp, and the `step` of the series that
answered travels with every figure.

Three consequences, which are the reason to materialise the table rather
than look prices up ad hoc:

1. **Every fiat figure is computed block by block and aggregated after.**
   Fees of an epoch in USD are the sum over its blocks of fee(h) times
   price(h). There is no intermediate "price of the day" in that sum.
2. **The daily view is an aggregation, not a close.** `price daily` is the
   simple mean of the block prices whose header falls in a UTC day, one
   weight per block. It does not coincide with any exchange candle and is
   not meant to: it is the price as the chain saw it, the one consistent
   with every other per-block number here. Value-weighted figures are
   computed per block, never through a day price.
3. **Every value carries its kind.** A day is `measured` (it had priced
   blocks), `carried` (none were priced, so the last measured price is
   carried forward, with the number of days since), or `none` (before the
   first observation, where no number is invented). A reader can drop the
   carried rows, or keep them knowing what they are; the CSV never lets
   the two look alike.

Before the first observation of any series there is **no price**, and the
blocks of that era are counted apart in any aggregation. The earliest
daily series commonly available starts in mid 2010; the chain starts in
January 2009. That gap is a fact about the sources, and it stays visible.

## What goes where

- [`formats/PriceSeries-v1.md`](formats/PriceSeries-v1.md): the canonical
  series, its `series.json`, and the reading rule.
- [`formats/BlockPrice-v1.md`](formats/BlockPrice-v1.md): the 9-byte
  record, the parents block, the prefix comparison.
- [`contracts/PriceSource.md`](contracts/PriceSource.md): the one question
  a consumer may ask (`at(ts)`), so that the source stays replaceable.
- [`build-and-query.md`](build-and-query.md), section 6b: the commands.

Every command and every column that rests on a price says so: *requires a
price series*. Nothing in the artifacts, their fingerprints or their
verification changes when a series is present or absent.
