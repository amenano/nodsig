# PriceSeries-v1: format (L0, external input)

**Not an artifact.** A price series is a file a publisher made available,
converted into one canonical shape. Nothing on the chain can reproduce
it, so it carries a **digest** (the sha256 of the file) and never a
fingerprint. Why the toolkit admits such a file, and what it promises
about it, is in [`external-inputs.md`](../external-inputs.md).

- **Directory** `<series>/`: `series.csv`, `series.json`
- **Defined over** one external file, named in `series.json` under
  `origin`
- **Read by** `price build` (and `price series-verify`); any consumer goes
  through [`PriceSource`](../contracts/PriceSource.md)
- **Built by** `price import`, from a CSV or JSON file already on disk.
  The toolkit does not fetch from anyone: the node is its only network
  peer, and the series is yours to obtain under the publisher's terms

## `series.csv`

    ts,price
    1279324800,0.09
    1279411200,0.08
    ...

- one header line, exactly `ts,price`;
- `ts`: unix seconds, integer, **strictly ascending**. Two observations
  at the same second would be two answers to one question, so `import`
  keeps the first and the reader refuses a file where the rule is broken;
- `price`: a **positive, finite decimal in plain notation** (no exponent,
  no sign), with the digits the publisher gave. Trailing zeros are the
  publisher's precision and are kept. A zero or negative value is not an
  observation and is refused at import: keeping it would let "no price"
  hide as a number;
- LF line endings, no other columns, no comments. The digest is taken
  over these exact bytes, which is why the shape admits no variation.

## `series.json`

| field | meaning |
|---|---|
| `format` | `price-series-v1` |
| `currency` | the quote currency (`USD`); every series of one table must agree |
| `step` | nominal seconds between observations: 86400 for a daily series, 3600 for hourly |
| `stale_after` | seconds after which an observation stops answering (default three steps) |
| `rule` | the reading rule below, as a sentence |
| `rows`, `coverage.from`, `coverage.to` | what the file holds |
| `origin` | the publisher, the URL, the license, the original file name, the field mapping used, when it was fetched, a free note |
| `file`, `digest` | `series.csv` and its sha256 |
| `imported_at`, `producer` | when and by which tool version the conversion was made |

`origin` is what makes a figure citable without the code: a reader who
sees *coinmetrics-community, CC BY-NC 4.0, fetched 2026-08-21, digest
...* can fetch the same file and compare.

## The reading rule

The price valid at time `ts` is the **last observation with
`obs_ts <= ts`**, and only if `ts - obs_ts <= stale_after`. Otherwise
there is **no price**, and the consumer says so.

- never a look into the future: an observation after `ts` is not used
  even when it is nearer;
- never an interpolation;
- a daily series applies the price of day D to the whole of D, by
  construction of `obs_ts` (midnight UTC) and of the rule. That
  convention is what `step` declares, and consumers print it beside
  their figures;
- `stale_after` is the honest edge: a series that stopped, or has a
  hole, answers nothing past three steps rather than carrying a price
  forward silently. Consumers that want to carry forward do it
  themselves and label the result (`price daily` does, as `carried`).

## Importing

`price import` takes any CSV (fields by header) or JSON (fields by key,
or by index for lists, found under a dotted `--records` path), a time
field and its format (`unix`, `unix_ms`, or a strptime pattern read as
UTC), a price field, the `step`, and the publisher's name, URL and
license. A `--preset` pins a published file's mapping; every flag
overrides it. Rows with an empty price are skipped: it is how publishers
write "the market did not exist yet".

Two imports of the same publisher's file give the same digest. Two
fetches of "the same" series on different days may not: that is the
publisher's business, and `blockprice` reports it where it shows.
