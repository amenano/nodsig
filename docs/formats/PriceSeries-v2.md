# PriceSeries-v2: format (L0, external input)

**Not an artifact.** A price series is a file a publisher made available,
converted into one canonical shape. Nothing on the chain can reproduce it,
so it carries a **digest** (the sha256 of the file) and never a fingerprint.
Why the toolkit admits such a file, and what it promises about it, is in
[`external-inputs.md`](../external-inputs.md).

- **Directory** `<series>/`: `series.csv`, `series.json`
- **Defined over** one external file, named in `series.json` under `origin`
- **Read by** `price build` (and `price series-verify`); any consumer goes
  through [`PriceSource`](../contracts/PriceSource.md)
- **Built by** `price import`, from a CSV or JSON file already on disk. The
  toolkit does not fetch from anyone
- **Supersedes** `price-series-v1`: same `series.csv`, same digest; the
  metadata now says **what** each observation is and **when** its stamp
  falls, and a reader refuses a metadata that does not

What changed from v1, in one sentence: a daily close stamped at the start
of its day is a number fixed up to 24 hours after the blocks it is applied
to, and the v1 promised "never a look into the future" without a field that
could tell a close from an open; the promise is now true of the timestamps
and the field says what it is not true of.

## `series.csv`

Unchanged from v1:

    ts,price
    1279324800,0.09
    ...

one header line, `ts` unix seconds strictly ascending, `price` a positive
finite decimal in plain notation with the publisher's digits, LF line
endings, nothing else. The digest is taken over these exact bytes.

## `series.json`

| field | meaning |
|---|---|
| `format` | `price-series-v2` |
| `currency` | the quote currency; every series of one table must agree |
| `step` | nominal seconds between observations |
| `stale_after` | seconds after which an observation stops answering (default three steps) |
| `observation.kind` | `open` \| `close` \| `mean` \| `vwap` \| `spot` \| `unknown`: what the publisher's number is over the period |
| `observation.stamp` | `period_start` \| `period_end` \| `instant`: where `ts` falls relative to the period the number describes |
| `rule` | the reading rule below, as a sentence |
| `rows`, `coverage.from`, `coverage.to` | what the file holds |
| `origin` | the publisher, the URL, the license, the original file name, the field mapping used, when it was fetched, a free note; and where the publisher documents the observation kind |
| `file`, `digest` | `series.csv` and its sha256 |
| `imported_at`, `producer` | when and by which tool version |

`observation` comes from `price import` (`--observation-kind`,
`--observation-stamp`), or from a preset that pins them for a known
publisher's file; without a preset both are required, like the publisher.
A series that cannot say is `unknown`, which every consumer prints as such.

## The reading rule

The price valid at time `ts` is the **last observation with
`obs_ts <= ts`**, and only if `ts - obs_ts <= stale_after`. Otherwise there
is **no price**, and the consumer says so.

- never an observation stamped after `ts`, never an interpolation;
- a daily series applies the observation of day D to the whole of D. When
  that observation is a close (or a mean, or a volume-weighted price) stamped
  at the start of the day, the number was fixed at the end of the day: up to
  `step` seconds after a block of that day. The rule does not move the
  number, because the literature applies the day's price to the day; it
  **declares** the look-ahead, as `lookahead_s` in every table built from
  the series ([`BlockPrice-v2`](BlockPrice-v2.md)) and in every caption that
  quotes a fiat figure;
- `stale_after` is the honest edge: a series that stopped answers nothing
  past three steps rather than carrying a price forward silently.

## Importing

As in v1: any CSV or JSON, a time field and its format, a price field, the
`step`, the publisher's name, URL and license, and now the observation kind
and stamp. Two imports of the same publisher's file give the same digest.
