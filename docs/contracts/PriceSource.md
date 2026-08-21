# PriceSource: contract

**Capability.** The price valid at a unix time, from an external series,
under one reading rule; or the explicit answer that there is none.

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [PriceSeries-v1](../formats/PriceSeries-v1.md).
- **Reference impl:** `priceseries.Series` and `priceseries.quote_first`;
  `blockprice.compute` is the one consumer in the tree.
- **Depends on:** nothing in the artifacts. A price is not a function of
  the chain, and this contract is the only door it enters through.
- **Types:** `u32` (unix seconds), decimal price, `str`: see
  [types](../types.md).

> **Not a reader contract.** This is not a question about the chain, so
> it does not speak the `Result<T>` envelope and carries no `Source`:
> there is no watermark and no fingerprint to put in one. What it carries
> instead is the series' **digest** and `origin`, which is what makes a
> fiat figure citable. See [external-inputs](../external-inputs.md) for
> why the two are never exchanged.
>
> **Why a contract at all.** Publishers change license, coverage and
> availability. Every analysis that wants a price asks this interface and
> never a publisher's CSV or API, so replacing the source is a new import
> mapping, not a change in any analysis.

## Operations

### `at(ts: u32) -> Quote | null`

The observation valid at `ts`: the **last** row with `obs_ts <= ts`,
provided `ts - obs_ts <= stale_after`. `null` when `ts` precedes the
series or the last observation is stale. Never an observation after
`ts`, never an interpolation, never a default.

`Quote { ts_used, price, currency, series, step }`: the observation's
time, its price as an exact decimal, the currency, the publisher's name,
and the series' nominal step (so a consumer can print the precision it
inherited).

### `coverage() -> (u32, u32)`

The first and last observation times.

### `declared(order) -> object`

What a consumer writes into its own metadata about this series as a
parent: order, publisher, digest, currency, step, stale_after, rows,
coverage, origin. A consumer that uses a price **must** record this for
every series it asked; a figure without it cannot be compared with
anyone else's.

### Composition: `quote_first(series[], ts) -> (order, Quote | null)`

Several series, asked in the consumer's declared order; the first that
answers wins, and its 1-based `order` is returned so the consumer can
record which one did. All series of one composition must share the
currency; the composition refuses otherwise.

## Implementing another source

Any file a publisher offers becomes a `PriceSeries-v1` through
`price import` (a field mapping, a step, an origin). A source that is not
a file (an exchange API) is **out of this contract by design**: the
toolkit's only network peer is the node. Fetch it with whatever tool you
trust, save the response, import the file. The digest then identifies
exactly what you fetched.
