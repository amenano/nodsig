# IndexReader — contract

**Capability.** Resolve an outpoint `(txid, vout)` to an output ordinal, and read
the primitive output / transaction / height facts from a sealed **OutpointIndex-v2**.
This is the read side that every heavier capability builds on.

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [OutpointIndex-v2](../formats/OutpointIndex-v2.md) (L0).
- **Reference impl:** `Index` (readable Python).
- **Backs:** `HistoryBackend`, `CoSpendBackend`, `FeeBackend`, the `lookup` CLI;
  `ExposureLookup` is *not* built on this (it reads the reveal archive).
- **Types:** `u32`, `u64`, `digest20`, `digest32`, `Source`, `Status`,
  `Result<T>` — see [types](../types.md).

> **Byte order of `txid`.** All txids in this contract are in **serialized
> (internal) order** — the bytes as they appear in the transaction. Block
> explorers show the *reverse*. Reversing display↔internal is the caller's job,
> at the edge.
>
> **Ordinals.** `tx_ordinal` and `output_ordinal` are `u64` in this contract. On
> disk they are 40-bit; that is an L0 encoding detail, not part of this
> interface.

## Source & status (apply to every operation)

Every return is a `Result<T>` carrying `Source { id, watermark:u32,
fingerprint:digest32 }` — the sealed index's canonical fingerprint and its
`covered_through_height`. Status:

- `OK` — the index answered. The value may still be a *definite negative* (e.g.
  a txid not present up to the watermark): that is `OK` with `value = null`, not
  an error — the absence is a real answer at this watermark.
- `UNSUPPORTED` — the source cannot serve this operation at all (a foreign
  backend that does not implement it). A sealed OutpointIndex never returns this
  for the operations below.
- `UNDETERMINED` is **not** used by IndexReader: a sealed index is complete up to
  its watermark, so it never has to say "I don't know". (Downstream backends over
  partial data may.)

## Operations

### `resolve(txid: digest32) -> Result<{ first_out: u64, n_out: u24 } | null>`
The resolver. Returns the first output ordinal of the transaction and its output
count, or `null` if that txid never appeared in confirmed history up to the
watermark.
- **BIP30:** for a duplicated coinbase txid, resolves to the **latest** instance
  (the one that overwrote the earlier in the UTXO set).

### `output(output_ordinal: u64) -> Result<{ amount: u64, lock: digest20 }>`
- `amount` — value in satoshis.
- `lock` — `hash160` of the **full** scriptPubKey. This identifies an *identical
  lock*, not a wallet and not a key under its other script faces. **The lock
  *type* is not stored here** (it is not recoverable from the hash160); type
  lives on the reveal-archive side.
- **Error** `OUT_OF_RANGE` if `output_ordinal ≥ total_outputs`.

### `spenders(output_ordinal: u64) -> Result<stream<{ spender_tx: u64 }>>`
Transaction ordinals that spent this output. Empty ⇒ unspent at the watermark.
Under consensus at most one; more than one is a `duplicate_spends` anomaly —
**reported, never hidden**.

### `txid_of(tx_ordinal: u64) -> Result<digest32>`
Transaction ordinal → txid (serialized order).

### `tx_of_output(output_ordinal: u64) -> Result<{ tx_ordinal: u64 }>`
Which transaction created a given output ordinal.

### `outpoint_of(output_ordinal: u64) -> Result<{ txid: digest32, vout: u32, tx_ordinal: u64 }>`
The reverse walk: an output ordinal back to its `(txid, vout)`. Convenience over
`tx_of_output` + `txid_of`.

### `height_of_tx(tx_ordinal: u64) -> Result<u32>` · `height_of_output(output_ordinal: u64) -> Result<u32>`
Block height that contains the transaction / output.

### `time_of_height(height: u32) -> Result<u32>`
Block time (unix seconds) at a height, `1 ≤ height ≤ watermark`.

### `lookup(txid: digest32, vout: u32) -> Result<{ output_ordinal: u64, amount: u64, lock: digest20, height: u32, spent_by: u64? } | null>`
Composed convenience (the didactic "one outpoint, its whole story"):
`resolve` → check `vout < n_out` → `output_ordinal = first_out + vout` →
`output` + `spenders` + `height_of_output`.
- `null` if the txid is absent up to the watermark (`OK`, definite negative).
- **Error** `INVALID_OUTPOINT` if the txid is present but `vout ≥ n_out` — the
  outpoint cannot exist; refused loudly (distinct from a valid negative).
- `spent_by` present ⇒ the spender tx ordinal; absent ⇒ unspent at the watermark.
- Note: no `type` field — the lock type is not in the index (see `output`).

## Invariants a re-implementation MUST hold

1. **Determinism:** same index bytes → identical results; the index's canonical
   fingerprint identifies the source in every `Source`.
2. **Loud refusal, never silent:** `OUT_OF_RANGE` / `INVALID_OUTPOINT` raise;
   anomalies (`duplicate_spends`) are reported, not swallowed.
3. **Watermark honesty:** every answer is "as of `watermark`"; a negative is a
   negative *at that height*, and says so via `Source`.
4. **BIP30 last-wins** on duplicated txids in `resolve`.

## Conformance vectors

`tests/fixtures/indexreader/` (to be added): a small sealed OutpointIndex over a
synthetic chain plus a table of `(operation, args) → expected result` and the
index fingerprint. A port passes iff it reproduces every expected value and the
same fingerprint. Includes at least: a resolve hit and miss, an `OUT_OF_RANGE`,
an `INVALID_OUTPOINT`, an unspent and a spent output, and a BIP30 duplicate.

## Notes for porters

- The reference answers each question with **one targeted read**: `blocks.bin`
  resident in RAM (heights/times), a per-file **ladder** sampled every K keys
  held in RAM to turn a search into a single ~one-bucket `pread`. This is a
  *performance* strategy, **not** part of the contract — a port may resolve keys
  however it likes, as long as results and fingerprint match.
- Positional files (`txids`, `tx_first_out`, `outputs`) are pure `record i @
  offset i×width`; only `txid_index` and `spends` are sorted/searched. See the
  format doc for widths and ordering.
