# FeeBackend — contract

**Capability.** The **fee** actually paid by a confirmed transaction, in
satoshis, read in O(1) — with coinbase transactions reported as such (they create
coins and pay no fee).

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [OutpointDerived-v2](../formats/OutpointDerived-v2.md)
  (`fees.bin`, positional).
- **Reference impl:** `Derived.fee` + the `fee` command composition.
- **Depends on:** [IndexReader](./IndexReader.md) (to resolve a txid to its tx
  ordinal, and to tell coinbase from non-coinbase via inputs).
- **Types:** `u64`, `digest32`, `bool`, `Source`, `Status`, `Result<T>` — see
  [types](../types.md).

> **Absolute fee, not a rate.** The answer is the fee in **satoshis**
> (Σ input values − Σ output values). A fee **rate** (sat/vByte) needs transaction
> sizes, which the graph deliberately excludes; it is a future derived scan, never
> a silent estimate here.
>
> **Binding invariant** (derived↔index fingerprints must match, else refuse):
> identical to [HistoryBackend](./HistoryBackend.md).

## Source & status

Every return carries `Source { id, watermark:u32, fingerprint:digest32 }`
(the derived fingerprint). Status:

- `OK` — answered, including the "not found" negative (a txid absent from
  confirmed history up to the watermark ⇒ value `null`) and the coinbase case.
- `UNSUPPORTED` — a source that does not implement this capability.
- `UNDETERMINED` — not used by a sealed OutpointDerived.

## Operations

### `fee(tx: digest32 | u64) -> Result<{ fee_sats: u64, is_coinbase: bool } | null>`

`tx` is either a **txid** (`digest32`, serialized/internal order) or a **tx
ordinal** (`u64`). Resolution:

1. If `tx` is a txid: resolve it via the index (`resolve` → `tx_of_output`) to a
   tx ordinal. If the txid is **absent** up to the watermark ⇒ return `null`
   (`OK`, definite negative).
2. If the transaction has **no inputs** (coinbase — the only no-input case under
   consensus) ⇒ `{ fee_sats: 0, is_coinbase: true }`.
3. Otherwise ⇒ `{ fee_sats: fees[tx_ordinal], is_coinbase: false }`, read
   positionally from `fees.bin`.

Notes:
- `is_coinbase` distinguishes a coinbase (structurally no fee) from a hypothetical
  genuine zero-fee transaction; do not collapse them.
- A tx ordinal out of range (`≥ total_transactions`) is an **error**
  (`OUT_OF_RANGE`), not a `null` — a null is reserved for a valid txid lookup
  that found nothing.

## Invariants a re-implementation MUST hold

1. **O(1) positional read** of `fees.bin` for the fee (record = `tx_ordinal`,
   8 bytes, big-endian u64); coinbase ⇒ 0.
2. **Coinbase test** is "has no inputs" (via `inputs_of`/`tx_inputs`), not "fee ==
   0": report `is_coinbase` accordingly.
3. **Absolute satoshis only**; never emit or imply a fee rate.
4. **Binding checked**, determinism, source; `null` = definite negative,
   `OUT_OF_RANGE` = invalid ordinal.

## Conformance vectors

`tests/fixtures/feebackend/` (to be added): expected results for a normal
transaction (known fee), a coinbase, an absent txid (`null`), and an out-of-range
ordinal (`OUT_OF_RANGE`), over a sealed derived pair — with the derived
fingerprint.

## Notes for porters

- `fees.bin` is purely positional: `fee_sats = u64_be(fees.bin[tx_ordinal*8 : +8])`.
  No search, no ladder.
- Telling coinbase from non-coinbase requires the spend side (`tx_inputs.bin` /
  `inputs_of`), i.e. the same derived artifact; the value 0 in `fees.bin` alone is
  not sufficient to claim "coinbase".
