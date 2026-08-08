# CoSpendBackend — contract

**Capability.** What a transaction spent **together**: the set of outputs consumed
by one transaction (its inputs), each with value, lock and origin outpoint. This
is the **common-input hint** (Q2) — a hint about shared ownership, never a proof.

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [OutpointDerived-v3](../formats/OutpointDerived-v3.md)
  (`tx_inputs.bin`) + [IndexReader](./IndexReader.md) (values, locks, outpoints,
  heights) + [FeeBackend](./FeeBackend.md) semantics for the group fee.
- **Reference impl:** `Derived.inputs_of` + the `cospends` command composition.
- **Types:** `u32`, `u64`, `digest20`, `digest32`, `bool`, `Source`,
  `Status`, `Result<T>` — see [types](../types.md).

> **HINT, not proof (MUST be surfaced).** Outputs co-spent by one transaction
> usually share an owner, but **not always**: CoinJoin and collaborative spends
> break the assumption. Every answer of this capability MUST carry the
> common-input caveat; it is part of the contract, not decoration.
>
> **Binding invariant** (derived↔index fingerprints must match, else refuse):
> identical to [HistoryBackend](./HistoryBackend.md).

## Source & status

Every return carries `Source { id, watermark:u32, fingerprint:digest32 }`
(the derived fingerprint). Status:

- `OK` — answered, including definite negatives (`null`): a txid absent up to the
  watermark, or an outpoint that is unspent at the watermark (nothing was
  co-spent with it).
- `UNSUPPORTED` — a source that does not implement this capability.
- `UNDETERMINED` — not used by a sealed OutpointDerived.

## Operations

### `cospends(target: TxRef | OutpointRef) -> Result<stream<CoSpendGroup> | null>`

`target` is one of:
- **`TxRef`** = a **spending transaction**, given as `txid:digest32` (internal
  order) or `tx_ordinal:u64`.
- **`OutpointRef`** = `{ txid: digest32, vout: u32 }` — an outpoint whose
  **spender** is found first, then that spender's co-inputs are returned.

```
CoSpendGroup = {
    spender_tx:     u64,          // the spending transaction (ordinal)
    spender_txid:   digest32,
    height:         u32,          // spender's block height
    is_coinbase:    bool,         // true ⇒ inputs empty (spends nothing)
    fee_sats:       u64,          // = FeeBackend.fee(spender_tx)
    inputs: stream<{
        output_ordinal: u64,
        amount:         u64,      // satoshis
        lock:           digest20, // hash160 of the consumed output's scriptPubKey
        txid:           digest32, // origin outpoint (internal order)
        vout:           u32,
    }>,
    common_input_caveat: true,    // ALWAYS present; see the HINT note above
}
```

Resolution and result cardinality:
- **`TxRef`** ⇒ exactly **one** `CoSpendGroup` (or `null` if the txid is absent up
  to the watermark). A coinbase yields a group with `is_coinbase = true` and an
  empty `inputs` stream.
- **`OutpointRef`** ⇒ the group(s) of the outpoint's **spender(s)**:
  - unspent at the watermark ⇒ `null` (definite negative: nothing co-spent);
  - normally **one** spender ⇒ one group;
  - more than one spender is a `duplicate_spends` anomaly — **reported** (multiple
    groups), never hidden.
  - `vout ≥ n_out` for a present txid ⇒ **error** `INVALID_OUTPOINT` (the outpoint
    cannot exist), distinct from a valid negative.

## Invariants a re-implementation MUST hold

1. **The caveat is mandatory:** every group carries `common_input_caveat` and any
   presentation MUST show the common-input HINT meaning.
2. **Inputs are the exact set** consumed by the spender, read from
   `tx_inputs.bin` (sorted by `(spender_tx, output_ordinal)`); order within a
   group is `output_ordinal` ascending.
3. **Coinbase** ⇒ empty inputs, `is_coinbase = true`; it spends nothing.
4. **Anomalies reported:** more than one spender for an outpoint surfaces as
   multiple groups, never collapsed or dropped.
5. **Binding checked**, determinism, source; `null` = definite negative,
   `INVALID_OUTPOINT`/`OUT_OF_RANGE` = invalid query.

## Conformance vectors

`tests/fixtures/cospendbackend/` (to be added): expected groups for a normal
multi-input spend (values/locks/outpoints), a coinbase (empty), an
`OutpointRef` to a spent output, an `OutpointRef` to an unspent output (`null`),
an absent txid (`null`), and an `INVALID_OUTPOINT` — over a sealed derived pair,
with the derived fingerprint.

## Notes for porters

- `tx_inputs.bin` is sorted by `(spender_tx, output_ordinal)`, so one
  transaction's inputs are a contiguous range: one ladder bucket then a forward
  scan while `spender_tx` matches. Performance strategy, not contract.
- `amount`, `lock`, and the origin `(txid, vout)` of each consumed output come
  from the **index** (`output`, `outpoint_of`); `tx_inputs.bin` stores only
  `(spender_tx, output_ordinal)`.
