# BalanceBackend — contract

**Capability.** The **offline** balance of a **lock** as of the index watermark:
how much it ever received, how much was spent, and what remains unspent. Computed
from confirmed history only — **no node is asked**.

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [OutpointDerived-v3](../formats/OutpointDerived-v3.md)
  (`history.bin`).
- **Reference impl:** `Derived.balance` (and the summary line of the `history`
  window).
- **Relation:** a reduction over the same scan as
  [HistoryBackend](./HistoryBackend.md); an implementation MAY compute both from
  one pass over the lock's rows.
- **Types:** `u32`, `u64`, `digest20`, `Source`, `Status`, `Result<T>` — see
  [types](../types.md).

> **Offline, not live.** This is the balance **at the watermark**, derived from
> sealed artifacts — reproducible by anyone. It is **not** the current balance:
> a live balance requires asking a node (that is a separate capability,
> `NodeClient`/`BalanceLive`, explicitly marked non-reproducible). Never conflate
> the two.
>
> **What a "lock" is** and the **binding invariant** (derived↔index fingerprints
> must match, else refuse): identical to [HistoryBackend](./HistoryBackend.md).

## Source & status

Every return carries `Source { id, watermark:u32, fingerprint:digest32 }`
(the derived fingerprint). Status:

- `OK` — answered, including the all-zeros answer for a lock never seen (a
  definite negative; `received = 0` distinguishes it from a seen-but-fully-spent
  lock, where `received > 0` and `unspent = 0`).
- `UNSUPPORTED` — a source that does not implement this capability.
- `UNDETERMINED` — not used by a sealed OutpointDerived.

## Operations

### `balance_at(lock: digest20) -> Result<{ received: u64, spent: u64, unspent: u64, unspent_count: u32 }>`

All amounts in satoshis, summed over every output ever paid to `lock`, as of the
watermark:

- `received` — Σ value of **all** outputs to the lock.
- `spent` — Σ value of the outputs that are **spent** at the watermark.
- `unspent` — Σ value of the outputs still **unspent**; `unspent == received − spent`
  (exact, integer).
- `unspent_count` — number of unspent outputs (the UTXO count for this lock).

Interpretation of edge cases (all `OK`):
- Lock never seen ⇒ `received = spent = unspent = 0`, `unspent_count = 0`.
- Lock fully spent ⇒ `received > 0`, `unspent = 0`, `unspent_count = 0`.

## Invariants a re-implementation MUST hold

1. **Identity:** `unspent == received − spent` and `unspent == Σ(value of rows
   with spender_tx == unspent-sentinel)`; the two roads MUST agree.
2. **Unspent sentinel:** on-disk `spender_tx = 0` means unspent; count/sum those.
3. **Offline semantics:** the answer is "as of `watermark`", carried in
   `Source`; it is not and must not be presented as a live balance.
4. **Binding checked**, determinism, source — as in HistoryBackend.

## Conformance vectors

`tests/fixtures/balancebackend/` (to be added): expected `balance_at` tuples for a
never-seen lock, a fully-spent lock, and a lock with mixed spent/unspent outputs,
over a sealed derived pair — with the derived fingerprint.

## Notes for porters

- One lock's rows are a contiguous range in `history.bin` (sorted by
  `(lock, output_ordinal)`); the whole balance is one sequential scan of that
  range — no index needed for the sums (only `history.bin`).
- Do **not** read the live UTXO set of a node to answer this; that would be a
  different, non-reproducible capability.
