# HistoryBackend — contract

**Capability.** The complete payment history of a **lock** (an identical
scriptPubKey), computed **offline**, as of the index watermark: every output ever
paid to that lock, with its value, its receive height, and — if spent — the
spender and the spend height.

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [OutpointDerived-v2](../formats/OutpointDerived-v2.md)
  (`history.bin`) **plus** the bound [OutpointIndex-v3](../formats/OutpointIndex-v3.md)
  (heights are read from the index, not stored in `history.bin`).
- **Reference impl:** `Derived.rows` + the `history` command composition.
- **Depends on:** [IndexReader](./IndexReader.md) (for heights).
- **Backs:** the `history` CLI window; the address-history answer of the pocket
  knife (which adds address→lock decoding on top).
- **Types:** `u32`, `u64`, `digest20`, `Source`, `Status`, `Result<T>` — see
  [types](../types.md).

> **What a "lock" is.** `hash160` of the **full** scriptPubKey. It identifies an
> *identical lock*, **not** a wallet and **not** the same key under its other
> script faces. Address→lock decoding happens upstream (the `addr` codec), never
> here — this contract takes a `digest20`.
>
> **Binding invariant (MUST).** A HistoryBackend is bound to one
> OutpointDerived **and** its source OutpointIndex. The derived manifest's
> `source_index_fingerprint` MUST equal the index fingerprint; otherwise the
> pairing mixes coordinate systems and MUST be refused (never answered). This is
> a hard error, not a status.

## Source & status (every operation)

Every return carries `Source { id, watermark:u32, fingerprint:digest32 }`
where `fingerprint` is the **derived** artifact's canonical fingerprint (which in
turn names the index's, which names the graph's). Status:

- `OK` — answered. An **empty** history is a *definite negative* (`OK`, empty
  stream): the lock was never seen in confirmed history up to the watermark. It
  is not an error and not `UNDETERMINED`.
- `UNSUPPORTED` — a source that does not implement this capability.
- `UNDETERMINED` — not used by a sealed OutpointDerived (it is complete up to its
  watermark).

## Operations

### `history(lock: digest20) -> Result<stream<HistoryRow>>`

One row per output **ever paid to `lock`**, streamed in **output-ordinal order**
(which is chain order = receive time; strictly increasing, no ties).

```
HistoryRow = {
    output_ordinal: u64,     // the received output
    amount:         u64,     // its value, satoshis
    receive_height: u32,     // = IndexReader.height_of_output(output_ordinal)
    spender_tx:     u64?,    // tx ordinal that spent it; null ⇒ unspent at watermark
    spend_height:   u32?,    // = IndexReader.height_of_tx(spender_tx); null ⇔ spender_tx null
}
```

- `spender_tx` and `spend_height` are both null or both present (never one).
- Empty stream ⇒ lock unseen up to the watermark (definite negative, `OK`).
- Ordering is total and deterministic: by `output_ordinal` ascending.

### `events(lock: digest20) -> Result<stream<HistoryEvent>>` (derived view)

The didactic expansion of `history` used by the CLI window. Each `HistoryRow`
unfolds into:
- a `RECV` event at `receive_height` with `+amount`, and
- if spent, a `SPEND` event at `spend_height` with `-amount`.

```
HistoryEvent = { kind:{RECV,SPEND}, height:u32, amount:u64,
                 output_ordinal:u64, spender_tx:u64? }
```

Emitted in a **fully specified total order** so any implementation reproduces the
same sequence: sort by `(height ASC, output_ordinal ASC, rank ASC)` where
`rank(RECV)=0` and `rank(SPEND)=1`. (Rationale: a receive and its own spend can
never share a height in the wrong order — a coin is spent after it is created —
but two different events can share a height; the tie-break makes the sequence
deterministic regardless.)

## Invariants a re-implementation MUST hold

1. **Row order** is `output_ordinal` ascending; **event order** is the total
   order specified above — both deterministic and reproducible.
2. **Heights come from the bound index**, never fabricated:
   `receive_height = height_of_output(output_ordinal)`,
   `spend_height = height_of_tx(spender_tx)`.
3. **Unspent sentinel:** the on-disk `spender_tx = 0` means *unspent*; it MUST be
   surfaced as `null`, never as "spent by transaction 0".
4. **Binding checked** (fingerprints match) before any answer.
5. **Determinism & source** as above; empty = definite negative.

## Conformance vectors

`tests/fixtures/historybackend/` (to be added): a sealed derived+index pair over a
synthetic chain, and for chosen locks the expected `history` rows and `events`
sequence, plus an unseen lock (empty), a lock with a spent output, and a lock
with an unspent output. A port passes iff it reproduces every row/event in order
and the derived fingerprint.

## Notes for porters

- `history.bin` is sorted by `(lock, output_ordinal)`, so one lock's rows are a
  **contiguous** range: the reference loads the lock ladder (RAM), seeks one
  ~40 KB bucket, then scans forward while the lock matches. That is a performance
  strategy, not part of the contract — reproduce the *rows*, however you find
  them.
- Heights are **not** in `history.bin`; they are read from the index
  (`blocks.bin`, resident). A port must hold both artifacts.
- `amount` is duplicated here and in the index's `outputs.bin` on purpose (it
  makes per-lock scans sequential); either source is authoritative and they must
  agree.
