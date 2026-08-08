# OutpointDerived-v2: format (L0)

The three spend-side derivatives of the outpoint index: a lock's payment
**history**, every transaction's **fee**, and the **co-spend** reading. Everything
is derived from [OutpointIndex-v3](./OutpointIndex-v3.md) alone — no node, no
graph. Read by [HistoryBackend](../contracts/HistoryBackend.md),
[BalanceBackend](../contracts/BalanceBackend.md),
[FeeBackend](../contracts/FeeBackend.md),
[CoSpendBackend](../contracts/CoSpendBackend.md).

- **Directory** of three record files + ladders + `state.json` + `manifest.json`.
- **Defined over:** an OutpointIndex-v3. The one it was actually built from is
  **declared** in `build.parent`, outside the fingerprint.
- **Captures:** per lock, its history rows; per transaction, its fee; per input,
  its co-spend grouping. **Does not capture:** heights, which a reader gets from
  the parent index.
  A reader still **refuses** a mismatched index: these files are keyed by the
  parent's ordinals, so pairing them with another one answers nonsense with
  confidence. See the binding invariant in [INVARIANTS](../INVARIANTS.md).

## Endianness

**Big-endian** everywhere (same rule and reason as the index).

## The three files

| file | width | order | layout |
|---|---|---|---|
| `history.bin` | 38 | sorted by `(lock, output_ordinal)`; key = `lock` (20) | `lock:digest20` \| `output_ordinal:u40` \| `spender_tx:u40` \| `value:u64` |
| `tx_inputs.bin` | 10 | sorted by `(spender_tx, output_ordinal)`; key = `spender_tx` (5) | `spender_tx:u40` \| `output_ordinal:u40` |
| `fees.bin` | 8 | positional by `tx_ordinal` | `fee:u64` (satoshis) |

- **`history.bin`** — one row per output **ever created**: who received it (the
  lock), when (the ordinal = chain time), whether/by whom it was spent, and its
  value. One row carries **both** events (receive and spend); a reader emits them
  as two (see [HistoryBackend](../contracts/HistoryBackend.md)).
- **`tx_inputs.bin`** — the spend side re-sorted by the **spender**: every
  transaction's inputs, adjacent (the co-spend reader; the inverse of the index's
  `spender_of.bin`, which is keyed by the output).
- **`fees.bin`** — `fee = Σ inputs − Σ outputs`; **0** for a coinbase (the only
  no-input case under consensus). O(1) positional read.

## UNSPENT sentinel

`spender_tx = 0`. Tx ordinal 0 is the first transaction of block 1 — a coinbase,
which can never spend — so `0` is unambiguous and **sorts below** every real
spender: an append updating a row from unspent to spent wins the "keep the last of
an equal key" rule by construction (the same mechanism as BIP30 in the index).

## Appending: which cursors survive a source-index fusion

A build cycle resumes from plain record counts into the source index, but the
three files it reads do **not** age alike, and a porter must not treat them
alike:

- `outputs.bin` and `tx_first_out.bin` are **append-only** — an ordinal is
  theirs forever — so a record offset means the same thing across index
  generations and is kept as is;
- `spender_of.bin` is positional too, and its slots never move — slot `i` is
  output `i` forever. **That does not make its cursor reusable across cycles**,
  and this is the one thing to get right here, because the obvious reading of
  the sentence above is wrong.

  Under `outpoint-index-v2` the spend side was `spends.bin`, re-sorted at every
  index fusion, so an offset into the old generation named a different record in
  the new one. That was the stated reason for re-reading from zero, and with
  `spender_of.bin` **that reason is gone**. The conclusion is not: a new block
  spending an old output **mutates a slot BELOW the cursor**, so the walk still
  has to start at slot 0. The reason changed, the rule did not. Anyone who reads
  only the old justification will remove the re-read and be confident about it.

A cycle therefore walks `spender_of.bin` from slot 0 and keeps the edges whose
**spender** is one of its own transactions (spender ≥ the cycle's first tx
ordinal). That is an exact partition — every edge belongs to the cycle that
scanned its spender, an old transaction can never gain an input, and a
transaction's inputs never change — and it costs one sequential pass per append,
now over 5 bytes per output instead of 10 bytes per edge. Within a cycle the
cursor is valid again (nothing moves under it), so a crash still resumes
mid-file; it is reset only when a cycle opens, the one moment the generation can
have changed underneath it.

A slot carrying the **more-than-one-spender marker** stops the build: the index
records that anomaly and counts it, and derivatives are built on
publication-grade sources only. Same refusal as before, at the same layer,
reading a different shape.

## Rewinding: the same asymmetry, read backwards

Coming back to a height already covered is the mirror of the above, and the file
list splits the same way. `tx_inputs.bin` and `fees.bin` are ordered by spender
and by transaction, both of which only ever grow, so what goes is a **tail**: a
truncation to the counts the source index holds. `history.bin` is ordered by
lock, so what goes is scattered through it, and it is **re-fused through a
sift** — the ordinary fusion with the current generation as its only source.

One row needs more than dropping. A row whose `spender` is a transaction above
the cut records a spend that, at the target height, had not happened: its five
spender bytes go back to `UNSPENT` and its **value stays**, because the value is
the output's and is present whether or not it was spent (see the record layout
above). The key does not change and neither does the order, which is what makes
this legal inside a fusion.

Both totals are then **recomputed, not carried**: Σ inputs from the surviving
spent rows, Σ fees from the truncated `fees.bin`. The seal's cross-check is
therefore a real test of the rewind rather than a formality — the two roads are
re-walked, and a sift that dropped the wrong row makes them disagree.

## Sidecar ladders — caches, NOT in the fingerprint

`history` every **1024** (samples the 20-byte lock), `tx_inputs` every **4096**
(samples the 5-byte spender ordinal). Rebuilt with their file; excluded from the
fingerprint. Same sampling rule and the same audit as the index's: the step is
fixed by this format, and `verify` rebuilds both ladders from the files they
index instead of trusting the digests the seal recorded.

A lock's story is **one contiguous run of records**, not one bucket: a reused
lock can own millions of rows and therefore hundreds of buckets and many equal
ladder samples. The reader enters at the rightmost sample **strictly below** the
lock and keeps reading forward until the key changes — see the normative entry
rule in [OutpointIndex-v3](OutpointIndex-v3.md) and invariant 9 in
[INVARIANTS](../INVARIANTS.md). Same for `tx_inputs`, whose group is one row per
input of a transaction and can exceed the step on large consolidations.

## Seal cross-check (accounting)

At seal the build verifies the cross-file identity **Σ(spent values in
`history.bin`) == Σ(input values consumed by the fee computation)** — two
independent roads to the same satoshis — plus the invariants: one history row per
output, one `tx_inputs` row per spend, one fee per tx. A `build` **refuses** an
index with `unresolved > 0`.

## Watermark & canonical fingerprint

`manifest.json` follows the shared shape in
[Artifact](../contracts/Artifact.md). The identity holds the tag
`outpoint-derived-v2`, the coverage, and the three data files'
digests in this order:

```
FP_ORDER = ("history", "tx_inputs", "fees")
```

Ladders excluded, and so is `updated_rows`: it says how this copy was built, not
what it holds, so it lives in `build`, which is also why a `rewind` does not
restore it. Same index + same height ⇒ same three files and the same fingerprint
on any machine.

## Notes for porters

- `value` is stored in `history.bin` on purpose (it is also in the index's
  `outputs.bin`): per-lock statistical scans stay sequential. Either source is
  authoritative and they must agree.
- `history` and `tx_inputs` are plain sorted fixed-width files; `fees` is pure
  positional (`fee = u64_be(fees.bin[tx_ordinal*8 : +8])`).
- Heights are **not** here; a reader gets them from the parent index
  (`height_of_output`, `height_of_tx`).
