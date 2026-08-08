# Types — the neutral vocabulary

The types every contract speaks. Chosen to map to C structs / Java classes / JSON
fields / protobuf messages **without impedance**, so a port carries them across
languages unchanged. This file is the single definition; contracts reference it.

## Scalars

| Type | Meaning |
|---|---|
| `u32`, `u64` | unsigned integers, **big-endian** in every format and on the wire |
| `u24`, `u40`, `u56` | 24-/40-/56-bit unsigned (**on-disk widths only**); widen to `u32`/`u64` in-memory. `u56` carries satoshis: the whole supply is 2.1e15 and 2^56 is 7.2e16 |
| `digest20` | 20 bytes — a `hash160` (RIPEMD160∘SHA256) |
| `digest32` | 32 bytes — a `sha256` or a txid |
| `bytes`, `string`, `bool` | as usual; `string` is UTF-8 |

**Byte order.** Formats and contracts are **big-endian**: the lexicographic byte
order then *is* the numeric order, so sort / merge / binary search run on raw
`memcmp` and never decode a field. (The block *parser* sees Bitcoin's native
little-endian; everything downstream of it is big-endian.)

## Domain aliases (semantic names for the scalars)

| Alias | Underlying | Meaning |
|---|---|---|
| `height` | `u32` | block height; `1`-based (genesis, height 0, is excluded everywhere) |
| `tx_ordinal` | `u64` | position of a transaction in chain order, from block 1 (0-based) |
| `output_ordinal` | `u64` | position of an output in chain order (block, tx, vout) |
| `amount` | `u64` | value in **satoshis** (absolute; never a rate) |

## Enums

```
Status       = { OK, UNDETERMINED, UNSUPPORTED }
LockType     = { P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, UNKNOWN }
AddressKind  = { P2PKH, P2SH, P2WPKH, P2WSH, P2TR }            // decodable mainnet forms
Category     = { keys, scripts20, scripts32 }                 // reveal-archive partitions
EventKind    = { RECV, SPEND }
```

> **`LockType` is an INPUT-side concept.** It comes from an address (via
> [AddressCodec](contracts/AddressCodec.md)) or is read from a scriptPubKey
> *template* at scan time. It is **not** recoverable from a stored `lock`
> (`hash160` of a scriptPubKey): the index keeps the digest, not the type. No
> reader can classify a bare lock — do not expect one to.

## Source

```
Source = { id: string, watermark: u32, fingerprint: digest32? }
```

- `id` — a **stable identifier of the source artifact**: its format tag
  plus its logical role (e.g. `outpoint-derived-v3`). It is **not** a filesystem
  path. Paths are local and private and MUST NEVER appear in a result (they would
  leak topology and make results non-portable).
- `watermark` — highest confirmed height the source covers; every answer is "as
  of `watermark`".
- `fingerprint` — the source's canonical fingerprint when it is fully sealed;
  **absent** when the source includes unfused runs (a queryable-but-not-sealed
  state that MUST be reported, never presented as sealed).

## The Result envelope

```
Result<T> = { status: Status, value: T?, source: Source }
```

- **At the capability boundary, once per operation** — **never per streamed
  record.** A `Result<stream<T>>` carries source **once**; the (possibly
  millions of) streamed items stay bare. In-process reference readers MAY return
  raw values internally; the envelope is applied at the boundary, and is exactly
  what an L2 transport serializes.
- **Status meanings** (uniform across readers):
  - `OK` — the source answered. `value` may be a **definite negative**
    (`null`, or an empty stream): a real answer at the watermark, not a failure.
  - `UNSUPPORTED` — the source does not implement this capability at all.
  - `UNDETERMINED` — the source cannot decide from partial data. A **sealed**
    artifact is complete up to its watermark and never returns this; backends over
    partial/foreign data may.
- **`value: T?` (optional).** `null` is a value (definite negative), never an
  error signal. Errors are a separate channel (below).

## Errors vs negatives (keep them distinct)

- A **negative** is `OK` + `null`/empty (e.g. "txid absent up to the watermark").
- An **error** is an invalid query or corrupt source — a *raise*, not a status:
  `OUT_OF_RANGE` (ordinal past the artifact), `INVALID_OUTPOINT` (`vout ≥ n_out`
  for a present txid), `INVALID_DIGEST` (wrong width for a category), sha/format
  mismatches. Errors are loud; they are never smuggled as a quiet default.

## Streaming semantics

- A `Result<stream<T>>` delivers `status` + `source` **up front** (when the
  operation is admitted). The stream is finite; its **order is part of each
  reader's contract** (total and reproducible).
- If an error arises while producing items (e.g. a truncated file), the stream
  **terminates abnormally**: a raising language raises; a value-oriented binding
  yields a terminal error marker. Items already delivered stay valid, but the
  consumer MUST treat abnormal termination as **failure**, not end-of-data.
