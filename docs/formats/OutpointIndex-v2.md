# OutpointIndex-v2: format (L0)

The one expensive derivative that resolves any input reference `(txid, vout)` to
the output it spends, and reads the primitive output / tx / height facts. Built
from a [Graph-v2](./Graph-v2.md) archive in one pass. Read by
[IndexReader](../contracts/IndexReader.md).

- **Directory** of fixed-width record files + sidecar ladders + `state.json` +
  `manifest.json`.
- **Defined over:** a Graph-v2 archive (a `graph-v1` emission reads identically:
  that break moved the seal, not the stream). The parent it was actually built
  from is **declared** in `build.parent`, outside the fingerprint.
- **Captures:** for every output, its value and lock hash160; for every input,
  the resolved edge; per transaction, txid and first-output ordinal; per block,
  first tx, first output and time. **Does not capture:** locktime, version,
  sequence, scriptSig, witness — the graph does not carry them either.
  An index built over an unsealed graph declares `parent: null`: it has nothing
  to name, which is a gap in what it can attest and not a difference in what it
  is. Its fingerprint is the same as any other honest build of the same heights.

## Endianness & coordinates

**Big-endian** integers everywhere (byte order = numeric order → sort / merge /
search on raw `memcmp`, no field decoding). The chain is numbered **once**:

- `tx_ordinal` = position of a transaction in chain order, from block 1 (0-based);
- `output_ordinal` = position of an output in chain order.

Ordinals are **40-bit** (`ORD = 5` bytes); output counts per tx are **24-bit**.
Genesis excluded — ordinals start at block 1.

## Positional files (record `i` = ordinal `i`; no keys stored, append-only)

| file | width | record `i` = | layout |
|---|---|---|---|
| `blocks.bin` | 14 | height `i+1` | `first_tx:u40` \| `first_out:u40` \| `time:u32` |
| `txids.bin` | 32 | tx ordinal | `txid` (serialized order) |
| `tx_first_out.bin` | 5 | tx ordinal | `first_output_ordinal:u40` (strictly increasing → also binary-searchable by value) |
| `outputs.bin` | 28 | output ordinal | `value:u64` \| `lock:digest20` (hash160 of the **full** scriptPubKey) |

## Sorted files (searchable by key, deduplicated)

| file | width | key | layout |
|---|---|---|---|
| `txid_index.bin` | 40 | `txid` (32) | `txid:32` \| `first_out:u40` \| `n_out:u24` — the **resolver**: `(txid,vout)` → `first_out + vout`, refusing `vout ≥ n_out` loudly |
| `spends.bin` | 10 | `spent_out` (5) | `spent_output_ordinal:u40` \| `spender_tx_ordinal:u40` — the whole spend side, 10 bytes/edge |

A tx's own ordinal is not stored in `txid_index`: it is recovered by
binary-searching `tx_first_out.bin` for `first_out`.

## Sidecar ladders (`.lad`) — caches, NOT in the fingerprint

Every K-th key of a searchable file, sampled at seal, resident in RAM → a point
query is one ~40 KB bucket read. Steps: `txid_index` every **1024**, `spends`
every **4096**, `tx_first_out` every **8192**. Rebuilt with their file; excluded
from the canonical fingerprint.

The sampling rule is one rule for all of them: record 0, then every K-th record,
each contributing its first key-length bytes. The step is **fixed by this
format**, not chosen per artifact — a manifest declaring another one is
rejected — and `verify` rebuilds every ladder from its file rather than trusting
the digest the seal recorded (see [Artifact](../contracts/Artifact.md)).

**Entry rule (normative).** For an **equality scan** (every record whose key
prefix equals K) the entry point is the rightmost sample **strictly below** K,
or record 0 when no sample is below it; the walk then continues across buckets
until a different key appears. The rightmost sample `<= K` is NOT a valid entry:
a group longer than the sampling step owns several consecutive samples equal to
K, and entering at the last of them silently drops the head of the group. For a
**position** lookup over unique keys (`tx_first_out`: which transaction contains
this output ordinal?) the answer IS the rightmost sample `<= K` — a different
question, deliberately a different rule. The ladder only decides where to read:
with it, without it, or with another step, the records returned are identical
(see [INVARIANTS](../INVARIANTS.md), invariant 9).

## BIP30 (the one dedup rule)

For a duplicated coinbase txid the resolver keeps the **latest** instance (highest
`first_out`, i.e. the record that sorts last → "keep the last of an equal-key run"
= consensus). Positional files keep **both** instances honestly. The overwrite
count is expected **exactly 2** on mainnet (built-in cross-check); equal keys in
`spends.bin` are expected **0**.

This rule is also the one thing a **rewind** cannot undo. The earlier record is
gone from the resolver, so cutting *between* two instances of one txid would
drop the survivor and leave the key absent, where a rebuild to that height still
holds the earlier one. Positional files keeping both instances is what makes the
hazard detectable: `rewind` looks for a txid present on both sides of the cut in
`txids.bin` — and only when the index says duplicates exist at all, which after
BIP34 no chain produces any more. Found, it refuses; the artifact is never
half-cut, because the check runs before a byte moves.

## Watermark & canonical fingerprint

`manifest.json` follows the shared shape in
[Artifact](../contracts/Artifact.md): an `identity` the fingerprint covers and a
`build` block that does not. For this format the identity holds the tag
`outpoint-index-v2`, the coverage `1..H`, and the six data
files' digests in this order:

```
FP_ORDER = ("blocks", "txids", "tx_first_out", "txid_index", "outputs", "spends")
```

Ladders are excluded (a cache must not change what an artifact *is*). Record
counts, anomaly tallies and the actual file names live in `build`, so a
generation number can never move the fingerprint. Same graph + same end height ⇒
same fingerprint on any machine.

The coverage is **exact** here: one `blocks.bin` record per height, so the
file's own length states the watermark and `verify` refuses a manifest that
claims another.

## Notes for porters

- Everything positional is `record i @ offset i×width` — one read, no search.
- The resolver and the spend side are plain sorted fixed-width files: a port can
  binary-search them directly; the ladder is only a round-trip optimization.
- `lock` is `hash160(scriptPubKey)`, **not** a key or script hash — see the two
  digest systems in the [glossary](../GLOSSARY.md).
