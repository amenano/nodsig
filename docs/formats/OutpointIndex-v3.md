# OutpointIndex-v3: format (L0)

The one expensive derivative that resolves any input reference `(txid, vout)` to
the output it spends, and reads the primitive output / tx / height facts. Built
from a [Graph-v2](./Graph-v2.md) archive in one pass. Read by
[IndexReader](../contracts/IndexReader.md).

- **Directory** of fixed-width record files + sidecar ladders + `state.json` +
  `manifest.json`.
- **Defined over:** a Graph-v2 archive (a `graph-v1` emission reads identically:
  that break moved the seal, not the stream). The parent it was actually built
  from is **declared** in `build.parent`, outside the fingerprint.
- **Captures:** for every output, its value, lock hash160 and the transaction
  that spent it (if any); per transaction, txid and first-output ordinal; per
  block, first tx, first output and time. **Does not capture:** locktime,
  version, sequence, scriptSig, witness — the graph does not carry them either.
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

A tx's own ordinal is not stored in `txid_index`: it is recovered by
binary-searching `tx_first_out.bin` for `first_out`.

## The spend side: `spender_of.bin` + `spend_extra.bin`

Two files, and **three states per output**. `spender_of.bin` is positional like
the files above — slot `i` belongs to output ordinal `i` — but it is the one
file that is **mutated in the middle**, because an output written long ago gains
a spender when a later block spends it.

| slot value | meaning |
|---|---|
| `0` | **not spent** up to the watermark |
| `2^40-1` (`ffffffffff`) | **more than one spender**: the answer is not here, read `spend_extra.bin` |
| anything else | the `tx_ordinal` of the transaction that spent it |

| file | width | record `i` = | layout |
|---|---|---|---|
| `spender_of.bin` | 5 | output ordinal | `spender_tx_ordinal:u40`, or one of the two sentinels above |
| `spend_extra.bin` | 10 | — | `spent_output_ordinal:u40` \| `spender_tx_ordinal:u40`, sorted, holding **every** spender of each marked output. **Empty on any consensus-valid chain.** |

**Why the sentinels are free.** Transaction ordinal `0` is the genesis coinbase,
and a coinbase spends nothing, so no real spender ever carries `0`. The marker
is a single **reserved value**, not a threshold — a value is compared and
verified, a threshold invites interpretation — and it sits far above any
reachable ordinal, since a chain exhausts 2^40 *outputs* long before 2^40
transactions.

**Why the third state exists at all.** An output with two spenders cannot occur
under consensus, and this toolkit takes its chain from a node that already
applied it. But
[INVARIANTS](../INVARIANTS.md) invariant 3 names duplicate spends among the
anomalies that are **counted and reported, never hidden**, so the format must be
able to *represent* one. A dense array alone cannot, and a format that cannot
represent an anomaly does not declare an assumption — it enforces one. Hence the
marker: the array states its own incompleteness instead of guessing, and a
reader that ignores `spend_extra.bin` cannot answer wrongly in silence, because
what it meets is not an ordinal.

Note also what the marker **avoids**: with no spender kept in the slot, the
overflow holds them all, so nobody has to decide which spender "wins" the slot.
There is no tie-break here, and that is deliberate.

**`build.totals.duplicate_spends`** is the number of marked slots, and it is
sealed in the manifest, so a third party reading the artifact sees it. Expected
**0**.

**Reading it.** `spenders(out_ord)` is one 5-byte positional read. `0` → the
empty list; a marker → `spend_extra.bin`, which is loaded resident (it is
expected empty, so this costs no extra round trip) and **refused above a
declared cap**, because an artifact from a stranger is untrusted input and must
not be able to make a reader hold an arbitrary file in memory. Past a handful of
records that index is to be thrown away, not read.

**The seal checks both files, and checks them against each other:**

```
(slots that are neither 0 nor marker) + records(spend_extra) == edges resolved
count of marked slots                                       == distinct out_ord in spend_extra
```

The first replaces v2's "`spends.bin` holds as many records as the join
resolved". That check could not survive the change as written: with a dense
array the record count *is* the slot count, which is `n_out` and already known,
so comparing it would confirm nothing. The count is therefore recomputed at seal
from the bytes on disk, independently of whatever the fusion tallied. The second
check is the price of splitting one answer across two files: without it, a
marker with nothing behind it, or records with no marker, would be invisible.

## Sidecar ladders (`.lad`) — caches, NOT in the fingerprint

Every K-th key of a searchable file, sampled at seal, resident in RAM → a point
query is one ~40 KB bucket read. Steps: `txid_index` every **1024**,
`tx_first_out` every **8192**. Rebuilt with their file; excluded from the
canonical fingerprint.

The spend side carries **no ladder**: one is addressed positionally and the
other is resident. v2's `spends.lad` has no successor.

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
count is expected **exactly 2** on mainnet (built-in cross-check); marked slots
in `spender_of.bin` are expected **0**.

The two are the same doctrine seen twice: where a question admits one answer,
consensus decides and the choice is **declared and isolated** (this rule, and it
is the only one); the record layer keeps what was there; the divergence is
**counted** and sealed. Duplicate spends get the third state for the same reason
positional files keep both BIP30 instances.

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
`outpoint-index-v3`, the coverage `1..H`, and the seven data
files' digests in this order:

```
FP_ORDER = ("blocks", "txids", "tx_first_out", "txid_index", "outputs",
            "spender_of", "spend_extra")
```

The two spend files take the place `spends` held, **in its position**: the order
is part of the recipe, so substituting in place leaves every other file's
contribution where it was. `spend_extra` is covered even though it is normally
empty — without it, two indexes differing only in a recorded anomaly would share
a fingerprint, which would be a hole in "an artifact is named by what it holds".

Ladders are excluded (a cache must not change what an artifact *is*). Record
counts, anomaly tallies and the actual file names live in `build`, so a
generation number can never move the fingerprint. Same graph + same end height ⇒
same fingerprint on any machine.

The coverage is **exact** here: one `blocks.bin` record per height, so the
file's own length states the watermark and `verify` refuses a manifest that
claims another.

## Rewind, and the one trap the marker sets

A rewind to height `H` drops every transaction ordinal at or above `n_tx_cut`
and every output at or above `n_out_cut`. On the spend side that is

```
slot = 0            where slot >= n_tx_cut       (its spender is cut)
truncate to n_out_cut slots                      (the output is gone)
```

**`>=`, not `>`**: the surviving ordinals are `0 .. n_tx_cut-1`, so `n_tx_cut`
is already past the cut. A `>` would leave a spender that does not exist
standing, and nothing downstream would notice — the ordinal is valid in shape,
merely false.

**The trap is the marker.** `2^40-1` satisfies `>= n_tx_cut` for every possible
cut, so the rule applied literally would zero every marked slot and a duplicate
spend would **vanish in silence** during a rewind — silently, because `0` is a
perfectly legitimate value. A marked slot must instead be re-derived from the
survivors in the overflow file:

```
survivors = [s for s in extra[o] if s < n_tx_cut]
0 survivors  -> slot = 0
1 survivor   -> slot = that spender, and its record leaves the overflow
>= 2         -> slot stays marked
```

Both files are rewritten as a new generation and committed before the old one is
deleted, like every other merged file (invariant 10). Never in place: zeroing
inside the live file has no recoverable failure mode.

## The previous format (`outpoint-index-v2`)

`outpoint-index-v2` is this format with the spend side as a single sorted file,
`spends.bin` (10 B: `spent_out:u40 | spender_tx:u40`, key `spent_out`, ladder
every 4096), and `FP_ORDER` ending in `spends` instead of the two files above.
Everything else — the positional files, the resolver, BIP30, the watermark — is
identical.

The tool **reads a v2 index**: `lookup`, `verify`, `stats` and the whole
`IndexReader` surface work on one, so an artifact downloaded under the previous
version keeps its value. `verify` audits it against the v2 file list, under the
v2 tag: a tag sequence would not do, because that mechanism assumes every tag in
it is made of the same files in the same order, and here one file became two.

It **cannot be extended, rewound, or used to build derivatives**, and that limit
is not an omission. `append ≡ rebuild` and `rewind ≡ rebuild` promise the bytes a
rebuild would have written; a fusion mixing the two layouts matches no rebuild at
all. Each of the three refuses and says why. Emission is never widened: a builder
writes one tag.

## Notes for porters

- Everything positional is `record i @ offset i×width` — one read, no search.
- The resolver is a plain sorted fixed-width file: a port can binary-search it
  directly; the ladder is only a round-trip optimization.
- **The spend side needs no search at all**, but a port MUST implement the third
  state. Reading `spender_of.bin` as a plain array of ordinals is wrong: the
  marker would be read as transaction `1099511627775`. A port that does not want
  to carry `spend_extra.bin` must **fail loudly on the marker**, never return it
  as a number and never map it to "unspent".
- `lock` is `hash160(scriptPubKey)`, **not** a key or script hash — see the two
  digest systems in the [glossary](../GLOSSARY.md).
