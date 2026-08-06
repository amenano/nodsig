# RevealArchive-v2: format (L0)

The complete archive of every public key and candidate script **ever revealed** in
an unlocking context in confirmed blocks. It answers the exposure question with a
local membership check, and is **appendable** from day one (the card-index seed).
Read by [ExposureLookup](../contracts/ExposureLookup.md).

- **Directory:** one merged file per category (`archive_<cat>_g<NNNN>.bin`), one
  ladder sidecar per category (`archive_<cat>_g<NNNN>.lad`, a search cache: see
  below), zero or more run files under `runs/` (unfused), `state.json`, and
  `manifest.json` (after `merge`). The four-digit **generation** counts fusions;
  the manifest names each file, so a reader never derives a name (see
  *Appendability*).
- **Defined over:** nothing; it is produced from confirmed
  blocks (optionally co-emitted with a Graph-v2 scan).

## What one record is

The archive stores **revelations, not conclusions**: sorted, deduplicated,
fixed-width records, one partition per category. Categories **never mix**.

| category | record width | layout |
|---|---|---|
| `keys` | 24 | `hash160(pubkey):digest20` \| `flags:u8` \| `first_height:u24` |
| `scripts20` | 24 | `hash160(redeem_script):digest20` \| `inner_keys:u8` \| `first_height:u24` |
| `scripts32` | 36 | `sha256(witness_script):digest32` \| `inner_keys:u8` \| `first_height:u24` |

Fixed order of categories: `CAT_ORDER = (keys, scripts20, scripts32)`.
Records are sorted by digest; the two payload fields never enter the order.

### `first_height`, on every record

The **lowest** height the digest was ever seen at, big-endian in three bytes
(16.7M heights, around 318 years of chain). Two sightings of one digest merge
by `min`, which is associative and commutative and therefore leaves the fusion
independent of when it happens, exactly as the `or` on the flags does.

It costs about 12% of the file and it is the one field of this format that **no
later pass could recover**: a digest says nothing about its own date, and
[Graph-v2](./Graph-v2.md) deliberately keeps no unlocking data to re-derive it
from. What it buys:

- the exposure answer gains a **when**, not only a whether;
- "which digests appeared between H1 and H2" stops being an impossible question
  and becomes a filter;
- the declared coverage gains a **floor**: the highest `first_height` in the
  data is a lower bound on the watermark. Not a proof, because a stretch of
  chain with no new revelation leaves no trace, but it turns a word given about
  the whole range into a word given about the tail. See
  [Artifact](../contracts/Artifact.md).

It does **not** buy a `rewind`. Restoring the state at a lower height would
mean knowing which flag bits were already set below the cut, and one minimum
height cannot say: it would take one height per **provenance** bit, twelve
bytes on every `keys` record. (The form bit needs none: it is constant for a
digest, so it cannot have arrived later. Four heights, not five.) That is why
this format has no rewind, and the reason is a measurement rather than an
omission.

### The `flags` byte (category `keys`)

Where the key was sighted, **OR-ed** across all sightings (so the read-time
perimeter can be chosen: full, or the narrow `--no-faces`/`--no-cosigners`
readings, reproduce exactly), plus one bit of **form**:

```
FLAG_SIG          = 1   // direct, pushed in a scriptSig
FLAG_WIT          = 2   // direct, pushed in a witness
FLAG_INNER_SIG    = 4   // inside a revealed redeem script (a cosigner)
FLAG_INNER_WIT    = 8   // inside a revealed witness script (a cosigner)
FLAG_UNCOMPRESSED = 16  // the key came in the 65-byte serialization
```

`FLAG_UNCOMPRESSED` is not provenance: it records that the key's serialized
form was the uncompressed one. The form is a function of the digest's preimage
(the 33-byte and the 65-byte serializations of one point hash to *different*
digests), so every sighting of a digest agrees on the bit, the OR merge cannot
change it, and append ≡ rebuild is untouched. It rides a bit that was idle, on
a length test the extraction already performs, and it is as unrecoverable later
as the height: the archive stores the hash, never the key. What it buys is a
census of the form dimension across the whole chain (the uncompressed form is
the historically dominant one among exposed-and-weak spends).

### The `inner_keys` byte (categories `scripts20`/`scripts32`)

How many public-key-shaped pushes were found **inside** that script, saturating
at 255. The extraction has just walked the script looking for keys, so the
number is free, and the byte it fills was previously reserved and always zero.

It is a function of the script bytes, so every sighting of one script agrees;
sightings merge by `max`, which is a no-op that a test pins. What it buys is a
census of multisig shapes across the whole chain, from an archive that stores
hashes and never scripts, and it is as unrecoverable later as the height is.

> **Over-collection is harmless, never wrong:** a stored digest can only match a
> lock that is its exact preimage, so junk records cost bytes, not correctness.
> The archive has **no perimeter**; the perimeter is applied at read time.

## Appendability

The canonical form at height H is one well-defined set of bytes whatever the run
boundaries were: an interrupted-and-resumed scan **fuses to the same files** as a
one-shot scan (the determinism rule). A lookup consults the merged file **plus**
any unfused runs of that category (flags OR-ed); `merge` fuses runs into the
merged files and rewrites the manifest.

**A fusion is additive, and that is what makes it crash-safe.** It writes
generation N+1 **beside** generation N and commits `manifest.json` only once
every category is on disk; the consumed runs and the superseded generation are
deleted after the state and the manifest have stopped naming them. Nothing the
manifest names is ever overwritten while it still names it, so no kill can
leave the manifest describing bytes that do not exist, which would be
unrecoverable, since every reader (including `merge` itself) verifies the
recorded `sha256` before yielding a byte. On the next `merge`, whatever the
manifest does not name is swept: the rule the runs already lived by.

Between the manifest write and the state write a reader sees the new merged
base **together with** the runs it already contains. This is harmless by
construction: the fusion deduplicates by OR-ing flags, so reading a record
twice is reading it once.

## Watermark & manifest

`manifest.json` follows the shared shape in
[Artifact](../contracts/Artifact.md): an `identity` the fingerprint covers
(format tag, coverage, the three category digests in `CAT_ORDER`) and a
`build` block that does not (generation, file names, records, ladders).
`identity.coverage.to` is the **watermark**. With unfused runs present the
archive is queryable but **not sealed**, and that state must be reported: there
is no single sealed fingerprint yet.

`build.files.<cat>.file` is the **authority** on which file holds a category:
resolve it from the manifest, never by formatting the category name. The
generation number lives there too, and neither can move the fingerprint, which
is the identity/build split doing its job.

## Canonical fingerprint

The shared recipe, stated once in [Artifact](../contracts/Artifact.md): the
identity block is serialized to bytes and hashed. For this format that block
holds the tag `reveal-archive-v2`, the coverage, and the three
category digests in `CAT_ORDER`.

Same chain + same height ⇒ same fingerprint on any machine.

Note what it does **not** contain: a file name, a generation, a record count.
So an archive fused once has the same identity as one fused ten times over the
same history. And note what it **does** contain, which the file digests could
never state on their own: the coverage. An archive of hashes carries no heights
outside its `first_height` fields, so a manifest could otherwise claim a taller
watermark than the scan reached and every "not revealed up to H" would inherit
the lie.

## Ladder sidecars (search caches, NOT fingerprinted)

Each merged file has a sibling `.lad` of the same generation: the key of
**every `every`-th
record** (`ARCHIVE_LADDER_EVERY`, currently 2048), concatenated, in file order.
A lookup loads the ladder once (resident, tens of MB at chain scale), bisects it in
RAM to pick a bucket, and reads **one** `every`-record slice (~49–74 KB) from the
merged file: one round-trip where a blind on-disk binary search pays ~log₂(records)
seeks. The manifest records `{ file, every, sha256 }` per category.

The ladder is a **pure cache**: it is deterministic (rebuilt with its file), it is
excluded from the canonical fingerprint, and its `every` may change freely without
changing the archive's identity. A reader with no ladder (an older archive, or a
porter that skips the optimisation) must fall back to the blind bisect and get the
**same** byte: the ladder only decides *where* to read, never *what* is returned.

Keys in a merged file are **unique** (the fusion deduplicates, OR-ing the flags),
so a lookup matches 0 or 1 record and the equal-key groups that make the entry
rule delicate elsewhere cannot occur here. The rule still applies unchanged,
enter at the rightmost sample **strictly below** the key (invariant 9 in
[INVARIANTS](../INVARIANTS.md)), because the shared reader is the same code.

## Verifying a sealed archive

`archive verify` is this audit; the recipe is written out here so a porter can
run it without reading the implementation. Two roads, checking different things:

- **the bytes, one read.** Each merged file named by `build.files.<cat>.file` is
  re-hashed and confronted with the digest `identity.files[]` records for that
  category; each `.lad` is **rebuilt from the file it indexes** by the sampling
  rule above and confronted with `build.caches.<cat>.sha256`; the identity block
  is re-serialized and re-hashed, and must give `fingerprint`. Rebuilding the
  ladder is what separates "intact" from "right": comparing a ladder with a
  digest of itself would accept one sampled by a wrong rule, and a wrong ladder
  makes a lookup read the wrong bucket and answer *absent*.
- **the records, one more read** (`--deep`). Bytes can be exactly the ones that
  were sealed and still be a badly built archive: the digests prove the file did
  not rot, never that the fusion did its job. So, per category: digests strictly
  ascending (order and deduplication in one statement, since the fusion emits
  each digest once), as many records as `build.files.<cat>.records`, a `flags`
  byte with no bit outside the five defined ones, and every `first_height`
  between 1 and the watermark.

The highest `first_height` a deep pass finds is the archive's coverage **floor**:
every height below it is proven present, and the tail above it cannot be proven
at all, because a stretch of chain that reveals nothing new leaves no record.
That is a weaker statement than the header archive's exact coverage, and it is
the strongest one this format admits. Without `--deep` the coverage is taken on
trust, and the report says so rather than staying silent.

An archive with unfused runs is queryable but **not sealed**: the audit covers
the merged base, and must say at which height the fingerprint stops and how many
runs sit beyond it.

## The v1 projection (`archive v1-digests`)

The published v1 archive stored `digest | byte` with **no height**; its keys
byte held only the four provenance bits, and its scripts byte was reserved and
zero. Every field this format added is therefore removable by construction, and
`archive v1-digests` does exactly that: it streams the fused base and prints,
per category, the sha256 of the records projected to the v1 layout (height
stripped; keys byte masked to the four v1 bits; scripts byte zeroed).

An archive rebuilt from the chain by current code, projected this way, must
reproduce the per-category digests a sealed v1 archive recorded: new code
confronted with a historical artifact, which is the strongest cheap statement
the two can make about each other. The masks are pinned by a test, so a flag
added without teaching the projection fails in the suite, not in the
confrontation. Defined on the fused base only: pending runs are a refusal.

The reference is written here rather than left in an artifact somebody has to
possess. A v1 archive sealed on the chain through height 957,301 recorded:

| Category | Records | sha256 of the v1 layout |
|---|---|---|
| `keys` | 1,613,342,055 | `95e6915c759bdb7c2268e552280024bfd205ebdad2dafa58fc96bced1a6f4fca` |
| `scripts20` | 976,147,552 | `103ef99541fe840fa9a79123f740584e0e72ac5a9cbb38059431dd1a6d48228b` |
| `scripts32` | 986,793,535 | `29c28a8a77248ee4421798164116b2ca68b406ecac90978e10c334d1c2613258` |

Three digests over 3.58 billion records, published in July 2026 by a build that
predates this format. They are what `archive v1-digests` is confronted with,
and reproducing them from a fresh scan is a statement no amount of internal
consistency can make: the same history, read twice, years and formats apart.

## Notes for porters

- A reader needs only: for a query `(digest, category)`, binary-search the
  category's merged file **and** each unfused run of that category; OR the flag
  bytes of any hits. Membership + flags are the whole answer.
- The ladder sidecar is an **optional accelerator**, not required for correctness:
  ignore it and bisect the file directly, or use it exactly as the index does.
- Record widths are `digest_width + 1 + 3`; files are sorted by the digest
  prefix, so `memcmp` on the leading bytes drives the search.
- "Not in the archive" = not revealed on-chain up to the watermark, confirmed
  blocks only; off-chain exposure is invisible by declaration.
