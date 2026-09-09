# RevealArchive-v3: format (L0)

The complete archive of every public key and every script **ever revealed** in
confirmed blocks: pushed in an unlocking context, published in an output, or
sitting inside a revealed script. It answers the exposure question with a
local membership check, and is **appendable** from day one (the card-index
seed). Read by [ExposureLookup](../contracts/ExposureLookup.md).

- **Directory:** one merged file per category (`archive_<cat>_g<NNNN>.bin`), one
  ladder sidecar per category (`archive_<cat>_g<NNNN>.lad`, a search cache: see
  below), zero or more run files under `runs/` (unfused), `state.json`, and
  `manifest.json` (after `merge`). The four-digit **generation** counts fusions;
  the manifest names each file, so a reader never derives a name (see
  *Appendability*).
- **Defined over:** nothing; it is produced from confirmed blocks (optionally
  co-emitted with a Graph-v2 scan).
- **Supersedes:** `reveal-archive-v2`, which this release neither reads nor
  reproduces. An archive sealed under v2 keeps its fingerprint as a historical
  number, reproducible from the chain with the release that wrote it.

What changed from v2, in one paragraph: a key is identified by its **point**
and no longer by the bytes it happened to be serialized in; keys published in
outputs (P2PK, bare multisig), the hybrid 65-byte forms and the x-only keys of
a taproot script path count as revealed; and the two script partitions hold
scripts only, because the candidate an input pushes last is filtered by its
shape before it is hashed. On the chain through height 957,301 the v2 script
partitions were about 60% public keys and about 89% signatures and control
blocks respectively, which is 45 GB of a 98 GB archive saying nothing.

## What one record is

The archive stores **revelations, not conclusions**: sorted, deduplicated,
fixed-width records, one partition per category. Categories **never mix**.

| category | record width | layout |
|---|---|---|
| `keys` | 24 | `hash160(serialized key):digest20` \| `flags:u8` \| `first_height:u24` |
| `scripts20` | 24 | `hash160(redeem_script):digest20` \| `inner_keys:u8` \| `first_height:u24` |
| `scripts32` | 36 | `sha256(witness_script):digest32` \| `inner_keys:u8` \| `first_height:u24` |

Fixed order of categories: `CAT_ORDER = (keys, scripts20, scripts32)`.
Records are sorted by digest; the two payload fields never enter the order.
Widths, order and ladder step are the ones of v2: what changed is what a
record means and which records exist.

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
height cannot say: it would take one height per **provenance** bit, and with
the six provenances of this format that is fifteen more bytes on every `keys`
record, about 25 GB on the whole chain, for a question nobody asks of this
artifact. That is why this format has no rewind, and the reason is a
measurement rather than an omission. Rebuild, or nothing.

The same one minimum is why a reuse curve read out of this archive is exact
under the full perimeter only: under `--no-faces` or `--no-cosigners` an
intermediate row would date a burn by a sighting the perimeter excludes, so
`derive --curve` refuses the combination. The narrow curve is the second
road's job (`reuse scan`), which burns as it reads.

## The identity of a key

A public key is a **point** on the curve. The chain serializes it in three
ways: 33 bytes (`02` or `03` then `x`, the leading byte being the parity of
`y`), 65 bytes (`04` then `x` then `y`; the hybrid leads `06`/`07` repeat the
parity and mean the same point), and 32 bytes (`x` alone, the x-only form of
taproot, which BIP 340 defines as the point with even `y`). The private key is
the same behind all of them, so a reader who fears a quantum adversary at the
moment of spending cares about the point, never about the string. v2 keyed its
records by the serialization seen, so one point sighted at 65 bytes did not
mark the address of its 33-byte form. v3 keeps one digest per serialization,
because locks are built on serializations, and adds one **invariant**:

> For every point ever revealed, the digest of its **compressed** form is in
> `keys`. The digest of another form the chain showed, when there is one, is
> in `keys` too, and the compressed record carries `FLAG_OTHER_FACE`.

The compressed form is computed without curve arithmetic:

```
canonical_key(item):
    33 bytes, lead 02 or 03           -> comp = item
    65 bytes, lead 04, 06 or 07       -> comp = (0x02 | (y[-1] & 1)) || x
                                          (the parity is the last bit of y;
                                           the lead byte is ignored)
    32 bytes, in a taproot leaf or
        control block only            -> comp = 0x02 || x
    anything else                     -> not a key
    returns hash160(comp), hash160(item), form
```

Two slices and an OR, on bytes the extraction already holds. The other
direction, 33 to 65, needs `y` from `x` (`y^2 = x^3 + 7 mod p`, one modular
exponentiation since `p = 3 mod 4`): it is field arithmetic, not point
arithmetic, and it lives only in `check --key` and `nonces address --key`, once
per key a person types, never in the scan. The output of those commands says
when it was used. A key that is not on the curve is refused there, loudly.

One function, `canonical_key`, is shared by the archive, by the second road
(`reuse scan`), by `check` and by the witness table, so "is this a key" is
decided once. A test vector, on public data: the key of the genesis coinbase,
65 bytes, lead `04`, `y` ending in `5f` (odd):

| form | hash160 |
|---|---|
| the 65 bytes as seen | `62e907b15cbf27d5425399ebf6f0fb50ebb88f18` |
| `03 || x`, the compressed face | `9f81322cc88622ca4ccb2a52a21e2888727aa535` |

A stranger reproduces both with a hash function and nothing else.

### The `flags` byte (category `keys`)

Eight bits, all **OR-ed** across sightings: six say where the point was seen,
two say in which form.

```
FLAG_SIG          = 1    // pushed in a scriptSig
FLAG_WIT          = 2    // an item of a witness (the control block's internal key included)
FLAG_INNER_SIG    = 4    // inside a revealed redeem script (a cosigner)
FLAG_INNER_WIT    = 8    // inside a revealed witness script, or a revealed taproot leaf
FLAG_UNCOMPRESSED = 16   // form: the preimage of THIS digest is 65 bytes (04, 06 or 07)
FLAG_OUT          = 32   // published in a scriptPubKey (P2PK, bare multisig)
FLAG_OTHER_FACE   = 64   // the point was seen in another serialization; this digest is its compressed form
FLAG_XONLY        = 128  // form: seen as an x-only key (control block or leaf); digest = hash160(02 || x)
```

The read-time perimeter chooses which provenances count (full, or the narrow
`--no-faces` / `--no-cosigners` readings, reproduce exactly); `OUT`,
`OTHER_FACE` and `XONLY` count under the full perimeter only, and no perimeter
flag is added for them. `UNCOMPRESSED` is a function of the digest's preimage,
so every sighting agrees on it and the OR cannot change it; `XONLY` and
`OTHER_FACE` can share a compressed digest with `SIG` or `WIT` (a key seen
x-only in a leaf, later pushed as 33 bytes in a witness), and OR is exactly the
right operation. The byte is full: a ninth provenance is a format, not a bit.

### The `inner_keys` byte (categories `scripts20`/`scripts32`)

How many public-key-shaped pushes were found **inside** that script, saturating
at 255. The extraction has just walked the script looking for keys, so the
number is free. It is a function of the script bytes, so every sighting of one
script agrees; sightings merge by `max`, which is a no-op that a test pins.
Under v3 the partitions hold scripts and nothing else, so this byte is at last
what its name says: a census of multisig shapes across the whole chain.

## What one sighting emits

For every input of every non-coinbase transaction, with `pushes` the data
pushes of the scriptSig and `items` the witness:

1. every push that `canonical_key` accepts: a `keys` record for the digest
   seen, with `SIG` and its form bit; and, when the compressed digest differs,
   a second record for it with `OTHER_FACE`, at the same height;
2. every witness item **outside the taproot signature slots**, the same way
   with `WIT`. A slot holds a signature, and a 65-byte Schnorr signature whose
   `R.x` begins with `02`, `03` or `04` is not a key, whatever its shape;
3. the last scriptSig push and the last witness item are the **candidate
   scripts** of `scripts20` and `scripts32`; each passes the shape filter below
   or is dropped; a surviving candidate yields its script record with
   `inner_keys`, and every key inside it yields a `keys` record with
   `INNER_SIG` or `INNER_WIT` (plus `OTHER_FACE` when the forms differ);
4. when the last witness item (after removing an annex) has the shape of a
   control block, the internal key in its bytes 1..33 yields
   `hash160(02 || x)` with `WIT | XONLY`, and in the leaf (the item before it)
   every 32-byte push followed by `OP_CHECKSIG`, `OP_CHECKSIGVERIFY` or
   `OP_CHECKSIGADD` yields `hash160(02 || x)` with `INNER_WIT | XONLY`. The
   leaf itself is walked for keys and is **not** a `scripts32` candidate.

For every output of every transaction, coinbase included:

5. a scriptPubKey of the form `<key> OP_CHECKSIG` (P2PK) or
   `OP_m <keys> OP_n OP_CHECKMULTISIG` (bare multisig) yields, for every push
   `canonical_key` accepts, a `keys` record with `OUT` and its form bit, plus
   the `OTHER_FACE` record when the forms differ. A taproot output publishes
   its key by construction and no lock hides behind it: it yields nothing.

The `first_height` of an `OTHER_FACE` record is the height of the sighting
that produced it, which is exactly when that `x` became public. The genesis
block is not scanned, so the one key of its coinbase is the one P2PK key the
archive does not hold; the page says so instead of the archive pretending.

## The shape filter

v2 hashed the last push of every scriptSig and the last item of every witness
as a candidate script, without knowing the output being spent. A P2PKH input
ends with its public key, a P2WPKH witness with its public key, a taproot
key-path witness with its signature, a script-path witness with its control
block: all of them became permanent script records. The filter drops a
candidate when it has one of these shapes, decidable on the item's bytes and
position alone:

| shape | test | why it cannot be a confirmed script |
|---|---|---|
| a key | `canonical_key` accepts it (33 or 65 bytes; 32 only in a taproot slot) | it can: `02` is `OP_PUSH2`. This is the exception, counted below |
| a DER signature | the census's DER reader accepts it (exact layout, `0 < r < n`) | it can: `30` is `OP_PUSH48`. Counted below |
| a Schnorr signature | the item sits in a taproot slot and the census's reader accepts it | a witness script of 64 or 65 bytes as the only item is possible. Counted below |
| a control block | length `33 + 32 m`, first byte `c0` or `c1` | the first byte of a script always executes, and those are undefined opcodes that fail the script: exact |
| an annex | last item, first byte `50`, witness of two or more items | `OP_RESERVED` executed fails the script: exact |

Everything else is kept: the 22-byte P2SH-P2WPKH wrapper `0014<20>`, multisig,
hashlocks, timelocks, scripts without keys. The rule is a pure function of the
bytes and the position, so a rebuild applies it identically. Its cost is
negative: the key and DER tests are already paid for, the other three are
comparisons, and almost every input saves one hash.

The state counts what the filter dropped (`filtered_key_shaped`,
`filtered_signature_shaped`, `filtered_control_or_annex`) and what the outputs
yielded (`out_keys`); `malformed_inner_script` is back to counting scripts
that do not parse.

### The exception, counted

A real redeem script or witness script can have the shape of a key or of a
signature, and the filter drops it: the lock built on it would then answer
"protected" after having spent. Rather than a bit that marks every candidate
and keeps the 45 GB, the release counts the exception exactly and publishes
the count here, beside the format.

The count needs no index. The programs of every P2SH and P2WSH output ever
created, `C20` and `C32`, come from one sequential pass over the scriptPubKey
column of the graph (Graph-v2 keeps it verbatim). The sealed v2 archive is, by
construction, the complete list of candidates; the v3 archive restricted to
`first_height <= H` is the filtered list. The exception is the three-way
merge, per partition: a digest in v2, not in v3, and in the created programs.
Exact up to digest collisions, and reproducible by anyone holding the v2
archive at its release tag, the v3 archive and the graph.

On the chain through height 957,301: `E20` and `E32` **to be measured at the
2.0.0 run**; the digests, if they are a handful, will be listed here with the
height at which each was spent, so the script itself can be read back from
the chain. `check` names the count in the sentence it prints for a script
lock, so the person asking about exactly that lock does not receive a silent
"protected".

## Appendability

The canonical form at height H is one well-defined set of bytes whatever the run
boundaries were: an interrupted-and-resumed scan **fuses to the same files** as a
one-shot scan (the determinism rule). Every record is a pure function of the
item's bytes, its position and the height; `OTHER_FACE` is a function of the
bytes seen; the filter is a pure function; every flag merges by `or` and every
height by `min`. A lookup consults the merged file **plus** any unfused runs of
that category (flags OR-ed); `merge` fuses runs into the merged files and
rewrites the manifest.

**A fusion is additive, and that is what makes it crash-safe.** It writes
generation N+1 **beside** generation N and commits `manifest.json` only once
every category is on disk; the consumed runs and the superseded generation are
deleted after the state and the manifest have stopped naming them. Nothing the
manifest names is ever overwritten while it still names it, so no kill can
leave the manifest describing bytes that do not exist. On the next `merge`,
whatever the manifest does not name is swept: the rule the runs already lived
by. The first fusion of a scan reads the whole run pile, about twice the size
of what it will seal; `merge` prints the pile and the space it needs and
refuses before the first byte when the disk has less.

Between the manifest write and the state write a reader sees the new merged
base **together with** the runs it already contains. This is harmless by
construction: the fusion deduplicates by OR-ing flags, so reading a record
twice is reading it once.

## Watermark & manifest

`manifest.json` follows the shared shape in
[Artifact](../contracts/Artifact.md): an `identity` the fingerprint covers
(format tag, coverage, the three category digests in `CAT_ORDER`) and a
`build` block that does not (generation, file names, records, ladders, the
filter counters). `identity.coverage.to` is the **watermark**. With unfused
runs present the archive is queryable but **not sealed**, and that state must
be reported: there is no single sealed fingerprint yet.

`build.files.<cat>.file` is the **authority** on which file holds a category:
resolve it from the manifest, never by formatting the category name.

## Canonical fingerprint

The shared recipe, stated once in [Artifact](../contracts/Artifact.md): the
identity block is serialized to bytes and hashed. For this format that block
holds the tag `reveal-archive-v3`, the coverage, and the three category
digests in `CAT_ORDER`. Same chain + same height, same fingerprint on any
machine; and the same chain read under v2 gives a different one, on purpose:
the records are not the same set.

Note what it does **not** contain: a file name, a generation, a record count.
And note what it **does** contain, which the file digests could never state on
their own: the coverage. An archive of hashes carries no heights outside its
`first_height` fields, so a manifest could otherwise claim a taller watermark
than the scan reached and every "not revealed up to H" would inherit the lie.

## Ladder sidecars (search caches, NOT fingerprinted)

Each merged file has a sibling `.lad` of the same generation: the key of
**every `every`-th record** (`ARCHIVE_LADDER_EVERY`, 2048), concatenated, in
file order. A lookup loads the ladder once (resident, tens of MB at chain
scale), bisects it in RAM to pick a bucket, and reads **one** `every`-record
slice from the merged file: one round-trip where a blind on-disk binary search
pays about `log2(records)` seeks. The manifest records `{ file, every, sha256 }`
per category.

The ladder is a **pure cache**: deterministic, excluded from the canonical
fingerprint, and its `every` may change without changing the archive's
identity. A reader with no ladder must fall back to the blind bisect and get
the **same** byte: the ladder only decides *where* to read, never *what* is
returned. Keys in a merged file are **unique**, so a lookup matches 0 or 1
record; the entry rule is the shared one (invariant 9 in
[INVARIANTS](../INVARIANTS.md)).

## Verifying a sealed archive

`archive verify` is this audit; the recipe is written out here so a porter can
run it without reading the implementation. Two roads, checking different things:

- **the bytes, one read.** Each merged file named by `build.files.<cat>.file` is
  compared by size with the records the seal names, then re-hashed and
  confronted with the digest `identity.files[]` records for that category; each
  `.lad` is **rebuilt from the file it indexes** by the sampling rule above and
  confronted with `build.caches.<cat>.sha256`; the identity block is
  re-serialized and re-hashed, and must give `fingerprint`. Rebuilding the
  ladder is what separates "intact" from "right".
- **the records, one more read** (`--deep`). Per category: digests strictly
  ascending (order and deduplication in one statement), as many records as
  `build.files.<cat>.records`, a `flags` byte with no meaning outside the
  eight bits above (and, for `keys`, never `UNCOMPRESSED` together with
  `XONLY`), and every `first_height` between 1 and the watermark.

The highest `first_height` a deep pass finds is the archive's coverage
**floor**; the tail above it cannot be proven at all, because a stretch of
chain that reveals nothing new leaves no record. Without `--deep` the coverage
is taken on trust, and the report says so.

## What v3 removes

- The v1 projection (`archive v1-digests`) and its three published digests:
  they were defined over the over-collected set that the filter removes, so no
  projection of a v3 archive can reproduce them. They stay reproducible from
  the chain with the release that wrote them, which is what a historical
  number needs.
- Every reader of `reveal-archive-v1` and `reveal-archive-v2`. An archive in
  those formats is refused by its tag, with the release that reads it named.

## Constants, for a porter and for the test that pins this page

| name | value |
|---|---|
| `CAT_ORDER` | `keys`, `scripts20`, `scripts32` |
| record widths | 24, 24, 36 |
| digest widths | 20, 20, 32 |
| `first_height` | u24, big-endian, 1..watermark |
| `ARCHIVE_LADDER_EVERY` | 2048 |
| `keys` flags | 1, 2, 4, 8, 16, 32, 64, 128 as listed; 16 and 128 never together |
| `scripts*` payload | `inner_keys`, saturating at 255 |
| reduction at fusion | flags `or`, `inner_keys` `max`, `first_height` `min` |
| identity tag | `reveal-archive-v3` |

## Notes for porters

- A reader needs only: for a query `(digest, category)`, binary-search the
  category's merged file **and** each unfused run of that category; OR the flag
  bytes of any hits. Membership + flags are the whole answer.
- To ask about a **point** rather than a serialization, query the digest of
  its compressed form; the record's `OTHER_FACE` says whether the chain also
  showed another form, whose digest is a second query. From a 33-byte key the
  65-byte digest needs the square root described above; from 65 or 32 bytes
  the compressed digest needs nothing.
- The ladder sidecar is an **optional accelerator**, not required for
  correctness.
- Record widths are `digest_width + 1 + 3`; files are sorted by the digest
  prefix, so `memcmp` on the leading bytes drives the search.
- "Not in the archive" = not revealed on-chain up to the watermark, confirmed
  blocks only; off-chain exposure is invisible by declaration. A script lock
  whose script has the shape of a key or a signature is the one declared
  exception, and its count is on this page.
