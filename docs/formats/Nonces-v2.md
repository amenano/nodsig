# Nonces-v2: format (L0)

Every **signature nonce point** ever published in a confirmed block, sorted, with
the height that published it. A repeated point is the finding: one key signing
two different messages with the same nonce leaks that key with school algebra,
and the repetition is visible from public data alone.

- **Directory:** one merged file (`nonces_g<NNNN>.bin`), its ladder sidecar
  (`nonces_g<NNNN>.lad`, a search cache: see below), zero or more run files
  under `runs/` (unfused), `state.json`, and `manifest.json` (after `merge`).
  The four-digit **generation** counts fusions; the manifest names the file, so
  a reader never derives a name.
- **Defined over:** nothing. It is produced from confirmed blocks, co-emitted by the
  scan that builds [RevealArchive-v2](./RevealArchive-v2.md).
- **Read by:** `nonces groups` and `nonces lookup` for the chain-wide question,
  and `nonces address` for one address of yours, which joins the outpoint index
  and a node to it. The how-to is [`../nonce-check.md`](../nonce-check.md).
- **Built by:** `archive scan --nonces <dir>`, then `nonces merge`. That pass
  only, and not the reuse scan which also hosts `--graph` and `--headers`: one
  host is enough for an artifact fed from the per-input walk, and this is the
  pass that walks inputs for the archive anyway.

## What one record is

One record is **one signature**, 16 bytes:

| field | width | meaning |
|---|---|---|
| `point` | 12 | top 12 bytes of the 32-byte nonce point, big-endian |
| `height` | 3 | the block the signature was confirmed in (u24, big-endian) |
| `flags` | 1 | the signature scheme, and the sighash mode it committed to |

Records are sorted by the **whole record**, so the order is point, then height,
then flags: a point's sightings come out in chain order, which is the order a
reader wants them in.

```
FLAG_ECDSA   = 1   // DER signature, the r of (r, s)
FLAG_SCHNORR = 2   // BIP 340 signature, its leading R.x
                   // bits 2..4: the sighash code, see below
```

Exactly one **scheme** bit is set per record, because a record is one signature.
The byte is a bitfield and not an enum so that a group can be summarized by
OR-ing its members, and so a future scheme costs a bit rather than a format.

### The sighash code (bits 2..4)

What the signature committed to, in three bits that were idle:

| code | meaning | byte |
|---|---|---|
| 0 | `default` — no sighash byte at all | the 64-byte BIP 340 form |
| 1 | `all` | `0x01` |
| 2 | `none` | `0x02` |
| 3 | `single` | `0x03` |
| 4 | `all\|acp` | `0x81` |
| 5 | `none\|acp` | `0x82` |
| 6 | `single\|acp` | `0x83` |
| 7 | `nonstandard` | any other byte |

The map is exact and closed, and the collapse into `nonstandard` is deliberate:
an ECDSA sighash byte is **not constrained by consensus** (BIP 66 validates the
DER shape; strict encoding is policy), so early history holds bytes no rule
describes, and giving each oddity a code would be inventing meaning the chain
does not carry. Taproot's byte **is** constrained, to the six standard values,
so a Schnorr record can never carry code 7 and `verify --deep` refuses one that
does. Absence gets its own code rather than being folded into `all`: that the
short form was used is a fact about the signature, not an interpretation.

Why it is here and not derivable later: recovering a key from a repeated nonce
needs the two message digests, and which parts of the transaction each
signature committed to is half of that. The extraction has the byte in hand
(it is the DER trailer it already validated, or the 65th byte of the long
form), so the cost is zero bytes and zero work, and no artifact this project
keeps could give it back: [Graph-v2](./Graph-v2.md) holds no unlocking data and
[RevealArchive-v2](./RevealArchive-v2.md) holds hashes. The price, stated: a
flags byte now has ~32 valid values out of 256 instead of 2, so it detects a
little less corruption on its own — the file's sha256 is what detects it.

### The two schemes share one keyspace, on purpose

ECDSA's `r` and Schnorr's `R.x` are the same quantity: the x-coordinate of
`k*G`, on the same curve. A wallet with a broken generator that signs a legacy
input and a taproot input with the same `k` is compromised across both, so
separating the schemes into two partitions would hide exactly the case a census
exists to find. They are therefore sorted together, and `flags` records which
scheme each sighting used.

### Truncation to 12 bytes

The point is truncated, not hashed: the top bytes, so the order of the truncated
key is the order of the full one. For **drawn** nonces the shortening is free:
with 3.4 billion signatures over 96 bits the expected number of accidental
collisions is about **7e-11**. Twelve bytes rather than eight is a deliberate
margin: eight would put the expectation near 0.3, which is small but no longer
negligible, and the saving (3 bytes a record) is not worth spending certainty
on.

That estimate assumes the values are drawn, and **the chain's are not all
drawn**, which is where it stops applying. A short `r`, whether constructed or
degenerate, spends most of the 12 bytes on zeros and has few left to
distinguish it. Measured at height 957,301: **one group in 5,149** turned out
to be a prefix collision rather than a repeated nonce, and its three scalars
were `0`, `1` and `82`. So a repeated point is a repeated nonce **for values
the estimate covers**, and for the rest it is a candidate that the whole
scalar settles: that is one of the things the witness table keeps
(see [`Nonces-witness-v1`](Nonces-witness-v1.md)).

The general lesson, stated because it cost something to learn: a probability
computed over an assumed distribution is not a measurement, and this format's
population is not the assumed one.

### Nothing is deduplicated

Two signatures sharing a nonce **inside one block** are two records with the
same point and the same height. Collapsing them would erase the finding, so
equal records survive the fusion; the merge counts them and reports the count in
`build`. This is the one place where this format's fusion differs from the
archive's, and it is why it can use the shared append-and-fuse store unchanged:
the merge **reduces nothing**.

## What a group means, and what it does not

A **group** is a point with two or more records. It is a *candidate*, and the
format cannot promise more:

- recovering a private key needs one key signing twice with one nonce. A record
  holds no key, so a group is grounds for a look and not a conclusion;
- for a taproot **key-path** spend the public key is not even in the input: it
  lives in the `scriptPubKey` of the output being spent, which a pass over
  unlocking data never sees;
- what closes the gap is the `height` on every record. Groups are rare, so the
  keys can be recovered by re-reading only the blocks a group names. That is
  what the height is for, beyond dating the sighting.

Two properties of real groups, measured over the chain before this format was
written, because they decide how a reader must be built:

- **repeated points are rare, repeated sightings are not.** In a sparse sample
  of 1,200 blocks (4.25 million inputs) there were 4.66 million distinct points,
  **4** repeated, and **4,491** sightings of a single value. Any report must
  count the two separately or it will describe a handful of constructions as an
  epidemic;
- **the biggest groups have a shape, and the shape is not a reason.** Tiny
  nonces (`r` with its top bytes zero) recur for years across unrelated
  transactions, and sorting groups by size puts those first. That makes the
  tiny-`r` shape the cheapest first filter a reader can apply, and nothing
  more: chance produces it about once in 2^24, a short `r` does shorten a
  signature's encoding, and the format cannot tell those apart. Reading the
  blocks a group names is what decides, and the chain rewards doing so: the
  largest group on the chain is one 166-bit `r`, which no fee-saving grind
  reaches, republished across a decade.

## What it does not cover

**Only exact repetitions.** A nonce that is merely biased or partially leaked is
attacked with lattice methods over many signatures of one key: different inputs,
different computation, and out of this format's perimeter. Saying so is part of
the format, because an artifact that is silent about its perimeter invites the
reading that it has none.

Inputs that carry **no signature** contribute no record, and that is not a gap:
pay-to-anchor spends have an empty witness and scriptSig by construction, and
some scripts are satisfied with no signature at all. On a recent sample 1.6% of
inputs produced nothing, and 84% of those had an entirely empty witness.

**A record means the bytes had a signature's SHAPE, not that they were one.**
The filter checks the three markers, the two lengths and the total, which is
strong enough that a false positive has to be data deliberately shaped like a
signature. The chain contains some: resolving the groups at height 957,301
found one point whose 12 bytes cover three different scalars, and they are
`0`, `1` and `82`. None can be a nonce point, since ECDSA requires
`0 < r < n` and an `r` of 1 would ask a curve point's x-coordinate to be one.

This format does not apply that validity rule, and the omission is stated
rather than repaired in place: adding it would change what is collected and
therefore the canonical fingerprint of every census already sealed. What
resolves such a point is the witness table, which keeps the whole scalar
(see [`Nonces-witness-v1`](Nonces-witness-v1.md)).

Note which rule is legitimate and which is not. `r == 0` and `r >= n` are
invalid by definition. A rule on SIZE would be wrong: the chain carries real
signatures, validated by consensus, whose `r` is 166 and 223 bits, so any
"too small to be genuine" threshold would reject genuine data.

## Appendability

New blocks only ever **add** runs, and a fusion folds runs plus the previous
generation into the next one. Because the merge reduces nothing and every record
carries its own height, the result does not depend on when the fusion happened:

**append ≡ rebuild.** An archive grown in two passes holds the same bytes, and
therefore the same fingerprint, as one built in a single pass to the same
height.

The mechanics (run naming, generation numbering, crash-safe commit order, the
ladder sampled while writing) are the shared store in `genstore.py`, the same
one the outpoint index and the derivatives use. See
[Artifact](../contracts/Artifact.md).

## Rewind

**rewind ≡ rebuild.** `nonces rewind --to-height H` produces exactly the bytes a
build stopped at `H` would have written, for any `H` the artifact already covers.

It is a fusion with a filter, not a second builder: dropping every record whose
height is above the cut leaves a sorted file sorted, so the current generation
becomes its own only source and the store's `sift` does the rest. Nothing needs
rebuilding, because nothing in a record was derived from a record above the cut:
there is no reduction to undo, no minimum to recompute, no flag whose history
was folded away.

This is the property [RevealArchive-v2](./RevealArchive-v2.md) cannot have, and
the contrast is instructive: the archive folds many sightings into one record,
so it cannot restore what it folded; this format keeps every sighting, pays 16
bytes for each, and gets reversibility for it.

## Watermark & manifest

`state.json` carries the working state (the height reached, the last block hash,
the pending runs, the current generation, counters). `manifest.json`, written by
`merge`, carries the seal: an `identity` block and a `build` block, split by the
rule in [Artifact](../contracts/Artifact.md).

In `identity`: the format tag, the coverage, and the file
digest. In `build`: the generation, the file names, the ladder, the record
count, the count of equal keys the merge saw, and the per-scheme tallies. All of
`build` is recomputable from the data, which is why none of it is in the
fingerprint.

## Canonical fingerprint

The shared recipe: `sha256` over the canonical identity block, one logical file
named `nonces`. See [Artifact](../contracts/Artifact.md) for the byte layout.

The coverage is inside the identity, so a claim about how far the scan reached
cannot be moved without moving the fingerprint.

## Ladder sidecar (search cache, NOT fingerprinted)

Every 4096th record's 12-byte point is sampled into `nonces_g<NNNN>.lad` while
the fusion writes, so a lookup bisects the resident ladder (about 10 MB for a
full chain) and reads **one 64 KB bucket** instead of ~32 seeks. It is a cache:
excluded from the fingerprint, and a copy without one still answers by a blind
bisect.

Optional is not the same as trusted. A ladder that is *present* is compared
with the sha256 the state records for it, and a mismatch is refused rather than
used: a rotted rung sends the bisect to the wrong bucket, and the answer would
be a confident "not found". Absent, checked, or refused: never believed.

The step is fixed at 4096 by this format. `verify` rebuilds the ladder from the
file it indexes, inside the pass it already pays for, so an intact ladder built
by a wrong rule is caught rather than compared with itself.

## Verifying a sealed archive

```
nonces verify <dir>          # digests, ladder rebuilt, fingerprint, coverage floor
nonces verify <dir> --deep   # and one pass over every record
```

The fast road re-reads the sealed file, rebuilds the ladder from it, and
recomputes the fingerprint. `--deep` adds a pass over the records that checks
they are **non-decreasing** (equal records are legal here, unlike in the
index), that every `flags` byte holds exactly one scheme bit and nothing
outside the defined ones, that no Schnorr record claims a nonstandard sighash
code, and that every height falls inside the declared coverage. The highest height found is a
**floor** under the watermark: a stretch of chain with no signature would leave
no trace, so a claim above it cannot be confirmed, while a claim below it is
refused.

## Notes for porters

- Big-endian everywhere: byte order is numeric order, so a sorted file sorts by
  the record's meaning.
- Canonicalize `r` before truncating: strip the leading zeros a DER integer may
  carry, then left-pad to 32 bytes. Two encodings of one scalar must produce one
  point, or a real group splits in two and reports nothing.
- A DER signature at exactly 64 or 65 bytes cannot be told apart from a Schnorr
  signature whose `R.x` begins with `0x30`. Parse both readings, count neither
  as malformed: one taproot signature in 256 starts that way.
- A 65-byte item is a Schnorr signature with an explicit sighash byte. Where a
  public key could have been pushed instead, refuse the three first bytes a
  65-byte key can start with (`0x04`, `0x06`, `0x07`); where the witness holds a
  single item, do not, because a lone item cannot be a pushed key and refusing
  it loses 1.17% of that form.
- Schnorr signatures are only looked for where BIP 341 puts them: the sole item
  of a key-path spend, or the items before the script and control block of a
  script-path spend. A witness script or a control block that happens to be 64
  bytes would otherwise repeat identically on every spend of the same tree and
  fabricate a group.
