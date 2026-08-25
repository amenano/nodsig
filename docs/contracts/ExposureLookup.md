# ExposureLookup — contract

**Capability.** Was the key or script behind a lock **ever revealed on-chain**?
A membership check against the archive of every public key and candidate script
that appeared in an unlocking context in confirmed blocks — answered from local
disk, with **where** a key was seen and **when** it was first seen.

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [RevealArchive-v2](../formats/RevealArchive-v2.md).
- **Reference impl:** `RevealArchiveExposure.query` + the `lookup` command.
- **Independent of** the outpoint index/derivatives: this reads the reveal
  archive only.
- **Backs:** the exposure line of the pocket-knife answer (which adds
  address→digest decoding on top).
- **Types:** `u32`, `bool`, `digest20`, `digest32`, `Source`, `Status`,
  `Result<T>` — see [types](../types.md).

> **What the archive stores** (and does NOT). It stores **revelations**, not
> answers: the set of digests that appeared, deduplicated, each with the
> **lowest** height it was ever seen at. So this capability answers *whether* and
> *when first*, never *how many times* or *in what order*, which the
> deduplication has folded away for good.
>
> **Honest boundary (MUST be surfaced).** "Not revealed" means **not revealed in
> confirmed blocks up to the watermark**. Off-chain exposure and unconfirmed
> mempool are **invisible here by declaration**. Every negative MUST carry this
> qualification.
>
> **Digest, not address.** The input is a digest + its category. Decoding an
> address to `(digest, category)` and explaining what a hit means per lock type is
> upstream (the `addr` codec), never here.

## Categories (which digest, in which partition)

The archive is partitioned; **categories never mix** — a digest is only looked up
in its own partition:

| Category | Digest | Partition | What a hit means |
|---|---|---|---|
| `KEY` | `digest20` (hash160 of a public key) | `keys` | that public key appeared in an unlocking context |
| `REDEEM_SCRIPT` | `digest20` (hash160 of a script) | `scripts20` | that P2SH redeem script was revealed |
| `WITNESS_SCRIPT` | `digest32` (sha256 of a script) | `scripts32` | that P2WSH witness script was revealed |

A digest whose width does not match its category is an **error**
(`INVALID_DIGEST`), not a negative.

## Source & status

Every return carries `Source { id, watermark:u32, fingerprint:digest32 }`:
- `watermark` = highest confirmed height the archive covers.
- `fingerprint` = the archive's canonical fingerprint **when it is fully merged**.
  The archive is appendable: a query also consults **unfused runs**, so if runs
  are present the source is watermark-defined but not a single sealed fingerprint;
  that state MUST be reported (fingerprint absent / "includes N unfused runs"),
  never presented as a sealed result.

Status: `OK` (including a definite `revealed=false`); `UNSUPPORTED` (a source
without this capability). `UNDETERMINED` is not used — membership is definite up
to the watermark.

## Operations

### `exposure(digest: digest20 | digest32, category: Category) -> Result<{ revealed: bool, where: RevealWhere, uncompressed_form: bool, inner_keys: u8, first_height: u32 }>`

Membership of `digest` in the category's partition (merged file **reduced** with
any unfused runs of that category):

```
RevealWhere = {                 // meaningful only for category KEY; all false otherwise
    in_scriptsig:          bool,   // the key was pushed directly in a scriptSig
    in_witness:            bool,   // pushed directly in a witness
    inside_redeem_script:  bool,   // found inside a revealed redeem script (a cosigner)
    inside_witness_script: bool,   // found inside a revealed witness script (a cosigner)
}
```

- `revealed = true` ⇒ the digest is present. For `KEY`, `where` is the OR of every
  sighting's four **provenance** bits.
- `uncompressed_form` (`KEY` only) is the record's fifth bit, and it is
  deliberately **not** a `where`: it says the key was serialized in the 65-byte
  uncompressed form, which is a property of the key and not a place it was seen.
  It is constant across sightings by construction (the two serializations of one
  point hash to *different* digests), so the OR is a no-op on it, which is what
  keeps append ≡ rebuild true. A port MUST NOT fold it into the provenance group.
- `inner_keys` (`REDEEM_SCRIPT`/`WITNESS_SCRIPT` only) is how many pubkey-shaped
  pushes that script carried, saturating at 255; those categories have no
  provenance, so `where` is all-false and carries no meaning. Reading this count
  as flags is the mistake the format names explicitly: it would tell a multisig
  owner their key had signed when only the script surfaced.
- `first_height` is the **lowest** height the digest was ever seen at (sightings
  merge by `min`). It is a first-reveal claim and nothing more. (The same claim
  restated in time order, for window reads, is the
  [`FirstReveal-v1`](../formats/FirstReveal-v1.md) artifact; this lookup stays
  the one road for a single digest.)
- `revealed = false` ⇒ not present up to the watermark (definite negative, with
  the off-chain/mempool qualification above).
- Width/category mismatch ⇒ `INVALID_DIGEST` (error), distinct from a negative.

## Invariants a re-implementation MUST hold

1. **Categories never mix**: look up a digest only in its own partition.
2. **Merged + runs reduced, per field**: a hit in any unfused run counts, and the
   reduction is the format's, field by field: `or` on a key's flags byte (a no-op
   on the form bit, a union on the four provenance bits), `max` on a script's
   `inner_keys`, `min` on `first_height`. All three are associative and
   commutative, which is why the answer cannot depend on how many fusions have
   happened.
3. **No claim beyond first reveal**: report `first_height` and never a count of
   sightings, a last height, or an ordering: deduplication folded those away.
4. **Negative is qualified**: "not revealed up to `watermark`, confirmed blocks
   only; off-chain invisible by declaration".
5. **Over-collection is harmless, never wrong**: a stored digest can only match a
   lock that is its exact preimage; extra records cost bytes, not correctness.
6. Determinism & source as above; `INVALID_DIGEST` for a wrong-width digest.

## Conformance vectors

`tests/fixtures/exposurelookup/` (to be added): a small archive (merged, plus a
case with an unfused run) and expected `exposure` results for: a revealed key with
several `where` flags, one revealed in the uncompressed form, a key first seen
below and sighted again above a run boundary (`first_height` must be the lower),
a revealed redeem script with its `inner_keys` count, a revealed witness script, a
never-revealed digest (negative), a hit that lives only in an unfused run, and a
wrong-width digest (`INVALID_DIGEST`). A port passes iff it reproduces every
result (and the archive fingerprint where merged).

## Notes for porters

- Each partition is a **sorted, fixed-width** file: record =
  `digest_width + 1 byte + 3 bytes`, the byte being the flags for `keys` and the
  `inner_keys` count for the two script partitions, the three being
  `first_height` big-endian. A lookup is a binary search on record boundaries,
  no full load. Performance strategy; reproduce the membership and the fields
  however you like.
- The **published v1** archive had the same records without the height, and with
  the scripts byte reserved and zero. `archive v1-digests` projects a v2 archive
  back to that layout, which is how new code is confronted with the historical
  artifact; a port that wants the same confrontation needs the same masks
  (see RevealArchive-v2).
- A merged file may carry a **ladder sidecar** that turns the search into one
  bucket read (see RevealArchive-v2). It is an optional accelerator, excluded
  from the fingerprint: with or without it the answer is identical.
- Appendability: the merged file of a category plus zero or more run files of
  that category; a correct lookup consults all of them. Take both file names
  from `manifest.json` (`categories.<cat>.file`, `caches.<cat>.file`) — merged
  files carry a generation number, so a name derived from the category alone
  will miss them.
