# RevealArchive-v4: format (L0)

The complete archive of every public key and every script **ever revealed** in
confirmed blocks: pushed in an unlocking context, published in an output, or
sitting inside a revealed script. It answers the exposure question with a
local membership check, and is **appendable** from day one (the card-index
seed). Read by [ExposureLookup](../contracts/ExposureLookup.md).

- **Directory:** one merged file per category (`archive_<cat>_g<NNNN>.bin`), one
  ladder sidecar per category (`archive_<cat>_g<NNNN>.lad`, a search cache: see
  below), zero or more run files under `runs/` (unfused), `state.json`,
  `manifest.json` (after `merge`), and `proof/`, the sibling artifact
  `reveal-proof-v1` that the same fusion seals (see *The proof*). The
  four-digit **generation** counts fusions; the manifest names each file, so a
  reader never derives a name (see *Appendability*).
- **Defined over:** nothing; it is produced from confirmed blocks (optionally
  co-emitted with a Graph-v2 scan).
- **Supersedes:** `reveal-archive-v3`, which this release neither reads nor
  reproduces. An archive sealed under v3 keeps its fingerprint as a historical
  number, reproducible from the chain with the release that wrote it (2.1.2).

What changed from v3, in one paragraph: the two script partitions hold the
candidates **the chain proves** to be scripts, instead of the candidates a
shape filter let through. v3 dropped a candidate that looked like a key or a
signature, and with it some real scripts and the keys inside them (measured on
the chain through height 957,301: 73 P2SH and 17 P2WSH locks answered
"protected" after their script was revealed, and 2,699 key digests were never
recorded). v4 keeps every candidate through the scan, records the programs of
the P2SH and P2WSH outputs the chain created, and decides at the fusion. The
candidates no program opens are kept too, beside the archive, because a
program created later can open them. The exception v3 counted and declared no
longer exists.

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
Widths, order and ladder step are the ones of v3: what changed is which records
the script partitions hold.

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

For a script, `first_height` is the height its **bytes** first appeared as a
candidate, not the height its program was created: a script pushed at height
2 whose P2SH output is created at height 4 carries 2. The preimage of the lock
was public from 2.

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
moment of spending cares about the point, never about the string. Locks are
built on serializations, so the archive keeps one digest per serialization, and
one **invariant**:

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
FLAG_INNER_SIG    = 4    // inside the last scriptSig push, a candidate redeem script (a cosigner)
FLAG_INNER_WIT    = 8    // inside the last witness item, a candidate witness script, or a revealed taproot leaf
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

The inner bits are set for the keys inside **every** candidate, proven or not
(see *What one sighting emits*): a key pushed inside bytes that turned out not
to be a script is still a key the chain published.

### The `inner_keys` byte (categories `scripts20`/`scripts32`)

How many public-key-shaped pushes were found **inside** that script, saturating
at 255. The extraction has just walked the script looking for keys, so the
number is free. It is a function of the script bytes, so every sighting of one
script agrees; sightings merge by `max`, which is a no-op that a test pins.
The partitions hold scripts the chain proved and nothing else, so this byte is
what its name says: a census of multisig shapes across the whole chain.

## What one sighting emits

For every input of every non-coinbase transaction, with `pushes` the data
pushes of the scriptSig and `items` the witness:

1. every push that `canonical_key` accepts: a `keys` record for the digest
   seen, with `SIG` and its form bit; and, when the compressed digest differs,
   a second record for it with `OTHER_FACE`, at the same height;
2. every witness item that `canonical_key` accepts, **wherever it sits**, the
   same way with `WIT`. No position is excluded: a P2WSH spend of a conditional
   script puts a genuine key where a taproot spend would put a signature, and
   excluding that position cost 804 key digests on the chain (corrected in
   2.1.2). A 65-byte signature mistaken for a key is a record that can only
   match its own preimage;
3. the last scriptSig push and the last witness item are the **candidate
   scripts** of `scripts20` and `scripts32`, whatever they look like, unless
   their bytes prove they cannot be a script (see *The proof*); a candidate
   yields its script record with `inner_keys`, and every key inside it yields a
   `keys` record with `INNER_SIG` or `INNER_WIT` (plus `OTHER_FACE` when the
   forms differ). Whether the script record reaches the archive is the fusion's
   decision; the keys inside reach it in any case;
4. when the last witness item (after removing an annex) has the shape of a
   control block, the internal key in its bytes 1..33 yields
   `hash160(02 || x)` with `WIT | XONLY`, and in the leaf (the item before it)
   every 32-byte push followed by `OP_CHECKSIG`, `OP_CHECKSIGVERIFY` or
   `OP_CHECKSIGADD` yields `hash160(02 || x)` with `INNER_WIT | XONLY`. The
   leaf itself is walked for keys and is **not** a `scripts32` candidate;
5. when the input has a witness and its last scriptSig push is `0020 <32>`,
   the 32 bytes are a **program** (`PROGRAM_NESTED`, below).

For every output of every transaction, coinbase included:

6. a scriptPubKey of the form `<key> OP_CHECKSIG` (P2PK) or
   `OP_m <keys> OP_n OP_CHECKMULTISIG` (bare multisig) yields, for every push
   `canonical_key` accepts, a `keys` record with `OUT` and its form bit, plus
   the `OTHER_FACE` record when the forms differ. A taproot output publishes
   its key by construction and no lock hides behind it: it yields nothing;
7. a scriptPubKey `a914 <20> 87` (P2SH) or `0020 <32>` (P2WSH) yields a
   **program** (`PROGRAM_OUTPUT`, below).

The `first_height` of an `OTHER_FACE` record is the height of the sighting
that produced it, which is exactly when that `x` became public. The genesis
block is not scanned, so the one key of its coinbase is the one P2PK key the
archive does not hold; the page says so instead of the archive pretending.

## The proof

The scan sees the input that spends, never the output it spends. From the
unlocking data alone a redeem script and a public key are the same bytes (a
33-byte script starting with `02` is a push of two bytes), and a witness script
and a signature can be too. 1.x kept every candidate and filled its script
partitions with keys and signatures; v3 guessed from the shape and dropped real
scripts. v4 follows one rule, with no exception:

> An item is excluded only when the chain itself proves it cannot be what it
> would be archived for. A shape is not a proof. A position is not a proof.

The proof is in the chain, only not in the input. A redeem script runs only
behind a P2SH output whose program is its `hash160`; a witness script runs only
behind a witness program that is its `sha256`, either a P2WSH output or the
`0020 <32>` redeem script of a P2SH-P2WSH spend. So:

1. the **scan** keeps every candidate (records 3 above) and every program
   (records 5 and 7), in runs of their own;
2. the **fusion** fuses the programs, then joins the candidates with them: a
   candidate whose digest is among the programs is a revealed script and joins
   `scripts20`/`scripts32`; any other is set aside.

A nested witness script needs its own program because no output carries it:
the output holds `hash160(0020 <32>)`, and the `<32>` is in the redeem script.
BIP 141 makes that redeem script the scriptSig's only push, and a witness on
any other spend of a non-witness output invalid, so the test of record 5 (any
input with a witness whose last push is `0020 <32>`) can only add programs to
the ones consensus implies, never miss one.

**Why what is set aside is kept.** "No program opens this candidate" is a
proof at a height, not forever: anyone can create an output with any program
later, and from that block the old candidate is the published preimage of a
lock. A rebuild at the later height sees the old candidate and the new program
together and keeps it; an archive grown from the earlier seal must do the same,
or appending would not equal rebuilding. So the candidates not proven and the
programs are a second artifact, sealed in the same fusion: a program appearing
in a later run promotes a candidate the proof has held since its first
sighting, with that sighting's height.

**What the bytes still exclude.** Two shapes are proofs rather than guesses,
because the first byte of a script always executes: a **control block** (length
`33 + 32m`, first byte `c0` or `c1`) and, as the last item of a witness of two
or more, an **annex** (first byte `50`). Both fail the script at its first
opcode. They are neither candidates nor kept in the proof, and `control_or_annex`
counts them.

**The second road needs no proof.** `reuse scan` burns a candidate only against
a lock, and a lock in a snapshot is a program the chain created: the lock set is
its proof. The two roads meet at the cross-check without sharing this step,
which is two independent ways to the same fact rather than one rule written
twice.

The state counts `control_or_annex`, `unparsed_candidates` (candidates that do
not parse as a script: almost all are keys and signatures, walked for keys like
every candidate), `out_keys`, `program_outputs` and `nested_programs`.

## `reveal-proof-v1`: the proof beside the archive

- **Directory:** `<archive>/proof/`: one merged file and one ladder per
  category (`proof_<cat>_g<NNNN>.bin` and `.lad`, the archive's generation) and
  `manifest.json`.
- **Sealed by** the archive's `merge`, in the same fusion and at the same
  coverage; **declared parent** the archive sealed with it.
- **Needed** to grow the archive and to audit that the proof was applied
  (`archive verify --deep`). **Not needed** to read the archive: every question
  up to the watermark is answered without it.

| category | record width | layout |
|---|---|---|
| `programs20` | 24 | `program20` \| `carrier:u8` \| `first_height:u24` |
| `programs32` | 36 | `program32` \| `carrier:u8` \| `first_height:u24` |
| `unproven20` | 24 | as `scripts20`: a candidate no program opens |
| `unproven32` | 36 | as `scripts32` |

Fixed order: `PROOF_ORDER = (programs20, programs32, unproven20, unproven32)`.
The `carrier` byte of a program is a bitfield OR-ed across sightings:
`PROGRAM_OUTPUT = 1` (an output was created with it), `PROGRAM_NESTED = 2` (a
P2SH-P2WSH spend pushed it). A program's `first_height` is the lowest height of
either. An `unproven*` record reduces like a script record (`max`, `min`).

Two invariants hold between the two artifacts at every seal, and `verify
--deep` checks both with a merge-join: **every digest in `scripts20`/`scripts32`
is among the programs of its width**, and **no digest in `unproven20`/`unproven32`
is**.

On the chain through height 957,301, projected from the counts 2.0.0 measured
and to be measured at the 3.0.0 run: the candidates v3 dropped by shape were
about 1.47 billion records (594 M 20-byte, 878 M 32-byte), about 45 GB at these
widths, of which the control blocks stay out; the programs are 780 M P2SH and
56.8 M P2WSH outputs, whose distinct 20-byte programs alone take 7.2 GB as bare
digests. The archive a reader receives stays the size of v3; the builder who
means to grow it keeps the proof as well.

## Appendability

The canonical form at height H is one well-defined set of bytes whatever the run
boundaries were: an interrupted-and-resumed scan **fuses to the same files** as a
one-shot scan, and an archive grown in two takes to the same files as one built
at once (the determinism rule). Every record is a pure function of the item's
bytes, its position and the height; the proof is membership in a set that only
grows; every flag merges by `or`, every count by `max`, every height by `min`.
A lookup consults the merged file **plus** any unfused runs of that category,
and for a script partition applies the proof to the candidates of the runs and
of the proof's pile, against the programs of the proof and of the runs: a reader
gives the answer the next fusion will seal.

**A fusion is additive, and that is what makes it crash-safe.** It writes
generation N+1 of the archive and of the proof **beside** generation N and
deletes nothing before its commit, which is three writes in this order: the
archive's `manifest.json`, the proof's `manifest.json`, the state that stops
naming the runs. The consumed runs and the superseded generations are deleted
after all three. Nothing a manifest names is ever overwritten while it still
names it. On the next `merge`, whatever a manifest does not name is swept: the
rule the runs already lived by. The first fusion of a scan reads the whole run
pile; `merge` prints the pile and the space it needs and refuses before the
first byte when the disk has less.

A kill between the two manifests leaves the new archive beside the previous
proof, with the runs still named and the watermark already sealed. That state is
recognized (runs pending at the sealed watermark, a proof whose parent is the
archive's `fused_onto`), a scan refuses to run on top of it, and the next
`merge` fuses the same runs again and lands on the same bytes: every candidate
the previous proof promotes is already in the archive, and merging a record
twice is merging it once. The order matters: committed the other way round, the
new proof would no longer hold the candidates it promoted while the archive
holding them was swept.

## A sealed archive without its state

An archive handed over as its merged files and `manifest.json`, with no
`state.json` and no runs, is read as it is: the watermark comes from the
coverage and the block at the watermark from `build.last_block_hash`. With its
`proof/` beside it, a scan **grows it from its seal**: the first block fetched
must link to that hash, and the fusion needs the proof it was sealed with. A
scan refuses to grow an archive whose proof is missing or is another archive's.

## Watermark & manifest

`manifest.json` follows the shared shape in
[Artifact](../contracts/Artifact.md): an `identity` the fingerprint covers
(format tag, coverage, the three category digests in `CAT_ORDER`) and a `build`
block that does not. `identity.coverage.to` is the **watermark**. With unfused
runs present the archive is queryable but **not sealed**, and that state must be
reported: there is no single sealed fingerprint yet.

`build` holds the generation, file names, records and ladders, and five fields a
reader holding only this manifest needs:

| field | what it is |
|---|---|
| `last_block_hash` | the block at the watermark, display order |
| `proof` | `{format, fingerprint}` of the proof sealed in the same fusion |
| `fused_onto` | the fingerprint of the generation this one was fused onto, or null |
| `unproven` | `{scripts20, scripts32}`: how many candidates the proof holds, the archive's answer to "what did you leave out" for a reader who never received the proof |
| `kernels` | which road scanned the runs fused here: `["python"]` (the reference), `["native"]` (the C kernel, `nodsig.kernel`), or both across resumes. How the bytes were made, never what they are: both roads write the same bytes, and the fingerprint does not depend on it |

`build.files.<cat>.file` is the **authority** on which file holds a category:
resolve it from the manifest, never by formatting the category name.

## Canonical fingerprint

The shared recipe, stated once in [Artifact](../contracts/Artifact.md): the
identity block is serialized to bytes and hashed. For this format that block
holds the tag `reveal-archive-v4`, the coverage, and the three category digests
in `CAT_ORDER`; for the proof, the tag `reveal-proof-v1`, the same coverage and
the four digests in `PROOF_ORDER`. Same chain + same height, same fingerprints
on any machine; and the same chain read under v3 gives a different one, on
purpose: the records are not the same set.

Note what it does **not** contain: a file name, a generation, a record count.
And note what it **does** contain, which the file digests could never state on
their own: the coverage. An archive of hashes carries no heights outside its
`first_height` fields, so a manifest could otherwise claim a taller watermark
than the scan reached and every "not revealed up to H" would inherit the lie.

## Ladder sidecars (search caches, NOT fingerprinted)

Each merged file, of the archive and of the proof, has a sibling `.lad` of the
same generation: the key of **every `every`-th record**
(`ARCHIVE_LADDER_EVERY`, 2048), concatenated, in file order. A lookup loads the
ladder once (resident, tens of MB at chain scale), bisects it in RAM to pick a
bucket, and reads **one** `every`-record slice from the merged file: one
round-trip where a blind on-disk binary search pays about `log2(records)` seeks.
The manifest records `{ file, every, sha256 }` per category.

The ladder is a **pure cache**: deterministic, excluded from the canonical
fingerprint, and its `every` may change without changing the archive's
identity. A reader with no ladder must fall back to the blind bisect and get
the **same** byte: the ladder only decides *where* to read, never *what* is
returned. Keys in a merged file are **unique**, so a lookup matches 0 or 1
record; the entry rule is the shared one (invariant 9 in
[INVARIANTS](../INVARIANTS.md)).

## Verifying a sealed archive

`archive verify` is this audit; the recipe is written out here so a porter can
run it without reading the implementation. Two roads, checking different things,
applied to the archive and then, when it is there, to its proof:

- **the bytes, one read.** Each merged file named by `build.files.<cat>.file` is
  compared by size with the records the seal names, then re-hashed and
  confronted with the digest `identity.files[]` records for that category; each
  `.lad` is **rebuilt from the file it indexes** by the sampling rule above and
  confronted with `build.caches.<cat>.sha256`; the identity block is
  re-serialized and re-hashed, and must give `fingerprint`. For the proof, its
  coverage must equal the archive's, and its parent and the archive's
  `build.proof` must name each other. Rebuilding the ladder is what separates
  "intact" from "right".
- **the records, one more read** (`--deep`). Per category: digests strictly
  ascending (order and deduplication in one statement), as many records as
  `build.files.<cat>.records`, a `flags` byte with no meaning outside the
  eight bits above (and, for `keys`, never `UNCOMPRESSED` together with
  `XONLY`), a `carrier` byte of `1`, `2` or `3` for a program, and every
  `first_height` between 1 and the watermark. Then the proof itself: the two
  invariants between `scripts*`, `programs*` and `unproven*`.

The highest `first_height` a deep pass finds is the archive's coverage
**floor**; the tail above it cannot be proven at all, because a stretch of
chain that reveals nothing new leaves no record. Without `--deep` the coverage
is taken on trust, and the report says so. Without a proof the report says the
archive cannot grow.

## What v4 removes

- The shape filter on candidates, its three counters (`filtered_key_shaped`,
  `filtered_signature_shaped`, `filtered_control_or_annex`) and the declared
  exception v3 published for it. `control_or_annex` counts the one exclusion
  left, which is a proof.
- `malformed_inner_script`, which counted inner scripts that do not parse and
  now would count mostly keys and signatures: `unparsed_candidates` says so.
- The limit sentence `check` printed for a script lock under the exception.
- Every reader of `reveal-archive-v3`, `reveal-archive-v2` and
  `reveal-archive-v1`. An archive in those formats is refused by its tag, with
  the release that reads it named.

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
| reduction at fusion | flags `or`, `inner_keys` `max`, program carrier `or`, `first_height` `min` |
| identity tag | `reveal-archive-v4` |
| proof tag | `reveal-proof-v1` |
| `PROOF_ORDER` | `programs20`, `programs32`, `unproven20`, `unproven32` |
| program carrier | 1 (`PROGRAM_OUTPUT`), 2 (`PROGRAM_NESTED`) |

## Notes for porters

- A reader of a sealed archive needs only: for a query `(digest, category)`,
  binary-search the category's merged file. Membership + flags are the whole
  answer.
- A reader of an archive with unfused runs searches each run of the category
  too and ORs the hits; for `scripts20`/`scripts32` a hit in a run, or in the
  proof's `unproven*`, counts only when the digest is among the programs of the
  proof or of the runs.
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
  blocks only; off-chain exposure is invisible by declaration. A lock whose
  script is shaped like a control block or an annex cannot be spent, and its
  script is not archived.
