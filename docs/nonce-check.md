# Checking whether a key gave itself away

[`exposure-check.md`](exposure-check.md) answers whether a key is **public**.
This page answers a different question about the same chain: whether a key is
**computable**. The two are not degrees of the same thing.

Every signature publishes the x-coordinate of the one-time secret behind it, the
nonce. Sign two different messages with one key and one nonce, and both
signatures carry the same value, at which point the private key follows from the
two of them by school algebra. So an exposed key waits on cryptography that has
not arrived, while a repeated nonce is arithmetic somebody can do today, and has
been able to do since the second signature confirmed.

Same discipline as everywhere else here: **nodsig measures a fact, it does not
assess a risk.** The reason this page states the timing so plainly is that the
timing *is* the fact, not a warning wrapped around it.

## What it needs, and what it costs

This is the expensive question, and the honest comparison is with the page next
door:

| | exposure | a repeated nonce |
|---|---|---|
| artifacts | the archive alone (33.9 GB for single-key addresses) | the outpoint index **and** its derivatives (~415 GB) |
| a node | no | **yes** |
| offline | yes | no |
| optional extra | none | the census (~55-60 GB) for the chain-wide view |

**Why it cannot be offline.** No artifact keeps unlocking data. The graph is
flow, not unlocking; the reveal archive keeps hashes; the census keeps 12 bytes
of a nonce point, the height, the scheme and the sighash mode, with no key and
no message attached. The signatures exist only in the blocks,
so the blocks are where they have to be read from. What keeps that cheap is the
index: it says exactly which heights to fetch, so this reads a handful of blocks
and not a chain.

**What is still true of privacy.** Blocks are fetched **by height, from your own
node**, so no address and no query leaves your machine, and no third party is
involved. The promise that breaks is *offline*, not *private*, and the two are
worth keeping apart.

**Two limits that follow from needing blocks:** a **pruned** node cannot answer
for spends whose blocks it has discarded, and the answer is bounded by the
**index watermark**, which is older than the node's tip by construction.

## Two questions, two commands

```sh
# the owner's question: did THIS address's key ever repeat a nonce with itself?
nodsig nonces address <address> --index <index-dir> --derived <derived-dir> \
       --rpc <url> --cookie-file <path/.cookie> [--nonces <nonces-dir>]

# the chain's question: which nonce points repeat, anywhere?
nodsig nonces groups --nonces <nonces-dir>
```

The first is the one to reach for if you own the address. It is also much
smaller than it sounds: every signature a key ever made is a spend of that
lock's own outputs, and a lock has a handful of those.

## Asking about one address

The join is what makes the answer exact. The derivatives say which of the lock's
outputs were spent and by which transaction; the index turns that into a height
and a txid; the node hands back the block. An **outpoint names one input of one
transaction**, so nothing guesses which signature belongs to the address being
asked about. That exactness is also why it works for a taproot key-path spend,
whose public key is not in the spending input at all.

Everything below is real output, printed by the code over the **synthetic
five-block chain of the test suite** (`tests/test_nonces.py`). The heights of 2
and 3 give it away. It is shown instead of chain output for the reason stated at
the end of this page.

```console
$ nodsig nonces address 112D2adLM3UKy4Z4giRbReR6gjWuvHUqB \
      --index <index-dir> --derived <derived-dir> --nonces <nonces-dir> --rpc <url>

112D2adLM3UKy4Z4giRbReR6gjWuvHUqB
  pay-to-pubkey-hash (1…)
  lock 81a232dfed271986129033be5d67100ff354bb86, index through height 5
  2 signature(s) read from 2 block(s):
    height         2  66f1c4b0e5d3a27681f0c5d4  ecdsa    all         in 31bbc4a04c1bc490…
    height         3  66f1c4b0e5d3a27681f0c5d4  ecdsa    all         in 6a7fb21513cc240b…
  REPEATED NONCE 66f1c4b0e5d3a27681f0c5d4 at heights 2, 3
    this lock is opened by ONE key, and the signatures differ, so they signed
    different messages with the same key and the same nonce: the private key
    follows from the two of them, by arithmetic anybody can do
  census: 66f1c4b0e5d3a27681f0c5d4 was also published 1 time(s) by signatures
  that are not this lock's. Two DIFFERENT keys sharing a nonce does not hand
  either one over; it does show the point was not drawn at random, though not
  whether that was a fault or a choice
```

Three other shapes of answer, from the same chain:

```console
  # a script lock: the collision is real, the attribution is not
  REPEATED NONCE 1199aabbccddeeff00112233 at heights 4, 4
    this lock can be opened by several keys, and telling which cosigner signed
    needs verifying signatures, which this tool does not do. The collision is
    real; the conclusion is not automatic

  # a lock that signed exactly once
  one signature only: a nonce cannot repeat with itself, so there is nothing
  here to find

  # a lock that received and never spent
  no signature to examine: this lock has no confirmed spend up to that height,
  so it has never signed
```

That last one is worth stating positively: **an address that has never spent
cannot have this problem**, because it has never signed. It is the one answer
on this page that needs no caveat.

## What the answer means, and what it does not

- **Single-key locks give a conclusive read; script locks do not.** For a
  `1…` or a `bc1q…` 20-byte lock, the signature can only have come from the one
  key, so a repeat is that key signing twice. A `3…` or a 32-byte `bc1q…` can be
  opened by several keys, and pairing a signature with a cosigner means
  *verifying* signatures, which this project deliberately does not do: it has no
  curve arithmetic anywhere. The collision is reported; the conclusion is left
  unmade.
- **Two different keys sharing a nonce hands neither one over.** With
  `s₁ = k⁻¹(z₁ + r·d₁)` and `s₂ = k⁻¹(z₂ + r·d₂)` there are three unknowns for
  two equations. It does show the point was not drawn at random, which is
  worth knowing and is not a key recovery, and it does not say whether that
  was a fault or a choice. The census line says this every time it fires.
- **The `z` in that arithmetic is why the record keeps the sighash mode.** Each
  signature commits to a digest of the transaction, and *which parts* it
  commits to is the sighash byte; without it a reader holding a repeated pair
  would not know what to hash. The census records the mode and never the
  message: recomputing `z` needs the transaction, which is in the blocks, and
  reading it there is the reader's own step.
- **A tiny nonce is a shape, and the shape is not a reason.** Values of `r`
  with their top bytes zero recur for years across unrelated transactions and
  form the largest groups in the census, so the report names them rather than
  letting a size ranking read like an epidemic. Naming is all it does: chance
  puts a drawn nonce there about once in 2^24, a short `r` does shorten a
  signature's encoding and its fee, and three zero bytes cannot tell those
  apart. Re-reading the blocks is what decides, and it is worth doing: the
  largest group on the chain is a 166-bit `r` that no fee-saving grind
  reaches.
- **A repeat is not a reuse until `s` differs, canonically.** The same key
  signing the same message twice publishes one signature, which may be
  serialized twice or appear as the pair `s` and `n-s` (the two legal forms of
  one signature, from nonces `k` and `-k`, whose points share an
  x-coordinate). Both repeat the point and expose nothing. `nonces address`
  compares `min(s, n-s)` for exactly this reason, and the chain contains both
  cases.
- **Only exact repetitions.** A nonce that is merely biased or partially leaked
  is attacked with lattice methods over many signatures of one key: different
  inputs, different computation, out of this perimeter.
- **A lock is one scriptPubKey, not a wallet.** Another address of yours, from
  the same seed, is a different lock and needs its own question. Same boundary
  as the exposure check, for the same reason.

## If it does report a repeat on a lock you control

Treat the key as public, and act on that footing rather than on the hope that
nobody looked. The two signatures have been on the chain since they confirmed,
the arithmetic is short, and nothing about it needed this tool: anyone reading
blocks could have done it at any point since. Move whatever the lock still
guards to a lock whose key has never signed, and remember that every other
address guarded by the **same key** is in the same position even though its
answer here would be separate.

## The chain-wide view

`nonces groups` reads the census instead of one lock, and answers the
population question: which points repeat at all. Same synthetic chain:

```console
$ nodsig nonces groups --nonces <nonces-dir>

nonce groups over heights 1..5 (9 signatures)
  4 points sighted at least 2 times, accounting for 5 sightings beyond the first
  of those, 0 have a tiny r (0 of those sightings beyond the first): a point
  whose top bytes are zero, a shape a drawn nonce lands on about once in 2^24.
  What that means for a point is not decided here
  0 span BOTH schemes: the same nonce point appears under an ecdsa and a
  schnorr signature
  4 are candidates only a block re-read can resolve: compare the public keys
  of the signatures they name

point (12 B)                   count  schemes        heights                  tiny
66f1c4b0e5d3a27681f0c5d4           3  ecdsa          2,3,5
1199aabbccddeeff00112233           2  ecdsa          4,4
2a7b3c4d5e6f70819202a3b4           2  ecdsa          4,5
5f1e2d3c4b5a69788796a5b4           2  ecdsa          4,5
```

Two numbers, never one: how many **points** repeat, and how many extra
**sightings** those points account for. On the real chain they differ by three
orders of magnitude, because a few values recur in bulk, and a report that
quoted only the second would describe a handful of constructions as an
epidemic.

Two of the four groups above are there to make a point the count cannot make:
one is a signature copied verbatim onto a second input, the other is the pair
`s` and `n-s`, the same signature in its two legal forms. Both repeat a point
and neither exposes anything. `nonces address` separates them; `groups`, which
never sees `s`, cannot.

`--csv` writes every group; `nonces lookup <point>` asks about one.

## Why there is no chain output on this page yet

The figures and outputs published with this project come from artifacts sealed
at height 957,301, and those were built before this census existed. Printing a
chain-scale example here would mean inventing one. When the rescan that produces
the v2 artifacts has run, this page gets real output and the real sizes.

There is a second reason the chain-scale example will stay narrow: a real
repeated nonce on a single-key lock names a specific address whose key can be
computed. Documenting the method belongs here; naming the address it
belongs to does not.

## Where to go next

- [`exposure-check.md`](exposure-check.md) for the offline, one-artifact
  question: has this address's key been revealed at all.
- [`formats/Nonces-v3.md`](formats/Nonces-v3.md) for the record layout, the
  append and rewind guarantees, and the perimeter in format terms.
- [`ARTIFACTS.md`](ARTIFACTS.md) for where the census sits among the artifacts,
  and what it costs to build.
