# Glossary

Neutral definitions of the domain terms, so a reader (human or LLM) without deep
Bitcoin background is grounded and cannot conflate close concepts. Scalar/enum
types are in [types](types.md).

### ordinal (tx ordinal, output ordinal)
The position of a transaction / output in **chain order** (block by block, tx by
tx, vout by vout), counting from the first transaction of block 1. **The order is
the key**: a file whose records are in ordinal order needs no stored key —
record `i` lives at byte offset `i × width`. Genesis (height 0) is excluded, so
ordinals start at block 1.

### height / watermark
`height` is a block height (1-based; genesis excluded). `watermark` is the highest
confirmed height an artifact covers. **Every answer is "as of the watermark"** — a
negative means "not found *up to that height*", never an absolute claim.

### lock
The `hash160` of the **full** scriptPubKey. It identifies an **identical lock** —
one exact locking script — **not** a wallet, and **not** a key seen under its
other script faces. History / balance / co-spend are all keyed by the lock.

### the two digest systems (do not conflate)
One address produces **two unrelated digests**:
- the **lock** = `hash160(scriptPubKey)` — used by history / balance / co-spend;
- the **exposure digest** = the pubkey hash / redeem-script hash / witness-script
  sha256 embedded in the address — used by exposure lookups, routed by `category`.

For a `P2PKH` address the lock is `hash160(76a914‹pkh›88ac)` while the exposure
digest is `‹pkh›` itself — different 20-byte values. See
[AddressCodec](contracts/AddressCodec.md).

### reveal / exposure
A key or script is **revealed** when it appears in an *unlocking* context (a
scriptSig push, a witness item, or inside a revealed script) in a **confirmed**
block. "**Not revealed**" means: not up to the watermark, **in confirmed blocks
only** — off-chain exposure and the mempool are invisible here by declaration.

### nonce / nonce point (signatures)
The **nonce** is the one-time secret `k` a signer draws for each signature. It is
never published, but the **nonce point** is: the x-coordinate of `k*G`, which is
the `r` of an ECDSA `(r, s)` and the leading 32 bytes of a BIP 340 (Schnorr)
signature. Both schemes therefore publish the same quantity on the same curve.

Not to be confused with the **block header nonce**, the field miners grind: same
word, unrelated thing.

Why it matters: one key signing two **different messages** with **one** nonce
publishes two signatures from which the private key follows by elementary
algebra. Each word in that sentence is load-bearing. The same key signing the
**same** message twice publishes one signature, possibly serialized twice, and
hands over nothing; so does the pair `s` and `n-s`, which is that signature in
its two legal forms. Two **different** keys sharing a nonce hands neither one
over (three unknowns for two equations); it does show the point was not drawn
at random, though not whether that was a fault or a choice. A **repeated
point** is therefore a candidate and not a conclusion, and the distinction
between "shown" (see *reveal / exposure*) and "computable" is the whole
difference between the two question pages.

### tiny r
A nonce point whose top bytes are zero. This is a shape, not a motive: chance
puts a drawn nonce there about once in 2^24, and a short `r` does shorten a
signature's DER encoding and its fee, so both kinds land in the same bucket
and the shape alone cannot separate them. These values recur for years across
unrelated transactions and form the largest repeated groups on the chain,
which is why a report names them instead of ranking by size and reading like
an epidemic. What any one of them means is decided by re-reading the blocks it
appears in, not by the byte test.

### by construction (P2TR)
A taproot output key **is** the scriptPubKey program (`51 20 <key>`): it is visible
on-chain the moment the UTXO exists. Such a key is exposed **by construction** — no
archive lookup is needed or possible; exposure is trivially true.

### coinbase / unspent sentinel
The **coinbase** is a block's single no-input transaction; it creates coins and
pays **no fee** (`fee = 0`). Transaction ordinal **0** (the first tx of block 1) is
a coinbase — which can never spend anything — so it doubles as the **unspent
sentinel**: a spend record with `spender = 0` means *unspent*, and it sorts below
every real spender.

### BIP30 (duplicate txids)
Two early coinbase txids are duplicated in Bitcoin's history. The resolver keeps
the **latest** instance (it overwrote the earlier in the UTXO set); the expected
count of such overwrites on mainnet is **exactly 2** — a built-in historical
cross-check. Positional files keep both instances honestly.

### fee (absolute) vs fee rate
A **fee** is absolute, in satoshis (Σ inputs − Σ outputs). A **fee rate**
(sat/vByte) needs transaction sizes, which the graph deliberately excludes — it is
a future derived scan, **never a silent estimate**.

### common-input hint (Q2)
Outputs consumed together by one transaction usually share an owner — a **hint**,
never proof: CoinJoin and collaborative spends break the assumption. The caveat is
part of the co-spend contract and MUST be shown with every answer.

### first spend (FirstSpend-v1)
When a lock was **first spent from**, ordered by that moment. The derivatives
answer it one lock at a time; this fifth artifact materialises the order the
collection lacks, so "which locks were first spent between H1 and H2" becomes a
contiguous read (`firstspend between`) rather than a scan. Its perimeter is the
derivatives': "first spent from", **not** "first exposed": a key seen inside a
revealed script (the co-signer case) is out, the same line the reveal archive
draws. A lock never spent from has no row.

### ancestry
`graph → outpoint index → derivatives` (and the reveal archive; `firstspend`
hangs off the derivatives), each sealed artifact **declaring its parent's
fingerprint** in `build`. The declaration sits
outside the fingerprint on purpose, so that the same content always takes the
same name; a reader holding both artifacts confirms the link, and `verify` says
so when it could not. Same chain + same height ⇒ the same bytes and the same
fingerprint on anyone's machine.

### canonical fingerprint
A deterministic digest of an artifact's content, defined by its format. It is how
**two strangers compare a string** instead of trusting each other. Sidecar caches
(ladders) are deterministic but **not** part of the fingerprint (rebuildable).

### ladder (`.lad`)
A sidecar cache sampling every K-th key of a sorted file, held in RAM. It turns a
point query into **one ~40 KB bucket read** instead of a blind on-disk binary
search (~35 seeks). A performance aid, never part of the canonical fingerprint.
One bucket is the common case, not the rule: a key whose group is longer than K
spans several buckets and several equal samples, so an equality scan enters at
the rightmost sample **strictly below** the key and reads on until the key
changes (invariant 9 in [INVARIANTS](INVARIANTS.md)).
