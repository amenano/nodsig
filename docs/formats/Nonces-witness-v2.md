# Nonces-witness-v2: format (L0)

The evidence that resolves a repeated nonce point. The census
([`Nonces-v3`](Nonces-v3.md)) can say **which** points repeat and never
**what** a repeat means, because the meaning lives in `s` and in the key that
signed, and a 16-byte record holds neither. This table holds the signatures
that decide, and the key each one belongs to.

- **Directory** `<witness>/` : `witness.bin`, `state.json`, `manifest.json`
- **Defined over** the repeated points of one sealed `nonces-v3` census, read
  against the chain and against a sealed outpoint index
- **Read by** `nonces witness-verify`, `check --witness`
- **Built by** `nonces resolve` (needs a node: the signatures live only in
  the blocks; and `--index`: the key of a P2PK or taproot key-path spend lives
  in the output being spent)
- **Parent** the census it resolved, `nonces-v3` only, declared in the
  manifest under its own tag; the index it read is declared beside it
- **Supersedes** `nonces-witness-v1`, which this release neither reads nor
  reproduces

What changed from v1, in one paragraph: a signature is attributed to a
**point**, not to the bytes a key was serialized in (the same key seen at 33
and at 65 bytes was two "keys", and a real exposure came out as
`distinct-keys`); the key is attributed from the **unlocking data and the
spent output**, by consensus where the script names the signer, and not from
the kind of address; a Schnorr signature is never mistaken for a key; and
what the v1 filed as a resolution but was only a prefix collision is a
column.

## What one record is

124 bytes, big-endian throughout, one row per witness:

| field | bytes | meaning |
|---|---|---|
| `r` | 32 | the nonce point **in full**, left-padded; `0 < r < n` for ECDSA |
| `x` | 32 | the x coordinate of the key the signature is attributed to; 32 zero bytes when the attribution class is NONE |
| `key_seen` | 20 | `hash160` of the 65-byte serialization the chain showed, when `UNCOMPRESSED` is set; 20 zero bytes otherwise |
| `s` | 32 | ECDSA: the **canonical** `s`, `min(s, n-s)`; Schnorr: `s` as published |
| `count` | 4 | how many distinct `(scheme, s)` this triple `(r, x, class)` has over the whole pass |
| `height` | 3 | where this witness was read |
| `flags` | 1 | see below |

```
SCHNORR      = 1     the signature is BIP 340 (otherwise DER)
HIGH_S       = 2     ECDSA: the serialized s was n-s; never with SCHNORR
ATTRIBUTION  = 4|8   two bits: 0 BESIDE, 1 POSITION, 2 OUTPUT, 3 NONE (x is zero)
AMBIGUOUS    = 16    only with NONE: several candidates; NONE without it: no candidate
ODD_Y        = 32    the point seen has odd y (lead 03, or 04/06/07 with odd y); 0 with XONLY
UNCOMPRESSED = 64    seen as 65 bytes: key_seen carries its hash160
XONLY        = 128   seen as 32 bytes (a leaf, a control block, a taproot output): parity unknown
```

Other bits are undefined and a record carrying one is refused.

The digest of the compressed form, the identity every other artifact of this
project keys a point by ([`RevealArchive-v4`](RevealArchive-v4.md)), is not a
field: it is `hash160((0x02 | ODD_Y) || x)`, derived on read, and for `XONLY`
it is `hash160(0x02 || x)` by the definition of BIP 340. Storing it beside
the value it is computed from would be two sources for one fact, the same
reason the v1 did not store the 12-byte point beside `r`. `key_seen` exists
only for the one form a digest cannot be derived from.

## Why `r`, `x` and `s` are values and not digests

Eight-byte digests would answer the same question in a third of the space,
and only for a reader who trusts this code to have hashed correctly. Full
values make a resolution **checkable by a stranger** against the chain,
without re-running `resolve` and without trusting the producer. The v1
already stored `r` and `s` whole for that reason and hashed the key; the key
is a value on the chain like the other two, and the resolution needs it as
one: `r` fixes the nonce **up to sign** in both schemes (`R` and `-R` share an
x coordinate), and a public key fixes the private key **up to sign** (`P` and
`-P` share `x`). So the identity a resolution works with is `x`, which a
digest hides: the same key used as `03 || x` in an ECDSA input and as an
x-only key in a taproot leaf (read as `02 || x`, the negated point) has two
different digests and one private key, and two signatures under one `r` from
those two forms give it away. Nothing here is secret: `r`, `s` and the key were
published in the clear by the transaction that spent, and this file is a copy
of them, not a disclosure.

## How a signature is attributed to a key

`signatures_of_input`, one road shared by `resolve` and by `nonces address`,
gives every signature whose point the census asked for a key and a **class**:

| class | when | what settles it |
|---|---|---|
| BESIDE | exactly one signature and exactly one key-shaped item among the scriptSig pushes and the witness items outside the taproot slots: the shape of P2PKH, P2WPKH and P2SH-P2WPKH; and the key hashes to the lock the input spends (read from the index) | shape, tied to consensus by the lock |
| POSITION | the redeem script, witness script or leaf names the signer by position: `OP_m <keys> OP_n OP_CHECKMULTISIG` with `m == n` (the interpreter consumes keys in order and fails if signatures outrun keys, so the i-th signature is the i-th key's); a single-key leaf `<x> OP_CHECKSIG`; the BIP 342 multisig template, where each key has its own stack slot | consensus |
| OUTPUT | one signature, no key in the input, and the spent scriptPubKey is `<key> OP_CHECKSIG` (P2PK) or a taproot key-path program `5120<Q>`: the key is `key` or `Q` | consensus, read from the index and the block that created the output |
| NONE + AMBIGUOUS | everything else with several candidates: `m < n` multisig, bare multisig with `m < n`, leaves outside the templates, inputs whose signatures cannot be told apart | nothing: no key is guessed |
| NONE | no candidate at all: a script outside every template, a spent output the index does not resolve | nothing |

The v1 attributed by kind of address, which was BESIDE plus the key-path
case, and answered "several keys" for a P2SH-P2WPKH input and for every
`m`-of-`m` multisig. A BESIDE row whose key does not hash to the lock it
spends is not attributed; it is counted (`shape_without_link`) and the count
is in the manifest.

## What a resolution means

Derived on read, never stored. For every full `r`:

1. rows whose class is not NONE, grouped by `x`, with the set of `(scheme, s)`
   of each group;
2. **`exposed`** when some `x` has at least two distinct `(scheme, s)`: two
   signatures, one nonce, one key, two messages; the private key follows by
   arithmetic anybody can do, and the exposed keys are those `x`;
3. otherwise **`distinct-keys`** when there are at least two `x`: the point was
   not drawn at random, and whether that was a fault or a choice is not said;
   neither key follows from the two of them alone;
4. otherwise **`one-signature`** when there is one `x` with one `(scheme, s)`
   and every NONE row of the same `r` carries that same `(scheme, s)`: one
   signature published more than once (copied, or as `s` and `n-s`); it signs
   one message and exposes nothing;
5. otherwise **`undetermined`**, with the two reasons counted apart:
   `rows_ambiguous` and `rows_absent`.

The four conditions of `exposed` are each load-bearing. The **full `r`**: two
scalars can share the census's 12-byte prefix; over the chain one prefix in
5,149 does, and that is a column (`scalars_under_prefix`), not a resolution.
The **same `x`**: a single-key lock says the signatures came from one key,
which is true and not enough; `x` is the key up to sign, which is what the
equation needs. The **canonical `s`** for ECDSA: nonces `k` and `-k` publish
the same `r` and, over one message, give `s` and `n-s`; low-s is relay
policy, not consensus, so the high form is on the chain and always may be.
Schnorr has no such pair: `R` is the point with even `y` by definition, so
`s` is stored as published and `HIGH_S` is never set on it. The **scheme in
the pair**: a key that signed with ECDSA and with BIP 340 under one `r` is
one triple with two `s`, and it is exposed.

`not-a-signature` is gone: a `nonces-v3` census refuses `r = 0` and `r >= n`
at extraction, so no such row can be brought through, and a table built by
earlier code from an earlier census is read with that release.

## Why at most two rows per triple

Exposure is decided by a pair of signatures that **disagree**. Two rows per
`(r, x, class)` settle it in either direction: two distinct `(scheme, s)` prove
the key is recoverable, one proves it is not. The first two in ascending
height order are kept; `count` holds how many distinct `(scheme, s)` the
triple has over the whole pass, so what was dropped is not dropped. Rows are
sorted by their raw bytes, which keeps the rows of one `r` contiguous and,
inside them, the rows of one key.

## What it does not cover

It resolves the points **its own census** reports, up to that census's
height, and nothing else. A table beside a different census is answering
about other points, which is why the parent is declared and why
`witness-verify --nonces` confronts it rather than trusting it.

It does not recover keys. `exposed` is a proof obligation met, not a key
computed: there is no point arithmetic in this project (one field square
root, in `check --key`, names the other serialization of a key you gave:
it multiplies no point, verifies nothing, recovers nothing), and the group
order is
used only to fold `s` with `n-s`.

What the census itself does not read, and this table therefore never sees, is
declared on the census's page: signatures whose DER layout is lax, 65-byte
items in a script-path slot that begin like a key, non-standard sighash codes,
`r` outside its range.

## Appendability: none, and said so

`resolve` is a pure function of the sealed census, the chain and the index it
declares: same three inputs, same tag, same bytes, on any machine. It is
**not appendable**: `count` and the choice of the first two rows depend on the
whole pass, so a census that grew is resolved again, from the start. On the
whole chain that is about an hour and a half of node reads plus the index
lookups, and an interruption costs exactly that; there is no cursor to resume
from, because a checkpoint would have to carry every witness gathered so far,
one more state for a pass that short. The v1 page promised a resume its code
never had; this one promises what the code does.

## Canonical fingerprint

The shared recipe of [`Artifact.md`](../contracts/Artifact.md), over the
one logical file `witness`, with the tag `nonces-witness-v2`. Coverage is the
lowest and highest height any row names. `build` records the parent census
by tag and fingerprint, the index by fingerprint, and the counters:
`points_resolved`, `rows`, `attributed_beside`, `attributed_position`,
`attributed_output`, `ambiguous_multisig_m_lt_n`, `shape_without_link`,
`none`.

## Verifying a sealed table

```sh
nodsig nonces witness-verify --witness <witness> [--nonces <nonces>] \
                             [--csv resolutions.csv] [--keys-csv keys.csv]
```

Re-reads every byte against the manifest (size first, then digest),
recomputes the fingerprint, and then **re-derives every resolution from the
rows themselves**, checking on the way that: `x` is zero if and only if the
class is NONE; `key_seen` is zero if and only if `UNCOMPRESSED` is off;
`UNCOMPRESSED` and `XONLY` are never together; `HIGH_S` is never with
`SCHNORR`; `ODD_Y` is off with `XONLY`; `r` is in range; `count` is at least
the number of rows of its triple. The digests prove the file has not rotted;
re-deriving proves it still *means* what it meant.

`--csv` writes one row per `r`: `r, point, resolution, scalars_under_prefix,
keys, exposed_keys, max_distinct_s, rows_ambiguous, rows_absent, attribution,
first_height, last_height, schemes`. `--keys-csv` writes one row per
attributed key: `key_canon, key_seen, form, exposed`. Both hang off the audit,
so exporting a resolution requires having verified the table it came from.

## Reproducing a row without this code

A BESIDE or POSITION row: read the block at `height`, find the input whose
signature has that `r`, and compare `x` with the key pushed beside it or with
the key in the position the script names. An OUTPUT row: the same input names
the outpoint it spends; read that output's scriptPubKey and compare `x` with
its key. A stranger needs the chain for the first two kinds and the chain plus
a way to look an outpoint up for the third; the page says so rather than
calling the third kind self-evident.

## Constants, for a porter and for the test that pins this page

| name | value |
|---|---|
| record width | 124 |
| fields | `r` 32, `x` 32, `key_seen` 20, `s` 32, `count` u32, `height` u24, `flags` u8 |
| byte order | big-endian throughout |
| flags | 1, 2, 4+8 (two bits), 16, 32, 64, 128 as listed |
| rows per triple | at most 2 |
| sort | raw bytes |
| identity tag | `nonces-witness-v2` |
| parent tag accepted | `nonces-v3` only |

## Notes for porters

- `x` is the key up to sign; the digest of the compressed form is
  `hash160((0x02 | ODD_Y) || x)`, and `hash160(0x02 || x)` for `XONLY`. A
  65-byte form's digest is in `key_seen` because it cannot be derived.
- an absent key is 32 zero bytes **and** the class NONE. Readers must test the
  class, not the zeros: a zero x coordinate is not on the curve, but the rule
  is the flag, not the value;
- `s` is canonical for ECDSA and as published for Schnorr: a porter that folds
  a Schnorr `s` will report signatures that were never published;
- the resolution is per `(r, x)`, never per point alone and never per
  serialization.
