# Nonces-witness-v1: format (L0)

The evidence that resolves a repeated nonce point. The census
([`Nonces-v2`](Nonces-v2.md)) can say **which** points repeat and never
**what** a repeat means, because the meaning lives in `s` and a 16-byte
record does not hold it. This table holds the signatures that decide.

- **Directory** `<witness>/` — `witness.bin`, `state.json`, `manifest.json`
- **Defined over** the repeated points of one sealed census, and no others
- **Read by** `nonces witness-verify`
- **Built by** `nonces resolve` (needs a node: the signatures live only in
  the blocks)
- **Parent** the `nonces-v2` census it resolved, declared in the manifest

## What one record is

92 bytes, big-endian throughout, one row per witness:

| field | bytes | meaning |
|---|---|---|
| `r` | 32 | the nonce point **in full**, left-padded |
| `key` | 20 | hash160 of the public key beside the signature, or 20 zero bytes when there was none |
| `s` | 32 | the **canonical** `s`, i.e. `min(s, n-s)` |
| `count` | 4 | how many distinct canonical `s` this `(r, key)` pair has over the whole chain |
| `height` | 3 | where this witness was read |
| `flags` | 1 | see below |

`flags`: `1` the signature was BIP 340 rather than DER; `2` no public key
was in the input; `4` the input held more than one signature or key, so
nothing is attributable; `8` the serialized `s` was `n-s` rather than the
canonical one. Other bits are undefined and a record carrying one is
refused.

The 12-byte point the census stores is **not** a field: it is `r[:12]`,
derived on read. Storing the truncation beside the value it truncates
would be two sources for one fact.

## Why `r` and `s` are values and not digests

Eight-byte digests would answer the same question in a third of the space,
and only for a reader who trusts this code to have hashed correctly. Full
values make a resolution **checkable by a stranger** against the chain,
without re-running `resolve` and without trusting the producer. Nothing
here is secret: `r` and `s` were published in the clear by the transaction
that spent, and this file is a copy of them, not a disclosure.

## Why at most two rows per pair

Exposure is decided by a pair of signatures that **disagree**. Two rows
per `(r, key)` settle it in either direction: two distinct canonical `s`
prove the key is recoverable, one proves it is not. Keeping every sighting
would be, over 957,301 blocks, 2,508,137 rows dominated by a single 2015
construction, against the **11,766 rows and 1.03 MB** a real resolve of
that chain produced. The count of what was dropped is not dropped: it is
the `count` field.

## What a resolution means

Per `(point, key)` pair, and never per point alone, because one point can
carry several keys with different outcomes:

| resolution | when | what follows |
|---|---|---|
| `exposed` | same full `r`, same key, ≥2 distinct canonical `s` | two signatures, one nonce, one key, two messages: the private key follows by arithmetic anybody can do |
| `one-signature` | same key, exactly one canonical `s` | one signature published more than once (copied, or as `s` and `n-s`): it signs one message and exposes nothing |
| `distinct-keys` | one point, several keys | neither key follows; the point was not drawn at random, and whether that was a fault or a choice is not said |
| `prefix-collision` | two different `r` under one 12-byte point | not a repeated nonce at all |
| `undetermined` | the key is absent or the input is ambiguous | no resolution, and none is guessed |

All three conditions of `exposed` are load-bearing, and each was a defect
once. The **full `r`**: two scalars can share the census's 12-byte prefix,
and over the chain one group in 5,149 does. The **same key**: a single-key
lock says the signatures came from one key, which is true and not enough.
The **canonical `s`**: nonces `k` and `-k` publish the same `r` and, over
one message, give `s` and `n-s`; over the chain one pair in 1,581 is
exactly that. Low-s is relay policy, not consensus, so the high form is
on the chain and always may be.

## What it does not cover

It resolves the points **its own census** reports, up to that census's
height, and nothing else. A table beside a different census is answering
about other points, which is why the parent is declared and why
`witness-verify --nonces` confronts it rather than trusting it.

It does not recover keys. `exposed` is a proof obligation met, not a key
computed: there is no curve arithmetic in this project, and the group
order in `nonces.py` is used only to fold `s` with `n-s`.

Taproot key-path spends and pay-to-pubkey inputs put the key in the output
being spent, not in the input, so they land in `undetermined`. Over the
chain that is the majority: **63.3% of groups**, and the number is
published beside the others rather than left to be discovered.

## Appendability

`resolve` is a pure read of the chain, so an interruption costs time and
nothing else: `state.json` holds the height cursor and a re-run continues
from it. When the census grows, the table is re-resolved: a point that was
a singleton can become a group, and its **first** sighting is at an old
height, so growth is not "read the new blocks". The cost stays
proportional to the repeated points and not to the chain.

Rows are sorted by their raw bytes and each row is a function of
`(r, key, s, height)` alone, so merging two resolutions of the same census
gives the file a single resolution would have: **appending equals
rebuilding**, byte for byte.

## Canonical fingerprint

The shared recipe of [`Artifact.md`](../contracts/Artifact.md), over the
one logical file `witness`. Coverage is the lowest and highest height any
row names.

## Verifying a sealed table

```sh
nodsig nonces witness-verify --witness <witness> [--nonces <nonces>] \
                             [--csv resolutions.csv]
```

Re-reads every byte against the manifest and recomputes the fingerprint,
and then **re-derives every resolution from the rows themselves**. The
digests prove the file has not rotted; re-deriving proves it still *means*
what it meant, which is the part a checksum cannot say. Passing `--nonces`
confronts the declared parent instead of taking it on trust.

`--csv` writes one row per point (resolution, keys attributed and exposed,
the height span, the schemes) from what the audit just re-derived. It
hangs off the audit rather than off a reader of its own, so exporting a
resolution requires having verified the table it came from: a number that
leaves this project has been checked by construction, and one result
does not get two roads.

## Notes for porters

- everything is big-endian, including `count` and the 3-byte height;
- `s` is stored canonical. A porter that stores the serialized value will
  report exposures that do not exist, roughly one pair in 1,600;
- `r` is stored whole. A porter that stores the census's 12-byte point
  will merge two nonces into one apparent repeat, roughly one group in
  5,000;
- an absent key is 20 zero bytes **and** the `KEY_ABSENT` flag. Readers
  must test the flag, not the zeros: a hash160 of twenty zero bytes is a
  legal value that nothing forbids;
- the resolution is per `(r, key)`, never per point.
