# NonceExposureBackend — contract

**Capability.** Was the key behind this address one of those that signed
**twice under the same nonce**? Answered offline from the witness table, for a
whole address list at once, without a node and without the index.

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [Nonces-witness-v1](../formats/Nonces-witness-v1.md)
  (`witness.bin`, `state.json`, `manifest.json`).
- **Reference impl:** `check_addresses.WitnessNonceExposure`.
- **Types:** `u32`, `digest20`, `bool`, `Source`, `Status`, `Result<T>` — see
  [types](../types.md).

> **This is the cheap half of a question with two answers.** Asked the strong
> way (`nodsig nonces address`) the same question needs the index, the
> derivatives and a node re-reading blocks: about 439 GB and hours. Asked here
> it is **1.03 MB read once**, offline, for the whole list. The two are not the
> same question and an implementation MUST NOT present them as one: this side
> sees only the points its census reported as **repeated**.

## Source & status

Every return carries `Source { id: "nonces-witness-v1", watermark: null,
fingerprint: digest32 }`.

**`watermark` is `null` on purpose, and a re-implementation MUST keep it so.**
The table covers the repeated points of one census — a **set**, not a range —
so a height would print "confirmed blocks 1..N" and promise a perimeter that
does not exist. The perimeter is stated in words with every answer.

- `OK` with a value — the key appears in one or more resolved points;
- `OK` with `null` — a **definite negative about this table's set**: the key is
  in none of the points the census resolved. It is NOT "no nonce reuse";
- `UNDETERMINED` — the address kind cannot carry the question (below);
- `UNSUPPORTED` — no witness table configured.

## Operations

### `query(address: Address) -> Result<NonceExposure | null>`

```
NonceExposure = {
    exposed: bool,                 // any point exposes THIS key
    points: [ {
        point:              hex12, // the census's 12-byte point
        resolution:         enum,  // exposed | one-signature |
                                   // distinct-keys | prefix-collision |
                                   // not-a-signature | undetermined
        exposes_this_key:   bool,
        first_height:       u32,   // lowest height of this key's rows there
    } ],                           // ordered by `point`, ascending
}
```

## Invariants a re-implementation MUST hold

1. **Single-key addresses only.** `p2pkh` and `p2wpkh` carry a key whose
   hash160 is exactly what the table stores. A `p2sh`/`p2wsh` hides which keys
   are behind it until it spends, and a taproot input carries no key beside the
   signature (its rows are flagged key-absent). For those the answer is
   `UNDETERMINED` **with the reason**, never a negative.
2. **Absence is a negative about the table, not about the chain.** Every
   rendering of a `null` MUST say so. The census hands the resolver only the
   points it could see repeated, and a large share of groups stay undecided.
3. **The resolution comes from the table, not from this backend.** The rows of
   a point are reduced by the shared rule (`witness.resolution_of`); this
   capability only asks whether the address's own key is among the exposed
   ones. Re-deriving the meaning here would give one result two roads.
4. **The format tag is checked before the first byte is read.** A directory
   whose `state.json` or manifest does not say `nonces-witness-v1` is refused,
   not parsed — a rebuilt table with a different layout must stop the
   capability, not be read at the wrong offsets.
5. **One pass for the whole list.** The table is ordered by `r`, not by key, so
   there is no index to bisect: rows are walked once and grouped by key in
   memory (about 1 MB). Calling it a lookup would promise a structure that is
   not there. Cost per address after the first: none.
6. **Nothing leaves the machine**, and the answer names a format tag and a
   fingerprint, never a directory.

## Conformance vectors

`tests/fixtures/nonceexposurebackend/` (to be added): over a sealed table built
from a synthetic chain — a key exposed by a repeated nonce (with its point and
height), a key present only in points resolved as `one-signature` (present,
exposed nothing), a key absent from the table (`null`), a `p2sh` and a `p2tr`
address (`UNDETERMINED`), and a table whose format tag was altered (refused).

## Notes for porters

- The join between an address and a row is `hash160(pubkey)`: the same identity
  the reveal archive uses, which is why the two artifacts can be read side by
  side without a translation table.
- Rows with `FLAG_KEY_ABSENT` or `FLAG_AMBIGUOUS` carry no attributable key and
  MUST NOT be indexed by key at all — pairing a signature with one of several
  cosigners would mean verifying signatures, which this project does not do.
