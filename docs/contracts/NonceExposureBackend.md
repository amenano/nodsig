# NonceExposureBackend — contract

**Capability.** Was the key behind this address one of those that signed
**twice under the same nonce**? Answered offline from the witness table, for a
whole address list at once, without a node and without the index.

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [Nonces-witness-v2](../formats/Nonces-witness-v2.md)
  (`witness.bin`, `state.json`, `manifest.json`).
- **Reference impl:** `check_addresses.WitnessNonceExposure`.
- **Types:** `u32`, `digest20`, `digest32`, `bool`, `Source`, `Status`,
  `Result<T>` — see [types](../types.md).

> **This is the cheap half of a question with two answers.** Asked the strong
> way (`nodsig nonces address`) the same question needs the index, the
> derivatives and a node re-reading blocks: about 439 GB and hours. Asked here
> it is **a few MB read once**, offline, for the whole list. The two are not the
> same question and an implementation MUST NOT present them as one: this side
> sees only the points its census reported as **repeated**.

## Source & status

Every return carries `Source { id: "nonces-witness-v2", watermark: null,
fingerprint: digest32 }`.

**`watermark` is `null` on purpose, and a re-implementation MUST keep it so.**
The table covers the repeated points of one census — a **set**, not a range —
so a height would print "confirmed blocks 1..N" and promise a perimeter that
does not exist. The perimeter is stated in words with every answer.

- `OK` with a value — the key appears in one or more resolved scalars;
- `OK` with `null` — a **definite negative about this table's set**: the key is
  in none of the scalars the census resolved. It is NOT "no nonce reuse";
- `UNDETERMINED` — the address kind cannot carry the question (below);
- `UNSUPPORTED` — no witness table configured.

## Operations

### `query(address: Address) -> Result<NonceExposure | null>`

```
NonceExposure = {
    exposed: bool,                 // any scalar exposes THIS key
    points: [ {
        r:                  hex32, // the full nonce scalar
        point:              hex12, // the census's 12-byte point, derived
        resolution:         enum,  // exposed | one-signature |
                                   // distinct-keys | undetermined
        exposes_this_key:   bool,
        first_height:       u32,   // lowest height of this key's rows there
    } ],                           // ordered by `r`, ascending
}
```

## Invariants a re-implementation MUST hold

1. **Keys the unlocking data or the spent output name.** A `p2pkh` or
   `p2wpkh` address is joined on its digest: the digest of the compressed form
   every attributed row derives from `x` and `ODD_Y`, or the 65-byte digest a
   row carries in `key_seen` when it was seen uncompressed. A `p2tr` address is
   joined on `x`: its program IS the key, and a key-path spend is attributed to
   it from the spent output. A `p2sh`/`p2wsh` hides which keys are behind it,
   and the answer is `UNDETERMINED` **with the reason**, never a negative.
2. **Absence is a negative about the table, not about the chain.** Every
   rendering of a `null` MUST say so. The census hands the resolver only the
   points it could see repeated, and a share of scalars stay undecided.
3. **The resolution comes from the table, not from this backend.** The rows of
   a scalar are reduced by the shared rule (`witness.resolution_of`), over the
   **full `r`** and never over the census's prefix; this capability only asks
   whether the address's own key is among the exposed `x`. Re-deriving the
   meaning here would give one result two roads.
4. **The format tag is checked before the first byte is read.** A directory
   whose `state.json` or manifest does not say `nonces-witness-v2` is refused,
   not parsed — a rebuilt table with a different layout must stop the
   capability, not be read at the wrong offsets.
5. **One pass for the whole list.** The table is ordered by `r`, not by key, so
   there is no index to bisect: rows are walked once and grouped by key in
   memory (a few MB). Calling it a lookup would promise a structure that is
   not there. Cost per address after the first: none.
6. **Nothing leaves the machine**, and the answer names a format tag and a
   fingerprint, never a directory.

## Conformance vectors

`tests/fixtures/nonceexposurebackend/` (to be added): over a sealed table built
from a synthetic chain — a key exposed by a repeated nonce (with its scalar and
height), a key present only in a scalar resolved as `one-signature` (present,
exposed nothing), a key absent from the table (`null`), a `p2sh` address
(`UNDETERMINED`), a `p2tr` address absent from the table (`null`), and a table
whose format tag was altered (refused).

## Notes for porters

- The join between a `1…`/`bc1q…` address and a row is
  `hash160((0x02 | ODD_Y) || x)`, the same identity the reveal archive keys a
  point by, which is why the two artifacts can be read side by side without a
  translation table; a key the chain showed at 65 bytes is also found under
  the digest of that form, which the row carries because it cannot be derived.
- Rows whose class is NONE carry no attributable key and MUST NOT be indexed
  by key at all — pairing a signature with one of several cosigners would mean
  verifying signatures, which this project does not do.
