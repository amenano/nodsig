# AddressCodec — contract

**Capability.** Decode a mainnet Bitcoin address and produce, from it, the three
things the rest of the toolkit needs: the **scriptPubKey** bytes, the **lock
digest** that keys history/balance/co-spend, and the **exposure query**
`(digest, category)` that routes to the reveal archive. A **pure** function of the
address string — no I/O, no artifact, no node.

- **Layer:** L1 — but a **pure codec** (a kernel), not a reader: it carries no
  `Result<T>` envelope and no source; it either returns a value or raises
  `AddressError`. See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reference impl:** `decode_address` + `script_pubkey` (readable Python).
- **Kernel:** the `addr` kernel (base58check, bech32/bech32m, convertbits) — pure,
  highly reusable, a prime port target.
- **Consumers:** [HistoryBackend](./HistoryBackend.md), [BalanceBackend](./BalanceBackend.md),
  [CoSpendBackend](./CoSpendBackend.md) (via the **lock**);
  [ExposureLookup](./ExposureLookup.md) (via the **exposure query**); the CLI answer.
- **Types:** `bytes`, `digest20`, `digest32`, and the enums below — see
  [types](../types.md).

## ⚠ The one thing not to get wrong: one address → TWO unrelated digests

A single address yields **two different digests**, for two different questions.
Conflating them is the classic error this contract exists to prevent:

| kind | `address.digest` (payload) | scriptPubKey template (hex) | **lock** = `hash160(scriptPubKey)` | **exposure** `(digest, category)` |
|---|---|---|---|---|
| `P2PKH`  | pubkey hash160 (20) | `76 a9 14 <d> 88 ac` | `hash160` of that whole script | `(<d>, keys)` |
| `P2SH`   | redeem-script hash160 (20) | `a9 14 <d> 87` | `hash160` of that whole script | `(<d>, scripts20)` |
| `P2WPKH` | pubkey hash160 (20) | `00 14 <d>` | `hash160` of that whole script | `(<d>, keys)` |
| `P2WSH`  | witness-script sha256 (32) | `00 20 <d>` | `hash160` of that whole script | `(<d>, scripts32)` |
| `P2TR`   | output key (32) | `51 20 <d>` | `hash160` of that whole script | **BY_CONSTRUCTION** (no lookup) |

For example, for a `P2PKH` address the **lock** is `hash160(76a914‹pkh›88ac)` while
the **exposure digest** is the `‹pkh›` itself — **different 20-byte values**. The
lock answers "what history does this scriptPubKey have"; the exposure digest
answers "was this key ever revealed". Never substitute one for the other.

## Enums

```
AddressKind        = {P2PKH, P2SH, P2WPKH, P2WSH, P2TR}
Category           = {keys, scripts20, scripts32}         // reveal-archive partitions
ExposureQuery      = { digest: digest20|digest32, category: Category } | BY_CONSTRUCTION
```

## Operations

### `decode(text: string) -> Address`  (raises `AddressError`)

Mainnet address string → structured address. **Loud** on anything invalid
(bad checksum, wrong version, mixed case, unknown witness version, non-mainnet
hrp): raises with the reason — never guesses an answer.

```
Address = {
    text:     string,
    kind:     AddressKind,
    digest:   bytes,          // the payload (see the table); the output key for P2TR
    category: Category?,      // reveal-archive partition; null for P2TR (by construction)
}
```

Recognition rules (mainnet only):
- `1…` → base58check, version `0x00` → `P2PKH`; payload 21 bytes.
- `3…` → base58check, version `0x05` → `P2SH`.
- `bc1…` → bech32/bech32m; hrp must be `bc`; witness v0 (plain bech32): 20-byte
  program → `P2WPKH`, 32-byte → `P2WSH`; witness v1 (bech32m) 32-byte → `P2TR`.
  Any other witness version has **no defined meaning yet** → raise (refuse to
  guess).

### `script_pubkey(a: Address) -> bytes`

The exact scriptPubKey the address encodes (templates in the table above). This
is the bridge to history: the index/derivatives key everything by
`hash160(script_pubkey)`.

### `lock_of(a: Address) -> digest20`

Convenience: `lock_of(a) == hash160(script_pubkey(a))`. This `digest20` is the
`lock` argument to History/Balance/CoSpend.

### `exposure_query(a: Address) -> ExposureQuery`

Route to the reveal archive:
- `P2PKH`, `P2WPKH` → `{ digest: a.digest, category: keys }`.
- `P2SH` → `{ digest: a.digest, category: scripts20 }`.
- `P2WSH` → `{ digest: a.digest, category: scripts32 }`.
- `P2TR` → **`BY_CONSTRUCTION`**: the taproot output key *is* the scriptPubKey
  program — visible on-chain the moment the UTXO exists. Its key is exposed by
  construction; there is **no archive lookup**, and [ExposureLookup](./ExposureLookup.md)
  MUST treat this as `revealed = true` without querying.

## Two-level boundary (state it, don't paper over it)

From an **address** alone, `exposure_query` gives the **outer** check only:
- `P2PKH`/`P2WPKH`: the digest *is* the key hash → the outer check *is* the key
  check. Complete.
- `P2SH`/`P2WSH`: the digest is the **script** hash → a hit means the *script*
  was revealed. Whether a **key inside** that script was revealed is an **inner**
  question that needs the script's actual bytes, which are unknown until the
  script is itself revealed. The inner-key check is therefore a deeper analysis,
  **not answerable from the address alone** — and this contract must not pretend
  otherwise.

## Invariants a re-implementation MUST hold

1. **Pure & deterministic:** output depends only on `text`; no I/O.
2. **Loud on invalid:** raise `AddressError` with a reason; never emit a
   best-guess address or answer.
3. **Mainnet only** here (other networks are a separate, explicit concern).
4. **The two digests are distinct** and produced by the two operations above;
   an implementation MUST NOT feed a `lock` where an exposure `digest` is
   expected, or vice versa.
5. **P2TR is by construction exposed:** `exposure_query` returns
   `BY_CONSTRUCTION`, and `category` is null.

## Conformance vectors

`tests/fixtures/addresscodec/vectors.json`: for one known address of each kind
(genesis P2PKH, a P2SH, the BIP-173 P2WPKH/P2WSH examples, the BIP-350 P2TR
example) — the expected `kind`, `digest`, `script_pubkey` (hex), `lock` (hex),
and `exposure_query`; plus a batch of invalid strings (bad checksum, wrong
length, testnet hrp, refused witness version) each expected to raise
`AddressError`. A port passes iff it reproduces every value and every
rejection. Run against the reference by `tests/test_conformance.py`.

## Notes for porters

- This is a **pure kernel** (`addr`): base58check, bech32/bech32m, convertbits,
  the five templates. No dependency on the index, the archive, or a node — port
  it in isolation and check it against the vectors.
- Keep the two producers (`lock_of` vs `exposure_query`) as **separate named
  operations** in every language binding; do not collapse them into one "get the
  digest" call — that collapse is precisely the bug this contract guards against.
