# LinkageBackend — contract

**Capability.** Which of the addresses somebody gave us can an outside observer
already tie together, and what that does to the separations they say they
intended.

- **Layer:** L1 (in-process). See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reads format:** [OutpointDerived-v3](../formats/OutpointDerived-v3.md)
  (`tx_inputs.bin`, `history.bin`) + [IndexReader](./IndexReader.md) (locks,
  txids, heights). Class 1 reads **nothing**.
- **Reference impl:** `linkage.same_key`, `linkage.IndexLinkage`.
- **Types:** `u32`, `u64`, `digest20`, `digest32`, `bool`, `Source`, `Status` —
  see [types](../types.md).

> **Three classes, three claims.** Collapsing them into one "linked" flag would
> be the most misleading thing this capability could do.

| class | what it asserts | what it needs |
|---|---|---|
| `same_key` | two addresses are the **same key** under two encodings | nothing |
| `common_input` | coins of two addresses were spent by one transaction, directly or through one bridge | index + derived |
| `payment_arc` | one address's coins funded an **output** of another | index + derived |

## Source & status

`Source { id: "outpoint-derived-v3", watermark: u32, fingerprint: digest32 }`
for classes 2 and 3. Class 1 answers with `source: "address-codec"` — no
watermark, no fingerprint, `perishable: false`.

**Each class carries its own status.** One status over the whole block would
either erase an answer that exists (class 1 answers with no artifacts) or
promise two that do not.

## Operations

### `common_input(mine: map<digest20, (position, address)>, depth: u32) -> ([Finding], Bounded)`

```
Finding = {
    addresses:  [text, text],       // ordered by input position
    positions:  [u32, u32],
    groups:     [label|null, label|null],
    hops: [ {
        bridge_lock:   digest20|null,   // null = direct co-spend
        txid:          digest32,
        height:        u32,
        bridge_fanout: u64,             // present when bridge_lock != null
    } ],
}
Bounded = { depth: u32, caps_hit: u32, bridges_not_expanded: u32 }
```

### `payment_arcs(mine) -> [Arc]`

```
Arc = { from: text, to: text, positions: [u32, u32],
        txid: digest32, height: u32, means: string }
```

## Invariants a re-implementation MUST hold

1. **Membership, never enumeration.** The engine is handed the caller's own
   locks and answers "is any of mine among the co-spenders?". Returning the
   neighbourhood instead would carry megabytes of strangers' locks in memory,
   one step from a report: a single member of a real wallet was measured with
   32,768-65,535 co-locks. Memory is O(addresses given), not O(neighbourhood).
2. **Nothing about a third party leaves**, except a **bridge lock** when depth
   > 1 — and that digest is named because it *is* the evidence for the finding.
3. **Weight travels with every bridge.** `bridge_fanout` is reported and no
   threshold is applied to the finding: a bridge shared by 3 locks is damning,
   the same bridge shared by 900,000 is an exchange, and the reader judges.
   Measured: 128 of about 190 bridges touch more than a thousand locks.
4. **A hub is refused, and the refusal is counted.** A bridge above the fanout
   limit is not expanded, and `bounded_by.bridges_not_expanded` says how often
   that happened. A search that stopped MUST say where it stopped.
5. **`depth_searched` travels with the result**, because depth changes what the
   result *means*. Default 1: the second hop costs about 7 s per address
   against fractions of a second, the cap bites for one member in ten, and one
   in sixty has a neighbourhood of tens of thousands of locks. Expensive **and**
   uninformative is an option, not a default.
6. **A payment arc never merges anything** and never breaks a declared
   separation. "A paid B" is not "A and B are one entity".
7. **`same_key` splits identity from visibility.** The identity is a fact of
   the encoding with no height and no expiry; whether an outsider can already
   see the tie comes from the exposure capability, has that capability's
   height, and is one spend away from changing. A finding MUST NOT give the
   identity a height, nor drop the perimeter from the visibility.
8. **Separations exist only for groups claimed `mine`**, and `held: true` is
   never an attestation: it carries `as_of` and `bounded_by`, and states the
   asymmetry — **a merge is permanent, a non-merge is perishable**, one future
   transaction ends it.
9. **Total order, always.** Findings are sorted by the pair of input positions,
   ascending — never by the order the search met them, so two runs over the
   same artifacts give the same bytes.
10. **The common-input caveat is mandatory** on every rendering of class 2, as
    it is for [CoSpendBackend](./CoSpendBackend.md): a hint, never proof, and
    CoinJoin breaks it on purpose.

## Conformance vectors

`tests/fixtures/linkagebackend/` (to be added): over a sealed index+derived
pair built from a chain where A and X are co-spent, C and X are co-spent, and A
and C never are — the two direct findings at depth 1, the bridged finding at
depth 2 with its fanout, a payment arc that breaks no separation, a hub refused
and counted, and the same-key pair with and without an exposure backend.

## Notes for porters

- Class 2 at depth 1 costs exactly what [CoSpendBackend](./CoSpendBackend.md)
  already costs: the spends of each lock, then the inputs of each spending
  transaction. There are no extra reads.
- The bridge expansion at depth 2 measures the fanout **before** walking it, so
  a hub is paid for once and abandoned, not walked and then discarded.
