# Matcher — contract (live extension seam)

**Capability.** Given a transaction (raw bytes) from a [LiveSource](./LiveSource.md),
decide whether it matches a rule — for example, "does it spend a quantum-exposed
output on a watchlist?". The **decision** half of the live extension seam. The
toolkit ships the interface and a neutral base matcher; novel heuristics are
extensions, and MAY be private instances of this public interface.

- **Layer:** L1 extension seam. See [ARCHITECTURE](../ARCHITECTURE.md). Pairs with
  [LiveSource](./LiveSource.md).
- **Reference impl:** a base matcher (membership of a transaction's spent outputs
  against a watchlist); no novel heuristic shipped.
- **Types:** `bytes` and the domain types of whatever it reports — see
  [types](../types.md).

## Operations

### `match(tx_bytes: bytes) -> Answer?`
Parse the transaction (via the shared `btcparse` kernel) and evaluate the rule.
Returns an `Answer` on a hit, or `null` on no match. An `Answer` is
implementation-defined but MUST be **self-describing and reproducible after the
fact**: it names the transaction and the on-chain facts that justify it (e.g. the
spent outpoint, the matched watchlist entry), so the claim can later be re-derived
from confirmed data.

### `watchlist_from(source) -> Watchlist` *(base matcher)*
Building the watchlist is itself a reproducible analysis (e.g. "exposed outputs up
to height H") over the offline readers — a public, deterministic step, distinct
from the live matching.

## Invariants a re-implementation MUST hold

1. **Reproducible justification:** an `Answer` references confirmed on-chain facts,
   never only ephemeral mempool state, so a published finding degrades to a
   historical, verifiable claim.
2. **Pure evaluation:** `match` is a pure function of `(tx_bytes, watchlist)` — no
   hidden state; testable with recorded transactions.
3. **Caveat honesty:** if the rule is a *hint* (like the common-input heuristic),
   the `Answer` carries the caveat, as elsewhere in the project.

## Notes for porters / extenders

- This is the natural home of **private** work: a novel heuristic is a new
  `Matcher` implementing this interface, kept in a private repo that depends on
  the public library — the public code never names it (one-way dependency).
- Test with recorded sample transactions + expected answers (conformance
  vectors); no live node needed to validate a matcher.
