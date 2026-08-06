# Invariants & non-goals

What MUST always hold across the project, and what is deliberately out of scope.
Terms in [glossary](GLOSSARY.md); types in [types](types.md). This file is the
**canonical** statement of the cross-cutting invariants; contracts link here
instead of restating them.

## Invariants (MUST hold everywhere)

1. **Determinism.** Same inputs → same bytes → same canonical fingerprint, on any
   machine. Artifacts are byte-reproducible; two RocksDB-style databases never
   are, ours always is.

2. **Source in every answer.** Every capability result carries `Source`
   (`id`, `watermark`, `fingerprint` when sealed) — once per operation
   (see the envelope rule in [types](types.md)). No answer is context-free.

3. **Never silent data.** An unknown or absent result is **explicit**: a definite
   negative (`OK` + `null`/empty), an honest `UNDETERMINED`/`UNSUPPORTED`, or a
   **loud error** — never a silent default, a swallowed exception, or an
   uncounted drop. Anomalies (BIP30 overwrites, duplicate spends, unresolved
   references) are **counted and reported**, never hidden.

4. **Watermark honesty.** Every answer is "as of the watermark"; a negative is a
   negative *at that height*, and says so via `Source`.

5. **Big-endian integers** in every format and on the wire (byte order = numeric
   order; `memcmp` sorts and searches without decoding).

6. **Total, reproducible stream order.** Each reader specifies the order of its
   stream; two implementations MUST produce the same sequence.

7. **Errors are loud, negatives are values** — and the two are distinct
   (`OUT_OF_RANGE`/`INVALID_OUTPOINT`/`INVALID_DIGEST` raise; "absent up to the
   watermark" is `OK` + `null`). See [types](types.md).

8. **One-way contracts.** Public code never names, imports, or hints at a private
   extension. Extension is additive and one-directional.

9. **A cache decides where to read, never what is returned.** Ladders (`.lad`
   sidecars) are sampled keys, excluded from the canonical fingerprint: an
   artifact read with a ladder, without one, or with a ladder of a different
   step MUST yield the **same records**. Concretely, for an equality scan the
   entry point is the rightmost sample **strictly below** the key, and the walk
   continues across buckets until a different key appears. Using the rightmost
   sample `<= key` is wrong: a group longer than the sampling step owns several
   consecutive samples equal to the key, and entering at the last of them drops
   the head of the group — a silent, uncounted loss (invariant 3). A **position**
   lookup ("which record covers this ordinal?", over unique keys) is the other
   question and does want `<=`; the two MUST NOT share one entry rule.
   Because a wrong ladder breaks this silently rather than loudly, `verify`
   **rebuilds** each ladder from the file it indexes; comparing it with the
   digest the seal wrote for it would only prove the sidecar is intact.

   This is not hypothetical: it shipped, and the fixtures could not see it
   because no test group ever crossed a bucket boundary. A port MUST cover a
   group longer than its sampling step.

10. **A commit is additive: write beside, name it, only then delete.** Every
    artifact that grows by generations — `outpoint-index-v2`,
    `outpoint-derived-v2` and `nonces-v2` through `genstore`,
    `reveal-archive-v2` by hand —
    MUST write the next generation of a file **beside** the current one, then
    commit the state/manifest that names it, and only then delete what is no
    longer named. What the state or the manifest does not name **does not
    exist** and is swept on the next run. A reader identifies a file by the
    name the manifest gives it, never by one derived from a category or a
    logical name.

    The rule is not stylistic: every sealed file is named together with its
    `sha256`, and every reader verifies that digest before yielding a byte.
    Overwriting a file in place therefore has no recoverable failure mode — a
    kill between the rename and the manifest write leaves the manifest
    describing bytes that are gone, and the tool that would repair it is the
    one that refuses to read. This too shipped, in the archive's fusion, and
    the fix was to make the write additive.

## The binding invariant (stated once)

**Derivatives are bound to the index they were built from.** A derived artifact's
manifest records its `source_index_fingerprint`; a reader MUST verify it equals
the index's fingerprint and **refuse** a mismatched pairing (mixing coordinate
systems would answer nonsense with confidence). This is a hard error, not a
status. The same rule generalizes along the ancestry: each sealed artifact
declares its parent, and a consumer checks the link before trusting the pair.
The declaration is not inside the fingerprint — an artifact is named by what it
holds — so checking it is the consumer's step and `verify` reports it as
unconfirmed until given the parent.

`HistoryBackend`, `BalanceBackend`, `FeeBackend`, `CoSpendBackend` all rely on this
invariant; it lives here, not restated in each.

## Publication-grade sources

A `build` **refuses** a partial source: derivatives reject an index with
`unresolved > 0` (a tolerated, partial graph), because fees and histories computed
over holes would be numbers that *look* true. Only complete, sealed artifacts back
published claims.

## Non-goals (deliberate — not gaps)

- **Consensus validation.** The node is trusted **once**, at scan time, with byte
  integrity checks (header hash, prev link, Merkle, witness commitment); we do not
  re-validate consensus.
- **Mempool / real-time state** in the core. Only confirmed blocks up to the
  watermark. (Real-time watching is an opt-in `LiveSource` extension, explicitly
  non-reproducible.)
- **Wallet / key management.** A `lock` is an identical scriptPubKey, not a wallet.
- **Online service.** Artifacts are files read by tools, not a server; zero
  daemons.
- **Fee rates.** Absolute fees only (sizes are excluded from the graph).
- **Off-chain / mempool exposure.** Invisible by declaration; "not revealed" is
  always qualified to confirmed blocks up to the watermark.

These are choices that buy determinism, offline reproducibility, and third-party
verifiability — the functions the project optimizes for.
