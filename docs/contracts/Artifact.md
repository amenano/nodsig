# Artifact: contract (builder)

**Capability.** Build, verify, and describe a **sealed, appendable, fingerprinted
artifact**. This is the shared lifecycle of every L0 artifact, captured once. It
is a **builder**, not a reader: it writes and validates artifacts, so it carries
no `Result<T>` envelope.

- **Layer:** orchestration over L0. See [ARCHITECTURE](../ARCHITECTURE.md).
- **Instances:** [Headers-v2](../formats/Headers-v2.md),
  [Graph-v2](../formats/Graph-v2.md),
  [OutpointIndex-v2](../formats/OutpointIndex-v2.md),
  [OutpointDerived-v2](../formats/OutpointDerived-v2.md),
  [RevealArchive-v2](../formats/RevealArchive-v2.md),
  [Nonces-v3](../formats/Nonces-v3.md),
  [Nonces-witness-v1](../formats/Nonces-witness-v1.md).
- **Reference impl:** `build`/`verify`/`stats`/`rewind` of each tool, over three
  shared pieces: `artifact.canonical_identity` (one definition of what an
  artifact *is*, and therefore of its fingerprint), `artifact.verify_sealed`
  (one audit), and `genstore.GenStore` (one append-and-fuse store: runs, merged
  generations, the crash-safe commit order, the orphan sweep). What stays
  per-artifact is the **phase machine** and what each phase computes, which is
  the part that genuinely differs: an index resolves a join, the derivatives
  walk a zip of three streams. A component, not a base class: the artifacts have
  no is-a relationship, only the same bookkeeping problem.

> This contract is where "**specialize the core, generalize the applications**"
> lands at the orchestration layer: the lifecycle (state, runs, manifest,
> fingerprint, verify) is the specialized core; a **new derivative** is a thin
> application: declare its files and its projection rule, inherit everything
> else.

## The artifact on disk

A directory containing: the data files, sidecar caches (ladders, deterministic
and **excluded** from the fingerprint), a `state.json` (build progress), and a
`manifest.json` after sealing.

### The manifest is two blocks

```
manifest = {
    format:      string,            // the format tag, repeated for cheap dispatch
    identity:    Identity,          // what the fingerprint covers
    fingerprint: digest32,          // sha256 of canonical_identity(identity)
    statement:   digest32,          // sha256 of canonical_statement(manifest)
    build:       { ... },           // how THIS copy happened to be produced
}

Identity = {
    format:   string,               // e.g. "outpoint-derived-v2"
    coverage: { from:u32, to:u32 }, // the range of chain this artifact holds
    files:    [ { name:string, sha256:digest32 } ],   // IN CANONICAL ORDER
}

build.parent   = { format, fingerprint } | null  // DECLARED, not sealed
build.producer = { version, commit?, dirty? }    // DECLARED, not sealed
build.seconds  = { <verb>: u32, … }              // DECLARED, not sealed
```

**The rule, and it is the whole contract:**

> The identity holds **what the artifact is**, never how it came to be.
> Everything else lives in `build`.

Three things qualify. The **digests**, which are the content. The **format
tag**, which says how to read those bytes and — the part a reader depends on —
*what this artifact captures*, so an absence can be told apart from a blind
spot. And the **coverage**, the range of chain the content speaks for, which
the bytes cannot prove on their own.

Everything recomputable from the data stays out: record counts, totals, anomaly
tallies. Putting them in would add no attestation the digests do not already
give. And everything that varies between two honest builds of identical bytes
**must** stay out, or the promise breaks: generation numbers, the actual file
names that carry them, ladders, timings, `updated_rows`.

Why the coverage matters more than it looks: an archive of hashes carries no
heights anywhere in its data, so nothing in its bytes contradicts a manifest
claiming a higher watermark than the scan reached, and every answer built on
that watermark would inherit the lie. With the coverage inside the identity the
claim cannot move without moving the fingerprint, and the artifact stops being
the one anyone published.

The file **order** is part of the identity and is written in the manifest rather
than carried in code: a reordered list is a different artifact and says so.

### The parent is declared, not sealed

A parent's fingerprint answers *where do I come from*, not *what am I*, so it
rides in `build` beside the generation and the counters. It was inside the
identity once, and that broke the single promise the fingerprint exists to
make: two indexes built from the same chain to the same height, byte for byte
identical, took **different names** because one builder had sealed their graph
and the other had not. Same content, same answers, two numbers.

What that costs is worth stating plainly: the declared parent can be altered
after sealing. It never protected against the builder, who computes a
consistent identity around a lie either way; only against a middleman editing
a manifest, and only for a reader who does not hold the parent — one who does
compares them and catches it in both designs. `verify` therefore reports the
parent as **declared and unconfirmed** until it is handed the parent, exactly
as it already does for a coverage it cannot derive. A publisher who wants that
declaration bound has the right tool for it, and it is a signature over the
manifest, not a field inside the fingerprint.

The parent's **format** is not in the identity either, and the reason survives
a format's evolution: if a change to the parent alters what the child captures,
the child's own tag moves; if it does not, the child is the same artifact and
must keep its name. Either way the parent's tag says nothing the child does not
already say about itself.

### The producer: who wrote this manifest

```
build.producer = {
    version: string,        // always present
    commit:  hex40,         // only when it can be determined
    dirty:   bool,          // only alongside commit
}
```

It means **who wrote this manifest**, and deliberately not *who produced the
bytes*. For an artifact re-sealed later, or sealed over data an earlier major
emitted, the two differ and only the first is knowable at seal time. A field
whose meaning depends on the artifact's history is a field that will be read
wrong, so it takes the reading that is always true.

The version is always there. The commit and the state of the tree appear only
when they can actually be determined, and are **absent** otherwise: an
installed package has no repository to ask, and a field that guesses is worse
than one that is missing.

**When it is read is part of what it means**: at process start, not at seal
time. A scan seals after days, so asking at seal time would describe the tree
as it stands at the END of the run. An edit made while the scan was running
would be reported against code that never executed, and a checkout moved
underneath it would name a revision that never ran. A re-implementation that
reads this at seal time produces a field that is wrong in a way no reader can
detect afterwards.

`dirty` is the part worth having, and it is why this exists as a field rather
than as a promise. The failure it guards against is not building from an
unlabelled revision, it is building from a tree carrying edits that were never
committed: a version string cannot tell the two apart, and no amount of
discipline detects it afterwards. A convention can be broken silently; a
recorded flag cannot.

This is a **declaration**, weaker than the parent's. Nothing can confirm it,
which is exactly why it stays out of the statement — see below.

### The seconds: what this artifact cost

```
build.seconds = { "build": 126891, "append": 4210, … }   // whole seconds
```

Wall time, not CPU time, keyed by the **public verb** that spent it. Whoever
decides whether a question is affordable decides it against how long they will
wait, and until an artifact carried the figure the only record of it was a log
somebody happened to keep. Absent where nothing recorded it, which is the case
for every artifact sealed before this field existed.

It is in `build` for the reason everything else here is: two honest builds of
identical bytes take different times, so a duration inside the identity would
give the same content two fingerprints. It is out of the statement for the
sharper reason `producer` is: nothing can ever confirm it.

Three properties a re-implementation has to get right, because each of them
changes what the number means:

- **it accumulates across resumes.** The running total lives in the artifact's
  state, which is what survives a kill, so a job stopped and restarted reports
  what it really cost. The seconds between the last checkpoint and the kill are
  lost, since nothing recorded them: the figure is a floor, and stating that is
  worth more than a number that silently restarts at zero;
- **it accumulates across runs.** An artifact fused twice has paid for two
  fusions and the entry under `merge` says so. The question it answers is what
  this artifact has cost, not what the last command took;
- **one pass writes several artifacts, so the entries do not add up.** A `scan`
  co-emits: one walk of the chain writes the archive, the header archive, the
  nonce census and the graph, and each records the SAME seconds under `scan`.
  Summing them across artifacts describes a run nobody performed. Only entries
  under different verbs, within one artifact, are costs paid one after another.

### The statement: what a signature would be over

Nothing here signs anything, and the project does not ship a key. What it does
ship is **one agreed target**, so that a signature layer — ours or anyone
else's — has something to aim at. Without it every signer invents a
serialization and no two verifiers agree.

```
canonical_statement(manifest) :=
      "nodsig-statement-v1\x00"
   || lp(manifest.format)
   || raw32(manifest.fingerprint)
   || u8(build.parent present ? 1 : 0)
   || [ lp(parent.format) || raw32(parent.fingerprint) ]     // if present

statement := sha256( canonical_statement(manifest) ), lowercase hex
```

What it binds is decided by the same rule the identity follows, one floor up:
**exactly what is neither inside the fingerprint nor recomputable from the
bytes, and checkable by whoever receives it.** The fingerprint already stands
for the tag, the coverage and every digest. Counters, totals, generations and
file names are recomputable, so a lie there is caught by reading the files.
That leaves the declared parent, and nothing else — which is why this is four
fields and not a serialization of the whole manifest. It also means a signature
is about the **artifact** and not about one copy of it: two honest builds that
differ in generation numbers sign the same statement.

The third clause is not decoration, and `build.producer` is the case that
requires it. That field satisfies the first two exactly as the parent does: it
is outside the fingerprint, and no reading of the bytes recovers it. It is
still not bound here, because **nothing can ever confirm it**. A declared
parent is checkable in principle: hand over the parent, compare the two
numbers. No artifact exists that could confirm *this manifest was written by
that revision*. Binding an unfalsifiable claim adds no verifiability to a
signature, it only lends it the weight of one, and a reader who cannot tell
the two apart is worse off than one who was told nothing.

A canonical form of the whole manifest is deliberately **not** offered. `build`
is unconstrained by design and differs between formats, so canonicalizing it is
the JSON-canonicalization problem refused above.

The digest is written into the manifest for the same reason the fingerprint is:
it is recomputable, and having it in view makes a disagreement visible. On its
own it secures nothing — whoever edits a declared parent edits this too — but
`verify` recomputes it, so a careless edit is caught, and a signature over it
makes the pair binding.

### When a format tag moves

The tag declares what the artifact captures, so it moves when **that** changes
— including when a change upstream makes it change. It does **not** move for a
new version of the tool: a reimplementation in another language that captures
the same things declares the same tag and computes the same fingerprint.

The two errors are not symmetric. Bumping a tag that did not need it costs
renames; failing to bump one that did costs silence, and a reader who cannot
tell "absent" from "not captured". So when the answer is genuinely unclear, the
tag moves. Each format document names the parent formats it is **defined over**
and states what it captures and what it does not, so that judgement is written
down where a reader can check it rather than recalled by whoever writes.

### The canonical form is bytes, not JSON

JSON has no canonical form (key order, whitespace, number formatting), so the
fingerprint is taken over an explicit byte string. Every variable-length field
is length-prefixed, because a canonical form that can be parsed two ways is not
canonical.

```
canonical_identity(identity) :=
      "nodsig-identity-v3\x00"
   || lp(identity.format)
   || u32be(coverage.from) || u32be(coverage.to)
   || u32be(number of files)
   || for each file, in order: lp(name) || raw32(sha256)

lp(s)      := u16be(byte length of s in UTF-8) || s in UTF-8
raw32(hex) := the 32 bytes the hex string denotes

fingerprint := sha256( canonical_identity(identity) ), lowercase hex
```

A re-implementation reproduces this from the recipe alone, without having to
reproduce anyone's JSON encoder.

**A logical file need not be a file.** The graph's data lives in runs whose
boundaries are buffering accidents, so its canonical form is the concatenation
of those runs in height order. It declares one logical file, `stream`, whose
digest is taken over that concatenation. Nothing else changes: one identity
recipe covers both the artifacts made of named files and the one made of a
stream, which is why invariant 3 can say "one recipe" where it used to have to
say "or".

## Operations

### `build(sources, end_height?) -> Manifest`
Produce (or extend) the artifact. Properties every implementation MUST hold:
- **Resumable:** driven by `state.json` through fixed phases; safe to re-run after
  a crash; committed sizes make a crash truncate-and-redo.
- **Appendable ≡ rebuild:** running `build` on a grown source appends; the result
  is **byte-identical** to a rebuild from zero (proven in tests). Growing with the
  chain is a cadence choice, not a design problem.
- **Refuses bad sources (loud):** a mismatched/stale parent (fingerprint differs)
  or a partial source (e.g. an index with `unresolved > 0`) is **rejected**, never
  built over, because numbers over holes look true.
- **Seals with cross-checks:** at seal, re-read + any accounting identity the
  format defines (e.g. the derivatives' Σ-spent == Σ-inputs), then write the
  manifest + canonical fingerprint.

### `rewind(artifact, to_height) -> Manifest`
Take a sealed artifact back to a height it already covered. The guarantee is the
mirror of append ≡ rebuild:

> **rewind ≡ rebuild.** `rewind(build(…, H2), H1)` holds the same file bytes, and
> therefore the same canonical fingerprint, as `build(…, H1)`.

It exists because a rewind costs one filtering pass per file where a rebuild
costs the whole chain, and because **removing records from a sorted file
preserves its order**: no re-sort is needed, so this is not a second builder.

- **Positional files are truncated** to the record counts the artifact itself
  records at that height; nothing is recomputed.
- **Merged files are re-fused through a sift**: the current generation is its own
  and only source, and records above the cut are dropped. The fusion is the
  ordinary one, so ladder sampling, generation numbering and the crash-safe
  commit order are the same code that built the file.
- **One transform is allowed, and only one**: a record that says "spent by a
  transaction above the cut" must be put back to unspent, because at the target
  height that spend had not happened. It changes no key and no order.
- **Then it re-seals**, which re-reads everything and re-runs the format's
  accounting identities. A sift that dropped the wrong record is caught there,
  by arithmetic the rewind does not control.

**What is NOT restored, and why that is honest rather than a gap.** Both cases
fall out of the identity/build split rather than needing a rule of their own,
which is the sign the split is drawn in the right place:
- counters that describe *how* the artifact was built rather than what it holds
  (the derivatives' `updated_rows`, an append's bookkeeping) cannot be derived
  from bytes. They live in `build`;
- the generation counter only ever moves forward, so a rewound file is named
  `…_gN+1` where a fresh build would name it `…_g1`. The identity carries the
  **logical** name and the actual file name lives in `build`, so the fingerprint
  matches regardless.

**Refuses (loud, before writing anything):**
- a target at or above the current watermark, or below 1: a rewind only ever
  removes;
- an artifact that is not sealed, or whose parent no longer matches;
- a source with `unresolved > 0`: how many of those holes lay below the cut is
  not recoverable, so the count would become a lie;
- **a collapsed duplicate straddling the cut.** Where a format deduplicates by
  key (the index's resolver keeps the later of two equal txids, BIP30), the
  earlier record is already gone; if the surviving one is above the cut, the key
  would vanish from a rewind but be present in a rebuild. The implementation
  detects this by counting: if fewer records are dropped than transactions are
  removed, some removed record had collapsed onto another, and the rewind stops.
  It does not need to know which chain it is on to be exact.

### `verify(artifact) -> { ok: bool, ... }`
Re-read **every byte**: each data file's sha256 against the manifest, each ladder,
then recompute the fingerprint from the identity block as it stands on disk and
check it equals the manifest's. Loud on any mismatch (corruption since sealing).
A ladder mismatch is recoverable (rebuild it); a data mismatch is not.

**The coverage gets a second road wherever one exists.** It is the one identity
field no digest can prove, so where the data themselves imply the covered range
the audit derives it and confronts the two: the index writes one `blocks.bin`
record per height, so the file's own length states the watermark, and a manifest
claiming another one is refused. Where nothing in the bytes implies it, the
report **says so in a line of its own** rather than staying silent, because an
audit quiet about what it did not check reads as an audit that checked
everything.

There are three cases, and the difference between the last two is not pedantry:

| | formats | what the audit can do |
|---|---|---|
| **exact** | headers and index (one record per height), graph (records carry their height), any child handed its parent | derive the watermark and refuse a manifest that claims another |
| **floor** | reveal archive, nonces | the records carry the height of an *event*, so the highest one found is a lower bound: a manifest claiming **less** is refused, one claiming **more** cannot be confirmed, because a stretch of chain with no new revelation leaves no trace |
| **none** | any format whose records hold no height at all | say so, and rely on the identity fingerprint compared against a published one |

A floor is worth having: it turns "the coverage is a word given" into "the
coverage is a word given about the last few blocks only".

**Each ladder is rebuilt from the file it indexes**, not merely compared with its
recorded digest. The digest alone proves only that the sidecar has not rotted on
disk: the seal wrote it by hashing the samples it had just built, so the
comparison is with itself, and a ladder sampled by the wrong rule would pass the
audit while making lookups enter the wrong bucket and answer short, invariant 9
broken silently, which invariant 4 forbids. Rebuilding costs no extra read: the
data file is being streamed for its sha anyway, and the samples fall out of that
pass. An implementation that declares no sampling projection for a cache MUST say
which caches it therefore checks only for integrity.

### `stats(artifact) -> {...}`
Instant, from `state.json`/`manifest.json`: phase, record counts, anomaly totals
(overwritten txids, duplicate/unresolved), and the fingerprint when sealed.

## Invariants a re-implementation MUST hold

1. **Determinism / append ≡ rebuild:** byte-identical regardless of run
   boundaries or checkpoints. Where `rewind` is offered, **rewind ≡ rebuild**
   too: the two are the same claim read in opposite directions, and a format
   that cannot hold the second has an ordering that depends on when a record
   arrived.
2. **Same content, same name.** An artifact's fingerprint is a function of what
   it holds and nothing else, so two honest builds of the same chain to the same
   height agree on it whatever they were built from and whoever built them.
   **Ancestry** is a separate question with a separate answer: each artifact
   declares its parent in `build`, and a reader who holds both confirms the link
   (see the binding invariant in [INVARIANTS](../INVARIANTS.md)). Comparing the
   fingerprints of a whole stack compares the whole ancestry.
3. **One identity recipe**, `canonical_identity` above, for every format. What
   goes in is decided by the rule, not case by case: the digests, the format tag,
   the coverage. **Ladders are excluded**, deliberately and for a reason that is
   not the rule: a cache must not change what an artifact *is*, or deleting one
   would hand you a different object. They are covered instead by `verify`
   rebuilding them from the file they index.
4. **Never silent:** corruption, mismatch, or an untrustworthy join **stops** the
   build/verify; anomalies are counted and reported; and an audit reports what it
   could **not** check, coverage included.
5. **Refuses partial/stale sources** before producing anything.

## Conformance vectors

The **golden canonical fingerprint** of each artifact on a small synthetic chain
is pinned in the builder tests (`test_reveal_archive`, `test_outpoint_index`,
`test_derivatives`), and crash-and-resume sealing to the **same** bytes, append ≡
rebuild, and `verify` rejecting a corrupted file are covered there too. A neutral
`tests/fixtures/artifact/` (the input chain + expected manifests, runtime-free so
a port can reproduce them) is a candidate follow-up; the pure-primitive vectors
(`hashing`, `compactsize`, `fingerprint`, `addresscodec`) already exist under
`tests/fixtures/`, see its `README.md`.

## Notes for porters

- The lifecycle is orchestration (glue): it is not on the hot path and need not be
  ported to native; a port typically reuses the reference lifecycle and swaps only
  the hot kernels (sort/merge, hashing) beneath it.
- A **new derivative** implements only its projection over the parent + its format
  (files, widths, fingerprint order); the state machine, manifest, verify and
  source are inherited from this contract.
