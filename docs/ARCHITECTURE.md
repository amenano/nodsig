# NodSig — Architecture: contracts, layering, kernels

> The architecture map of the project: the mental model in one page. Per-contract
> detail lives in `docs/contracts/`, byte formats in `docs/formats/`, the type
> vocabulary in `docs/types.md`, and the artifacts themselves — what produces
> each, what reads it, what it costs — in [`docs/ARTIFACTS.md`](ARTIFACTS.md).

## 0. Why this architecture (the project's "signature")

NodSig's value is not just the address check: it is **an architecture in which the
engineering choices are themselves a form of explanation and verifiability**.
Three pillars:

1. **Contracts before implementations** — well-defined interfaces/contracts; a
   base implementation is provided; anyone extends with their own instance (even
   in other languages). Extension is a *public feature*.
2. **Pure, portable kernels + thin orchestration** — performance and reuse live
   in pure, single-responsibility modules; the glue (I/O, CLI, resume,
   source) calls the kernels.
3. **Verifiability as the test of a port** — the canonical fingerprint and the
   conformance vectors tell you whether two implementations (two languages, or
   reference vs native kernel) are *identical*.

Consequence for extensibility: a private deep-dive or backend is just **a private
instance of a public interface**. No dedicated machinery.

## 1. Layering: L0 / L1 / L2 and the access rule

| Layer | What it is | Transport | Access pattern |
|---|---|---|---|
| **L0 — data at rest** | the `.bin` formats + canonical fingerprint | shared files, `mmap`/`pread`, zero-copy | **bulk/streaming** (billions of records): ALWAYS here, never over the network |
| **L1 — in-process interfaces** | the OOP contracts, idiomatic per language | direct call | extension within the same runtime |
| **L2 — inter-process/network** | an exchange protocol | UDS / stdin-stdout / TCP / HTTP / gRPC | **point queries** or remote access, where the round-trip amortizes |

**Golden rule (right layer, no performance degradation):** the *access pattern*
chooses the transport. Bulk scans stay at L0; NEVER wrap the hot streaming path
in an RPC. The network touches only the point-query surface. Default **local and
private** (UDS/localhost/file); network only opt-in and authenticated (like the
node's cookie-file).

Key note: **the byte formats are already the deepest and fastest cross-language
contract.** A reader in C/Java/Rust reads `outputs.bin` (28 B/record, big-endian)
with a `pread` and zero dependencies: the layout IS the spec. Porting just the
*readers* is the easiest and most verifiable cross-language activity (same
fingerprint = same result).

## 2. Neutral type vocabulary

Fixed types that map to C structs / Java classes / JSON fields / protobuf
messages without impedance (full detail in `docs/types.md`):

```
u32, u64        big-endian integers (height, ordinal, amount-in-sat)
digest20        20 bytes (hash160)     digest32   32 bytes (txid/sha256)
LockType        enum {P2PK,P2PKH,P2SH,P2WPKH,P2WSH,P2TR,UNKNOWN}
Source      { id, watermark:u32, fingerprint:digest32 }
Status          enum {OK, UNDETERMINED, UNSUPPORTED}
Result<T>       { status:Status, value:T?, source:Source }   // common envelope
```

The `Result` envelope ALWAYS carries source + status: a third-party
implementation cannot lie silently and must honestly declare UNDETERMINED/
UNSUPPORTED. This is the "never silent data / honest degradation" principle, in
the contract.

## 3. The list of contracts

### L0 — format contracts (in `docs/formats/`)

`Headers-v2` (headers/coinbase/coinbase_off), `Graph-v2`, `OutpointIndex-v2`
(blocks/txids/tx_first_out/txid_index/outputs/spends), `OutpointDerived-v2`
(history/tx_inputs/fees), `RevealArchive-v2`, `Nonces-v3`,
`Nonces-witness-v1`. Each:
record layout + ordering rule + canonical fingerprint + ancestry (every
manifest names its parent).

Two documents in that directory are **not artifacts** and say so in their first
line: [`AddressBook-v1`](formats/AddressBook-v1.md), the input of `check`, and
[`CheckReport-v1`](formats/CheckReport-v1.md), its complete output. Nobody
seals them and no nodsig command reads them back; they sit there because that
directory is *the formats we promise stability on*, which is what a third-party
tool needs.

### L1 — capability contracts (one question = one contract)

The **authoritative** signatures live in `docs/contracts/` — this section is a
*map*, not a copy (single source of truth: the one-line sketches that once sat
here had already drifted from the real interfaces). Contracts come in **kinds**,
and only *readers* speak the `Result<T>` envelope.

**Readers** — offline, deterministic; return `Result<T>`:
- [`IndexReader`](contracts/IndexReader.md) — resolve an outpoint; read output / tx / height facts.
- [`HistoryBackend`](contracts/HistoryBackend.md) — a lock's payment history (rows; plus a derived event view).
- [`BalanceBackend`](contracts/BalanceBackend.md) — a lock's offline balance at the watermark.
- [`FeeBackend`](contracts/FeeBackend.md) — a transaction's fee (coinbase reported).
- [`CoSpendBackend`](contracts/CoSpendBackend.md) — a transaction's co-spent inputs (common-input hint).
- [`ExposureLookup`](contracts/ExposureLookup.md) — was a key/script revealed on-chain? (reveal archive).
- [`AddressCodec`](contracts/AddressCodec.md) — address ↔ scriptPubKey ↔ lock, and address → `(digest, category)` for exposure. The most error-prone contract: **one address yields two unrelated digests** (hash160 of the whole scriptPubKey for history, vs the key/script digests for exposure).
- [`NonceExposureBackend`](contracts/NonceExposureBackend.md) — did the key behind this address sign twice under one nonce? (witness table, 1 MB, offline).
- [`LinkageBackend`](contracts/LinkageBackend.md) — which of the addresses you gave can an outsider already tie together, in three classes that are three different claims.

**Builders** — write sealed, appendable, fingerprinted artifacts; not readers: [`Artifact`](contracts/Artifact.md) (build / verify / stats) — the shared lifecycle of graph / index / derivatives / archive / nonce census — one fingerprint, one audit, one append-and-fuse store; a new derivative is a thin application of it.

**Live seams** — real-time, non-reproducible; extension points: [`LiveSource`](contracts/LiveSource.md), [`Matcher`](contracts/Matcher.md).

**Node** — live, cookie-file, explicitly non-reproducible: [`NodeClient`](contracts/NodeClient.md).

An alternative indexer backend (Electrs/Fulcrum) is an implementation of **equal
standing** for the reader contracts.

**Envelope rule (decided, and IMPLEMENTED in `capability.py`).** The
capabilities of the address check (`exposure`, `balance`, `history`,
`co-inputs`, `nonce-exposure`; `linkage` answers about the set rather than one
address, so it returns its block with a status per class) return `Result` today; a report's header lines ARE the
sources, which is why they name format tags and fingerprints and never a
directory. Source + status ride a `Result<T>` at the
**capability boundary**, *once per operation* — never per streamed record. A
`Result<stream<T>>` carries source once; the millions of streamed items stay
bare. In-process reference readers may return raw values internally; the envelope
is applied at the boundary, and is exactly what an L2 transport serializes.

### L2 — query protocol (across process/language/machine)

The SAME L1 operations over a transport: request `{op, args}`, response
`Result<T>` serialized. Only the point-query surface (`lookup/fee/exposure/
balance`); streaming `history`/`cospends` prefer L0 or a framed stream, not JSON
over HTTP. Default UDS/localhost.

## 4. Kernels vs orchestration

Performance and reuse live in **pure kernels** with single responsibility; the
**orchestration** (I/O policy, CLI, resume, source) is glue that calls them.

**Extracted — one implementation for every builder:**

1. **`hashing`** — sha256d, ripemd160 (with a pure-Python fallback for
   OpenSSL-legacy), hash160. The deepest leaf: pure bytes, no imports.
2. **`recio`** — slab I/O for fixed-width record files: the read/write budget
   (`IO_CHUNK`, `budgeted_slab`), the sha-verifying slab reader (`read_fixed`,
   which takes the caller's exception class), whole-file sha, atomic JSON.
3. **`recsort`** — the sorted-run writer (`write_run`) and the ladder-backed
   search (`bisect_blob`, `SortedFile`) over fixed-width big-endian records.
   The **hottest path** (CPU+I/O) and the **prime native-port target**:
   `memcmp` on big-endian is trivial and SIMD-friendly.
4. **`artifact`** — the sealed-artifact shape: the canonical fingerprint
   (`canonical_fingerprint`, the root of the ancestry) and the verify
   audit (`verify_sealed`), shared by the archive, index and derivatives.
5. **`blockparse`** (the btcparse kernel) — compactsize read+write, parse
   header/tx/block, merkle, witness commitment, script pushes. (The snapshot
   VARINT is a *different* integer format and stays in `utxo_census`.)
6. **`capability`** — the answer envelope: `Status`, `Source` and
   `Result`, plus the one header line a report prints per capability. It also
   enforces the rule that keeps results portable: a `id` containing a
   filesystem path is refused at construction.
7. **`genstore`** — the append-and-fuse store: sorted runs, merged
   generations, ladders sampled while writing, and the crash-safe commit
   order (state first, deletions after). An artifact declares only its
   directory and, per merged file, its projection `(record width, key
   length, ladder step)`; the index and the derivatives each own an
   instance. It is a *component*, not a base class: the derivatives are not
   a kind of index, they only grow the same way.

**Deliberately not merged, or pending:**

- The k-way **merge** stays format-specialised, not one function: the archive
  OR-dedups a `(digest, flag)` stream, while the index/derived merges sample
  ladders and keep-last. Only the pieces below them (`read_fixed`, `write_run`,
  the budget) are shared. The archive keeps its own fusion for the same reason
  — but it now follows `genstore`'s **commit discipline** (write generation
  N+1 beside N, commit the manifest, then delete), which is invariant 10 and
  not a detail either implementation gets to choose.
- **`records`** (per-format `.bin` field codecs) and **`addr`** (base58check,
  bech32, `decode_address`, `script_pubkey` — today single-source in
  `check_addresses`) are candidates, extracted on demand, not before.
- The `Index` and `Derived` **readers** still live with their formats. Sharing
  them would mean sharing a query model, which is not the same problem the
  builders had; extracted on demand, not before.
- **native kernels** — demand-driven, post-publication (see §6).

The orchestration (phase state machines, `build`, manifest/source,
checkpoint/resume, CLI) **stays glue**: it calls the kernels, and is not ported
to native unless needed.

## 5. Reference impl + conformance + porting

**Ideal end-state: two implementations bound by conformance.**
- **Python = the readable, auditable reference** — the executable truth, the spec
  anyone reads (readability is a stated value of the project).
- **native kernels = proven-identical accelerators** — same fingerprint, same
  vectors.

**Neutral conformance vectors:** input fixtures + expected outputs/fingerprints,
in a form that does NOT require the reference runtime. A C/Java implementation
proves conformance by running the vectors and comparing fingerprints. It is
verifiability applied to porting.

**Swap-and-verify:** replace a reference kernel with a native one behind the same
contract and *prove* equivalence (same fingerprint). No big-bang, no trust.

## 6. Performance reality + sequencing

A native rewrite attacks only the CPU; if the load is I/O-bound (reading from
network volumes), the I/O wait remains. So "re-engineering" is NOT "rewrite in
C"; it is: **(1) profile, (2) fix I/O and algorithm, (3) accelerate in native
only the residual CPU-bound part**, proven equivalent.

Low-cost wins before native: staging on fast local storage, `mmap`, large
buffers, sequential access; a run+merge algorithm (cheap run appends + rare
compaction) instead of full re-fusion; per-shard parallelism.

**Step (2), done for the fusion.** An append re-fuses whole files, billions of
records of which the new blocks touch a handful, so `genstore.merge_to_file`
takes the previous generation as a CURSOR and, whenever its next stretch is
entirely below the next pending record of the runs, settles that stretch in one
piece: the bytes move once, the ladder is sampled by arithmetic, and the
duplicate count is taken a column at a time rather than a record at a time. The
boundaries keep the per-record path, and so does a rewind, whose sift may drop
or rewrite any record. It is the same loop and the same rules either way, which
is what the suite asserts: same bytes, same ladder, same duplicate count and
same duplicate log as the plain walk, against a reference written the obvious
way. Measured on synthetic files with the four real shapes: **3.4×–11× on an
append's ratio** (runs ≈ 0.3% of the base), 1.5×–4.5× at 5%, and parity when the
runs are as large as the base: the stretch has to be worth measuring before the
fusion tries, or the search costs more than the walk it replaces. The plain road
(a first build, which has no previous generation) pays **2–5% more** for the
dispatch that chooses between the two.

**Step (2), done for the parser, and step (1) is why it looks like this.**
`blockparse` runs over every input ever confirmed, so a microsecond an input
is an hour of wall clock, and it had never been profiled: "it is only a
parser" reads like something already as fast as it gets. The profile says the
cost was not the work but the SHAPE of the code. Over thirty real blocks:
1,754,242 calls to `_take` and 1,037,092 to `read_compactsize`, whose bodies
are an addition, a comparison and a slice, plus 3,109,441 calls to `len`. So
the bounds checks stay inline and the helper is reached only to raise, `len`
is read once per transaction instead of once per field, and the one-byte
compactsize form is read inline while the long forms stay in the function.
Every error message is unchanged, which was the constraint and not a
by-product: with gigabytes streaming past, an error that says only "bad data"
is useless. Separately, a `TxIn` used to be built without its witness (which
is serialized after the outputs) and then rebuilt by `_replace`, at about
1.7× the constructor, once per input of every SegWit transaction; the fields
now wait in a plain tuple and the record is built once. Measured on 200 real
blocks drawn from five eras of the chain: **1.46×**, 7.73 to 5.29 microseconds
an input, with the parsed structures compared field by field and identical.

That measurement is also the clearest argument for this section's own
sequence, because it refuted the intuition that sent us looking. Inside the
old parser, hashing (already native, via OpenSSL) was 19.7% of the time,
walking the bytes 8.3%, and **building the Python objects 69.9%**. A native
kernel that parsed the same bytes and returned the same structures would
therefore have a ceiling near 1.12×: it removes the walk and pays the
allocation regardless. The residue worth attacking natively is never obvious
before (1), and here it was not the pass that looked slowest.

**Sequence (demand-driven):** kernel/orchestration boundaries first (design) →
I/O + algorithm wins if needed → native kernels only on the residue, one at a
time, when a bottleneck actually blocks a use case. The right moment is for the
**boundaries**, not the rewrite.

## 7. Agent-legible documentation (LLM-friendly)

The repo contains `.md` files designed so that whoever continues or deepens the
work can employ an LLM **as productively as possible**, and **without lock-in** to
a single model.

**Unifying principle:** the same thing that makes cross-language porting safe
makes an LLM's contribution safe — **the conformance vectors**. An LLM can
*generate* a port/extension AND *verify* it against the fingerprints: the
contribution is trusted because it is **checkable**, not because the model is
good.

Doc hierarchy:
- **`AGENTS.md`** (root, neutral): orientation for ANY agent — what the project
  is, how to build/test, the invariants, where the canonical spec lives, what NOT
  to do. Not specific to any assistant.
- **`docs/ARCHITECTURE.md`**: this map.
- **`docs/contracts/*.md`**: one file per contract — purpose, neutral signature,
  invariants, source/error semantics, pointer to the reference impl, location
  of the conformance vectors.
- **`docs/formats/*.md`**: the L0 formats (record layout, ordering, fingerprint).
- **Task-oriented recipes**: "add a derivative", "add a backend for capability X",
  "port a kernel to language Y" — step by step.
- **Question-oriented pages**: [`exposure-check.md`](exposure-check.md) (has this
  address's key been revealed, offline, from one artifact) and
  [`nonce-check.md`](nonce-check.md) (was a key given away by a repeated nonce,
  which needs the index, the derivatives and a node). One page per question, with
  its cost and its limits stated where the question is asked.
- **`docs/GLOSSARY.md`**: neutral definitions of the domain terms.
- **`docs/INVARIANTS.md`**: what must ALWAYS hold and what is out of scope.

Style rules: small, self-contained, chunkable files; exact commands + expected
output + fingerprints; docstrings as canonical spec.

**Anti-drift:** "clear" docs rot when they diverge from the code. Antidote: a
single source of truth (docstrings/spec + TESTED conformance vectors); wherever
possible, executable documentation. The conformance vectors are the thing that
cannot lie.

## 8. Open decisions

- **Neutral schema for L1/L2 types:** tables (lightweight, zero dependencies) now;
  an IDL (protobuf/Cap'n Proto) only if an L2 service appears. The tables are
  written IDL-ready (the vocabulary maps 1:1 to protobuf).
- **Private extensions:** a private backend/analysis is a private instance of a
  public interface; the public repo never names it (one-way dependency).
- **Language of the native kernels** (if/when): Rust or C with a C ABI (the lingua
  franca for Python/Java/… bindings). To be decided on demand.
