# Graph-v2: format (L0)

The raw **transaction graph** distilled from confirmed blocks: who pays whom,
under which lock, and which prior outputs each transaction consumes. It is the raw
material every other artifact (index, derivatives) is built from — deliberately
**not** an index. Co-emitted while a scan already streams the chain.

- **Directory:** run files under `runs/`, a `state.json` naming them, and (after
  `fingerprint`) a `manifest.json`.
- **Canonical form:** the **concatenation of the run files in height order** — one
  byte stream defined by the chain and the height range alone. Run boundaries are
  an artifact of buffering/checkpoints and are **not** part of the format: an
  interrupted-and-resumed emission produces the same stream, byte for byte.
- **Defined over:** nothing (it is the root of the ancestry).

## Endianness & conventions

**Little-endian** integers; hashes in **serialized order** (explorers display the
reverse); counts and variable lengths use Bitcoin's **compactsize**. The format
echoes the block serialization it distills. (This is the *only* L0 format that is
little-endian; everything downstream is big-endian — see the sibling formats.)

## The stream: a sequence of block records, heights ascending from 1

Genesis (height 0) is **not** emitted (its coinbase is unspendable and creates no
edge).

```
block record:
    height       u32
    block_hash   32 bytes      // sha256d of the header, serialized order
    time         u32           // header timestamp (miner-declared)
    n_tx         compactsize
    n_tx × transaction record

transaction record:
    txid         32 bytes      // serialized order
    flags        1 byte        // bit 0 = coinbase; bits 1-7 reserved (0)
    n_in         compactsize   // 0 for the coinbase (its input is a null reference, not an edge)
    n_in × input record
    n_out        compactsize
    n_out × output record

input record:                  // an EDGE: this tx consumes that output
    prev_txid    32 bytes      // serialized order
    prev_vout    u32

output record:                 // a TILE: a coin is born
    value        u64           // satoshis
    script_len   compactsize
    script       script_len bytes   // the scriptPubKey, verbatim
```

## Excluded on purpose (with the reason)

- **scriptSig & witness** — the *revelations*; archived by
  [RevealArchive-v2](./RevealArchive-v2.md). The graph is flow, not unlocking.
- **version, locktime, sequence** — consensus bookkeeping, not flow.
- **fees** — a join of these records (edges resolved against tiles); storing them
  would be transformation, not fidelity.

Records are **uncompressed**: the fingerprint is defined over these exact bytes;
compression is the filesystem's business.

## Watermark & canonical fingerprint

`manifest.json` follows the shared shape in
[Artifact](../contracts/Artifact.md). The graph declares **one logical file**,
`stream`, whose digest is taken over the concatenation above:

```
stream_digest = sha256( <the whole record stream, in height order> )
```

No format tag goes into that digest, on purpose: it is the digest of what the
chain dictated, so it is the number to compare **across format versions** when
the question is whether the bytes changed. The tag, the coverage and the digest
are then sealed by the one identity recipe every artifact here shares, and its
hash is the fingerprint.

Same chain + same end height ⇒ same fingerprint on any machine. Run boundaries
are invisible to both numbers, which is what makes an interrupted emission equal
to a one-shot one.

## Checking an emitter without writing the archive again

Because the data format does not change between majors, a rescan does not have
to write the graph a second time: the archive on disk stays valid and is only
re-sealed. Nothing would then check that the emitter still produces those bytes,
which is what `archive scan --graph-digest <graph-dir>` is for. It serializes
exactly the records `--graph` would have written, hashes them, and writes
nothing.

The comparison costs no read of the reference. `state.json` already records a
**sha256 per run**, so the check closes an interval exactly where the reference
closed a run and compares the two digests directly, reporting a mismatch by
interval the moment the scan crosses that boundary. Those recorded digests are
worth what the last `fingerprint` pass is worth, since that pass re-reads every
byte and checks each run against the file it names: run it on the reference
first.

Two properties follow from sha256 having no state anyone can write down:

- an interruption costs the **one interval** it falls inside, which is reported
  as not verified rather than assumed; every other interval is unaffected;
- the **whole-stream digest** above is accumulated too, and equals what
  `fingerprint` computes, but only for a pass that ran from height 1 in one go.
  A resumed pass reports it as unavailable and keeps its intervals.

The result is written next to the host scan's own state as `graph-digest.json`
and re-read with `graph digest --scan <scan-dir>`.

## An archive emitted under v1

The v1 → v2 break moved the **seal** and not one byte of the record stream, so
an archive emitted under `graph-v1` still decodes here, its per-run digests
still hold, and it can serve as the reference of a `--graph-digest` check. The
readers accept both tags; only `graph-v2` is ever written.

One thing such an archive cannot do is act as a **parent**. A v1 manifest's
fingerprint comes from a recipe this major does not compute, so an index that
adopted it would seal an ancestry nobody can rederive from these formats. The
index refuses it by name rather than taking it silently.

`fingerprint --reseal` is what gives the same bytes a v2 identity. It asks,
rather than superseding a published number by surprise, and it keeps the old
manifest beside the new one as `manifest.<oldformat>.json`: re-sealing adds an
identity and destroys none.

## Notes for porters

- A reader only needs `compactsize` + the record grammar above; no other artifact.
- The coinbase test at emission is structural: exactly one input, `prev_txid` all
  zero, `prev_vout = 0xFFFFFFFF` → `flags` bit 0 set and `n_in` written as 0.
- Integrity of the source blocks (header hash, prev link, Merkle, witness
  commitment) is the host scanner's job, done once at scan time; the format itself
  carries no consensus validation.
