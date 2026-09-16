# The artifacts: what each one is, what makes it, what reads it

Between the commands and the byte formats there is a layer that neither
documents: which files exist, which command produces each, which commands can
then read it, and what you can skip. This is that map.

Byte layouts are in [`formats/`](formats/); the interfaces that read them are in
[`contracts/`](contracts/); the commands themselves, in the order they are run,
are in [`build-and-query.md`](build-and-query.md). Directory names below are
placeholders: every one of them is a path you choose on the command line.

## What this version emits, and what it still reads

<!-- FORMAT-MATRIX: generated from the modules' FORMAT_TAG / READ_TAGS and
     pinned by tests/test_conformance.py. Edit the code, not this table. -->

| artifact | emits | also reads |
|---|---|---|
| graph | `graph-v2` | — |
| headers | `headers-v2` | — |
| revelation archive | `reveal-archive-v4` | — |
| nonce census | `nonces-v3` | — |
| nonce witness table | `nonces-witness-v2` | — |
| outpoint index | `outpoint-index-v3` | — |
| outpoint derivatives | `outpoint-derived-v3` | — |
| first-spend table | `firstspend-v1` | — |
| first-reveal table | `firstreveal-v2` | — |
| block stats | `block-stats-v3` | — |
| price series (external input) | `price-series-v2` | — |
| block price (external input, derived) | `blockprice-v2` | — |
| address book (input) | `address-book-v2` | — |
| check report (output) | `check-report-v3` | — |

One sealed output is deliberately not a row above: `derived timeline` seals a
`derived-timeline-v2` meta beside its two CSVs (and a third, priced one outside
the identity when a price table was given) — the same CSV-plus-sealed-meta
shape as block stats, but produced by the derivatives module rather than a
module of its own, and the table maps modules to the one artifact each emits.

**One format per major, read and written.** 2.0.0 reads only what it emits:
an artifact sealed under an earlier format is read, verified and queried with
the release that wrote it (the CHANGELOG names the format and the release),
and every reader refuses it by name rather than reading bytes at the wrong
widths. Reproducibility is untouched: the same chain and the same tag give the
same bytes; what 2.0.0 gives up is a reader for the previous layouts, which no
published figure needs.

This table is not maintained by hand. It is checked against the modules'
`FORMAT_TAG` and `READ_TAGS` by the test suite, so a format that moves without
the documentation moving fails the build rather than misleading a reader.

## The flow

**One pass over the chain is all you need.** It is the only long step that talks
to the node, and its co-emission flags feed everything else from it: the archive
of revelations, the raw graph the index and the derivatives are built from, and
the header chain that lets the pass's own checks be repeated later.

```
                ┌─ census ─────────────────────────────► census.csv   (context: the set by type and age)
  <snapshot> ──►│
  (dumptxoutset)└─ reuse prepare ──────────────────────► <locks>/     (the current UTXO locks)
                                                             │
   ONE PASS OVER THE CHAIN, over RPC or REST                  │
   archive scan ──────────┬──► <archive>/ ──► archive merge ──┴──► archive derive
     --graph --headers    │      ├ runs/…_keys.bin        (seal +      │
     --nonces             │      ├ runs/…_scripts20.bin   fingerprint) ├─► reuse table
                          │      ├ runs/…_scripts32.bin                └─► curve.csv ──► curve deltas
                          │      └ state.json → manifest.json
                          │            (merged) ──► firstreveal build ──► <firstreveal>/
                          │                                (keys by first-reveal time)
                          │
                          ├──► <headers>/ ──► headers fingerprint (seal)
                          │         │
                          │         ├──► headers verify / crosscheck --index
                          │         └──► curve dates            (no node needed)
                          │
                          ├──► <nonces>/ ──► nonces merge (seal)
                          │         │
                          │         ├──► nonces groups ──► the repeated points
                          │         ├──► nonces resolve ──► <witness>/  (needs the node and the index)
                          │         │         └──► the resolution on each repeated point
                          │         └──► nonces lookup / verify / rewind
                          │
                          └──► <graph>/ ──► graph fingerprint (seal)
                                   │
                                   ├──► blockstats build ──► block-stats CSV
                                   │
                                   └──► index build ──► <index>/ ──► derived build ──► <derived>/
                                                                  (a lock's history, fees, co-spends)

   everything above, plugged into:  check ──► per-address answers
```

`--graph` is optional: leave it out if you only came for the exposure question
and will never want fees, history or co-spends. It costs disk, not time: the
pass happens either way, and doing it twice would not.

`--nonces` is optional on the same terms, with one difference: it costs about
10% of the pass's CPU as well as its disk, because it reads the signatures the
other artifacts throw away. It is the one addition here that a later pass could
not reconstruct, since nothing kept afterwards holds unlocking data. See
[`nonce-check.md`](nonce-check.md) for what it answers, alone and together with
the index.

**Keep the perimeter identical between `scan` and `derive`.** `--no-faces` and
`--no-cosigners` narrow what counts as a revelation; they exist for exploring,
but a narrowed scan and a full derive describe different questions, and the
comparison refuses rather than quietly mixing them.

## What you actually need

Not all of it. Pick by the question you came for.

| If you want | Build |
|---|---|
| the UTXO set by type and age | snapshot → `census` |
| "has this key already been revealed?" | snapshot → `reuse prepare`, then `archive scan` → `archive merge` |
| how much value sits behind revealed keys | the above, then `archive derive --locks` |
| exposure of today's coins by the height their key became public | `archive derive --curve` → `curve deltas` |
| fees, a lock's history, co-spends | `archive scan --graph` → `index build` → `derived build` |
| per-block statistics | `archive scan --graph` → `blockstats build` |
| to repeat the scan's checks later, or to put real dates on a curve | `archive scan --headers` → `headers fingerprint` |
| which keys were first revealed in a height window, as a contiguous read | the archive above, then `firstreveal build` |
| whether a signing key ever gave itself away by repeating a nonce | `archive scan --nonces` → `nonces merge` → `nonces groups` |
| the same, for one of your addresses | `index build` → `derived build`, then `nonces address` (needs a node) |
| fiat figures, one price per block | `index build`, then a publisher's series you fetched → `price import` → `price build` (an external input, not an artifact: [external-inputs](external-inputs.md)) |

### The second road, and why it is not in the list

There is another way to count reuse: `reuse scan` walks the chain comparing
every revelation against the locks as it goes, keeping a bitmap of a few
megabytes instead of tens of gigabytes, and `archive crosscheck` then derives
the same figure from the sealed archive and puts the two side by side. Different
data structures, different order of work, different moment of comparison.

What that comparison covers, precisely, and what it does not. The two roads
walk the chain with different code, join against the locks in a different
order, and keep different structures (a bitmap burnt as it reads against a
sorted archive read after the fact): that is what the comparison tests. Since
2.0.0 they share one classifier of what counts as a revelation
(`sightings.py`), on purpose: two hand-written readings of the same scripts
drifted apart, and it was this cross-check that kept forcing them back
together. So a wrong rule about revelations would make the roads agree, and
the check does not cover it; the format page and its vectors do. Both roads
also burn the same lock files through the same lookup code, so a broken locks
directory would make them agree rather than disagree, which is why the files
are verified against the sha256 their manifest recorded at `prepare`, and why
`crosscheck --reuse-state` refuses a checkpoint made against a different
locks manifest.

It is worth knowing that road exists, and the commands are here for anyone who
wants to walk it. But it costs a second full pass over the chain, and what it
buys is confidence in the *method* rather than a number you do not already have.
Treat it as a result to inherit, not a step to repeat — which is how the numbers
published with this project were produced: run once, agreed, reported. It is
maintained on those terms: it is the maintainer's audit of the archive, run at
every release that changes what the archive extracts, with the outcome
published beside the figures; it takes no new features (those go to the
archive); and a release at which it is not run is the release it comes out.

## The artifacts

| Artifact | Format | What it is | Produced by | Read by |
|---|---|---|---|---|
| `<snapshot>` | `dumptxoutset` v2 | The UTXO set at one block: the pinned root of every count below | `bitcoin-cli dumptxoutset` | `census`, `reuse prepare` |
| `census.csv` | CSV | Totals per script type and height band. **Aggregates only**: no individual coin | `census` | a human |
| `<locks>/` | `locks-v2` | The current locks: sorted digests of unspent outputs, one file per type, sealed with the snapshot's height | `reuse prepare` | `reuse scan`, `reuse verify`, `archive derive/crosscheck` |
| ├ `locks_{p2pkh,p2sh,p2wpkh,p2wsh}.bin` | sorted records | One lock type per file | `reuse prepare` | as above |
| └ `manifest.json` | `locks-v2` | The identity over the four files at the snapshot's height (from `--headers` or `--height`, checked by the first consumer that sees the block), the base hash declared beside it; every reader checks the files before burning a lock | `reuse prepare` | as above |
| `<archive>/` | `reveal-archive-v4` | Every key and script ever revealed, appendable; answers without its state and without its proof | `archive scan` | `archive merge/verify/derive/crosscheck/curve/lookup`, `check`, `firstreveal build` |
| ├ `runs/…_keys.bin` | records | `hash160` of public keys revealed in a scriptSig, a witness, an output or a taproot leaf, one identity per point | `archive scan` | as above |
| ├ `runs/…_scripts20.bin`, `runs/…_scripts32.bin` | records | Every candidate redeem and witness script, before the proof | `archive scan` | as above |
| ├ `runs/…_programs20.bin`, `runs/…_programs32.bin` | records | The programs of the P2SH and P2WSH outputs created, and of the P2SH-P2WSH redeem scripts pushed | `archive scan` | `archive merge` |
| ├ `manifest.json` | `reveal-archive-v4` | The canonical fingerprint, written by `merge`: the scripts are the candidates a created program opens | `archive merge` | `archive verify` |
| └ `proof/` | `reveal-proof-v1` | The programs and the candidates none of them opens yet, sealed in the same fusion with the archive as parent. Needed to grow the archive and to audit the proof, not to read it | `archive merge` | `archive merge`, `archive verify --deep`, a scan that grows the archive |
| `curve.csv` | CSV + `reuse-curve-v2` sidecar | One row per height step over the snapshot's locks: the coins spendable at the snapshot whose key was public by that height, with the `reuse-hits-v2` fingerprint of the row; the sidecar seals the CSV and names the grid, the locks and the perimeter | `archive derive --curve`, `reuse scan` | `curve deltas`, `curve dates`, `archive crosscheck --curve` |
| `revelations.csv` | CSV + `archive-curve-v2` sidecar | One row per window of heights: the points and the scripts first revealed in it, no locks and no perimeter | `archive curve` | `curve dates`, a human |
| `<headers>/` | `headers-v2` | The header chain the scan verified, from genesis: 88 B per height plus each coinbase script. Off by default, enabled with `--headers` (~150 MB) | `archive scan --headers` | `headers verify/crosscheck`, `curve dates` |
| ├ `headers.bin` | records | The 80 header bytes verbatim, then the block's size and weight | `archive scan --headers` | as above |
| ├ `coinbase.bin`, `coinbase_off.bin` | records | Each block's coinbase scriptSig, and where it starts | `archive scan --headers` | as above |
| └ `manifest.json` | `headers-v2` | Fingerprint and coverage `0..H`; no parent, it comes from the blocks | `headers fingerprint` | verification |
| `<nonces>/` | `nonces-v3` | Every signature nonce point ever published, with the height. Off by default, enabled with `--nonces` (~55-60 GB): the repeated ones are the candidates for a key recoverable from public data, which a block re-read confirms or rules out | `archive scan --nonces` | `nonces groups/lookup/verify/rewind`, `nonces address` (with the index and a node) |
| ├ `nonces_gNNNN.bin` | records | One 16-byte record per signature: point, height, scheme, and the sighash mode it committed to | `archive scan --nonces` | as above |
| └ `manifest.json` | `nonces-v3` | Fingerprint and coverage; no parent, it comes from the blocks | `nonces merge` | `nonces verify` |
| `<witness>/` | `nonces-witness-v2` | The evidence that resolves each repeated point: per (nonce point, key, attribution class), the signatures that decide whether a key follows, the key being the one the unlocking data or the spent output names (a key beside the signature that hashes to the lock, a position in an m-of-m script or a tapscript template, a P2PK or taproot key-path output). Optional, built after the census (~1.5 h over the whole chain plus the index lookups, a few MB) | `nonces resolve` (needs the node and the index) | `nonces witness-verify`, `check --witness` |
| `<graph>/` | `graph-v2` | The raw transaction graph. Off by default, enabled with `--graph` | `archive scan --graph` | `graph`, `blockstats`, `index build` |
| block-stats CSV | `block-stats-v3` | Per-block series (transactions, inputs, outputs, value, time, and the outputs no key can spend with their value) derived from the graph, sealed by a meta beside it | `blockstats build` | `blockstats summary/verify`, a human |
| `<index>/` | `outpoint-index-v3` | The chain numbered once: a record per output, its spend already resolved | `index build` | `index lookup`, `derived build`, `check` |
| ├ `outputs.bin`, `spender_of_gNNNN.bin`, `spend_extra_gNNNN.bin` | records | Outputs in ordinal coordinates; one slot per output naming its spender, with an overflow file for the duplicate-spend anomaly (empty on a consensus-valid chain) | `index build` | as above |
| ├ `txids.bin`, `txid_index_gNNNN.bin`, `tx_first_out.bin`, `blocks.bin` | records | The dictionaries turning txids and heights into ordinals, and back | `index build` | as above |
| └ `manifest.json` | `outpoint-index-v3` | Fingerprint and coverage; the parent graph is **declared** in `build` | `index build` | verification, `derived build` |
| `<derived>/` | `outpoint-derived-v3` | The same facts reordered by lock, by transaction, by co-spend | `derived build` | `derived history/fee/cospends`, `check` |
| ├ `history_gNNNN.bin` | records | One row per output carrying both events, receipt and spend | `derived build` | `derived history`, `check` |
| ├ `tx_inputs.bin`, `fees.bin` | records | Inputs per transaction, and each transaction's fee | `derived build` | `derived fee/cospends`, `check` |
| └ `manifest.json` | `outpoint-derived-v3` | Fingerprint and coverage; the parent index is declared in `build`, and a stale pairing is refused | `derived build` | verification |
| `<firstspend>/` | `firstspend-v1` | The first spend of every lock, ordered by that moment (25 B: `spender_tx` \| `lock`) | `firstspend build` | `firstspend between` |
| └ `firstspend_gNNNN.bin`, `manifest.json` | records / `firstspend-v1` | One row per lock ever spent from; the parent derivatives are **declared** in `build` | `firstspend build` | `firstspend between/verify` |
| `<firstreveal>/` | `firstreveal-v2` | The first revelation of every key, ordered by that moment (20 B per row in `keys.bin`, one u40 offset per height in `first_off.bin`; was 23 B: `first_height` \| `key`) | `firstreveal build` | `firstreveal between` |
| └ `keys.bin`, `first_off.bin`, `manifest.json` | records / `firstreveal-v2` | One row per revealed key, a 1:1 restatement of the archive's keys partition; the parent archive is **declared** in `build` | `firstreveal build` | `firstreveal between/verify` |
| `*.lad` (inside the archive and its proof, the census, the index, the derivatives and firstspend; **not** firstreveal, whose height column is its own offset table) | ladders | Search caches: one sample every few thousand keys. **Outside the fingerprint**; without them a search falls back to a blind bisection, slower and with the same answer | the builders | the readers, when present |
| `<checkpoint>/` | `reuse-scan-v2` | The burnt set: a `hits_<type>.bin` bitmap of which locks history has opened, plus `state.json` (the locks, the height and the perimeter the `reuse-hits-v2` fingerprint names) and, from the scan, its own sealed `curve.csv` | `reuse scan`, `archive derive --checkpoint` | itself (resume), `reuse stats`, `archive crosscheck` |

## What the scan checks while it reads

The long pass runs for hours or days, unattended, over a connection you may not
control end to end. It is worth knowing what it refuses to accept, because none
of it is optional and none of it can be turned off:

1. **the bytes must hash to the block that was asked for** — the header is
   re-hashed and compared with the requested hash;
2. **the transactions must be the ones the header commits to** — the Merkle root
   is recomputed from the parsed txids;
3. **the witness bytes must be committed too** — recomputing the Merkle root is
   not enough, because a txid excludes witness data by construction, and the
   witness is exactly where most revealed keys live. The witness commitment in
   the coinbase closes that gap, and is verified;
4. **each block must link to the previous one** — a `prev_hash` that does not
   chain stops the scan rather than producing a plausible number over a reorg or
   a different node.

Every byte must also be consumed: trailing bytes mean the input was not one
well-formed block. So a corrupted or substituted block fails while it is being
read, before it can become a number. The scan writes a checkpoint as it goes and
resumes from it, so an interruption costs the current interval, not the run.

All four happen in memory and then evaporate, which is what the **header
archive** is for. With `--headers` on, checks 1, 4 and 2 become **repeatable**
offline forever: `headers verify` re-derives every block id and every link from
the 80 bytes it kept, and `headers crosscheck --index` recomputes every Merkle
root from the index's own txids. Check 3 cannot be repeated from anything kept,
because the witness is deliberately not archived, and saying so is part of the
claim.
See [Headers-v2](formats/Headers-v2.md).

## Sealed, fingerprinted, and named by their children

Every artifact directory holds a `state.json` while it is being built and a
`manifest.json` once sealed. The manifest carries the canonical fingerprint — the format tag, the coverage
and the data files' digests in a fixed order, ladders excluded — which names
what the artifact **is**, so two honest builds of the same heights agree on it
whoever made them. Where it came from is declared separately in `build`:
derivatives name the index, the index names the graph, and a consumer holding
both confirms the link, which `verify` does for them and says when it could
not.

`verify` re-reads every byte against the manifest; `stats` reports from the
manifest alone and is instant; `rewind` takes a sealed artifact back to a height
it already covered, into the bytes a build that had stopped there would have
written.

Fingerprints of a run are published where that run is described, not here: this
file describes the shapes, and shapes do not have fingerprints. `nodsig
--version` and the release tag say which code produced yours.

## Rough sizes

On the 2026 chain through height 957,301, as an order of magnitude for planning.
Yours will differ with the height and with how much of the chain you cover.

`<index>` and `<derived>` were projected here for a while and are now
**measured**: the v2 pair was 248 and 191 GB, the narrower spend side and
`u56` satoshi fields predicted 229.1 and 185.8 by arithmetic on the record
widths, and the completed v3 build measured 229.6 and 185.3. The projection
held to within half a percent, which is what fixed-width records buy.

| Artifact | Size |
|---|---|
| `<graph>/` | ~301 GB |
| `<index>/` | ~230 GB |
| `<derived>/` | ~185 GB |
| `<archive>/` | ~105 GB measured on a 3.0.x run, of which the sealed archive is ~51 GB |
| └ `<archive>/proof/` | ~54 GB of that: no query reads it, and `archive scan` refuses to grow an archive without it |
| `<nonces>/` | ~55-60 GB |
| `<firstspend>/` | ~37 GB (optional; 1.48 G locks ever spent from × 25 B) |
| `<firstreveal>/` | ~34 GB (optional; 1.70 G revealed keys × 20 B) |
| `<locks>/`, `<checkpoint>/`, CSVs | small enough not to plan for |

Add headroom on top: a fusion writes a new generation before deleting the old.
The FIRST fusion of a scan is the largest: it fuses the whole run pile, which
holds every sighting and is far larger than what it will seal (a 3.0.x run
measured 8.02 G revelations in a 145 GB pile of 5,300 runs against 2.19 G
records sealed, and took 5 h 04). `merge`
prints both numbers and refuses before the first byte if the space is not free.

## All of it is shareable

Every artifact here derives from **public chain data**. None contains an address
you looked up, and the census is aggregated by construction, so any of them can
be published or handed to someone else without leaking what you were curious
about.

The exception is not an artifact: `check` writes `check-results.txt` (and, with
`--csv` and `--json`, two more files), which list the addresses **you** asked
about. Those are yours, the default names are kept out of version control, and
they are the files in this project that should not be shared.
