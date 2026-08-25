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
| revelation archive | `reveal-archive-v2` | — |
| nonce census | `nonces-v3` | `nonces-v2` |
| nonce witness table | `nonces-witness-v1` | — |
| outpoint index | `outpoint-index-v3` | `outpoint-index-v2` |
| outpoint derivatives | `outpoint-derived-v3` | `outpoint-derived-v2` |
| first-spend table | `firstspend-v1` | — |
| first-reveal table | `firstreveal-v1` | — |
| block stats | `block-stats-v2` | — |
| price series (external input) | `price-series-v1` | — |
| block price (external input, derived) | `blockprice-v1` | — |
| address book (input) | `address-book-v2` | — |
| check report (output) | `check-report-v2` | — |

**Reading widens; emission never does.** Where a previous format is listed, an
artifact sealed under it still verifies and still answers questions, so what
you downloaded keeps its value. It cannot be **extended or rewound**: both
operations promise the bytes a rebuild would have written, and a fusion across
two layouts matches no rebuild. Each refusal says which format it met and why.

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
                          │         ├──► nonces resolve ──► <witness>/  (needs the node)
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
| reuse over time, as a series | `archive derive --curve` → `curve deltas` |
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

What that comparison covers, precisely: the two **extraction pipelines** are
written separately, and they are what it tests. Both roads then burn the same
lock files through the same lookup code, so a broken locks directory would make
them agree rather than disagree, which is why the files are verified against
the sha256 their manifest recorded at `prepare`, and why `crosscheck
--reuse-state` refuses a checkpoint made against a different locks manifest.

It is worth knowing that road exists, and the commands are here for anyone who
wants to walk it. But it costs a second full pass over the chain, and what it
buys is confidence in the *method* rather than a number you do not already have.
Treat it as a result to inherit, not a step to repeat — which is how the numbers
published with this project were produced: run once, agreed, reported.

## The artifacts

| Artifact | Format | What it is | Produced by | Read by |
|---|---|---|---|---|
| `<snapshot>` | `dumptxoutset` v2 | The UTXO set at one block: the pinned root of every count below | `bitcoin-cli dumptxoutset` | `census`, `reuse prepare` |
| `census.csv` | CSV | Totals per script type and height band. **Aggregates only**: no individual coin | `census` | a human |
| `<locks>/` | `locks-v1` | The current locks: sorted digests of unspent outputs, one file per type | `reuse prepare` | `reuse scan`, `archive crosscheck` |
| ├ `locks_{p2pkh,p2sh,p2wpkh,p2wsh}.bin` | sorted records | One lock type per file | `reuse prepare` | as above |
| └ `manifest.json` | `locks-v1` | Pins the snapshot's base hash (so a scan stops at that height) and each file's record count and sha256, which every reader checks before burning a lock | `reuse prepare` | as above |
| `<archive>/` | `reveal-archive-v2` | Every key and script ever revealed, appendable | `archive scan` | `archive merge/verify/derive/crosscheck/lookup/v1-digests`, `check` |
| ├ `runs/…_keys.bin` | records | `hash160` of public keys revealed in a scriptSig or witness | `archive scan` | as above |
| ├ `runs/…_scripts20.bin` | records | `hash160` of candidate redeem scripts | `archive scan` | as above |
| ├ `runs/…_scripts32.bin` | records | `sha256` of candidate witness scripts | `archive scan` | as above |
| └ `manifest.json` | `reveal-archive-v2` | The canonical fingerprint, written by `merge` | `archive merge` | `archive verify` |
| `curve.csv` | CSV | One row per height step: this **is** the reuse curve over time | `archive derive --curve` | `curve deltas` |
| `<headers>/` | `headers-v2` | The header chain the scan verified, from genesis: 88 B per height plus each coinbase script. Off by default, enabled with `--headers` (~150 MB) | `archive scan --headers` | `headers verify/crosscheck`, `curve dates` |
| ├ `headers.bin` | records | The 80 header bytes verbatim, then the block's size and weight | `archive scan --headers` | as above |
| ├ `coinbase.bin`, `coinbase_off.bin` | records | Each block's coinbase scriptSig, and where it starts | `archive scan --headers` | as above |
| └ `manifest.json` | `headers-v2` | Fingerprint and coverage `0..H`; no parent, it comes from the blocks | `headers fingerprint` | verification |
| `<nonces>/` | `nonces-v3` | Every signature nonce point ever published, with the height. Off by default, enabled with `--nonces` (~55-60 GB): the repeated ones are the candidates for a key recoverable from public data, which a block re-read confirms or rules out | `archive scan --nonces` | `nonces groups/lookup/verify/rewind`, `nonces address` (with the index and a node) |
| ├ `nonces_gNNNN.bin` | records | One 16-byte record per signature: point, height, scheme, and the sighash mode it committed to | `archive scan --nonces` | as above |
| └ `manifest.json` | `nonces-v3` | Fingerprint and coverage; no parent, it comes from the blocks | `nonces merge` | `nonces verify` |
| `<witness>/` | `nonces-witness-v1` | The evidence that resolves each repeated point: per (nonce point, public key), the signatures that decide whether a key follows. Optional, built after the census (~36 min over the whole chain, a few MB) | `nonces resolve` (needs the node) | `nonces witness-verify` |
| `<graph>/` | `graph-v2` | The raw transaction graph. Off by default, enabled with `--graph` | `archive scan --graph` | `graph`, `blockstats`, `index build` |
| block-stats CSV | `block-stats-v2` | Per-block series (transactions, inputs, outputs, size, time) derived from the graph | `blockstats build` | `blockstats summary`, a human |
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
| `<firstreveal>/` | `firstreveal-v1` | The first revelation of every key, ordered by that moment (23 B: `first_height` \| `key`) | `firstreveal build` | `firstreveal between` |
| └ `firstreveal_gNNNN.bin`, `manifest.json` | records / `firstreveal-v1` | One row per revealed key, a 1:1 restatement of the archive's keys partition; the parent archive is **declared** in `build` | `firstreveal build` | `firstreveal between/verify` |
| `*.lad` (inside index, derived, firstspend and firstreveal) | ladders | Search caches: one sample every few thousand keys. **Outside the fingerprint**; without them a search falls back to a blind bisection, slower and with the same answer | the builders | the readers, when present |
| `<checkpoint>/` | `reuse-scan-v1` | *Second road only.* The direct reuse scan's state: a `hits_<type>.bin` bitmap of which locks history has opened, plus `state.json` and its own `curve.csv` | `reuse scan` | itself (resume), `archive crosscheck` |

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
| `<archive>/` | ~98 GB |
| `<nonces>/` | ~60 GB |
| `<firstspend>/` | ~37 GB (optional; 1.48 G locks ever spent from × 25 B) |
| `<firstreveal>/` | ~37 GB (optional; 1.61 G revealed keys × 23 B) |
| `<locks>/`, `<checkpoint>/`, CSVs | small enough not to plan for |

Add headroom on top: a fusion writes a new generation before deleting the old.

## All of it is shareable

Every artifact here derives from **public chain data**. None contains an address
you looked up, and the census is aggregated by construction, so any of them can
be published or handed to someone else without leaking what you were curious
about.

The exception is not an artifact: `check` writes `check-results.txt`, which lists the
addresses **you** asked about. That one is yours, it is kept out of version
control, and it is the only file in this project that should not be shared.
