# Build and query: every command, in order

The command sequence and nothing else: what to run, in which order, and what
you may skip. Why any of it exists is elsewhere ([README](../README.md) for the
reasoning, [ARTIFACTS](ARTIFACTS.md) for what each file is, `nodsig <command>
-h` for every option). This page is meant to be followed while a build runs.

Sections 0 to 6 are the sequence. The [list at the end](#every-command-in-one-list)
is the whole command surface, including what a build never runs: nothing in the
tool is missing from it.

Directory names are placeholders: every one of them is yours to choose, and
nothing here writes outside the paths you pass.

Read the three ordering rules at the end before starting a real run. They are
the only places where doing the steps in the wrong order costs a rebuild.

**How to read the blocks below.** Every line beginning with `nodsig` is one
command, run on its own and waited for: a block of several lines is a sequence,
never one invocation. There is exactly **one** command that does several things
at once, and it is the long one, step 2: the chain is read once and each
co-emission flag feeds a different artifact out of that single pass. That is
the whole point of it, and it is why those flags are worth passing even for
artifacts you did not come for.

## 0. The snapshot (your node writes it)

```sh
bitcoin-cli dumptxoutset /path/snapshot.dat        # note the height it reports
```

Required for anything about the **current** UTXO set (the census, the reuse
figures). Not needed if you only want history: the chain scan does not read it.

## 1. From the snapshot, offline

| | command | what it gives |
|---|---|---|
| optional | `nodsig census /path/snapshot.dat --csv census.csv` | totals per lock type and age band, aggregates only |
| needed for reuse | `nodsig reuse prepare --out <locks> /path/snapshot.dat` | the sorted lock files every reuse number is counted against |

`prepare` writes a manifest pinning the snapshot's base block, plus each file's
record count and sha256: every later reader checks those before burning a lock,
so a truncated or moved locks file is refused instead of silently scanned
against.

## 2. One pass over block history

The only long step that talks to the node. Everything else is offline. The
co-emission flags cost this pass almost nothing extra and are the only chance
to produce what they produce: a later pass cannot reconstruct them.

One command, and the only one on this page that is: everything in brackets is
an optional flag of *this* invocation, not a separate step.

```sh
nodsig archive scan --rpc <url> --cookie-file <path/.cookie> \
                    --end <H> --archive <archive> \
                    [--rest --prefetch-depth 4] \
                    [--graph <graph>] [--headers <headers>] [--nonces <nonces>]
```

| flag | cost | without it |
|---|---|---|
| (none) | ~87 GB | you still get the revelation archive: the exposure question |
| `--graph` | 300-400 GB | no index, no derivatives, no block statistics: they are all built from it |
| `--headers` | ~150 MB | dates need the node, and the scan's integrity checks cannot be repeated offline |
| `--nonces` | ~55 GB, ~10% CPU | the nonce census does not exist and no later pass can rebuild it |
| `--rest` | none, saves ~half the bytes on the wire | JSON-RPC instead: correct, slower, needs a credential |

`--graph-digest <graph>` replaces `--graph` when you already have one: it
serializes the same records, hashes them, writes nothing, and so checks that
this code still emits the graph it is not rewriting.

Resumable: rerun the same command after an interruption and it continues from
its last checkpoint.

### Running it unattended, and what an interruption costs

A pass over the whole chain is not something most people can watch. Three
things make the difference between a run you can leave and one you have to
babysit, and none of them is obvious from the command line.

**Write a durable log, and make the tool unbuffered.** `python3 -u` (or
`PYTHONUNBUFFERED=1`) matters more than it looks: without it the progress
lines sit in a buffer, and an interruption takes them with it — you are left
knowing that it stopped and not where. Put the log outside the artifact
directory, so a `rewind` or a failed build never takes your record of what
happened with it.

**Know what an interruption costs, because you choose it.** Work becomes
durable at each checkpoint, so a kill loses at most the stretch since the last
one. The default is every 10,000 blocks, which early in the chain is minutes
and late in the chain can be hours: blocks get heavier, so the same block
count is a longer wall-clock bet. `--checkpoint-every` moves that trade-off,
and it is a trade-off rather than a free win — a checkpoint flushes the open
buffers into run files, and those runs are merged later by a phase that is
itself expensive. Lower it when the loss you are risking is worth more than
the extra merge, which is usually deep into the chain rather than at the
start.

**Read the cost from the artifact, not from your log.** Every manifest carries
`build.seconds`, keyed by verb, and it accumulates across resumes because the
running total lives in the state that survives a kill — so a run split over
five sessions still reports what it really cost. Your log is the second road,
useful for confronting that figure rather than replacing it. One caution when
you add them up: a scan co-emits, so the archive, the graph, the header
archive and the nonce census each record **the same** seconds under `scan`.
Those four are one pass seen four times. Take it once, then add the phases
that really did run one after another.

## 3. Seal what the pass produced

Five separate commands, one per artifact the pass wrote: run the ones whose
flags you passed. Each turns a directory into a citable artifact by writing its
manifest and printing its fingerprint.

```sh
nodsig archive merge  --archive <archive>
nodsig archive derive --archive <archive> --locks <locks> --curve curve.csv
nodsig headers fingerprint --headers <headers>          # if --headers
nodsig nonces  merge                --nonces <nonces>   # if --nonces
nodsig graph   fingerprint --graph <graph>              # if --graph
```

`archive derive` is the reuse table and its curve, read out of the archive
without a second pass over the chain. Either side of `merge` gives the same
answer; after it is cheaper, because the fused base holds each digest once
instead of once per sighting.

Optional, from the merged archive — the keys partition restated in time
order, so "which keys were first revealed in this height window" becomes a
contiguous read:

```sh
nodsig firstreveal build --archive <archive> --out <firstreveal>
```

The archive's own curve is a separate verb, because it needs no locks and so no
snapshot and no node:

```sh
nodsig archive curve --archive <archive> --out revelations.csv --every 10000
```

One row per window of heights, counting the digests whose **first** revelation
falls in it. `nodsig curve dates --curve <either curve> --headers <headers>`
puts calendar dates on either file, offline.

## 4. The indexed side, offline from here on

Two commands, in this order: the second reads what the first sealed.

```sh
nodsig index   build --graph <graph> --index <index> --end <H>
nodsig derived build --index <index> --out <derived>
```

`index build` needs a **sealed** graph to record a parent (rule 2). The
derivatives reorder the same facts by lock, by transaction and by co-spend;
both steps are resumable and seal themselves.

Optional, from the graph:

```sh
nodsig blockstats build <graph> --out block-stats.csv
```

## 4b. Resolve the repeated nonce points (optional, needs the node)

```sh
nodsig nonces resolve --nonces <nonces> --witness <witness> \
                      --rpc <url> [--rest] [--cookie-file <path/.cookie>]
```

Its own step rather than one of the seals in 3, because it is the only
offline-side command that talks to the node again. `nonces groups` can say
which points repeat and never what a repeat means, because the meaning lives
in `s` and a 16-byte census record does not hold it. This re-reads only the
blocks those points name, and keeps, per (nonce point, public key) pair, the
signatures that settle it.

Cost is proportional to the repeated points and not to the chain: over
957,301 blocks that was **4,494 blocks re-read in about 36 minutes**, and a
table of a few thousand rows. It declares the census it resolved as its
parent, so a table beside a different census is answering about something
else, and `witness-verify --nonces` is what confirms that.

## 5. Check what you built

One command per artifact, in any order, none of which changes a byte. Cheap,
and worth running once on anything you intend to publish or keep.

```sh
nodsig archive verify --archive <archive> [--deep]
nodsig nonces  verify --nonces  <nonces>  [--deep]
nodsig index   verify --index   <index>   [--graph <graph>]
nodsig derived verify --derived <derived> [--index <index>]
nodsig headers verify --headers <headers>
nodsig nonces  witness-verify --witness <witness> [--nonces <nonces>] [--csv OUT]
nodsig firstspend  verify --firstspend  <firstspend>  [--derived <derived>]
nodsig firstreveal verify --firstreveal <firstreveal> [--archive <archive>]
```

Without `--deep` an audit re-reads every byte against the manifest and rebuilds
every search ladder from the file it indexes; with it, it also reads every
record and holds the declared coverage to what those records prove. Passing the
parent (`--graph`, `--index`) makes the audit confirm the declared ancestry
instead of taking it on trust.

Two confrontations that verify cannot make on its own:

```sh
nodsig headers crosscheck --headers <headers> --index <index>
nodsig archive v1-digests --archive <archive>
```

The first recomputes every block's Merkle root from the index's txids and
confronts it with the header: the strongest cheap statement about the pair, and
its reference is the chain itself. The second projects the archive back to the
published v1 layout and prints one sha256 per category, which is how a new
build is confronted with a historical one.

Once they pass, one page describes the lot:

```sh
nodsig report --graph <graph> --headers <headers> --archive <archive> \
              --nonces <nonces> --index <index> --derived <derived>
```

Markdown on stdout, read out of the manifests: what each artifact is and covers,
its fingerprint, what each step cost in wall time, which artifact each one
descends from and whether the artifacts in hand confirm it, and the machine that
did the work. It names no directory and asks the host for nothing that
identifies it, so the page can be published as it comes out. What only a person
knows (the device the artifacts sit on, where the node runs, over which
transport) comes out as blank lines to fill in, because those decide the
durations more than the code does.

## 6. Ask the questions

```sh
nodsig check --archive <archive> --index <index> --derived <derived> \
             --stdout <address> [<address> …]

nodsig derived history  --derived <derived> --index <index> --lock <hash160>
nodsig derived fee      --derived <derived> --index <index> <txid>
nodsig derived cospends --derived <derived> --index <index> <txid>:<vout>
nodsig derived supply   --derived <derived> --index <index> [--csv series.csv]
nodsig derived timeline --derived <derived> --index <index> --out <dir> \
                        [--grid N] [--price <blockprice>]
nodsig archive lookup   --archive <archive> <digest>
nodsig nonces  groups   --nonces  <nonces>
nodsig nonces  address  --index <index> --derived <derived> --nonces <nonces> \
                        --rpc <url> <address>            # needs the node
nodsig curve   deltas   curve.csv
nodsig curve   dates    --curve curve.csv --headers <headers>
nodsig blockstats summary block-stats.csv
```

`derived history` takes the lock, not the address: `--lock <hash160 of the
scriptPubKey>` or `--spk <raw scriptPubKey>`. `nodsig check` is the one command
that decodes addresses for you.

`derived supply` is the one command above that reads whole files: one
sequential pass over `fees.bin` plus one small read per block of the index's
`outputs.bin`, so it takes minutes on a local disk and up to an hour on a slow
mount. It confronts three things nothing else confronts: the coinbase values
the index holds, the fees the derivatives hold, and the subsidy schedule. A
coinbase above its allowance is an error exit; one below it is counted as
unclaimed and reported. `--csv` writes the per-block series (height, time,
transactions, coinbase, fees, subsidy, outputs, and the coinbase's outputs,
first spender and value spent) for whatever comes next. The rule for a
column there: what the index's block table and the block's one coinbase
transaction give with positional reads, plus the fee; never a scan of the
block's transactions, which is `blockstats`' job. Transactions and outputs
per block are therefore printed by both commands from two different
artifacts, and must agree. The coinbase's first spender is the first spend
of an *output*; FirstSpend records the first spend of a *lock*. With
`--price <blockprice>` (section 6b; requires a price series) it adds the fees
in the series' currency, computed block by block and summed per epoch, with
the blocks that had no price counted apart and the digests it rests on
printed under the table.

`derived timeline` is the statistical scan `history.bin` was laid out for:
ONE sequential pass over every row — at the full chain's 141 GB that is
hours, not minutes, and the summary prints its own rate — folding the file
along its two axes into two small CSVs under `--out`, aggregates only.
`timeline_bands.csv` holds, per checkpoint (every `--grid` heights, default
10,000, plus the tip) and per balance decade, how many locks held a balance
in that decade and their satoshis. `timeline_windows.csv` holds, per
(creation window, spend window | unspent) cell, the output count, the
satoshis, and the two weights Σ value·create_height and Σ value·spend_height
(unit: sat·heights) — the primitives every age reading is a formula over:
coin-age destroyed in a cell is their difference; the value-weighted mean
age of the unspent at a height H is (H · sats − Σ value·create_height) /
sats, exact. The pass re-meets the manifest's identities before writing
(row count, spent satoshis, distinct locks) and the two tables must agree
on the unspent satoshis at the tip, so a defect fails the run instead of
shipping a plausible CSV. The meta beside the CSVs declares the parent
derivatives fingerprint and, with `--price <blockprice>` (section 6b), the
price table's digest; the price adds two columns per cell — the satoshis
that had a price at creation, and Σ value·price(create_height), the
at-creation cost basis of the coins that ended in that cell. A lock is an
identical scriptPubKey, not a wallet and not a person; the bands say
nothing about who holds what, only how balances distribute.

Two other artifacts meet this one, and each meeting is stated rather than
left for a confused evening. The windows' creation totals are the value
`blockstats` counts per block, re-added at window width: two roads from two
artifacts (the graph, the derivatives), **expected to agree exactly** — a
disagreement means one of the two is broken. The unspent side meets the
**UTXO census** from your node's `dumptxoutset`, and there the two do NOT
match, by design: `history.bin` holds one row per output ever created, so
its unspent side also carries what the node no longer tracks — the two
BIP30-overwritten coinbases (2 outputs, 100 BTC exactly) and provably
unspendable outputs, which never enter the UTXO set. At height 957,301
that reconciliation is 235,248,867 outputs and about 151 BTC. The census
can only ever hold **less** than the timeline's unspent; a range where it
holds more means a broken artifact. The timeline's checkpoints are the
reuse curve's — one row every 10,000 blocks, the same grid — so the two
CSVs join directly by height.

Everything above is a local lookup except `nonces address`, which fetches the
few blocks the index names, by height, from your own node.

## 6b. A price per block (optional, requires a price series)

Nothing above needs a price, and nothing on the chain holds one. If you
want fiat figures, you bring a series a publisher made available, convert
it into the one shape every consumer here reads, and derive one price per
block from it. The series is an **external input**, identified by a
digest and never by a fingerprint; what that means for what you can and
cannot reproduce is in [`external-inputs.md`](external-inputs.md).

```sh
nodsig price import --from btc.csv --out <series> --preset coinmetrics \
                    --fetched-at 2026-08-21            # any CSV/JSON: see -h
nodsig price series-verify --series <series>
nodsig price build  --index <index> --out <blockprice> --series <series>
nodsig price verify --blockprice <blockprice> --index <index> --series <series>
nodsig price at     --blockprice <blockprice> 840000
nodsig price daily  --blockprice <blockprice> --index <index> [--csv daily.csv]
```

`derived supply --price <blockprice>` is the first consumer: the fees of
each epoch in the series' currency, block by block. `derived timeline
--price <blockprice>` is the second: the at-creation cost basis per
(creation, spend) window, one integer multiply per row.

`price build` reads the index's block table and the series, and takes
seconds; `--series` repeats, finest first, and the table records which
one answered at each height. It is rebuilt whole, and a rebuild compares
itself with the file it replaces: a publisher that corrected its past
shows up as a count of changed heights in `blockprice.json`, never as a
silent change. `price daily` is an aggregation of the block prices, one
weight per block, each row carrying its kind (`measured`, `carried`,
`none`); it is not an exchange close and does not try to be.

The toolkit fetches nothing: the node is its only network peer. You
obtain the publisher's file under its terms, and the digest then names
exactly what you used.

## The second road (optional, and a full extra pass)

```sh
nodsig reuse scan --locks <locks> --rpc <url> --end <H> --checkpoint <cp>
nodsig archive crosscheck --archive <archive> --locks <locks> \
                          --reuse-state <cp>/state.json
nodsig reuse stats --locks <locks> --checkpoint <cp>
```

A second, separately written pipeline reaching the same reuse figure, which the
cross-check then compares bit for bit. It buys confidence in the *method*, not
a number you do not already have: a result to inherit rather than a step to
repeat. Scan and cross-check must use the **same perimeter** (rule 3).

## Growing them, when the chain moves

> **First, if the artifacts predate this version.** Growing and rewinding both
> promise the bytes a rebuild would have written, so neither works across a
> format change: an `outpoint-index-v2`, an `outpoint-derived-v2` or a
> `nonces-v2` **cannot be extended or rewound** by 1.2.0, and the builders
> refuse by name rather than producing something no rebuild matches. They are
> still read, verified and queried — see the table in
> [ARTIFACTS](ARTIFACTS.md#what-this-version-emits-and-what-it-still-reads).
> Growing past one means building the new artifact from its parent, and for the
> nonce census that means a fresh scan, because the census is co-emitted by the
> pass that writes the archive.

There is **no append command**. You re-run the same builders with a higher
`--end`, and each one reads its own `state.json` to see that it already covers
part of the range: new blocks extend the append-only files and add runs, and
the fusions merge old with new. Because merging sorted sources is associative,
the result is contractual and not merely intended: **appending equals
rebuilding**, byte for byte and therefore fingerprint for fingerprint, against
a build that had started from zero and stopped at the same height.

The order is forced by ancestry, because each artifact can only grow after its
parent has:

```sh
# 1. the graph first: it is the root, and only a scan can extend it
nodsig archive scan --rpc <url> --end <H2> --archive <archive> \
                    --graph <graph> --headers <headers> --nonces <nonces>
nodsig graph   fingerprint --graph <graph>       # re-seal: new bytes, new fingerprint
nodsig archive merge  --archive <archive>
nodsig nonces  merge  --nonces  <nonces>
nodsig headers fingerprint --headers <headers>

# 2. then the offline side, in the same order as a first build
nodsig index   build --graph <graph> --index <index> --end <H2>
nodsig derived build --index <index> --out <derived>

# 3. the tables that follow a parent, by re-running the same build:
#    each re-emits its rows against the grown parent and the fusion
#    collapses what was already there (a re-run against an unchanged
#    seal says "nothing to do" and costs nothing)
nodsig firstspend  build --derived <derived> --out <firstspend>
nodsig firstreveal build --archive <archive> --out <firstreveal>
```

Note what this costs beyond the new blocks. **`--graph` replaces
`--graph-digest` here**: growing the chain means writing graph records, not
checking them, and re-sealing the graph gives it a new fingerprint, which every
artifact built from it will then declare as its parent. And every derivatives
append pays **one sequential pass over `spender_of.bin`**, because a new block
can spend an output written years earlier and so change a record below wherever
the previous run stopped: the cost is proportional to the whole file, not to the
new blocks.

### What decides that it is an append

`state.json`, not the manifest. The two files have different jobs, the same
split the manifest itself makes: the state is **how** the artifact was built
(the phase, the watermark, the runs not yet fused, the committed byte counts)
and the manifest is **what** it holds (the canonical fingerprint, for readers
and for `verify`). A builder loads its state if there is one and continues from
its watermark; resuming after a crash and appending after the source grew are
therefore *the same code path*, not two.

Two consequences worth knowing before they surprise you:

- **Re-running a builder that has nothing to do is a no-op**, not a rebuild.
  A sealed index puts itself back into its scanning phase, finds the graph has
  not grown, and stops: the sealed files stand, untouched. The derivatives read
  the index's append-only cursors and answer the same way. So there is no harm
  in running the sequence again to find out where you are, and `stats` answers
  that instantly anyway.
- **An artifact you received cannot be grown.** A directory holding the files
  and the manifest but no `state.json` is what a copy looks like, and a builder
  does not read it as work in progress: it starts a build of its own, which
  means truncating the positional files to the zero bytes its fresh state
  commits and sweeping the merged generations that state does not name. It
  says so line by line rather than corrupting anything, and the rule behind it
  (what the state does not name does not exist) is the same one that makes the
  crash windows safe, but the effect is that the copy is gone. Received
  artifacts are for reading and verifying; to extend the chain you need the
  builder's own state, or a build of your own.

Honest boundary, stated here because it is the kind of thing a reader should
not have to discover: at chain scale this path is covered by tests and by the
argument above, not yet by a run. See *Running it at chain scale* in the
[README](../README.md#running-it-at-chain-scale) for exactly what has been
exercised on real artifacts and what has not.

## Rewinding instead of rebuilding

The mirror of the section above, and four separate commands: run them in this
order, because each follower takes its new watermark from its parent.

```sh
nodsig index      rewind --index <index> --graph <graph> --to-height <H>
nodsig derived    rewind --derived <derived> --index <index>
nodsig firstspend rewind --firstspend <firstspend> --derived <derived>
nodsig nonces     rewind --nonces <nonces> --to-height <H>
```

A rewind takes a sealed artifact back to a height it already covers, into the
bytes a build that had stopped there would have written — which is why it is
refused on an artifact sealed under an older format, exactly like growing one. It is not an undo of
the last command; it is a different, cheaper road to the same artifact, and it
is what makes growing them a two-way street rather than a one-way one. The
reveal archive is the exception with a reason: its fusion folds many sightings
into one record, so it cannot restore what it folded, and its format says so.
The first-reveal table follows that exception rather than escaping it — its
parent cannot go back, so it has no rewind verb — while the first-spend table
follows its derivatives down, the cleanest rewind here (rows are dropped,
never rewritten).

## Every command, in one list

Everything the tool exposes, grouped by the artifact it belongs to, with the
step above where it appears. The ones marked **-** are not part of any build:
they read, time or explain something you already have.

| Command | What it does | Step |
|---|---|---|
| `census <snapshot>` | the UTXO set by lock type and age band | 1 |
| `reuse prepare` | the snapshot distilled into sorted lock files | 1 |
| `reuse scan` | the second road: burn locks while walking the chain | second road |
| `reuse stats` | value distribution across exposed locks (median, Gini, bands) from a scan checkpoint | second road |
| `archive scan` | the one pass: revelations, and whatever the co-emission flags ask for | 2 |
| `archive merge` | fuse the runs, seal, fingerprint | 3 |
| `archive derive` | the reuse table and its curve, read out of the archive | 3 |
| `archive curve` | first revelations per window of heights: the archive alone, no locks | 3 |
| `archive verify` | re-read a sealed archive against its manifest; `--deep` reads every record | 5 |
| `archive crosscheck` | the two roads compared bit for bit | second road |
| `archive v1-digests` | the fused base projected back to the published v1 layout | 5 |
| `archive lookup` | was this digest ever revealed, where, and when first | 6 |
| `graph fingerprint` | seal the graph (and audit every byte doing it) | 3 |
| `graph digest` | read back the result of a `--graph-digest` check | - |
| `graph stats` | watermark and totals, instant | - |
| `graph show` | decode a height range, human-readable | - |
| `headers fingerprint` | seal the header archive | 3 |
| `headers verify` | re-read it against its manifest | 5 |
| `headers crosscheck` | every Merkle root recomputed from the index's txids | 5 |
| `headers stats` | watermark and totals, instant | - |
| `headers show` | decode a height range, human-readable | - |
| `nonces merge` | fuse the runs, seal, fingerprint | 3 |
| `nonces verify` | re-read it against its manifest; `--deep` reads every record | 5 |
| `nonces rewind` | back to a height already covered | rewind |
| `nonces groups` | the nonce points published more than once, and what the census can say about them | 6 |
| `nonces resolve` | re-read the blocks those points name and keep the evidence that decides them (**needs the node**) | 4b |
| `nonces witness-verify` | audit that evidence, re-derive its resolutions, `--csv` to export them | 5 |
| `nonces lookup` | was this nonce point published? | - |
| `nonces address` | the same question for one of your addresses (**needs the node**) | 6 |
| `nonces bench` | time the extraction over real blocks | - |
| `index build` | number the chain once, spends resolved | 4 |
| `index rewind` | back to a height already covered | rewind |
| `index verify` | re-read it against its manifest, and confirm its parent | 5 |
| `index stats` | phase, watermark and counts, instant | - |
| `index lookup` | one outpoint's whole story: created when, worth what, spent by whom | - |
| `derived build` | the same facts reordered by lock, transaction and co-spend | 4 |
| `derived rewind` | back to a height already covered | rewind |
| `derived verify` | re-read it against its manifest, and confirm its parent | 5 |
| `derived stats` | phase and counts, instant | - |
| `derived history` | a lock's events in order, each with height and date | 6 |
| `derived fee` | what a transaction paid | 6 |
| `derived cospends` | what was spent together with an outpoint | 6 |
| `derived supply` | coinbase <= subsidy + fees checked on every block; fees, subsidy and coinbase per epoch; `--price` adds them in a currency | 6 |
| `derived timeline` | one pass over history.bin: balance bands per checkpoint, and outputs/sats/age weights per (creation, spend) window; `--price` adds the at-creation cost | 6 |
| `firstspend build` | when each lock was first spent from, ordered by time | 4 |
| `firstspend rewind` | back to a height already covered | rewind |
| `firstspend verify` | re-read it against its manifest, and confirm its parent | 5 |
| `firstspend stats` | coverage, row count and fingerprint, instant | - |
| `firstspend between` | which locks were first spent in a height window | 6 |
| `firstreveal build` | when each key was first revealed, ordered by time | 3 |
| `firstreveal verify` | re-read it against its manifest, and confirm its parent | 5 |
| `firstreveal stats` | coverage, row count and fingerprint, instant | - |
| `firstreveal between` | which keys were first revealed in a height window | 6 |
| `price import` | a publisher's CSV or JSON into a sealed price series (**external input**) | 6b |
| `price series-verify` | a series against its `series.json` | 6b |
| `price build` | one price per block, from the index's header times and the series in order | 6b |
| `price verify` | the table against its metadata; with the parents, recomputed byte for byte | 6b |
| `price stats` | rule, parents, what the last rebuild changed, instant | - |
| `price at` | the price of one block, and which series gave it | 6b |
| `price daily` | the per-day aggregation, dense, each value with its kind | 6b |
| `blockstats build` | per-block series out of the graph | 4 |
| `blockstats summary` | the same series read per epoch | 6 |
| `curve deltas` | how reuse grew, interval by interval | 6 |
| `curve dates` | heights turned into real dates (from the headers, or the node) | 6 |
| `check` | the assembled per-address answer, from whichever backends you plug in | 6 |
| `report` | one page over the artifacts you name: identity, cost, ancestry, machine | - |

`index lookup` is the one to try first on a fresh index: it is the didactic
window on the whole design, and it needs no other artifact.

## The three ordering rules

There used to be a fourth, "derive the curve before merging the archive",
because the curve was sampled at the boundaries of the scan's runs and the
merge fuses those runs away. It is gone, and not by relaxing anything: both
curves are now built from the `first_height` each record carries, which the
fusion keeps (it reduces duplicates to the earliest). Nothing is spent, so
nothing has to come first, and the rows land on the grid you ask for instead
of on the boundaries your download batch size happened to produce.

1. **Fingerprint the graph before building the index.** An index built on an
   unsealed graph records no parent and cannot attest its ancestry; it says so
   and keeps working, but the only fix is to seal and build again.
2. **Scan and derive with the same perimeter.** `--no-faces` and
   `--no-cosigners` change what counts as a revelation, so a bitmap made under
   one reading and a table made under another describe different questions. The
   comparison refuses rather than averaging them.
3. **Merge before reading.** `nonces groups`, `nonces lookup` and
   `archive lookup` do consult unfused runs, so they answer correctly either
   way, but only a merged artifact has a fingerprint, and `archive v1-digests`
   is defined on the fused base alone.
