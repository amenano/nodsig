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

Everything above is a local lookup except `nonces address`, which fetches the
few blocks the index names, by height, from your own node.

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
```

Note what this costs beyond the new blocks. **`--graph` replaces
`--graph-digest` here**: growing the chain means writing graph records, not
checking them, and re-sealing the graph gives it a new fingerprint, which every
artifact built from it will then declare as its parent. And every derivatives
append pays **one sequential pass over `spends.bin`**, because that file is
re-ordered by every fusion and a position inside it does not survive: the cost
is proportional to the whole file, not to the new blocks.

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

The mirror of the section above, and three separate commands: run them in this
order, because the derivatives take their new watermark from the index.

```sh
nodsig index   rewind --index <index> --graph <graph> --to-height <H>
nodsig derived rewind --derived <derived> --index <index>
nodsig nonces  rewind --nonces <nonces> --to-height <H>
```

A rewind takes a sealed artifact back to a height it already covers, into the
bytes a build that had stopped there would have written. It is not an undo of
the last command; it is a different, cheaper road to the same artifact, and it
is what makes growing them a two-way street rather than a one-way one. The
reveal archive is the exception with a reason: its fusion folds many sightings
into one record, so it cannot restore what it folded, and its format says so.

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
| `nonces address` | the same question for one address of yours (**needs the node**) | 6 |
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
