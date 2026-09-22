# NodSig

> **`nod·sig`**: **nod** = your node (a vertex of the graph) · **sig** =
> `OP_CHECKSIG`, the operation that forces the public key to appear on-chain.

NodSig answers questions about the Bitcoin blockchain out of your own node. It
builds local artifacts once, and from then on every question is a lookup in a
file: no block explorer, no third-party index, no network. Each answer names
the artifact it came from, the height that artifact covers, and a fingerprint
anyone else can recompute from the same chain. The artifacts are files: hand
them to someone else and they check them by recomputing that fingerprint.

How much you build depends on the question. A Taproot address is answered
from its encoding alone, with nothing on disk; "has this key already appeared
on the chain?" needs one artifact, 54 GB to keep once built (41 GB of it, the
key partition, answers single-key addresses) and more while it is being
built, since the scan writes ~145 GB of runs and the fusion needs room beside
them; dated histories, fees and co-spends need the index and its derivatives,
another 415 GB. Building every artifact there is costs about 130 hours and
960 GB at today's height, measured rather than projected, and
[`docs/building.md`](docs/building.md) says step by step which part of that
each question needs. Nothing has to be installed or built to see how it
behaves: the first commands under *Try it* run from a clone, with no node.

## What you can ask it

Seven questions. Each is answered from a file you built, each answer carries
the height that file holds to, and where the file is missing the answer is an
explicit UNDETERMINED that names the flag which would enable it:

1. **Has this address's public key already appeared on the chain?** `check`,
   against the archive of revelations; with the index built too, `derived
   history` dates the spend that put it there.
2. **Has one of your signatures ever reused its nonce point?** `nonces
   address` for one address, `nonces groups` for the whole chain, from the
   census the scan emits beside the archive.
3. **What is this outpoint's whole story?** Created when, worth what, under
   which [lock](docs/GLOSSARY.md#lock), spent by whom: `index lookup` and
   `derived history`.
4. **What did this transaction pay in fees, and what was spent together with
   what?** `derived fee` and `derived cospends`, over your own files.
5. **How much of the UTXO set sits behind keys that are already revealed?**
   `census` counts it by lock type and by age; `archive derive` names the
   locks and dates the revelations, from the archive and the snapshot.
6. **How much of today's coin sits behind a key that was already public by a
   given block?** `derived timeline`, as a series over the current UTXO set,
   block by block and on calendar dates.
7. **What was all that worth, in a currency?** `price`, only if you bring a
   price series: nothing on the chain holds one, and the toolkit never fetches
   one.

Each question is taken up at more length under *The questions, one at a
time*, after the part you can run.

The output is text and CSV. Here is what the chain looks like when
[`tools/plot_ledger.py`](tools/plot_ledger.py) draws two of those CSVs, at
height 957,301:

![All coins in circulation, type by type: bar length is the value held by that
type, the filled part the value with its key in view (hatched = exposed by
construction)](docs/figures/ledger-map.svg)

More examples of what the commands actually print, and what the numbers look
like once drawn, are in [`docs/gallery.md`](docs/gallery.md).

## Try it before building anything

Nothing has to be installed. From a clone, the package runs where it lies,
once `src` is on the import path:

```sh
git clone https://github.com/amenano/nodsig.git
cd nodsig
export PYTHONPATH=src                   # the package lives in src/
python3 -m nodsig --version
python3 -m nodsig                       # the map of commands
```

That `export` is the whole of it: the code is laid out with the package under
`src/`, which keeps a stray directory from shadowing it, and a clone therefore
has to say where it is. Everything below that writes `python3 -m nodsig …`
assumes it, for the rest of the shell session.

If you would rather have `nodsig` on your PATH, install it from the clone with
`pip install .`, or skip the clone entirely and let pip build it from the
repository:

```sh
pip install "git+https://github.com/amenano/nodsig.git@<tag>"
```

with any release tag from the [CHANGELOG](CHANGELOG.md); without `@<tag>` pip
installs the current tip of `main`. Installed or run from the clone, it is the
same program. This README writes `nodsig …`; substitute `python3 -m nodsig …`
if you did not install. Reading the code while it runs is a supported way to
use this repository, which is why `python3 -m nodsig.<module>` also runs a
single tool directly, under the same `PYTHONPATH`.

Now run the tool with nothing built and no node, on any address you do not mind
typing:

```console
$ nodsig check --stdout 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
# exposure: not configured (pluggable: reveal-archive-v4 (--archive))
# balance: not configured (pluggable: bitcoin-core-rpc scantxoutset (--rpc))
# history: not configured (pluggable: outpoint-index derivatives (--index + --derived))
# co-inputs: not configured (pluggable: outpoint-index derivatives (--index + --derived))
# linkage: not configured (pluggable: outpoint-index derivatives (--index + --derived))
# nonce-exposure: not configured (pluggable: nonces-witness-v2 (--witness))

overview (each line counts only what the capability naming it actually checked):
- input: 1 address(es) checked of 1 given (1 p2pkh)
- not answered: exposure, balance, history, co-inputs, nonce-exposure — the source lines above name what would plug each one in. Not answered is not a negative

links: the co-spend search did not run, and no two of these addresses are the same key

1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    p2pkh: UNDETERMINED
    no exposure backend configured (--archive)

caveats (the perimeter of every answer above):
- off-chain exposure is invisible here: an xpub shared with a service
  exposes descendant keys without any on-chain trace;
- a P2SH/P2WSH address hides its script until it spends: "protected"
  speaks of the hash, not of who could spend behind it;
- perimeter is CONFIRMED blocks up to the stated heights: a spend
  sitting in the mempool has already revealed its keys.
```

This is worth running before anything else precisely because it has nothing to
work with. The address is decoded locally, what the encoding alone settles is
settled, everything that needs an artifact you have not built comes back
`UNDETERMINED` with the name of the flag that would enable it, and the
perimeter of what any answer can mean is printed whether you asked for it or
not. Which is the behaviour you want to see from a tool before trusting it with
a question that matters.

What the same command prints with the archive plugged in, three real
addresses all of them exposed and one of them since height 1, is the run in
[`docs/exposure-check.md`](docs/exposure-check.md).

The next size up from trying is an afternoon:
[`docs/quickstart.md`](docs/quickstart.md) walks two small exercises with your
own node, a census of today's UTXO set and a complete build of the first
200,000 blocks, every mechanism of the full build included, at a small
fraction of its cost.

Without `--stdout` the same command writes `check-results.txt` instead, and says so:
that file lists the addresses you asked about, so it is treated as sensitive,
created readable by its owner alone, and kept out of version control.

Two things about that example are worth knowing before you use it on an address
you care about. An address typed on the command line sits in `argv`, readable by
every other account on the machine while the run lasts, and in your shell
history afterwards: `--file <path>` takes one address per line and avoids both.
And `--rpc`, which is what enables the balance, asks your node with the
addresses in the call, so the node learns the list. Neither matters on a machine
and a node that are yours alone, which is the case this tool is written for, and
both are in [`docs/exposure-check.md`](docs/exposure-check.md) for the cases
that are not.

## Why it exists

Most questions about the chain get answered out of somebody else's index. That
is usually the right trade: it is fast, it is free, and for most purposes the
answer is fine. What you give up is narrow but specific. The number is as good
as the service behind it, you cannot re-derive it yourself, and you had to say
what you were curious about in order to ask.

NodSig replaces trust with repetition. The artifacts are a deterministic
function of the chain: rebuild them from the same blocks up to the same height
and you get the same bytes, so two strangers compare a fingerprint instead of
comparing trust. That property is what makes an answer worth citing, and it is
also what makes it private, because nothing left the machine to obtain it.

A second goal shapes the code as much as that one: get there with the least
work and the least hardware the question actually needs. Chain-scale analysis
is usually the business of people with a cluster. It does not have to be.

If you already run a node, the reasonable objection is that the artifacts cost
about what the blocks cost, so why pay for the disk twice.
[`docs/why-artifacts.md`](docs/why-artifacts.md) answers that one directly: what
a node can and cannot be asked, how little you actually have to keep, and when
none of this is worth building.

And the sentence above has a limit worth reading before citing a number: a
fingerprint says *which* bytes, and that they are what the chain contains is
established by rebuilding them or by an independent builder who did.
[`docs/trust-model.md`](docs/trust-model.md) draws that line artifact by
artifact: what is bound to the chain, by what, and what can be re-checked from
the files that are kept.

## The questions, one at a time

The same seven, with what the answer contains and where its edges are.

- **Has this address's public key already appeared on the chain?** Spending
  reveals a public key, so a [lock](docs/GLOSSARY.md#lock) that has been spent from is in a different
  position from one that never has. Services answer this question too; the
  point here is answering it without asking anyone, because a question about
  your own coins is a question you would rather not send to a stranger.

  You get more than yes or no: the address's **type**, **where the key was
  seen** (directly in a scriptSig, in a witness, or *inside someone else's
  revealed script*), and **when**, since `derived history` prints that lock's
  events in order, each with its height and the block's timestamp, so the spend
  that put the key on the chain is dated and not merely known.

  One case stays undated, and it is worth knowing which: when the revealing
  transaction was not yours. A key exposed as a cosigner inside someone else's
  script, or under another face of the same key, became public through an event
  that is not in your lock's history. Exposure still reports it, which is the
  point of keeping an archive of revelations rather than only a history of
  locks, and the archive dates it (every record carries the height of its
  first revelation); what is missing is a row in your lock's own history.

- **Has one of your signatures ever reused its nonce point?** Signing two
  different messages with the same nonce hands the private key to anyone who
  noticed, which is why the census records every signature's nonce point,
  ECDSA and schnorr alike. `nonces address` asks the question about one of
  your addresses, from your own node, at the level of the KEY: the three
  locks the address's digest stands behind are read together, so a nonce
  repeated between two of them is reported as the key's, and `--key` takes
  the key itself. `nonces groups` asks it of the whole chain at once. The census is careful about what a repetition means: a
  repeated point is not yet a reused nonce (the same signature copied twice
  shares the point and exposes nothing), and where the evidence cannot
  settle the difference, the output says undecided instead of guessing.
  [`docs/nonce-check.md`](docs/nonce-check.md) is the walkthrough.

- **What is this outpoint's whole story?** Created when, worth what, under
  which lock, spent by whom.

- **What did this transaction pay in fees, and what was spent together with
  what?** Local lookups over your own files, with no index provider in the
  middle.

- **How much of the UTXO set sits behind keys that are already revealed?**
  Counted by lock type and by age, from the set itself, rather than estimated.

- **How much of today's coin sits behind a key that was already public by a
  given block?** As a series over the current UTXO set, block by block, and
  on real calendar dates.

- **What was all that worth, in a currency?** Only if you bring a price
  series: nothing on the chain holds a price, so the toolkit never fetches
  one. `nodsig price` converts a publisher's file into one canonical shape,
  identified by a digest, and derives **one price per block** from it (the
  header time is the only clock the chain certifies, to within hours). It is
  the one family of figures here that a stranger cannot reproduce from the
  chain alone, and it says so beside every number: see
  [`docs/external-inputs.md`](docs/external-inputs.md). What it yields on
  the real chain is in [the gallery's price
  section](docs/gallery.md#what-it-was-worth-block-by-block-requires-a-price-series):
  the same fees, per epoch, in BTC and in USD, and the two shapes disagree.

Answering one address is a small enough job that it deserves its own page:
[`docs/exposure-check.md`](docs/exposure-check.md) walks the exposure question
end to end, including how little you actually have to keep on disk and how to
run it on a machine that talks to nobody.

## How it works

Five ideas, each of which shows up everywhere in the code.

- **Determinism.** Every artifact is a deterministic function of the chain and
  of the height you stopped at. Same heights, same bytes, same fingerprint, on
  any machine. Every builder ends by sealing its output and printing that
  fingerprint; `verify` re-reads every byte against it; `rewind` takes a sealed
  artifact back to a height it already covered, into the bytes a build that had
  stopped there would have written.

- **A name for what it is.** An artifact's fingerprint covers what it holds and
  nothing else, so two honest builds of the same chain to the same height agree
  on it whoever built them and from whichever copy of the source. Where it came
  from is a separate question with a separate answer: each manifest declares its
  parent, derivatives naming the index and the index the graph, and `verify`
  confirms that naming when you hand it both. Comparing the fingerprints of a
  whole stack compares the whole ancestry.

- **An answer says when it does not know.** Every answer travels with its
  source and its watermark, and a capability with nothing plugged in returns an
  explicit UNDETERMINED. Silence and "no" are different answers, and conflating
  them is how tools mislead people about their own money. `nodsig check` is
  where this is most visible: per-address answers assembled from separate
  capabilities, each naming who answered and up to which height.

- **Economy of means.** The cheapest structure that answers the question, and
  not one byte more. One pass over the chain feeds both branches; one expensive
  derivative answers three questions instead of three separate indexes; an
  outpoint is cited by a **5-byte [ordinal](docs/GLOSSARY.md#ordinal-tx-ordinal-output-ordinal)** instead of the 36-byte pair, once
  and then billions of times; sorted streams meet in a merge-join instead of
  seeking at random over hundreds of GB; appending costs the new blocks rather
  than the chain again. It runs on a modest machine because it was written on
  one, against a node on a Raspberry Pi.

- **No lock-in.** Neutral, portable formats and interfaces; the reference is
  readable Python, and native accelerators attach proven-identical.

## Requirements

- **Python 3.10 or later, and nothing else.** No dependencies: the standard
  library is the whole runtime, on purpose, so that what you run is what you
  can read.
- **Optionally, a C compiler and Python's development headers** (`python3-dev`
  on Debian and Ubuntu), for the native kernel (`src/nodsig/native`): the
  archive scan's walk of a block and the fusion's k-way stage over the runs,
  the same as the Python reference, in C, proven to write the same bytes
  (the conformance vectors in `tests/fixtures/scan` and the suite hold the
  two to the same records, counters and refusals, and the fusion's two
  roads to the same blobs), about four times faster on the block and
  2.7 times on the fusion's round. It is built by `pip install` when a
  compiler is there and skipped when it is not, or by hand from a checkout with
  `PYTHONPATH=src python3 -m nodsig.native.build`; a package without it runs
  the reference, unchanged. The scan takes the C road only when it is not
  co-emitting: a scan with `--graph`, `--graph-digest` (a rescan that checks
  an existing graph instead of writing one) or `--nonces` reads the
  parsed block for the other artifact and keeps the Python road, so the block
  figure above is what a scan of the archive alone gains. `--headers` rides on
  either road, and the fusion's stage is native whenever the kernel is built. The archive's manifest says which road scanned it, outside the
  fingerprint. `NODSIG_NATIVE=0` forces the reference road.
- **Bitcoin Core 28 or later** if you want the snapshot-based steps
  (`census`, `reuse prepare`): they read the `dumptxoutset` format that Core 28
  writes, and refuse an older one by name. Mainnet only. The rest of the
  toolkit talks to any node that answers RPC.
- **Your own Bitcoin node**, not pruned, with RPC reachable (and `-rest=1` if
  you want the faster block fetch described in
  [`docs/building.md`](docs/building.md)). Pruned nodes
  cannot serve the block history these tools read. The node is contacted while
  building artifacts, and after that only for the two things files cannot hold:
  a current balance (`check --rpc`) and the calendar dates of blocks (`curve
  dates`). Everything else answers offline.
- **Disk and patience, but only for the heavy paths.** Building the full chain
  artifacts means hundreds of GB and tens of hours, dominated by I/O rather
  than CPU (see *Running it at chain scale*). Every one of those builds is
  resumable: a checkpoint is written as it goes, and re-running the same
  command continues instead of starting over.

## Building the artifacts

Everything else is a query over files, so this is the part that needs the node
and the hours. **One pass over block history** is the only long step that
talks to the node, and its co-emission flags feed every other artifact from
it; everything after it is offline. Pick one height and use it everywhere: an
artifact is defined by where it stopped, and pieces cut at different heights
do not join.

```sh
# only for the census and the reuse figures (questions 5 and 6): the snapshot
bitcoin-cli dumptxoutset /path/snapshot.dat        # note the height it reports
nodsig census /path/snapshot.dat                   # the set, by lock type and age
nodsig reuse prepare --out <locks-dir> --height <S> /path/snapshot.dat

# the one pass over the chain: the exposure question needs --archive alone,
# --headers is cheap and worth having, --graph and --nonces are decisions
nodsig archive scan --rpc <url> --cookie-file <path/.cookie> \
                    --end <H> --archive <archive-dir> \
                    --headers <headers-dir> [--graph <graph-dir>] [--nonces <nonces-dir>]
nodsig archive merge --archive <archive-dir>       # fuse runs, seal, fingerprint
nodsig archive verify --archive <archive-dir> --deep

# only for histories, fees and co-spends (questions 3 and 4): from the graph
nodsig index   build --graph <graph-dir> --index <index-dir> --end <H>
nodsig derived build --index <index-dir> --out <derived-dir>

nodsig check --archive <archive-dir> [--index <index-dir> --derived <derived-dir>] \
             --stdout <address> [<address> …]
```

`--end <H>` is required and is the height everything else is cut at: the
snapshot's, if you took one. `--rest` sits beside `--rpc`, not in its place:
same URL, and the blocks are then fetched from the node's REST interface on
the same port (`rest=1` in `bitcoin.conf`), which authenticates nobody, so
that step carries no credential.

The scan's flags are the one choice that cannot be revisited without walking
the chain again, so here is what each one costs and what you give up without it:

| flag | cost | without it |
|---|---|---|
| (none) | ~145 GB of runs, 111.8 GB once merged | you still get the revelation archive: the exposure question |
| `--graph` | 300-400 GB | no index, no derivatives, no block statistics: they are all built from it |
| `--headers` | ~150 MB | dates need the node, and the scan's integrity checks cannot be repeated offline |
| `--nonces` | 59.7 GB, ~10% CPU | the nonce census does not exist and no later pass can rebuild it |
| `--rest` | none, saves ~half the bytes on the wire | JSON-RPC instead: correct, slower, needs a credential |

The hours, measured at height 957,301 on the machine
[`docs/building.md`](docs/building.md) describes (a node over a LAN, the
artifacts on a USB disk): the scan **~56 h** with the nonce census co-emitted,
31 h 49 for a pass that emitted the archive and the headers alone;
`archive merge` **4 h 43**; `archive verify --deep` ~1 h 20; `index build`
**20 h 39**; `derived build` **21 h 52**. Checking everything you built costs
about a twentieth of building it, and a local node with the artifacts on an
NVMe disk should do better than every one of those figures.

What a given question needs, at height 957,301:

| To ask | Keep | Size |
|---|---|---|
| a Taproot address (`bc1p…`) | nothing: the program is the key | **0** |
| exposure, single-key addresses (`1…`, 20-byte `bc1q…`) | the archive's key partition | **40.8 GB** |
| exposure, any address kind | the whole archive, without its `proof/` | **53.9 GB** |
| …plus dated history, fees, co-spends | the index and its derivatives | +415 GB |

Three pages carry the rest. [`docs/building.md`](docs/building.md) is this
sequence with the reasoning behind each flag, **what every step costs** in
measured hours and gigabytes, what to keep afterwards, and the two costs that
are properties of the formats rather than of the code.
[`docs/build-and-query.md`](docs/build-and-query.md) is every command in
order, with nothing else, to keep open while a build runs, and the three
places where doing things in the wrong order costs a rebuild.
[`docs/ARTIFACTS.md`](docs/ARTIFACTS.md) is the map: what each artifact is,
which command produces it, which read it, and which parts you can skip. For
a first contact at a fraction of these costs, the same sequence on a small
early slice is [`docs/quickstart.md`](docs/quickstart.md); for a wallet
rather than one address, `check --address-book` and
[`docs/exposure-check.md`](docs/exposure-check.md).

With `NODSIG_HOME` set to a directory that holds the artifacts under their
roles' names (`archive`, `graph`, `headers`, `nonces`, `witness`, `index`,
`derived`, `firstspend`, `firstreveal`, `locks`, `timeline`; a symlink does
for one kept on another disk), the reading commands find them without being
named:
`nodsig check --stdout <address>`, `nodsig index lookup <txid>:<vout>`,
`nodsig report`. The commands that write an artifact take no default, on
purpose.

### Checking what you built

`index`, `derived`, `archive`, `headers` and
`nonces` carry `verify`, which re-reads every byte against the manifest and rebuilds
every search ladder from the file it indexes, so a ladder is checked for being
*right* and not merely intact. `index` and `derived` also carry `stats`, which
reports from the manifest alone and is instant, and `graph fingerprint`
re-reads a graph and prints its fingerprint, which is the same check under
another name.

`archive verify --deep` adds the pass the digests cannot replace: every record
read, digests strictly ascending (order and uniqueness at once), the flag
bits the format defines, every first-seen height inside the claimed coverage,
whose highest value then holds the watermark to a floor, and the proof: every
script the archive holds is a program the chain created, and no candidate the
proof set aside is. It
costs a second read of the archive, so it is a flag and not the default, and
without it the report says the coverage was taken on trust rather than staying
silent about it. The recipe, for anyone writing their own reader, is in
[`formats/RevealArchive-v4.md`](docs/formats/RevealArchive-v4.md). Checking everything you built costs about a twentieth of
building it, and [`docs/trust-model.md`](docs/trust-model.md) says what that
check establishes and what only an independent build can.

### What you can ask, once they exist

`check` is the assembled answer, but each artifact also answers directly, and
the direct questions are often the interesting ones. Unless noted, these are
offline and take seconds:

| Question | Command |
|---|---|
| What is this outpoint's whole story: created when, worth what, under which lock, spent by whom? | `index lookup TXID:VOUT` |
| What is this lock's history, event by event, with heights and dates? | `derived history --lock <hash160>` |
| What fee did this transaction pay? | `derived fee TXID` |
| What was spent together with this? (the common-input hint) | `derived cospends TXID[:VOUT]` |
| Does every coinbase respect subsidy + fees, and how much was left unclaimed? Fees per epoch? | `derived supply` |
| How did balances distribute over time, and how much coin-age did each era destroy? | `derived timeline` (one full pass over the largest file: hours, not seconds) |
| Was this raw digest ever revealed, and seen where? | `archive lookup <digest>` |
| Which eras' revelations still guard value today? | `curve deltas curve.csv` (a survivorship series over one snapshot, not a history of reuse) |
| …and on what real dates? | `curve dates`: block times are not in the curve, so the join is a declared step rather than a smuggled one. Offline with `--headers`, which is what that archive is for; only without it does it ask the node |
| What do the blocks themselves look like, per epoch? | `blockstats summary` |

Run any of them with `-h` for the exact arguments. `index lookup` is the one to
try first: it is the didactic window on the whole design, and shows in one
screen what the [ordinal](docs/GLOSSARY.md#ordinal-tx-ordinal-output-ordinal) coordinates buy.

### What to keep afterwards, and what the node is still for

Once the artifacts exist, **every query is offline**. The node is needed again
only to extend them to a later height, for a current balance (`check --rpc`)
and for `nonces address`. The three you keep to answer questions are
**archive, index and derived**; the `<graph>` is read by no query and is the
largest thing you own, so deleting it reclaims the most space, at the price
that extending or rewinding the index would mean walking the chain again.
`<archive>/proof/` is larger than the archive it sits beside, no query reads
it, and `archive scan` refuses to grow an archive without it. The table of
what each query needs, and what each deletion costs, is in
[`docs/building.md`](docs/building.md#what-to-keep-afterwards-and-what-the-node-is-still-for).

## Commands

One entry point, one verb per artifact:

| Command | What it does |
|---|---|
| `nodsig census` | census the UTXO set by lock type and age |
| `nodsig reuse` | scan the chain for reused (already-revealed) locks |
| `nodsig archive` | build and query the archive of key revelations |
| `nodsig headers` | seal and audit the header archive the scan co-emits |
| `nodsig nonces` | read the census of published signature nonce points |
| `nodsig graph` | inspect a `graph-v2` artifact |
| `nodsig index` | build and query the outpoint index |
| `nodsig derived` | build and query history, fees and co-spends |
| `nodsig firstspend` | when each lock was first spent from, ordered by time |
| `nodsig firstreveal` | when each key was first revealed, ordered by time |
| `nodsig blockstats` | per-block statistics derived from a graph |
| `nodsig price` | an external price series, and one price per block from it (requires a price series) |
| `nodsig curve` | read the reuse curve: deltas over time, real block dates |
| `nodsig check` | check addresses against every backend you have plugged in |
| `nodsig report` | one page: what your artifacts are, what they cost, what built them |
| `nodsig manifest` | re-seal a manifest under this release's statement (the artifacts 2.0.0 does not rebuild) |

Run `nodsig` for the map, `nodsig <command> -h` for a command's own options.

**Stability.** The **formats are the contract**; the CLI is convenience. Within
a major version the commands named above do not change, so text written
elsewhere about how to run them stays true. That promise is the reason the
version number exists, and it is what lets a printed manual keep describing a
moving codebase. `nodsig --version` prints it.

That number and the formats' numbers are **two different scales**, and the
artifacts settle it rather than merely claiming it: every one of them carries
`nodsig-identity-v3`, the recipe its fingerprint is taken over, which reached
its third revision on a clock of its own. A format tag answers *what does this artifact
capture*, which is what lets a reader tell an absence from a blind spot; a
release number answers *what does the command line promise until the next
major*. They move for different reasons, so `reveal-archive-v4` inside a 3.2.0
tool is not a discrepancy: the reveal archive really is at its fourth format,
and the tool at its third major. Internal module names carry no promise at
all: they are free to move, and they have.

**A worked application of one release.** A hands-on walkthrough of release
1.0.0 (the real command outputs, the timings, and the published fingerprints
to land on, at height 957,301) lives at
[liberlume.com](https://liberlume.com/en/bitcoin-and-quantum-computing-manual/)
([italiano](https://liberlume.com/it/bitcoin-e-quantum-computing-manuale/)).
It is a worked example of the release it names, not a document that tracks
this repository: what it shows keeps working within this major, exactly by
the promise above, but the artifacts and verbs added since appear here
first, in [`docs/`](docs/). Read it for the use cases and for what the
toolkit feels like at chain scale; read `docs/` for what the current
release does.

**Credentials never travel on the command line.** The node is contacted only
with `--rpc`, authenticating from the cookie file (`--cookie-file`) or from
`NODSIG_RPC_AUTH` in the environment. No flag accepts a secret: a process's
argv is readable by every other local user, for as long as the run lasts.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the map (L0/L1/L2
layering, contracts, kernels vs orchestration). Contracts in detail live in
`docs/contracts/`, byte formats in `docs/formats/`.

## Running it at chain scale

Two costs are properties of the formats, not accidents of the implementation,
and both are invisible on a test chain: **a fusion wants headroom** (a new
generation is written and committed before the old one is deleted, so a
machine killed mid-fusion leaves the previous one whole), and **an append
re-reads the spend side once, whole**, per append run rather than per block,
so batch the blocks you append. **Going back is cheaper than rebuilding**:
`rewind` takes a sealed artifact to a height it already covered, into the
same bytes a build stopped there would have written. All three are in
[`docs/building.md`](docs/building.md#running-it-at-chain-scale), with the
figures.

## What this is, and what it is not

**A proof of concept, not a product.** This code exists to show that the
questions it asks can be answered from your own node, with artifacts anyone can
rebuild and compare by fingerprint. There is no roadmap, no support, and no
promise of maintenance; the only compatibility commitment is the one stated
under Stability above, and it is about formats and command names, nothing else.

**Cross-check whatever it tells you.** The rule this project applies to itself
is that a number worth publishing is one that two independent roads reached:
the reuse scan and the reveal archive answer the same question by different
means, and the derivatives refuse to seal unless two separate walks meet on the
same satoshis. Where two roads share an input, the shared part is checked
instead of assumed: both burn the same lock files, so those are verified
against their manifest before either road starts, and a cross-check against a
checkpoint made with different locks is refused rather than reported as
agreement. That rule does not stop at the repository boundary. Before
acting on an answer, reproduce it another way: a block explorer, a different
tool, a second run over a rebuilt artifact. A single answer from a single tool
is a lead, not a fact, and this tool is no exception to a principle it is built
on.

This matters most where being wrong costs asymmetrically. `nodsig check`
reports whether a lock's public key has already appeared on-chain; "exposed",
"not exposed" and "undetermined" are three different answers, none of them a
statement about whether anyone's funds are safe, and the perimeter of what
counts as the same "address" is narrower than most people assume (identical
scriptPubKey, not a wallet). Decisions about custody deserve more than one
source, and more than one reading.

**No warranty.** The software is provided "as is", without warranty of any
kind, express or implied, including but not limited to the warranties of
merchantability, fitness for a particular purpose and non-infringement; the
full terms are in the [MIT license](LICENSE), repeated here because a license
file is easy to skip. Nothing in this repository promises throughput, latency,
or that a run will finish: the measured figures above describe one machine on
one day and are context, not a commitment.

## Status

**Public since 1.0.0.** The artifacts named in this README and in
[`docs/gallery.md`](docs/gallery.md) were built by the 1.x releases, from the
chain through height 957,301, and sealed with the fingerprints printed there.
Two releases have since forced the archive to be rebuilt — 2.1.2, because
2.0.0 and 2.1.0 dropped keys the chain had published, and 3.0.0, because the
archive now keeps a script when the chain proves it one — and a 3.0.x run has
been completed against them. The changelog says, release by release, which
artifacts each one invalidates. Rebuild
from the same chain to the same height and the same numbers come back: that is
the only claim this project makes, and it is checkable rather than persuasive.

The fingerprints of the current run are not listed anywhere as numbers to
check against, on purpose: a fingerprint is a fact about one build at one
height under one set of formats, every rebuild retires it, and
[`docs/gallery.md`](docs/gallery.md#reproducing-any-of-it) says why a
repository that quoted it in five places would get five chances to be wrong.
They appear where a transcript carries them (the run in
[`docs/exposure-check.md`](docs/exposure-check.md) names the archive's), and
the one to hold yours against is the one printed by your own build or by an
independent one at the same height.

Which revision built an artifact is recorded **in the artifact**, under
`build.producer`: the version always, the commit and whether the tree carried
uncommitted edits whenever those can be determined. It sits outside the
fingerprint, because the fingerprint is a function of the bytes and two honest
builds of identical content must reach the same number whatever produced them.
It is a declaration, and the manifest presents it as one.

What the full pipeline at chain scale has exercised, and what only the test
suite covers, is stated in
[`docs/building.md`](docs/building.md#what-a-run-has-exercised-and-what-only-the-tests-have)
rather than left to be discovered: how a scan resumes the spend side across an
append, how an archive fusion commits, and `rewind` on files of tens of GB are
the three paths that only the chain moving past this height will confront.

## License

Code under the **MIT** license (see [`LICENSE`](LICENSE)). The figures in
`docs/figures/` are ours too, under the same license, with one exception:
the two price figures are derived from a publisher's series and are
published under that publisher's terms, named beside them in
[`docs/gallery.md`](docs/gallery.md). The other four first appeared in
the write-up linked from that page.
