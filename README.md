# NodSig

> **`nod·sig`**: **nod** = your node (a vertex of the graph) · **sig** =
> `OP_CHECKSIG`, the operation that forces the public key to appear on-chain.

NodSig answers questions about the Bitcoin blockchain out of your own node. It
builds local artifacts once, and from then on every question is a lookup in a
file: no block explorer, no third-party index, no network. Each answer names
the artifact it came from, the height that artifact covers, and a fingerprint
anyone else can recompute from the same chain.

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

## What you can ask it

- **Has this address's public key already appeared on the chain?** Spending
  reveals a public key, so a lock that has been spent from is in a different
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
  locks, but the archive stores digests, not dates.

- **What is this outpoint's whole story?** Created when, worth what, under
  which lock, spent by whom.

- **What did this transaction pay in fees, and what was spent together with
  what?** Local lookups over your own files, with no index provider in the
  middle.

- **How much of the UTXO set sits behind keys that are already revealed?**
  Counted by lock type and by age, from the set itself, rather than estimated.

- **How did key reuse grow over time?** As a series, block by block, and on
  real calendar dates.

Answering one address is a small enough job that it deserves its own page:
[`docs/exposure-check.md`](docs/exposure-check.md) walks the exposure question
end to end, including how little you actually have to keep on disk and how to
run it on a machine that talks to nobody.

The output is text and CSV. Here is what the chain looks like when a spreadsheet
draws one of those CSVs, at height 957,301:

![All coins in circulation, type by type: bar length is the value held by that
type, the filled part the value with its key in view (hatched = exposed by
construction)](docs/figures/ledger-map.svg)

More examples of what the commands actually print, and what the numbers look
like once drawn, are in [`docs/gallery.md`](docs/gallery.md).

## Try it before building anything

Nothing has to be installed. From a clone, the package runs where it lies:

```sh
git clone https://github.com/amenano/nodsig.git
cd nodsig
python3 -m nodsig --version
python3 -m nodsig                       # the map of commands
```

If you would rather have `nodsig` on your PATH, install it from the clone with
`pip install .`. The two forms are the same program. This README writes
`nodsig …`; substitute `python3 -m nodsig …` if you did not install. Reading
the code while it runs is a supported way to use this repository, which is why
`python3 -m nodsig.<module>` also runs a single tool directly.

Now run the tool with nothing built and no node, on any address you do not mind
typing:

```console
$ nodsig check --stdout 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
# history: not configured (pluggable: outpoint-index derivatives (--index + --derived))
# co-inputs: not configured (pluggable: outpoint-index derivatives (--index + --derived))

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
  outpoint is cited by a **5-byte ordinal** instead of the 36-byte pair, once
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
- **Your own Bitcoin node**, not pruned, with RPC reachable (and `-rest=1` if
  you want the faster block fetch described below). Pruned nodes
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
and the hours. Pick one height and use it everywhere: an artifact is defined by
where it stopped, and pieces cut at different heights do not join.

**What each step costs**, so you can decide in advance where to stop. These are
wall times from one real run to height 957,301, and sizes for that height:

| Step | Time | Writes |
|---|---|---|
| `bitcoin-cli dumptxoutset` | minutes to an hour, on the node | the snapshot |
| `census` | ~18 min | a CSV |
| `reuse prepare` | ~35 min | `<locks>`, ~1.4 GB (one record per *distinct* lock, not per output) |
| `archive scan --graph` | **~3 days** | `<archive>` ~87 GB **and** `<graph>` ~301 GB |
| `archive scan --nonces` | +10% of the scan above | `<nonces>` ~55-60 GB |
| `archive merge` | ~4 h 20 | seals the archive in place |
| `nonces merge` | ~2 h 40 | seals the census in place |
| `nonces resolve` | ~36 min | ~1 MB: the evidence that resolves each repeated point (**needs the node**, optional) |
| `graph fingerprint` | ~5 h | nothing: it re-reads and prints |
| `archive derive` | ~5 h 40 | the reuse table, and its `curve.csv` |
| `archive curve` | ~2 h | `revelations.csv`: first revelations per window |
| `index build` | ~25 h | `<index>` ~248 GB |
| `derived build` | ~14 h 30 | `<derived>` ~191 GB |

The audits are cheap next to the builds, and that is the point of them. From
the same run: `archive verify --deep` ~1 h 40, `index verify --graph` ~1 h,
`headers crosscheck --index` ~1 h, `derived verify --index` ~40 min,
`nonces witness-verify` seconds. Checking everything you built costs about a
twentieth of building it, so there is no version of this where verifying is
the step you skip.

Every number in that table comes from the slow end of every choice it depends
on. Read the two paragraphs below before concluding that a use case is out of
reach.

The figures above come from one run to height 957,301, and the mount changed
partway through it, which is worth stating because the mount matters more than
anything else here. The fusions ran with the artifacts on a network share
(45 MB/s reading, 75 writing, measured); the index, the derivatives and their
audits ran on a local USB disk (75 and 97). A third configuration on the same
hardware and the same file, a 9p share, managed 14.4 MB/s, and quoting that one
would have made the same tool look three times slower.

So the honest reading is not "this is what a network costs". It is that the
choice of mount moves these rows by a factor of three to five, that the numbers
here come from the two faster of the three, and that a reader on a local SSD
should expect better rather than worse.

Which resource bounds which row is the part worth knowing: the scan is bounded
by the wire to the node, the fusions and the builds by the disk under the
artifacts, and only the nonce census by CPU. None of those is fixed by the tool.
A reader whose node runs on the same machine, with the artifacts on a local
disk, is looking at two handicaps in this table that they do not have. Once you
have built anything, `nodsig report` prints what **yours** cost beside what they
are: it reads the durations out of the manifests the builders sealed, so the
figures are the artifacts' own rather than a transcription.

Roughly **five to six days** and **~885 GB** if you build all of it and keep
everything. The section below on what to keep is worth reading before you size
the disk, because the largest artifact is the one no query reads.

Every row in that table has now been produced by a completed run to 957,301,
including the two `--nonces` ones, which until that run were arithmetic on a
measurement over 20,000 real blocks (about two microseconds of CPU per input,
and 1.02 to 1.09 records per input). What follows is kept for the reader who
wants to know how a projection was made, and as the record of a projection
that a run has now replaced.

The **scan** has a second bottleneck of its own, and it is not your CPU either:
it is the wire to the node. Ours was an Umbrel on a Raspberry Pi reached through
an SSH tunnel, which is roughly the slowest reasonable setup, over JSON-RPC,
which is the more expensive of the node's two ways of handing over a block (see
`--rest` below); a node on the same machine is much faster. Treat the table as
orders of magnitude, not as a forecast.

All of it is resumable, and none of it needs watching: every long command
writes checkpoints and continues from them when re-run.

**Reaching your node.** Two flags, and neither carries a secret. `--rpc` is the
node's URL and defaults to `http://127.0.0.1:8332`; `--cookie-file` is the path
to the `.cookie` your node writes in its data directory (`~/.bitcoin/.cookie`
on a default mainnet setup), read from the file at each call so it stays
current and never appears in `ps`. If the node lives on another machine,
forward the port to your own and keep using the local URL:

```sh
ssh -N -L 8332:127.0.0.1:8332 <user>@<node-host>   # then --rpc stays the default
```

Copy the cookie across too, or point `--cookie-file` at a copy: it changes
every time the node restarts.

**A cheaper wire, if your node offers it.** `--rest` fetches the blocks from
the node's binary REST interface (`rest=1` in `bitcoin.conf`, served on the
same port as the RPC) instead of asking `getblock` for hex wrapped in JSON. The
blocks arrive verbatim, which is about half the bytes for the one step whose
cost *is* the wire, and that interface authenticates nobody, so the fetch
carries no credential at all. It has no batching, though: two requests per
block, so pair it with `--prefetch-depth <n>` to keep several fetches in
flight. Nothing else changes, the integrity checks least of all. The transport
is chosen for bytes, never for trust, and the two roads are tested to produce
byte-identical artifacts.

Start from a UTXO snapshot, which your node writes for you:

```sh
bitcoin-cli dumptxoutset /path/snapshot.dat        # note the height it reports

nodsig census /path/snapshot.dat                   # the set, by lock type and age
nodsig reuse prepare --out <locks-dir> /path/snapshot.dat
```

Then **one pass over block history**. This is the only long step that talks to
the node, and the two co-emission flags feed every other artifact from it, which
is why they are worth passing even if you came only for the exposure question:

```sh
nodsig archive scan --rpc <url> --cookie-file <path/.cookie> \
                    --end <H> --archive <archive-dir> \
                    --graph <graph-dir> --headers <headers-dir>
nodsig archive merge --archive <archive-dir>       # fuse runs, seal, fingerprint
```

`--headers` costs about 150 MB for the whole chain and keeps the header chain the
scan verified, so its integrity checks can be repeated later without another
pass. `--graph` costs 300-400 GB and is what the index and the derivatives are
built from.

`--graph-digest <graph-dir>` is the alternative to `--graph` for anyone who
already has a graph: it serializes exactly the same records, hashes them, and
writes nothing, so a rescan can check that this code still emits the archive
it is not rewriting. The reference's `state.json` already holds a digest per
run, so the check compares interval by interval as the scan crosses each
boundary, at no extra read and no extra pass. Fingerprint the reference first,
which is the pass that verifies those per-run digests against the files
themselves. An interruption costs only the interval it lands inside, and the
report names it; read it back with `graph digest --scan <archive-dir>`.

An archive written under the earlier `graph-v1` seal reads here unchanged: that
break moved the seal, not the stream. It cannot be a **parent** until it is
re-sealed, though, because its fingerprint comes from a recipe this code does
not compute, and `index build` refuses it by name rather than sealing an
ancestry nobody can rederive. `graph fingerprint --reseal` gives the same bytes
a `graph-v2` identity and keeps the old manifest beside the new one.

`--nonces` costs about 55 GB and roughly 10% of this pass's CPU, measured rather
than guessed, and records every signature's nonce point with the height that
published it. Two signatures of one key over two different messages that share a
nonce hand out that key to anyone who noticed, so what this sorts together are
the candidates for that, already public and already computable rather than a
future risk. Candidates, because the census sees points and not `s`: a point
also repeats when one signature is copied onto a second input, and telling the
two apart takes re-reading the blocks. It is the one addition here that a later
pass could not reconstruct: the artifacts kept afterwards hold no unlocking
data. Seal it with `nodsig nonces merge`, then read it with `nodsig nonces
groups`. To ask the same question about one address of yours, `nodsig nonces
address` joins the index, the derivatives and your node on the outpoint:
[`docs/nonce-check.md`](docs/nonce-check.md) is the walkthrough.

Seal what you asked for, and get the numbers out of the archive:

```sh
nodsig graph fingerprint --graph <graph-dir>
nodsig headers fingerprint --headers <headers-dir>
nodsig archive derive --archive <archive-dir> --locks <locks-dir> \
                      --curve curve.csv          # the reuse table, and its curve
nodsig archive curve  --archive <archive-dir> --out revelations.csv
```

`--no-faces` and `--no-cosigners` narrow what counts as a revelation. They
exist for exploring, but **whatever perimeter you scan with, derive with**:
mixed perimeters describe different questions, and the comparison refuses
rather than quietly averaging them.

Both curves are built from the `first_height` every record carries, so they
read the same before and after a merge, and the rows land on the grid you ask
for. `archive curve` is the archive's own: how much the chain first revealed
per window of heights, needing no locks and therefore no snapshot and no node.
`curve dates` puts calendar dates on either of them, offline, from the
co-emitted headers.

From the graph, offline from here on, the indexed side:

```sh
nodsig index   build --graph <graph-dir> --index <index-dir> --end <H>
nodsig derived build --index <index-dir> --out <derived-dir>
```

Then the question you presumably came for, with everything plugged in:

```sh
nodsig check --archive <archive-dir> --index <index-dir> --derived <derived-dir> \
             --stdout <address> [<address> …]
```

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
| Was this raw digest ever revealed, and seen where? | `archive lookup <digest>` |
| How did reuse grow over time? | `curve deltas curve.csv` |
| …and on what real dates? | `curve dates`: block times are not in the curve, so the join is a declared step rather than a smuggled one. Offline with `--headers`, which is what that archive is for; only without it does it ask the node |
| What do the blocks themselves look like, per epoch? | `blockstats summary` |

Run any of them with `-h` for the exact arguments. `index lookup` is the one to
try first: it is the didactic window on the whole design, and shows in one
screen what the ordinal coordinates buy.

One table is not reachable this way. `reuse stats`, the distribution of value
across the exposed locks (median, Gini, the value bands), reads a checkpoint of
hit bitmaps, and only `reuse scan` writes those files today. `archive derive`
computes exactly the same bitmaps while it works, to the same fingerprint, and
then drops them, so the figure is not lost information: it is a missing writer.
Until there is one, that table comes from the second road described below.

### What to keep afterwards, and what the node is still for

Once the artifacts exist, **every query below is offline**. The node is needed
again only to extend them to a later height, or for one optional capability:

| To answer | You need | Node? |
|---|---|---|
| `check`: exposure, history, co-spends | `<archive>` `<index>` `<derived>` | no |
| `check`: balance as well | the above, plus `--rpc` | yes |
| `archive lookup`, `index lookup` | that artifact alone | no |
| `nonces groups`, `nonces lookup` | `<nonces>` alone | no |
| `nonces address`: did this key repeat a nonce? | `<index>` **and** `<derived>` | **yes** |
| `derived history / fee / cospends` | `<index>` **and** `<derived>` | no |
| `blockstats`, rebuilding or rewinding the index | `<graph>` | no |
| extending anything to a later height | the artifact, plus the node | yes |

So the three you keep to answer questions are **archive, index and derived**.
The `<graph>` is not read by any query: it is the material the index is built
from, and it is also the largest thing you own. Deleting it reclaims the most
space of any single choice here, at the price that rebuilding or rewinding the
index would mean walking the chain again. Keep it if you intend to follow the
chain forward; delete it if this was a one-time question.

The `<nonces>` census is a fourth, and its trade-off is its own. Its *answer* is
small: `nonces groups` writes every repeated nonce point to a CSV, and that file
outlives the 55 GB it came from. What deleting the census costs is not the
answer but the future: a later append can no longer notice that a signature at
the chain tip reuses a nonce from years ago, because the single sighting it
would have matched is gone. Keep it if you intend to watch the chain forward,
delete it once you have the CSV if this was a one-time question.

The snapshot and `<locks>` are inputs to `census`, `reuse prepare` and `archive
derive`. Once you have the numbers, only a new snapshot at a new height would
make them useful again.

That is the whole path: one pass, then everything else offline. There is a
second road to the same reuse figure. `nodsig reuse scan` walks the chain
comparing against the locks as it goes, and `nodsig archive crosscheck` puts
the two results side by side. What it compares are the two extraction
pipelines, which are written separately for exactly that reason; both roads
share the lock files, so those are verified against the sha256 their manifest
recorded rather than trusted. It costs another full pass, and what it buys is
confidence in the method rather than a number you do not already have. It is a
result to inherit, not a step to repeat.

[`docs/ARTIFACTS.md`](docs/ARTIFACTS.md) is the map behind this sequence: what
each artifact is, which command produces it, which ones read it, how large it
gets, and, the part worth reading before you start, **which parts you can
skip** depending on the question you came for.

[`docs/build-and-query.md`](docs/build-and-query.md) is this same sequence with
the reasoning taken out: the commands in order, what each one costs, the audits
worth running afterwards, and the four places where doing things in the wrong
order costs a rebuild. It ends with every command the tool has, the reading ones
included, so it is both the page to keep open while a build runs and the list of
what you can ask once it is done.

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
| `nodsig blockstats` | per-block statistics derived from a graph |
| `nodsig curve` | read the reuse curve: deltas over time, real block dates |
| `nodsig check` | check addresses against every backend you have plugged in |
| `nodsig report` | one page: what your artifacts are, what they cost, what built them |

Run `nodsig` for the map, `nodsig <command> -h` for a command's own options.

**Checking a sealed artifact.** `index`, `derived`, `archive`, `headers` and
`nonces` carry `verify`, which re-reads every byte against the manifest and rebuilds
every search ladder from the file it indexes, so a ladder is checked for being
*right* and not merely intact. `index` and `derived` also carry `stats`, which
reports from the manifest alone and is instant, and `graph fingerprint`
re-reads a graph and prints its fingerprint, which is the same check under
another name.

`archive verify --deep` adds the pass the digests cannot replace: every record
read, digests strictly ascending (order and uniqueness at once), the flag
bits within the five the format defines, and every first-seen height inside the
claimed coverage, whose highest value then holds the watermark to a floor. It
costs a second read of the archive, so it is a flag and not the default, and
without it the report says the coverage was taken on trust rather than staying
silent about it. The recipe, for anyone writing their own reader, is in
[`docs/formats/RevealArchive-v2.md`](docs/formats/RevealArchive-v2.md).

`archive v1-digests` is the check the other two cannot be: it confronts the
archive with the *published* one. It strips everything the format gained since
v1 (the first-seen height, the count of keys inside a script, the key's
serialized form) and prints one sha256 per category over what is left, which
must equal the digest the sealed v1 archive recorded. Verify says an archive is
internally sound; this says it is the same history someone else's build
already described. The `v1` in that command's name is the **archive's format**,
the one published in July 2026, and not a version of this tool: see the two
scales under Stability.

**Stability.** The **formats are the contract**; the CLI is convenience. Within
a major version the commands named above do not change, so text written
elsewhere about how to run them stays true. That promise is the reason the
version number exists, and it is what lets a printed manual keep describing a
moving codebase. `nodsig --version` reports `1.0.0`.

That number and the formats' numbers are **two different scales**, and the
artifacts settle it rather than merely claiming it: every one of them carries
`nodsig-identity-v3`, the recipe its fingerprint is taken over, while this
package has never been at 3. A format tag answers *what does this artifact
capture*, which is what lets a reader tell an absence from a blind spot; a
release number answers *what does the command line promise until the next
major*. They move for different reasons, so `reveal-archive-v2` inside a 1.0.0
tool is not a discrepancy: the reveal archive really is at its second format,
and the tool is at its first release. Internal module names carry no promise at
all: they are free to move, and they have.

**Credentials never travel on the command line.** The node is contacted only
with `--rpc`, authenticating from the cookie file (`--cookie-file`) or from
`NODSIG_RPC_AUTH` in the environment. No flag accepts a secret: a process's
argv is readable by every other local user, for as long as the run lasts.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the map (L0/L1/L2
layering, contracts, kernels vs orchestration). Contracts in detail live in
`docs/contracts/`, byte formats in `docs/formats/`.

## Running it at chain scale

Two costs are properties of the formats, not accidents of the implementation.
Both are invisible on a test chain and unmissable on the real one.

**A fusion wants headroom.** Fusing an index generation, or an archive, writes
a new generation, commits it, and only then deletes the old one. Plan for free
space of roughly the size of what is being fused, on top of what it already
occupies. That is the price of the guarantee: a machine killed mid-fusion
leaves the previous generation whole, and the artifact is never in a state that
has to be believed.

**An append re-reads `spends.bin` once, whole.** The spend file is re-sorted by
spent ordinal at every index fusion, so a byte offset into one generation names
nothing in the next; a resuming scan cannot seek, it partitions. Each append
cycle therefore makes one sequential pass over the whole file and keeps the
edges whose spender belongs to it. The cost is per append **run**, not per
block: appending a day of blocks in one run costs one pass, appending them one
at a time costs one pass each. Batch them.

**Going back is cheaper than rebuilding.** `index rewind` and `derived rewind`
take a sealed artifact to a height it already covered, into the same bytes, and
therefore the same fingerprint, a build that had stopped there would have
written. Removing records from a sorted file leaves it sorted, so this is one
filtering pass per file plus a re-seal, not a second chain walk. It is what
makes an append reversible: extend now, come back to a published height when
you want to reproduce the number that was published with it.

Per-step times and sizes are in the build sequence above, and the artifact map
in [`docs/ARTIFACTS.md`](docs/ARTIFACTS.md) carries the same figures per
artifact.

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

**First public release.** The artifacts named in this README and in
[`docs/gallery.md`](docs/gallery.md) were built by this code, from the chain
through height 957,301, and sealed with the fingerprints printed there. Rebuild
from the same chain to the same height and the same numbers come back: that is
the only claim this project makes, and it is checkable rather than persuasive.

Which revision built an artifact is recorded **in the artifact**, under
`build.producer`: the version always, the commit and whether the tree carried
uncommitted edits whenever those can be determined. It sits outside the
fingerprint, because the fingerprint is a function of the bytes and two honest
builds of identical content must reach the same number whatever produced them.
It is a declaration, and the manifest presents it as one.

The test suite (253 tests) runs on synthetic chains built in-process: it covers
correctness, determinism, and the equality of append and rebuild, but by
construction it cannot cover throughput, files of tens of GB, or a fusion
across a network mount.

**What a run has exercised, and what only the tests have.** The full pipeline
was built and sealed on the chain through height 957,301 and verified against
its manifests. Two paths that only chain scale reaches were confronted with the
real artifacts rather than with reasoning:

- **the seal's hashing**, re-read over the sealed derivatives and compared with
  the digests recorded at build time: 3.4 billion rows of `tx_inputs.bin` and
  1.4 billion of `fees.bin` agree, **ladder included**. At
  the time that was the one part `verify` could not check, since it compared a
  ladder with a digest of itself; `verify` now rebuilds every ladder from the
  file it indexes (invariant 9), so on a real artifact it repeats this check by
  itself;
- **`rewind`**, on real chain data over heights 91,700 to 100,000,
  byte-identical to builds that stopped at those heights, and correctly
  refusing the one cut that falls between the two instances of a BIP30
  duplicate coinbase while accepting a deeper cut below both.

What is still covered by tests rather than by a run, and is stated here rather
than left to be discovered: **how a scan resumes the spend side across an
append** and **how an archive fusion commits**, both at chain scale, and
`rewind` on files of tens of GB. All three need the chain to move past the
height this snapshot froze, and all three fall out of a single run when it
does, since `rewind` is what makes an append reversible.

## License

Code under the **MIT** license (see [`LICENSE`](LICENSE)). The figures in
`docs/figures/` are ours too, under the same license; they first appeared in
the write-up linked from [`docs/gallery.md`](docs/gallery.md).
