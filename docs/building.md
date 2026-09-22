# Building the artifacts: the sequence with its reasoning, the costs, and what a run has shown

This page was the long middle of the README: the build sequence with the
reasoning behind each flag, the measured cost of every step and the history
of those measurements, what to keep afterwards, the two costs that are
properties of the formats, and what a run at chain scale has exercised. The
README keeps the map; this keeps the figures. The same sequence with the
reasoning taken out, as a page to follow while a build runs, is
[`build-and-query.md`](build-and-query.md); what each artifact is, is
[`ARTIFACTS.md`](ARTIFACTS.md).

## The sequence, and what each step costs

Everything else is a query over files, so this is the part that needs the node
and the hours. Pick one height and use it everywhere: an artifact is defined by
where it stopped, and pieces cut at different heights do not join. For a first
contact at a fraction of these costs, the same sequence on a small early slice
is [`quickstart.md`](quickstart.md).

**What each step costs**, so you can decide in advance where to stop. These
are wall times measured at height 957,301. Most rows come from one run,
completed by 1.3.0 in August 2026 with every artifact on one local USB disk;
the few steps that run did not repeat (`census`, `nonces resolve`, `archive
curve`, the headers crosscheck) keep their measured times from the earlier
run on the same machine. Sizes are for that height. **Read the rows that
touch the archive as the older formats' figures**: the archive's scan and
merge, `firstreveal build`, `nonces resolve`, the reuse table. 2.1.2 and
3.0.0 each force a rebuild of the archive (the changelog says why), and a
3.0.x run has since been done: its two measured figures are named beside the
rows below. Everything else still comes from the run described above:

| Step | Time | Writes |
|---|---|---|
| `bitcoin-cli dumptxoutset` | minutes to an hour, on the node | the snapshot |
| `census` | ~18 min | a CSV |
| `reuse prepare` | ~20 min | `<locks>`, ~1.4 GB (one record per *distinct* lock, not per output), sealed with the snapshot's height |
| `archive scan --graph` | **~56 h** | `<archive>` as runs, ~145 GB on a 3.0.x run **and** `<graph>` ~301 GB |
| `archive scan --nonces` | included in the 56 h above, which was measured with the census co-emitted | `<nonces>` 59.7 GB |
| `archive merge` | **4 h 43** (sealed; 5 h 04 on the wall, on a 145 GB run pile) | seals the archive in place, **and writes `<archive>/proof/`**: the candidates and the programs that prove them, sealed with its own fingerprint |
| `nonces merge` | **3 h 27** | seals the census in place |
| `nonces resolve` | **3 h 10** | a few MB: the evidence that resolves each repeated point (**needs the node and the index**, optional) |
| `graph fingerprint` | ~1 h 11 | nothing: it re-reads and prints |
| `archive derive` | **2 h 52** | the reuse table, and its `curve.csv` |
| `archive curve` | **40 min** | `revelations.csv`: first revelations per window |
| `index build` | **20 h 39** | `<index>` 229.6 GB |
| `derived build` | **21 h 52** | `<derived>` 185.3 GB |
| `derived timeline --price` | **4 h 28** | `<timeline>`, three small CSVs: balance bands, the (creation, spend) windows, and the priced third table |
| `blockstats build` | **3 h 26** | `blockstats.csv`, 46.5 MB: one row per block, read from `<graph>` |
| `firstspend build` | **2 h 22** | `<firstspend>` 37.0 GB: the first spend of every lock, ordered by time (optional, from `<derived>` alone) |
| `firstreveal build` | **3 h 08** | `<firstreveal>` 34.0 GB: the first revelation of every key, ordered by time (optional, from the merged `<archive>` alone) |

The bold rows were measured over 16-20 September 2026, rebuilding every one of
them from the archive up, and they are the figures the builders **sealed**:
`nodsig report` prints these same numbers off your own manifests. A wall clock
around the same step reads longer — the interpreter start, the preflight, the
script waiting on the builder — by half a minute on a short step and by up to
an hour and a half on `derived build`. The sealed figure is the one quoted
here, because it is the one anybody can read back out of the artifact.

They replace projections taken from short stretches, and they miss in both
directions: `derived build` was given 15 h and sealed 21 h 52, `index build`
was given 23 and sealed 20 h 39. A per-record cost measured on the first
blocks does not survive the last ones, where the blocks are heaviest, and that
is the whole lesson of the two numbers.

The audits are cheap next to the builds, and that is the point of them. From
the same run: `archive verify --deep` ~1 h 20, `nonces verify --deep` ~1 h 10,
`index verify --graph` **59 min**, `headers crosscheck --index` ~1 h, `derived
verify --index` **45 min**, `firstspend verify` **28 min**, `firstreveal
verify` **26 min**, `nonces witness-verify` and `derived timeline-verify`
seconds. (The audits seal nothing, so those are wall times.) Checking everything you
built costs about a twentieth of building it, so there is no version of this
where verifying is the step you skip.

Every number in that table is a floor in one stated sense: the builds resume
from checkpoints, and a resume records what was checkpointed, never the
stretch a kill took with it. Read the two paragraphs below before concluding
that a use case is out of reach.

Two of the sizes used to be projections, and the run that replaced them is
worth a sentence because it confronted the arithmetic. 1.1.0 measured
`<index>` at 248 GB and `<derived>` at 191; narrowing the spend side and the
satoshi fields predicted 229.1 and 185.8 by arithmetic on the record widths;
the completed v3 build measured **229.6 and 185.3**. The prediction was
checkable and it held to within half a percent.

The figures above come from one configuration, which is worth stating because
the mount matters more than anything else here: every artifact sat on a local
USB disk measured at 83 MB/s sequential read, with the node reached over a
LAN. An earlier run on the same hardware split the same steps across a network
share (45 MB/s reading, 75 writing) and that USB disk, and a third mount on
the same hardware and the same file, a 9p share, managed 14.4 MB/s: quoting
that one would have made the same tool look three times slower.

So the honest reading is not "this is what a network costs". It is that the
choice of mount moves these rows by a factor of three to five, and that a
reader on a local NVMe disk should expect better than this table rather than
worse.

Which resource bounds which row is the part worth knowing: the scan is bounded
by whichever is slower, the wire to the node or parsing a block on a single
core (~25-30 MB/s on this machine, measured, and it does not thread); the
fusions and the builds by the disk under the artifacts, and only the nonce
census by CPU across cores. None of those is fixed by the tool.
A reader whose node runs on the same machine, with the artifacts on a local
disk, is looking at two handicaps in this table that they do not have. Once you
have built anything, `nodsig report` prints what **yours** cost beside what they
are: it reads the durations out of the manifests the builders sealed, so the
figures are the artifacts' own rather than a transcription.

Composed honestly, with the shared pass counted once: **~129 h of machine**
(about five and a half days if run back to back) and **~960 GB** if you build
all of it and keep everything. That total is now a sum of measurements rather
than of projections, and it grew: the projected one said ~110 h. `nodsig
report` composes the part it can see — the artifacts that seal a duration —
and printed **115 h 30 min** for this set; the rest is the steps that seal
none (the census, the lock set, the reuse table and its two CSVs, the graph's
fingerprint pass). One caveat the tool cannot state: the scan it counts is the
56 h one that co-emitted the nonce census, while this archive and these
headers came from a 31 h 49 pass that did not. Taking the longer one keeps the
total on the safe side of the truth. The archive
of a 3.0.x run measured 111.8 GB of that, of which **57.9 GB is the proof**
that `archive merge` writes beside it and `archive scan` needs in order to
grow the archive later; the scan's run pile, ~145 GB, is transient and the
fusion deletes it. The section below on what to keep is worth
reading before you size the disk, because the largest artifact is the one no
query reads.

Every row in that table has now been produced twice by completed runs to
957,301: once by the run that first measured the `--nonces` rows (until then
arithmetic on a measurement over 20,000 real blocks, about two microseconds
of CPU per input and 1.02 to 1.09 records per input), and again by the 1.3.0
run the current figures come from, which also reproduced the published
fingerprints from a fresh walk of the chain. What follows is kept for the
reader who wants to know how a projection was made, and as the record of a
projection that a run has now replaced.

The **scan**'s bottleneck is one of two things, and which one depends on where
your node is. Ours was an Umbrel on a Raspberry Pi reached through an SSH
tunnel, which is roughly the slowest reasonable setup, over JSON-RPC, the more
expensive of the node's two ways of handing over a block (see `--rest` below):
there the wire was the wall, at a few MB/s. With the node on the same machine
over `--rest`, fetching several blocks at once climbs past 40 MB/s, and the
wall becomes the other one: a block is parsed on a single core at ~25-30 MB/s,
and that does not thread, so more prefetch cannot lift it. Both were measured
here; treat the table as orders of magnitude, not a forecast, and expect a
local node to be single-core-bound rather than network-bound.

All of it is resumable, and none of it needs watching: every long command
writes checkpoints and continues from them when re-run. One command per
artifact directory at a time: a scan and a merge on the same directory
exclude each other, and the second one is refused while the first holds
the directory's `.lock`.

**Reaching your node.** Two flags, and neither carries a secret. `--rpc` is the
node's URL and defaults to `http://127.0.0.1:8332`; `--cookie-file` is the path
to the `.cookie` your node writes in its data directory (`~/.bitcoin/.cookie`
on a default mainnet setup), read from the file when the command starts and
read again if the node answers 401 (Core rewrites the cookie at every restart),
so it stays current and never appears in `ps`. If the node lives on another machine,
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
nodsig reuse prepare --out <locks-dir> --height <S> /path/snapshot.dat
```

`--height` is the height `dumptxoutset` reported (or `--headers <headers-dir>`
once that archive exists, which reads it off the chain): the lock set is
sealed with the moment it describes, and the first command that meets the
snapshot's block checks the claim.

Then **one pass over block history**. This is the only long step that talks to
the node, and the two [co-emission](GLOSSARY.md#co-emission) flags feed every other artifact from it, which
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

An archive written under the earlier `graph-v1` seal is not read by this
release: 2.0.0 reads and writes one format per artifact, and an artifact of an
earlier format is read with the release that wrote it (the CHANGELOG names
it). `index build` refuses a `graph-v1` seal as a parent by name rather than
sealing an ancestry nobody can rederive from these formats.

`--nonces` costs about 60 GB and roughly 10% of this pass's CPU, measured rather
than guessed, and records every signature's nonce point with the height that
published it. Two signatures of one key over two different messages that share a
nonce hand out that key to anyone who noticed, so what this sorts together are
the candidates for that, already public and already computable rather than a
future risk. Candidates, because the census sees points and not `s`: a point
also repeats when one signature is copied onto a second input, and telling the
two apart takes re-reading the blocks. It is the one addition here that a later
pass could not reconstruct: the artifacts kept afterwards hold no unlocking
data. Seal it with `nodsig nonces merge`, then read it with `nodsig nonces
groups`. To ask the same question about one of your addresses, `nodsig nonces
address` joins the index, the derivatives and your node on the outpoint:
[`nonce-check.md`](nonce-check.md) is the walkthrough.

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
for; each comes with a sealed sidecar (`<csv>.meta.json`) that names its grid
and, for the reuse curve, the locks and the perimeter it was burnt under.
The reuse curve is a survivorship series over the snapshot: row `H` is the
coin spendable at the snapshot whose key was already public by `H`, not how
much reuse happened by then. `archive curve` is the archive's own: how many
points and scripts the chain first revealed per window of heights, needing no
locks and therefore no snapshot and no node. `curve dates` puts calendar dates
on either of them, offline, from the co-emitted headers.

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

For a whole wallet rather than one address, `--address-book book.json` takes a
list in named groups, each claimed as `separate` or `watching`, and the report then
also says which of your addresses the chain already ties together and whether
the separations you meant to keep are still standing. `--json` writes the
complete form of the same answer for a tool to read. Both formats are
documented — [`AddressBook-v2`](formats/AddressBook-v2.md),
[`CheckReport-v3`](formats/CheckReport-v3.md) — and the page that explains
how to read a report with two perimeters in it is
[`exposure-check.md`](exposure-check.md).

### The direct questions, once they exist

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
screen what the [ordinal](GLOSSARY.md#ordinal-tx-ordinal-output-ordinal) coordinates buy.

One table takes one more flag. `reuse stats`, the distribution of value
across the exposed locks (median, Gini, the value bands), reads a checkpoint of
hit bitmaps: `archive derive --checkpoint <dir>` writes them from this road,
to the same fingerprint `reuse scan` would have written, so the table no
longer needs the second road.

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
outlives the tens of gigabytes it came from. What deleting the census costs is not the
answer but the future: a later append can no longer notice that a signature at
the chain tip reuses a nonce from years ago, because the single sighting it
would have matched is gone. Keep it if you intend to watch the chain forward,
delete it once you have the CSV if this was a one-time question.

**`<archive>/proof/` is not optional if you intend to grow the archive.** It
is the larger half of the archive directory (57.9 GB of the 111.8 measured on a
3.0.x run), no query reads it, and deleting it looks harmless — but `archive
scan` refuses to extend an archive whose proof is missing, because the proof
is what lets a later run decide a candidate the same way the first one did.
Delete it only if this height is the last you will ever ask about, and keep
in mind that rebuilding it means the whole scan again.

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

[`ARTIFACTS.md`](ARTIFACTS.md) is the map behind this sequence: what
each artifact is, which command produces it, which ones read it, how large it
gets, and, the part worth reading before you start, **which parts you can
skip** depending on the question you came for.

[`build-and-query.md`](build-and-query.md) is this same sequence with
the reasoning taken out: the commands in order, what each one costs, the audits
worth running afterwards, and the four places where doing things in the wrong
order costs a rebuild. It ends with every command the tool has, the reading ones
included, so it is both the page to keep open while a build runs and the list of
what you can ask once it is done.

## Checking a sealed artifact

**Checking a sealed artifact.** `index`, `derived`, `archive`, `headers` and
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
[`formats/RevealArchive-v4.md`](formats/RevealArchive-v4.md).

The 1.x releases had a third check, `archive v1-digests`, that confronted an
archive with the one *published* in July 2026 by projecting it back to that
first layout. It is gone with 2.0.0: the filter this version adds changes what
the archive collects, so no projection of a new archive can reproduce those
numbers, which stay reproducible with the release that wrote them. Two builds
of the same release are confronted by fingerprint.

## Running it at chain scale

Two costs are properties of the formats, not accidents of the implementation.
Both are invisible on a test chain and unmissable on the real one.

**A fusion wants headroom.** Fusing an index generation, or an archive, writes
a new generation, commits it, and only then deletes the old one. Plan for free
space of roughly the size of what is being fused, on top of what it already
occupies; for the FIRST `archive merge` after a scan that is the whole run
pile, about twice the sealed size (`merge` prints both numbers and refuses,
before writing, if the space is not there). That is the price of the guarantee: a machine killed mid-fusion
leaves the previous generation whole, and the artifact is never in a state that
has to be believed.

**An append re-reads the spend side once, whole.** A new block can spend an
output written years earlier, so the record for that output changes below
wherever a previous run stopped: a resuming scan cannot seek, it partitions.
Each append cycle therefore makes one sequential pass over `spender_of.bin` and
keeps the edges whose spender belongs to it. The cost is per append **run**, not
per block: appending a day of blocks in one run costs one pass, appending them
one at a time costs one pass each. Batch them.

**Going back is cheaper than rebuilding.** `index rewind` and `derived rewind`
take a sealed artifact to a height it already covered, into the same bytes, and
therefore the same fingerprint, a build that had stopped there would have
written. Removing records from a sorted file leaves it sorted, so this is one
filtering pass per file plus a re-seal, not a second chain walk. It is what
makes an append reversible: extend now, come back to a published height when
you want to reproduce the number that was published with it.

Per-step times and sizes are in the build sequence above, and the artifact map
in [`ARTIFACTS.md`](ARTIFACTS.md) carries the same figures per
artifact.

## What a run has exercised, and what only the tests have

The test suite runs on synthetic chains built in-process: it covers
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
