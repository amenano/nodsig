# What a fingerprint proves, and what it does not

Every artifact here ends in a fingerprint, and the README says two strangers can
compare one instead of comparing trust. This page is about the distance between
that sentence and "therefore this number describes the Bitcoin chain", because
the distance is real and a reader who means to cite a figure should know exactly
how much of it the tool covers.

The short version: **nodsig makes a computation repeatable, it does not make it
provable.** There is no succinct proof in any of these files. A fingerprint says
*which* bytes; that those bytes are what the chain contains is established by
building them again, or by comparing with somebody who did. Checking costs
re-execution. Everything below is a consequence of that sentence.

## Three questions that are easy to mistake for one

**Is this file the artifact it claims to be?** That is integrity, and `verify`
answers it completely: every byte re-read against the manifest, every search
ladder rebuilt from the file it indexes, the fingerprint recomputed from what is
on disk. `archive verify --deep` adds that the artifact is *well built*: records
in strictly ascending order, flags the format defines, every first-seen height
inside the claimed coverage, the proof consistent with the scripts. After it you
know you hold artifact `a4b678c5…`, whole and well formed.

**Is that artifact what the chain contains?** That is fidelity, and `verify`
does not answer it. It cannot: a file that leaves one key out, sealed with a
manifest computed over what remains, is internally consistent and passes every
check above. Fidelity has exactly two sources. You build the artifact from your
own node and get the same fingerprint, or you hold a fingerprint published by a
builder who is **independent of whoever handed you the file**, and the two agree.
Determinism is what makes the second one possible: it turns "trust the sender"
into "find a second builder". It does not turn it into nothing.

Stated plainly, because it is the limit of every figure this project has
published: **so far the published fingerprints come from one builder.** Four of
them were reproduced by a second, complete run weeks after the one that sealed
them, by code two majors newer (the changelog's 3.3.0 entry has the list), which
is evidence that the computation is deterministic. It is not evidence from an
independent party, and only somebody else's build can supply that.
[`quickstart.md`](quickstart.md) exists so that doing it on a slice costs an
afternoon.

**Which chain?** A fingerprint over heights `1..H` says nothing by itself about
whose blocks those were. The header archive is what answers: it holds the 80
bytes of every header from genesis, `headers verify` re-derives every id and
every link from them, and it measures the proof of work, adding it up into the
**chainwork** a node prints for the same tip
([Headers-v2](formats/Headers-v2.md) says where that measurement stops, and
why). The tip's hash and that chainwork are the two values to hold against any
node you trust:

```sh
nodsig headers verify --headers <headers>      # prints the tip and the chainwork
bitcoin-cli getblockheader <tip-hash>          # fields `height` and `chainwork`
```

A chain of nearly a million headers carrying that much work is the one figure in
this project nobody could afford to fabricate.

## What is bound to what

Not every artifact reaches the chain by the same road, and the roads are not
equally strong.

| Artifact | Bound to the chain by | Can the binding be re-checked from what is kept? |
|---|---|---|
| `<headers>` | its own hash chain from genesis, and the measured work | **yes**, offline: `headers verify` |
| `<index>` | every block's Merkle root, recomputed from the index's own txids and held against the header | **yes**, offline: `headers crosscheck --index` |
| `<derived>`, `<firstspend>` | the index they name as parent; the derivatives refuse to seal unless two separate walks agree on the satoshis | the parent link, **yes**: `verify` with the parent in hand |
| `<graph>` | the scan's four checks on each block as it is read | the link to the index it fed, yes; the blocks themselves, only by another pass |
| `<archive>`, `<nonces>`, `<firstreveal>` | the scan's four checks, **while reading, and then no longer** | **no**: what they distill is unlocking data, which no artifact keeps |
| `census.csv`, `<locks>` | the UTXO snapshot your node wrote | **no**: nodsig reads the snapshot, it does not re-derive it |
| anything in a currency | a price series from a publisher | it is an external input, named by a digest and never by a fingerprint |

Two rows deserve their sentence.

The **revelation archive**, which is the artifact most worth inheriting, is the
one with the weakest repeatable binding. The scan verifies that each block hashes
to the id it was asked for, that its transactions are the ones the header commits
to, that the witness bytes are committed too, and that it extends the previous
block ([ARTIFACTS](ARTIFACTS.md#what-the-scan-checks-while-it-reads)). Then the
witness is gone, by design, and nothing on disk lets anyone repeat those checks.
An archive is therefore tied to the chain by re-execution alone. The second road,
`reuse scan` with `archive crosscheck`, tests the *method* against an independent
implementation of the walk; it is run by the same builder, so it is evidence
about the code, not a second witness.

The **snapshot** is your node's statement about the UTXO set. `reuse prepare`
seals the block it names and its height, and the first command that meets that
block confronts the claim, so a snapshot cannot be paired with the wrong height.
Its *contents* are taken from the node. `dumptxoutset` prints a `txoutset_hash`
for what it wrote: two nodes dumping at the same block print the same one, which
makes it the value to publish beside a census and to compare before trusting
one.

Parent links are **declared, then confirmed**: a manifest names its parent's
format and fingerprint in `build`, outside its own fingerprint, and `verify`
reports the link as declared and unconfirmed until it is handed the parent. A
publisher who wants a declaration to be binding signs the manifest's
`statement`; [Artifact](contracts/Artifact.md) says why that belongs in a
signature and not inside the fingerprint.

## Three cases, asked by a reader

**The code was modified.** A fingerprint is a function of the bytes and of
nothing else, so modified code that writes the same bytes reaches the same
fingerprint. That is intended: it is how the native kernel is accepted, and how
another implementation would be. `build.producer` records the version and the
commit that built an artifact, and whether the tree was dirty, **as a
declaration**: it is outside the fingerprint and proves nothing. Modified code
that writes different bytes reaches a different fingerprint, and that is all the
tool says. The formats pages and the conformance vectors in
`tests/fixtures/scan/` are what a different implementation is held to.

**The node was a different one.** It makes no difference to an honest build,
which is the point: the fingerprint does not depend on the node, the transport
or the machine. A node that serves blocks which do not hash, do not commit to
their transactions or do not chain stops the scan where it happens. A node that
serves a *consistent other chain* produces a consistent other fingerprint, and
the builder does not learn it from the fingerprint: they learn it from the tip
and the chainwork above, which is why those two values are part of what gets
published.

**The artifact is partial.** Coverage is inside the fingerprint, so an artifact
that stops at another height is a different artifact and says so; `rewind` takes
one back to a height it covered, into the bytes a build stopped there would have
written, which is how two builders at different tips meet on one number. Inside
one artifact, the manifest records a sha256 per file: a copy that keeps one
partition of the archive cannot reproduce the fingerprint, and can still verify
the file it kept ([`exposure-check.md`](exposure-check.md) sizes that case).

## When two fingerprints disagree

This is the honest gap. Two builds that differ learn that they differ, and for
most artifacts the tool does not say where. The graph is the exception: its
state keeps a digest per scan interval, and `--graph-digest` compares a rescan
against them interval by interval. For the others, locating a difference means
holding both artifacts and comparing the sorted files, which the formats make
straightforward and which no command does yet. Nothing has to be sealed in
advance for that: both parties hold deterministic files and can digest any
partition of them after the fact.

## What to publish with a figure, and what to do with one

If you publish a number from these artifacts, publish what lets somebody else
land on it: the **height**, the **tip's hash and the chainwork**, every
**fingerprint** the number rests on (`nodsig report` prints them, and the
ancestry between them), the **release and commit** that built them, the
**perimeter** if you narrowed it, and for anything about the current UTXO set the
snapshot's **`txoutset_hash`**. For a figure in a currency, the price series'
digest and its publisher, since that part cannot be rebuilt from the chain.

If you are handed a number, the order of cost is: compare the tip and the
chainwork with your node (seconds); `verify` what you were given (an hour or
two, and it buys integrity); rebuild the slice in
[`quickstart.md`](quickstart.md) and compare its fingerprints with anybody
else's (an afternoon, and it buys confidence in the method); rebuild the
artifact (days, and it is the only thing that buys fidelity on your own
authority). And whatever this tool tells you about coins that matter, reach it a
second way before acting on it: the README says why that rule applies to this
project as much as to any other.
