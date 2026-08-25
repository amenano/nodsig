# Why build artifacts when you already run a node

A fair objection from someone who already keeps a full node: the artifacts cost
roughly what the blocks cost, so why pay for the disk twice, instead of writing
a few lines of code against the node that is already there?

This page answers it point by point. The short version is that the objection
measures bytes and not work: the node stores the chain in the order it happened,
and every question below is a question in some other order.

## 1. What the node can and cannot answer

Bitcoin Core has no index by address or by script. `txindex` maps a txid to its
position and nothing more, and `scantxoutset` reads the **UTXO set**, which is
by definition what has *not* been spent. "Has this key already appeared on the
chain?" is a question about **spent** history, which is exactly what the UTXO
set has discarded.

So the query that objection imagines is not a query. It is a pass over block
history: fetch every block, parse every input, reconstruct every scriptSig and
witness, hash. That pass is in the README's cost table at about **three days**
on a slow setup.

| | one exposure question |
|---|---|
| node plus a script | a full rescan of block history, every time you ask |
| nodsig | ~35 seeks in a sorted file, **under a second**, offline |

One case the script cannot reach at all: a key revealed as a cosigner inside
**somebody else's** script is not in your address's history, because there is no
transaction of yours to look at. Answering it needs an archive of revelations,
not a history of locks.

## 2. What the disk buys: an ordering the chain does not have

The chain is ordered by time. Every question here is ordered by something else:
by lock, by outpoint, by digest, by nonce.

Sorting 3.58 billion digests is the expensive part. The artifact is that
ordering, materialised once instead of recomputed per question. That is also the
rule this project uses to decide whether an artifact deserves to exist: it must
materialise an ordering that is missing, otherwise it is a cache and does not
get built.

## 3. What you actually keep

The ~874 GB in the README is the case where you build everything and keep
everything. What a given question needs is smaller, sometimes zero:

| To ask | Keep | Size at height 957,301 |
|---|---|---|
| A Taproot address (`bc1p…`) | nothing: the program is the key | **0** |
| Exposure, single-key addresses (`1…`, 20-byte `bc1q…`) | `archive_keys.bin` | **33.9 GB** |
| Exposure, any address kind | the whole archive | **86.9 GB** |
| …plus dated history, fees, co-spends | the index and its derivatives | +439 GB |
| Which locks were first spent in a height window | `<firstspend>` (from the derivatives) | +37 GB |
| Which keys were first revealed in a height window | `<firstreveal>` (from the archive) | +37 GB |

The largest artifact, `<graph>` at ~301 GB, answers none of the questions above:
it is the material the index is built from, read only by `blockstats` and by a
rebuild or a rewind of the index. If this was a one-time question, deleting it
reclaims more space than any other single choice.

There is a symmetric point that is easy to miss: once the artifacts exist, every
query in the first three rows is offline, and the node is needed again only to
extend them to a later height, for a current balance, and for `nonces address`.
The blocks, not the artifacts, are the part that can then be shed. That is a
consequence of the table in the README rather than a workflow this repository
tests, and it is not free: a pruned node cannot serve `nonces address` for
spends whose blocks it discarded, and cannot rebuild anything.

## 4. You may not have to build them at all

Every artifact here is a deterministic function of public chain data. None
contains an address you looked up, and none records anything about the machine
that built it. They can therefore be published, handed over, and checked:

```sh
nodsig archive verify --archive <archive-dir>          # bytes, ladders, fingerprint
nodsig archive verify --archive <archive-dir> --deep   # …and every record
nodsig archive v1-digests --archive <archive-dir>      # …and against the published v1 numbers
```

So the cost is not necessarily "three days of scanning plus 87 GB". It can be
"87 GB copied from removable media and verified locally". Determinism is what
makes accepting a file from a stranger safe: you do not trust the sender, you
recompute the fingerprint.

## 5. Three things an ad hoc script does not give you

Independent of speed, and true even for someone willing to rescan every time.

- **The answer is citable.** Every answer names the artifact it came from, the
  height range it covers, and the fingerprint of the bytes that were read.
  Somebody who repeats the build to the same height gets the same fingerprint
  and can repeat the answer rather than take it. A script prints a number that
  only you have seen, and that you cannot reproduce a year later.

- **The answer says when it does not know.** A capability with nothing plugged
  in returns `UNDETERMINED` and names the flag that would settle it. Silence and
  "no" are different answers. The answer also carries its perimeter: an xpub
  shared with a service leaves no on-chain trace, and "protected" for a P2SH
  address speaks of the hash, not of who can spend behind it.

- **It is incremental.** The build is paid once and then extended, which is
  section 6 below. A script starts over every time.

One thing is genuinely unrecoverable if it was not recorded during the scan. The
artifacts kept afterwards hold no unlocking data, so the nonce census cannot be
reconstructed from them, only by scanning the blocks again. Deleting it does not
cost you the answer you already extracted; it costs the future, because a later
append can no longer notice that a signature at the tip repeats a nonce from
years ago.

## 6. Keeping them current, without rebuilding

The days in the cost table are paid once. Running `build` again on a source that
has grown appends to the sealed artifact instead of starting over, and the
result is byte-identical to a build that had gone straight to the new height.
That equality, **append ≡ rebuild**, is a stated guarantee of
[`contracts/Artifact.md`](contracts/Artifact.md), not a hope about the
implementation, and it is what makes the artifacts a thing you keep rather than
a snapshot that ages.

Its mirror is `rewind`, which takes a sealed artifact back to a height it
already covered, into the bytes a build that had stopped there would have
written. Removing records from a sorted file leaves it sorted, so this is one
filtering pass plus a re-seal, not a second walk over the chain. Together they
make extending reversible: follow the tip now, and come back to a published
height when you want to reproduce the number that was published with it.

Two qualifications, because "incremental" is not the same as "free":

- **An append cycle re-reads the spend side once, whole.** A new block can spend
  an output written years earlier, so the record for that output changes below
  wherever the previous run stopped, and a resuming scan partitions instead of
  seeking. The cost is per append **run**, not per block: a day of blocks
  appended in one run costs one pass, the same blocks appended one at a time
  cost one pass each. Batch them. `<graph>` also has to be kept, since it is
  what the index extends from.
- **This path has run on synthetic chains and on small real files, not yet at
  chain scale.** How a scan resumes the spend side across an append is one of
  the things the README's *Status* section lists as covered by tests rather than
  by a run. Until a real append is recorded, treat the cost above as a property
  of the format, which it is, and the wall time as unmeasured.

## 7. Privacy

For most people the real alternative is not a node plus a script, it is a block
explorer. An explorer can answer correctly and still learn which addresses
interest you.

`check` contacts the network only when you pass `--rpc`, and has no other
network path: without it the program opens the archive files and your terminal.
Copy one partition onto removable media, carry it to a machine with no network,
and the question of which coins are yours does not leave that machine.
[`exposure-check.md`](exposure-check.md) has the air-gapped procedure.

## 8. Compared with an address indexer

The serious comparison is not with a script but with an Electrum-protocol
indexer such as electrs or Fulcrum, which also costs tens of GB on top of the
node. Those solve a different problem: script history, to serve a wallet.

| | address indexer | nodsig |
|---|---|---|
| built for | a wallet's own history and balances | questions about the chain as a whole |
| cosigner exposure, other faces of a key | not covered: not in your script's history | covered by the archive |
| reproducible fingerprint of the answer | no | yes, and the artifact it came from is named |
| repeated nonces | no | the census |
| aggregate views (UTXO set by type and age, reuse over time) | no | yes |

## 9. When this is not worth it

- One answer, once, and trusting an explorer is acceptable: build nothing, and
  run `nodsig check` with no artifacts to see what the encoding alone settles.
- You want your wallet's history in order to spend: you want an address indexer,
  not this.
- You want the mempool, the tip in real time, or a risk assessment: nodsig
  measures a fact over confirmed blocks, and deliberately does not assess risk.

## Where to go next

- [`exposure-check.md`](exposure-check.md): the exposure question end to end,
  including the smallest disk that answers it.
- [`ARTIFACTS.md`](ARTIFACTS.md): what each artifact is, who reads it, how large
  it gets, and which parts you can skip.
- [`../README.md`](../README.md): the build sequence and its measured costs.
