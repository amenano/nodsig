# Checking one address, on a machine that talks to nobody

Spending a coin publishes the public key that guarded it. Before the first
spend an address is a hash and the key behind it is nobody's business; after
it, the key is on the chain forever. "Has this address's public key already
appeared?" is therefore a question with a definite answer, and it is the
question this page is about, end to end: what you have to keep on disk, what
the run looks like, and what the answer does and does not mean.

Many people are asking it now for one particular reason, so let it be said
plainly at the top: **nodsig measures a fact about the chain, it does not
assess a risk.** Whether a revealed key is a problem, and on what horizon,
depends on cryptography and on timelines that are not in this repository.
"Exposed" is an observation, not a warning, and "protected" is not a
certificate.

## What you need on disk, and nothing more

**One artifact: the revelation archive.** Not the index, not the derivatives,
not the graph, not the snapshot, not the locks. The archive is a sorted set of
every digest the chain has ever revealed, in three partitions, and a lookup is
a membership check inside one of them.

Measured on the real artifact at height 957,301:

| Partition | Records | Size | Consulted for |
|---|---|---|---|
| `archive_keys.bin` | 1,613,342,055 | 33.9 GB | `1…` (P2PKH) and 20-byte `bc1q…` (P2WPKH) |
| `archive_scripts20.bin` | 976,147,552 | 20.5 GB | `3…` (P2SH) |
| `archive_scripts32.bin` | 986,793,535 | 32.6 GB | 32-byte `bc1q…` (P2WSH) |
| **whole archive** | **3.58 billion** | **86.9 GB** | |

**An address kind consults exactly one partition.** That is the mapping in
`check_addresses.KINDS`, and it has a consequence worth knowing before you size
a disk: if the addresses you care about are single-key ones, which is what a
modern wallet hands you, the file that answers them is `archive_keys.bin`
alone, **33.9 GB** of the 86.9. A Taproot address (`bc1p…`) needs no file at
all: the program *is* the key, so the answer is settled by the encoding.

Keeping one partition instead of three costs you one thing, and it is worth
being precise about what. The archive's canonical fingerprint is computed over
all three category digests in a fixed order, so a partial copy cannot
reproduce it. But `manifest.json` records a `sha256` **per category**, so the
file you kept is still verifiable on its own terms, which is the check that
actually covers the lookup you are making.

## The run

> **Transcript pending.** The block below is re-taken from the build this
> release describes; until then the fingerprint and the per-line heights carry
> a placeholder.

```console
$ nodsig check --archive <archive-dir> --stdout \
      1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa \
      12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX \
      bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
# exposure: reveal-archive-v2 (confirmed blocks 1..957,301, sealed aacaf02dca2fc5ba8532e54fa75159041fc99051efa68eb63e59bc9537369ced)
# history: not configured (pluggable: outpoint-index derivatives (--index + --derived))
# co-inputs: not configured (pluggable: outpoint-index derivatives (--index + --derived))

1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    p2pkh: EXPOSED (by reuse)
    seen inside a revealed script (co-signer exposure counts)
12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX
    p2pkh: PROTECTED until first spend
    not revealed in confirmed blocks up to height 957,301
bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
    p2wpkh: EXPOSED (by reuse)
    key seen in a witness

caveats (the perimeter of every answer above):
- off-chain exposure is invisible here: an xpub shared with a service
  exposes descendant keys without any on-chain trace;
- a P2SH/P2WSH address hides its script until it spends: "protected"
  speaks of the hash, not of who could spend behind it;
- perimeter is CONFIRMED blocks up to the stated heights: a spend
  sitting in the mempool has already revealed its keys.
```

Three public addresses, real archive, **under a second** including the
interpreter start, with the files on a network mount rather than a local disk.
The banner names the artifact that answered, the range of blocks it covers and
the exact bytes that were read, and each exposed line ends with the height the
key was first seen at, which the archive records per digest. This page keeps
the output it actually got rather than an edited prediction, so it is re-taken
whenever the artifacts are rebuilt.
A lookup is a binary search over a sorted file: about 35 seeks on a 34 GB
partition, and fewer when the search ladder is present. Nothing is loaded into
memory, so the cost does not grow with how much of the archive you keep.

The first line of the report is the point of the whole design: the answer names
the artifact that produced it, the range of blocks it covers, and the
fingerprint of the exact bytes that were read. Somebody else who repeats the
build to the same height gets the same fingerprint, and can therefore repeat
your answer rather than take it.

## Nothing leaves the machine

`check` contacts the node only when you pass `--rpc`, and it has no other
network path: no flag, no call, no lookup. Without that flag the program opens
two things, the archive files and your terminal.

That makes the air-gapped procedure the obvious one. Copy the archive (or the
one partition you need) onto removable media, carry it to a machine with no
network, clone this repository there, and run the command above. The addresses
you are curious about never exist outside that machine, which is the difference
between this and typing the same address into a website: the website learns
which addresses interest you even when it answers correctly.

One file wants care. Without `--stdout`, `check` writes its report to
`check-results.txt`, and that file lists **your** addresses. It is the only output
in this project that is not safe to share, it is excluded from version control,
and it is the reason `--stdout` is opt-in rather than the default. It is created
readable by its owner alone, whatever your umask says, and so is the `--csv`
file: on a machine with more than one account the usual default would hand your
questions to every other login.

Two disclosures are left, and both are yours to make rather than the program's
to prevent:

- **an address typed on the command line is in `argv`**, which every other local
  account can read for as long as the run lasts, and in your shell's history
  afterwards. That is the same argument the manual makes about credentials, and
  it applies to the questions as much as to the secrets. `--file <path>` takes
  one address per line and keeps them out of both.
- **`--rpc` tells your node which addresses you asked about.** The balance comes
  from one `scantxoutset` call, so the node learns the list. That is fine when
  the node is yours and the point of running one; it is worth a thought when the
  node belongs to somebody else, is hosted, or is reached across a network you
  do not own. Without `--rpc` the question is answered from files alone and the
  node is never told anything.

## Inheriting an archive instead of building one

Building the archive means one pass over block history against your own node,
about three days on a slow setup. You may not want to pay that, and you do not
have to: the archive is a function of public chain data, contains nothing about
the machine that built it and nothing about what anyone ever looked up in it,
so it is safe to publish and safe to accept.

What you should not do is accept it on someone's word. Check it:

```sh
nodsig archive verify --archive <archive-dir>          # bytes, ladders, fingerprint
nodsig archive verify --archive <archive-dir> --deep   # …and every record
nodsig archive v1-digests --archive <archive-dir>      # …and against the published v1 numbers
```

The first re-reads every byte against the manifest, rebuilds each search ladder
from the file it indexes, and recomputes the fingerprint from what is actually
on disk: that number is what you compare with a published one. The second adds
a pass over the records, which is the only thing that can say an archive is
*well built* rather than merely unrotted, and it holds the claimed watermark to
the highest height its records prove. It reads the archive a second time, which
on a full one is not free, and it is worth it once when you accept an archive
from someone else.

The third confronts the archive with an *older* published one: it strips
everything this format gained since v1 (the first-seen height, the count of
keys inside a script, the key's serialized form) and prints one sha256 per
category over what is left, which must be the digest the sealed v1 archive
recorded for that category. Same chain, different code, one number each: it
costs a read and it is the cheapest statement anyone can make that two
independent builds of this archive describe the same history.

The recipe both follow is written out in
[`formats/RevealArchive-v2.md`](formats/RevealArchive-v2.md), for anyone who
would rather check by hand or from another implementation.

## What the answer means, and what it does not

Three answers, and the difference between them is the point:

- **EXPOSED**: the preimage this address is guarded by has been seen on the
  chain, in a confirmed block at or below the stated height. The detail line
  says where it was seen, which matters, see below.
- **PROTECTED until first spend**: it has not been seen, up to that height. Not
  "safe": one spend changes it, and a spend already sitting in the mempool has
  already changed it without being counted here.
- **UNDETERMINED**: no archive was plugged in, so the question was not answered
  at all. It is not a negative, and the tool refuses to let it read like one.

Four boundaries, all of them narrower than people assume:

- **A lock is one scriptPubKey, not a wallet.** The answer speaks about the
  exact script this address encodes. Another address of yours, derived from the
  same seed, is a different lock and gets its own answer.
- **Off-chain exposure is invisible.** An xpub handed to a service exposes
  descendant keys with no on-chain trace at all, and nothing in this repository
  can see that.
- **The perimeter is confirmed blocks**, up to the watermark the report prints.
- **Some addresses are exposed by construction**, and no archive is consulted
  for them: P2PK outputs carry the key itself, and a Taproot output *is* a key.

The most interesting case is the one the example above happens to land on. The
first address comes back exposed **inside a revealed script**, which means the
key became public through a transaction that was not a spend of that address:
someone else revealed a script containing it, as a cosigner or under another
face of the same key. This is exactly why the project keeps an archive of
revelations rather than only a history of locks. It is also the one case that
stays undated, because the archive stores digests and not heights: the event
that exposed the key is not in your lock's history, so there is nothing to date
it against.

## One more check you can add: shown, or given away?

The check above is complete for the question it asks. There is a stronger one you
can ask of the same chain, and it is worth knowing it exists even if you stop
here: exposure says the key is **public**, and a *repeated nonce* would mean it
is **computable**. An exposed key waits on cryptography that has not arrived; a
key that signed twice with one nonce can be worked out today, by arithmetic, and
could have been since the second signature confirmed.

nodsig can check that for a single address, and it is deliberately not folded
into the check above, because it costs a different order of things: the outpoint
index and its derivatives instead of the archive, and **a call to your own
node**, since no artifact keeps unlocking data and the signatures exist only in
the blocks. So it is not the offline, one-artifact check this page is about. It
stays private (blocks are fetched by height from your own node, so no address
leaves the machine); what it gives up is *offline*, not *privacy*.

If you want it, [`nonce-check.md`](nonce-check.md) is that page: what it needs,
what the answer means for a single-key lock and why it means less for a multisig
one, and why an address that has never spent cannot have the problem at all.

## If you also want the dates

The yes/no needs the archive alone. Dates need the outpoint index and its
derivatives, which is another 439 GB (248.5 + 190.5 at this height) and about
64 hours of building. What they buy is the lock's story in order:

```console
$ nodsig derived history --index <index-dir> --derived <derived-dir> \
      --lock b2b81d4e9ff14d85c2d393558da7d0b620e3960d
lock b2b81d4e9ff14d85c2d393558da7d0b620e3960d — 16 outputs, 17 events, index through height 957,301
  height    57,043  2010-05-22  IN   +10,000.00000000  a1075db5…d48d:0
  height    57,044  2010-05-22  OUT  -10,000.00000000  a1075db5…d48d:0 spent by cca75078…4d79
  height   352,701  2015-04-19  IN   +0.00010000  2c63ac6d…b112:0
  …
```

So the spend that put the key on the chain is dated, not merely known. For the
exposure question by itself, this is optional.

## Where to go next

- [`../README.md`](../README.md) for the build sequence that produces the
  archive, and what the rest of the pipeline is for.
- [`ARTIFACTS.md`](ARTIFACTS.md) for the artifact map, including which parts
  you can skip.
- [`gallery.md`](gallery.md) for what the other commands print.
- [`formats/Nonces-v2.md`](formats/Nonces-v2.md) for the census of nonce points,
  what a repeated one means, and what it deliberately does not cover.
