# FirstSpend-v1: format (L0)

When a lock was first spent from, ordered by that moment. The derivatives
([`OutpointDerived-v3`](OutpointDerived-v3.md)) answer it one lock at a time
(`derived history` reads a lock's story and the first spend is in it), but
they cannot enumerate *which* locks were first spent inside a height range,
because `history.bin` is ordered by lock, not by time. This table
materialises that one missing order.

- **Directory** `<firstspend>/`: `firstspend.bin`, its ladder, `state.json`,
  `manifest.json`
- **Defined over** one sealed `outpoint-derived-v3`, and no other
- **Read by** `firstspend between` (and `stats`, `verify`)
- **Built by** `firstspend build`, a read of the derivatives alone: no node,
  no graph, no index at build time
- **Parent** the derivatives it was built from (`outpoint-derived-v3`),
  declared in the manifest under its own tag, never under the one the
  building code happens to emit

## What one record is

25 bytes, big-endian throughout, one row per lock **ever spent from**:

| field | bytes | meaning |
|---|---|---|
| `spender_tx` | 5 | ordinal of the transaction that first spent an output of this lock |
| `lock` | 20 | the lock: `hash160` of the key or script, exactly as the archive and the derivatives key it |

Rows are sorted by `(spender_tx, lock)`. The search key is `spender_tx`
alone (5 bytes); `lock` orders ties so the file is a total order and two
builds cannot disagree.

## Why the ordinal is the time, and no height is stored

Transaction ordinals are assigned in chain order, so **sorting by
`spender_tx` already sorts by height**: block 1's first transaction is
ordinal 0, and every later transaction has a higher one. Storing a height
beside the ordinal would be a second representation of the same instant,
one more thing to keep consistent across an append and a rewind. A reader
that wants the height asks the parent index's `blocks.bin`, which turns an
ordinal into a height by one positional read: the same translation every
other artifact defers to it.

## Why a lock appears at most once

A lock can be spent from many times; this table keeps only the **first**.
The first spend of a lock never changes once known: an append adds spends
at higher ordinals, and a higher ordinal cannot be a smaller minimum. That
is what makes the row a function of the chain up to the coverage height and
nothing else, and it is what makes the rewind below the cleanest in the
project.

The count of later spends is **not** kept: this table answers "when was it
first revealed by spending", and a lock's full history is already
`derived history`. Two artifacts answering one question is how they begin
to diverge, so there is no verb here for a single lock.

## What "first spent from" covers, and what it does not

It covers a lock **revealed by spending it**: the public key or script
reached the chain because an input consumed an output of that lock. It does
**not** cover a key seen *inside* a revealed script (the co-signer case
that the reveal archive records and `history` does not). This table is built
from `history`, so it inherits `history`'s perimeter, and naming it after
"revelation" would promise the archive's wider one. It is first **spend**,
not first exposure.

A lock created but never spent from has no row: `history` carries it with
the unspent sentinel (`spender_tx = 0`), and this build skips it. Ordinal
`0` is block 1's coinbase, which can never spend, so `0` is never a legal
value in this file and `verify` refuses a row carrying it.

## Size

One row per lock ever spent from, at 25 bytes. On the chain through height
957,301 that is **1,479,497,990 locks of 1,554,718,932 (95.2%)**, so
**~37 GB**, measured rather than projected by counting the spent locks in the
sealed derivatives. The 4.8% never spent from are the unspent balance of the
chain at that height. A porter sizing a disk should scale by spent locks,
which the derivatives' manifest reports as it counts them.

Dropping `spender_tx` into a per-block positional table would take the row
to 20 bytes and 30 GB, at the cost of a second file and a two-step read for
`between`. The 20% is real and the complication is not worth it at this
size; the note is here so the trade is on record, not to invite it.

## Building it

One sequential pass over `history.bin`. Its rows arrive grouped by lock
(it is sorted by `(lock, output_ordinal)`), so a build walks a lock's group,
takes the **minimum non-zero `spender_tx`** in it as the first spend, and
emits `(spender_tx, lock)` when the group closes, or nothing if every spend
in the group is the unspent sentinel. Runs then fuse into the sorted file with
the shared run/merge machinery, and the seal is taken over it.

The value and the receive side of `history` are not read: only the lock and
the spender ordinal decide a row.

## Appendability

When the parent grows, the table is rebuilt from the grown `history`. A lock
that was unspent can become spent, and its first spend is then at whatever
ordinal did it, always **above** the old coverage, because an append only
adds higher ordinals. So a lock already in the table keeps its row unchanged
and a lock new to it enters with its genuine first spend. Rows are a function
of `(spender_tx, lock)` alone, so merging two builds of the same coverage
gives the file a single build would: **appending equals rebuilding**, byte
for byte.

## Rewinding

`firstspend rewind` takes the table back to the coverage its parent
derivatives now hold, the way the derivatives follow the index: there is no
height argument, because this table has never chosen its own coverage. It
drops every row whose `spender_tx` is at or above the transaction count the
parent declares, and keeps the rest untouched. Because a first spend never
moves, no surviving row changes value: this is a fusion with a filter,
without the row mutation `history` needs and without the BIP30 hazard of the
index, which this file has no reason to deduplicate. Rewinding then
rebuilding to the same coverage gives the same bytes.

## Canonical fingerprint

The shared recipe of [`Artifact.md`](../contracts/Artifact.md), over the one
logical file `firstspend`. Coverage is `1..H`, the parent derivatives'
coverage; the parent fingerprint is declared in `build`, outside the
identity, and a reader **refuses** a mismatched parent, because these rows
are keyed by the parent's ordinals and pairing them with another index
answers nonsense with confidence.

## Verifying a sealed table

```sh
nodsig firstspend verify --firstspend <firstspend> [--derived <derived>]
```

Two checks, and the second is the one a checksum cannot make:

- **structural**, over the whole file: rows strictly increasing by
  `(spender_tx, lock)`, and every `spender_tx` below the transaction count
  the parent derivatives declare. This is the pass the seal makes anyway.
- **sampled, against the other road**: for `k` locks drawn from the file,
  the first spend it records must equal the one `derived history` reports for
  that lock, read the long way. It is the only check that confronts this
  artifact with something it did not build itself: the guard whose absence
  was the defect fixed elsewhere in this project, where a check rebuilt its
  own answer and agreed with it.

Passing `--derived` confronts the declared parent instead of trusting it.

## Notes for porters

- everything is big-endian, including the 5-byte `spender_tx`;
- the sort key is `spender_tx`; `lock` breaks ties but is not part of the
  ladder's search. The ladder entry point is the rightmost sample **strictly
  below** the key, because several locks can share one `spender_tx` (a
  transaction that first-spends twenty locks at once), so a group can exceed
  the ladder stride and the walk must start below it and read the whole run;
- `spender_tx = 0` is not a legal row: it is `history`'s unspent sentinel,
  which this file omits rather than stores;
- a row means "first spent from", not "first exposed": the co-signer case is
  out of perimeter, by inheritance from `history`.
