# Quickstart: an afternoon, in two exercises

The full build costs days of machine and hundreds of gigabytes, and the
[README](../README.md) states those costs step by step before asking you to
pay them. This page is the smaller first contact: two exercises, one that
answers a question about **today** in well under an hour, and one that walks
**every mechanism of the project** on a slice of the chain small enough to
finish in an afternoon. Both need your own Bitcoin Core node. Neither needs
the disk, or the days.

One thing this page is not, stated up front: a way to analyze the recent
chain cheaply. The artifacts are cumulative by nature, because a transaction
at the tip spends outputs born anywhere in the past, and an index that starts
anywhere but genesis cannot resolve its inputs: no fees, no histories, no
co-spends. "Just the last year" is not a smaller build, it is the full build.
The cheap slice is therefore the **early** chain, where blocks are nearly
empty. What it buys is not current data but the working experience of every
command, verification included, before you decide whether the full build is
worth your disk.

## Exercise one: the UTXO set as of today

The census is the exception to the cumulative rule: it does not walk the
chain, it reads a snapshot of the UTXO set exactly as your node holds it now,
so its numbers are current by construction.

```sh
bitcoin-cli dumptxoutset /path/snapshot.dat    # the node writes it; Core 28+
nodsig census /path/snapshot.dat --csv census.csv
```

One streaming pass over the snapshot: about 18 minutes at height 957,301 on
the machine of the README's table, after the minutes to an hour the node
takes to write the snapshot itself. It prints a summary and writes a CSV:
for every script type, how many coins stand and how much value they hold,
split by the height they were created at, per halving epoch and per
50,000-block range. Aggregates only, by construction: no address and no
single coin appears in the output, so the CSV is shareable as it is.

That is a real, current dataset from one command: how today's standing value
distributes across lock types and ages. Keep the snapshot's reported height;
if you later decide on the full build, `--end <that height>` is what makes
the scan and the census answer about the same chain.

## Exercise two: the whole machine, on the first 200,000 blocks

Heights 1..200,000 end in September 2012. The whole stretch is on the order
of two gigabytes of raw blocks and a few million transactions, which is why
this slice is the one that fits in an afternoon: the same sequence the README
describes at full height, at a small fraction of the cost.

A note on the numbers here, in this repository's own terms: the times below
are **projections from rates measured at full height** (the README's table),
not measurements of this slice. Once you have run it, `nodsig report` prints
what yours actually cost, read from the manifests the builders sealed, and
that figure is the one worth quoting.

### Build

```sh
H=200000

nodsig archive scan --rpc http://127.0.0.1:8332 --cookie-file ~/.bitcoin/.cookie \
                    --end $H --archive archive/ \
                    --graph graph/ --headers headers/ --nonces nonces/
nodsig archive merge --archive archive/
nodsig nonces  merge --nonces nonces/

nodsig graph   fingerprint --graph graph/
nodsig headers fingerprint --headers headers/

nodsig index   build --graph graph/ --index index/ --end $H
nodsig derived build --index index/ --out derived/
```

The scan is the only step that talks to the node, and it is bounded by your
wire or by parsing on one core, whichever is slower: minutes to tens of
minutes for two gigabytes, not the 56 hours of the full chain. Everything
after it reads files you now own. The co-emission flags are worth passing
even here, exactly as at full height: `--graph` is what the index is built
from, `--headers` keeps the header chain the scan verified, `--nonces` is
the one record a later pass could not reconstruct.

### Ask

What these commands print at full height, verbatim, is
[gallery.md](gallery.md). At height 200,000 the same commands answer with
what the chain knew then, and the most famous transaction of the era is
inside the slice: the 10,000 BTC pizza, created at height 57,043 and spent
at 57,044.

```sh
nodsig index lookup --index index/ \
    a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0

nodsig derived fee      --derived derived/ --index index/ \
    a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d
nodsig derived history  --derived derived/ --index index/ \
    --lock b2b81d4e9ff14d85c2d393558da7d0b620e3960d
nodsig derived cospends --derived derived/ --index index/ \
    a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d
nodsig derived supply   --derived derived/ --index index/

nodsig archive lookup --archive archive/ b2b81d4e9ff14d85c2d393558da7d0b620e3960d
nodsig nonces  groups --nonces nonces/
```

Two details worth noticing while they print. The pizza lock kept receiving
tribute payments for years, but `derived history` here stops at the two
events of 1..200,000, because an artifact is defined by where it ended; the
full-height transcript in the gallery shows the rest. And the `archive
lookup` line asks about the pizza lock itself: its key entered the chain
with the spend at height 57,044, inside the slice, so this archive already
holds it.

If you want the statistical pass too, it is hours at full height and minutes
here:

```sh
nodsig derived timeline --derived derived/ --index index/ --out timeline/
```

### Verify, then compare

The audits are cheap next to the builds at any height, and at this one they
are nearly free:

```sh
nodsig archive verify --archive archive/ --deep
nodsig index   verify --index index/ --graph graph/
nodsig derived verify --derived derived/ --index index/
nodsig report  --archive archive/ --graph graph/ --headers headers/ \
               --nonces nonces/ --index index/ --derived derived/
```

Then the point of the whole project, at afternoon scale: the artifacts are a
deterministic function of the chain, so **build the same slice again**, on
another machine, another day, or another node, and compare fingerprints.
They must match byte for byte. That is the property the full build has too;
here it costs an afternoon to see it fail or hold.

### What this slice does not contain

The reuse table (`archive derive`) joins the archive with the locks cut from
a UTXO snapshot **at the same height**, and your snapshot is at the tip:
that join belongs to a build whose `--end` is the snapshot's height, which
is the full build. The same goes for any question about the present: this
slice knows September 2012 and nothing after it.

When the afternoon convinces you, the README's cost table is the map for the
real thing. Pick one height and use it everywhere; the artifacts you built
here do not join with it, but every command you just ran is the same.
