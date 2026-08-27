# What the commands print

Everything below is real output from the artifacts sealed at height 957,301,
with the files on a network mount rather than a local disk, so the timings are
a pessimistic case rather than a flattering one. Nothing here is a mock-up, and
nothing here contacted a node: these are lookups in files.

> **Which artifacts these are, stated up front.** They were sealed by 1.0.0 and
> 1.1.0, so they are `outpoint-index-v2`, `outpoint-derived-v2` and
> `nonces-v2`. Version 1.2.0 **reads all three** — that is what the transcripts
> below show — but it **emits** `outpoint-index-v3`, `outpoint-derived-v3` and
> `nonces-v3`, which are different bytes and therefore different fingerprints.
> A file name in a transcript (`spends_g0002.bin`) is the v2 name for that
> reason. See [the changelog](../CHANGELOG.md) for what moved and what it
> costs; this page will be re-shot from v3 artifacts once they exist.

The output is text and CSV. The figures further down are what a plotting
script makes of those CSVs; nodsig does not draw, it counts. The two on the
nonce census and the two on prices come with the script that drew them.

## An outpoint, from creation to spend

The didactic window on the whole design. Give it a transaction id and an output
index, get everything the chain knows about that coin.

```console
$ nodsig index lookup --index <index-dir> \
      a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0
index covers heights 1..957,301
a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0
  created  height 57,043 (2010-05-22 18:16 UTC)
  value    10,000.00000000 BTC (1,000,000,000,000 sat)
  lock     hash160(scriptPubKey) b2b81d4e9ff14d85c2d393558da7d0b620e3960d
  spent    height 57,044 (2010-05-22 18:26 UTC) by cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79
```

That is the pizza, and it took 4.5 seconds. Two binary searches and two record
reads over a 248 GB index (the v2 pair this was measured on; the v3 index is
230): the txid becomes an ordinal, the ordinal is a
position, and the spend was resolved once at build time instead of being hunted
for now.

## What was spent together, and what it cost

```console
$ nodsig derived cospends --index <index-dir> --derived <derived-dir> \
      a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d
a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d (height 57,043) spends 131 output(s) together:
  f2e83235b8f466c5044ba1f6a0cc63d110cf292db22d299f9b3a898d9fe326fe:0  150.00000000 BTC  lock 34e6a0c0f7f188a3b3c798cde706794e5b777413
  5b22c03c9427334f61f57fb0714a8eb1f3a0b073c6a5310f873f86f534dd34f1:1  0.01000000 BTC  lock 34e6a0c0f7f188a3b3c798cde706794e5b777413
  ce806910ce4804de564a9b2a3704b57b0c87c7517ca2a5012e3b6aa9563dcc7b:0  0.01000000 BTC  lock 34e6a0c0f7f188a3b3c798cde706794e5b777413
  …
```

The trailing line of that report is a warning, not a footnote: co-spent inputs
are a common-input *hint*, the same spender rather than proof of the same
owner, and a CoinJoin breaks the assumption outright.

```console
$ nodsig derived fee --index <index-dir> --derived <derived-dir> \
      a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d
a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d: fee 99,000,000 sat (0.99000000 BTC)
```

A fee is inputs minus outputs, which sounds trivial and is not: it means
resolving every input to the output it spends, over the whole chain. The
derivatives do that once, at build time, and here it costs one read.

## A lock's whole story, in order

```console
$ nodsig derived history --index <index-dir> --derived <derived-dir> \
      --lock b2b81d4e9ff14d85c2d393558da7d0b620e3960d
lock b2b81d4e9ff14d85c2d393558da7d0b620e3960d — 16 outputs, 17 events, index through height 957,301
  height    57,043  2010-05-22  IN   +10,000.00000000  a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0
  height    57,044  2010-05-22  OUT  -10,000.00000000  a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0 spent by cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79
  height   352,701  2015-04-19  IN   +0.00010000  2c63ac6d71e696dea43ef1ef7fba8c376a6a220383e73a17ba6c3795996db112:0
  height   474,237  2017-07-04  IN   +0.00100000  62104aa084f4a158cb9aa545ee30d68db88bb22d4a66904b78d41e4512c1969a:0
  height   547,057  2018-10-23  IN   +0.00001111  6e05c708d88cc5bf0f1533938c969de2cc48f438b0ae28ce89fefbaa1938185a:0
  height   615,962  2020-02-04  IN   +0.00141482  1318b899852c8ecd4c7ff4c540ea469e36b15f781ca517a94168da72b68e427d:0
  …
  height   864,522  2024-10-07  IN   +0.00001010  881db2b47fe09f6cad8361bd95a8daffc797e72705043eb8f3006aed084ffd73:0
```

The pizza address, still receiving tribute payments fourteen years later, in
nine seconds. Every event carries its height **and** the block's timestamp,
which is what makes an exposure dateable rather than merely known.

## Was this digest ever revealed, and where

```console
$ nodsig archive lookup --archive <archive-dir> 62e907b15cbf27d5425399ebf6f0fb50ebb88f18
archive covers heights 1..957,301
62e907b15cbf27d5425399ebf6f0fb50ebb88f18: REVEALED — keys (inside a redeem script)
```

Half a second, on 87 GB. Note *where*: that key did not become public by
spending its own coins, it surfaced inside somebody else's revealed script. The
per-address form of this question, with its perimeter and its caveats, is
[`exposure-check.md`](exposure-check.md).

That answer was printed by the build that sealed the archive quoted at the
foot of this page, and the record has gained two fields since: the line now
carries the height the digest was **first** seen at, and, for a key pushed in
the 65-byte serialization, that it was uncompressed. The shape of the answer
is in [`formats/RevealArchive-v2.md`](formats/RevealArchive-v2.md); this page
keeps the output it actually got, and will be re-taken from the next build
rather than edited into a prediction.

## Where a build got to

```console
$ nodsig index stats --index <index-dir>
phase: sealed   heights 1..957,301
  transactions    1,393,498,473
  outputs         3,819,356,162
  inputs seen     3,417,883,234
  spends_g0002.bin          3,417,883,234 records
  txid_index_g0001.bin      1,393,498,471 records
  overwritten txids: 2, duplicate spends: 0, unresolved: 0
fingerprint: 338c6c48f6e6c806c6d0a494bb9ca5060adcb83167c0db45328d39b40b14a69d
```

Instant, because it reads the manifest and nothing else. The two overwritten
txids are the BIP30 duplicate coinbases of 2010, and the fact that the index
counts them rather than tripping over them is why `rewind` refuses a cut that
would fall between the two instances of one.

## The whole reuse picture, from a small CSV

`archive derive --curve` writes one row per height step, and every row carries
its own fingerprint. Reading it back is arithmetic on a few kilobytes:

```console
$ nodsig curve deltas curve.csv
checkpoints: 96  span: ..957,301
cumulative:  reuse >= 5,084,725.41 BTC (8,784,364 locks)
  p2pkh      3,925,128 locks   >=     1,185,751.57 BTC
  p2sh       1,155,896 locks   >=     1,283,224.01 BTC
  p2wpkh     3,612,318 locks   >=     1,924,332.48 BTC
  p2wsh         91,022 locks   >=       691,417.35 BTC

top 5 intervals by newly revealed locks (diffuse behaviour):
    830,000 →   840,000      294,087 locks   >=     124,214.97 BTC
    870,000 →   880,000      243,162 locks   >=     237,014.60 BTC
    930,000 →   940,000      237,865 locks   >=     261,316.71 BTC
    940,000 →   950,000      230,418 locks   >=     169,205.65 BTC
    580,000 →   590,000      222,634 locks   >=      15,470.90 BTC

top 5 intervals by newly revealed BTC (whale steps):
    540,000 →   550,000       78,334 locks   >=     448,507.87 BTC
    910,000 →   920,000      209,040 locks   >=     391,037.84 BTC
    760,000 →   770,000      123,022 locks   >=     345,958.33 BTC
    930,000 →   940,000      237,865 locks   >=     261,316.71 BTC
    920,000 →   930,000      214,823 locks   >=     247,048.73 BTC

concentration across 96 intervals (how lumpy the timeline of revelation is):
  Gini   BTC deltas 0.688    lock deltas 0.434
  top  5 intervals carry  33.3% of revealed BTC,  14.0% of revealed locks
  top 20 intervals carry  76.4% of revealed BTC,  46.5% of revealed locks
```

Forty milliseconds, and it is the payoff of the three days that came before:
the expensive pass is over, and the questions are now cheap.

## The same numbers, drawn

Two figures from that CSV and from the reuse table, at the same height. They
are here to show the shape of the output, not to argue anything: the reading of
these numbers, with the caveats a chart cannot carry, belongs to the write-up
linked at the bottom.

![All coins in circulation, type by type: bar length is the value held by that
type, the filled part the value with its key in view (hatched = exposed by
construction)](figures/ledger-map.svg)

*From `census` (the floor: P2PK and Taproot, exposed by construction) and
`archive derive --locks` (the filled part: locks whose key the chain has
already shown).*

![BTC spendable today whose key was revealed by the block on the x-axis, by
lock type](figures/reuse-curve.svg)

*From `archive derive --curve` for the series, and `curve dates` for the
calendar years, which is the one step here that asks the node for something
files cannot hold.*

## Which nonce points repeat, over the whole chain

```console
$ nodsig nonces groups --nonces <nonces-dir> --limit 6

nonce groups over heights 1..957,301 (3,727,721,550 signatures)
  5,149 points sighted at least 2 times, accounting for 2,570,875 sightings beyond the first
  of those, 3 have a tiny r (2,552,833 of those sightings beyond the first): a point
  whose top bytes are zero, a shape a drawn nonce lands on about once in 2^24. What
  that means for a point is not decided here
  1 span BOTH schemes: the same nonce point appears under an ecdsa and a schnorr signature
  5,146 are candidates only a block re-read can resolve: compare the public keys of the
  signatures they name

point (12 B)                   count  schemes        heights                  tiny
00000000000000000000003b   2,552,755  ecdsa          364,767 x8 …             yes
00006fcf15e8d272d1a995af       7,900  ecdsa          364,929 x8 …
809edb01f5931cc992763731         998  schnorr        757,922 x8 …
79be667ef9dcbbac55a06295         287  ecdsa          296,149 298,481 x6 298,505 …
1206589b08a84cb090431daa         265  ecdsa          296,115 296,122 296,160 x2 296,245 …
2ef0d2ae4c49c37703ba16a3          91  ecdsa          296,580 x8 …
… 5,143 more (raise --limit, or use --csv for all of them)
```

Two numbers, never one, and the top row is why: one point accounts for 2.55
million of the 2.57 million repeated sightings, so a report that quoted only
the second would describe a single construction as an epidemic.

`x8` is a run: that point was published eight times in the block named, which
is the interesting part of the row and the reason the column collapses runs
rather than repeating a height.

The fourth row is worth a look. `79be667ef9dcbbac55a06295…` is the
x-coordinate of the curve's **generator**, so `r` came from `k = 1`: 287
signatures, from height 296,149 to 828,160. Nothing here interprets that, and
nothing has to: it is twelve bytes compared with a public constant.

## Resolving them against the blocks

```console
$ nodsig nonces witness-verify --witness <witness-dir> --nonces <nonces-dir>

ok  5,149 point(s) re-resolved from the rows themselves
          471  exposed
        1,209  distinct-keys
          209  one-signature
            1  prefix-collision
        3,259  undetermined
ok  witness.bin
..  coverage 121,343..957,290 taken on trust
ok  parent nonces-v2 8aa19fba72a482958b61ddc6ef315fec40a275237d705f8e85cd15a8df8da8a1
fingerprint verified: 7d4823f419306ff4b25757e47e365498cb8f3d165361b8ecc82ed0cf47ab5bf8
```

The audit does two separate things and prints both. The digests prove the
file has not rotted; re-deriving every resolution from the rows proves it
still *means* what it meant, which is the part a checksum cannot say. Passing
the census confronts the declared parent instead of taking it on trust.

The largest number is `undetermined`, and it is meant to be first thing seen:
for most repeated points the signer is not identifiable from the input, so
none is guessed.

## What the repeated nonce points turn out to be

Two more figures, from two CSVs the tool writes. Same rule as the two above:
they show the shape of an output, and the reading of these numbers belongs to
a write-up rather than to a chart.

![Bars, widest first: undetermined 3,259, distinct-keys 1,209, exposed 471,
one-signature 209, prefix-collision 1](figures/nonce-resolutions.svg)

*From `nonces witness-verify --csv`. The bar worth looking at is the first
one: for most repeated points the signer is not identifiable from the input,
so no resolution is given and none is guessed.*

![Bar chart on a log scale: 4,261 points seen twice, falling away to a single
point seen 2,552,755 times](figures/nonce-group-sizes.svg)

*From `nonces groups --csv`. Almost every repeated point is a pair; one
constructed value from 2015 accounts for millions of sightings by itself,
which is why a report has to count points and sightings separately.*

Both were drawn by [`tools/plot_nonces.py`](../tools/plot_nonces.py), which
reads those two CSVs and writes the SVG with nothing but python3. No number in
either figure is typed in: they are the artifacts' own output, which is the
only footing on which a picture belongs in a repository that asks to be
checked rather than believed.

## What it was worth, block by block (requires a price series)

Nothing on the chain holds a price, so nothing above needed one. This
section is the exception, and it is built differently from the rest of the
page in two ways that are worth stating before the numbers.

First, the **artifacts**: these were read from the **v3 index and
derivatives at height 957,301**, not from the v2 set the transcripts above
were shot on. Same chain, same height, different formats; the fees and
coinbase values are the same facts either way.

Second, the **external input**. One price series was fetched on
2026-08-21, imported with `price import`, and turned into a block price
table by `price build`:

- **CoinMetrics community data**, daily `PriceUSD`, licensed *CC BY-NC
  4.0*, fetched 2026-08-21, digest
  `fc97f61f72694fe6a5fc8554ebb230147d01a48a41a72563a69c7afb0f6d7a3c`;
- the block price table built from it, digest
  `11b8a0241deef68827fcce4ca73d57c32c4adaccb8cc4429d96fa1a2f6247589`.

An earlier revision of this page combined an hourly exchange series with
this one. The figures now rest on the daily series alone, so that every
USD number below stands on one publisher's data under one stated license;
what that costs is granularity (a block's price is its UTC day's, never
finer) and coverage (the blocks after the series' last day are unpriced
rather than guessed), and both costs are visible in the output rather
than smoothed over.

These are **digests, not fingerprints**: they name a file, and nobody can
rebuild that file from the chain. They are quoted here for the one reason a
digest is worth quoting: so that a reader who fetches the same series can
tell in one line whether they are holding the same input. The figures and
the USD columns below are derived from that publisher's data and are
published under **its** terms, not under this repository's license; a
series fetched later may differ where its publisher corrected the past, and
nothing here can say whose the difference is. The rule and its limit are in
[`external-inputs.md`](external-inputs.md).

```console
$ nodsig derived supply --derived <derived> --index <index> --price <blockprice>

supply identity over heights 1..957,301 (genesis is not in the index: its 50 BTC are outside every total here)
  coinbase    20,354,467.43715143 BTC
  subsidy     20,054,018.75000000 BTC
  fees           300,477.64560047 BTC
  unclaimed           28.95844904 BTC in 1,124 block(s) that claimed less than subsidy + fees
  ok  coinbase <= subsidy + fees on every block
  fees           4,425,115,735.65 USD over 882,267 priced block(s), block by block; 75,034 block(s) had no price (161.67056235 BTC of fees not converted)

per halving epoch:
              heights     blocks             tx          fees BTC      coinbase BTC       subsidy BTC   unclaimed BTC  fees/coinbase            fees USD     priced
          1–209,999      209,999      9,344,204          8,918.06     10,508,858.01     10,499,950.00     10.05648817  0.0008           81,714.31    141,220
    210,000–419,999      210,000    132,046,965         38,448.49      5,288,448.34      5,250,000.00      0.14820867  0.0073       11,485,664.83    210,000
    420,000–629,999      210,000    387,700,343        163,370.98      2,788,352.23      2,625,000.00     18.75033220  0.0586    1,036,308,705.11    210,000
    630,000–839,999      210,000    461,937,631         79,511.40      1,392,011.40      1,312,500.00      0.00000000  0.0571    2,630,963,262.18    210,000
    840,000–1,049,999    117,302    402,469,330         10,228.71        376,797.46        366,568.75      0.00342000  0.0271      746,276,389.22    111,047

USD figures rest on an external input: blockprice digest 11b8a0241deef68827fcce4ca73d57c32c4adaccb8cc4429d96fa1a2f6247589, series coinmetrics-community fc97f61f72694fe6.... A series fetched later may differ where its publisher corrected the past.
```

The left of that table is the issuance identity, checked on every block
and needing no price. The two columns on the right are what a price adds:
the same fees, converted **block by block** (each block's fee at that
block's price) and summed. The epoch that paid the most coins in fees is
the third; the epoch that paid the most money is the fourth, with half the
coins. The first epoch is mostly unpriced: the series starts in July
2010, at height 68,780, and the 68,779 blocks before it are counted apart
rather than priced at anything. The same exclusion holds at the other
edge: the series' copy ends on 2026-05-23, and the 6,255 blocks after its
last answering observation are counted, not converted.

![Dots on a log scale, one per difficulty period, rising from a few cents
at height 68,780 to around one hundred thousand USD; the eras before the
first observation and after the last are shaded as having no price, and
the halvings are dashed verticals](figures/price-by-height.svg)

*From `derived supply --price --csv` and the block price table. The x-axis
is the **height**, not the date: the chain's clock is the height, and the
header time is only how a price was attached to each block, to within a
day. The halvings are drawn because they are heights. The shaded edges are
exclusions, not zeros: where the series has no observation at or before a
block's header time, the block has no price.*

![Two panels of five bars each, one per halving epoch: fees in BTC peak in
the third epoch, fees in USD peak in the fourth](figures/fees-by-epoch.svg)

*The same fees in two units. Nothing is typed in: the USD bars are the
per-epoch sums of the `fees_usd` column the command writes.*

Both were drawn by [`tools/plot_price.py`](../tools/plot_price.py), which
also prints the one measurement behind the second figure: what each
epoch's total would be if its fees were multiplied by the epoch's **mean**
price instead of being priced block by block.

```console
  epoch      priced/blocks        fees BTC    block by block     by mean price  difference
      0   141,220/209,999         8,918.06            81,714            47,113     -42.34%
      1   210,000/210,000        38,448.49        11,485,665        13,192,538     +14.86%
      2   210,000/210,000       163,370.98     1,036,308,705       947,602,306      -8.56%
      3   210,000/210,000        79,511.40     2,630,963,262     2,620,547,976      -0.40%
      4   111,047/117,302        10,228.71       746,276,389       871,460,435     +16.77%
```

That column is why the table exists. Fees and prices move together inside
an epoch, so a total taken through an average price is off by an amount
that depends on *how* they moved: 42% in the first epoch, 17% in the last
one, under half a percent in the third. None of those is an error in the
series; they are the difference between a number computed where the chain
puts it and a number computed afterwards.

## The whole history, folded into five figures

`derived timeline` is the statistical scan `history.bin` was laid out for:
one sequential pass over every row, folded into two small CSVs of
aggregates (balance bands per checkpoint; outputs, satoshis and age
weights per (creation window, spend window) cell). The command and the two
files are described in [build-and-query.md](build-and-query.md). The five
figures below are drawn from those two CSVs at height 957,301, sealed by
1.9.0. The first two need no price; the last three read the priced pass
and rest on the external input the previous section stated. No number in
any caption is typed in: each is the CSVs' own output, and where an
independent total exists the figure is checked against it.

### Balance bands over time

![Stacked bands: all unspent BTC at each checkpoint, split by the size of
the balance holding it, closing at 20.05 million BTC at the
tip](figures/timeline-balance-bands.svg)

**What you see.** All unspent BTC at each sampled height (one every 10,000
blocks, plus the tip), split by the size of the balance sitting on each
lock at that height. A lock holding 3 BTC contributes its 3 BTC to the
"0.1–10 BTC" band; bands group decades of satoshis.

**How it is built.** One pass over `history.bin`. A lock's balance at a
height is what it had received minus what it had spent up to that height;
between two events the balance is constant, so every sampled point is
exact. The stack at the tip re-adds to 20,053,989.79 BTC, total coinbase
minus total fees: the supply identity met from an independent road.

**Not in the picture.** Clustering. A lock is one exact scriptPubKey, not
a wallet and not a person. Distribution charts published elsewhere usually
group addresses into entities first; this one deliberately does not, so it
reads "how balances distribute across locks", never "how many whales". It
also includes ~151 BTC the node no longer tracks (the two
BIP30-overwritten coinbases and unspendable outputs).

### HODL waves (unspent value by age band)

![Stacked bands: the same unspent BTC split by how long each output had
been sitting unspent, darkest for the oldest coins, axis closing at height
949,999](figures/timeline-hodl-waves.svg)

**What you see.** The same unspent BTC, split by how long the output
holding it had been sitting unspent; "HODL waves" is the name this family
of figures goes by elsewhere. Light bands are young coins; the darkest
band is value that had not moved for more than 400,000 blocks (about 7.6
years).

**How it is built.** From the timeline's windows table: every output ever
created falls in a (creation window, spend window) cell, so at the last
height of each 10,000-block window both the unspent set and every age are
exact. Ages are counted in blocks (52,560 blocks is about one year) and in
whole windows, never in calendar days.

**Not in the picture.** Self-transfer guessing. "Moved" means the output
was spent: coins moving to a change output count as moved, and no
heuristic tries to undo that (figures elsewhere often do, silently). The
tip window is partial, so the axis ends at height 949,999; ages carry the
10,000-block resolution. Coin-age destroyed (CDD) is not drawn either: it
stays available as a formula over the windows CSV, not as a gallery
figure.

### Realized cap

The three figures below add the one thing the chain does not hold, a
price, and they inherit its terms. A figure derived from a price series is
governed by that series' license, whatever the repository's: these three
rest on the Coin Metrics community daily series (*CC BY-NC 4.0*, the same
input, same digest, as the section above) and are published under those
terms. To hold the same figures under terms you choose, bring your own
series and rebuild; the result is then governed by your source's license,
which you evaluate.

```console
nodsig price import     --from yours.csv --out series/ ...
nodsig price build      --index index/ --out blockprice/ --series series/
nodsig derived timeline --derived derived/ --index index/ --out out/ --price blockprice/
```

![One line on a log scale rising to 1,086 billion USD at height 949,999,
dollar labels written out](figures/timeline-realized-cap.svg)

**What you see.** At each sampled height, the sum of every unspent output
priced at what it was worth **when the output was created, that is, when
the coins last moved into their current resting place, not when they were
first issued**: coins mined in 2010 but moved in 2021 count at the 2021
price. Published elsewhere as "realized capitalization": the aggregate
cost basis of the coins at rest, as opposed to market cap (today's price
times supply). Log scale, labels written out. At height 949,999: 1,086
billion USD.

**How it is built.** From the priced pass of `derived timeline`: each
output's value times the block price of its creation height, read from the
block price table the previous section quoted, digest and all.

**Not in the picture.** Unpriced coins. Outputs created before the first
price observation (height 68,780) or after the last carry no price and are
left out: 1.56M of the 20.03M unspent BTC at the last point. The figure
states its own coverage instead of pretending it is total.

### Realized price and market price

![Two lines on one log axis: the market price and, mostly below it, the
realized price](figures/timeline-realized-price.svg)

**What you see.** Two prices in USD per BTC on one log axis, labels
written out. Amber: the market price at each sampled height. Blue: the
"realized price", realized cap divided by the priced unspent BTC, the
average creation-time price of the coins at rest. Where blue sits far
below amber, the resting coins were created much cheaper than the market
asks today.

**How it is built.** The realized side comes from the timeline's priced
windows; the market series is the same one the price-by-height figure
draws: same series, same digest, not a third source.

**Not in the picture.** A valuation model. The two series answer different
questions (what the market asks now vs what the resting coins cost when
created); their ratio is a fact about the chain's history, not advice. The
realized side averages over priced coins only.

### The same two series, from height 450,000

![The same two price lines from height 450,000 on, four decades of the log
axis instead of eight](figures/timeline-realized-price-recent.svg)

**What you see.** The same two series as the figure above, from height
450,000 on (2016→): four decades instead of eight, so the recent half is
readable at a glance.

**How it is built.** Identically to the figure above: same sources, same
resolution; only the axis window changes.

**Not in the picture.** Anything the figure above does not already
declare; this is a crop, not a new reading.

## Reproducing any of it

The build sequence is in the [README](../README.md).

The artifacts these numbers come from are the **first published set**: height
957,301, sealed by 1.0.0 and 1.1.0. Their fingerprints are recorded here once,
as a historical reference and as a worked example of what a fingerprint looks
like and what it covers:

- revelation archive: `aacaf02dca2fc5ba8532e54fa75159041fc99051efa68eb63e59bc9537369ced`
- outpoint index: `338c6c48f6e6c806c6d0a494bb9ca5060adcb83167c0db45328d39b40b14a69d`
- outpoint derivatives: `44689372f169a5c503bdf128a082c31fef767e35c77696e8e60843b42afa1c80`
- transaction graph: `a014f787256e1831c90290e04c2adbcf1fe00cfc3f2d26bb668bff491aa54190`
- header archive: `6af1fed6c48f59461efefbb0868a2e002fcfb68cb7fd578a10fca2b538cbe5d4`
- nonce census: `8aa19fba72a482958b61ddc6ef315fec40a275237d705f8e85cd15a8df8da8a1`
- nonce witness table: `7d4823f419306ff4b25757e47e365498cb8f3d165361b8ecc82ed0cf47ab5bf8`

Rebuild to height 957,301 **with the version that sealed them** and you should
find them again, byte for byte. That is the whole claim of this project, and it
is checkable rather than persuasive.

The qualification is not a softening, and leaving it out would have been the
dishonest move. Three of those seven — index, derivatives, nonce census —
belong to formats 1.2.0 no longer emits, so rebuilding with 1.2.0 reproduces
the other four and produces **new, equally reproducible** fingerprints for the
three. The promise was always "same input, same version, same bytes"; it never
was "the bytes never change", which would have meant a format that can never be
corrected.

### This list is not updated, and that is the policy

**No other document in this repository cites a fingerprint as something to
check against, and none will.** A fingerprint is a fact about one build, at one
height, under one set of formats: every rebuild retires it, and a repository
that quotes it in five places gets five chances to be wrong and no way to
notice. We had exactly that problem, which is how this paragraph came to be
written.

What replaces it is not less checkable, it is checkable at the right moment:
every build **prints** its fingerprint, every artifact **records** it in its own
`manifest.json`, `verify` **recomputes** it from the bytes on disk, and the
declared parent lets a consumer confirm the chain graph → index → derivatives.
None of that goes stale, because none of it is a copy.

What stays here is what a frozen number is actually good for: a worked example,
and the historical record of the first publication. The other one in this
repository is the same species — the three v1 digests in
[RevealArchive-v2](formats/RevealArchive-v2.md), published in July 2026 by a
build predating the format, which `archive v1-digests` confronts a fresh scan
with. Both are anchors to a moment. Neither is a promise about the next build.

What the rule rules out is **copies**, not a list. A single document naming
known artifacts — height, formats, fingerprint — for somebody who wants to
confront a download against something is the opposite of scattering, and would
have one honest property this page cannot have: it would say what it covers,
and admit it can never cover everything. There is no such document yet.

---

Four of the figures (the ledger map, the reuse curve and the two nonce
figures) first appeared, with the analysis they belong to, in
[*Bitcoin and quantum computing: the data, July
2026*](https://liberlume.com/en/bitcoin-and-quantum-computing-data-july-2026/).
They are reproduced here under this repository's license. The two price
figures and the five timeline figures were drawn for this page; those that
rest on a publisher's series (the two price figures and the three priced
timeline figures) are published under that publisher's terms, stated in
their own sections.
