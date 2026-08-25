# Changelog

What changed, and — the section no generic changelog has — **what it costs
you**. Updating this tool is free; rebuilding artifacts is not, and the honest
unit for that is hours, not megabytes.

This file exists for a reason particular to this repository: the public history
starts from a single squashed root, so "read the commits" is not an answer
available to anyone arriving from outside.

Three questions are answered under every release:

1. **what changed on the command line** — the promise until the next major;
2. **what changed in the formats**, with the old and new tags;
3. **do your existing artifacts still work?** and if not, **how long it takes
   to rebuild them, in real hours**.

The two clocks of this project stay separate, as
[the README's *Stability* section](README.md) says: the **formats** are the
contract, the **CLI** is convenience, and `reveal-archive-v2` inside a tool
numbered 1.3.0 is not a discrepancy. Artifacts are identified by their
fingerprint, never by a tag.

## Unreleased

### Documentation

- The README no longer opens with a link labeled a manual. The
  walkthrough at liberlume.com is presented beside *Stability* as what
  it is: a worked application of release 1.0.0, pinned at height
  957,301, that does not track this repository; the same link, without
  the expectation that it follows the latest release. The price bullet
  now points at the gallery's price section, and the *License* section
  states the exception the price figures already lived under: they are
  derived from a publisher's series and carry that publisher's terms,
  not MIT. The gallery's closing credit is scoped the same way: four
  figures are reproduced from the July 2026 write-up, and the two price
  figures were drawn for the page itself.

## 1.7.0 — the coinbase's fate, four columns per block

### Command line

- `derived supply --csv` gains four columns, appended after `subsidy_sats`
  and before the price columns: `n_out`, `cb_n_out`, `cb_first_spend_ord`
  (the lowest ordinal among the transactions that spent an output of the
  coinbase; 0 when none has) and `cb_spent_sats`. All four are positional
  reads off the index, one coinbase per block; the rule that decides what
  belongs in that CSV is now written in the command's docstring. Readers
  of the price columns by position must move two columns to the right;
  readers by header are unaffected.

### Documentation

- `docs/gallery.md` gains a section on the price layer, read from the v3
  artifacts at height 957,301: the `derived supply --price` transcript,
  the price of a block over the whole chain against height, the fees of
  each halving epoch in BTC and in USD, and the measurement behind the
  table (a total taken through an epoch's mean price is off by up to 42%
  against the block-by-block sum). Drawn by `tools/plot_price.py` from
  the command's CSV; the series, its license and the digests are named
  beside the figures, which are published under the publisher's terms.
  The section was first shot on an hourly-plus-daily pair of series and
  then re-shot on the CoinMetrics community daily series alone, so every
  USD number stands on one publisher and one stated license. What that
  moved, both ways: per-epoch USD totals shift by at most 1.2% (+0.03%
  over the whole chain), and 6,255 blocks at the tip lose their price
  because the daily copy ends earlier than the hourly one did; the
  first figure now shades the unpriced era at both edges instead of one.

### Do your artifacts still work?

Yes, all of them, with zero rebuild hours. No format moved and no
fingerprint changes: the four columns are positional reads off the index
at query time, the CSV is an output rather than an artifact, and the
figures are documentation. The one thing to check is downstream of you,
not of the artifacts: a script that reads the supply CSV's price columns
by position must move two columns to the right.

## 1.6.0 — a price per block, as an external input

### Command line

- **`nodsig derived supply`**: the issuance identity, coinbase <= subsidy
  + fees, checked on every block, with fees, subsidy, coinbase and the
  unclaimed remainder per halving epoch (or any `--epoch`), and `--csv`
  for the per-block series. It confronts three things no other command
  confronts: the coinbase values in the index, the fees in the
  derivatives, the subsidy schedule. A coinbase above its allowance is
  an error exit.
- `Index.outputs_of_tx(tx_ord)`: a transaction's outputs in vout order,
  the reader the coinbase of a height needed.
- **`nodsig price`**, a new command group for the one thing the chain
  does not hold: a price. `price import` converts a publisher's CSV or
  JSON (a `--preset` for the CoinMetrics community file, or any field
  mapping) into a canonical series identified by a digest; `price build`
  derives **one price per block** from a sealed index's header times and
  the series in order; `price at`, `price daily` (the per-day
  aggregation, each row with its kind: measured, carried, none),
  `price stats`, `price verify` (with the parents, the table is
  recomputed byte for byte) and `price series-verify`. The toolkit
  fetches nothing: you bring the file, under the publisher's terms.
- **`derived supply --price <blockprice>`**: the fees of each epoch in
  the series' currency, computed block by block (fee times the price of
  the block) and never through a day price; blocks without a price are
  counted apart, and the digests the figures rest on are printed under
  the table.

### Formats

- Two new formats, both **external inputs and not artifacts**:
  `price-series-v1` and `blockprice-v1`. They carry a digest, never a
  fingerprint, because nobody can rebuild them from the chain; what that
  means is in `docs/external-inputs.md`. No existing format moved. No
  artifact needs rebuilding, and no fingerprint changes whether or not a
  series is present.

### Cost

- `derived supply` reads `fees.bin` once and one coinbase per block:
  minutes on a local disk, up to an hour on a slow mount.
- `price build` reads the index's block table and the series: seconds,
  and 9 bytes per block on disk (about 8 MB at today's height).

### Do your artifacts still work?

Yes, all of them, with zero rebuild hours. Nothing here touches an
artifact: the price layer reads the index's block table and writes its
own files beside it, and no fingerprint moves whether or not a series
is present. What you cannot inherit from anyone is the series itself:
fetch it under the publisher's terms, import it, and the digest names
exactly what you used.

## 1.5.0 — a fifth artifact: when each lock was first spent

### Command line

- **`nodsig firstspend`**, a new artifact and command group: the first
  spend of every lock, ordered by that moment. The derivatives answer
  "when was this lock first spent" one lock at a time; nothing enumerated
  "which locks were first spent between H1 and H2", because `history.bin`
  is ordered by lock, not by time. `firstspend build` materialises that
  order from the sealed derivatives alone (no node, no graph), and
  `firstspend between --from H1 --to H2` reads a height window as a
  contiguous scan. Also `stats`, `verify` (a shared audit plus a sampled
  second road that re-derives each first spend from the parent's history),
  and `rewind` (follows the derivatives back, dropping rows never
  rewriting them). Its perimeter is history's: first **spent from**, not
  first exposed. Optional; ~37 GB at height 957,301 (the 95.2% of locks
  ever spent from, at 25 bytes each).

### Formats

- **New: `firstspend-v1`.** A 25-byte record, `spender_tx | lock`, sorted
  by the ordinal. No existing format, tag or fingerprint moves; the six
  earlier artifacts verify unchanged.

### Documentation

- The scan's bottleneck is now stated as the slower of two walls, the
  wire to the node or single-core block parsing (~25-30 MB/s, measured),
  with the crossover: a local node is single-core-bound, not
  network-bound. The old line named one regime as the rule.

### Do your artifacts still work?

Yes, all of them, with zero rebuild hours. `firstspend` is purely
additive: a new optional artifact built from derivatives you already
have. Nothing you hold changes, and no fingerprint moves.

## 1.4.0 — the manifest learns to say when

### Command line

- **`archive derive` refuses locks photographed at another block.** The
  reuse table is defined by two moments: the archive's coverage and the
  block the snapshot's locks were taken at. The locks manifest names its
  block by hash and the archive checkpoints the hash at its watermark,
  so the two are confronted offline and exactly; when they differ the
  command now stops instead of printing a table that silently mixes two
  moments of the chain and cannot be told from a right one. The new
  `--allow-base-mismatch` flag crosses the two moments on purpose, and
  the header prints both hashes either way. A derive that used to pass
  on misaligned inputs was reporting a number nobody had defined.
- Progress lines of the three scans print two named rates (the last
  checkpoint interval and the stretch average) instead of one
  ambiguous `blk/s`, and the ETA now extrapolates from the interval
  rate, tagged with the model it assumes.

### Manifests

- **`build.wall`: when, beside how long.** Every seal now records, next
  to `build.seconds`, one `[start, end]` pair of UTC timestamps per
  process stretch that worked on the verb. Durations still come only
  from the monotonic clock; the stamps exist because monotonic can
  drift on virtualized hosts, and confronting the two is what makes
  that drift visible without an externally dated log. `build` stays
  outside the identity, so no fingerprint moves; manifests sealed
  earlier simply lack the field.

### Formats

- Nothing moves. Every format tag reads and writes exactly as in 1.3.0.

### Do your artifacts still work?

Yes, all of them, with zero rebuild hours. No fingerprint changes, no
record moves, and nothing new refuses an old artifact: the one new
refusal (`derive`) is about mismatched INPUTS, not about age, and the
only inputs it stops are pairs that never belonged together. Resuming,
growing or resealing an artifact built by 1.3.0 adds the `build.wall`
field to its manifest and changes nothing else.

## 1.3.0 — a pass that measures itself

### Under the hood

- **The scan now records its own seconds.** `build.seconds` already specified
  what a `scan` entry would mean — including the warning that the four
  co-emitted artifacts each record the *same* seconds and must never be summed
  — but no scan was writing one, so the longest phase of the whole pipeline
  was the one with no measured cost attached to it. It is wired now, in all
  four writers, and the figure accumulates across resumes because the total
  lives in each artifact's state.

  Why that last property is the point: a chain-scale run is not something most
  people can leave running for days without interruption. A scan stopped at
  height 400,000 and resumed reports what it really cost, not what its last
  stretch cost. What is lost is the interval between the last checkpoint and
  the interruption, so the figure is a **floor** — the contract said so
  already, and it still does.

  Nothing about how commands are invoked changes: no flag, no wrapper, no
  special mode.

- **`report` now gives the total, not just the rows.** It already refused to
  add the durations up, because a `scan` co-emits and those rows are one pass
  seen several times. That refusal was right and incomplete: a reader left
  with a table and no total composes one by hand, and the hand-composed one is
  exactly the wrong sum the note warns against. The total is now printed, with
  the co-emitted pass counted once and the sequential phases added — and it
  says which it did.

- **`build-and-query.md` says how to run a pass unattended.** Three things
  that decide whether a chain-scale run is something you can leave: an
  unbuffered durable log (without `-u` an interruption takes the progress
  lines with it, and you know that it stopped but not where), what a kill
  costs and how `--checkpoint-every` moves that trade-off in both directions,
  and where to read the cost afterwards.

### Do your artifacts still work?

**Yes, unchanged.** No format moved, no record width, no fingerprint. An
artifact sealed before this simply carries no `scan` entry, which is the same
"absent where nothing recorded it" the contract already described.

One limit of the field worth stating, since this release is the one that makes
it matter: **a run split across sessions carries the version of the last
process that sealed it**, not of every process that built it. `build.producer`
records one version and one commit — the ones the sealing process ran under.
If a long build spans releases, the manifest names the last, and the honest
way to use that is to keep a durable log beside it. The alternative would be a
list of every revision that touched the artifact, which nothing can verify
after the fact and which would therefore be a field that guesses.

## 1.2.1 — a v2 pair can confirm its own ancestry again

### Fixed

- **`derived verify --index` refused a v2 index.** The parent's manifest was
  loaded with the strict reader, so confronting `outpoint-derived-v2` with the
  `outpoint-index-v2` it declares failed instantly with "unknown index manifest
  format", while every other v2 path worked. Reading a parent to confirm
  ancestry is a read, and now uses the widened set like the rest of them.

  Found by running the audit against the real published artifacts rather than
  against fixtures: the suite covered `derived verify` on a v2 pair, but not
  with `--index`, which is the form that actually confirms anything. The test
  now passes the parent, and fails without the fix.

### Do your artifacts still work?

**Yes, and one more command works on them than did yesterday.** Nothing about
what this version *writes* changed — no format, no record width, no
fingerprint, and an artifact built by 1.2.0 is byte-identical to one built by
1.2.1. Nothing needs rebuilding for this.

## 1.2.0 — the spend side, in one slot per output

### Formats

- **`address-book-v1` → `address-book-v2`** (input, not an artifact). Three
  renames, no value changed meaning:

  | v1 | v2 | why |
  |---|---|---|
  | group key `provenance` | `origin` | `provenance` already names the bits recording where a key was seen inside an input. One word, one job |
  | inner key `source` | `method` | `source` already names who answered a question, in the report's `sources` block |
  | claim `"mine"` | `"separate"` | the value never described ownership, only whether the group takes part in the separation sentences. nodsig cannot know who controls an address, and a value name should not imply it did |

- **`check-report-v1` → `check-report-v2`** (output, not an artifact). Follows
  the input: in `coverage.groups`, `provenance` → `origin` and
  `provenance_attributed_to` → `origin_attributed_to`, and `claim` carries
  `separate` where it carried `mine`.
- **`nonces-v2` → `nonces-v3`.** The census refuses two values ECDSA cannot
  produce, `r == 0` and `r >= n`, so what is collected changes. Reading is
  widened rather than moved: `groups`, `lookup`, `verify`, `resolve` and
  `check` all work on a v2 census, so a census downloaded under 1.0.0 or 1.1.0
  keeps its value. **A v2 census cannot be grown or rewound**, and the tool
  says so: extending it would fuse records the current rules refuse, producing
  a file no rebuild reproduces.
- **`outpoint-index-v2` → `outpoint-index-v3`.** The spend side changes shape.
  `spends.bin` (10 B per edge, sorted by spent output) becomes
  `spender_of.bin`, one **5-byte slot per output** holding the transaction
  that spent it, plus `spend_extra.bin`, which is **empty on a
  consensus-valid chain**. The index loses **15.1 GB** (34.2 → 19.1 for that
  side, ~240 → ~225 GB in total) and one ladder, `spenders()` becomes a
  5-byte positional read instead of a ~40 KB bucket scan, and an append's
  spend fusion moves about **44% less I/O**.

  A slot has **three** states, and the third is the point: `0` unspent,
  `2^40-1` **more than one spender** (the answer is in `spend_extra.bin`),
  anything else the spender's ordinal. A dense array cannot hold two spenders
  in one slot, and refusing to build would have been the easy way out — but
  INVARIANTS names duplicate spends among the anomalies that are *counted and
  reported, never hidden*, and a format that cannot represent an anomaly does
  not declare an assumption, it enforces one. The marker also means the array
  never silently answers wrong: what a reader meets is not an ordinal.

  Reading is widened rather than moved: `lookup`, `verify`, `stats` and the
  whole reader surface work on a **v2 index**, so one downloaded under 1.0.0
  or 1.1.0 keeps its value — there is a test that builds a genuine v2
  artifact and reads it. **A v2 index cannot be extended, rewound, or used to
  build derivatives**, and each of the three refuses by name: mixing the two
  layouts would produce bytes no rebuild reproduces.
- **`outpoint-derived-v2` → `outpoint-derived-v3`**, and the index's
  `outputs.bin` with it: **satoshi fields become `u56`**, 7 bytes instead of 8.
  The whole supply is 2.1e15 satoshis against 2^56 = 7.2e16, so every amount
  that can exist fits with 34× of room. Records go 28 → 27 (`outputs`),
  38 → 37 (`history`), 8 → 7 (`fees`), for about **9 GB** across the two
  artifacts.

  The bound is a consensus fact carrying a layout, not an arithmetic
  impossibility, so it is written into the format text and **every write site
  refuses loudly** instead of truncating: a value past the maximum means the
  source is not consensus data, and the build stops. Big-endian is kept, so
  `memcmp` still sorts and no search changes.

  Reading is widened again: a **v2 derived artifact** still answers `history`,
  `fee`, `cospends`, `verify` and `check` when paired with the v2 index it was
  built from, and a test builds that genuine pair and reads it back. It
  **cannot be extended or rewound** — fusing 38-byte rows into a 37-byte file
  is not a format question but a corruption — and the build says so.
- **unchanged:** `reveal-archive-v2`, `nonces-witness-v1`, `graph-v2`,
  `headers-v2`.

### Do your artifacts still work?

**Every artifact still verifies and still answers questions. What none of the
touched ones can do any more is GROW.** That is the whole shape of this
release: reading was widened everywhere, writing was not, and the two are
different promises.

| you hold | still reads & verifies | can be extended / rewound |
|---|---|---|
| a `nonces-v2` census | yes | **no** — needs a fresh scan |
| an `outpoint-index-v2` | yes | **no** — needs a rebuild |
| `outpoint-derived-v2`, paired with its v2 index | yes | **no** — the build refuses both |
| archive, headers, graph | yes | yes, untouched |

Rebuilding the census means a full chain scan, because it is co-emitted by the
pass that builds the reveal archive: on the last measured run that pass took
**58 h 47**, and it re-emits the archive and the headers with it. The index
then rebuilds from the graph in **24 h 51**, and the derivatives from the
index in **14 h 30**. These are sequential; the honest total for going all the
way to v3 is around **98 hours**, not the sum of the parts you were hoping to
skip.

What the rebuild buys, stated plainly so nobody hurries for the wrong reason:
the nonce rules remove **at most 79 records out of 3,727,721,550** — worth
having for correctness, not for space. The spend side is worth **15.1 GB** and
a faster lookup, `u56` about **9 GB** more: roughly **24 GB off ~596**, which
is 4%. None of it is a reason to rebuild by itself. **The
reason to rebuild is that you want the chain re-scanned anyway**; if you only
query what you already have, this release costs you nothing and you can stay
where you are.

One consequence that is not a byte count: rebuilding **retires the published
fingerprints**. Anyone who cited the current index and derived fingerprints
will need to cite the new ones.

### Under the hood

- **`blockparse` is 1.46× faster**, measured on 200 real blocks from five eras
  of the chain (7.73 → 5.29 microseconds per input), with the parsed
  structures compared field by field and identical. It changes no format and
  no fingerprint; it makes every scan shorter. Roughly 3.6 hours of the 58 h
  47 above.

## 1.1.0 — the check reads a whole wallet

### Command line

- `nodsig check --address-book PATH` — a list of addresses in named groups,
  each claimed `mine` or `watching`
  ([`AddressBook-v1`](docs/formats/AddressBook-v1.md)).
- `nodsig check --json [PATH]` — the complete report, default
  `check-results.json` ([`CheckReport-v1`](docs/formats/CheckReport-v1.md)).
  The text stays for a person, the CSV stays a lossy one-row-per-address
  projection.
- `nodsig check --witness DIR` — the `nonce-exposure` capability, read from a
  `nonces-witness-v1` table: 1 MB read once, offline, for the whole list.
- `nodsig check --linkage-depth N` — how many hops the link search takes.
  Default 1.
- **The text report gained an overview, a links section, and one more caveat.**
  Every capability now appears in the source header lines, configured or not:
  before this, `exposure` and `balance` simply vanished when their flag was
  absent, and a missing line reads as "not relevant here" instead of "nobody
  asked it".
- **The CSV gained a `nonce_exposure` column**, and its columns are now derived
  from the same list the text renders. A tool that pinned column *positions*
  should pin the header names instead.

### Formats

- **new:** `address-book-v1` (input, not an artifact), `check-report-v1`
  (output, not an artifact). Neither is sealed and no nodsig command reads them
  back; they are documented because somebody else's tool will produce or parse
  them.
- **unchanged:** every artifact format. `reveal-archive-v2`,
  `outpoint-index-v2`, `outpoint-derived-v2`, `nonces-v2`, `nonces-witness-v1`,
  `graph-v2`, `headers-v2` are all exactly as 1.0.0 wrote them.

### Do your artifacts still work?

**Yes, all of them, with nothing to rebuild.** No fingerprint moves, no scan is
needed, and every number published for 1.0.0 stands. This release only adds
ways to ask.

### Notes

- `docs/contracts/CoSpendBackend.md` did not change and did not need to: the
  capability already promised the co-spent locks, and it was the *tool* that
  threw them away with a `len()`. The linkage work asks it for membership
  instead — "is any of MY locks among them?" — so a neighbourhood of tens of
  thousands of strangers' locks is never carried around, let alone printed.
- The report has no timestamp, deliberately: two runs over the same artifacts
  with the same input produce a byte-identical file, so yesterday's report can
  be diffed against today's to show only what moved on the chain.

## 1.0.0 — first public release

The four artifacts, their formats, and the commands that build, verify and
query them, with every published number reproducible from the same chain.
Fingerprints and durations are in [`docs/gallery.md`](docs/gallery.md); the
public history begins at the squashed root that carries this release.
