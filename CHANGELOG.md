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
numbered 1.1.0 is not a discrepancy. Artifacts are identified by their
fingerprint, never by a tag.

## Unreleased

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
