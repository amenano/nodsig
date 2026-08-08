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
- **unchanged:** `reveal-archive-v2`, `outpoint-index-v2`,
  `outpoint-derived-v2`, `nonces-witness-v1`, `graph-v2`, `headers-v2`.

### Do your artifacts still work?

**Every artifact still verifies, and only the nonce census needs rebuilding
to gain anything.** The census you hold is read, audited and resolved by this
version exactly as before; what it cannot do is grow. Rebuilding it means a
full chain scan, because the census is co-emitted by the pass that builds the
reveal archive: on the last measured run that pass took **58 h 47**, and it
re-emits the archive and the headers with it.

What the rebuild buys is small and worth stating plainly: measured on the
sealed census, the two rules remove **at most 79 records out of
3,727,721,550**. They are worth having for correctness, not for space. A
reader who only queries has no reason to hurry.

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
