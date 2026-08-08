# CheckReport-v2: format (output)

> **Not an artifact.** No manifest, no fingerprint, nothing seals it and
> no nodsig command reads it back. It is here because this directory is
> *the formats we promise stability on*, and this is the one a tool
> written by somebody else will parse.

The complete form of what `nodsig check` found. The text report is for a
person and the CSV is a lossy projection of one row per address; this is
everything.

- **File** `check-results.json` by default, `nodsig check --json PATH`
- **Written by** `nodsig check`
- **Read by** whatever you write
- **Mode** `0600`, like every file that lists somebody's addresses

## The question that governs the document

> For every line the report prints: **was it produced by a check that
> actually ran on this path?**

A per-address answer is hard to misread. An aggregate is not: it sums,
and in summing it loses where each piece came from. The two shapes that
loss takes, and the two rules that answer them:

- a number that adds up answers given **at different heights** without
  saying so → **one perimeter per number**, and the single exception is
  confined to `crossed`;
- a zero that means "nobody looked" and reads as "there is nothing" →
  **a capability that did not answer has `values: null`**, a status and a
  reason. Never zeros.

## Shape

```json
{
  "warning": "this file lists YOUR addresses and what is known about them",
  "format": "check-report-v2",
  "sources":  { "…": "one entry per capability" },
  "coverage": { "…": "what was given, what was checked" },
  "summary":  { "…": "sums, per capability, plus `crossed`" },
  "linkage":  { "…": "three classes, three statuses" },
  "addresses": [ { "…": "one entry per input line, input order" } ],
  "limits":   [ "…the caveats, as stable strings" ]
}
```

Key order is the inverted pyramid, because a JSON also gets read with
`less`. **The order is not semantic**: bind to keys, never to position.

`warning` is the first key and the only redundant one: the text report
carries the same sentence as a comment on line one, a JSON has no
comments, and this is the most pasteable file this project produces. A
warning that lives outside the file does not survive a paste into an
issue.

## `sources`

Every capability the build knows about appears, configured or not — one
that simply vanished with its flag would read as "not relevant here"
instead of "nobody asked it".

```json
"sources": {
  "exposure": {"status": "OK", "id": "reveal-archive-v2",
               "watermark": 957301, "fingerprint": "aacaf02d…",
               "live": false},
  "balance":  {"status": "OK", "id": "bitcoin-core-rpc scantxoutset",
               "watermark": 957412, "fingerprint": null, "live": true},
  "nonce-exposure": {"status": "UNSUPPORTED", "id": null,
                     "pluggable": "nonces-witness-v1 (--witness)"}
}
```

| key | type | value |
|---|---|---|
| `status` | string | `OK` \| `UNSUPPORTED` \| `UNDETERMINED`. **These three, everywhere in this document**: `OK` means the source answered and the answer may well be a definite negative; `UNSUPPORTED` means this source has no such capability, usually because nothing was plugged in; `UNDETERMINED` means partial data that cannot decide |
| `id` | string or null | a format tag (`reveal-archive-v2`), or a role name for a live source (`bitcoin-core-rpc scantxoutset`). **Never a path.** `null` when nothing answered |
| `watermark` | integer or null | highest confirmed height the source covers |
| `fingerprint` | string or null | the canonical fingerprint of a **sealed** source. `null` when the source still holds unfused runs, which is queryable but unsealed and must be reported as such rather than dressed up as sealed |
| `live` | boolean | true when the answer came from a node rather than a sealed artifact, and therefore moves between runs |
| `pluggable` | string | present only on `UNSUPPORTED`: what would plug this capability in, with its flag |

Fingerprints go in **whole**: the text truncates them because a person
reads it, a tool wants the digest. `id` is a format tag or a role name,
**never a path**.

`nonce-exposure` has no `watermark`, and that is deliberate: it covers
the repeated points of one census, which is a **set** and not a range. A
height there would promise a perimeter the table has not got.

## `coverage`

```json
"coverage": {
  "addresses_given": 43, "addresses_checked": 40,
  "addresses_undecodable": 3,
  "groups": [{"label": "cold", "claim": "mine", "addresses": 25,
              "duplicates_removed": 1,
              "origin": {"…": "as given"},
              "origin_attributed_to": "input, not verified"}],
  "wallet_completeness": "unknown to nodsig"
}
```

`wallet_completeness` always says exactly that, and it is not a lazy
field: nodsig does not know how many addresses you did not name and
cannot. `origin_attributed_to` exists because without it, in a JSON,
that block reads like something the tool checked.

| key | type | value |
|---|---|---|
| `addresses_given` | integer | lines read from the input, decodable or not |
| `addresses_checked` | integer | those that decoded, so those the capabilities could answer about |
| `addresses_undecodable` | integer | the difference, kept rather than dropped: a book with three unreadable addresses is a book checked for three fewer |
| `groups` | list | one entry per group, only when an address book was given |
| `groups[].label` | string | as written in the book, **verbatim** |
| `groups[].claim` | string | `separate` \| `watching`, as written |
| `groups[].addresses` | integer | how many after duplicates inside the group were dropped |
| `groups[].duplicates_removed` | integer | present only when non-zero |
| `groups[].origin` | object | the book's `origin` block, **as given** |
| `groups[].origin_attributed_to` | string | always `"input, not verified"`, present whenever `origin` is |
| `wallet_completeness` | string | always `"unknown to nodsig"` |

## `summary`

One group per capability. `input` is the only group without `sources` —
it is not an answer about the chain, it is a count of what you gave.

```json
"summary": {
  "input": {"addresses": 40, "by_kind": {"p2wpkh": 31, "p2pkh": 9}},
  "exposure": {"status": "OK", "sources": ["exposure"],
               "values": {"exposed_by_construction": 0,
                          "exposed_by_reuse": 12, "protected": 28,
                          "undetermined": 0}},
  "balance": {"status": "UNSUPPORTED", "sources": ["balance"],
              "values": null,
              "why": "not configured (pluggable: … (--rpc))"},
  "crossed": [ "…" ]
}
```

When a capability did not answer, `values` is `null` with the reason.
`"exposed_by_reuse": 0` with no archive plugged in would say "I looked
and found no exposure", which is the reassuring lie the whole format is
shaped against. Nothing is lost by the null: the by-construction count,
which comes from the *encoding* and not from the archive, is readable
from `input.by_kind` (`p2tr`).

### `crossed` — the one place a value may have two sources

```json
"crossed": [
  {"name": "exposed_with_balance", "value": 3,
   "sources": ["exposure", "balance"],
   "watermarks": {"exposure": 957301, "balance": 957412},
   "gap_blocks": 111, "direction": "reassuring"}
]
```

- `gap_blocks` is the exact size of the blind spot — a computed fact,
  not a judgement;
- `direction` says which way the number errs if the blind spot bites.
  `reassuring` means the archive is behind the node, so a key revealed
  in those blocks still reads as protected while its balance is current.
  **Erring on the reassuring side has to be said out loud**;
  `alarming` is the other way round; `none` when the perimeters meet;
- `watermarks` is redundant with `sources` plus the `sources` block, and
  is allowed **here only**, because whoever reads this line must be able
  to judge it without climbing back up.

**No other number in this format may have more than one source.** A new
one that needs two enters `crossed` or does not enter.

## `linkage`

Three classes, and they are not the same claim. Each carries its **own**
status, because `same_key` answers with no artifacts at all while the
other two need the index and the derivatives.

```json
"linkage": {
  "depth_searched": 1,
  "classes": {
    "same_key": {"status": "OK", "findings": [
      {"addresses": ["1…", "bc1q…"], "positions": [0, 7],
       "groups": ["cold", "hot"],
       "evidence": {"fact": "identical 20-byte digest under two encodings",
                    "certainty": "from the encoding, not a heuristic",
                    "source": "address-codec", "perishable": false},
       "observable": {"value": true, "source": "exposure",
                      "at_height": 712004,
                      "why": "the key was revealed by a spend"}}]},
    "common_input": {"status": "OK", "caveat": "common-input is a hint…",
                     "findings": [
      {"addresses": ["bc1qA…", "bc1qB…"], "positions": [1, 4],
       "groups": ["cold", "cold"],
       "hops": [{"bridge_lock": null, "txid": "…", "height": 690112}]}]},
    "payment_arc": {"status": "OK", "findings": [
      {"from": "bc1qA…", "to": "bc1qC…", "height": 700455,
       "means": "A paid B, which is NOT the claim that A and B are one entity"}]}
  },
  "declared_separations": [
    {"groups": ["cold", "hot"], "held": false,
     "broken_by": "same_key", "at_height": 712004},
    {"groups": ["cold", "counterparty"], "held": true, "as_of": 957301,
     "bounded_by": {"depth": 1, "caps_hit": 0, "bridges_not_expanded": 0},
     "note": "a merge is permanent, a non-merge is perishable: …"}
  ]
}
```

- **`same_key` composes two facts of different natures**, so each names
  its own source: the identity comes from the codec (no height, no
  fingerprint, `perishable: false`), while whether an outsider can
  already *see* it comes from the exposure capability and has a height,
  because one spend changes it;
- **`depth_searched` is mandatory.** Depth changes what the result
  *means*, so it travels with the result and not with the command line.
  The default is 1 for a measured reason: the second hop costs about 7 s
  per address against fractions of a second, and the neighbourhood it
  walks is usually a hub;
- **`bridge_fanout` is weight, not a filter.** A bridge shared by 3
  locks is damning, one shared by 900,000 is an exchange. It is shown;
  the reader judges. A hub is not expanded, and the refusal is counted
  in `bounded_by.bridges_not_expanded` — a search that stopped must say
  where;
- **`payment_arc` never breaks a separation.** "A paid B" is not "A and
  B are one entity";
- **`declared_separations` exists only for groups claimed `separate`**,
  and `held: true` is never an attestation: it always carries `as_of`
  and `bounded_by`. The claim is about intended separation and not about
  ownership: see [AddressBook-v2](AddressBook-v2.md).

The three classes, which are three different statements and not three
strengths of one:

| class | the fact | what it does NOT mean |
|---|---|---|
| `same_key` | two addresses are the same 20-byte digest under two encodings | nothing perishable: this one comes from the codec, has no height and no fingerprint |
| `common_input` | coins of two addresses were spent by one transaction | not proof of one owner: a coinjoin is exactly this shape, which is why the class carries a `caveat` string |
| `payment_arc` | one address's coins funded an output of another | **never** that they are one entity, and it never breaks a separation |

Each class carries its own `status` from the same three values as
`sources`, because `same_key` answers with no artifacts at all while the
other two need the index and the derivatives.

## `addresses`

One entry per input line, in input order, each capability naming its own
source once:

```json
{"address": "bc1q…", "kind": "p2wpkh", "group": "cold",
 "exposure": {"status": "OK", "source": "exposure",
              "value": "exposed_by_reuse", "detail": "…"},
 "balance":  {"status": "OK", "source": "balance", "sats": 0},
 "history":  {"status": "OK", "source": "history", "values": {"…": "…"}}}
```

| key | type | value |
|---|---|---|
| `address` | string | as you wrote it, **verbatim** |
| `kind` | string | `p2pkh` \| `p2sh` \| `p2wpkh` \| `p2wsh` \| `p2tr`. What the address decoded to, not what your `origin.script_type` claimed |
| `group` | string or absent | the group label, when an address book was given |
| `error` | string | present **instead of every capability block** when the address did not decode |
| `exposure.value` | string | `exposed_by_construction` \| `exposed_by_reuse` \| `protected` \| `undetermined` |
| `balance.sats` | integer | satoshis at the balance source's watermark |
| `history.values` | object | `received_sats`, `spent_sats`, `unspent_sats`, `outputs`, `first_height`, `last_height` |

The four `exposure.value` keys say what is known about the public key
behind the address, and they are not degrees of a single scale:

- `exposed_by_construction` — the encoding itself carries the key, so
  nothing had to be spent for it to be visible. `p2tr` is the case, and
  it is readable from `input.by_kind` without any archive;
- `exposed_by_reuse` — the key was revealed by a spend, and the archive
  holds the sighting. **It implies the address has spent**;
- `protected` — the archive covers this address's category and has no
  sighting of it. It speaks of the hash and not of who could spend
  behind it;
- `undetermined` — no answer, and none guessed.

`exposure.value` is a **key**, not the printed sentence: the sentence
merges the balance in ("exposed but empty: nothing at stake"), and a
value with two perimeters may live only in `crossed`. An entry that did
not decode carries `error` instead of any capability block.

## What this file never contains

- **no paths.** Not the artifact directories, not the address book, not
  the report itself. The pointer to the file goes to stderr;
- **nothing resembling key material.** No xpub, no descriptor: only a
  checksum, a script type, a gap limit, a height;
- **no score, no threshold, no word of judgement**;
- **no clock.** There is no `generated_at` and there will not be one.
  Heights are this project's clock. What that buys is worth more than a
  timestamp: **two runs over the same artifacts with the same input
  produce a byte-identical file**, so the report can be tested against a
  golden file and yesterday's can be diffed against today's to show only
  what moved on the chain. Whoever wants the date has it from the
  filesystem.

## Compatibility

`format` is exactly `check-report-v2`. Inside v2, **keys may be added;
the meaning of an existing key never changes.** Anything else is
`check-report-v3`. A careful reader ignores keys it does not know — the
only place this project recommends that, and the opposite of
[AddressBook-v2](AddressBook-v2.md), where an unknown key is refused,
because there it is you mistyping and here it is us adding.

**What changed from v1**, which shipped in 1.1.0: in `coverage.groups`,
`provenance` is now `origin` and `provenance_attributed_to` is now
`origin_attributed_to`; `groups[].claim` carries `separate` where it
used to carry `mine`. Both follow the input format
([AddressBook-v2](AddressBook-v2.md)), and both are renames: no value
changed meaning and no number moved.

Reference implementation: `src/nodsig/check_report.py`, with the
aggregation rules exercised in `tests/test_check_report.py`.
