# AddressBook-v2: format (input)

> **Not an artifact.** Everything else in this directory is a sealed file
> with a manifest and a fingerprint. This one is written by **you**, read
> by `nodsig check`, and sealed by nobody. It lives here because this
> directory is *the formats we promise stability on*, and that promise is
> the point for anyone writing a tool that produces one.

A list of addresses plus the two things a bare list cannot say.

- **File** one JSON document, given as `nodsig check --address-book PATH`
- **Written by** you, or by a tool that derives addresses from your
  descriptors
- **Read by** `nodsig check`
- **Never read by** anything else, and nothing in it makes anything open

## Why it exists

`check` already takes addresses positionally or one per line with
`--file`, and for the per-address questions that is enough. Two answers
need more:

- **compartments** — which addresses you *meant* to keep apart. That is
  the left half of the report's most useful comparison: intended
  separation against observed separation. A flat list has no
  compartments, so the comparison cannot even be stated;
- **a claim** — whether a compartment was *meant* to stay apart from
  the others. "A and B are linked" asks you nothing; the evidence is on
  the chain. "A and B still look separate" says nothing at all unless
  somebody claimed they were meant to be: two random addresses are
  trivially unlinked.

The claim is **not** a statement of ownership, and the format is careful
about that on purpose. nodsig cannot know who controls an address, that
would take a signature, and a field that asked would be collecting an
answer it can neither use nor check. What you declare is what you
intended about the addresses, never a relationship between you and
them.

## The document

```json
{
  "format": "address-book-v2",
  "groups": [
    {
      "label": "cold",
      "claim": "separate",
      "addresses": ["bc1q…", "1…"],
      "origin": {
        "method": "descriptor",
        "descriptor_checksum": "8rjyrgz9",
        "script_type": "wpkh",
        "chain": "both",
        "range": [0, 999],
        "gap_limit": 20,
        "derived_at_height": 957301,
        "derived_by": "bitcoin core 27.0, deriveaddresses"
      }
    },
    { "label": "counterparty", "claim": "watching", "addresses": ["3…"] }
  ]
}
```

### Top level

| key | required | type | value |
|---|---|---|---|
| `format` | yes | string | exactly `"address-book-v2"` |
| `groups` | yes | list | at least one group |

Nothing else. Any other key is refused.

### Group

| key | required | type | allowed values |
|---|---|---|---|
| `label` | yes | string | non-empty, unique in the file. **It is printed in the report** |
| `claim` | yes | string | exactly `"separate"` or `"watching"` |
| `addresses` | yes | list of strings | non-empty. **Order is meaning**, see below |
| `origin` | no | object | see the next table |

`claim` is the field that changes what the report can say, and it is
worth reading before choosing:

- `"separate"` — **you meant this group to stay apart from your other
  `separate` groups**. That intent is the whole content of the claim: it
  says nothing about who controls the addresses, and it does not claim
  the group is complete;
- `"watching"` — **you claim no separation about this group**. Not a
  second-class group and not less observed: links *towards* it are
  searched and reported exactly like any other. What changes is that it
  takes no part in the separation sentences, because nobody said it was
  meant to be apart from anything.

### `origin`

How you say you got this list. Every field is optional, and every field
is **reported as your claim** and verified by nothing here: the report
renders the whole block attributed (`origin_attributed_to`), never
asserted. The types are checked all the same, because a `chain` of
`"recieve"` would be printed verbatim and read as a fact.

| key | type | allowed values | what it says |
|---|---|---|---|
| `method` | string | `descriptor` \| `wallet-export` \| `manual` | how the list was produced. `manual` is a first-class answer: it says nobody derived these, you typed them |
| `descriptor_checksum` | string | the 8 characters of `getdescriptorinfo` | identifies the descriptor **without containing it**. It confirms a guess only for somebody who already holds the descriptor, and who therefore already holds everything |
| `script_type` | string | free text (e.g. `wpkh`, `tr`, `sh(wpkh)`) | the output type the descriptor produces. Not checked against the addresses: the report shows what each address actually decoded to under `by_kind` |
| `chain` | string | `receive` \| `change` \| `both` | which branch of the descriptor these came from. With `both`, the position no longer maps to a single derivation index |
| `range` | list | exactly two integers | the derivation indices covered, first and last inclusive |
| `gap_limit` | integer | | the gap limit used when deriving. Declarative: nothing here re-derives, so this is context for a person reading the report, not an input to a computation |
| `derived_at_height` | integer | | the chain height at which the list was produced. Useful when the report's own watermark is higher: addresses derived later are not in the file |
| `derived_by` | string | free text | the tool and version. The one place a version string belongs, because it is the thing a future reader will want when a number looks odd |

**Order is meaning.** The list order is preserved: when it comes from a
descriptor, the position *is* the derivation index, so the report can
say "the 17th receive address" without the format carrying one more
field. It is also why `chain: "both"` is worth declaring: with two
branches interleaved, position alone no longer names an index.

## What your choices cause in the report

The two decisions this format asks of you both change what
[CheckReport-v2](CheckReport-v2.md) is able to say. Stated here, because
nobody should have to read the output format to learn what the input
means.

**How you split the addresses into groups** decides the left half of the
report's most useful comparison. `linkage.declared_separations` holds
one entry per pair of groups, saying whether the separation you meant
still holds on the chain. Put everything in one group and there are no
pairs, so there is nothing to compare: the links are still found and
reported, they just answer no question you asked.

**What you claim about each group** decides which sentences exist:

| you write | what the report can say | what it cannot |
|---|---|---|
| `claim: "separate"` on two groups | `declared_separations` for that pair, `held: true` or `held: false` with what broke it and at which height | nothing more: `held: true` always carries `as_of` and `bounded_by`, and is never an attestation |
| `claim: "watching"` | every link *towards* that group, in `linkage.classes`, exactly as for any other | any separation sentence about it, because nobody claimed one |

**What you put in `origin`** decides only the `coverage.groups` block,
which is context and never evidence. Leaving it out costs nothing but
the context.

## What the reader refuses, and why refusing beats guessing

- **an unknown key, at any level.** The rule that looks pedantic and
  matters most: an `"adresses"` with one `d`, skipped in silence, is
  half a wallet left unchecked inside a report that still looks
  complete;
- `format` missing or different;
- `claim` missing, or a value other than the two. An unknown value is
  **not** quietly downgraded to the cautious case: somebody who wrote
  `"theirs"` meaning `"watching"` must read an error, not a report that
  is silent on half its sentences without saying why;
- a repeated or empty `label`;
- a group with no addresses;
- **the same address in two groups.** Not a duplicate, a contradiction:
  nobody can have *meant* to keep an address separate from itself, so
  the file does not describe the compartments it says it describes.

It does **not** refuse, and these look like errors:

- **the same address twice inside one group** — deduplicated, and *how
  many* were dropped is declared in the report;
- **two addresses that are the same key** (one digest, two encodings) —
  a finding, not a mistake. If they sit in different groups, those two
  compartments share a key, and the report says so as a certainty of the
  encoding;
- **an address that does not decode** — not fatal: it appears in the
  report as it always did, and it counts in the coverage, because a book
  with three unreadable addresses is a book checked for three addresses
  fewer.

## What this format deliberately has not

- **no field for an xpub or a descriptor.** A field that exists gets
  filled, and then the file gets pasted into an issue. The checksum
  identifies without containing (and confirms a guess only for somebody
  who already has the descriptor, who therefore already has everything);
- **no file paths.** Nothing in the book makes anything open;
- **no scores, thresholds or words of judgement**, in or out;
- **no per-address note** in v1. Every free-text field is one more place
  for something to end up that then leaves in the report.

> **The labels appear in the report.** Somebody who names a group "my
> mother's account" has just written that sentence into a file they
> might share.

## Compatibility

Inside v2 the reader's rule is the strict one: **unknown keys are
refused**, because here it is you mistyping. That is the opposite of
[CheckReport-v2](CheckReport-v2.md), where a reader should ignore keys it
does not know, because there it is us adding them. Anything that would
change the meaning of a key here is `address-book-v3`.

**What changed from v1**, which shipped in 1.1.0 and is not read by this
version: the group key `provenance` is now `origin` and its inner key
`source` is now `method`; the claim `"mine"` is now `"separate"`.
Nothing else moved, and no value changed meaning.

`"mine"` went for a reason worth stating, because it is the kind of
thing a format teaches without meaning to: it named a claim of
ownership, while the only thing the value has ever governed is whether
the group takes part in the separation sentences. A tool that measures
what the chain shows should not be asking who owns what, and a value
name that says otherwise trains every reader of the file to think it
did. The rename is not cosmetic: in this project `provenance` names
the bits recording where a key was seen inside an input, and one word
doing two jobs in two format documents is how a reader ends up reading
the wrong one (see `AGENTS.md`). `source` moved for the same reason: it
already names who answered a question, in `sources` of the report.

## Minimal example, public addresses only

```json
{
  "format": "address-book-v2",
  "groups": [
    {"label": "example", "claim": "watching",
     "addresses": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                   "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"]}
  ]
}
```

Reference implementation: `src/nodsig/address_book.py`; the refusals are
exercised one by one in `tests/test_address_book.py`.
