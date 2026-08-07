# AddressBook-v1: format (input)

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
- **a claim** — who a compartment belongs to. "A and B are linked" asks
  you nothing; the evidence is on the chain. "A and B still look
  separate" says nothing at all unless somebody claimed they were meant
  to be: two random addresses are trivially unlinked.

## The document

```json
{
  "format": "address-book-v1",
  "groups": [
    {
      "label": "cold",
      "claim": "mine",
      "addresses": ["bc1q…", "1…"],
      "provenance": {
        "source": "descriptor",
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

**Top level.** `format` (required, exactly `"address-book-v1"`) and
`groups` (required, at least one). Nothing else.

**Group.** `label` (required, non-empty, unique in the file), `claim`
(required, exactly `"mine"` or `"watching"`), `addresses` (required,
non-empty list of strings), `provenance` (optional object).

- `"mine"` — **you control them**. A statement of yours, which this tool
  cannot verify (that would take a signature) and which does not claim
  the set is complete;
- `"watching"` — **somebody else's; tell me if they touch mine**. Not a
  second-class group: links *towards* it are searched and reported like
  any other. What changes is that an unclaimed group takes no part in
  the separation sentences, because nobody claimed a separation.

**Provenance.** Every field optional, every field **reported as your
claim** and verified by nothing: `source` (`descriptor` | `wallet-export`
| `manual`), `descriptor_checksum` (the 8 digits of `getdescriptorinfo`,
which identify without containing), `script_type`, `chain` (`receive` |
`change` | `both`), `range` (two integers), `gap_limit`,
`derived_at_height`, `derived_by`.

**Order is meaning.** The list order is preserved: when it comes from a
descriptor, the position *is* the derivation index, so the report can
say "the 17th receive address" without the format carrying one more
field.

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

Inside v1 the reader's rule is the strict one: **unknown keys are
refused**, because here it is you mistyping. That is the opposite of
[CheckReport-v1](CheckReport-v1.md), where a reader should ignore keys it
does not know, because there it is us adding them. Anything that would
change the meaning of a key here is `address-book-v2`.

## Minimal example, public addresses only

```json
{
  "format": "address-book-v1",
  "groups": [
    {"label": "example", "claim": "watching",
     "addresses": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                   "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"]}
  ]
}
```

Reference implementation: `src/nodsig/address_book.py`; the refusals are
exercised one by one in `tests/test_address_book.py`.
