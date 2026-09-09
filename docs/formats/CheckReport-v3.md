# CheckReport-v3: format (output)

The complete form of what `check` found, for a tool to read. Everything in
[`CheckReport-v2`](CheckReport-v2.md) holds unchanged unless this page says
otherwise: the question that governs the document, the shape, the three
statuses, `sources`, `coverage`, `summary` and `crossed`, `addresses`, what
the file never contains. This page is the delta, and the reason for the tag.

- **Supersedes** `check-report-v2`. A reader of v2 that ignores unknown keys
  reads a v3 file correctly for everything v2 said; what v3 adds is not
  expressible in v2, which is why the tag moved.

## Why a v3

Three things the 2.0.0 formats know that the v2 report could not say:

1. a key is a **point**, and `check --key` now asks about the point under
   every face the chain can show it (both serializations, each behind three
   address forms), one of the faces being named by one field square root;
2. a key can be revealed in an **output** (pay-to-pubkey, bare multisig), in
   its **other serialization**, or as an **x-only** key of a taproot script
   path; the exposure reasons name those sightings;
3. the linkage block carries the weight of the evidence with every sentence
   that rests on it: the bridge's fanout is a count of distinct locks, says
   when it is a floor, and travels into the broken separation it broke.

## `keys`

A new top-level block, present only when `--key` was given, one entry per
key typed, in input order. The addresses a key expands to do **not** appear
in `addresses` as if the user had typed them; they are here, under the key.

```json
"keys": [
  {"key": "03…", "given_as": "compressed" | "uncompressed" | "hash160",
   "revealed": {"value": "exposed_by_reuse" | "protected" | "undetermined",
                "first_height": 57043,
                "sightings": ["scriptSig", "other serialization"],
                "source": "exposure"},
   "faces": [
     {"address": "1…", "kind": "p2pkh", "form": "compressed",
      "exposure": {"value": "exposed_by_reuse", "why": "…"}},
     {"address": "3…", "kind": "p2sh-p2wpkh", "form": "compressed",
      "exposure": {"value": "exposed_by_reuse", "why": "key in view; this wrapper never spent"}},
     {"address": "bc1q…", "kind": "p2wpkh", "form": "compressed", "exposure": {"…": "…"}},
     {"address": "1…", "kind": "p2pkh", "form": "uncompressed",
      "derived_by": "one square root mod p", "exposure": {"…": "…"}}
   ]}
]
```

- `given_as: hash160` means the other serialization is **not derivable**
  (a hash is one way), so `faces` holds the three forms of that digest only,
  and `revealed` answers for that digest;
- `derived_by` is present on every face whose serialization was computed
  and not given: it names the one piece of field arithmetic in the project.
  The same sentence is repeated once in `sources` (below) and in `limits`
  whenever a `--key` is present;
- `sightings` are the archive's own words for its flags: `scriptSig`,
  `witness`, `inside a redeem script`, `inside a witness script or leaf`,
  `output`, `other serialization`, `x-only`.

## `sources`

Two additions to the table of v2:

| key | change |
|---|---|
| `id` | the 2.0.0 tags: `reveal-archive-v3`, `outpoint-derived-v3`, `nonces-witness-v2`, …; always the tag of the artifact **read**, never the constant of the code that reads it |
| `key-forms` | a new entry, present only with `--key`: `{"status": "OK", "id": "key-forms", "live": false, "root": "one modular square root per key given: names the other serialization, multiplies no point, verifies nothing, recovers nothing"}` |

## `addresses[].exposure`

`value` keeps its four words. `detail` (the field v2 defined) may now name
the sightings listed under `keys` above, including `published in an output` (a P2PK or bare multisig
output revealed this key before any spend), `seen in its other
serialization` (the point is in view although this exact digest never was
pushed), and `seen as a taproot internal or leaf key`. A script lock whose
script has the shape of a key or of a signature is the archive's one
declared exception, and `why` says so when it applies, with the count the
archive's page publishes.

## `linkage`

The block of v2 with four fields made explicit:

```json
"common_input": {"status": "OK", "caveat": "…", "findings": [
  {"addresses": ["…", "…"], "positions": [0, 3], "groups": ["cold", "hot"],
   "hops": [{"bridge_lock": "…", "txid": "…", "height": 690112,
             "bridge_fanout": 480, "bridge_fanout_is_floor": false}, {"…": "…"}]}]},
"payment_arc": {"status": "OK", "findings": ["…"],
                "bounded_by": {"arc_caps_hit": 0}},
"declared_separations": [
  {"groups": ["cold", "hot"], "held": false, "broken_by": "common_input",
   "at_height": 690112, "via_bridge": true, "bridge_fanout": 480,
   "bridge_fanout_is_floor": false}
]
```

- `bridge_fanout` counts **distinct locks** that co-spent with the bridge,
  the unit every sentence about bridges is written in and the unit the hub
  threshold is compared with; `bridge_fanout_is_floor` is true when the walk
  that measured it hit its cap, so the number is at least that;
- a broken separation carries `via_bridge` and, when true, the bridge's
  fanout and floor flag: a direct co-spend and a two-hop path through a
  480-lock bridge are not the same sentence, and the JSON must let a tool
  tell them apart without walking back to `findings`;
- a direct hop outranks a bridged one for the same pair; among equals the
  lower height wins;
- `payment_arc.bounded_by.arc_caps_hit` counts the addresses whose arc walk
  hit its cap: a search that stopped says where.

## `limits`

One more stable string when `--key` is present, the square-root sentence
above; and one when a script lock met the archive's exception.

## Compatibility

A v2 reader ignoring unknown keys reads everything v2 defined; `format`
says `check-report-v3`, so a strict reader refuses rather than guessing.
`check` writes v3 only.
