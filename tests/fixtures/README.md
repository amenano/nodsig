# Conformance vectors

Language-neutral vectors: input → expected output, as hex / decimal / JSON,
with **no dependency on the Python reference runtime**. They are the test of a
port (another language, or a native kernel): run the same files, compare, and
you have proven the two implementations identical — verifiability applied to
porting (see `docs/ARCHITECTURE.md` §5).

`tests/test_conformance.py` runs these against the Python reference, so they
also guard the reference against drift: the docs promise the vectors, and the
reference must keep meeting them.

## What is covered

| directory | primitive | authority |
|---|---|---|
| `hashing/` | `sha256d`, `ripemd160`, `hash160` (hex in → hex out) | published RIPEMD-160 vectors; the `hash160` case is the genesis coinbase key, whose digest is the hash160 of address `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` |
| `compactsize/` | Bitcoin compact-size integer, `value ↔ hex` (both directions) | fixed by the protocol |
| `fingerprint/` | `artifact.canonical_identity` + its fingerprint | recipe stated in full in the fixture and `docs/contracts/Artifact.md` |
| `statement/` | `artifact.canonical_statement` + its digest: the bytes a signature would be over | same recipe document; pinned so two independent signers agree on the target |
| `addresscodec/` | `decode_address` + `script_pubkey`: address → `{kind, digest, script_pubkey, lock, exposure_query}`, plus invalid strings that must be rejected | genesis P2PKH, BIP-173 P2WPKH/P2WSH, BIP-350 P2TR, a known P2SH |

## Vector format

Each directory holds one `vectors.json`. Every file starts with a `note`
describing the recipe in words, then the vectors. Bytes are always **lowercase
hex**; integers are decimal. A port needs only a JSON reader and the primitive
under test — no artifact, no node, no index.

Adding a vector set: create `tests/fixtures/<name>/vectors.json`, describe the
recipe in its `note`, and add a `test_<name>_vectors` to
`tests/test_conformance.py`. Prefer **known-answer** values (published test
vectors, protocol constants, real chain data) over values merely recomputed by
the reference, so the vectors are authoritative and not circular.
