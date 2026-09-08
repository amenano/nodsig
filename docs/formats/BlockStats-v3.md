# BlockStats-v3: format (L1)

One row per block, aggregated from the graph in one sequential pass:
transactions, edges, tiles, value created, and, from this version, what the
block created that no key can ever spend. Read by nothing in the toolkit
but a person and a plotting script; built by `blockstats build`, verified
by `blockstats verify`.

- **Files** `<out>.csv` and `<out>.csv.meta.json`
- **Defined over** one `graph-v2`, sealed (the parent) or still growing (then
  no parent is declared, and the meta says so)
- **Parent** the graph, by fingerprint, declared in the meta; a graph seal
  that stops short of the stream is refused as parent
- **Supersedes** `block-stats-v2`, which this release neither reads nor
  reproduces

## The columns

```
height,time,n_tx,n_inputs,n_outputs,value_created_sats,n_unspendable,unspendable_sats
```

The first six as in v2. The two new ones count, per block, the outputs that
are **provably unspendable** by the rule the reference node applies when it
builds its UTXO set: a scriptPubKey that begins with `OP_RETURN`, or one
longer than 10,000 bytes. Such an output is never in the node's UTXO set and
is never spent; the index and the derivatives record it like any other
output, because they record outputs and not spendability. These two
columns are what reconciles the two counts: at any checkpoint `H`,

    unspent(H) - sum over h <= H of unspendable_sats(h) - 100 BTC

is the supply the node counts, the 100 BTC being the two coinbases BIP30
overwrote, which are counted once in each of the index-side artifacts and
never by the node. `derived supply` and `derived timeline` cite this page
where they print `coinbase` and `unspent`.

The pass reads every scriptPubKey verbatim, which is the one thing the
graph keeps that no index-side artifact does; the same pass, asked to, can
write beside the artifact the sets of P2SH and P2WSH programs ever created,
which is how the reveal archive's shape-filter exception is counted
([`RevealArchive-v3`](RevealArchive-v3.md)). Those sets are working files,
not part of this artifact.

## The meta

```
identity:  { format: "block-stats-v3", coverage: {from: 1, to: H},
             files: [ {name: "csv", sha256} ] }
fingerprint: the shared recipe
build:     { producer, seconds, wall,
             parent: null | { format: "graph-v2", fingerprint, coverage },
             rows, totals: { n_tx, n_inputs, n_outputs, value_created_sats,
                             n_unspendable, unspendable_sats },
             rule: "OP_RETURN as the first byte, or a scriptPubKey longer
                    than 10,000 bytes, as the reference node's IsUnspendable",
             reconstruction: "aggregate each graph block record into one row" }
```

## Canonical fingerprint

The shared recipe of [`Artifact.md`](../contracts/Artifact.md), over the
one logical file `csv`, with the tag `block-stats-v3`. Two derivatives of the
same graph bytes take the same name; the parent is in `build`, outside the
identity.

## Verifying

`blockstats verify` compares the size and the digest of the CSV with the
identity, recomputes the fingerprint, and, given the graph, confirms the
parent by recomputing the graph's identity and comparing coverages.

## Constants, for a porter and for the test that pins this page

| name | value |
|---|---|
| columns | `height,time,n_tx,n_inputs,n_outputs,value_created_sats,n_unspendable,unspendable_sats` |
| unspendable rule | first byte `0x6a`, or length > 10,000 |
| identity tag | `block-stats-v3` |
| parent tag accepted | `graph-v2` |
