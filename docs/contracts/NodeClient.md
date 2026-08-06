# NodeClient — contract (node / live)

**Capability.** Opt-in, **read-only** access to **your own** Bitcoin node:
JSON-RPC for everything, plus an optional binary **REST** transport for the one
operation that moves bulk (fetching raw blocks). Everything it returns is
**live** (the node's current tip) and therefore **non-reproducible**:
explicitly outside the offline, fingerprinted world.

- **Layer:** L1, but a **live node** contract, not a reader over sealed
  artifacts. See [ARCHITECTURE](../ARCHITECTURE.md).
- **Reference impl:** `CoreBalance` (a `scantxoutset` consumer), plus two block
  transports behind one method: `RpcClient` (JSON-RPC, batched) and
  `RestClient` (`/rest/*.bin`, one persistent connection per thread).
- **Types:** `string`, `u32`, `u64`, `bool` — see [types](../types.md).

> **Non-reproducible, by nature.** A node answer reflects the chain **now**, at the
> node's height. It carries **no canonical fingerprint**; it MUST be labelled
> *live* and never presented as a sealed, replicable result. Contrast
> [BalanceBackend](./BalanceBackend.md) (offline, reproducible, at a watermark):
> the two must never be conflated.

## Safety invariants (MUST)

1. **Never by surprise.** The node is contacted **only** when the user explicitly
   asks (an `--rpc` opt-in). No flag → no call. The RPC callable is injectable, so
   tests never touch a node.
2. **Never on the command line.** Authenticate with the node's cookie file
   (`--cookie-file`), or, for a node with an explicit user and password, with the
   `NODSIG_RPC_AUTH` environment variable. There is deliberately **no flag that
   takes a credential**: a process's argv is readable by every other local user,
   for the whole length of a run that can last days.
3. **Read-only.** Only queries that read public chain state; no wallet, no writes.
4. **The REST transport carries no credential, and that cuts both ways.** The
   node's REST interface (`-rest=1`) is unauthenticated by design, so the block
   fetch over it holds no secret to leak; the same property means the node MUST
   NOT expose that port beyond localhost or a tunnel, exactly as for the RPC
   port. A scanner offered REST MUST still verify every block by hash: the
   transport is chosen for bytes on the wire, never for trust.
5. **Warn before blocking.** Operations that walk large state (e.g.
   `scantxoutset` over the whole UTXO set — minutes, longer on a Raspberry Pi /
   cold cache) print a heads-up to **stderr** (never mixing with results on
   stdout) before waiting.

## Operations

### `call(method: string, params: [...]) -> result`
The raw read-only RPC. Raises on an RPC error. All higher operations are built on
it.

### `live_balance(addresses: [Address]) -> { height: u32, per_address: { text -> u64 } }`
One `scantxoutset` call for the whole list (the RPC accepts many descriptors at
once). Returns the node's `height` and the unspent total (satoshis) per address.
This is the **current** balance, marked live/non-reproducible.

### `fetch_blocks(heights: [u32]) -> ([hash32], [bytes])`
The bulk operation, and the only one a long scan repeats millions of times: for
a window of heights, the block hashes in **serialized order** (not the reversed
display form) and the raw block bytes, both in the order asked. It is one
method so that the transport underneath is a choice and not a rewrite of the
scanner: JSON-RPC pairs `getblockhash` and `getblock <hash> 0` in two batched
round-trips, REST issues `GET /rest/blockhashbyheight/<H>.bin` and
`GET /rest/block/<display-hex>.bin` per block over a kept-open connection.

The two differ in bytes on the wire, not in what the caller may believe. RPC
carries each block as hex inside JSON, so ~2× the bytes plus escaping; REST
carries the block verbatim, with no credential and no batching (two GETs per
block, which is why the connection must be reused and why a fetch depth
greater than one is worth having). A conformance test MUST show the two
transports producing **byte-identical artifacts** over the same chain.

*(Integrity of fetched blocks, meaning header hash, prev link, Merkle and
witness commitment, is checked by the scanner at ingest whichever transport
delivered them, and a scanner consumes them to feed
[Artifact](./Artifact.md) builds.)*

## Conformance vectors

`tests/fixtures/nodeclient/` (to be added): with an **injected** RPC callable
(canned `scantxoutset` replies) — the expected `live_balance` height and
per-address totals, and the descriptor round-trip (`addr(X)#checksum` parsing).
No live node is ever required to test conformance.

## Notes for porters

- Keep the RPC callable **injectable**: it is what makes the contract testable
  without a node and guarantees "no call unless asked".
- Label every live result as such at the boundary; do not let a live number flow
  into a place that expects a watermarked, fingerprinted answer.
