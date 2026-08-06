# LiveSource — contract (live extension seam)

**Capability.** A real-time stream of confirmed blocks and/or mempool
transactions from a node, for **live watching** (e.g. a sentinel over exposed
outputs). This is an **extension seam**: the toolkit ships the interface and a
neutral base source; concrete watchers plug in on top (and MAY be private).

- **Layer:** L1 extension seam — **live, non-reproducible**. See
  [ARCHITECTURE](../ARCHITECTURE.md). Pairs with [Matcher](./Matcher.md).
- **Reference impl:** a base source (ZMQ subscription / RPC polling over
  [NodeClient](./NodeClient.md)); no concrete watcher shipped.
- **Types:** `bytes`, `u32` — see [types](../types.md).

> **Not reproducible, and not in the fingerprinted world.** The mempool is not
> consensus data; a live stream cannot be replayed to the same bytes. Anything a
> live watcher *publishes* must degrade to a **historical on-chain fact** (an
> event that later sits in a confirmed block, verifiable by anyone against the
> chain via the offline readers) — the real-time head start stays with the
> watcher. See the exposure/sentinel discussion in project design notes.

## Operations

### `stream() -> stream<Event>`
An unbounded stream of events until closed:

```
Event = { kind:{BLOCK, MEMPOOL_TX}, height:u32?, bytes:bytes }
```

- `BLOCK` — a newly confirmed block (`height` set), raw bytes.
- `MEMPOOL_TX` — an unconfirmed transaction (`height` null), raw bytes.
- The stream is **best-effort and live**: it carries no watermark and no
  fingerprint; consumers MUST treat it as non-reproducible.

## Invariants a re-implementation MUST hold

1. **Live/non-reproducible labelling:** events carry no source fingerprint;
   never present them as sealed.
2. **Read-only, opt-in:** built on [NodeClient](./NodeClient.md)'s safety rules
   (cookie-file, never by surprise).
3. **Backpressure honesty:** if events are dropped (a slow consumer), that MUST be
   surfaced, never silently swallowed.

## Notes for porters / extenders

- The base source only *delivers* bytes; **what to do with them** is a
  [Matcher](./Matcher.md). Keep the two separate (source vs decision) so a private
  or specialized watcher is just a new `Matcher` over the shared source.
- A published watcher result is a claim about a **confirmed** transaction; provide
  a way to reproduce that claim with the offline readers (index/derivatives/
  archive), so the finding is third-party verifiable even though the live stream
  is not.
