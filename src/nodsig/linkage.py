#!/usr/bin/env python3
"""
linkage.py — the links between the addresses somebody gave us: which of
them an outside observer can already tie together, and what that does
to the separations the owner says they intended.

THREE CLASSES, AND THEY ARE NOT THE SAME CLAIM
==============================================
Keeping them apart is the whole design. Collapsing them into one
"linked" flag would be the single most misleading thing this feature
could do.

    same_key      two addresses are the SAME 20-byte key under two
                  encodings. A fact of the codec: it has no height, it
                  came from no artifact, and it does not perish. If the
                  key ever surfaced on-chain, the tie is also visible
                  to everyone — and THAT half does have a height;

    common_input  coins of two addresses were spent by one transaction,
                  directly or through one bridge. The common-input
                  heuristic: usually one owner, and CoinJoin breaks it
                  on purpose. A HINT, never proof;

    payment_arc   one address's coins funded an output of another. "A
                  paid B" is NOT "A and B are one entity", so an arc is
                  reported and never merges anything, and never breaks
                  a declared separation.

WEIGHT TRAVELS WITH EVERY BRIDGE
================================
A bridge shared by 3 locks is damning; the same bridge shared by
900,000 is an exchange hot wallet and says nothing at all. Measured on
real data: 128 of about 190 bridges touch more than a thousand locks.
So `bridge_fanout` is reported beside every hop and no threshold is
applied to the finding itself — data, not judgement — while expansion
of a hub is refused and COUNTED, because a search that stopped must say
where it stopped.

AN ABSENCE MUST DECLARE WHAT BOUNDED IT
=======================================
"These groups still look separate" is produced by a search with a
depth, a cap and a hub rule. Without those three numbers beside it, the
sentence reads as a property of the chain instead of a property of the
search. And the asymmetry is worth repeating wherever this is printed:
A MERGE IS PERMANENT, A NON-MERGE IS PERISHABLE — one future
transaction destroys it.

WHY EACH CLASS CARRIES ITS OWN STATUS
=====================================
`same_key` answers with no artifacts at all, `common_input` and
`payment_arc` need the index and the derivatives. One status on the
whole block would either erase an answer that exists or promise two
that do not.

MEMORY IS O(ADDRESSES), NOT O(NEIGHBOURHOOD)
============================================
The question asked of the engine is MEMBERSHIP — "is any of MY locks
among the co-spenders?" — never enumeration. A single member of a real
wallet was measured with a 32,768-65,535 lock neighbourhood: returning
those sets would carry megabytes of strangers' locks around in memory,
one step away from ending up in a report. Nothing about a third party
that is not already in the user's own address book ever enters this
module's output.
"""

from nodsig.capability import Status

# Classes, as they are named in `check-report-v1`.
SAME_KEY = "same_key"
COMMON_INPUT = "common_input"
PAYMENT_ARC = "payment_arc"

# A bridge touching more than this many locks is not expanded at the
# next hop: it is a hub, the finding it would produce means nothing,
# and the walk would cost the neighbourhood of an exchange. Refusals
# are counted into `bounded_by`, never silent.
HUB_FANOUT = 1_000

CAVEAT_COMMON_INPUT = ("common-input is a hint, not proof of ownership; "
                       "CoinJoin breaks it on purpose")
CAVEAT_PAYMENT_ARC = ("A paid B, which is NOT the claim that A and B are "
                      "one entity")


def _unsupported(why):
    return {"status": Status.UNSUPPORTED, "why": why, "findings": []}


def _ok(findings, caveat=None):
    block = {"status": Status.OK, "findings": findings}
    if caveat:
        block["caveat"] = caveat
    return block


# ---------------------------------------------------------------------------
# Class 1: the same key under two encodings. Free, and the sharpest.
# ---------------------------------------------------------------------------

def same_key(entries):
    """Findings for addresses that are literally the same key.

    Two facts of different natures live in one finding, so each one
    names its own source: the identity comes from the ENCODING (no
    height, imperishable), while whether an outsider can already SEE it
    comes from the exposure capability (a height, an artifact, and one
    spend away from changing)."""
    by_digest = {}
    for i, e in enumerate(entries):
        if not e.valid or e.address.category != "keys":
            continue
        by_digest.setdefault(e.address.digest, []).append((i, e))

    findings = []
    for digest, group in by_digest.items():
        if len(group) < 2:
            continue
        for a in range(len(group)):
            for b in range(a + 1, len(group)):
                (ia, ea), (ib, eb) = group[a], group[b]
                findings.append({
                    "addresses": [ea.text, eb.text],
                    "positions": [ia, ib],
                    "groups": [ea.group, eb.group],
                    "evidence": {
                        "fact": "identical 20-byte digest under two "
                                "encodings",
                        "certainty": "from the encoding, not a heuristic",
                        "source": "address-codec",
                        "perishable": False},
                    "observable": _observable(ea, eb)})
    findings.sort(key=lambda f: f["positions"])
    return findings


def _observable(ea, eb):
    """Whether the tie is already visible to an outsider, which is a
    different question from whether it is true."""
    heights = [e.answer.first_height for e in (ea, eb)
               if e.answer.first_height is not None]
    if heights:
        return {"value": True, "source": "exposure",
                "at_height": min(heights),
                "why": "the key was revealed by a spend"}
    keys = {e.answer.key for e in (ea, eb)}
    if "undetermined" in keys:
        return {"value": None, "status": Status.UNDETERMINED,
                "source": "exposure",
                "why": "no exposure backend configured (--archive)"}
    return {"value": False, "source": "exposure",
            "why": "neither key has been revealed on-chain yet, so the "
                   "tie is real but not yet visible from outside"}


# ---------------------------------------------------------------------------
# Classes 2 and 3: what the index and the derivatives can see
# ---------------------------------------------------------------------------

class IndexLinkage:
    """The linkage capability over our own index and derivatives.

    It never enumerates a neighbourhood: it is handed the caller's own
    locks and answers membership. What comes back names only locks the
    caller already listed, plus the transaction and height that tie
    them — the bridge lock itself is named as a digest because it IS
    the evidence, and it is the one third-party datum in the output."""

    def __init__(self, index, derived, cap=10_000):
        self.index = index
        self.derived = derived
        self.watermark = index.watermark
        self.cap = cap

    def source(self):
        from nodsig import derivatives as dvm
        from nodsig.capability import Source
        return Source.artifact(dvm.FORMAT_TAG, self.watermark,
                               self.derived.manifest["fingerprint"])

    def describe(self):
        return self.source().describe("linkage")

    def close(self):
        self.derived.close()
        self.index.close()

    # -- the two primitives the engine gives ----------------------------

    def _spenders(self, lock):
        """The transactions that spent this lock's coins, and whether
        the cap bit."""
        spenders, truncated = [], False
        seen = set()
        for _out, spender, _value in self.derived.rows(lock):
            if spender is None or spender in seen:
                continue
            if len(seen) >= self.cap:
                truncated = True
                break
            seen.add(spender)
            spenders.append(spender)
        return spenders, truncated

    def _co_locks(self, tx_ord, exclude):
        """The locks of the OTHER inputs of one transaction."""
        out = []
        for so in self.derived.inputs_of(tx_ord):
            _v, lock = self.index.output(so)
            if lock != exclude:
                out.append(lock)
        return out

    def _received_in(self, lock):
        """(tx_ord, out_ord) for every output that paid this lock."""
        return [(self.index.tx_of_output(o), o)
                for o, _spender, _v in self.derived.rows(lock)]

    # -- class 2 --------------------------------------------------------

    def common_input(self, mine, depth=1):
        """`mine` is {lock: (position, entry)}. Returns (findings,
        bounded_by): who is tied to whom, and what limited the search.

        Depth 1 is a direct co-spend. Depth 2 goes through ONE bridge,
        and is not the default for a measured reason: about 7 seconds
        per address against fractions of a second, the cap bites for
        one member in ten, and one in sixty has a neighbourhood of tens
        of thousands of locks. Expensive AND uninformative is an
        option, not a default."""
        found, caps_hit, hubs = {}, 0, 0
        for lock, (pos, _entry) in mine.items():
            spenders, truncated = self._spenders(lock)
            caps_hit += 1 if truncated else 0
            for tx_ord in spenders:
                height = self.index.height_of_tx(tx_ord)
                txid = self.index.txid_of(tx_ord).hex()
                for other in self._co_locks(tx_ord, lock):
                    if other in mine:
                        self._record(found, mine, pos, other,
                                     [{"bridge_lock": None,
                                       "txid": txid, "height": height}])
                    elif depth > 1:
                        hit, skipped = self._through_bridge(
                            mine, pos, other, txid, height, found)
                        hubs += skipped
        findings = sorted(found.values(), key=lambda f: f["positions"])
        bounded = {"depth": depth, "caps_hit": caps_hit,
                   "bridges_not_expanded": hubs}
        return findings, bounded

    def _through_bridge(self, mine, pos, bridge, txid, height, found):
        """One more hop, through a lock that is not the caller's.

        The bridge's fanout is measured first: a hub is not expanded,
        because the finding it would produce ("both of you touched an
        exchange") means nothing, and the walk would be the price of an
        exchange's neighbourhood."""
        spenders, _truncated = self._spenders(bridge)
        fanout = 0
        reachable = []
        for tx_ord in spenders:
            others = self._co_locks(tx_ord, bridge)
            fanout += len(others)
            reachable.append((tx_ord, others))
            if fanout > HUB_FANOUT:
                return 0, 1
        for tx_ord, others in reachable:
            for other in others:
                if other in mine and mine[other][0] != pos:
                    self._record(
                        found, mine, pos, other,
                        [{"bridge_lock": bridge.hex(), "txid": txid,
                          "height": height,
                          "bridge_fanout": fanout},
                         {"bridge_lock": bridge.hex(),
                          "txid": self.index.txid_of(tx_ord).hex(),
                          "height": self.index.height_of_tx(tx_ord),
                          "bridge_fanout": fanout}])
        return 1, 0

    @staticmethod
    def _record(found, mine, pos, other_lock, hops):
        other_pos, other_entry = mine[other_lock]
        if other_pos == pos:
            return
        key = tuple(sorted((pos, other_pos)))
        prev = found.get(key)
        if prev is not None and prev["hops"][0]["height"] <= \
                hops[0]["height"]:
            return
        mine_entry = next(e for _l, (p, e) in mine.items() if p == pos)
        first, second = ((mine_entry, other_entry) if pos < other_pos
                         else (other_entry, mine_entry))
        found[key] = {"addresses": [first.text, second.text],
                      "positions": list(key),
                      "groups": [first.group, second.group],
                      "hops": hops}

    # -- class 3 --------------------------------------------------------

    def payment_arcs(self, mine):
        """"A paid B": one address's coins were among the inputs of a
        transaction that created an output of another address.

        Reported apart, and never as a merge: paying somebody is the
        most ordinary thing an address does, and reading it as shared
        ownership would turn every purchase into a link."""
        arcs = {}
        for lock, (pos, entry) in mine.items():
            for tx_ord, _out in self._received_in(lock):
                if tx_ord is None:
                    continue
                for so in self.derived.inputs_of(tx_ord):
                    _v, funder = self.index.output(so)
                    if funder == lock or funder not in mine:
                        continue
                    from_pos, from_entry = mine[funder]
                    key = (from_pos, pos, tx_ord)
                    arcs.setdefault(key, {
                        "from": from_entry.text, "to": entry.text,
                        "positions": [from_pos, pos],
                        "txid": self.index.txid_of(tx_ord).hex(),
                        "height": self.index.height_of_tx(tx_ord),
                        "means": CAVEAT_PAYMENT_ARC})
        return [arcs[k] for k in sorted(arcs)]


# ---------------------------------------------------------------------------
# The block, assembled
# ---------------------------------------------------------------------------

def build(entries, backend, depth=1, book=None, watermark=None):
    """The whole `linkage` block of the report.

    Class 1 is computed whatever is plugged in; classes 2 and 3 declare
    themselves unsupported when there is no index. That is why the
    block has no status of its own."""
    classes = {SAME_KEY: _ok(same_key(entries))}

    if backend is None:
        why = ("not configured (pluggable: outpoint-index derivatives "
               "(--index + --derived))")
        classes[COMMON_INPUT] = _unsupported(why)
        classes[PAYMENT_ARC] = _unsupported(why)
        bounded = {"depth": 0, "caps_hit": 0, "bridges_not_expanded": 0}
    else:
        from nodsig.check_addresses import script_pubkey
        from nodsig.hashing import hash160
        mine = {}
        for i, e in enumerate(entries):
            if e.valid:
                mine.setdefault(hash160(script_pubkey(e.address)), (i, e))
        findings, bounded = backend.common_input(mine, depth)
        classes[COMMON_INPUT] = _ok(findings, CAVEAT_COMMON_INPUT)
        classes[PAYMENT_ARC] = _ok(backend.payment_arcs(mine),
                                   CAVEAT_PAYMENT_ARC)
        watermark = backend.watermark

    return {"depth_searched": bounded["depth"],
            "classes": classes,
            "declared_separations": separations(classes, book, bounded,
                                                watermark)}


def separations(classes, book, bounded, watermark):
    """The half of the report that needs a permission, and the
    permission is the user's claim.

    Only groups claimed `mine` take part: "A and B are linked" needs
    nothing from the author, while "A and B still look separate" says
    nothing at all unless somebody meant to keep them apart. A
    `watching` group is not second class — links towards it are
    reported like any other — it simply cannot be separated from
    anything, because nobody claimed it."""
    if book is None:
        return []
    claimed = [g.label for g in book.groups if g.claimed_mine]
    breaks = {}
    for cls in (SAME_KEY, COMMON_INPUT):
        for f in classes[cls]["findings"]:
            a, b = f["groups"]
            if a is None or b is None or a == b:
                continue
            key = tuple(sorted((a, b)))
            height = (f.get("observable", {}).get("at_height")
                      if cls == SAME_KEY
                      else f["hops"][0]["height"])
            if key not in breaks or cls == SAME_KEY:
                breaks[key] = {"broken_by": cls, "at_height": height}

    out = []
    for i in range(len(claimed)):
        for j in range(i + 1, len(claimed)):
            key = tuple(sorted((claimed[i], claimed[j])))
            item = {"groups": list(key)}
            if key in breaks:
                item["held"] = False
                item.update(breaks[key])
            else:
                # Never an attestation, and not by accident: what
                # bounded the search travels with the answer, or the
                # sentence reads as a property of the chain.
                item["held"] = True
                item["as_of"] = watermark
                item["bounded_by"] = dict(bounded)
                item["note"] = ("a merge is permanent, a non-merge is "
                                "perishable: one future transaction "
                                "ends it")
            out.append(item)
    return out


def render_text(block, out):
    """The links, for a person. Short by construction: a wallet with
    forty addresses has a handful of findings, and each one is a
    sentence somebody has to be able to act on."""
    classes = block["classes"]
    same = classes[SAME_KEY]["findings"]
    common = classes[COMMON_INPUT]
    arcs = classes[PAYMENT_ARC]

    if common["status"] != Status.OK:
        # Nothing was searched and there is nothing to show: one line,
        # because the source header above already names the flag. The
        # line is still printed — silence here would read as "no links".
        if not same:
            print("links: the co-spend search did not run, and no two "
                  "of these addresses are the same key", file=out)
            return
        print("links (the co-spend search did not run):", file=out)
    else:
        print(f"links (co-spend search to depth "
              f"{block['depth_searched']}):", file=out)
    for f in same:
        obs = f["observable"]
        seen = ("already visible from outside since height "
                f"{obs['at_height']:,}" if obs.get("value")
                else "not visible from outside yet"
                if obs.get("value") is False
                else "visibility unknown: no exposure backend")
        print(f"- same key: {f['addresses'][0]} and {f['addresses'][1]} "
              f"are one key under two encodings ({seen})", file=out)

    if common["status"] != Status.OK:
        print(f"- common input: not searched — {common['why']}", file=out)
    else:
        for f in common["findings"]:
            hop = f["hops"][0]
            through = ("" if hop["bridge_lock"] is None
                       else f" through a bridge with "
                            f"{hop['bridge_fanout']:,} co-spending lock(s)")
            print(f"- common input: {f['addresses'][0]} and "
                  f"{f['addresses'][1]} were spent together at height "
                  f"{hop['height']:,}{through} — {CAVEAT_COMMON_INPUT}",
                  file=out)
        if not common["findings"]:
            print("- common input: nothing found at this depth, which "
                  "is bounded by the search and not a property of the "
                  "chain", file=out)

    if arcs["status"] == Status.OK:
        for a in arcs["findings"]:
            print(f"- payment: {a['from']} funded an output of "
                  f"{a['to']} at height {a['height']:,} — "
                  f"{CAVEAT_PAYMENT_ARC}", file=out)

    for s in block["declared_separations"]:
        a, b = s["groups"]
        if s["held"]:
            bounded = s["bounded_by"]
            print(f"- separation {a!r}/{b!r}: still holds as of height "
                  f"{s['as_of']:,} (depth {bounded['depth']}, "
                  f"{bounded['caps_hit']} cap(s) hit, "
                  f"{bounded['bridges_not_expanded']} hub(s) not "
                  "expanded). A merge is permanent, a non-merge is "
                  "perishable", file=out)
        else:
            at = s.get("at_height")
            when = f" at height {at:,}" if at else ""
            print(f"- separation {a!r}/{b!r}: BROKEN by "
                  f"{s['broken_by']}{when}", file=out)
