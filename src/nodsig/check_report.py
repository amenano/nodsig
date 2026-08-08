#!/usr/bin/env python3
"""
check_report.py — `check-report-v2`, the output format of the address
check, and the aggregation every rendering of it reads.

THE QUESTION THAT GOVERNS THE WHOLE DOCUMENT
============================================
For every line this report prints: WAS IT PRODUCED BY A CHECK THAT
ACTUALLY RAN ON THIS PATH?

A per-address answer is hard to misread. An aggregate is not: it sums,
and in summing it loses where each piece came from. The two concrete
shapes that loss takes here are the two things this module exists to
prevent:

    a number that adds up answers given AT DIFFERENT HEIGHTS without
    saying so;

    a zero that means "nobody looked" and reads as "there is nothing".
    That is the worst class of error in this project, because it is
    FALSELY REASSURING and nothing downstream can contradict it.

Hence the rule the `summary` block enforces: when a capability did not
answer, its group is `null` with the status and the reason — never
zeros. `"exposed_by_reuse": 0` with no archive plugged in would say "I
looked and found no exposure", which is precisely the reassuring lie.

ONE PERIMETER PER NUMBER, EXCEPT IN ONE PLACE
=============================================
Every answer carries the source that produced it, once per group and
never per record (`capability.py` §ONCE PER OPERATION). A value with
TWO sources exists in exactly one key of this format, `crossed`, and
that key carries the distance between the two perimeters (`gap_blocks`)
and which way the number errs if the blind spot bites (`direction`).
The crossing is not forbidden — "how many exposed addresses still hold
coins" is the line people read first, and it needs an artifact and a
live node — it is CONFINED, and declared where it happens.

NO CLOCK
========
There is no `generated_at` and there will not be one. Heights are this
project's clock: the node's watermark says when the balances were read,
the artifacts are sealed. What that buys is worth more than a
timestamp: two runs over the same artifacts with the same input produce
a byte-identical file, so the report can be tested against a golden
file, and yesterday's report diffed against today's shows ONLY what
moved on the chain. Whoever wants the date has it from the filesystem.

Nothing in here opens a file, asks a backend, or decides an answer: it
reads a Report that `check_addresses.build_report` already filled, and
renders it. Two roads to the same number always diverge in the end, and
here they would diverge in silence — nobody compares a text report with
a JSON one by hand.
"""

import json
import textwrap

from nodsig.capability import Status
from nodsig.reuse_scan import SAT

FORMAT_TAG = "check-report-v2"

# The first key of the document, and the only redundant one. The text
# report carries the same warning as a comment on its first line; JSON
# has no comments, and this is the most pasteable file this project has
# ever produced. A warning that lives outside the file does not survive
# a copy into an issue. Inside it, first key, it does.
WARNING = ("this file lists YOUR addresses and what is known about "
           "them")

# The perimeter of every per-address answer. One list, wrapped for the
# text report and serialized as-is for tools: two copies of the same
# sentence would drift, and these are sentences people quote.
PERIMETER_CAVEATS = (
    "off-chain exposure is invisible here: an xpub shared with a "
    "service exposes descendant keys without any on-chain trace;",
    'a P2SH/P2WSH address hides its script until it spends: '
    '"protected" speaks of the hash, not of who could spend behind it;',
    "perimeter is CONFIRMED blocks up to the stated heights: a spend "
    "sitting in the mempool has already revealed its keys.",
)

# Three more that only exist because this report AGGREGATES. Each is
# printed only when the report actually contains what it warns about,
# so a caveat never describes something that is not on the page.
CAVEAT_PERIMETERS = (
    "this sheet mixes perimeters: numbers that cross two of them are "
    "listed under `crossed`, with the distance between the heights.")
CAVEAT_COVERAGE = (
    "coverage is what you gave, not what you have: nodsig cannot know "
    "how many of your addresses you did not name.")
CAVEAT_COSPEND = (
    "your co-spend surface does not depend on how much YOU spend: it "
    "depends on who spent together with you, and one coin of yours "
    "swept into somebody's consolidation is enough.")


def _btc(sats):
    return f"{sats / SAT:,.8f} BTC"


# ---------------------------------------------------------------------------
# The blocks
# ---------------------------------------------------------------------------

def sources(report):
    """§sources — every capability the build knows about, configured or
    not. A capability that simply vanished when its flag was absent
    reads as "not relevant here" instead of "nobody asked it".

    Fingerprints go in WHOLE: the text truncates them because a person
    reads it, a tool wants the digest."""
    out = {}
    for line in report.sources:
        if line.status != Status.OK:
            out[line.capability] = {"status": line.status, "id": None,
                                    "pluggable": line.pluggable}
            continue
        s = line.source
        out[line.capability] = {"status": line.status, "id": s.id,
                                "watermark": s.watermark,
                                "fingerprint": s.fingerprint,
                                "live": s.live}
    return out


def coverage(report):
    """§coverage — the block that separates "your 40 addresses" from
    "the 40 addresses you gave me". Its most important field is the one
    that always says the same thing."""
    checked = [e for e in report.entries if e.valid]
    cov = {"addresses_given": len(report.entries),
           "addresses_checked": len(checked),
           "addresses_undecodable": len(report.entries) - len(checked),
           "groups": [],
           # Not a lazy field: it is the only true answer. Nodsig does
           # not know how many addresses you did not name, and cannot.
           "wallet_completeness": "unknown to nodsig"}
    if report.book is not None:
        for g in report.book.groups:
            entry = {"label": g.label, "claim": g.claim,
                     "addresses": len(g.addresses)}
            if g.duplicates_removed:
                entry["duplicates_removed"] = g.duplicates_removed
            if g.origin is not None:
                entry["origin"] = g.origin
                # Without this field the block reads, in a JSON, like
                # something the tool verified. It verified nothing.
                entry["origin_attributed_to"] = "input, not verified"
            cov["groups"].append(entry)
    return cov


def _group(status, source_names, values, why=None):
    """One summary group: the envelope once, the numbers bare inside."""
    g = {"status": status, "sources": list(source_names),
         "values": values}
    if why is not None:
        g["why"] = why
    return g


def _why_unsupported(report, capability):
    line = report.source_of(capability)
    if line is None:
        return f"no {capability} backend was registered"
    return f"not configured (pluggable: {line.pluggable})"


def summary(report):
    """§summary — sums over answers already obtained. No new reads, no
    new questions, and no number that mixes two perimeters: those live
    in `crossed`."""
    checked = [e for e in report.entries if e.valid]

    by_kind = {}
    for e in checked:
        by_kind[e.kind] = by_kind.get(e.kind, 0) + 1
    # `input` is the one group without sources, and rightly so: it is
    # not an answer about the chain, it is a count of what you gave.
    out = {"input": {"addresses": len(checked), "by_kind": by_kind}}

    if report.answered("exposure"):
        counts = {}
        for e in checked:
            counts[e.answer.key] = counts.get(e.answer.key, 0) + 1
        out["exposure"] = _group(
            Status.OK, ["exposure"],
            {k: counts.get(k, 0) for k in
             ("exposed_by_construction", "exposed_by_reuse", "protected",
              "undetermined")})
    else:
        # No zeros. The by-construction addresses ARE still counted —
        # in `input.by_kind`, where p2tr says it, because that fact
        # comes from the encoding and not from the archive.
        out["exposure"] = _group(Status.UNSUPPORTED, ["exposure"], None,
                                 _why_unsupported(report, "exposure"))

    if report.answered("balance"):
        with_balance = [e for e in checked if e.balance_sats]
        out["balance"] = _group(
            Status.OK, ["balance"],
            {"total_sats": sum(e.balance_sats or 0 for e in checked),
             "addresses_with_balance": len(with_balance)})
    else:
        out["balance"] = _group(Status.UNSUPPORTED, ["balance"], None,
                                _why_unsupported(report, "balance"))

    if report.answered("history"):
        seen = [e.capabilities["history"].value for e in checked
                if "history" in e.capabilities]
        active = [v for v in seen if v]
        out["history"] = _group(
            Status.OK, ["history"],
            {"addresses_with_activity": len(active),
             "received_sats": sum(v["received_sats"] for v in active),
             "spent_sats": sum(v["spent_sats"] for v in active),
             "unspent_sats": sum(v["unspent_sats"] for v in active),
             # An address that was paid more than once: reuse as the
             # chain shows it, not as a wallet intended it.
             "reused_addresses": sum(1 for v in active
                                     if v["outputs"] > 1),
             "first_height": min((v["first_height"] for v in active),
                                 default=None),
             "last_height": max((v["last_height"] for v in active),
                                default=None)})
    else:
        out["history"] = _group(Status.UNSUPPORTED, ["history"], None,
                                _why_unsupported(report, "history"))

    if report.answered("co-inputs"):
        seen = [e.capabilities["co-inputs"].value for e in checked
                if "co-inputs" in e.capabilities]
        active = [v for v in seen if v]
        out["co_inputs"] = _group(
            Status.OK, ["co-inputs"],
            {"addresses_ever_spent": len(active),
             "spending_txs": sum(v["spending_txs"] for v in active),
             "co_spent_outputs": sum(v["co_outputs"] for v in active),
             "truncated_addresses": sum(1 for v in active
                                        if v["truncated"])})
    else:
        out["co_inputs"] = _group(Status.UNSUPPORTED, ["co-inputs"],
                                  None,
                                  _why_unsupported(report, "co-inputs"))

    if report.answered("nonce-exposure"):
        answers = [e.capabilities["nonce-exposure"] for e in checked
                   if "nonce-exposure" in e.capabilities]
        found = [a.value for a in answers if a.value]
        out["nonce_exposure"] = _group(
            Status.OK, ["nonce-exposure"],
            {"addresses_asked": sum(1 for a in answers
                                    if a.status == Status.OK),
             # An address whose kind cannot carry this question is NOT
             # a negative: it is one the capability could not answer.
             "addresses_not_answerable": sum(
                 1 for a in answers if a.status != Status.OK),
             "addresses_in_resolved_points": len(found),
             "addresses_exposed": sum(1 for v in found if v["exposed"])})
    else:
        out["nonce_exposure"] = _group(
            Status.UNSUPPORTED, ["nonce-exposure"], None,
            _why_unsupported(report, "nonce-exposure"))

    out["crossed"] = crossed(report)
    return out


def crossed(report):
    """§crossed — the ONLY place in this format where a value may have
    more than one source. Everything in here says how far apart its
    perimeters are and which way it errs."""
    if not (report.answered("exposure") and report.answered("balance")):
        return []
    exposure = report.source_of("exposure").source.watermark
    balance = report.source_of("balance").source.watermark
    n = sum(1 for e in report.entries
            if e.valid and e.answer.key in ("exposed_by_construction",
                                            "exposed_by_reuse")
            and e.balance_sats)
    item = {"name": "exposed_with_balance", "value": n,
            "sources": ["exposure", "balance"],
            "watermarks": {"exposure": exposure, "balance": balance}}
    if exposure is None or balance is None:
        item["gap_blocks"] = None
        item["direction"] = "unknown"
        return [item]
    item["gap_blocks"] = abs(balance - exposure)
    # Which way the number is wrong when the gap bites. Erring on the
    # reassuring side is the one that has to be said out loud.
    item["direction"] = ("reassuring" if exposure < balance
                         else "alarming" if exposure > balance
                         else "none")
    return [item]


def limits(report):
    """§limits — the caveats, as stable strings. The aggregate ones are
    added only when the report contains what they warn about."""
    out = list(PERIMETER_CAVEATS)
    if crossed(report):
        out.append(CAVEAT_PERIMETERS)
    if report.book is not None:
        out.append(CAVEAT_COVERAGE)
    if report.answered("co-inputs"):
        out.append(CAVEAT_COSPEND)
    return out


def addresses(report):
    """§addresses — one entry per input line, in input order.

    Each capability's answer carries its own source NAME, once. The
    exposure entry carries the KEY, not the printed sentence: the
    sentence merges the balance in ("but empty: nothing at stake") and
    a value with two perimeters may only live in `crossed`."""
    out = []
    for e in report.entries:
        item = {"address": e.text, "kind": e.kind, "group": e.group}
        if not e.valid:
            item["error"] = e.detail
            out.append(item)
            continue
        item["exposure"] = {
            "status": (Status.OK if e.answer.key != "undetermined"
                       else Status.UNDETERMINED),
            "source": e.answer.source_name,
            "value": e.answer.key,
            "detail": e.answer.detail}
        if e.answer.key == "exposed_by_construction":
            # A fact of the encoding: no height, no fingerprint, and it
            # will still be true in ten years.
            item["exposure"]["perishable"] = False
        if e.balance_sats is not None:
            item["balance"] = {"status": Status.OK, "source": "balance",
                               "sats": e.balance_sats}
        for cap, got in e.capabilities.items():
            item[cap.replace("-", "_")] = {
                "status": got.status, "source": cap,
                "values": got.value}
        out.append(item)
    return out


def document(report):
    """The whole `check-report-v2`, as a plain dict.

    Key order is the inverted pyramid, because a JSON also gets read
    with `less`. The ORDER IS NOT SEMANTIC: a tool binds to keys, never
    to position. Inside v2 keys may be ADDED; the meaning of an
    existing key never changes. Anything else is check-report-v3."""
    return {"warning": WARNING,
            "format": FORMAT_TAG,
            "sources": sources(report),
            "coverage": coverage(report),
            "summary": summary(report),
            "linkage": report.linkage,
            "addresses": addresses(report),
            "limits": limits(report)}


def dumps(report):
    """Serialized exactly as it will be written: stable separators, no
    key sorting (the order above is deliberate), and a trailing
    newline, so that two runs on the same artifacts give the same
    bytes and a golden file is possible."""
    return json.dumps(document(report), indent=2,
                      ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# The same content, rendered for a person
# ---------------------------------------------------------------------------

def caveats_text(report):
    """The caveats block of the text report, wrapped from the same
    strings the JSON serializes."""
    return "caveats (the perimeter of every answer above):\n" + "\n".join(
        textwrap.fill(c, width=70, initial_indent="- ",
                      subsequent_indent="  ") for c in limits(report))


def _heights(source_line):
    s = source_line.source
    if s.watermark is None:
        return ""
    return (f" (node height {s.watermark:,})" if s.live
            else f" (up to height {s.watermark:,})")


def render_overview_text(report, out):
    """The summary, for a person, before the per-address lines: what
    was given, what each capability answered, and — where it happens —
    which numbers cross two perimeters.

    Every line here is a rendering of `summary`/`coverage`/`crossed`.
    None of it is recomputed: a text report and a JSON one that
    disagreed would disagree in silence."""
    s = summary(report)
    cov = coverage(report)

    print("overview (each line counts only what the capability naming "
          "it actually checked):", file=out)

    kinds = ", ".join(f"{n} {k}" for k, n in
                      sorted(s["input"]["by_kind"].items()))
    given = (f"- input: {cov['addresses_checked']} address(es) checked"
             f" of {cov['addresses_given']} given")
    if cov["addresses_undecodable"]:
        given += (f", {cov['addresses_undecodable']} that did not "
                  "decode")
    print(given + (f" ({kinds})" if kinds else ""), file=out)

    if report.book is not None:
        for g in cov["groups"]:
            line = (f"- group {g['label']!r}: {g['addresses']} "
                    f"address(es), claimed {g['claim']}")
            if "duplicates_removed" in g:
                line += (f", {g['duplicates_removed']} repeat(s) "
                         "dropped")
            if "origin" in g:
                p = g["origin"]
                said = ", ".join(f"{k} {v}" for k, v in sorted(p.items()))
                line += f"; you state: {said} (not verified here)"
            print(line, file=out)
        print("- coverage: nodsig cannot know whether these are all "
              "your addresses", file=out)

    # The capabilities nobody configured are named ONCE, together. Each
    # of them already has its own source line above, with the flag that
    # would plug it in: repeating that here, capability by capability,
    # turned a report with nothing plugged in into a page of apologies.
    # The JSON keeps them one by one, where a tool reads them.
    silent = []
    for cap, group in (("exposure", s["exposure"]),
                       ("balance", s["balance"]),
                       ("history", s["history"]),
                       ("co-inputs", s["co_inputs"]),
                       ("nonce-exposure", s["nonce_exposure"])):
        line = report.source_of(cap)
        if group["status"] != Status.OK:
            silent.append(cap)
            continue
        v = group["values"]
        if cap == "exposure":
            body = (f"{v['exposed_by_reuse']} exposed by reuse, "
                    f"{v['exposed_by_construction']} by construction, "
                    f"{v['protected']} protected, "
                    f"{v['undetermined']} undetermined")
        elif cap == "balance":
            body = (f"{_btc(v['total_sats'])} over "
                    f"{v['addresses_with_balance']} address(es)")
        elif cap == "history":
            body = (f"{v['addresses_with_activity']} with activity, "
                    f"received {_btc(v['received_sats'])}, unspent "
                    f"{_btc(v['unspent_sats'])}, "
                    f"{v['reused_addresses']} paid more than once")
            if v["first_height"] is not None:
                body += (f" (heights {v['first_height']:,}–"
                         f"{v['last_height']:,})")
        elif cap == "nonce-exposure":
            body = (f"{v['addresses_exposed']} exposed by a repeated "
                    f"nonce, {v['addresses_in_resolved_points']} present "
                    f"in a resolved point, of {v['addresses_asked']} "
                    "single-key address(es) asked")
            if v["addresses_not_answerable"]:
                body += (f"; {v['addresses_not_answerable']} of a kind "
                         "this table cannot answer for")
            body += (" — absent here means 'not among the points the "
                     "census resolved', not 'no reuse'")
        else:
            body = (f"{v['addresses_ever_spent']} ever spent, "
                    f"{v['spending_txs']} spending tx(s), "
                    f"{v['co_spent_outputs']} co-spent output(s)")
            if v["truncated_addresses"]:
                body += (f", {v['truncated_addresses']} address(es) "
                         "sampled, not exhausted")
        print(f"- {cap}{_heights(line)}: {body}", file=out)

    if silent:
        print(f"- not answered: {', '.join(silent)} — the source lines "
              "above name what would plug each one in. Not answered is "
              "not a negative", file=out)

    for item in s["crossed"]:
        line = (f"- crossed ({' + '.join(item['sources'])}): "
                f"{item['value']} exposed address(es) holding coins")
        if item["gap_blocks"]:
            w = item["watermarks"]
            line += (f". Exposure stops at height {w['exposure']:,}, "
                     f"balances are at {w['balance']:,}: "
                     f"{item['gap_blocks']:,} block(s) in which a "
                     "revealed key still reads as protected here"
                     if item["direction"] == "reassuring" else
                     f". Exposure is at height {w['exposure']:,}, "
                     f"balances only at {w['balance']:,}: "
                     f"{item['gap_blocks']:,} block(s) in which a coin "
                     "may have moved without this number knowing")
        print(line, file=out)

    print(file=out)
