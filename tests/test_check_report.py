#!/usr/bin/env python3
"""
test_check_report.py — self-test for check_report.py, the
`check-report-v2` document.

The per-address answers are already covered by test_check_addresses.py.
What is tested here is what AGGREGATION can get wrong, and every case
below is one way an aggregate lies while looking complete:

    a zero where nobody looked   the falsely reassuring answer, and the
                                 worst class of defect in this project
    a sum across two heights     a number whose two halves are as-of
                                 different moments, without saying so
    a coverage that counts what  "40 of your addresses" when 3 of the
    it could not check           43 given never decoded
    a path inside the document   a report that describes the machine
                                 that produced it instead of the chain

Plus the property everything else leans on: two runs over the same
artifacts produce the SAME BYTES, which is what makes a golden file
possible at all (there is no timestamp in the format on purpose).

Usage:
    python3 test_check_report.py    # prints PASS or fails loudly
"""

import io
import json
import os
import stat
import sys
import tempfile

import pytest

from nodsig import check_addresses as ca
from nodsig import check_report as cr
from nodsig import reuse_scan as rs
import test_check_addresses as tca
import test_reuse_scan as trs


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


NODE_HEIGHT = 900_000


def _balance(addresses_with_coins):
    """A CoreBalance riding an injected RPC: no node is ever contacted,
    and the tip it reports is far ahead of the test archive — which is
    exactly the perimeter gap `crossed` exists to declare."""
    def fake_rpc(_method, _params):
        return {"success": True, "height": NODE_HEIGHT,
                "unspents": [{"desc": f"addr({a})#aa",
                              "scriptPubKey": ca.script_pubkey(
                                  ca.decode_address(a)).hex(),
                              "amount": 1.5}
                             for a in addresses_with_coins]}
    return ca.CoreBalance("http://x", "u:p", rpc_call=fake_rpc)


def _addresses():
    revealed = tca.segwit_addr(rs.hash160(trs.PUB1), 0)
    protected = tca.segwit_addr(rs.hash160(trs.PUB5), 0)
    return revealed, protected


def test_no_zero_where_nobody_looked(archive):
    """With no exposure backend the summary group is null with a
    reason. `"exposed_by_reuse": 0` would say "I looked and found no
    exposure", which is the reassuring lie this whole format is shaped
    against."""
    revealed, _ = _addresses()
    report = ca.build_report([revealed], ca.build_backends(
        _sources(archive=None)))
    doc = cr.document(report)
    exposure = doc["summary"]["exposure"]
    check(exposure["values"] is None,
          f"an unasked capability must have no values: {exposure}")
    check(exposure["status"] == "UNSUPPORTED", f"status: {exposure}")
    check("--archive" in exposure["why"],
          f"the reason must name what would answer: {exposure}")
    check("exposed_by_reuse" not in json.dumps(doc["summary"]),
          "no key of an unanswered capability may appear, not even at "
          "zero")

    # And with the archive plugged, the same keys ARE there.
    with_archive = cr.document(ca.build_report(
        [revealed], ca.build_backends(_sources(archive=archive))))
    v = with_archive["summary"]["exposure"]["values"]
    check(v["exposed_by_reuse"] == 1 and v["protected"] == 0,
          f"the counted case must be counted: {v}")
    print("ok  summary: no zeros where nobody looked, real counts where "
          "somebody did")


def _sources(archive=None, index=None, derived=None, rpc=None):
    """What to plug in, as `build_backends` wants it: a plain mapping.

    It used to build an argparse Namespace, which is how the coupling
    showed itself before anyone named it — a test that has to
    manufacture a command line to reach a reader is a test reporting
    that the reader knows about command lines.
    """
    return {"archive": archive, "rpc": rpc, "index": index,
            "derived": derived}


def test_crossed_declares_the_gap(archive):
    """The one number allowed two perimeters carries the distance
    between them and which way it errs. Here the archive is far behind
    the node, so the error is on the reassuring side — the direction
    that has to be said out loud."""
    revealed, protected = _addresses()
    backends = {"exposure": ca.RevealArchiveExposure(archive),
                "balance": _balance([revealed])}
    doc = cr.document(ca.build_report([revealed, protected], backends))
    crossed = doc["summary"]["crossed"]
    check(len(crossed) == 1, f"one crossed value expected: {crossed}")
    item = crossed[0]
    check(item["value"] == 1,
          f"one exposed address holds coins: {item}")
    check(item["watermarks"]["balance"] == NODE_HEIGHT,
          f"the node's tip must travel with the number: {item}")
    gap = NODE_HEIGHT - item["watermarks"]["exposure"]
    check(item["gap_blocks"] == gap,
          f"gap_blocks must be the real distance ({gap}): {item}")
    check(item["direction"] == "reassuring",
          f"an archive behind the node errs by reassuring: {item}")
    print("ok  crossed: the gap between two perimeters is measured and "
          "its direction stated")


def test_only_crossed_has_two_sources(archive):
    """Walk the WHOLE document: any group with more than one source
    must be a `crossed` item. This is worth more than three tests on
    single cases, because it also holds for the keys added later."""
    revealed, protected = _addresses()
    backends = {"exposure": ca.RevealArchiveExposure(archive),
                "balance": _balance([revealed])}
    doc = cr.document(ca.build_report([revealed, protected], backends))
    crossed = [id(x) for x in doc["summary"]["crossed"]]

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("sources"), list) \
                    and len(node["sources"]) > 1:
                check(id(node) in crossed,
                      "a value with two sources outside `crossed`: "
                      f"{node}")
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(doc)
    check(len(doc["summary"]["crossed"][0]["sources"]) == 2,
          "the crossed item itself must really have two")
    print("ok  perimeters: two sources exist in `crossed` and nowhere "
          "else")


def test_coverage_counts_what_it_could_not_check(archive):
    revealed, _ = _addresses()
    report = ca.build_report([revealed, "totally-bogus"],
                             ca.build_backends(_sources(archive=archive)))
    cov = cr.document(report)["coverage"]
    check(cov["addresses_given"] == 2 and cov["addresses_checked"] == 1
          and cov["addresses_undecodable"] == 1,
          f"an address that did not decode is one less checked: {cov}")
    check(cov["wallet_completeness"] == "unknown to nodsig",
          "the only true answer about completeness is that there is "
          f"none: {cov}")
    print("ok  coverage: what did not decode is subtracted, "
          "completeness stays unknown")


def test_book_groups_are_attributed_not_asserted(tmp, archive):
    from nodsig import address_book as ab
    path = os.path.join(tmp, "book.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"format": ab.FORMAT_TAG, "groups": [
            {"label": "group-a", "claim": "separate",
             "addresses": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                           "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
             "origin": {"method": "descriptor",
                            "descriptor_checksum": "8rjyrgz9"}}]}, f)
    book = ab.load(path)
    doc = cr.document(ca.build_report(
        book.addresses, ca.build_backends(_sources(archive=archive)), book))
    g = doc["coverage"]["groups"][0]
    check(g["label"] == "group-a" and g["claim"] == "separate",
          f"the group must reach the report: {g}")
    check(g["duplicates_removed"] == 1,
          f"a dropped repeat is declared, not absorbed: {g}")
    check(g["origin_attributed_to"] == "input, not verified",
          "origin without that field reads as something the tool "
          f"checked: {g}")
    check(cr.CAVEAT_COVERAGE in doc["limits"],
          "a report built from a book must carry the coverage caveat")
    print("ok  coverage: groups carried, origin attributed, "
          "duplicates declared")


def test_reproducible_and_private(tmp, archive):
    """No clock in the format: the same question over the same
    artifacts gives the same bytes. That is what makes a golden file
    possible — and it lets yesterday's report be diffed against
    today's, showing only what moved on the chain."""
    revealed, protected = _addresses()
    out = os.path.join(tmp, "check-results.txt")
    j1 = os.path.join(tmp, "one.json")
    j2 = os.path.join(tmp, "two.json")
    for path in (j1, j2):
        ca.main([revealed, protected, "--archive", archive,
                 "--out", out, "--json", path])
    first, second = open(j1, "rb").read(), open(j2, "rb").read()
    check(first == second,
          "two runs over the same artifacts must give the same bytes")
    check(stat.S_IMODE(os.stat(j1).st_mode) == 0o600,
          "the JSON lists somebody's addresses: 0600, whatever the "
          f"umask says (got {stat.S_IMODE(os.stat(j1).st_mode):04o})")

    doc = json.loads(first)
    check(doc["format"] == cr.FORMAT_TAG, "format tag missing")
    check(list(doc)[0] == "warning",
          "the warning is the first key: a warning that lives outside "
          "the file does not survive a paste into an issue")
    text = first.decode()
    check(tmp not in text and archive not in text,
          "no path may appear in the document: a report carries "
          "identity, not the topology of the machine")
    check("generated_at" not in text and "timestamp" not in text,
          "heights are this project's clock, not the wall clock")
    print("ok  document: byte-identical between runs, 0600, no paths, "
          "no clock")


def test_addresses_block_keeps_exposure_pure(archive):
    """The printed sentence merges the balance in ("exposed but empty");
    the VALUE must not, or a per-address number would silently carry two
    perimeters."""
    revealed, _ = _addresses()
    backends = {"exposure": ca.RevealArchiveExposure(archive),
                "balance": _balance([])}          # everything at zero
    doc = cr.document(ca.build_report([revealed], backends))
    entry = doc["addresses"][0]
    check(entry["exposure"]["value"] == "exposed_by_reuse",
          f"the exposure value must stay a pure key: {entry}")
    check(entry["balance"]["sats"] == 0,
          f"zero is a value and travels on its own: {entry}")
    check("nothing at stake" not in json.dumps(entry["exposure"]),
          "the merged sentence belongs to the text, not to the value")
    print("ok  addresses: the exposure value stays one perimeter wide")


def test_taproot_is_attributed_to_the_codec(archive):
    """Exposure by construction comes from the ENCODING: no height, no
    fingerprint, and it does not perish. Attributing it to the archive
    would give a height to a fact that has none."""
    tr = tca.segwit_addr(bytes(range(32)), 1)
    doc = cr.document(ca.build_report(
        [tr], ca.build_backends(_sources(archive=archive))))
    exposure = doc["addresses"][0]["exposure"]
    check(exposure["source"] == ca.ADDRESS_CODEC,
          f"a fact of the encoding is not an artifact answer: {exposure}")
    check(exposure["perishable"] is False,
          f"it will still be true in ten years: {exposure}")
    print("ok  addresses: by-construction exposure is attributed to the "
          "codec, not to the archive")


@pytest.fixture
def archive(tmp):
    return tca.build_archive(tmp)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        arch = tca.build_archive(tmp)
        test_no_zero_where_nobody_looked(arch)
        test_crossed_declares_the_gap(arch)
        test_only_crossed_has_two_sources(arch)
        test_coverage_counts_what_it_could_not_check(arch)
        test_book_groups_are_attributed_not_asserted(tmp, arch)
        test_reproducible_and_private(tmp, arch)
        test_addresses_block_keeps_exposure_pure(arch)
        test_taproot_is_attributed_to_the_codec(arch)
    print("PASS: the aggregate says what it checked, declares every "
          "perimeter it crosses, and describes the chain instead of the "
          "machine.")


if __name__ == "__main__":
    main()


def test_the_keys_block_answers_the_point(archive):
    """`--key` is a question about a POINT: both serializations, each
    behind its faces, one entry per key and none of the faces leaked
    into `addresses`. The archive reveals PUB1 in a scriptSig at height
    2, so every face of it is exposed, the wrapper never spent
    included; a real key nobody revealed answers protected under four
    faces, the fourth named by one square root and saying so; a bare
    hash160 has three faces and no other serialization."""
    from nodsig.keyforms import KeyFormError, uncompressed_of
    backends = {"exposure": ca.RevealArchiveExposure(archive)}
    gen = ("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16"
           "F81798")
    report = ca.build_report([], backends, keys_text=[
        trs.PUB1.hex(), gen, rs.hash160(trs.PUB1).hex()])
    doc = cr.document(report)
    check(doc["format"] == "check-report-v3" and len(doc["keys"]) == 3,
          "one entry per key, under the v3 tag")
    check(doc["addresses"] == [], "the faces are not addresses the user typed")
    check(doc["sources"]["key-forms"]["root"] and ca.ROOT_SENTENCE in
          doc["limits"], "the square root is named as a source and a limit")

    k1, k2, k3 = doc["keys"]
    check(k1["given_as"] == "compressed"
          and k1["revealed"]["value"] == "exposed_by_reuse"
          and k1["revealed"]["first_height"] == 2
          and k1["revealed"]["sightings"] == ["scriptSig"],
          f"the revealed point: {k1['revealed']}")
    try:
        uncompressed_of(trs.PUB1)
        on_curve = True
    except KeyFormError:
        on_curve = False
    kinds = [f["kind"] for f in k1["faces"]]
    check(kinds[:3] == ["p2pkh", "p2sh-p2wpkh", "p2wpkh"]
          and len(kinds) == (4 if on_curve else 3)
          and (on_curve or "cannot be named" in k1["note"]),
          f"the faces of a compressed key: {kinds}, {k1.get('note')}")
    check(all(f["exposure"]["value"] == "exposed_by_reuse"
              for f in k1["faces"]),
          "a point in view exposes every face")
    wrapper = next(f for f in k1["faces"] if f["kind"] == "p2sh-p2wpkh")
    check(wrapper["exposure"]["why"] == "key in view; this wrapper never spent",
          f"the wrapper's reason: {wrapper}")
    check("scriptSig" in k1["faces"][0]["exposure"]["why"],
          f"the key-hash face names the sighting: {k1['faces'][0]}")

    check(k2["revealed"]["value"] == "protected"
          and [f["kind"] for f in k2["faces"]]
          == ["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2pkh"]
          and k2["faces"][3]["form"] == "uncompressed"
          and k2["faces"][3]["derived_by"] == "one square root mod p"
          and all("derived_by" not in f for f in k2["faces"][:3])
          and all(f["exposure"]["value"] == "protected" for f in k2["faces"]),
          f"a real key nobody revealed: {k2}")

    check(k3["given_as"] == "hash160"
          and k3["revealed"]["value"] == "exposed_by_reuse"
          and [f["form"] for f in k3["faces"]] == ["hash160"] * 3
          and "not derivable" in k3["note"],
          f"a bare digest: {k3}")

    # The block exists only when a key was given, and so does its source.
    plain = cr.document(ca.build_report([], backends))
    check("keys" not in plain and "key-forms" not in plain["sources"]
          and ca.ROOT_SENTENCE not in plain["limits"],
          "no key, no block")
    buf = io.StringIO()
    ca.render_text(report, buf)
    text = buf.getvalue()
    check(f"key {trs.PUB1.hex()} (compressed): REVEALED at height 2" in text
          and "one square root mod p" in text,
          f"the text names the key and the root: {text[:600]}")
    print("ok  keys: the point under its faces, the root named, nothing "
          "leaked into addresses")
