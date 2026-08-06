#!/usr/bin/env python3
"""
test_check_addresses.py — self-test for check_addresses.py. No node, no
real chain: public address vectors, a mirror encoder, and a synthetic
reveal archive built from the shared test chain.

Two things are proven, and kept separate:

1. DECODING is anchored to the outside world by two well-known public
   vectors (the genesis P2PKH address; the BIP-173 P2WPKH vector), so a
   bug in charset/checksum/version logic cannot pass unnoticed. The
   rest of the address space is exercised by a MIRROR ENCODER written
   here (independent of the decoder): encode a program/digest, decode
   it back, demand it round-trips to the right kind and bytes. The two
   styles cover each other — external truth for the constants, mirror
   symmetry for breadth — the same doubling the rest of the suite uses.
   The encoder also lets the test build addresses whose digests MATCH
   the archive, which is what a public-fixtures-only exposure test
   needs.

2. The PER-CAPABILITY interface behaves: exposure resolves against our
   own archive (revealed → EXPOSED by reuse with the right source;
   unrevealed → PROTECTED with the watermark); by-construction Taproot
   never touches the archive; a missing backend degrades to UNDETERMINED
   instead of guessing; balance rides an INJECTED rpc call so the node
   is never contacted; history and co-inputs answer from a real
   index+derivatives pipeline built on the derivatives suite's chain
   (whose numbers are known by hand), with honest absences for locks
   the chain never saw.

Usage:
    python3 test_check_addresses.py    # prints PASS or fails loudly
"""

import argparse
import hashlib
import io
import os
import stat
import sys
import tempfile

import pytest

from nodsig import check_addresses as ca
from nodsig import derivatives as dvm
from nodsig import reuse_scan as rs
from nodsig import reveal_archive as ra
import test_blockparse as tbw
import test_derivatives as tdv
import test_reuse_scan as trs


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


# ---------------------------------------------------------------------------
# Mirror encoders (test-only, independent of the decoder under test)
# ---------------------------------------------------------------------------

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58check_encode(version, payload):
    raw = bytes([version]) + payload
    raw += sha256d(raw)[:4]
    n = int.from_bytes(raw, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = ca.B58_ALPHABET[r] + s
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + s


def _to5(data):
    acc = bits = 0
    out = []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def bech32_encode(hrp, data, const):
    values = ([ord(c) >> 5 for c in hrp] + [0]
              + [ord(c) & 31 for c in hrp] + data)
    polymod = ca._bech32_polymod(values + [0] * 6) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(ca.BECH32_CHARSET[d]
                               for d in data + checksum)


def segwit_addr(program, version):
    const = 1 if version == 0 else ca.BECH32M_CONST
    return bech32_encode("bc", [version] + _to5(program), const)


# ---------------------------------------------------------------------------
# 1. Decoding
# ---------------------------------------------------------------------------

def test_public_vectors():
    """External truth: two addresses whose bytes the whole world knows."""
    # The genesis coinbase address — P2PKH, hash160 well documented.
    a = ca.decode_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    check(a.kind == "p2pkh", "genesis address not decoded as p2pkh")
    check(a.digest.hex() == "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
          "genesis hash160 wrong")
    check(a.category == "keys", "p2pkh must route to the keys category")

    # BIP-173 P2WPKH test vector (uppercase on purpose: case handling).
    b = ca.decode_address("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
    check(b.kind == "p2wpkh", "BIP-173 vector not decoded as p2wpkh")
    check(b.digest.hex() == "751e76e8199196d454941c45d1b3a323f1433bd6",
          "BIP-173 program wrong")
    print("ok  decode: public P2PKH and P2WPKH vectors match the world")


def test_roundtrip_all_kinds():
    """Mirror symmetry across the whole address space we handle."""
    h20 = bytes(range(20))
    h32 = bytes(range(32))
    cases = [
        (b58check_encode(0x00, h20), "p2pkh", h20, "keys"),
        (b58check_encode(0x05, h20), "p2sh", h20, "scripts20"),
        (segwit_addr(h20, 0), "p2wpkh", h20, "keys"),
        (segwit_addr(h32, 0), "p2wsh", h32, "scripts32"),
        (segwit_addr(h32, 1), "p2tr", h32, None),
    ]
    for text, kind, digest, cat in cases:
        a = ca.decode_address(text)
        check(a.kind == kind, f"{text}: kind {a.kind} != {kind}")
        check(a.digest == digest, f"{text}: digest mismatch")
        check(a.category == cat, f"{text}: category {a.category} != {cat}")
    check(ca.decode_address(cases[-1][0]).by_construction,
          "taproot must be exposed by construction")
    print("ok  decode: round-trip for p2pkh/p2sh/p2wpkh/p2wsh/p2tr")


def test_rejections():
    """The checksum and the encoding constant must actually reject."""
    good = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
    flipped = good[:-1] + ("5" if good[-1] != "5" else "4")
    for bad, why in [
        (flipped, "flipped checksum char"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna", "base58 checksum"),
        (bech32_encode("bc", [0] + _to5(bytes(20)), ca.BECH32M_CONST),
         "segwit v0 with bech32m constant"),
        (bech32_encode("bc", [1] + _to5(bytes(32)), 1),
         "segwit v1 with plain bech32"),
        (b58check_encode(0x6f, bytes(20)), "testnet version byte"),
        ("bc1p" + "0" * 40, "garbage bech32m body"),
        ("not-an-address", "not an address at all"),
    ]:
        try:
            ca.decode_address(bad)
        except ca.AddressError:
            continue
        fail(f"decode accepted an invalid address ({why}): {bad}")
    print("ok  decode: bad checksums, wrong constants, wrong network "
          "rejected")


# ---------------------------------------------------------------------------
# 2. Capabilities
# ---------------------------------------------------------------------------

def build_archive(tmp):
    """A real reveal-archive-v2 built from the shared synthetic chain,
    so its digests are exactly hash160(PUBn)/sha256(script) — the same
    cast the reveal_archive test uses."""
    server, url = trs.serve(trs.build_chain())
    archive = os.path.join(tmp, "arch")
    try:
        ra.run_scan(url, "user:pass", 4, archive,
                    batch_size=2, checkpoint_every=2)
    finally:
        server.shutdown()
    return archive


def test_exposure(archive):
    exp = ca.RevealArchiveExposure(archive)
    backends = {"exposure": exp}

    # A revealed key (PUB1, seen in a scriptSig) dressed as a P2WPKH
    # address — same 'keys' category, its hash160 is in the archive.
    revealed = ca.decode_address(segwit_addr(rs.hash160(trs.PUB1), 0))
    v, d, _ = ca.answer(revealed, backends)
    check(v == "EXPOSED (by reuse)", f"revealed key answer: {v}")
    check("scriptSig" in d, f"source lost: {d}")

    # An unrevealed key (PUB5) → protected, and the message must carry
    # the watermark height (the perimeter of the claim).
    protected = ca.decode_address(segwit_addr(rs.hash160(trs.PUB5), 0))
    v, d, _ = ca.answer(protected, backends)
    check(v == "PROTECTED until first spend", f"unrevealed answer: {v}")
    check(str(exp.watermark) in d.replace(",", ""),
          f"watermark missing from the protected answer: {d}")

    # A revealed witness script (32-byte category) → exposed by reuse.
    # Its record's third byte is a COUNT of the public keys the script
    # carried (one, in this chain's 1-of-1), not provenance flags: the
    # story must say the script surfaced, and must NOT read the count
    # as bits and claim the key itself signed somewhere.
    wscript_digest = hashlib.sha256(trs.WSCRIPT).digest()
    revealed32 = ca.decode_address(segwit_addr(wscript_digest, 0))
    v, d, _ = ca.answer(revealed32, backends)
    check(v == "EXPOSED (by reuse)", f"revealed wscript answer: {v}")
    check("script revealed by a spend" in d and "1 key inside" in d,
          f"the script's answer must count the keys inside: {d}")
    check("scriptSig" not in d and "witness" not in d,
          f"a script hash never signed anywhere itself: {d}")
    print("ok  exposure: reuse hit w/ source, protected w/ watermark, "
          "script hit w/ its key count")


def test_by_construction_skips_archive(archive):
    """Taproot is exposed by its own definition; the answer must not
    depend on the archive at all (proven by passing NO exposure
    backend and still getting the exposed answer)."""
    tr = ca.decode_address(segwit_addr(bytes(range(32)), 1))
    v, d, _ = ca.answer(tr, {})
    check(v == "EXPOSED (by construction)", f"taproot answer: {v}")
    check("key" in d.lower(), f"taproot detail unclear: {d}")
    print("ok  by-construction: taproot exposed without any archive")


def test_undetermined_without_backend():
    """A hash-guarded address with no exposure backend must say so, not
    fall through to a false 'protected'."""
    a = ca.decode_address(segwit_addr(bytes(20), 0))
    v, d, _ = ca.answer(a, {})
    check(v == "UNDETERMINED", f"missing-backend answer: {v}")
    check("archive" in d, f"reason not explained: {d}")
    # NotPlugged stub behaves the same as truly absent.
    stub = {"exposure": ca.NotPlugged("exposure", "x")}
    v2, _, _ = ca.answer(a, stub)
    check(v2 == "UNDETERMINED", "NotPlugged exposure should be undetermined")
    print("ok  degradation: no exposure backend → UNDETERMINED, not "
          "a false answer")


def test_balance_injected():
    """Balance rides an injected rpc_call: the node is never contacted,
    the 'nothing at stake' path is exercised, and one scantxoutset
    serves the whole list."""
    keyed = segwit_addr(bytes(range(20)), 0)          # will have balance
    empty = segwit_addr(bytes(range(20, 40)), 0)       # zero balance
    calls = []

    def fake_rpc(method, params):
        calls.append(method)
        check(method == "scantxoutset", f"unexpected RPC {method}")
        descs = params[1]
        check(len(descs) == 2, "balance should scan the list in ONE call")
        return {"height": 800000,
                "unspents": [{"desc": f"addr({keyed})#aa",
                              "scriptPubKey": ca.script_pubkey(
                                  ca.decode_address(keyed)).hex(),
                              "amount": 1.5}]}

    bal = ca.CoreBalance("http://x", "u:p", rpc_call=fake_rpc)
    addrs = [ca.decode_address(keyed), ca.decode_address(empty)]
    bal.scan(addrs)
    check(calls == ["scantxoutset"], "node contacted more than once")
    check(bal.query(addrs[0]).value == 150_000_000,
          "balance satoshis wrong")
    check(bal.query(addrs[1]).value == 0,
          "empty address should be 0 sats")
    # Zero is a VALUE: the envelope must say OK, not "nothing found".
    check(bal.query(addrs[1]).status == ca.Status.OK,
          "an empty address is a definite answer, not a failure")

    # 'exposed but empty' composes exposure + balance=0.
    backends = {"exposure": _AllExposed(), "balance": bal}
    v, _, sats = ca.answer(addrs[1], backends)
    check(sats == 0 and "nothing at stake" in v,
          f"empty exposed address answer: {v}")
    print("ok  balance: injected RPC, one call for the list, empty flagged")


def test_balance_matches_a_taproot_output_by_its_script():
    """The node does not echo the addr() it was asked: `desc` is what
    it infers from the script it matched, and for a taproot output that
    is `rawtr(<x-only key>)`, which no address string equals. Reading
    the address out of the descriptor left every p2tr balance at zero —
    and p2tr is the class this tool calls exposed by construction, so
    the wrong answer was the reassuring one."""
    tr = ca.decode_address(segwit_addr(bytes(range(32)), 1))
    spk = ca.script_pubkey(tr).hex()

    def fake_rpc(_method, _params):
        return {"height": 900000,
                "unspents": [{"desc": f"rawtr({bytes(range(32)).hex()})#ck",
                              "scriptPubKey": spk,
                              "amount": 0.25}]}

    bal = ca.CoreBalance("http://x", "u:p", rpc_call=fake_rpc)
    bal.scan([tr])
    check(bal.query(tr).value == 25_000_000,
          f"taproot balance lost: {bal.query(tr).value}")
    v, _d, sats = ca.answer(tr, {"balance": bal})
    check(sats == 25_000_000 and "nothing at stake" not in v,
          f"a funded taproot address was called empty: {v}")
    print("ok  balance: a taproot output is matched by its script, not "
          "by a descriptor that never names it")


def test_balance_ignores_an_unspent_it_did_not_ask_for():
    """An unspent whose script matches none of the asked addresses
    cannot be attributed: counting it under some other address would
    invent a balance."""
    a = ca.decode_address(segwit_addr(bytes(range(20)), 0))
    other = ca.script_pubkey(
        ca.decode_address(segwit_addr(bytes(range(20, 40)), 0))).hex()

    def fake_rpc(_method, _params):
        return {"height": 900000,
                "unspents": [{"desc": "addr(?)#ck",
                              "scriptPubKey": other, "amount": 9.0}]}

    bal = ca.CoreBalance("http://x", "u:p", rpc_call=fake_rpc)
    bal.scan([a])
    check(bal.query(a).value == 0,
          "an unrelated unspent was counted as this address's balance")
    print("ok  balance: an unspent for another script is not attributed")


class _AllExposed:
    """Tiny exposure backend that flags everything as reuse-exposed,
    to drive the 'exposed but empty' composition without a chain. It
    speaks the envelope like a real backend: a double that skipped it
    would be testing a contract nobody implements."""
    watermark = 1

    def source(self):
        return ca.Source.artifact("all-exposed test double",
                                      self.watermark, None)

    def describe(self):
        return self.source().describe("exposure")

    def query(self, address):
        return ca.Result.ok((ra.FLAG_SIG, 2), self.source())


def test_end_to_end(archive):
    """The whole run() over a mixed list, capturing stdout: answers
    printed, invalid line reported, caveats always present."""
    good = segwit_addr(rs.hash160(trs.PUB1), 0)
    tr = segwit_addr(bytes(range(32)), 1)
    buf = io.StringIO()
    ca.run([good, tr, "totally-bogus"],
           {"exposure": ca.RevealArchiveExposure(archive)}, out=buf)
    text = buf.getvalue()
    check("EXPOSED (by reuse)" in text, "reuse answer missing from output")
    check("EXPOSED (by construction)" in text, "taproot answer missing")
    check("NOT AN ADDRESS" in text, "invalid line not reported")
    check("caveats" in text, "caveats block missing")
    print("ok  end-to-end: mixed list prints answers, invalids, caveats")


def test_report_file_default(tmp, archive):
    """The report lands in a LOCAL FILE (screens get shared, terminals
    get logged — the manual's privacy rule): the CLI writes --out with
    the sensitivity warning on top; --stdout is the explicit opt-out."""
    out = os.path.join(tmp, "check-results.txt")
    good = segwit_addr(rs.hash160(trs.PUB1), 0)
    ca.main([good, "--archive", archive, "--out", out])
    text = open(out).read()
    check(text.startswith("# this file lists YOUR addresses"),
          "sensitivity warning missing from the top of the report file")
    check("EXPOSED (by reuse)" in text, "answer missing from the file")
    check(stat.S_IMODE(os.stat(out).st_mode) == 0o600,
          "the report lists the addresses somebody asked about: it must "
          "be created readable by its owner alone, whatever the umask "
          f"says (got {stat.S_IMODE(os.stat(out).st_mode):04o})")
    print("ok  report file: default on disk, warning on top, 0600")


# ---------------------------------------------------------------------------
# history / co-inputs: the real backends over a real pipeline
# ---------------------------------------------------------------------------

def build_pipeline(tmp):
    """The derivatives suite's chain (known numbers, a real co-spend)
    through the real pipeline: graph → index → derivatives."""
    blocks, _txids = tdv.derived_chain()
    _graph, index = tdv.build_index(tmp, blocks, name="ca_index")
    derived = os.path.join(tmp, "ca_derived")
    dvm.run_build(index, derived)
    return index, derived


@pytest.fixture
def pipeline(tmp):
    return build_pipeline(tmp)


def _index_backends(pipeline):
    index_dir, derived_dir = pipeline
    return ca.build_backends(argparse.Namespace(
        archive=None, rpc=None, auth=None, cookie_file=None,
        index=index_dir, derived=derived_dir))


def test_script_pubkey():
    """The address→scriptPubKey bridge, checked shape by shape against
    the standard templates (the derivatives key everything by hash160
    of these exact bytes, so a wrong template = a wrong history)."""
    h20, h32 = b"\x11" * 20, b"\x22" * 32
    cases = [
        (b58check_encode(0x00, h20), b"\x76\xa9\x14" + h20 + b"\x88\xac"),
        (b58check_encode(0x05, h20), b"\xa9\x14" + h20 + b"\x87"),
        (segwit_addr(h20, 0), b"\x00\x14" + h20),
        (segwit_addr(h32, 0), b"\x00\x20" + h32),
        (segwit_addr(h32, 1), b"\x51\x20" + h32),
    ]
    for text, want in cases:
        got = ca.script_pubkey(ca.decode_address(text))
        check(got == want, f"{text}: scriptPubKey {got.hex()} != "
                           f"{want.hex()}")
    print("ok  script_pubkey: all five templates exact")


def test_history_backend(pipeline):
    """Lock A (the shared P2PKH template) on the derivatives chain:
    6 coinbase-and-change receives, 2 spends, 4×50 BTC left — the
    numbers the derivatives suite established by hand."""
    backends = _index_backends(pipeline)
    hist = backends["history"]
    check(isinstance(hist, ca.IndexHistory), "history not plugged")
    a = ca.decode_address(b58check_encode(0x00, tbw.FAKE_H20))
    s = hist.query(a).value
    check(s == {"outputs": 6, "received_sats": 250 * rs.SAT + 2,
                "spent_outputs": 2, "spent_sats": 50 * rs.SAT + 2,
                "unspent_outputs": 4, "unspent_sats": 200 * rs.SAT,
                "first_height": 1, "last_height": 5},
          f"lock A history summary wrong: {s}")
    b = ca.decode_address(segwit_addr(b"\xBB" * 20, 0))
    s = hist.query(b).value
    check(s["outputs"] == 2 and s["spent_outputs"] == 2
          and s["unspent_sats"] == 0 and s["received_sats"] == 13,
          f"lock B history summary wrong: {s}")
    tr = ca.decode_address(segwit_addr(bytes(range(32)), 1))
    absent = hist.query(tr)
    check(absent.value is None and absent.status == ca.Status.OK,
          "an unseen lock is a definite negative, not a failure")
    check(absent.source.watermark == hist.watermark
          and "/" not in absent.source.id,
          "every answer carries its watermark, and never a path")
    check("no confirmed activity" in hist.report(tr),
          "the honest absence line is missing")
    print("ok  history backend: hand-checked totals, honest absence")


def test_coinputs_backend(pipeline):
    """Lock B's coins were spent by t3 (alone) and t4 (together with a
    lock-A coin): 2 spending txs, 1 co-spent output, 1 other lock."""
    backends = _index_backends(pipeline)
    co = backends["co-inputs"]
    check(isinstance(co, ca.IndexCoInputs), "co-inputs not plugged")
    b = ca.decode_address(segwit_addr(b"\xBB" * 20, 0))
    s = co.query(b).value
    check(s == {"spending_txs": 2, "co_outputs": 1, "co_locks": 1,
                "truncated": False},
          f"lock B co-spend summary wrong: {s}")
    check("HINT" in co.report(b) and "CoinJoin" in co.report(b),
          "the heuristic caveat must be in every co-inputs report")
    tr = ca.decode_address(segwit_addr(bytes(range(32)), 1))
    check(co.query(tr).value is None, "an unspent/unseen lock has no "
                                      "co-spend surface")
    check("never spent" in co.report(tr), "honest absence line missing")
    print("ok  co-inputs backend: the t4 co-spend found, caveat "
          "always stated")


def test_report_with_index(pipeline, tmp):
    """run() with the new capabilities plugged: per-address lines,
    describe headers, and the CSV columns all present."""
    backends = _index_backends(pipeline)
    addr_a = b58check_encode(0x00, tbw.FAKE_H20)
    addr_b = segwit_addr(b"\xBB" * 20, 0)
    csv_path = os.path.join(tmp, "answers.csv")
    buf = io.StringIO()
    ca.run([addr_a, addr_b], backends, csv_path=csv_path, out=buf)
    text = buf.getvalue()
    check(f"# history: {dvm.FORMAT_TAG}" in text,
          "history describe header missing")
    check("/" not in text.split("\n")[0].split("(")[0],
          "a source header must never carry a filesystem path")
    check("history: received 6×" in text, "lock A history line missing")
    check("co-inputs: spent in 2 tx(s)" in text,
          "co-inputs line missing")
    check("UNDETERMINED" in text,
          "without an archive the exposure answer must degrade")
    import csv as csv_module
    with open(csv_path, newline="") as f:
        rows = list(csv_module.reader(f))
    check(rows[0][-2:] == ["history", "co_inputs"],
          "CSV must carry the two new columns")
    check(rows[1][-2].startswith("history: received")
          and rows[2][-1].startswith("co-inputs: spent"),
          "CSV rows must carry the capability summaries")
    print("ok  report: plugged capabilities appear in text and CSV")


def main():
    test_public_vectors()
    test_roundtrip_all_kinds()
    test_rejections()
    test_script_pubkey()
    with tempfile.TemporaryDirectory() as tmp:
        archive = build_archive(tmp)
        test_exposure(archive)
        test_by_construction_skips_archive(archive)
        test_undetermined_without_backend()
        test_balance_injected()
        test_balance_matches_a_taproot_output_by_its_script()
        test_balance_ignores_an_unspent_it_did_not_ask_for()
        test_end_to_end(archive)
        test_report_file_default(tmp, archive)
        pipe = build_pipeline(tmp)
        test_history_backend(pipe)
        test_coinputs_backend(pipe)
        test_report_with_index(pipe, tmp)
    print("PASS: addresses decode against public truth and by mirror "
          "symmetry, and the per-capability interface gives honest "
          "answers from our own archive, index and derivatives.")


if __name__ == "__main__":
    main()
