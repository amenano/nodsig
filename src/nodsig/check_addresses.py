#!/usr/bin/env python3
"""
check_addresses.py — the address check: given a list of addresses,
describe the QUANTUM EXPOSURE situation of each one, asking only
infrastructure you run yourself.

Why this exists: the census (utxo_census.py) and the reuse scan
(reuse_scan.py) answer the aggregate question — how much value sits
behind exposed keys, chain-wide. The natural next question is personal:
"and MY addresses?". Answering it must not cost your privacy: pasting
addresses into a public block explorer tells a third party exactly
which coins you care about. This tool asks only your own node and your
own archives. (Privacy rule, from the manual: NEVER send your own
addresses to public explorers or APIs. Develop and test with public
fixtures only.)

THE PER-CAPABILITY INTERFACE (architectural, decided 2026-07-11)
================================================================
An answer is assembled from independent CAPABILITIES, each one a
question with its own backend, each backend swappable WITHOUT touching
the others. This is a deliberate design element, not plumbing: the
provider mix is already heterogeneous today (exposure = our own
revelation archive; balance = Bitcoin Core RPC; history/co-inputs =
not plugged yet, Electrs or a graph derivative when a concrete need
arrives), and it will drift over time as graph-v2 derivatives replace
external indexes capacity by capacity. The contract each backend
signs:

    capability  question answered            backend today
    ----------  -------------------------    -------------------------
    exposure    was the key/script behind    RevealArchiveExposure
                this address ever revealed      (reveal-archive-v2 dir)
                on-chain?
    balance     how many satoshis sit         CoreBalance (scantxoutset
                behind it right now?             via your node's RPC)
    history     which coins came, which       IndexHistory (outpoint
                went, what remains?              index + derivatives,
                                                 --index + --derived)
    co-inputs   what was spent together       IndexCoInputs (same two
                with its coins?                  directories)

history and co-inputs were NOT PLUGGED stubs until 2026-07-21, with
"Electrs or a graph-v2 derivative" on the label: the derivative
arrived (outpoint-index-v3 + outpoint-derived-v2), so the interface
absorbed it exactly as designed — two new classes, zero changes
elsewhere, and no third-party indexer was ever needed. Both answer
from local sorted files (one ~40 KB bucket read per question) and
carry their own watermark, which may differ from the archive's: each
capability states its own perimeter.

Every backend answers in the same envelope (`capability.Result`):
status, value, and the source that says WHO answered and up to
which height, under which fingerprint. That is what keeps three cases
apart which would otherwise read alike — "not configured"
(UNSUPPORTED), "looked and found nothing" (OK with an empty value),
"cannot decide" (UNDETERMINED) — and only the middle one is
reassuring. A missing backend therefore never fakes an answer: the
answer degrades honestly ("UNDETERMINED" plus the reason), the same
rule the archive's lookup applies to absence. Adding an implementation
= one class with `source()`, `describe()` and `query()`, registered
in build_backends(); nothing else changes. That function takes a plain
mapping of directories and URLs, never the command line's own object:
the readers below it must work for any interface, and a signature that
demanded a Namespace would have made the one designed attachment point
the one place a second interface could not reach.

The source is also why a report names `outpoint-derived-v2` and a
fingerprint instead of the directory it read: a result must be
portable and must not describe the machine that produced it. Defaults are OUR documented choice; flags exist so that
third parties can explore other mixes (same philosophy as the scan's
perimeter flags).

WHAT THE ANSWERS MEAN
======================
- EXPOSED (by construction): the address itself contains the public
  key (bc1p… Taproot: the "program" IS the tweaked key, a point on the
  curve — Shor applies to it directly; same class as ancient P2PK).
- EXPOSED (by reuse): the address is a hash of key or script, but the
  archive has seen the preimage revealed in some confirmed spend. The
  flags say where (scriptSig / witness / inside a revealed script —
  the last one meaning: your key became public because a script it
  belongs to was spent, possibly by a co-signer).
- PROTECTED until first spend: hash-guarded and never revealed up to
  the archive watermark. Not a certificate: one spend changes it.
- exposed but empty: nothing at stake (needs the balance capability).
- UNDETERMINED: the capability that could answer is not configured.

Printed caveats (the tool repeats them, because an answer without its
perimeter is a number with too many decimals): off-chain exposure
(shared xpubs) is invisible by declaration; a P2SH/P2WSH address hides
its script until spent, so "protected" says nothing about WHO can
spend; unconfirmed mempool spends already reveal keys but confirmed
blocks are the archive's perimeter.

Usage:
    python3 check_addresses.py ADDR [ADDR...] --archive DIR
    python3 check_addresses.py --file list.txt --archive DIR \\
            [--rpc URL --cookie-file PATH] [--csv out.csv]

The report goes to a LOCAL FILE by default (check-results.txt, or --out):
screens get shared and terminals get logged, files stay where you put
them (manual privacy rule). --stdout prints to the screen instead,
for public fixtures or piping.

Mainnet only, on purpose: the archive is a mainnet artifact.
"""

import argparse
import base64
import csv
import json
import os
import sys
import urllib.error
import urllib.request

from nodsig import address_book as ab
from nodsig import check_report as cr
from nodsig import derivatives as dvm
from nodsig import linkage as lk
from nodsig import outpoint_index as oi
from nodsig import reveal_archive as ra
from nodsig import witness as wit
from nodsig.capability import Source, Result, Status
from nodsig.hashing import hash160, sha256d
from nodsig.reuse_scan import SAT, resolve_auth

# ---------------------------------------------------------------------------
# Address decoding — from text to (kind, digest)
#
# On-chain there are no addresses, only script patterns; an address is
# a checksummed TEXT ENCODING of the part of the pattern that varies
# (a hash, or for Taproot the key itself). Decoding is therefore pure
# arithmetic, no network: base58check for the 1…/3… families (sha256d
# checksum), bech32/bech32m for the bc1… families (BIP-173/BIP-350
# polynomial checksum). Both implemented here from the specs, stdlib
# only, with the BIP test vectors in test_check_addresses.py.
# ---------------------------------------------------------------------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2bc830a3   # BIP-350; plain bech32 uses 1


class AddressError(ValueError):
    """The string is not a valid mainnet address, with the reason."""


def _b58check_decode(addr):
    """base58check → payload bytes (version byte included)."""
    n = 0
    for ch in addr:
        try:
            n = n * 58 + B58_ALPHABET.index(ch)
        except ValueError:
            raise AddressError(f"invalid base58 character {ch!r}")
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    # each leading '1' encodes a leading zero byte the bigint lost
    raw = b"\x00" * (len(addr) - len(addr.lstrip("1"))) + raw
    if len(raw) < 5:
        raise AddressError("too short for a checksum")
    payload, checksum = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != checksum:
        raise AddressError("base58 checksum mismatch")
    return payload


def _bech32_polymod(values):
    gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _bech32_decode(addr):
    """bech32/bech32m string → (hrp, data values, encoding constant)."""
    if addr != addr.lower() and addr != addr.upper():
        raise AddressError("mixed case")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise AddressError("missing or misplaced separator")
    hrp, rest = addr[:pos], addr[pos + 1:]
    try:
        data = [BECH32_CHARSET.index(c) for c in rest]
    except ValueError:
        raise AddressError("invalid bech32 character")
    expanded = ([ord(c) >> 5 for c in hrp] + [0]
                + [ord(c) & 31 for c in hrp])
    const = _bech32_polymod(expanded + data)
    if const not in (1, BECH32M_CONST):
        raise AddressError("bech32 checksum mismatch")
    return hrp, data[:-6], const


def _convertbits(data, frombits, tobits):
    """Regroup a bit stream (5→8 here); strict padding per BIP-173."""
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise AddressError("invalid bit padding")
    return bytes(out)


# ---------------------------------------------------------------------------
# Address encoding — the reverse road, for the key entry point
#
# A public key is not an address: it is the thing three standard address
# forms wrap. `--key` takes the key (or its hash160) and expands it into
# those forms' canonical text encodings, and everything downstream —
# decoding, categories, capabilities, the report — treats them as the
# addresses they are. That is the whole design: the key entry point adds
# an expansion, never a second answering road. Correctness is pinned two
# ways in the tests: round-trip through the decoders above (which carry
# the BIP vectors), and frozen public vectors (the BIP-173 P2WPKH
# example, the wiki's P2PKH example).
# ---------------------------------------------------------------------------

def _b58check_encode(payload):
    """payload bytes (version byte included) → base58check string."""
    data = payload + sha256d(payload)[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58_ALPHABET[r] + s
    # each leading zero byte becomes a leading '1' the bigint would lose
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + s


def _bech32_encode(hrp, version, program):
    """segwit v0 (hrp, witness program) → bech32 string."""
    acc = bits = 0
    data = [version]
    for b in program:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expanded = ([ord(c) >> 5 for c in hrp] + [0]
                + [ord(c) & 31 for c in hrp])
    polymod = _bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def key_addresses(text):
    """A public key, as hex, expanded into its standard address forms:
    → (hash160 of the key, [p2pkh, p2sh-p2wpkh, p2wpkh address texts]).

    Accepts the serialized key itself (33 bytes starting 02/03, or 65
    starting 04) or its bare hash160 (20 bytes). The serialization
    matters and is the caller's statement: the two serializations of one
    point hash to different digests, so each is its own set of addresses
    (and its own archive record) — passing the key bytes your wallet
    uses asks about the addresses your wallet derives.

    The perimeter is the three single-key STANDARD forms. A key inside a
    multisig or any custom script has no address of its own: what the
    chain sees there is the script, and the archive's flags on the key's
    digest (which the p2pkh/p2wpkh rows consult) already cover the
    cosigner case at the key level."""
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raise AddressError(f"not hex: {text!r}")
    if len(raw) == 20:
        d20 = raw
    elif (len(raw) == 33 and raw[0] in (2, 3)) or \
            (len(raw) == 65 and raw[0] == 4):
        d20 = hash160(raw)
    else:
        raise AddressError(
            f"{len(raw)} bytes is neither a serialized public key "
            "(33 starting 02/03, 65 starting 04) nor a hash160 (20)")
    redeem = b"\x00\x14" + d20                  # the p2sh-p2wpkh wrapper
    return d20, [
        _b58check_encode(b"\x00" + d20),
        _b58check_encode(b"\x05" + hash160(redeem)),
        _bech32_encode("bc", 0, d20),
    ]


# What decoding yields: enough to route the capabilities. `category`
# names the archive category holding the preimage for hash-guarded
# kinds (None when the address exposes the key by construction).
KINDS = {
    "p2pkh":  ("keys",      "pay-to-pubkey-hash (1…)"),
    "p2sh":   ("scripts20", "pay-to-script-hash (3…)"),
    "p2wpkh": ("keys",      "native segwit v0 key hash (bc1q…, 20B)"),
    "p2wsh":  ("scripts32", "native segwit v0 script hash (bc1q…, 32B)"),
    "p2tr":   (None,        "taproot (bc1p…): the program IS the key"),
}


class Address:
    def __init__(self, text, kind, digest):
        self.text = text
        self.kind = kind
        self.digest = digest          # bytes, or the key for p2tr
        self.category = KINDS[kind][0]

    @property
    def by_construction(self):
        return self.category is None


def decode_address(text):
    """Mainnet address string → Address. Loud on anything else."""
    if text[:1] in ("1", "3"):
        payload = _b58check_decode(text)
        if len(payload) != 21:
            raise AddressError(f"unexpected payload length {len(payload)}")
        version, digest = payload[0], payload[1:]
        if version == 0x00:
            return Address(text, "p2pkh", digest)
        if version == 0x05:
            return Address(text, "p2sh", digest)
        raise AddressError(f"unknown base58 version {version:#04x} "
                           "(mainnet only)")
    if text.lower().startswith("bc1"):
        hrp, data, const = _bech32_decode(text)
        if hrp != "bc":
            raise AddressError(f"not a mainnet hrp: {hrp!r}")
        if not data:
            raise AddressError("empty witness data")
        version, program = data[0], _convertbits(data[1:], 5, 8)
        if version > 16 or not 2 <= len(program) <= 40:
            raise AddressError("invalid witness program")
        if version == 0:
            if const != 1:
                raise AddressError("segwit v0 must use plain bech32")
            if len(program) == 20:
                return Address(text, "p2wpkh", program)
            if len(program) == 32:
                return Address(text, "p2wsh", program)
            raise AddressError("v0 program must be 20 or 32 bytes")
        if const != BECH32M_CONST:
            raise AddressError("segwit v1+ must use bech32m")
        if version == 1 and len(program) == 32:
            return Address(text, "p2tr", program)
        raise AddressError(f"witness v{version} has no defined meaning "
                           "yet: refusing to guess an answer")
    raise AddressError("not a recognized mainnet address form")


def script_pubkey(address):
    """The scriptPubKey the address encodes — the exact bytes a sender
    locks coins with. The index derivatives key everything by hash160
    of these bytes (a LOCK, the honest boundary: one identical
    script, not a wallet, not a key under its other faces), so this
    mapping is the whole bridge between an address and its history."""
    d = address.digest
    if address.kind == "p2pkh":
        return b"\x76\xa9\x14" + d + b"\x88\xac"
    if address.kind == "p2sh":
        return b"\xa9\x14" + d + b"\x87"
    if address.kind == "p2wpkh":
        return b"\x00\x14" + d
    if address.kind == "p2wsh":
        return b"\x00\x20" + d
    return b"\x51\x20" + d                     # p2tr


# ---------------------------------------------------------------------------
# Capability backends
# ---------------------------------------------------------------------------

class RevealArchiveExposure:
    """Exposure via OUR archive: a sorted-file membership check
    answered entirely from local disk. The answer carries the archive
    watermark: 'not revealed' always means 'not revealed UP TO height
    H, in confirmed blocks'.

    The merged files are read through the archive's own ladder-backed
    reader — one resident ladder bisected in RAM, then ONE ~40 KB
    bucket read — and the readers are opened once and reused across the
    whole address list, so a hundred addresses pay the ladder load
    once. (This used to be the blind on-disk bisect, ~35 seeks per
    address per category, while the archive's own `lookup` already had
    the ladder: same files, two roads, and the slow one was in the
    tool people actually run.) Unfused runs keep the blind bisect:
    they have no ladder, and there are few of them."""

    def __init__(self, archive_dir):
        self.dir = archive_dir
        self.state = ra._load_state(archive_dir)
        self.manifest = ra._load_manifest(archive_dir)
        self.watermark = self.state["last_height"]
        self._readers = {}

    def _reader(self, cat):
        """The merged reader for a category, opened (and its ladder
        sha-checked) on first use."""
        if cat not in self._readers:
            self._readers[cat] = (
                None if self.manifest is None
                else ra._open_merged(self.dir, self.manifest, cat))
        return self._readers[cat]

    def close(self):
        for reader in self._readers.values():
            if reader is not None:
                reader.close()
        self._readers = {}

    def source(self):
        # The answers OR the merged file with any run not yet fused, so
        # a leftover run means the reply covers more than the manifest
        # describes: that is precisely the unsealed case, and the
        # fingerprint must be withheld rather than implied.
        sealed = self.manifest is not None and not self.state["runs"]
        return Source.artifact(
            ra.FORMAT_TAG, self.watermark,
            self.manifest["fingerprint"] if sealed else None)

    def describe(self):
        return self.source().describe("exposure")

    def query(self, address):
        """→ Result whose value is (byte, first_height), reduced across
        the merged file and any unfused runs, or a definite negative when
        the digest was never revealed. Categories don't mix: a p2sh digest
        is only looked up among revealed redeem scripts."""
        cat = address.category
        hit = None
        if self.manifest is not None:
            hit = ra._merged_sighting(self.dir, self.manifest, cat,
                                      address.digest, self._reader(cat))
        for run in self.state["runs"]:
            if run["category"] != cat:
                continue
            got = ra._bisect_file(
                os.path.join(self.dir, ra.RUNS_DIR, run["name"]),
                cat, address.digest)
            if got is not None:
                hit = got if hit is None else ra._reduce(
                    cat, hit[0], hit[1], got[0], got[1])
        return Result.ok(hit, self.source())


class CoreBalance:
    """Balance via your own node: ONE scantxoutset call for the whole
    list (the RPC accepts many descriptors per call — on a Raspberry
    Pi that is minutes for the lot instead of minutes each). The rpc
    callable is injectable so tests never need a node — and so this
    tool NEVER touches the node by surprise: no --rpc flag, no call."""

    def __init__(self, rpc_url, auth, rpc_call=None):
        self.rpc_url = rpc_url
        self.auth = auth
        self._call = rpc_call or self._http_call
        # True only when we will really hit a node (no injected call):
        # gates the "this is slow" heads-up so tests stay silent.
        self._real_node = rpc_call is None
        self.height = None
        self._unspents = None

    def _http_call(self, method, params):
        req = urllib.request.Request(
            self.rpc_url,
            json.dumps({"jsonrpc": "2.0", "id": 0, "method": method,
                        "params": params}).encode(),
            {"Content-Type": "application/json",
             "Authorization": "Basic " + base64.b64encode(
                 self.auth.encode()).decode()})
        with urllib.request.urlopen(req, timeout=7200) as resp:
            reply = json.loads(resp.read())
        if reply.get("error"):
            raise RuntimeError(f"RPC {method}: {reply['error']}")
        return reply["result"]

    @property
    def scanned(self):
        """True once `scan` has run: until then there is no answer to
        give, and asking would report a false zero."""
        return self._unspents is not None

    def source(self):
        # A live node is not a sealed artifact: no fingerprint, and the
        # watermark is the tip it scanned, known only after the call.
        # The URL stays out — it is topology, like a path.
        return Source.node("bitcoin-core-rpc scantxoutset",
                               self.height)

    def describe(self):
        return self.source().describe("balance")

    def scan(self, addresses):
        """One pass for all addresses; keeps per-script totals."""
        if self._real_node:
            # scantxoutset walks the WHOLE UTXO set (one call for the
            # whole list): minutes on a Pi, more on a cold cache. Say so
            # before we block, or it looks hung. Goes to stderr so it
            # never mixes with the answers on stdout.
            print(f"scanning the UTXO set on your node ({self.rpc_url}): "
                  f"one scantxoutset call for all {len(addresses)} "
                  "address(es) — this can take several minutes, longer "
                  "on a Raspberry Pi / cold cache. The client waits.",
                  file=sys.stderr, flush=True)
        result = self._call("scantxoutset",
                            ["start",
                             [f"addr({a.text})" for a in addresses]])
        self.height = result.get("height")
        # Keyed by scriptPubKey, not by the descriptor's text. The node
        # does NOT echo back the addr() that was asked: `desc` is what
        # the node infers from the script it matched, and for a taproot
        # output that inference is `rawtr(<x-only key>)`, which no
        # address string ever equals. Reading the address out of it
        # left every p2tr balance at zero — and zero is the answer that
        # reassures, on the one class this tool calls exposed by
        # construction. The scriptPubKey is in the reply and is exactly
        # what `script_pubkey` builds, so the two sides meet on bytes.
        wanted = {script_pubkey(a).hex(): a.text for a in addresses}
        self._unspents = {}
        for u in result.get("unspents", []):
            key = wanted.get(u.get("scriptPubKey", ""))
            if key is None:
                # An unspent that matches no address we asked about
                # cannot be attributed; counting it under some other
                # address would invent a balance.
                continue
            sats = round(u["amount"] * 100_000_000)
            self._unspents[key] = self._unspents.get(key, 0) + sats

    def query(self, address):
        """→ Result whose value is the satoshis behind the address at
        the scanned tip. Zero is a value, not an absence."""
        return Result.ok(self._unspents.get(address.text, 0),
                         self.source())


def _btc(sats):
    return f"{sats / SAT:,.8f} BTC"


class IndexHistory:
    """History via OUR outpoint index and its derivatives: one ladder
    bucket read streams every output that ever paid this lock, each
    row already carrying its spend. Nothing leaves the machine, and
    the answer is as-of the index watermark — an OFFLINE view, older
    than the node's tip by construction and honest about it."""

    def __init__(self, index, derived):
        self.index = index
        self.derived = derived
        self.watermark = index.watermark

    def source(self):
        return Source.artifact(dvm.FORMAT_TAG, self.watermark,
                                   self.derived.manifest["fingerprint"])

    def describe(self):
        return self.source().describe("history")

    def close(self):
        """The Index/Derived pair is shared with IndexCoInputs, so both
        close it and the second call must be a no-op — it is."""
        self.derived.close()
        self.index.close()

    def query(self, address):
        """→ Result whose value is a dict of totals, or a definite
        negative when the lock never appeared."""
        idx, first, last = self.index, None, 0
        n = received = spent_sats = n_spent = unspent_sats = 0
        for out_ord, spender, value in self.derived.rows(
                hash160(script_pubkey(address))):
            n += 1
            received += value
            h = idx.height_of_output(out_ord)
            first = h if first is None else first
            last = max(last, h)
            if spender is None:
                unspent_sats += value
            else:
                n_spent += 1
                spent_sats += value
                last = max(last, idx.height_of_tx(spender))
        if n == 0:
            return Result.ok(None, self.source())
        return Result.ok({"outputs": n, "received_sats": received,
                          "spent_outputs": n_spent,
                          "spent_sats": spent_sats,
                          "unspent_outputs": n - n_spent,
                          "unspent_sats": unspent_sats,
                          "first_height": first, "last_height": last},
                         self.source())

    def report(self, address):
        """The one-line summary, for a caller with no Result in hand."""
        return self.render(self.query(address).value)

    def render(self, s, status=Status.OK):
        """The same line from a value already obtained. The split is
        not decoration: a caller that wants BOTH the structured value
        and the line would otherwise ask twice, and each ask is a
        ladder bucket read.

        The status is taken rather than assumed: this backend answers
        OK or raises, but the caller renders every capability through
        the same call, and one that could not decide must not print as
        a negative."""
        if status != Status.OK:
            return f"history: {status} — no summary was produced"
        if s is None:
            return ("history: no confirmed activity up to height "
                    f"{self.watermark:,}")
        return (f"history: received {s['outputs']}× "
                f"{_btc(s['received_sats'])}, spent "
                f"{s['spent_outputs']}× {_btc(s['spent_sats'])}, "
                f"unspent {s['unspent_outputs']}× "
                f"{_btc(s['unspent_sats'])} "
                f"(heights {s['first_height']:,}–{s['last_height']:,}, "
                f"index at {self.watermark:,})")


class IndexCoInputs:
    """Co-spends via the same derivatives: for every spend of this
    lock's coins, the spending transaction's OTHER inputs and their
    locks. What it means is stated every time it is printed: outputs
    consumed by one transaction usually share an owner (the
    common-input heuristic, Q2) — a HINT, never proof, and CoinJoin
    breaks the assumption on purpose. Enumeration is capped for
    pathological locks (an exchange address with millions of spends):
    the report says when it sampled."""

    CAP = 10_000

    def __init__(self, index, derived):
        self.index = index
        self.derived = derived
        self.watermark = index.watermark

    def source(self):
        return Source.artifact(dvm.FORMAT_TAG, self.watermark,
                                   self.derived.manifest["fingerprint"])

    def describe(self):
        return self.source().describe("co-inputs")

    def close(self):
        self.derived.close()
        self.index.close()

    def query(self, address):
        """→ Result whose value is a dict of counts, or a definite
        negative when nothing was ever spent (an unspent coin has no
        co-spend surface)."""
        lock = hash160(script_pubkey(address))
        spenders = set()
        truncated = False
        for _out, spender, _value in self.derived.rows(lock):
            if spender is None:
                continue
            if len(spenders) >= self.CAP:
                truncated = True
                break
            spenders.add(spender)
        if not spenders:
            return Result.ok(None, self.source())
        co_locks = set()
        co_outputs = 0
        for tx_ord in spenders:
            for so in self.derived.inputs_of(tx_ord):
                _v, so_lock = self.index.output(so)
                if so_lock != lock:
                    co_locks.add(so_lock)
                    co_outputs += 1
        return Result.ok({"spending_txs": len(spenders),
                          "co_outputs": co_outputs,
                          "co_locks": len(co_locks),
                          "truncated": truncated},
                         self.source())

    def report(self, address):
        """The one-line summary, for a caller with no Result in hand."""
        return self.render(self.query(address).value)

    def render(self, s, status=Status.OK):
        """The same line from a value already obtained (see
        IndexHistory.render: asking twice costs a second walk over
        every spend of the lock)."""
        if status != Status.OK:
            return f"co-inputs: {status} — no summary was produced"
        if s is None:
            return "co-inputs: never spent — no co-spend surface"
        text = (f"co-inputs: spent in {s['spending_txs']} tx(s), "
                f"co-spent with {s['co_outputs']} output(s) under "
                f"{s['co_locks']} other lock(s)")
        if s["truncated"]:
            text += f" (first {self.CAP:,} spends sampled)"
        return text + (" — common-input HINT, not ownership proof "
                       "(CoinJoin breaks the assumption)")


class NotPlugged:
    """The honest stub: the capability exists in the design, no backend
    is configured. It says so instead of guessing — and it documents
    what WOULD plug in, because the gap is a roadmap, not a bug."""

    def __init__(self, capability, candidates):
        self.capability = capability
        self.candidates = candidates

    def source(self):
        return Source(f"not configured (pluggable: "
                          f"{self.candidates})")

    def describe(self):
        return self.source().describe(self.capability)

    def query(self, address):
        """UNSUPPORTED, never a negative: "no backend" and "the backend
        looked and found nothing" are different answers, and only one
        of them is reassuring."""
        return Result.unsupported(self.source())


class WitnessNonceExposure:
    """Nonce exposure via the witness table: was the key behind this
    address one of those that signed twice under the same nonce?

    THE QUESTION AND ITS PRICE. Asked the strong way — `nodsig nonces
    address` — this needs the index, the derivatives and a node that
    re-reads blocks: about 439 GB and hours. Asked here it is 1.03 MB
    read once, offline, for the whole address list, because the witness
    table already holds the resolutions. The two questions are NOT the
    same, and the report says so: this one only sees the points the
    census reported as repeated.

    THREE THINGS THAT TRAVEL WITH EVERY ANSWER, not in a footnote:

    1. the search is a LINEAR SCAN. The table is ordered by `r`, not by
       key, so there is no index to bisect: 11,766 rows are walked once
       and grouped by key in memory. Calling it a lookup would promise
       a structure that is not there;
    2. ABSENT DOES NOT MEAN CLEAN. It means "not among the cases this
       table resolved", and the census hands the resolver only the
       points it could decide were repeated. A negative here is a
       negative about a set, not about the chain;
    3. it answers for SINGLE-KEY addresses only. A p2sh/p2wsh hides
       which keys are behind it until it spends, and a taproot input
       carries no key beside the signature (the rows are flagged
       key-absent). For those the answer is UNDETERMINED with the
       reason, never a reassuring negative.

    THE FORMAT TAG IS CHECKED FROM THE FIRST COMMIT, and that is not
    ceremony: the v3 package rebuilds this table from public code. If
    the rebuild changed the tag or the row layout, this capability must
    stop instead of reading bytes at the wrong offsets."""

    def __init__(self, witness_dir):
        # Both refuse a directory that is not a witness table, and
        # _load_state refuses one whose format tag is not ours.
        self.state = wit._load_state(witness_dir)
        self.manifest = wit._load_manifest(witness_dir)
        if self.manifest.get("format") != wit.FORMAT_TAG:
            raise wit.WitnessError(
                f"witness manifest says {self.manifest.get('format')!r}, "
                f"this build reads {wit.FORMAT_TAG!r}")
        self.dir = witness_dir
        self._by_key = None
        self._by_point = None

    def _load(self):
        """One pass over the whole table, for every address at once."""
        if self._by_key is None:
            by_key, by_point = {}, {}
            for rec in wit.iter_records(self.dir):
                by_point.setdefault(wit.rec_point(rec), []).append(rec)
                if wit.has_key(rec):
                    by_key.setdefault(wit.rec_key(rec), []).append(rec)
            self._by_key, self._by_point = by_key, by_point
        return self._by_key, self._by_point

    def source(self):
        # NO WATERMARK, on purpose. A height here would print "confirmed
        # blocks 1..N" and promise a perimeter this table does not have:
        # it covers the points its census reported as repeated, which is
        # a SET and not a range. The perimeter is stated in words, in
        # every line this capability prints.
        return Source.artifact(wit.FORMAT_TAG, None,
                               self.manifest.get("fingerprint"))

    def describe(self):
        return self.source().describe("nonce-exposure")

    def query(self, address):
        """→ Result whose value lists the resolved points this key
        appears in, or a definite negative when it appears in none."""
        if address.category != "keys":
            return Result.undetermined(self.source())
        if address.kind == "p2tr":
            return Result.undetermined(self.source())
        by_key, by_point = self._load()
        rows = by_key.get(address.digest)
        if not rows:
            return Result.ok(None, self.source())

        points = []
        for point in sorted({wit.rec_point(r) for r in rows}):
            resolution, exposed = wit.resolution_of(by_point[point])
            heights = [wit.rec_height(r) for r in by_point[point]
                       if wit.rec_key(r) == address.digest]
            points.append({"point": point.hex(),
                           "resolution": resolution,
                           "exposes_this_key": address.digest in exposed,
                           "first_height": min(heights)})
        return Result.ok({"points": points,
                          "exposed": any(p["exposes_this_key"]
                                         for p in points)},
                         self.source())

    def report(self, address):
        """The one-line summary, for a caller with no Result in hand."""
        res = self.query(address)
        return self.render(res.value, res.status)

    def render(self, value, status=Status.OK):
        if status != Status.OK:
            return ("nonce-exposure: UNDETERMINED — this table names the "
                    "public key beside a signature, which a script hash "
                    "or a taproot input does not give")
        if value is None:
            return ("nonce-exposure: not among the repeated-nonce cases "
                    "this table resolved — which is NOT 'no reuse': the "
                    "census hands over only the points it could see "
                    "repeated")
        if value["exposed"]:
            hit = next(p for p in value["points"]
                       if p["exposes_this_key"])
            return ("nonce-exposure: EXPOSED — two signatures under one "
                    f"nonce and this key (point {hit['point'][:8]}…, "
                    f"first seen at height {hit['first_height']:,}): the "
                    "private key follows by arithmetic anybody can do")
        kinds = sorted({p["resolution"] for p in value["points"]})
        return (f"nonce-exposure: present in {len(value['points'])} "
                f"resolved point(s), none exposing this key "
                f"({', '.join(kinds)})")


def _private_file(path, **kw):
    """Open a file for writing that only its owner can read.

    Both files this tool writes list the addresses somebody asked
    about, which is the one thing this whole project exists not to
    disclose. Created with 0600 instead of whatever the umask says,
    because the usual 0644 hands them to every other account on the
    machine, and a tool that tells you not to send your questions to a
    stranger should not leave them readable by the next login.

    The mode applies at CREATION: a file that already exists keeps the
    permissions it has. Changing those would be this tool deciding
    something about a path the user chose, and truncating it is already
    as much as it should do to a file it was merely pointed at.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, "w", **kw)


def build_backends(sources, rpc_call=None):
    """The single registration point of the interface. Order and
    content ARE the configuration: our defaults, overridable by what the
    caller supplies, explorable by anyone who clones the tools.

    `sources` is a plain mapping of what to plug in, and every key is
    optional:

        archive       a reveal-archive-v2 directory
        index         an outpoint-index-v3 directory
        derived       an outpoint-derived-v2 directory (needs `index`)
        witness       a nonces-witness-v1 directory
        rpc           a node URL, for the live balance
        cookie_file   where the node's credential is (never the value)

    A MAPPING AND NOT THE COMMAND LINE'S OBJECT, and the distinction is
    an invariant of this project rather than a preference: the kernels
    and the readers know nothing about how a caller was invoked, and the
    orchestration adapts. This function used to take argparse's
    `Namespace`, which made the one place designed to be an attachment
    point the one place that required a command line. `_backends_from_args`
    below is that adapter, and it is the only thing here that knows what
    a flag is.
    """
    get = sources.get
    backends = {}
    if get("archive"):
        backends["exposure"] = RevealArchiveExposure(get("archive"))
    if get("rpc"):
        # One single path for credentials, the same as every other
        # command: the cookie file, or NODSIG_RPC_AUTH. Never the argv.
        # See resolve_auth in reuse_scan.py.
        backends["balance"] = CoreBalance(
            get("rpc"), resolve_auth(get("cookie_file")), rpc_call)
    if get("index") and get("derived"):
        # One Index/Derived pair shared by both capabilities: the
        # resident tables (blocks.bin, ladders) are paid for once.
        index = oi.Index(get("index"))
        derived = dvm.Derived(get("derived"), index)
        backends["history"] = IndexHistory(index, derived)
        backends["co-inputs"] = IndexCoInputs(index, derived)
        backends["linkage"] = lk.IndexLinkage(index, derived)
    # Every capability the report speaks about appears, configured or
    # not. A capability that simply vanished from the report when its
    # flag was absent read as "not relevant here" instead of "nobody
    # asked it", and the two are different answers — only one of them
    # is reassuring. The stub costs nothing and says which flag would
    # plug it in.
    if get("witness"):
        backends["nonce-exposure"] = WitnessNonceExposure(get("witness"))
    for cap, candidates in (
            ("exposure", "reveal-archive-v2 (--archive)"),
            ("balance", "bitcoin-core-rpc scantxoutset (--rpc)"),
            ("history", "outpoint-index derivatives "
                        "(--index + --derived)"),
            ("co-inputs", "outpoint-index derivatives "
                          "(--index + --derived)"),
            ("linkage", "outpoint-index derivatives "
                        "(--index + --derived)"),
            ("nonce-exposure", f"{wit.FORMAT_TAG} (--witness)")):
        backends.setdefault(cap, NotPlugged(cap, candidates))
    return backends


def _backends_from_args(args, rpc_call=None):
    """The command line's own object, translated into the mapping above.

    This is where knowledge of flags stops. Everything below it takes
    directories and URLs, which is what lets a second interface (a
    service, a notebook, another tool) reach the same readers without
    manufacturing a Namespace to satisfy a signature.
    """
    return build_backends(
        {k: getattr(args, k, None) for k in
         ("archive", "index", "derived", "witness", "rpc", "cookie_file")},
        rpc_call)


# ---------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------

def flags_story(flags):
    """Turn a KEY record's flags byte into words. The distinction
    that matters: FLAG_SIG/FLAG_WIT mean the key itself signed in
    public; the INNER flags mean the key surfaced because a script
    containing it was revealed — possibly by a co-signer, not by the
    key's owner. Different behaviour, same exposure.

    FLAG_UNCOMPRESSED is read and deliberately NOT reported here: the
    form a key was serialized in says nothing about whether it is
    exposed, and this report answers exposure. The archive's own
    `lookup` prints it, because that command describes the record
    rather than the owner's risk."""
    where = []
    if flags & ra.FLAG_SIG:
        where.append("key seen in a scriptSig")
    if flags & ra.FLAG_WIT:
        where.append("key seen in a witness")
    if flags & (ra.FLAG_INNER_SIG | ra.FLAG_INNER_WIT):
        where.append("seen inside a revealed script "
                     "(co-signer exposure counts)")
    return "; ".join(where) if where else "key revealed by a spend"


def sighting_story(address, byte):
    """The record's third byte means two different things, and the
    address's category says which — same split the archive's own
    `lookup` makes. For a key it holds the flags. For a
    revealed redeem/witness script it holds HOW MANY public keys the
    script carried (in the byte that was reserved and zero under v1):
    reading that count as flags told a multisig owner their key had
    signed in a scriptSig when only the script had surfaced."""
    if address.category == "keys":
        return flags_story(byte)
    inside = (f" ({byte} key{'s' if byte != 1 else ''} inside, "
              "co-signer exposure counts)" if byte else "")
    return "script revealed by a spend" + inside


# The four things the exposure question can resolve to, as KEYS: the
# printed sentence is for a person and may grow a clause (the balance
# one does), while a tool needs a token that never moves. The words
# themselves are the summary's own key names, so the two cannot drift.
EXPOSED_BY_CONSTRUCTION = "exposed_by_construction"
EXPOSED_BY_REUSE = "exposed_by_reuse"
PROTECTED = "protected"
UNDETERMINED = "undetermined"

# Exposure by construction is a fact of the ENCODING: the bc1p… program
# IS the key. It comes from no artifact, has no height, and does not
# perish — so it must not be attributed to the exposure backend, which
# has all three. Same source name the same-key finding uses.
ADDRESS_CODEC = "address-codec"


class Answer:
    """What the exposure question resolved to for one address.

    `key` is the token (one of the four above), `text` is the sentence
    a person reads. They are NOT the same thing on purpose: the
    sentence merges in "but empty: nothing at stake", which is a
    statement about exposure AND balance at once. That merge is fine in
    prose and forbidden in a numeric answer — two perimeters in one
    value belong in the report's `crossed` block and nowhere else — so
    the key stays pure exposure and the balance travels beside it."""

    __slots__ = ("key", "text", "detail", "balance_sats", "source_name",
                 "first_height")

    def __init__(self, key, text, detail, balance_sats, source_name,
                 first_height=None):
        self.key = key
        self.text = text
        self.detail = detail
        self.balance_sats = balance_sats
        self.source_name = source_name
        # Where the reuse was first seen, when there was one. Kept
        # structured because the linkage block needs the number and the
        # printed sentence only has it inside prose.
        self.first_height = first_height


def answer(address, backends):
    """→ Answer. The single place where an exposure question is
    resolved, whatever renders it afterwards."""
    balance = None
    bal = backends.get("balance")
    if isinstance(bal, CoreBalance) and bal.scanned:
        balance = bal.query(address).value

    first_seen = None
    if address.by_construction:
        key, origin = EXPOSED_BY_CONSTRUCTION, ADDRESS_CODEC
        v = "EXPOSED (by construction)"
        d = KINDS[address.kind][1]
    else:
        origin = "exposure"
        exp = backends.get("exposure")
        # The status decides, not the class: a source that declines the
        # capability and one that answers "nothing" must not collapse
        # into the same answer — only the second is reassuring.
        res = exp.query(address) if exp is not None else None
        if res is None or res.status != Status.OK:
            return Answer(UNDETERMINED, "UNDETERMINED",
                          "no exposure backend configured (--archive)",
                          balance, None)
        hit = res.value
        if hit is not None:
            byte, first_height = hit
            first_seen = first_height
            key = EXPOSED_BY_REUSE
            v = "EXPOSED (by reuse)"
            d = (f"{sighting_story(address, byte)}, "
                 f"first seen at height {first_height:,}")
        else:
            key = PROTECTED
            v = "PROTECTED until first spend"
            # The height comes off the answer's own source, not off
            # the backend object: that is the whole point of the
            # envelope, and it keeps `answer` working with any
            # exposure backend, not only this one.
            d = (f"not revealed in confirmed blocks up to "
                 f"height {res.source.watermark:,}")

    if v.startswith("EXPOSED") and balance == 0:
        v += " but empty: nothing at stake"
    return Answer(key, v, d, balance, origin, first_seen)


# The capabilities a report speaks about, in the order they are
# printed. One list, so text and CSV cannot drift into disagreeing
# about which capabilities exist or in which order they appear.
CAPABILITIES = ("exposure", "balance", "history", "co-inputs",
                "linkage", "nonce-exposure")

# The ones that add a line of their own under each address.
PER_ADDRESS_CAPABILITIES = ("history", "co-inputs", "nonce-exposure")

# One column per capability, derived from the list above: a column that
# had to be added by hand is a column that gets forgotten.
CSV_COLUMNS = (["address", "kind", "answer", "detail", "balance_sats"]
               + [c.replace("-", "_") for c in PER_ADDRESS_CAPABILITIES])


class SourceLine:
    """Who answered one capability, and whether it was asked at all.

    Kept as a small object rather than a printed line because the two
    readers want different things out of it: the text truncates the
    fingerprint (a person reads it), a tool wants the whole digest, and
    a capability nobody configured has no fingerprint at all but does
    have the name of the flag that would plug it in."""

    __slots__ = ("capability", "source", "status", "pluggable")

    def __init__(self, capability, source, status, pluggable=None):
        self.capability = capability
        self.source = source
        self.status = status
        self.pluggable = pluggable

    def describe(self):
        return self.source.describe(self.capability)


class CapabilityAnswer:
    """One capability's answer about one address: the envelope it came
    in, plus the line it renders to. Both are kept because both are
    asked for — and asking the backend twice would mean reading the
    same ladder bucket twice."""

    __slots__ = ("capability", "status", "value", "source", "text")

    def __init__(self, capability, result, text):
        self.capability = capability
        self.status = result.status
        self.value = result.value
        self.source = result.source
        self.text = text


class Entry:
    """One line of the report: an address that decoded and its answers,
    or a line that is not an address at all.

    `address` is None for the second case, and that is the only thing
    that distinguishes them: an invalid line still occupies a row in
    every rendering, because dropping it would silently shrink what the
    user asked about."""

    __slots__ = ("address", "text", "kind", "answer", "capabilities",
                 "group")

    def __init__(self, address, text, kind, answer, capabilities=None,
                 group=None):
        self.address = address
        self.text = text
        self.kind = kind
        # An Answer in both cases: a line that is not an address still
        # got an answer, it came from the codec instead of the chain.
        self.answer = answer
        # capability name → CapabilityAnswer, only for the backends
        # that were actually plugged.
        self.capabilities = capabilities or {}
        # The label of the address book group that listed it, None when
        # it came from the command line: an address with no compartment
        # can be answered about, but cannot take part in a sentence
        # about compartments.
        self.group = group

    @property
    def valid(self):
        return self.address is not None

    @property
    def detail(self):
        """The second line under the address: the reason for the
        answer, or the reason the text is not an address."""
        return self.answer.detail

    @property
    def balance_sats(self):
        return self.answer.balance_sats


class Report:
    """The whole answer, in memory, before anybody renders it.

    THE ANTI-DRIFT RULE: text, CSV — and the JSON that comes next —
    are RENDERINGS of this object. None of them recomputes anything of
    its own. Two roads that produce the same number always diverge in
    the end, and here they would diverge in silence, because nobody
    compares a text report against a JSON one by hand.

    `sources` keeps the `Source` OBJECT, not the line it prints: the
    text truncates fingerprints because a person reads it, while a tool
    wants the whole digest, and only the object has both."""

    __slots__ = ("sources", "entries", "book", "linkage")

    def __init__(self, sources, entries, book=None, linkage=None):
        self.sources = sources          # [SourceLine, …]
        self.entries = entries          # [Entry, …], input order
        # The links between those entries, with each class carrying its
        # own status: `same_key` answers with no artifacts at all.
        self.linkage = linkage
        # The address book the addresses came from, when there was one:
        # it is what the coverage sentence is made of, and it is the
        # only thing that knows what the user MEANT to keep apart.
        self.book = book

    def source_of(self, capability):
        for line in self.sources:
            if line.capability == capability:
                return line
        return None

    def answered(self, capability):
        """True when the capability was configured and answered — the
        one question every aggregate has to ask before it prints a
        number, because a zero from a capability nobody asked reads as
        'looked, found nothing'."""
        line = self.source_of(capability)
        return line is not None and line.status == Status.OK

    def csv_rows(self):
        """The lossy projection: one flat row per entry, no structure.
        Kept here rather than in the CSV writer so that every rendering
        reads its values off the same object."""
        for e in self.entries:
            yield ([e.text, e.kind, e.answer.text, e.detail,
                    "" if e.balance_sats is None else e.balance_sats]
                   + [e.capabilities[c].text if c in e.capabilities
                      else "" for c in PER_ADDRESS_CAPABILITIES])


def build_report(addresses_text, backends, book=None, depth=1):
    """Ask every capability about every address → a Report. Prints
    nothing, opens nothing, and is the single place where an answer is
    decided."""
    addresses, bad = [], []
    for t in addresses_text:
        try:
            addresses.append(decode_address(t))
        except AddressError as e:
            bad.append((t, str(e)))

    bal = backends.get("balance")
    if isinstance(bal, CoreBalance) and addresses:
        bal.scan(addresses)

    # Who answered, up to what height, under which fingerprint. No
    # paths — a report must be portable and must not describe the
    # machine that produced it. Read AFTER the balance scan, because a
    # live node's watermark is the tip it scanned and is unknown until
    # the call has happened.
    sources = []
    for cap in CAPABILITIES:
        b = backends.get(cap)
        if b is None:
            continue
        unplugged = isinstance(b, NotPlugged)
        sources.append(SourceLine(
            cap, b.source(),
            Status.UNSUPPORTED if unplugged else Status.OK,
            b.candidates if unplugged else None))

    entries = []
    for a in addresses:
        ans = answer(a, backends)
        extra = {}
        for cap in PER_ADDRESS_CAPABILITIES:
            b = backends.get(cap)
            if b is not None and not isinstance(b, NotPlugged):
                res = b.query(a)
                extra[cap] = CapabilityAnswer(
                    cap, res, b.render(res.value, res.status))
        entries.append(Entry(a, a.text, a.kind, ans, extra,
                             book.group_of(a.text) if book else None))
    # The invalid lines come last, together: they are the one part of
    # the report that says nothing about the chain. They keep their
    # group: an address that did not decode still came from somewhere,
    # and the coverage sentence counts it as one the book has and the
    # report could not check.
    for t, why in bad:
        entries.append(Entry(None, t, "invalid",
                             Answer(None, "NOT AN ADDRESS", why, None,
                                    ADDRESS_CODEC),
                             group=book.group_of(t) if book else None))

    # The links come last: they are about the SET, and every entry has
    # to exist before a pair of them can be tied together.
    backend = backends.get("linkage")
    if isinstance(backend, NotPlugged):
        backend = None
    linkage = lk.build(entries, backend, depth, book)

    return Report(sources, entries, book=book, linkage=linkage)


def render_text(report, out=sys.stdout):
    """The report as a person reads it."""
    for line in report.sources:
        print(f"# {line.describe()}", file=out)
    print(file=out)

    cr.render_overview_text(report, out)
    if report.linkage is not None:
        lk.render_text(report.linkage, out)
        print(file=out)

    for e in report.entries:
        if not e.valid:
            print(f"{e.text}\n    NOT AN ADDRESS: {e.detail}", file=out)
            continue
        line = f"{e.text}\n    {e.kind}: {e.answer.text}\n    {e.detail}"
        if e.balance_sats is not None:
            line += f"\n    balance: {e.balance_sats:,} sats"
        for cap in PER_ADDRESS_CAPABILITIES:
            if cap in e.capabilities:
                line += f"\n    {e.capabilities[cap].text}"
        print(line, file=out)

    print(file=out)
    print(cr.caveats_text(report), file=out)


def render_csv(report, csv_path):
    """The report as a spreadsheet reads it: one row per address and
    nothing else. A LOSSY projection by design — the paths and the
    structured findings do not fit in a cell, which is why the JSON
    exists — and 0600 like every other file that lists somebody's
    addresses."""
    with _private_file(csv_path, newline="") as f:
        w = csv.writer(f)
        w.writerow(CSV_COLUMNS)
        w.writerows(report.csv_rows())


def render_json(report, json_path):
    """The report as a tool reads it: `check-report-v2`, the complete
    form. 0600 like every other file that lists somebody's addresses,
    and byte-identical between two runs over the same artifacts — there
    is no timestamp in it on purpose."""
    with _private_file(json_path, encoding="utf-8") as f:
        f.write(cr.dumps(report))


def run(addresses_text, backends, csv_path=None, out=sys.stdout,
        book=None, json_path=None, depth=1):
    """Build once, render as many ways as asked."""
    report = build_report(addresses_text, backends, book, depth)
    render_text(report, out)
    if csv_path:
        render_csv(report, csv_path)
        print(f"\nCSV written: {csv_path} — it lists YOUR addresses: "
              "treat the file as sensitive.", file=out)
    if json_path:
        render_json(report, json_path)
        print(f"\nJSON written: {json_path} ({cr.FORMAT_TAG}) — it "
              "lists YOUR addresses: treat the file as sensitive.",
              file=out)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="per-address exposure answers, self-hosted only")
    p.add_argument("addresses", nargs="*", help="addresses to check")
    p.add_argument("--key", action="append", metavar="HEX",
                   help="a public key (33/65-byte hex) or its hash160 "
                        "(20-byte hex), checked as its three standard "
                        "address forms (p2pkh, p2sh-p2wpkh, p2wpkh). "
                        "Repeatable. An expansion, not a fourth answer "
                        "road: the forms go through the same pipeline "
                        "as any address")
    p.add_argument("--file", help="text file, one address per line, "
                                  "# comments allowed")
    p.add_argument("--address-book",
                   help=f"{ab.FORMAT_TAG} JSON: addresses in named "
                        "groups, each group claimed as 'separate' or "
                        "'watching'. A flat list cannot say which "
                        "addresses you MEANT to keep apart, and "
                        "without that claim a sentence about "
                        "separation would mean nothing")
    p.add_argument("--archive", help="reveal-archive-v2 directory "
                                     "(enables the exposure capability)")
    p.add_argument("--index", help="outpoint-index-v3 directory "
                                   "(with --derived enables history "
                                   "and co-inputs)")
    p.add_argument("--derived", help="outpoint-derived-v2 directory "
                                     "built from that same index")
    p.add_argument("--witness",
                   help=f"{wit.FORMAT_TAG} directory (enables "
                        "nonce-exposure: 1 MB read once, offline, for "
                        "the whole list. It answers only about the "
                        "repeated-nonce points its census resolved, "
                        "which is a different and much cheaper "
                        "question than `nodsig nonces address`)")
    p.add_argument("--rpc", help="node RPC URL (enables balance; the "
                                 "node is only contacted if given)")
    p.add_argument("--cookie-file", help="path to the node's .cookie file: "
                                         "read from the file, out of the "
                                         "argv and always current "
                                         "(recommended). Without a cookie: "
                                         "NODSIG_RPC_AUTH=user:password in "
                                         "the environment.")
    p.add_argument("--linkage-depth", type=int, default=1,
                   help="how many hops the link search takes (default 1: "
                        "a direct co-spend). Depth 2 goes through one "
                        "bridge and costs about 7 s per address against "
                        "fractions of a second, so it is an option and "
                        "not a default")
    p.add_argument("--csv", help="also write the answers as CSV")
    p.add_argument("--json", nargs="?", const="check-results.json",
                   help=f"also write the whole report as {cr.FORMAT_TAG} "
                        "JSON (default: check-results.json). The text "
                        "is for a person and the CSV is a lossy "
                        "projection; this is the complete form")
    p.add_argument("--out", default="check-results.txt",
                   help="report file (default: check-results.txt). Results "
                        "list YOUR addresses, so they go to a local "
                        "file, not to a screen that can be shared.")
    p.add_argument("--stdout", action="store_true",
                   help="print the report to stdout instead of a file "
                        "(fine for public fixtures, or for piping)")
    args = p.parse_args(argv)

    todo = list(args.addresses)
    key_notes = []
    for k in (args.key or []):
        try:
            d20, forms = key_addresses(k)
        except AddressError as e:
            sys.exit(f"ERROR: --key {k}: {e}")
        todo.extend(forms)
        key_notes.append(f"# key {d20.hex()} checked as its standard "
                         f"forms: {', '.join(forms)}")
    if args.file:
        with open(args.file) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    todo.append(line)
    # The book is read before anything is opened or asked: a malformed
    # book must cost nothing and must stop the run, because a report
    # built on half a book is the falsely complete one.
    book = None
    if args.address_book:
        try:
            book = ab.load(args.address_book)
        except (ab.BookError, OSError) as e:
            sys.exit(f"ERROR: {args.address_book}: {e}")
        todo.extend(book.addresses)
    if not todo:
        p.error("no addresses given (positional, --key, --file or "
                "--address-book)")

    if bool(args.index) != bool(args.derived):
        p.error("--index and --derived go together (the derivatives are "
                "bound to the index they were built from)")

    # The expected failures of this tool are an archive/index directory
    # that is not one, or a node that will not answer: they get the
    # one-line ERROR every other command in the suite prints, not a
    # traceback. ScanError and OutpointError are both RuntimeError, as
    # is the RPC failure, so one clause covers the three.
    backends = {}
    try:
        backends = _backends_from_args(args)
        if args.stdout:
            for note in key_notes:
                print(note)
            run(todo, backends, args.csv, book=book,
                json_path=args.json, depth=args.linkage_depth)
        else:
            with _private_file(args.out, encoding="utf-8") as f:
                print("# this file lists YOUR addresses and their "
                      "answers: treat it as sensitive.", file=f)
                for note in key_notes:
                    print(note, file=f)
                run(todo, backends, args.csv, out=f, book=book,
                    json_path=args.json, depth=args.linkage_depth)
            # The pointer goes to stderr: it names the file, never a
            # answer.
            print(f"results written to {args.out} — the file lists YOUR "
                  "addresses: treat it as sensitive.", file=sys.stderr)
    except (RuntimeError, OSError, urllib.error.URLError) as e:
        sys.exit(f"ERROR: {e}")
    finally:
        # Ladders and file descriptors the backends opened. Closing is
        # optional for a process about to exit, but the backends are
        # objects other code may hold, so they own a close().
        for backend in backends.values():
            closer = getattr(backend, "close", None)
            if closer is not None:
                closer()


if __name__ == "__main__":
    main()
