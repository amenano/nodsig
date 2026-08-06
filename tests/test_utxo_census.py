#!/usr/bin/env python3
"""
test_utxo_census.py — self-test for utxo_census.py, no real data needed.

Builds a tiny synthetic snapshot in the dumptxoutset v2 format (the writer
here is the mirror image of the reader in utxo_census.py: an independent
implementation of Bitcoin Core's encodings, so the two check each other),
runs the census on it and verifies every number in the CSV and the epoch
attribution.

Usage:
    python3 test_utxo_census.py        # prints PASS or fails loudly
"""

import csv
import io
import os
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Writers for Bitcoin Core's encodings (inverse of the readers under test)
# ---------------------------------------------------------------------------

def write_varint(n):
    """Inverse of Core's ReadVarInt: 7 bits per byte, MSB = 'continue',
    with the +1 offset on every non-final byte."""
    out = bytearray()
    while True:
        out.insert(0, (n & 0x7F) | (0x80 if out else 0x00))
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
    return bytes(out)


def write_compactsize(n):
    if n < 253:
        return bytes([n])
    if n < 2**16:
        return b"\xfd" + n.to_bytes(2, "little")
    if n < 2**32:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def compress_amount(n):
    """Bitcoin Core's CompressAmount, translated 1:1."""
    if n == 0:
        return 0
    e = 0
    while n % 10 == 0 and e < 9:
        n //= 10
        e += 1
    if e < 9:
        d = n % 10
        n //= 10
        return 1 + (n * 9 + d - 1) * 10 + e
    return 1 + (n - 1) * 10 + 9


def coin(vout, height, coinbase, sat, type_code, payload):
    return (write_compactsize(vout)
            + write_varint(height * 2 + coinbase)
            + write_varint(compress_amount(sat))
            + write_varint(type_code)
            + payload)


# ---------------------------------------------------------------------------
# The synthetic coins (all invented, nothing real)
# ---------------------------------------------------------------------------

H20 = bytes(20)                                        # a fake 20-byte hash
K32 = bytes(range(32))                                 # a fake 32-byte key

P2WPKH = bytes([0x00, 0x14]) + H20                     # 22 bytes
P2WSH = bytes([0x00, 0x20]) + K32                      # 34 bytes
P2TR = bytes([0x51, 0x20]) + K32                       # 34 bytes
MULTISIG = bytes([0x51, 0x21]) + bytes(33) + bytes([0x51, 0xAE])  # 1-of-1
P2A = bytes([0x51, 0x02, 0x4E, 0x73])                  # pay-to-anchor
WEIRD = bytes([0x6A, 0x04, 1, 2, 3, 4])                # OP_RETURN-like

# (txid, vout, height, coinbase, sat, type_code, payload)
# Compressed type codes: 0=P2PKH(20B) 1=P2SH(20B) 2/3=P2PK compressed(32B)
# 4/5=P2PK uncompressed(32B); >=6: raw script of length code-6.
COINS = [
    (b"\x01" * 32, 0, 100,     1, 5_000_000_000, 4, K32),   # p2pk_u, epoch 1
    (b"\x01" * 32, 1, 100,     1, 1,             2, K32),   # p2pk_c, same txid
    (b"\x02" * 32, 0, 250_000, 0, 123_456_789,   0, H20),   # p2pkh
    (b"\x03" * 32, 5, 500_000, 0, 50_000,        1, H20),   # p2sh
    (b"\x04" * 32, 0, 700_000, 0, 999,           6 + len(P2WPKH), P2WPKH),
    (b"\x05" * 32, 0, 700_001, 0, 1_000,         6 + len(P2WSH), P2WSH),
    (b"\x06" * 32, 0, 850_000, 0, 2_100_000_000, 6 + len(P2TR), P2TR),
    (b"\x07" * 32, 0, 150_000, 0, 10_000_000,    6 + len(MULTISIG), MULTISIG),
    # height 215,000: range 200,000 (starts in epoch 1) but epoch 2 —
    # catches any epoch attribution done on ranges instead of heights.
    (b"\x07" * 32, 1, 215_000, 0, 700_000_000,   6 + len(P2TR), P2TR),
    (b"\x08" * 32, 0, 900_000, 0, 330,           6 + len(P2A), P2A),
    (b"\x09" * 32, 0, 900_001, 0, 0,             6 + len(WEIRD), WEIRD),
]

EXPECTED_CSV = {
    # (type, height_from): (entries, satoshis)
    ("p2pk_u", 0): (1, 5_000_000_000),
    ("p2pk_c", 0): (1, 1),
    ("p2pkh", 250_000): (1, 123_456_789),
    ("p2sh", 500_000): (1, 50_000),
    ("p2wpkh", 700_000): (1, 999),
    ("p2wsh", 700_000): (1, 1_000),
    ("p2tr", 850_000): (1, 2_100_000_000),
    ("p2tr", 200_000): (1, 700_000_000),
    ("multisig", 150_000): (1, 10_000_000),
    ("witness_other", 900_000): (1, 330),
    ("other", 900_000): (1, 0),
}


def build_snapshot(path):
    out = bytearray()
    out += b"utxo\xff"
    out += (2).to_bytes(2, "little")                   # version
    out += bytes.fromhex("f9beb4d9")                   # mainnet magic
    out += bytes.fromhex("aa" * 32)                    # fake base block hash
    out += len(COINS).to_bytes(8, "little")

    i = 0
    while i < len(COINS):
        txid = COINS[i][0]
        group = [c for c in COINS if c[0] == txid]
        out += txid
        out += write_compactsize(len(group))
        for (_, vout, h, cb, sat, code, payload) in group:
            out += coin(vout, h, cb, sat, code, payload)
        i += len(group)

    with open(path, "wb") as f:
        f.write(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    # The tool is exercised as a subprocess: a fresh interpreter that does not
    # inherit pytest's `pythonpath = ["src"]`, so src/ is put on PYTHONPATH and
    # the CLI is run as a module (`-m nodsig.utxo_census`).
    src_dir = os.path.join(os.path.dirname(here), "src")
    env = {**os.environ,
           "PYTHONPATH": os.pathsep.join([src_dir,
                                          os.environ.get("PYTHONPATH", "")])}
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = os.path.join(tmp, "test.dat")
        csv_path = os.path.join(tmp, "census.csv")
        build_snapshot(snapshot)

        result = subprocess.run(
            [sys.executable, "-m", "nodsig.utxo_census", snapshot,
             "--csv", csv_path],
            capture_output=True, text=True, env=env)
        if result.returncode != 0:
            sys.exit(f"FAIL: census exited with {result.returncode}\n"
                     f"{result.stdout}\n{result.stderr}")

        got = {}
        with open(csv_path) as f:
            for row in csv.DictReader(f):
                key = (row["type"], int(row["height_from"]))
                got[key] = (int(row["entries"]), int(row["satoshis"]))
        if got != EXPECTED_CSV:
            sys.exit(f"FAIL: CSV mismatch.\nexpected: {EXPECTED_CSV}\n"
                     f"got:      {got}")

        # The height-215,000 P2TR coin must be counted in epoch 2.
        summary = result.stdout
        for line in summary.splitlines():
            if line.startswith("epoch 2"):
                if "7" not in line.split("epoch 2 (25 BTC, 2012-2016)")[1]:
                    sys.exit(f"FAIL: 7 BTC expected in epoch 2, got: {line}")
                break
        else:
            sys.exit("FAIL: epoch 2 row not found in summary")

        # Exposed lower bound: p2pk_u + p2pk_c + multisig + both p2tr.
        expected_exposed = 5_000_000_000 + 1 + 10_000_000 \
            + 2_100_000_000 + 700_000_000
        if f"{expected_exposed / 100_000_000:,.8f}" not in summary:
            sys.exit(f"FAIL: exposed total {expected_exposed} sat "
                     f"not found in summary:\n{summary}")

    print("PASS: all census numbers match the synthetic snapshot.")


if __name__ == "__main__":
    main()
