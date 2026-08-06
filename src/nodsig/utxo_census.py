#!/usr/bin/env python3
"""
utxo_census.py — census of the Bitcoin UTXO set from a `dumptxoutset` snapshot.

What it does: reads the binary file produced by `bitcoin-cli dumptxoutset`
(Bitcoin Core snapshot format v2) in a single streaming pass — nothing is
kept in memory beyond the running totals — and counts, for every script
type (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, bare multisig, other), how
many coins exist and at which block height each one was created.

What it outputs: a summary table on stdout and a CSV with totals per type
and per height range. AGGREGATES ONLY: no single address or coin ever
appears in the output — it is shareable by construction.

Where the format comes from: it is the same format parsed by the reference
converter shipped with Bitcoin Core itself (contrib/utxo-tools/
utxo_to_sqlite.py). This script reimplements it in a didactic form and can
be cross-checked against that tool.

Usage:
    python3 utxo_census.py utxos.dat [--csv census.csv]

It talks to no one: no network, no RPC, just the input file.
"""

import argparse
import sys
import time


class CensusError(RuntimeError):
    """A snapshot that is not one, or one this reader cannot trust:
    wrong magic, wrong version, wrong network, or bytes that end mid
    entry. It is raised, not exited on, because these readers are a
    library too — reuse_scan walks the same format with them, and a
    module that calls sys.exit() cannot be reused by anything."""

# ---------------------------------------------------------------------------
# Format and protocol constants
# ---------------------------------------------------------------------------

MAGIC = b"utxo\xff"           # first 5 bytes of every snapshot
EXPECTED_VERSION = 2          # format v2 (Bitcoin Core >= 28)
MAINNET_MAGIC = bytes.fromhex("f9beb4d9")  # identifies the real Bitcoin network

# Subsidy epochs (halvings): EXACT boundaries, fixed by the protocol.
# Every 210,000 blocks the block reward halves; dates are approximate,
# heights are not.
EPOCHS = [
    (0,       "epoch 1 (50 BTC, 2009-2012)"),
    (210_000, "epoch 2 (25 BTC, 2012-2016)"),
    (420_000, "epoch 3 (12.5 BTC, 2016-2020)"),
    (630_000, "epoch 4 (6.25 BTC, 2020-2024)"),
    (840_000, "epoch 5 (3.125 BTC, 2024-…)"),
]

# Width of the height ranges in the CSV: 50,000 blocks (~11.5 months).
RANGE = 50_000

# Script types, with the property this census is about: is the public key
# visible to anyone reading the chain (exposed), or protected behind a
# hash until the coin is spent?
TYPES = {
    "p2pk_u":   ("P2PK uncompressed key",   "EXPOSED"),
    "p2pk_c":   ("P2PK compressed key",     "EXPOSED"),
    "multisig": ("bare multisig",           "EXPOSED"),
    "p2tr":     ("P2TR (Taproot)",          "EXPOSED"),
    "p2pkh":    ("P2PKH (1…)",              "behind hash"),
    "p2sh":     ("P2SH (3…)",               "behind hash"),
    "p2wpkh":   ("P2WPKH (bc1q…, short)",   "behind hash"),
    "p2wsh":    ("P2WSH (bc1q…, long)",     "behind hash"),
    "witness_other": ("witness other/future", "other"),
    "other":    ("other / non-standard",    "other"),
}

EXPOSED = [t for t, (_, e) in TYPES.items() if e == "EXPOSED"]


# ---------------------------------------------------------------------------
# Reading Bitcoin Core's number encodings
# ---------------------------------------------------------------------------

def read_exact(f, n):
    """Read exactly n bytes; fail with a clear error if the file ends early."""
    data = f.read(n)
    if len(data) != n:
        raise CensusError("file ended in the middle of an entry — "
                          "snapshot truncated or corrupted "
                          "(interrupted transfer?)")
    return data


def read_varint(f):
    """Bitcoin Core's VARINT: 7 bits per byte, high bit = 'continue'.

    Same algorithm as contrib/utxo-tools/utxo_to_sqlite.py.
    """
    n = 0
    while True:
        byte = read_exact(f, 1)[0]
        n = (n << 7) | (byte & 0x7F)
        if byte & 0x80:
            n += 1
        else:
            return n


def read_compactsize(f):
    """Bitcoin's classic 'compact size' (0xfd/0xfe/0xff prefixes)."""
    n = read_exact(f, 1)[0]
    if n == 253:
        n = int.from_bytes(read_exact(f, 2), "little")
    elif n == 254:
        n = int.from_bytes(read_exact(f, 4), "little")
    elif n == 255:
        n = int.from_bytes(read_exact(f, 8), "little")
    return n


def decompress_amount(x):
    """Amounts in the snapshot are compressed; this turns them back into
    satoshis. Bitcoin Core's DecompressAmount, translated 1:1."""
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n


# ---------------------------------------------------------------------------
# Script classification
# ---------------------------------------------------------------------------

def classify(type_code, script):
    """Return the script type label.

    In the snapshot the most common types are 'compressed' to a code 0-5;
    everything else arrives as a raw script (type_code >= 6) and is
    recognized by looking at the bytes.
    """
    # Bitcoin Core's six special compressed cases:
    if type_code == 0:
        return "p2pkh"            # pay-to-pubkey-hash (1… addresses)
    if type_code == 1:
        return "p2sh"             # pay-to-script-hash (3… addresses)
    if type_code in (2, 3):
        return "p2pk_c"           # bare public key, compressed
    if type_code in (4, 5):
        return "p2pk_u"           # bare public key, uncompressed

    # Raw script: recognize by structure.
    n = len(script)
    if n == 22 and script[0] == 0x00 and script[1] == 20:
        return "p2wpkh"           # witness v0, 20-byte program
    if n == 34 and script[0] == 0x00 and script[1] == 32:
        return "p2wsh"            # witness v0, 32-byte program
    if n == 34 and script[0] == 0x51 and script[1] == 32:
        return "p2tr"             # witness v1 (Taproot): the key IS there
    if n >= 4 and script[-1] == 0xAE and 0x51 <= script[0] <= 0x60:
        return "multisig"         # OP_m <keys…> OP_n OP_CHECKMULTISIG
    if (n >= 4 and (script[0] == 0x00 or 0x51 <= script[0] <= 0x60)
            and script[1] == n - 2 and 2 <= n - 2 <= 40):
        return "witness_other"    # other witness programs (incl. P2A)
    return "other"


def epoch_index(height):
    """Subsidy epoch (0-based) for a block height. Exact boundaries."""
    return min(height // 210_000, len(EPOCHS) - 1)


# ---------------------------------------------------------------------------
# The census itself
# ---------------------------------------------------------------------------

def run_census(path, csv_path):
    start = time.monotonic()
    # Counters: (type, height range) -> [entries, satoshis].
    # A few hundred keys at most: memory is not a concern.
    counts = {}
    # Separate counter for subsidy epochs: their boundaries (210,000) are
    # not multiples of the range width (50,000), so the epoch must be
    # decided on the exact height, not on the range.
    epoch_counts = {}

    with open(path, "rb", buffering=1024 * 1024) as f:
        # --- Snapshot header ---
        if read_exact(f, 5) != MAGIC:
            raise CensusError("this is not a dumptxoutset snapshot (magic "
                              "bytes missing) — or it is in the old v1 "
                              "format")
        version = int.from_bytes(read_exact(f, 2), "little")
        if version != EXPECTED_VERSION:
            raise CensusError(f"snapshot format v{version}, this script "
                              f"reads v{EXPECTED_VERSION} (Bitcoin Core "
                              ">= 28)")
        if read_exact(f, 4) != MAINNET_MAGIC:
            raise CensusError("snapshot is not from the Bitcoin main "
                              "network (mainnet)")
        # Hash of the block the snapshot was taken at: compare it with the
        # base_hash reported by dumptxoutset.
        base_hash = read_exact(f, 32)[::-1].hex()
        declared_coins = int.from_bytes(read_exact(f, 8), "little")

        print(f"snapshot base block: {base_hash}")
        print(f"declared entries:    {declared_coins:,}")
        print("reading…", file=sys.stderr)

        # --- The entries, grouped by transaction ---
        # Format v2 writes each transaction id once, followed by how many
        # of its outputs are still spendable.
        coins_left_in_group = 0
        read_count = 0
        while read_count < declared_coins:
            if coins_left_in_group == 0:
                read_exact(f, 32)                  # txid: not needed here
                coins_left_in_group = read_compactsize(f)
            coins_left_in_group -= 1

            read_compactsize(f)                    # output index: not needed
            code = read_varint(f)                  # height*2 + coinbase flag
            height = code >> 1
            sat = decompress_amount(read_varint(f))
            type_code = read_varint(f)
            if type_code < 6:
                # compressed type: 20 bytes (hash) or 32 (key)
                payload = read_exact(f, 20 if type_code < 2 else 32)
                kind = classify(type_code, payload)
            else:
                script = read_exact(f, type_code - 6)
                kind = classify(type_code, script)

            key = (kind, height // RANGE * RANGE)
            if key in counts:
                entry = counts[key]
                entry[0] += 1
                entry[1] += sat
            else:
                counts[key] = [1, sat]

            if kind in TYPES and TYPES[kind][1] == "EXPOSED":
                ekey = (kind, epoch_index(height))
                if ekey in epoch_counts:
                    e = epoch_counts[ekey]
                    e[0] += 1
                    e[1] += sat
                else:
                    epoch_counts[ekey] = [1, sat]

            read_count += 1
            if read_count % 10_000_000 == 0:
                elapsed = time.monotonic() - start
                print(f"  …{read_count // 1_000_000}M entries "
                      f"({elapsed / 60:.1f} min)", file=sys.stderr)

        # Integrity check: after the last entry the file must end.
        if f.read(1):
            raise CensusError("data beyond the last declared entry — "
                              "anomalous snapshot")

    print_summary(counts, epoch_counts, declared_coins)
    write_csv(counts, csv_path)
    print(f"\nCSV written to {csv_path} (aggregates only: shareable).")
    print(f"total time: {(time.monotonic() - start) / 60:.1f} min")


def btc(sat):
    """Human-readable: satoshis to BTC (1 BTC = 100,000,000 sat)."""
    return f"{sat / 100_000_000:,.8f}"


def print_summary(counts, epoch_counts, declared_coins):
    # Totals per type, over all height ranges.
    by_type = {}
    for (kind, _), (entries, sat) in counts.items():
        t = by_type.setdefault(kind, [0, 0])
        t[0] += entries
        t[1] += sat

    total_entries = sum(v for v, _ in by_type.values())
    total_sat = sum(s for _, s in by_type.values())

    print(f"\n=== Census by script type ===")
    print(f"{'type':<26} {'pubkey':<12} {'entries':>13} {'BTC':>22}")
    for kind in TYPES:
        if kind not in by_type:
            continue
        entries, sat = by_type[kind]
        name, exposure = TYPES[kind]
        print(f"{name:<26} {exposure:<12} {entries:>13,} {btc(sat):>22}")
    print(f"{'TOTAL':<26} {'':<12} {total_entries:>13,} {btc(total_sat):>22}")

    if total_entries != declared_coins:
        print(f"WARNING: read {total_entries:,} entries, "
              f"declared {declared_coins:,}.")

    # The certain lower bound: coins whose public key is already visible
    # on chain by construction of the script.
    exp_sat = sum(by_type[t][1] for t in EXPOSED if t in by_type)
    exp_entries = sum(by_type[t][0] for t in EXPOSED if t in by_type)
    share = f"{exp_sat / total_sat * 100:.2f}% of total" if total_sat else "—"
    print(f"\nkey exposed by construction (certain lower bound): "
          f"{exp_entries:,} entries, {btc(exp_sat)} BTC ({share})")

    # Age distribution of the exposed types by subsidy epoch: this is
    # where "how much has sat still since the earliest era?" comes from.
    print(f"\n=== Exposed types by creation epoch (BTC) ===")
    print(f"{'epoch':<30}" + "".join(f"{t:>14}" for t in EXPOSED)
          + f"{'epoch total':>16}")
    for i, (_, name) in enumerate(EPOCHS):
        row = f"{name:<30}"
        epoch_total = 0
        for t in EXPOSED:
            sat = epoch_counts.get((t, i), [0, 0])[1]
            epoch_total += sat
            row += f"{sat // 100_000_000:>14,}"
        row += f"{epoch_total // 100_000_000:>16,}"
        print(row)
    print("(amounts truncated to whole BTC; exact satoshis are in the CSV)")


def write_csv(counts, csv_path):
    """A flat CSV: type, height range (start/end), entries, satoshis.

    Every table in the summary can be rebuilt from these rows; satoshis
    are integers, no rounding anywhere.
    """
    with open(csv_path, "w") as out:
        out.write("type,height_from,height_to,entries,satoshis\n")
        for (kind, range_start), (entries, sat) in sorted(counts.items()):
            out.write(f"{kind},{range_start},{range_start + RANGE - 1},"
                      f"{entries},{sat}\n")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Census of the Bitcoin UTXO set from a dumptxoutset "
                    "snapshot.")
    p.add_argument("snapshot", help="file produced by dumptxoutset")
    p.add_argument("--csv", default="census.csv",
                   help="where to write the aggregates (default: census.csv)")
    args = p.parse_args(argv)
    try:
        run_census(args.snapshot, args.csv)
    except (CensusError, OSError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
