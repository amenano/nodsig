#!/usr/bin/env python3
"""
block_dates.py — map block heights to their confirmed timestamps, via
your own node.

Why this exists: the reuse curve and the behaviour series are indexed by
HEIGHT — the scanner knows heights, not calendar dates (curve_deltas.py
keeps them apart on purpose). To put HONEST dates on the figures we need
real block timestamps, not an interpolation between halvings.

Where the timestamps come from, in order of preference:

  --headers   a header archive (headers-v2), read locally. The timestamp
              IS the header, and the median-time-past is a median over
              eleven of them, so both figures are a seek into a local
              file. Nothing is asked of anyone;
  --rpc       your own node, read-only (getblockhash/getblockheader).
              The fallback for anyone who has not co-emitted a header
              archive: the same self-hosted rule as the rest of the
              toolkit — no third-party explorer, no addresses, nothing
              sensitive leaves the machine. Two round-trips for the
              whole list.

Both roads must give the same numbers, which is what the self-test
checks: a header archive is a copy of what the node would answer, and a
copy that disagreed would be worse than no copy.

Input: either --curve (a reuse-scan curve.csv, whose first column is the
checkpoint heights) or --heights h1,h2,…. Output: a table and, with
--out, a CSV of height, unix time, mediantime (the monotone MTP), and the
UTC date.
"""

import argparse
import csv
import datetime
import sys

# The RPC client and the cookie/auth resolver already live in the
# scanner; reuse them so there is one JSON-RPC implementation and one
# credential rule (prefer --cookie-file: the secret stays out of argv).
from nodsig import reuse_scan as rs

# The offline road: the header archive answers the same question with no
# node at all (see the module docstring).
from nodsig import headers as hd


def read_heights_from_curve(path):
    """The heights are the first column, whatever the rest of the CSV
    holds: this dates the reuse curve and the archive's own curve
    alike, and putting dates on heights has nothing to do with the
    columns beside them. `curve deltas` is the one that needs the reuse
    schema, because it does arithmetic on it."""
    with open(path) as f:
        reader = csv.reader(f)
        next(reader, None)                       # skip the header row
        return [int(row[0]) for row in reader if row and row[0].strip()]


def fetch_dates(client, heights):
    """[(height, time, mediantime)] for the given heights.

    One batch resolves the block hashes, a second the headers — two HTTP
    round-trips for the whole list. The node's reported height is checked
    against the one asked for: a mismatch means we are talking to the
    wrong chain/node, and a silent wrong date is worse than a loud stop.
    `client` is any object with .batch([(method, params), …]) — the real
    RpcClient in use, a fake in the tests.
    """
    hashes = client.batch([("getblockhash", [h]) for h in heights])
    headers = client.batch([("getblockheader", [hh]) for hh in hashes])
    rows = []
    for h, hdr in zip(heights, headers):
        if hdr.get("height") != h:
            raise rs.ScanError(f"height mismatch: asked {h}, node returned "
                               f"{hdr.get('height')} — wrong node/chain?")
        rows.append((h, hdr["time"], hdr["mediantime"]))
    return rows


def read_dates(headers_dir, heights):
    """[(height, time, mediantime)] read out of a header archive.

    The node's twin, offline: `time` is the header's own field and
    `mediantime` is recomputed by the archive's reader with the rule a
    node uses (the median of the eleven timestamps ending at that
    height), so the two roads produce the same CSV.
    """
    with hd.HeaderReader(headers_dir) as reader:
        return [(h, reader.record(h)["time"], reader.median_time(h))
                for h in heights]


def utc_date(ts):
    return datetime.datetime.fromtimestamp(
        ts, datetime.timezone.utc).strftime("%Y-%m-%d")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="height → confirmed block date, from your own node")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--curve", help="reuse-scan curve.csv (heights = col 1)")
    src.add_argument("--heights", help="comma-separated heights")
    p.add_argument("--headers", help="a headers-v2 archive: read the dates "
                                     "from it instead of asking a node "
                                     "(--rpc and --cookie-file are then "
                                     "unused)")
    p.add_argument("--rpc", default="http://127.0.0.1:8332",
                   help="node RPC URL (default: %(default)s; a remote node "
                        "is reached through a local tunnel)")
    p.add_argument("--cookie-file", help="path to the node's .cookie file "
                                         "(read from the file, out of the "
                                         "argv). Without a cookie: "
                                         "NODSIG_RPC_AUTH=user:password in "
                                         "the environment.")
    p.add_argument("--out", help="write CSV height,unix,mediantime,utc here")
    args = p.parse_args(argv)

    heights = (read_heights_from_curve(args.curve) if args.curve
               else [int(x) for x in args.heights.split(",") if x.strip()])

    try:
        if args.headers:
            rows = read_dates(args.headers, heights)
        else:
            auth = rs.resolve_auth(args.cookie_file)
            rows = fetch_dates(rs.RpcClient(args.rpc, auth), heights)
    except (rs.ScanError, hd.HeaderError, OSError) as e:
        # `--rpc` has a default, so forgetting `--headers` does not fail
        # loudly, it quietly asks the node instead. This is the one command
        # here whose SOURCE depends on an argument you can leave out, and
        # every other one names the flag that would have answered offline
        # (`check` does it for each capability it lacks). So when the node
        # is the road that failed, say the other one exists.
        if not args.headers:
            sys.exit(f"ERROR: {e}\n"
                     "       this asked the node because --headers was not "
                     "given.\n"
                     "       A header archive answers the same question "
                     "offline:\n"
                     "           curve dates --curve <curve> --headers "
                     "<headers>")
        sys.exit(f"ERROR: {e}")

    print(f"{'height':>9}  {'utc':>10}  {'unix':>11}")
    for h, t, _ in rows:
        print(f"{h:>9,}  {utc_date(t):>10}  {t:>11}")
    if args.out:
        with open(args.out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["height", "unix", "mediantime", "utc"])
            for h, t, mt in rows:
                w.writerow([h, t, mt, utc_date(t)])
        print(f"\nwritten: {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
