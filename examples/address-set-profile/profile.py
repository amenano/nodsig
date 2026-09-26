#!/usr/bin/env python3
"""Profile a set of addresses against sealed artifacts, in aggregate.

An example, not part of the package: nothing imports it, and it may be
removed without touching anything outside `examples/`. It reads the
artifacts only through `nodsig.check_addresses.build_backends`, the same
attachment point the `check` command uses, so every answer carries the
format, height and fingerprint it came from.

    python3 profile.py --index DIR --derived DIR --archive DIR \\
                       --addresses FILE [--before HEIGHT] [--json]

FILE holds one mainnet address per line (blank lines and lines starting
with '#' are skipped). Output is aggregate only: counts, never the
addresses themselves, so a profile can be shared without the list.

Per address, from three capabilities:
  history    outputs received, how many were spent, first height seen
             (`HistoryBackend`, as of the derivatives' height);
  co-inputs  whether its coins were ever spent together with coins under
             other locks (`CoSpendBackend`; a hint of common ownership,
             never proof);
  exposure   whether its key or script was ever revealed on-chain, and the
             first height it was (`ExposureLookup`).
With --before HEIGHT, "first funded before" and "revealed before" are
counted against that height (for example, the height of the sweep you are
studying). "Spent before" is not: the history capability summarises the
whole range up to its height.

A capability that is not configured is reported as such for every
address; it is never counted as a negative.
"""

import argparse
import json
import sys
from collections import Counter

from nodsig.capability import Status
from nodsig.check_addresses import AddressError, build_backends, decode_address


def band(n):
    return "1" if n == 1 else "2-5" if n <= 5 else "6-20" if n <= 20 else ">20"


def profile(addresses, backends, before=None):
    """Aggregate counts for `addresses` (a list of strings)."""
    out = {"addresses": len(addresses), "invalid": 0,
           "history": Counter(), "receipts": Counter(),
           "co_inputs": Counter(), "exposure": Counter(),
           "first_heights": []}
    for text in addresses:
        try:
            address = decode_address(text)
        except AddressError:
            out["invalid"] += 1
            continue

        h = backends["history"].query(address)
        if h.status != Status.OK:
            out["history"][str(h.status)] += 1
        elif h.value is None:
            out["history"]["never seen"] += 1
        else:
            v = h.value
            out["history"]["seen"] += 1
            out["receipts"][band(v["outputs"])] += 1
            out["history"]["never spent" if v["spent_outputs"] == 0
                           else "spent"] += 1
            out["first_heights"].append(v["first_height"])
            if before is not None:
                out["history"]["first funded before" if v["first_height"] < before
                               else "first funded at or after"] += 1

        c = backends["co-inputs"].query(address)
        if c.status != Status.OK:
            out["co_inputs"][str(c.status)] += 1
        elif c.value is None:
            out["co_inputs"]["never spent"] += 1
        else:
            out["co_inputs"]["co-spent with other locks" if c.value["co_locks"]
                             else "spent alone"] += 1

        e = backends["exposure"].query(address)
        if e.status != Status.OK:
            out["exposure"][str(e.status)] += 1
        elif e.value is None:
            out["exposure"]["never revealed"] += 1
        else:
            first = e.value[1]
            out["exposure"]["revealed"] += 1
            if before is not None:
                out["exposure"]["revealed before" if first < before
                                else "revealed at or after"] += 1
    hs = sorted(out.pop("first_heights"))
    out["first_height"] = ({"min": hs[0], "median": hs[len(hs) // 2], "max": hs[-1]}
                           if hs else None)
    for k in ("history", "receipts", "co_inputs", "exposure"):
        out[k] = dict(sorted(out[k].items()))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--index")
    ap.add_argument("--derived")
    ap.add_argument("--archive")
    ap.add_argument("--addresses", required=True)
    ap.add_argument("--before", type=int)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    with open(a.addresses, encoding="utf-8") as f:
        addresses = [ln.strip() for ln in f
                     if ln.strip() and not ln.lstrip().startswith("#")]
    backends = build_backends({"index": a.index, "derived": a.derived,
                               "archive": a.archive})
    result = profile(addresses, backends, a.before)
    result["answered_by"] = {cap: backends[cap].describe()
                             for cap in ("history", "co-inputs", "exposure")}
    if a.json:
        json.dump(result, sys.stdout, indent=1)
        print()
        return 0
    print(f"addresses: {result['addresses']} (invalid: {result['invalid']})")
    for k in ("history", "receipts", "co_inputs", "exposure"):
        print(f"{k}: {result[k]}")
    print(f"first_height: {result['first_height']}")
    for cap, line in result["answered_by"].items():
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
