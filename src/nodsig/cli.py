#!/usr/bin/env python3
"""
cli.py — the single public entry point: `nodsig <group> [subcommand] …`.

Why this exists: every tool in this package already owns a complete
argparse CLI, and each one can still be run on its own
(`python3 -m nodsig.outpoint_index build …`) straight from a git clone,
with nothing installed. That path is supported and documented: reading
the code while running it is a first-class use of this toolkit.

But a module path is an INTERNAL name, and internal names move: the
fusion machinery, the record kernels, one day a native replacement for a
hot loop. Anything written down outside this repository — a manual, a
post, someone's runbook — would go stale the day a module is renamed,
and published text does not get quietly rewritten. So the published
command surface is deliberately NOT the module layout: it is one verb
per ARTEFACT, stable by contract.

    nodsig census                 the UTXO-set census
    nodsig reuse      prepare|scan|stats
    nodsig archive    scan|merge|verify|crosscheck|derive|lookup|v1-digests
    nodsig nonces     merge|verify|rewind|groups|lookup|address|bench
                      resolve|witness-verify
    nodsig headers    fingerprint|verify|crosscheck|stats|show
    nodsig graph      stats|fingerprint|show|digest
    nodsig index      build|stats|verify|lookup
    nodsig derived    build|stats|verify|history|fee|cospends
    nodsig blockstats build|summary
    nodsig curve      deltas|dates
    nodsig check                  the address checker
    nodsig report                 what you hold, and what it cost

The promise attached to that surface: the FORMATS are the contract, the
CLI is convenience, and within a major version the commands named here
do not change. That is what lets a manual say "this describes nodsig
1.x" and stay true without ever being edited.

Two details this dispatcher owns, because a process has exactly one of
each and the individual tools should not fight over them:

  - line buffering on stdout. Progress lines go to stderr (line-buffered
    by default since 3.9), but summaries go to stdout, which is block-
    buffered when redirected: in a `2>&1 | tee build.log` the two
    streams would then interleave in the wrong order. `python3 -u` used
    to fix that from the outside; an installed console script has no
    such flag, so the fix belongs here.
  - the exit status, mapped once from the tools' own error type.

Two entries in that list are not artefact verbs, and both speak about
the artefacts as a SET rather than about one of them: `check` assembles
an answer from whichever backends are plugged in, and `report` describes
what a machine holds and what building it cost. A verb per artefact is
the rule because artefacts are what the formats promise; a question that
ranges over all of them has nowhere else to live.

`nodsig curve` is the only group that is not one module: `deltas` and
`dates` both work on the reuse curve (one differentiates it, the other
puts real block dates on its heights), so they read as one noun even
though they live in two files. The grouping is for the reader, not for
the code.
"""

import argparse
import importlib
import sys

from . import __version__

# group → module, or group → {subcommand: module}. The ONLY place where
# the public names and the internal ones are tied together: renaming a
# module means editing this table, not the manual.
GROUPS = {
    "census": "utxo_census",
    "reuse": "reuse_scan",
    "archive": "reveal_archive",
    "nonces": "nonces",
    "headers": "headers",
    "graph": "graphemit",
    "index": "outpoint_index",
    "derived": "derivatives",
    "blockstats": "block_stats",
    "curve": {"deltas": "curve_deltas", "dates": "block_dates"},
    "check": "check_addresses",
    "report": "report",
}

SUMMARY = {
    "census": "census the UTXO set by lock type and age",
    "reuse": "scan the chain for reused (already-revealed) locks",
    "archive": "build and query the archive of key revelations",
    "nonces": "read the census of published signature nonce points",
    "headers": "seal and audit the header archive the scan co-emits",
    "graph": "inspect a graph-v2 artefact",
    "index": "build and query the outpoint index",
    "derived": "build and query history, fees and co-spends",
    "blockstats": "per-block statistics derived from a graph",
    "curve": "read the reuse curve: deltas over time, real dates",
    "check": "check addresses against every backend you have plugged in",
    "report": "describe the artifacts you hold, and what they cost",
}


def _usage():
    """The map of the toolkit, in the order the work is done."""
    lines = [
        "usage: nodsig <command> [subcommand] [options]",
        "",
        "commands:",
    ]
    for name, target in GROUPS.items():
        lines.append(f"  {name:<11} {SUMMARY[name]}")
        if isinstance(target, dict):
            lines.append(f"  {'':<11} subcommands: "
                         + " ".join(target))
    lines += [
        "",
        "Run a command with -h for its own options, e.g. "
        "`nodsig index build -h`.",
        "",
        "Every command is also reachable without installing anything, "
        "straight",
        "from a clone: `python3 -m nodsig.<module>` (see docs/"
        "ARCHITECTURE.md).",
    ]
    return "\n".join(lines)


def _resolve(argv):
    """argv → (module name, remaining args, public name), or exit with
    the map.

    Kept deliberately dumb: no argparse at this level, so a group's own
    parser sees EXACTLY the arguments the user typed, and its `-h` is
    the real one instead of a summary written twice.

    The third value is what the user typed to get here (`nodsig index`,
    `nodsig curve dates`). It becomes the tool's `prog`, so that
    `nodsig index build -h` answers with the command the manual quotes
    and not with the file that happens to implement it.
    """
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_usage())
        raise SystemExit(0)
    if argv[0] in ("-V", "--version"):
        print(f"nodsig {__version__}")
        raise SystemExit(0)

    group, rest = argv[0], argv[1:]
    target = GROUPS.get(group)
    if target is None:
        raise SystemExit(
            f"nodsig: unknown command '{group}'\n\n{_usage()}")

    if isinstance(target, dict):
        if not rest or rest[0] in ("-h", "--help"):
            raise SystemExit(
                f"usage: nodsig {group} <{'|'.join(target)}> [options]")
        sub, rest = rest[0], rest[1:]
        module = target.get(sub)
        if module is None:
            raise SystemExit(
                f"nodsig {group}: unknown subcommand '{sub}' "
                f"(expected one of: {', '.join(target)})")
        return module, rest, f"nodsig {group} {sub}"
    return target, rest, f"nodsig {group}"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    module_name, rest, prog = _resolve(argv)

    # See the module docstring: a console script cannot be given -u, so
    # the ordering guarantee for `2>&1 | tee` is established here, once,
    # for whichever tool is about to run.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):        # not a real stream
        pass

    module = importlib.import_module(f".{module_name}", __package__)
    # argparse takes its `prog` from sys.argv[0] when a parser does not
    # name itself. Setting it here means the modules stay unaware of the
    # public grouping (one mechanism, in one place) while their usage
    # lines still read `nodsig index build …`, which is what people will
    # have in front of them.
    saved_argv0, sys.argv[0] = sys.argv[0], prog
    try:
        # The tools raise their own error type for expected failures (a
        # missing artefact, an index that tolerates holes). argparse
        # already exits 2 on usage errors; anything else is a real
        # traceback and stays one, on purpose.
        return module.main(rest)
    finally:
        sys.argv[0] = saved_argv0


if __name__ == "__main__":
    sys.exit(main())
