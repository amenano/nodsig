#!/usr/bin/env python3
"""manifest_tool.py — `nodsig manifest reseal`: a manifest re-sealed under
this release's statement, the bytes of the artifact untouched.

Why it exists: the 2.0.0 statement binds the declared parent's coverage,
and the artifacts this release does not rebuild (the graph, the headers,
the census, the index, the derivatives, the first-spend table) keep
manifests sealed with the earlier statement. Their fingerprints stand;
what moves is the statement, and the parent's coverage is read off the
parent's own manifest, never typed.
"""

import argparse
import sys

from nodsig.artifact import reseal


class ManifestError(RuntimeError):
    pass


def main(argv=None):
    # No subparser here, and that is the convention rather than a
    # shortcut: `cli._resolve` has already eaten both the group and the
    # subcommand for a grouped module, so a parser that asked for
    # `reseal` again would be handed the directory in its place and
    # refuse every real invocation. Every other grouped module
    # (`curve_deltas`, `block_dates`, …) parses its own arguments
    # directly, and this one did not, so `nodsig manifest reseal <dir>`
    # was unusable while the surface tests still counted the command as
    # present.
    p = argparse.ArgumentParser(
        prog="nodsig manifest reseal",
        description="recompute the statement of a sealed manifest under "
                    "this release's recipe, and give the declared parent "
                    "its coverage (the artifact's bytes and fingerprint "
                    "do not move)")
    p.add_argument("directory", help="the artifact directory")
    p.add_argument("--parent", help="the parent artifact's directory, when "
                                    "the manifest declares one without "
                                    "its coverage")
    args = p.parse_args(argv)
    try:
        reseal(args.directory, ManifestError, parent_dir=args.parent)
    except ManifestError as e:
        sys.exit(f"ERROR: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
