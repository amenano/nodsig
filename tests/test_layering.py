#!/usr/bin/env python3
"""Tests for the rules that are architecture rather than behaviour.

WHY THESE EXIST, AND WHY AS TESTS. Three rules of this project lived in
prose, in `AGENTS.md` and in commit messages, and all three drifted:

  - `verdict` was removed from the tree in July with the reasons written
    in a commit message. It came back months later as the name of a
    public API;
  - `provenance` was split into three words because it was doing three
    jobs. The split was recorded in a commit message. A new input format
    then used it for a fourth job, and shipped;
  - "the orchestration calls the kernels, not the other way round" is one
    of the three pillars in `ARCHITECTURE` §0. The single registration
    point of the address check took argparse's `Namespace` for months,
    through a correctness review, a space review and a security audit.

None of those is a behaviour, so no test could fail, and every audit ran
with a lens that was looking elsewhere. An audit finds what it looks for;
a test looks every time. That is the whole argument for this file: a rule
nobody can execute is a rule that degrades, and the cost of writing it
down here is minutes.

WHAT THESE TESTS ARE NOT. They do not judge design. Each one pins a
decision that was already taken and written down, so a failure here means
"the tree drifted from a rule", never "the rule is wrong". If a rule
genuinely needs to change, the change belongs in `AGENTS.md` first and in
this file second, in that order and in the same commit.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "nodsig"


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def check(cond, msg):
    if not cond:
        fail(msg)


def modules():
    return sorted(p for p in SRC.glob("*.py"))


# ---------------------------------------------------------------------------
# The kernels know nothing about how they were invoked
# ---------------------------------------------------------------------------

# Modules that must never import argparse: the pure kernels and the
# readers. The list is explicit rather than derived, because a rule that
# computes its own scope cannot be violated, only satisfied vacuously.
NO_CLI = {
    "address_book.py",     # reads a format, not a command line
    "artifact.py",         # the sealed-artifact shape
    "blockparse.py",       # bytes in, structures out
    "capability.py",       # the Result envelope
    "check_report.py",     # builds a document, renders nothing
    "diststats.py",
    "genstore.py",         # the append-and-fuse store
    "hashing.py",
    "linkage.py",
    "recio.py",
    "recsort.py",
}


def test_the_kernels_do_not_import_argparse():
    """`ARCHITECTURE` §0, pillar 2: pure kernels, thin orchestration.

    A kernel that imports argparse has learned that a command line
    exists, and the next interface has to pretend to be one.
    """
    for path in modules():
        if path.name not in NO_CLI:
            continue
        text = path.read_text()
        check("import argparse" not in text,
              f"{path.name} is a kernel and imports argparse")
    # And the list must stay honest: a module that disappears or gets
    # renamed would silently shrink the rule to nothing.
    present = {p.name for p in modules()}
    missing = NO_CLI - present
    check(not missing,
          f"NO_CLI names modules that no longer exist: {sorted(missing)}. "
          "Fix the list rather than letting the rule cover less")
    print(f"ok  {len(NO_CLI)} kernel modules, none knows what a flag is")


def test_only_the_cli_seam_takes_the_command_line_object():
    """Below `main()`, functions take directories, URLs and values.

    argparse's `Namespace` may cross exactly one line per module, and
    that line is the adapter. The failure this catches is specific and
    has happened: `build_backends`, whose docstring calls it "the single
    registration point of the interface", required a Namespace, so the
    one place designed as an attachment point was the one place a second
    interface could not reach without faking a command line.
    """
    # `main` builds the Namespace; a name starting with `_` and ending in
    # `_from_args` (or `_from_args`-shaped) is a declared adapter.
    allowed = re.compile(r"^(main|_[a-z_]*_from_args|_[a-z_]*_args)$")
    takes_args = re.compile(r"^def ([a-z_]+)\(([^)]*)\)", re.M)
    offenders = []
    for path in modules():
        for name, params in takes_args.findall(path.read_text()):
            first = [p.strip().split("=")[0].strip()
                     for p in params.split(",") if p.strip()]
            if "args" in first and not allowed.match(name):
                offenders.append(f"{path.name}:{name}")
    check(not offenders,
          "these take the command line's object below the seam: "
          f"{', '.join(offenders)}. Take a mapping of directories and "
          "values instead, and translate in a `*_from_args` adapter")
    print("ok  the Namespace stops at the CLI adapter")


# ---------------------------------------------------------------------------
# Words that name one thing (AGENTS.md, "Words reserved to ONE job")
# ---------------------------------------------------------------------------

def _sources_and_docs():
    for p in modules():
        yield p
    for p in sorted((ROOT / "docs").rglob("*.md")):
        yield p
    for name in ("README.md", "AGENTS.md", "CHANGELOG.md", "SECURITY.md"):
        p = ROOT / name
        if p.exists():
            yield p


def test_verdict_is_gone_from_the_tree():
    """`AGENTS.md`: the one flat case, removed even from the denials.

    It is flat precisely because leaving three uses where the word
    DENIED is what let the next reader find it and read precedent.
    """
    hits = [p.relative_to(ROOT) for p in _sources_and_docs()
            if "verdict" in p.read_text().lower()
            and p.name not in ("AGENTS.md", "test_layering.py")]
    check(not hits, f"`verdict` is back, in: {hits}")
    print("ok  `verdict` appears nowhere but the rule that forbids it")


def test_provenance_names_only_the_archive_bits():
    """`AGENTS.md`, reserved words: `provenance` is the origin of a key
    SIGHTING and nothing else.

    Where the other jobs go: `source` for who answered, `ancestry` for
    the chain back to the blocks, `origin` for where a list of addresses
    came from. This is the rule whose breach shipped in a public input
    format, so the allowed set is written by name.
    """
    allowed = {"reveal_archive.py", "RevealArchive-v2.md",
               "ExposureLookup.md", "AGENTS.md",
               "AddressBook-v2.md",     # explains the rename it made
               "CheckReport-v2.md",     # same
               "CHANGELOG.md"}          # records it, historically
    hits = []
    for p in _sources_and_docs():
        if p.name in allowed or p.name == "test_layering.py":
            continue
        if "provenance" in p.read_text().lower():
            hits.append(str(p.relative_to(ROOT)))
    check(not hits,
          f"`provenance` is doing a second job, in: {hits}. "
          "Use `source`, `ancestry` or `origin`")
    print("ok  `provenance` names the archive's sighting bits, and only those")


def test_no_claim_is_named_after_ownership():
    """`AGENTS.md`: the input may ask what the author INTENDED, never
    what they own. nodsig cannot know who controls an address.

    Checked on the value the address book actually accepts, because that
    is the string a person types into a file.
    """
    sys.path.insert(0, str(ROOT / "src"))
    from nodsig import address_book as ab
    forbidden = {"mine", "owned", "ours", "my", "yours"}
    bad = forbidden & set(ab.CLAIMS)
    check(not bad, f"a claim is named after ownership: {sorted(bad)}")
    print(f"ok  claims are {ab.CLAIMS}, none of them a statement of ownership")


def main():
    test_the_kernels_do_not_import_argparse()
    test_only_the_cli_seam_takes_the_command_line_object()
    test_verdict_is_gone_from_the_tree()
    test_provenance_names_only_the_archive_bits()
    test_no_claim_is_named_after_ownership()
    print("PASS: the tree still matches the rules written in AGENTS.md.")


if __name__ == "__main__":
    main()
