#!/usr/bin/env python3
"""
report.py — one page describing the artifacts you hold: what they are,
what they cost, and on what machine.

Why this is a command and not a habit: the figures that end up in a
README, in a manual or in a message to somebody else are today copied by
hand out of the manifests. A fingerprint is sixty-four hexadecimal
characters, and a transcription error in one of them is invisible
exactly where it matters most, because the number's whole job is to be
compared. Reading the manifests and printing the table is the antidote,
and it costs nothing that was not already on disk.

WHAT IT REFUSES TO PRINT
========================
Paths. This command takes directories as arguments and never names one:
an artifact appears under the role its flag gave it (`graph`, `headers`,
`archive`, `nonces`, `witness`, `index`, `derived`, `firstspend`,
`firstreveal`), which is what a reader outside this machine can use. The same rule governs the machine block below,
which reports the CPU, the memory and the operating system and asks the
host for nothing that identifies it: no host name, no user name, no
environment. A page meant to be published must not be able to leak the
disk it was written on, and the way to guarantee that is to never put it
in the page rather than to remember to take it out.

WHAT IT CANNOT KNOW, AND SAYS SO
================================
Where an artifact lives, how fast that device is, where the node runs
and over which transport: none of it is recoverable from a manifest, and
all of it decides the durations more than the code does. Those lines
come out as questions with the answers left blank, because a page that
quietly omitted them would read as though the times it prints were a
property of the tool.

An artifact whose directory holds no manifest is reported as unsealed
rather than skipped: a report silent about what it could not read is a
report that looks complete.

WHAT YOU CAN ASK, AND WHAT IS MISSING
=====================================
Which artifacts a question needs, in which order they are built, which
heights have to agree: that logic lived in the documents only, and a
reader found out by reading. The page now says it about the set in
hand: each question with its command when its artifacts are sealed, with
what it waits on when they are not, and what builds the missing ones.
It PRINTS a build and never runs one: a pass of days over the chain is
not something a describing command starts, and an orchestrator would be
a second thing to keep correct. Costs are left to the documents, which
measure them; a figure typed into this file would be one machine's, and
stale at the next rebuild.
"""

import argparse
import json
import os
import platform
import sys

from nodsig import __version__
from nodsig import home
from nodsig.recio import read_json

MANIFEST_NAME = "manifest.json"

# The roles this page can describe, in the order the work produces them.
# Every role is read the same generic way (a sealed manifest and the
# bytes under the directory), so adding one here is the whole change:
# the ancestry section matches parents by fingerprint, not by name.
# Each is a flag, and the name of the flag is the name in the table: no
# directory ever reaches the output.
ROLES = ("graph", "headers", "archive", "nonces", "witness", "index",
         "derived", "firstspend", "firstreveal")

# What a reader can ask of the artifacts in hand: the question, the
# roles its command reads, the command. Reading commands only, written
# the way they are typed with NODSIG_HOME set (see home.py), so no line
# here has a directory to name; every command and flag below is held
# against the real parsers by tests/test_report.py.
QUESTIONS = (
    ("Has this address's public key already appeared on the chain?",
     ("archive",), "`nodsig check --stdout <address>`"),
    ("…and the lock's dated history, fees and co-spends with it?",
     ("archive", "index", "derived"),
     "`nodsig check --stdout <address>`, then the "
     "`nodsig derived history --lock <hash160>` line it prints"),
    ("What is this outpoint's whole story?",
     ("index",), "`nodsig index lookup <txid>:<vout>`"),
    ("What fee did this transaction pay, and what was spent with it?",
     ("index", "derived"),
     "`nodsig derived fee <txid>` and `nodsig derived cospends <txid>`"),
    ("Which nonce points repeat, over the whole chain?",
     ("nonces",), "`nodsig nonces groups`"),
    ("What did each repeated point turn out to be?",
     ("witness",), "`nodsig nonces witness-verify`"),
    ("Did one of this address's signatures reuse its nonce point?",
     ("index", "derived"),
     "`nodsig nonces address <address>` (asks your node for the blocks)"),
    ("Which locks were first spent in a height window?",
     ("firstspend", "index"),
     "`nodsig firstspend between --from <height> --to <height>`"),
    ("Which keys were first revealed in a height window?",
     ("firstreveal",),
     "`nodsig firstreveal between --from <height> --to <height>`"),
    ("Do these headers still chain, and do they commit to the index?",
     ("headers", "index"),
     "`nodsig headers verify` and `nodsig headers crosscheck`"),
)

# What builds a role that is missing. These DO name directories, as
# placeholders: a command that writes an artifact takes no default, and
# this page prints a build, it never runs one.
BUILT_BY = {
    "archive": "`nodsig archive scan --end <H> --archive <archive>`, then "
               "`nodsig archive merge --archive <archive>`",
    "graph": "the `--graph <graph>` co-emission of `nodsig archive scan`, "
             "the one pass over the chain, then "
             "`nodsig graph fingerprint --graph <graph>`",
    "headers": "the `--headers <headers>` co-emission of "
               "`nodsig archive scan`, then "
               "`nodsig headers fingerprint --headers <headers>`",
    "nonces": "the `--nonces <nonces>` co-emission of "
              "`nodsig archive scan`, then "
              "`nodsig nonces merge --nonces <nonces>`",
    "witness": "`nodsig nonces resolve --nonces <nonces> --witness <witness> "
               "--index <index>` (asks your node)",
    "index": "`nodsig index build --graph <graph> --index <index> "
             "--end <H>`",
    "derived": "`nodsig derived build --index <index> --out <derived>`",
    "firstspend": "`nodsig firstspend build --derived <derived> "
                  "--out <firstspend>`",
    "firstreveal": "`nodsig firstreveal build --archive <archive> "
                   "--out <firstreveal>`",
}


class ReportError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# reading what is on disk
# ---------------------------------------------------------------------------

def _manifest(directory):
    """The sealed manifest of an artifact directory, or None when it has
    none. A missing directory is an error the caller made; a directory
    without a manifest is an artifact that is simply not sealed yet, and
    the difference is worth keeping."""
    if not os.path.isdir(directory):
        raise ReportError(f"not a directory: {os.path.basename(directory)}")
    path = os.path.join(directory, MANIFEST_NAME)
    if not os.path.exists(path):
        return None
    return read_json(path, ReportError)


def _bytes_on_disk(directory):
    """Everything under the directory, counted by stat and not read. On
    a network mount this is the difference between a page that prints in
    a second and one that reads hundreds of GB to say how big they
    are."""
    total = 0
    for root, _dirs, names in os.walk(directory):
        for name in names:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:          # vanished under us: not our business
                pass
    return total


def _size(n):
    """Decimal GB, which is the unit the published tables already use
    (an 87 GB archive is what `du` calls 81G)."""
    if n >= 10 ** 9:
        return f"{n / 10 ** 9:,.1f} GB"
    if n >= 10 ** 6:
        return f"{n / 10 ** 6:,.1f} MB"
    return f"{n:,} B"


def _duration(seconds):
    """Seconds as a human reads them. Whole minutes above an hour: a
    35-hour build reported to the second is precision nobody has, since
    the figure already misses whatever a resume did not record."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min {seconds % 60} s"
    return f"{seconds // 3600} h {(seconds % 3600) // 60} min"


# ---------------------------------------------------------------------------
# the machine
# ---------------------------------------------------------------------------

def _cpu_model():
    """The processor's own name, on the systems that publish one. Read
    from /proc rather than from a shell, and absent rather than guessed
    where there is no /proc."""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _memory_gb():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return f"{kb * 1024 / 10 ** 9:,.1f} GB"
    except (OSError, ValueError, IndexError):
        pass
    return "unknown"


def machine():
    """What the host can say about itself without identifying itself.

    Every entry here is a property of the hardware or of the runtime.
    `platform.node()`, `socket.gethostname()`, the user name and the
    environment are deliberately not consulted: they answer "whose
    machine", which is the one question this page must not be able to
    answer.
    """
    return [
        ("CPU", _cpu_model()),
        ("Cores", str(os.cpu_count() or "unknown")),
        ("Memory", _memory_gb()),
        # The system, not the release: a distribution- or WSL-specific
        # kernel string is not an identity, but it is a narrow enough
        # fingerprint of one environment for a page meant to be pasted
        # in public.
        ("OS", platform.system()),
        ("Python", platform.python_version()),
        ("nodsig", __version__),
    ]


# The lines no machine can fill in, and which decide the durations more
# than the code does. Printed as questions with the answer left blank:
# see the module docstring.
UNKNOWNS = (
    ("Artifacts on", "device and interface, plus a measured sequential "
                     "MB/s if you have one"),
    ("Node on", "same machine, LAN, or a tunnel"),
    ("Node transport", "`--rpc` or `--rest`, and `--prefetch-depth` if used"),
)


# ---------------------------------------------------------------------------
# the page
# ---------------------------------------------------------------------------

def _artifact_rows(found):
    rows = []
    for role, directory, manifest in found:
        size = _size(_bytes_on_disk(directory))
        if manifest is None:
            rows.append((role, "not sealed", "", size, ""))
            continue
        cov = manifest["identity"]["coverage"]
        rows.append((role,
                     manifest["identity"]["format"],
                     f"{cov['from']:,}..{cov['to']:,}",
                     size,
                     manifest["fingerprint"]))
    return rows


def _cost_rows(found):
    """One row per verb an artifact has paid for. `scan` is one pass that
    wrote several artifacts, so the rows that carry it are the same
    seconds seen more than once: the note under the table says so rather
    than letting a reader add them up."""
    rows, shared = [], False
    for role, _directory, manifest in found:
        if manifest is None:
            continue
        seconds = (manifest.get("build") or {}).get("seconds") or {}
        for verb in sorted(seconds):
            rows.append((role, verb, _duration(seconds[verb])))
            shared = shared or verb == "scan"
    return rows, shared


def _total(found):
    """What the whole set cost, composed the one way that is correct.

    Refusing to add the rows up is right and was already here; offering
    nothing in its place was not. The total is the question a reader
    actually has — "what does having all of this cost me" — and leaving
    them to compose it by hand invites exactly the sum the note warns
    against.

    The rule: a co-emitted verb is counted ONCE across all artifacts
    that report it, because those figures are one pass seen several
    times. Every other entry is counted per artifact, because those
    phases really did run one after another.

    Returns (total seconds, how many entries were folded), or None when
    nothing recorded a duration."""
    CO_EMESSI = ("scan",)          # one pass, several artifacts
    once, per_artifact, folded = {}, 0, 0
    for _role, _directory, manifest in found:
        if manifest is None:
            continue
        for verb, sec in ((manifest.get("build") or {}).get("seconds") or {}).items():
            if verb in CO_EMESSI:
                if verb in once:
                    folded += 1
                # The largest wins: co-emission can be switched on later
                # than the host, so one artifact honestly owes less than
                # another. Taking the max reports the pass, not a share
                # of it.
                once[verb] = max(once.get(verb, 0), int(sec))
            else:
                per_artifact += int(sec)
    if not once and not per_artifact:
        return None
    return sum(once.values()) + per_artifact, folded


def _producer_rows(found):
    rows = []
    for role, _directory, manifest in found:
        if manifest is None:
            continue
        prod = (manifest.get("build") or {}).get("producer") or {}
        commit = prod.get("commit")
        state = ""
        if commit:
            state = commit[:12] + (" (dirty)" if prod.get("dirty") else "")
        rows.append((role, prod.get("version", "unknown"), state or "not a "
                     "checkout"))
    return rows


def _ancestry(found):
    """The declared chain, and whether the artifacts in hand confirm it.

    `build.parent` is a declaration: it names a format and a
    fingerprint. When the artifact it names is one of the ones being
    reported, the two numbers can be compared here and the link is
    confirmed; when it is not, the link is reported as declared, which
    is exactly how `verify` phrases the same gap."""
    by_fp = {m["fingerprint"]: role for role, _d, m in found
             if m is not None}
    lines = []
    for role, _directory, manifest in found:
        if manifest is None:
            continue
        parent = (manifest.get("build") or {}).get("parent")
        if parent is None:
            lines.append(f"- **{role}** declares no parent (a root)")
            continue
        known = by_fp.get(parent["fingerprint"])
        cov = parent.get("coverage")
        span = (f", sealed through height {cov['to']:,} as declared"
                if cov else ", declared without its coverage (sealed with "
                "the earlier statement: `nodsig manifest reseal`)")
        if known:
            actual = next(m for r, _d, m in found if r == known
                          )["identity"]["coverage"]
            agree = cov is None or (int(cov["from"]) == int(actual["from"])
                                    and int(cov["to"]) == int(actual["to"]))
            if not agree:
                lines.append(
                    f"- **{role}** ← **{known}** ({parent['format']}), "
                    f"fingerprint confirmed but the declared coverage "
                    f"{cov['from']:,}..{cov['to']:,} is not the parent's "
                    f"{actual['from']:,}..{actual['to']:,}: the declaration "
                    "was edited")
            else:
                lines.append(f"- **{role}** ← **{known}** "
                             f"({parent['format']}), confirmed: the artifact "
                             f"reported above carries that fingerprint{span}")
        else:
            lines.append(f"- **{role}** ← {parent['format']} "
                         f"`{parent['fingerprint']}`, declared and not "
                         f"confirmed (that artifact is not in this report)"
                         f"{span}")
    return lines


def _askable(found):
    """(rows, the roles something is waiting on). A role counts when it
    is SEALED: a directory with no manifest answers nothing yet, and a
    page that listed its questions as ready would claim a build that has
    not finished."""
    sealed = {role for role, _d, m in found if m is not None}
    there = {role for role, _d, _m in found}
    rows, wanted = [], []
    for question, roles, command in QUESTIONS:
        missing = [r for r in roles if r not in sealed]
        if not missing:
            rows.append((question, command))
            continue
        wanted += [r for r in missing if r not in wanted]
        rows.append((question, "needs " + ", ".join(
            f"**{r}**" + (" (here, not sealed)" if r in there else "")
            for r in missing)))
    return rows, wanted


def _caveats(found):
    """What is cheap to see from the manifests and expensive to find out
    later. Observations, not judgements: two heights in one set is
    legitimate, and the reader has to know it is the case."""
    lines = []
    heights = {}
    for role, _d, m in found:
        if m is not None:
            heights.setdefault(int(m["identity"]["coverage"]["to"]),
                               []).append(role)
    if len(heights) > 1:
        spans = "; ".join(f"{', '.join(roles)} through {h:,}"
                          for h, roles in sorted(heights.items()))
        lines.append(
            f"- **More than one height in this set** ({spans}). An answer "
            "assembled from them carries each artifact's own perimeter, "
            "and says so; an artifact and its parent must still share "
            "one, which the section on ancestry checks.")
    for role, directory, m in found:
        if (role == "archive" and m is not None and not os.path.exists(
                os.path.join(directory, "proof", MANIFEST_NAME))):
            lines.append(
                "- **The archive has no `proof/` beside it.** Every lookup "
                "still answers, but `archive scan` will refuse to extend "
                "this archive: the proof is what lets a later run decide a "
                "candidate the way the first one did, and rebuilding it is "
                "the whole scan again.")
    return lines


def _table(head, rows):
    out = ["| " + " | ".join(head) + " |",
           "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(cell or "" for cell in row) + " |"
            for row in rows]
    return out


def render(found, out=sys.stdout):
    """The whole page, in Markdown, because what consumes it is
    documents."""
    p = out.write
    p("# nodsig artifacts\n\n")

    p("## What these are\n\n")
    p("\n".join(_table(("Artifact", "Format", "Heights", "On disk",
                        "Fingerprint"), _artifact_rows(found))) + "\n\n")

    rows, wanted = _askable(found)
    p("## What you can ask of them\n\n")
    p("\n".join(_table(("Question", "Command, or what it waits on"),
                       rows)) + "\n\n")
    p(f"The commands are written as they are typed with `{home.ENV}` "
      "naming the directory that holds these artifacts under their "
      "roles' names; without it, each takes its artifact's flag "
      "(`--archive <dir>`, `--index <dir>`, …).\n\n")
    if wanted:
        p("What builds the ones that are missing, in the order the work "
          "is done. A build names what it reads and what it writes, so "
          "these carry placeholders; `docs/build-and-query.md` has the "
          "sequence, its costs and the three ordering rules.\n\n")
        p("\n".join(f"- **{role}**: {BUILT_BY[role]}"
                    for role in BUILT_BY if role in wanted) + "\n\n")
    caveats = _caveats(found)
    if caveats:
        p("## Worth knowing before you rely on them\n\n")
        p("\n".join(caveats) + "\n\n")

    cost, shared = _cost_rows(found)
    p("## What they cost\n\n")
    if cost:
        p("\n".join(_table(("Artifact", "Step", "Wall time"), cost)) + "\n\n")
        if shared:
            p("One `scan` walks the chain once and writes several of these "
              "artifacts, so every row above that names it reports the same "
              "pass. Those figures describe one run and must not be added "
              "together.\n\n")
        tot = _total(found)
        if tot is not None:
            total, folded = tot
            p(f"**All of it, composed: {_duration(total)}.** ")
            if folded:
                p(f"The shared pass is counted once rather than "
                  f"{folded + 1} times; ")
            p("the remaining steps really did run one after another. "
              "Every figure is a floor: a resume records what was "
              "checkpointed, never the stretch a kill took with it.\n\n")
    else:
        p("No artifact here records a duration. The field is written at "
          "seal time, so artifacts sealed by an earlier version carry "
          "none.\n\n")

    p("## Where they come from\n\n")
    p("\n".join(_ancestry(found)) + "\n\n")

    p("## What built them\n\n")
    p("\n".join(_table(("Artifact", "Version", "Commit"),
                       _producer_rows(found))) + "\n\n")

    p("## The machine\n\n")
    p("\n".join(_table(("", ""), machine())) + "\n\n")
    p("\n".join(_table(("To fill in", "What is being asked"),
                       [(k, v) for k, v in UNKNOWNS])) + "\n\n")
    p("Durations are a property of that machine at least as much as of "
      "the code: the wire to the node bounds a scan, the disk under the "
      "artifacts bounds the fusions and the builds.\n")


def run_report(dirs, out=sys.stdout):
    found = [(role, dirs[role], _manifest(dirs[role]))
             for role in ROLES if dirs.get(role)]
    if not found:
        raise ReportError(
            "nothing to report: name at least one artifact, e.g. "
            "`nodsig report --index <dir> --derived <dir>`")
    render(found, out=out)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="describe the artifacts you hold: identity, cost, "
                    "ancestry, and the machine that built them")
    for role in ROLES:
        p.add_argument(f"--{role}", **home.optional(
            role, help=f"a sealed {role} directory"))
    args = p.parse_args(argv)

    try:
        run_report({role: getattr(args, role) for role in ROLES})
    except (ReportError, OSError, KeyError, ValueError) as e:
        # A directory that is not an artifact, a manifest this version
        # cannot read: the suite's one-line ERROR, not a traceback.
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
