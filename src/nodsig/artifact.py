#!/usr/bin/env python3
"""
artifact.py — the shared shape of a sealed, appendable artifact.

The reveal archive, the outpoint index and the derivatives are instances of
one idea: a directory of fixed-width files, sealed by a manifest that names
each file and its sha256, and identified by ONE canonical fingerprint. This
module holds what that shape has in common.

THE MANIFEST IS TWO BLOCKS, AND THE SPLIT IS THE WHOLE POINT
============================================================
A manifest records two kinds of thing, and conflating them is how a
fingerprint ends up attesting either too little or too much:

    identity — what any honest build of the same content MUST reproduce.
               It is what the fingerprint covers.
    build    — how THIS copy happened to be produced. Generation numbers,
               actual file names, ladders, counters, timings. Two honest
               builds of identical bytes may differ here, so none of it can
               enter the fingerprint without breaking the promise that the
               same chain at the same height yields the same number.

Within `identity` the rule is: **what the artifact IS, never how it came to
be.** Three things qualify, and nothing else has:

    the file digests   the content itself;
    the format tag     how to read those bytes, and — the part that matters
                       for a reader — WHAT this artifact captures, so an
                       absence can be told apart from a blind spot;
    the coverage       the range of chain the content speaks for.

The coverage is in here because the bytes cannot prove it. An archive of
hashes carries no heights at all, so nothing in it contradicts a manifest
claiming a higher watermark than the scan reached; inside the identity that
claim cannot move without moving the fingerprint.

THE PARENT IS NOT IN HERE, AND THAT IS THE POINT
================================================
A parent's fingerprint answers "where do I come from", not "what am I", so
it belongs in `build` with the generation and the counters. Keeping it in the
identity broke the one promise the fingerprint exists to make: two indexes
built from the same chain to the same height, byte for byte identical, took
DIFFERENT names when one builder had sealed their graph and the other had
not. Same information, same answers, two numbers — which is the failure this
project is written to prevent, appearing in the mechanism meant to prevent
it.

What a consumer loses is narrow and worth stating: the declared parent can
now be altered after sealing. It never protected against the builder (a liar
computes a consistent identity around the lie), only against a middleman
editing a manifest, and only for a reader who does not hold the parent —
because one who does compares the two and catches it either way. `verify`
therefore reports the parent as declared-and-unconfirmed until it is handed
the parent, exactly as it already does for a coverage it cannot derive.

The parent's FORMAT is not in here either, for a reason that survives a
format's evolution: if a parent change alters what the child captures, the
child's own tag moves; if it does not, the child is the same artifact and
must keep its name. Either way the parent's tag adds nothing the child does
not already say about itself.

THE SERIALIZATION IS BYTES, NOT JSON
====================================
JSON has no canonical form (key order, whitespace, number formatting), so the
fingerprint is taken over an explicit byte string with every variable-length
field length-prefixed. A re-implementation in another language reproduces it
from the recipe below without having to reproduce a JSON encoder.
"""

import hashlib
import os
import subprocess
import time

from nodsig import __version__
from nodsig.recio import checked_name, read_slabs, sha_file

# The recipe's own version, and it is separate from any artifact's format
# tag on purpose: this is the shape of the identity block, shared by every
# artifact, and it moves when THAT changes. v3 dropped the parent (see
# above). It is a domain separator as much as a version: a reader of the
# older recipe cannot mistake these bytes for its own.
IDENTITY_TAG = b"nodsig-identity-v3\x00"


def _lp(text):
    """A length-prefixed UTF-8 string: u16be length, then the bytes.

    Prefixed, not merely concatenated: with bare concatenation a sequence of
    variable-length names has more than one reading, and a canonical form
    that can be parsed two ways is not canonical.
    """
    raw = text.encode()
    if len(raw) > 0xFFFF:
        raise ValueError(f"identity field too long: {text[:40]}…")
    return len(raw).to_bytes(2, "big") + raw


def canonical_identity(identity):
    """The identity block of a sealed artifact, as the bytes it hashes to.

        IDENTITY_TAG
        || lp(format)
        || u32be(coverage.from) || u32be(coverage.to)
        || u32be(number of files)
        || for each file, IN ORDER: lp(name) || raw32(sha256)

    The file order is part of the identity and is written down in the
    manifest, not carried separately in code: a reordered list is a different
    artifact and says so.
    """
    cov = identity["coverage"]
    out = bytearray(IDENTITY_TAG)
    out += _lp(identity["format"])
    out += int(cov["from"]).to_bytes(4, "big")
    out += int(cov["to"]).to_bytes(4, "big")
    files = identity["files"]
    out += len(files).to_bytes(4, "big")
    for entry in files:
        out += _lp(entry["name"])
        out += bytes.fromhex(entry["sha256"])
    return bytes(out)


def identity_fingerprint(identity):
    """sha256 of `canonical_identity`, hex. The number a stranger recomputes
    to check an artifact, and the number a child artifact binds to."""
    return hashlib.sha256(canonical_identity(identity)).hexdigest()


def make_identity(tag, covered_from, covered_to, files):
    """Assemble an identity block. `files` is an ordered sequence of
    (logical name, sha256 hex).

    There is no parent here by design; a derived artifact records the one it
    was built from under `build.parent` (see the module docstring)."""
    return {
        "format": tag,
        "coverage": {"from": int(covered_from), "to": int(covered_to)},
        "files": [{"name": name, "sha256": sha} for name, sha in files],
    }


STATEMENT_TAG = b"nodsig-statement-v1\x00"


def canonical_statement(manifest):
    """The bytes a signature would be over, if anyone wants one.

        STATEMENT_TAG
        || lp(format)
        || raw32(fingerprint)
        || u8(parent is present)
        || [ lp(parent.format) || raw32(parent.fingerprint) ]   if present

    What it binds is decided by the same rule the identity follows, applied one
    floor up: **exactly what is neither inside the fingerprint nor recomputable
    from the bytes, and checkable by whoever receives it.** The fingerprint
    already stands for the tag, the coverage and every digest. Counters,
    totals, generations and file names are recomputable, so a lie there is
    caught by reading the files. That leaves the declared parent, and nothing
    else — which is why this is four fields and not a serialization of the
    whole manifest.

    The last clause of the rule is not decoration, and `build.producer` is why
    it is written down. That field meets the first two conditions exactly as
    the parent does: it is outside the fingerprint and no reading of the bytes
    recovers it. It is still not signed here, because nothing can ever confirm
    it. A declared parent is checkable in principle — hand over the parent,
    compare the two numbers, which is precisely what `verify` does and why it
    reports the parent as unconfirmed until then. No artifact exists that
    could confirm "this manifest was written by that commit". Binding an
    unfalsifiable claim adds no verifiability to a signature; it only lends it
    the weight of one, which is the trade this project refuses everywhere
    else.

    A canonical form of the WHOLE manifest is deliberately not offered.
    `build` is unconstrained by design and differs between formats, so
    canonicalizing it is the JSON-canonicalization problem this project
    already refused once: a canonical form that can be read two ways is not
    one.

    Nothing here signs anything. This exists so that a signature layer, built
    by us or by anyone else, has ONE agreed target: without it every signer
    invents a serialization and no two verifiers agree. The tag carries its
    own version so a future scheme can wrap these bytes unambiguously.
    """
    out = bytearray(STATEMENT_TAG)
    out += _lp(manifest["format"])
    out += bytes.fromhex(manifest["fingerprint"])
    parent = (manifest.get("build") or {}).get("parent")
    if parent is None:
        out += b"\x00"
    else:
        out += b"\x01"
        out += _lp(parent["format"])
        out += bytes.fromhex(parent["fingerprint"])
    return bytes(out)


def statement_digest(manifest):
    """sha256 of `canonical_statement`, hex. Written into the manifest as
    `statement`, for the same reason the fingerprint is written there: it is
    recomputable, and having it in view is what makes a disagreement visible.
    On its own it secures nothing — whoever edits a declared parent can edit
    this too — but `verify` recomputes it, so an inconsistent manifest is
    caught, and a signature over it makes the pair binding."""
    return hashlib.sha256(canonical_statement(manifest)).hexdigest()


def seal_manifest(fmt, identity, build):
    """The manifest of a sealed artifact: the two blocks, the fingerprint the
    identity hashes to, and the statement a signature would be over. One
    function so the shape is written once and every format has the same one."""
    manifest = {"format": fmt,
                "identity": identity,
                "fingerprint": identity_fingerprint(identity),
                "build": build}
    manifest["statement"] = statement_digest(manifest)
    return manifest


def declared_parent(fmt, fingerprint):
    """The `build.parent` entry: which artifact this one was built from.

    Declared, not attested. It travels outside the fingerprint because it
    says where this artifact came from and not what it is, so `verify` calls
    it unconfirmed until it is given the parent to compare against."""
    return {"format": fmt, "fingerprint": fingerprint}


def _read_producer(module_file=os.path.abspath(__file__)):
    """Ask git once, when this module loads. See `producer`.

    Before asking for HEAD, ask whether the repository git finds is the
    one this module lives in: git walks up from the package directory to
    the FIRST enclosing repository, and for an installed copy (a venv
    under someone's project, a git-managed home directory) that is a
    repository this code knows nothing about. Its HEAD describes that
    person's disk, and a manifest is written to be published — so unless
    this very file is tracked there, the answer is nobody's commit, and
    the field stays absent."""
    out = {"version": __version__}
    here = os.path.dirname(module_file)
    try:
        tracked = subprocess.run(
            ["git", "-C", here, "ls-files", "--error-unmatch", "--",
             os.path.basename(module_file)],
            capture_output=True, text=True, timeout=5).returncode == 0
        if not tracked:
            return out
        commit = subprocess.run(
            ["git", "-C", here, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5).stdout.strip()
        if len(commit) != 40 or not all(c in "0123456789abcdef"
                                        for c in commit):
            return out
        changed = subprocess.run(
            ["git", "-C", here, "status", "--porcelain",
             "--untracked-files=no"],
            capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return out
    out["commit"] = commit
    out["dirty"] = bool(changed.strip())
    return out


# Read once, at import, and never again: see `producer` for why the moment
# matters. Roughly 5 ms of git, paid once per process.
_PRODUCER = _read_producer()

# The same reasoning applied to the clock: see `WallClock`. Monotonic, so a
# clock the machine adjusts underneath a three-day run cannot turn a duration
# negative or add an hour that nobody waited.
_PROCESS_STARTED = time.monotonic()


def producer():
    """The `build.producer` entry: who wrote THIS manifest.

    Not who produced the bytes. For an artifact that is re-sealed later, or
    sealed from data an earlier major emitted, the two differ, and only the
    first is knowable at seal time. Saying "who wrote this manifest" is the
    reading that is always true, so it is the one this field means.

    The version is always there. The commit and the state of the tree are
    recorded only when they can actually be determined — running from a
    checkout OF THIS CODE, with git answering — and are simply ABSENT
    otherwise, because an installed package has no repository to ask and a
    field that guesses is worse than a field that is missing. "Of this
    code" is load-bearing: git happily answers for whatever repository
    encloses the package directory, and an installed copy can sit inside
    somebody's unrelated one, whose HEAD names their work, not this
    manifest's writer. `_read_producer` checks the module is tracked
    before believing the answer.

    `dirty` is the part worth having. The failure this guards against is not
    building from an untagged commit, it is building from a tree with edits
    that were never committed: a version string alone cannot tell the two
    apart, and no discipline catches it after the fact. Modifications to
    tracked files count; untracked files do not, since a stray file beside
    the package is not the code that ran.

    WHEN it is read is part of what it means, and the answer is: when the
    process starts, not when the manifest is written. A scan seals after
    days. Asking git at seal time would describe the tree as it is at the
    END of the run, so an edit made while the scan was running would be
    reported against code that never executed, and a checkout moved
    underneath it would name a revision that never ran. Neither is a lie
    anyone could catch later, which is exactly the kind of field this is
    meant not to be. Reading at import costs one fork per process and
    describes the code that is actually running.

    Outside the identity by the module's own rule (it is how this copy came
    to be, not what it is), and outside `canonical_statement` for a sharper
    reason: see there.
    """
    return dict(_PRODUCER)


class WallClock:
    """What an artifact cost in wall time, in whole seconds, under the
    verb that spent them: the `build.seconds` of every manifest.

    Why an artifact carries this at all: the only guide anyone has for
    deciding whether a question is affordable is a table of durations,
    and until now that table was assembled by hand from a log that no
    artifact keeps. A duration recorded at seal time travels with the
    thing it describes, and a reader who holds the artifact holds the
    cost of having built it.

    WHERE IT LIVES IS NOT A CHOICE
    ==============================
    In `build`, never in the identity. Two honest builds of identical
    bytes take different times, so a duration inside the identity would
    hand the same content two fingerprints, which is the single failure
    the identity exists to prevent. It is outside `canonical_statement`
    too, for the sharper reason `producer` is: nothing can ever confirm
    it, and binding an unfalsifiable claim only lends it the weight of a
    signature.

    WHAT IT MEASURES, AND WHAT IT MISSES
    ====================================
    The wall clock and not the CPU, because what a person plans against
    is how long they wait. It is keyed by the PUBLIC verb (`scan`,
    `merge`, `build`, `append`, `fingerprint`, `rewind`) and not by the
    module that ran, for the reason cli.py exists: the verbs are the
    surface that does not move.

    It accumulates, in two senses, and both are deliberate:

      across resumes  the running total lives in the artifact's state,
                      which is what survives a kill, so a job stopped
                      and restarted reports what it really cost instead
                      of what its last stretch cost. The seconds between
                      the last checkpoint and the kill are lost, since
                      nothing recorded them. A figure that undercounts
                      by a bounded and stated amount is worth more than
                      one that silently restarts at zero;
      across runs     an artifact fused twice has paid for two fusions,
                      and the entry under `merge` says so. The number
                      answers "what has this artifact cost me", not
                      "what did the last command take".

    A command with no state of its own (a fingerprint pass, a one-shot
    derivative) has nothing to carry and simply reports its own seconds.

    ONE PASS, SEVERAL ARTIFACTS: THE FIGURES DO NOT ADD UP
    ======================================================
    Every artifact carries its own entry, because an artifact that
    cannot say what it cost is no better than a log somebody kept. But
    a `scan` co-emits: one walk of the chain writes the archive, the
    header archive, the nonce census and the graph, and each of them
    records the SAME seconds under `scan`. Those four numbers are one
    pass seen four times, and summing them describes a run nobody
    performed. Only entries under different verbs, and within one
    artifact, are costs that were really paid one after the other.

    WHEN THE CLOCK STARTS
    =====================
    At process start, read once at import exactly as `producer` is, and
    not at the moment a `WallClock` happens to be constructed. A seal
    runs at the END of the work it is timing, so a clock born there
    would measure nothing; making the baseline the process means every
    site that records a duration is one line, and none of them has to
    thread a start time down from wherever the command began. What
    licenses that is the CLI's own shape: a process runs one command.
    A caller that drives several in one process (the test suite, an
    embedding) therefore gets the time since that process started, and
    `started` is there for anyone who needs the narrower reading.
    """

    KEY = "seconds"

    def __init__(self, verb, state=None, started=None):
        self.verb = verb
        carried = dict((state or {}).get(self.KEY) or {})
        self._carried_others = {k: int(v) for k, v in carried.items()
                                if k != verb}
        self._carried = int(carried.get(verb, 0))
        self._started = _PROCESS_STARTED if started is None else started

    def seconds(self):
        """This verb's total: what earlier segments recorded, plus what
        this process has spent so far."""
        return self._carried + round(time.monotonic() - self._started)

    def stamp(self, state=None):
        """The whole `seconds` mapping, written into `state` when
        there is one to write it into.

        Called at every checkpoint (so a kill loses at most the last
        stretch) and once more at seal time, where the returned mapping
        is what goes into `build`."""
        total = dict(self._carried_others)
        total[self.verb] = self.seconds()
        if state is not None:
            state[self.KEY] = total
        return total


def sha_and_ladder(path, rec, key_len, every, error):
    """One pass over a `rec`-byte record file: its sha256, and the ladder
    that file implies — every `every`-th record's first `key_len` bytes,
    counted from record 0.

    That sampling rule is the ONE rule every ladder in this codebase
    follows: `genstore.merge_to_file` writes it while fusing, and the two
    hand-built ladders (tx_first_out, tx_inputs) write the same thing at
    seal time. Only the (rec, key_len, every) triple differs, and each
    artifact declares its own. So a ladder can always be reconstructed from
    the file it indexes, which is what turns `verify` from "intact" into
    "correct" — see verify_sealed.

    Hashed by slab, sampled by record: the files this runs on hold billions
    of rows, and one sha256 update per row would spend more time calling
    than hashing. The sampling steps THROUGH the slab instead of walking
    it, so the ladder costs a few thousand slices, not a few billion."""
    digest = hashlib.sha256()
    ladder = bytearray()
    n = 0
    for slab in read_slabs(path, rec, error=error):
        digest.update(slab)
        rows = len(slab) // rec
        for i in range(-n % every, rows, every):
            ladder.extend(slab[i * rec:i * rec + key_len])
        n += rows
    return digest.hexdigest(), bytes(ladder)


def verify_sealed(directory, manifest, tag, error, fp_order, ladder_hint="",
                  ladders=None, coverage_from_data=None, trust_hint="",
                  parent_confirmed=None, prepared=None):
    """The audit `verify` runs: re-read every sealed file and cache of an
    artifact against its manifest, then recompute the fingerprint from what
    is actually on disk. Raise `error` on any mismatch. Every artifact that
    seals an identity shares this verbatim.

    `tag` is normally one format tag. It may instead be a sequence, for
    a format that has a READABLE PREDECESSOR: a tool that emits the new
    version and still reads artifacts somebody downloaded under the old
    one. The sequence is legitimate only while every tag in it is made
    of the same files in the same order, since `fp_order` is passed
    once; a version that adds or renames a file needs its own call.
    Emission is never widened this way: a builder writes one tag.

    `fp_order` is the file list the format tag mandates, stated by the
    code and not read from the manifest, and the audit's first check is
    that the identity lists exactly those names in exactly that order.
    The manifest carries the list too — the fingerprint is over it — but
    a manifest can only vouch for being CONSISTENT with itself: a
    truncated one whose fingerprint is recomputed over the same shortened
    list would pass every digest and still describe an artifact its
    declared format does not define. What the format is made of is the
    one fact the audit must bring with it. `ladder_hint` is appended to
    the corrupt-ladder message (the index can point at a rebuild). Prints
    one line per file, as the CLI `verify` did before it was shared.

    `coverage_from_data` is the second road for the one identity field the
    digests cannot prove. The artifact passes a callable returning
    `("exact", h)` or `("floor", h)`, or None when its bytes hold no height
    at all:

      exact  the data state the watermark (one `blocks.bin` record per
             height): any other claim is refused;
      floor  the records carry the height of an EVENT, so the highest one
             found is a lower bound. A claim below it is refused; a claim
             above it cannot be confirmed, because a stretch of chain with
             no new revelation leaves no trace. Worth having anyway: it
             turns "the coverage is a word given" into "a word given about
             the last few blocks only";
      None   nothing to confront, and the report SAYS so. An audit silent
             about what it did not check reads as an audit that checked
             everything. `trust_hint` names the flag that would supply
             the missing road, where one exists.

    `ladders` is the artifact's projection, logical name → (record width,
    key length, ladder step), for the files that carry a ladder. It is what
    lets this audit check a ladder is RIGHT and not merely intact. Without
    it a `.lad` is only compared with `manifest.caches.<name>.sha256`, which
    the seal wrote by hashing the very samples it had just built: the
    comparison is with itself, and a ladder sampled by a wrong rule would
    pass while making lookups answer short. With it, the ladder is rebuilt
    from the data file during the read that file already pays for — no
    extra pass — and the manifest is confronted with a second, independent
    road, exactly as `sha_file` already does for the data.

    A cache with no declared projection still gets the intact-only check.
    That is a narrower guarantee, and the printed line says so.

    `prepared` is name → (sha256 hex, ladder bytes) for files the caller
    has ALREADY streamed in a pass of its own — the archive's `--deep`
    record audit walks every byte anyway, and reading the same tens of
    GB twice buys nothing. The values must come from the same two rules
    this function would apply (`sha_and_ladder`), so what is checked is
    unchanged; only the second read is gone."""
    ladders = ladders or {}
    prepared = prepared or {}
    accepted = (tag,) if isinstance(tag, str) else tuple(tag)
    identity = manifest["identity"]
    build = manifest["build"]
    found_tag = identity["format"]
    if found_tag not in accepted:
        raise error(f"identity declares format {found_tag!r}, not "
                    + " or ".join(repr(t) for t in accepted))
    listed = [entry["name"] for entry in identity["files"]]
    if listed != list(fp_order):
        raise error(
            f"identity lists files {', '.join(listed) or '(none)'}, but "
            f"{found_tag} is made of {', '.join(fp_order)}: this manifest "
            "does not describe a complete artifact of its declared format")
    rebuilt = {}
    for entry in identity["files"]:
        name = entry["name"]
        # The manifest is untrusted the moment this process did not
        # write it, and an artifact is a thing people hand each other.
        # See recio.checked_name.
        file_name = checked_name(build["files"][name]["file"], error)
        path = os.path.join(directory, file_name)
        spec = ladders.get(name) if name in build["caches"] else None
        if spec is not None:
            every = build["caches"][name]["every"]
            if every != spec[2]:
                raise error(
                    f"{build['caches'][name]['file']}: declares a step of "
                    f"{every} records, but {found_tag} fixes it at "
                    f"{spec[2]}{ladder_hint}")
        if name in prepared:
            found, ladder = prepared[name]
            if spec is not None:
                rebuilt[name] = ladder
        elif spec is None:
            found = sha_file(path)
        else:
            rec, key_len, _declared_every = spec
            found, rebuilt[name] = sha_and_ladder(path, rec, key_len, every,
                                                  error)
        if found != entry["sha256"]:
            raise error(f"{file_name}: sha256 mismatch, corrupted "
                        "since sealing")
        print(f"ok  {file_name}")
    for name, entry in build["caches"].items():
        cache_path = os.path.join(directory,
                                  checked_name(entry["file"], error, "cache"))
        if sha_file(cache_path) != entry["sha256"]:
            raise error(f"{entry['file']}: sha256 mismatch, corrupted "
                        f"ladder{ladder_hint}")
        if name not in rebuilt:
            print(f"ok  {entry['file']} (cache, intact but not rebuilt)")
            continue
        if hashlib.sha256(rebuilt[name]).hexdigest() != entry["sha256"]:
            raise error(
                f"{entry['file']}: intact, but it is not the ladder "
                f"{build['files'][name]['file']} implies: the samples it "
                f"holds are not the ones that file's records give. A search "
                f"through it can land in the wrong bucket and answer "
                f"short{ladder_hint}")
        print(f"ok  {entry['file']} (cache, rebuilt from "
              f"{build['files'][name]['file']})")

    # The coverage is the one identity field no digest can prove. Where the
    # data imply it, confront the two; where they cannot, say so out loud.
    declared = identity["coverage"]["to"]
    # The range is read from the identity at both ends: the header archive
    # starts at genesis where every other artifact starts at 1, and a report
    # that assumed the 1 would be quietly describing a different range.
    span = f"{identity['coverage']['from']:,}..{declared:,}"
    if coverage_from_data is None:
        print(f"..  coverage {span} taken on trust"
              + (f" (pass {trust_hint} to confront it)" if trust_hint else ""))
    else:
        kind, derived = coverage_from_data()
        wrong = derived != declared if kind == "exact" else derived > declared
        if wrong:
            raise error(
                f"manifest claims coverage through height {declared:,}, but "
                f"the data reach {derived:,}: the coverage is inside the "
                f"identity, so this artifact is not the one its fingerprint "
                f"names")
        if kind == "exact":
            print(f"ok  coverage {span} (rebuilt from the data)")
        else:
            print(f"ok  coverage {span} (data reach {derived:,}: a "
                  f"floor, not a proof; the tail beyond it leaves no trace)")

    recomputed = identity_fingerprint(identity)
    if recomputed != manifest["fingerprint"]:
        raise error("manifest fingerprint does not match its own identity "
                    "block")

    # The parent is declared, not sealed, so the audit reports it the way it
    # reports a coverage it cannot derive: named, and marked unconfirmed
    # until somebody hands over the artifact it names. `parent_confirmed` is
    # what the caller passes once it has compared them.
    parent = build.get("parent")
    if parent is None:
        print("..  parent none declared")
    elif parent_confirmed is None:
        print(f"..  parent {parent['format']} {parent['fingerprint']} "
              "declared, not confirmed"
              + (f" (pass {trust_hint} to confront it)" if trust_hint else ""))
    elif parent_confirmed:
        print(f"ok  parent {parent['format']} {parent['fingerprint']}")
    else:
        raise error(f"the artifact given is not the {parent['format']} this "
                    "one declares as its parent")

    # The statement is recomputable from what the manifest already holds, so
    # a disagreement means the manifest contradicts itself. It secures
    # nothing on its own — whoever edits a declared parent edits this too —
    # but it makes a careless edit visible, and it is the agreed target for
    # anyone building a signature on top.
    stated = manifest.get("statement")
    if stated is not None and stated != statement_digest(manifest):
        raise error("the manifest's statement does not match the manifest: "
                    "the fingerprint or the declared parent was edited "
                    "without recomputing it")
    print(f"fingerprint verified: {manifest['fingerprint']}")
