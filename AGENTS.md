# AGENTS.md — orientation for agents (neutral)

Instructions for anyone working on this repo with the help of an assistant/LLM.
**Deliberately neutral:** not specific to any model or tool.

## What this is

NodSig is a toolkit to analyze the Bitcoin chain with your **own node**, in a
**reproducible and fingerprint-verifiable** way. It does not validate consensus,
does not serve real-time state, and is not an online service: it is a replica
optimized for analytical reads.

## Where the truth lives

1. **Module docstrings** = canonical spec of format/behavior.
2. **`docs/`** = architecture (`ARCHITECTURE.md`), contracts (`contracts/`),
   byte formats (`formats/`), types (`types.md`), glossary, invariants.
3. **Tests + conformance vectors** = the *executable* contract. If code and a
   doc disagree, the test is the arbiter.

## Build / test

- Python, minimal dependencies. Tests with `pytest`.
- Do not add heavy dependencies without reason: minimalism is a value here.

## Invariants — do NOT violate

- **Determinism**: same inputs → same bytes → same canonical fingerprint.
- **Source in every answer**: watermark + source + fingerprint.
- **Never silent data**: an absent/unknown capability yields an explicit state
  (UNDETERMINED/UNSUPPORTED), never a silent default or an uncounted drop.
- **Big-endian integers** in the formats (byte order is numeric order).
- **One-way contracts**: public code never names private extensions.
- **Do not scatter fingerprints through the documentation.** A fingerprint is
  a fact about one build, at one height, under one set of formats, so every
  copy of it is a place that will silently go stale — and the reader has no
  way to tell which copy aged. The live answer is printed by the build,
  recorded in each `manifest.json`, and recomputed from the bytes by `verify`.

  Two frozen sets exist on purpose and are **historical anchors, not values to
  keep aligned**: the first published artifacts in `docs/gallery.md` and the
  three v1 digests in `docs/formats/RevealArchive-v2.md`, which
  `archive v1-digests` confronts a fresh scan with. Do not update either.

  The rule forbids **copies**, not a registry. A single document listing known
  artifacts (height, formats, fingerprint) for readers who want a cross-check
  would be its opposite, and is an open idea rather than a prohibition: one
  place that says what it covers, and admits it can never be exhaustive.
- **The format matrix in `docs/ARTIFACTS.md` is generated from the code.** If
  a `FORMAT_TAG` or `READ_TAGS` moves, fix the table; never the reverse.
  `tests/test_conformance.py` fails if the two disagree, in both directions.

## Out of scope (do not add it)

Consensus validation, mempool/real-time state in the core, wallet, online
service. These are deliberate choices, not gaps.

## Conventions

- **Pure kernels** (parse / hash / sort-merge / record codec / address codec)
  with no I/O and no state; the **orchestration** (CLI, resume, source)
  calls them.
- Code **readable before clever**; comments explain *what* and *why*.
- Extend a contract by implementing its interface and passing the **conformance
  vectors**; see the recipes in `docs/`.

### These rules are executable

The three sections below (words this project does not name its output
after, words reserved to one job, and claims that must not be named after
ownership) are checked by **`tests/test_layering.py`**, together with the
kernel/orchestration seam of `ARCHITECTURE` §4.

They are tests because all four had already drifted while written only as
prose: two of them came back through a rule that lived in a commit
message, and the seam one survived three audits, each of which was
looking for something else. An audit finds what it looks for; a test looks
every time. If a rule genuinely needs to change, change it **here first**
and in that file second, in the same commit.

One thing that file deliberately does NOT do is collect exceptions. Every
name added to an allowlist is a place where the next reader greps, finds
the word in a curated file, and reads precedent where a prohibition was
meant, which is exactly how `verdict` came back. Documents that help
somebody migrate from an older format may name the old key, because a
migration needs it. Code points at the rule instead.

### Words this project does not use to NAME what it produces

This tool **measures and does not judge**, and the vocabulary has to carry
that or the code drifts out of it before the behaviour does. The rule is
about naming and labelling, because that is where it bites first: a function
named after a judgment grows a docstring that defends one, and a CSV header
teaches every reader the wrong noun before any prose gets a chance.

Never as an identifier, a parameter, a CSV header, a file or figure name, or
a label in printed output:

| not this | because | use |
|---|---|---|
| `verdict` | names a judgment we do not pass. The artifacts *store* and *resolve*; a court reaches verdicts | `resolution`, `answer`, `outcome` |
| `victim`, `attacker` | assigns roles to people nobody here has identified | name the fact: an exposed key, a repeated point |
| `risk`, `safe`, `unsafe` | a risk assessment is exactly what this does not do | `exposed`, `not exposed`, `undetermined` |
| `discovery`, `first`, `novel` | claims novelty. What is measured here is public, and mostly already known | `measurement`, `count`, `what the run produced` |

**Stating the opposite is required, not forbidden.** "nodsig measures a fact,
it does not assess a risk", "no statement about whether anyone's funds are
safe", "a candidate and not a conclusion": these sentences are the doctrine
and they must stay. The rule forbids the word as a **label on our output**,
not the sentence that denies we produce one. And it does not reach ordinary
engineering compounds: a *crash-safe* commit order is exactly that.

`verdict` is the one flat case: it is gone from the tree entirely, including
from the denials, and `conclusion` says the same thing there.

**The rule follows the words, not the file.** It holds for anything written
about this project for somebody else to read — a note to a collaborator, a
draft handed to whoever writes about the numbers, an answer to a question —
and in any language, since a translated judgment is still a judgment. A tool
that measures and does not judge cannot describe itself with the vocabulary
of judgment the moment it stops talking to a compiler. Where an equivalent is
needed: *risoluzione* for `resolution`, *conclusione* for `conclusion`.

**Why this section exists, and it is not hypothetical.** `verdict` was
removed from the per-address report in July, for these reasons, written out
in the commit message and nowhere else. It came back months later as the name
of a public API. Two lessons, and this file is the fix for both:

- **a rule that lives in a commit message is not recorded.** Nobody greps the
  log for vocabulary. It goes here, where a reader with no memory will look;
- **do not leave silent exceptions in the tree.** That removal deliberately
  kept three uses where the word DENIED. Sound reasoning, and a trap: the
  next reader grepped, found the word in three curated files, and read
  precedent where a prohibition was meant. An exception is only safe when it
  is written down beside the rule, as the paragraph above does.

### Words reserved to ONE job

A different failure from the one above, and it has already happened twice.
These words are not forbidden: each names exactly one thing here, and using
it for a second thing is what makes a format document unreadable, because a
reader who greps finds two answers and no way to tell which is theirs.

| word | names, and only this | for the other job |
|---|---|---|
| `provenance` | the bits recording **where a key was seen inside an input** (`reveal-archive-v2`) | `source` for who answered; `ancestry` for the chain back to the blocks; `origin` for where a list of addresses came from |
| `source` | **who answered a question**, as `Source { id, watermark, fingerprint }` | `origin`, `method`, or the specific noun |
| `ancestry` | the chain of artifacts back to the blocks | it has no second job |

**How both breaches happened**, because the pattern is the point. The first
time, one word was doing three jobs at once and had to be split. The split
was correct, and it was recorded **in a commit message**: months later a new
input format called its origin block `provenance`, which was a fourth job,
and it shipped in a public format before anyone noticed. That is the same
lesson as the section above, arriving from a different direction: **the rule
was written, but not where a reader looks.**

The tell is worth learning, because it is cheap: when naming a field, grep
the tree for the word first. Two unrelated hits mean the name is taken.

### Do not name a claim after ownership

`check` reads an address book whose groups carry a `claim`. That claim used
to be `"mine"`, and it is now `"separate"`. Not for delicacy: `"mine"`
described a relationship between the author and the addresses, while the
only thing the value has ever governed is whether the group takes part in
the separation sentences.

nodsig cannot know who controls an address; that would take a signature. A
field, a value or a sentence that implies otherwise teaches every reader
that the tool established something it never looked at. What the input may
ask about is **what the author intended** (these were meant to be kept
apart, this one I am only watching), never who owns what.

### Naming an output file

Two shapes, and which one applies is decided by **what happens to the file
next**, not by taste:

- **a terminal report**, that nothing here reads back, is named
  `<command>-results.<ext>`. The only question a reader has in front of it is
  where it came from, and the name answers that. `check` writes
  `check-results.txt`;
- **a file another command consumes** is named for its **content**. At the
  point of use the reader needs to know what is inside, not who made it:
  `curve deltas curve.csv` says what it is doing, while a name carrying the
  producing command would hide it behind provenance nobody needs there.
  `curve.csv`, `revelations.csv`, `block-stats.csv`, `resolutions.csv`.

If a file starts as terminal and later gets a reader, it moves to the second
shape and the default changes with it.

## Repo hygiene (pseudonymity)

- **One development identity, always.** Every commit carries the identity
  configured in this repo. Never override it — not with `git -c user.email=…`,
  not with `git commit --author=…`, not "just this once". A `pre-commit` hook
  refuses both, because git history is public after the first push and cannot
  be corrected afterwards. If the project's identity ever has to change, that
  is an explicit decision and the hook is edited by hand.
- **One voice in the log.** A commit message carries no co-author trailer and
  no mark of assistance — no `Co-Authored-By:`, no "generated with", no tool or
  model name. This is not about what gets published: it is about what gets
  written, so it holds for every commit from the first. Assistants that add
  such a trailer by default must be told not to, here.
- No real data in fixtures (addresses / xpubs / your node's paths): public,
  synthetic fixtures only. Local paths live in uncommitted config.
- **Nothing in this directory is private.** Write nothing here — code,
  comment, doc, test fixture, commit message — that you would not want
  published under this identity forever. Machine paths, host names and
  directory layouts count: a sample path in a docstring is still a
  description of somebody's machine. Use neutral placeholders
  (`/srv/artifacts/…`).

## Cutting a release

A release is a version number, a commit that explains it, and an annotated tag.
The version has a single source, `src/nodsig/__init__.py`: `pyproject.toml`
reads it from there, so the two can never disagree. The tag spells the same
version the way git tags read it, with a hyphen before a pre-release segment:
`__version__ = "1.0.0"` is tagged `v1.0.0`, and `"1.1.0rc1"` would be tagged
`v1.1.0-rc1`.

This number is not the formats' number. An artifact declares its own format tag
(`reveal-archive-v2`, and `nodsig-identity-v3` for the recipe every fingerprint
is taken over), and those move when a format moves, which has nothing to do with
when a release is cut. Do not align them.

The order matters, because each step is what makes the next one honest:

0. **sweep the public documentation**, if any format tag moved. This step
   exists because it was learned the expensive way: after the 1.2.0 formats
   landed, the gallery still told readers to rebuild and find the same bytes,
   four documents still quoted the previous sizes as measurements, and the
   page a reader with older artifacts would actually open said nothing about
   the refusal they were about to hit. None of it was caught by the tests,
   because none of it was wrong code — it was prose that had quietly stopped
   being true.

   Two of the mechanical checks are now automatic, and fail the suite: the
   format matrix in `docs/ARTIFACTS.md` is rebuilt from the modules'
   `FORMAT_TAG`/`READ_TAGS`, and no document may name a format tag that no
   module emits, reads, or has a stated reason for. What is left is the part a
   machine cannot judge, so read for it:

   - **claims that a rebuild reproduces something.** A format change makes
     every one of them false. `git grep -n "byte for byte"`;
   - **sizes and durations.** They were measured on the previous formats. Either
     re-measure or label them projections and keep the measured figure beside
     them — a provisioning number that is quietly optimistic is worse than one
     that is openly conservative;
   - **record widths and file names** in the format documents and in the module
     docstrings, which are format documentation too;
   - **what happens to artifacts somebody already has.** `build-and-query.md`
     under "Growing them", and the changelog's "Do your artifacts still work?"
     Say which operations refuse, and say it where a reader looks *before*
     hitting the refusal;
   - **fingerprints**: do not update them, do not add them (see the invariant
     above).

   `git grep -n "<old-tag>"` finds the names. Nothing finds the sentences: they
   have to be read.

1. **bump** `__version__`, and the tag name in the comment beside it;
2. **commit** as `release: <version>, <what it is>`, with a body that says what
   changed *for the reader* rather than listing the commits, which the log
   already holds. The one thing worth naming explicitly is anything that
   changes the BYTES an artifact will hold, because that is what makes this
   version and the previous one different artifacts rather than different
   packaging;
3. **check**, before tagging: the tests are green; every commit about to be
   pushed carries the repository's identity; no message carries a co-author
   trailer or a mark of assistance; the diff contains no machine path, host
   name or non-English text; nothing private is tracked;
4. **tag**, annotated, and only then push.

Why a release matters here beyond packaging: every sealed manifest records
`build.producer`, which carries this version string. Running a multi-hour build
from an untagged tree stamps its artifacts with the version of the *last*
release, which names code that may no longer produce those bytes. Bump before
the run, not after it.

**The tag and the push are asked for, every time.** An annotated tag is as
public as a commit and additionally carries the identity of the tagger, which
the `pre-commit` hook does not check. Committing locally is free; publishing is
the step that cannot be undone by deleting anything.
