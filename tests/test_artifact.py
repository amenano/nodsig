#!/usr/bin/env python3
"""
test_artifact.py — the identity recipe, pinned.

The fingerprint is the number a stranger recomputes to check an artifact,
so its recipe must not drift. These tests state it independently, and then
check the two properties that make it an IDENTITY rather than a checksum of
a bag of bytes: everything the identity names moves it (order, tag,
coverage, digests), and everything `build` holds does not — the parent
above all, since two builds of the same content must take the same name
whatever they were built from.
"""

import hashlib
import os
import subprocess
import time

import pytest

from nodsig import __version__
from nodsig.artifact import (WallClock, _read_producer, canonical_identity,
                             canonical_statement, identity_fingerprint,
                             make_identity, producer, seal_manifest,
                             statement_digest)


def _ago(seconds):
    """A monotonic baseline `seconds` in the past: the clock's own start
    is the process's, and a test that waited would only be slower."""
    return time.monotonic() - seconds


A = hashlib.sha256(b"A").hexdigest()
B = hashlib.sha256(b"B").hexdigest()


def _lp(text):
    raw = text.encode()
    return len(raw).to_bytes(2, "big") + raw


def test_recipe_matches_independent_recomputation():
    """The recipe restated by hand, field by field, as a porter would read
    it out of the contract."""
    ident = make_identity("fmt-v2", 1, 4, [("beta", B), ("alpha", A)])
    want = bytearray(b"nodsig-identity-v3\x00")
    want += _lp("fmt-v2")
    want += (1).to_bytes(4, "big") + (4).to_bytes(4, "big")
    want += (2).to_bytes(4, "big")
    want += _lp("beta") + bytes.fromhex(B)
    want += _lp("alpha") + bytes.fromhex(A)
    assert canonical_identity(ident) == bytes(want)
    assert identity_fingerprint(ident) == hashlib.sha256(want).hexdigest()


def test_the_identity_holds_no_parent():
    """The recipe has no room for one, in either direction: a builder
    cannot smuggle a parent in, and adding the key to a manifest by hand
    cannot move the number."""
    ident = make_identity("fmt-v2", 1, 4, [("only", A)])
    assert "parent" not in ident
    before = identity_fingerprint(ident)
    ident["parent"] = {"format": "elsewhere-v2", "fingerprint": B}
    assert identity_fingerprint(ident) == before


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda i: i["files"].reverse(), id="file order"),
    pytest.param(lambda i: i.__setitem__("format", "other-v2"), id="tag"),
    pytest.param(lambda i: i["coverage"].__setitem__("to", 5),
                 id="coverage to"),
    pytest.param(lambda i: i["coverage"].__setitem__("from", 2),
                 id="coverage from"),
    pytest.param(lambda i: i["files"][0].__setitem__("name", "renamed"),
                 id="file name"),
    pytest.param(lambda i: i["files"][0].__setitem__("sha256", B),
                 id="file digest"),
])
def test_every_identity_field_moves_the_fingerprint(mutate):
    """Nothing in the identity is decoration: touch any of it and the
    artifact is a different one, which is the whole point of putting the
    coverage inside it alongside the digests."""
    base = make_identity("fmt-v2", 1, 4, [("alpha", A), ("beta", B)])
    before = identity_fingerprint(base)
    mutate(base)
    assert identity_fingerprint(base) != before


def test_length_prefixes_keep_the_form_unambiguous():
    """Without length prefixes these two would concatenate to the same
    bytes, and a canonical form that can be read two ways is not
    canonical."""
    one = make_identity("t", 1, 1, [("ab", A), ("c", B)])
    two = make_identity("t", 1, 1, [("a", A), ("bc", B)])
    assert identity_fingerprint(one) != identity_fingerprint(two)


def test_accepts_any_ordered_iterable():
    # Builders pass a generator, not a list: the pairs are consumed once.
    pairs = ((n, A) for n in ("only",))
    assert (identity_fingerprint(make_identity("t", 1, 2, pairs))
            == identity_fingerprint(make_identity("t", 1, 2, [("only", A)])))


# ---------------------------------------------------------------------------
# the signable statement
# ---------------------------------------------------------------------------

def _manifest(parent=None):
    ident = make_identity("fmt-v2", 1, 4, [("only", A)])
    build = {"generation": 1, "counters": {"rows": 7}}
    if parent is not None:
        build["parent"] = {"format": "parent-v2", "fingerprint": parent}
    return seal_manifest("fmt-v2", ident, build)


def test_statement_recipe_matches_independent_recomputation():
    """Restated by hand, as a porter writing a signer would read it out of
    the contract."""
    m = _manifest(parent=B)
    want = bytearray(b"nodsig-statement-v1\x00")
    want += _lp("fmt-v2")
    want += bytes.fromhex(m["fingerprint"])
    want += b"\x01" + _lp("parent-v2") + bytes.fromhex(B)
    assert canonical_statement(m) == bytes(want)
    assert m["statement"] == hashlib.sha256(want).hexdigest()


def test_a_root_artifact_states_the_absence_of_a_parent():
    m = _manifest()
    assert canonical_statement(m).endswith(b"\x00")
    assert m["statement"] != _manifest(parent=B)["statement"]


def test_the_statement_binds_the_parent_and_nothing_recomputable():
    """It exists to cover what the fingerprint does not and the files do
    not: the declared parent. Everything a reader could recompute from the
    data must leave it alone, or a signature would be about a copy rather
    than about an artifact."""
    base = _manifest(parent=B)
    moved = _manifest(parent=A)
    assert moved["statement"] != base["statement"]

    same = _manifest(parent=B)
    same["build"]["generation"] = 9
    same["build"]["counters"]["rows"] = 999
    assert statement_digest(same) == base["statement"]


# --- the producer -----------------------------------------------------------

def test_the_producer_always_names_a_version():
    """Absent is allowed for the commit, invented is not: away from a
    checkout there is no repository to ask, and the field says so by not
    being there."""
    p = producer()
    assert p["version"] == __version__
    assert ("commit" in p) == ("dirty" in p)
    if "commit" in p:
        assert len(p["commit"]) == 40
        assert isinstance(p["dirty"], bool)


def test_the_producer_is_read_once_and_handed_out_by_copy():
    """It describes the process, so it is read when the process starts: a
    scan that seals after three days must not report the tree as it is at
    the end. And each caller gets its own dict, so one manifest cannot edit
    what the next one records."""
    first, second = producer(), producer()
    assert first == second
    first["dirty"] = "tampered"
    assert producer()["dirty"] == second["dirty"]


def _git(*args):
    """Git against a throwaway fixture repository, with a synthetic
    identity supplied by environment so the test does not depend on (or
    touch) the machine's git configuration."""
    subprocess.run(
        ["git", *args], check=True, capture_output=True,
        env={**os.environ,
             "GIT_AUTHOR_NAME": "test",
             "GIT_AUTHOR_EMAIL": "test@example.com",
             "GIT_COMMITTER_NAME": "test",
             "GIT_COMMITTER_EMAIL": "test@example.com"})


def test_the_producer_refuses_a_repository_that_is_not_this_code(tmp):
    """git answers for the FIRST repository enclosing the package
    directory, and for an installed copy that can be anyone's: a venv
    under a project, a git-managed home. Its HEAD names that person's
    work, and the manifest is written to be published — so unless the
    module itself is tracked there, the commit stays absent."""
    repo = os.path.join(tmp, "theirs")
    pkg = os.path.join(repo, "venv", "lib", "nodsig")
    os.makedirs(pkg)
    _git("init", "-q", repo)
    with open(os.path.join(repo, "README"), "w") as f:
        f.write("somebody else's project\n")
    _git("-C", repo, "add", "README")
    _git("-C", repo, "commit", "-qm", "theirs")
    installed = os.path.join(pkg, "artifact.py")
    with open(installed, "w") as f:
        f.write("# an installed copy of this module\n")
    assert _read_producer(installed) == {"version": __version__}


def test_the_producer_names_the_commit_of_a_checkout_of_this_code(tmp):
    """The other side of the guard, so it cannot rot into 'never record
    a commit': where the module IS tracked, the commit and the dirty
    bit are read exactly as before."""
    repo = os.path.join(tmp, "checkout")
    os.makedirs(repo)
    _git("init", "-q", repo)
    module = os.path.join(repo, "artifact.py")
    with open(module, "w") as f:
        f.write("# this module, committed\n")
    _git("-C", repo, "add", "artifact.py")
    _git("-C", repo, "commit", "-qm", "checkout")
    out = _read_producer(module)
    assert len(out["commit"]) == 40 and out["dirty"] is False
    with open(module, "a") as f:
        f.write("# an edit that never got committed\n")
    assert _read_producer(module)["dirty"] is True


def test_the_producer_moves_neither_the_fingerprint_nor_the_statement():
    """It is the one claim in `build` that nothing can ever confirm, so it
    stays out of both numbers. Two builders of identical bytes must reach
    the same fingerprint whatever produced them, and a signature must not
    lend its weight to an unfalsifiable line."""
    base = _manifest(parent=B)
    with_producer = _manifest(parent=B)
    with_producer["build"]["producer"] = {
        "version": "9.9.9", "commit": "de" * 20, "dirty": True}
    assert with_producer["fingerprint"] == base["fingerprint"]
    assert statement_digest(with_producer) == base["statement"]


# ---------------------------------------------------------------------------
# the wall clock
# ---------------------------------------------------------------------------

def test_the_clock_carries_what_earlier_segments_recorded():
    """A resumed job reports what it really cost, not what its last
    stretch cost: the running total lives in the state, which is what
    survives a kill."""
    state = {}
    WallClock("build", state, started=_ago(30)).stamp(state)
    assert state["seconds"]["build"] == 30
    # A second process over the same state: its own seconds ON TOP.
    WallClock("build", state, started=_ago(12)).stamp(state)
    assert state["seconds"]["build"] == 42


def test_each_verb_is_counted_on_its_own():
    """One artifact pays for several kinds of work, and a fusion is not
    a scan. A clock reads and rewrites its own entry and carries the
    others through untouched."""
    state = {"seconds": {"scan": 187_000}}
    total = WallClock("merge", state, started=_ago(600)).stamp(state)
    assert total == {"scan": 187_000, "merge": 600}
    assert state["seconds"] == total


def test_a_command_with_no_state_reports_only_itself():
    """A fingerprint pass has nothing to carry, and nothing to write
    into: it hands back the mapping and leaves no trace."""
    assert WallClock("fingerprint", started=_ago(5)).stamp() == \
        {"fingerprint": 5}


def test_the_wall_stretches_ride_along_and_do_not_duplicate():
    """`stamp` writes the real-time stretches under their own key: one
    [start, end] UTC pair per process stretch. A second clock in the
    SAME process (an in-process resume) continues its own stretch
    instead of appending a twin; a stretch from ANOTHER process is
    carried through untouched, and the new one lands after it."""
    state = {"wall": {"build": [["2026-01-01T00:00:00Z",
                                 "2026-01-01T02:00:00Z"]]}}
    WallClock("build", state, started=_ago(30)).stamp(state)
    stretches = state["wall"]["build"]
    assert stretches[0] == ["2026-01-01T00:00:00Z",
                            "2026-01-01T02:00:00Z"]
    assert len(stretches) == 2
    start, end = stretches[1]
    assert start.endswith("Z") and end.endswith("Z") and start <= end
    # The same process stamps again: still two stretches, its own one
    # continued, the foreign one untouched.
    WallClock("build", state, started=_ago(12)).stamp(state)
    assert len(state["wall"]["build"]) == 2
    assert state["wall"]["build"][0][0] == "2026-01-01T00:00:00Z"


def test_the_wall_carries_other_verbs_untouched():
    """Like the seconds: a clock owns its verb's stretches and hands
    every other verb's through by copy, not by reference."""
    scan = [["2026-01-01T00:00:00Z", "2026-01-03T10:00:00Z"]]
    state = {"wall": {"scan": [list(scan[0])]}}
    WallClock("merge", state, started=_ago(600)).stamp(state)
    assert state["wall"]["scan"] == scan
    assert len(state["wall"]["merge"]) == 1


def test_the_clock_moves_neither_the_fingerprint_nor_the_statement():
    """Two honest builds of identical bytes take different times, so a
    duration inside the identity would give the same content two names.
    It is outside the statement too, for the reason `producer` is: it
    cannot be confirmed by anyone."""
    base = _manifest(parent=B)
    timed = _manifest(parent=B)
    timed["build"]["seconds"] = {"build": 126_891}
    assert timed["fingerprint"] == base["fingerprint"]
    assert statement_digest(timed) == base["statement"]
