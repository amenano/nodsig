#!/usr/bin/env python3
"""
capability.py — the answer envelope every capability backend speaks:
`Result{status, value, source}`, the F2 rule of docs/types.md.

WHY AN ENVELOPE AT ALL
======================
A capability answers a question about the chain, and the answer alone is
not enough to be worth anything to a stranger. "This key was never
revealed" means nothing until it also says AS OF WHICH HEIGHT and FROM
WHICH ARTIFACT — and whether that artifact was sealed or still had
unfused runs. Three different things travel together or the answer is
not checkable:

    status      did the source answer, decline, or fail to decide;
    value       the answer, which may legitimately be "nothing";
    source      who answered, up to what height, under what fingerprint.

NEGATIVES ARE NOT ERRORS
========================
The distinction this type exists to keep: `OK` with an empty value is a
DEFINITE NEGATIVE — the source looked and there is nothing, up to its
watermark. That is a real answer and the strongest thing an offline
artifact can say. It is not `UNDETERMINED`, which means the source could
not decide, and it is not an error, which means the question or the
source was broken and is raised, never returned. Collapsing the three
would let a missing backend read as "you are safe".

NO PATHS, EVER
==============
`id` is the format tag, never a directory. A result that carried
`/srv/artifacts/derived` would leak the topology of the machine it ran on
and would stop being portable: the same question asked of the same
sealed artifact must produce the same source on anyone's disk. The
fingerprint is the identity that travels; the path is a local accident.

ONCE PER OPERATION, NEVER PER RECORD
====================================
The envelope is applied at the boundary of a capability, not inside the
loops. A stream of millions of history rows carries its source ONCE,
up front; the rows themselves stay bare bytes. In-process readers may go
on returning raw values to each other — `Index` and `Derived` do — and
the wrapping happens where the answer leaves the capability, which is
also exactly what a future network transport would serialize.
"""


class Status:
    """Uniform across every backend (docs/types.md)."""

    OK = "OK"                       # the source answered (value may be
                                    # a definite negative)
    UNSUPPORTED = "UNSUPPORTED"     # this source has no such capability
    UNDETERMINED = "UNDETERMINED"   # partial data, cannot decide


class Source:
    """Who answered, as of when, under which fingerprint.

    `id` is a format tag (`reveal-archive-v2`), a role name for
    a live source (`bitcoin-core-rpc`), never a path.
    `watermark` is the highest confirmed height the source covers.
    `fingerprint` is the canonical fingerprint of a SEALED source, and
    is None when the source still holds unfused runs — a queryable but
    unsealed state that must be reported, never dressed up as sealed."""

    __slots__ = ("id", "watermark", "fingerprint", "live")

    def __init__(self, id, watermark=None, fingerprint=None,
                 live=False):
        if id and ("/" in id or "\\" in id):
            raise ValueError(
                f"id must be a format tag, not a path: {id}"
                " — results carry identity, not local topology")
        self.id = id
        self.watermark = watermark
        self.fingerprint = fingerprint
        self.live = live

    @classmethod
    def artifact(cls, id, watermark, fingerprint=None):
        """A sealed-by-design source. Pass the fingerprint only when it
        really is sealed: withholding it is how an unfused state gets
        reported instead of implied."""
        return cls(id, watermark, fingerprint)

    @classmethod
    def node(cls, id, height=None):
        """A live source. It has a tip, not a seal, and saying "not
        sealed" about it would be noise: nobody expects a running node
        to have a fingerprint."""
        return cls(id, height, None, live=True)

    def describe(self, capability):
        """The one header line a report prints per capability."""
        parts = []
        if self.live:
            if self.watermark is not None:
                parts.append(f"node height {self.watermark:,} at scan time")
        else:
            if self.watermark is not None:
                parts.append(f"confirmed blocks 1..{self.watermark:,}")
            if self.fingerprint:
                parts.append(f"sealed {self.fingerprint[:8]}…"
                             f"{self.fingerprint[-4:]}")
            elif self.watermark is not None:
                parts.append("NOT sealed: unfused runs are included in "
                             "the answers")
        tail = f" ({', '.join(parts)})" if parts else ""
        return f"{capability}: {self.id}{tail}"

    def __repr__(self):
        return (f"Source({self.id!r}, {self.watermark!r}, "
                f"{self.fingerprint!r}, live={self.live})")


class Result:
    """`{status, value, source}` — built through the three
    constructors below so a status is never spelled by hand."""

    __slots__ = ("status", "value", "source")

    def __init__(self, status, value, source):
        self.status = status
        self.value = value
        self.source = source

    @classmethod
    def ok(cls, value, source):
        """An answer. `value=None` is a DEFINITE NEGATIVE, not a
        failure: the source looked, up to its watermark, and there is
        nothing."""
        return cls(Status.OK, value, source)

    @classmethod
    def unsupported(cls, source):
        """This source does not implement the capability at all."""
        return cls(Status.UNSUPPORTED, None, source)

    @classmethod
    def undetermined(cls, source):
        """Cannot decide from partial data. A sealed artifact is
        complete up to its watermark and never returns this."""
        return cls(Status.UNDETERMINED, None, source)

    @property
    def answered(self):
        """True when the source answered — including with a negative."""
        return self.status == Status.OK

    @property
    def found(self):
        """True when the source answered with something."""
        return self.status == Status.OK and self.value is not None

    def __repr__(self):
        return (f"Result({self.status}, {self.value!r}, "
                f"{self.source!r})")
