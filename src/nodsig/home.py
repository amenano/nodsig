#!/usr/bin/env python3
"""
home.py — NODSIG_HOME: one directory that holds your artifacts, so a
question does not have to name them again.

Why this exists: every reading command takes its artifacts as paths, and
a person who has built them types the same two to six directories on
every question. With `NODSIG_HOME` set, an artifact kept under its role's
name there (`<home>/archive`, `<home>/index`, …) is found without being
named:

    export NODSIG_HOME=/srv/artifacts
    nodsig check --stdout <address>
    nodsig index lookup TXID:VOUT

THE RULE, AND IT IS THE WHOLE DESIGN
====================================
The variable fills in a directory a READING command would otherwise
refuse to run without. It never does anything else:

  - a command that WRITES an artifact takes no default, for its output
    or for its inputs: `scan`, `merge`, `build`, `rewind`, `resolve`,
    `fingerprint`, `derive`, `curve`, `timeline`. A run of hours or days
    names what it reads and what it writes, every time, on the command
    line where a log keeps it;
  - an OPTIONAL flag takes no default either, because on those commands
    the presence of the flag is the request: `archive scan --graph`
    turns on a co-emission of hundreds of gigabytes, `index verify
    --graph` asks for the parent to be confirmed, `nonces address
    --nonces` for a second question to be answered. A variable set in a
    shell profile must not be able to ask for any of them, and a report
    must not say it confirmed a parent nobody handed it;
  - the two commands that speak about the artifacts as a SET are the
    exception to the second point, and only they: `check` plugs in
    every backend it finds and `report` describes every artifact it
    finds, which is what each of them is for, and each says in its
    output what it found;
  - it never reaches the node: `--rpc` has no default here, because a
    balance query tells the node which addresses were asked about.

An explicit flag always wins, and with the variable unset every command
behaves exactly as it did before this module existed.

Each command opts in where it declares the flag, visibly:

    pl.add_argument("--archive", **home.required("archive"))

so which commands take a default is readable in their own parsers, from
`nodsig …` and from `python3 -m nodsig.<module>` alike, and there is no
table elsewhere that could drift from them.

WHAT IT REFUSES
===============
A `NODSIG_HOME` that is set and is not a directory stops the command,
naming the variable. Falling back to "required" would answer a typo in a
shell profile with a complaint about `--archive`, which is the wrong
thing to be told.
"""

import os
import sys

ENV = "NODSIG_HOME"

# The names `report` already gives its flags, which are the names the
# documents use for the artifacts; `locks` and `timeline` are the two
# directories a reading command takes that `report` does not describe.
ROLES = ("archive", "graph", "headers", "nonces", "witness", "index",
         "derived", "firstspend", "firstreveal", "locks", "timeline")


def directory(role):
    """`<home>/<role>` when NODSIG_HOME is set and that directory
    exists, else None. An artifact that is not there is not an error:
    the command then asks for the flag, as it always has."""
    if role not in ROLES:
        raise ValueError(f"not an artifact role: {role!r}")
    base = os.environ.get(ENV)
    if not base:
        return None
    if not os.path.isdir(base):
        sys.exit(f"ERROR: {ENV} is set to {base!r}, which is not a "
                 "directory")
    path = os.path.join(base, role)
    return path if os.path.isdir(path) else None


def _help(role, text):
    note = f"default: ${ENV}/{role}, when that directory exists"
    return f"{text} ({note})" if text else note


def required(role, help=None, **kwargs):
    """Keyword arguments for a directory flag a reading command cannot
    run without: the home's copy when there is one, `required=True` as
    before when there is not."""
    found = directory(role)
    if found is None:
        return {"required": True, "help": _help(role, help), **kwargs}
    return {"default": found, "help": _help(role, help), **kwargs}


def optional(role, help=None, **kwargs):
    """The same for `check` and `report`, whose flags plug a backend in
    or name an artifact to describe: absent stays absent."""
    return {"default": directory(role), "help": _help(role, help), **kwargs}
