#!/usr/bin/env python3
"""
test_home.py — NODSIG_HOME fills in a directory a reading command would
refuse to run without, and does nothing else.

The second half of that sentence is the part worth a test. On the
commands that write an artifact, and on every optional flag, the
presence of a directory flag is a request (`archive scan --graph` turns
on a co-emission of hundreds of gigabytes), so a variable in a shell
profile must never be able to supply one. `WHO_TAKES_A_DEFAULT` below is
therefore written out by hand, like the public surface in test_cli.py,
and compared with what the parsers actually declare: a default added to
a builder fails here, by name, before it can start anybody's week-long
run with a parent they did not choose.
"""

import argparse
import ast
import os
import subprocess
import sys

import pytest

from nodsig import home

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "src")
_PKG = os.path.join(_SRC, "nodsig")

# module → {subcommand (None: the module has one parser) → roles}.
# Only reading commands, and on those only the flags that were
# `required=True`; `check` and `report` are the two that speak about the
# artifacts as a set, and take every backend they find.
WHO_TAKES_A_DEFAULT = {
    "reveal_archive": {"verify": {"archive"},
                       "crosscheck": {"archive", "locks"},
                       "lookup": {"archive"}},
    "nonces": {"verify": {"nonces"}, "groups": {"nonces"},
               "lookup": {"nonces"}, "address": {"index", "derived"},
               "witness-verify": {"witness"}},
    "headers": {"verify": {"headers"}, "crosscheck": {"headers", "index"},
                "stats": {"headers"}, "show": {"headers"}},
    "graphemit": {"stats": {"graph"}, "show": {"graph"}},
    "outpoint_index": {"stats": {"index"}, "verify": {"index"},
                       "lookup": {"index"}},
    "derivatives": {"stats": {"derived"}, "verify": {"derived"},
                    "history": {"derived", "index"},
                    "fee": {"derived", "index"},
                    "cospends": {"derived", "index"},
                    "supply": {"derived", "index"},
                    "timeline-verify": {"timeline"}},
    "firstspend": {"stats": {"firstspend"}, "verify": {"firstspend"},
                   "between": {"firstspend", "index"}},
    "firstreveal": {"stats": {"firstreveal"}, "verify": {"firstreveal"},
                    "between": {"firstreveal"}},
    "check_addresses": {None: {"archive", "index", "derived", "witness"}},
    "report": {None: "every role `report` describes"},
}


def _declared(module):
    """{subcommand: roles} as the module's parser declares them, read
    from the source in line order: parser variables are reused (`pv` is
    two different subcommands in one file), so what a variable names is
    whatever it was last assigned."""
    with open(os.path.join(_PKG, f"{module}.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    events = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and getattr(node.value.func, "attr", "") == "add_parser"
                and isinstance(node.targets[0], ast.Name)):
            events.append((node.lineno, "parser", node.targets[0].id,
                           node.value.args[0].value))
        if (isinstance(node, ast.Call)
                and getattr(node.func, "attr", "") == "add_argument"
                and isinstance(node.func.value, ast.Name)):
            for kw in node.keywords:
                call = kw.value
                if (kw.arg is None and isinstance(call, ast.Call)
                        and getattr(call.func, "attr", "")
                        in ("required", "optional")
                        and getattr(call.func.value, "id", "") == "home"):
                    flag = node.args[0]
                    role = call.args[0]
                    events.append((node.lineno, "flag", node.func.value.id,
                                   (getattr(flag, "value", None),
                                    getattr(role, "value", None),
                                    call.func.attr)))
    names, found = {}, {}
    for _line, kind, var, what in sorted(events, key=lambda e: e[0]):
        if kind == "parser":
            names[var] = what
        else:
            found.setdefault(names.get(var), []).append(what)
    return found


def test_only_the_reading_commands_take_a_default():
    modules = sorted(
        name[:-3] for name in os.listdir(_PKG)
        if name.endswith(".py") and name not in ("home.py",))
    for module in modules:
        declared = _declared(module)
        expected = WHO_TAKES_A_DEFAULT.get(module, {})
        assert set(declared) == set(expected), (
            f"{module}: the commands taking a NODSIG_HOME default are "
            f"{sorted(map(str, declared))}, the list written by hand says "
            f"{sorted(map(str, expected))}. A command that writes an "
            "artifact must not be among them")
        for sub, flags in declared.items():
            if module == "report":
                continue                    # one f-string flag per role
            roles = {role for _flag, role, _how in flags}
            assert roles == expected[sub], (module, sub, roles)
            for flag, role, how in flags:
                assert flag == f"--{role}", (
                    f"{module} {sub}: {flag} takes the default of role "
                    f"{role!r}; a flag and its role share a name")
                want = ("optional" if module == "check_addresses"
                        else "required")
                assert how == want, (module, sub, flag, how)


def test_unset_is_exactly_the_old_behaviour(monkeypatch):
    monkeypatch.delenv(home.ENV, raising=False)
    assert home.directory("archive") is None
    assert home.required("archive")["required"] is True
    assert "default" not in home.required("archive")
    assert home.optional("archive")["default"] is None


def test_a_role_kept_under_its_name_is_found(monkeypatch, tmp_path):
    (tmp_path / "archive").mkdir()
    monkeypatch.setenv(home.ENV, str(tmp_path))
    assert home.directory("archive") == str(tmp_path / "archive")
    got = home.required("archive")
    assert got["default"] == str(tmp_path / "archive")
    assert "required" not in got
    # an artifact that is not there is not an error: the flag is asked
    # for, as before
    assert home.required("index")["required"] is True
    assert home.optional("index")["default"] is None


def test_an_explicit_flag_wins(monkeypatch, tmp_path):
    (tmp_path / "archive").mkdir()
    monkeypatch.setenv(home.ENV, str(tmp_path))
    p = argparse.ArgumentParser()
    p.add_argument("--archive", **home.required("archive"))
    assert p.parse_args([]).archive == str(tmp_path / "archive")
    assert p.parse_args(["--archive", "elsewhere"]).archive == "elsewhere"


def test_the_help_names_the_variable_and_never_a_path(monkeypatch, tmp_path):
    (tmp_path / "archive").mkdir()
    monkeypatch.setenv(home.ENV, str(tmp_path))
    text = home.required("archive", help="archive directory")["help"]
    assert home.ENV in text and "archive directory" in text
    assert str(tmp_path) not in text


def test_a_home_that_is_not_a_directory_stops_the_command(monkeypatch,
                                                         tmp_path):
    monkeypatch.setenv(home.ENV, str(tmp_path / "typo"))
    with pytest.raises(SystemExit) as stop:
        home.directory("archive")
    assert home.ENV in str(stop.value)


def test_a_role_is_one_of_the_names_the_documents_use():
    with pytest.raises(ValueError):
        home.directory("snapshot")


def _run(args, env_home):
    env = {**os.environ,
           "PYTHONPATH": os.pathsep.join(
               [_SRC, os.environ.get("PYTHONPATH", "")])}
    env.pop(home.ENV, None)
    if env_home is not None:
        env[home.ENV] = env_home
    return subprocess.run([sys.executable, "-m", "nodsig", *args],
                          env=env, capture_output=True, text=True)


def test_through_the_command_line(tmp_path):
    """The default reaches the tool: with the role's directory there,
    `headers stats` gets past its parser and fails on what the directory
    holds (exit 1, the tool's own ERROR); without it, the parser asks for
    the flag (exit 2), as it always has."""
    asked = _run(["headers", "stats"], None)
    assert asked.returncode == 2 and "--headers" in asked.stderr

    (tmp_path / "headers").mkdir()
    found = _run(["headers", "stats"], str(tmp_path))
    assert found.returncode == 1, found.stderr
    assert "ERROR" in found.stderr

    other = _run(["index", "stats"], str(tmp_path))
    assert other.returncode == 2 and "--index" in other.stderr


def test_a_builder_still_asks_for_everything(tmp_path):
    """Every role present, and the commands that write still refuse to
    start without being told what to read and where to write."""
    for role in home.ROLES:
        (tmp_path / role).mkdir()
    for args, flag in ((["index", "build"], "--graph"),
                       (["derived", "build"], "--index"),
                       (["archive", "merge"], "--archive"),
                       (["headers", "fingerprint"], "--headers"),
                       (["firstreveal", "build"], "--archive")):
        got = _run(args, str(tmp_path))
        assert got.returncode == 2 and flag in got.stderr, (args, got.stderr)
