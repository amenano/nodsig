#!/usr/bin/env python3
"""
test_cli.py — the guard on the PUBLISHED command surface.

Why this file is different from the other tests here: it does not check
what the tools compute, it checks what they are CALLED. Those names are
quoted in text that lives outside this repository (a manual, a post,
someone's runbook) and that does not get quietly rewritten, so the
promise attached to them is that they do not change within a major
version. A rename that slips through would break printed paper, which
no fingerprint can detect.

So the assertions are deliberately dumb and complete: every group in the
map resolves, every subcommand of the two-level group resolves, and the
whole thing is reachable both as an installed console script
(`nodsig …`, exercised here through its `main`) and from a bare clone
(`python3 -m nodsig …`).
"""

import contextlib
import io
import os
import subprocess
import sys
import unittest

from nodsig import cli

# Same reasoning as the other subprocess tests: a fresh interpreter does
# not inherit pytest's `pythonpath = ["src"]`, so it is re-exported here.
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "src")
_ENV = {**os.environ,
        "PYTHONPATH": os.pathsep.join([_SRC, os.environ.get("PYTHONPATH", "")])}

# The surface as the manual will quote it. Written out by hand on
# purpose: importing cli.GROUPS and comparing it to itself would prove
# nothing.
PUBLIC_SURFACE = {
    "census": None,
    "reuse": ("prepare", "scan", "stats"),
    "archive": ("scan", "merge", "verify", "crosscheck", "derive", "curve",
                "lookup", "v1-digests"),
    "nonces": ("merge", "verify", "rewind", "groups", "lookup",
               "address", "bench",
               "resolve", "witness-verify"),
    "headers": ("fingerprint", "verify", "crosscheck", "stats", "show"),
    "graph": ("stats", "fingerprint", "show", "digest"),
    "index": ("build", "rewind", "stats", "verify", "lookup"),
    "derived": ("build", "rewind", "stats", "verify", "history", "fee",
                "cospends", "supply"),
    "firstspend": ("build", "stats", "verify", "between", "rewind"),
    "firstreveal": ("build", "stats", "verify", "between"),
    "blockstats": ("build", "summary"),
    "price": ("import", "series-verify", "build", "stats", "verify", "at",
              "daily"),
    "curve": ("deltas", "dates"),
    "check": None,
    "report": None,
}


class TestCommandSurface(unittest.TestCase):

    def test_every_public_group_resolves(self):
        """Each published name maps to a module that really imports."""
        for group in PUBLIC_SURFACE:
            with self.subTest(group=group):
                argv = [group]
                if group == "curve":            # the one two-level group
                    argv.append("deltas")
                module, rest, prog = cli._resolve(argv)
                self.assertEqual(rest, [])
                self.assertTrue(prog.startswith(f"nodsig {group}"))
                __import__(f"nodsig.{module}")

    def test_curve_groups_two_modules_under_one_noun(self):
        self.assertEqual(cli._resolve(["curve", "deltas"])[0], "curve_deltas")
        self.assertEqual(cli._resolve(["curve", "dates"])[0], "block_dates")

    def test_arguments_are_passed_through_untouched(self):
        """The dispatcher must not eat or reorder a tool's own flags."""
        module, rest, _ = cli._resolve(
            ["index", "build", "--graph", "g", "--end", "42"])
        self.assertEqual(module, "outpoint_index")
        self.assertEqual(rest, ["build", "--graph", "g", "--end", "42"])

    def test_usage_line_names_the_published_command(self):
        """The usage line a user is shown must be the one a manual can
        quote: `nodsig derived …`, never the file that implements it."""
        r = subprocess.run(
            [sys.executable, "-m", "nodsig", "derived", "-h"],
            capture_output=True, text=True, env=_ENV)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("usage: nodsig derived", r.stdout)
        self.assertNotIn("__main__.py", r.stdout)

    def test_unknown_command_lists_the_map(self):
        with self.assertRaises(SystemExit) as cm:
            cli._resolve(["nosuchthing"])
        self.assertIn("unknown command", str(cm.exception))
        self.assertIn("derived", str(cm.exception))

    def test_unknown_subcommand_of_curve(self):
        with self.assertRaises(SystemExit) as cm:
            cli._resolve(["curve", "nosuchthing"])
        self.assertIn("deltas", str(cm.exception))

    def test_bare_invocation_prints_the_map(self):
        buf = io.StringIO()
        with self.assertRaises(SystemExit) as cm, \
                contextlib.redirect_stdout(buf):
            cli._resolve([])
        self.assertEqual(cm.exception.code, 0)
        for group in PUBLIC_SURFACE:
            self.assertIn(group, buf.getvalue())

    def test_version(self):
        buf = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(buf):
            cli._resolve(["--version"])
        self.assertTrue(buf.getvalue().startswith("nodsig "))


class TestSubcommandsAreReal(unittest.TestCase):
    """The names above are not just keys in a table: each one has to be
    a subcommand the tool's own parser accepts. `-h` is the cheapest way
    to ask a parser 'do you know this verb?' without doing any work."""

    def test_each_subcommand_has_a_parser(self):
        for group, subs in PUBLIC_SURFACE.items():
            if subs is None:
                continue
            for sub in subs:
                if group == "curve":            # two modules, no verb
                    continue
                with self.subTest(group=group, sub=sub):
                    r = subprocess.run(
                        [sys.executable, "-m", "nodsig", group, sub, "-h"],
                        capture_output=True, text=True, env=_ENV)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertIn("usage", r.stdout.lower())


class TestTheRunnablePagesNameRealCommands(unittest.TestCase):
    """The two pages a reader follows with a terminal open: the README,
    which must work on its own without following a link, and
    `docs/build-and-query.md`, which is the same sequence stripped of the
    reasoning. They overlap by design, which is exactly why a rename
    has two places to be forgotten in: every command either page prints
    must be one the tool accepts.

    The surface above is checked against the real parsers by the tests
    before this one, so comparing against it is enough and no page
    needs a subprocess of its own.

    The build page carries a closing list that claims to name the
    WHOLE surface, so for that one the check runs both ways: a verb
    added without a line there would make the claim false, and a claim
    of completeness nobody enforces is the kind of sentence this
    project treats as a defect. The README makes no such claim and is
    checked one way only."""

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    BUILD_PAGE = os.path.join(ROOT, "docs", "build-and-query.md")
    PAGES = (os.path.join(ROOT, "README.md"), BUILD_PAGE)

    @staticmethod
    def _commands(path):
        """Every `nodsig <group> [sub]` inside a fenced block."""
        import re
        found = set()
        fenced = False
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("```"):
                    fenced = not fenced
                    continue
                if not fenced:
                    continue
                m = re.match(r"\s*\$?\s*nodsig\s+([a-z]+)"
                             r"(?:\s+([a-z0-9-]+))?", line)
                if m:
                    found.add((m.group(1), m.group(2)))
        return found

    @classmethod
    def _listed(cls):
        """Every command named in the closing list's table rows, which
        write them as ``group sub`` rather than as invocations."""
        import re
        found = set()
        with open(cls.BUILD_PAGE, encoding="utf-8") as f:
            for line in f:
                if not line.startswith("| `"):
                    continue
                m = re.match(r"\|\s*`([a-z]+)(?:\s+([a-z0-9-]+))?", line)
                if m:
                    found.add((m.group(1), m.group(2)))
        return found

    def test_the_pages_have_commands_at_all(self):
        # A parser that quietly matched nothing would make every
        # assertion below vacuous.
        for page in self.PAGES:
            with self.subTest(page=os.path.basename(page)):
                self.assertGreater(len(self._commands(page)), 10)

    def test_every_command_on_the_pages_is_real(self):
        for page in self.PAGES:
            name = os.path.basename(page)
            for group, sub in sorted(self._commands(page)):
                with self.subTest(page=name, group=group, sub=sub):
                    self.assertIn(group, PUBLIC_SURFACE,
                                  f"{name} names `nodsig {group}`, "
                                  "which is not a command")
                    subs = PUBLIC_SURFACE[group]
                    if subs is None:
                        continue    # single-verb group: the rest is flags
                    self.assertIsNotNone(
                        sub, f"{name}: `nodsig {group}` needs a subcommand")
                    self.assertIn(sub, subs,
                                  f"{name} names `nodsig {group} {sub}`, "
                                  "which is not a subcommand")

    def test_the_closing_list_names_every_command(self):
        """The other direction, for the page that promises it."""
        listed = self._listed()
        for group, subs in PUBLIC_SURFACE.items():
            if subs is None:
                with self.subTest(group=group):
                    self.assertIn((group, None), listed,
                                  f"`nodsig {group}` has no line in the "
                                  "closing list of build-and-query.md")
                continue
            for sub in subs:
                with self.subTest(group=group, sub=sub):
                    self.assertIn((group, sub), listed,
                                  f"`nodsig {group} {sub}` has no line in "
                                  "the closing list of build-and-query.md")


class TestModulePathStillWorks(unittest.TestCase):
    """The documented no-install path: reading the code while running
    it must keep working, or the repo stops being auditable the easy
    way."""

    def test_python_m_package(self):
        r = subprocess.run([sys.executable, "-m", "nodsig", "--version"],
                           capture_output=True, text=True, env=_ENV)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("nodsig "))

    def test_python_m_single_module(self):
        r = subprocess.run(
            [sys.executable, "-m", "nodsig.outpoint_index", "-h"],
            capture_output=True, text=True, env=_ENV)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("usage", r.stdout.lower())


class TestCredentialsNeverOnTheCommandLine(unittest.TestCase):
    """--auth is gone on purpose: a secret in the argv is readable by
    anyone on the machine for the whole length of a multi-day run. The
    test is here, next to the surface it protects, because this is a
    property of what we PUBLISH, not of what the scanner computes."""

    def test_no_auth_flag_anywhere_in_the_surface(self):
        for group, subs in PUBLIC_SURFACE.items():
            argv = [group] if subs is None else [group, subs[0]]
            if group == "curve":
                argv = ["curve", "dates"]
            with self.subTest(group=group):
                r = subprocess.run(
                    [sys.executable, "-m", "nodsig", *argv, "-h"],
                    capture_output=True, text=True, env=_ENV)
                self.assertNotIn("--auth", r.stdout)

    def test_env_var_is_accepted_as_the_fallback(self):
        from nodsig.reuse_scan import RPC_AUTH_ENV, resolve_auth
        os.environ[RPC_AUTH_ENV] = "user:secret"
        try:
            self.assertEqual(resolve_auth(None), "user:secret")
        finally:
            del os.environ[RPC_AUTH_ENV]

    def test_no_credentials_at_all_is_a_clear_refusal(self):
        from nodsig.reuse_scan import RPC_AUTH_ENV, resolve_auth
        saved = os.environ.pop(RPC_AUTH_ENV, None)
        try:
            with self.assertRaises(SystemExit) as cm:
                resolve_auth(None)
            self.assertIn("--cookie-file", str(cm.exception))
            self.assertIn(RPC_AUTH_ENV, str(cm.exception))
        finally:
            if saved is not None:
                os.environ[RPC_AUTH_ENV] = saved


if __name__ == "__main__":
    unittest.main()
