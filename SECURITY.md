# Reporting a vulnerability

**Report privately, not in an issue.** Use GitHub's private vulnerability
reporting on this repository: the **Security** tab → **Report a vulnerability**.
That channel is enabled precisely so that a first message about a flaw does not
have to be public. There is no email address here on purpose; the form is the
whole contact surface.

## What counts as a vulnerability here

This is a tool for reading a public blockchain: it holds no accounts, serves no
requests, and stores no secrets. So the classes worth reporting are narrower
than usual, and one of them is easy to overlook.

- **A wrong answer that looks right.** This is the serious one. A build, an
  append or a rewind that produces a *plausible* artifact rather than a correct
  one, an accounting identity that can be made to pass while the numbers are
  wrong, a lookup that silently returns a short answer instead of failing.
  People make decisions about their own coins from these answers, so a
  convincing wrong number is a security bug, not a correctness nitpick.
- **Anything that leaks what the user is asking about.** The addresses fed to
  `check`, the artifact paths, the node's RPC credentials. Credentials are kept
  off the command line by design, because a process's argv is readable by every
  local user for as long as the run lasts; a path back into argv, into a log
  line, into a report header, or into an error message is a real finding.
- **Anything that lets untrusted input drive the tools.** Block data arrives
  from a node the user chose, but it is still parsed: a crafted block that
  writes outside the intended file, exhausts memory in an unbounded way, or
  makes a parser accept bytes it should refuse, is in scope.

## What is not

Performance, memory use, missing features, and the limits already written down
in the README under **Status** and **What this is, and what it is not**. This is
a proof of concept: what has been verified and what has not is stated there
rather than implied, and a report that it has not been verified at some scale is
already answered.

## What to expect

One author, working on this in whatever time exists. There is no service level,
no bounty, and no promise of a fix within any period. What there is: a reply
that says plainly whether the report is understood and accepted, and, if a fix
lands, a commit message that explains what was wrong rather than hiding it — the
same standard the rest of this history keeps.

If a flaw affects artifacts already published by fingerprint, the fix will say
so and name the fingerprints, because a number that was wrong stays wrong until
it is publicly retracted.
