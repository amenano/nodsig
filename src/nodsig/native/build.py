#!/usr/bin/env python3
"""Build the native kernel, `nodsig._native`, from the C beside this file.

    python3 -m nodsig.native.build          # into the package directory
    python3 -m nodsig.native.build --check  # is a compiler there? (exit 1 if not)

Nothing but a C99 compiler and Python's own headers: the kernel has no
dependency, and neither has this. It is what the wheel build hook runs and
what a checkout runs by hand; it is never run at import time, and a
package without the result works unchanged on the pure-Python road (see
`nodsig.kernel`). The extension lands beside the package as
`_native<EXT_SUFFIX>`, where the interpreter that built it will find it
and no other will, which is what the suffix is for.
"""

import os
import shutil
import subprocess
import sys
import sysconfig

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.dirname(HERE)
SOURCES = ["nodsig_hash.c", "nodsig_extract.c", "nodsig_scan.c",
           "nodsig_kway.c", "nodsig_native.c"]


def compiler():
    """The C compiler to use, or None: the one Python was built with when
    it is on the path, else cc/gcc/clang."""
    for name in (sysconfig.get_config_var("CC") or "cc").split()[:1] + \
            ["cc", "gcc", "clang"]:
        found = shutil.which(name)
        if found:
            return found
    return None


def target(directory=PACKAGE):
    return os.path.join(directory, "_native" + sysconfig.get_config_var("EXT_SUFFIX"))


def build(directory=PACKAGE, quiet=False):
    """Compile into `directory`; returns the path of the extension.
    Raises RuntimeError with the compiler's words when it cannot."""
    cc = compiler()
    if cc is None:
        raise RuntimeError("no C compiler found (cc, gcc or clang)")
    include = sysconfig.get_paths()["include"]
    if not os.path.exists(os.path.join(include, "Python.h")):
        raise RuntimeError(f"Python.h not found under {include}: the "
                           "interpreter's development headers are missing")
    out = target(directory)
    cmd = [cc, "-std=c99", "-O2", "-fPIC", "-shared", "-Wall",
           "-I" + include, "-o", out] + [os.path.join(HERE, s) for s in SOURCES]
    if sys.platform == "darwin":
        cmd[cmd.index("-shared")] = "-bundle"
        cmd.insert(cmd.index("-bundle") + 1, "-undefined")
        cmd.insert(cmd.index("-undefined") + 1, "dynamic_lookup")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "the compiler failed")
    if not quiet:
        print(f"built {out}")
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--check" in argv:
        cc = compiler()
        print(cc or "no C compiler")
        return 0 if cc else 1
    try:
        build()
    except RuntimeError as e:
        print(f"native kernel not built: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
