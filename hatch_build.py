"""The wheel's build hook: compile the native kernel if a C compiler is
there, ship a pure-Python wheel otherwise.

`nodsig` needs Python and nothing else; the kernel (src/nodsig/native) is
an accelerator that is proven identical to the Python reference and is
never required. So this hook tries `nodsig.native.build`, and on any
failure — no compiler, no headers, a platform the C does not know — it
says so on stderr and leaves the wheel pure: the package installs and
works unchanged, on the Python road. When the build succeeds the wheel is
tagged for this interpreter and platform, as any wheel carrying an
extension must be.

The same builder serves a checkout: `python3 -m nodsig.native.build`.
"""

import os
import sys

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class NativeKernelHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version, build_data):
        if self.target_name != "wheel":
            return
        src = os.path.join(self.root, "src")
        sys.path.insert(0, src)
        try:
            from nodsig.native import build as nb
            out = nb.build(quiet=True)
        except Exception as e:           # noqa: BLE001 - any failure means pure
            print(f"nodsig: native kernel not built ({e}); the wheel is "
                  "pure Python and the scan takes the reference road",
                  file=sys.stderr)
            return
        finally:
            sys.path.remove(src)
        rel = os.path.relpath(out, src)
        build_data["force_include"][out] = rel
        build_data["pure_python"] = False
        build_data["infer_tag"] = True
        print(f"nodsig: native kernel built ({rel})", file=sys.stderr)
