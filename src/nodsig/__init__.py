"""nodsig — verifiable, own-node Bitcoin on-chain analysis.

Reference implementation (readable Python) of the kernels and capability
backends. See ``docs/ARCHITECTURE.md`` for the design.
"""

# The single source of the version number: pyproject reads it from here
# (hatchling `dynamic`), so the package and the distribution can never
# disagree. A major means what the README's stability line says: the
# formats are the contract, the CLI is convenience, and within a major
# version the published commands do not change. Spelled the way PEP 440
# normalizes it; the git tag for the same version reads `v1.3.0`.
#
# THIS NUMBER AND THE FORMATS' NUMBERS ARE TWO DIFFERENT SCALES, and the
# artifacts prove it rather than merely claiming it: every one of them
# carries `nodsig-identity-v3`, the recipe the fingerprint is taken over,
# while this package has never been at 3. A format tag answers *what does
# this artifact capture*, which is why a reader can tell an absence from a
# blind spot; a release number answers *what does the command line promise
# until the next major*. They move for different reasons and there is no
# arithmetic between them. So `reveal-archive-v2` inside a 1.1.0 tool is
# not a discrepancy: the reveal archive really is at its second format,
# and the tool is two additive releases past its first.
#
# Which revision built an artifact is not a matter of release discipline
# either: every manifest records it under `build.producer`, together with
# whether the tree carried uncommitted edits. A version number is how a
# release is referred to, not how an artifact is attributed.
__version__ = "1.3.0"
