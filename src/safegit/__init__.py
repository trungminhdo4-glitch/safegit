"""SafeGit - Git safety and repository protection for AI coding agents.

SafeGit is a deterministic, offline policy engine that inspects proposed
git and repository operations *before* they run and returns one of four
explicit verdicts: ALLOW, DENY, REQUIRE_OWNER, UNKNOWN.

The package is dependency-free (Python standard library only) and has no
network, account, telemetry, or platform requirement.
"""

from __future__ import annotations

__all__ = ["__version__", "PRODUCT_NAME", "SPEC_VERSION"]

PRODUCT_NAME = "SafeGit"
__version__ = "0.1.0"
SPEC_VERSION = "safegit.policy/1"
