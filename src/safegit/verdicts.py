"""The SafeGit verdict vocabulary.

Four explicit verdicts.  There is deliberately no "warn-only" pseudo
verdict: a warning is a verdict of ALLOW plus a finding, so that the
machine-readable result never hides a blocking decision behind wording.
"""

from __future__ import annotations

ALLOW = "ALLOW"
DENY = "DENY"
REQUIRE_OWNER = "REQUIRE_OWNER"
UNKNOWN = "UNKNOWN"

VERDICTS: tuple[str, ...] = (ALLOW, DENY, REQUIRE_OWNER, UNKNOWN)

SEVERITY: dict[str, int] = {
    ALLOW: 0,
    UNKNOWN: 1,
    REQUIRE_OWNER: 2,
    DENY: 3,
}

EXIT_OK = 0
EXIT_DENIED = 2
EXIT_OWNER_REQUIRED = 3
EXIT_UNKNOWN = 4
EXIT_USAGE = 64
EXIT_INTERNAL_ERROR = 70

VERDICT_EXIT_CODES: dict[str, int] = {
    ALLOW: EXIT_OK,
    DENY: EXIT_DENIED,
    REQUIRE_OWNER: EXIT_OWNER_REQUIRED,
    UNKNOWN: EXIT_UNKNOWN,
}


def most_restrictive(*verdicts: str) -> str:
    """Return the most restrictive verdict of the given ones."""
    result = ALLOW
    for verdict in verdicts:
        if verdict not in SEVERITY:
            return DENY
        if SEVERITY[verdict] > SEVERITY[result]:
            result = verdict
    return result


def is_blocking(verdict: str) -> bool:
    return verdict in (DENY, REQUIRE_OWNER, UNKNOWN)
