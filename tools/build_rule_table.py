"""Generate the rule table for docs/CONFIGURATION.md from the policy code.

Keeping the table generated guarantees that the documentation cannot drift
away from the actual verdicts.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from safegit import gitop, policy as policy_module  # noqa: E402

PROFILES = ("default", "strict", "relaxed", "ci")


def main() -> int:
    lines = [
        "| Rule id | default | strict | relaxed | ci |",
        "| --- | --- | --- | --- | --- |",
    ]
    for rule in gitop.RULE_IDS + policy_module.FS_RULE_IDS:
        verdicts = [
            policy_module._profile_rules(profile).get(rule, "UNKNOWN")
            for profile in PROFILES
        ]
        lines.append("| `%s` | %s | %s | %s | %s |" % (rule, *verdicts))
    table = "\n".join(lines) + "\n"
    docs = pathlib.Path(__file__).resolve().parents[1] / "docs"
    generated = docs / "RULES_GENERATED.md"
    generated.write_text(table, encoding="utf-8")
    configuration = docs / "CONFIGURATION.md"
    if configuration.is_file():
        text = configuration.read_text(encoding="utf-8")
        if "@RULES@" in text:
            configuration.write_text(text.replace("@RULES@", table.rstrip()), encoding="utf-8")
            print("inlined the rule table into %s" % configuration)
    print("wrote %s (%d rules)" % (generated, len(lines) - 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
