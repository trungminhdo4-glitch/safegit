"""Privacy gate for the release tree.

Fails (non-zero exit) when the tree contains anything that must not leave the
owner's private environment: credentials, real secret paths, personal Windows
paths, internal project identifiers or private infrastructure names.

Matched values are never printed in full - only a redacted fingerprint - so
running the check cannot itself leak what it found.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys

SKIP_DIRS = {
    ".git",
    "__pycache__",
    "build",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "_owner",
    "node_modules",
}
SKIP_SUFFIXES = {".pyc", ".zip", ".whl", ".png", ".jpg", ".ico", ".pdf"}
SELF = pathlib.Path(__file__).resolve()

MAX_LINE_CHARS = 400

PATTERNS: tuple[tuple[str, str], ...] = (
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{16,}"),
    ("openai_key", r"sk-[A-Za-z0-9]{20,}"),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("slack_token", r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    ("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    (
        "assigned_secret",
        r"(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']",
    ),
    ("personal_windows_path", r"(?i)[A-Z]:\\\\?Users\\\\?[A-Za-z0-9._-]+"),
    ("private_platform_path", r"(?i)D:\\\\?agent-platform"),
    ("private_scripts_path", r"(?i)D:\\\\?scripts"),
    (
        "private_internal_id",
        r"(?i)\b(owner_goal|workspace_registry|migration_ledger|hermes_canonical|coreguard|aethelgard|spaeti|agent_platform|delegate_run|pre_exec_firewall)\b",
    ),
    (
        "private_client_name",
        r"(?i)\b(asia-choice|la-familia|moon-restaurants|smaragd-coffee|viet-food-website|yama-restaurant)\b",
    ),
    ("internal_log_reference", r"\bAGENT_LOG\b"),
    (
        "real_email",
        r"[A-Za-z0-9._%+-]+@(?!example\.(invalid|com)|test\.invalid|localhost)[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    ),
)

ALLOWED_SUBSTRINGS: tuple[str, ...] = (
    "example.invalid",
    "test@example",
    "@example.com",
    "noreply",
    "C:\\\\Users\\\\farme",
    "D:\\\\temp\\\\opencode",
)

# The guards above are described in the security report and the threat model;
# naming them in prose is not a leak, so those files are exempt for the
# internal-identifier rule only.
PROSE_EXEMPT = {
    "docs/SECURITY_REPORT.md",
    "docs/THREAT_MODEL.md",
    "docs/COMPARISON.md",
    "docs/PROVENANCE.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
}


def _redact(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:10]
    return "<redacted:%s len=%d>" % (digest, len(value))


def scan(path: pathlib.Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    root = path.resolve()
    for candidate in sorted(root.rglob("*")):
        if not candidate.is_file():
            continue
        if any(part in SKIP_DIRS for part in candidate.parts):
            continue
        if candidate.suffix.lower() in SKIP_SUFFIXES:
            continue
        if candidate.resolve() == SELF:
            continue
        relative = candidate.relative_to(root).as_posix()
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.append(
                {
                    "file": relative,
                    "line": 0,
                    "pattern": "unreadable",
                    "detail": exc.__class__.__name__,
                }
            )
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS]
            if any(allowed in line for allowed in ALLOWED_SUBSTRINGS):
                continue
            for name, pattern in PATTERNS:
                if name == "private_internal_id" and relative in PROSE_EXEMPT:
                    continue
                match = re.search(pattern, line)
                if not match:
                    continue
                findings.append(
                    {
                        "file": relative,
                        "line": number,
                        "pattern": name,
                        "detail": _redact(match.group(0)),
                    }
                )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a tree for private data")
    parser.add_argument("--path", default=".", help="root of the tree to scan")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    root = pathlib.Path(args.path)
    if not root.is_dir():
        sys.stderr.write("not a directory: %s\n" % root)
        return 2
    findings = scan(root)

    if args.json:
        import json

        sys.stdout.write(
            json.dumps({"findings": findings, "count": len(findings)}, indent=2) + "\n"
        )
    else:
        for finding in findings:
            sys.stdout.write(
                "%s:%s  %s  %s\n"
                % (
                    finding["file"],
                    finding["line"],
                    finding["pattern"],
                    finding["detail"],
                )
            )
        sys.stdout.write(
            "privacy scan: %d finding(s) in %s\n" % (len(findings), root.resolve())
        )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
