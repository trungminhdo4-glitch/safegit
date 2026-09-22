"""Structural command-string parsing for SafeGit.

This module deliberately does not try to be a complete shell parser.  It
extracts the *structure* that matters for a safety decision:

* how many commands a single string contains (``;``, ``&&``, ``||``, ``|``,
  ``&``, newlines),
* what the argv of each command is (quote-aware, Windows-friendly),
* which interpreter wrappers hide a nested command string
  (``bash -c``, ``powershell -Command``, ``cmd /c``, ``python -c``, ...),
* command substitutions (``$(...)`` and backticks) which contain commands
  that would run as well.

Everything that cannot be resolved is reported through
:attr:`ParseResult.unknown_reasons` so the caller can escalate instead of
guessing.  SafeGit never assumes "parsed fine" when it did not.
"""

from __future__ import annotations

import dataclasses
import re

MAX_SEGMENTS = 64
MAX_NESTING_DEPTH = 4
MAX_COMMAND_CHARS = 200_000

OPERATORS = ("&&", "||", "|&", ";", "|", "&", "\n")

_INTERPRETER_WRAPPERS = {
    "bash": ("-c",),
    "sh": ("-c",),
    "zsh": ("-c",),
    "dash": ("-c",),
    "ksh": ("-c",),
    "cmd": ("/c", "/C", "/k", "/K"),
    "cmd.exe": ("/c", "/C", "/k", "/K"),
    "powershell": ("-command", "-c", "-Command", "-C"),
    "powershell.exe": ("-command", "-c", "-Command", "-C"),
    "pwsh": ("-command", "-c", "-Command", "-C"),
    "pwsh.exe": ("-command", "-c", "-Command", "-C"),
    "python": ("-c",),
    "python3": ("-c",),
    "python.exe": ("-c",),
    "node": ("-e", "--eval"),
    "perl": ("-e",),
    "ruby": ("-e",),
    "php": ("-r",),
}

_TRANSPARENT_PREFIXES = {
    "sudo",
    "doas",
    "env",
    "nohup",
    "command",
    "builtin",
    "exec",
    "time",
    "nice",
    "ionice",
    "setsid",
    "stdbuf",
    "gtimeout",
}

_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

_INTERPRETER_PROGRAMS = frozenset(
    {
        "python",
        "python3",
        "python.exe",
        "node",
        "node.exe",
        "pwsh",
        "pwsh.exe",
        "powershell",
        "powershell.exe",
        "perl",
        "ruby",
        "php",
        "bash",
        "sh",
        "zsh",
        "dash",
        "cmd",
        "cmd.exe",
    }
)
_TIMEOUT_TAKES_VALUE = {"timeout", "gtimeout"}
_NICE_TAKES_VALUE = {"nice", "ionice"}
_WRAPPER_VALUE_OPTIONS: dict[str, frozenset[str]] = {
    "sudo": frozenset(
        {"-u", "-g", "-h", "-p", "-C", "-T", "-r", "-t", "--user", "--group"}
    ),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "-S", "--unset", "--chdir"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p", "--class", "--classdata", "--pid"}),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
}


@dataclasses.dataclass(frozen=True)
class ParsedCommand:
    """One command found in a command string."""

    argv: tuple[str, ...]
    raw: str
    nested_depth: int
    from_substitution: bool = False
    env_assignments: tuple[tuple[str, str], ...] = ()

    @property
    def program(self) -> str:
        if not self.argv:
            return ""
        return self.argv[0]


@dataclasses.dataclass
class ParseResult:
    commands: list[ParsedCommand]
    unknown_reasons: list[str]
    truncated: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "command_count": len(self.commands),
            "commands": [list(c.argv) for c in self.commands],
            "unknown_reasons": list(self.unknown_reasons),
            "truncated": self.truncated,
        }


def basename(token: str) -> str:
    """Return the lowercased file name of a program token."""
    cleaned = token.strip().strip('"').strip("'")
    for sep in ("\\", "/"):
        if sep in cleaned:
            cleaned = cleaned.rsplit(sep, 1)[1]
    return cleaned.lower()


def split_segments(command: str) -> tuple[list[str], bool]:
    """Split a command string on unquoted shell operators.

    Returns ``(segments, truncated)``.  Quote state is tracked so that
    ``echo "a;b"`` stays a single segment; command substitutions are
    returned as part of their segment (they are scanned separately).
    """
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    truncated = False
    length = len(command)

    while index < length:
        char = command[index]

        if quote:
            current.append(char)
            if char == "\\" and quote == '"' and index + 1 < length:
                current.append(command[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue

        if char in ("'", '"'):
            quote = char
            current.append(char)
            index += 1
            continue

        if char == "\\" and index + 1 < length:
            current.append(char)
            current.append(command[index + 1])
            index += 2
            continue

        matched = None
        for operator in OPERATORS:
            if command.startswith(operator, index):
                matched = operator
                break

        if matched is None:
            current.append(char)
            index += 1
            continue

        segments.append("".join(current))
        current = []
        index += len(matched)
        if len(segments) >= MAX_SEGMENTS:
            truncated = True
            segments.append(command[index:])
            return segments, truncated

    segments.append("".join(current))
    return segments, truncated


def tokenize(segment: str) -> list[str]:
    """Split one segment into argv tokens, honouring single/double quotes.

    Backslashes are preserved outside quotes and inside double quotes
    unless they escape a quote character, which keeps Windows paths
    intact (``C:\\Program Files\\Git\\git.exe``).
    """
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    length = len(segment)

    while index < length:
        char = segment[index]

        if quote:
            if char == "\\" and quote == '"' and index + 1 < length:
                nxt = segment[index + 1]
                if nxt in ('"', "\\"):
                    current.append(nxt)
                    index += 2
                    continue
                current.append(char)
                index += 1
                continue
            if char == quote:
                quote = None
                index += 1
                continue
            current.append(char)
            index += 1
            continue

        if char in ("'", '"'):
            quote = char
            index += 1
            continue

        if char == "\\" and index + 1 < length and segment[index + 1].isspace():
            if current:
                tokens.append("".join(current))
                current = []
            index += 2
            continue

        if char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            index += 1
            continue

        current.append(char)
        index += 1

    if current:
        tokens.append("".join(current))
    return tokens


def strip_wrappers(tokens: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Remove env assignments and transparent command prefixes.

    Returns the remaining argv plus the environment assignments that were
    stripped, because ``HUSKY=0 git commit`` and similar prefixes matter
    for the safety decision even though they are not argv.
    """
    result = list(tokens)
    assignments: list[tuple[str, str]] = []
    changed = True
    while changed and result:
        changed = False
        while result and _ENV_ASSIGN_RE.match(result[0]):
            key, _, value = result[0].partition("=")
            assignments.append((key, value))
            result = result[1:]
            changed = True
        if not result:
            return result, assignments
        head = basename(result[0])
        if head in ("xargs",):
            consumed, nested = _strip_xargs(args=result)
            if nested:
                return nested, assignments
            result = consumed
            changed = True
            continue
        if head in _TRANSPARENT_PREFIXES:
            result = result[1:]
            values = _WRAPPER_VALUE_OPTIONS.get(head, frozenset())
            while result and result[0].startswith("-"):
                takes_value = result[0] in values
                result = result[1:]
                if takes_value and result:
                    result = result[1:]
            changed = True
            continue
        if head in _TIMEOUT_TAKES_VALUE:
            result = _strip_timeout_prefix(result[1:], head)
            changed = True
            continue
        if head in _NICE_TAKES_VALUE:
            result = result[1:]
            while result and result[0].startswith("-"):
                token = result[0]
                result = result[1:]
                if token in ("-n", "--adjustment") and result:
                    result = result[1:]
            changed = True
            continue
        if result and result[0] in ("&", "."):
            result = result[1:]
            changed = True
    return result, assignments


def _strip_timeout_prefix(tokens: list[str], head: str) -> list[str]:
    """Skip ``timeout`` options (including their values) and the duration."""
    result = list(tokens)
    value_options = {"-s", "--signal", "-k", "--kill-after"}
    while result and result[0].startswith("-"):
        token = result[0]
        result = result[1:]
        if token in value_options and result:
            result = result[1:]
    if result:
        result = result[1:]
    return result


def _strip_xargs(args: list[str]) -> tuple[list[str], list[str]]:
    """Return the command that xargs would run after its own options."""
    index = 1
    value_options = {
        "-a",
        "--arg-file",
        "-d",
        "--delimiter",
        "-E",
        "--eof",
        "-I",
        "--replace",
        "-L",
        "--max-lines",
        "-n",
        "--max-args",
        "-P",
        "--max-procs",
        "-s",
        "--max-chars",
    }
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if not token.startswith("-"):
            break
        if token in value_options:
            index += 2
            continue
        index += 1
    return args[:1], args[index:]


_SUBSTITUTION_RE = re.compile(r"\$\((?P<paren>[^()]*)\)|`(?P<backtick>[^`]*)`")


def _extract_substitutions(segment: str) -> list[str]:
    found: list[str] = []
    for match in _SUBSTITUTION_RE.finditer(segment):
        body = match.group("paren") or match.group("backtick") or ""
        if body.strip():
            found.append(body)
    return found


def _interpreter_body(argv: list[str]) -> str | None:
    if not argv:
        return None
    head = basename(argv[0])
    flags = _INTERPRETER_WRAPPERS.get(head)
    if not flags:
        return None
    lowered_flags = {flag.lower() for flag in flags}
    for index, token in enumerate(argv[1:], start=1):
        candidate = token
        if candidate.startswith("//"):
            candidate = "/" + candidate[2:]
        if candidate.lower() in lowered_flags:
            if index + 1 < len(argv):
                return " ".join(argv[index + 1 :])
            return None
        if (
            candidate.startswith("-")
            and not candidate.startswith("--")
            and len(candidate) > 2
        ):
            for char in candidate[1:]:
                if ("-" + char.lower()) in lowered_flags:
                    if index + 1 < len(argv):
                        return " ".join(argv[index + 1 :])
                    return None
    return None


def parse(command: str) -> ParseResult:
    """Parse a command string into commands plus explicit unknowns."""
    unknown_reasons: list[str] = []
    if not isinstance(command, str) or not command.strip():
        return ParseResult(commands=[], unknown_reasons=unknown_reasons)

    truncated = False
    if len(command) > MAX_COMMAND_CHARS:
        unknown_reasons.append("COMMAND_TOO_LONG_TRUNCATED")
        command = command[:MAX_COMMAND_CHARS]
        truncated = True

    commands: list[ParsedCommand] = []
    pending: list[tuple[str, int, bool]] = [(command, 0, False)]
    seen = 0

    while pending:
        segment, depth, from_sub = pending.pop(0)
        if seen >= MAX_SEGMENTS:
            unknown_reasons.append("SEGMENT_LIMIT_REACHED")
            truncated = True
            break
        seen += 1

        for substitution in _extract_substitutions(segment):
            if depth + 1 <= MAX_NESTING_DEPTH:
                pending.append((substitution, depth + 1, True))
            else:
                unknown_reasons.append("NESTING_DEPTH_EXCEEDED")

        segments, was_truncated = split_segments(segment)
        if was_truncated:
            truncated = True
            unknown_reasons.append("SEGMENT_LIMIT_REACHED")

        for part in segments:
            tokens, assignments = strip_wrappers(tokenize(part))
            if not tokens:
                continue
            head = basename(tokens[0])
            if head in _INTERPRETER_PROGRAMS:
                body = _interpreter_body(tokens)
                commands.append(
                    ParsedCommand(
                        argv=tuple(tokens),
                        raw=part.strip(),
                        nested_depth=depth,
                        from_substitution=from_sub,
                        env_assignments=tuple(assignments),
                    )
                )
                if body is None:
                    unknown_reasons.append("INTERPRETER_WITHOUT_COMMAND_FLAG:%s" % head)
                    continue
                if depth + 1 <= MAX_NESTING_DEPTH:
                    pending.append((body, depth + 1, False))
                else:
                    unknown_reasons.append("NESTING_DEPTH_EXCEEDED")
                continue
            if tokens[0].startswith("$") or "$(" in tokens[0] or "`" in tokens[0]:
                unknown_reasons.append("INDIRECT_PROGRAM_NAME:%s" % tokens[0][:40])
                continue
            commands.append(
                ParsedCommand(
                    argv=tuple(tokens),
                    raw=part.strip(),
                    nested_depth=depth,
                    from_substitution=from_sub,
                    env_assignments=tuple(assignments),
                )
            )

    if truncated:
        unknown_reasons.append("PARSE_TRUNCATED")

    return ParseResult(
        commands=commands, unknown_reasons=unknown_reasons, truncated=truncated
    )
