"""Structural command-string parsing for SafeGit.

This module deliberately does not try to be a complete shell parser.  It
extracts the *structure* that matters for a safety decision:

* how many commands a single string contains (``;``, ``&&``, ``||``, ``|``,
  ``&``, newlines),
* what the argv of each command is (quote-aware, Windows-friendly),
* which interpreter wrappers hide a nested command string
  (``bash -c``, ``powershell -Command``, ``cmd /c``, ``python -c``, ...),
* command substitutions (``$(...)`` and backticks), sub-shells and
  PowerShell script blocks (``(...)``, ``{...}``) which contain commands
  that would run as well,
* PowerShell indirection (``Invoke-Expression``, ``Start-Process``,
  ``-EncodedCommand``) and arguments that are only known at run time
  (``$VAR``, ``@splat``).

Bash and PowerShell differ where it matters for safety: the escape
character (backslash vs. backtick) and whether a statement that starts with
``$`` runs a command (bash: ``$cmd args``) or is an expression (PowerShell).
:func:`parse` therefore takes a *dialect*; nested ``pwsh -Command`` bodies
are always parsed as PowerShell.

Everything that cannot be resolved is reported through
:attr:`ParseResult.unknown_reasons` so the caller can escalate instead of
guessing.  SafeGit never assumes "parsed fine" when it did not.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import re

MAX_SEGMENTS = 64
MAX_NESTING_DEPTH = 4
MAX_COMMAND_CHARS = 200_000

OPERATORS = ("&&", "||", "|&", ";", "|", "&", "\n")

DIALECT_BASH = "bash"
DIALECT_POWERSHELL = "powershell"

_POWERSHELL_PROGRAMS = frozenset({"pwsh", "pwsh.exe", "powershell", "powershell.exe"})
_INVOKE_EXPRESSION = frozenset({"iex", "invoke-expression"})
_START_PROCESS = frozenset({"start-process", "saps", "start"})
# Shell keywords that are followed by an ordinary command in the same segment.
_LEADING_KEYWORDS = frozenset({"then", "do", "else", "elif", "if", "while", "until", "!"})
_POWERSHELL_ASSIGNMENT_OPS = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "??="})
_POWERSHELL_GLUED_ASSIGNMENT = re.compile(r"^\$[A-Za-z_][\w:]*(?:[-+*/%]|\?\?)?=(?P<rest>.+)$")
_DYNAMIC_AFTER_DOLLAR = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{(?!@*#$:"
)

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
    # Aligned with argv: True where the token is only known at run time
    # ($VAR, ${VAR}, $(...), bash backticks, PowerShell @splat).
    dynamic: tuple[bool, ...] = ()

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


def split_segments(
    command: str, dialect: str = DIALECT_BASH
) -> tuple[list[str], bool]:
    """Split a command string on unquoted shell operators.

    Returns ``(segments, truncated)``.  Quote state is tracked so that
    ``echo "a;b"`` stays a single segment; command substitutions are
    returned as part of their segment (they are scanned separately).
    The escape character is the backslash in bash and the backtick in
    PowerShell, where ``echo a\\; git status`` really is two statements.
    """
    escape = "`" if dialect == DIALECT_POWERSHELL else "\\"
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
            if char == escape and quote == '"' and index + 1 < length:
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

        if char == escape and index + 1 < length:
            current.append(char)
            current.append(command[index + 1])
            index += 2
            continue

        matched = None
        for operator in OPERATORS:
            if command.startswith(operator, index):
                matched = operator
                break

        if matched == "&" and not "".join(current).strip():
            # A leading "&" is PowerShell's call operator ("& $exe args"),
            # not a separator; keep it so the program after it is checked.
            matched = None

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


def tokenize(segment: str, dialect: str = DIALECT_BASH) -> list[str]:
    """Split one segment into argv tokens, honouring single/double quotes.

    Backslashes are preserved outside quotes and inside double quotes
    unless they escape a quote character, which keeps Windows paths
    intact (``C:\\Program Files\\Git\\git.exe``).  In PowerShell the
    backtick is the escape character and is removed, so ``g`it`` and
    ```--hard`` read as ``git`` and ``--hard``.
    """
    return [token for token, _dynamic in tokenize_marked(segment, dialect)]


def tokenize_marked(
    segment: str, dialect: str = DIALECT_BASH
) -> list[tuple[str, bool]]:
    """Like :func:`tokenize`, flagging tokens only known at run time.

    A token is dynamic when it contains an expansion outside single quotes
    (``$VAR``, ``${VAR}``, ``$(...)``, ``$env:X``), a bash backtick
    substitution, or is a PowerShell splat (``@args``).
    """
    powershell = dialect == DIALECT_POWERSHELL
    tokens: list[tuple[str, bool]] = []
    current: list[str] = []
    dynamic = False
    quote: str | None = None
    index = 0
    length = len(segment)

    def flush() -> None:
        nonlocal current, dynamic
        if current:
            tokens.append(("".join(current), dynamic))
        current = []
        dynamic = False

    while index < length:
        char = segment[index]

        if (
            char == "$"
            and quote != "'"
            and index + 1 < length
            and segment[index + 1] in _DYNAMIC_AFTER_DOLLAR
        ):
            dynamic = True

        if quote:
            if powershell and char == "`" and quote == '"' and index + 1 < length:
                current.append(segment[index + 1])
                index += 2
                continue
            if not powershell and char == "\\" and quote == '"' and index + 1 < length:
                nxt = segment[index + 1]
                if nxt in ('"', "\\"):
                    current.append(nxt)
                    index += 2
                    continue
                current.append(char)
                index += 1
                continue
            if not powershell and char == "`" and quote == '"':
                dynamic = True
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

        if char == "`":
            if powershell:
                if index + 1 < length and not segment[index + 1].isspace():
                    current.append(segment[index + 1])
                    index += 2
                    continue
                flush()
                index += 2
                continue
            dynamic = True

        if (
            powershell
            and char == "@"
            and not current
            and index + 1 < length
            and (segment[index + 1].isalpha() or segment[index + 1] in "_(")
        ):
            dynamic = True

        if (
            not powershell
            and char == "\\"
            and index + 1 < length
            and segment[index + 1].isspace()
        ):
            flush()
            index += 2
            continue

        if char.isspace():
            flush()
            index += 1
            continue

        current.append(char)
        index += 1

    flush()
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
            continue
        if len(result) > 1 and result[0].lower() in _LEADING_KEYWORDS:
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


_BACKTICK_RE = re.compile(r"`(?P<backtick>[^`]*)`")


def _extract_substitutions(segment: str, dialect: str = DIALECT_BASH) -> list[str]:
    """Return bash backtick substitution bodies (PowerShell: escapes, none)."""
    if dialect == DIALECT_POWERSHELL:
        return []
    found: list[str] = []
    for match in _BACKTICK_RE.finditer(segment):
        body = match.group("backtick") or ""
        if body.strip():
            found.append(body)
    return found


_GROUP_CLOSE = {"(": ")", "{": "}"}


def _extract_groups(segment: str, dialect: str = DIALECT_BASH) -> list[str]:
    """Return the top-level ``(...)`` and ``{...}`` bodies of a segment.

    These run as commands: ``$(...)`` and ``@(...)`` substitutions, bash
    sub-shells and ``{ ...; }`` groups, PowerShell script blocks
    (``& { }``, ``Invoke-Command { }``, ``if (...) { }``) and conditions.
    Single-quoted text is literal; ``$(...)`` inside double quotes still
    runs and is extracted.  Nested groups are found when a returned body
    is parsed in turn.  Unbalanced groups are skipped: the shell rejects
    them as a syntax error, so nothing runs.
    """
    escape = "`" if dialect == DIALECT_POWERSHELL else "\\"
    bodies: list[str] = []
    index = 0
    length = len(segment)
    quote: str | None = None
    while index < length:
        char = segment[index]
        if quote != "'" and char == escape and index + 1 < length:
            index += 2
            continue
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if quote == '"':
            if char == '"':
                quote = None
                index += 1
                continue
            if not segment.startswith("$(", index):
                index += 1
                continue
            index += 1
            char = "("
        elif char in ("'", '"'):
            quote = char
            index += 1
            continue
        if char in _GROUP_CLOSE:
            end = _matching_close(segment, index, escape)
            if end < 0:
                index += 1
                continue
            body = segment[index + 1 : end]
            if body.strip():
                bodies.append(body)
            index = end + 1
            continue
        index += 1
    return bodies


def _matching_close(segment: str, start: int, escape: str) -> int:
    """Return the index of the bracket closing ``segment[start]``, or -1."""
    stack = [_GROUP_CLOSE[segment[start]]]
    index = start + 1
    quote: str | None = None
    length = len(segment)
    while index < length:
        char = segment[index]
        if quote != "'" and char == escape and index + 1 < length:
            index += 2
            continue
        if quote:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif char in _GROUP_CLOSE:
            stack.append(_GROUP_CLOSE[char])
        elif char in (")", "}"):
            if char != stack[-1]:
                return -1
            stack.pop()
            if not stack:
                return index
        index += 1
    return -1


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


# PowerShell host parameters that take a value (``pwsh -?``).  Parameter
# names are case-insensitive, may start with "/" on Windows PowerShell and
# have no combined short form, so "-NonInteractive" is not "-c".
_POWERSHELL_VALUE_PARAMETERS = frozenset(
    {
        "-executionpolicy",
        "-ex",
        "-ep",
        "-workingdirectory",
        "-wd",
        "-windowstyle",
        "-w",
        "-configurationname",
        "-config",
        "-configurationfile",
        "-outputformat",
        "-o",
        "-of",
        "-inputformat",
        "-inp",
        "-if",
        "-version",
        "-v",
        "-psconsolefile",
        "-custompipename",
        "-settingsfile",
        "-settings",
        "-encodedarguments",
        "-ea",
    }
)


def _powershell_body(
    argv: list[str], dynamic: list[bool]
) -> tuple[str | None, str | None]:
    """Return ``(body, unknown_reason)`` for a ``pwsh``/``powershell`` call.

    ``-Command`` (and its prefixes from four characters, plus ``-c``) yields
    the rest of the line; ``-EncodedCommand`` is decoded.  A command read
    from stdin (``-Command -``), an undecodable payload, a script file, a
    positional argument or a command string built from variables cannot be
    inspected and yields ``(None, ...)``.
    """
    index = 1
    while index < len(argv):
        token = argv[index]
        name = token.lower()
        if name.startswith("/"):
            name = "-" + name[1:]
        if not name.startswith("-") or name in ("-", "--"):
            return None, None
        if name == "-c" or (len(name) >= 4 and "-command".startswith(name)):
            body = " ".join(argv[index + 1 :]).strip()
            if not body or body == "-":
                return None, "POWERSHELL_COMMAND_FROM_STDIN"
            if any(dynamic[index + 1 :]):
                return None, "POWERSHELL_COMMAND_IS_DYNAMIC"
            return body, None
        if name in ("-e", "-ec") or (
            len(name) >= 4 and "-encodedcommand".startswith(name)
        ):
            if index + 1 >= len(argv):
                return None, "POWERSHELL_ENCODED_COMMAND_UNREADABLE"
            try:
                decoded = base64.b64decode(argv[index + 1], validate=True).decode(
                    "utf-16-le"
                )
            except (binascii.Error, ValueError):
                return None, "POWERSHELL_ENCODED_COMMAND_UNREADABLE"
            if not decoded.strip():
                return None, "POWERSHELL_ENCODED_COMMAND_UNREADABLE"
            return decoded, None
        if name in ("-f", "-file") or (len(name) >= 3 and "-file".startswith(name)):
            return None, None
        if name in _POWERSHELL_VALUE_PARAMETERS:
            index += 2
            continue
        index += 1
    return None, None


def _invoke_expression_body(argv: list[str]) -> str | None:
    """The string ``Invoke-Expression`` evaluates, or None (piped input)."""
    args = list(argv[1:])
    if args and args[0].lower() in ("-command", "-c", "-co", "-com", "-comm"):
        args = args[1:]
    body = " ".join(args).strip()
    return body or None


_START_PROCESS_ALIASES = {
    "-path": "-filepath",
    "-pspath": "-filepath",
    "-args": "-argumentlist",
    "-lup": "-loaduserprofile",
}
_START_PROCESS_VALUE_PARAMETERS = (
    "-filepath",
    "-argumentlist",
    "-workingdirectory",
    "-verb",
    "-windowstyle",
    "-redirectstandardoutput",
    "-redirectstandarderror",
    "-redirectstandardinput",
    "-credential",
    "-environment",
)
_START_PROCESS_SWITCHES = (
    "-nonewwindow",
    "-wait",
    "-passthru",
    "-usenewenvironment",
    "-loaduserprofile",
    "-whatif",
    "-confirm",
)


def _resolve_parameter(name: str) -> str | None:
    """Resolve a (possibly abbreviated) Start-Process parameter name."""
    if name in _START_PROCESS_ALIASES:
        return _START_PROCESS_ALIASES[name]
    known = _START_PROCESS_VALUE_PARAMETERS + _START_PROCESS_SWITCHES
    if name in known:
        return name
    candidates = [option for option in known if option.startswith(name)]
    return candidates[0] if len(candidates) == 1 else None


def _start_process_body(argv: list[str]) -> str | None:
    """The command line ``Start-Process`` (or ``start``) would launch.

    Unrecognised tokens are kept as arguments rather than dropped, so an
    unusual spelling can only make the result stricter.
    """
    file_path: str | None = None
    arguments: list[str] = []
    positional = 0
    index = 1

    def take_list(start: int) -> tuple[list[str], int]:
        values = [argv[start]]
        cursor = start + 1
        while cursor < len(argv) and (
            values[-1].endswith(",") or argv[cursor].startswith(",")
        ):
            values.append(argv[cursor])
            cursor += 1
        return values, cursor

    while index < len(argv):
        token = argv[index]
        resolved = (
            _resolve_parameter(token.lower())
            if token.startswith("-") and len(token) > 1
            else None
        )
        if resolved in _START_PROCESS_SWITCHES:
            index += 1
            continue
        if resolved in _START_PROCESS_VALUE_PARAMETERS:
            if index + 1 >= len(argv):
                break
            if resolved == "-filepath":
                file_path = argv[index + 1]
                index += 2
            elif resolved == "-argumentlist":
                values, index = take_list(index + 1)
                arguments.extend(values)
            else:
                index += 2
            continue
        if file_path is None and positional == 0:
            file_path = token
            positional += 1
            index += 1
            continue
        values, index = take_list(index)
        arguments.extend(values)
        positional += 1
    if not file_path:
        return None
    pieces = [file_path]
    for value in arguments:
        pieces.extend(part for part in value.split(",") if part.strip())
    return " ".join(pieces)


def _indirect_program(raw: list[str], tokens: list[str], dialect: str) -> bool:
    """True when the program to run is computed rather than written out."""
    if len(raw) > 1 and raw[0] in ("&", ".") and raw[1][:1] in ("(", "[", "$"):
        return True
    program = tokens[0]
    if program.startswith("[") and "]::" in program:
        return True
    if dialect == DIALECT_POWERSHELL:
        # Only reached for a "$..." statement that runs code by itself.
        return program.startswith("$")
    return program.startswith("$") or "$(" in program or "`" in program


# Expression members that execute code: $sb.Invoke(), .InvokeScript(...),
# [powershell]::Create().AddScript(...), $ExecutionContext.InvokeCommand.
_POWERSHELL_EXECUTING_MEMBER = re.compile(
    r"(?i)\.(?:invoke\w*|addscript|addcommand|begininvoke)\s*\(|\$executioncontext\b"
)


def _powershell_statement(
    tokens: list[str], dynamic: list[bool]
) -> tuple[list[str], list[bool]]:
    """Reduce a PowerShell statement that starts with ``$`` to its command.

    ``$x = git status`` runs ``git status``; any other statement starting
    with a variable (``$_.Name``, ``$a -eq 1``) is an expression and runs
    nothing by itself (script blocks and sub-expressions in it are parsed
    separately), unless it calls a member that executes code; that one is
    returned unchanged so the caller reports it as indirect.
    """
    while tokens and tokens[0].startswith("$"):
        if any(_POWERSHELL_EXECUTING_MEMBER.search(token) for token in tokens):
            return tokens, dynamic
        if len(tokens) > 1 and tokens[1] in _POWERSHELL_ASSIGNMENT_OPS:
            tokens, dynamic = tokens[2:], dynamic[2:]
            continue
        glued = _POWERSHELL_GLUED_ASSIGNMENT.match(tokens[0])
        if glued:
            tokens = [glued.group("rest"), *tokens[1:]]
            dynamic = [True, *dynamic[1:]]
            continue
        return [], []
    return tokens, dynamic


def parse(command: str, dialect: str = DIALECT_BASH) -> ParseResult:
    """Parse a command string into commands plus explicit unknowns.

    ``dialect`` is the shell that will run the string: ``"bash"`` (also used
    for sh/cmd) or ``"powershell"``.
    """
    unknown_reasons: list[str] = []
    if not isinstance(command, str) or not command.strip():
        return ParseResult(commands=[], unknown_reasons=unknown_reasons)

    truncated = False
    if len(command) > MAX_COMMAND_CHARS:
        unknown_reasons.append("COMMAND_TOO_LONG_TRUNCATED")
        command = command[:MAX_COMMAND_CHARS]
        truncated = True

    commands: list[ParsedCommand] = []
    pending: list[tuple[str, int, bool, str]] = [(command, 0, False, dialect)]
    seen = 0

    def nest(body: str, depth: int, from_sub: bool, body_dialect: str) -> None:
        if depth + 1 <= MAX_NESTING_DEPTH:
            pending.append((body, depth + 1, from_sub, body_dialect))
        else:
            unknown_reasons.append("NESTING_DEPTH_EXCEEDED")

    while pending:
        segment, depth, from_sub, current = pending.pop(0)
        if seen >= MAX_SEGMENTS:
            unknown_reasons.append("SEGMENT_LIMIT_REACHED")
            truncated = True
            break
        seen += 1

        for substitution in _extract_substitutions(segment, current):
            nest(substitution, depth, True, current)
        for group in _extract_groups(segment, current):
            nest(group, depth, True, current)

        segments, was_truncated = split_segments(segment, current)
        if was_truncated:
            truncated = True
            unknown_reasons.append("SEGMENT_LIMIT_REACHED")

        for part in segments:
            marked = tokenize_marked(part, current)
            raw = [token for token, _ in marked]
            tokens, assignments = strip_wrappers(raw)
            # strip_wrappers only removes leading tokens: re-align the flags.
            dynamic = [flag for _, flag in marked][len(raw) - len(tokens) :]
            if (
                tokens
                and current == DIALECT_POWERSHELL
                and tokens[0].startswith("$")
                and not (raw and raw[0] in ("&", "."))
            ):
                tokens, dynamic = _powershell_statement(tokens, dynamic)
                if tokens:
                    stripped, more = strip_wrappers(tokens)
                    dynamic = dynamic[len(tokens) - len(stripped) :]
                    tokens = stripped
                    assignments.extend(more)
            if not tokens:
                continue
            parsed_command = ParsedCommand(
                argv=tuple(tokens),
                raw=part.strip(),
                nested_depth=depth,
                from_substitution=from_sub,
                env_assignments=tuple(assignments),
                dynamic=tuple(dynamic),
            )
            head = basename(tokens[0])
            if head in _INTERPRETER_PROGRAMS:
                commands.append(parsed_command)
                if head in _POWERSHELL_PROGRAMS:
                    body, reason = _powershell_body(tokens, dynamic)
                    body_dialect = DIALECT_POWERSHELL
                else:
                    body, reason = _interpreter_body(tokens), None
                    body_dialect = DIALECT_BASH
                if body is None:
                    unknown_reasons.append(
                        reason or "INTERPRETER_WITHOUT_COMMAND_FLAG:%s" % head
                    )
                    continue
                nest(body, depth, False, body_dialect)
                continue
            if head in _INVOKE_EXPRESSION:
                commands.append(parsed_command)
                body = _invoke_expression_body(tokens)
                if body is None or any(dynamic[1:]):
                    # Piped input or a string built from variables.
                    unknown_reasons.append("INVOKE_EXPRESSION_INPUT_NOT_VISIBLE")
                    continue
                nest(body, depth, False, DIALECT_POWERSHELL)
                continue
            if head in _START_PROCESS:
                commands.append(parsed_command)
                body = _start_process_body(tokens)
                if body is None or body.startswith(("$", "(", "@")):
                    unknown_reasons.append("START_PROCESS_TARGET_NOT_RESOLVED")
                    continue
                # The argument list reaches the program as plain words.
                nest(body, depth, False, DIALECT_BASH)
                continue
            if _indirect_program(raw, tokens, current):
                unknown_reasons.append("INDIRECT_PROGRAM_NAME:%s" % tokens[0][:40])
                continue
            commands.append(parsed_command)

    if truncated:
        unknown_reasons.append("PARSE_TRUNCATED")

    return ParseResult(
        commands=commands, unknown_reasons=unknown_reasons, truncated=truncated
    )
