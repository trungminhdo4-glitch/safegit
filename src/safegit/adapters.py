"""Adapt tool-call shapes from different agents to SafeGit's action model.

SafeGit's safety decision is agent-independent: adapters translate a
host-specific tool call into zero or more :class:`Action` objects, and the
engine decides on those.  Adapters contain no policy.

Two kinds of action are guarded:

* ``CommandAction`` - a shell command string (git and filesystem checks),
* ``FileAction`` - a write/edit/delete of a path (protected-path checks).

Anything else is reported as out-of-scope with an explicit limitation
string rather than being silently approved.
"""

from __future__ import annotations

import dataclasses
import re

COMMAND_TOOLS: dict[str, str] = {
    "bash": "command",
    "shell": "command",
    "sh": "command",
    "terminal": "command",
    "run": "command",
    "run_shell": "command",
    "execute_command": "command",
    "execute_bash": "command",
    "command": "command",
    "bashcommand": "command",
    "runshellcommand": "command",
}

FILE_WRITE_TOOLS: dict[str, str] = {
    "write": "write",
    "writefile": "write",
    "write_file": "write",
    "create_file": "write",
    "createfile": "write",
    "write_to_file": "write",
    "createtextfile": "write",
    "notebookwrite": "write",
    "notebook_write": "write",
    "notebookedit": "write",
    "notebook_edit": "write",
    "save_file": "write",
    "edit": "edit",
    "editfile": "edit",
    "edit_file": "edit",
    "replace_in_file": "edit",
    "multiedit": "edit",
    "multi_edit": "edit",
    "str_replace_editor": "edit",
    "apply_patch": "patch",
    "patch": "patch",
    "delete": "write",
    "delete_file": "write",
    "deletefile": "write",
    "remove_file": "write",
    "removefile": "write",
}

_WRITE_KEYWORDS: tuple[str, ...] = (
    "write",
    "edit",
    "delete",
    "remove",
    "patch",
    "replace",
    "create",
    "save",
    "rename",
    "move",
    "mkdir",
    "chmod",
)

_COMMAND_TOOL_KEYWORDS: tuple[str, ...] = (
    "bash",
    "shell",
    "command",
    "terminal",
    "exec",
    "run_",
)

MAX_COMMAND_ARG_CHARS = 200_000

READ_ONLY_TOOLS: frozenset[str] = frozenset(
    {
        "read",
        "readfile",
        "read_file",
        "view",
        "cat",
        "glob",
        "list",
        "ls",
        "grep",
        "search",
        "find",
        "rg",
        "webfetch",
        "websearch",
        "fetch",
        "todoread",
        "todowrite",
        "todo",
        "think",
        "plan",
        "task",
        "agent",
        "question",
        "notify",
        "ping",
        "memory",
        "session",
        "askuserquestion",
        "listdirectory",
        "directorytree",
    }
)

_OPAQUE_PREFIXES = ("mcp__", "mcp_", "mcp-")

_PATCH_PATH_RE = re.compile(r"^(?:\+\+\+|---)\s+[ab]/(.+)$", re.MULTILINE)

MAX_PATH_ARG_CHARS = 4096


@dataclasses.dataclass(frozen=True)
class CommandAction:
    command: str
    cwd: str
    tool_name: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "command",
            "command": self.command,
            "cwd": self.cwd,
            "tool_name": self.tool_name,
        }


@dataclasses.dataclass(frozen=True)
class FileAction:
    path: str
    mode: str
    cwd: str
    tool_name: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "file",
            "path": self.path,
            "mode": self.mode,
            "cwd": self.cwd,
            "tool_name": self.tool_name,
        }


Action = CommandAction | FileAction


@dataclasses.dataclass
class NormalizedCall:
    actions: list[Action]
    out_of_scope: bool
    limitations: list[str]
    tool_name: str

    def to_dict(self) -> dict[str, object]:
        return {
            "tool_name": self.tool_name,
            "out_of_scope": self.out_of_scope,
            "limitations": list(self.limitations),
            "actions": [action.to_dict() for action in self.actions],
        }


def _key(tool_name: str) -> str:
    return (tool_name or "").strip().lower().replace("-", "_")


def _first_str(args: dict[str, object], *names: str) -> str:
    for name in names:
        value = args.get(name)
        if isinstance(value, str) and value:
            return value[:MAX_PATH_ARG_CHARS]
    return ""


def _first_command(args: dict[str, object], *names: str) -> str:
    for name in names:
        value = args.get(name)
        if isinstance(value, str) and value:
            return value[:MAX_COMMAND_ARG_CHARS]
        if isinstance(value, (list, tuple)) and value:
            joined = " ".join(str(item) for item in value)
            return joined[:MAX_COMMAND_ARG_CHARS]
    return ""


def normalize(
    tool_name: str,
    tool_args: dict[str, object] | None,
    *,
    cwd: str = "",
) -> NormalizedCall:
    """Translate one tool call into SafeGit actions."""
    args = dict(tool_args or {})
    key = _key(tool_name)
    event_cwd = _first_str(args, "cwd", "working_directory", "workingDirectory") or cwd
    limitations: list[str] = []

    if key in COMMAND_TOOLS:
        command = _first_command(
            args, "command", "cmd", "script", "commandLine", "command_line"
        )
        if not command:
            return NormalizedCall(
                actions=[],
                out_of_scope=False,
                limitations=["COMMAND_ARGUMENT_MISSING"],
                tool_name=tool_name,
            )
        return NormalizedCall(
            actions=[
                CommandAction(command=command, cwd=event_cwd, tool_name=tool_name)
            ],
            out_of_scope=False,
            limitations=limitations,
            tool_name=tool_name,
        )

    if key in FILE_WRITE_TOOLS and FILE_WRITE_TOOLS[key] == "patch":
        patch_text = _first_command(
            args, "patch", "patchText", "patch_text", "diff", "input"
        )
        paths = sorted(
            set(match.strip() for match in _PATCH_PATH_RE.findall(patch_text))
        )
        if not paths:
            limitations.append("PATCH_TARGETS_NOT_RESOLVABLE")
            direct = _first_str(args, "file_path", "filePath", "path")
            if direct:
                paths = [direct]
            else:
                return NormalizedCall(
                    actions=[],
                    out_of_scope=False,
                    limitations=limitations,
                    tool_name=tool_name,
                )
        return NormalizedCall(
            actions=[
                FileAction(path=path, mode="edit", cwd=event_cwd, tool_name=tool_name)
                for path in paths
            ],
            out_of_scope=False,
            limitations=limitations,
            tool_name=tool_name,
        )

    if key in FILE_WRITE_TOOLS:
        path = _first_str(
            args,
            "file_path",
            "filePath",
            "path",
            "notebook_path",
            "notebookPath",
            "target_file",
            "targetFile",
        )
        if not path:
            return NormalizedCall(
                actions=[],
                out_of_scope=False,
                limitations=["FILE_PATH_ARGUMENT_MISSING"],
                tool_name=tool_name,
            )
        return NormalizedCall(
            actions=[
                FileAction(
                    path=path,
                    mode=FILE_WRITE_TOOLS[key],
                    cwd=event_cwd,
                    tool_name=tool_name,
                )
            ],
            out_of_scope=False,
            limitations=limitations,
            tool_name=tool_name,
        )

    if key in READ_ONLY_TOOLS:
        return NormalizedCall(
            actions=[],
            out_of_scope=True,
            limitations=["READ_ONLY_TOOL"],
            tool_name=tool_name,
        )

    if key.startswith(_OPAQUE_PREFIXES):
        return NormalizedCall(
            actions=[],
            out_of_scope=True,
            limitations=["OPAQUE_MCP_TOOL_NOT_INSPECTED"],
            tool_name=tool_name,
        )

    if any(keyword in key for keyword in _COMMAND_TOOL_KEYWORDS):
        command = _first_command(
            args, "command", "cmd", "script", "commandLine", "command_line"
        )
        if command:
            return NormalizedCall(
                actions=[
                    CommandAction(command=command, cwd=event_cwd, tool_name=tool_name)
                ],
                out_of_scope=False,
                limitations=["TOOL_NAME_INFERRED_AS_COMMAND"],
                tool_name=tool_name,
            )
        return NormalizedCall(
            actions=[],
            out_of_scope=False,
            limitations=["COMMAND_ARGUMENT_MISSING"],
            tool_name=tool_name,
        )

    if any(keyword in key for keyword in _WRITE_KEYWORDS):
        path = _first_str(
            args,
            "file_path",
            "filePath",
            "path",
            "notebook_path",
            "notebookPath",
            "target_file",
            "targetFile",
        )
        if path:
            return NormalizedCall(
                actions=[
                    FileAction(
                        path=path, mode="write", cwd=event_cwd, tool_name=tool_name
                    )
                ],
                out_of_scope=False,
                limitations=["TOOL_NAME_INFERRED_AS_WRITE"],
                tool_name=tool_name,
            )
        return NormalizedCall(
            actions=[],
            out_of_scope=False,
            limitations=["FILE_PATH_ARGUMENT_MISSING"],
            tool_name=tool_name,
        )

    return NormalizedCall(
        actions=[],
        out_of_scope=True,
        limitations=["UNCLASSIFIED_TOOL"],
        tool_name=tool_name,
    )
