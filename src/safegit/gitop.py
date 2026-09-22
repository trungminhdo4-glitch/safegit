"""Structural git invocation parsing and operation classification.

SafeGit classifies git usage from *parsed argv*, not from a growing pile of
regular expressions over the raw command string.  A rule matches a parsed
operation with known flags, refspecs and (where relevant) a branch or path
hint; everything that cannot be classified is reported as ``git.other`` and
resolved by policy to UNKNOWN rather than being silently allowed.

One invocation can match several rules (``git push --force --no-verify``).
:func:`classify_all` returns all of them; the engine takes the most
restrictive verdict.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Iterable

from . import shellparse

RULE_RESET_HARD = "git.reset.hard"
RULE_RESET_KEEP = "git.reset.keep"
RULE_CLEAN_FORCE = "git.clean.force"
RULE_PUSH_FORCE = "git.push.force"
RULE_PUSH_FORCE_LEASE = "git.push.force_with_lease"
RULE_PUSH_DELETE = "git.push.delete_branch"
RULE_PUSH_BROAD = "git.push.broad"
RULE_PUSH_PLAIN = "git.push.plain"
RULE_REBASE = "git.rebase"
RULE_REBASE_CONTINUE = "git.rebase.continue"
RULE_COMMIT_AMEND = "git.commit.amend"
RULE_COMMIT_PLAIN = "git.commit.plain"
RULE_WORKTREE_REMOVE = "git.worktree.remove"
RULE_WORKTREE_PRUNE = "git.worktree.prune"
RULE_BRANCH_DELETE_FORCE = "git.branch.delete.force"
RULE_BRANCH_DELETE_SAFE = "git.branch.delete.safe"
RULE_BRANCH_RENAME = "git.branch.rename"
RULE_CHECKOUT_DISCARD = "git.checkout.discard"
RULE_CHECKOUT_SWITCH = "git.checkout.switch"
RULE_RESTORE_WORKTREE = "git.restore.worktree"
RULE_ADD_ALL = "git.add.all"
RULE_STASH_DESTROY = "git.stash.destroy"
RULE_HISTORY_FILTER = "git.history.filter"
RULE_HISTORY_EXPIRE = "git.history.expire"
RULE_REF_WRITE = "git.ref.write"
RULE_CONFIG_WRITE = "git.config.write"
RULE_CONFIG_INLINE = "git.config.inline_override"
RULE_REMOTE_CHANGE = "git.remote.change"
RULE_TAG_DELETE = "git.tag.delete"
RULE_SUBMODULE_CHANGE = "git.submodule.change"
RULE_MERGE = "git.merge"
RULE_RM_TRACKED = "git.rm.tracked"
RULE_HOOK_BYPASS = "git.hook.bypass"
RULE_REPO_OVERRIDE = "git.repo.override"
RULE_NON_DESTRUCTIVE = "git.non_destructive"
RULE_OTHER = "git.other"

RULE_IDS: tuple[str, ...] = (
    RULE_RESET_HARD,
    RULE_RESET_KEEP,
    RULE_CLEAN_FORCE,
    RULE_PUSH_FORCE,
    RULE_PUSH_FORCE_LEASE,
    RULE_PUSH_DELETE,
    RULE_PUSH_BROAD,
    RULE_PUSH_PLAIN,
    RULE_REBASE,
    RULE_REBASE_CONTINUE,
    RULE_COMMIT_AMEND,
    RULE_COMMIT_PLAIN,
    RULE_WORKTREE_REMOVE,
    RULE_WORKTREE_PRUNE,
    RULE_BRANCH_DELETE_FORCE,
    RULE_BRANCH_DELETE_SAFE,
    RULE_BRANCH_RENAME,
    RULE_CHECKOUT_DISCARD,
    RULE_CHECKOUT_SWITCH,
    RULE_RESTORE_WORKTREE,
    RULE_ADD_ALL,
    RULE_STASH_DESTROY,
    RULE_HISTORY_FILTER,
    RULE_HISTORY_EXPIRE,
    RULE_REF_WRITE,
    RULE_CONFIG_WRITE,
    RULE_CONFIG_INLINE,
    RULE_REMOTE_CHANGE,
    RULE_TAG_DELETE,
    RULE_SUBMODULE_CHANGE,
    RULE_MERGE,
    RULE_RM_TRACKED,
    RULE_HOOK_BYPASS,
    RULE_REPO_OVERRIDE,
    RULE_NON_DESTRUCTIVE,
    RULE_OTHER,
)

READ_ONLY_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "status",
        "log",
        "diff",
        "diff-tree",
        "diff-index",
        "show",
        "show-branch",
        "rev-parse",
        "rev-list",
        "ls-files",
        "ls-tree",
        "ls-remote",
        "cat-file",
        "shortlog",
        "blame",
        "whatchanged",
        "describe",
        "name-rev",
        "merge-base",
        "count-objects",
        "verify-pack",
        "fsck",
        "check-attr",
        "check-ignore",
        "check-ref-format",
        "for-each-ref",
        "show-ref",
        "grep",
        "help",
        "version",
        "fetch",
        "range-diff",
        "var",
        "verify-commit",
        "verify-tag",
        "diagnose",
        "bugreport",
        "reflog",
        "symbolic-ref",
    }
)

_KNOWN_BUT_UNCLASSIFIED = frozenset(
    {
        "apply",
        "am",
        "archive",
        "bisect",
        "bundle",
        "notes",
        "note",
        "lfs",
        "sparse-checkout",
        "prune",
        "cherry",
        "cherry-pick",
        "clone",
        "column",
        "commit-tree",
        "credential",
        "fast-export",
        "fast-import",
        "format-patch",
        "gc",
        "hash-object",
        "init",
        "interpret-trailers",
        "maintenance",
        "merge-file",
        "merge-tree",
        "mktag",
        "mktree",
        "multi-pack-index",
        "pack-objects",
        "patch-id",
        "pull",
        "read-tree",
        "replace",
        "request-pull",
        "rerere",
        "send-pack",
        "sparse-checkout",
        "stripspace",
        "update-index",
        "update-server-info",
        "upload-archive",
        "write-tree",
    }
)

_GIT_PROGRAMS = frozenset({"git", "git.exe", "git-cmd", "git-cmd.exe"})

_LONG_VALUE_OPTIONS = frozenset(
    {
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--exec-path",
        "--super-prefix",
        "--message",
        "--file",
        "--author",
        "--date",
        "--onto",
        "--strategy",
        "--strategy-option",
        "--depth",
        "--upload-pack",
        "--receive-pack",
        "--exclude",
        "--output",
        "--set-upstream-to",
        "--contains",
        "--format",
        "--pretty",
        "--grep",
        "--before",
        "--after",
        "--since",
        "--until",
        "--max-count",
        "--skip",
        "--repo",
        "--push-option",
        "--source",
        "--reference",
        "--points-at",
        "--merged",
        "--no-merged",
        "--sort",
        "--column",
        "--abbrev",
        "--cleanup",
        "--trailer",
        "--pathspec-from-file",
        "--type",
        "--state",
        "--branches",
        "--tags",
        "--remotes",
        "--glob",
        "--not",
        "--expire",
        "--expire-unreachable",
        "--template",
        "--name",
        "--path",
    }
)

_SHORT_VALUE_OPTIONS: dict[str, frozenset[str]] = {
    "*": frozenset(),
    "commit": frozenset({"-m", "-F", "-C", "-c", "-t"}),
    "tag": frozenset({"-m", "-F"}),
    "branch": frozenset({"-u"}),
    "checkout": frozenset({"-b", "-B", "-t", "-c"}),
    "switch": frozenset({"-c", "-C", "-t"}),
    "rebase": frozenset({"-X", "-x"}),
    "merge": frozenset({"-m", "-X", "-s"}),
    "log": frozenset({"-n"}),
    "diff": frozenset({"-n"}),
    "show": frozenset({"-n"}),
    "restore": frozenset({"-s"}),
    "clean": frozenset({"-e"}),
    "push": frozenset({"-o"}),
    "config": frozenset({"-f"}),
    "worktree": frozenset(),
    "reset": frozenset(),
}

_INLINE_CONFIG_RISK_KEYS: tuple[str, ...] = (
    "core.hookspath",
    "core.sshcommand",
    "commit.gpgsign",
    "user.email",
    "user.name",
    "protocol.file.allow",
    "url.",
    "credential.helper",
    "http.",
    "core.editor",
    "safe.directory",
)

_HOOK_BYPASS_CONFIG_KEYS: tuple[str, ...] = (
    "core.hookspath",
    "commit.gpgsign",
)

_DANGEROUS_LONG_OPTIONS: tuple[str, ...] = (
    "--force",
    "--force-with-lease",
    "--force-if-includes",
    "--delete",
    "--hard",
    "--merge",
    "--keep",
    "--all",
    "--mirror",
    "--tags",
    "--prune",
    "--discard-changes",
    "--in-place",
    "--recurse-submodules",
    "--no-verify",
    "--no-gpg-sign",
)

_KNOWN_LONG_OPTIONS: dict[str, frozenset[str]] = {
    "clean": frozenset(
        {"--force", "--dry-run", "--directories", "--ignored", "--exclude", "--quiet"}
    ),
    "push": frozenset(
        {
            "--force",
            "--force-with-lease",
            "--force-if-includes",
            "--delete",
            "--all",
            "--mirror",
            "--tags",
            "--dry-run",
            "--set-upstream",
            "--no-verify",
            "--atomic",
            "--prune",
            "--quiet",
            "--verbose",
            "--repo",
            "--push-option",
            "--follow-tags",
            "--progress",
            "--signed",
            "--no-signed",
        }
    ),
    "branch": frozenset(
        {
            "--delete",
            "--force",
            "--move",
            "--copy",
            "--list",
            "--all",
            "--remotes",
            "--verbose",
            "--contains",
            "--merged",
            "--no-merged",
            "--points-at",
            "--format",
            "--set-upstream-to",
            "--unset-upstream",
            "--track",
            "--no-track",
            "--quiet",
            "--sort",
            "--color",
            "--column",
            "--edit-description",
        }
    ),
    "reflog": frozenset({"delete", "expire", "show", "exists"}),
    "gc": frozenset(
        {
            "--prune",
            "--aggressive",
            "--auto",
            "--quiet",
            "--force",
            "--keep-largest-pack",
            "--cruft",
        }
    ),
    "restore": frozenset(
        {
            "--staged",
            "--worktree",
            "--source",
            "--ours",
            "--theirs",
            "--merge",
            "--ignore-unmerged",
            "--pathspec-from-file",
            "--quiet",
            "--overlay",
            "--no-overlay",
        }
    ),
    "switch": frozenset(
        {
            "--create",
            "--force-create",
            "--detach",
            "--force",
            "--discard-changes",
            "--merge",
            "--orphan",
            "--track",
            "--guess",
            "--no-guess",
            "--quiet",
            "--progress",
        }
    ),
    "checkout": frozenset(
        {
            "--force",
            "--ours",
            "--theirs",
            "--merge",
            "--detach",
            "--orphan",
            "--track",
            "--no-track",
            "--guess",
            "--no-guess",
            "--quiet",
            "--recurse-submodules",
            "--overlay",
            "--no-overlay",
            "--pathspec-from-file",
            "--conflict",
        }
    ),
    "reset": frozenset(
        {
            "--hard",
            "--soft",
            "--mixed",
            "--merge",
            "--keep",
            "--quiet",
            "--pathspec-from-file",
        }
    ),
    "stash": frozenset(
        {
            "--include-untracked",
            "--all",
            "--keep-index",
            "--staged",
            "--patch",
            "--quiet",
            "--message",
            "--index",
        }
    ),
    "worktree": frozenset(
        {
            "--force",
            "--detach",
            "--quiet",
            "--porcelain",
            "--expire",
            "--dry-run",
            "--verbose",
            "--track",
            "--no-track",
            "--lock",
            "--reason",
        }
    ),
    "tag": frozenset(
        {
            "--delete",
            "--force",
            "--list",
            "--annotate",
            "--message",
            "--sign",
            "--verify",
            "--contains",
            "--merged",
            "--points-at",
            "--sort",
            "--format",
            "--no-verify",
        }
    ),
}

_CONFIG_SENSITIVE_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "add",
        "am",
        "apply",
        "branch",
        "checkout",
        "cherry-pick",
        "clean",
        "clone",
        "commit",
        "fetch",
        "filter-branch",
        "gc",
        "init",
        "merge",
        "mv",
        "pull",
        "push",
        "rebase",
        "reflog",
        "reset",
        "restore",
        "revert",
        "rm",
        "stash",
        "submodule",
        "switch",
        "tag",
        "worktree",
    }
)

_UNKNOWN_LONG_MARKER = "__safegit_unknown_long_option__"


def _resolve_long_option_prefixes(
    flags: frozenset[str], subcommand: str
) -> frozenset[str]:
    """Resolve git's unambiguous long-option abbreviations.

    ``git clean --forc`` is accepted by git as ``--force``; matching only
    the literal spelling would classify it as harmless.  Unknown long
    options on risk-shaping subcommands are marked so the caller can
    escalate instead of guessing.
    """
    resolved: set[str] = set(flags)
    known = _KNOWN_LONG_OPTIONS.get(subcommand)
    for flag in flags:
        if not flag.startswith("--") or "=" in flag or len(flag) < 3:
            continue
        dangerous = [
            option for option in _DANGEROUS_LONG_OPTIONS if option.startswith(flag)
        ]
        if len(dangerous) == 1:
            resolved.add(dangerous[0])
        if known is not None and flag not in known:
            candidates = [option for option in known if option.startswith(flag)]
            if len(candidates) == 1:
                resolved.add(candidates[0])
            elif not candidates and not dangerous:
                resolved.add(_UNKNOWN_LONG_MARKER)
    return frozenset(resolved)


@dataclasses.dataclass(frozen=True)
class GitInvocation:
    """A single ``git`` execution resolved from a parsed command."""

    tokens: tuple[str, ...]
    cwd_hint: str | None
    git_dir_hint: str | None
    work_tree_hint: str | None
    config_overrides: tuple[tuple[str, str], ...]
    env_assignments: tuple[tuple[str, str], ...]
    raw: str
    nested_depth: int

    @property
    def argv(self) -> tuple[str, ...]:
        """Global options removed; starts with the subcommand."""
        return self.tokens

    def describe(self) -> str:
        return "git " + " ".join(self.tokens)


@dataclasses.dataclass(frozen=True)
class GitOp:
    rule_id: str
    subcommand: str
    flags: frozenset[str]
    positionals: tuple[str, ...]
    branch_hint: str | None
    path_hint: str | None
    refspecs: tuple[str, ...]
    invocation: GitInvocation
    detail: str = ""
    ambiguity: str = ""

    @property
    def rule_key(self) -> str:
        return self.rule_id

    @property
    def is_ambiguous(self) -> bool:
        return bool(self.ambiguity)


def is_git_program(token: str) -> bool:
    return shellparse.basename(token) in _GIT_PROGRAMS


def _split_global_options(tokens: list[str]) -> tuple[list[str], dict[str, object]]:
    extra: dict[str, object] = {
        "cwd": None,
        "git_dir": None,
        "work_tree": None,
        "config": [],
    }
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-C" and index + 1 < len(tokens):
            extra["cwd"] = tokens[index + 1]
            index += 2
            continue
        if token.startswith("-C") and len(token) > 2:
            extra["cwd"] = token[2:]
            index += 1
            continue
        if token == "--git-dir" and index + 1 < len(tokens):
            extra["git_dir"] = tokens[index + 1]
            index += 2
            continue
        if token.startswith("--git-dir="):
            extra["git_dir"] = token.split("=", 1)[1]
            index += 1
            continue
        if token == "--work-tree" and index + 1 < len(tokens):
            extra["work_tree"] = tokens[index + 1]
            index += 2
            continue
        if token.startswith("--work-tree="):
            extra["work_tree"] = token.split("=", 1)[1]
            index += 1
            continue
        if token == "-c" and index + 1 < len(tokens):
            pair = tokens[index + 1]
            if "=" in pair:
                key, _, value = pair.partition("=")
                extra["config"].append((key.lower(), value))  # type: ignore[union-attr]
            index += 2
            continue
        if token.startswith("--exec-path") or token.startswith("--namespace"):
            index += 2 if "=" not in token else 1
            continue
        if token in (
            "--no-pager",
            "--paginate",
            "-P",
            "--bare",
            "--no-replace-objects",
            "--literal-pathspecs",
            "--glob-pathspecs",
            "--noglob-pathspecs",
            "--icase-pathspecs",
            "--no-optional-locks",
            "--no-advice",
            "--version",
            "--help",
            "-h",
            "-v",
            "--html-path",
            "--man-path",
            "--info-path",
            "--list-cmds=main,others,alias,nohelpers",
        ):
            index += 1
            continue
        break
    return tokens[index:], extra


def resolve_invocations(parsed: shellparse.ParseResult) -> list[GitInvocation]:
    invocations: list[GitInvocation] = []
    for command in parsed.commands:
        if not command.argv or not is_git_program(command.argv[0]):
            continue
        rest, extra = _split_global_options(list(command.argv[1:]))
        if not rest:
            continue
        invocations.append(
            GitInvocation(
                tokens=tuple(rest),
                cwd_hint=extra["cwd"],  # type: ignore[arg-type]
                git_dir_hint=extra["git_dir"],  # type: ignore[arg-type]
                work_tree_hint=extra["work_tree"],  # type: ignore[arg-type]
                config_overrides=tuple(extra["config"]),  # type: ignore[arg-type]
                env_assignments=command.env_assignments,
                raw=command.raw,
                nested_depth=command.nested_depth,
            )
        )
    return invocations


def _parse_flags(
    tokens: Iterable[str], subcommand: str
) -> tuple[frozenset[str], list[str]]:
    short_values = _SHORT_VALUE_OPTIONS.get(subcommand, _SHORT_VALUE_OPTIONS["*"])
    flags: set[str] = set()
    positionals: list[str] = []
    seen_double_dash = False
    items = list(tokens)
    index = 0
    while index < len(items):
        token = items[index]
        if seen_double_dash:
            positionals.append(token)
            index += 1
            continue
        if token == "--":
            seen_double_dash = True
            flags.add("--")
            index += 1
            continue
        if token.startswith("--"):
            name, sep, _value = token.partition("=")
            flags.add(name)
            if sep:
                flags.add(token)
            elif name in _LONG_VALUE_OPTIONS and index + 1 < len(items):
                index += 1
            index += 1
            continue
        if token.startswith("-") and len(token) > 1 and not _is_negative_number(token):
            if token in short_values and index + 1 < len(items):
                flags.add(token)
                index += 2
                continue
            for char in token[1:]:
                flags.add("-" + char)
            flags.add(token)
            index += 1
            continue
        positionals.append(token)
        index += 1
    return _resolve_long_option_prefixes(frozenset(flags), subcommand), positionals


def _is_negative_number(token: str) -> bool:
    return bool(re.match(r"^-[0-9]+$", token))


def _flag_present(flags: frozenset[str], *names: str) -> bool:
    return any(name in flags for name in names)


def _first_branch(refspecs: tuple[str, ...]) -> str | None:
    for refspec in refspecs:
        candidate = refspec.lstrip("+")
        if candidate.startswith(":"):
            candidate = candidate[1:]
        if ":" in candidate:
            candidate = candidate.split(":", 1)[1]
        candidate = candidate.replace("refs/heads/", "").strip()
        if candidate and candidate != "HEAD":
            return candidate
    return None


def _branch_from_push_args(positionals: list[str]) -> str | None:
    if len(positionals) >= 2:
        return _first_branch(tuple(positionals[1:]))
    return None


def classify_all(invocation: GitInvocation) -> list[GitOp]:
    """Classify one git invocation into every matching operation rule."""
    tokens = list(invocation.tokens)
    subcommand = tokens[0]
    if subcommand == "help":
        return []
    flags, positionals = _parse_flags(tokens[1:], subcommand)
    ops: list[GitOp] = []

    def add(
        rule_id: str,
        *,
        branch_hint: str | None = None,
        path_hint: str | None = None,
        refspecs: tuple[str, ...] = (),
        detail: str = "",
        ambiguity: str = "",
    ) -> None:
        ops.append(
            GitOp(
                rule_id=rule_id,
                subcommand=subcommand,
                flags=flags,
                positionals=tuple(positionals),
                branch_hint=branch_hint,
                path_hint=path_hint,
                refspecs=refspecs,
                invocation=invocation,
                detail=detail,
                ambiguity=ambiguity,
            )
        )

    if invocation.git_dir_hint or invocation.work_tree_hint:
        add(RULE_REPO_OVERRIDE, detail="--git-dir/--work-tree redirects the repository")

    for key, value in invocation.config_overrides:
        normalized = key.lower()
        if subcommand not in _CONFIG_SENSITIVE_SUBCOMMANDS:
            continue
        if any(normalized.startswith(risk) for risk in _INLINE_CONFIG_RISK_KEYS):
            add(RULE_CONFIG_INLINE, detail="-c %s=%s" % (key, value))
        if any(normalized.startswith(risk) for risk in _HOOK_BYPASS_CONFIG_KEYS):
            if value.lower() in ("false", "0", "no", "nul", "/dev/null", ""):
                add(RULE_HOOK_BYPASS, detail="-c %s=%s" % (key, value))

    bypass_env = {
        "HUSKY",
        "SKIP_HUSKY",
        "GIT_HOOKS",
        "PRECOMMIT_ALLOW_NO_CONFIG",
        "GITLEAKS_ALLOW_NO_CONFIG",
    }
    for key, value in invocation.env_assignments:
        upper = key.upper()
        if (
            upper in bypass_env
            and value.strip() in ("0", "false", "off", "no")
            and subcommand in _CONFIG_SENSITIVE_SUBCOMMANDS
        ):
            add(RULE_HOOK_BYPASS, detail="env %s=%s" % (key, value))
        if upper.startswith("GIT_CONFIG_KEY_") or upper in (
            "GIT_CONFIG_COUNT",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
        ):
            add(RULE_REPO_OVERRIDE, detail="env %s" % key)

    if _UNKNOWN_LONG_MARKER in flags:
        add(
            RULE_OTHER,
            detail="unrecognised long option: %s"
            % ",".join(sorted(f for f in flags if f.startswith("--")))[:120],
        )

    if subcommand == "reset":
        if _flag_present(flags, "--hard"):
            add(RULE_RESET_HARD, detail="--hard discards uncommitted work")
        elif _flag_present(flags, "--merge", "--keep"):
            add(
                RULE_RESET_KEEP, detail="reset --merge/--keep can discard local changes"
            )
        else:
            add(RULE_NON_DESTRUCTIVE, detail="reset --soft/--mixed keeps the changes")

    elif subcommand == "clean":
        if _flag_present(flags, "-n", "--dry-run"):
            add(RULE_NON_DESTRUCTIVE, detail="clean --dry-run only previews")
        elif _flag_present(flags, "-f", "--force"):
            add(
                RULE_CLEAN_FORCE,
                detail="clean removes untracked files permanently",
            )
        else:
            add(RULE_NON_DESTRUCTIVE, detail="clean without --force does nothing")

    elif subcommand == "push":
        refspecs = tuple(p for p in positionals[1:] if p and not p.startswith("-"))
        broad = _flag_present(flags, "--all", "--mirror", "--tags")
        if _flag_present(flags, "-n", "--dry-run"):
            add(
                RULE_NON_DESTRUCTIVE, detail="push --dry-run does not change the remote"
            )
        elif _flag_present(flags, "-d", "--delete") or any(
            r.lstrip("+").startswith(":") for r in refspecs
        ):
            add(
                RULE_PUSH_DELETE,
                branch_hint=_first_branch(refspecs),
                refspecs=refspecs,
                detail="deletes a remote branch",
            )
        elif _flag_present(flags, "-f", "--force"):
            add(
                RULE_PUSH_FORCE,
                branch_hint=_first_branch(refspecs),
                refspecs=refspecs,
                detail="force push rewrites remote history",
            )
        elif _flag_present(flags, "--force-with-lease", "--force-if-includes"):
            add(
                RULE_PUSH_FORCE_LEASE,
                branch_hint=_first_branch(refspecs),
                refspecs=refspecs,
                detail="force-with-lease rewrites remote history when the lease matches",
            )
        elif any(r.startswith("+") for r in refspecs):
            add(
                RULE_PUSH_FORCE,
                branch_hint=_first_branch(refspecs),
                refspecs=refspecs,
                detail="+refspec forces the update",
            )
        else:
            if broad:
                add(RULE_PUSH_BROAD, detail="push --all/--mirror/--tags")
            add(
                RULE_PUSH_PLAIN,
                branch_hint=_branch_from_push_args(positionals),
                refspecs=refspecs,
            )
        if _flag_present(flags, "--no-verify"):
            add(RULE_HOOK_BYPASS, detail="--no-verify skips the pre-push hook")

    elif subcommand == "rebase":
        if _flag_present(
            flags, "--continue", "--abort", "--skip", "--quit", "--edit-todo"
        ):
            add(
                RULE_REBASE_CONTINUE, detail="continues or aborts an in-progress rebase"
            )
        else:
            add(RULE_REBASE, branch_hint=positionals[0] if positionals else None)

    elif subcommand == "commit":
        if _flag_present(flags, "--amend"):
            add(RULE_COMMIT_AMEND, detail="amend rewrites the last commit")
        else:
            add(RULE_COMMIT_PLAIN)
        if _flag_present(flags, "--no-verify", "-n"):
            add(RULE_HOOK_BYPASS, detail="commit --no-verify skips the pre-commit hook")
        if _flag_present(flags, "--no-gpg-sign"):
            add(RULE_HOOK_BYPASS, detail="commit --no-gpg-sign skips signing")

    elif subcommand == "worktree":
        action = positionals[0] if positionals else ""
        if action == "remove":
            add(
                RULE_WORKTREE_REMOVE,
                path_hint=positionals[1] if len(positionals) > 1 else None,
                detail="removes a worktree directory",
            )
        elif action == "prune":
            add(RULE_WORKTREE_PRUNE, detail="prunes worktree metadata")
        elif action in ("list", "add", "lock", "unlock", "move", "repair"):
            add(RULE_NON_DESTRUCTIVE, detail="worktree %s" % action)

    elif subcommand == "branch":
        if _flag_present(flags, "-D") or (
            _flag_present(flags, "--delete") and _flag_present(flags, "--force")
        ):
            add(
                RULE_BRANCH_DELETE_FORCE,
                branch_hint=positionals[0] if positionals else None,
                detail="branch -D deletes without a merge check",
            )
        elif _flag_present(flags, "-d", "--delete"):
            add(
                RULE_BRANCH_DELETE_SAFE,
                branch_hint=positionals[0] if positionals else None,
            )
        elif _flag_present(flags, "-m", "-M", "--move", "-c", "-C", "--copy"):
            add(
                RULE_BRANCH_RENAME,
                branch_hint=positionals[0] if positionals else None,
            )
        elif not positionals or _flag_present(
            flags,
            "-l",
            "--list",
            "-a",
            "--all",
            "-r",
            "--remotes",
            "-v",
            "--verbose",
            "--contains",
            "--merged",
            "--no-merged",
            "--points-at",
            "--format",
        ):
            add(RULE_NON_DESTRUCTIVE, detail="branch listing")

    elif subcommand in ("checkout", "switch"):
        path_like = [p for p in positionals if p in (".", "..", "*") or "*" in p]
        if _flag_present(flags, "--ours", "--theirs"):
            add(RULE_NON_DESTRUCTIVE, detail="conflict side selection during a merge")
        elif _flag_present(flags, "-f", "--force", "--discard-changes"):
            add(
                RULE_CHECKOUT_DISCARD,
                path_hint=positionals[-1] if positionals else ".",
                detail="forced checkout overwrites local files",
            )
        elif path_like or (subcommand == "checkout" and "--" in flags):
            add(
                RULE_CHECKOUT_DISCARD,
                path_hint=positionals[-1] if positionals else ".",
                detail="checkout of paths discards uncommitted edits",
            )
        elif positionals:
            target = positionals[0]
            add(
                RULE_CHECKOUT_DISCARD,
                path_hint=target,
                detail="checkout target may be a path or a branch",
                ambiguity="path_or_ref",
            )
        elif subcommand == "switch" and _flag_present(
            flags, "-c", "-C", "--create", "--force-create"
        ):
            add(RULE_NON_DESTRUCTIVE, detail="switch creates a branch")

    elif subcommand == "restore":
        staged_only = _flag_present(flags, "--staged") and not _flag_present(
            flags, "--worktree"
        )
        if staged_only:
            add(RULE_NON_DESTRUCTIVE, detail="restore --staged only unstages")
        elif positionals or _flag_present(flags, "--worktree", "--source", "-s"):
            add(
                RULE_RESTORE_WORKTREE,
                path_hint=positionals[-1] if positionals else ".",
                detail="restore of the worktree discards uncommitted edits",
            )
        else:
            add(RULE_OTHER, detail="restore without a target")

    elif subcommand == "add":
        if (
            _flag_present(flags, "-A", "--all", "-u", "--update")
            or "." in positionals
            or any(p.endswith(":/") for p in positionals)
        ):
            add(RULE_ADD_ALL, path_hint=".", detail="stages a broad path set")
        else:
            add(RULE_NON_DESTRUCTIVE, detail="add of explicit paths")

    elif subcommand == "stash":
        action = positionals[0] if positionals else ""
        if action in ("drop", "clear"):
            add(RULE_STASH_DESTROY, detail="deletes stashed work permanently")
        elif action in (
            "",
            "push",
            "save",
            "list",
            "show",
            "pop",
            "apply",
            "branch",
            "create",
            "store",
        ):
            add(RULE_NON_DESTRUCTIVE, detail="stash %s" % (action or "push"))

    elif subcommand in ("filter-branch", "filter-repo"):
        add(RULE_HISTORY_FILTER, detail="rewrites history")

    elif (
        subcommand == "reflog"
        and positionals
        and positionals[0] in ("expire", "delete")
    ):
        add(
            RULE_HISTORY_EXPIRE,
            detail="reflog %s removes recovery information" % positionals[0],
        )

    elif subcommand == "gc" and (
        _flag_present(flags, "--prune")
        or "--prune=now" in flags
        or _flag_present(flags, "--aggressive")
        or any(f.startswith("--prune=") for f in flags)
    ):
        add(RULE_HISTORY_EXPIRE, detail="aggressive gc can drop unreachable objects")

    elif subcommand == "gc":
        add(RULE_NON_DESTRUCTIVE, detail="routine gc")

    elif subcommand == "update-index" and _flag_present(flags, "--refresh"):
        add(
            RULE_NON_DESTRUCTIVE,
            detail="update-index --refresh only refreshes stat info",
        )

    elif subcommand in ("update-ref", "symbolic-ref", "pack-refs", "update-index"):
        add(RULE_REF_WRITE, detail="writes git refs or the index")

    elif subcommand == "config":
        if (
            _flag_present(
                flags,
                "--unset",
                "--unset-all",
                "--add",
                "--replace-all",
                "--edit",
                "-e",
                "--rename-section",
                "--remove-section",
                "--set",
            )
            or len(positionals) >= 2
        ):
            add(RULE_CONFIG_WRITE, detail="mutates git config")
        else:
            add(RULE_NON_DESTRUCTIVE, detail="git config read")

    elif (
        subcommand == "remote"
        and positionals
        and positionals[0]
        in (
            "add",
            "remove",
            "rm",
            "rename",
            "set-url",
            "set-branches",
            "prune",
            "update",
            "set-head",
        )
    ):
        add(RULE_REMOTE_CHANGE, detail="remote %s" % positionals[0])

    elif subcommand == "remote":
        add(RULE_NON_DESTRUCTIVE, detail="remote read")

    elif subcommand == "tag" and _flag_present(
        flags, "-d", "--delete", "-f", "--force"
    ):
        add(RULE_TAG_DELETE, detail="deletes or moves a tag")

    elif subcommand == "tag":
        add(RULE_NON_DESTRUCTIVE, detail="tag listing or creation")

    elif (
        subcommand == "submodule"
        and positionals
        and positionals[0]
        in (
            "deinit",
            "update",
            "add",
            "remove",
            "set-url",
            "sync",
            "absorbgitdirs",
        )
    ):
        add(RULE_SUBMODULE_CHANGE, detail="submodule %s" % positionals[0])

    elif subcommand == "submodule" and (
        not positionals
        or positionals[0] in ("status", "summary", "--quiet", "--cached")
    ):
        add(RULE_NON_DESTRUCTIVE, detail="submodule status")

    elif subcommand == "merge":
        add(RULE_MERGE, branch_hint=positionals[0] if positionals else None)

    elif subcommand == "rm":
        if _flag_present(flags, "--cached") and not _flag_present(
            flags, "-f", "--force"
        ):
            add(RULE_NON_DESTRUCTIVE, detail="rm --cached only unstages")
        else:
            add(RULE_RM_TRACKED, path_hint=positionals[-1] if positionals else None)

    elif subcommand == "update-index" and _flag_present(flags, "--refresh"):
        add(
            RULE_NON_DESTRUCTIVE,
            detail="update-index --refresh only refreshes stat info",
        )

    elif subcommand in ("cherry-pick", "revert", "init"):
        add(
            RULE_NON_DESTRUCTIVE,
            detail="%s adds commits without discarding work" % subcommand,
        )

    elif subcommand == "pull":
        if _flag_present(flags, "-r", "--rebase"):
            add(RULE_REBASE, detail="pull --rebase rewrites local commits")
        else:
            add(RULE_NON_DESTRUCTIVE, detail="pull integrates remote work")

    if not ops:
        if subcommand in READ_ONLY_SUBCOMMANDS:
            add(RULE_NON_DESTRUCTIVE, detail="read-only git subcommand")
        elif subcommand in _KNOWN_BUT_UNCLASSIFIED:
            add(RULE_OTHER, detail="git subcommand without a specific rule")
        else:
            add(RULE_OTHER, detail="unrecognised git subcommand")

    return ops


def classify(invocation: GitInvocation) -> GitOp:
    """Return the primary (first) operation rule of an invocation."""
    ops = classify_all(invocation)
    if not ops:
        return GitOp(
            rule_id=RULE_OTHER,
            subcommand=invocation.tokens[0] if invocation.tokens else "",
            flags=frozenset(),
            positionals=(),
            branch_hint=None,
            path_hint=None,
            refspecs=(),
            invocation=invocation,
            detail="no rule matched",
        )
    return ops[0]


def looks_like_ref_name(value: str) -> bool:
    return bool(value) and not value.startswith("-") and " " not in value
