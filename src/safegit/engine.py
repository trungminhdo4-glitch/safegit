"""The SafeGit decision engine.

``evaluate`` turns a normalised tool call plus repository state plus a
policy into an explicit verdict.  Design rules:

* the decision is deterministic: same inputs, same verdict;
* the decision is state-aware where state changes the answer (a branch that
  is already merged, a path with no local edits, a published commit);
* every finding carries a machine-readable reason code and evidence;
* an unresolvable input becomes UNKNOWN, never a silent ALLOW;
* in ``binding`` enforcement, UNKNOWN escalates to REQUIRE_OWNER - a human
  decides, and the result is still visible and machine-readable;
* no action here mutates the repository.

The engine never executes the action it judges.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import os
import posixpath
import re
import stat
from typing import Any

from . import adapters, approvals, gitop, gitstate, policy as policy_module, shellparse
from .verdicts import (
    ALLOW,
    DENY,
    REQUIRE_OWNER,
    UNKNOWN,
    most_restrictive,
)

REASON_ALLOW = "ALLOW_POLICY"
REASON_ALLOW_OWNER_APPROVED = "ALLOW_OWNER_APPROVED"
REASON_ALLOW_NO_LOCAL_CHANGES = "ALLOW_NO_LOCAL_CHANGES_AT_TARGET"
REASON_ALLOW_NO_EFFECT = "ALLOW_OPERATION_HAS_NO_EFFECT"
REASON_DENY_POLICY = "DENY_POLICY_RULE"
REASON_DENY_DATA_LOSS = "DENY_WOULD_DESTROY_LOCAL_WORK"
REASON_DENY_PUBLISHED_HISTORY = "DENY_WOULD_REWRITE_PUBLISHED_HISTORY"
REASON_DENY_PROTECTED_PATH = "DENY_PROTECTED_PATH_WRITE"
REASON_DENY_SECRET_PATH = "DENY_SECRET_PATH_WRITE"
REASON_DENY_REMOTE_COMMITS = "DENY_WOULD_REWRITE_REMOTE_COMMITS"
REASON_REQUIRE_OWNER = "REQUIRE_OWNER_POLICY_RULE"
REASON_REQUIRE_OWNER_BRANCH = "REQUIRE_OWNER_PROTECTED_BRANCH"
REASON_REQUIRE_OWNER_UNMERGED = "REQUIRE_OWNER_UNMERGED_BRANCH"
REASON_REQUIRE_OWNER_CI = "REQUIRE_OWNER_CI_CONFIGURATION"
REASON_UNKNOWN_PARSE = "UNKNOWN_COMMAND_NOT_FULLY_PARSED"
REASON_UNKNOWN_STATE = "UNKNOWN_REPOSITORY_STATE_UNAVAILABLE"
REASON_UNKNOWN_RULE = "UNKNOWN_OPERATION_NOT_CLASSIFIED"
REASON_UNKNOWN_PATH = "UNKNOWN_PATH_OR_BRANCH_UNRESOLVED"
REASON_UNKNOWN_NONINTERACTIVE = "UNKNOWN_REQUIRES_OWNER_BUT_NONINTERACTIVE"
REASON_OUT_OF_SCOPE = "OUT_OF_GUARDED_SCOPE"

_STATE_DEPENDENT_RULES: frozenset[str] = frozenset(
    {
        gitop.RULE_RESET_HARD,
        gitop.RULE_RESET_KEEP,
        gitop.RULE_CLEAN_FORCE,
        gitop.RULE_CHECKOUT_DISCARD,
        gitop.RULE_RESTORE_WORKTREE,
        gitop.RULE_BRANCH_DELETE_FORCE,
        gitop.RULE_BRANCH_DELETE_SAFE,
        gitop.RULE_COMMIT_AMEND,
        gitop.RULE_COMMIT_PLAIN,
        gitop.RULE_WORKTREE_REMOVE,
        gitop.RULE_PUSH_FORCE_LEASE,
        gitop.RULE_PUSH_PLAIN,
        gitop.RULE_PUSH_BROAD,
        gitop.RULE_PUSH_DELETE,
        gitop.RULE_STASH_DESTROY,
        gitop.RULE_ADD_ALL,
        gitop.RULE_REBASE,
    }
)

_WRITE_VERBS: tuple[str, ...] = (
    "set-content",
    "add-content",
    "clear-content",
    "out-file",
    "remove-item",
    "move-item",
    "rename-item",
    "copy-item",
    "new-item",
    "del",
    "erase",
    "rm",
    "rmdir",
    "mv",
    "cp",
    "ren",
    "tee",
    "truncate",
    "dd",
    "touch",
    "install",
    "sed",
    "chmod",
    "chown",
)

_READ_VERBS: frozenset[str] = frozenset(
    {
        "get-content",
        "get-item",
        "get-filehash",
        "test-path",
        "select-string",
        "type",
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "ls",
        "dir",
        "get-childitem",
        "stat",
        "file",
        "wc",
        "grep",
        "rg",
        "find",
        "findstr",
    }
)

_ALTERNATIVES: dict[str, str] = {
    gitop.RULE_RESET_HARD: "commit or stash first, or use 'git reset --soft' to keep changes staged",
    gitop.RULE_CLEAN_FORCE: "preview with 'git clean -n' and remove specific paths instead",
    gitop.RULE_CHECKOUT_DISCARD: "stash the changes first, or restore a single file you inspected",
    gitop.RULE_RESTORE_WORKTREE: "use 'git restore --staged <path>' to unstage without losing edits",
    gitop.RULE_STASH_DESTROY: "apply or export the stash before dropping it",
    gitop.RULE_PUSH_FORCE: "use 'git push --force-with-lease', or open a pull request",
    gitop.RULE_PUSH_FORCE_LEASE: "push normal commits, or ask the owner to approve the rewrite",
    gitop.RULE_BRANCH_DELETE_FORCE: "merge the branch first, or use 'git branch -d'",
    gitop.RULE_COMMIT_AMEND: "create an additional commit instead of rewriting one",
    gitop.RULE_REBASE: "merge instead of rebasing, or ask the owner to approve the rebase",
    gitop.RULE_HISTORY_FILTER: "rewriting history is irreversible; ask the owner to approve it",
    gitop.RULE_HISTORY_EXPIRE: "leave the reflog intact so work stays recoverable",
    gitop.RULE_WORKTREE_REMOVE: "commit the worktree changes first",
    gitop.RULE_ADD_ALL: "stage explicit paths instead of everything",
    gitop.RULE_HOOK_BYPASS: "let the configured hooks run; do not bypass verification",
    policy_module.FS_PROTECTED_WRITE: "edit the file as the owner, outside of the agent session",
    policy_module.FS_SECRET_WRITE: "never write credentials from an agent session",
    policy_module.FS_CI_WRITE: "ask the owner to change CI configuration",
}


@dataclasses.dataclass
class Finding:
    rule_id: str
    verdict: str
    reason_code: str
    message: str
    action: str
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    limitations: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "verdict": self.verdict,
            "reason_code": self.reason_code,
            "message": self.message,
            "action": self.action,
            "evidence": dict(self.evidence),
            "limitations": list(self.limitations),
        }


@dataclasses.dataclass
class Decision:
    verdict: str
    reason_code: str
    findings: list[Finding]
    evidence: dict[str, Any]
    limitations: list[str]
    policy_profile: str
    policy_digest: str
    enforcement: str
    tool_name: str
    approved_rule: str = ""
    approval_id: str = ""
    out_of_scope: bool = False

    @property
    def blocked(self) -> bool:
        return self.verdict != ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "safegit.decision/1",
            "verdict": self.verdict,
            "reason_code": self.reason_code,
            "tool_name": self.tool_name,
            "policy_profile": self.policy_profile,
            "policy_digest": self.policy_digest,
            "enforcement": self.enforcement,
            "out_of_scope": self.out_of_scope,
            "approved_rule": self.approved_rule,
            "approval_id": self.approval_id,
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence": dict(self.evidence),
            "limitations": list(self.limitations),
        }


@dataclasses.dataclass
class EngineContext:
    cwd: str
    policy: policy_module.Policy
    git_executable: str = "git"
    timeout: float = gitstate.DEFAULT_TIMEOUT_SECONDS
    approval_store: str = ""
    check_approvals: bool = True
    state_cache: dict[str, gitstate.RepoState] = dataclasses.field(default_factory=dict)

    @property
    def store_path(self) -> Any:
        if self.approval_store:
            import pathlib

            return pathlib.Path(self.approval_store)
        return None


MAX_PATH_TOKENS = 200
MAX_TOKEN_CHARS = 260
MAX_PATH_PATTERNS = 200
# Always case-insensitive (fail closed): Windows and default macOS volumes treat `.ENV` and
# `.env` as the same file, and the same policy must not allow it on one OS but deny it on another.
_CASE_INSENSITIVE_MATCHING = True


def _split_parts(value: str) -> list[str]:
    return [
        part for part in value.replace("\\", "/").split("/") if part not in ("", ".")
    ]


def _match_glob(relative: str, absolute: str, pattern: str) -> bool:
    """Match a repo-relative or absolute path against a glob pattern.

    ``**`` matches zero or more path segments (so ``**/.env`` matches both
    ``.env`` and ``config/.env``).  A pattern without a slash matches any
    path segment, which is the common expectation for ``*.pem``.

    The matcher is linear in the number of path segments: it never expands
    candidate suffixes, because an attacker who can choose the command can
    otherwise choose a path that makes the gate exceed its host timeout.
    """
    if not pattern or len(pattern) > 512:
        return False
    rel = relative.replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]
    abs_posix = absolute.replace("\\", "/")
    if abs_posix.startswith("./"):
        abs_posix = abs_posix[2:]
    candidates = [rel, abs_posix]
    if not abs_posix.startswith("/"):
        candidates.append("/" + abs_posix)

    variants = {pattern.replace("\\", "/")}
    while True:
        expanded = set()
        for variant in variants:
            if variant.startswith("**/"):
                expanded.add(variant[3:])
            if variant.startswith("./"):
                expanded.add(variant[2:])
            if variant.startswith("/"):
                expanded.add(variant[1:])
        new_variants = expanded - variants
        if not new_variants:
            break
        variants |= new_variants
    if "/" not in pattern:
        variants.add("**/" + pattern)

    for variant in variants:
        pattern_parts = _split_parts(variant)
        if not pattern_parts:
            continue
        for candidate in candidates:
            if _glob_segments_match(_split_parts(candidate), pattern_parts):
                return True
    return False


def _glob_segments_match(path_parts: list[str], pattern_parts: list[str]) -> bool:
    if _CASE_INSENSITIVE_MATCHING:
        path_parts = [part.lower() for part in path_parts]
        pattern_parts = [part.lower() for part in pattern_parts]
    return _glob_segments_match_exact(path_parts, pattern_parts)


def _glob_segments_match_exact(path_parts: list[str], pattern_parts: list[str]) -> bool:
    if not pattern_parts:
        return not path_parts
    head = pattern_parts[0]
    rest = pattern_parts[1:]
    if head == "**":
        for index in range(len(path_parts) + 1):
            if _glob_segments_match_exact(path_parts[index:], rest):
                return True
        return False
    if not path_parts:
        return False
    if not fnmatch.fnmatchcase(path_parts[0], head):
        return False
    return _glob_segments_match_exact(path_parts[1:], rest)


def _relative_to(path: str, root: str) -> tuple[str, bool]:
    """Relativise ``path`` against ``root``; a lexical match wins, otherwise both are resolved.

    git reports the resolved toplevel, while the agent may name the same directory through an
    alias (a symlink such as macOS ``/var`` -> ``/private/var``, or a Windows 8.3 short name
    such as ``RUNNER~1``).  Without resolving, such a path looks outside the repository and
    repo-relative rules (``.git/**``, ``.github/workflows/**``) never match it.
    """
    if not root:
        return path, False
    for resolve in (os.path.abspath, os.path.realpath):
        try:
            candidate = os.path.normcase(resolve(path))
            root_key = os.path.normcase(resolve(root))
        except (OSError, ValueError):
            continue
        if candidate == root_key:
            return ".", True
        prefix = root_key.rstrip("\\/") + os.sep
        if candidate.startswith(prefix):
            return candidate[len(prefix) :], True
    return path, False


def _path_views(
    absolute: str, relative: str, root: str
) -> list[tuple[str, str]]:
    """Return every ``(relative, absolute)`` spelling of a target that policy globs must see.

    The lexical spelling comes first.  The resolved spellings follow: ``realpath`` sees through
    a symlink inside the repository (``link/config`` with ``link`` -> ``.git``), and a walk over
    the resolved ancestors finds the repository root by file identity, which also covers a
    case-variant spelling of the root on a case-insensitive volume that ``realpath`` leaves
    as written.  File identity never folds case itself, so a case-sensitive volume is unaffected.
    Callers deny when any view matches; the views never decide whether a target is inside the
    repository.
    """
    views = [(relative, absolute)]
    try:
        resolved = os.path.realpath(absolute)
    except (OSError, ValueError):
        return views
    resolved_relative, _ = _relative_to(resolved, root)
    views.append((resolved_relative, resolved))
    if not root:
        return views
    try:
        root_stat = os.stat(root)
    except (OSError, ValueError):
        return views
    if not root_stat.st_ino:
        # No file identity on this volume (some FAT/network mounts): every directory would match.
        return views
    current = resolved
    tail: list[str] = []
    while True:
        try:
            if os.path.samestat(os.stat(current), root_stat):
                views.append((os.path.join(*reversed(tail)) if tail else ".", resolved))
                break
        except (OSError, ValueError):
            pass
        parent, name = os.path.split(current)
        if parent == current:
            break
        tail.append(name)
        current = parent
    return views


def _views_match(views: list[tuple[str, str]], patterns: Any) -> bool:
    return any(
        _match_glob(relative, absolute, pattern)
        for relative, absolute in views
        for pattern in patterns
    )


def _views_match_secret(views: list[tuple[str, str]], patterns: Any) -> bool:
    """A view is a secret unless that same view is allowlisted (a symlinked template is not)."""
    return any(
        not _views_match([view], policy_module.SECRET_PATH_ALLOWLIST)
        and _views_match([view], patterns)
        for view in views
    )


def _state_for(ctx: EngineContext, directory: str) -> gitstate.RepoState:
    return gitstate.probe(
        directory,
        timeout=ctx.timeout,
        git_executable=ctx.git_executable,
        cache=ctx.state_cache,
    )


def _state_for_path(ctx: EngineContext, path: str) -> gitstate.RepoState:
    """Probe the repository that owns ``path``.

    A write target usually does not exist yet, and neither may its parent
    directories, so we walk up to the nearest existing directory.  A ``.git``
    directory is never used as the probe root: probing inside it resolves the
    wrong toplevel, which would silently mis-relativise every later path
    comparison.
    """
    candidate = os.path.abspath(path)
    if os.path.isfile(candidate):
        candidate = os.path.dirname(candidate)
    while candidate and not os.path.isdir(candidate):
        parent = os.path.dirname(candidate)
        if parent == candidate:
            break
        candidate = parent
    candidate = _outside_git_dir(candidate)
    return _state_for(ctx, candidate or ctx.cwd)


def _outside_git_dir(directory: str) -> str:
    """Cut ``directory`` at its first ``.git`` component, lexical or resolved.

    git finds no toplevel from ``.git/hooks``, nor from an in-repo symlink to ``.git``; the
    repository root would then be empty and repo-relative rules such as ``.git/**`` never match.
    """
    if not directory:
        return directory
    spellings = [directory]
    try:
        spellings.append(os.path.realpath(directory))
    except (OSError, ValueError):
        pass
    for spelling in spellings:
        current = spelling
        cut = ""
        while True:
            parent, name = os.path.split(current)
            if name.lower() == ".git":
                cut = parent
            if not name or parent == current:
                break
            current = parent
        if cut:
            return cut
    return directory


def _is_link(path: str) -> bool:
    """True for a symlink, and on Windows for any reparse point (junctions included)."""
    try:
        info = os.lstat(path)
    except (OSError, ValueError):
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _link_escape(ctx: EngineContext, absolute: str) -> tuple[str, str]:
    """Return ``(repository root, resolved target)`` when a link inside a repository leads out.

    ``absolute`` may sit lexically inside a repository while a symlink or junction on its way
    (``link/new.txt`` with ``link`` -> ``/elsewhere``) puts the physical target outside.  Each
    link along the path is checked against the repository that contains it.  The root is empty
    when no link escapes; the resolved target is empty when the path cannot be resolved, which
    callers must treat as outside.  This is a pre-execution check, not filesystem isolation: a
    link created or retargeted after the decision is not seen.
    """
    try:
        resolved = os.path.realpath(absolute)
    except (OSError, ValueError):
        resolved = ""
    current = absolute
    while True:
        if _is_link(current):
            state = _state_for(ctx, _outside_git_dir(os.path.dirname(current)))
            if state.available and state.root:
                try:
                    os.stat(current)
                    target = resolved
                except FileNotFoundError:
                    target = resolved  # dangling: realpath still names where it points
                except (OSError, ValueError):
                    target = ""  # a link loop or an unreadable link
                if not target or not _relative_to(target, state.root)[1]:
                    return state.root, target
        parent = os.path.dirname(current)
        if parent == current:
            return "", resolved
        current = parent


def _push_branch(op: gitop.GitOp, state: gitstate.RepoState) -> str:
    if op.branch_hint:
        return op.branch_hint
    if state.branch:
        return state.branch
    if state.upstream:
        return state.upstream.split("/", 1)[-1]
    return ""


def _is_protected_branch(branch: str, policy: policy_module.Policy) -> bool:
    if not branch:
        return False
    for pattern in policy.protected_branches:
        if fnmatch.fnmatch(branch, pattern):
            return True
    return False


def _has_redirect_target(segment: str) -> bool:
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(segment):
        char = segment[index]
        if quote:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            index += 1
            continue
        if char == ">":
            depth += 1
            index += 1
            continue
        index += 1
    return depth > 0


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

_QUOTED_SUBSTRING_RE = re.compile(r"['\"]([^'\"\n]{2,200})['\"]")


def _path_anchors(policy: policy_module.Policy) -> list[tuple[str, str]]:
    """Return ``(rule_id, literal_anchor)`` pairs for opaque-command scanning.

    An interpreter body such as ``pathlib.Path('.safegit/p.json').unlink()``
    is not a path token, so glob matching cannot see it.  The literal part of
    each policy pattern (``.safegit/p.json`` -> ``.safegit``) is used as a
    substring anchor instead, which is what makes the check survive
    interpreter indirection.
    """
    anchors: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    groups = (
        (policy_module.FS_PROTECTED_WRITE, policy.protected_paths),
        (policy_module.FS_SECRET_WRITE, policy.secret_paths),
        (policy_module.FS_CI_WRITE, policy.ci_paths),
    )
    for rule_id, patterns in groups:
        for pattern in patterns:
            literal_parts = [
                part
                for part in pattern.replace("\\", "/").split("/")
                if part
                and part not in ("**", "*", ".")
                and not any(ch in part for ch in "*?[")
            ]
            if not literal_parts:
                continue
            anchor = "/".join(literal_parts).lower()
            if len(anchor) < 4:
                continue
            key = (rule_id, anchor)
            if key in seen:
                continue
            seen.add(key)
            anchors.append(key)
    return anchors


def _anchor_findings(
    command: str,
    *,
    policy: policy_module.Policy,
    writes: bool,
    reporoot: str,
) -> list[Finding]:
    if not writes or not command:
        return []
    haystack = command.replace("\\", "/").lower()
    findings: list[Finding] = []
    for rule_id, anchor in _path_anchors(policy):
        if anchor not in haystack:
            continue
        verdict = policy.rule_verdict(rule_id)
        if rule_id == policy_module.FS_SECRET_WRITE and any(
            _match_glob(anchor, anchor, allowed)
            for allowed in policy_module.SECRET_PATH_ALLOWLIST
        ):
            continue
        findings.append(
            Finding(
                rule_id=rule_id,
                verdict=verdict,
                reason_code={
                    policy_module.FS_SECRET_WRITE: REASON_DENY_SECRET_PATH,
                    policy_module.FS_CI_WRITE: REASON_REQUIRE_OWNER_CI,
                }.get(rule_id, REASON_DENY_PROTECTED_PATH),
                message="Command text references a guarded path (%s) from an interpreter or writer"
                % anchor,
                action=command[:MAX_TOKEN_CHARS],
                evidence={"anchor": anchor, "inside_repo": bool(reporoot)},
                limitations=["OPAQUE_COMMAND_PATH_SCAN_IS_ANCHOR_BASED"],
            )
        )
        if verdict == DENY:
            break
    return findings


def _write_indicators(parsed: shellparse.ParseResult, segment: str) -> bool:
    """Return True when the command may modify files.

    Conservative by construction: an interpreter invocation counts as a
    possible write, because the file APIs it can reach are not visible in
    the command line.  A false "may write" only costs a more careful look
    at the path; a false "read only" would silently disable path
    protection.
    """
    if _has_redirect_target(segment):
        return True
    for command in parsed.commands:
        program = shellparse.basename(command.argv[0])
        if program in _WRITE_VERBS:
            return True
        if program in _INTERPRETER_PROGRAMS:
            return True
    return False


def _command_path_tokens(parsed: shellparse.ParseResult) -> list[str]:
    """Extract path-like tokens, including paths inside interpreter bodies."""
    tokens: list[str] = []
    for command in parsed.commands:
        program = shellparse.basename(command.argv[0]) if command.argv else ""
        for token in command.argv[1:]:
            if token.startswith("-"):
                continue
            if any(sep in token for sep in ("/", "\\", ".")):
                tokens.append(token)
            if program in _INTERPRETER_PROGRAMS and len(token) > 4:
                for quoted in _QUOTED_SUBSTRING_RE.findall(token):
                    if any(sep in quoted for sep in ("/", "\\", ".")):
                        tokens.append(quoted)
            if len(tokens) >= MAX_PATH_TOKENS:
                return tokens[:MAX_PATH_TOKENS]
    return [token[:MAX_TOKEN_CHARS] for token in tokens[:MAX_PATH_TOKENS]]


def _evaluate_path_findings(
    parsed: shellparse.ParseResult,
    raw: str,
    *,
    ctx: EngineContext,
    reporoot: str,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    policy = ctx.policy
    tokens = _command_path_tokens(parsed)
    writes = _write_indicators(parsed, raw)
    findings.extend(
        _anchor_findings(raw, policy=policy, writes=writes, reporoot=reporoot)
    )
    if not tokens:
        return findings, warnings
    for token in tokens:
        absolute = token if os.path.isabs(token) else os.path.join(ctx.cwd, token)
        relative, inside = _relative_to(absolute, reporoot)
        views = _path_views(absolute, relative, reporoot)
        if _views_match_secret(views, policy.secret_paths):
            if writes:
                findings.append(
                    Finding(
                        rule_id=policy_module.FS_SECRET_WRITE,
                        verdict=policy.rule_verdict(policy_module.FS_SECRET_WRITE),
                        reason_code=REASON_DENY_SECRET_PATH,
                        message="Command writes to a secret-bearing path: %s" % token,
                        action=raw,
                        evidence={"path": token, "inside_repo": inside},
                        limitations=["SECRET_PATH_MATCH_IS_PATTERN_BASED"],
                    )
                )
            continue
        if _views_match(views, policy.ci_paths):
            if writes:
                findings.append(
                    Finding(
                        rule_id=policy_module.FS_CI_WRITE,
                        verdict=policy.rule_verdict(policy_module.FS_CI_WRITE),
                        reason_code=REASON_REQUIRE_OWNER_CI,
                        message="Command modifies CI configuration: %s" % token,
                        action=raw,
                        evidence={"path": token, "inside_repo": inside},
                    )
                )
            continue
        if _views_match(views, policy.protected_paths):
            if writes:
                findings.append(
                    Finding(
                        rule_id=policy_module.FS_PROTECTED_WRITE,
                        verdict=policy.rule_verdict(policy_module.FS_PROTECTED_WRITE),
                        reason_code=REASON_DENY_PROTECTED_PATH,
                        message="Command writes to a protected path: %s" % token,
                        action=raw,
                        evidence={"path": token, "inside_repo": inside},
                    )
                )
            else:
                warnings.append("PROTECTED_PATH_REFERENCED_READ_ONLY:%s" % token)
        if any(finding.verdict == DENY for finding in findings):
            break
    return findings, warnings


def _evaluate_file_action(
    action: adapters.FileAction, *, ctx: EngineContext
) -> tuple[list[Finding], list[str]]:
    policy = ctx.policy
    absolute = (
        action.path
        if os.path.isabs(action.path)
        else os.path.join(action.cwd or ctx.cwd, action.path)
    )
    state = _state_for_path(ctx, absolute)
    reporoot = state.root if state.available else ""
    relative, inside = _relative_to(absolute, reporoot)
    findings: list[Finding] = []
    limitations: list[str] = []
    escaped_root, resolved = _link_escape(ctx, absolute)
    if escaped_root:
        reporoot = reporoot or escaped_root
        inside = False
    if reporoot and not inside and policy.allowed_repo_roots:
        for allowed in policy.allowed_repo_roots:
            allowed_abs = (
                allowed if os.path.isabs(allowed) else os.path.join(reporoot, allowed)
            )
            if _relative_to(absolute, allowed_abs)[1] and (
                bool(resolved) and _relative_to(resolved, allowed_abs)[1]
            ):
                inside = True
                relative, _ = _relative_to(absolute, allowed_abs)
                break
    if (
        reporoot
        and not inside
        and policy.rule_verdict(policy_module.FS_REPO_ESCAPE_WRITE) != ALLOW
    ):
        findings.append(
            Finding(
                rule_id=policy_module.FS_REPO_ESCAPE_WRITE,
                verdict=policy.rule_verdict(policy_module.FS_REPO_ESCAPE_WRITE),
                reason_code=REASON_DENY_POLICY,
                message="Write target is outside the repository: %s" % action.path,
                action=action.path,
                evidence={"path": action.path, "repo_root": reporoot},
            )
        )
        return findings, limitations

    views = _path_views(absolute, relative, reporoot)
    if _views_match_secret(views, policy.secret_paths):
        findings.append(
            Finding(
                rule_id=policy_module.FS_SECRET_WRITE,
                verdict=policy.rule_verdict(policy_module.FS_SECRET_WRITE),
                reason_code=REASON_DENY_SECRET_PATH,
                message="%s of a secret-bearing path is not permitted: %s"
                % (action.mode, action.path),
                action=action.path,
                evidence={"path": action.path, "mode": action.mode},
                limitations=["SECRET_PATH_MATCH_IS_PATTERN_BASED"],
            )
        )
        return findings, limitations
    if _views_match(views, policy.ci_paths):
        findings.append(
            Finding(
                rule_id=policy_module.FS_CI_WRITE,
                verdict=policy.rule_verdict(policy_module.FS_CI_WRITE),
                reason_code=REASON_REQUIRE_OWNER_CI,
                message="Modifying CI configuration requires the owner: %s"
                % action.path,
                action=action.path,
                evidence={"path": action.path, "mode": action.mode},
            )
        )
        return findings, limitations
    if _views_match(views, policy.protected_paths):
        findings.append(
            Finding(
                rule_id=policy_module.FS_PROTECTED_WRITE,
                verdict=policy.rule_verdict(policy_module.FS_PROTECTED_WRITE),
                reason_code=REASON_DENY_PROTECTED_PATH,
                message="Modifying a protected path is not permitted: %s" % action.path,
                action=action.path,
                evidence={"path": action.path, "mode": action.mode},
            )
        )
        return findings, limitations
    if reporoot and not inside:
        limitations.append("WRITE_OUTSIDE_REPOSITORY_NOT_GUARDED")
    findings.append(
        Finding(
            rule_id=policy_module.FS_OTHER_WRITE,
            verdict=policy.rule_verdict(policy_module.FS_OTHER_WRITE),
            reason_code=REASON_ALLOW,
            message="Write inside the repository is allowed by policy",
            action=action.path,
            evidence={"path": action.path, "mode": action.mode},
        )
    )
    return findings, limitations


def _op_finding(
    op: gitop.GitOp,
    *,
    ctx: EngineContext,
    state: gitstate.RepoState,
) -> tuple[list[Finding], list[str]]:
    policy = ctx.policy
    rule = op.rule_id
    verdict = policy.rule_verdict(rule)
    limitations: list[str] = []
    findings: list[Finding] = []
    evidence: dict[str, Any] = {"subcommand": op.subcommand}
    reason = (
        REASON_ALLOW
        if verdict == ALLOW
        else (REASON_DENY_POLICY if verdict == DENY else REASON_REQUIRE_OWNER)
    )
    detail = op.detail

    def emit(
        *,
        final_verdict: str = verdict,
        final_reason: str = reason,
        final_detail: str = detail,
        extra: dict[str, Any] | None = None,
        rule_override: str = "",
    ) -> None:
        merged = dict(evidence)
        if extra:
            merged.update(extra)
        findings.append(
            Finding(
                rule_id=rule_override or rule,
                verdict=final_verdict,
                reason_code=final_reason,
                message=_message_for(rule, final_detail, final_verdict),
                action=op.invocation.describe(),
                evidence=merged,
            )
        )

    if rule in (gitop.RULE_RESET_HARD, gitop.RULE_RESET_KEEP, gitop.RULE_CLEAN_FORCE):
        if state.available:
            at_risk = (
                state.unstaged + state.staged
                if rule != gitop.RULE_CLEAN_FORCE
                else state.untracked + state.unstaged
            )
            evidence["work_at_risk"] = at_risk
            evidence["untracked"] = state.untracked
            emit(
                final_reason=REASON_DENY_DATA_LOSS if at_risk else reason,
                extra={"data_loss_confirmed": at_risk > 0},
            )
        else:
            emit()
            limitations.append(REASON_UNKNOWN_STATE)

    elif rule in (gitop.RULE_CHECKOUT_DISCARD, gitop.RULE_RESTORE_WORKTREE):
        target = op.path_hint or (op.positionals[-1] if op.positionals else ".")
        forced = bool(op.flags & {"-f", "--force", "--discard-changes"})
        if forced and state.available:
            evidence["target"] = target
            evidence["work_in_progress"] = state.work_in_progress
            if state.work_in_progress == 0:
                emit(
                    final_verdict=ALLOW,
                    final_reason=REASON_ALLOW_NO_LOCAL_CHANGES,
                    final_detail="forced checkout with a clean working tree",
                )
            else:
                emit(
                    final_verdict=DENY,
                    final_reason=REASON_DENY_DATA_LOSS,
                    final_detail="forced checkout of %s discards the whole working tree (%d file(s))"
                    % (target, state.work_in_progress),
                )
            return findings, limitations
        if op.ambiguity == "path_or_ref" and state.available:
            resolved = gitstate.resolve_path_or_ref(
                state, target, timeout=ctx.timeout, git_executable=ctx.git_executable
            )
            evidence["target_resolution"] = resolved
            if resolved == "ref":
                if forced:
                    evidence["target"] = target
                    evidence["work_in_progress"] = state.work_in_progress
                    if state.work_in_progress == 0:
                        emit(
                            final_verdict=ALLOW,
                            final_reason=REASON_ALLOW_NO_LOCAL_CHANGES,
                            final_detail="branch checkout with a clean working tree",
                        )
                    else:
                        emit(
                            final_verdict=DENY,
                            final_reason=REASON_DENY_DATA_LOSS,
                            final_detail="forced checkout of %s discards the whole working tree (%d file(s))"
                            % (target, state.work_in_progress),
                        )
                    return findings, limitations
                emit(
                    final_verdict=policy.rule_verdict(gitop.RULE_CHECKOUT_SWITCH),
                    final_reason=REASON_ALLOW,
                    final_detail="resolved to a branch, not a path",
                    extra={"target": target},
                    rule_override=gitop.RULE_CHECKOUT_SWITCH,
                )
                return findings, limitations
            if resolved == "unknown":
                emit(final_verdict=UNKNOWN, final_reason=REASON_UNKNOWN_PATH)
                return findings, limitations
        if forced and state.available:
            evidence["target"] = target
            evidence["work_in_progress"] = state.work_in_progress
            if state.work_in_progress == 0:
                emit(
                    final_verdict=ALLOW,
                    final_reason=REASON_ALLOW_NO_LOCAL_CHANGES,
                    final_detail="forced checkout with a clean working tree",
                )
                return findings, limitations
        if state.available and target not in (".", "..", "*"):
            dirty = _path_has_local_changes(ctx, state, target)
            evidence["target"] = target
            evidence["local_changes_at_target"] = dirty
            if dirty == 0:
                emit(
                    final_verdict=ALLOW,
                    final_reason=REASON_ALLOW_NO_LOCAL_CHANGES,
                    final_detail="no local changes at %s" % target,
                )
                return findings, limitations
            if dirty < 0:
                limitations.append("PATH_DIRT_CHECK_UNAVAILABLE")
        emit()

    elif rule == gitop.RULE_BRANCH_DELETE_FORCE:
        branch = op.branch_hint or (op.positionals[0] if op.positionals else "")
        if state.available and branch:
            if not gitstate.branch_exists(
                state, branch, timeout=ctx.timeout, git_executable=ctx.git_executable
            ):
                emit(
                    final_verdict=ALLOW,
                    final_reason=REASON_ALLOW_NO_EFFECT,
                    final_detail="branch %s does not exist" % branch,
                    extra={"branch": branch},
                )
                return findings, limitations
            unmerged = gitstate.unmerged_commit_count(
                state, branch, timeout=ctx.timeout, git_executable=ctx.git_executable
            )
            evidence["branch"] = branch
            evidence["unmerged_commits"] = unmerged
            if unmerged == 0:
                emit(
                    final_verdict=ALLOW,
                    final_reason=REASON_ALLOW_NO_LOCAL_CHANGES,
                    final_detail="branch %s is fully merged into HEAD" % branch,
                )
                return findings, limitations
            if unmerged > 0:
                emit(
                    final_verdict=REQUIRE_OWNER,
                    final_reason=REASON_REQUIRE_OWNER_UNMERGED,
                    final_detail="branch %s has %d unmerged commit(s)"
                    % (branch, unmerged),
                )
                return findings, limitations
        emit()

    elif rule == gitop.RULE_COMMIT_AMEND:
        if state.available:
            published = gitstate.revision_is_published(
                state, "HEAD", timeout=ctx.timeout, git_executable=ctx.git_executable
            )
            evidence["head_published"] = published
            if published == 1:
                emit(
                    final_verdict=DENY,
                    final_reason=REASON_DENY_PUBLISHED_HISTORY,
                    final_detail="HEAD is already published on a remote",
                )
                return findings, limitations
            if published < 0:
                limitations.append("PUBLISHED_STATE_UNAVAILABLE")
                emit(final_verdict=REQUIRE_OWNER)
                return findings, limitations
        emit()

    elif rule == gitop.RULE_WORKTREE_REMOVE:
        target = op.path_hint or ""
        if state.available and target:
            absolute = (
                target if os.path.isabs(target) else os.path.join(ctx.cwd, target)
            )
            dirty = _path_has_local_changes(ctx, state, absolute)
            evidence["worktree"] = target
            evidence["worktree_dirty_files"] = dirty
            if dirty > 0:
                emit(
                    final_verdict=DENY,
                    final_reason=REASON_DENY_DATA_LOSS,
                    final_detail="worktree %s has %d uncommitted file(s)"
                    % (target, dirty),
                )
                return findings, limitations
            if dirty < 0:
                limitations.append("WORKTREE_DIRT_CHECK_UNAVAILABLE")
        emit()

    elif rule == gitop.RULE_STASH_DESTROY:
        if state.available:
            evidence["stash_count"] = state.stash_count
            if state.stash_count == 0:
                emit(
                    final_verdict=ALLOW,
                    final_reason=REASON_ALLOW_NO_EFFECT,
                    final_detail="no stash entries exist",
                )
                return findings, limitations
        emit()

    elif rule in (
        gitop.RULE_PUSH_FORCE,
        gitop.RULE_PUSH_FORCE_LEASE,
        gitop.RULE_PUSH_DELETE,
        gitop.RULE_PUSH_PLAIN,
        gitop.RULE_PUSH_BROAD,
    ):
        branch = _push_branch(op, state) if state.available else (op.branch_hint or "")
        final_verdict = verdict
        final_reason = reason
        final_detail = detail
        if state.available:
            evidence["branch"] = branch
            evidence["upstream"] = state.upstream
            evidence["ahead"] = state.ahead
            evidence["behind"] = state.behind
        protected = _is_protected_branch(branch, policy)
        if protected:
            evidence["protected_branch"] = branch
            if rule == gitop.RULE_PUSH_DELETE:
                final_verdict = DENY
                final_reason = REASON_REQUIRE_OWNER_BRANCH
                final_detail = "deleting protected branch %s on the remote" % branch
            elif final_verdict == ALLOW:
                final_verdict = REQUIRE_OWNER
                final_reason = REASON_REQUIRE_OWNER_BRANCH
                final_detail = "push targets protected branch %s" % branch
        if (
            rule == gitop.RULE_PUSH_FORCE_LEASE
            and state.available
            and state.behind > 0
            and final_verdict != DENY
        ):
            final_verdict = DENY
            final_reason = REASON_DENY_REMOTE_COMMITS
            final_detail = "remote has %d commit(s) not present locally" % state.behind
        emit(
            final_verdict=final_verdict,
            final_reason=final_reason,
            final_detail=final_detail,
        )

    elif rule == gitop.RULE_ADD_ALL:
        if state.available:
            evidence["untracked"] = state.untracked
            evidence["unstaged"] = state.unstaged
            if state.untracked:
                limitations.append("STAGES_UNTRACKED_FILES:%d" % state.untracked)
        emit()

    elif rule == gitop.RULE_COMMIT_PLAIN:
        if state.available:
            branch = state.branch
            evidence["branch"] = branch
            if getattr(
                policy, "protect_default_branch_commits", False
            ) and _is_protected_branch(branch, policy):
                emit(
                    final_verdict=REQUIRE_OWNER,
                    final_reason=REASON_REQUIRE_OWNER_BRANCH,
                    final_detail="commit on protected branch %s" % branch,
                )
                return findings, limitations
        emit()

    elif rule == gitop.RULE_CHECKOUT_SWITCH:
        if state.available and state.work_in_progress:
            limitations.append("DIRTY_WORKTREE_SWITCH:%d" % state.work_in_progress)
        emit()

    elif rule == gitop.RULE_OTHER:
        emit(
            final_verdict=UNKNOWN,
            final_reason=REASON_UNKNOWN_RULE,
            final_detail=detail or "operation is not classified by any rule",
        )
        limitations.append(REASON_UNKNOWN_RULE)

    else:
        emit()

    return findings, limitations


def _path_has_local_changes(
    ctx: EngineContext, state: gitstate.RepoState, target: str
) -> int:
    """Return the number of dirty files at a path, or -1 when unknown."""
    if not state.available or not state.root:
        return -1
    env = gitstate.build_env()
    code, stdout, _ = gitstate.run_git(
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--", target],
        cwd=state.root,
        timeout=ctx.timeout,
        env=env,
        git_executable=ctx.git_executable,
    )
    if code != 0:
        return -1
    return len([entry for entry in stdout.split("\0") if entry])


def _message_for(rule: str, detail: str, verdict: str) -> str:
    prefix = {
        ALLOW: "Allowed",
        DENY: "Denied",
        REQUIRE_OWNER: "Owner approval required",
        UNKNOWN: "Cannot be decided automatically",
    }.get(verdict, "Decision")
    body = detail or rule
    alternative = _ALTERNATIVES.get(rule, "")
    if verdict in (DENY, REQUIRE_OWNER, UNKNOWN) and alternative:
        return "%s: %s. %s." % (prefix, body, alternative)
    return "%s: %s" % (prefix, body)


def _escalate_for_unknown(
    decision_verdict: str,
    policy: policy_module.Policy,
    *,
    non_interactive: bool,
) -> tuple[str, str]:
    """Resolve an UNKNOWN result according to the policy's unknown ceiling.

    ``unknown_git_operations`` bounds what an UNKNOWN may become:

    * ``ALLOW`` - an explicit, deliberate policy decision to allow;
    * ``DENY`` - unknown operations are blocked outright;
    * ``UNKNOWN`` - runtime escalation applies (binding: owner/deny,
      advisory: stays UNKNOWN and is reported as such);
    * ``REQUIRE_OWNER`` - escalate when a human is available, else deny.
    """
    if decision_verdict != UNKNOWN:
        return decision_verdict, ""
    ceiling = policy.unknown_git_operations
    if ceiling == ALLOW:
        return ALLOW, ""
    if ceiling == DENY:
        return (
            DENY,
            REASON_UNKNOWN_NONINTERACTIVE if non_interactive else REASON_UNKNOWN_RULE,
        )
    if policy.enforcement != "binding":
        return UNKNOWN, ""
    if non_interactive or not policy.interactive:
        return DENY, REASON_UNKNOWN_NONINTERACTIVE
    return REQUIRE_OWNER, REASON_UNKNOWN_RULE


def evaluate(
    tool_name: str,
    tool_args: dict[str, Any] | None,
    *,
    ctx: EngineContext,
    non_interactive: bool = False,
) -> Decision:
    """Decide on one tool call."""
    policy = ctx.policy
    call = adapters.normalize(tool_name, tool_args, cwd=ctx.cwd)
    all_findings: list[Finding] = []
    limitations: list[str] = list(call.limitations)
    evidence: dict[str, Any] = {
        "cwd": ctx.cwd,
        "actions": len(call.actions),
    }

    for action in call.actions:
        if isinstance(action, adapters.FileAction):
            findings, extra = _evaluate_file_action(action, ctx=ctx)
            all_findings.extend(findings)
            limitations.extend(extra)
            continue

        parsed = shellparse.parse(action.command)
        state = _state_for(ctx, action.cwd or ctx.cwd)
        evidence["repo"] = state.to_dict()
        if parsed.unknown_reasons:
            limitations.extend(parsed.unknown_reasons)
            all_findings.append(
                Finding(
                    rule_id="command.parse",
                    verdict=UNKNOWN,
                    reason_code=REASON_UNKNOWN_PARSE,
                    message="Command could not be fully parsed: %s"
                    % ",".join(sorted(set(parsed.unknown_reasons))),
                    action=action.command,
                    evidence={"unknown_reasons": sorted(set(parsed.unknown_reasons))},
                )
            )
        path_findings, warnings = _evaluate_path_findings(
            parsed,
            action.command,
            ctx=ctx,
            reporoot=state.root if state.available else "",
        )
        all_findings.extend(path_findings)
        limitations.extend(warnings)

        invocations = gitop.resolve_invocations(parsed)
        if not invocations:
            if not path_findings:
                evidence.setdefault("scope", "no_guarded_action")
            continue

        for invocation in invocations:
            invocation_dir = action.cwd or ctx.cwd
            if invocation.cwd_hint:
                hint = invocation.cwd_hint
                invocation_dir = (
                    hint if os.path.isabs(hint) else os.path.join(invocation_dir, hint)
                )
            invocation_state = _state_for(ctx, invocation_dir)
            if invocation_state.available:
                evidence["repo"] = invocation_state.to_dict()
            for op in gitop.classify_all(invocation):
                findings, extra = _op_finding(op, ctx=ctx, state=invocation_state)
                limitations.extend(extra)
                if (
                    not invocation_state.available
                    and op.rule_id in _STATE_DEPENDENT_RULES
                ):
                    findings.append(
                        Finding(
                            rule_id=op.rule_id,
                            verdict=UNKNOWN,
                            reason_code=REASON_UNKNOWN_STATE,
                            message="Repository state unavailable (%s): %s"
                            % (invocation_state.reason, op.invocation.describe()),
                            action=op.invocation.describe(),
                            evidence={"state_reason": invocation_state.reason},
                        )
                    )
                if op.ambiguity == "path_or_ref" and not invocation_state.available:
                    findings.append(
                        Finding(
                            rule_id=op.rule_id,
                            verdict=UNKNOWN,
                            reason_code=REASON_UNKNOWN_PATH,
                            message="Cannot resolve whether %r is a path or a branch without repository state"
                            % (op.path_hint or ""),
                            action=op.invocation.describe(),
                        )
                    )
                all_findings.extend(findings)

    if not all_findings:
        out_of_scope_limitations = {
            "READ_ONLY_TOOL",
            "UNCLASSIFIED_TOOL",
            "OPAQUE_MCP_TOOL_NOT_INSPECTED",
        }
        unresolved = [
            item for item in call.limitations if item not in out_of_scope_limitations
        ]
        if unresolved:
            verdict = UNKNOWN
            reason = REASON_UNKNOWN_PARSE
        elif call.out_of_scope and policy.guard_opaque_tools and call.limitations:
            verdict = UNKNOWN
            reason = REASON_OUT_OF_SCOPE
        else:
            verdict = ALLOW
            reason = REASON_OUT_OF_SCOPE if call.out_of_scope else REASON_ALLOW
        if verdict == UNKNOWN:
            all_findings.append(
                Finding(
                    rule_id="tool.arguments",
                    verdict=UNKNOWN,
                    reason_code=reason,
                    message="Tool call could not be resolved to a checkable action: %s"
                    % ",".join(sorted(set(unresolved or call.limitations))),
                    action=call.tool_name,
                    evidence={"limitations": sorted(set(call.limitations))},
                )
            )
            if policy.enforcement == "binding":
                verdict, reason = _escalate_for_unknown(
                    UNKNOWN, policy, non_interactive=non_interactive
                )
                reason = reason or REASON_UNKNOWN_PARSE
        return Decision(
            verdict=verdict,
            reason_code=reason,
            findings=all_findings,
            evidence=evidence,
            limitations=limitations,
            policy_profile=policy.profile,
            policy_digest=policy.digest,
            enforcement=policy.enforcement,
            tool_name=call.tool_name,
            out_of_scope=call.out_of_scope,
        )

    verdict = most_restrictive(*[finding.verdict for finding in all_findings])

    approved_rule = ""
    approval_id = ""
    if verdict == REQUIRE_OWNER and ctx.check_approvals:
        approved_rule, approval_id, approval_limitations = _try_approval(
            all_findings, ctx=ctx, evidence=evidence
        )
        limitations.extend(approval_limitations)
        if approved_rule:
            verdict = ALLOW

    final_verdict, unknown_reason = _escalate_for_unknown(
        verdict, policy, non_interactive=non_interactive
    )
    if approved_rule and final_verdict == ALLOW:
        reason_code = REASON_ALLOW_OWNER_APPROVED
    else:
        reason_code = unknown_reason or _primary_reason(final_verdict, all_findings)

    return Decision(
        verdict=final_verdict,
        reason_code=reason_code,
        findings=all_findings,
        evidence=evidence,
        limitations=sorted(set(limitations)),
        policy_profile=policy.profile,
        policy_digest=policy.digest,
        enforcement=policy.enforcement,
        tool_name=call.tool_name,
        approved_rule=approved_rule,
        approval_id=approval_id,
        out_of_scope=call.out_of_scope,
    )


def _primary_reason(verdict: str, findings: list[Finding]) -> str:
    if verdict == ALLOW:
        for finding in findings:
            if finding.reason_code.startswith("ALLOW"):
                return finding.reason_code
        return REASON_ALLOW
    for finding in findings:
        if finding.verdict == verdict:
            return finding.reason_code
    for finding in findings:
        if finding.verdict != ALLOW:
            return finding.reason_code
    return REASON_ALLOW


def action_fingerprint_for_findings(
    findings: list[Finding],
    *,
    ctx: EngineContext,
    evidence: dict[str, Any],
) -> tuple[str, str]:
    """Compute the fingerprint of the most restrictive owner-gated finding."""
    candidate: Finding | None = None
    severity = {ALLOW: 0, UNKNOWN: 1, REQUIRE_OWNER: 2, DENY: 3}
    for finding in findings:
        if finding.verdict != REQUIRE_OWNER:
            continue
        if (
            candidate is None
            or severity[finding.verdict] >= severity[candidate.verdict]
        ):
            candidate = finding
    if candidate is None:
        return "", ""
    repo = evidence.get("repo") or {}
    fingerprint = approvals.compute_fingerprint(
        policy_digest=ctx.policy.digest,
        rule_id=candidate.rule_id,
        action_text=candidate.action,
        repo_root=str(repo.get("root", "")),
        branch=str(repo.get("branch", "")),
        head=str(repo.get("head", "")),
    )
    return fingerprint, candidate.rule_id


def _try_approval(
    findings: list[Finding],
    *,
    ctx: EngineContext,
    evidence: dict[str, Any],
) -> tuple[str, str, list[str]]:
    """Consume an owner approval for a decision that is exactly owner-gated.

    An approval clears the decision only when *every* blocking finding is
    REQUIRE_OWNER and they resolve to a single fingerprint.  Anything else
    (a DENY, an UNKNOWN, or two different owner-gated operations in one
    command) stays blocked, so one approval can never unlock more than the
    operation a human actually approved.
    """
    limitations: list[str] = []
    blocking = [finding for finding in findings if finding.verdict != ALLOW]
    if not blocking:
        return "", "", limitations
    if any(finding.verdict != REQUIRE_OWNER for finding in blocking):
        limitations.append("APPROVAL_NOT_APPLICABLE_MIXED_FINDINGS")
        return "", "", limitations
    fingerprints = {
        approvals.compute_fingerprint(
            policy_digest=ctx.policy.digest,
            rule_id=finding.rule_id,
            action_text=finding.action,
            repo_root=str((evidence.get("repo") or {}).get("root", "")),
            branch=str((evidence.get("repo") or {}).get("branch", "")),
            head=str((evidence.get("repo") or {}).get("head", "")),
        )
        for finding in blocking
    }
    if len(fingerprints) != 1:
        limitations.append("APPROVAL_REQUIRES_ONE_ACTION_AT_A_TIME")
        return "", "", limitations
    fingerprint = next(iter(fingerprints))
    rule_id = blocking[0].rule_id
    store = ctx.store_path
    try:
        approval = approvals.find_valid(fingerprint, path=store)
    except approvals.ApprovalError as exc:
        limitations.append("APPROVAL_STORE_ERROR:%s" % exc)
        return "", "", limitations
    if approval is None:
        return "", "", limitations
    if ctx.policy.approvals.require_interactive and not approval.interactive:
        limitations.append("APPROVAL_NOT_INTERACTIVE")
        return "", "", limitations
    try:
        approvals.consume(
            approval.approval_id,
            path=store,
            max_uses=ctx.policy.approvals.max_uses,
        )
    except approvals.ApprovalError as exc:
        limitations.append("APPROVAL_CONSUME_FAILED:%s" % exc)
        return "", "", limitations
    return rule_id, approval.approval_id, limitations
