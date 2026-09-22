"""Read-only repository state probing.

SafeGit's differentiating property is that decisions are made with
knowledge of the actual repository state, not only the command text.  This
module collects that state with bounded, read-only git calls and returns an
explicit "unavailable" result when it cannot.  It never mutates a
repository, never prompts, and never writes to the index.

All calls use a scrubbed environment (``GIT_DIR``, ``GIT_WORK_TREE``,
``GIT_INDEX_FILE`` and friends are removed) so that an agent cannot redirect
the probe with environment variables, and a hard timeout so a guard can
never hang a tool call.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import subprocess
import time

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_BUDGET_SECONDS = 6.0
MIN_TIMEOUT_SECONDS = 0.2
STATE_REASON_BUDGET = "GIT_PROBE_BUDGET_EXCEEDED"
MAX_STDERR_CHARS = 400
MAX_OUTPUT_CHARS = 4_000_000

_SCRUBBED_ENV_PREFIXES = ("GIT_",)
_SCRUBBED_ENV_NAMES = frozenset(
    {
        "HOME",
        "XDG_CONFIG_HOME",
        "SSH_ASKPASS",
        "GIT_ASKPASS",
    }
)
_KEEP_ENV_NAMES = frozenset(
    {
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_TRACE",
    }
)

STATE_REASON_OK = "OK"
STATE_REASON_NO_GIT = "GIT_NOT_FOUND"
STATE_REASON_NOT_A_REPO = "NOT_A_GIT_REPOSITORY"
STATE_REASON_TIMEOUT = "GIT_PROBE_TIMEOUT"
STATE_REASON_ERROR = "GIT_PROBE_ERROR"


@dataclasses.dataclass(frozen=True)
class RepoState:
    available: bool
    reason: str
    root: str = ""
    git_dir: str = ""
    common_dir: str = ""
    branch: str = ""
    head: str = ""
    detached: bool = False
    unborn: bool = False
    staged: int = 0
    unstaged: int = 0
    untracked: int = 0
    conflicted: int = 0
    stash_count: int = 0
    worktrees: tuple[str, ...] = ()
    default_branch: str = ""
    upstream: str = ""
    ahead: int = -1
    behind: int = -1
    limitations: tuple[str, ...] = ()

    @property
    def work_in_progress(self) -> int:
        return self.staged + self.unstaged + self.untracked

    @property
    def is_dirty(self) -> bool:
        return self.work_in_progress > 0 or self.conflicted > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "reason": self.reason,
            "root": self.root,
            "branch": self.branch,
            "head": self.head,
            "detached": self.detached,
            "unborn": self.unborn,
            "staged": self.staged,
            "unstaged": self.unstaged,
            "untracked": self.untracked,
            "conflicted": self.conflicted,
            "stash_count": self.stash_count,
            "worktrees": list(self.worktrees),
            "default_branch": self.default_branch,
            "upstream": self.upstream,
            "ahead": self.ahead,
            "behind": self.behind,
            "limitations": list(self.limitations),
        }


def build_env() -> dict[str, str]:
    """Return a deterministic environment for read-only git probes."""
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        if key in _KEEP_ENV_NAMES:
            env[key] = value
            continue
        if key in _SCRUBBED_ENV_NAMES:
            continue
        if any(key.startswith(prefix) for prefix in _SCRUBBED_ENV_PREFIXES):
            continue
        env[key] = value
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_PAGER"] = "cat"
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    return env


class ProbeBudget:
    """Wall-clock budget shared by all git calls of one decision.

    A guard that exceeds the host's hook timeout is worse than no guard: on
    Claude Code a timed-out command hook does not block the tool call.  The
    budget therefore bounds the *whole* probe, not each individual call, and
    exhausting it is reported as unavailable state (which escalates) rather
    than silently continuing.
    """

    def __init__(self, seconds: float = DEFAULT_BUDGET_SECONDS) -> None:
        self.seconds = max(seconds, MIN_TIMEOUT_SECONDS)
        self._start = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    @property
    def remaining(self) -> float:
        return self.seconds - self.elapsed

    @property
    def exhausted(self) -> bool:
        return self.remaining < MIN_TIMEOUT_SECONDS

    def clamp(self, timeout: float) -> float:
        return max(min(timeout, self.remaining), MIN_TIMEOUT_SECONDS)


def run_git(
    args: list[str],
    *,
    cwd: str,
    timeout: float,
    env: dict[str, str],
    git_executable: str,
    budget: ProbeBudget | None = None,
) -> tuple[int, str, str]:
    if budget is not None:
        if budget.exhausted:
            return (-4, "", STATE_REASON_BUDGET)
        timeout = budget.clamp(timeout)
    command = [
        git_executable,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "advice.detachedHead=false",
        "-c",
        "color.ui=false",
    ] + args
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=timeout,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return (-2, "", "git executable not found")
    except subprocess.TimeoutExpired:
        return (-1, "", "timeout")
    except OSError as exc:
        return (-3, "", str(exc)[:MAX_STDERR_CHARS])
    stdout = completed.stdout or ""
    if len(stdout) > MAX_OUTPUT_CHARS:
        stdout = stdout[:MAX_OUTPUT_CHARS]
    return (
        completed.returncode,
        stdout,
        (completed.stderr or "")[:MAX_STDERR_CHARS],
    )


def _strip_nul(lines: str) -> list[str]:
    return [line for line in lines.split("\0") if line]


def _count_status(porcelain: str) -> tuple[int, int, int, int]:
    staged = unstaged = untracked = conflicted = 0
    for entry in _strip_nul(porcelain):
        if entry.startswith("??"):
            untracked += 1
            continue
        if len(entry) < 2:
            continue
        code = entry[:2]
        if code in ("DD", "AU", "UD", "UA", "DU", "AA", "UU"):
            conflicted += 1
            continue
        if code[0] not in (" ", "?"):
            staged += 1
        if code[1] not in (" ", "?"):
            unstaged += 1
    return staged, unstaged, untracked, conflicted


def _default_branch(
    root: str,
    timeout: float,
    env: dict[str, str],
    git_executable: str,
    budget: ProbeBudget | None = None,
) -> str:
    code, stdout, _ = run_git(
        ["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
        cwd=root,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    if code == 0 and stdout.strip():
        return stdout.strip().split("/", 1)[-1]
    code, stdout, _ = run_git(
        ["config", "--get", "init.defaultBranch"],
        cwd=root,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    if code == 0 and stdout.strip():
        return stdout.strip()
    return ""


def probe(
    directory: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    git_executable: str = "git",
    cache: dict[str, RepoState] | None = None,
    budget_seconds: float = DEFAULT_BUDGET_SECONDS,
) -> RepoState:
    """Collect read-only state for the repository containing ``directory``."""
    key = os.path.normcase(os.path.abspath(directory))
    if cache is not None and key in cache:
        return cache[key]

    state = _probe_uncached(
        directory,
        timeout=timeout,
        git_executable=git_executable,
        budget=ProbeBudget(budget_seconds),
    )
    if cache is not None:
        cache[key] = state
    return state


def _probe_uncached(
    directory: str,
    *,
    timeout: float,
    git_executable: str,
    budget: ProbeBudget | None = None,
) -> RepoState:
    env = build_env()
    budget = budget or ProbeBudget(timeout + 1.0)
    if not os.path.isdir(directory):
        return RepoState(available=False, reason="CWD_NOT_A_DIRECTORY")

    code, stdout, stderr = run_git(
        ["rev-parse", "--show-toplevel", "--git-common-dir", "--git-dir"],
        cwd=directory,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    if code == -2:
        return RepoState(available=False, reason=STATE_REASON_NO_GIT)
    if code == -1:
        return RepoState(available=False, reason=STATE_REASON_TIMEOUT)
    if code != 0:
        reason = STATE_REASON_NOT_A_REPO
        if "dubious ownership" in stderr:
            reason = "GIT_DUBIOUS_OWNERSHIP"
        return RepoState(available=False, reason=reason)

    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) < 3:
        return RepoState(available=False, reason=STATE_REASON_ERROR)
    root, common_dir, git_dir = lines[0], lines[1], lines[2]
    if not os.path.isabs(common_dir):
        common_dir = os.path.normpath(os.path.join(root, common_dir))
    if not os.path.isabs(git_dir):
        git_dir = os.path.normpath(os.path.join(root, git_dir))

    limitations: list[str] = []

    head_code, head_out, _ = run_git(
        ["rev-parse", "--verify", "--quiet", "HEAD"],
        cwd=root,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    head = head_out.strip() if head_code == 0 else ""
    unborn = head_code != 0

    branch_code, branch_out, _ = run_git(
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=root,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    branch = branch_out.strip() if branch_code == 0 else ""
    detached = not branch and not unborn

    staged = unstaged = untracked = conflicted = 0
    status_code, status_out, status_err = run_git(
        ["status", "--porcelain=v1", "-z", "--untracked-files=normal", "--no-renames"],
        cwd=root,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    if status_code == 0:
        staged, unstaged, untracked, conflicted = _count_status(status_out)
    elif status_code == -1:
        return RepoState(
            available=False,
            reason=STATE_REASON_TIMEOUT,
            root=root,
            branch=branch,
            head=head,
        )
    else:
        limitations.append("WORKTREE_STATUS_UNAVAILABLE")
        if status_err:
            limitations.append("STATUS_STDERR_PRESENT")

    stash_code, stash_out, _ = run_git(
        ["stash", "list", "--format=%gd"],
        cwd=root,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    stash_count = (
        len([line for line in stash_out.splitlines() if line.strip()])
        if stash_code == 0
        else 0
    )
    if stash_code != 0:
        limitations.append("STASH_STATE_UNAVAILABLE")

    worktrees: list[str] = []
    wt_code, wt_out, _ = run_git(
        ["worktree", "list", "--porcelain"],
        cwd=root,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    if wt_code == 0:
        for line in wt_out.splitlines():
            if line.startswith("worktree "):
                worktrees.append(line[len("worktree ") :].strip())
    else:
        limitations.append("WORKTREE_STATE_UNAVAILABLE")

    upstream = ""
    ahead = behind = -1
    up_code, up_out, _ = run_git(
        ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        cwd=root,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    if up_code == 0:
        upstream = up_out.strip()
        count_code, count_out, _ = run_git(
            ["rev-list", "--left-right", "--count", "@{upstream}...HEAD"],
            cwd=root,
            timeout=timeout,
            env=env,
            git_executable=git_executable,
        )
        if count_code == 0:
            parts = count_out.split()
            if len(parts) == 2 and all(p.isdigit() for p in parts):
                behind, ahead = int(parts[0]), int(parts[1])
            else:
                limitations.append("AHEAD_BEHIND_PARSE_FAILED")
        else:
            limitations.append("AHEAD_BEHIND_UNAVAILABLE")

    return RepoState(
        available=True,
        reason=STATE_REASON_OK,
        root=root,
        git_dir=git_dir,
        common_dir=common_dir,
        branch=branch,
        head=head,
        detached=detached,
        unborn=unborn,
        staged=staged,
        unstaged=unstaged,
        untracked=untracked,
        conflicted=conflicted,
        stash_count=stash_count,
        worktrees=tuple(worktrees),
        default_branch=_default_branch(root, timeout, env, git_executable, budget),
        upstream=upstream,
        ahead=ahead,
        behind=behind,
        limitations=tuple(
            limitations
            + (["UNTRACKED_ENTRIES_ARE_DIRECTORY_LEVEL"] if untracked else [])
        ),
    )


def resolve_path_or_ref(
    state: RepoState,
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    git_executable: str = "git",
    budget: ProbeBudget | None = None,
) -> str:
    """Return ``ref``, ``path``, ``missing`` or ``unknown`` for a target.

    Used to resolve git's own path/branch ambiguity (``git checkout x``)
    with repository state instead of guessing from the string.
    """
    if not state.available or not state.root:
        return "unknown"
    env = build_env()
    for namespace in ("refs/heads/", "refs/tags/", "refs/remotes/"):
        code, _, _ = run_git(
            ["show-ref", "--verify", "--quiet", namespace + target],
            cwd=state.root,
            timeout=timeout,
            env=env,
            git_executable=git_executable,
        )
        if code == 0:
            return "ref"
    code, _, _ = run_git(
        ["ls-files", "--error-unmatch", "--", target],
        cwd=state.root,
        timeout=timeout,
        env=env,
        git_executable=git_executable,
        budget=budget,
    )
    if code == 0:
        return "path"
    candidate = os.path.join(state.root, target)
    if os.path.exists(candidate):
        return "path"
    return "missing"


def unmerged_commit_count(
    state: RepoState,
    branch: str,
    *,
    base: str = "HEAD",
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    git_executable: str = "git",
    budget: ProbeBudget | None = None,
) -> int:
    """Count commits reachable from ``branch`` but not from ``base`` (-1 unknown)."""
    if not state.available or not state.root or not branch:
        return -1
    code, stdout, _ = run_git(
        ["rev-list", "--count", "%s" % branch, "--not", base],
        cwd=state.root,
        timeout=timeout,
        env=build_env(),
        git_executable=git_executable,
        budget=budget,
    )
    if code != 0:
        return -1
    value = stdout.strip()
    return int(value) if value.isdigit() else -1


def revision_is_published(
    state: RepoState,
    revision: str = "HEAD",
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    git_executable: str = "git",
    budget: ProbeBudget | None = None,
) -> int:
    """Return 1 published, 0 not published, -1 unknown."""
    if not state.available or not state.root:
        return -1
    code, stdout, _ = run_git(
        ["branch", "-r", "--contains", revision],
        cwd=state.root,
        timeout=timeout,
        env=build_env(),
        git_executable=git_executable,
        budget=budget,
    )
    if code != 0:
        return -1
    return 1 if stdout.strip() else 0


def branch_exists(
    state: RepoState,
    branch: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    git_executable: str = "git",
    budget: ProbeBudget | None = None,
) -> bool:
    if not state.available or not state.root or not branch:
        return False
    code, _, _ = run_git(
        ["show-ref", "--verify", "--quiet", "refs/heads/" + branch],
        cwd=state.root,
        timeout=timeout,
        env=build_env(),
        git_executable=git_executable,
        budget=budget,
    )
    return code == 0


def find_repo_root(
    directory: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    git_executable: str = "git",
    budget: ProbeBudget | None = None,
) -> str:
    if not os.path.isdir(directory):
        return ""
    code, stdout, _ = run_git(
        ["rev-parse", "--show-toplevel"],
        cwd=directory,
        timeout=timeout,
        env=build_env(),
        git_executable=git_executable,
        budget=budget,
    )
    return stdout.strip() if code == 0 else ""


def is_git_executable_available(git_executable: str = "git") -> bool:
    import shutil

    return bool(shutil.which(git_executable)) or pathlib.Path(git_executable).is_file()
