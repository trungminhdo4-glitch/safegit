"""Commit preflight: what exactly is about to be committed?

The preflight answers the questions a reviewer would ask before a commit
lands, using git's own plumbing for the answers:

* is a merge, rebase or cherry-pick still in progress?
* what is staged, and is it only what was intended?
* does ``git diff --cached --check`` report whitespace errors or leftover
  conflict markers?
* are there unmerged (conflicted) stages in the index?
* are new binary or unusually large files being committed?
* are secret-bearing, protected or generated paths included?
* how much uncommitted work is being left behind?

It never modifies the index: nothing is staged, unstaged or reset.  A
preflight that changes the repository would be worse than no preflight.
"""

from __future__ import annotations

import dataclasses
import os
import re
import subprocess
from typing import Any

from . import gitop  # noqa: F401  (rules referenced by docs/messages)
from . import gitstate, policy as policy_module
from .verdicts import DENY, REQUIRE_OWNER

FAIL = "FAIL"
WARN = "WARN"
INFO = "INFO"

MAX_LISTED_PATHS = 40
MAX_STAGED_FOR_SIZE_PROBE = 400
CONFLICT_MARKER_RE = re.compile(r"^(<{7}|={7}|>{7})", re.MULTILINE)

_DENY_PATH_RULES = (policy_module.FS_SECRET_WRITE, policy_module.FS_PROTECTED_WRITE)


@dataclasses.dataclass
class PreflightFinding:
    check: str
    severity: str
    message: str
    paths: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity,
            "message": self.message,
            "paths": list(self.paths[:MAX_LISTED_PATHS]),
            "path_count": len(self.paths),
        }


@dataclasses.dataclass
class PreflightResult:
    ok: bool
    repo_root: str
    branch: str
    head: str
    staged_files: list[str]
    staged_added: int
    staged_deleted: int
    binary_files: list[str]
    large_files: list[str]
    findings: list[PreflightFinding]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "safegit.preflight/1",
            "ok": self.ok,
            "repo_root": self.repo_root,
            "branch": self.branch,
            "head": self.head,
            "staged_count": len(self.staged_files),
            "staged_files": self.staged_files[:MAX_LISTED_PATHS],
            "staged_added_lines": self.staged_added,
            "staged_deleted_lines": self.staged_deleted,
            "binary_files": self.binary_files[:MAX_LISTED_PATHS],
            "large_files": self.large_files[:MAX_LISTED_PATHS],
            "findings": [finding.to_dict() for finding in self.findings],
            "limitations": list(self.limitations),
        }

    @property
    def failures(self) -> list[PreflightFinding]:
        return [finding for finding in self.findings if finding.severity == FAIL]


def _git(
    args: list[str],
    *,
    cwd: str,
    timeout: float,
    git_executable: str,
    input_text: str | None = None,
) -> tuple[int, str, str]:
    command = [
        git_executable,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "color.ui=false",
    ] + args
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=gitstate.build_env(),
            capture_output=True,
            timeout=timeout,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            input=input_text,
        )
    except FileNotFoundError:
        return (-2, "", "git executable not found")
    except subprocess.TimeoutExpired:
        return (-1, "", "timeout")
    except OSError as exc:
        return (-3, "", str(exc)[:400])
    return completed.returncode, completed.stdout or "", (completed.stderr or "")[:400]


def _split_nul(text: str) -> list[str]:
    return [item for item in text.split("\0") if item]


def run_preflight(
    repo_dir: str,
    *,
    policy: policy_module.Policy,
    expect_globs: tuple[str, ...] = (),
    timeout: float = gitstate.DEFAULT_TIMEOUT_SECONDS,
    git_executable: str = "git",
) -> PreflightResult:
    findings: list[PreflightFinding] = []
    limitations: list[str] = []
    state = gitstate.probe(repo_dir, timeout=timeout, git_executable=git_executable)
    if not state.available:
        findings.append(
            PreflightFinding(
                check="repository",
                severity=FAIL,
                message="Repository state unavailable: %s" % state.reason,
            )
        )
        return PreflightResult(
            ok=False,
            repo_root="",
            branch="",
            head="",
            staged_files=[],
            staged_added=0,
            staged_deleted=0,
            binary_files=[],
            large_files=[],
            findings=findings,
            limitations=["REPOSITORY_STATE_UNAVAILABLE"],
        )

    root = state.root
    preflight_config = policy.commit_preflight

    for marker, label in (
        ("MERGE_HEAD", "merge"),
        ("CHERRY_PICK_HEAD", "cherry-pick"),
        ("REVERT_HEAD", "revert"),
    ):
        code, _, _ = _git(
            ["rev-parse", "--verify", "--quiet", marker],
            cwd=root,
            timeout=timeout,
            git_executable=git_executable,
        )
        if code == 0:
            findings.append(
                PreflightFinding(
                    check="operation_in_progress",
                    severity=FAIL,
                    message="a %s is still in progress; finish or abort it first"
                    % label,
                )
            )
    for directory, label in (
        ("rebase-merge", "rebase"),
        ("rebase-apply", "rebase"),
    ):
        if os.path.isdir(os.path.join(state.git_dir or "", directory)):
            findings.append(
                PreflightFinding(
                    check="operation_in_progress",
                    severity=FAIL,
                    message="a %s is still in progress; finish or abort it first"
                    % label,
                )
            )
            break

    if state.detached:
        findings.append(
            PreflightFinding(
                check="head_state",
                severity=WARN,
                message="HEAD is detached; a commit here is easy to lose",
            )
        )
    if state.unborn:
        findings.append(
            PreflightFinding(
                check="head_state",
                severity=INFO,
                message="repository has no commits yet",
            )
        )

    unmerged_code, unmerged_out, _ = _git(
        ["ls-files", "-u", "-z"],
        cwd=root,
        timeout=timeout,
        git_executable=git_executable,
    )
    if unmerged_code == 0 and unmerged_out.strip():
        conflicted = sorted({entry for entry in _split_nul(unmerged_out)})
        findings.append(
            PreflightFinding(
                check="merge_conflicts",
                severity=FAIL,
                message="unmerged index entries present (resolve the conflict first)",
                paths=conflicted,
            )
        )

    check_code, check_out, check_err = _git(
        ["diff", "--cached", "--check"],
        cwd=root,
        timeout=timeout,
        git_executable=git_executable,
    )
    if check_code != 0:
        detail = (check_out or check_err).strip().splitlines()
        if isinstance(check_err, str) and check_err.strip() and check_code != 1:
            findings.append(
                PreflightFinding(
                    check="diff_check",
                    severity=FAIL,
                    message="`git diff --cached --check` failed: %s"
                    % check_err.strip()[:200],
                )
            )
        else:
            findings.append(
                PreflightFinding(
                    check="diff_check",
                    severity=FAIL if preflight_config.block_conflict_markers else WARN,
                    message="`git diff --cached --check` reported %d problem(s)"
                    % len(detail),
                    paths=[line[:200] for line in detail[:MAX_LISTED_PATHS]],
                )
            )

    marker_code, marker_out, _ = _git(
        ["diff", "--cached", "-U0"],
        cwd=root,
        timeout=timeout,
        git_executable=git_executable,
    )
    if marker_code == 0 and CONFLICT_MARKER_RE.search(marker_out or ""):
        findings.append(
            PreflightFinding(
                check="conflict_markers",
                severity=FAIL if preflight_config.block_conflict_markers else WARN,
                message="staged diff contains conflict markers",
            )
        )

    staged_code, staged_out, staged_err = _git(
        ["diff", "--cached", "--name-only", "--diff-filter=ACDMRT", "-z"],
        cwd=root,
        timeout=timeout,
        git_executable=git_executable,
    )
    staged_files = sorted(_split_nul(staged_out)) if staged_code == 0 else []
    if staged_code != 0:
        findings.append(
            PreflightFinding(
                check="staged_set",
                severity=FAIL,
                message="could not read the staged file set: %s"
                % (staged_err or "unknown"),
            )
        )
        limitations.append("STAGED_SET_UNAVAILABLE")

    numstat_code, numstat_out, _ = _git(
        ["diff", "--cached", "--numstat", "-z", "--no-renames"],
        cwd=root,
        timeout=timeout,
        git_executable=git_executable,
    )
    added_total = deleted_total = 0
    binary_files: list[str] = []
    if numstat_code == 0:
        entries = _split_nul(numstat_out)
        index = 0
        while index < len(entries):
            entry = entries[index]
            parts = entry.split("\t")
            if len(parts) >= 3:
                added, deleted, path = parts[0], parts[1], parts[2]
                if added == "-" or deleted == "-":
                    binary_files.append(path)
                else:
                    added_total += int(added) if added.isdigit() else 0
                    deleted_total += int(deleted) if deleted.isdigit() else 0
                index += 1
                continue
            if len(parts) == 2 and index + 1 < len(entries):
                path = entries[index + 1]
                binary_files.append(path)
                index += 2
                continue
            index += 1
    else:
        limitations.append("NUMSTAT_UNAVAILABLE")

    if len(staged_files) > preflight_config.max_files:
        findings.append(
            PreflightFinding(
                check="staged_size",
                severity=FAIL,
                message="%d staged files exceed the limit of %d"
                % (len(staged_files), preflight_config.max_files),
                paths=staged_files,
            )
        )
    if added_total > preflight_config.max_added_lines:
        findings.append(
            PreflightFinding(
                check="staged_size",
                severity=FAIL,
                message="%d added lines exceed the limit of %d"
                % (added_total, preflight_config.max_added_lines),
            )
        )
    if deleted_total > preflight_config.max_deleted_lines:
        findings.append(
            PreflightFinding(
                check="staged_size",
                severity=FAIL,
                message="%d deleted lines exceed the limit of %d"
                % (deleted_total, preflight_config.max_deleted_lines),
            )
        )

    if binary_files:
        findings.append(
            PreflightFinding(
                check="binary_files",
                severity=WARN,
                message="%d binary file(s) staged; binary changes cannot be reviewed as a diff"
                % len(binary_files),
                paths=binary_files,
            )
        )

    large_files, large_limitations = _detect_large_files(
        root,
        staged_files,
        limit=preflight_config.max_file_bytes,
        timeout=timeout,
        git_executable=git_executable,
    )
    limitations.extend(large_limitations)
    if large_files:
        findings.append(
            PreflightFinding(
                check="large_files",
                severity=FAIL,
                message="%d staged file(s) exceed %d bytes"
                % (len(large_files), preflight_config.max_file_bytes),
                paths=[path for path, _ in large_files],
            )
        )

    secret_hits: list[str] = []
    protected_hits: list[str] = []
    ci_hits: list[str] = []
    for path in staged_files:
        absolute = os.path.join(root, path)
        for pattern in policy.secret_paths:
            if _match(path, absolute, pattern) and not _match_allowlist(path, absolute):
                secret_hits.append(path)
                break
        for pattern in policy.protected_paths:
            if _match(path, absolute, pattern):
                protected_hits.append(path)
                break
        for pattern in policy.ci_paths:
            if _match(path, absolute, pattern):
                ci_hits.append(path)
                break

    if secret_hits and preflight_config.block_denied_paths:
        findings.append(
            PreflightFinding(
                check="secret_paths",
                severity=FAIL,
                message="staged files match the secret path policy",
                paths=secret_hits,
            )
        )
    if protected_hits and preflight_config.block_denied_paths:
        findings.append(
            PreflightFinding(
                check="protected_paths",
                severity=FAIL,
                message="staged files match the protected path policy",
                paths=protected_hits,
            )
        )
    if ci_hits:
        findings.append(
            PreflightFinding(
                check="ci_paths",
                severity=WARN,
                message="CI configuration is staged; review it explicitly",
                paths=ci_hits,
            )
        )

    for pattern in preflight_config.generated_paths:
        matched = [
            path
            for path in staged_files
            if _match(path, os.path.join(root, path), pattern)
        ]
        if matched:
            findings.append(
                PreflightFinding(
                    check="generated_paths",
                    severity=WARN if preflight_config.warn_generated_paths else INFO,
                    message="staged files look generated (pattern %s)" % pattern,
                    paths=matched,
                )
            )

    if expect_globs:
        unexpected = [
            path
            for path in staged_files
            if not any(
                _match(path, os.path.join(root, path), pattern)
                for pattern in expect_globs
            )
        ]
        if unexpected:
            findings.append(
                PreflightFinding(
                    check="declared_scope",
                    severity=FAIL,
                    message="staged files outside the declared scope",
                    paths=unexpected,
                )
            )

    if not staged_files:
        findings.append(
            PreflightFinding(
                check="staged_set",
                severity=INFO,
                message="nothing is staged; a commit would be empty",
            )
        )

    leftover = state.unstaged + state.untracked
    if leftover:
        findings.append(
            PreflightFinding(
                check="left_behind",
                severity=INFO,
                message="%d file(s) with uncommitted changes remain in the working tree"
                % leftover,
            )
        )
    if state.stash_count:
        findings.append(
            PreflightFinding(
                check="left_behind",
                severity=INFO,
                message="%d stash entr(ies) exist" % state.stash_count,
            )
        )

    ok = not any(finding.severity == FAIL for finding in findings)
    return PreflightResult(
        ok=ok,
        repo_root=root,
        branch=state.branch,
        head=state.head,
        staged_files=staged_files,
        staged_added=added_total,
        staged_deleted=deleted_total,
        binary_files=binary_files,
        large_files=[path for path, _ in large_files],
        findings=findings,
        limitations=sorted(set(limitations)),
    )


def _detect_large_files(
    root: str,
    staged_files: list[str],
    *,
    limit: int,
    timeout: float,
    git_executable: str,
) -> tuple[list[tuple[str, int]], list[str]]:
    if not staged_files or limit <= 0:
        return [], []
    limitations: list[str] = []
    probed = staged_files
    if len(staged_files) > MAX_STAGED_FOR_SIZE_PROBE:
        probed = sorted(staged_files)[:MAX_STAGED_FOR_SIZE_PROBE]
        limitations.append(
            "LARGE_FILE_PROBE_SAMPLED:%d_OF_%d" % (len(probed), len(staged_files))
        )
    code, ls_out, _ = _git(
        ["ls-files", "-s", "-z", "--"],
        cwd=root,
        timeout=timeout,
        git_executable=git_executable,
    )
    if code != 0:
        return [], limitations + ["INDEX_READ_FAILED"]
    staged_set = set(probed)
    object_ids: list[tuple[str, str]] = []
    for entry in _split_nul(ls_out):
        parts = entry.split("\t", 1)
        if len(parts) != 2:
            continue
        meta, path = parts
        fields = meta.split()
        if len(fields) < 3:
            continue
        if path in staged_set and fields[2] == "0":
            object_ids.append((fields[1], path))
    if not object_ids:
        return [], []
    payload = "".join("%s\n" % object_id for object_id, _ in object_ids)
    check_code, check_out, _ = _git(
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        cwd=root,
        timeout=timeout,
        git_executable=git_executable,
        input_text=payload,
    )
    if check_code != 0:
        return [], ["OBJECT_SIZE_PROBE_FAILED"]
    sizes: dict[str, int] = {}
    for line in check_out.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2].isdigit():
            sizes[fields[0]] = int(fields[2])
    large: list[tuple[str, int]] = []
    for object_id, path in object_ids:
        size = sizes.get(object_id)
        if size is not None and size > limit:
            large.append((path, size))
    return large, limitations


def _match(relative: str, absolute: str, pattern: str) -> bool:
    from .engine import _match_glob

    return _match_glob(relative, absolute, pattern)


def _match_allowlist(relative: str, absolute: str) -> bool:
    from .engine import _match_glob

    return any(
        _match_glob(relative, absolute, pattern)
        for pattern in policy_module.SECRET_PATH_ALLOWLIST
    )


def verdict_for_preflight(result: PreflightResult, policy: policy_module.Policy) -> str:
    if result.ok:
        return "ALLOW"
    for finding in result.findings:
        if finding.severity == FAIL:
            if finding.check in ("secret_paths", "protected_paths"):
                return policy.rule_verdict(policy_module.FS_SECRET_WRITE)
            if finding.check in ("ci_paths", "generated_paths"):
                return REQUIRE_OWNER
            return DENY
    return REQUIRE_OWNER
