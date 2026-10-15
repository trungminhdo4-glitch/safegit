"""SafeGit command line interface."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from typing import Any

from . import (
    __version__,
    approvals,
    engine,
    gitop,
    gitstate,
    policy as policy_module,
)
from . import preflight as preflight_module
from .preflight import FAIL, WARN
from . import receipt as receipt_module
from .verdicts import (
    ALLOW,
    DENY,
    REQUIRE_OWNER,
    VERDICT_EXIT_CODES,
    EXIT_INTERNAL_ERROR,
    EXIT_USAGE,
)

SUPPORTED_PYTHON = (3, 9)
CLAUDE_HOOK_MATCHER = "Bash|PowerShell|Write|Edit|NotebookEdit|MultiEdit|Task|mcp__.*"
CLAUDE_HOOK_TIMEOUT_SECONDS = 15
SAFEGIT_PACKAGE_NAME = "safegit"
_SHELL_METACHARACTERS = set("&|<>^%\"`$'")
_ISOLATED_PYTHON = sys.version_info >= (3, 11)


def _guard_against_cwd_shadowing() -> None:
    """Refuse to run when the working directory shadows this package.

    ``python -m safegit`` puts the current directory first on ``sys.path``,
    so a repository that contains ``safegit.py`` would execute attacker
    controlled code inside the hook.  We launch with ``-P`` where the
    interpreter supports it and fail closed here when the module we are
    actually running from is not the installed package.
    """
    try:
        package_dir = pathlib.Path(__file__).resolve().parent
    except OSError:
        raise SystemExit(2)
    cwd = pathlib.Path.cwd()
    shadow_files = [
        cwd / ("%s.py" % SAFEGIT_PACKAGE_NAME),
        cwd / SAFEGIT_PACKAGE_NAME / "__init__.py",
    ]
    for candidate in shadow_files:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.is_file() and resolved.parent != package_dir:
            if cwd != package_dir.parent:
                sys.stderr.write(
                    "SAFEGIT_SHADOWED_BY_WORKING_DIRECTORY: refusing to run, "
                    "%s would be imported instead of SafeGit\n" % resolved
                )
                raise SystemExit(2)


def _print_json(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


def _fail(message: str, code: int = EXIT_USAGE) -> int:
    sys.stderr.write("%s\n" % message)
    return code


def _load_policy(args: argparse.Namespace, start_dir: str) -> policy_module.Policy:
    return policy_module.load(
        getattr(args, "policy", None),
        profile=getattr(args, "profile", None),
        start_dir=start_dir,
    )


def _make_context(
    args: argparse.Namespace, *, cwd: str, policy: policy_module.Policy
) -> engine.EngineContext:
    return engine.EngineContext(
        cwd=cwd,
        policy=policy,
        git_executable=getattr(args, "git", "git") or "git",
        timeout=float(getattr(args, "timeout", gitstate.DEFAULT_TIMEOUT_SECONDS)),
        approval_store=getattr(args, "approval_store", "") or "",
        check_approvals=not getattr(args, "no_approvals", False),
    )


def _audit(
    receipt: dict[str, Any],
    policy: policy_module.Policy,
    *,
    cwd: str,
    repo_root: str = "",
) -> pathlib.Path | None:
    if not policy.audit.enabled:
        return None
    if policy.audit.path:
        path = pathlib.Path(policy.audit.path)
    else:
        path = receipt_module.default_audit_path(
            policy_path=policy.source_path, cwd=cwd, repo_root=repo_root
        )
    return receipt_module.append_audit(
        receipt, path=path, retention_days=policy.audit.retention_days
    )


def _repo_root_of(decision: engine.Decision) -> str:
    repo = (decision.evidence or {}).get("repo") or {}
    if isinstance(repo, dict) and repo.get("available"):
        return str(repo.get("root", ""))
    return ""


def _render_decision_lines(decision: engine.Decision) -> list[str]:
    lines = ["SafeGit %s: %s" % (decision.verdict, decision.reason_code)]
    for finding in decision.findings:
        if finding.verdict == ALLOW:
            continue
        lines.append("  [%s] %s" % (finding.verdict, finding.message))
        if finding.evidence:
            relevant = {
                key: value
                for key, value in finding.evidence.items()
                if key
                in (
                    "work_at_risk",
                    "untracked",
                    "unmerged_commits",
                    "branch",
                    "protected_branch",
                    "stash_count",
                    "data_loss_confirmed",
                    "head_published",
                    "target",
                    "path",
                    "worktree_dirty_files",
                    "local_changes_at_target",
                    "state_reason",
                    "behind",
                )
            }
            if relevant:
                lines.append("      evidence: %s" % json.dumps(relevant, sort_keys=True))
    for limitation in decision.limitations:
        lines.append("  limitation: %s" % limitation)
    return lines


def cmd_version(args: argparse.Namespace) -> int:
    payload = {
        "name": "SafeGit",
        "version": __version__,
        "python": "%d.%d.%d" % sys.version_info[:3],
        "git": _git_version(args.git if hasattr(args, "git") else "git"),
    }
    if getattr(args, "json", False):
        _print_json(payload)
    else:
        sys.stdout.write(
            "SafeGit %s (python %s, %s)\n" % (payload["version"], payload["python"], payload["git"])
        )
    return 0


def _git_version(git_executable: str) -> str:
    try:
        completed = subprocess.run(
            [git_executable, "--version"],
            capture_output=True,
            timeout=5,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return "git:unavailable"
    return (completed.stdout or "").strip() or "git:unknown"


def cmd_check(args: argparse.Namespace) -> int:
    cwd = os.path.abspath(args.cwd or os.getcwd())
    try:
        policy = _load_policy(args, cwd)
    except policy_module.PolicyError as exc:
        return _fail("SafeGit policy error: %s" % exc, EXIT_INTERNAL_ERROR)

    ctx = _make_context(args, cwd=cwd, policy=policy)
    started = time.perf_counter()

    if args.command_text:
        tool_name = args.tool or "Bash"
        tool_args: dict[str, Any] = {"command": args.command_text, "cwd": cwd}
    elif args.args_json:
        try:
            tool_args = json.loads(args.args_json)
        except json.JSONDecodeError as exc:
            return _fail("--args-json is not valid JSON: %s" % exc.msg)
        if not isinstance(tool_args, dict):
            return _fail("--args-json must be a JSON object")
        tool_name = args.tool or "Bash"
    else:
        return _fail("check requires --command or --args-json")

    decision = engine.evaluate(tool_name, tool_args, ctx=ctx, non_interactive=args.non_interactive)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    action_text = str(tool_args.get("command") or tool_args.get("file_path") or tool_name)
    receipt = receipt_module.build_receipt(
        decision=decision.to_dict(),
        tool_name=tool_name,
        action_text=action_text,
        execution_context="cli",
        include_command=policy.audit.include_command,
        extra={"duration_ms": round(elapsed_ms, 3)},
    )
    _audit(receipt, policy, cwd=cwd, repo_root=_repo_root_of(decision))

    if args.json:
        payload = decision.to_dict()
        payload["receipt"] = receipt
        payload["duration_ms"] = round(elapsed_ms, 3)
        _print_json(payload)
    else:
        for line in _render_decision_lines(decision):
            sys.stdout.write(line + "\n")
        sys.stdout.write("  duration: %.2f ms\n" % elapsed_ms)
    return VERDICT_EXIT_CODES.get(decision.verdict, EXIT_INTERNAL_ERROR)


def _read_stdin_event() -> dict[str, Any] | None:
    try:
        raw = sys.stdin.read()
    except (OSError, UnicodeDecodeError):
        return None
    if not raw.strip():
        return {}
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(event, dict):
        return None
    return event


def cmd_hook(args: argparse.Namespace) -> int:
    """Agent host hook mode: block by exit code, never fail open."""
    event = _read_stdin_event()
    if event is None:
        sys.stderr.write("SAFEGIT_HOOK_INPUT_INVALID\n")
        return 2
    try:
        return _hook_decision(args, event)
    except SystemExit:
        raise
    except Exception as exc:  # any internal failure must still block the call
        sys.stderr.write("SAFEGIT_HOOK_ERROR: %s: %s\n" % (exc.__class__.__name__, str(exc)[:200]))
        return 2


def _hook_decision(args: argparse.Namespace, event: dict[str, Any]) -> int:
    cwd = os.path.abspath(str(event.get("cwd") or args.cwd or os.getcwd()))
    tool_name = str(event.get("tool_name") or event.get("tool") or "")
    tool_input = event.get("tool_input")
    if tool_input is None:
        tool_input = event.get("args")
    if isinstance(tool_input, dict) and cwd and "cwd" not in tool_input:
        tool_input = dict(tool_input)
        tool_input["cwd"] = cwd

    if not tool_name:
        sys.stderr.write("SAFEGIT_HOOK_TOOL_NAME_MISSING\n")
        return 2

    try:
        policy = _load_policy(args, cwd)
    except policy_module.PolicyError as exc:
        sys.stderr.write("SAFEGIT_POLICY_ERROR: %s\n" % exc)
        return 2
    except Exception as exc:
        sys.stderr.write(
            "SAFEGIT_POLICY_ERROR: %s: %s\n" % (exc.__class__.__name__, str(exc)[:160])
        )
        return 2

    ctx = _make_context(args, cwd=cwd, policy=policy)
    decision = engine.evaluate(
        tool_name,
        tool_input if isinstance(tool_input, dict) else {},
        ctx=ctx,
        non_interactive=True,
    )

    action_text = ""
    if isinstance(tool_input, dict):
        action_text = str(
            tool_input.get("command") or tool_input.get("file_path") or tool_input.get("path") or ""
        )
    receipt = receipt_module.build_receipt(
        decision=decision.to_dict(),
        tool_name=tool_name,
        action_text=action_text,
        execution_context="hook:%s" % args.host,
        include_command=policy.audit.include_command,
    )
    _audit(receipt, policy, cwd=cwd, repo_root=_repo_root_of(decision))

    if decision.verdict == ALLOW:
        return 0

    reason = _hook_reason(decision)
    if args.host == "claude":
        payload = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
        sys.stdout.write(json.dumps(payload) + "\n")
    sys.stderr.write(reason + "\n")
    return 2


def _hook_reason(decision: engine.Decision) -> str:
    blocked = [
        finding
        for finding in decision.findings
        if finding.verdict != ALLOW and finding.verdict == decision.verdict
    ] or [finding for finding in decision.findings if finding.verdict != ALLOW]
    parts = ["SafeGit %s (%s)." % (decision.verdict, decision.reason_code)]
    for finding in blocked[:3]:
        parts.append("%s: %s" % (finding.rule_id, finding.message))
    parts.append("Do not retry the same command; ask the owner or use the suggested alternative.")
    return " ".join(parts)[:1200]


def cmd_preflight(args: argparse.Namespace) -> int:
    repo = os.path.abspath(args.repo or os.getcwd())
    try:
        policy = _load_policy(args, repo)
    except policy_module.PolicyError as exc:
        return _fail("SafeGit policy error: %s" % exc, EXIT_INTERNAL_ERROR)
    result = preflight_module.run_preflight(
        repo,
        policy=policy,
        expect_globs=tuple(args.expect or ()),
        timeout=float(args.timeout),
        git_executable=args.git,
    )
    verdict = preflight_module.verdict_for_preflight(result, policy)
    strict_failure = args.strict and any(
        finding.severity in ("FAIL", "WARN") for finding in result.findings
    )
    if strict_failure and verdict == ALLOW:
        verdict = REQUIRE_OWNER

    payload = result.to_dict()
    payload["verdict"] = verdict
    payload["policy_profile"] = policy.profile
    payload["policy_digest"] = policy.digest
    receipt = receipt_module.build_receipt(
        decision={
            "verdict": verdict,
            "reason_code": "PREFLIGHT_%s" % ("OK" if result.ok else "BLOCKED"),
            "policy_profile": policy.profile,
            "policy_digest": policy.digest,
            "enforcement": policy.enforcement,
            "findings": [
                {
                    "rule_id": "preflight.%s" % finding.check,
                    "verdict": DENY
                    if finding.severity == FAIL
                    else (REQUIRE_OWNER if finding.severity == WARN else ALLOW),
                    "reason_code": "PREFLIGHT_%s" % finding.severity,
                    "message": finding.message,
                    "evidence": {
                        "paths": finding.paths[:10],
                        "path_count": len(finding.paths),
                    },
                }
                for finding in result.findings
            ],
            "limitations": result.limitations,
            "evidence": {
                "repo": {
                    "root": result.repo_root,
                    "branch": result.branch,
                    "head": result.head,
                }
            },
        },
        tool_name="commit-preflight",
        action_text="%s %s" % (result.branch, result.head),
        execution_context="preflight",
        include_command=False,
    )
    _audit(receipt, policy, cwd=repo, repo_root=result.repo_root)

    if args.json:
        payload["receipt"] = receipt
        _print_json(payload)
    else:
        sys.stdout.write("SafeGit preflight: %s\n" % verdict)
        sys.stdout.write("  repository: %s\n" % (result.repo_root or "<none>"))
        sys.stdout.write(
            "  branch: %s  head: %s  staged: %d files (+%d/-%d lines)\n"
            % (
                result.branch or "<detached>",
                (result.head or "")[:10],
                len(result.staged_files),
                result.staged_added,
                result.staged_deleted,
            )
        )
        for finding in result.findings:
            sys.stdout.write("  [%s] %s: %s\n" % (finding.severity, finding.check, finding.message))
            for path in finding.paths[:10]:
                sys.stdout.write("        %s\n" % path)
        if result.limitations:
            sys.stdout.write("  limitations: %s\n" % ", ".join(result.limitations))
    return VERDICT_EXIT_CODES.get(verdict, EXIT_INTERNAL_ERROR)


def cmd_explain(args: argparse.Namespace) -> int:
    cwd = os.path.abspath(args.cwd or os.getcwd())
    try:
        policy = _load_policy(args, cwd)
    except policy_module.PolicyError as exc:
        return _fail("SafeGit policy error: %s" % exc, EXIT_INTERNAL_ERROR)

    target = args.target
    if target in policy.rules:
        rule_verdict = policy.rules[target]
        payload = {
            "kind": "rule",
            "rule_id": target,
            "verdict": rule_verdict,
            "alternative": engine._ALTERNATIVES.get(target, ""),
            "policy_profile": policy.profile,
        }
        if args.json:
            _print_json(payload)
        else:
            sys.stdout.write("%s -> %s\n" % (target, rule_verdict))
            if payload["alternative"]:
                sys.stdout.write("  alternative: %s\n" % payload["alternative"])
        return 0

    from . import shellparse

    parsed = shellparse.parse(target)
    invocations = gitop.resolve_invocations(parsed)
    operations = []
    for invocation in invocations:
        for op in gitop.classify_all(invocation):
            operations.append(
                {
                    "rule_id": op.rule_id,
                    "verdict": policy.rule_verdict(op.rule_id),
                    "subcommand": op.subcommand,
                    "detail": op.detail,
                    "flags": sorted(op.flags),
                    "branch_hint": op.branch_hint,
                    "path_hint": op.path_hint,
                    "ambiguity": op.ambiguity,
                }
            )
    payload = {
        "kind": "command",
        "command": target,
        "parse_unknowns": parsed.unknown_reasons,
        "invocations": len(invocations),
        "operations": operations,
        "policy_profile": policy.profile,
    }
    if args.json:
        _print_json(payload)
    else:
        if not operations:
            sys.stdout.write("no git operation detected in: %s\n" % target)
        for operation in operations:
            sys.stdout.write(
                "%s -> %s (%s)\n"
                % (operation["rule_id"], operation["verdict"], operation["detail"])
            )
        if parsed.unknown_reasons:
            sys.stdout.write("unknowns: %s\n" % ", ".join(parsed.unknown_reasons))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    cwd = os.path.abspath(args.cwd or os.getcwd())
    try:
        policy = _load_policy(args, cwd)
    except policy_module.PolicyError as exc:
        return _fail("SafeGit policy error: %s" % exc, EXIT_INTERNAL_ERROR)

    ctx = _make_context(args, cwd=cwd, policy=policy)
    ctx.check_approvals = False
    decision = engine.evaluate(
        args.tool or "Bash",
        {"command": args.command_text, "cwd": cwd},
        ctx=ctx,
        non_interactive=True,
    )
    fingerprint, rule_id = engine.action_fingerprint_for_findings(
        decision.findings, ctx=ctx, evidence=decision.evidence
    )
    if not fingerprint:
        if decision.verdict == ALLOW:
            sys.stdout.write("SafeGit: nothing to approve - the action is already allowed.\n")
            return 0
        return _fail(
            "SafeGit: no owner-gated finding for this action (%s / %s)"
            % (decision.verdict, decision.reason_code),
            EXIT_USAGE,
        )

    code = approvals.confirmation_code(fingerprint)
    repo = decision.evidence.get("repo") or {}
    if not args.confirm_code:
        sys.stdout.write(
            "Approval request\n"
            "  rule:        %s\n"
            "  action:      %s\n"
            "  repository:  %s\n"
            "  branch/head: %s %s\n"
            "  fingerprint: %s\n"
            "  code:        %s\n"
            'Re-run with --confirm-code %s --reason "<why>" in an interactive terminal.\n'
            % (
                rule_id,
                args.command_text,
                repo.get("root", "<unknown>"),
                repo.get("branch", ""),
                str(repo.get("head", ""))[:10],
                fingerprint,
                code,
                code,
            )
        )
        return 0

    if args.confirm_code.strip().upper() != code:
        return _fail("SafeGit: confirmation code does not match", EXIT_USAGE)
    if policy.approvals.require_interactive and not sys.stdin.isatty():
        return _fail(
            "SafeGit: minting an approval requires an interactive terminal "
            "(non-interactive callers must not be able to self-approve)",
            EXIT_USAGE,
        )
    try:
        approval = approvals.mint(
            fingerprint=fingerprint,
            rule_id=rule_id,
            repo_root=str(repo.get("root", "")),
            branch=str(repo.get("branch", "")),
            head=str(repo.get("head", "")),
            reason=args.reason or "",
            interactive=sys.stdin.isatty(),
            ttl_seconds=args.ttl or policy.approvals.ttl_seconds,
            max_uses=policy.approvals.max_uses,
            path=ctx.store_path,
        )
    except approvals.ApprovalError as exc:
        return _fail("SafeGit: could not store approval: %s" % exc, EXIT_INTERNAL_ERROR)
    payload = approval.to_dict()
    if args.json:
        _print_json(payload)
    else:
        sys.stdout.write(
            "Approval %s stored (single use, expires in %ds).\n"
            % (approval.approval_id, approval.expires_at - approval.created_at)
        )
        sys.stdout.write("The next matching action will be allowed once.\n")
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    if args.action == "init":
        target = pathlib.Path(args.path or ".safegit/safegit.policy.json")
        try:
            written = policy_module.write_default(
                target, profile=args.profile or "default", overwrite=args.force
            )
        except policy_module.PolicyError as exc:
            return _fail("SafeGit: %s" % exc, EXIT_USAGE)
        sys.stdout.write("wrote %s (profile: %s)\n" % (written, args.profile or "default"))
        return 0

    if args.action == "show":
        try:
            policy = _load_policy(args, os.getcwd())
        except policy_module.PolicyError as exc:
            return _fail("SafeGit policy error: %s" % exc, EXIT_INTERNAL_ERROR)
        _print_json(policy.to_dict())
        return 0

    if args.action == "validate":
        args.policy = args.policy or args.path
        try:
            policy = _load_policy(args, os.getcwd())
        except policy_module.PolicyError as exc:
            sys.stdout.write("INVALID: %s\n" % exc)
            return 1
        sys.stdout.write(
            "VALID: %s (profile=%s, rules=%d, digest=%s)\n"
            % (
                policy.source_path or "<builtin>",
                policy.profile,
                len(policy.rules),
                policy.digest[:23],
            )
        )
        return 0

    return _fail("unknown policy action", EXIT_USAGE)


def cmd_audit(args: argparse.Namespace) -> int:
    try:
        policy = _load_policy(args, os.getcwd())
    except policy_module.PolicyError:
        policy = None
    cwd = os.path.abspath(args.cwd or os.getcwd())
    if args.path:
        path = pathlib.Path(args.path)
    elif policy is not None and policy.audit.path:
        path = pathlib.Path(policy.audit.path)
    else:
        path = receipt_module.default_audit_path(
            policy_path=policy.source_path if policy else "",
            cwd=cwd,
            repo_root=gitstate.find_repo_root(cwd, git_executable=args.git or "git"),
        )
    if args.summary:
        summary = receipt_module.summarize_audit(path)
        if args.json:
            _print_json(summary.to_dict())
        else:
            sys.stdout.write("%s\n" % summary.path)
            sys.stdout.write("  entries: %d\n" % summary.entries)
            for verdict, count in sorted(summary.verdicts.items()):
                sys.stdout.write("  %s: %d\n" % (verdict, count))
        return 0
    entries = receipt_module.read_audit(path, limit=args.tail)
    if args.json:
        _print_json(entries)
    else:
        for entry in entries:
            sys.stdout.write(
                "%s %s %s %s\n"
                % (
                    entry.get("created_at", ""),
                    entry.get("verdict", ""),
                    entry.get("reason_code", ""),
                    entry.get("action_digest", "")[:19],
                )
            )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    cwd = os.path.abspath(args.cwd or os.getcwd())
    checks: list[dict[str, Any]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    python_ok = sys.version_info[:2] >= SUPPORTED_PYTHON
    add(
        "python_version",
        "PASS" if python_ok else "FAIL",
        "%d.%d.%d (>= %d.%d required)"
        % (
            sys.version_info[0],
            sys.version_info[1],
            sys.version_info[2],
            *SUPPORTED_PYTHON,
        ),
    )

    git_executable = args.git or "git"
    git_ok = gitstate.is_git_executable_available(git_executable)
    add("git_available", "PASS" if git_ok else "FAIL", _git_version(git_executable))

    state = gitstate.probe(cwd, git_executable=git_executable, timeout=float(args.timeout))
    if state.available:
        add(
            "repository",
            "PASS",
            "%s branch=%s dirty=%d worktrees=%d"
            % (
                state.root,
                state.branch or "<detached>",
                state.work_in_progress,
                len(state.worktrees),
            ),
        )
    else:
        add("repository", "WARN", "no repository at %s (%s)" % (cwd, state.reason))

    try:
        policy = _load_policy(args, cwd)
        add(
            "policy",
            "PASS",
            "%s profile=%s rules=%d digest=%s"
            % (
                policy.source_path or "<builtin>",
                policy.profile,
                len(policy.rules),
                policy.digest[:19],
            ),
        )
    except policy_module.PolicyError as exc:
        add("policy", "FAIL", "policy invalid or missing: %s" % exc)
        policy = None

    store = (
        pathlib.Path(args.approval_store) if args.approval_store else approvals.default_store_path()
    )
    store_parent_writable = _is_writable(store.parent)
    add(
        "approval_store",
        "PASS" if store_parent_writable else "WARN",
        "%s (%s)" % (store, "writable" if store_parent_writable else "not writable"),
    )

    claude_settings = pathlib.Path(cwd) / ".claude" / "settings.json"
    opencode_plugin = pathlib.Path(cwd).joinpath(*OPENCODE_PLUGIN_DIR, "safegit.js")
    add(
        "claude_hook",
        "PASS" if _file_mentions(claude_settings, "safegit") else "WARN",
        str(claude_settings) if claude_settings.is_file() else "no project .claude/settings.json",
    )
    add(
        "opencode_plugin",
        "PASS" if opencode_plugin.is_file() else "WARN",
        str(opencode_plugin) if opencode_plugin.is_file() else "no project plugin installed",
    )

    selftest_failures = _selftest_failures(policy)
    add(
        "rule_selftest",
        "PASS" if not selftest_failures else "FAIL",
        "all built-in rule expectations hold"
        if not selftest_failures
        else "; ".join(selftest_failures[:3]),
    )

    overall = "PASS"
    if any(check["status"] == "FAIL" for check in checks):
        overall = "FAIL"
    elif any(check["status"] == "WARN" for check in checks):
        overall = "WARN"
    payload = {
        "schema": "safegit.doctor/1",
        "overall": overall,
        "version": __version__,
        "checks": checks,
    }
    if args.json:
        _print_json(payload)
    else:
        sys.stdout.write("SafeGit doctor: %s\n" % overall)
        for check in checks:
            sys.stdout.write(
                "  [%s] %-20s %s\n" % (check["status"], check["check"], check["detail"])
            )
    return 0 if overall != "FAIL" else 1


def _is_writable(path: pathlib.Path) -> bool:
    probe = path
    while True:
        if probe.exists():
            break
        if probe.parent == probe:
            return False
        probe = probe.parent
    return os.access(probe, os.W_OK)


def _file_mentions(path: pathlib.Path, needle: str) -> bool:
    if not path.is_file():
        return False
    try:
        return needle in path.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False


_EXPECTATIONS: tuple[tuple[str, str, str], ...] = (
    ("git reset --hard", gitop.RULE_RESET_HARD, DENY),
    ("git clean -fd", gitop.RULE_CLEAN_FORCE, DENY),
    ("git push --force origin main", gitop.RULE_PUSH_FORCE, DENY),
    ("git push -f origin main", gitop.RULE_PUSH_FORCE, DENY),
    ("git branch -D feature", gitop.RULE_BRANCH_DELETE_FORCE, REQUIRE_OWNER),
    ("git commit --amend", gitop.RULE_COMMIT_AMEND, REQUIRE_OWNER),
    ("git rebase -i HEAD~2", gitop.RULE_REBASE, REQUIRE_OWNER),
    (
        "git push --force-with-lease origin main",
        gitop.RULE_PUSH_FORCE_LEASE,
        REQUIRE_OWNER,
    ),
    ("git commit --no-verify -m x", gitop.RULE_HOOK_BYPASS, DENY),
    ("git restore .", gitop.RULE_RESTORE_WORKTREE, DENY),
    ("git stash drop", gitop.RULE_STASH_DESTROY, DENY),
    ("git filter-branch --all", gitop.RULE_HISTORY_FILTER, DENY),
    ("git add .", gitop.RULE_ADD_ALL, ALLOW),
    ("git commit -m ok", gitop.RULE_COMMIT_PLAIN, ALLOW),
    ("git status", gitop.RULE_NON_DESTRUCTIVE, ALLOW),
    ("git diff --cached --check", gitop.RULE_NON_DESTRUCTIVE, ALLOW),
    ("git clean -n", gitop.RULE_NON_DESTRUCTIVE, ALLOW),
    ("git push --dry-run --force origin main", gitop.RULE_NON_DESTRUCTIVE, ALLOW),
)


def _selftest_failures(policy: policy_module.Policy | None) -> list[str]:
    """Check classification always, verdicts against the built-in default table.

    The expected *verdicts* belong to the `default` profile; `strict` and `ci`
    deliberately deny operations that `default` allows.  So the selftest
    verifies two profile-independent things instead: every command classifies
    as documented, and no profile ever allows an operation on the
    never-allowed list.
    """
    failures: list[str] = []
    active_policy = policy or policy_module.from_dict(policy_module.default_policy_dict())
    expected_policy = policy_module.from_dict(policy_module.default_policy_dict())
    from . import shellparse

    never_allowed = (
        gitop.RULE_RESET_HARD,
        gitop.RULE_CLEAN_FORCE,
        gitop.RULE_PUSH_FORCE,
        gitop.RULE_HISTORY_FILTER,
        gitop.RULE_HISTORY_EXPIRE,
        gitop.RULE_HOOK_BYPASS,
    )
    for rule_id in never_allowed:
        if active_policy.rule_verdict(rule_id) == ALLOW:
            failures.append("%s must never be ALLOW in an active policy" % rule_id)

    for command, expected_rule, expected_verdict in _EXPECTATIONS:
        parsed = shellparse.parse(command)
        ops = []
        for invocation in gitop.resolve_invocations(parsed):
            ops.extend(gitop.classify_all(invocation))
        matching = [op for op in ops if op.rule_id == expected_rule]
        if not matching:
            failures.append(
                "%r did not map to %s (got %s)"
                % (command, expected_rule, [op.rule_id for op in ops] or "no operation")
            )
            continue
        verdict = expected_policy.rule_verdict(expected_rule)
        if verdict != expected_verdict:
            failures.append(
                "%s resolves to %s in the default profile, expected %s"
                % (expected_rule, verdict, expected_verdict)
            )
    return failures


def cmd_selftest(args: argparse.Namespace) -> int:
    try:
        policy = _load_policy(args, os.getcwd())
    except policy_module.PolicyError as exc:
        return _fail("SafeGit policy error: %s" % exc, EXIT_INTERNAL_ERROR)
    failures = _selftest_failures(policy)
    payload = {
        "schema": "safegit.selftest/1",
        "checks": len(_EXPECTATIONS),
        "failures": failures,
        "ok": not failures,
    }
    if args.json:
        _print_json(payload)
    else:
        for failure in failures:
            sys.stdout.write("FAIL: %s\n" % failure)
        sys.stdout.write(
            "SafeGit selftest: %d/%d expectations hold\n"
            % (len(_EXPECTATIONS) - len(failures), len(_EXPECTATIONS))
        )
    return 0 if not failures else 1


def cmd_install(args: argparse.Namespace) -> int:
    cwd = os.path.abspath(args.dir or os.getcwd())
    host = args.host
    if host == "claude":
        return _install_claude(args, cwd)
    if host == "opencode":
        return _install_opencode(args, cwd)
    if host == "githooks":
        return _install_githooks(args, cwd)
    return _fail("unknown integration: %s" % host, EXIT_USAGE)


def _python_launcher_argv() -> list[str]:
    argv = [sys.executable]
    if _ISOLATED_PYTHON:
        argv.append("-P")
    argv.extend(["-m", "safegit"])
    return argv


def _hook_command_prefix() -> str:
    executable = sys.executable
    if any(char in executable for char in _SHELL_METACHARACTERS):
        raise policy_module.PolicyError("UNSAFE_INTERPRETER_PATH:%s" % executable)
    launcher = " ".join(_python_launcher_argv())
    if " " in executable:
        return '"%s" %s' % (executable, " ".join(_python_launcher_argv()[1:]))
    return launcher


def _sh_hook_command_prefix() -> str:
    """Interpreter prefix for a POSIX ``sh`` hook (Git for Windows runs hooks in Git Bash).

    ``sh`` treats an unquoted backslash as an escape, so a Windows path collapses to
    ``C:Users...``.  The path is quoted and written with forward slashes, which both
    Git Bash and Windows accept.
    """
    executable = sys.executable
    if any(char in executable for char in _SHELL_METACHARACTERS):
        raise policy_module.PolicyError("UNSAFE_INTERPRETER_PATH:%s" % executable)
    quoted = '"%s"' % executable.replace("\\", "/")
    return " ".join([quoted, *_python_launcher_argv()[1:]])


def _plugin_argv_literal() -> str:
    return json.dumps(_python_launcher_argv())


def _pinned_args(cwd: str) -> list[str]:
    """Pin the policy and approval store at install time.

    Without pinning, a persisted ``SAFEGIT_POLICY`` / ``SAFEGIT_APPROVAL_STORE``
    environment variable silently redirects the gate.  The installed hook
    therefore carries explicit paths (or an explicit builtin profile) so the
    environment cannot change what the gate trusts.
    """
    args: list[str] = []
    try:
        resolved = policy_module.resolve_policy_path(start_dir=cwd)
    except Exception:
        resolved = None
    if resolved is not None and pathlib.Path(resolved).is_file():
        args.extend(["--policy", str(resolved)])
    else:
        args.extend(["--profile", "default"])
    args.extend(["--approval-store", str(approvals.default_store_path())])
    return args


def _install_claude(args: argparse.Namespace, cwd: str) -> int:
    settings_path = pathlib.Path(args.settings or (pathlib.Path(cwd) / ".claude" / "settings.json"))
    try:
        entry_command = "%s hook claude %s" % (
            _hook_command_prefix(),
            " ".join(_pinned_args(cwd)),
        )
    except policy_module.PolicyError as exc:
        return _fail("SafeGit: cannot build a safe hook command (%s)" % exc, EXIT_USAGE)
    payload = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": args.matcher or CLAUDE_HOOK_MATCHER,
                    "hooks": [
                        {
                            "type": "command",
                            "command": entry_command,
                            "timeout": args.hook_timeout or CLAUDE_HOOK_TIMEOUT_SECONDS,
                        }
                    ],
                }
            ]
        }
    }
    existing: dict[str, Any] = {}
    if settings_path.is_file():
        try:
            existing = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return _fail("existing %s is not valid JSON; refusing to touch it" % settings_path)
        if not isinstance(existing, dict):
            return _fail("existing %s is not a JSON object; refusing to touch it" % settings_path)

    if args.global_scope and not args.i_understand_this_is_global:
        return _fail(
            "refusing to treat this as a global settings write without "
            "--i-understand-this-is-global",
            EXIT_USAGE,
        )

    merged = _merge_claude_settings(existing, payload)
    if not args.write:
        sys.stdout.write("SafeGit install (dry run) - Claude Code PreToolUse hook\n")
        sys.stdout.write("target: %s\n" % settings_path)
        _print_json(merged)
        sys.stdout.write("Re-run with --write to apply.\n")
        return 0

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    backup = settings_path.with_suffix(settings_path.suffix + ".safegit-backup")
    if settings_path.is_file() and not backup.exists():
        backup.write_text(settings_path.read_text(encoding="utf-8"), encoding="utf-8")
    settings_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sys.stdout.write("wrote hook into %s\n" % settings_path)
    sys.stdout.write("verify with: %s doctor\n" % _hook_command_prefix())
    return 0


def _merge_claude_settings(existing: dict[str, Any], addition: dict[str, Any]) -> dict[str, Any]:
    merged = json.loads(json.dumps(existing))
    hooks = merged.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        merged["hooks"] = hooks
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        pre = []
        hooks["PreToolUse"] = pre
    for entry in pre:
        if isinstance(entry, dict):
            for hook in entry.get("hooks", []) or []:
                if isinstance(hook, dict) and "safegit" in str(hook.get("command", "")):
                    return merged
    pre.extend(addition["hooks"]["PreToolUse"])
    return merged


OPENCODE_PLUGIN_TEMPLATE = """// SafeGit plugin for OpenCode - thin adapter, no policy of its own.
// Every tool call is classified by the SafeGit CLI before it runs.
// SafeGit decides; this file only transports the decision.
// Dual export: OpenCode 2.x calls setup(ctx); OpenCode 1.x calls server(input).
// Fail-closed: unknown project dir, spawn error, timeout or non-zero exit => refused.
import { spawnSync } from "node:child_process"
import path from "node:path"

const SAFEGIT_ARGV = process.env.SAFEGIT_CLI ? [process.env.SAFEGIT_CLI] : __SAFEGIT_ARGV__
const SAFEGIT_PINNED_ARGS = __SAFEGIT_PINNED_ARGS__

function gate(cwd, call) {
  if (!cwd) throw new Error("SafeGit: project directory unknown. Refusing the tool call.")
  const payload = JSON.stringify({ ...call, cwd, args: call.args ?? {} })
  const result = spawnSync(
    SAFEGIT_ARGV[0],
    [...SAFEGIT_ARGV.slice(1), "hook", "opencode", "--non-interactive", ...SAFEGIT_PINNED_ARGS],
    { input: payload, encoding: "utf8", timeout: 20000, windowsHide: true },
  )
  if (result.error) {
    throw new Error(`SafeGit could not run (${result.error.message}). Refusing the tool call.`)
  }
  if (result.status === 0) return
  const reason = (result.stderr || "").trim() || `SafeGit blocked this call (exit ${result.status})`
  throw new Error(reason)
}

function within(dir, root) {
  const norm = (p) => {
    const r = path.resolve(p)
    return process.platform === "win32" ? r.toLowerCase() : r
  }
  const rel = path.relative(norm(root), norm(dir))
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))
}

export default {
  id: "safegit",
  // OpenCode 2.x: the plugin runs in a background service whose process.cwd() is not the
  // project. ctx.location is where this plugin instance loaded, not necessarily where a
  // session runs, so each call is gated in its session's directory, and only if that lies
  // inside this instance's project (the pinned policy belongs to it). Throwing aborts the call.
  async setup(ctx) {
    const root = ctx?.location?.directory
    await ctx.tool.hook("execute.before", async (event) => {
      let session = null
      try {
        session = await ctx.session.get({ sessionID: event.sessionID })
      } catch (err) {
        throw new Error(`SafeGit: session lookup failed (${err?.message}). Refusing the tool call.`)
      }
      const cwd = session?.location?.directory
      if (!root || !cwd) throw new Error("SafeGit: project directory unknown. Refusing the tool call.")
      if (!within(cwd, root)) {
        throw new Error(`SafeGit: session directory ${cwd} is outside the plugin project ${root}. Refusing the tool call.`)
      }
      gate(cwd, { tool: event.tool, sessionID: event.sessionID, callID: event.id, args: event.input })
    })
  },
  // OpenCode 1.x
  async server({ directory }) {
    return {
      "tool.execute.before": async (input, output) => {
        gate(directory, { tool: input.tool, sessionID: input.sessionID, callID: input.callID, args: output.args })
      },
    }
  },
}
"""

OPENCODE_PLUGIN_DIR = (".opencode", "plugins")


def _opencode_pinned_args(args: argparse.Namespace, cwd: str) -> list[str]:
    """Pinned args plus an absolute ``--git``: OpenCode's service PATH may lack git."""
    pinned = _pinned_args(cwd)
    git = shutil.which(args.git)
    if git:
        pinned.extend(["--git", os.path.abspath(git)])
    else:
        sys.stderr.write(
            "SafeGit: warning: %r not found on PATH; the plugin will rely on the PATH "
            "OpenCode runs with (pass --git <absolute path>)\n" % args.git
        )
    return pinned


def _install_opencode(args: argparse.Namespace, cwd: str) -> int:
    plugin_dir = pathlib.Path(cwd).joinpath(*OPENCODE_PLUGIN_DIR)
    target = plugin_dir / "safegit.js"
    pinned = _opencode_pinned_args(args, cwd)
    content = OPENCODE_PLUGIN_TEMPLATE.replace("__SAFEGIT_ARGV__", _plugin_argv_literal()).replace(
        "__SAFEGIT_PINNED_ARGS__", json.dumps(pinned)
    )
    legacy = pathlib.Path(cwd) / ".opencode" / "plugin" / "safegit.js"
    if not args.write:
        sys.stdout.write("SafeGit install (dry run) - OpenCode plugin\n")
        sys.stdout.write("target: %s\n" % target)
        sys.stdout.write("pinned arguments: %s\n" % " ".join(pinned))
        sys.stdout.write("--- plugin content ---\n%s\n" % content)
        sys.stdout.write("Re-run with --write to apply.\n")
        return 0
    plugin_dir.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    sys.stdout.write("wrote OpenCode plugin %s\n" % target)
    sys.stdout.write(
        "OpenCode loads plugins from .opencode/plugins automatically; "
        "run 'opencode --pure' only if you deliberately want it off.\n"
    )
    if legacy.is_file():
        sys.stdout.write(
            "note: an older SafeGit plugin exists at %s (ignored by OpenCode 2.x); "
            "remove it yourself once the new plugin is verified.\n" % legacy
        )
    return 0


GITHOOK_MARKER = "# >>> safegit pre-commit >>>"


def _install_githooks(args: argparse.Namespace, cwd: str) -> int:
    repo = os.path.abspath(args.repo or cwd)
    state = gitstate.probe(repo, timeout=float(args.timeout), git_executable=args.git)
    if not state.available:
        return _fail("not a git repository: %s (%s)" % (repo, state.reason), EXIT_USAGE)
    hooks_dir = pathlib.Path(state.common_dir or "") / "hooks"
    if not hooks_dir.is_dir():
        hooks_dir = pathlib.Path(repo) / ".git" / "hooks"
    target = hooks_dir / "pre-commit"
    block = '%s\nexec %s preflight --repo "$(git rev-parse --show-toplevel)" --strict\n%s\n' % (
        GITHOOK_MARKER,
        _sh_hook_command_prefix(),
        GITHOOK_MARKER.replace(">>>", "<<<"),
    )
    existing = ""
    if target.is_file():
        try:
            existing = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            existing = ""
    if GITHOOK_MARKER in existing:
        sys.stdout.write("SafeGit pre-commit hook already installed at %s\n" % target)
        return 0
    if existing.strip() and not args.force:
        return _fail(
            "an existing pre-commit hook is present at %s; refusing to modify it "
            "(use --force to append a SafeGit block)" % target,
            EXIT_USAGE,
        )
    if not args.write:
        sys.stdout.write("SafeGit install (dry run) - git pre-commit hook\n")
        sys.stdout.write("target: %s\n" % target)
        sys.stdout.write("--- appended block ---\n%s\n" % block)
        sys.stdout.write("Re-run with --write to apply.\n")
        return 0
    hooks_dir.mkdir(parents=True, exist_ok=True)
    prefix = existing if existing.strip() else "#!/bin/sh\n"
    # newline="\n": sh reads a trailing CR as part of the word, so CRLF breaks the hook.
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(prefix + ("\n" if not prefix.endswith("\n") else "") + block)
    try:
        os.chmod(target, 0o755)
    except OSError:
        pass
    sys.stdout.write("installed SafeGit pre-commit hook at %s\n" % target)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safegit",
        description="Git safety and repository protection for AI coding agents.",
    )
    parser.add_argument("--version", action="version", version="SafeGit %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_policy_flags(target: argparse.ArgumentParser) -> None:
        target.add_argument("--policy", help="path to safegit.policy.json")
        target.add_argument("--profile", help="built-in profile when no policy file exists")
        target.add_argument(
            "--timeout",
            type=float,
            default=gitstate.DEFAULT_TIMEOUT_SECONDS,
            help="git probe timeout in seconds (default: %(default)s)",
        )
        target.add_argument("--git", default="git", help="git executable (default: %(default)s)")
        target.add_argument("--approval-store", default="", help="path to approvals.json")
        target.add_argument(
            "--no-approvals",
            action="store_true",
            help="ignore outstanding owner approvals",
        )

    p_version = sub.add_parser("version", help="print version information")
    p_version.add_argument("--json", action="store_true")
    p_version.add_argument("--git", default="git")
    p_version.set_defaults(func=cmd_version)

    p_check = sub.add_parser("check", help="evaluate one command or tool call")
    p_check.add_argument("--command", dest="command_text", help="shell command to evaluate")
    p_check.add_argument("--tool", help="tool name (default: Bash)")
    p_check.add_argument("--args-json", help="raw tool arguments as JSON")
    p_check.add_argument("--cwd", help="working directory of the action")
    p_check.add_argument("--json", action="store_true")
    p_check.add_argument(
        "--non-interactive",
        action="store_true",
        help=(
            "no human is available: an UNKNOWN operation is denied instead of "
            "escalated to REQUIRE_OWNER. REQUIRE_OWNER itself still needs a "
            "pre-minted owner approval"
        ),
    )
    add_policy_flags(p_check)
    p_check.set_defaults(func=cmd_check)

    p_hook = sub.add_parser("hook", help="agent hook mode (reads one tool event from stdin)")
    p_hook.add_argument("host", choices=["claude", "opencode", "generic"])
    p_hook.add_argument("--cwd")
    p_hook.add_argument("--non-interactive", action="store_true", default=True)
    add_policy_flags(p_hook)
    p_hook.set_defaults(func=cmd_hook)

    p_pre = sub.add_parser("preflight", help="check what a commit is about to record")
    p_pre.add_argument("--repo")
    p_pre.add_argument(
        "--expect", action="append", help="glob of intended staged paths (repeatable)"
    )
    p_pre.add_argument("--strict", action="store_true", help="treat warnings as blocking")
    p_pre.add_argument("--json", action="store_true")
    add_policy_flags(p_pre)
    p_pre.set_defaults(func=cmd_preflight)

    p_explain = sub.add_parser("explain", help="explain a rule or a command classification")
    p_explain.add_argument("target")
    p_explain.add_argument("--cwd")
    p_explain.add_argument("--json", action="store_true")
    add_policy_flags(p_explain)
    p_explain.set_defaults(func=cmd_explain)

    p_approve = sub.add_parser("approve", help="mint a single-use owner approval")
    p_approve.add_argument("--command", dest="command_text", required=True)
    p_approve.add_argument("--tool", default="Bash")
    p_approve.add_argument("--cwd")
    p_approve.add_argument("--reason", default="")
    p_approve.add_argument("--ttl", type=int, default=0)
    p_approve.add_argument("--confirm-code", default="")
    p_approve.add_argument("--json", action="store_true")
    add_policy_flags(p_approve)
    p_approve.set_defaults(func=cmd_approve)

    p_policy = sub.add_parser("policy", help="create, show or validate the policy")
    p_policy.add_argument("action", choices=["init", "show", "validate"])
    p_policy.add_argument("--path")
    p_policy.add_argument("--policy", dest="policy")
    p_policy.add_argument("--force", action="store_true")
    p_policy.add_argument("--profile")
    p_policy.set_defaults(func=cmd_policy)

    p_audit = sub.add_parser("audit", help="read the decision audit log")
    p_audit.add_argument("--tail", type=int, default=20)
    p_audit.add_argument("--summary", action="store_true")
    p_audit.add_argument("--path")
    p_audit.add_argument("--cwd")
    p_audit.add_argument("--json", action="store_true")
    p_audit.add_argument("--policy")
    p_audit.add_argument("--profile")
    p_audit.add_argument("--git", default="git")
    p_audit.set_defaults(func=cmd_audit)

    p_doctor = sub.add_parser("doctor", help="check the local installation")
    p_doctor.add_argument("--cwd")
    p_doctor.add_argument("--json", action="store_true")
    p_doctor.add_argument("--policy")
    p_doctor.add_argument("--profile")
    p_doctor.add_argument("--timeout", type=float, default=gitstate.DEFAULT_TIMEOUT_SECONDS)
    p_doctor.add_argument("--git", default="git")
    p_doctor.add_argument("--approval-store", default="")
    p_doctor.set_defaults(func=cmd_doctor)

    p_self = sub.add_parser("selftest", help="run built-in rule expectations")
    p_self.add_argument("--json", action="store_true")
    p_self.add_argument("--policy")
    p_self.add_argument("--profile")
    p_self.set_defaults(func=cmd_selftest)

    p_install = sub.add_parser("install", help="wire SafeGit into an agent or git")
    p_install.add_argument("host", choices=["claude", "opencode", "githooks"])
    p_install.add_argument("--dir")
    p_install.add_argument("--repo")
    p_install.add_argument("--settings")
    p_install.add_argument("--matcher")
    p_install.add_argument("--hook-timeout", type=int, default=0)
    p_install.add_argument("--write", action="store_true", help="apply the change")
    p_install.add_argument("--force", action="store_true")
    p_install.add_argument("--global-scope", action="store_true")
    p_install.add_argument("--i-understand-this-is-global", action="store_true")
    p_install.add_argument("--git", default="git")
    p_install.add_argument("--timeout", type=float, default=gitstate.DEFAULT_TIMEOUT_SECONDS)
    p_install.set_defaults(func=cmd_install)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "func", None) is not cmd_hook:
        _guard_against_cwd_shadowing()
    try:
        return int(args.func(args))
    except policy_module.PolicyError as exc:
        return _fail("SafeGit policy error: %s" % exc, EXIT_INTERNAL_ERROR)
    except approvals.ApprovalError as exc:
        return _fail("SafeGit approval error: %s" % exc, EXIT_INTERNAL_ERROR)
    except KeyboardInterrupt:
        return _fail("interrupted", EXIT_INTERNAL_ERROR)
    except BrokenPipeError:
        return EXIT_INTERNAL_ERROR
    except Exception as exc:  # never let an unexpected error look like success
        sys.stderr.write(
            "SAFEGIT_INTERNAL_ERROR: %s: %s\n" % (exc.__class__.__name__, str(exc)[:200])
        )
        return EXIT_INTERNAL_ERROR
