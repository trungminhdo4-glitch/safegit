"""Regression tests for bypasses and false positives found in independent review.

Every test in this file corresponds to a concrete finding from the
adversarial code review or the security audit of the first release
candidate.  Each one failed before the fix; keeping them here is what makes
the fix durable.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from safegit import approvals, engine, gitop, policy as policy_module, shellparse  # noqa: E402
from safegit.verdicts import ALLOW, DENY, REQUIRE_OWNER, UNKNOWN  # noqa: E402

DANGEROUS = "git " + "reset --" + "hard"
FORCE_PUSH = "git " + "push --" + "force origin main"


def git(repo: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "SafeGit Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "SafeGit Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
    )
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=60,
        check=False,
    )


class RuleRegressionTests(unittest.TestCase):
    """Classification regressions: no repository required."""

    def rules(self, command: str) -> list[str]:
        parsed = shellparse.parse(command)
        found: list[str] = []
        for invocation in gitop.resolve_invocations(parsed):
            found.extend(op.rule_id for op in gitop.classify_all(invocation))
        return found

    def test_clean_long_option_abbreviation_is_caught(self) -> None:
        for command in ("git clean --forc -d", "git clean --f", "git clean --forc -x"):
            self.assertIn(
                gitop.RULE_CLEAN_FORCE,
                self.rules(command),
                "%r slipped past the force check" % command,
            )

    def test_branch_delete_with_abbreviated_force_is_caught(self) -> None:
        rules = self.rules("git branch --delete --forc feature")
        self.assertIn(gitop.RULE_BRANCH_DELETE_FORCE, rules)

    def test_push_force_with_lease_abbreviation_is_caught(self) -> None:
        rules = self.rules("git push --force-w origin feature")
        self.assertIn(gitop.RULE_PUSH_FORCE_LEASE, rules)

    def test_push_mirror_and_all_are_broad(self) -> None:
        for command in (
            "git push --mirror origin",
            "git push --all origin",
            "git push --tags origin",
        ):
            self.assertIn(gitop.RULE_PUSH_BROAD, self.rules(command), command)

    def test_push_dry_run_is_not_destructive(self) -> None:
        rules = self.rules("git push --dry-run --force origin main")
        self.assertIn(gitop.RULE_NON_DESTRUCTIVE, rules)
        self.assertNotIn(gitop.RULE_PUSH_FORCE, rules)

    def test_reflog_delete_is_history_expiry(self) -> None:
        self.assertIn(
            gitop.RULE_HISTORY_EXPIRE, self.rules("git reflog delete HEAD@{0}")
        )

    def test_unknown_long_option_on_clean_escalates(self) -> None:
        rules = self.rules("git clean --frobnicate -d")
        self.assertIn(gitop.RULE_OTHER, rules)

    def test_daily_commands_are_non_destructive(self) -> None:
        for command in (
            "git pull",
            "git pull --ff-only",
            "git reset --soft HEAD~1",
            "git reset --mixed",
            "git cherry-pick abc123",
            "git revert abc123",
            "git gc",
            "git init",
            "git rm --cached file.txt",
            "git update-index --refresh",
            "git checkout --ours conflicted.txt",
            "git switch -c new-branch",
        ):
            rules = self.rules(command)
            self.assertTrue(rules, "%r classified as nothing" % command)
            for rule in rules:
                self.assertEqual(
                    rule, gitop.RULE_NON_DESTRUCTIVE, "%r -> %s" % (command, rule)
                )

    def test_pull_rebase_is_a_rebase(self) -> None:
        self.assertIn(gitop.RULE_REBASE, self.rules("git pull --rebase"))

    def test_checkout_target_is_always_ambiguous(self) -> None:
        for command in (
            "git checkout main",
            "git checkout src",
            "git checkout src/app.py",
        ):
            parsed = shellparse.parse(command)
            ops = gitop.classify_all(gitop.resolve_invocations(parsed)[0])
            self.assertEqual(ops[0].ambiguity, "path_or_ref", command)

    def test_inline_config_on_read_only_subcommand_is_not_a_bypass(self) -> None:
        self.assertNotIn(
            gitop.RULE_HOOK_BYPASS, self.rules("git -c core.hooksPath=/dev/null status")
        )
        self.assertIn(
            gitop.RULE_HOOK_BYPASS,
            self.rules("git -c core.hooksPath=/dev/null commit -m x"),
        )

    def test_interpreter_wrapper_variants_are_scanned(self) -> None:
        for command in (
            'bash -lc "git status"',
            'powershell -COMMAND "git status"',
            'cmd //c "git status"',
            'sh -c "git status"',
        ):
            self.assertIn(
                "git", [c.argv[0] for c in shellparse.parse(command).commands], command
            )

    def test_transparent_prefix_values_are_skipped(self) -> None:
        for command in (
            "timeout -s KILL 5 git status",
            "nice -n 10 git status",
            "xargs git status",
        ):
            self.assertIn(
                "git", [c.argv[0] for c in shellparse.parse(command).commands], command
            )

    def test_escaped_space_program_is_split(self) -> None:
        commands = [c.argv for c in shellparse.parse("git\\ status").commands]
        self.assertEqual(commands, [("git", "status")])

    def test_interpreter_without_command_flag_is_flagged(self) -> None:
        parsed = shellparse.parse("bash script.sh")
        self.assertTrue(
            any(
                reason.startswith("INTERPRETER_WITHOUT_COMMAND_FLAG")
                for reason in parsed.unknown_reasons
            ),
            parsed.unknown_reasons,
        )

    def test_indirect_program_name_is_flagged(self) -> None:
        parsed = shellparse.parse("$G reset --hard")
        self.assertTrue(
            any(
                reason.startswith("INDIRECT_PROGRAM_NAME")
                for reason in parsed.unknown_reasons
            ),
            parsed.unknown_reasons,
        )


class EngineRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="safegit-regress-")
        self.addCleanup(self._tmp.cleanup)
        self.repo = os.path.join(self._tmp.name, "repo")
        os.makedirs(self.repo, exist_ok=True)
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.email", "test@example.invalid")
        git(self.repo, "config", "user.name", "SafeGit Test")
        pathlib.Path(self.repo, "README.md").write_text("hello\n", encoding="utf-8")
        pathlib.Path(self.repo, "src").mkdir(exist_ok=True)
        pathlib.Path(self.repo, "src", "app.py").write_text(
            "print('hi')\n", encoding="utf-8"
        )
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "initial")

        self.store_dir = tempfile.TemporaryDirectory(prefix="safegit-regress-store-")
        self.addCleanup(self.store_dir.cleanup)
        self.store = os.path.join(self.store_dir.name, "approvals.json")
        self.audit = os.path.join(self.store_dir.name, "audit.jsonl")
        previous = os.environ.get("SAFEGIT_AUDIT_PATH")
        os.environ["SAFEGIT_AUDIT_PATH"] = self.audit
        self.addCleanup(self._restore_audit_env, previous)

    def _restore_audit_env(self, previous: str | None) -> None:
        if previous is None:
            os.environ.pop("SAFEGIT_AUDIT_PATH", None)
        else:
            os.environ["SAFEGIT_AUDIT_PATH"] = previous

    def context(self, profile: str = "default") -> engine.EngineContext:
        return engine.EngineContext(
            cwd=self.repo,
            policy=policy_module.from_dict(
                policy_module.default_policy_dict(profile), source_path="<test>"
            ),
            approval_store=self.store,
            timeout=15.0,
        )

    def decide(
        self,
        command: str,
        *,
        profile: str = "default",
        tool: str = "Bash",
        **extra: object,
    ) -> engine.Decision:
        args: dict[str, object] = {"command": command, "cwd": self.repo}
        args.update(extra)
        return engine.evaluate(
            tool, args, ctx=self.context(profile), non_interactive=False
        )

    def test_forced_checkout_of_branch_with_dirty_tree_is_denied(self) -> None:
        pathlib.Path(self.repo, "src", "app.py").write_text(
            "print('dirty')\n", encoding="utf-8"
        )
        for command in (
            "git checkout -f main",
            "git switch -f main",
            "git checkout --force main",
        ):
            decision = self.decide(command)
            self.assertEqual(
                decision.verdict, DENY, "%s -> %s" % (command, decision.to_dict())
            )

    def test_forced_checkout_of_branch_with_clean_tree_is_allowed(self) -> None:
        self.assertEqual(self.decide("git checkout -f main").verdict, ALLOW)

    def test_plain_branch_checkout_with_dirty_tree_is_allowed(self) -> None:
        pathlib.Path(self.repo, "src", "app.py").write_text(
            "print('dirty')\n", encoding="utf-8"
        )
        decision = self.decide("git checkout main")
        self.assertEqual(decision.verdict, ALLOW)
        self.assertEqual(decision.findings[0].rule_id, "git.checkout.switch")

    def test_checkout_of_directory_with_local_changes_is_denied(self) -> None:
        pathlib.Path(self.repo, "src", "app.py").write_text(
            "print('dirty')\n", encoding="utf-8"
        )
        self.assertEqual(self.decide("git checkout src").verdict, DENY)

    def test_filesystem_write_is_still_checked_next_to_a_git_command(self) -> None:
        for command in (
            "git status && echo x > .env",
            "git status; Set-Content .env -Value x",
            "git log --oneline > .git/config",
        ):
            decision = self.decide(command)
            self.assertEqual(
                decision.verdict, DENY, "%s -> %s" % (command, decision.to_dict())
            )

    def test_repo_metadata_directory_is_protected(self) -> None:
        for target in (".git", ".git/hooks", ".safegit"):
            decision = engine.evaluate(
                "Bash",
                {
                    "command": "Remove-Item -Recurse -Force %s" % target,
                    "cwd": self.repo,
                },
                ctx=self.context(),
            )
            self.assertEqual(decision.verdict, DENY, target)

    def test_interpreter_write_to_protected_path_is_denied(self) -> None:
        for command in (
            "python -c \"import pathlib; pathlib.Path('.claude/settings.json').write_text('{}')\"",
            "python -c \"import pathlib; pathlib.Path('.safegit/safegit.policy.json').unlink()\"",
            "node -e \"require('fs').rmSync('.opencode/plugin', {recursive:true})\"",
            "python -c \"import shutil; shutil.rmtree('.safegit')\"",
        ):
            decision = self.decide(command)
            self.assertEqual(
                decision.verdict, DENY, "%s -> %s" % (command, decision.to_dict())
            )

    def test_planted_policy_file_cannot_be_written(self) -> None:
        for tool_args in (
            {"command": "Set-Content safegit.policy.json -Value {}", "cwd": self.repo},
            {
                "command": "Set-Content src/safegit.policy.json -Value {}",
                "cwd": self.repo,
            },
        ):
            decision = engine.evaluate("Bash", tool_args, ctx=self.context())
            self.assertEqual(decision.verdict, DENY, tool_args)

    def test_policy_file_write_tool_is_denied(self) -> None:
        decision = engine.evaluate(
            "Write",
            {
                "file_path": os.path.join(self.repo, "safegit.policy.json"),
                "content": "{}",
            },
            ctx=self.context(),
        )
        self.assertEqual(decision.verdict, DENY)

    def test_minimal_policy_keeps_the_default_protective_lists(self) -> None:
        minimal = policy_module.from_dict(
            {"schema": policy_module.SPEC_VERSION, "profile": "default"},
            source_path="<test>",
        )
        self.assertTrue(minimal.secret_paths)
        self.assertTrue(minimal.protected_paths)
        self.assertTrue(minimal.protected_branches)
        self.assertEqual(minimal.rules["git.reset.hard"], DENY)

    def test_policy_profile_field_is_honoured(self) -> None:
        document = policy_module.default_policy_dict("strict")
        document.pop("rules")
        loaded = policy_module.from_dict(document, source_path="<test>")
        self.assertEqual(loaded.rules["git.push.plain"], REQUIRE_OWNER)
        self.assertEqual(loaded.rules["git.push.force_with_lease"], DENY)

    def test_unknown_tool_arguments_are_not_an_implicit_allow(self) -> None:
        decision = engine.evaluate("Bash", {}, ctx=self.context())
        self.assertEqual(decision.verdict, REQUIRE_OWNER)

    def test_missing_file_path_is_not_an_implicit_allow(self) -> None:
        decision = engine.evaluate("Write", {"content": "x"}, ctx=self.context())
        self.assertEqual(decision.verdict, REQUIRE_OWNER)

    def test_write_named_tools_are_classified(self) -> None:
        for tool in (
            "write_to_file",
            "replace_in_file",
            "NotebookEdit",
            "Delete",
            "remove_file",
        ):
            decision = engine.evaluate(
                tool, {"path": os.path.join(self.repo, ".env")}, ctx=self.context()
            )
            self.assertEqual(
                decision.verdict, DENY, "%s -> %s" % (tool, decision.to_dict())
            )

    def test_command_named_tools_are_classified(self) -> None:
        decision = engine.evaluate(
            "bash_command", {"command": DANGEROUS, "cwd": self.repo}, ctx=self.context()
        )
        self.assertEqual(decision.verdict, DENY)

    def test_strict_profile_without_repository_state_is_not_allowed(self) -> None:
        outside = os.path.join(self._tmp.name, "no-repo")
        os.makedirs(outside, exist_ok=True)
        ctx = engine.EngineContext(
            cwd=outside,
            policy=policy_module.from_dict(
                policy_module.default_policy_dict("strict"), source_path="<test>"
            ),
            approval_store=self.store,
        )
        decision = engine.evaluate(
            "Bash", {"command": "git commit -m x", "cwd": outside}, ctx=ctx
        )
        self.assertNotEqual(decision.verdict, ALLOW)

    def test_approval_does_not_swallow_an_unknown_finding(self) -> None:
        command = "git commit --" + "amend -m x && git frobnicate"
        first = self.decide(command)
        self.assertEqual(first.verdict, REQUIRE_OWNER)
        blocking = [f for f in first.findings if f.verdict != ALLOW]
        self.assertTrue(any(f.verdict == UNKNOWN for f in blocking))
        fingerprint = engine.action_fingerprint_for_findings(
            first.findings, ctx=self.context(), evidence=first.evidence
        )[0]
        repo = first.evidence["repo"]
        approvals.mint(
            fingerprint=fingerprint,
            rule_id="git.commit.amend",
            repo_root=str(repo["root"]),
            branch=str(repo["branch"]),
            head=str(repo["head"]),
            reason="regression",
            interactive=True,
            path=pathlib.Path(self.store),
        )
        second = self.decide(command)
        self.assertNotEqual(second.verdict, ALLOW)

    def test_one_approval_cannot_cover_two_gated_operations(self) -> None:
        git(self.repo, "checkout", "-b", "feature")
        pathlib.Path(self.repo, "feature.txt").write_text("work\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "work")
        git(self.repo, "checkout", "main")
        command = "git branch -D feature && git rebase main"
        decision = self.decide(command)
        self.assertEqual(decision.verdict, REQUIRE_OWNER)
        restrictions = [
            f.rule_id for f in decision.findings if f.verdict == REQUIRE_OWNER
        ]
        self.assertGreaterEqual(len(set(restrictions)), 2, restrictions)
        repo = decision.evidence["repo"]
        fingerprint = approvals.compute_fingerprint(
            policy_digest=self.context().policy.digest,
            rule_id="git.rebase",
            action_text="git rebase main",
            repo_root=str(repo["root"]),
            branch=str(repo["branch"]),
            head=str(repo["head"]),
        )
        approvals.mint(
            fingerprint=fingerprint,
            rule_id="git.rebase",
            repo_root=str(repo["root"]),
            branch=str(repo["branch"]),
            head=str(repo["head"]),
            reason="regression",
            interactive=True,
            path=pathlib.Path(self.store),
        )
        self.assertNotEqual(self.decide(command).verdict, ALLOW)

    def test_approval_use_count_cannot_be_inflated(self) -> None:
        git(self.repo, "checkout", "-b", "feature2")
        pathlib.Path(self.repo, "feature2.txt").write_text("work\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "work")
        git(self.repo, "checkout", "main")
        command = "git branch -D feature2"
        decision = self.decide(command)
        fingerprint, rule_id = engine.action_fingerprint_for_findings(
            decision.findings, ctx=self.context(), evidence=decision.evidence
        )
        repo = decision.evidence["repo"]
        approval = approvals.mint(
            fingerprint=fingerprint,
            rule_id=rule_id,
            repo_root=str(repo["root"]),
            branch=str(repo["branch"]),
            head=str(repo["head"]),
            reason="regression",
            interactive=True,
            path=pathlib.Path(self.store),
        )
        document = json.loads(pathlib.Path(self.store).read_text(encoding="utf-8"))
        document["approvals"][0]["uses_remaining"] = 1000
        document["approvals"][0]["digest"] = approvals._digest_of(
            document["approvals"][0]
        )
        pathlib.Path(self.store).write_text(json.dumps(document), encoding="utf-8")
        self.assertEqual(self.decide(command).verdict, ALLOW)
        self.assertEqual(
            self.decide(command).verdict, REQUIRE_OWNER, "clamped to one use"
        )
        self.assertEqual(
            approval.approval_id,
            json.loads(pathlib.Path(self.store).read_text(encoding="utf-8"))[
                "approvals"
            ][0]["approval_id"],
        )
        self.assertEqual(
            json.loads(pathlib.Path(self.store).read_text(encoding="utf-8"))[
                "approvals"
            ][0]["uses_remaining"],
            0,
        )

    def test_approved_decision_reports_the_approval_reason(self) -> None:
        git(self.repo, "checkout", "-b", "feature3")
        pathlib.Path(self.repo, "feature3.txt").write_text("work\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "work")
        git(self.repo, "checkout", "main")
        command = "git branch -D feature3"
        decision = self.decide(command)
        fingerprint, rule_id = engine.action_fingerprint_for_findings(
            decision.findings, ctx=self.context(), evidence=decision.evidence
        )
        repo = decision.evidence["repo"]
        approvals.mint(
            fingerprint=fingerprint,
            rule_id=rule_id,
            repo_root=str(repo["root"]),
            branch=str(repo["branch"]),
            head=str(repo["head"]),
            reason="regression",
            interactive=True,
            path=pathlib.Path(self.store),
        )
        approved = self.decide(command)
        self.assertEqual(approved.verdict, ALLOW)
        self.assertEqual(approved.reason_code, engine.REASON_ALLOW_OWNER_APPROVED)

    def test_case_insensitive_protection_outside_a_repository(self) -> None:
        outside = os.path.join(self._tmp.name, "no-repo-2")
        os.makedirs(outside, exist_ok=True)
        decision = engine.evaluate(
            "Write",
            {"file_path": os.path.join(outside, ".ENV"), "content": "A=1"},
            ctx=engine.EngineContext(
                cwd=outside, policy=self.context().policy, approval_store=self.store
            ),
        )
        self.assertEqual(decision.verdict, DENY)

    def test_global_git_config_write_is_denied(self) -> None:
        home = pathlib.Path(self._tmp.name) / "fakehome"
        home.mkdir(exist_ok=True)
        decision = engine.evaluate(
            "Write",
            {
                "file_path": str(home / ".gitconfig"),
                "content": "[core]\n\thooksPath = /dev/null\n",
            },
            ctx=self.context(),
        )
        self.assertEqual(decision.verdict, DENY)

    def test_long_command_is_not_truncated_into_an_allow(self) -> None:
        padding = "echo " + "x" * 4200
        decision = self.decide(padding + " && " + DANGEROUS)
        self.assertEqual(decision.verdict, DENY)

    def test_path_token_flood_stays_bounded(self) -> None:
        command = "echo " + " ".join(
            "a/../a/%d/file.txt" % index for index in range(400)
        )
        decision = self.decide(command)
        self.assertIn(decision.verdict, (ALLOW, REQUIRE_OWNER, DENY))

    def test_mcp_tools_stay_out_of_scope_by_default_and_guarded_in_strict(self) -> None:
        default_decision = engine.evaluate(
            "mcp__filesystem__run_shell",
            {"command": DANGEROUS, "cwd": self.repo},
            ctx=self.context("default"),
        )
        self.assertEqual(default_decision.verdict, ALLOW)
        self.assertTrue(default_decision.out_of_scope)
        strict_decision = engine.evaluate(
            "mcp__filesystem__run_shell",
            {"command": DANGEROUS, "cwd": self.repo},
            ctx=self.context("strict"),
        )
        self.assertNotEqual(strict_decision.verdict, ALLOW)

    def test_candidate_probe_stays_bounded_on_a_large_untracked_tree(self) -> None:
        """A repo full of untracked files must not make the gate miss its budget."""
        import time

        big = os.path.join(self._tmp.name, "big")
        os.makedirs(big, exist_ok=True)
        git(big, "init", "-b", "main")
        git(big, "config", "user.email", "test@example.invalid")
        git(big, "config", "user.name", "SafeGit Test")
        pathlib.Path(big, "a.txt").write_text("x\n", encoding="utf-8")
        git(big, "add", "a.txt")
        git(big, "commit", "-m", "init")
        for index in range(1200):
            directory = pathlib.Path(big) / "node_modules" / ("pkg%d" % index)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "index.js").write_text(
                "module.exports = %d\n" % index, encoding="utf-8"
            )

        from safegit import gitstate

        started = time.monotonic()
        state = gitstate.probe(big)
        elapsed = time.monotonic() - started
        self.assertTrue(state.available)
        self.assertLess(
            elapsed, 6.0, "probe took %.2fs on a large untracked tree" % elapsed
        )
        self.assertIn(
            "UNTRACKED_ENTRIES_ARE_DIRECTORY_LEVEL" if state.untracked else "",
            list(state.limitations) + [""],
        )

    def test_probe_budget_exhaustion_is_reported(self) -> None:
        import time as _time

        from safegit import gitstate

        budget = gitstate.ProbeBudget(gitstate.MIN_TIMEOUT_SECONDS)
        _time.sleep(gitstate.MIN_TIMEOUT_SECONDS + 0.05)
        self.assertTrue(budget.exhausted)
        code, _, stderr = gitstate.run_git(
            ["rev-parse", "--show-toplevel"],
            cwd=self.repo,
            timeout=5.0,
            env=gitstate.build_env(),
            git_executable="git",
            budget=budget,
        )
        self.assertEqual(code, -4)
        self.assertEqual(stderr, gitstate.STATE_REASON_BUDGET)
        self.assertLess(
            gitstate.ProbeBudget(0.0).seconds,
            gitstate.DEFAULT_BUDGET_SECONDS,
            "a tiny budget must be clamped to the minimum, not disable the probe",
        )

    def test_shadowing_guard_refuses_a_planted_module(self) -> None:
        from safegit import cli

        scratch = os.path.join(self._tmp.name, "shadowed")
        os.makedirs(scratch, exist_ok=True)
        pathlib.Path(scratch, "safegit.py").write_text(
            "raise SystemExit(0)\n", encoding="utf-8"
        )
        previous = os.getcwd()
        os.chdir(scratch)
        try:
            with self.assertRaises(SystemExit) as captured:
                cli._guard_against_cwd_shadowing()
            self.assertEqual(captured.exception.code, 2)
        finally:
            os.chdir(previous)


if __name__ == "__main__":
    unittest.main(verbosity=2)
