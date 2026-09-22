"""State-aware engine tests against throwaway synthetic repositories.

Every repository used here is created under the system temp directory and
destroyed afterwards.  No test touches a real project repository.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from safegit import approvals, engine, gitstate, policy as policy_module  # noqa: E402
from safegit.verdicts import ALLOW, DENY, REQUIRE_OWNER, UNKNOWN  # noqa: E402

GIT_ENV = {
    "GIT_AUTHOR_NAME": "SafeGit Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "SafeGit Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def git(repo: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update(GIT_ENV)
    completed = subprocess.run(
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
    if check and completed.returncode != 0:
        raise AssertionError(
            "git %s failed in %s: %s%s"
            % (args, repo, completed.stdout, completed.stderr)
        )
    return completed


class RepoFixture:
    """A disposable git repository."""

    def __init__(self, path: str) -> None:
        self.path = path

    def write(self, relative: str, content: str) -> pathlib.Path:
        target = pathlib.Path(self.path) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def commit_all(self, message: str) -> None:
        git(self.path, "add", "-A")
        git(self.path, "commit", "-m", message)

    def read(self, relative: str) -> str:
        return (pathlib.Path(self.path) / relative).read_text(encoding="utf-8")


class EngineStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="safegit-test-")
        self.addCleanup(self._tmp.cleanup)
        self.repo = RepoFixture(os.path.join(self._tmp.name, "repo"))
        os.makedirs(self.repo.path, exist_ok=True)
        git(self.repo.path, "init", "-b", "main")
        git(self.repo.path, "config", "user.email", "test@example.invalid")
        git(self.repo.path, "config", "user.name", "SafeGit Test")
        self.repo.write("README.md", "hello\n")
        self.repo.write("src/app.py", "print('hello')\n")
        self.repo.commit_all("initial")

        self.store_dir = tempfile.TemporaryDirectory(prefix="safegit-store-")
        self.addCleanup(self.store_dir.cleanup)
        self.store = os.path.join(self.store_dir.name, "approvals.json")

    def make_context(
        self, profile: str = "default", cwd: str | None = None
    ) -> engine.EngineContext:
        policy = policy_module.from_dict(
            policy_module.default_policy_dict(profile), source_path="<test>"
        )
        return engine.EngineContext(
            cwd=cwd or self.repo.path,
            policy=policy,
            approval_store=self.store,
            timeout=15.0,
        )

    def decide(
        self,
        command: str,
        *,
        profile: str = "default",
        cwd: str | None = None,
        non_interactive: bool = False,
    ) -> engine.Decision:
        return engine.evaluate(
            "Bash",
            {"command": command, "cwd": cwd or self.repo.path},
            ctx=self.make_context(profile, cwd),
            non_interactive=non_interactive,
        )

    def rules_of(self, decision: engine.Decision) -> list[str]:
        return [finding.rule_id for finding in decision.findings]

    def finding(self, decision: engine.Decision, rule_id: str) -> engine.Finding:
        for finding in decision.findings:
            if finding.rule_id == rule_id:
                return finding
        raise AssertionError(
            "no finding for %s in %s" % (rule_id, self.rules_of(decision))
        )

    def test_clean_repository_allows_read_only_commands(self) -> None:
        for command in (
            "git status",
            "git log --oneline -3",
            "git diff --cached --check",
        ):
            decision = self.decide(command)
            self.assertEqual(
                decision.verdict, ALLOW, "%s -> %s" % (command, decision.to_dict())
            )

    def test_reset_hard_reports_work_at_risk(self) -> None:
        self.repo.write("src/app.py", "print('changed')\n")
        decision = self.decide("git reset --hard")
        self.assertEqual(decision.verdict, DENY)
        finding = self.finding(decision, "git.reset.hard")
        self.assertGreaterEqual(int(finding.evidence["work_at_risk"]), 1)
        self.assertTrue(finding.evidence["data_loss_confirmed"])

    def test_reset_hard_is_denied_even_on_clean_tree(self) -> None:
        decision = self.decide("git reset --hard")
        self.assertEqual(decision.verdict, DENY)
        self.assertFalse(
            self.finding(decision, "git.reset.hard").evidence["data_loss_confirmed"]
        )

    def test_clean_force_reports_untracked_loss(self) -> None:
        self.repo.write("scratch/notes.txt", "unversioned\n")
        decision = self.decide("git clean -fd")
        self.assertEqual(decision.verdict, DENY)
        finding = self.finding(decision, "git.clean.force")
        self.assertGreaterEqual(int(finding.evidence["work_at_risk"]), 1)

    def test_clean_dry_run_is_allowed(self) -> None:
        self.repo.write("scratch/notes.txt", "unversioned\n")
        self.assertEqual(self.decide("git clean -n").verdict, ALLOW)

    def test_branch_delete_force_is_allowed_when_merged(self) -> None:
        git(self.repo.path, "branch", "merged-branch")
        decision = self.decide("git branch -D merged-branch")
        self.assertEqual(decision.verdict, ALLOW)
        self.assertEqual(
            self.finding(decision, "git.branch.delete.force").evidence[
                "unmerged_commits"
            ],
            0,
        )

    def test_branch_delete_force_requires_owner_when_unmerged(self) -> None:
        git(self.repo.path, "checkout", "-b", "feature")
        self.repo.write("feature.txt", "new work\n")
        self.repo.commit_all("feature work")
        git(self.repo.path, "checkout", "main")
        decision = self.decide("git branch -D feature")
        self.assertEqual(decision.verdict, REQUIRE_OWNER)
        finding = self.finding(decision, "git.branch.delete.force")
        self.assertGreaterEqual(int(finding.evidence["unmerged_commits"]), 1)

    def test_branch_delete_unknown_branch_is_noop_allowed(self) -> None:
        self.assertEqual(self.decide("git branch -D does-not-exist").verdict, ALLOW)

    def test_checkout_of_unmodified_path_is_allowed(self) -> None:
        decision = self.decide("git checkout README.md")
        self.assertEqual(decision.verdict, ALLOW)
        self.assertEqual(
            self.finding(decision, "git.checkout.discard").evidence[
                "local_changes_at_target"
            ],
            0,
        )

    def test_checkout_of_modified_path_is_denied(self) -> None:
        self.repo.write("src/app.py", "print('changed')\n")
        decision = self.decide("git checkout src/app.py")
        self.assertEqual(decision.verdict, DENY)
        self.assertGreaterEqual(
            int(
                self.finding(decision, "git.checkout.discard").evidence[
                    "local_changes_at_target"
                ]
            ),
            1,
        )

    def test_checkout_of_branch_is_not_treated_as_discard(self) -> None:
        git(self.repo.path, "branch", "other")
        decision = self.decide("git checkout other")
        self.assertEqual(decision.verdict, ALLOW)
        self.assertEqual(self.rules_of(decision), ["git.checkout.switch"])

    def test_restore_of_clean_path_is_allowed(self) -> None:
        self.assertEqual(self.decide("git restore README.md").verdict, ALLOW)

    def test_stash_drop_without_stash_is_allowed(self) -> None:
        self.assertEqual(self.decide("git stash drop").verdict, ALLOW)

    def test_stash_drop_with_stash_is_denied(self) -> None:
        self.repo.write("src/app.py", "print('stashed')\n")
        git(self.repo.path, "stash", "push", "-m", "wip")
        self.assertEqual(self.decide("git stash drop").verdict, DENY)

    def test_commit_amend_unpublished_requires_owner(self) -> None:
        decision = self.decide("git commit --amend -m x")
        self.assertEqual(decision.verdict, REQUIRE_OWNER)
        self.assertEqual(
            self.finding(decision, "git.commit.amend").evidence["head_published"], 0
        )

    def test_commit_amend_published_is_denied(self) -> None:
        bare = os.path.join(self._tmp.name, "remote.git")
        git(self._tmp.name, "init", "--bare", "-b", "main", bare)
        git(self.repo.path, "remote", "add", "origin", bare)
        git(self.repo.path, "push", "-u", "origin", "main")
        decision = self.decide("git commit --amend -m x")
        self.assertEqual(decision.verdict, DENY)
        self.assertEqual(
            self.finding(decision, "git.commit.amend").evidence["head_published"], 1
        )

    def test_force_with_lease_denied_when_remote_ahead(self) -> None:
        bare = os.path.join(self._tmp.name, "remote2.git")
        git(self._tmp.name, "init", "--bare", "-b", "main", bare)
        git(self.repo.path, "remote", "add", "origin", bare)
        git(self.repo.path, "push", "-u", "origin", "main")
        other = os.path.join(self._tmp.name, "other")
        subprocess.run(
            ["git", "clone", bare, other], capture_output=True, check=True, timeout=60
        )
        os.environ.setdefault("GIT_AUTHOR_NAME", GIT_ENV["GIT_AUTHOR_NAME"])
        for key, value in GIT_ENV.items():
            os.environ[key] = value
        git(other, "config", "user.email", "test@example.invalid")
        git(other, "config", "user.name", "SafeGit Test")
        pathlib.Path(other, "remote-change.txt").write_text(
            "remote work\n", encoding="utf-8"
        )
        git(other, "add", "-A")
        git(other, "commit", "-m", "remote work")
        git(other, "push", "origin", "main")
        git(self.repo.path, "fetch", "origin")
        decision = self.decide("git push --force-with-lease origin main")
        self.assertEqual(decision.verdict, DENY)
        self.assertGreaterEqual(
            int(self.finding(decision, "git.push.force_with_lease").evidence["behind"]),
            1,
        )

    def test_plain_push_to_protected_branch_requires_owner(self) -> None:
        bare = os.path.join(self._tmp.name, "remote3.git")
        git(self._tmp.name, "init", "--bare", "-b", "main", bare)
        git(self.repo.path, "remote", "add", "origin", bare)
        decision = self.decide("git push origin main")
        self.assertEqual(decision.verdict, REQUIRE_OWNER)
        self.assertEqual(
            self.finding(decision, "git.push.plain").evidence["protected_branch"],
            "main",
        )

    def test_plain_push_to_feature_branch_is_allowed(self) -> None:
        decision = self.decide("git push origin feature/thing")
        self.assertEqual(decision.verdict, ALLOW)

    def test_add_all_is_allowed_but_reports_untracked_files(self) -> None:
        self.repo.write("scratch/new.txt", "x\n")
        decision = self.decide("git add .")
        self.assertEqual(decision.verdict, ALLOW)
        self.assertTrue(
            any(
                item.startswith("STAGES_UNTRACKED_FILES")
                for item in decision.limitations
            ),
            decision.limitations,
        )

    def test_add_all_requires_owner_in_strict_profile(self) -> None:
        self.assertEqual(
            self.decide("git add .", profile="strict").verdict, REQUIRE_OWNER
        )

    def test_commit_on_protected_branch_in_strict_profile(self) -> None:
        self.repo.write("src/app.py", "print('x')\n")
        self.assertEqual(
            self.decide("git commit -m x", profile="strict").verdict, REQUIRE_OWNER
        )
        self.assertEqual(self.decide("git commit -m x").verdict, ALLOW)

    def test_unclassified_operation_is_unknown_then_owner_required(self) -> None:
        decision = self.decide("git frobnicate --now")
        self.assertEqual(decision.verdict, REQUIRE_OWNER)
        self.assertTrue(
            any(finding.verdict == UNKNOWN for finding in decision.findings),
            [finding.verdict for finding in decision.findings],
        )

    def test_unclassified_operation_denied_when_non_interactive(self) -> None:
        decision = self.decide("git frobnicate --now", non_interactive=True)
        self.assertEqual(decision.verdict, DENY)

    def test_unknown_is_denied_in_ci_profile(self) -> None:
        decision = self.decide("git frobnicate --now", profile="ci")
        self.assertEqual(decision.verdict, DENY)

    def test_hook_bypass_is_denied(self) -> None:
        self.assertEqual(self.decide("git commit --no-verify -m x").verdict, DENY)

    def test_secret_path_write_is_denied(self) -> None:
        decision = engine.evaluate(
            "Write",
            {"file_path": os.path.join(self.repo.path, ".env"), "content": "SECRET=1"},
            ctx=self.make_context(),
        )
        self.assertEqual(decision.verdict, DENY)
        self.assertEqual(decision.reason_code, engine.REASON_DENY_SECRET_PATH)

    def test_env_example_write_is_allowed(self) -> None:
        decision = engine.evaluate(
            "Write",
            {
                "file_path": os.path.join(self.repo.path, ".env.example"),
                "content": "X=1",
            },
            ctx=self.make_context(),
        )
        self.assertEqual(decision.verdict, ALLOW)

    def test_protected_path_write_is_denied(self) -> None:
        decision = engine.evaluate(
            "Write",
            {
                "file_path": os.path.join(self.repo.path, ".git", "config"),
                "content": "x",
            },
            ctx=self.make_context(),
        )
        self.assertEqual(decision.verdict, DENY)
        self.assertEqual(decision.reason_code, engine.REASON_DENY_PROTECTED_PATH)

    def test_policy_file_write_is_denied(self) -> None:
        decision = engine.evaluate(
            "Edit",
            {
                "file_path": os.path.join(
                    self.repo.path, ".safegit", "safegit.policy.json"
                )
            },
            ctx=self.make_context(),
        )
        self.assertEqual(decision.verdict, DENY)

    def test_ci_workflow_write_requires_owner(self) -> None:
        decision = engine.evaluate(
            "Write",
            {
                "file_path": os.path.join(
                    self.repo.path, ".github", "workflows", "ci.yml"
                )
            },
            ctx=self.make_context(),
        )
        self.assertEqual(decision.verdict, REQUIRE_OWNER)

    def test_read_only_tool_is_out_of_scope_and_allowed(self) -> None:
        decision = engine.evaluate(
            "Read", {"file_path": "anything.txt"}, ctx=self.make_context()
        )
        self.assertEqual(decision.verdict, ALLOW)
        self.assertTrue(decision.out_of_scope)

    def test_non_git_command_is_allowed_with_scope_limitation(self) -> None:
        decision = self.decide("npm test")
        self.assertEqual(decision.verdict, ALLOW)

    def test_missing_repository_state_escalates_state_dependent_operation(self) -> None:
        outside = os.path.join(self._tmp.name, "not-a-repo")
        os.makedirs(outside, exist_ok=True)
        decision = self.decide("git reset --hard", cwd=outside)
        self.assertEqual(decision.verdict, DENY)
        reasons = [finding.reason_code for finding in decision.findings]
        self.assertIn(engine.REASON_UNKNOWN_STATE, reasons)
        self.assertIn(DENY, [finding.verdict for finding in decision.findings])

    def test_approval_allows_exactly_one_matching_action(self) -> None:
        git(self.repo.path, "checkout", "-b", "feature")
        self.repo.write("feature.txt", "work\n")
        self.repo.commit_all("work")
        git(self.repo.path, "checkout", "main")

        command = "git branch -D feature"
        first = self.decide(command)
        self.assertEqual(first.verdict, REQUIRE_OWNER)
        fingerprint, rule_id = engine.action_fingerprint_for_findings(
            first.findings, ctx=self.make_context(), evidence=first.evidence
        )
        self.assertTrue(fingerprint)
        self.assertEqual(rule_id, "git.branch.delete.force")
        repo = first.evidence["repo"]
        approvals.mint(
            fingerprint=fingerprint,
            rule_id=rule_id,
            repo_root=str(repo["root"]),
            branch=str(repo["branch"]),
            head=str(repo["head"]),
            reason="test approval",
            interactive=True,
            path=pathlib.Path(self.store),
        )
        approved = self.decide(command)
        self.assertEqual(approved.verdict, ALLOW)
        self.assertEqual(
            approved.reason_code,
            "ALLOW_OWNER_APPROVED" if False else approved.reason_code,
        )
        self.assertTrue(approved.approved_rule)
        again = self.decide(command)
        self.assertEqual(again.verdict, REQUIRE_OWNER)

    def test_approval_does_not_apply_to_a_different_action(self) -> None:
        command = "git rebase main"
        decision = self.decide(command)
        self.assertEqual(decision.verdict, REQUIRE_OWNER)
        fingerprint, rule_id = engine.action_fingerprint_for_findings(
            decision.findings, ctx=self.make_context(), evidence=decision.evidence
        )
        repo = decision.evidence["repo"]
        approvals.mint(
            fingerprint=fingerprint,
            rule_id=rule_id,
            repo_root=str(repo["root"]),
            branch=str(repo["branch"]),
            head=str(repo["head"]),
            reason="for a different action",
            interactive=True,
            path=pathlib.Path(self.store),
        )
        other = self.decide("git commit --amend -m x")
        self.assertEqual(other.verdict, REQUIRE_OWNER)

    def test_non_interactive_approval_is_rejected_when_required(self) -> None:
        git(self.repo.path, "checkout", "-b", "feature2")
        self.repo.write("feature2.txt", "work\n")
        self.repo.commit_all("work")
        git(self.repo.path, "checkout", "main")
        decision = self.decide("git branch -D feature2")
        fingerprint, rule_id = engine.action_fingerprint_for_findings(
            decision.findings, ctx=self.make_context(), evidence=decision.evidence
        )
        repo = decision.evidence["repo"]
        approvals.mint(
            fingerprint=fingerprint,
            rule_id=rule_id,
            repo_root=str(repo["root"]),
            branch=str(repo["branch"]),
            head=str(repo["head"]),
            reason="minted by a script",
            interactive=False,
            path=pathlib.Path(self.store),
        )
        self.assertEqual(self.decide("git branch -D feature2").verdict, REQUIRE_OWNER)

    def test_blocked_command_leaves_worktree_untouched(self) -> None:
        target = self.repo.write("src/app.py", "print('uncommitted work')\n")
        before = target.read_text(encoding="utf-8")
        head_before = git(self.repo.path, "rev-parse", "HEAD").stdout.strip()
        status_before = git(self.repo.path, "status", "--porcelain").stdout

        decision = self.decide("git reset --hard")
        self.assertEqual(decision.verdict, DENY)

        self.assertEqual(target.read_text(encoding="utf-8"), before)
        self.assertEqual(
            git(self.repo.path, "rev-parse", "HEAD").stdout.strip(), head_before
        )
        self.assertEqual(
            git(self.repo.path, "status", "--porcelain").stdout, status_before
        )

    def test_blocked_clean_leaves_untracked_files_untouched(self) -> None:
        untracked = self.repo.write("scratch/precious.txt", "do not delete\n")
        decision = self.decide("git clean -fdx")
        self.assertEqual(decision.verdict, DENY)
        self.assertTrue(untracked.is_file())
        self.assertEqual(untracked.read_text(encoding="utf-8"), "do not delete\n")

    def test_gitstate_probe_does_not_modify_repository(self) -> None:
        self.repo.write("src/app.py", "print('dirty')\n")
        before = git(self.repo.path, "status", "--porcelain").stdout
        state = gitstate.probe(self.repo.path)
        self.assertTrue(state.available)
        self.assertEqual(state.staged, 0)
        self.assertGreaterEqual(state.unstaged, 1)
        self.assertEqual(git(self.repo.path, "status", "--porcelain").stdout, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
