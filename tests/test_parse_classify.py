"""Parser and classifier tests (stdlib unittest, no dependencies)."""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from safegit import gitop, shellparse  # noqa: E402

DASH = "-"
DASHH = "--"


class ShellParseTests(unittest.TestCase):
    def test_single_command(self) -> None:
        result = shellparse.parse("git status")
        self.assertEqual(len(result.commands), 1)
        self.assertEqual(result.commands[0].argv, ("git", "status"))
        self.assertEqual(result.unknown_reasons, [])

    def test_chained_commands_are_separate(self) -> None:
        result = shellparse.parse("git status && git log ; git diff")
        self.assertEqual(len(result.commands), 3)

    def test_quoted_separator_is_not_a_split(self) -> None:
        result = shellparse.parse('echo "a;b"')
        self.assertEqual(len(result.commands), 1)
        self.assertEqual(result.commands[0].argv, ("echo", "a;b"))

    def test_commit_message_is_opaque(self) -> None:
        result = shellparse.parse("git commit -m 'fix rm -rf bug'")
        self.assertEqual(len(result.commands), 1)
        self.assertIn("rm -rf bug", result.commands[0].argv[3])

    def test_command_substitution_is_scanned(self) -> None:
        result = shellparse.parse("echo $(git status)")
        programs = [c.argv[0] for c in result.commands]
        self.assertIn("echo", programs)
        self.assertIn("git", programs)
        git_cmd = [c for c in result.commands if c.argv[0] == "git"][0]
        self.assertTrue(git_cmd.from_substitution)

    def test_backtick_substitution_is_scanned(self) -> None:
        result = shellparse.parse("echo `git status`")
        self.assertIn("git", [c.argv[0] for c in result.commands])

    def test_interpreter_body_is_scanned(self) -> None:
        result = shellparse.parse('bash -c "git status"')
        self.assertIn("git", [c.argv[0] for c in result.commands])

    def test_env_assignment_is_captured_and_stripped(self) -> None:
        result = shellparse.parse("HUSKY=0 git status")
        self.assertEqual(result.commands[0].argv, ("git", "status"))
        self.assertEqual(result.commands[0].env_assignments, (("HUSKY", "0"),))

    def test_wrapper_prefix_is_stripped(self) -> None:
        result = shellparse.parse("sudo -u root git status")
        self.assertEqual(result.commands[0].argv, ("git", "status"))

    def test_windows_path_program_is_preserved(self) -> None:
        result = shellparse.parse('"C:\\Program Files\\Git\\bin\\git.exe" status')
        self.assertEqual(shellparse.basename(result.commands[0].argv[0]), "git.exe")

    def test_oversized_command_is_truncated_and_flagged(self) -> None:
        result = shellparse.parse("x" * (shellparse.MAX_COMMAND_CHARS + 10))
        self.assertTrue(result.truncated)
        self.assertIn("COMMAND_TOO_LONG_TRUNCATED", result.unknown_reasons)

    def test_segment_explosion_is_bounded(self) -> None:
        result = shellparse.parse(" ; ".join(["git status"] * 100))
        self.assertIn("SEGMENT_LIMIT_REACHED", result.unknown_reasons)

    def test_empty_command(self) -> None:
        result = shellparse.parse("   ")
        self.assertEqual(result.commands, [])


class ClassifierTests(unittest.TestCase):
    def classify(self, command: str) -> list[str]:
        parsed = shellparse.parse(command)
        rules: list[str] = []
        for invocation in gitop.resolve_invocations(parsed):
            rules.extend(op.rule_id for op in gitop.classify_all(invocation))
        return rules

    def assert_rules(self, command: str, *expected: str) -> None:
        rules = self.classify(command)
        for rule in expected:
            self.assertIn(
                rule, rules, "%r did not yield %s (got %s)" % (command, rule, rules)
            )

    def assert_not_rules(self, command: str, *unexpected: str) -> None:
        rules = self.classify(command)
        for rule in unexpected:
            self.assertNotIn(
                rule, rules, "%r unexpectedly yielded %s" % (command, rule)
            )

    def test_reset_hard(self) -> None:
        self.assert_rules("git reset --hard", gitop.RULE_RESET_HARD)
        self.assert_rules("git -C /repo reset --hard HEAD~1", gitop.RULE_RESET_HARD)

    def test_soft_and_mixed_reset_are_not_destructive(self) -> None:
        self.assert_not_rules("git reset --soft HEAD~1", gitop.RULE_RESET_HARD)
        self.assert_not_rules("git reset --mixed", gitop.RULE_RESET_HARD)

    def test_clean_force_variants(self) -> None:
        for command in (
            "git clean -f",
            "git clean -fd",
            "git clean -xfd",
            "git clean -fdx",
        ):
            self.assert_rules(command, gitop.RULE_CLEAN_FORCE)

    def test_clean_dry_run_is_allowed(self) -> None:
        self.assert_not_rules("git clean -n", gitop.RULE_CLEAN_FORCE)
        self.assert_not_rules("git clean --dry-run", gitop.RULE_CLEAN_FORCE)

    def test_push_force_long_and_short(self) -> None:
        self.assert_rules("git push --force origin main", gitop.RULE_PUSH_FORCE)
        self.assert_rules("git push -f origin main", gitop.RULE_PUSH_FORCE)
        self.assert_rules("git push origin +main:main", gitop.RULE_PUSH_FORCE)

    def test_push_force_with_lease_is_its_own_rule(self) -> None:
        self.assert_rules(
            "git push --force-with-lease origin main", gitop.RULE_PUSH_FORCE_LEASE
        )
        self.assert_not_rules(
            "git push --force-with-lease origin main", gitop.RULE_PUSH_FORCE
        )

    def test_push_delete(self) -> None:
        self.assert_rules("git push origin --delete feature", gitop.RULE_PUSH_DELETE)
        self.assert_rules("git push origin :feature", gitop.RULE_PUSH_DELETE)

    def test_push_plain_keeps_refspec_as_branch_hint(self) -> None:
        parsed = shellparse.parse("git push origin release/1.0")
        invocations = gitop.resolve_invocations(parsed)
        ops = gitop.classify_all(invocations[0])
        self.assertEqual(ops[0].rule_id, gitop.RULE_PUSH_PLAIN)
        self.assertEqual(ops[0].branch_hint, "release/1.0")

    def test_push_option_value_is_not_a_refspec(self) -> None:
        parsed = shellparse.parse("git push -o ci.skip origin main")
        ops = gitop.classify_all(gitop.resolve_invocations(parsed)[0])
        self.assertEqual(ops[0].rule_id, gitop.RULE_PUSH_PLAIN)
        self.assertEqual(ops[0].branch_hint, "main")

    def test_branch_delete_force_vs_safe(self) -> None:
        self.assert_rules("git branch -D feature", gitop.RULE_BRANCH_DELETE_FORCE)
        self.assert_rules("git branch -d feature", gitop.RULE_BRANCH_DELETE_SAFE)
        self.assert_rules(
            "git branch --delete --force feature", gitop.RULE_BRANCH_DELETE_FORCE
        )

    def test_commit_amend_vs_plain(self) -> None:
        self.assert_rules("git commit --amend", gitop.RULE_COMMIT_AMEND)
        self.assert_not_rules("git commit --amend", gitop.RULE_COMMIT_PLAIN)
        self.assert_rules("git commit -m msg", gitop.RULE_COMMIT_PLAIN)

    def test_checkout_discard(self) -> None:
        self.assert_rules("git checkout -- .", gitop.RULE_CHECKOUT_DISCARD)
        self.assert_rules("git checkout -f main", gitop.RULE_CHECKOUT_DISCARD)
        self.assert_rules("git checkout .", gitop.RULE_CHECKOUT_DISCARD)
        self.assert_rules("git checkout main", gitop.RULE_CHECKOUT_DISCARD)
        self.assert_rules("git switch --detach main", gitop.RULE_CHECKOUT_DISCARD)
        self.assert_rules("git switch main", gitop.RULE_CHECKOUT_DISCARD)

    def test_checkout_path_or_ref_is_marked_ambiguous(self) -> None:
        ops = gitop.classify_all(
            gitop.resolve_invocations(shellparse.parse("git checkout feature/x"))[0]
        )
        self.assertEqual(ops[0].rule_id, gitop.RULE_CHECKOUT_DISCARD)
        self.assertEqual(ops[0].ambiguity, "path_or_ref")
        ops = gitop.classify_all(
            gitop.resolve_invocations(shellparse.parse("git checkout main"))[0]
        )
        self.assertEqual(ops[0].ambiguity, "path_or_ref")
        ops = gitop.classify_all(
            gitop.resolve_invocations(shellparse.parse("git checkout ."))[0]
        )
        self.assertEqual(ops[0].ambiguity, "")

    def test_switch_discard(self) -> None:
        self.assert_rules(
            "git switch --discard-changes main", gitop.RULE_CHECKOUT_DISCARD
        )

    def test_restore_worktree_vs_staged(self) -> None:
        self.assert_rules("git restore .", gitop.RULE_RESTORE_WORKTREE)
        self.assert_not_rules(
            "git restore --staged file.py", gitop.RULE_RESTORE_WORKTREE
        )

    def test_add_all(self) -> None:
        for command in ("git add .", "git add -A", "git add --all", "git add -u"):
            self.assert_rules(command, gitop.RULE_ADD_ALL)
        self.assert_not_rules("git add src/app.py", gitop.RULE_ADD_ALL)

    def test_stash_destroy(self) -> None:
        self.assert_rules("git stash drop", gitop.RULE_STASH_DESTROY)
        self.assert_rules("git stash clear", gitop.RULE_STASH_DESTROY)
        self.assert_not_rules("git stash pop", gitop.RULE_STASH_DESTROY)

    def test_worktree_remove(self) -> None:
        self.assert_rules("git worktree remove ../wt", gitop.RULE_WORKTREE_REMOVE)
        self.assert_rules("git worktree prune", gitop.RULE_WORKTREE_PRUNE)

    def test_hook_bypass(self) -> None:
        self.assert_rules("git commit --no-verify -m x", gitop.RULE_HOOK_BYPASS)
        self.assert_rules("git commit -n -m x", gitop.RULE_HOOK_BYPASS)
        self.assert_rules("git push --no-verify", gitop.RULE_HOOK_BYPASS)
        self.assert_rules("git commit --no-gpg-sign -m x", gitop.RULE_HOOK_BYPASS)

    def test_inline_config_override(self) -> None:
        self.assert_rules(
            "git -c core.hooksPath=/dev/null commit -m x", gitop.RULE_HOOK_BYPASS
        )
        self.assert_rules("git -c user.email=a@b commit -m x", gitop.RULE_CONFIG_INLINE)

    def test_repo_override(self) -> None:
        self.assert_rules("git --git-dir=/other/.git status", gitop.RULE_REPO_OVERRIDE)
        self.assert_rules("git --work-tree=/other status", gitop.RULE_REPO_OVERRIDE)

    def test_history_rewrite_family(self) -> None:
        self.assert_rules("git rebase -i HEAD~3", gitop.RULE_REBASE)
        self.assert_rules("git rebase --abort", gitop.RULE_REBASE_CONTINUE)
        self.assert_rules("git filter-branch --all", gitop.RULE_HISTORY_FILTER)
        self.assert_rules(
            "git reflog expire --expire=now --all", gitop.RULE_HISTORY_EXPIRE
        )
        self.assert_rules("git gc --prune=now", gitop.RULE_HISTORY_EXPIRE)

    def test_read_only_commands_produce_no_destructive_rule(self) -> None:
        for command in (
            "git status",
            "git log --oneline -5",
            "git diff --cached --check",
            "git show HEAD",
            "git rev-parse --show-toplevel",
            "git fetch origin",
            "git branch",
            "git config --get user.email",
            "git stash list",
            "git worktree list",
            "git remote -v",
            "git tag -l",
            "git submodule status",
            "git clean -n",
        ):
            rules = self.classify(command)
            self.assertTrue(rules, "%r classified as nothing" % command)
            for rule in rules:
                self.assertEqual(
                    rule,
                    gitop.RULE_NON_DESTRUCTIVE,
                    "%r -> %s (expected an allowed non-destructive rule)"
                    % (command, rule),
                )

    def test_unrecognised_subcommand_is_other(self) -> None:
        self.assert_rules("git frobnicate --now", gitop.RULE_OTHER)

    def test_multiple_rules_from_one_invocation(self) -> None:
        rules = self.classify("git push --force --no-verify origin main")
        self.assertIn(gitop.RULE_PUSH_FORCE, rules)
        self.assertIn(gitop.RULE_HOOK_BYPASS, rules)

    def test_chained_destructive_command_after_safe_one(self) -> None:
        rules = self.classify("git status && git reset --hard")
        self.assertIn(gitop.RULE_RESET_HARD, rules)

    def test_data_inside_commit_message_is_not_a_rule(self) -> None:
        rules = self.classify('git commit -m "revert reset --hard handling"')
        self.assertEqual(rules, [gitop.RULE_COMMIT_PLAIN])

    def test_data_inside_echo_is_not_a_rule(self) -> None:
        rules = self.classify('echo "git reset --hard"')
        self.assertEqual(rules, [])

    def test_rule_ids_are_unique_and_complete(self) -> None:
        self.assertEqual(len(set(gitop.RULE_IDS)), len(gitop.RULE_IDS))
        self.assertIn(gitop.RULE_OTHER, gitop.RULE_IDS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
