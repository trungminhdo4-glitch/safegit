"""CLI, hook-protocol and privacy tests (no live agent required)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from safegit import cli, receipt as receipt_module  # noqa: E402

DANGEROUS = "git " + "reset --" + "hard"
DANGEROUS_TEXT = "git " + "push --" + "force origin main"


class CliHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="safegit-cli-")
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.store = os.path.join(self.root, "approvals.json")
        self.audit_path = os.path.join(self.root, "audit.jsonl")
        previous_audit_env = os.environ.get("SAFEGIT_AUDIT_PATH")
        os.environ["SAFEGIT_AUDIT_PATH"] = self.audit_path

        def restore() -> None:
            if previous_audit_env is None:
                os.environ.pop("SAFEGIT_AUDIT_PATH", None)
            else:
                os.environ["SAFEGIT_AUDIT_PATH"] = previous_audit_env

        self.addCleanup(restore)
        self.claude_pretooluse = {
            "session_id": "s",
            "cwd": self.root,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
        }

    def run_cli(self, argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        original_stdin = sys.stdin
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(argv)
        finally:
            sys.stdin = original_stdin
        return code, out.getvalue(), err.getvalue()

    def base(self, *extra: str) -> list[str]:
        return [*extra, "--approval-store", self.store]


class HookProtocolTests(CliHarness):
    def test_claude_hook_blocks_dangerous_command_with_exit_2(self) -> None:
        event = dict(self.claude_pretooluse)
        event["tool_input"] = {"command": DANGEROUS}
        code, out, err = self.run_cli(self.base("hook", "claude"), json.dumps(event))
        self.assertEqual(code, 2)
        payload = json.loads(out)
        self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("SafeGit", payload["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertIn("SafeGit", err)

    def test_claude_hook_allows_safe_command_with_exit_0_and_no_stdout(self) -> None:
        code, out, err = self.run_cli(
            self.base("hook", "claude"), json.dumps(self.claude_pretooluse)
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_claude_hook_is_fail_closed_on_invalid_stdin(self) -> None:
        code, out, err = self.run_cli(self.base("hook", "claude"), "not json at all")
        self.assertEqual(code, 2)
        self.assertIn("SAFEGIT_HOOK_INPUT_INVALID", err)

    def test_claude_hook_is_fail_closed_when_tool_name_missing(self) -> None:
        code, out, err = self.run_cli(self.base("hook", "claude"), json.dumps({"cwd": self.root}))
        self.assertEqual(code, 2)
        self.assertIn("SAFEGIT_HOOK_TOOL_NAME_MISSING", err)

    def test_claude_hook_blocks_secret_file_write(self) -> None:
        event = dict(self.claude_pretooluse)
        event["tool_name"] = "Write"
        event["tool_input"] = {
            "file_path": os.path.join(self.root, ".env"),
            "content": "A=1",
        }
        code, out, _ = self.run_cli(self.base("hook", "claude"), json.dumps(event))
        self.assertEqual(code, 2)
        self.assertIn("deny", out)

    def test_claude_hook_ignores_read_only_tools(self) -> None:
        event = dict(self.claude_pretooluse)
        event["tool_name"] = "Read"
        event["tool_input"] = {"file_path": os.path.join(self.root, "notes.txt")}
        code, out, _ = self.run_cli(self.base("hook", "claude"), json.dumps(event))
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_claude_hook_blocks_with_broken_policy(self) -> None:
        policy_path = os.path.join(self.root, "broken.policy.json")
        pathlib.Path(policy_path).write_text("{ this is not json", encoding="utf-8")
        event = dict(self.claude_pretooluse)
        event["tool_input"] = {"command": DANGEROUS}
        code, _, err = self.run_cli(
            self.base("hook", "claude", "--policy", policy_path), json.dumps(event)
        )
        self.assertEqual(code, 2)
        self.assertIn("SAFEGIT_POLICY_ERROR", err)

    def test_opencode_hook_blocks_dangerous_command(self) -> None:
        event = {"tool": "bash", "cwd": self.root, "args": {"command": DANGEROUS}}
        code, _, err = self.run_cli(self.base("hook", "opencode"), json.dumps(event))
        self.assertEqual(code, 2)
        self.assertIn("SafeGit", err)

    def test_opencode_hook_allows_safe_command(self) -> None:
        event = {"tool": "bash", "cwd": self.root, "args": {"command": "git status"}}
        code, _, err = self.run_cli(self.base("hook", "opencode"), json.dumps(event))
        self.assertEqual(code, 0)


class CheckCommandTests(CliHarness):
    def test_allow_exit_code_is_zero(self) -> None:
        code, out, _ = self.run_cli(self.base("check", "--command", "git status", "--json"))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["verdict"], "ALLOW")

    def test_deny_exit_code_is_two(self) -> None:
        code, out, _ = self.run_cli(self.base("check", "--command", DANGEROUS, "--json"))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["verdict"], "DENY")

    def test_owner_required_exit_code_is_three(self) -> None:
        code, out, _ = self.run_cli(
            self.base("check", "--command", "git commit --" + "amend -m x", "--json")
        )
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["verdict"], "REQUIRE_OWNER")

    def test_missing_arguments_is_a_usage_error(self) -> None:
        code, _, err = self.run_cli(self.base("check"))
        self.assertEqual(code, 64)
        self.assertIn("--command", err)

    def test_broken_policy_is_an_internal_error_not_an_allow(self) -> None:
        policy_path = os.path.join(self.root, "broken.json")
        pathlib.Path(policy_path).write_text("{}", encoding="utf-8")
        code, _, err = self.run_cli(
            self.base("check", "--command", "git status", "--policy", policy_path)
        )
        self.assertEqual(code, 70)
        self.assertIn("policy error", err)

    def test_profile_flag_selects_a_builtin_profile(self) -> None:
        code, out, _ = self.run_cli(
            self.base("check", "--command", "git add .", "--profile", "strict", "--json")
        )
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["policy_profile"], "strict")

    def test_explain_reports_rule_and_verdict(self) -> None:
        code, out, _ = self.run_cli(self.base("explain", "git.non_destructive", "--json"))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["verdict"], "ALLOW")

    def test_explain_of_a_command_lists_operations(self) -> None:
        code, out, _ = self.run_cli(self.base("explain", DANGEROUS, "--json"))
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["operations"][0]["rule_id"], "git.reset.hard")


class PrivacyTests(CliHarness):
    def test_audit_log_does_not_store_command_text_by_default(self) -> None:
        secret_marker = "token=ghp_" + "A" * 20
        code, _, _ = self.run_cli(
            self.base(
                "check",
                "--cwd",
                self.root,
                "--command",
                "git status && echo %s" % secret_marker,
            )
        )
        audit_path = pathlib.Path(self.audit_path)
        self.assertTrue(audit_path.is_file(), "audit log was not written")
        content = audit_path.read_text(encoding="utf-8")
        self.assertNotIn(secret_marker, content)
        self.assertNotIn("ghp_", content)
        entry = json.loads(content.strip().splitlines()[-1])
        self.assertIn("action_digest", entry)
        self.assertTrue(entry["action_digest"].startswith("sha256:"))

    def test_audit_log_falls_back_to_the_user_profile_outside_a_repository(
        self,
    ) -> None:
        profile = pathlib.Path(self.root) / "profile"
        profile.mkdir()
        audit_target = profile / ".safegit" / "audit.jsonl"
        previous = {
            key: os.environ.get(key) for key in ("USERPROFILE", "HOME", "SAFEGIT_AUDIT_PATH")
        }
        os.environ["USERPROFILE"] = str(profile)
        os.environ["HOME"] = str(profile)
        os.environ.pop("SAFEGIT_AUDIT_PATH", None)
        try:
            code, _, _ = self.run_cli(
                self.base("check", "--cwd", self.root, "--command", "git status")
            )
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(code, 0)
        self.assertTrue(audit_target.is_file(), "audit log was not written to the profile")
        self.assertFalse((pathlib.Path(self.root) / ".safegit").exists())

    def test_decision_receipt_is_digest_sealed_and_verifiable(self) -> None:
        code, out, _ = self.run_cli(self.base("check", "--command", "git status", "--json"))
        receipt = json.loads(out)["receipt"]
        self.assertTrue(receipt_module.verify_receipt(receipt))
        tampered = dict(receipt)
        tampered["verdict"] = "ALLOW"
        tampered["reason_code"] = "TAMPERED"
        self.assertFalse(receipt_module.verify_receipt(tampered))

    def test_audit_summary_counts_verdicts(self) -> None:
        self.run_cli(self.base("check", "--cwd", self.root, "--command", "git status"))
        self.run_cli(self.base("check", "--cwd", self.root, "--command", DANGEROUS))
        code, out, _ = self.run_cli(["audit", "--summary", "--json", "--cwd", self.root])
        self.assertEqual(code, 0)
        summary = json.loads(out)
        self.assertEqual(summary["entries"], 2)
        self.assertEqual(summary["verdicts"]["DENY"], 1)
        self.assertEqual(summary["verdicts"]["ALLOW"], 1)


class PolicyCommandTests(CliHarness):
    def test_selftest_passes_for_every_builtin_profile(self) -> None:
        for profile in ("default", "strict", "relaxed", "ci"):
            code, out, _ = self.run_cli(["selftest", "--profile", profile, "--json"])
            self.assertEqual(code, 0, "%s: %s" % (profile, out))
            self.assertTrue(json.loads(out)["ok"], profile)

    def test_doctor_selftest_check_passes(self) -> None:
        code, out, _ = self.run_cli(self.base("doctor", "--cwd", self.root, "--json"))
        payload = json.loads(out)
        check = [item for item in payload["checks"] if item["check"] == "rule_selftest"][0]
        self.assertEqual(check["status"], "PASS", check["detail"])
        self.assertNotEqual(payload["overall"], "FAIL")

    def test_policy_init_writes_a_valid_policy(self) -> None:
        target = os.path.join(self.root, "policy.json")
        code, out, _ = self.run_cli(["policy", "init", "--path", target, "--profile", "strict"])
        self.assertEqual(code, 0)
        document = json.loads(pathlib.Path(target).read_text(encoding="utf-8"))
        self.assertEqual(document["profile"], "strict")
        self.assertEqual(document["rules"]["git.push.plain"], "REQUIRE_OWNER")

    def test_policy_validate_reports_invalid_policy(self) -> None:
        target = os.path.join(self.root, "bad.json")
        pathlib.Path(target).write_text(json.dumps({"schema": "nope"}), encoding="utf-8")
        code, out, _ = self.run_cli(["policy", "validate", "--policy", target])
        self.assertEqual(code, 1)
        self.assertIn("INVALID", out)

    def test_default_and_strict_profiles_differ(self) -> None:
        _, default_out, _ = self.run_cli(["policy", "show", "--profile", "default"])
        _, strict_out, _ = self.run_cli(["policy", "show", "--profile", "strict"])
        self.assertNotEqual(json.loads(default_out)["rules"], json.loads(strict_out)["rules"])
        self.assertEqual(
            json.loads(strict_out)["rules"]["git.force_with_lease"]
            if "git.force_with_lease" in json.loads(strict_out)["rules"]
            else json.loads(strict_out)["rules"]["git.push.force_with_lease"],
            "DENY",
        )


class InstallTests(CliHarness):
    def test_claude_install_dry_run_writes_nothing(self) -> None:
        settings = os.path.join(self.root, ".claude", "settings.json")
        code, out, _ = self.run_cli(
            ["install", "claude", "--dir", self.root, "--settings", settings]
        )
        self.assertEqual(code, 0)
        self.assertFalse(pathlib.Path(settings).exists())
        self.assertIn("dry run", out)

    def test_claude_install_merges_without_destroying_existing_settings(self) -> None:
        settings = pathlib.Path(self.root) / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text(
            json.dumps({"permissions": {"deny": ["Bash(rm:*)"]}, "hooks": {}}),
            encoding="utf-8",
        )
        code, _, _ = self.run_cli(
            [
                "install",
                "claude",
                "--dir",
                self.root,
                "--settings",
                str(settings),
                "--write",
            ]
        )
        self.assertEqual(code, 0)
        document = json.loads(settings.read_text(encoding="utf-8"))
        self.assertEqual(document["permissions"]["deny"], ["Bash(rm:*)"])
        commands = [
            hook["command"] for entry in document["hooks"]["PreToolUse"] for hook in entry["hooks"]
        ]
        self.assertTrue(any("safegit" in command for command in commands))
        self.assertTrue((settings.parent / "settings.json.safegit-backup").is_file())

    def test_claude_install_is_idempotent(self) -> None:
        settings = pathlib.Path(self.root) / ".claude" / "settings.json"
        argv = [
            "install",
            "claude",
            "--dir",
            self.root,
            "--settings",
            str(settings),
            "--write",
        ]
        self.run_cli(argv)
        self.run_cli(argv)
        document = json.loads(settings.read_text(encoding="utf-8"))
        self.assertEqual(len(document["hooks"]["PreToolUse"]), 1)

    def test_opencode_install_writes_a_plugin_that_only_shells_out(self) -> None:
        code, _, _ = self.run_cli(["install", "opencode", "--dir", self.root, "--write"])
        self.assertEqual(code, 0)
        plugin = pathlib.Path(self.root) / ".opencode" / "plugin" / "safegit.js"
        self.assertTrue(plugin.is_file())
        content = plugin.read_text(encoding="utf-8")
        self.assertIn("tool.execute.before", content)
        self.assertIn("hook", content)
        self.assertNotIn("reset", content)
        self.assertNotIn("push", content)

    def test_githook_install_refuses_to_clobber_existing_hook(self) -> None:
        repo = os.path.join(self.root, "hookrepo")
        os.makedirs(repo, exist_ok=True)
        subprocess.run(
            ["git", "init", "-b", "main", repo],
            capture_output=True,
            check=True,
            timeout=60,
        )
        hook = pathlib.Path(repo) / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
        code, _, err = self.run_cli(["install", "githooks", "--repo", repo, "--write"])
        self.assertEqual(code, 64)
        self.assertIn("refusing", err)
        self.assertIn("echo existing", hook.read_text(encoding="utf-8"))


class NodePluginTests(unittest.TestCase):
    """The OpenCode plugin adapter logic, exercised with node directly."""

    def setUp(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not available")
        self.node = node
        self._tmp = tempfile.TemporaryDirectory(prefix="safegit-node-")
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name

    def test_plugin_blocks_by_throwing_and_allows_by_returning(self) -> None:
        plugin = pathlib.Path(self.root) / ".opencode" / "plugin" / "safegit.js"
        plugin.parent.mkdir(parents=True, exist_ok=True)
        code, _, err = self._run_install(str(plugin))
        self.assertEqual(code, 0, err)

        module_path = pathlib.Path(self.root) / "safegit-plugin.mjs"
        shutil.copyfile(plugin, module_path)
        harness = pathlib.Path(self.root) / "harness.mjs"
        harness.write_text(
            "\n".join(
                [
                    "import { pathToFileURL } from 'node:url'",
                    "const mod = await import(pathToFileURL(process.argv[2]).href)",
                    "const plugin = await mod.SafegitPlugin({ directory: process.argv[3] })",
                    "const handler = plugin['tool.execute.before']",
                    "const results = []",
                    "const cases = [",
                    "  { tool: 'bash', args: { command: process.env.SG_DANGEROUS } },",
                    "  { tool: 'bash', args: { command: 'git status' } },",
                    "]",
                    "for (const item of cases) {",
                    "  try {",
                    "    await handler({ tool: item.tool, sessionID: 's', callID: 'c' }, { args: item.args })",
                    "    results.push({ blocked: false })",
                    "  } catch (error) {",
                    "    results.push({ blocked: true, message: String(error.message).slice(0, 200) })",
                    "  }",
                    "}",
                    "console.log(JSON.stringify(results))",
                ]
            ),
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[1] / "src")
        env["SAFEGIT_CLI"] = ""
        env["SG_DANGEROUS"] = DANGEROUS
        completed = subprocess.run(
            [self.node, str(harness), str(module_path), self.root],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=120,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        results = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertTrue(results[0]["blocked"], results)
        self.assertIn("SafeGit", results[0]["message"])
        self.assertFalse(results[1]["blocked"], results)

    def _run_install(self, plugin_path: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["install", "opencode", "--dir", self.root, "--write"])
        return code, out.getvalue(), err.getvalue()


if __name__ == "__main__":
    unittest.main(verbosity=2)
