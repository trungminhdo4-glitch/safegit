# Security report - SafeGit 0.1.0 release candidate

This report is the result of adversarial review of the release candidate. It
states what was reviewed, what was found, what was fixed, and what remains as
accepted risk. It is not a marketing document: the residual risks are as
important as the fixes.

## Method

| Step | What was done |
| --- | --- |
| Independent code review | A separate reviewer agent (different model, read-only) read all source and test files, ran the suite, and probed the classifier and engine with its own scripts in throwaway repositories. It reported 33 findings across correctness, classification, bypass paths, fail-open paths and test quality. |
| Independent security audit | A second, independent security audit answered six questions (same-user bypass, approval integrity, injection, denial of service, information disclosure, policy tampering) with reproductions. It reported 21 findings. |
| Host-protocol verification | The Claude Code hook contract was checked against the official documentation and executed directly with synthetic events; the OpenCode plugin contract was checked against the installed plugin SDK typings. |
| Live agent verification | A real agent (OpenCode 1.18.31 with a free model) was asked to discard an uncommitted change in a throwaway repository. |
| Regression suite | Every confirmed bypass was turned into a test in `tests/test_regression_bypasses.py` (42 tests). |
| Privacy and isolation | A dedicated scanner (`tools/selfcheck_no_private_data.py`) checks the release tree for credentials, personal paths and internal identifiers; it is part of the release receipt. |

## Verified live: OpenCode end to end

Setup: throwaway repository with a committed file and one uncommitted
modification, the SafeGit plugin installed, `--auto` so that nothing but
SafeGit could block the call.

Result: the agent chose `git restore -- README.md`, SafeGit returned `DENY`
(`git.restore.worktree`), the plugin threw, the agent reported the block and
explicitly declined to retry with another command. Independent verification
afterwards:

* `README.md` still contained the uncommitted modification,
* `HEAD` unchanged (`037dc92`),
* the audit log contained three entries: two `ALLOW` for the agent's read-only
  `git status`/`git diff`, one `DENY` for the restore, and **no command text**
  (only action digests).

A second run, after hardening, produced a further real finding: the agent
retried with `git stash push -- README.md`, which is *allowed* (stash preserves
the work). That is intended behaviour - the guard steered the agent to a
recoverable path instead of destroying the change - and the same run also
exposed the probe-latency issue fixed below (F-A1).

## Findings and disposition

Severity is the reviewer's assessment, not a CVSS score. "Fixed" means the
code changed *and* a regression test exists.

### Critical

| # | Finding | Disposition |
| --- | --- | --- |
| A1 | Executing `python -m safegit` from a repository that contains `safegit.py` runs attacker code inside the hook (module shadowing via `sys.path[0]`). | Fixed: the installed hook and plugin launch with `-P`, and `main()` refuses to run when the working directory shadows the package. Test: `test_shadowing_guard_refuses_a_planted_module`. |
| A2 | A repository-root `safegit.policy.json` was read but not write-protected, so an agent could plant a permissive policy. | Fixed: the policy file, `**/safegit.policy.json`, `.safegit` and `.safegit/**` are protected paths; the installed hook pins the policy path. Tests: `test_planted_policy_file_cannot_be_written`, `test_policy_file_write_tool_is_denied`. |
| A3 | Commands longer than 4096 characters were truncated before parsing, so a padded command hid the dangerous part and was allowed. | Fixed: commands are no longer truncated (paths still are); the parser's own bound reports an explicit unknown. Test: `test_long_command_is_not_truncated_into_an_allow`. |
| A4 | The installed Claude matcher omitted the `PowerShell` tool, so on Windows shell commands routed there were never inspected. | Fixed: matcher extended to `Bash|PowerShell|...`. |
| A5 | Quadratic glob expansion made a crafted command take up to ~87 s, above the 15 s hook timeout - and a timed-out hook does not block in Claude Code. | Fixed: the matcher is now linear in path segments (no suffix expansion), tokens and patterns are capped, and a global probe budget bounds every decision. Measured: a repository with 1 200 untracked files now probes in 0.64 s (previously > 20 s). Tests: `test_candidate_probe_stays_bounded_on_a_large_untracked_tree`, `test_probe_budget_exhaustion_is_reported`, `test_path_token_flood_stays_bounded`. |
| B1 | `git clean --forc`, `git branch --delete --forc`, `git push --force-w` bypassed the force checks (git accepts unambiguous long-option prefixes). | Fixed: dangerous long options are resolved by prefix, and unknown long options on risk-shaping subcommands escalate. Tests: `test_clean_long_option_abbreviation_is_caught`, `test_branch_delete_with_abbreviated_force_is_caught`, `test_push_force_with_lease_abbreviation_is_caught`, `test_unknown_long_option_on_clean_escalates`. |
| B2 | `git checkout -f main` / `git switch -f main` discarded the whole worktree while the dirty check only looked at a pathspec named `main`. | Fixed: a forced checkout evaluates worktree-wide dirtiness and denies when anything would be lost. Test: `test_forced_checkout_of_branch_with_dirty_tree_is_denied`. |
| B3 | `git checkout src` (single path argument without `/` or `.`) was treated as a branch switch and allowed, discarding local changes. | Fixed: every single-positional checkout target is marked ambiguous and resolved against the repository; `git checkout src` now denies when `src` has local changes. Test: `test_checkout_of_directory_with_local_changes_is_denied`. |
| B4 | Filesystem path checks were skipped for any command that contained a git invocation (`git status && echo x > .env` was allowed). | Fixed: path evaluation runs for every command segment, independent of git invocations. Test: `test_filesystem_write_is_still_checked_next_to_a_git_command`. |
| B5 | `rm -rf .git` was allowed; the repository metadata directory was not covered by the protected patterns. | Fixed: `.git`, `.git/**`, `.safegit`, `.safegit/**` added. Test: `test_repo_metadata_directory_is_protected`. |
| B6 | Writes performed from interpreter code (`python -c "pathlib.Path('.safegit/x').unlink()"`) bypassed protected and secret path checks. | Fixed: interpreter bodies are scanned for literal path anchors and an interpreter invocation counts as a possible write. Test: `test_interpreter_write_to_protected_path_is_denied`. |
| B7 | Interpreter wrappers with combined or differently cased flags (`bash -lc`, `powershell -COMMAND`, `cmd //c`) were not unwrapped. | Fixed: combined short flags, case-insensitive long flags and the MSYS `//c` spelling are handled. Tests: `test_interpreter_wrapper_variants_are_scanned`, `test_interpreter_without_command_flag_is_flagged`. |
| B8 | Transparent prefixes with option values (`timeout -s KILL 5 git ...`, `nice -n 10 git ...`, `xargs git ...`, `$G reset --hard`) hid the real command. | Fixed: value options are consumed for `timeout`/`nice`/`ionice`/`stdbuf`, `xargs` is unwrapped, escaped-space programs are split, and an indirect program name escalates. Tests: `test_transparent_prefix_values_are_skipped`, `test_escaped_space_program_is_split`, `test_indirect_program_name_is_flagged`. |
| B9 | Missing or malformed tool arguments produced `ALLOW` (`{"tool_name": "Bash", "tool_input": {}}`). | Fixed: an unresolvable guarded tool call is `UNKNOWN` (which escalates). Tests: `test_unknown_tool_arguments_are_not_an_implicit_allow`, `test_missing_file_path_is_not_an_implicit_allow`. |
| B10 | Common write-tool names (`write_to_file`, `replace_in_file`, `Delete`, `NotebookEdit`, `bash_command`) were out of scope and therefore allowed. | Fixed: names added plus keyword-based inference for command-like and write-like tools. Tests: `test_write_named_tools_are_classified`, `test_command_named_tools_are_classified`. |
| B11 | One approval cleared *all* owner-gated findings in a decision, including co-existing `UNKNOWN` findings. | Fixed: an approval applies only when every blocking finding is `REQUIRE_OWNER` **and** they share exactly one fingerprint. Tests: `test_approval_does_not_swallow_an_unknown_finding`, `test_one_approval_cannot_cover_two_gated_operations`. |
| B12 | A hand-edited approval store could set `uses_remaining` to 1000 and buy unlimited approvals; the read-modify-write was lock-free (double-spend window). | Fixed: uses are clamped to the policy maximum on consume, and the whole transaction runs under a create-exclusive store lock. Test: `test_approval_use_count_cannot_be_inflated`. |
| B13 | `git push --mirror`/`--all`/`--tags` were classified as plain pushes (the broad-push rule was unreachable). | Fixed: broad pushes are detected from the flag set. Test: `test_push_mirror_and_all_are_broad`. |
| B14 | Invalid UTF-8 in a policy file escaped as exit 70, which Claude Code treats as a non-blocking hook error. | Fixed: hook mode catches every exception and blocks; unrelated internal errors also exit 2 in hook mode. |

### High

| # | Finding | Disposition |
| --- | --- | --- |
| H1 | `protect_default_branch_commits` could not work without repository state and silently allowed. | Fixed: a plain commit is now state-dependent. Test: `test_strict_profile_without_repository_state_is_not_allowed`. |
| H2 | A minimal policy file emptied every protective list (`protected_branches`, `secret_paths`, ...). | Fixed: protective lists fall back to the built-in defaults when omitted. Test: `test_minimal_policy_keeps_the_default_protective_lists`. |
| H3 | A policy declaring `"profile": "strict"` did not receive the strict rule base. | Fixed: the profile supplies the merge base. Test: `test_policy_profile_field_is_honoured`. |
| H4 | `~/.gitconfig`, shell profiles and `.netrc` were writable, allowing `core.hooksPath` to be planted outside the repository. | Fixed: added to protected/secret patterns; pattern checks now run even for targets outside the repository. Test: `test_global_git_config_write_is_denied`. |
| H5 | Interpreter writes were not detected (same root cause as B6). | Fixed with B6. |
| H6 | Opaque MCP tools were unconditionally allowed, although the installed matcher routes them to SafeGit. | Partially fixed: a `guard_opaque_tools` policy key turns them into `UNKNOWN` (default in `strict`). The default profile keeps them out of scope *and records that in the receipt*. Test: `test_mcp_tools_stay_out_of_scope_by_default_and_guarded_in_strict`. Residual risk accepted and documented (a git guard cannot interpret an arbitrary MCP server). |
| H7 | Environment variables could redirect policy, approval store and audit path. | Mitigated: the installers pin `--policy`, `--approval-store` and (through the policy) the audit path explicitly; an explicit path wins over the environment, and a missing explicit policy is an error. Residual risk accepted (an owner or a non-hooked process can still set up a permissive policy). |
| H8 | Approval double-spend race. | Fixed with B12. |
| H9 | A write named through an alias of the repository (a symlink such as macOS `/var` -> `/private/var`, or a Windows 8.3 short name such as `RUNNER~1`) was classified as outside the repository, because git reports the resolved toplevel. `.git/config` and `.github/workflows/*` were then allowed in the default profile, and in-repo writes were denied as repo escapes in `strict`. | Fixed: a path that does not lexically sit under the repository root is compared again after resolving both. Tests: `test_protected_paths_hold_through_a_repository_alias`, `test_repository_alias_is_not_a_repo_escape`. Follow-up fix: secret, CI and protected globs now see both the lexical and the resolved spelling of a target, and deny if either matches. The resolved spelling sees through a symlink *inside* the repository that points at a protected directory (`link/config` with `link` -> `.git`), and the repository root is also found by file identity, which covers a case-variant spelling of the root on a case-insensitive macOS volume that `realpath` leaves as written. The inside/outside decision is unchanged and never folds case. The probe root is cut at any `.git` component, lexical or resolved: before, a write to `.git/hooks/pre-commit` found no repository and was allowed. Tests: `test_protected_paths_hold_through_a_symlink_inside_the_repository`, `test_protected_paths_hold_through_a_case_variant_repository_root`, `test_case_variant_directory_on_a_case_sensitive_volume_stays_outside`, `test_writes_below_git_subdirectories_are_protected`. |

### Medium / Low (selected)

| # | Finding | Disposition |
| --- | --- | --- |
| M1 | `git push --dry-run --force` was denied (false positive). | Fixed: dry runs are non-destructive. Test: `test_push_dry_run_is_not_destructive`. |
| M2 | Read-only `sed -n 1p .env` was denied because `sed` was treated as a write verb. | Fixed: only `sed -i`/`--in-place` counts as a write. |
| M3 | `git pull`, `git reset --soft`, `git cherry-pick`, `git revert`, `git gc`, `git rm --cached`, `git update-index --refresh`, `git checkout --ours`, `git switch -c` required the owner or were denied. | Fixed: all classified non-destructive, with `pull --rebase` mapped to the rebase rule. Test: `test_daily_commands_are_non_destructive`. |
| M4 | `git reflog delete` was allowed. | Fixed: treated like `reflog expire`. Test: `test_reflog_delete_is_history_expiry`. |
| M5 | `-c core.hooksPath=...` on a read-only subcommand was a false positive. | Fixed: bypass rules apply only to config-sensitive subcommands. Test: `test_inline_config_on_read_only_subcommand_is_not_a_bypass`. |
| M6 | Path protection was case-sensitive outside a repository on Windows (`.ENV` allowed). | Fixed: matching is case-insensitive on every OS (also case-insensitive macOS volumes; fail closed on Linux). Test: `test_case_insensitive_protection_outside_a_repository`. |
| M7 | The hook crashed (exit 70) when `tool_input` was a string instead of an object. | Fixed: a type guard, plus hook-level exception handling. |
| M8 | `--non-interactive` was documented as "treat REQUIRE_OWNER as DENY" but only affected `UNKNOWN`. | Fixed: the help text now states the real semantics (no human available for `UNKNOWN`; `REQUIRE_OWNER` still needs a pre-minted approval). Design kept, because turning every owner-gated operation into a hard denial would break interactive OpenCode sessions. |
| M9 | The audit writer truncated over-long JSON lines, producing unparsable entries that later reads dropped. | Fixed: records are bounded field by field and never cut mid-JSON. |
| M10 | The preflight skipped the large-file check entirely for staged sets over 400 files. | Fixed: it samples and records `LARGE_FILE_PROBE_SAMPLED`. |
| M11 | `explain` contradicted `check` for `git.other`. | Fixed: the unknown ceiling governs both; the inert per-profile `git.other` overrides were removed. |
| M12 | Dead code (`Decision.blocked`, `gitop.classify`, unreachable branches, unused alternative-dict entry) and an unused policy knob. | Fixed: removed or wired (`allowed_repo_roots` is now honoured, `approvals.store` is used, `generated_paths` is type-validated). |
| M13 | Tests contained a tautological assertion and implementation-level assertions. | Fixed: the tautology is gone; plugin content assertions were replaced by a behavioural node test that calls the plugin handler and asserts block/allow. |

## What was verified as correct (positive controls)

The reviewers explicitly confirmed:

* the dangerous baseline commands are caught (`reset --hard`, `clean -fd`,
  `push --force`, `push -f`, `checkout .`, `restore .`, `stash drop`,
  `filter-branch`, `reflog expire`, `branch -D` unmerged, `commit --amend`
  published, `add -A`, hook bypasses, secret and protected path writes);
* blocked commands leave the worktree, HEAD and the index untouched (asserted
  by inspecting files and `git status` before and after);
* the state probe is read-only;
* approvals are single-use, bound to repo/branch/HEAD, refuse non-interactive
  minting from the CLI, and a corrupt store fails closed;
* receipts are digest-sealed and tampering is detected;
* the audit log contains no command text by default;
* no part of an evaluated command is ever passed to a shell (all subprocess
  calls are argv lists, the plugin uses `spawnSync` without `shell`);
* SafeGit never executes the action it evaluates (verified with a side-effecting
  probe);
* parser, nesting, segment and length bounds hold;
* interpreter wrappers with separate flags (`bash -c`, `sh -c`, `cmd /c`,
  `powershell -Command`, `python -c`) were already scanned.

## Residual risk (accepted, documented)

1. **Same-user attacker with a terminal** can mint approvals and can edit files
   when SafeGit is not the one being asked. There is no cryptographic defence
   without an OS-level secret store.
2. **Opaque tools (MCP, scripts, compiled helpers)** are not interpreted. They
   are reported, and the `strict` profile escalates them, but a determined
   indirection path exists.
3. **Pattern-based path protection** can be defeated by constructing a path at
   runtime.
4. **A host that ignores the exit code, or a hook that times out**, cannot be
   forced to block. The internal budget makes this unlikely, not impossible.
5. **A stale remote-tracking ref** limits what the guard knows about a remote.
6. **Deleting the policy file** downgrades to the built-in default profile;
   the audit log makes the downgrade visible but does not prevent it.
7. **No live Claude Code session was exercised** (cost/quota). The protocol is
   verified from documentation and by executing the hook; the exact blocking
   behaviour in a live session is marked UNVERIFIED.

## How to reproduce the verification

```bash
python -m unittest discover -s tests                    # 156 tests
python -m safegit selftest                              # built-in expectations
python -m safegit check --command "git reset --hard" --json
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"},"cwd":"."}' \
  | safegit hook claude; echo "exit=$?"                 # expect exit=2
python tools/selfcheck_no_private_data.py --path .      # privacy gate
python tools/measure_latency.py                         # performance numbers
```
