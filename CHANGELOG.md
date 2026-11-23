# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Security

* Installed hooks could be redirected by the environment. When no policy
  file existed at install time the hook was pinned to `--profile default`,
  but `--profile` is only a fallback, so a `SAFEGIT_POLICY` or
  `SAFEGIT_POLICY_DIR` set later (or a policy file dropped on the search path)
  replaced the pinned ruleset. `install` now also writes `--pinned`, which
  makes `--policy`/`--profile` binding. **Re-run `safegit install` for existing
  Claude Code and OpenCode hooks.**
* The git `pre-commit` hook (`install githooks`) pinned no policy at all, so
  the commit gate followed `SAFEGIT_POLICY` and policy discovery at commit
  time. It now pins `--policy`/`--profile` with `--pinned` too, quoted and with
  forward slashes for `sh`. Re-run `safegit install githooks`, and again after
  adding or moving a policy: a re-install now replaces an existing SafeGit
  block in place (other hook lines are kept) instead of reporting "already
  installed" and leaving the old block untouched.
* `install` no longer pins the builtin default when the found or named policy
  is missing or invalid; it refuses with `POLICY_NOT_FOUND` /
  `POLICY_JSON_INVALID`.

### Fixed

* The Claude Code hook command quotes pinned paths that contain whitespace
  (for example a home folder `C:\Users\<first last>`), which previously broke every
  hook call, and refuses pinned paths with shell metacharacters.

### Added

* `safegit audit --verdict ALLOW|DENY|REQUIRE_OWNER|UNKNOWN` filters both
  tail output and whole-log summaries, in text or JSON.

### Fixed

* Audit queries stream records instead of loading the entire log into memory.
  Malformed JSON, non-object records, invalid UTF-8, excessively nested JSON
  and oversized lines are skipped; `--tail` counts valid matching records.
* `safegit preflight` crashed with `NameError: name 'FAIL' is not defined`
  (exit 70) whenever there was any finding, so the pre-commit gate refused
  every such commit. `FAIL`/`WARN` are now imported in `cli.py`.
* `install githooks` wrote an unquoted backslash interpreter path with CRLF
  line endings, which Git Bash cannot run (`exec: C:Users...: not found`).
  The hook now quotes a forward-slash path and is written with LF.
* `install opencode` wrote a 1.x-only plugin to `.opencode/plugin/` that
  OpenCode 2.x ignores, so guarded commands ran unchecked. It now writes a
  dual-export plugin (2.x `setup(ctx)` + 1.x `server()`) to
  `.opencode/plugins/`, takes the project directory from
  `ctx.location.directory`, refuses calls when it is unknown, and pins
  `--git` to an absolute path. `doctor` checks the new location.
* The OpenCode 2.x plugin gated every call in `ctx.location.directory`, which
  is the plugin instance's location, not the session's. It now gates each call
  in its session's directory (`ctx.session.get`) and refuses calls from a
  session outside the plugin's project or whose session cannot be looked up.
* A shell tool's `workdir` (OpenCode) was ignored, and an explicit
  `working_directory` was shadowed by the hook's own `cwd`, so a command run
  in another repository was judged against the session's repository (e.g.
  `git checkout -- f` allowed in a clean repo while discarding work in a dirty
  one). Relative action directories are anchored at the event `cwd`.
* `test_owner_required_exit_code_is_three` depended on the directory the suite
  was started from; it now pins `--cwd` to its temporary directory.

## 0.1.0 - release candidate

First public release candidate. Everything below is implemented and covered by
the test suite (156 tests, including 42 regression tests for bypasses found in
independent review).

### Added

* Deterministic policy core with four verdicts (`ALLOW`, `DENY`,
  `REQUIRE_OWNER`, `UNKNOWN`) and four built-in profiles (`default`, `strict`,
  `relaxed`, `ci`).
* Structural command parsing: shell segments, quoting, command substitution,
  interpreter bodies (`bash -c`, `pwsh -Command`, `python -c`, `cmd /c`),
  env-assignment prefixes, wrapper programs (`sudo`, `env`, `timeout`,
  `nice`, `xargs`).
* Git operation classification by argv (36 rule ids) including a
  force-flag prefix resolver, so `git clean --forc` cannot slip past.
* Read-only, budget-bounded repository state probing (root, branch, HEAD,
  staged/unstaged/untracked, conflicts, stash, worktrees, upstream,
  ahead/behind) in a scrubbed environment.
* State-aware decisions: merged-branch deletion allowed, unmerged deletion
  requires the owner, amend of a published commit denied, force-with-lease
  denied when the remote is ahead, forced checkout denied when the worktree is
  dirty, restores/checkouts allowed when the target has no local changes,
  no-op operations recognised (empty stash, missing branch).
* Protected-path and secret-path protection for shell commands *and* file
  write tools, including interpreter indirection via literal anchors.
* Commit preflight: in-progress merge/rebase, unmerged index entries,
  `git diff --cached --check`, conflict markers, staged set and size limits,
  binary and large files, secret/protected/CI paths, declared staging scope.
* Single-use owner approvals bound to rule + action + repository + branch +
  HEAD, with an interactive-terminal requirement, an integrity digest, a
  store lock and a use-count clamp.
* Digest-sealed decision receipts and a privacy-preserving audit log (action
  digest instead of command text by default).
* CLI: `version`, `doctor`, `check`, `hook`, `preflight`, `explain`,
  `approve`, `policy`, `audit`, `install`, `selftest`.
* Adapters: Claude Code `PreToolUse` hook (exit 2 + JSON deny), OpenCode
  plugin (throws on a blocked call), git `pre-commit` hook.
* Installers that merge configuration without clobbering it, pin the policy
  and approval store, and refuse unsafe interpreter paths.
* Self-protection: refuses to run when the working directory shadows the
  package, blocks hook-bypass flags and config overrides, and protects its own
  policy file.

### Security

* Two independent adversarial reviews were run against this release candidate
  (one code review, one security audit). 54 findings were reported; all
  critical and high findings were fixed and each fix has a regression test.
  The remaining, accepted risks are listed in `docs/SECURITY_REPORT.md` and
  `docs/KNOWN_LIMITATIONS.md`.
* Live verification: an AI coding agent (OpenCode, free model) was asked to
  discard an uncommitted change in a throwaway repository. SafeGit blocked the
  operation, the agent reported the denial, the repository was unchanged, and
  the audit log recorded the decision.
