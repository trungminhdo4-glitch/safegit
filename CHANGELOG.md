# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
