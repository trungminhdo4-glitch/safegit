# Configuration

Everything SafeGit decides comes from one JSON policy file plus a few
command-line flags. There is no hidden configuration and no environment
variable that silently changes what the guard trusts (the installed hook pins
its policy path explicitly).

## Policy file

Default locations, in order:

1. `--policy <path>`
2. `SAFEGIT_POLICY` (file) or `SAFEGIT_POLICY_DIR` (directory)
3. `<dir>/.safegit/safegit.policy.json`, walking up from the working directory
4. `<repository root>/safegit.policy.json`
5. `~/.safegit/safegit.policy.json`
6. otherwise the built-in `default` profile, recorded as `<builtin:default>`

A policy that is requested explicitly or discovered but cannot be read, parsed
or validated is an **error** (exit 70 in CLI mode, exit 2 in hook mode). It
never degrades into a weaker policy.

```bash
safegit policy init --profile strict     # write a starting point
safegit policy validate                  # exit 0 = valid, exit 1 = invalid
safegit policy show                      # effective policy + digest
```

## Schema

```json
{
  "schema": "safegit.policy/1",
  "profile": "default",
  "enforcement": "binding",
  "interactive": true,
  "rules": { "git.push.force": "REQUIRE_OWNER" },
  "protected_branches": ["main", "master", "trunk", "develop", "release/*", "release-*"],
  "protected_paths": [".git", ".git/**", ".safegit/**", "safegit.policy.json"],
  "secret_paths": ["**/.env", "**/*.pem", "**/*.key", "**/.ssh/**"],
  "ci_paths": [".github/workflows/**", ".gitlab-ci.yml"],
  "allowed_repo_roots": [],
  "unknown_git_operations": "REQUIRE_OWNER",
  "protect_default_branch_commits": false,
  "guard_opaque_tools": false,
  "commit_preflight": {
    "enabled": true,
    "max_files": 40,
    "max_added_lines": 900,
    "max_deleted_lines": 900,
    "max_file_bytes": 5242880,
    "block_conflict_markers": true,
    "block_denied_paths": true,
    "warn_generated_paths": true,
    "generated_paths": []
  },
  "approvals": {
    "ttl_seconds": 900,
    "max_uses": 1,
    "store": "",
    "require_interactive": true
  },
  "audit": {
    "enabled": true,
    "path": "",
    "retention_days": 30,
    "include_command": false
  }
}
```

### Field semantics

| Field | Meaning |
| --- | --- |
| `enforcement` | `binding` (default): an `UNKNOWN` escalates. `advisory`: an `UNKNOWN` stays `UNKNOWN` and is reported without blocking |
| `interactive` | `false` means no human is available: an `UNKNOWN` becomes `DENY`. Set automatically by the `ci` profile |
| `rules` | Verdict per rule id; unknown ids are a validation error. The profile supplies the base, this object overrides single entries |
| `protected_branches` | Glob list; a push or delete to a match escalates (a delete is denied) |
| `protected_paths` | Glob list; a write (shell or file tool) is denied |
| `secret_paths` | Glob list; a write is denied. `**/.env.example`, `.template`, `.sample`, `.dist` are always allowed |
| `ci_paths` | Glob list; a write requires the owner (denied in `strict`) |
| `allowed_repo_roots` | When non-empty, a write outside these roots (relative to the repo root) is subject to `fs.repo_escape_write` |
| `unknown_git_operations` | The ceiling for an `UNKNOWN` result: `ALLOW` (explicit), `DENY`, `REQUIRE_OWNER` (escalate), `UNKNOWN` (never improve automatically in binding mode, stay `UNKNOWN` in advisory mode) |
| `protect_default_branch_commits` | `true` makes a plain `git commit` on a protected branch require the owner (default in `strict`) |
| `guard_opaque_tools` | `true` turns opaque tools (MCP, unclassified) into `UNKNOWN` instead of out-of-scope `ALLOW` (default in `strict`) |
| `commit_preflight.generated_paths` | Globs reported as generated artefacts in the preflight |
| `approvals.store` | Explicit approval store path. Empty means `SAFEGIT_APPROVAL_STORE` or `~/.safegit/approvals.json` |
| `approvals.require_interactive` | Reject approvals that were minted without a terminal |
| `approvals.max_uses` | Upper bound for uses; a hand-edited `uses_remaining` is clamped to this value on consume |
| `audit.enabled` | Write one audit line per decision |
| `audit.path` | Explicit audit path. Empty means the repository's `.safegit/audit.jsonl`, else the user profile |
| `audit.include_command` | `false` (default) stores a SHA-256 of the action instead of the command text. Set `true` only if you accept that command text (which can contain sensitive arguments) is written to disk |
| `audit.retention_days` | Lines older than this are dropped on the next write (`0` disables pruning) |

### Protected and secret defaults

Protected (write denied): `.git`, `.git/**`, `.safegit`, `.safegit/**`,
`safegit.policy.json`, `**/safegit.policy.json`, `opencode.json`, `opencode.jsonc`,
`.opencode/**`, `.claude/settings.json`, `.claude/settings.local.json`,
`.claude/hooks/**`, `**/.gitconfig`, `**/.config/git/config`, `**/.npmrc`.

Secret (write denied): `**/.env`, `**/.env.*`, `**/*.pem`, `**/*.key`,
`**/credentials`, `**/credentials.*`, `**/*_secret`, `**/*_secret.*`,
`**/.aws/**`, `**/.ssh/**`, `**/id_rsa*`, `**/.netrc`, `**/.bashrc`,
`**/.zshrc`, `**/.profile`, `**/.bash_profile`, `**/.config/powershell/**`,
`**/.local/share/powershell/**`. Known template names are allowlisted.

If a policy file omits one of these lists, the built-in defaults apply - a
minimal policy can never silently remove all protection.

## Profiles

| Profile | Intent |
| --- | --- |
| `default` | Day-to-day work with an agent: irreversible operations blocked, recoverable-but-risky ones need the owner, normal development flow untouched |
| `strict` | Unattended/CI-like work: force-push-with-lease, rebase, amend, `rm` and config writes are denied, `push`/`merge`/`add -A` need the owner, opaque tools are escalated |
| `relaxed` | Trusted local work: most destructive operations require the owner instead of being denied, so a human can approve them quickly. Irreversible history rewrites stay denied |
| `ci` | Non-interactive: no human to ask, so escalations become denials where it matters (`push.plain`, `unknown`) |

### Rule verdict table

Generated from the code by `tools/build_rule_table.py`; regenerate after
changing a profile.

| Rule id | default | strict | relaxed | ci |
| --- | --- | --- | --- | --- |
| `git.reset.hard` | DENY | DENY | REQUIRE_OWNER | DENY |
| `git.reset.keep` | DENY | DENY | REQUIRE_OWNER | DENY |
| `git.clean.force` | DENY | DENY | REQUIRE_OWNER | DENY |
| `git.push.force` | DENY | DENY | REQUIRE_OWNER | DENY |
| `git.push.force_with_lease` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.push.delete_branch` | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.push.broad` | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.push.plain` | ALLOW | REQUIRE_OWNER | ALLOW | DENY |
| `git.rebase` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.rebase.continue` | ALLOW | REQUIRE_OWNER | ALLOW | ALLOW |
| `git.commit.amend` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.commit.plain` | ALLOW | ALLOW | ALLOW | ALLOW |
| `git.worktree.remove` | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.worktree.prune` | ALLOW | REQUIRE_OWNER | ALLOW | ALLOW |
| `git.branch.delete.force` | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.branch.delete.safe` | ALLOW | REQUIRE_OWNER | ALLOW | ALLOW |
| `git.branch.rename` | ALLOW | ALLOW | ALLOW | ALLOW |
| `git.checkout.discard` | DENY | DENY | REQUIRE_OWNER | DENY |
| `git.checkout.switch` | ALLOW | ALLOW | ALLOW | ALLOW |
| `git.restore.worktree` | DENY | DENY | REQUIRE_OWNER | DENY |
| `git.add.all` | ALLOW | REQUIRE_OWNER | ALLOW | ALLOW |
| `git.stash.destroy` | DENY | DENY | REQUIRE_OWNER | DENY |
| `git.history.filter` | DENY | DENY | DENY | DENY |
| `git.history.expire` | DENY | DENY | DENY | DENY |
| `git.ref.write` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.config.write` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.config.inline_override` | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.remote.change` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.tag.delete` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.submodule.change` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.merge` | ALLOW | REQUIRE_OWNER | ALLOW | ALLOW |
| `git.rm.tracked` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.hook.bypass` | DENY | DENY | DENY | DENY |
| `git.repo.override` | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER | REQUIRE_OWNER |
| `git.non_destructive` | ALLOW | ALLOW | ALLOW | ALLOW |
| `git.other` | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |
| `fs.protected_write` | DENY | DENY | DENY | DENY |
| `fs.secret_write` | DENY | DENY | DENY | DENY |
| `fs.ci_write` | REQUIRE_OWNER | DENY | REQUIRE_OWNER | REQUIRE_OWNER |
| `fs.repo_escape_write` | ALLOW | DENY | ALLOW | ALLOW |
| `fs.other_write` | ALLOW | ALLOW | ALLOW | ALLOW |

## Command-line flags that matter

| Flag | Effect |
| --- | --- |
| `--profile <name>` | Use a built-in profile as the base (ignored when a policy file is found) |
| `--policy <path>` | Use exactly this policy file; a missing file is an error |
| `--non-interactive` | No human is available: `UNKNOWN` becomes `DENY`. `REQUIRE_OWNER` still needs a pre-minted approval |
| `--timeout <seconds>` | Per-git-call timeout (default 5 s; the whole probe is additionally bounded by a 6 s budget) |
| `--approval-store <path>` | Explicit approval store |
| `--no-approvals` | Ignore outstanding approvals (useful for testing and for CI) |
| `--strict` (preflight) | Treat preflight warnings as blocking |

## Recipes

**Block direct pushes to a release branch, allow the rest**

```json
{
  "schema": "safegit.policy/1",
  "profile": "default",
  "protected_branches": ["main", "master", "release/*", "release-*", "production"]
}
```

**Let an agent commit on a branch but never on `main`**

```json
{
  "schema": "safegit.policy/1",
  "profile": "default",
  "protect_default_branch_commits": true
}
```

**Require the owner for every force-push, even with a lease**

```json
{
  "schema": "safegit.policy/1",
  "profile": "default",
  "rules": { "git.push.force_with_lease": "REQUIRE_OWNER" }
}
```

**Machine-readable evidence in CI, no audit log in the repository**

```json
{
  "schema": "safegit.policy/1",
  "profile": "ci",
  "audit": { "enabled": false }
}
```

**Keep the audit trail but store the command text** (accepting that arguments
become readable on disk):

```json
{ "schema": "safegit.policy/1", "profile": "default",
  "audit": { "include_command": true } }
```

## Environment variables

| Variable | Purpose | Trusted in hook mode? |
| --- | --- | --- |
| `SAFEGIT_POLICY`, `SAFEGIT_POLICY_DIR` | Policy location | No: the installed hook pins `--policy`, which wins |
| `SAFEGIT_APPROVAL_STORE` | Approval store | No: the installed hook pins `--approval-store` |
| `SAFEGIT_AUDIT_PATH` | Audit log location | Only when the policy does not set a path; pin the policy to disable it |
| `SAFEGIT_CLI` | Interpreter used by the OpenCode plugin | No: the plugin is generated with an absolute argv |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | `ALLOW` |
| 2 | `DENY` (also used for a hook-level block on any non-allow verdict) |
| 3 | `REQUIRE_OWNER` |
| 4 | `UNKNOWN` |
| 64 | usage error |
| 70 | internal error (a broken policy, an unreadable store) - a CI gate must treat this as a failure |
