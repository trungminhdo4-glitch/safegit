# Installation

## Requirements

* Python 3.9 or newer (3.11+ recommended: the installed hook then runs with
  `-P`, which prevents a repository-local `safegit.py` from shadowing the
  package).
* `git` on `PATH` (tested with git 2.52 on Windows 11; any recent git works).
* No third-party Python packages, no network access, no account.
* Supported hosts: Claude Code (2.1.x), OpenCode (1.18.x), git itself, any CI
  that can run a command. Verified on Windows 11; Linux/macOS are expected to
  work (no platform-specific code beyond path case handling) but are not part
  of the verified configuration - see `docs/COMPATIBILITY` notes in the release
  receipt.

## Install the package

From the release-candidate directory:

```bash
pipx install ./safegit-0.1.0-py3-none-any.whl    # recommended: isolated
# or
python -m pip install ./safegit-0.1.0-py3-none-any.whl
```

Without installing (source checkout):

```bash
cd safegit
python -m safegit doctor          # works with PYTHONPATH or an editable install
```

Verify:

```bash
safegit version
safegit doctor
safegit selftest
```

`doctor` reports the Python version, the git executable, the resolved policy
(including whether it is the built-in default), the approval store path, the
detected hook wiring, and the built-in rule self-test.

## Create a policy

Without a policy file SafeGit uses the built-in `default` profile and records
`<builtin:default>` as the policy source, so an audit trail always shows which
ruleset decided.

```bash
safegit policy init                       # writes .safegit/safegit.policy.json
safegit policy init --profile strict      # stricter starting point
safegit policy validate                   # exit 0 = valid
safegit policy show                       # the effective policy, with its digest
```

Commit the policy if you want every developer to share it; the file is
protected from agent writes either way. Add `.safegit/audit.jsonl` to
`.gitignore` (the shipped `.gitignore` already does).

## Claude Code

```bash
safegit install claude --dir .            # dry run: prints the merged settings
safegit install claude --dir . --write    # apply
```

What the installer does:

* reads `.claude/settings.json` if present and merges a `PreToolUse` entry
  without touching any other key;
* writes a one-time backup `settings.json.safegit-backup`;
* is idempotent: running it twice does not add a second hook;
* builds the hook command from the absolute interpreter path plus
  `-P -m safegit` (on Python 3.11+), and pins `--policy <path>` (or
  `--profile default`) and `--approval-store <path>`;
* refuses to build a command if the interpreter path contains shell
  metacharacters;
* defaults to the matcher
  `Bash|PowerShell|Write|Edit|NotebookEdit|MultiEdit|Task|mcp__.*`.

Manual equivalent (if you prefer to edit settings yourself):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Write|Edit|NotebookEdit|MultiEdit|Task|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "\"/path/to/python\" -P -m safegit hook claude --policy /repo/.safegit/safegit.policy.json --approval-store /home/you/.safegit/approvals.json",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

Verify the hook without a model call:

```bash
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"."}' | safegit hook claude; echo "exit=$?"
# expect exit=0 and no output

printf '%s' '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"},"cwd":"."}' | safegit hook claude; echo "exit=$?"
# expect exit=2, a JSON deny object on stdout and a reason on stderr
```

A timed-out or failed hook does not block in Claude Code. Keep the hook timeout
(default 15 s) comfortably above SafeGit's internal budget (6 s); `doctor`
does not verify the timeout, so check the settings file if you changed it.

## OpenCode

```bash
safegit install opencode --dir . --write
```

Writes `.opencode/plugins/safegit.js`, a dual-export plugin: OpenCode 2.x
calls `setup(ctx)` (hook `execute.before`, project directory from
`ctx.location.directory`), OpenCode 1.x calls `server()` (hook
`tool.execute.before`). OpenCode 2.x does not load the 1.x-only
`.opencode/plugin/` file older SafeGit versions wrote; remove that file after
reinstalling. `--git` is pinned to an absolute path at install time. The plugin shells out to `safegit hook opencode` and **throws** on a
blocked call or on a spawn failure, so it fails closed.

Notes:

* `opencode --pure` starts without external plugins - a deliberate off switch,
  not a SafeGit feature.
* The plugin passes `--non-interactive`, so an `UNKNOWN` operation is denied
  rather than escalated. A pre-minted approval still works.
* If the plugin is missing, OpenCode simply runs the tool call. `safegit
  doctor` reports the plugin's presence.

## git hooks

```bash
safegit install githooks --repo . --write
```

Appends a marked block to `.git/hooks/pre-commit` that runs
`safegit preflight --strict`. An existing hook is never overwritten: SafeGit
refuses unless `--force` is given. Use `--repo` to target a specific
repository.

## Approving one risky action

```bash
safegit approve --command "git push --force-with-lease origin release/1.0"
# prints a fingerprint and a short confirmation code

safegit approve --command "git push --force-with-lease origin release/1.0" \
  --confirm-code ABC12345 --reason "hotfix, coordinated with the team"
```

Requirements and limits:

* must run in an interactive terminal (an agent tool call is not interactive);
* bound to the rule, the exact action, the repository root, the branch and
  HEAD - any change invalidates it;
* single use by default; consumed before the action runs;
* expires (default 900 s).

## Uninstall

```bash
safegit install claude --dir . --write      # remove the hook entry manually
python -m pip uninstall safegit
rm -rf .safegit                             # local policy and audit log (optional)
```

There are no services, scheduled tasks, registry entries or global hooks.
SafeGit never installs anything outside the paths you see in
`safegit install ... --write` output.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Every command is `REQUIRE_OWNER` | No policy file and an unknown operation; or the `strict` profile | `safegit policy show`, then `safegit explain "<command>"` |
| Hook never fires in Claude Code | Matcher does not cover the tool, or the settings file is not the one Claude reads | `safegit doctor`, check the project `.claude/settings.json` |
| `SAFEGIT_SHADOWED_BY_WORKING_DIRECTORY` | A `safegit.py` exists in the working directory | Reinstall with Python 3.11+ (`-P`), or remove the shadowing file |
| `SAFEGIT_HOOK_ERROR` on every call | Policy unreadable/invalid, or the interpreter path moved | `safegit policy validate`, then re-run the installer |
| Plugin blocks everything with "SafeGit could not run" | `safegit` is not importable for that interpreter, or the probe exhausted its budget | Run `safegit doctor` with the same interpreter; raise `--timeout` if the repository is huge |
| `git` operations on a linked worktree behave oddly | State is resolved for the worktree you are in, not the parent repository | Run with `--cwd` pointing at the worktree |
