# SafeGit

**Git safety and repository protection for AI coding agents.**

SafeGit sits in front of the shell and the file writes that an AI coding agent
proposes, and answers one question deterministically: *may this action touch
this repository?* It returns `ALLOW`, `DENY`, `REQUIRE_OWNER` or `UNKNOWN`,
with a machine-readable reason and evidence.

* Dependency-free (Python standard library only)
* Offline: no telemetry, no account, no network call
* Agent-independent: the same policy core serves Claude Code, OpenCode, git
  hooks, CI and a plain CLI
* State-aware: decisions use the real repository state, not only the text of a
  command

---

## What is SafeGit?

A small, auditable policy engine plus thin adapters. The engine parses a
proposed action into concrete operations, reads the repository state
(read-only), evaluates a JSON policy, and returns a verdict with evidence.
Nothing else. There is no model in the decision path and no server.

```
agent tool call ──► host hook (Claude Code / OpenCode / git / CI)
                         │
                         ▼
                 SafeGit CLI "hook" mode
                         │
        parse command ──► classify git ops ──► read repo state
                         │                         │
                         └──────► policy engine ◄──┘
                                     │
                     ALLOW / DENY / REQUIRE_OWNER / UNKNOWN
                                     │
                       receipt + audit record (digests)
```

## Who is it for?

Developers who let an agent run shell commands in a repository they care about,
and who want a deterministic, reviewable boundary instead of a prompt that says
"please be careful" - plus a way to grant one specific risky action to one
specific action without disabling the guard.

## What problems does it solve?

| Problem | What SafeGit does |
| --- | --- |
| `git reset --hard` / `git clean -fd` silently discards uncommitted work | Denies the operation and reports how many files were at risk |
| `git push --force` rewrites shared history | Denies it; `--force-with-lease` requires the owner, and is denied when the remote is ahead |
| An agent stages and commits someone else's work in progress | Commit preflight shows exactly what is staged, including secrets, protected paths and CI files |
| `git branch -D` destroys unmerged commits | The delete is allowed only when the branch is really merged |
| `git commit --amend` rewrites published history | Denied when HEAD is already on a remote |
| An agent disables the check that would have caught it | Hook bypasses (`--no-verify`, `HUSKY=0`, `-c core.hooksPath`) are denied |
| Silent `ALLOW` because a command could not be classified | Unclassified git operations become `UNKNOWN`, and `UNKNOWN` never silently becomes `ALLOW` in binding mode |
| "It said no but nothing happened" | Every decision is a digest-sealed receipt with evidence |

## How does it work?

1. **Adapt.** A thin adapter hands SafeGit the tool call exactly as the host
   produced it (Bash command, file path, patch text).
2. **Parse structurally.** The command string is tokenised; segments
   (`&&`, `;`, `|`), command substitutions, interpreter bodies (`bash -c`,
   `pwsh -Command`, `python -c`), env prefixes and wrapper programs
   (`sudo`, `env`, `timeout`, `xargs`) are unwrapped. No regex is used to
   decide whether a git command is dangerous.
3. **Classify by argv.** Each `git` invocation becomes typed operations with
   flags and refspecs, so `git push --force` and
   `git commit -m "revert reset --hard"` are not confused.
4. **Read state (read-only).** Repo root, branch, HEAD, staged/unstaged/
   untracked counts, stash, worktrees, upstream, ahead/behind, whether a
   branch is merged, whether HEAD is published, whether a path has local
   edits. Bounded by a wall-clock budget so the guard can never hang a tool
   call.
5. **Decide.** A JSON policy maps each operation to a verdict. State refines
   the answer: a branch that is fully merged may be deleted, a path with no
   local changes may be restored, an amend of an unpublished commit needs the
   owner, an amend of a published commit is denied.
6. **Record.** One receipt per decision (digest-sealed) and one audit line
   that contains a hash of the action, not the action itself.

## What does it protect against?

* Destructive git operations: `reset --hard/--merge/--keep`, `clean -f`,
  `checkout -f`/path checkouts, `restore` of the worktree, `stash drop/clear`,
  `filter-branch`/`filter-repo`, `reflog expire`/`delete`, aggressive `gc`.
* History and remote rewrites: `push --force`/`-f`/`+refspec`, `--mirror`,
  `--delete`, `--force-with-lease` (context-dependent), `commit --amend`,
  `rebase`.
* Work loss: any of the above is reported together with the number of files
  that would have been destroyed, and the action is denied.
* Protected branches: pushes and deletes targeting `main`, `master`,
  `release/*`, ... require the owner.
* Foreign work: `git add -A`/`.` is allowed but reported (it stages untracked
  files); the commit preflight is the gate that catches an unintended staging
  set.
* Repository and guard integrity: `.git`, `.safegit`, the policy file, agent
  configuration (`opencode.json`, `.claude/settings*`), user git config
  (`~/.gitconfig`), shell profiles and secret paths (`.env`, `*.pem`,
  `*.key`, credentials, `.ssh`, `.aws`) cannot be written by the agent.
* Verification bypasses: `--no-verify`, `--no-gpg-sign`, `HUSKY=0`,
  `-c core.hooksPath=...`, `--git-dir`/`--work-tree` redirection.

## What does it NOT protect against?

Read this section as carefully as the one above.

* **It is not a sandbox.** An agent with the same OS user and an unguarded
  shell can bypass SafeGit entirely, e.g. by running the command outside the
  hooked tool, by launching a second agent (`opencode --pure`), by calling a
  script the guard never sees, or by editing its own configuration.
* **Opaque indirection is reported, not understood.** Structured file
  evaluation cannot see inside an arbitrary script, a compiled program, or an
  MCP tool; those are marked out of scope (or `UNKNOWN` in the `strict`
  profile).
* **Pattern-based path protection can be evaded** by constructing a path at
  runtime (`p = ".e" + "nv"`). It raises the cost, it is not a filesystem
  boundary.
* **It cannot undo anything.** It decides before an action; if a host ignores
  the exit code, the action still happens.
* **Non-git filesystem damage is out of scope** (for example `rm -rf src`);
  SafeGit guards git operations and writes to the paths listed above.
* **Approvals are not cryptographic.** A same-user agent with an interactive
  terminal can mint one.
* **A stale remote-tracking ref** limits what the guard knows about the
  remote.

See [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full, itemised list.

## Install

Requires Python 3.9+ and `git` on `PATH`. No third-party packages.

```bash
pipx install .            # or: pip install .
safegit doctor            # check the installation
safegit selftest          # verify the built-in rule expectations
```

Run without installing (from a checkout):

```bash
python -m safegit check --command "git status"
```

See [`docs/INSTALLATION.md`](docs/INSTALLATION.md) for the full procedure
including Windows specifics and the release-candidate wheel.

## Integrate with your coding agent

### Claude Code

```bash
safegit install claude --dir .            # dry run, prints the settings JSON
safegit install claude --dir . --write    # merges the PreToolUse hook
```

The installer merges into the existing `.claude/settings.json` (never
clobbers it), keeps a backup, pins the policy and the approval store at
install time, and is idempotent. The hook returns exit code 2 with a reason -
Claude Code blocks a tool call on exit 2 and shows the reason to the model.

Verify the wiring:

```bash
python -m safegit doctor
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"."}' | safegit hook claude
```

### OpenCode

```bash
safegit install opencode --dir . --write
```

This writes `.opencode/plugins/safegit.js`, a small plugin that shells out
to `safegit hook opencode` before every tool call and throws on a non-zero
exit. It exports both the OpenCode 2.x shape (`{ id, setup(ctx) }`) and the
1.x `server()` hook; OpenCode 2.x ignores the old 1.x-only `.opencode/plugin/`
layout. The installer pins `--git` to an absolute path because OpenCode's
background service may run without git on its PATH. Note that
`opencode --pure` deliberately disables plugins.

### git hooks

```bash
safegit install githooks --repo . --write   # pre-commit: safegit preflight --strict
```

An existing `pre-commit` hook is never overwritten; SafeGit refuses unless you
pass `--force`, and then it appends a marked block.

### CLI and CI

```bash
safegit check --command "git push --force origin main" --json
safegit preflight --repo . --json
safegit explain git.push.force
safegit policy init --profile strict
safegit approve --command "git push --force-with-lease origin release/1.0"
safegit audit --summary
```

Exit codes: `0` ALLOW, `2` DENY, `3` REQUIRE_OWNER, `4` UNKNOWN, `64` usage,
`70` internal error. In hook mode, exit `2` means "blocked" and is used for
every non-ALLOW verdict, including internal errors.

### Measured cost

Windows 11, Python 3.12.6, git 2.52, measured with
`python tools/measure_latency.py`: a full decision costs **~380 ms** (dominated
by eight read-only `git` subprocess probes), and the OpenCode/Claude hook end to
end costs **~540 ms** including Python startup. The policy core itself is
0.05 ms per command. SafeGit keeps an internal probe budget of 6 s, well below
the installed 15 s hook timeout, so a slow repository escalates instead of
timing out.

## What does the free version include?

Everything described on this page: the complete policy engine, the CLI, all
four built-in profiles, all adapters, the commit preflight, approvals,
receipts, the audit log and the full test suite. SafeGit is MIT-licensed and
there is no feature that is withheld to be sold separately. Free does not mean
reduced safety.

## What does the €5 Developer Kit add?

Convenience, not protection. The kit is a separate download that contains the
configuration a team usually writes by hand:

* ready-to-use hook configurations for Claude Code and OpenCode (project and
  strict variants),
* four additional policy profiles for common repository shapes,
* a commit-preflight template with a declared staging scope,
* GitHub Actions examples (preflight gate, protected-branch guard),
* install/verify scripts and a compatibility matrix,
* troubleshooting, recovery and update procedures.

It contains no security fix and no enforcement logic that the free version
lacks. See `_owner/DEVELOPER_KIT.md` in the release candidate.

## Security

Do not open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md) for the disclosure process, the supported
versions and the exact commands that produce evidence. The current threat
model, the reviewed bypasses and the residual risks are documented in
[`docs/SECURITY_REPORT.md`](docs/SECURITY_REPORT.md).

## Documentation

| Document | Content |
| --- | --- |
| [`docs/INSTALLATION.md`](docs/INSTALLATION.md) | Install, uninstall, verify |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Policy reference and every rule id |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Modules, data flow, extension points |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, attackers, trust boundaries |
| [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) | What does not work, honestly |
| [`docs/SECURITY_REPORT.md`](docs/SECURITY_REPORT.md) | Findings, fixes, residual risk |
| [`docs/COMPARISON.md`](docs/COMPARISON.md) | How SafeGit differs from other guards |
| [`docs/PROVENANCE.md`](docs/PROVENANCE.md) | Origin, ownership, third-party code |

## License

MIT - see [`LICENSE`](LICENSE). SafeGit is an independent implementation; the
design draws on experience with an internal agent platform, but the code in
this repository was written for this project and contains no third-party code.
