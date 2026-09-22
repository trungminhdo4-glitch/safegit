# Threat model

Scope: SafeGit 0.1.x as a pre-execution gate for AI coding agents on a
developer workstation. This document states what is protected, against whom,
where the trust boundaries are, and - most importantly - what is assumed away.

## Assets

| Asset | Why it matters |
| --- | --- |
| Uncommitted work (staged, unstaged, untracked) | Not in the object database; a `reset --hard`/`clean` destroys it irrecoverably |
| Local commits not yet pushed | Recoverable from the reflog until it expires; a `branch -D` or `rebase` can strand them |
| Remote history on shared branches | Rewriting it breaks every other clone; force-push deletes commits others may have pulled |
| Repository metadata (`.git`) | Its loss ends the repository (reflog, objects, config, hooks) |
| Protected files (policy, agent config, user git config, shell profiles) | Whoever can write them controls the guard itself |
| Secrets (`.env`, keys, credentials) | Exfiltration risk; also accidental commits |
| The evidence trail (receipts, audit log) | Needed to answer "what did the agent do?" after the fact |

## Attacker model

**A1 - The confused agent (primary).** A capable but non-malicious LLM with
shell access: it invents a wrong flag, follows a stale instruction from a
README, believes a clean state that is not clean, or retries a variant of a
blocked command. This is the threat SafeGit is built for and the one it
reliably stops.

**A2 - The injected agent (primary).** Same capabilities, but driven by
untrusted content from a cloned repository (a prompt injection in a file, an
issue body, a dependency README). It actively tries to reach a dangerous
operation, including via `--force`, `-c` overrides, interpreter indirection
and alternative command spellings. SafeGit treats it as an adversary for
*classification* purposes: unknown shapes are `UNKNOWN`, not `ALLOW`.

**A3 - The same-user local attacker (partial).** Code running as the developer
with the ability to write files. It can edit or delete the policy, the plugin,
the hook configuration and SafeGit's own source, and can mint an approval in an
interactive terminal. SafeGit defends the *files* (they are protected paths, so
the agent's own tool calls cannot write them) and detects some tampering
(digests, the shadowing guard), but it cannot defend against an attacker who
writes those files with a tool that is not routed through the hook.

**A4 - Remote/network attacker.** Out of scope. SafeGit makes no network
calls, has no listening socket and no remote state.

**A5 - Malicious host or hostile pull request.** Out of scope; the GitHub side
is addressed by the CI and repository configuration, not by this policy engine.

## Trust boundaries

```
[ untrusted ]                 [ trusted ]
agent model output            policy file (protected path, pinned at install)
repository content  ───────►  git binary (resolved via PATH)
cloned policy file            SafeGit source (installed package)
tool arguments                the human owner's terminal
```

Boundary crossings and how they are handled:

| Crossing | Control |
| --- | --- |
| Model output → command string | Structural parse; unparseable input becomes `UNKNOWN` |
| Command string → git argv | Classification by argv + flag-prefix resolution; unknown long options on risk-shaping subcommands escalate |
| Command string → filesystem targets | Token, quote and interpreter-anchor scanning against protected/secret/CI patterns |
| Repository → policy | A repository-local policy is only read from `.safegit/` or the repository root, is a protected path, and is pinned at install time |
| Environment → policy/approval store | Pinned explicit paths in the installed hook; a broken or missing explicit policy fails closed |
| Host → SafeGit | Exit code 0/2 with the semantics of each host (see below) |
| Human → approval | Interactive terminal, typed confirmation code, single use, bound to rule + action + repo + branch + HEAD |

## Host enforcement semantics (the honest part)

| Host | Blocking mechanism | What happens on a hook failure | Verified |
| --- | --- | --- | --- |
| Claude Code `PreToolUse` | Exit code 2 (stderr is shown to the model) and/or `permissionDecision: deny` | **A hook that cannot run is a non-blocking error: the tool call proceeds.** A hook that *times out* also does not block. | Protocol verified against the official hook documentation and by executing the hook; a live end-to-end Claude run was **not** performed (no free execution path) - see `SECURITY_REPORT.md` |
| OpenCode plugin | `tool.execute.before` throws | The plugin throws on non-zero exit *and* on spawn failure, so it fails closed. `opencode --pure` disables plugins by design. | Verified live: a real agent attempted a destructive command, the plugin blocked it, the repository was unchanged |
| git `pre-commit` | Non-zero exit | A missing executable is a normal hook error; git runs the hook via `sh`, so an absolute interpreter path is used | Mechanically verified by generating and inspecting the hook |
| SafeGit CLI / CI | Exit codes 0/2/3/4 | An internal error is exit 70, which a CI gate must treat as a failure | Covered by tests |

Consequence: **only the OpenCode plugin is fail-closed by construction.** On
Claude Code, a *timeout* is the dangerous case, which is why SafeGit enforces a
global probe budget (default 6 s) far below the installed 15 s hook timeout and
why the timeout value is configurable at install time.

## Threats considered and controls

| # | Threat | Control | Residual risk |
| --- | --- | --- | --- |
| T1 | `reset --hard` / `clean -f` / `checkout -f` / `restore` discards work | Denied; the number of files at risk is reported. Forced checkout of a branch evaluates worktree-wide dirtiness | Path-scoped checks can only see what git reports |
| T2 | Force-push rewrites shared history | `--force`/`-f`/`+refspec` denied; `--force-with-lease` requires the owner and is denied when the local tracking ref says the remote is ahead | A stale tracking ref limits what is known; `git` itself refuses an unsafe lease |
| T3 | Push/delete to a protected branch | Escalated to the owner; a delete of a protected branch is denied | Protected branch list is user-configured |
| T4 | Unmerged commits destroyed by `branch -D` | Allowed only when the branch is provably merged into HEAD | `rev-list` result reflects the local view |
| T5 | Amend/rebase rewrites published history | Amend of a published HEAD is denied; rebase requires the owner | Remote detection needs a remote-tracking ref |
| T6 | Foreign/untracked work staged and committed | `add -A`/`.` is reported; the commit preflight lists every staged path and can be given a declared scope | Preflight reports; it does not decide intent |
| T7 | Secrets committed | Secret path patterns block writes and preflight fails on staged secret paths | Pattern-based, `.env.example` style allowlist |
| T8 | Guard self-modification (policy, plugin, settings) | Protected paths (`.safegit`, `safegit.policy.json`, `.claude/settings*`, `.opencode`, `.git`, `~/.gitconfig`, shell profiles) cannot be written via hooked tools; the policy is pinned at install time | Any write path outside the hook is unguarded |
| T9 | Hook bypass flags | `--no-verify`, `-n` (commit), `--no-gpg-sign`, `HUSKY=0`, `-c core.hooksPath`, `--config-env` are classified as bypass and denied for hook-running subcommands | Not applicable to read-only subcommands (deliberate) |
| T10 | Repository boundary confusion (`--git-dir`, `--work-tree`, `-C`) | `--git-dir`/`--work-tree` are escalated; `-C` is honoured for state resolution | An operation on a *different* repository via `-C` is judged against that repository's state |
| T11 | Unknown/obfuscated command shape | `UNKNOWN`; in binding mode it escalates to the owner, and in a non-interactive context to `DENY` | Opaque wrappers (a script, a compiled helper) are reported, not interpreted |
| T12 | Path construction at runtime (`".e" + "nv"`) | Interpreter bodies are scanned for literal anchors of guarded paths; a write verb or interpreter makes the scan active | A fully computed path with no literal fragment is missed |
| T13 | Denial of service against the gate | Bounded parse (segments, nesting, length), bounded token/pattern counts, a global probe budget, no unbounded glob expansion | A very large repository can still exhaust the budget; the result is an escalation, not an allow |
| T14 | Forged approval | Store lock, integrity digest, use clamp, single use, binding to repo + branch + HEAD, interactive requirement | A same-user attacker with a terminal can mint one; documented |
| T15 | Evidence loss | Receipts are digest-sealed; audit lines are bounded by construction (never truncated JSON); a failed audit write is a limitation, not a crash | Audit file deletion by the same user cannot be prevented |
| T16 | SafeGit executing attacker input | SafeGit never runs the action it evaluates; every subprocess call is an argv list without a shell; only read-only git commands are executed | - |

## Explicit non-goals

* OS-level access control. SafeGit is not a sandbox, not an ACL, not seccomp,
  not a container. Use a container or a separate OS user when you need an
  isolation boundary.
* Preventing *all* filesystem damage. `SafeGit` guards git operations and the
  configured protected/secret paths; general `rm -rf` policy is another tool's
  job and would be a false sense of safety here.
* Governing the agent's own loop (budgets, retries, cost). Different failure
  mode, different tool.
* Judging intent. SafeGit decides about *operations*; it never guesses why.

## Assumptions

1. The agent's shell and file tools are routed through the host hook. If the
   agent has a second execution path, the gate does not see it.
2. `git` on `PATH` is the real git and is not replaced between installation and
   the action.
3. The installed package is not writable by the agent (protected paths cover
   its configuration; the interpreters used are outside the repository).
4. The human owner reads a denial message and decides; approvals are given
   knowingly.
5. The system clock is roughly correct (approval expiry).
