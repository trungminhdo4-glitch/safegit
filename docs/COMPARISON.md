# How SafeGit compares

There are many command guards for coding agents. This page is written to be
useful rather than flattering: it states what SafeGit does differently, and
where another tool is the better choice.

**Method and caveat.** The statements below come from the projects' own public
documentation, READMEs and package registries as of September 2026. SafeGit's
authors did **not** run, benchmark or audit any of these tools, and their
behaviour may have changed since. Verify anything you intend to rely on against
the project itself.

## The landscape (as published by the projects)

| Project | Shape | Notable property |
| --- | --- | --- |
| `gg` (Rust) | git/gh proxy CLI, deny/confirm/allow rules | Sits between the agent and `git`; the agent must be configured to call `gg` |
| `gitfence` (Go) | drop-in `git` wrapper, allowlist of read-only commands | Mutating commands are blocked or delegated to an HTTP "policy gateway" |
| `dcg` (Rust) | hook for many agents | 50+ rule packs, fail-open design, allow-once codes |
| `agent-guard` (Rust/Node) | SDK + Claude Code hook | Focus on outbound effects (push, publish, deploy) with signed audit records |
| `guardrails`, `leash`, `claude-code-command-guard` | Claude Code `PreToolUse` hooks | Curated deny lists, path sandboxing, compound-command splitting |
| `HAL` (Python) | hook with YAML rule packs | Token-level matching, explicitly fail-open |
| `qedra` (Rust) | MCP server gate | Machine-checked (z3) protected-branch sub-policy |
| `gitleash` (Node) | git pre-commit/pre-push hook | Commit-size, test-deletion, CI and secret tripwires |
| `safegit` (Go, unrelated) | concurrent multi-agent git wrapper | Per-invocation index files, CAS ref updates |
| `safegit` (TypeScript, unrelated) | Safe multisig approval for commits | EIP-712 signatures and a GitHub required check |

## What is genuinely different about SafeGit

1. **Structural classification instead of pattern lists.** A command is
   tokenised and each `git` invocation is classified by argv, with prefix
   resolution for long options, so `git commit -m "revert reset --hard"` is not
   a false positive and `git clean --forc` is not a false negative. Most guards
   in the table above match patterns over the command text.
2. **Decisions use repository state.** "Is this branch merged?", "would this
   destroy uncommitted work?", "is this commit already published?", "does this
   path have local edits?" change the verdict. A text matcher cannot answer
   those questions, so it must either allow or block unconditionally.
3. **Four verdicts with an explicit unknown.** `UNKNOWN` is a first-class
   result that escalates in binding mode and is never silently `ALLOW`. Several
   comparable tools advertise fail-open behaviour by design.
4. **Single-use, state-bound owner approvals.** `REQUIRE_OWNER` is not a
   prompt inside the agent loop; it is a fingerprint bound to the rule, the
   exact action, the repository, the branch and HEAD, minted from an
   interactive terminal and consumed once.
5. **Evidence, not just exit codes.** Every decision produces a digest-sealed
   receipt and an audit line that stores a hash of the action instead of its
   text.
6. **One engine, several hosts, no runtime.** The same policy decides for
   Claude Code, OpenCode, a git hook, CI and the CLI, as a stdlib-only Python
   package with no daemon, database or account.

## Where another tool is the better choice

| If you need | Use |
| --- | --- |
| A hard filesystem/OS boundary | A container or a separate OS user. None of these tools is a sandbox; SafeGit is explicit about that |
| Protection for a whole class of destructive shell commands (`rm -rf`, `dd`, database drops) | `dcg`, `HAL` or `claude-code-command-guard`, which ship broad rule packs. SafeGit deliberately guards git and a configured path set |
| A wrapper that intercepts `git` for *every* process, including ones the agent spawns indirectly | `gitfence` or `gg` with a PATH shim. SafeGit only sees calls routed through the host hook |
| Formal verification of a policy | `qedra` (z3-checked git-branch policy) |
| Commit-content tripwires without an agent integration | `gitleash` (git hooks) |
| Safe multisig approval of commits | the unrelated TypeScript `safegit` |
| Concurrent multi-agent git isolation | the unrelated Go `safegit` (per-invocation index, CAS refs) |

## Honest gaps relative to those tools

* **No PATH shim.** `gitfence`/`gg` can catch git calls from scripts the agent
  runs; SafeGit sees the command string, so a script that calls `git` is
  opaque to it (`UNKNOWN` in strict mode, out of scope otherwise).
* **No formal proof.** `qedra`'s machine-checked branch policy is a stronger
  guarantee for that narrow property than SafeGit's rule table.
* **No broad shell-command packs.** SafeGit will not stop `rm -rf src`.
* **No signed (Ed25519) audit chain.** SafeGit receipts are digest-sealed, not
  cryptographically signed.
* **Smaller community.** The projects above have had more eyes on them; that is
  a real advantage and a reason to read their threat models too.

## Why the overlap is not a problem

A guard is only useful if it matches how you actually work. SafeGit is aimed at
the case where the git-specific, state-aware decision is the one that matters -
"would this lose my work?" - and where the answer must be reproducible from a
receipt afterwards, without a service, an account or a network call.
