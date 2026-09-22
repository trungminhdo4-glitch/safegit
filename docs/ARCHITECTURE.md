# Architecture

SafeGit is one package with a linear pipeline. There is no plugin system, no
service, no database and no background process.

## Modules

| Module | Lines | Responsibility |
| --- | --- | --- |
| `shellparse.py` | 429 | Tokenise a command string into segments and argv; unwrap interpreters, wrappers and substitutions; report what it could not resolve |
| `gitop.py` | 1122 | Classify git argv into 41 typed operations with flags, refspecs and ambiguity markers |
| `gitstate.py` | 536 | Read-only, budget-bounded repository state; scrubbed environment; path/ref resolution |
| `policy.py` | 500 | Policy schema, four built-in profiles, fail-closed loading and validation |
| `engine.py` | 1278 | The decision: findings, state-aware refinement, verdict aggregation, approval application |
| `approvals.py` | 335 | Single-use owner approvals with a locked, digest-checked store |
| `adapters.py` | 327 | Translate host tool calls into `CommandAction` / `FileAction` |
| `preflight.py` | 555 | Commit preflight on the real index, without modifying it |
| `receipt.py` | 258 | Digest-sealed receipts and the privacy-preserving audit log |
| `verdicts.py` | 40 | The four verdicts, severity order, exit codes |
| `cli.py` | 1214 | Argument parsing, all commands, installers, self-test |

Total: 6 612 lines of source, 1 689 lines of tests. No dependencies.

## Data flow of one decision

```
tool call (host specific)
   │  adapters.normalize()
   ▼
NormalizedCall ── CommandAction(command, cwd) / FileAction(path, mode, cwd)
   │
   │  shellparse.parse()             gitstate.probe() (once per directory,
   │      segments, argv,                 cached per decision, budget-bounded)
   │      interpreters, subst.
   ▼
ParsedCommand[] ── gitop.resolve_invocations() ── GitInvocation[]
   │                                                 │ gitop.classify_all()
   │                                                 ▼
   │                                            GitOp[] (rule_id, flags,
   │                                                   refspecs, hints)
   │
   │  policy.rule_verdict(rule_id) + state refinement
   ▼
Finding[] ── engine.evaluate() ── most_restrictive() ── verdict
   │                                        │
   │                                        └─ approvals (only if all blocking
   │                                           findings are REQUIRE_OWNER and
   │                                           they share one fingerprint)
   │                                        └─ UNKNOWN escalation
   ▼
Decision ── receipt.build_receipt() ── receipt.append_audit()
```

## Decision rules (aggregation)

1. Each finding carries a verdict from the policy table plus refinements made
   with repository state.
2. Findings combine with `DENY > REQUIRE_OWNER > UNKNOWN > ALLOW`.
3. If the aggregate verdict is `REQUIRE_OWNER`, an approval may clear the
   decision - but only when *every* blocking finding is `REQUIRE_OWNER` and
   they resolve to a single fingerprint. A `DENY`, an `UNKNOWN`, or two
   different owner-gated operations in one command stay blocked.
4. `UNKNOWN` is resolved by the policy key `unknown_git_operations`: an
   explicit allow, an explicit deny, or an escalation (owner when a human is
   available, deny when not, stay `UNKNOWN` in advisory mode).
5. Nothing in the engine mutates the repository. The only subprocess calls are
   read-only `git` invocations and (in preflight) `git cat-file` reads.

## State refinement (what makes it git-aware)

| Operation | Refinement |
| --- | --- |
| `reset --hard`, `clean -f` | Report `work_at_risk` and `data_loss_confirmed` from real counts |
| `checkout`/`restore` of a path | Resolve path-vs-branch from the repository; allow when the target has no local changes |
| forced `checkout -f <branch>` | Evaluates worktree-wide dirtiness, not the branch name as a pathspec |
| `branch -D` | Allow when merged into HEAD, allow when the branch does not exist, require the owner when unmerged (with the unmerged commit count) |
| `commit --amend` | Deny when HEAD is published, require the owner when it is not |
| `worktree remove` | Deny when that worktree has uncommitted files |
| `stash drop`/`clear` | Allow when no stash entry exists |
| `push` | Resolve the target branch (refspec, current branch, upstream), escalate on protected branches, deny `--force-with-lease` when the remote is ahead |
| `add -A`/`.` | Allowed, but reports how many untracked/staged files it would sweep in |

## Policy model

* JSON, versioned (`safegit.policy/1`), validated fail-closed: unknown rule id,
  unknown verdict, wrong type or a missing list field is an error, not a
  weaker policy.
* Profiles: `default`, `strict`, `relaxed`, `ci`. A policy file may name a
  profile; the profile supplies the rule base, and the file's `rules` override
  individual entries. Protective lists (protected branches, protected paths,
  secret paths, CI paths) always fall back to the built-in defaults, so a
  minimal policy can never silently unprotected everything.
* Discovery order: explicit `--policy`, `SAFEGIT_POLICY`, `SAFEGIT_POLICY_DIR`,
  then `<dir>/.safegit/safegit.policy.json` walking up from the working
  directory, then the repository root, then the user profile. A discovered or
  explicit file that is unreadable or invalid is an error.
* The policy file and `.safegit/**` are protected paths and are pinned
  explicitly in the installed hook, so environment variables cannot redirect
  the gate.

## Extension points

| Want to | Do |
| --- | --- |
| Change a verdict | Edit `rules` in your policy file |
| Add branches/paths to protect | `protected_branches`, `protected_paths`, `secret_paths`, `ci_paths` |
| Support a new agent | Add a mapping in `adapters.py` and, if needed, a hook mode in `cli.py`; the engine stays unchanged |
| Tighten CI | `--profile strict` or `--non-interactive`, `preflight --strict` |
| Change the guard's time budget | `--timeout` (per git call) and `gitstate.DEFAULT_BUDGET_SECONDS` (whole probe) |

## Deliberate non-decisions

* **No YAML/TOML policy.** JSON only: one parser, no dependencies, no
  ambiguity about types, and diff-friendly output.
* **No dynamic plugin loading.** A policy must not be able to execute code.
* **No caching across decisions** other than the per-decision state cache: a
  stale cache is a correctness risk in exactly the situation the guard exists
  for.
* **No model in the decision path.** An LLM never decides a safety verdict.

## Performance

Measured on Windows 11, Python 3.12.6, git 2.52.0 with
`python tools/measure_latency.py --iterations 8` (mean of 8-24 samples per
row; rerun it on your own machine rather than trusting these numbers):

| Path | Mean | Max observed |
| --- | --- | --- |
| Policy core only (classify + verdict, no repository access) | 0.05 ms per command | - |
| Full decision, read-only command in a small repo | 386 ms | 926 ms |
| Full decision, state-dependent command | 383 ms | 846 ms |
| Full decision, dangerous command (denied before extra probes) | 321 ms | 354 ms |
| Repository probe alone, small repo | 322 ms | 346 ms |
| Repository probe alone, 1 200 untracked files | 327 ms | 438 ms |
| `safegit hook` end to end (process start, parse, probe, audit write) | 541 ms | 734 ms |
| `safegit check` end to end | 556 ms | 759 ms |

Almost all of the cost is Windows process startup for the read-only `git`
probes (roughly eight `git` invocations at ~40 ms each), not classification.
The policy core is effectively free, which is why the design spends its
complexity budget on classification rather than on micro-optimisation.

The installed hook timeout is 15 s and the internal probe budget is 6 s, so a
slow repository produces an escalation, never a timeout-induced fail-open. The
budget is enforced across the whole probe, not per call, so a pathological
repository cannot multiply the cost by the number of probes.
