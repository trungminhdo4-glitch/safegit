# Contributing

Thanks for considering a contribution. SafeGit is deliberately small: the
safety decision must stay auditable, so most contributions should make the
existing machinery more correct, not add new layers.

## Ground rules

* **No third-party dependencies.** Standard library only. A new dependency
  needs a written justification that explains why the standard library cannot
  do the job.
* **A new abstraction needs a concrete problem it solves now.**
* **Every security-relevant change needs a test that fails on the old code.**
  Add it to `tests/test_regression_bypasses.py` if it closes a bypass.
* **No comments that restate the code.** Docstrings for public functions are
  welcome; a comment must explain a decision, not repeat an expression.
* **Fail closed.** If something cannot be classified, the result is `UNKNOWN`,
  never a silent `ALLOW`.

## Development setup

```bash
git clone <your fork>
cd safegit
python -m unittest discover -s tests          # full suite (~2.5 min)
python -m safegit --help
```

There is nothing to install and no build step.

## Where to change what

| Task | File |
| --- | --- |
| A new git rule | `src/safegit/gitop.py` (classification) + `src/safegit/policy.py` (verdicts per profile) |
| A new state-aware refinement | `src/safegit/engine.py` |
| A new repository fact | `src/safegit/gitstate.py` (read-only, bounded) |
| A new host integration | `src/safegit/adapters.py` + `src/safegit/cli.py` |
| Commit checks | `src/safegit/preflight.py` |
| Policy defaults | `src/safegit/policy.py` |

## Pull request checklist

1. `python -m py_compile src/safegit/*.py` passes.
2. `python -m unittest discover -s tests` is green.
3. `python -m safegit selftest` is green.
4. New rule ids are added to `RULE_IDS` and have a default verdict in every
   profile (`default`, `strict`, `relaxed`, `ci`).
5. The README, `docs/CONFIGURATION.md` and `docs/KNOWN_LIMITATIONS.md` are
   updated if behaviour visible to users changed.
6. `CHANGELOG.md` has an entry under `## Unreleased`.
7. No command text, file content, credential or personal path appears in a log
   line, receipt, error message or test fixture.

## Reporting a rule that blocks a legitimate command

False positives are treated as bugs, because a guard that is switched off
protects nothing. Include:

* the command, the policy profile, and the repository state that makes it
  legitimate,
* the verdict you expect,
* why the existing "alternative" in the denial message does not work for you.

## Testing philosophy

* Prefer a test that proves the *effect* (the file is untouched, the branch
  still exists, the target survives) over a test that only asserts a verdict.
* Use throwaway repositories under the system temp directory. Never run a
  destructive command against a real repository.
* Timing-sensitive behaviour (the probe budget) gets a generous bound, not a
  tight one, so the test does not become flaky on a slow machine.
