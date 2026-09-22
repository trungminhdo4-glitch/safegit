# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (current release candidate) | yes, security fixes |
| anything older | no |

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

1. Use GitHub's **private vulnerability reporting** ("Report a vulnerability"
   on the Security tab of the repository). This keeps the report private and
   creates a tracked advisory draft.
2. If that is unavailable, open a minimal public issue that says only
   "security report - please contact me" and no details.

Please include:

* the SafeGit version (`safegit version --json`) and platform,
* the policy in effect (`safegit policy show`) - redact secrets,
* the exact tool call or command that was mishandled,
* the observed verdict and the verdict you expected,
* whether the action actually executed (this is the important part).

A negative test is worth more than a description: a command that is wrongly
`ALLOW`ed, or a protection that is bypassed, ideally with the output of

```bash
safegit check --command "<your command>" --profile strict --json
```

## What counts as a vulnerability

In scope:

* a destructive git operation that SafeGit reports as `ALLOW`,
* a protected path (see `docs/CONFIGURATION.md`) that an agent can write,
* a way to turn a `DENY`/`REQUIRE_OWNER`/`UNKNOWN` into an `ALLOW` from inside
  the agent's own tool calls,
* a fail-open path: any error, timeout or malformed input that results in
  `ALLOW` where the code claims a blocked result,
* a denial of service that makes the guard exceed the host hook timeout, since
  a timed-out hook does **not** block on some hosts.

Out of scope (documented, by design - see `docs/KNOWN_LIMITATIONS.md`):

* an agent that bypasses the guard by using an execution path the host does not
  route through the hook (a second agent, an unguarded shell, a compiled
  helper),
* anything that requires the same OS user to edit SafeGit's own files while
  SafeGit is not running,
* `--pure`, disabling the plugin, or removing the hook - these are deliberate
  off switches,
* pattern-based path protection being evaded by constructing the path at
  runtime,
* arbitrary non-git filesystem damage.

Reports about the out-of-scope list are still welcome as documentation
improvements.

## Disclosure process

| Step | Target |
| --- | --- |
| Acknowledgement of the report | 3 business days |
| Initial assessment (in scope? reproducible?) | 10 business days |
| Fix or mitigation for a confirmed high/critical issue | 30 days |
| Coordinated public disclosure | after a release with the fix, by agreement |

Please give us the chance to release a fix before publishing details. We will
credit you in `CHANGELOG.md` and in the advisory unless you prefer otherwise.

## What we will do

* Confirm the report with a reproduction first, then fix it.
* Add a regression test to `tests/test_regression_bypasses.py` for every
  confirmed bypass, so the fix cannot silently disappear.
* Publish the finding in `docs/SECURITY_REPORT.md` with its severity and the
  residual risk, whether or not it is fixed.
* Never ship a release artefact without a passing test suite and a recorded
  build receipt.

## Verifying a release yourself

```bash
python -m unittest discover -s tests      # 156+ tests, ~2.5 minutes
python -m safegit selftest                # built-in rule expectations
python -m safegit doctor --json           # environment + policy + wiring
python -m safegit explain "git push --force origin main"
```
