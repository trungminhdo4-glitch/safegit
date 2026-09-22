---
name: Bug report
about: Something behaves incorrectly (a wrong verdict, a crash, a false positive)
labels: bug
---

**What happened**

<!-- The verdict you got, and what you expected. -->

**Reproduction**

```
safegit check --command "<the command>" --profile <profile> --json
```

**Environment**

```
safegit version --json
safegit doctor --json     # redact paths you do not want to share
```

* Repository state when it happened (clean / dirty / mid-merge / ...):
* Policy source (builtin profile or your own file):

**Is this a false positive?**

A guard that blocks legitimate work gets switched off, so false positives are
treated as bugs. Please include why the suggested alternative in the denial
message does not work for your case.

**Security issues**: do not file them here - see SECURITY.md.
