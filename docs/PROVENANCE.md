# Provenance, ownership and licensing

## Origin

SafeGit is an independent implementation written for this project. Its design
draws on experience with the owner's internal agent platform (in particular:
fail-closed policy compilation, a per-invocation mediation contract, receipts
with integrity digests, single-use owner approvals, and a reparse/junction-aware
path guard). No file from that platform was copied, and no history, registry,
state directory or private configuration is referenced at runtime.

This was a deliberate choice over extracting the platform modules directly:
they carry platform-specific dependencies (registry files, goal authority,
capability vocabulary) that would have made a standalone product harder to
audit and impossible to install without the platform.

## Third-party code

**None.** The package has no third-party dependencies and bundles no third-party
source. `src/safegit/*.py` imports only the Python standard library:

```
dataclasses, fnmatch, hashlib, json, os, pathlib, posixpath, re, secrets,
statistics, subprocess, sys, time, typing, argparse, contextlib, io, shutil
```

The OpenCode plugin that `safegit install opencode` writes uses only
`node:child_process` and is generated from a template in `cli.py`.

The test suite uses only `unittest`, `tempfile`, `subprocess`, `json`, `os`,
`pathlib`, `sys`, `shutil` and (in one timing test) `time`.

## Ownership

Copyright (c) 2026 SafeGit contributors. The code was written by the owner or by
agents working on the owner's behalf; the owner holds the rights and releases
the project under the MIT license (see `LICENSE`).

No third-party license notice is therefore required in this repository. If you
add a dependency or copy code in the future, add its notice here and keep the
license compatible with MIT (or the project must be relicensed deliberately).

## Attribution that must be preserved

There is exactly one attribution obligation, and it is ordinary copyright law
rather than a third-party license: the MIT license text and the copyright line
must remain in the repository and in any distributed copy. Do not strip
`LICENSE` from a redistribution, and do not claim authorship of the original.

## Trade names referenced

The documentation names other tools (git, Claude Code, OpenCode, and comparable
guard projects) for the purpose of describing interoperability and comparison.
Those names belong to their owners; naming them does not imply affiliation or
endorsement, and none of their code or artwork is used.

## Data handling

The produced software:

* makes no network requests of any kind,
* has no telemetry, analytics, crash reporting or update check,
* stores no command text by default (the audit log records a SHA-256 of the
  action, the verdict, the rule and the repository state summary),
* stores no file contents,
* writes only to `.safegit/` (or the user profile when there is no repository)
  and to the configuration files an explicit `safegit install ... --write`
  names.

## Verification of this statement

```bash
python tools/selfcheck_no_private_data.py --path .
python -m safegit doctor --json
```

The privacy scanner refuses to print matched values in full, so running it
cannot itself leak what it finds.
