# Known limitations

This document is deliberately blunt. Every entry is a real, observed property
of the current release candidate. Nothing here is hypothetical, and nothing is
hidden in a footnote of the README.

## Enforcement boundaries

1. **SafeGit is not a sandbox.** It decides about tool calls that a host routes
   through it. An agent with any other execution path - a second agent
   (`opencode --pure`, another CLI), a compiled helper, a background job, an
   editor integration, a direct `git` call from a script the guard never sees -
   is not guarded. There is no OS-level access control, no container, no ACL.
2. **A host that ignores the exit code cannot be helped.** OpenCode's plugin
   throws (fail-closed by construction). Claude Code blocks on exit 2, but a
   hook that *fails to start* or *times out* is a non-blocking error there. The
   internal probe budget (6 s) is far below the installed timeout (15 s), but a
   sufficiently slow machine or a pathological repository can still exceed any
   budget. That failure mode is a deliberate escalation, not an allow.
3. **A live Claude Code end-to-end test was not performed** (no free execution
   path; a live model call costs money or quota). The hook protocol was
   verified against the official documentation and by executing the hook
   itself; the OpenCode integration was verified live with a real agent.
4. **`--pure`, plugin removal and hook removal are off switches.** Deleting the
   hook entry, running OpenCode without plugins, or editing the settings file
   by hand disables the guard. SafeGit blocks *agent* writes to those files,
   not the owner's.
5. **Interlocks are advisory on Linux/macOS.** The verified platform is
   Windows 11. Path comparison is case-insensitive on Windows and
   case-sensitive elsewhere; the store lock uses a create-exclusive lock file
   and works on both, but POSIX was not part of the verification run.

## Classification

6. **Opaque indirection is reported, not understood.** `python run.py`,
   `./deploy.sh`, `make release`, a `pip` script or an MCP tool that performs
   git operations internally is out of scope by default (escalated to
   `UNKNOWN` in the `strict` profile and in hook mode when the tool itself is
   opaque). SafeGit does not read scripts to find out what they do.
7. **Shell semantics are approximated.** The tokeniser handles quoting,
   escaping, chaining, command substitution and the common interpreter
   wrappers. It does not implement a full shell grammar: exotic constructs
   (arrays, heredocs with expansion, process substitution, `eval`, backslash
   line continuation in the middle of a word) can defeat it. Unknown or
   unparseable input becomes `UNKNOWN`; it does not become `ALLOW`.
8. **Aliases and functions.** `alias gs='git status'` or a shell function
   named `git` is not resolved from a command string. A command invoked
   through an alias is not recognised as git.
9. **Git option coverage is finite.** Flag prefixes are resolved against a
   curated option set per subcommand, and an unknown long option on a
   risk-shaping subcommand escalates. A future git release could add an option
   whose effect SafeGit misjudges - the escalation is the safety net, and the
   option tables are in `gitop.py` for a one-line fix.
10. **Path protection is pattern-based.** A path constructed at runtime
    (`p = ".e" + "nv"`) will not match a pattern. Build-time paths are covered;
    computed paths are not.
11. **`Untracked` counts are directory-level.** For performance, probing uses
    `git status --untracked-files=normal`, so an untracked directory counts as
    one entry, not as the number of files inside it. The evidence field says so
    (`UNTRACKED_ENTRIES_ARE_DIRECTORY_LEVEL`).
12. **Remote state is what the local tracking refs say.** `--force-with-lease`
    is denied when the local view says the remote is ahead. Without a `git
    fetch`, the local view can be stale. Git itself refuses an unsafe lease;
    a plain `--force` is denied unconditionally anyway.
13. **Non-git destruction is out of scope.** `rm -rf src`, `shutil.rmtree`,
    disk tools: SafeGit guards git operations and writes to the paths listed in
    `docs/CONFIGURATION.md`. Adding a general "dangerous command" list would be
    a different product and a weaker promise.

## Approvals

14. **Approvals are not cryptographic.** The store is a normal file owned by
    the same OS user; the digest is integrity, not authenticity. Any process
    running as that user can mint an approval if it has a terminal.
15. **The interactive requirement is a real but limited barrier.** The CLI
    refuses to mint without a TTY, and hook mode never mints. An attacker with
    a pseudo-terminal can still mint.
16. **One approval covers one finding.** A command with two owner-gated
    operations needs two approvals (or two separate commands). This is
    deliberate; it does not mean two approvals can be combined automatically.
17. **A hand-edited store is clamped, not rejected.** `uses_remaining` is
    clamped to the policy maximum on consume; other fields are protected by the
    integrity digest, which an attacker can recompute.

## Policy and evidence

18. **Deleting the policy file downgrades to the built-in `default` profile.**
    An agent cannot write the policy (it is a protected path), but an owner or
    a non-hooked process can delete it. `safegit doctor` reports the source,
    and every receipt records `policy_profile` and `policy_digest`, so a
    downgrade is visible in the audit log.
19. **The audit log can be deleted** by the same user. It is a record, not a
    tamper-proof ledger.
20. **`action_digest` is an unsalted SHA-256** of the action text. For short,
    guessable commands it is a confirmation oracle; it is not a secret.
21. **Finding messages contain path names.** A denial message names the file it
    blocked (for example a `.env` path). That is intentional - a denial that
    does not say what it blocked is not actionable - but it means the audit
    line and the hook stderr can reveal a path. Contents, credentials and
    environment values are never included.
22. **`commit_preflight` reads the real index** and is bounded: a staged set
    larger than 400 files is sampled for the large-file check (the limitation
    is recorded), and the preflight never stages, unstages or resets anything.

## Product

23. **No GUI, no dashboard, no server.** Local CLI, receipts and an audit log
    only.
24. **No Windows service or scheduled task.** SafeGit runs when a host calls
    it.
25. **The name needs a clearance decision.** Several unrelated projects are
    called `safegit`; see `_owner/NAME_AVAILABILITY.md` in the release
    candidate. This is a documentation and branding problem, not a technical
    one, but it is unresolved.
