# Examples

Copy what you need. Nothing here is required for SafeGit to work.

| File | Purpose |
| --- | --- |
| `policies/strict-monorepo.json` | Large repository with generated artefacts; adds workspace paths to the protected set |
| `policies/ci-gate.json` | Non-interactive CI: no human, so escalations deny; audit disabled |
| `policies/solo-relaxed.json` | Solo work where the owner prefers approving instead of being blocked |
| `policies/audit-include-command.json` | Debugging setup that stores command text (read the warning first) |
| `claude-settings.json` | A complete `.claude/settings.json` with the SafeGit hook plus permission deny rules as a second layer |
| `github-actions/safegit-preflight.yml` | CI job that blocks a pull request whose staged set fails the preflight |
| `github-actions/safegit-command-audit.yml` | CI job that classifies a list of commands from a file (useful for reviewing agent transcripts) |
| `pre-commit.sample` | A hand-written pre-commit hook calling `safegit preflight --strict` |

## Trying a policy without committing it

```bash
safegit policy validate --policy examples/policies/ci-gate.json
safegit check --command "git push origin main" --policy examples/policies/ci-gate.json
```

## Second layer: host permission rules

`examples/claude-settings.json` shows both layers: SafeGit as a `PreToolUse`
hook (which blocks even under `--dangerously-skip-permissions`) *and* a
`permissions.deny` list. The deny list is a hard rule the model cannot talk its
way around but it is a text-prefix match, so it is brittle; the hook is the
deterministic layer. Use both.
