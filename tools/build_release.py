"""Complete the Developer Kit and build the release artefacts.

Everything here is offline and deterministic:

* it writes the remaining Developer Kit files (the ones that are configuration
  rather than documentation),
* it builds a pure-Python wheel without a build backend (a wheel is a zip),
* it builds a source archive of the free project,
* it zips the Developer Kit,
* it writes SHA256SUMS and a build receipt with file counts and sizes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import shutil
import sys
import time
import zipfile

VERSION = "0.1.0"
DIST_NAME = "safegit"
WHEEL_TAG = "py3-none-any"

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

DEVKIT_FILES: dict[str, str] = {
    "workflows/claude/settings.project.json": """{
  "permissions": {
    "deny": [
      "Bash(git push --force:*)",
      "Bash(git reset --hard:*)",
      "Edit(./.env)",
      "Edit(./.git/**)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Write|Edit|NotebookEdit|MultiEdit|Task|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "\\"/absolute/path/to/python\\" -P -m safegit hook claude --policy .safegit/safegit.policy.json --approval-store /absolute/path/to/.safegit/approvals.json",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
""",
    "workflows/opencode/plugin-strict.js.txt": """// SafeGit plugin variant for a project that runs several agents in parallel.
// Difference from the generated default: a spawn failure and a non-zero exit
// are both turned into a thrown error, and the pinned policy is the strict
// one, so an UNKNOWN operation is denied rather than escalated.
//
// Rename to .opencode/plugin/safegit.js after reviewing the paths and the
// policy name.
import { spawnSync } from "node:child_process"

const SAFEGIT_ARGV = ["C:\\\\absolute\\\\path\\\\to\\\\python.exe", "-P", "-m", "safegit"]
const PINNED = ["--policy", ".safegit/safegit.policy.json", "--approval-store",
  "C:\\\\absolute\\\\path\\\\to\\\\.safegit\\\\approvals.json"]

export const SafegitPlugin = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    const payload = JSON.stringify({
      tool: input.tool, sessionID: input.sessionID, callID: input.callID,
      cwd: directory, args: output.args ?? {},
    })
    const result = spawnSync(
      SAFEGIT_ARGV[0],
      [...SAFEGIT_ARGV.slice(1), "hook", "opencode", "--non-interactive", ...PINNED],
      { input: payload, encoding: "utf8", timeout: 20000 },
    )
    if (result.error) {
      throw new Error(`SafeGit did not run (${result.error.message}) - refusing the call`)
    }
    if (result.status === 0) return
    throw new Error((result.stderr || "").trim() || `SafeGit blocked this call (exit ${result.status})`)
  },
})
""",
    "workflows/opencode/NOTES.md": """# OpenCode notes

Verified against OpenCode 1.18.31 on Windows 11.

## What is verified

* Plugins in `.opencode/plugin/` **and** `.opencode/plugins/` are loaded
  (measured by placing a probe plugin in each directory and observing that both
  ran).
* `tool.execute.before` is called before the tool runs, receives
  `{ tool, sessionID, callID }` plus a mutable `{ args }`, and **throwing
  prevents the tool call**.
* A live run with a free model proved end to end that a destructive command was
  blocked, that the model reported the denial, and that the repository was
  unchanged.

## Failure modes to know

| Situation | Behaviour | Why |
| --- | --- | --- |
| Plugin throws (SafeGit blocked) | Tool call refused | Intended |
| `safegit` cannot be spawned | Plugin throws | Fail-closed by construction |
| `safegit` exceeds the 20 s plugin timeout | Plugin throws | The plugin's own timeout; keep `safegit` fast (see the probe budget) |
| `opencode --pure` | No plugin, no protection | Documented off switch |
| Plugin file deleted | No plugin, no protection | `safegit doctor` reports the plugin's presence |
| Tool not in the tool list SafeGit knows | Out of scope / `UNKNOWN` | See `docs/KNOWN_LIMITATIONS.md` of the free project |

## Practical advice for multi-agent setups

1. Pin the policy in the plugin (this variant does) so `SAFEGIT_POLICY` cannot
   redirect the gate.
2. Use `policies/agent-farm.json`: `git.commit.plain` requires the owner and
   unclassified operations deny, which is what you want when three agents share
   one repository.
3. Give each agent its own worktree (`examples/multi-agent/WORKTREE_WORKFLOW.md`)
   and keep the shared branch read-only for the agents.
""",
    "commit-preflight/pre-commit.sh": """#!/bin/sh
# Declared-scope preflight. Install as .git/hooks/pre-commit (chmod +x).
# The scope file lists one glob per line; see declared-scope.md.
set -eu

REPO="$(git rev-parse --show-toplevel)"
SCOPE_FILE="${SAFEGIT_SCOPE_FILE:-.safegit/scope/current.txt}"

if ! command -v safegit >/dev/null 2>&1; then
    echo "safegit: not installed - refusing to commit (fail-closed)" >&2
    exit 1
fi

args="--repo $REPO --strict"
if [ -f "$SCOPE_FILE" ]; then
    while IFS= read -r glob; do
        case "$glob" in ''|'#'*) continue;; esac
        args="$args --expect $glob"
    done < "$SCOPE_FILE"
fi

# shellcheck disable=SC2086
exec safegit preflight $args
""",
    "commit-preflight/pre-commit.cmd": """@echo off
REM Declared-scope preflight for Windows. Copy to .git\\hooks\\pre-commit.cmd
REM and add a one-line .git\\hooks\\pre-commit shim if your git uses sh:
REM   #!/bin/sh
REM   exec cmd //c "$(git rev-parse --show-toplevel)/.git/hooks/pre-commit.cmd"
setlocal enabledelayedexpansion

for /f "delims=" %%i in ('git rev-parse --show-toplevel') do set "REPO=%%i"
set "SCOPE=%REPO%\\.safegit\\scope\\current.txt"

where safegit >nul 2>nul
if errorlevel 1 (
  echo safegit: not installed - refusing to commit ^(fail-closed^) 1>&2
  exit /b 1
)

set "ARGS=--repo "%REPO%" --strict"
if exist "%SCOPE%" (
  for /f "usebackq tokens=*" %%g in ("%SCOPE%") do (
    set "LINE=%%g"
    if not "!LINE!"=="" if not "!LINE:~0,1!"=="#" set "ARGS=!ARGS! --expect "!LINE!""
  )
)

safegit preflight %ARGS%
exit /b %ERRORLEVEL%
""",
    "install/install.ps1": """<#
.SYNOPSIS
  Install the SafeGit Developer Kit into a repository.
.DESCRIPTION
  Copies a policy profile, installs the agent integrations and prints a
  verification command. Dry run by default: pass -Apply to write anything.
.EXAMPLE
  .\\install.ps1 -Repo C:\\work\\myrepo -Policy agent-farm -Apply
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Repo,
  [ValidateSet('agent-farm', 'minimal-lockdown', 'monorepo-generated', 'regulated-ci')]
  [string]$Policy = 'agent-farm',
  [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$kit = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path -LiteralPath (Join-Path $Repo '.git'))) {
  throw "not a git repository: $Repo"
}
if (-not (Get-Command safegit -ErrorAction SilentlyContinue)) {
  throw "safegit is not on PATH - install it first: pipx install safegit"
}

$policySource = Join-Path $kit "policies\\$Policy.json"
$policyTarget = Join-Path $Repo '.safegit\\safegit.policy.json'

Write-Host "policy:  $Policy"
Write-Host "source:  $policySource"
Write-Host "target:  $policyTarget"

if (-not $Apply) {
  Write-Host ""
  Write-Host "dry run - nothing was written. Planned actions:"
  Write-Host "  1. copy the policy to $policyTarget"
  Write-Host "  2. safegit install claude   --dir $Repo --write"
  Write-Host "  3. safegit install opencode --dir $Repo --write"
  Write-Host "  4. safegit doctor --json"
  Write-Host ""
  Write-Host "re-run with -Apply to perform them."
  return
}

New-Item -ItemType Directory -Path (Split-Path -Parent $policyTarget) -Force | Out-Null
Copy-Item -LiteralPath $policySource -Destination $policyTarget -Force
Write-Host "copied policy"

Push-Location $Repo
try {
  safegit policy validate
  safegit install claude   --dir $Repo --write
  safegit install opencode --dir $Repo --write
  safegit doctor --json
}
finally { Pop-Location }

Write-Host ""
Write-Host "verify enforcement with:"
Write-Host "  powershell -File (Join-Path $PSScriptRoot 'verify.ps1') -Repo $Repo"
""",
    "install/verify.ps1": """<#
.SYNOPSIS
  Prove that SafeGit blocks a destructive call in this repository.
.DESCRIPTION
  Runs the hook directly with synthetic events (no model call, no cost) and
  checks the exit codes. Read-only with respect to the repository.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Repo)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $Repo).Path
$failures = 0

function Test-Hook {
  param([string]$Name, [string]$Command, [int]$Expected)
  $event = @{
    tool_name  = 'Bash'
    tool_input = @{ command = $Command }
    cwd        = $repo
  } | ConvertTo-Json -Compress -Depth 5

  $stderrFile = [System.IO.Path]::GetTempFileName()
  try {
    $event | & safegit hook claude 2>$stderrFile | Out-Null
    $code = $LASTEXITCODE
    $reason = (Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue)
  }
  finally { Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue }

  if ($code -eq $Expected) {
    Write-Host ("  PASS  {0,-28} exit={1}" -f $Name, $code)
  } else {
    Write-Host ("  FAIL  {0,-28} exit={1} (expected {2}) {3}" -f $Name, $code, $Expected, $reason) -ForegroundColor Red
    $script:failures++
  }
}

Write-Host "SafeGit verification in $repo"
Test-Hook -Name 'read-only command' -Command 'git status' -Expected 0
Test-Hook -Name 'hard reset' -Command ("git reset --" + "hard") -Expected 2
Test-Hook -Name 'force push' -Command ("git push --" + "force origin main") -Expected 2
Test-Hook -Name 'clean force' -Command 'git clean -fdx' -Expected 2
Test-Hook -Name 'write to .git/config' -Command 'Set-Content .git/config -Value x' -Expected 2

Write-Host ""
if ($failures -eq 0) {
  Write-Host "all checks passed" -ForegroundColor Green
  exit 0
}
Write-Host "$failures check(s) failed" -ForegroundColor Red
exit 1
""",
    "install/verify.sh": """#!/bin/sh
# Prove that SafeGit blocks a destructive call in this repository.
# Runs the hook directly with synthetic events: no model call, no cost,
# read-only with respect to the repository.
set -eu

REPO="${1:-.}"
REPO="$(cd "$REPO" && pwd)"
failures=0

check() {
    name="$1"; command="$2"; expected="$3"
    payload=$(printf '{"tool_name":"Bash","tool_input":{"command":"%s"},"cwd":"%s"}' "$command" "$REPO")
    printf '%s' "$payload" | safegit hook claude >/dev/null 2>/tmp/safegit-verify.err || true
    code=$?
    if [ "$code" -eq "$expected" ]; then
        printf '  PASS  %-28s exit=%s\\n' "$name" "$code"
    else
        printf '  FAIL  %-28s exit=%s (expected %s) %s\\n' "$name" "$code" "$expected" "$(cat /tmp/safegit-verify.err 2>/dev/null || true)"
        failures=$((failures + 1))
    fi
    rm -f /tmp/safegit-verify.err
}

echo "SafeGit verification in $REPO"
check 'read-only command' 'git status' 0
check 'hard reset' "git reset --hard" 2
check 'force push' "git push --force origin main" 2
check 'clean force' 'git clean -fdx' 2

echo ""
if [ "$failures" -eq 0 ]; then
    echo "all checks passed"
    exit 0
fi
echo "$failures check(s) failed"
exit 1
""",
    "examples/multi-agent/WORKTREE_WORKFLOW.md": """# Multi-agent workflow with one worktree per agent

The problem: three agents in one checkout overwrite each other's uncommitted
work, and a single destructive command can destroy all of it.

The shape that works:

```
main repository (protected)        D:\\work\\myrepo
  worktrees (one per agent)        D:\\work\\myrepo.agent-a
                                   D:\\work\\myrepo.agent-b
                                   D:\\work\\myrepo.agent-c
```

## Setup

```bash
cd /d/work/myrepo                     # the shared repository
git worktree add ../myrepo.agent-a -b agent/a
git worktree add ../myrepo.agent-b -b agent/b
git worktree add ../myrepo.agent-c -b agent/c
```

Per worktree, install the agent integration **inside that worktree** so the
pinned policy path is the worktree's own:

```bash
cd ../myrepo.agent-a
cp /path/to/devkit/policies/agent-farm.json .safegit/safegit.policy.json
safegit policy validate
safegit install claude --dir . --write
safegit install opencode --dir . --write
```

## Rules that make this safe

1. **The shared branch is read-only for agents.** `agent-farm.json` sets
   `protect_default_branch_commits: true`, so a plain commit on `main` requires
   the owner even inside a worktree.
2. **`git worktree remove` is denied** in that profile. Worktrees hold
   uncommitted work by definition; removing one is a human decision.
3. **`git clean -fdx` is denied** everywhere: in a worktree it is the fastest
   way to lose a whole agent's work.
4. **Each agent commits on its own branch.** Integration happens by the owner
   merging branches, never by an agent force-pushing a shared branch.
5. **No two agents share a worktree.** A SafeGit guard cannot arbitrate two
   writers in one directory; that is a workflow invariant, not a policy.

## Integrating the results

```bash
cd /d/work/myrepo
git fetch . agent/a:agent/a            # branches already exist locally
git log --oneline main..agent/a
git merge --no-ff agent/a              # by the owner, not by an agent
```

Then remove a worktree once its branch is merged:

```bash
git worktree remove ../myrepo.agent-a   # requires the owner (DENY for agents)
git branch -d agent/a                   # -d refuses unmerged work by design
```

## What SafeGit does not do here

It does not allocate worktrees, schedule agents or merge branches. It makes the
destructive steps of this workflow impossible for the agents, and leaves the
coordination to you (or to `git worktree` itself).
""",
    "UPDATING.md": """# Updating SafeGit and this kit

## Update the free package

```bash
pipx upgrade safegit          # or: python -m pip install --upgrade safegit
safegit version --json
safegit selftest
safegit doctor --json
```

After an upgrade, re-run the installers once so the pinned interpreter path and
policy path match the new environment:

```bash
safegit install claude   --dir . --write
safegit install opencode --dir . --write
```

The installers merge and are idempotent, so this is safe to repeat.

## Update this kit

1. Keep your local edits in a place the kit does not own: your policy is
   `.safegit/safegit.policy.json` (not `policies/*.json`), your scope files are
   under `.safegit/scope/`, and your hooks live in the repository.
2. Unpack the new kit over the old directory, or into a fresh directory and
   diff it against the old one.
3. Re-apply any file you had modified. Because the kit's profiles are inputs
   rather than outputs, most updates do not require any change on your side.

Recommended: put the kit under version control in your own repository (after
checking its license terms) so updates are a normal merge.

## Compatibility

`VERSION.json` states the SafeGit range the kit was built for
(`requires_safegit`). If your SafeGit version is outside that range, start with
`policies/minimal-lockdown.json` and `safegit policy validate` before copying
anything else: a policy that references a rule id your version does not know is
rejected, which is the intended behaviour.

## If an update changes a verdict

`CHANGELOG.md` of the free project lists behaviour changes. To see what a new
version would decide without changing anything:

```bash
safegit check --command "<the command>" --policy policies/agent-farm.json --json
```

Then compare `findings[].verdict` with `safegit policy show` on your installed
policy.
""",
    "COMPATIBILITY.md": """# Compatibility

No claim here is aspirational: an entry is VERIFIED only if it was executed in
the release build and the evidence is in the release receipt.

| Component | Version | Status | Evidence |
| --- | --- | --- | --- |
| Windows 11 | 10.0.26100 | VERIFIED | Full test suite, latency measurement, live agent run |
| Python | 3.12.6 | VERIFIED | Full test suite |
| Python | 3.9 - 3.11 | EXPECTED, not executed in this build | Code targets 3.9 syntax; CI matrix covers 3.9/3.12 but was not run for this receipt |
| git | 2.52.0.windows.1 | VERIFIED | All state-aware tests |
| git | 2.30+ | EXPECTED | The probes use long-stable plumbing (`rev-parse`, `status --porcelain=v1 -z`, `ls-files`, `cat-file --batch-check`, `show-ref`, `rev-list`) |
| Claude Code | 2.1.278 | PARTIAL | Hook contract verified against official documentation and by executing the hook; no live model session was run |
| OpenCode | 1.18.31 | VERIFIED | Plugin loading measured, live agent run blocked a destructive command |
| Linux / macOS | - | NOT VERIFIED | Install steps documented; no execution in this build. Path matching is case-sensitive there |
| Other agents (Codex, Cursor, ...) | - | NOT SUPPORTED | `safegit check`/`preflight` can be called from any host that can run a command, but no adapter exists |

## What "PARTIAL" means for Claude Code

The blocking mechanism (`exit 2` from a `PreToolUse` command hook) is documented
by the vendor and the hook binary was exercised directly with synthetic events.
What was **not** run is a live session in which a model attempts a destructive
command and is stopped. Two consequences to keep in mind:

* a hook that fails to start or times out is a non-blocking error in Claude
  Code, so the internal probe budget (6 s) is deliberately far below the
  installed hook timeout (15 s);
* if you change the matcher or the timeout, re-verify with
  `install/verify.ps1`.

## Policy-version compatibility

Policies written for `safegit.policy/1` validate against any 0.1.x release.
A rule id that does not exist in your installed version makes
`safegit policy validate` fail, which is intended: an unknown rule must never
be silently ignored.
""",
}


def write_devkit_files(devkit: pathlib.Path) -> list[str]:
    written: list[str] = []
    for relative, content in sorted(DEVKIT_FILES.items()):
        target = devkit / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        written.append(relative)
    return written


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_wheel(out_dir: pathlib.Path) -> pathlib.Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = out_dir / ("%s-%s-%s.whl" % (DIST_NAME, VERSION, WHEEL_TAG))
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    metadata = "\n".join(
        [
            "Metadata-Version: 2.1",
            "Name: %s" % DIST_NAME,
            "Version: %s" % VERSION,
            "Summary: Git safety and repository protection for AI coding agents",
            "License: MIT",
            "Requires-Python: >=3.9",
            "Description-Content-Type: text/markdown",
            "",
            readme,
            "",
        ]
    )
    wheel_meta = "\n".join(
        [
            "Wheel-Version: 1.0",
            "Generator: safegit-build-release",
            "Root-Is-Purelib: true",
            "Tag: %s" % WHEEL_TAG,
            "",
        ]
    )
    entry_points = "[console_scripts]\nsafegit = safegit.cli:main\n"
    license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")

    entries: list[tuple[str, bytes]] = []
    for source in sorted((REPO_ROOT / "src" / "safegit").glob("*.py")):
        entries.append(("safegit/%s" % source.name, source.read_bytes()))
    typed = REPO_ROOT / "src" / "safegit" / "py.typed"
    if typed.is_file():
        entries.append(("safegit/py.typed", typed.read_bytes()))
    dist_info = "%s-%s.dist-info" % (DIST_NAME, VERSION)
    entries.append(("%s/METADATA" % dist_info, metadata.encode("utf-8")))
    entries.append(("%s/WHEEL" % dist_info, wheel_meta.encode("utf-8")))
    entries.append(("%s/entry_points.txt" % dist_info, entry_points.encode("utf-8")))
    entries.append(("%s/licenses/LICENSE" % dist_info, license_text.encode("utf-8")))

    record_lines = ["%s,%s,%d" % (name, _record_hash(data), len(data)) for name, data in entries]
    record_lines.append("%s/RECORD,," % dist_info)
    entries.append(("%s/RECORD" % dist_info, ("\n".join(record_lines) + "\n").encode("utf-8")))

    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return wheel_path


def build_source_archive(out_dir: pathlib.Path) -> pathlib.Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / ("%s-%s-source.zip" % (DIST_NAME, VERSION))
    include = [
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "pyproject.toml",
        ".gitignore",
    ]
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in include:
            path = REPO_ROOT / name
            if path.is_file():
                archive.write(path, "%s-%s/%s" % (DIST_NAME, VERSION, name))
        for directory, prefix in (
            (REPO_ROOT / "src", "src"),
            (REPO_ROOT / "tests", "tests"),
            (REPO_ROOT / "docs", "docs"),
            (REPO_ROOT / "examples", "examples"),
            (REPO_ROOT / "tools", "tools"),
        ):
            for path in sorted(directory.rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts:
                    archive.write(
                        path,
                        "%s-%s/%s/%s"
                        % (DIST_NAME, VERSION, prefix, path.relative_to(directory).as_posix()),
                    )
        github = REPO_ROOT / ".github"
        for path in sorted(github.rglob("*")):
            if path.is_file():
                archive.write(
                    path,
                    "%s-%s/.github/%s" % (DIST_NAME, VERSION, path.relative_to(github).as_posix()),
                )
    return target


def build_devkit_zip(devkit: pathlib.Path, out_dir: pathlib.Path) -> pathlib.Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / ("safegit-developer-kit-%s.zip" % VERSION)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(devkit.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                info = zipfile.ZipInfo(
                    "safegit-developer-kit-%s/%s" % (VERSION, path.relative_to(devkit).as_posix()),
                    date_time=(2026, 1, 1, 0, 0, 0),
                )
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, path.read_bytes())
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the release artefacts")
    parser.add_argument("--devkit", default=str(REPO_ROOT.parent / "safegit-devkit"))
    parser.add_argument("--out", default=str(REPO_ROOT / "build"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    devkit = pathlib.Path(args.devkit)
    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    written = write_devkit_files(devkit)
    wheel = build_wheel(out_dir)
    source = build_source_archive(out_dir)
    kit_zip = build_devkit_zip(devkit, out_dir)

    artifacts = [wheel, source, kit_zip]
    sums = out_dir / "SHA256SUMS"
    sum_lines = ["%s  %s" % (sha256_file(path), path.name) for path in artifacts]
    sums.write_text("\n".join(sum_lines) + "\n", encoding="ascii")

    receipt = {
        "schema": "safegit.release-build/1",
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": VERSION,
        "python": "%d.%d.%d" % sys.version_info[:3],
        "platform": sys.platform,
        "devkit_files_written": written,
        "devkit_file_count": sum(1 for path in devkit.rglob("*") if path.is_file()),
        "artifacts": [
            {
                "name": path.name,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "entries": (
                    len(zipfile.ZipFile(path).namelist())
                    if path.suffix == ".whl" or path.suffix == ".zip"
                    else None
                ),
            }
            for path in artifacts
        ],
    }
    receipt_path = out_dir / "build-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json:
        sys.stdout.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write("built %d artefacts in %s\n" % (len(artifacts), out_dir.resolve()))
        for entry in receipt["artifacts"]:
            sys.stdout.write(
                "  %-44s %8d bytes  %s\n" % (entry["name"], entry["bytes"], entry["sha256"][:16])
            )
        sys.stdout.write("  receipt: %s\n" % receipt_path.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
