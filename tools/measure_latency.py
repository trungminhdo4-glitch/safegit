"""Measure SafeGit latency and probe cost on this machine.

The numbers are printed and (optionally) written as JSON so a release receipt
can cite them. Nothing here is a benchmark claim about other machines.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import pathlib
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from safegit import cli, engine, gitop, gitstate, policy as policy_module, shellparse  # noqa: E402

COMMANDS: tuple[str, ...] = (
    "git status",
    "git log --oneline -5",
    "git diff --cached --check",
    "git commit -m 'message'",
    "git push origin feature/x",
    "git reset --hard",
    "git clean -fdx",
    "git push --force-with-lease origin main",
    "git checkout -f main",
    "git branch -D feature",
    "echo hello && git status",
    'bash -c "git reset --hard"',
    'python -c "print(1)"',
)


def git(repo: str, *args: str) -> None:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "SafeGit Measure",
            "GIT_AUTHOR_EMAIL": "measure@example.invalid",
            "GIT_COMMITTER_NAME": "SafeGit Measure",
            "GIT_COMMITTER_EMAIL": "measure@example.invalid",
        }
    )
    subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        env=env,
        timeout=60,
        check=False,
    )


def make_repo(root: str, untracked: int = 0) -> str:
    repo = os.path.join(root, "repo")
    os.makedirs(repo, exist_ok=True)
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "measure@example.invalid")
    git(repo, "config", "user.name", "SafeGit Measure")
    pathlib.Path(repo, "app.py").write_text("print('hello')\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "initial")
    if untracked:
        for index in range(untracked):
            directory = pathlib.Path(repo) / "node_modules" / ("pkg%d" % index)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "index.js").write_text("x\n", encoding="utf-8")
    return repo


def measure_policy_core(iterations: int) -> dict[str, float]:
    policy = policy_module.from_dict(
        policy_module.default_policy_dict(), source_path="<measure>"
    )
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        for command in COMMANDS:
            parsed = shellparse.parse(command)
            for invocation in gitop.resolve_invocations(parsed):
                for op in gitop.classify_all(invocation):
                    policy.rule_verdict(op.rule_id)
        samples.append((time.perf_counter() - started) * 1000.0 / len(COMMANDS))
    return {"mean_ms_per_command": round(statistics.mean(samples), 4)}


def measure_decision(
    repo: str, iterations: int, *, profile: str, commands: tuple[str, ...]
) -> dict[str, float]:
    ctx = engine.EngineContext(
        cwd=repo,
        policy=policy_module.from_dict(
            policy_module.default_policy_dict(profile), source_path="<measure>"
        ),
        timeout=10.0,
    )
    samples: list[float] = []
    for _ in range(iterations):
        for command in commands:
            ctx.state_cache.clear()
            started = time.perf_counter()
            engine.evaluate("Bash", {"command": command, "cwd": repo}, ctx=ctx)
            samples.append((time.perf_counter() - started) * 1000.0)
    return {
        "mean_ms": round(statistics.mean(samples), 2),
        "p95_ms": round(sorted(samples)[max(int(len(samples) * 0.95) - 1, 0)], 2),
        "max_ms": round(max(samples), 2),
        "samples": len(samples),
    }


def measure_probe(repo: str, iterations: int) -> dict[str, float]:
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        gitstate.probe(repo, timeout=10.0)
        samples.append((time.perf_counter() - started) * 1000.0)
    return {
        "mean_ms": round(statistics.mean(samples), 2),
        "max_ms": round(max(samples), 2),
    }


def measure_hook(repo: str, iterations: int) -> dict[str, float]:
    payload = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "git status", "cwd": repo},
            "cwd": repo,
        }
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[1] / "src")
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        completed = subprocess.run(
            [
                sys.executable,
                "-P",
                "-m",
                "safegit",
                "hook",
                "claude",
                "--profile",
                "default",
            ],
            input=payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=repo,
            timeout=60,
            check=False,
        )
        samples.append((time.perf_counter() - started) * 1000.0)
        if completed.returncode != 0:
            raise AssertionError(
                "hook returned %d: %s" % (completed.returncode, completed.stderr[:200])
            )
    return {
        "mean_ms": round(statistics.mean(samples), 2),
        "max_ms": round(max(samples), 2),
    }


def measure_cli_check(repo: str, iterations: int) -> dict[str, float]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[1] / "src")
    env["SAFEGIT_AUDIT_PATH"] = os.path.join(repo, "audit.jsonl")
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        completed = subprocess.run(
            [
                sys.executable,
                "-P",
                "-m",
                "safegit",
                "check",
                "--command",
                "git status",
                "--profile",
                "default",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=repo,
            timeout=60,
            check=False,
        )
        samples.append((time.perf_counter() - started) * 1000.0)
        if completed.returncode != 0:
            raise AssertionError("check returned %d" % completed.returncode)
    return {
        "mean_ms": round(statistics.mean(samples), 2),
        "max_ms": round(max(samples), 2),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure SafeGit latency")
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    results: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="safegit-measure-") as temporary:
        small = make_repo(temporary)
        big = make_repo(os.path.join(temporary, "big"), untracked=1200)

        results["policy_core"] = measure_policy_core(max(args.iterations * 20, 200))
        results["decision_read_only_small_repo"] = measure_decision(
            small,
            args.iterations,
            profile="default",
            commands=("git status", "git log --oneline -3"),
        )
        results["decision_state_dependent_small_repo"] = measure_decision(
            small,
            args.iterations,
            profile="default",
            commands=(
                "git commit -m x",
                "git branch -D nope",
                "git push origin feature/x",
            ),
        )
        results["decision_dangerous_small_repo"] = measure_decision(
            small,
            args.iterations,
            profile="default",
            commands=("git reset --hard", "git clean -fdx"),
        )
        results["probe_small_repo"] = measure_probe(small, args.iterations)
        results["probe_large_untracked_repo"] = measure_probe(
            big, max(args.iterations, 5)
        )
        results["hook_mode_end_to_end"] = measure_hook(small, max(args.iterations, 5))
        results["cli_check_end_to_end"] = measure_cli_check(
            small, max(args.iterations, 5)
        )

    results["platform"] = {
        "python": "%d.%d.%d" % sys.version_info[:3],
        "os": sys.platform,
    }
    if args.json:
        sys.stdout.write(json.dumps(results, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(
            "SafeGit latency (python %s, %s)\n"
            % (results["platform"]["python"], results["platform"]["os"])
        )
        for name, value in results.items():
            if name == "platform":
                continue
            sys.stdout.write("  %-38s %s\n" % (name, json.dumps(value, sort_keys=True)))
    return 0


if __name__ == "__main__":
    with contextlib.suppress(BrokenPipeError):
        raise SystemExit(main())
