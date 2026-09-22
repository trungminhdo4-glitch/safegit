"""Decision receipts and the privacy-preserving audit log.

A receipt is a self-contained, machine-readable record of one decision: the
verdict, the reason, the findings, the evidence and a digest over all of
it.  Receipts are what make a SafeGit decision reviewable after the fact
without replaying the action.

The audit log stores **no command text and no file content** by default:
the log line carries a SHA-256 of the action instead, so an operator can
correlate repeated attempts without SafeGit becoming a log of the agent's
work.  ``audit.include_command`` opts into storing the command text and is
off by default.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import time
from typing import Any

RECEIPT_SCHEMA = "safegit.receipt/1"
AUDIT_SCHEMA = "safegit.audit/1"
AUDIT_DIR_NAME = ".safegit"
AUDIT_FILE_NAME = "audit.jsonl"
AUDIT_ENV = "SAFEGIT_AUDIT_PATH"
MAX_AUDIT_LINE_CHARS = 8192
MAX_MESSAGE_CHARS = 400


def digest_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def action_digest(text: str) -> str:
    return (
        "sha256:" + hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()
    )


def build_receipt(
    *,
    decision: dict[str, Any],
    tool_name: str,
    action_text: str,
    execution_context: str,
    include_command: bool = False,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a digest-sealed receipt from a decision payload."""
    findings = []
    for finding in decision.get("findings", []) or []:
        findings.append(
            {
                "rule_id": str(finding.get("rule_id", ""))[:120],
                "verdict": str(finding.get("verdict", "")),
                "reason_code": str(finding.get("reason_code", ""))[:120],
                "message": str(finding.get("message", ""))[:MAX_MESSAGE_CHARS],
                "evidence": _bounded(finding.get("evidence", {})),
            }
        )
    repo = (decision.get("evidence") or {}).get("repo") or {}
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verdict": str(decision.get("verdict", "")),
        "reason_code": str(decision.get("reason_code", ""))[:120],
        "tool_name": str(tool_name)[:80],
        "execution_context": str(execution_context)[:40],
        "policy_profile": str(decision.get("policy_profile", ""))[:40],
        "policy_digest": str(decision.get("policy_digest", "")),
        "enforcement": str(decision.get("enforcement", ""))[:20],
        "out_of_scope": bool(decision.get("out_of_scope", False)),
        "approved_rule": str(decision.get("approved_rule", ""))[:120],
        "approval_id": str(decision.get("approval_id", ""))[:40],
        "action_digest": action_digest(action_text),
        "findings": findings,
        "limitations": [
            str(item)[:120] for item in (decision.get("limitations") or [])
        ][:40],
        "repository": {
            "root": str(repo.get("root", ""))[:260],
            "branch": str(repo.get("branch", ""))[:120],
            "head": str(repo.get("head", ""))[:64],
            "staged": int(repo.get("staged", 0) or 0),
            "unstaged": int(repo.get("unstaged", 0) or 0),
            "untracked": int(repo.get("untracked", 0) or 0),
            "available": bool(repo.get("available", False)),
        },
    }
    if extra:
        receipt.update(_bounded(extra))
    if include_command:
        receipt["action"] = action_text[:MAX_AUDIT_LINE_CHARS]
    receipt["receipt_digest"] = digest_payload(receipt)
    return receipt


def verify_receipt(receipt: dict[str, Any]) -> bool:
    digest = receipt.get("receipt_digest")
    if not digest:
        return False
    payload = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    return digest_payload(payload) == digest


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "..."
    if isinstance(value, dict):
        return {
            str(key)[:60]: _bounded(item, depth + 1)
            for key, item in list(value.items())[:24]
        }
    if isinstance(value, (list, tuple)):
        return [_bounded(item, depth + 1) for item in list(value)[:24]]
    if isinstance(value, str):
        return value[:MAX_MESSAGE_CHARS]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:MAX_MESSAGE_CHARS]


def default_audit_path(
    *,
    policy_path: str = "",
    cwd: str = "",
    repo_root: str = "",
    env: dict[str, str] | None = None,
) -> pathlib.Path:
    """Choose where the audit log lives.

    Preference order: an explicit policy path, ``SAFEGIT_AUDIT_PATH``, the
    repository's own ``.safegit/`` directory (guarded by SafeGit's protected
    path rules and easy to gitignore), then the user profile.  The current
    working directory is only a last resort: a guard must not sprinkle log
    files into whatever directory it happens to be called from.
    """
    environment = env if env is not None else os.environ
    explicit = environment.get(AUDIT_ENV)
    if explicit:
        return pathlib.Path(explicit)
    if policy_path and not policy_path.startswith("<builtin"):
        return pathlib.Path(policy_path).parent / AUDIT_FILE_NAME
    if repo_root:
        return pathlib.Path(repo_root) / AUDIT_DIR_NAME / AUDIT_FILE_NAME
    home = environment.get("USERPROFILE") or environment.get("HOME")
    if home:
        return pathlib.Path(home) / AUDIT_DIR_NAME / AUDIT_FILE_NAME
    base = pathlib.Path(cwd or pathlib.Path.cwd())
    return base / AUDIT_DIR_NAME / AUDIT_FILE_NAME


def append_audit(
    receipt: dict[str, Any],
    *,
    path: pathlib.Path,
    retention_days: int = 30,
) -> pathlib.Path | None:
    """Append one receipt to the JSONL audit log (best effort, bounded)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = _bounded_json_line(receipt)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        _prune_audit(path, retention_days)
    except OSError:
        return None
    return path


def _bounded_json_line(receipt: dict[str, Any]) -> str:
    """Serialise a receipt without ever emitting a truncated JSON line.

    Truncating serialised JSON produces unparsable entries that later reads
    silently drop (lost evidence).  Instead the record is bounded field by
    field until it fits.
    """
    candidate = dict(receipt)
    line = json.dumps(candidate, sort_keys=True, default=str)
    for key in ("findings", "limitations", "action"):
        if len(line) <= MAX_AUDIT_LINE_CHARS:
            break
        value = candidate.get(key)
        if isinstance(value, list):
            while value and len(line) > MAX_AUDIT_LINE_CHARS:
                value = value[: max(len(value) // 2, 1)] if len(value) > 1 else []
                candidate[key] = value
                line = json.dumps(candidate, sort_keys=True, default=str)
        elif isinstance(value, str):
            candidate[key] = value[: max(len(value) // 2, 0)]
            line = json.dumps(candidate, sort_keys=True, default=str)
    while len(line) > MAX_AUDIT_LINE_CHARS and candidate.get("findings"):
        candidate["findings"] = list(candidate["findings"])[
            : len(candidate["findings"]) // 2
        ]
        line = json.dumps(candidate, sort_keys=True, default=str)
    if len(line) > MAX_AUDIT_LINE_CHARS:
        candidate = {
            "schema": receipt.get("schema", AUDIT_SCHEMA),
            "created_at": receipt.get("created_at", ""),
            "verdict": receipt.get("verdict", ""),
            "reason_code": receipt.get("reason_code", ""),
            "action_digest": receipt.get("action_digest", ""),
            "truncated": True,
        }
        line = json.dumps(candidate, sort_keys=True, default=str)
    return line


def _prune_audit(path: pathlib.Path, retention_days: int) -> None:
    if retention_days <= 0:
        return
    try:
        stat = path.stat()
    except OSError:
        return
    if (time.time() - stat.st_mtime) < retention_days * 86400:
        return
    cutoff = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - retention_days * 86400)
    )
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    kept: list[str] = []
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if str(entry.get("created_at", "")) >= cutoff:
            kept.append(line)
    try:
        path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    except OSError:
        return


def read_audit(path: pathlib.Path, limit: int = 20) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for line in lines[-max(limit, 1) :]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


@dataclasses.dataclass(frozen=True)
class AuditSummary:
    path: str
    entries: int
    verdicts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "entries": self.entries,
            "verdicts": dict(sorted(self.verdicts.items())),
        }


def summarize_audit(path: pathlib.Path) -> AuditSummary:
    counts: dict[str, int] = {}
    total = 0
    if path.is_file():
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total += 1
                verdict = str(entry.get("verdict", "UNKNOWN"))
                counts[verdict] = counts.get(verdict, 0) + 1
        except OSError:
            pass
    return AuditSummary(path=str(path), entries=total, verdicts=counts)
