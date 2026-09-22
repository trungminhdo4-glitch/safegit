"""Single-use, state-bound owner approvals.

An ``ALLOW`` from SafeGit is a statement about a policy.  A
``REQUIRE_OWNER`` verdict is a statement about intent, and intent cannot be
inferred - so it must be produced deliberately by a human and consumed by
exactly one matching action.

Design constraints that make approvals meaningful rather than decorative:

* the approval is bound to a *fingerprint* over the rule, the canonical
  action, the repository root, the branch and HEAD, so replay against a
  different action, branch or commit is impossible;
* minting requires an interactive terminal and a typed confirmation code,
  so a non-interactive agent tool call cannot mint one;
* use is single-use by default and consumed *before* the action runs, so a
  crash or a race cannot yield a second use;
* the store lives outside any repository (user profile), so a
  ``git clean`` cannot delete an outstanding approval;
* every record carries an integrity digest.

What this is not: a cryptographic attestation.  The store is a normal file
owned by the same OS user, so an agent running as that user with terminal
access can create approvals.  See docs/KNOWN_LIMITATIONS.md.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import secrets
import time
from typing import Any

SCHEMA = "safegit.approvals/1"
DEFAULT_TTL_SECONDS = 900
DEFAULT_MAX_USES = 1
STORE_ENV = "SAFEGIT_APPROVAL_STORE"
STORE_DIR_NAME = ".safegit"
STORE_FILE_NAME = "approvals.json"
MAX_REASON_CHARS = 200
CONFIRM_CODE_CHARS = 8


class ApprovalError(Exception):
    """Raised for approval store or approval usage problems."""


@dataclasses.dataclass(frozen=True)
class Approval:
    approval_id: str
    fingerprint: str
    rule_id: str
    repo_root: str
    branch: str
    head: str
    created_at: int
    expires_at: int
    uses_remaining: int
    reason: str
    interactive: bool
    digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "repo_root": self.repo_root,
            "branch": self.branch,
            "head": self.head,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "uses_remaining": self.uses_remaining,
            "reason": self.reason,
            "interactive": self.interactive,
            "digest": self.digest,
        }

    def with_digest(self) -> "Approval":
        return dataclasses.replace(self, digest=_digest_of(self.to_dict()))

    def is_expired(self, now: int | None = None) -> bool:
        return (now if now is not None else _now()) >= self.expires_at

    @property
    def is_exhausted(self) -> bool:
        return self.uses_remaining <= 0


def _now() -> int:
    return int(time.time())


def _digest_of(payload: dict[str, Any]) -> str:
    body = {key: value for key, value in payload.items() if key != "digest"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def compute_fingerprint(
    *,
    policy_digest: str,
    rule_id: str,
    action_text: str,
    repo_root: str,
    branch: str,
    head: str,
) -> str:
    """Bind an approval to exactly one action in exactly one repository state."""
    payload = {
        "policy": policy_digest,
        "rule": rule_id,
        "action": _normalize_action_text(action_text),
        "repo": os.path.normcase(os.path.abspath(repo_root)) if repo_root else "",
        "branch": branch,
        "head": head,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _normalize_action_text(text: str) -> str:
    return " ".join((text or "").split())


def confirmation_code(fingerprint: str) -> str:
    """A short code a human must read from the prompt and type back."""
    return fingerprint.replace("sha256:", "")[:CONFIRM_CODE_CHARS].upper()


def default_store_path(env: dict[str, str] | None = None) -> pathlib.Path:
    environment = env if env is not None else os.environ
    explicit = environment.get(STORE_ENV)
    if explicit:
        return pathlib.Path(explicit)
    home = environment.get("USERPROFILE") or environment.get("HOME")
    base = pathlib.Path(home) if home else pathlib.Path.home()
    return base / STORE_DIR_NAME / STORE_FILE_NAME


def _store_lock(path: pathlib.Path, *, timeout: float = 5.0):
    """Serialise approval store mutations across processes.

    ``os.replace`` makes the write atomic but not the read-modify-write, so
    two concurrent consumers could both spend the last use.  A lock file
    (create-exclusive) closes that window; if it cannot be taken, the caller
    treats the approval as unusable, which keeps the verdict at
    REQUIRE_OWNER rather than allowing a double spend.
    """
    import contextlib
    import time as _time

    lock_path = path.with_suffix(path.suffix + ".lock")

    @contextlib.contextmanager
    def _hold():
        deadline = _time.monotonic() + timeout
        handle: int | None = None
        while True:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                handle = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                if _time.monotonic() >= deadline:
                    raise ApprovalError("APPROVAL_STORE_LOCKED") from None
                _time.sleep(0.05)
            except OSError as exc:
                raise ApprovalError("APPROVAL_STORE_LOCK_UNWRITABLE") from exc
        try:
            yield
        finally:
            if handle is not None:
                os.close(handle)
            try:
                os.unlink(lock_path)
            except OSError:
                pass

    return _hold()


def _load_document(path: pathlib.Path) -> dict[str, Any]:
    if not path.is_file():
        return {"schema": SCHEMA, "approvals": []}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ApprovalError("APPROVAL_STORE_UNREADABLE") from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ApprovalError("APPROVAL_STORE_JSON_INVALID") from exc
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ApprovalError("APPROVAL_STORE_SCHEMA_INVALID")
    if not isinstance(document.get("approvals"), list):
        raise ApprovalError("APPROVAL_STORE_ENTRIES_INVALID")
    return document


def _save_document(path: pathlib.Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, indent=2, sort_keys=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload + "\n", encoding="utf-8")
    os.replace(temporary, path)


def load_approvals(path: pathlib.Path | None = None) -> list[Approval]:
    target = path or default_store_path()
    document = _load_document(target)
    approvals: list[Approval] = []
    for entry in document["approvals"]:
        if not isinstance(entry, dict):
            raise ApprovalError("APPROVAL_ENTRY_INVALID")
        digest = str(entry.get("digest", ""))
        rebuilt = _digest_of(entry)
        if digest != rebuilt:
            raise ApprovalError("APPROVAL_ENTRY_DIGEST_MISMATCH")
        try:
            approvals.append(
                Approval(
                    approval_id=str(entry["approval_id"]),
                    fingerprint=str(entry["fingerprint"]),
                    rule_id=str(entry["rule_id"]),
                    repo_root=str(entry["repo_root"]),
                    branch=str(entry["branch"]),
                    head=str(entry["head"]),
                    created_at=int(entry["created_at"]),
                    expires_at=int(entry["expires_at"]),
                    uses_remaining=int(entry["uses_remaining"]),
                    reason=str(entry.get("reason", ""))[:MAX_REASON_CHARS],
                    interactive=bool(entry.get("interactive", False)),
                    digest=digest,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ApprovalError("APPROVAL_ENTRY_FIELDS_INVALID") from exc
    return approvals


def find_valid(
    fingerprint: str,
    *,
    path: pathlib.Path | None = None,
    now: int | None = None,
) -> Approval | None:
    moment = now if now is not None else _now()
    matches = [
        approval
        for approval in load_approvals(path)
        if approval.fingerprint == fingerprint
        and not approval.is_expired(moment)
        and not approval.is_exhausted
    ]
    if not matches:
        return None
    return max(matches, key=lambda approval: approval.created_at)


def mint(
    *,
    fingerprint: str,
    rule_id: str,
    repo_root: str,
    branch: str,
    head: str,
    reason: str,
    interactive: bool,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    max_uses: int = DEFAULT_MAX_USES,
    path: pathlib.Path | None = None,
    now: int | None = None,
) -> Approval:
    if ttl_seconds <= 0:
        raise ApprovalError("APPROVAL_TTL_INVALID")
    if max_uses <= 0:
        raise ApprovalError("APPROVAL_MAX_USES_INVALID")
    target = path or default_store_path()
    moment = now if now is not None else _now()
    approval = Approval(
        approval_id=secrets.token_hex(8),
        fingerprint=fingerprint,
        rule_id=rule_id,
        repo_root=repo_root,
        branch=branch,
        head=head,
        created_at=moment,
        expires_at=moment + ttl_seconds,
        uses_remaining=max_uses,
        reason=(reason or "")[:MAX_REASON_CHARS],
        interactive=interactive,
    ).with_digest()

    with _store_lock(target):
        document = _load_document(target)
        document["approvals"] = [
            entry
            for entry in document["approvals"]
            if _digest_of(entry) == entry.get("digest")
            and int(entry.get("expires_at", 0)) > moment
            and int(entry.get("uses_remaining", 0)) > 0
        ]
        document["approvals"].append(approval.to_dict())
        _save_document(target, document)
    return approval


def consume(
    approval_id: str,
    *,
    path: pathlib.Path | None = None,
    now: int | None = None,
    max_uses: int = 0,
) -> Approval:
    """Consume one use atomically (rewrite before the action executes).

    ``max_uses`` clamps a store entry to the policy's limit, so an entry
    edited by hand (``uses_remaining: 1000``) cannot buy unlimited
    approvals.  The whole transaction runs under the store lock.
    """
    target = path or default_store_path()
    moment = now if now is not None else _now()
    with _store_lock(target):
        document = _load_document(target)
        updated: list[dict[str, Any]] = []
        consumed: Approval | None = None
        for entry in document["approvals"]:
            if str(entry.get("approval_id")) != approval_id or consumed is not None:
                updated.append(entry)
                continue
            if _digest_of(entry) != entry.get("digest"):
                raise ApprovalError("APPROVAL_ENTRY_DIGEST_MISMATCH")
            remaining = int(entry.get("uses_remaining", 0))
            if max_uses > 0:
                remaining = min(remaining, max_uses)
            if remaining <= 0:
                raise ApprovalError("APPROVAL_ALREADY_CONSUMED")
            if int(entry.get("expires_at", 0)) <= moment:
                raise ApprovalError("APPROVAL_EXPIRED")
            entry = dict(entry)
            entry["uses_remaining"] = remaining - 1
            entry["digest"] = _digest_of(entry)
            consumed = Approval(
                approval_id=str(entry["approval_id"]),
                fingerprint=str(entry["fingerprint"]),
                rule_id=str(entry["rule_id"]),
                repo_root=str(entry["repo_root"]),
                branch=str(entry["branch"]),
                head=str(entry["head"]),
                created_at=int(entry["created_at"]),
                expires_at=int(entry["expires_at"]),
                uses_remaining=int(entry["uses_remaining"]),
                reason=str(entry.get("reason", "")),
                interactive=bool(entry.get("interactive", False)),
                digest=str(entry["digest"]),
            )
            updated.append(entry)
        if consumed is None:
            raise ApprovalError("APPROVAL_NOT_FOUND")
        document["approvals"] = updated
        _save_document(target, document)
        return consumed


def prune(*, path: pathlib.Path | None = None, now: int | None = None) -> int:
    target = path or default_store_path()
    moment = now if now is not None else _now()
    document = _load_document(target)
    before = len(document["approvals"])
    document["approvals"] = [
        entry
        for entry in document["approvals"]
        if int(entry.get("expires_at", 0)) > moment
        and int(entry.get("uses_remaining", 0)) > 0
        and _digest_of(entry) == entry.get("digest")
    ]
    removed = before - len(document["approvals"])
    if removed:
        _save_document(target, document)
    return removed
