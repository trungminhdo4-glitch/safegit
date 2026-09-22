"""Policy model, profiles, loading and validation.

The policy is data, not code: a JSON document with an explicit rule table.
Loading is fail-closed - a missing, unreadable, malformed or semantically
invalid policy never degrades into "allow"; it raises
:class:`PolicyError` and the caller must treat the result as
``REQUIRE_OWNER``/``DENY`` depending on enforcement mode.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
from typing import Any

from . import gitop
from .verdicts import ALLOW, DENY, REQUIRE_OWNER, UNKNOWN, VERDICTS

SPEC_VERSION = "safegit.policy/1"
DEFAULT_POLICY_FILENAME = "safegit.policy.json"
POLICY_DIR_ENV = "SAFEGIT_POLICY_DIR"
POLICY_PATH_ENV = "SAFEGIT_POLICY"

PROFILE_DEFAULT = "default"
PROFILE_STRICT = "strict"
PROFILE_RELAXED = "relaxed"
PROFILE_CI = "ci"
PROFILES = (PROFILE_DEFAULT, PROFILE_STRICT, PROFILE_RELAXED, PROFILE_CI)

FS_PROTECTED_WRITE = "fs.protected_write"
FS_SECRET_WRITE = "fs.secret_write"
FS_CI_WRITE = "fs.ci_write"
FS_REPO_ESCAPE_WRITE = "fs.repo_escape_write"
FS_OTHER_WRITE = "fs.other_write"

FS_RULE_IDS = (
    FS_PROTECTED_WRITE,
    FS_SECRET_WRITE,
    FS_CI_WRITE,
    FS_REPO_ESCAPE_WRITE,
    FS_OTHER_WRITE,
)

ALL_RULE_IDS = gitop.RULE_IDS + FS_RULE_IDS

_DEFAULT_RULES: dict[str, str] = {
    gitop.RULE_RESET_HARD: DENY,
    gitop.RULE_RESET_KEEP: DENY,
    gitop.RULE_CLEAN_FORCE: DENY,
    gitop.RULE_CHECKOUT_DISCARD: DENY,
    gitop.RULE_RESTORE_WORKTREE: DENY,
    gitop.RULE_STASH_DESTROY: DENY,
    gitop.RULE_HISTORY_FILTER: DENY,
    gitop.RULE_HISTORY_EXPIRE: DENY,
    gitop.RULE_PUSH_FORCE: DENY,
    gitop.RULE_HOOK_BYPASS: DENY,
    gitop.RULE_CONFIG_INLINE: REQUIRE_OWNER,
    gitop.RULE_REPO_OVERRIDE: REQUIRE_OWNER,
    gitop.RULE_PUSH_FORCE_LEASE: REQUIRE_OWNER,
    gitop.RULE_PUSH_DELETE: REQUIRE_OWNER,
    gitop.RULE_PUSH_BROAD: REQUIRE_OWNER,
    gitop.RULE_REBASE: REQUIRE_OWNER,
    gitop.RULE_COMMIT_AMEND: REQUIRE_OWNER,
    gitop.RULE_WORKTREE_REMOVE: REQUIRE_OWNER,
    gitop.RULE_WORKTREE_PRUNE: ALLOW,
    gitop.RULE_BRANCH_DELETE_FORCE: REQUIRE_OWNER,
    gitop.RULE_BRANCH_DELETE_SAFE: ALLOW,
    gitop.RULE_BRANCH_RENAME: ALLOW,
    gitop.RULE_ADD_ALL: ALLOW,
    gitop.RULE_RM_TRACKED: REQUIRE_OWNER,
    gitop.RULE_REF_WRITE: REQUIRE_OWNER,
    gitop.RULE_CONFIG_WRITE: REQUIRE_OWNER,
    gitop.RULE_REMOTE_CHANGE: REQUIRE_OWNER,
    gitop.RULE_TAG_DELETE: REQUIRE_OWNER,
    gitop.RULE_SUBMODULE_CHANGE: REQUIRE_OWNER,
    gitop.RULE_REBASE_CONTINUE: ALLOW,
    gitop.RULE_MERGE: ALLOW,
    gitop.RULE_COMMIT_PLAIN: ALLOW,
    gitop.RULE_PUSH_PLAIN: ALLOW,
    gitop.RULE_CHECKOUT_SWITCH: ALLOW,
    gitop.RULE_NON_DESTRUCTIVE: ALLOW,
    gitop.RULE_OTHER: UNKNOWN,
    FS_PROTECTED_WRITE: DENY,
    FS_SECRET_WRITE: DENY,
    FS_CI_WRITE: REQUIRE_OWNER,
    FS_REPO_ESCAPE_WRITE: ALLOW,
    FS_OTHER_WRITE: ALLOW,
}

_STRICT_OVERRIDES: dict[str, str] = {
    gitop.RULE_PUSH_FORCE_LEASE: DENY,
    gitop.RULE_REBASE: DENY,
    gitop.RULE_COMMIT_AMEND: DENY,
    gitop.RULE_ADD_ALL: REQUIRE_OWNER,
    gitop.RULE_RM_TRACKED: DENY,
    gitop.RULE_PUSH_PLAIN: REQUIRE_OWNER,
    gitop.RULE_MERGE: REQUIRE_OWNER,
    gitop.RULE_REBASE_CONTINUE: REQUIRE_OWNER,
    gitop.RULE_WORKTREE_PRUNE: REQUIRE_OWNER,
    gitop.RULE_REF_WRITE: DENY,
    gitop.RULE_CONFIG_WRITE: DENY,
    gitop.RULE_REMOTE_CHANGE: DENY,
    gitop.RULE_SUBMODULE_CHANGE: DENY,
    gitop.RULE_TAG_DELETE: DENY,
    gitop.RULE_BRANCH_DELETE_SAFE: REQUIRE_OWNER,
    gitop.RULE_CHECKOUT_SWITCH: ALLOW,
    FS_CI_WRITE: DENY,
    FS_REPO_ESCAPE_WRITE: DENY,
}

_RELAXED_OVERRIDES: dict[str, str] = {
    gitop.RULE_RESET_HARD: REQUIRE_OWNER,
    gitop.RULE_RESET_KEEP: REQUIRE_OWNER,
    gitop.RULE_CLEAN_FORCE: REQUIRE_OWNER,
    gitop.RULE_CHECKOUT_DISCARD: REQUIRE_OWNER,
    gitop.RULE_RESTORE_WORKTREE: REQUIRE_OWNER,
    gitop.RULE_STASH_DESTROY: REQUIRE_OWNER,
    gitop.RULE_PUSH_FORCE: REQUIRE_OWNER,
    gitop.RULE_WORKTREE_REMOVE: REQUIRE_OWNER,
    gitop.RULE_BRANCH_DELETE_FORCE: REQUIRE_OWNER,
}

_CI_OVERRIDES: dict[str, str] = {
    gitop.RULE_PUSH_PLAIN: DENY,
    gitop.RULE_CHECKOUT_SWITCH: ALLOW,
    gitop.RULE_COMMIT_PLAIN: ALLOW,
    gitop.RULE_MERGE: ALLOW,
    FS_OTHER_WRITE: ALLOW,
}

DEFAULT_PROTECTED_BRANCHES = (
    "main",
    "master",
    "trunk",
    "develop",
    "release/*",
    "release-*",
)

_DEFAULT_PROTECTED_PATHS: tuple[str, ...] = (
    ".git",
    ".git/**",
    ".safegit",
    ".safegit/**",
    "safegit.policy.json",
    "**/safegit.policy.json",
    "opencode.json",
    "opencode.jsonc",
    ".opencode/**",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/hooks/**",
    "**/.gitconfig",
    "**/.config/git/config",
    "**/.npmrc",
)

_DEFAULT_SECRET_PATHS: tuple[str, ...] = (
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/credentials",
    "**/credentials.*",
    "**/*_secret",
    "**/*_secret.*",
    "**/.aws/**",
    "**/.ssh/**",
    "**/id_rsa*",
    "**/.netrc",
    "**/.bashrc",
    "**/.zshrc",
    "**/.profile",
    "**/.bash_profile",
    "**/.config/powershell/**",
    "**/.local/share/powershell/**",
)

_DEFAULT_CI_PATHS: tuple[str, ...] = (
    ".github/workflows/**",
    ".github/actions/**",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".circleci/**",
)

SECRET_PATH_ALLOWLIST: tuple[str, ...] = (
    "**/.env.example",
    "**/.env.template",
    "**/.env.sample",
    "**/.env.dist",
)

_DEFAULT_UNKNOWN_CEILING: dict[str, str] = {
    PROFILE_DEFAULT: REQUIRE_OWNER,
    PROFILE_STRICT: DENY,
    PROFILE_RELAXED: REQUIRE_OWNER,
    PROFILE_CI: DENY,
}


class PolicyError(Exception):
    """Raised when a policy is missing, unreadable or invalid."""


@dataclasses.dataclass(frozen=True)
class CommitPreflightConfig:
    enabled: bool = True
    max_files: int = 40
    max_added_lines: int = 900
    max_deleted_lines: int = 900
    max_file_bytes: int = 5_242_880
    block_conflict_markers: bool = True
    block_denied_paths: bool = True
    warn_generated_paths: bool = True
    generated_paths: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ApprovalConfig:
    ttl_seconds: int = 900
    max_uses: int = 1
    store: str = ""
    require_interactive: bool = True

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class AuditConfig:
    enabled: bool = True
    path: str = ""
    retention_days: int = 30
    include_command: bool = False

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Policy:
    schema: str
    profile: str
    enforcement: str
    interactive: bool
    rules: dict[str, str]
    protected_branches: tuple[str, ...]
    protected_paths: tuple[str, ...]
    secret_paths: tuple[str, ...]
    ci_paths: tuple[str, ...]
    allowed_repo_roots: tuple[str, ...]
    unknown_git_operations: str
    protect_default_branch_commits: bool
    guard_opaque_tools: bool
    commit_preflight: CommitPreflightConfig
    approvals: ApprovalConfig
    audit: AuditConfig
    source_path: str = ""
    digest: str = ""

    def rule_verdict(self, rule_id: str) -> str:
        return self.rules.get(rule_id, UNKNOWN)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "profile": self.profile,
            "enforcement": self.enforcement,
            "interactive": self.interactive,
            "rules": dict(sorted(self.rules.items())),
            "protected_branches": list(self.protected_branches),
            "protected_paths": list(self.protected_paths),
            "secret_paths": list(self.secret_paths),
            "ci_paths": list(self.ci_paths),
            "allowed_repo_roots": list(self.allowed_repo_roots),
            "unknown_git_operations": self.unknown_git_operations,
            "protect_default_branch_commits": self.protect_default_branch_commits,
            "guard_opaque_tools": self.guard_opaque_tools,
            "commit_preflight": self.commit_preflight.to_dict(),
            "approvals": self.approvals.to_dict(),
            "audit": self.audit.to_dict(),
            "source_path": self.source_path,
            "digest": self.digest,
        }


def _profile_rules(profile: str) -> dict[str, str]:
    rules = dict(_DEFAULT_RULES)
    if profile == PROFILE_STRICT:
        rules.update(_STRICT_OVERRIDES)
    elif profile == PROFILE_RELAXED:
        rules.update(_RELAXED_OVERRIDES)
    elif profile == PROFILE_CI:
        rules.update(_CI_OVERRIDES)
    return rules


def default_policy_dict(profile: str = PROFILE_DEFAULT) -> dict[str, Any]:
    """Return a complete, valid policy document for a named profile."""
    if profile not in PROFILES:
        raise PolicyError("UNKNOWN_PROFILE:%s" % profile)
    return {
        "schema": SPEC_VERSION,
        "profile": profile,
        "enforcement": "binding",
        "interactive": profile != PROFILE_CI,
        "rules": _profile_rules(profile),
        "protected_branches": list(DEFAULT_PROTECTED_BRANCHES),
        "protected_paths": list(_DEFAULT_PROTECTED_PATHS),
        "secret_paths": list(_DEFAULT_SECRET_PATHS),
        "ci_paths": list(_DEFAULT_CI_PATHS),
        "allowed_repo_roots": [],
        "unknown_git_operations": _DEFAULT_UNKNOWN_CEILING.get(profile, REQUIRE_OWNER),
        "protect_default_branch_commits": profile == PROFILE_STRICT,
        "guard_opaque_tools": profile == PROFILE_STRICT,
        "commit_preflight": dataclasses.asdict(CommitPreflightConfig()),
        "approvals": dataclasses.asdict(ApprovalConfig()),
        "audit": dataclasses.asdict(AuditConfig()),
    }


def canonical_digest(document: dict[str, Any]) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _require_str_list(document: dict[str, Any], key: str) -> tuple[str, ...]:
    value = document.get(key, [])
    if isinstance(value, tuple):
        value = list(value)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PolicyError("INVALID_LIST:%s" % key)
    return tuple(value)


def _require_bool(document: dict[str, Any], key: str, default: bool) -> bool:
    value = document.get(key, default)
    if not isinstance(value, bool):
        raise PolicyError("INVALID_BOOL:%s" % key)
    return value


def _require_int(document: dict[str, Any], key: str, default: int) -> int:
    value = document.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise PolicyError("INVALID_INT:%s" % key)
    if value < 0:
        raise PolicyError("NEGATIVE_INT:%s" % key)
    return value


def validate(document: Any) -> list[str]:
    """Return a list of validation errors; empty means valid."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["POLICY_NOT_AN_OBJECT"]
    if document.get("schema") != SPEC_VERSION:
        errors.append("UNKNOWN_SCHEMA:%s" % document.get("schema"))
    profile = document.get("profile")
    if profile not in PROFILES:
        errors.append("UNKNOWN_PROFILE:%s" % profile)
    if document.get("enforcement", "binding") not in ("binding", "advisory"):
        errors.append("UNKNOWN_ENFORCEMENT:%s" % document.get("enforcement"))
    rules = document.get("rules", {})
    if not isinstance(rules, dict):
        errors.append("RULES_NOT_AN_OBJECT")
    else:
        for key, value in rules.items():
            if key not in ALL_RULE_IDS:
                errors.append("UNKNOWN_RULE:%s" % key)
            if value not in VERDICTS:
                errors.append("UNKNOWN_VERDICT:%s=%s" % (key, value))
    for key in (
        "protected_branches",
        "protected_paths",
        "secret_paths",
        "ci_paths",
        "allowed_repo_roots",
    ):
        try:
            _require_str_list(document, key)
        except PolicyError as exc:
            errors.append(str(exc))
    unknown_verdict = document.get("unknown_git_operations", REQUIRE_OWNER)
    if unknown_verdict not in VERDICTS:
        errors.append("UNKNOWN_VERDICT:unknown_git_operations")
    return errors


def from_dict(document: dict[str, Any], *, source_path: str = "") -> Policy:
    errors = validate(document)
    if errors:
        raise PolicyError("INVALID_POLICY:%s" % ",".join(sorted(errors)[:8]))

    preflight_raw = document.get("commit_preflight", {})
    if not isinstance(preflight_raw, dict):
        raise PolicyError("INVALID_SECTION:commit_preflight")
    approvals_raw = document.get("approvals", {})
    if not isinstance(approvals_raw, dict):
        raise PolicyError("INVALID_SECTION:approvals")
    audit_raw = document.get("audit", {})
    if not isinstance(audit_raw, dict):
        raise PolicyError("INVALID_SECTION:audit")

    preflight = CommitPreflightConfig(
        enabled=_require_bool(preflight_raw, "enabled", True),
        max_files=_require_int(preflight_raw, "max_files", 40),
        max_added_lines=_require_int(preflight_raw, "max_added_lines", 900),
        max_deleted_lines=_require_int(preflight_raw, "max_deleted_lines", 900),
        max_file_bytes=_require_int(preflight_raw, "max_file_bytes", 5_242_880),
        block_conflict_markers=_require_bool(
            preflight_raw, "block_conflict_markers", True
        ),
        block_denied_paths=_require_bool(preflight_raw, "block_denied_paths", True),
        warn_generated_paths=_require_bool(preflight_raw, "warn_generated_paths", True),
        generated_paths=_require_str_list(preflight_raw, "generated_paths"),
    )
    approvals = ApprovalConfig(
        ttl_seconds=_require_int(approvals_raw, "ttl_seconds", 900),
        max_uses=_require_int(approvals_raw, "max_uses", 1),
        store=str(approvals_raw.get("store", "") or ""),
        require_interactive=_require_bool(approvals_raw, "require_interactive", True),
    )
    audit = AuditConfig(
        enabled=_require_bool(audit_raw, "enabled", True),
        path=str(audit_raw.get("path", "") or ""),
        retention_days=_require_int(audit_raw, "retention_days", 30),
        include_command=_require_bool(audit_raw, "include_command", False),
    )

    rules = _profile_rules(str(document.get("profile") or PROFILE_DEFAULT))
    rules.update({str(k): str(v) for k, v in (document.get("rules") or {}).items()})

    policy = Policy(
        schema=SPEC_VERSION,
        profile=str(document["profile"]),
        enforcement=str(document.get("enforcement", "binding")),
        interactive=_require_bool(document, "interactive", True),
        rules=rules,
        protected_branches=_require_str_list(document, "protected_branches")
        or DEFAULT_PROTECTED_BRANCHES,
        protected_paths=_require_str_list(document, "protected_paths")
        or _DEFAULT_PROTECTED_PATHS,
        secret_paths=_require_str_list(document, "secret_paths")
        or _DEFAULT_SECRET_PATHS,
        ci_paths=_require_str_list(document, "ci_paths") or _DEFAULT_CI_PATHS,
        allowed_repo_roots=_require_str_list(document, "allowed_repo_roots"),
        unknown_git_operations=str(
            document.get("unknown_git_operations", REQUIRE_OWNER)
        ),
        protect_default_branch_commits=_require_bool(
            document,
            "protect_default_branch_commits",
            document.get("profile") == PROFILE_STRICT,
        ),
        guard_opaque_tools=_require_bool(
            document, "guard_opaque_tools", document.get("profile") == PROFILE_STRICT
        ),
        commit_preflight=preflight,
        approvals=approvals,
        audit=audit,
        source_path=source_path,
    )
    digest_document = policy.to_dict()
    digest_document.pop("source_path", None)
    return dataclasses.replace(policy, digest=canonical_digest(digest_document))


def resolve_policy_path(
    explicit: str | pathlib.Path | None = None,
    *,
    start_dir: str | pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> pathlib.Path | None:
    """Locate the policy: explicit, env, repo-local, then user-global."""
    import os

    environment = env if env is not None else os.environ
    if explicit:
        return pathlib.Path(explicit)
    env_path = environment.get(POLICY_PATH_ENV)
    if env_path:
        return pathlib.Path(env_path)
    env_dir = environment.get(POLICY_DIR_ENV)
    if env_dir:
        return pathlib.Path(env_dir) / DEFAULT_POLICY_FILENAME

    candidates: list[pathlib.Path] = []
    current = pathlib.Path(start_dir or pathlib.Path.cwd()).resolve()
    for parent in [current, *current.parents]:
        candidates.append(parent / ".safegit" / DEFAULT_POLICY_FILENAME)
        candidates.append(parent / DEFAULT_POLICY_FILENAME)
    home = environment.get("USERPROFILE") or environment.get("HOME")
    if home:
        candidates.append(pathlib.Path(home) / ".safegit" / DEFAULT_POLICY_FILENAME)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def load(
    path: str | pathlib.Path | None = None,
    *,
    profile: str | None = None,
    start_dir: str | pathlib.Path | None = None,
    allow_builtin_default: bool = True,
) -> Policy:
    """Load and validate a policy.

    Fail-closed rules:

    * a policy that was explicitly requested (argument, environment variable
      or a discovered file path) but is missing, unreadable, malformed or
      invalid raises :class:`PolicyError` - it never degrades into a weaker
      policy;
    * when no policy file exists anywhere and no explicit path was given,
      the built-in default profile is used and the result records
      ``<builtin:default>`` as its source, so the audit log shows which
      ruleset produced a decision.
    """
    resolved = resolve_policy_path(path, start_dir=start_dir)
    if resolved is None:
        if profile:
            return from_dict(
                default_policy_dict(profile), source_path="<builtin:%s>" % profile
            )
        if allow_builtin_default:
            return from_dict(
                default_policy_dict(PROFILE_DEFAULT), source_path="<builtin:default>"
            )
        raise PolicyError("POLICY_NOT_FOUND")
    if not resolved.is_file():
        raise PolicyError("POLICY_NOT_FOUND:%s" % resolved)
    try:
        raw = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError("POLICY_UNREADABLE:%s" % exc.__class__.__name__) from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyError("POLICY_JSON_INVALID:%s" % exc.msg) from exc
    return from_dict(document, source_path=str(resolved))


def write_default(
    path: str | pathlib.Path,
    *,
    profile: str = PROFILE_DEFAULT,
    overwrite: bool = False,
) -> pathlib.Path:
    target = pathlib.Path(path)
    if target.exists() and not overwrite:
        raise PolicyError("POLICY_EXISTS:%s" % target)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(default_policy_dict(profile), indent=2, sort_keys=True)
    target.write_text(payload + "\n", encoding="utf-8")
    return target
