"""Security policy engine and secret redaction for github-app."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

DEFAULT_PROTECTED_BRANCHES: tuple[str, ...] = ("main", "master")
ALLOWED_POLICY_KEYS: frozenset[str] = frozenset(
    {
        "protected_branches",
        "allow_force_push",
        "allow_delete_remote_branch",
        "allow_merge_branches",
    }
)

_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_GH_TOKEN_RE = re.compile(
    r"\b(?:gh[psou]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,})\b"
)
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"
)
_SECRETS_OR_VARS_API_RE = re.compile(
    r"/(?:actions|dependabot|codespaces)/(?:secrets|variables)(?:/|$)"
    r"|/environments/[^/]+/(?:secrets|variables)(?:/|$)"
)
_MUTATING_HTTP_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_GH_VALUE_FLAGS = frozenset(
    {
        "--hostname",
        "--jq",
        "-q",
        "--template",
        "-t",
        "--body",
        "-b",
        "--body-file",
        "-F",
        "--title",
        "--base",
        "-B",
        "--head",
        "-H",
        "--state",
        "-s",
        "--label",
        "-l",
        "--assignee",
        "-a",
        "--author",
        "-A",
        "--milestone",
        "-m",
        "--limit",
        "-L",
        "--json",
        "--match-head-commit",
        "--subject",
        "--merge-method",
    }
)

_GH_API_VALUE_FLAGS = frozenset(
    {
        "-H",
        "--header",
        "--hostname",
        "--jq",
        "-q",
        "-t",
        "--template",
        "--cache",
        "--preview",
        "-R",
        "--repo",
    }
)


class PolicyViolationError(Exception):
    """Raised when an operation is blocked by security policy."""

    def __init__(self, rule: str, message: str, remediation: str = "") -> None:
        self.rule = rule
        self.message = message
        self.remediation = remediation
        detail = f"{message} (rule={rule})"
        if remediation:
            detail = f"{detail}. {remediation}"
        super().__init__(detail)


@dataclass(frozen=True)
class Policy:
    """Effective security guardrails for a github-app profile."""

    protected_branches: tuple[str, ...] = DEFAULT_PROTECTED_BRANCHES
    allow_force_push: bool = False
    allow_delete_remote_branch: bool = False
    allow_merge_branches: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "protected_branches": list(self.protected_branches),
            "allow_force_push": self.allow_force_push,
            "allow_delete_remote_branch": self.allow_delete_remote_branch,
            "allow_merge_branches": list(self.allow_merge_branches),
        }


def _parse_branch_list(key: str, value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TypeError(f"policy '{key}' must be a list of branch names")
    branches: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"policy '{key}' entries must be non-empty strings")
        branches.append(_normalize_branch_name(item.strip()))
    return tuple(dict.fromkeys(branches))


def _parse_bool(key: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"policy '{key}' must be a boolean")
    return value


def load_effective_policy(profile: dict[str, Any]) -> Policy:
    """Resolve effective profile policy by merging overrides onto restrictive defaults."""
    raw = profile.get("policy")
    if raw is None:
        return Policy()
    if not isinstance(raw, dict):
        raise TypeError("profile 'policy' must be a JSON object")

    unknown = set(raw.keys()) - ALLOWED_POLICY_KEYS
    if unknown:
        raise ValueError(f"unknown policy key(s): {', '.join(sorted(unknown))}")

    protected = (
        _parse_branch_list("protected_branches", raw["protected_branches"])
        if "protected_branches" in raw
        else DEFAULT_PROTECTED_BRANCHES
    )
    allow_merge = (
        _parse_branch_list("allow_merge_branches", raw["allow_merge_branches"])
        if "allow_merge_branches" in raw
        else ()
    )
    allow_force = (
        _parse_bool("allow_force_push", raw["allow_force_push"])
        if "allow_force_push" in raw
        else False
    )
    allow_delete = (
        _parse_bool("allow_delete_remote_branch", raw["allow_delete_remote_branch"])
        if "allow_delete_remote_branch" in raw
        else False
    )

    return Policy(
        protected_branches=protected,
        allow_force_push=allow_force,
        allow_delete_remote_branch=allow_delete,
        allow_merge_branches=allow_merge,
    )


def _normalize_branch_name(ref: str) -> str:
    return ref.strip().lstrip("+").removeprefix("refs/heads/")


def validate_git_push(
    policy: Policy,
    *,
    current_branch: str | None,
    refspecs: list[str] | None = None,
    force: bool = False,
    force_with_lease: bool = False,
    delete: bool = False,
) -> None:
    """Validate a git push request against profile policy."""
    specs = list(refspecs or [])

    has_plus_refspec = any(spec.strip().startswith("+") for spec in specs)
    if (force or force_with_lease or has_plus_refspec) and not policy.allow_force_push:
        raise PolicyViolationError(
            rule="deny_force_push",
            message="Force push is denied by profile policy",
            remediation="Run git push manually or enable allow_force_push via CLI.",
        )

    has_delete_refspec = any(spec.strip().lstrip("+").startswith(":") for spec in specs)
    if (delete or has_delete_refspec) and not policy.allow_delete_remote_branch:
        raise PolicyViolationError(
            rule="deny_delete_remote_branch",
            message="Deleting remote branches is denied by profile policy",
            remediation="Run git push manually or enable allow_delete_remote_branch via CLI.",
        )

    targets: list[str] = []
    if specs:
        for spec in specs:
            cleaned = spec.strip().lstrip("+")
            if ":" in cleaned:
                src, dst = cleaned.split(":", 1)
                raw_target = dst or src
            else:
                raw_target = cleaned
            target = _normalize_branch_name(raw_target)
            if target in ("", "HEAD"):
                if not current_branch or current_branch.strip() == "HEAD":
                    raise PolicyViolationError(
                        rule="unresolved_push_target",
                        message="Cannot resolve destination branch for git push",
                        remediation="Specify an explicit destination branch refspec.",
                    )
                target = _normalize_branch_name(current_branch)
            targets.append(target)
    else:
        if not current_branch or current_branch.strip() == "HEAD":
            raise PolicyViolationError(
                rule="unresolved_push_target",
                message="Cannot resolve target branch for git push (detached HEAD)",
                remediation="Checkout a branch or specify an explicit refspec.",
            )
        targets.append(_normalize_branch_name(current_branch))

    for branch in targets:
        if branch in policy.protected_branches:
            raise PolicyViolationError(
                rule="protected_branch",
                message=f"Direct push to protected branch '{branch}' is denied by profile policy",
                remediation="Push to a feature branch and open a PR, or update protected_branches via CLI.",
            )


def _extract_gh_positionals_and_repo(args: list[str]) -> tuple[list[str], str | None]:
    positionals: list[str] = []
    repo_flag: str | None = None
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--":
            positionals.extend(args[idx + 1 :])
            break
        if arg in ("-R", "--repo"):
            if idx + 1 < len(args):
                repo_flag = args[idx + 1]
                idx += 2
                continue
            idx += 1
            continue
        if arg.startswith("--repo="):
            repo_flag = arg.split("=", 1)[1]
            idx += 1
            continue
        if arg.startswith("-R") and len(arg) > 2:
            repo_flag = arg[2:]
            idx += 1
            continue
        if arg.startswith("-"):
            if arg in _GH_VALUE_FLAGS and idx + 1 < len(args):
                idx += 2
            else:
                idx += 1
            continue
        positionals.append(arg)
        idx += 1
    return positionals, repo_flag


def _validate_gh_api(policy: Policy, args: list[str]) -> None:
    api_idx = next(i for i, a in enumerate(args) if a.lower() == "api")
    rest = args[api_idx + 1 :]

    explicit_method: str | None = None
    has_body_input = False
    endpoint: str | None = None
    field_values: list[str] = []

    idx = 0
    while idx < len(rest):
        arg = rest[idx]
        if arg == "--":
            if endpoint is None and idx + 1 < len(rest):
                endpoint = rest[idx + 1]
            break
        if arg in ("-X", "--method"):
            if idx + 1 < len(rest):
                explicit_method = rest[idx + 1].upper()
                idx += 2
                continue
            idx += 1
            continue
        if arg.startswith("--method="):
            explicit_method = arg.split("=", 1)[1].upper()
            idx += 1
            continue
        if arg.startswith("-X") and len(arg) > 2:
            explicit_method = arg[2:].upper()
            idx += 1
            continue
        if arg in ("-f", "--raw-field", "-F", "--field", "--input"):
            has_body_input = True
            if idx + 1 < len(rest):
                field_values.append(rest[idx + 1])
                idx += 2
                continue
            idx += 1
            continue
        if arg.startswith(("--raw-field=", "--field=", "--input=")):
            has_body_input = True
            field_values.append(arg.split("=", 1)[1])
            idx += 1
            continue
        if arg.startswith(("-f", "-F")) and len(arg) > 2:
            has_body_input = True
            field_values.append(arg[2:])
            idx += 1
            continue
        if arg.startswith("-"):
            if arg in _GH_API_VALUE_FLAGS and idx + 1 < len(rest):
                idx += 2
            else:
                idx += 1
            continue
        if endpoint is None:
            endpoint = arg
        idx += 1

    if not endpoint:
        return

    method = explicit_method or ("POST" if has_body_input else "GET")
    clean_ep = endpoint.split("?", 1)[0].strip("/")
    ep_lower = clean_ep.lower()
    parts = ep_lower.split("/")

    if ep_lower == "graphql":
        joined = " ".join(field_values).lower()
        if "mergepullrequest" in joined or "deleterepository" in joined:
            raise PolicyViolationError(
                rule="deny_gh_api_graphql",
                message="GraphQL mergePullRequest and deleteRepository mutations are denied by policy",
                remediation="Perform merges/deletions through governed workflows or manually.",
            )
        return

    if (
        method == "PUT"
        and len(parts) == 6
        and parts[0] == "repos"
        and parts[3] == "pulls"
        and parts[5] == "merge"
    ):
        raise PolicyViolationError(
            rule="deny_gh_api_pr_merge",
            message="Direct REST API pull request merge is denied by policy",
            remediation="Use 'gh pr merge' on an allowed merge branch or merge manually.",
        )

    if method == "DELETE" and len(parts) == 3 and parts[0] == "repos":
        raise PolicyViolationError(
            rule="deny_gh_api_repo_delete",
            message="Repository deletion via REST API is denied by policy",
            remediation="Delete repositories manually via GitHub UI or CLI.",
        )

    if method in _MUTATING_HTTP_METHODS and _SECRETS_OR_VARS_API_RE.search(f"/{ep_lower}"):
        raise PolicyViolationError(
            rule="deny_gh_api_secrets_variables",
            message="Mutating GitHub secrets or variables via REST API is denied by policy",
            remediation="Manage secrets and variables manually outside agent sessions.",
        )

    if (
        method in ("PATCH", "DELETE")
        and len(parts) >= 7
        and parts[0] == "repos"
        and parts[3] == "git"
        and parts[4] in ("refs", "ref")
        and parts[5] == "heads"
    ):
        target_branch = "/".join(clean_ep.split("/")[6:])
        if target_branch in policy.protected_branches:
            raise PolicyViolationError(
                rule="deny_gh_api_protected_ref",
                message=(
                    f"Mutating or deleting protected branch ref '{target_branch}' "
                    "via REST API is denied by policy"
                ),
                remediation="Update protected branches via governed PRs or manually.",
            )


def validate_gh_args(
    policy: Policy,
    args: list[str],
    *,
    pr_base_resolver: Callable[[str | None, str | None], str] | None = None,
) -> None:
    """Validate a GitHub CLI argument vector against profile policy."""
    if not args:
        raise PolicyViolationError(
            rule="empty_gh_args",
            message="gh command arguments cannot be empty",
            remediation="Provide a valid gh subcommand and arguments.",
        )

    positionals, repo_flag = _extract_gh_positionals_and_repo(args)
    if not positionals:
        return

    cmd = positionals[0].lower()
    sub = positionals[1].lower() if len(positionals) > 1 else ""

    if cmd == "auth":
        raise PolicyViolationError(
            rule="deny_gh_auth",
            message="'gh auth' commands are denied by policy",
            remediation="Authentication is managed automatically by github-app.",
        )

    if cmd == "repo" and sub == "delete":
        raise PolicyViolationError(
            rule="deny_gh_repo_delete",
            message="'gh repo delete' is denied by policy",
            remediation="Delete repositories manually via GitHub UI or CLI.",
        )

    if cmd in ("secret", "variable") and sub and sub != "list":
        raise PolicyViolationError(
            rule="deny_gh_secret_variable_mutation",
            message=f"'gh {cmd} {sub}' is denied by policy (only 'list' is permitted)",
            remediation="Mutate secrets and variables manually outside agent sessions.",
        )

    if cmd == "pr" and sub == "merge":
        if not policy.allow_merge_branches:
            raise PolicyViolationError(
                rule="deny_gh_pr_merge",
                message="'gh pr merge' is denied by profile policy",
                remediation="Merge PRs manually or configure allow_merge_branches via CLI.",
            )
        if pr_base_resolver is None:
            raise PolicyViolationError(
                rule="unresolved_pr_base",
                message="Cannot verify PR base branch before merge",
                remediation="PR base branch verification is required to execute 'gh pr merge'.",
            )
        pr_selector = positionals[2] if len(positionals) > 2 else None
        try:
            raw_base = pr_base_resolver(pr_selector, repo_flag)
        except Exception as exc:
            raise PolicyViolationError(
                rule="unresolved_pr_base",
                message=f"Failed to verify PR base branch before merge ({exc})",
                remediation="Ensure the PR exists and retry, or merge manually.",
            ) from exc

        base_branch = _normalize_branch_name(raw_base)
        if not base_branch or base_branch not in policy.allow_merge_branches:
            raise PolicyViolationError(
                rule="deny_gh_pr_merge_branch",
                message=(
                    f"Merging PR into base branch '{base_branch or 'unknown'}' is denied by policy "
                    f"(allowed: {', '.join(policy.allow_merge_branches)})"
                ),
                remediation="Merge manually or update allow_merge_branches via CLI.",
            )
        return

    if cmd == "api":
        _validate_gh_api(policy, args)


def redact_secrets(text: str, extra_secrets: Iterable[str] = ()) -> str:
    """Scrub GitHub tokens, JWTs, PEM blocks, and explicit secrets from text."""
    scrubbed = text
    exact = sorted({s for s in extra_secrets if s}, key=len, reverse=True)
    for secret in exact:
        scrubbed = scrubbed.replace(secret, "[REDACTED]")
    scrubbed = _PEM_RE.sub("[REDACTED]", scrubbed)
    scrubbed = _GH_TOKEN_RE.sub("[REDACTED]", scrubbed)
    scrubbed = _JWT_RE.sub("[REDACTED]", scrubbed)
    return scrubbed
