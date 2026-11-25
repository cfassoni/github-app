"""Unit tests for github-app security policy engine and secret redaction."""

from __future__ import annotations

import pytest

from github_app.policy import (
    DEFAULT_PROTECTED_BRANCHES,
    Policy,
    PolicyViolationError,
    load_effective_policy,
    redact_secrets,
    validate_gh_args,
    validate_git_push,
)


def test_load_effective_policy_defaults_and_overrides() -> None:
    default_policy = load_effective_policy({})
    assert default_policy == Policy()
    assert default_policy.protected_branches == DEFAULT_PROTECTED_BRANCHES
    assert default_policy.allow_force_push is False
    assert default_policy.allow_delete_remote_branch is False
    assert default_policy.allow_merge_branches == ()
    assert default_policy.to_dict() == {
        "protected_branches": ["main", "master"],
        "allow_force_push": False,
        "allow_delete_remote_branch": False,
        "allow_merge_branches": [],
    }

    custom = load_effective_policy(
        {
            "policy": {
                "protected_branches": ["refs/heads/main", "production", "main"],
                "allow_force_push": True,
                "allow_delete_remote_branch": True,
                "allow_merge_branches": ["preview", "refs/heads/staging"],
            }
        }
    )
    assert custom.protected_branches == ("main", "production")
    assert custom.allow_force_push is True
    assert custom.allow_delete_remote_branch is True
    assert custom.allow_merge_branches == ("preview", "staging")


def test_load_effective_policy_validation_errors() -> None:
    with pytest.raises(TypeError, match="must be a JSON object"):
        load_effective_policy({"policy": ["invalid"]})

    with pytest.raises(ValueError, match="unknown policy key"):
        load_effective_policy({"policy": {"unknown_flag": True}})

    with pytest.raises(TypeError, match="must be a list of branch names"):
        load_effective_policy({"policy": {"protected_branches": "main"}})

    with pytest.raises(ValueError, match="must be non-empty strings"):
        load_effective_policy({"policy": {"allow_merge_branches": ["preview", "  "]}})

    with pytest.raises(TypeError, match="must be a boolean"):
        load_effective_policy({"policy": {"allow_force_push": "yes"}})


def test_policy_violation_error_formatting() -> None:
    err_plain = PolicyViolationError(rule="test_rule", message="Blocked")
    assert str(err_plain) == "Blocked (rule=test_rule)"

    err_with_hint = PolicyViolationError(rule="test_rule", message="Blocked", remediation="Fix it.")
    assert str(err_with_hint) == "Blocked (rule=test_rule). Fix it."


def test_validate_git_push_default_guardrails() -> None:
    policy = Policy()

    # Allowed feature branch push
    validate_git_push(policy, current_branch="feat/new-thing")
    validate_git_push(policy, current_branch="feat/new-thing", refspecs=["HEAD:feat/new-thing"])
    validate_git_push(policy, current_branch="feat/new-thing", refspecs=["HEAD"])
    validate_git_push(policy, current_branch="feat/new-thing", refspecs=["feat/other:"])

    # Blocked direct pushes to protected branches
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch="main")
    assert exc_info.value.rule == "protected_branch"

    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch="feat/x", refspecs=["HEAD:refs/heads/master"])
    assert exc_info.value.rule == "protected_branch"

    # Blocked force push variants
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch="feat/x", force=True)
    assert exc_info.value.rule == "deny_force_push"

    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch="feat/x", force_with_lease=True)
    assert exc_info.value.rule == "deny_force_push"

    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch="feat/x", refspecs=["+HEAD:feat/x"])
    assert exc_info.value.rule == "deny_force_push"

    # Blocked remote branch deletion variants
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch="feat/x", delete=True, refspecs=["feat/old"])
    assert exc_info.value.rule == "deny_delete_remote_branch"

    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch="feat/x", refspecs=[":feat/old"])
    assert exc_info.value.rule == "deny_delete_remote_branch"

    # Unresolved push targets fail closed
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch=None)
    assert exc_info.value.rule == "unresolved_push_target"

    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch="HEAD", refspecs=["HEAD"])
    assert exc_info.value.rule == "unresolved_push_target"


def test_validate_git_push_with_policy_overrides() -> None:
    policy = Policy(
        protected_branches=("main",),
        allow_force_push=True,
        allow_delete_remote_branch=True,
    )
    validate_git_push(policy, current_branch="feat/x", force_with_lease=True)
    validate_git_push(policy, current_branch="feat/x", delete=True, refspecs=["feat/old"])
    validate_git_push(policy, current_branch="feat/x", refspecs=[":feat/old"])

    # Protected branch remains protected even when force/delete are enabled
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_git_push(policy, current_branch="feat/x", refspecs=[":main"])
    assert exc_info.value.rule == "protected_branch"


def test_validate_gh_args_core_guardrails() -> None:
    policy = Policy()

    # Benign commands pass
    validate_gh_args(policy, ["--version"])
    validate_gh_args(policy, ["pr", "list", "--state", "open"])
    validate_gh_args(policy, ["issue", "view", "42", "-R", "cfassoni/github-app"])
    validate_gh_args(policy, ["secret", "list"])
    validate_gh_args(policy, ["variable", "list"])
    validate_gh_args(policy, ["secret", "--help"])
    validate_gh_args(policy, ["pr", "view", "--", "42"])

    # Empty args fail closed
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(policy, [])
    assert exc_info.value.rule == "empty_gh_args"

    # gh auth * denied
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(policy, ["auth", "token"])
    assert exc_info.value.rule == "deny_gh_auth"

    # gh repo delete denied (including flag reordering)
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(policy, ["-R", "cfassoni/github-app", "repo", "delete", "--yes"])
    assert exc_info.value.rule == "deny_gh_repo_delete"

    # gh secret / variable mutations denied
    for cmd_args in (
        ["secret", "set", "MY_SECRET"],
        ["secret", "delete", "MY_SECRET"],
        ["variable", "set", "MY_VAR", "--body", "1"],
        ["variable", "remove", "MY_VAR"],
    ):
        with pytest.raises(PolicyViolationError) as exc_info:
            validate_gh_args(policy, cmd_args)
        assert exc_info.value.rule == "deny_gh_secret_variable_mutation"


def test_validate_gh_pr_merge_and_live_base_verification() -> None:
    default_policy = Policy()
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(default_policy, ["pr", "merge", "12"])
    assert exc_info.value.rule == "deny_gh_pr_merge"

    preview_policy = Policy(allow_merge_branches=("preview",))

    # Missing resolver fails closed
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(preview_policy, ["pr", "merge", "12"])
    assert exc_info.value.rule == "unresolved_pr_base"

    # Resolver exception fails closed
    def failing_resolver(selector: str | None, repo: str | None) -> str:
        raise RuntimeError("gh pr view failed")

    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(preview_policy, ["pr", "merge", "12"], pr_base_resolver=failing_resolver)
    assert exc_info.value.rule == "unresolved_pr_base"

    # Matching baseRefName allowed across repo flag syntaxes
    seen: list[tuple[str | None, str | None]] = []

    def ok_resolver(selector: str | None, repo: str | None) -> str:
        seen.append((selector, repo))
        return "preview"

    validate_gh_args(
        preview_policy,
        ["pr", "merge", "12", "--repo=cfassoni/github-app", "--squash"],
        pr_base_resolver=ok_resolver,
    )
    validate_gh_args(
        preview_policy,
        ["pr", "merge", "-Rcfassoni/github-app"],
        pr_base_resolver=ok_resolver,
    )
    validate_gh_args(
        preview_policy,
        ["pr", "merge", "-R"],
        pr_base_resolver=ok_resolver,
    )
    assert seen == [
        ("12", "cfassoni/github-app"),
        (None, "cfassoni/github-app"),
        (None, None),
    ]

    # Non-allowed baseRefName blocked
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(
            preview_policy,
            ["pr", "merge", "12"],
            pr_base_resolver=lambda selector, repo: "main",
        )
    assert exc_info.value.rule == "deny_gh_pr_merge_branch"


def test_validate_gh_api_surgical_denylist() -> None:
    policy = Policy()

    # Allowed REST/GraphQL calls
    validate_gh_args(policy, ["api", "--help"])
    validate_gh_args(policy, ["api", "repos/cfassoni/github-app/pulls/1"])
    validate_gh_args(policy, ["api", "repos/cfassoni/github-app/issues/1/comments", "-f", "body=hi"])
    validate_gh_args(policy, ["api", "-H", "Accept: application/vnd.github+json", "--", "user"])
    validate_gh_args(
        policy,
        ["api", "repos/cfassoni/github-app/actions/secrets", "--method=GET"],
    )
    validate_gh_args(
        policy,
        ["api", "graphql", "-f", "query={ viewer { login } }"],
    )
    validate_gh_args(
        policy,
        ["api", "-XDELETE", "repos/cfassoni/github-app/git/refs/heads/feat/temp"],
    )
    validate_gh_args(policy, ["api", "-X"])
    validate_gh_args(policy, ["api", "-f"])

    # Blocked REST PR merge
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(
            policy,
            ["api", "-X", "PUT", "/repos/cfassoni/github-app/pulls/12/merge?sha=abc"],
        )
    assert exc_info.value.rule == "deny_gh_api_pr_merge"

    # Blocked REST repo delete
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(policy, ["api", "--method=DELETE", "repos/cfassoni/github-app"])
    assert exc_info.value.rule == "deny_gh_api_repo_delete"

    # Blocked REST secrets / variables mutations
    for api_args in (
        ["api", "-XPUT", "repos/cfassoni/github-app/actions/secrets/FOO", "-fencrypted_value=x"],
        ["api", "repos/cfassoni/github-app/actions/variables", "--field=name=BAR"],
        ["api", "-X", "DELETE", "orgs/acme/dependabot/secrets/KEY"],
        ["api", "repos/cfassoni/github-app/environments/prod/secrets/S", "--input", "body.json"],
    ):
        with pytest.raises(PolicyViolationError) as exc_info:
            validate_gh_args(policy, api_args)
        assert exc_info.value.rule == "deny_gh_api_secrets_variables"

    # Blocked REST protected branch ref mutation/deletion
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(
            policy,
            ["api", "-X", "PATCH", "repos/cfassoni/github-app/git/refs/heads/main", "-F", "force=true"],
        )
    assert exc_info.value.rule == "deny_gh_api_protected_ref"

    # Blocked GraphQL merge/delete mutations
    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(
            policy,
            ["api", "graphql", "-f", "query=mutation { mergePullRequest(input:{}) { clientMutationId } }"],
        )
    assert exc_info.value.rule == "deny_gh_api_graphql"

    with pytest.raises(PolicyViolationError) as exc_info:
        validate_gh_args(
            policy,
            ["api", "graphql", "--raw-field=query=mutation { deleteRepository(input:{}) { clientMutationId } }"],
        )
    assert exc_info.value.rule == "deny_gh_api_graphql"


def test_redact_secrets() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ==\n-----END PRIVATE KEY-----"
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0NSJ9.c2lnbmF0dXJlMTIz"
    ghs = "ghs_1234567890abcdef123456"
    pat = "github_pat_11ABCDEFGH_0123456789abcdef"
    raw = (
        f"token={ghs} pat={pat} jwt={jwt} custom=super-secret-val\n"
        f"{pem}\n"
        "safe=visible-text"
    )

    scrubbed = redact_secrets(raw, extra_secrets=["super-secret-val", ""])
    assert ghs not in scrubbed
    assert pat not in scrubbed
    assert jwt not in scrubbed
    assert "super-secret-val" not in scrubbed
    assert "BEGIN PRIVATE KEY" not in scrubbed
    assert "safe=visible-text" in scrubbed
    assert scrubbed.count("[REDACTED]") == 5
