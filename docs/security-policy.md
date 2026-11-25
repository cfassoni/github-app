# Security Policy & Secret Redaction

`github-app` enforces profile-scoped security guardrails in `src/github_app/policy.py` and scrubs sensitive tokens from outputs before they can be returned to agents or callers.

## Storage & Ownership Boundary

Policy overrides live under the optional `"policy"` key of each profile in `~/.config/github-app/profiles.json` (or `$GITHUB_APP_CONFIG_DIR/profiles.json`):

```json
{
  "my-project": {
    "app_id": "336189891",
    "installation_id": "12345678",
    "private_key_path": "~/.ssh/my-app.pem",
    "git_name": "my-app[bot]",
    "git_email": "336189891+my-app[bot]@users.noreply.github.com",
    "policy": {
      "protected_branches": ["main", "master", "release"],
      "allow_merge_branches": ["preview"],
      "allow_force_push": false,
      "allow_delete_remote_branch": false
    }
  }
}
```

- **Human-Only Management:** Policies are modified exclusively via `github-app profile policy set|reset` on the CLI and are never exposed as mutable MCP tools.
- **Fail-Closed Validation:** Unknown policy keys or malformed types raise an error instead of silently falling back to permissive behavior.
- **Re-import Safety:** Running `github-app profile import` for an existing profile preserves its existing `"policy"` overrides.

## Policy Keys & Restrictive Defaults

| Key | Type | Default | Effect |
| :--- | :--- | :--- | :--- |
| `protected_branches` | `string[]` | `["main", "master"]` | Destination branches blocked from direct `git push` and REST API ref mutations (`PATCH`/`DELETE`). |
| `allow_merge_branches` | `string[]` | `[]` | PR base branches permitted for `gh pr merge`. Empty denies all merges. |
| `allow_force_push` | `boolean` | `false` | Allows `--force`, `--force-with-lease`, and `+refspec` pushes to non-protected branches when `true`. |
| `allow_delete_remote_branch` | `boolean` | `false` | Allows `--delete` and `:branch` remote deletions of non-protected branches when `true`. |

## Enforced Rules

### Git Push (`validate_git_push`)

1. **`deny_force_push`**: Blocks `force=True`, `force_with_lease=True`, and `+refspec` unless `allow_force_push` is `true`.
2. **`deny_delete_remote_branch`**: Blocks `delete=True` and `:branch` refspecs unless `allow_delete_remote_branch` is `true`.
3. **`unresolved_push_target`**: Fails closed when destination branch cannot be resolved (for example, detached `HEAD` without an explicit refspec).
4. **`protected_branch`**: Blocks pushes targeting any branch in `protected_branches` (including `refs/heads/<branch>` and `src:<branch>` refspecs), even if force-push or remote branch deletion is enabled.

### GitHub CLI (`validate_gh_args`)

- **`deny_gh_auth`**: Blocks all `gh auth *` subcommands.
- **`deny_gh_repo_delete`**: Blocks `gh repo delete`.
- **`deny_gh_secret_variable_mutation`**: Blocks all `gh secret` and `gh variable` subcommands except read-only `list`.
- **`deny_gh_pr_merge` / `deny_gh_pr_merge_branch` / `unresolved_pr_base`**:
  - Denied when `allow_merge_branches` is empty.
  - When `allow_merge_branches` is non-empty, requires a live `pr_base_resolver` check against the PR's `baseRefName`. Fails closed if resolution fails or if `baseRefName` is not in `allow_merge_branches`.
- **Surgical `gh api` Denylist**:
  - `deny_gh_api_pr_merge`: Blocks `PUT repos/{owner}/{repo}/pulls/{number}/merge`.
  - `deny_gh_api_repo_delete`: Blocks `DELETE repos/{owner}/{repo}`.
  - `deny_gh_api_secrets_variables`: Blocks `POST`/`PUT`/`PATCH`/`DELETE` on `*/actions/secrets*`, `*/actions/variables*`, `*/dependabot/secrets*`, `*/codespaces/secrets*`, and `*/environments/*/secrets|variables*`.
  - `deny_gh_api_protected_ref`: Blocks `PATCH`/`DELETE` on `repos/{owner}/{repo}/git/refs/heads/<protected_branch>`.
  - `deny_gh_api_graphql`: Blocks GraphQL `mergePullRequest` and `deleteRepository` mutations.

## Mandatory Secret Redaction (`redact_secrets`)

All sensitive material is replaced with `[REDACTED]`:

- Explicit runtime secret values passed via `extra_secrets` (such as active installation tokens or JWTs).
- GitHub tokens: `ghs_*`, `ghp_*`, `gho_*`, `ghu_*`, `github_pat_*`.
- Signed JWTs (`eyJ...`).
- PEM private key blocks (`-----BEGIN ... PRIVATE KEY-----` through `-----END ... PRIVATE KEY-----`).

## CLI Reference

```bash
github-app profile policy show --name NAME
github-app profile policy set --name NAME \
  [--protected-branches a,b] \
  [--allow-merge-branches a,b] \
  [--allow-force-push true|false] \
  [--allow-delete-remote-branch true|false]
github-app profile policy reset --name NAME
```
