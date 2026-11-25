---
name: github-app
description: "Operate authenticated remote Git and GitHub CLI workflows via the github-app MCP server, resolve repository profiles, pass multiline markdown safely, and handle policy guardrails."
---

# GitHub App MCP Guide

Use the `github-app` MCP server when working with GitHub repositories so authentication, token caching, and security guardrails run cleanly on the host outside the terminal sandbox.

## Tool Surface (8 Tools)

| Tool | Use For | Key Arguments |
| :--- | :--- | :--- |
| `github_app_profiles` | Discover available profile names, git identities, and effective policies. | None |
| `github_app_status` | Verify the active profile for `cwd`, token expiry, and GitHub App permissions. | `cwd` or `profile` |
| `github_app_init` | Bind an existing profile to a checkout (sets local identity and credential helper). | `cwd`, `profile`, optional `repository`, `create` |
| `git_clone` | Clone a repository and bind it to a profile. | `profile`, `repository`, optional `directory`, `cwd` |
| `git_fetch` | Fetch remote refs (`shell=False`). | `cwd`, optional `remote`, `refspec`, `prune`, `tags` |
| `git_pull` | Pull remote updates (`shell=False`). | `cwd`, optional `remote`, `branch`, `rebase`, `ff_only` |
| `git_push` | Push commits subject to profile policy guardrails. | `cwd`, optional `remote`, `refspecs`, `set_upstream`, `force`, `force_with_lease`, `delete` |
| `gh_run` | Run any permitted `gh` command via direct `argv`. | `cwd`, `args`, optional `body`, `body_flag`, `profile` |

## Operational Patterns

### 1. Check Profile Binding First
Call `github_app_status(cwd="<repo>")` when starting GitHub work in an unfamiliar repository. If no profile is configured, list profiles with `github_app_profiles()` and bind one with `github_app_init(cwd="<repo>", profile="<name>")`.

### 2. Multiline Markdown in `gh_run`
When creating or editing PRs, issues, or comments with multiline markdown, backticks, or Unicode, pass the markdown text in `body` instead of inline `--body` arguments:

```json
{
  "cwd": "/path/to/repo",
  "args": ["pr", "create", "--title", "feat: summary"],
  "body": "## Summary\n\n- Supports `gh_run` safely."
}
```

`gh_run` writes `body` to a temporary UTF-8 file, appends `["--body-file", "<temp-path>"]` (or custom `body_flag`), and removes the temp file after execution.

### 3. Policy Guardrails & Remediation
Profile policies default to restrictive guardrails:
- Direct pushes to `main` / `master`, `--force`, `--force-with-lease`, and remote branch deletions are blocked by default.
- `gh auth *`, `gh repo delete`, `gh secret` / `gh variable` mutations, and `gh pr merge` (unless live `baseRefName` is in `allow_merge_branches`) are blocked by default.
- Surgical `gh api` equivalents of blocked operations are also denied.

Policies are human-only and cannot be changed via MCP. When blocked, inform the user of the denied rule; a human can inspect or adjust overrides via:
```bash
github-app profile policy show --name <profile>
github-app profile policy set --name <profile> --allow-merge-branches preview
```
