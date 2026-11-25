# Built-in Stdio MCP Server (`github-app mcp`)

`github-app` includes a built-in Model Context Protocol (MCP) server over `stdio` using JSON-RPC 2.0 and the Python standard library. It allows sandboxed AI coding agents to execute authenticated remote Git operations and `gh` commands on the host without exposing private keys, JWTs, or installation tokens inside the agent's shell environment.

## Starting the Server

```bash
github-app mcp
```

Standard MCP client configuration (`mcp_config.json`):

```json
{
  "mcpServers": {
    "github-app": {
      "command": "github-app",
      "args": ["mcp"]
    }
  }
}
```

## Available Tools (8)

| Tool | Purpose | Required Parameters |
| :--- | :--- | :--- |
| `github_app_profiles` | List configured profile names, git identities, and effective security policies. | — |
| `github_app_status` | Report resolved profile, token expiration, declared permissions, git identity, and policy. | — (`cwd` or `profile`) |
| `github_app_init` | Bind an existing profile to a repository checkout (`cwd`). | `cwd`, `profile` |
| `git_clone` | Clone a repository using an existing profile and configure the local checkout. | `profile`, `repository` |
| `git_fetch` | Run authenticated `git fetch` (`shell=False`). | `cwd` |
| `git_pull` | Run authenticated `git pull` (`shell=False`). | `cwd` |
| `git_push` | Run authenticated `git push` subject to profile policy guardrails. | `cwd` |
| `gh_run` | Run `gh` via direct `argv` (`shell=False`) with optional multiline `body` temp file. | `cwd`, `args` |

## Security Guarantees

- **Human-Only Config Boundary:** Profile creation, `.env` import, and policy mutations (`github-app profile ...`) are CLI-only and never exposed as MCP tools.
- **No Shell Execution:** All `git` and `gh` invocations use direct `argv` execution (`shell=False`).
- **Multiline Body Safety:** `gh_run` accepts `body` text and writes it to a temporary UTF-8 file passed via `--body-file` (or custom `body_flag`), removing the temp file in a `finally` block.
- **Live Merge Target Verification:** When `allow_merge_branches` permits `gh pr merge`, the server queries `gh pr view --json baseRefName` before execution and blocks merges targeting disallowed branches.
- **Mandatory Redaction:** All tool outputs and errors are scrubbed via `redact_secrets` before returning over `stdout`.
