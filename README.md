# github-app

Harness-independent CLI for authenticating Git and GitHub CLI (`gh`) operations in coding-agent projects using ephemeral GitHub App installation tokens.

## Features

- **Zero Long-Lived Personal Tokens**: Mints short-lived (1-hour) GitHub App installation tokens on demand using RS256 JWT signing.
- **Private Key Isolation**: Profile configurations record only the path to the existing `.pem` private key file—never copying private key material into configuration or cache files.
- **Git Credential Helper**: Configures repository-local `credential.helper` so standard `git fetch`, `git pull`, and `git push` authenticate seamlessly over HTTPS.
- **GitHub CLI (`gh`) Wrapper**: `github-app run gh ...` injects `GH_TOKEN` and `GITHUB_TOKEN` into the child process environment without exposing secrets in shell history or prompts.
- **Profile-Scoped Security Policy & Secret Redaction**: Restrictive default guardrails (blocking force-pushes, remote branch deletions, direct pushes to `main`/`master`, `gh auth *`, `gh repo delete`, `gh pr merge`, `gh secret`/`gh variable` mutations, and direct `gh api` equivalents) with human-only CLI overrides and mandatory redaction of GitHub tokens, JWTs, and PEM blocks.
- **Built-in Stdio MCP Server**: `github-app mcp` exposes 8 policy-enforced tools (`github_app_profiles`, `github_app_status`, `github_app_init`, `git_clone`, `git_fetch`, `git_pull`, `git_push`, `gh_run`) over JSON-RPC 2.0 `stdio` for sandboxed coding agents.

## Installation

Install globally using `uv`:

### Directly from GitHub

```bash
uv tool install git+https://github.com/cfassoni/github-app.git
```

### From Local Source

```bash
uv tool install .
```

### Upgrading

To upgrade to the latest version:

```bash
uv tool upgrade github-app
```

## Usage

```text
GitHub App auth for coding-agent projects

Commands:
  github-app profile import --name NAME --env FILE --git-name NAME --git-email EMAIL
  github-app profile policy show|set|reset --name NAME [OPTIONS]
  github-app profiles
  github-app init --profile NAME [--create] [REPOSITORY]
  github-app clone --profile NAME REPOSITORY [DIRECTORY]
  github-app credential-helper get|store|erase
  github-app run [--profile NAME] COMMAND [ARGS...]
  github-app status [--profile NAME]
  github-app mcp
```

### 1. Import a Profile from `.env`

Your project's ignored `.env` file must define:

```dotenv
GITHUB_APP_ID=336189891
GITHUB_INSTALLATION_ID=12345678
GITHUB_PRIVATE_KEY=~/.ssh/your-app.private-key.pem
```

Import the profile once:

```bash
github-app profile import \
  --name my-project \
  --env .env \
  --git-name 'my-app[bot]' \
  --git-email '336189891+my-app[bot]@users.noreply.github.com'
```

### 2. Initialize an Existing Checkout

```bash
github-app init --profile my-project
```

### 3. Clone a Private Repository

```bash
github-app clone --profile my-project https://github.com/owner/repo.git
```

### 4. Run GitHub CLI (`gh`) Commands

```bash
github-app run gh pr list
github-app run gh issue view 42
```

### 5. Check Token & Profile Status

```bash
github-app status
```

### 6. Manage Profile Security Policy

Each profile in `~/.config/github-app/profiles.json` inherits restrictive defaults that are managed exclusively via the CLI (never mutated by agents):

| Policy Key | Default | Description |
| :--- | :--- | :--- |
| `protected_branches` | `["main", "master"]` | Branches blocked from direct pushes and protected-ref API mutations. |
| `allow_merge_branches` | `[]` | Target PR base branches permitted for `gh pr merge` (empty denies all merges). |
| `allow_force_push` | `false` | Permits `--force`, `--force-with-lease`, or `+refspec` pushes when `true`. |
| `allow_delete_remote_branch` | `false` | Permits `--delete` or `:branch` remote deletions when `true` (protected branches remain blocked). |

Always denied by policy: `gh auth *`, `gh repo delete`, `gh secret`/`gh variable` mutations (only `list` is permitted), and direct `gh api` equivalents (`PUT repos/*/*/pulls/*/merge`, `DELETE repos/*/*`, mutating calls on secrets/variables endpoints, `PATCH`/`DELETE` on protected `git/refs/heads/*`, and GraphQL `mergePullRequest`/`deleteRepository`).

Inspect, override, or reset a profile's policy:

```bash
# Show effective policy and overrides
github-app profile policy show --name my-project

# Allow merging PRs whose live baseRefName is 'preview' and protect 'release'
github-app profile policy set \
  --name my-project \
  --protected-branches main,master,release \
  --allow-merge-branches preview

# Clear a branch list or toggle boolean guardrails
github-app profile policy set \
  --name my-project \
  --allow-merge-branches "" \
  --allow-force-push false \
  --allow-delete-remote-branch false

# Reset to restrictive defaults
github-app profile policy reset --name my-project
```

Re-running `github-app profile import` for an existing profile preserves its stored `policy` overrides. See [docs/security-policy.md](docs/security-policy.md) for the complete rule reference and secret redaction specification.

### 7. Run the Built-in Stdio MCP Server

```bash
github-app mcp
```

See [docs/mcp-server.md](docs/mcp-server.md) for the JSON-RPC 2.0 `stdio` configuration snippet, all 8 MCP tools, and security guarantees.
