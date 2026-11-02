# github-app

Harness-independent CLI for authenticating Git and GitHub CLI (`gh`) operations in coding-agent projects using ephemeral GitHub App installation tokens.

## Features

- **Zero Long-Lived Personal Tokens**: Mints short-lived (1-hour) GitHub App installation tokens on demand using RS256 JWT signing.
- **Private Key Isolation**: Profile configurations record only the path to the existing `.pem` private key file—never copying private key material into configuration or cache files.
- **Git Credential Helper**: Configures repository-local `credential.helper` so standard `git fetch`, `git pull`, and `git push` authenticate seamlessly over HTTPS.
- **GitHub CLI (`gh`) Wrapper**: `github-app run gh ...` injects `GH_TOKEN` and `GITHUB_TOKEN` into the child process environment without exposing secrets in shell history or prompts.

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
  github-app profiles
  github-app init --profile NAME [--create] [REPOSITORY]
  github-app clone --profile NAME REPOSITORY [DIRECTORY]
  github-app credential-helper get|store|erase
  github-app run [--profile NAME] COMMAND [ARGS...]
  github-app status [--profile NAME]
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
