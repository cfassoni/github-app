# GitHub App MCP Routing Rules

Use the `github-app` MCP server tools instead of `run_command` for authenticated Git remote and GitHub CLI operations:

- **Remote Git operations:** Use `git_clone`, `git_fetch`, `git_pull`, and `git_push` (with explicit `cwd`). Do not run `git clone`, `git fetch`, `git pull`, or `git push` in the sandboxed shell.
- **GitHub CLI (`gh`) operations:** Use `gh_run(cwd, args, ...)` instead of `github-app run gh ...` or `gh ...` in the sandboxed shell. Pass multiline PR/issue bodies via the `body` parameter rather than inline shell flags.
- **Profile inspection & repo binding:** Use `github_app_profiles`, `github_app_status`, and `github_app_init`.
- **Local Git operations:** Keep local-only commands (`git status`, `git add`, `git commit`, `git diff`, `git checkout`, `git switch`, `git branch`, `git log`) in the sandboxed shell.
- **Policy & credential boundary:** Never read or modify `~/.config/github-app/profiles.json`, `~/.cache/github-app/`, or `.pem` files. If a `github-app` MCP tool denies an operation due to policy (such as pushing to `main`, force-pushing, or merging a PR), report the exact rule and remediation to the user rather than attempting workarounds.
