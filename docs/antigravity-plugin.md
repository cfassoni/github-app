# Antigravity Global Plugin

`github-app` ships a bundled Antigravity plugin inside the Python wheel so users can enable sandbox-free authenticated Git and `gh` operations in two commands:

```bash
uv tool install --force git+https://github.com/cfassoni/github-app.git
github-app plugin install antigravity
```

## Installed Bundle Layout

`github-app plugin install antigravity` copies the packaged assets into `~/.gemini/config/plugins/github-app/` (overridable via `GITHUB_APP_ANTIGRAVITY_PLUGINS_DIR` or `--target`):

```text
~/.gemini/config/plugins/github-app/
├── plugin.json
├── mcp_config.json
├── rules/
│   └── AGENTS.md
└── skills/
    └── github-app/
        └── SKILL.md
```

- **Zero `hooks.json`:** No synchronous `PreToolUse` shell hooks are installed.
- **Zero `config.json` mutation:** The installer never edits `~/.gemini/config/config.json`; enable/disable state remains managed cleanly by Antigravity.
- **Portable `mcp_config.json`:** Defaults to `"command": "github-app", "args": ["mcp"]`. If `github-app` is not on the host `PATH`, `install` and `status` emit a warning and you can pass `--command <path>` on install.

## CLI Reference

```bash
# Install or update the Antigravity global plugin
github-app plugin install antigravity [--target DIR] [--command PATH]

# Inspect installation status, packaged vs installed version, and PATH resolution
github-app plugin status antigravity [--target DIR]

# Uninstall the plugin directory
github-app plugin uninstall antigravity [--target DIR]
```
