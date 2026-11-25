"""Antigravity global plugin installer and status management."""

from __future__ import annotations

import json
import os
import shutil
from importlib import resources
from pathlib import Path
from typing import Any

from github_app import __version__

PLUGIN_DIR_NAME = "github-app"
SUPPORTED_PLUGIN_TARGETS = ("antigravity",)
ANTIGRAVITY_ASSET_FILES = (
    "plugin.json",
    "mcp_config.json",
    "rules/AGENTS.md",
    "skills/github-app/SKILL.md",
)


def get_antigravity_plugins_dir() -> Path:
    """Return the Antigravity global plugins directory."""
    override = os.environ.get("GITHUB_APP_ANTIGRAVITY_PLUGINS_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".gemini" / "config" / "plugins"


def _resolve_dest_dir(target_root: Path | None = None) -> Path:
    base = (target_root or get_antigravity_plugins_dir()).expanduser().resolve()
    return base / PLUGIN_DIR_NAME


def _check_command_available(command: str) -> str | None:
    found = shutil.which(command)
    if found:
        return found
    candidate = Path(command).expanduser()
    if candidate.is_file():
        return str(candidate.resolve())
    return None


def install_antigravity_plugin(
    *,
    target_root: Path | None = None,
    command: str | None = None,
) -> dict[str, Any]:
    """Install or update the bundled Antigravity plugin into the global plugins folder."""
    if command is not None and not command.strip():
        raise ValueError("'--command' must be a non-empty executable name or path")

    dest_dir = _resolve_dest_dir(target_root)
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    asset_root = resources.files("github_app.plugin_assets.antigravity")
    for rel_path in ANTIGRAVITY_ASSET_FILES:
        src = asset_root.joinpath(*rel_path.split("/"))
        content = src.read_text(encoding="utf-8")
        if rel_path == "mcp_config.json" and command is not None:
            mcp_data = json.loads(content)
            mcp_data["mcpServers"]["github-app"]["command"] = command.strip()
            content = json.dumps(mcp_data, indent=2) + "\n"
        out_path = dest_dir / rel_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")

    effective_command = command.strip() if command is not None else "github-app"
    resolved_cmd = _check_command_available(effective_command)
    result: dict[str, Any] = {
        "status": "installed",
        "target": "antigravity",
        "path": str(dest_dir),
        "version": __version__,
        "command": effective_command,
        "command_found": resolved_cmd is not None,
        "resolved_command": resolved_cmd,
    }
    if resolved_cmd is None:
        result["warning"] = (
            f"Executable '{effective_command}' was not found on PATH; "
            "ensure it is on PATH or reinstall with '--command <path>'."
        )
    return result


def uninstall_antigravity_plugin(*, target_root: Path | None = None) -> dict[str, Any]:
    """Remove the installed Antigravity plugin directory if present."""
    dest_dir = _resolve_dest_dir(target_root)
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
        return {
            "status": "uninstalled",
            "target": "antigravity",
            "removed": True,
            "path": str(dest_dir),
        }
    return {
        "status": "not_installed",
        "target": "antigravity",
        "removed": False,
        "path": str(dest_dir),
    }


def status_antigravity_plugin(*, target_root: Path | None = None) -> dict[str, Any]:
    """Report installation status, versions, asset integrity, and binary resolution."""
    dest_dir = _resolve_dest_dir(target_root)
    installed = dest_dir.is_dir()
    files_ok = installed and all((dest_dir / rel).is_file() for rel in ANTIGRAVITY_ASSET_FILES)

    installed_version: str | None = None
    configured_command = "github-app"
    if installed:
        manifest_path = dest_dir / "plugin.json"
        if manifest_path.is_file():
            try:
                installed_version = json.loads(manifest_path.read_text(encoding="utf-8")).get(
                    "version"
                )
            except (OSError, ValueError):
                installed_version = None
        mcp_path = dest_dir / "mcp_config.json"
        if mcp_path.is_file():
            try:
                mcp_data = json.loads(mcp_path.read_text(encoding="utf-8"))
                cmd_val = mcp_data.get("mcpServers", {}).get("github-app", {}).get("command")
                if isinstance(cmd_val, str) and cmd_val.strip():
                    configured_command = cmd_val.strip()
            except (OSError, ValueError):
                pass

    resolved_cmd = _check_command_available(configured_command)
    result: dict[str, Any] = {
        "target": "antigravity",
        "installed": installed,
        "files_ok": files_ok,
        "path": str(dest_dir),
        "installed_version": installed_version,
        "packaged_version": __version__,
        "command": configured_command,
        "command_found": resolved_cmd is not None,
        "resolved_command": resolved_cmd,
    }
    if installed and resolved_cmd is None:
        result["warning"] = (
            f"Executable '{configured_command}' was not found on PATH; "
            "ensure it is on PATH or reinstall with '--command <path>'."
        )
    return result
