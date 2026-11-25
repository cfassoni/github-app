"""Unit and integration tests for Antigravity plugin packaging and CLI management."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from github_app import __version__, cli, plugin


def test_bundled_antigravity_assets_schema() -> None:
    from importlib import resources

    root = resources.files("github_app.plugin_assets.antigravity")
    assert not root.joinpath("hooks.json").is_file()

    manifest = json.loads(root.joinpath("plugin.json").read_text(encoding="utf-8"))
    allowed_keys = {
        "name",
        "displayName",
        "description",
        "version",
        "author",
        "homepage",
        "repository",
        "suggestedPrompts",
        "logo",
        "disabled",
    }
    assert set(manifest.keys()).issubset(allowed_keys)
    assert manifest["name"] == "github-app"
    assert manifest["version"] == __version__
    assert len(manifest["suggestedPrompts"]) == 3

    mcp_cfg = json.loads(root.joinpath("mcp_config.json").read_text(encoding="utf-8"))
    assert mcp_cfg == {
        "mcpServers": {
            "github-app": {
                "command": "github-app",
                "args": ["mcp"],
            }
        }
    }

    rules_text = root.joinpath("rules", "AGENTS.md").read_text(encoding="utf-8")
    assert not rules_text.startswith("---")
    assert "gh_run" in rules_text

    skill_text = root.joinpath("skills", "github-app", "SKILL.md").read_text(encoding="utf-8")
    assert skill_text.startswith("---\nname: github-app\n")


def test_plugin_install_status_uninstall_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugins_dir = tmp_path / "plugins"
    monkeypatch.setenv("GITHUB_APP_ANTIGRAVITY_PLUGINS_DIR", str(plugins_dir))
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/github-app" if cmd == "github-app" else None)

    assert plugin.get_antigravity_plugins_dir() == plugins_dir

    # Status before install
    pre_status = plugin.status_antigravity_plugin()
    assert pre_status["installed"] is False
    assert pre_status["files_ok"] is False

    # Install
    installed = plugin.install_antigravity_plugin()
    assert installed["status"] == "installed"
    assert installed["command_found"] is True
    dest = Path(installed["path"])
    assert (dest / "plugin.json").is_file()
    assert (dest / "mcp_config.json").is_file()
    assert (dest / "rules" / "AGENTS.md").is_file()
    assert (dest / "skills" / "github-app" / "SKILL.md").is_file()

    # Stale files are removed on idempotent reinstall
    stale_file = dest / "stale.txt"
    stale_file.write_text("stale", encoding="utf-8")
    reinstalled = plugin.install_antigravity_plugin()
    assert reinstalled["status"] == "installed"
    assert not stale_file.exists()

    # Status after install
    post_status = plugin.status_antigravity_plugin()
    assert post_status["installed"] is True
    assert post_status["files_ok"] is True
    assert post_status["installed_version"] == __version__
    assert post_status["command_found"] is True

    # Uninstall and uninstall again when absent
    removed = plugin.uninstall_antigravity_plugin()
    assert removed["status"] == "uninstalled"
    assert removed["removed"] is True
    assert not dest.exists()

    not_installed = plugin.uninstall_antigravity_plugin()
    assert not_installed["status"] == "not_installed"
    assert not_installed["removed"] is False


def test_plugin_command_override_and_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugins_dir = tmp_path / "plugins"
    fake_bin = tmp_path / "bin" / "github-app"
    fake_bin.parent.mkdir()
    fake_bin.write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(shutil, "which", lambda _: None)

    # Empty --command fails
    with pytest.raises(ValueError, match="non-empty"):
        plugin.install_antigravity_plugin(target_root=plugins_dir, command="  ")

    # Explicit binary path resolves without PATH
    installed = plugin.install_antigravity_plugin(target_root=plugins_dir, command=str(fake_bin))
    assert installed["command_found"] is True
    mcp_cfg = json.loads((plugins_dir / "github-app" / "mcp_config.json").read_text(encoding="utf-8"))
    assert mcp_cfg["mcpServers"]["github-app"]["command"] == str(fake_bin)

    # Unresolvable command warns on install and status
    warned = plugin.install_antigravity_plugin(target_root=plugins_dir, command="missing-github-app")
    assert warned["command_found"] is False
    assert "warning" in warned

    status_warn = plugin.status_antigravity_plugin(target_root=plugins_dir)
    assert status_warn["command_found"] is False
    assert "warning" in status_warn

    # Corrupt plugin.json / mcp_config.json handled gracefully in status
    (plugins_dir / "github-app" / "plugin.json").write_text("{bad", encoding="utf-8")
    (plugins_dir / "github-app" / "mcp_config.json").write_text("{bad", encoding="utf-8")
    corrupt_status = plugin.status_antigravity_plugin(target_root=plugins_dir)
    assert corrupt_status["installed_version"] is None
    assert corrupt_status["command"] == "github-app"


def test_default_antigravity_plugins_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_APP_ANTIGRAVITY_PLUGINS_DIR", raising=False)
    default_dir = plugin.get_antigravity_plugins_dir()
    assert default_dir.parts[-3:] == (".gemini", "config", "plugins")


def test_plugin_cli_commands_and_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plugins_dir = tmp_path / "plugins"
    monkeypatch.setattr(shutil, "which", lambda _: None)

    assert cli.main(["plugin", "install", "antigravity", "--target", str(plugins_dir)]) == 0
    out, err = capsys.readouterr()
    assert '"status": "installed"' in out
    assert "warning:" in err

    assert cli.main(["plugin", "status", "antigravity", "--target", str(plugins_dir)]) == 0
    out, err = capsys.readouterr()
    assert '"installed": true' in out
    assert "warning:" in err

    assert (
        cli.main(
            [
                "plugin",
                "install",
                "antigravity",
                "--target",
                str(plugins_dir),
                "--command",
                "  ",
            ]
        )
        == 1
    )

    assert cli.main(["plugin", "uninstall", "antigravity", "--target", str(plugins_dir)]) == 0
    out, _ = capsys.readouterr()
    assert '"removed": true' in out

    # CLI validation errors
    assert cli.main(["plugin"]) == 1
    assert cli.main(["plugin", "unknown", "antigravity"]) == 1
    assert cli.main(["plugin", "install"]) == 1
    assert cli.main(["plugin", "install", "vscode"]) == 1
    assert cli.main(["plugin", "install", "antigravity", "--bad"]) == 1
    assert cli.main(["plugin", "status", "antigravity", "extra"]) == 1
