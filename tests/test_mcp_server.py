"""Unit and integration tests for the built-in stdio MCP server."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Any, Self

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from github_app import cli, mcp_server


@pytest.fixture
def mcp_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_file = tmp_path / "test-app.pem"
    key_file.write_bytes(pem_bytes)

    config_dir = tmp_path / "config"
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GITHUB_APP_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("GITHUB_APP_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("GITHUB_APP_BIN", "/usr/local/bin/github-app")
    monkeypatch.delenv("GITHUB_APP_PROFILE", raising=False)

    env_file = tmp_path / ".env"
    env_file.write_text(
        f"GITHUB_APP_ID=336189891\n"
        f"GITHUB_INSTALLATION_ID=99887766\n"
        f"GITHUB_PRIVATE_KEY={key_file.as_posix()}\n",
        encoding="utf-8",
    )
    assert (
        cli.main(
            [
                "profile",
                "import",
                "--name",
                "demo",
                "--env",
                str(env_file),
                "--git-name",
                "cfassoni-ai[bot]",
                "--git-email",
                "336189891+cfassoni-ai[bot]@users.noreply.github.com",
            ]
        )
        == 0
    )

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init", "-b", "feat/demo", str(repo_dir)], check=True, capture_output=True)
    cli.init_repository("demo", cwd=repo_dir)

    return {"tmp": tmp_path, "config": config_dir, "cache": cache_dir, "repo": repo_dir, "pem": key_file}


def _mock_token_urlopen(token: str = "ghs_secret_token_9876543210"):
    class DummyResp:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "token": token,
                    "expires_at": "2099-01-01T00:00:00Z",
                    "permissions": {"contents": "write", "pull_requests": "write"},
                }
            ).encode("utf-8")

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            pass

    return lambda req, timeout=30: DummyResp()


def _call_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    resp = mcp_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert resp is not None
    return resp["result"]


def test_stdio_protocol_lifecycle_and_errors() -> None:
    lines = "\n".join(
        [
            "",
            "{invalid json",
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"},
                }
            ),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "unknown/method"}),
        ]
    )
    stdin = io.StringIO(lines + "\n")
    stdout = io.StringIO()
    assert mcp_server.serve_stdio(stdin=stdin, stdout=stdout) == 0

    responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert len(responses) == 5
    assert responses[0]["error"]["code"] == -32700
    assert responses[1]["result"]["protocolVersion"] == "2024-11-05"
    assert responses[2]["result"] == {}
    tool_names = [t["name"] for t in responses[3]["result"]["tools"]]
    assert tool_names == [
        "github_app_profiles",
        "github_app_status",
        "github_app_init",
        "git_clone",
        "git_fetch",
        "git_pull",
        "git_push",
        "gh_run",
    ]
    assert responses[4]["error"]["code"] == -32601


def test_jsonrpc_validation_edge_cases() -> None:
    assert mcp_server.handle_message("not-a-dict")["error"]["code"] == -32600
    assert mcp_server.handle_message({"jsonrpc": "2.0", "id": True, "method": "ping"})["error"]["code"] == -32600
    assert mcp_server.handle_message({"jsonrpc": "2.0", "id": 1})["error"]["code"] == -32600
    assert mcp_server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": []})["error"]["code"] == -32602

    init_fallback = mcp_server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}
    )
    assert init_fallback["result"]["protocolVersion"] == mcp_server.DEFAULT_PROTOCOL_VERSION

    assert (
        mcp_server.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "nope"}}
        )["error"]["code"]
        == -32602
    )
    assert (
        mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "github_app_profiles", "arguments": "bad"},
            }
        )["error"]["code"]
        == -32602
    )


def test_profiles_status_and_init_tools(mcp_env: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    res = _call_tool("github_app_profiles")
    assert res["isError"] is False
    profiles_payload = json.loads(res["content"][0]["text"])
    assert profiles_payload["profiles"][0]["name"] == "demo"
    assert "private_key_path" not in json.dumps(profiles_payload)

    # Extra arguments rejected
    bad_profiles = _call_tool("github_app_profiles", {"extra": 1})
    assert bad_profiles["isError"] is True

    # Invalid policy in profiles.json reports cleanly
    profiles = cli.load_profiles()
    profiles["demo"]["policy"] = {"unknown": True}
    cli.save_profiles(profiles)
    assert _call_tool("github_app_profiles")["isError"] is True
    profiles["demo"].pop("policy")
    cli.save_profiles(profiles)

    monkeypatch.setattr(urllib.request, "urlopen", _mock_token_urlopen())
    status_res = _call_tool("github_app_status", {"cwd": str(mcp_env["repo"])})
    assert status_res["isError"] is False
    status_payload = json.loads(status_res["content"][0]["text"])
    assert status_payload["profile"] == "demo"
    assert status_payload["policy"]["protected_branches"] == ["main", "master"]
    assert "ghs_" not in json.dumps(status_payload)

    # Corrupt cache file is handled cleanly by _collect_cached_secret
    cache_file = mcp_env["cache"] / "tokens" / "demo.json"
    cache_file.write_text("{corrupt", encoding="utf-8")
    assert mcp_server._collect_cached_secret("demo") == []

    # Valid cache file yields token for secret redaction
    cache_file.write_text(json.dumps({"token": "ghs_cached_tok_1234567890"}), encoding="utf-8")
    assert mcp_server._collect_cached_secret("demo") == ["ghs_cached_tok_1234567890"]

    # Input validation edge cases across helpers
    assert _call_tool("github_app_init", {"cwd": str(mcp_env["repo"]), "profile": ""})["isError"] is True
    assert _call_tool("github_app_status", {"profile": 123})["isError"] is True
    assert _call_tool("github_app_init", {"cwd": str(mcp_env["repo"]), "profile": "demo", "create": "yes"})["isError"] is True

    # github_app_init on a new directory
    new_dir = mcp_env["tmp"] / "new-checkout"
    new_dir.mkdir()
    init_res = _call_tool(
        "github_app_init",
        {"cwd": str(new_dir), "profile": "demo", "repository": "cfassoni/new-checkout"},
    )
    assert init_res["isError"] is False
    assert cli.resolve_profile_name(cwd=new_dir) == "demo"

    # Missing directory rejected
    missing_res = _call_tool("github_app_init", {"cwd": str(mcp_env["tmp"] / "nope"), "profile": "demo"})
    assert missing_res["isError"] is True
    assert "Directory does not exist" in missing_res["content"][0]["text"]


def test_git_clone_fetch_pull_and_push_tools(
    mcp_env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    real_run = subprocess.run

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["git", "config"]:
            return real_run(cmd, **kwargs)
        calls.append(cmd)
        if cmd[:3] == [cmd[0], "rev-parse", "--abbrev-ref"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="feat/demo\n", stderr="")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="ok ghs_secret_token_9876543210",
            stderr="",
        )

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(cli, "configure_git_repo", lambda *a, **kw: None)

    clone_res = _call_tool(
        "git_clone",
        {"profile": "demo", "repository": "cfassoni/demo", "cwd": str(mcp_env["tmp"])},
    )
    assert clone_res["isError"] is False
    clone_payload = json.loads(clone_res["content"][0]["text"])
    assert "[REDACTED]" in clone_payload["stdout"]
    assert "ghs_secret_token_9876543210" not in clone_payload["stdout"]

    fetch_res = _call_tool(
        "git_fetch",
        {"cwd": str(mcp_env["repo"]), "refspec": "main", "prune": True, "tags": True},
    )
    assert fetch_res["isError"] is False
    assert calls[-1][-5:] == ["fetch", "--prune", "--tags", "origin", "main"]

    pull_res = _call_tool(
        "git_pull",
        {"cwd": str(mcp_env["repo"]), "branch": "feat/demo", "rebase": True},
    )
    assert pull_res["isError"] is False
    assert calls[-1][-4:] == ["pull", "--rebase", "origin", "feat/demo"]

    assert (
        _call_tool(
            "git_pull",
            {"cwd": str(mcp_env["repo"]), "ff_only": True},
        )["isError"]
        is False
    )
    assert calls[-1][-2:] == ["pull", "--ff-only"]

    bad_pull = _call_tool(
        "git_pull",
        {"cwd": str(mcp_env["repo"]), "rebase": True, "ff_only": True},
    )
    assert bad_pull["isError"] is True

    # Allowed feature branch push with set_upstream
    push_res = _call_tool(
        "git_push",
        {"cwd": str(mcp_env["repo"]), "set_upstream": True},
    )
    assert push_res["isError"] is False
    assert calls[-1][-4:] == ["push", "--set-upstream", "origin", "feat/demo"]

    # Default remote inferred when refspecs provided
    assert (
        _call_tool("git_push", {"cwd": str(mcp_env["repo"]), "refspecs": ["feat/demo"]})["isError"]
        is False
    )
    assert calls[-1][-3:] == ["push", "origin", "feat/demo"]

    # Blocked push to main
    blocked_push = _call_tool(
        "git_push",
        {"cwd": str(mcp_env["repo"]), "refspecs": ["HEAD:main"]},
    )
    assert blocked_push["isError"] is True
    assert "protected_branch" in blocked_push["content"][0]["text"]

    # Blocked force push
    blocked_force = _call_tool(
        "git_push",
        {"cwd": str(mcp_env["repo"]), "force": True},
    )
    assert blocked_force["isError"] is True
    assert "deny_force_push" in blocked_force["content"][0]["text"]

    # Invalid refspecs and invalid profile policy fail cleanly
    assert _call_tool("git_push", {"cwd": str(mcp_env["repo"]), "refspecs": [""]})["isError"] is True
    assert _call_tool("git_push", {"cwd": str(mcp_env["repo"]), "force": "yes"})["isError"] is True

    profiles = cli.load_profiles()
    profiles["demo"]["policy"] = {"allow_force_push": True, "allow_delete_remote_branch": True}
    cli.save_profiles(profiles)
    assert (
        _call_tool(
            "git_push",
            {
                "cwd": str(mcp_env["repo"]),
                "force": True,
                "force_with_lease": True,
                "delete": True,
                "refspecs": ["feat/old"],
            },
        )["isError"]
        is False
    )

    profiles["demo"]["policy"] = {"bad": 1}
    cli.save_profiles(profiles)
    assert _call_tool("git_push", {"cwd": str(mcp_env["repo"])})["isError"] is True


def test_git_push_detached_head_and_missing_binary(
    mcp_env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    real_run = subprocess.run

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["git", "config"]:
            return real_run(cmd, **kwargs)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not a head")

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", fake_run)
    res = _call_tool("git_push", {"cwd": str(mcp_env["repo"])})
    assert res["isError"] is True
    assert "unresolved_push_target" in res["content"][0]["text"]

    monkeypatch.setattr(shutil, "which", lambda name: None)
    missing_bin = _call_tool("git_fetch", {"cwd": str(mcp_env["repo"])})
    assert missing_bin["isError"] is True
    assert "executable not found on PATH" in missing_bin["content"][0]["text"]


def test_gh_run_body_file_policy_and_redaction(
    mcp_env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", _mock_token_urlopen("ghs_live_tok_1234567890"))
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/gh")

    observed_body_files: list[Path] = []
    observed_envs: list[dict[str, str]] = []
    real_run = subprocess.run

    def fake_gh_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["git", "config"]:
            return real_run(cmd, **kwargs)
        observed_envs.append(kwargs["env"])
        if cmd[1:3] == ["pr", "view"]:
            if "99" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")
            return subprocess.CompletedProcess(cmd, 0, stdout="preview\n", stderr="")
        if "--body-file" in cmd:
            body_path = Path(cmd[cmd.index("--body-file") + 1])
            observed_body_files.append(body_path)
            assert body_path.exists()
            assert "Line 1\nLine 2 `code`" in body_path.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="created with ghs_live_tok_1234567890",
            stderr="note eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxIn0.c2lnbmF0dXJl",
        )

    monkeypatch.setattr(subprocess, "run", fake_gh_run)

    # Multiline body creates temp --body-file and cleans it up afterwards
    res = _call_tool(
        "gh_run",
        {
            "cwd": str(mcp_env["repo"]),
            "args": ["pr", "create", "--title", "My PR"],
            "body": "Line 1\nLine 2 `code`",
        },
    )
    assert res["isError"] is False
    assert len(observed_body_files) == 1
    assert not observed_body_files[0].exists()
    assert observed_envs[-1]["GH_TOKEN"] == "ghs_live_tok_1234567890"
    payload = json.loads(res["content"][0]["text"])
    assert "ghs_live_tok_1234567890" not in payload["stdout"]
    assert "eyJ" not in payload["stderr"]

    # Blocked gh pr merge by default
    blocked_merge = _call_tool(
        "gh_run",
        {"cwd": str(mcp_env["repo"]), "args": ["pr", "merge", "12"]},
    )
    assert blocked_merge["isError"] is True
    assert "deny_gh_pr_merge" in blocked_merge["content"][0]["text"]

    # Enable allow_merge_branches=["preview"] and verify live baseRefName lookup
    profiles = cli.load_profiles()
    profiles["demo"]["policy"] = {"allow_merge_branches": ["preview"]}
    cli.save_profiles(profiles)

    ok_merge = _call_tool(
        "gh_run",
        {"cwd": str(mcp_env["repo"]), "args": ["pr", "merge", "12", "-R", "cfassoni/github-app"]},
    )
    assert ok_merge["isError"] is False

    failed_view_merge = _call_tool(
        "gh_run",
        {"cwd": str(mcp_env["repo"]), "args": ["pr", "merge", "99"]},
    )
    assert failed_view_merge["isError"] is True
    assert "unresolved_pr_base" in failed_view_merge["content"][0]["text"]

    # Input validation & corrupt policy errors
    assert _call_tool("gh_run", {"cwd": str(mcp_env["repo"]), "args": []})["isError"] is True
    assert (
        _call_tool("gh_run", {"cwd": str(mcp_env["repo"]), "args": ["pr", "list"], "body": 123})[
            "isError"
        ]
        is True
    )
    assert (
        _call_tool("gh_run", {"cwd": str(mcp_env["repo"]), "args": ["pr", "list"], "profile": 123})[
            "isError"
        ]
        is True
    )

    profiles["demo"]["policy"] = {"bad": 1}
    cli.save_profiles(profiles)
    assert _call_tool("gh_run", {"cwd": str(mcp_env["repo"]), "args": ["pr", "list"]})["isError"] is True


def test_call_tool_unexpected_exception_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(args: dict[str, Any], secrets: list[str]) -> tuple[str, bool]:
        secrets.append("top-secret-runtime-val")
        raise RuntimeError("crash with top-secret-runtime-val")

    monkeypatch.setitem(mcp_server.TOOL_HANDLERS, "github_app_profiles", boom)
    res = _call_tool("github_app_profiles")
    assert res["isError"] is True
    assert "top-secret-runtime-val" not in res["content"][0]["text"]
    assert "[REDACTED]" in res["content"][0]["text"]
