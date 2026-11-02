"""Unit and integration tests for github-app CLI."""

from __future__ import annotations

import io
import json
import subprocess
import urllib.error
from pathlib import Path
from typing import Any, Self

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from github_app import cli


@pytest.fixture
def rsa_pem_file(tmp_path: Path) -> Path:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_file = tmp_path / "test-app.pem"
    key_file.write_bytes(pem_bytes)
    return key_file


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rsa_pem_file: Path) -> dict[str, Path]:
    config_dir = tmp_path / "config"
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GITHUB_APP_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("GITHUB_APP_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("GITHUB_APP_BIN", "/usr/local/bin/github-app")
    monkeypatch.delenv("GITHUB_APP_PROFILE", raising=False)

    env_file = tmp_path / ".env"
    env_file.write_text(
        f"# Sample comment\n"
        f"export GITHUB_APP_ID='336189891'\n"
        f'GITHUB_INSTALLATION_ID="99887766"\n'
        f"GITHUB_PRIVATE_KEY={rsa_pem_file.as_posix()}\n",
        encoding="utf-8",
    )
    return {
        "tmp": tmp_path,
        "config": config_dir,
        "cache": cache_dir,
        "env": env_file,
        "pem": rsa_pem_file,
    }


def _mock_urlopen_factory(response_dict: dict[str, Any], status: int = 201):
    class DummyResp:
        def __init__(self) -> None:
            self.status = status

        def read(self) -> bytes:
            return json.dumps(response_dict).encode("utf-8")

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            pass

    def _urlopen(req: Any, timeout: int = 30) -> DummyResp:
        return DummyResp()

    return _urlopen


def test_help_and_unknown_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 0
    out, _ = capsys.readouterr()
    assert "GitHub App auth for coding-agent projects" in out
    assert "github-app profile import" in out

    assert cli.main(["--help"]) == 0
    out, _ = capsys.readouterr()
    assert "github-app credential-helper get|store|erase" in out

    assert cli.main(["nonexistent"]) == 1
    _, err = capsys.readouterr()
    assert "github-app: unknown command 'nonexistent'" in err


def test_profile_import_and_profiles_list(
    isolated_env: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main(
        [
            "profile",
            "import",
            "--name",
            "fiainvest-mcp",
            "--env",
            str(isolated_env["env"]),
            "--git-name",
            "cfassoni-ai[bot]",
            "--git-email",
            "336189891+cfassoni-ai[bot]@users.noreply.github.com",
        ]
    )
    assert rc == 0

    assert cli.main(["profiles"]) == 0
    out, _ = capsys.readouterr()
    assert out.strip() == "fiainvest-mcp"

    profiles_data = cli.load_profiles()
    assert profiles_data["fiainvest-mcp"]["app_id"] == "336189891"
    assert profiles_data["fiainvest-mcp"]["installation_id"] == "99887766"
    assert profiles_data["fiainvest-mcp"]["private_key_path"] == isolated_env["pem"].as_posix()
    assert "BEGIN" not in json.dumps(profiles_data)


def test_profile_import_errors(
    isolated_env: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["profile", "other"]) == 1
    assert cli.main(["profile", "import", "--name", "only-name"]) == 1
    assert cli.main(["profile", "import", "--bad-flag"]) == 1
    assert cli.main(["profiles", "extra"]) == 1

    missing_env = isolated_env["tmp"] / "missing.env"
    assert cli.main(["profile", "import", "--name", "p", "--env", str(missing_env)]) == 1

    incomplete_env = isolated_env["tmp"] / "incomplete.env"
    incomplete_env.write_text("GITHUB_APP_ID=123\n", encoding="utf-8")
    assert cli.main(["profile", "import", "--name", "p", "--env", str(incomplete_env)]) == 1
    _, err = capsys.readouterr()
    assert "must define GITHUB_APP_ID" in err


def test_corrupt_profiles_json(isolated_env: dict[str, Path]) -> None:
    profiles_file = cli.get_profiles_file()
    profiles_file.parent.mkdir(parents=True, exist_ok=True)
    profiles_file.write_text("{corrupt", encoding="utf-8")
    with pytest.raises(cli.CLIError, match="failed to read profiles"):
        cli.load_profiles()

    profiles_file.write_text("[]", encoding="utf-8")
    assert cli.load_profiles() == {}


def test_jwt_and_key_validation(isolated_env: dict[str, Path], tmp_path: Path) -> None:
    inline_pem = isolated_env["pem"].read_text(encoding="utf-8").replace("\n", "\\n")
    key_bytes = cli.load_private_key_bytes(inline_pem)
    token = cli.generate_app_jwt("336189891", key_bytes, now=1700000000)
    assert len(token.split(".")) == 3

    with pytest.raises(cli.CLIError, match="private key file not found"):
        cli.load_private_key_bytes(str(tmp_path / "nope.pem"))

    with pytest.raises(cli.CLIError, match="invalid PEM private key"):
        cli.generate_app_jwt("123", b"not-a-pem")

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(cli.CLIError, match="must be an RSA private key"):
        cli.generate_app_jwt("123", ec_pem)


def test_status_and_token_caching(
    isolated_env: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(
        [
            "profile",
            "import",
            "--name",
            "recomp-pro-core",
            "--env",
            str(isolated_env["env"]),
            "--git-name",
            "cfassoni-ai[bot]",
            "--git-email",
            "336189891+cfassoni-ai[bot]@users.noreply.github.com",
        ]
    )

    calls = 0

    def fake_urlopen(req: Any, timeout: int = 30) -> Any:
        nonlocal calls
        calls += 1
        return _mock_urlopen_factory(
            {
                "token": "ghs_test_ephemeral_token_123",
                "expires_at": "2099-10-11T17:26:18Z",
                "permissions": {
                    "contents": "write",
                    "issues": "write",
                    "metadata": "read",
                    "pull_requests": "write",
                    "workflows": "write",
                },
            }
        )(req, timeout)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    assert cli.main(["status", "--profile", "recomp-pro-core"]) == 0
    out, _ = capsys.readouterr()
    assert "Profile: recomp-pro-core" in out
    assert "Expires: 2099-10-11T17:26:18Z" in out
    assert (
        'Permissions: {"contents":"write","issues":"write","metadata":"read","pull_requests":"write","workflows":"write"}'
        in out
    )
    assert "Git identity: cfassoni-ai[bot] <336189891+cfassoni-ai[bot]@users.noreply.github.com>" in out
    assert calls == 1

    # Second call uses cached token
    assert cli.main(["status", "--profile", "recomp-pro-core"]) == 0
    assert calls == 1

    # Corrupt cache file falls back to fetching a fresh token
    cache_file = cli.get_cache_dir() / "tokens" / "recomp-pro-core.json"
    cache_file.write_text("{corrupt-cache", encoding="utf-8")
    assert cli.main(["status", "--profile", "recomp-pro-core"]) == 0
    assert calls == 2

    assert cli.main(["status", "--bad"]) == 1


def test_credential_helper(
    isolated_env: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(["profile", "import", "--name", "fiainvest-mcp", "--env", str(isolated_env["env"])])
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        _mock_urlopen_factory(
            {
                "token": "ghs_cred_token_456",
                "expires_at": "invalid-date-format",
                "permissions": {"contents": "write"},
            }
        ),
    )

    # Ignore store/erase
    assert cli.main(["credential-helper", "store"]) == 0
    assert cli.main(["credential-helper", "erase", "--other"]) == 0

    # Ignore non-github host
    monkeypatch.setattr("sys.stdin", io.StringIO("protocol=https\nhost=gitlab.com\n"))
    assert cli.main(["credential-helper", "get", "--profile", "fiainvest-mcp"]) == 0
    out, _ = capsys.readouterr()
    assert out == ""

    # Missing profile fails with code 1
    monkeypatch.setattr("sys.stdin", io.StringIO("protocol=https\nhost=github.com\n"))
    assert cli.main(["credential-helper", "get", "--profile", "unknown-prof"]) == 1

    # Valid get with GITHUB_APP_PROFILE env
    monkeypatch.setenv("GITHUB_APP_PROFILE", "fiainvest-mcp")
    monkeypatch.setattr("sys.stdin", io.StringIO("protocol=https\nhost=github.com\n"))
    assert cli.main(["credential-helper", "get"]) == 0
    out, _ = capsys.readouterr()
    assert "username=x-access-token" in out
    assert "password=ghs_cred_token_456" in out


def test_init_and_repo_profile_resolution(
    isolated_env: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli.main(
        [
            "profile",
            "import",
            "--name",
            "fiainvest-mcp",
            "--env",
            str(isolated_env["env"]),
            "--git-name",
            "cfassoni-ai[bot]",
            "--git-email",
            "336189891+cfassoni-ai[bot]@users.noreply.github.com",
        ]
    )
    repo_dir = isolated_env["tmp"] / "sample-repo"
    repo_dir.mkdir()
    monkeypatch.chdir(repo_dir)

    assert cli.main(["init"]) == 1
    assert cli.main(["init", "--profile", "fiainvest-mcp", "--bad"]) == 1

    # Initialize git and configure origin via shorthand
    assert cli.main(["init", "--profile", "fiainvest-mcp", "cfassoni/sample-repo"]) == 0
    assert (repo_dir / ".git").exists()
    assert cli.resolve_profile_name() == "fiainvest-mcp"

    # Second init updates existing origin URL
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        _mock_urlopen_factory(
            {
                "token": "ghs_create_tok",
                "expires_at": "2099-01-01T00:00:00Z",
                "clone_url": "https://github.com/cfassoni/sample-repo.git",
            }
        ),
    )
    assert cli.main(["init", "--profile", "fiainvest-mcp", "--create", "cfassoni/sample-repo"]) == 0

    # Init passing explicit target directory path
    sub_repo = isolated_env["tmp"] / "sub-repo"
    sub_repo.mkdir()
    assert cli.main(["init", "--profile", "fiainvest-mcp", str(sub_repo)]) == 0
    assert cli.resolve_profile_name(cwd=sub_repo) == "fiainvest-mcp"

    # Run command inside initialized repo without --profile
    assert (
        cli.main(
            [
                "run",
                "--",
                "git",
                "config",
                "--local",
                "--get",
                "user.name",
            ]
        )
        == 0
    )
    assert cli.main(["run", "--profile", "fiainvest-mcp"]) == 1


def test_clone_command(
    isolated_env: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli.main(
        [
            "profile",
            "import",
            "--name",
            "fiainvest-mcp",
            "--env",
            str(isolated_env["env"]),
            "--git-name",
            "cfassoni-ai[bot]",
            "--git-email",
            "336189891+cfassoni-ai[bot]@users.noreply.github.com",
        ]
    )

    # Create a local bare repo to clone from
    bare_repo = isolated_env["tmp"] / "remote.git"
    subprocess.run(["git", "init", "--bare", str(bare_repo)], check=True)

    work_dir = isolated_env["tmp"] / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)

    assert cli.main(["clone", "--profile", "fiainvest-mcp"]) == 1
    assert cli.main(["clone", "--profile", "fiainvest-mcp", "--unknown"]) == 1

    dest = work_dir / "cloned-repo"
    assert cli.main(["clone", "--profile", "fiainvest-mcp", str(bare_repo), str(dest)]) == 0
    assert (dest / ".git").exists()
    assert cli.resolve_profile_name(cwd=dest) == "fiainvest-mcp"

    # Default directory name deduction
    assert cli.main(["clone", "--profile", "fiainvest-mcp", str(bare_repo)]) == 0
    assert (work_dir / "remote" / ".git").exists()

    # Failing clone returns non-zero exit code
    assert cli.main(["clone", "--profile", "fiainvest-mcp", "file:///nonexistent/repo.git"]) != 0


def test_http_errors_and_url_helpers(
    isolated_env: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert cli.normalize_repository_url("https://github.com/a/b.git") == "https://github.com/a/b.git"
    assert cli.normalize_repository_url("owner/repo") == "https://github.com/owner/repo.git"
    assert cli.extract_repo_slug("https://github.com/owner/repo.git") == "owner/repo"
    assert cli.extract_repo_slug("git@github.com:owner/repo.git") == "owner/repo"
    assert cli.extract_repo_slug("singleword") is None

    def raise_http_422(req: Any, timeout: int = 30) -> Any:
        raise urllib.error.HTTPError(
            req.full_url, 422, "Unprocessable", hdrs=None, fp=io.BytesIO(b"exists")
        )

    monkeypatch.setattr(urllib.request, "urlopen", raise_http_422)
    assert cli.create_github_repository("tok", "owner/repo") == "https://github.com/owner/repo.git"

    def raise_http_500(req: Any, timeout: int = 30) -> Any:
        raise urllib.error.HTTPError(
            req.full_url, 500, "Server Error", hdrs=None, fp=io.BytesIO(b"boom")
        )

    monkeypatch.setattr(urllib.request, "urlopen", raise_http_500)
    with pytest.raises(cli.CLIError, match="failed to create repository"):
        cli.create_github_repository("tok", "owner/repo")

    with pytest.raises(cli.CLIError, match="GitHub API error"):
        cli.request_installation_token("99", "jwt")

    def raise_generic(req: Any, timeout: int = 30) -> Any:
        raise RuntimeError("network down")

    monkeypatch.setattr(urllib.request, "urlopen", raise_generic)
    with pytest.raises(cli.CLIError, match="failed to request installation token"):
        cli.request_installation_token("99", "jwt")


def test_default_dirs_and_executable_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("GITHUB_APP_CONFIG_DIR", raising=False)
    monkeypatch.delenv("GITHUB_APP_CACHE_DIR", raising=False)
    monkeypatch.delenv("GITHUB_APP_BIN", raising=False)

    assert cli.get_config_dir().name == "github-app"
    assert cli.get_cache_dir().name == "github-app"

    monkeypatch.setattr("shutil.which", lambda _: "/custom/bin/github-app")
    assert "github-app" in cli.resolve_executable_for_git()

    monkeypatch.setattr("shutil.which", lambda _: None)
    assert "github-app" in cli.resolve_executable_for_git()

    monkeypatch.chdir(tmp_path)
    with pytest.raises(cli.CLIError, match="no profile specified"):
        cli.resolve_profile_name()

