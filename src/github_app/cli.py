"""CLI implementation for github-app."""

from __future__ import annotations

import base64
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

HELP_TEXT = """GitHub App auth for coding-agent projects

Commands:
  github-app profile import --name NAME --env FILE --git-name NAME --git-email EMAIL
  github-app profiles
  github-app init --profile NAME [--create] [REPOSITORY]
  github-app clone --profile NAME REPOSITORY [DIRECTORY]
  github-app credential-helper get|store|erase
  github-app run [--profile NAME] COMMAND [ARGS...]
  github-app status [--profile NAME]

Profiles contain App/installation IDs, a private-key file path, and the local Git
commit identity. The key itself stays in its existing file. Tokens are cached
privately and expire automatically."""


class CLIError(Exception):
    """Expected CLI error reported to stderr with exit code 1."""


def get_config_dir() -> Path:
    override = os.environ.get("GITHUB_APP_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "github-app"


def get_cache_dir() -> Path:
    override = os.environ.get("GITHUB_APP_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".cache" / "github-app"


def get_profiles_file() -> Path:
    return get_config_dir() / "profiles.json"


def _secure_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2, sort_keys=True) + "\n"
    path.write_text(content, encoding="utf-8")
    if os.name != "nt":  # pragma: no cover - POSIX file mode hardening
        path.chmod(0o600)


def load_profiles() -> dict[str, dict[str, str]]:
    profiles_file = get_profiles_file()
    if not profiles_file.exists():
        return {}
    try:
        data = json.loads(profiles_file.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception as exc:
        raise CLIError(f"github-app: failed to read profiles ({exc})") from exc
    return {}


def save_profiles(profiles: dict[str, dict[str, str]]) -> None:
    _secure_write_json(get_profiles_file(), profiles)


def parse_env_file(env_path: Path) -> dict[str, str]:
    if not env_path.exists():
        raise CLIError(f"github-app: env file not found: {env_path}")
    env_vars: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, val = line.split("=", 1)
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        env_vars[key.strip()] = val
    return env_vars


def resolve_git_Profile_from_repo(cwd: Path | None = None) -> str | None:
    proc = subprocess.run(
        ["git", "config", "--local", "--get", "github-app.profile"],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return None


def resolve_profile_name(explicit_profile: str | None = None, cwd: Path | None = None) -> str:
    if explicit_profile:
        return explicit_profile
    env_profile = os.environ.get("GITHUB_APP_PROFILE")
    if env_profile:
        return env_profile
    repo_profile = resolve_git_Profile_from_repo(cwd=cwd)
    if repo_profile:
        return repo_profile
    raise CLIError(
        "github-app: no profile specified and no 'github-app.profile' configured in current repo"
    )


def get_profile(profile_name: str) -> dict[str, str]:
    profiles = load_profiles()
    if profile_name not in profiles:
        raise CLIError(f"github-app: profile '{profile_name}' not found")
    return profiles[profile_name]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_private_key_bytes(pk_val: str) -> bytes:
    expanded = Path(os.path.expanduser(pk_val))
    if expanded.exists() and expanded.is_file():
        return expanded.read_bytes()
    if "BEGIN" in pk_val and "PRIVATE KEY" in pk_val:
        return pk_val.replace("\\n", "\n").encode("utf-8")
    raise CLIError(f"github-app: private key file not found: {pk_val}")


def generate_app_jwt(app_id: str, pk_bytes: bytes, now: int | None = None) -> str:
    current_time = int(time.time()) if now is None else now
    try:
        private_key = load_pem_private_key(pk_bytes, password=None)
    except Exception as exc:
        raise CLIError(f"github-app: invalid PEM private key ({exc})") from exc

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CLIError("github-app: private key must be an RSA private key")

    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": current_time - 60, "exp": current_time + 540, "iss": str(app_id)}
    segments = [
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    ]
    signing_input = ".".join(segments).encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{segments[0]}.{segments[1]}.{_b64url(signature)}"


def request_installation_token(installation_id: str, jwt_token: str) -> dict[str, Any]:
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    req = urllib.request.Request(
        url,
        data=b"",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "github-app-cli",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise CLIError(f"github-app: GitHub API error ({exc.code}): {detail}") from exc
    except Exception as exc:
        raise CLIError(f"github-app: failed to request installation token ({exc})") from exc


def get_token_data(profile_name: str, force_refresh: bool = False) -> dict[str, Any]:
    profile = get_profile(profile_name)
    cache_file = get_cache_dir() / "tokens" / f"{profile_name}.json"
    now = int(time.time())

    if not force_refresh and cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if cached.get("token") and int(cached.get("expires_at_epoch", 0)) > (now + 120):
                return cached
        except (OSError, ValueError, TypeError):
            pass

    pk_ref = profile.get("private_key_path") or profile.get("private_key", "")
    pk_bytes = load_private_key_bytes(pk_ref)
    jwt_token = generate_app_jwt(profile["app_id"], pk_bytes, now=now)
    resp_data = request_installation_token(profile["installation_id"], jwt_token)

    token = resp_data["token"]
    expires_at = resp_data.get("expires_at", "")
    permissions = resp_data.get("permissions", {})
    exp_epoch = now + 3500
    if expires_at:
        try:
            dt = datetime.datetime.fromisoformat(expires_at)
            exp_epoch = int(dt.timestamp())
        except ValueError:
            pass

    cache_payload = {
        "token": token,
        "expires_at": expires_at,
        "expires_at_epoch": exp_epoch,
        "permissions": permissions,
    }
    _secure_write_json(cache_file, cache_payload)
    return cache_payload


def resolve_executable_for_git() -> str:
    override = os.environ.get("GITHUB_APP_BIN")
    if override:
        return override.replace("\\", "/")
    which_bin = shutil.which("github-app")
    if which_bin:
        return Path(which_bin).resolve().as_posix()
    local_bin = Path.home() / ".local" / "bin" / ("github-app.exe" if os.name == "nt" else "github-app")
    return local_bin.as_posix()


def normalize_repository_url(repo: str) -> str:
    if repo.startswith(("https://", "http://", "git@", "ssh://", "file://")):
        return repo
    slug = repo.strip("/")
    if "/" in slug and not Path(repo).exists():
        if not slug.endswith(".git"):
            slug = f"{slug}.git"
        return f"https://github.com/{slug}"
    return repo


def extract_repo_slug(repo: str) -> str | None:
    cleaned = repo.strip()
    if cleaned.startswith("https://github.com/"):
        cleaned = cleaned[len("https://github.com/") :]
    elif cleaned.startswith("git@github.com:"):
        cleaned = cleaned[len("git@github.com:") :]
    cleaned = cleaned.removesuffix(".git")
    parts = [p for p in cleaned.strip("/").split("/") if p]
    if len(parts) == 2:
        return f"{parts[0]}/{parts[1]}"
    return None


def create_github_repository(token: str, repo_spec: str) -> str:
    slug = extract_repo_slug(repo_spec)
    repo_name = slug.split("/")[1] if slug else repo_spec.strip("/")
    url = "https://api.github.com/user/repos"
    body = json.dumps({"name": repo_name, "private": True}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "github-app-cli",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("clone_url") or normalize_repository_url(repo_spec)
    except urllib.error.HTTPError as exc:
        if exc.code == 422:
            # Repository already exists or installation cannot call /user/repos
            return normalize_repository_url(repo_spec)
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise CLIError(f"github-app: failed to create repository ({exc.code}): {detail}") from exc


def configure_git_repo(repo_dir: Path, profile_name: str, profile: dict[str, str]) -> None:
    helper_cmd = f"{resolve_executable_for_git()} credential-helper"

    subprocess.run(
        ["git", "config", "--local", "github-app.profile", profile_name],
        cwd=str(repo_dir),
        check=True,
    )
    if profile.get("git_name"):
        subprocess.run(
            ["git", "config", "--local", "user.name", profile["git_name"]],
            cwd=str(repo_dir),
            check=True,
        )
    if profile.get("git_email"):
        subprocess.run(
            ["git", "config", "--local", "user.email", profile["git_email"]],
            cwd=str(repo_dir),
            check=True,
        )

    subprocess.run(
        ["git", "config", "--local", "--unset-all", "credential.helper"],
        cwd=str(repo_dir),
        check=False,
    )
    subprocess.run(
        ["git", "config", "--local", "--add", "credential.helper", ""],
        cwd=str(repo_dir),
        check=True,
    )
    subprocess.run(
        ["git", "config", "--local", "--add", "credential.helper", helper_cmd],
        cwd=str(repo_dir),
        check=True,
    )


def cmd_profile(args: list[str]) -> int:
    if not args or args[0] != "import":
        raise CLIError("github-app: expected 'github-app profile import ...' (run github-app --help)")

    name: str | None = None
    env_file: str | None = None
    git_name: str | None = None
    git_email: str | None = None

    idx = 1
    while idx < len(args):
        arg = args[idx]
        if arg == "--name" and idx + 1 < len(args):
            name = args[idx + 1]
            idx += 2
        elif arg == "--env" and idx + 1 < len(args):
            env_file = args[idx + 1]
            idx += 2
        elif arg == "--git-name" and idx + 1 < len(args):
            git_name = args[idx + 1]
            idx += 2
        elif arg == "--git-email" and idx + 1 < len(args):
            git_email = args[idx + 1]
            idx += 2
        else:
            raise CLIError(f"github-app: unknown or incomplete option '{arg}' for 'profile import'")

    if not name or not env_file:
        raise CLIError(
            "github-app: 'profile import' requires --name NAME and --env FILE"
        )

    env_vars = parse_env_file(Path(env_file))
    app_id = env_vars.get("GITHUB_APP_ID")
    installation_id = env_vars.get("GITHUB_INSTALLATION_ID")
    pk_val = env_vars.get("GITHUB_PRIVATE_KEY") or env_vars.get("GITHUB_PRIVATE_KEY_PATH")

    if not app_id or not installation_id or not pk_val:
        raise CLIError(
            f"github-app: {env_file} must define GITHUB_APP_ID, GITHUB_INSTALLATION_ID, and GITHUB_PRIVATE_KEY"
        )

    # Validate private key exists and is readable without copying key contents
    _ = load_private_key_bytes(pk_val)

    resolved_git_name = git_name or env_vars.get("GITHUB_GIT_NAME") or ""
    resolved_git_email = git_email or env_vars.get("GITHUB_GIT_EMAIL") or ""

    profiles = load_profiles()
    profiles[name] = {
        "app_id": str(app_id),
        "installation_id": str(installation_id),
        "private_key_path": pk_val,
        "git_name": resolved_git_name,
        "git_email": resolved_git_email,
    }
    save_profiles(profiles)
    return 0


def cmd_profiles(args: list[str]) -> int:
    if args:
        raise CLIError("github-app: 'profiles' takes no arguments")
    profiles = load_profiles()
    for name in sorted(profiles.keys()):
        print(name)
    return 0


def cmd_init(args: list[str]) -> int:
    profile_name: str | None = None
    create_flag = False
    positional: list[str] = []

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--profile" and idx + 1 < len(args):
            profile_name = args[idx + 1]
            idx += 2
        elif arg == "--create":
            create_flag = True
            idx += 1
        elif arg.startswith("-"):
            raise CLIError(f"github-app: unknown option '{arg}' for 'init'")
        else:
            positional.append(arg)
            idx += 1

    if not profile_name:
        raise CLIError("github-app: 'init' requires --profile NAME")

    profile = get_profile(profile_name)
    repo_arg = positional[0] if positional else None
    target_dir = Path.cwd()

    if repo_arg and Path(repo_arg).is_dir():
        target_dir = Path(repo_arg).resolve()
        repo_arg = None

    git_dir = target_dir / ".git"
    if not git_dir.exists():
        subprocess.run(["git", "init"], cwd=str(target_dir), check=True)

    configure_git_repo(target_dir, profile_name, profile)

    if repo_arg:
        remote_url = normalize_repository_url(repo_arg)
        if create_flag:
            token_data = get_token_data(profile_name)
            remote_url = create_github_repository(token_data["token"], repo_arg)
        existing_remote = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        if existing_remote.returncode == 0:
            subprocess.run(
                ["git", "remote", "set-url", "origin", remote_url],
                cwd=str(target_dir),
                check=True,
            )
        else:
            subprocess.run(
                ["git", "remote", "add", "origin", remote_url],
                cwd=str(target_dir),
                check=True,
            )

    return 0


def cmd_clone(args: list[str]) -> int:
    profile_name: str | None = None
    positional: list[str] = []

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--profile" and idx + 1 < len(args):
            profile_name = args[idx + 1]
            idx += 2
        elif arg.startswith("-"):
            raise CLIError(f"github-app: unknown option '{arg}' for 'clone'")
        else:
            positional.append(arg)
            idx += 1

    if not profile_name or not positional:
        raise CLIError("github-app: usage: github-app clone --profile NAME REPOSITORY [DIRECTORY]")

    profile = get_profile(profile_name)
    repo_spec = positional[0]
    remote_url = normalize_repository_url(repo_spec)

    if len(positional) >= 2:
        dest_dir = Path(positional[1]).resolve()
    else:
        normalized_path = remote_url.replace("\\", "/").rstrip("/")
        repo_leaf = normalized_path.split("/")[-1].removesuffix(".git")
        dest_dir = (Path.cwd() / repo_leaf).resolve()

    helper_cmd = f"{resolve_executable_for_git()} credential-helper"
    env = os.environ.copy()
    env["GITHUB_APP_PROFILE"] = profile_name

    clone_cmd = [
        "git",
        "-c",
        "credential.helper=",
        "-c",
        f"credential.helper={helper_cmd}",
        "clone",
        remote_url,
        str(dest_dir),
    ]
    proc = subprocess.run(clone_cmd, env=env, check=False)
    if proc.returncode != 0:
        return proc.returncode

    configure_git_repo(dest_dir, profile_name, profile)
    return 0


def cmd_credential_helper(args: list[str]) -> int:
    profile_name: str | None = None
    action: str | None = None

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--profile" and idx + 1 < len(args):
            profile_name = args[idx + 1]
            idx += 2
        elif not arg.startswith("-") and action is None:
            action = arg
            idx += 1
        else:
            idx += 1

    if action != "get":
        return 0

    raw_stdin = sys.stdin.read()
    attrs: dict[str, str] = {}
    for line in raw_stdin.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            attrs[k.strip()] = v.strip()

    if attrs.get("host") != "github.com":
        return 0

    try:
        resolved_profile = resolve_profile_name(profile_name)
        token_data = get_token_data(resolved_profile)
    except CLIError:
        return 1

    print("username=x-access-token")
    print(f"password={token_data['token']}")
    return 0


def cmd_run(args: list[str]) -> int:
    profile_name: str | None = None
    idx = 0
    if len(args) >= 2 and args[0] == "--profile":
        profile_name = args[1]
        idx = 2
    if idx < len(args) and args[idx] == "--":
        idx += 1

    cmd_args = args[idx:]
    if not cmd_args:
        raise CLIError("github-app: usage: github-app run [--profile NAME] COMMAND [ARGS...]")

    resolved_profile = resolve_profile_name(profile_name)
    token_data = get_token_data(resolved_profile)

    env = os.environ.copy()
    env["GH_TOKEN"] = token_data["token"]
    env["GITHUB_TOKEN"] = token_data["token"]
    env["GITHUB_APP_PROFILE"] = resolved_profile

    executable = shutil.which(cmd_args[0]) or cmd_args[0]
    proc = subprocess.run([executable, *cmd_args[1:]], env=env, check=False)
    return proc.returncode


def cmd_status(args: list[str]) -> int:
    profile_name: str | None = None
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--profile" and idx + 1 < len(args):
            profile_name = args[idx + 1]
            idx += 2
        else:
            raise CLIError(f"github-app: unknown option '{arg}' for 'status'")

    resolved_profile = resolve_profile_name(profile_name)
    profile = get_profile(resolved_profile)
    token_data = get_token_data(resolved_profile)

    perms_json = json.dumps(token_data.get("permissions", {}), separators=(",", ":"), sort_keys=True)
    git_name = profile.get("git_name", "")
    git_email = profile.get("git_email", "")
    git_identity = f"{git_name} <{git_email}>".strip() if (git_name or git_email) else "unconfigured"

    print(f"Profile: {resolved_profile}")
    print(f"Expires: {token_data.get('expires_at', 'unknown')}")
    print(f"Permissions: {perms_json}")
    print(f"Git identity: {git_identity}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        print(HELP_TEXT)
        return 0

    cmd = args[0]
    rest = args[1:]

    try:
        if cmd == "profile":
            return cmd_profile(rest)
        if cmd == "profiles":
            return cmd_profiles(rest)
        if cmd == "init":
            return cmd_init(rest)
        if cmd == "clone":
            return cmd_clone(rest)
        if cmd == "credential-helper":
            return cmd_credential_helper(rest)
        if cmd == "run":
            return cmd_run(rest)
        if cmd == "status":
            return cmd_status(rest)
        raise CLIError(f"github-app: unknown command '{cmd}' (run github-app --help)")
    except CLIError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

