"""Built-in stdlib JSON-RPC 2.0 Stdio MCP server for github-app."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, TextIO

from github_app import __version__, cli
from github_app.policy import (
    PolicyViolationError,
    load_effective_policy,
    redact_secrets,
    validate_gh_args,
    validate_git_push,
)

SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = "2025-03-26"
COMMAND_TIMEOUT_SECONDS = 120

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "github_app_profiles",
        "description": (
            "List configured github-app profiles, their git identities, and effective security "
            "policies. Never exposes private keys or tokens."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "github_app_status",
        "description": (
            "Report the resolved profile for a repository checkout or explicit profile name, "
            "token expiration, GitHub-declared permissions, git identity, and effective policy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwd": {"type": "string", "description": "Repository working directory."},
                "profile": {"type": "string", "description": "Explicit profile name."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "github_app_init",
        "description": (
            "Bind an existing github-app profile to a local checkout by configuring local "
            "git identity and the ephemeral credential helper."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwd": {"type": "string", "description": "Repository working directory."},
                "profile": {"type": "string", "description": "Existing profile name."},
                "repository": {
                    "type": "string",
                    "description": "Optional owner/repo slug or remote URL to configure origin.",
                },
                "create": {
                    "type": "boolean",
                    "description": "Create the remote GitHub repository if missing.",
                    "default": False,
                },
            },
            "required": ["cwd", "profile"],
            "additionalProperties": False,
        },
    },
    {
        "name": "git_clone",
        "description": (
            "Clone a Git repository using an existing github-app profile and configure the "
            "cloned checkout with local git identity and credential helper."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "description": "Existing profile name."},
                "repository": {
                    "type": "string",
                    "description": "Repository URL or owner/repo shorthand.",
                },
                "directory": {"type": "string", "description": "Optional destination directory."},
                "cwd": {
                    "type": "string",
                    "description": "Base directory when directory is relative or omitted.",
                },
            },
            "required": ["profile", "repository"],
            "additionalProperties": False,
        },
    },
    {
        "name": "git_fetch",
        "description": "Run authenticated git fetch in a repository checkout without shell execution.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwd": {"type": "string", "description": "Repository working directory."},
                "remote": {"type": "string", "description": "Remote name (default: origin when refspec set)."},
                "refspec": {"type": "string", "description": "Optional refspec to fetch."},
                "prune": {"type": "boolean", "default": False},
                "tags": {"type": "boolean", "default": False},
                "profile": {"type": "string", "description": "Optional explicit profile override."},
            },
            "required": ["cwd"],
            "additionalProperties": False,
        },
    },
    {
        "name": "git_pull",
        "description": "Run authenticated git pull in a repository checkout without shell execution.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwd": {"type": "string", "description": "Repository working directory."},
                "remote": {"type": "string", "description": "Remote name (default: origin when branch set)."},
                "branch": {"type": "string", "description": "Optional branch to pull."},
                "rebase": {"type": "boolean", "default": False},
                "ff_only": {"type": "boolean", "default": False},
                "profile": {"type": "string", "description": "Optional explicit profile override."},
            },
            "required": ["cwd"],
            "additionalProperties": False,
        },
    },
    {
        "name": "git_push",
        "description": (
            "Run authenticated git push in a repository checkout, subject to profile security "
            "policy guardrails (blocks protected branches, force push, and remote deletion by default)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwd": {"type": "string", "description": "Repository working directory."},
                "remote": {"type": "string", "description": "Remote name."},
                "refspecs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional refspecs to push.",
                },
                "set_upstream": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "force_with_lease": {"type": "boolean", "default": False},
                "delete": {"type": "boolean", "default": False},
                "profile": {"type": "string", "description": "Optional explicit profile override."},
            },
            "required": ["cwd"],
            "additionalProperties": False,
        },
    },
    {
        "name": "gh_run",
        "description": (
            "Run GitHub CLI (gh) with direct argv execution (no shell) and ephemeral token "
            "injection, enforcing profile security policy and secret redaction. Optionally writes "
            "multiline markdown body to a temporary --body-file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwd": {"type": "string", "description": "Repository working directory."},
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Argument vector passed directly to gh.",
                },
                "profile": {"type": "string", "description": "Optional explicit profile override."},
                "body": {
                    "type": "string",
                    "description": "Optional multiline markdown written to a temp file.",
                },
                "body_flag": {
                    "type": "string",
                    "default": "--body-file",
                    "description": "Flag paired with the temporary body file.",
                },
            },
            "required": ["cwd", "args"],
            "additionalProperties": False,
        },
    },
]


class ToolInputError(ValueError):
    """Raised when tool arguments fail schema or runtime validation."""


def _require_str(args: dict[str, Any], key: str) -> str:
    val = args.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ToolInputError(f"'{key}' must be a non-empty string")
    return val


def _optional_str(args: dict[str, Any], key: str) -> str | None:
    val = args.get(key)
    if val is None:
        return None
    if not isinstance(val, str) or not val.strip():
        raise ToolInputError(f"'{key}' must be a non-empty string when provided")
    return val


def _optional_bool(args: dict[str, Any], key: str, default: bool = False) -> bool:
    val = args.get(key)
    if val is None:
        return default
    if not isinstance(val, bool):
        raise ToolInputError(f"'{key}' must be a boolean")
    return val


def _require_dir(raw_cwd: str) -> Path:
    path = Path(raw_cwd).expanduser().resolve()
    if not path.is_dir():
        raise ToolInputError(f"Directory does not exist: {path}")
    return path


def _collect_cached_secret(profile_name: str) -> list[str]:
    cache_file = cli.get_cache_dir() / "tokens" / f"{profile_name}.json"
    if not cache_file.exists():
        return []
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    token = data.get("token")
    return [token] if isinstance(token, str) and token else []


def _resolve_binary(name: str) -> str:
    exe = shutil.which(name)
    if not exe:
        raise cli.CLIError(f"github-app: '{name}' executable not found on PATH")
    return exe


def _run_git_authenticated(
    cwd: Path,
    profile_name: str,
    git_args: list[str],
) -> subprocess.CompletedProcess[str]:
    git_exe = _resolve_binary("git")
    helper_cmd = f"{cli.resolve_executable_for_git()} credential-helper"
    env = os.environ.copy()
    env["GITHUB_APP_PROFILE"] = profile_name

    cmd = [
        git_exe,
        "-c",
        "credential.helper=",
        "-c",
        f"credential.helper={helper_cmd}",
        *git_args,
    ]
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )


def _current_git_branch(cwd: Path) -> str | None:
    git_exe = _resolve_binary("git")
    proc = subprocess.run(
        [git_exe, "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        return None
    branch = proc.stdout.strip()
    return branch or None


def _format_subprocess_result(
    proc: subprocess.CompletedProcess[str],
    *,
    secrets: list[str],
    extra: dict[str, Any] | None = None,
) -> tuple[str, bool]:
    payload: dict[str, Any] = {
        "returncode": proc.returncode,
        "stdout": redact_secrets(proc.stdout or "", secrets),
        "stderr": redact_secrets(proc.stderr or "", secrets),
    }
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2), proc.returncode != 0


def _tool_profiles(args: dict[str, Any], secrets: list[str]) -> tuple[str, bool]:
    if args:
        raise ToolInputError("github_app_profiles takes no arguments")
    profiles = cli.load_profiles()
    items: list[dict[str, Any]] = []
    for name in sorted(profiles.keys()):
        entry = profiles[name]
        try:
            policy_dict = load_effective_policy(entry).to_dict()
        except (TypeError, ValueError) as exc:
            raise cli.CLIError(
                f"github-app: invalid policy for profile '{name}' ({exc})"
            ) from exc
        items.append(
            {
                "name": name,
                "git_name": entry.get("git_name", ""),
                "git_email": entry.get("git_email", ""),
                "policy": policy_dict,
            }
        )
    return json.dumps({"profiles": items}, indent=2), False


def _tool_status(args: dict[str, Any], secrets: list[str]) -> tuple[str, bool]:
    raw_cwd = _optional_str(args, "cwd")
    profile_name = _optional_str(args, "profile")
    cwd_path = _require_dir(raw_cwd) if raw_cwd else None
    info = cli.get_status_info(profile_name, cwd=cwd_path)
    secrets.extend(_collect_cached_secret(info["profile"]))
    return json.dumps(info, indent=2), False


def _tool_init(args: dict[str, Any], secrets: list[str]) -> tuple[str, bool]:
    cwd_path = _require_dir(_require_str(args, "cwd"))
    profile_name = _require_str(args, "profile")
    repository = _optional_str(args, "repository")
    create = _optional_bool(args, "create", False)
    target = cli.init_repository(
        profile_name,
        cwd=cwd_path,
        repository=repository,
        create=create,
    )
    secrets.extend(_collect_cached_secret(profile_name))
    return (
        json.dumps(
            {
                "status": "ok",
                "cwd": str(target),
                "profile": profile_name,
                "repository": repository,
            },
            indent=2,
        ),
        False,
    )


def _tool_git_clone(args: dict[str, Any], secrets: list[str]) -> tuple[str, bool]:
    profile_name = _require_str(args, "profile")
    repository = _require_str(args, "repository")
    directory = _optional_str(args, "directory")
    raw_cwd = _optional_str(args, "cwd")
    cwd_path = _require_dir(raw_cwd) if raw_cwd else None

    proc, dest_dir = cli.clone_repository(
        profile_name,
        repository,
        directory=directory,
        cwd=cwd_path,
        capture_output=True,
    )
    secrets.extend(_collect_cached_secret(profile_name))
    return _format_subprocess_result(
        proc,
        secrets=secrets,
        extra={"directory": str(dest_dir), "profile": profile_name},
    )


def _tool_git_fetch(args: dict[str, Any], secrets: list[str]) -> tuple[str, bool]:
    cwd_path = _require_dir(_require_str(args, "cwd"))
    profile_name = cli.resolve_profile_name(_optional_str(args, "profile"), cwd=cwd_path)
    cli.get_profile(profile_name)

    remote = _optional_str(args, "remote")
    refspec = _optional_str(args, "refspec")
    prune = _optional_bool(args, "prune", False)
    tags = _optional_bool(args, "tags", False)

    git_args = ["fetch"]
    if prune:
        git_args.append("--prune")
    if tags:
        git_args.append("--tags")
    if refspec and not remote:
        remote = "origin"
    if remote:
        git_args.append(remote)
    if refspec:
        git_args.append(refspec)

    proc = _run_git_authenticated(cwd_path, profile_name, git_args)
    secrets.extend(_collect_cached_secret(profile_name))
    return _format_subprocess_result(proc, secrets=secrets, extra={"profile": profile_name})


def _tool_git_pull(args: dict[str, Any], secrets: list[str]) -> tuple[str, bool]:
    cwd_path = _require_dir(_require_str(args, "cwd"))
    profile_name = cli.resolve_profile_name(_optional_str(args, "profile"), cwd=cwd_path)
    cli.get_profile(profile_name)

    remote = _optional_str(args, "remote")
    branch = _optional_str(args, "branch")
    rebase = _optional_bool(args, "rebase", False)
    ff_only = _optional_bool(args, "ff_only", False)
    if rebase and ff_only:
        raise ToolInputError("'rebase' and 'ff_only' cannot both be true")

    git_args = ["pull"]
    if rebase:
        git_args.append("--rebase")
    if ff_only:
        git_args.append("--ff-only")
    if branch and not remote:
        remote = "origin"
    if remote:
        git_args.append(remote)
    if branch:
        git_args.append(branch)

    proc = _run_git_authenticated(cwd_path, profile_name, git_args)
    secrets.extend(_collect_cached_secret(profile_name))
    return _format_subprocess_result(proc, secrets=secrets, extra={"profile": profile_name})


def _tool_git_push(args: dict[str, Any], secrets: list[str]) -> tuple[str, bool]:
    cwd_path = _require_dir(_require_str(args, "cwd"))
    profile_name = cli.resolve_profile_name(_optional_str(args, "profile"), cwd=cwd_path)
    profile = cli.get_profile(profile_name)
    try:
        policy = load_effective_policy(profile)
    except (TypeError, ValueError) as exc:
        raise cli.CLIError(
            f"github-app: invalid policy for profile '{profile_name}' ({exc})"
        ) from exc

    remote = _optional_str(args, "remote")
    raw_refspecs = args.get("refspecs")
    refspecs: list[str] = []
    if raw_refspecs is not None:
        if not isinstance(raw_refspecs, list) or not all(
            isinstance(item, str) and item.strip() for item in raw_refspecs
        ):
            raise ToolInputError("'refspecs' must be a list of non-empty strings")
        refspecs = [item.strip() for item in raw_refspecs]

    set_upstream = _optional_bool(args, "set_upstream", False)
    force = _optional_bool(args, "force", False)
    force_with_lease = _optional_bool(args, "force_with_lease", False)
    delete = _optional_bool(args, "delete", False)

    current_branch = _current_git_branch(cwd_path)
    validate_git_push(
        policy,
        current_branch=current_branch,
        refspecs=refspecs,
        force=force,
        force_with_lease=force_with_lease,
        delete=delete,
    )

    git_args = ["push"]
    if set_upstream:
        git_args.append("--set-upstream")
    if force:
        git_args.append("--force")
    if force_with_lease:
        git_args.append("--force-with-lease")
    if delete:
        git_args.append("--delete")

    if refspecs and not remote:
        remote = "origin"
    elif set_upstream and not remote:
        remote = "origin"
        if not refspecs and current_branch:
            refspecs = [current_branch]

    if remote:
        git_args.append(remote)
    git_args.extend(refspecs)

    proc = _run_git_authenticated(cwd_path, profile_name, git_args)
    secrets.extend(_collect_cached_secret(profile_name))
    return _format_subprocess_result(proc, secrets=secrets, extra={"profile": profile_name})


def _tool_gh_run(args: dict[str, Any], secrets: list[str]) -> tuple[str, bool]:
    cwd_path = _require_dir(_require_str(args, "cwd"))
    raw_cmd_args = args.get("args")
    if (
        not isinstance(raw_cmd_args, list)
        or not raw_cmd_args
        or not all(isinstance(item, str) and item for item in raw_cmd_args)
    ):
        raise ToolInputError("'args' must be a non-empty list of strings")
    cmd_args = list(raw_cmd_args)

    body = args.get("body")
    if body is not None and not isinstance(body, str):
        raise ToolInputError("'body' must be a string")
    body_flag = _optional_str(args, "body_flag") or "--body-file"

    profile_name = cli.resolve_profile_name(_optional_str(args, "profile"), cwd=cwd_path)
    profile = cli.get_profile(profile_name)
    try:
        policy = load_effective_policy(profile)
    except (TypeError, ValueError) as exc:
        raise cli.CLIError(
            f"github-app: invalid policy for profile '{profile_name}' ({exc})"
        ) from exc

    token_data = cli.get_token_data(profile_name)
    token = token_data["token"]
    secrets.append(token)

    gh_exe = _resolve_binary("gh")
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    env["GITHUB_TOKEN"] = token
    env["GITHUB_APP_PROFILE"] = profile_name

    def resolve_pr_base(selector: str | None, repo: str | None) -> str:
        view_cmd = [gh_exe, "pr", "view"]
        if selector:
            view_cmd.append(selector)
        if repo:
            view_cmd.extend(["--repo", repo])
        view_cmd.extend(["--json", "baseRefName", "--jq", ".baseRefName"])
        view_proc = subprocess.run(
            view_cmd,
            cwd=str(cwd_path),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        if view_proc.returncode != 0 or not view_proc.stdout.strip():
            detail = (view_proc.stderr or view_proc.stdout).strip()
            raise RuntimeError(detail or f"exit code {view_proc.returncode}")
        return view_proc.stdout.strip()

    validate_gh_args(policy, cmd_args, pr_base_resolver=resolve_pr_base)

    temp_body_path: Path | None = None
    try:
        if body is not None:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".md",
                delete=False,
            ) as tmp:
                tmp.write(body)
                temp_body_path = Path(tmp.name)
            cmd_args.extend([body_flag, str(temp_body_path)])

        proc = subprocess.run(
            [gh_exe, *cmd_args],
            cwd=str(cwd_path),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
        return _format_subprocess_result(proc, secrets=secrets, extra={"profile": profile_name})
    finally:
        if temp_body_path is not None:
            temp_body_path.unlink(missing_ok=True)


TOOL_HANDLERS = {
    "github_app_profiles": _tool_profiles,
    "github_app_status": _tool_status,
    "github_app_init": _tool_init,
    "git_clone": _tool_git_clone,
    "git_fetch": _tool_git_fetch,
    "git_pull": _tool_git_pull,
    "git_push": _tool_git_push,
    "gh_run": _tool_gh_run,
}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    }


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    handler = TOOL_HANDLERS[name]
    secrets: list[str] = []
    try:
        text, is_error = handler(arguments, secrets)
    except (
        ToolInputError,
        PolicyViolationError,
        cli.CLIError,
        subprocess.SubprocessError,
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
    ) as exc:
        text = str(exc)
        is_error = True

    scrubbed = redact_secrets(text, secrets)
    return {
        "content": [{"type": "text", "text": scrubbed}],
        "isError": is_error,
    }


def handle_message(msg: Any) -> dict[str, Any] | None:
    """Process one JSON-RPC 2.0 request or notification and return response or None."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        req_id = msg.get("id") if isinstance(msg, dict) else None
        return _jsonrpc_error(req_id, -32600, "Invalid JSON-RPC 2.0 request")

    has_id = "id" in msg
    req_id = msg.get("id")
    if has_id and req_id is not None and (isinstance(req_id, bool) or not isinstance(req_id, (str, int))):
        return _jsonrpc_error(None, -32600, "Invalid request id")

    method = msg.get("method")
    if not isinstance(method, str) or not method:
        return _jsonrpc_error(req_id if has_id else None, -32600, "Missing method")

    # Notifications omit 'id' and expect no response.
    if not has_id:
        return None

    params = msg.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _jsonrpc_error(req_id, -32602, "Params must be a JSON object")

    if method == "initialize":
        requested = params.get("protocolVersion")
        negotiated = (
            requested
            if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS
            else DEFAULT_PROTOCOL_VERSION
        )
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "github-app", "version": __version__},
            },
        )

    if method == "ping":
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": TOOL_DEFINITIONS})

    if method == "tools/call":
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or tool_name not in TOOL_HANDLERS:
            return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name}")
        raw_args = params.get("arguments")
        if raw_args is None:
            tool_args: dict[str, Any] = {}
        elif isinstance(raw_args, dict):
            tool_args = raw_args
        else:
            return _jsonrpc_error(req_id, -32602, "Tool arguments must be a JSON object")
        return _jsonrpc_result(req_id, _call_tool(tool_name, tool_args))

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def serve_stdio(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run the newline-delimited JSON-RPC 2.0 MCP loop on stdio."""
    in_stream = sys.stdin if stdin is None else stdin
    out_stream = sys.stdout if stdout is None else stdout

    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            resp: dict[str, Any] | None = _jsonrpc_error(None, -32700, f"Parse error: {exc}")
        else:
            resp = handle_message(msg)

        if resp is not None:
            out_stream.write(json.dumps(resp, separators=(",", ":")) + "\n")
            out_stream.flush()

    return 0
