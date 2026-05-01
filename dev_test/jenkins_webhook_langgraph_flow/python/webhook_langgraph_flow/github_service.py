from __future__ import annotations

import base64
import os
from pathlib import PurePosixPath
from typing import Any

import httpx

from .env_loader import load_project_env


load_project_env()


def _env_value(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_flag_any(names: tuple[str, ...], default: bool) -> bool:
    for name in names:
        raw = os.getenv(name)
        if raw is not None:
            return raw.strip().lower() in {"1", "true", "yes", "on"}
    return default


GITHUB_API_URL = os.getenv("PAYLOAD_MONITOR_GITHUB_API_URL", "https://api.github.com")
GITHUB_TOKEN = _env_value("PAYLOAD_MONITOR_GITHUB_TOKEN", "GITHUB_TOKEN")
GITHUB_DRY_RUN = _env_flag_any(("PAYLOAD_MONITOR_GITHUB_DRY_RUN", "GITHUB_DRY_RUN"), True)

TARGET_FILE_NAMES = {
    "dockerfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
    "settings.gradle",
    "settings.gradle.kts",
}


def _repo_parts(repo_name: str) -> tuple[str, str]:
    normalized = repo_name.strip()
    if "/" not in normalized:
        raise ValueError("Repo must be in owner/repo format.")
    owner, repo = normalized.split("/", 1)
    if not owner or not repo:
        raise ValueError("Repo must be in owner/repo format.")
    return owner, repo


def _require_token() -> str:
    if not GITHUB_TOKEN:
        raise ValueError("PAYLOAD_MONITOR_GITHUB_TOKEN is not configured.")
    return GITHUB_TOKEN


def _github_headers() -> dict[str, str]:
    token = _require_token()
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _github_error_text(response: httpx.Response, action: str) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    message = payload.get("message") if isinstance(payload, dict) else None
    return f"{action} failed with {response.status_code}{f': {message}' if message else ''}"


def _raise_for_status(response: httpx.Response, action: str) -> None:
    if response.status_code >= 400:
        raise ValueError(_github_error_text(response, action))


def _resolve_target_file_path(
    client: httpx.Client,
    owner: str,
    repo: str,
    ref_name: str,
    target_file: str,
) -> str:
    tree_response = client.get(
        f"/repos/{owner}/{repo}/git/trees/{ref_name}",
        params={"recursive": "1"},
    )
    _raise_for_status(tree_response, f"Fetching tree for {owner}/{repo}@{ref_name}")
    paths = [
        item["path"]
        for item in tree_response.json().get("tree", [])
        if item.get("type") == "blob" and isinstance(item.get("path"), str)
    ]

    normalized = target_file.strip().strip("/")
    if normalized in paths:
        return normalized

    lower_target = normalized.lower()
    exact_case_insensitive = [path for path in paths if path.lower() == lower_target]
    if len(exact_case_insensitive) == 1:
        return exact_case_insensitive[0]

    basename_matches = [path for path in paths if PurePosixPath(path).name.lower() == PurePosixPath(normalized).name.lower()]
    if len(basename_matches) == 1:
        return basename_matches[0]
    if len(basename_matches) > 1:
        raise ValueError(
            f"Target file '{target_file}' is ambiguous in {owner}/{repo}@{ref_name}: {', '.join(sorted(basename_matches))}"
        )

    raise ValueError(f"Target file '{target_file}' was not found in {owner}/{repo}@{ref_name}.")


def _fetch_repo_file(
    client: httpx.Client,
    owner: str,
    repo: str,
    branch_name: str,
    file_path: str,
) -> tuple[str, str]:
    resolved_path = _resolve_target_file_path(client, owner, repo, branch_name, file_path)
    content_response = client.get(
        f"/repos/{owner}/{repo}/contents/{resolved_path}",
        params={"ref": branch_name},
    )
    _raise_for_status(content_response, f"Fetching {resolved_path} from {owner}/{repo}@{branch_name}")
    payload = content_response.json()
    encoded = payload.get("content", "")
    if payload.get("encoding") != "base64":
        raise ValueError(f"GitHub content encoding for {resolved_path} was not base64.")
    return resolved_path, base64.b64decode(encoded).decode("utf-8")


def fetch_repo_files_by_paths(repo_name: str, branch_name: str, file_paths: list[str]) -> dict[str, str]:
    owner, repo = _repo_parts(repo_name)
    if not branch_name.strip():
        raise ValueError("Branch name is required.")
    cleaned_paths = [path.strip() for path in file_paths if isinstance(path, str) and path.strip()]
    if not cleaned_paths:
        return {}

    with httpx.Client(base_url=GITHUB_API_URL, headers=_github_headers(), timeout=30.0) as client:
        fetched: dict[str, str] = {}
        for path in cleaned_paths:
            resolved_path, content = _fetch_repo_file(client, owner, repo, branch_name, path)
            fetched[resolved_path] = content
    return fetched


def fetch_analysis_files(repo_name: str, branch_name: str) -> dict[str, str]:
    owner, repo = _repo_parts(repo_name)
    if not branch_name.strip():
        raise ValueError("Branch name is required.")

    with httpx.Client(base_url=GITHUB_API_URL, headers=_github_headers(), timeout=30.0) as client:
        tree_response = client.get(
            f"/repos/{owner}/{repo}/git/trees/{branch_name}",
            params={"recursive": "1"},
        )
        _raise_for_status(tree_response, f"Fetching tree for {repo_name}@{branch_name}")

        paths = [
            item["path"]
            for item in tree_response.json().get("tree", [])
            if item.get("type") == "blob"
            and isinstance(item.get("path"), str)
            and PurePosixPath(item["path"]).name.lower() in TARGET_FILE_NAMES
        ]

        fetched: dict[str, str] = {}
        for path in paths:
            resolved_path, content = _fetch_repo_file(client, owner, repo, branch_name, path)
            fetched[resolved_path] = content
    return fetched


def create_branch_and_push_files(
    repo_name: str,
    base_branch: str,
    new_branch: str,
    files: list[dict[str, str]],
    commit_message: str,
) -> dict[str, Any]:
    owner, repo = _repo_parts(repo_name)
    if not base_branch.strip():
        raise ValueError("Base branch is required.")
    if not new_branch.strip():
        raise ValueError("New branch is required.")
    if not files:
        raise ValueError("At least one file update is required.")

    normalized_files: list[dict[str, str]] = []
    for item in files:
        path = str(item.get("path", "")).strip()
        updated_content = str(item.get("updated_content", ""))
        if not path:
            raise ValueError("Each file update must include a path.")
        normalized_files.append({"path": path, "updated_content": updated_content})

    if GITHUB_DRY_RUN:
        return {
            "status": "dry-run",
            "branch_name": new_branch,
            "branch_created": True,
            "changed_files": [{"path": item["path"]} for item in normalized_files],
            "compare_url": f"https://github.com/{owner}/{repo}/compare/{base_branch}...{new_branch}",
        }

    with httpx.Client(base_url=GITHUB_API_URL, headers=_github_headers(), timeout=30.0) as client:
        ref_response = client.get(f"/repos/{owner}/{repo}/git/ref/heads/{base_branch}")
        _raise_for_status(ref_response, f"Looking up base branch {base_branch}")
        base_sha = ref_response.json()["object"]["sha"]

        create_ref_response = client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{new_branch}", "sha": base_sha},
        )
        branch_already_exists = False
        if create_ref_response.status_code not in {201, 422}:
            _raise_for_status(create_ref_response, f"Creating branch {new_branch}")
        if create_ref_response.status_code == 422:
            error_text = _github_error_text(create_ref_response, f"Creating branch {new_branch}")
            if "Reference already exists" in error_text:
                branch_already_exists = True
            else:
                raise ValueError(error_text)

        changed_files: list[dict[str, str]] = []
        for file_update in normalized_files:
            content_ref = new_branch if branch_already_exists or changed_files else base_branch
            resolved_path = _resolve_target_file_path(client, owner, repo, content_ref, file_update["path"])
            content_response = client.get(
                f"/repos/{owner}/{repo}/contents/{resolved_path}",
                params={"ref": content_ref},
            )
            _raise_for_status(content_response, f"Fetching {resolved_path} from {repo_name}@{content_ref}")
            existing_sha = content_response.json()["sha"]

            update_response = client.put(
                f"/repos/{owner}/{repo}/contents/{resolved_path}",
                json={
                    "message": commit_message,
                    "content": base64.b64encode(file_update["updated_content"].encode("utf-8")).decode("utf-8"),
                    "branch": new_branch,
                    "sha": existing_sha,
                },
            )
            _raise_for_status(update_response, f"Updating {resolved_path} on branch {new_branch}")
            changed_files.append({"path": resolved_path})

    return {
        "status": "pushed",
        "branch_name": new_branch,
        "branch_created": not branch_already_exists,
        "changed_files": changed_files,
        "compare_url": f"https://github.com/{owner}/{repo}/compare/{base_branch}...{new_branch}",
    }


def create_pull_request(repo_name: str, base_branch: str, new_branch: str, title: str, body: str) -> dict[str, str]:
    owner, repo = _repo_parts(repo_name)
    if GITHUB_DRY_RUN:
        return {
            "pull_request_url": f"https://github.com/{owner}/{repo}/compare/{base_branch}...{new_branch}",
            "pull_request_number": "",
        }

    with httpx.Client(base_url=GITHUB_API_URL, headers=_github_headers(), timeout=30.0) as client:
        pr_response = client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": title,
                "body": body,
                "head": new_branch,
                "base": base_branch,
            },
        )
        _raise_for_status(pr_response, f"Creating pull request for {new_branch}")
    payload = pr_response.json()
    return {
        "pull_request_url": str(payload.get("html_url", "")),
        "pull_request_number": str(payload.get("number", "")),
    }
