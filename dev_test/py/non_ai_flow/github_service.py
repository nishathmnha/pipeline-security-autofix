from __future__ import annotations

import base64
import os

import httpx

from .env_loader import load_project_env


load_project_env()


def _env_value(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


GITHUB_API_URL = os.getenv("PAYLOAD_MONITOR_GITHUB_API_URL", "https://api.github.com")
GITHUB_TOKEN = _env_value("PAYLOAD_MONITOR_GITHUB_TOKEN", "GITHUB_TOKEN")

TARGET_FILE_NAMES = {
    "dockerfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
    "settings.gradle",
    "settings.gradle.kts",
}


def _require_github_token() -> str:
    if not GITHUB_TOKEN:
        raise ValueError("PAYLOAD_MONITOR_GITHUB_TOKEN is not configured.")
    return GITHUB_TOKEN


def _repo_parts(repo_name: str) -> tuple[str, str]:
    normalized = repo_name.strip()
    if "/" not in normalized:
        raise ValueError("Repo must be in owner/repo format.")
    owner, repo = normalized.split("/", 1)
    if not owner or not repo:
        raise ValueError("Repo must be in owner/repo format.")
    return owner, repo


def _github_error_text(response: httpx.Response, action: str) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}

    message = payload.get("message") if isinstance(payload, dict) else None
    errors = payload.get("errors") if isinstance(payload, dict) else None

    details: list[str] = []
    if isinstance(message, str) and message.strip():
        details.append(message.strip())
    if isinstance(errors, list):
        for item in errors:
            if isinstance(item, dict):
                code = item.get("code")
                field = item.get("field")
                item_message = item.get("message")
                parts = [str(part) for part in (code, field, item_message) if part]
                if parts:
                    details.append(" / ".join(parts))
            elif item:
                details.append(str(item))

    suffix = f": {'; '.join(details)}" if details else ""
    return f"{action} failed with {response.status_code}{suffix}"


def _raise_for_status(response: httpx.Response, action: str) -> None:
    if response.status_code >= 400:
        raise ValueError(_github_error_text(response, action))


def _github_headers() -> dict[str, str]:
    token = _require_github_token()
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


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

    blob_paths = [
        item["path"]
        for item in tree_response.json().get("tree", [])
        if item.get("type") == "blob" and isinstance(item.get("path"), str)
    ]

    if target_file in blob_paths:
        return target_file

    target_lower = target_file.lower()
    full_path_matches = [path for path in blob_paths if path.lower() == target_lower]
    if len(full_path_matches) == 1:
        return full_path_matches[0]
    if len(full_path_matches) > 1:
        raise ValueError(
            f"Target file '{target_file}' is ambiguous in {owner}/{repo}@{ref_name}: {', '.join(full_path_matches)}"
        )

    basename_matches = [path for path in blob_paths if path.split("/")[-1].lower() == target_lower]
    if len(basename_matches) == 1:
        return basename_matches[0]
    if len(basename_matches) > 1:
        raise ValueError(
            f"Target file '{target_file}' matched multiple files in {owner}/{repo}@{ref_name}: {', '.join(basename_matches)}"
        )

    raise ValueError(f"Target file '{target_file}' was not found in {owner}/{repo}@{ref_name}.")


def fetch_analysis_files(repo_name: str, branch_name: str) -> dict[str, str]:
    owner, repo = _repo_parts(repo_name)
    branch_name = branch_name.strip()
    if not branch_name:
        raise ValueError("Branch name is required.")

    def should_fetch(path: str) -> bool:
        name = path.split("/")[-1].lower()
        return name in TARGET_FILE_NAMES or path.lower().endswith("/dockerfile")

    with httpx.Client(base_url=GITHUB_API_URL, headers=_github_headers(), timeout=30.0) as client:
        tree_response = client.get(
            f"/repos/{owner}/{repo}/git/trees/{branch_name}",
            params={"recursive": "1"},
        )
        _raise_for_status(tree_response, f"Fetching tree for {repo_name}@{branch_name}")

        files: dict[str, str] = {}
        for item in tree_response.json().get("tree", []):
            if item.get("type") != "blob":
                continue

            path = item["path"]
            if not should_fetch(path):
                continue

            content_response = client.get(
                f"/repos/{owner}/{repo}/contents/{path}",
                params={"ref": branch_name},
            )
            _raise_for_status(content_response, f"Fetching {path} from {repo_name}@{branch_name}")

            payload = content_response.json()
            encoded = payload.get("content", "")
            if payload.get("encoding") != "base64":
                continue

            files[path] = base64.b64decode(encoded).decode("utf-8")

    return files


def create_branch_and_push_file(
    repo_name: str,
    base_branch: str,
    new_branch: str,
    target_file: str,
    updated_content: str,
    commit_message: str,
) -> dict[str, str]:
    owner, repo = _repo_parts(repo_name)
    base_branch = base_branch.strip()
    new_branch = new_branch.strip()
    target_file = target_file.strip()
    if not base_branch:
        raise ValueError("Base branch is required.")
    if not new_branch:
        raise ValueError("New branch is required.")
    if not target_file:
        raise ValueError("Target file is required.")

    with httpx.Client(base_url=GITHUB_API_URL, headers=_github_headers(), timeout=30.0) as client:
        ref_response = client.get(f"/repos/{owner}/{repo}/git/ref/heads/{base_branch}")
        _raise_for_status(ref_response, f"Looking up base branch {base_branch}")
        base_sha = ref_response.json()["object"]["sha"]

        create_ref_response = client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{new_branch}", "sha": base_sha},
        )
        if create_ref_response.status_code not in {201, 422}:
            _raise_for_status(create_ref_response, f"Creating branch {new_branch}")

        branch_already_exists = False
        if create_ref_response.status_code == 422:
            error_text = _github_error_text(create_ref_response, f"Creating branch {new_branch}")
            if "Reference already exists" in error_text:
                branch_already_exists = True
            else:
                raise ValueError(error_text)

        content_ref = new_branch if branch_already_exists else base_branch
        resolved_target_file = _resolve_target_file_path(client, owner, repo, content_ref, target_file)

        content_response = client.get(
            f"/repos/{owner}/{repo}/contents/{resolved_target_file}",
            params={"ref": content_ref},
        )
        _raise_for_status(
            content_response,
            f"Fetching {resolved_target_file} from {repo_name}@{content_ref}",
        )
        existing_sha = content_response.json()["sha"]

        update_response = client.put(
            f"/repos/{owner}/{repo}/contents/{resolved_target_file}",
            json={
                "message": commit_message,
                "content": base64.b64encode(updated_content.encode("utf-8")).decode("utf-8"),
                "branch": new_branch,
                "sha": existing_sha,
            },
        )
        _raise_for_status(update_response, f"Updating {resolved_target_file} on branch {new_branch}")

    return {
        "status": "pushed",
        "branch_name": new_branch,
        "branch_created": not branch_already_exists,
        "target_file": resolved_target_file,
        "compare_url": f"https://github.com/{owner}/{repo}/compare/{base_branch}...{new_branch}",
    }
