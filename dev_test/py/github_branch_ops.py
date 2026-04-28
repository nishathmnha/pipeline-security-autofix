from __future__ import annotations

import base64
import os

import httpx


GITHUB_API_URL = os.getenv("PAYLOAD_MONITOR_GITHUB_API_URL", "https://api.github.com")
GITHUB_TOKEN = os.getenv("PAYLOAD_MONITOR_GITHUB_TOKEN", "")

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


def _github_headers() -> dict[str, str]:
    token = _require_github_token()
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def fetch_analysis_files(repo_name: str, branch_name: str) -> dict[str, str]:
    owner, repo = repo_name.split("/", 1)

    def should_fetch(path: str) -> bool:
        name = path.split("/")[-1].lower()
        return name in TARGET_FILE_NAMES or path.lower().endswith("/dockerfile")

    with httpx.Client(base_url=GITHUB_API_URL, headers=_github_headers(), timeout=30.0) as client:
        tree_response = client.get(
            f"/repos/{owner}/{repo}/git/trees/{branch_name}",
            params={"recursive": "1"},
        )
        tree_response.raise_for_status()

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
            content_response.raise_for_status()

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
    
    owner, repo = repo_name.split("/", 1)

    with httpx.Client(base_url=GITHUB_API_URL, headers=_github_headers(), timeout=30.0) as client:
        ref_response = client.get(f"/repos/{owner}/{repo}/git/ref/heads/{base_branch}")
        ref_response.raise_for_status()
        base_sha = ref_response.json()["object"]["sha"]

        create_ref_response = client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{new_branch}", "sha": base_sha},
        )
        create_ref_response.raise_for_status()

        content_response = client.get(
            f"/repos/{owner}/{repo}/contents/{target_file}",
            params={"ref": base_branch},
        )
        content_response.raise_for_status()
        existing_sha = content_response.json()["sha"]

        update_response = client.put(
            f"/repos/{owner}/{repo}/contents/{target_file}",
            json={
                "message": commit_message,
                "content": base64.b64encode(updated_content.encode("utf-8")).decode("utf-8"),
                "branch": new_branch,
                "sha": existing_sha,
            },
        )
        update_response.raise_for_status()

    return {
        "status": "pushed",
        "branch_name": new_branch,
        "compare_url": f"https://github.com/{owner}/{repo}/compare/{base_branch}...{new_branch}",
    }
