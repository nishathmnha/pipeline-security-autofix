from __future__ import annotations

import base64
import json
import os
import re
from collections import deque
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from .env_loader import load_project_env
from . import github_service as github_branch_ops

load_project_env()


APP_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = APP_DIR / "runtime"
EVENTS_FILE = RUNTIME_DIR / "requests.jsonl"
MAX_EVENTS = 200

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-webhook-secret"}
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


@dataclass
class StoredEvent:
    event_id: str
    received_at: str
    method: str
    path: str
    client: str | None
    content_type: str | None
    content_length: int
    headers: dict[str, str]
    payload: Any | None
    raw_body: str
    summary: dict[str, Any]
    build_url: str | None = None
    console_text: str = ""
    console_source: str = "payload"
    console_status: str = "payload-only"
    local_repo_path: str | None = None
    analysis: dict[str, Any] | None = None
    proposal: dict[str, Any] | None = None
    github_result: dict[str, Any] | None = None


class EventStore:
    def __init__(self, events_file: Path, max_events: int = MAX_EVENTS) -> None:
        self.events_file = events_file
        self.max_events = max_events
        self._lock = Lock()
        self._events: deque[StoredEvent] = deque(maxlen=max_events)
        self._load()

    def _load(self) -> None:
      
        self.events_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.events_file.exists():
            self.events_file.touch()
            return

        with self.events_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                self._events.append(self._event_from_record(record))

    def _event_from_record(self, record: dict[str, Any]) -> StoredEvent:
        field_names = {field.name for field in fields(StoredEvent)}
        filtered = {name: record[name] for name in field_names if name in record}
        return StoredEvent(**filtered)

    def _persist(self) -> None:
        with self.events_file.open("w", encoding="utf-8") as handle:
            for event in self._events:
                handle.write(json.dumps(asdict(event), ensure_ascii=False))
                handle.write("\n")

    def add(self, event: StoredEvent) -> None:
        with self._lock:
            self._events.append(event)
            self._persist()

    def save(self, event: StoredEvent) -> None:
        with self._lock:
            for index, existing in enumerate(self._events):
                if existing.event_id == event.event_id:
                    self._events[index] = event
                    self._persist()
                    return
            self._events.append(event)
            self._persist()

    def list_events(self, limit: int = 50) -> list[StoredEvent]:
        with self._lock:
            events = list(self._events)
        events.reverse()
        return events[:limit]

    def get(self, event_id: str) -> StoredEvent | None:
        with self._lock:
            for event in reversed(self._events):
                if event.event_id == event_id:
                    return event
        return None

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._persist()

    def count(self) -> int:
        with self._lock:
            return len(self._events)


store = EventStore(EVENTS_FILE)
app = FastAPI(title="Jenkins Failure Log Monitor", version="0.3.0")


class FixApplyRequest(BaseModel):
    base_branch: str | None = None


class GitHubFetchRequest(BaseModel):
    repo_name: str
    branch_name: str


class GitHubPushRequest(BaseModel):
    repo_name: str
    base_branch: str
    new_branch: str
    target_file: str
    target_path: str | None = None
    updated_content: str
    commit_message: str


def _env_flag(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _env_value(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


GITHUB_API_URL = os.getenv("PAYLOAD_MONITOR_GITHUB_API_URL", "https://api.github.com")
GITHUB_TOKEN = _env_value("PAYLOAD_MONITOR_GITHUB_TOKEN", "GITHUB_TOKEN")
GITHUB_DRY_RUN = _env_flag("PAYLOAD_MONITOR_GITHUB_DRY_RUN", True)
DEFAULT_BASE_BRANCH = os.getenv("PAYLOAD_MONITOR_DEFAULT_BASE_BRANCH", "qa")
REMEDIATION_DIR = RUNTIME_DIR / "remediation"
VERSION_PATTERN = r"\d[\w.\-+:~]*"


def _mask_header_value(name: str, value: str) -> str:
    lowered = name.lower()
    if lowered in SENSITIVE_HEADERS:
        if len(value) <= 6:
            return "*" * len(value)
        return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
    return value


def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: _mask_header_value(name, value) for name, value in headers.items()}


def _normalize_console_text(text: str | None) -> str:
    if not text:
        return ""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = ANSI_ESCAPE_RE.sub("", normalized)
    return normalized.strip("\n")


def _count_lines(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + 1


def _extract_payload_console_text(payload: Any | None, raw_body: str = "") -> str:
    if isinstance(payload, dict):
        console_text = payload.get("console_text")
        if isinstance(console_text, str) and console_text.strip():
            return _normalize_console_text(console_text)
    return _normalize_console_text(raw_body)


def _resolve_build_url(payload: Any | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    build_url = payload.get("build_url")
    if isinstance(build_url, str) and build_url.strip():
        return build_url.strip()
    return None


def _build_summary(
    payload: Any | None,
    raw_body: str,
    request: Request,
    content_length: int,
    console_text: str,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "method": request.method,
        "path": request.url.path,
        "byte_size": content_length,
        "json_valid": payload is not None,
        "received_from": request.client.host if request.client else None,
        "console_line_count": _count_lines(console_text),
        "console_char_count": len(console_text),
        "console_status": "payload-only" if console_text else "missing",
    }

    build_url = _resolve_build_url(payload)
    if build_url:
        summary["build_url"] = build_url

    if isinstance(payload, dict):
        summary.update(
            {
                "job_name": payload.get("job_name"),
                "status": payload.get("status"),
                "repo": payload.get("repo"),
                "branch": payload.get("branch"),
                "build_number": payload.get("build_number"),
                "payload_kind": "json-object",
                "top_level_keys": list(payload.keys())[:12],
            }
        )
    elif isinstance(payload, list):
        summary.update(
            {
                "payload_kind": "json-array",
                "item_count": len(payload),
            }
        )
    elif raw_body:
        summary.update({"payload_kind": "raw-text"})
    else:
        summary.update({"payload_kind": "empty"})

    return summary


def _payload_preview(payload: Any | None) -> Any | None:
    if not isinstance(payload, dict):
        return payload

    preview = dict(payload)
    console_text = preview.get("console_text")
    if isinstance(console_text, str) and console_text:
        preview["console_text"] = (
            f"[collapsed in payload view: {len(console_text):,} characters. "
            "See Failure Log section instead.]"
        )
    return preview


def _pretty_payload(event: StoredEvent) -> str:
    if event.payload is not None:
        return json.dumps(_payload_preview(event.payload), indent=2, ensure_ascii=False)
    if event.raw_body:
        return event.raw_body
    return "{}"


def _build_console_view(event: StoredEvent) -> dict[str, Any]:
    console_text = event.console_text or _extract_payload_console_text(event.payload, event.raw_body)
    return {
        "source": event.console_source,
        "status": event.console_status,
        "line_count": _count_lines(console_text),
        "char_count": len(console_text),
        "raw_text": console_text,
    }


def _extract_cve_ids(text: str) -> list[str]:
    matches = re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)
    return sorted({match.upper() for match in matches})


def _extract_package_versions(console_text: str) -> tuple[str | None, str | None, str | None, str | None]:
    patterns = [
        re.compile(
            rf"(?:pkg|package)[=: ](?P<package>[a-zA-Z0-9._:+-]+).*?"
            rf"installed version[=: ](?P<current>{VERSION_PATTERN}).*?"
            rf"fixed version[=: ](?P<recommended>{VERSION_PATTERN})(?:.*?target[=: ](?P<target>\S+))?",
            flags=re.IGNORECASE,
        ),
        re.compile(
            rf"(?P<package>[a-zA-Z0-9._:+-]+)=(?P<current>{VERSION_PATTERN}).*?"
            rf"(?:fixed version|required|upgrade to)\s+(?P<recommended>{VERSION_PATTERN})(?:.*?target[=: ](?P<target>\S+))?",
            flags=re.IGNORECASE,
        ),
        re.compile(
            rf"(?P<package>[a-zA-Z0-9._:+-]+)\s+installed\s+(?P<current>{VERSION_PATTERN}).*?"
            rf"(?:fixed in|patched in)\s+(?P<recommended>{VERSION_PATTERN})(?:.*?target[=: ](?P<target>\S+))?",
            flags=re.IGNORECASE,
        ),
    ]

    for line in console_text.splitlines():
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                return (
                    match.group("package"),
                    match.group("current"),
                    match.group("recommended"),
                    match.groupdict().get("target"),
                )

    return None, None, None, None


def _event_payload_value(event: StoredEvent, key: str) -> Any | None:
    if isinstance(event.payload, dict):
        return event.payload.get(key)
    return None


def _determine_target_file(event: StoredEvent, console_text: str, explicit_target: str | None) -> str:
    candidate = explicit_target or _event_payload_value(event, "target_file") or _event_payload_value(event, "manifest_path")
    if isinstance(candidate, str) and candidate.strip():
        return candidate.strip()

    lower_text = console_text.lower()
    if "pom.xml" in lower_text:
        return "pom.xml"
    if "build.gradle" in lower_text or "build.gradle.kts" in lower_text:
        return "build.gradle"
    if "package-lock.json" in lower_text:
        return "package-lock.json"
    return "Dockerfile"


def _solution_kind_for_target(target_file: str) -> str:
    lower_name = target_file.lower()
    if lower_name.endswith("pom.xml") or lower_name.endswith("build.gradle") or lower_name.endswith("build.gradle.kts"):
        return "bom-friendly-upgrade"
    if lower_name.endswith("dockerfile"):
        return "docker-package-upgrade"
    return "manifest-version-bump"


def _analyze_event(event: StoredEvent) -> dict[str, Any]:
    console_text = event.console_text or _extract_payload_console_text(event.payload, event.raw_body)
    cve_ids = _extract_cve_ids(console_text)
    package_name, current_version, recommended_version, explicit_target = _extract_package_versions(console_text)
    target_file = _determine_target_file(event, console_text, explicit_target)
    solution_kind = _solution_kind_for_target(target_file)
    supported = bool(package_name and current_version and recommended_version)
    confidence = 0.91 if supported else 0.20

    recommendation = (
        "Prefer upgrading the BOM, parent, or managed property before hard-coding a dependency version."
        if solution_kind == "bom-friendly-upgrade"
        else "Upgrade the vulnerable version in the deployment manifest."
    )
    summary = (
        f"{package_name} should move from {current_version} to {recommended_version} in {target_file}."
        if supported
        else "The failure payload was captured, but the log pattern was not specific enough for a safe automatic patch."
    )

    actions = []
    if supported:
        actions.append(f"Review {target_file} for {package_name} version {current_version}.")
        actions.append(f"Apply {recommended_version} using a {solution_kind} strategy.")
        if solution_kind == "bom-friendly-upgrade":
            actions.append("If the dependency is managed by a Spring Boot parent or BOM, update that source instead of adding a new inline version.")

    return {
        "analysis_id": f"an_{uuid4().hex[:10]}",
        "event_id": event.event_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "supported": supported,
        "issue_type": "VULNERABILITY" if supported else "UNSUPPORTED",
        "confidence": confidence,
        "package_name": package_name,
        "current_version": current_version,
        "recommended_version": recommended_version,
        "target_file": target_file,
        "solution_kind": solution_kind,
        "cve_ids": cve_ids,
        "summary": summary,
        "recommendation": recommendation,
        "actions": actions,
        "repo": _event_payload_value(event, "repo"),
        "branch": _event_payload_value(event, "branch"),
    }


def _resolve_target_file(event: StoredEvent, target_file: str) -> Path | None:
    if not event.local_repo_path:
        return None
    candidate = Path(event.local_repo_path).resolve() / target_file
    return candidate if candidate.exists() else None


def _normalize_package_coordinates(package_name: str | None) -> tuple[str | None, str | None]:
    if not package_name:
        return None, None
    if ":" in package_name:
        group_id, artifact_id = package_name.split(":", 1)
        return group_id, artifact_id
    return None, package_name


def _patch_dependency_block(block: str, group_id: str | None, artifact_id: str | None, current_version: str, recommended_version: str) -> tuple[str, bool]:
    group_match = True
    artifact_match = True
    if group_id:
        group_match = re.search(rf"<groupId>\s*{re.escape(group_id)}\s*</groupId>", block) is not None
    if artifact_id:
        artifact_match = re.search(rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>", block) is not None
    if not (group_match and artifact_match):
        return block, False

    replaced_block, replacements = re.subn(
        rf"(<version>\s*){re.escape(current_version)}(\s*</version>)",
        rf"\g<1>{recommended_version}\g<2>",
        block,
        count=1,
    )
    return replaced_block, replacements > 0


def _patch_pom_xml(content: str, package_name: str | None, current_version: str, recommended_version: str) -> tuple[str, str, bool]:
    group_id, artifact_id = _normalize_package_coordinates(package_name)
    dependency_pattern = re.compile(r"<dependency>.*?</dependency>", flags=re.DOTALL)

    for match in dependency_pattern.finditer(content):
        updated_block, changed = _patch_dependency_block(
            match.group(0),
            group_id=group_id,
            artifact_id=artifact_id,
            current_version=current_version,
            recommended_version=recommended_version,
        )
        if changed:
            return (
                f"{content[:match.start()]}{updated_block}{content[match.end():]}",
                "direct-dependency-version-bump",
                True,
            )

    property_pattern = re.compile(
        rf"(<(?P<name>[A-Za-z0-9_.-]*version[A-Za-z0-9_.-]*)>\s*){re.escape(current_version)}(\s*</(?P=name)>)"
    )
    property_match = property_pattern.search(content)
    if property_match:
        updated_content = property_pattern.sub(
            rf"\g<1>{recommended_version}\g<3>",
            content,
            count=1,
        )
        return updated_content, "bom-property-version-bump", True

    return content, "manual-bom-review", False


def _patch_file_content(target_file: str, original_content: str, package_name: str | None, current_version: str, recommended_version: str) -> tuple[str, str, bool]:
    lower_name = target_file.lower()
    if lower_name.endswith("pom.xml"):
        return _patch_pom_xml(original_content, package_name, current_version, recommended_version)

    updated_content, replacements = re.subn(re.escape(current_version), recommended_version, original_content, count=1)
    strategy = "direct-version-bump" if replacements else "manual-review"
    return updated_content, strategy, replacements > 0


def _build_diff_preview(original_content: str, updated_content: str) -> list[str]:
    import difflib

    diff_lines: list[str] = []
    for line in difflib.unified_diff(
        original_content.splitlines(),
        updated_content.splitlines(),
        fromfile="before",
        tofile="after",
        lineterm="",
    ):
        if (line.startswith("-") or line.startswith("+")) and not line.startswith("---") and not line.startswith("+++"):
            diff_lines.append(line)
    return diff_lines


def _build_branch_name(analysis: dict[str, Any]) -> str:
    package_name = str(analysis.get("package_name") or "dependency").replace(":", "-").replace(".", "-").replace("_", "-")
    cve_part = str((analysis.get("cve_ids") or ["remediation"])[0]).lower()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"auto-fix/{package_name}-{cve_part}-{timestamp}"


def _prepare_fix(event: StoredEvent, analysis: dict[str, Any]) -> dict[str, Any]:
    target_file = str(analysis.get("target_file") or "Dockerfile")
    target_path = _resolve_target_file(event, target_file)
    base_branch = str(analysis.get("branch") or DEFAULT_BASE_BRANCH)
    current_version = str(analysis.get("current_version") or "")
    recommended_version = str(analysis.get("recommended_version") or "")
    package_name = analysis.get("package_name")

    if target_path:
        original_content = target_path.read_text(encoding="utf-8")
    else:
        repo_name = _event_payload_value(event, "repo")
        original_content = (
            _fetch_github_file_content(repo_name, target_file, base_branch)
            if isinstance(repo_name, str) and "/" in repo_name
            else None
        )

    if original_content is None:
        return {
            "proposal_id": f"fp_{uuid4().hex[:10]}",
            "event_id": event.event_id,
            "analysis_id": analysis.get("analysis_id"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "manual-review-required",
            "branch_name": _build_branch_name(analysis),
            "target_file": target_file,
            "target_file_path": str(target_path) if target_path else None,
            "patch_strategy": "source-content-unavailable",
            "diff_preview": [],
            "pr_title": f"Review vulnerability remediation for {target_file}",
            "pr_body": (
                "The payload was analyzed successfully, but the service could not read the source file content "
                "from a local checkout or GitHub. Provide local_repo_path or enable live GitHub access."
            ),
            "updated_file_content": "",
            "original_file_content": "",
            "package_name": package_name,
            "current_version": current_version,
            "recommended_version": recommended_version,
        }

    updated_content, patch_strategy, patched = _patch_file_content(
        target_file=target_file,
        original_content=original_content,
        package_name=package_name,
        current_version=current_version,
        recommended_version=recommended_version,
    )
    diff_preview = _build_diff_preview(original_content, updated_content) if patched else []

    summary = analysis.get("summary") or "Automated remediation proposal."
    pr_title = f"Fix vulnerability in {target_file}: {package_name}"
    pr_body = (
        f"{summary}\n\n"
        f"- Base branch: {base_branch}\n"
        f"- Target file: {target_file}\n"
        f"- Patch strategy: {patch_strategy}\n"
        f"- Recommendation: {analysis.get('recommendation') or 'Review before merge'}\n"
    )

    return {
        "proposal_id": f"fp_{uuid4().hex[:10]}",
        "event_id": event.event_id,
        "analysis_id": analysis.get("analysis_id"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "ready" if patched else "manual-review-required",
        "branch_name": _build_branch_name(analysis),
        "target_file": target_file,
        "target_file_path": str(target_path) if target_path else None,
        "patch_strategy": patch_strategy,
        "diff_preview": diff_preview,
        "pr_title": pr_title,
        "pr_body": pr_body,
        "updated_file_content": updated_content,
        "original_file_content": original_content,
        "package_name": package_name,
        "current_version": current_version,
        "recommended_version": recommended_version,
    }


def _write_artifact(event: StoredEvent, proposal: dict[str, Any]) -> Path:
    artifact_dir = REMEDIATION_DIR / event.event_id / str(proposal["proposal_id"])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    target_file = Path(str(proposal["target_file"]))
    artifact_path = artifact_dir / target_file.name
    artifact_path.write_text(str(proposal.get("updated_file_content") or ""), encoding="utf-8")
    return artifact_path


def _repo_parts(repo_name: str) -> tuple[str, str]:
    owner, repo = repo_name.split("/", 1)
    return owner, repo


def _fetch_github_file_content(repo_name: str, target_file: str, base_branch: str) -> str | None:
    if GITHUB_DRY_RUN or not GITHUB_TOKEN:
        return None

    owner, repo = _repo_parts(repo_name)
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    with httpx.Client(base_url=GITHUB_API_URL, headers=headers, timeout=20.0) as client:
        response = client.get(
            f"/repos/{owner}/{repo}/contents/{target_file}",
            params={"ref": base_branch},
        )
        if response.status_code >= 400:
            return None
        payload = response.json()

    encoded_content = payload.get("content")
    if not isinstance(encoded_content, str) or payload.get("encoding") != "base64":
        return None
    return base64.b64decode(encoded_content).decode("utf-8")


def _apply_fix_to_github(event: StoredEvent, proposal: dict[str, Any], base_branch: str) -> dict[str, Any]:
    repo_name = _event_payload_value(event, "repo")
    if not isinstance(repo_name, str) or "/" not in repo_name:
        raise HTTPException(status_code=400, detail="Webhook payload must include repo in owner/name format.")

    artifact_path = _write_artifact(event, proposal)
    branch_name = str(proposal["branch_name"])
    target_file = str(proposal["target_file"])

    if GITHUB_DRY_RUN or not GITHUB_TOKEN:
        owner, repo = _repo_parts(repo_name)
        return {
            "status": "dry-run",
            "base_branch": base_branch,
            "branch_name": branch_name,
            "pull_request_url": f"https://github.example.local/{owner}/{repo}/compare/{base_branch}...{branch_name}",
            "artifact_file_path": str(artifact_path),
            "message": "Dry run only. Set PAYLOAD_MONITOR_GITHUB_DRY_RUN=false and PAYLOAD_MONITOR_GITHUB_TOKEN to push for real.",
        }

    owner, repo = _repo_parts(repo_name)
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    with httpx.Client(base_url=GITHUB_API_URL, headers=headers, timeout=20.0) as client:
        ref_response = client.get(f"/repos/{owner}/{repo}/git/ref/heads/{base_branch}")
        ref_response.raise_for_status()
        base_sha = ref_response.json()["object"]["sha"]

        create_ref_response = client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
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
                "message": str(proposal["pr_title"]),
                "content": base64.b64encode(str(proposal["updated_file_content"]).encode("utf-8")).decode("utf-8"),
                "branch": branch_name,
                "sha": existing_sha,
            },
        )
        update_response.raise_for_status()

        pr_response = client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": str(proposal["pr_title"]),
                "body": str(proposal["pr_body"]),
                "head": branch_name,
                "base": base_branch,
            },
        )
        pr_response.raise_for_status()

    return {
        "status": "applied",
        "base_branch": base_branch,
        "branch_name": branch_name,
        "pull_request_url": pr_response.json()["html_url"],
        "artifact_file_path": str(artifact_path),
        "message": "Branch pushed and pull request created.",
    }


def _list_item(event: StoredEvent) -> dict[str, Any]:
    console_text = event.console_text or _extract_payload_console_text(event.payload, event.raw_body)
    return {
        "event_id": event.event_id,
        "received_at": event.received_at,
        "content_length": event.content_length,
        "content_type": event.content_type,
        "method": event.method,
        "path": event.path,
        "summary": event.summary,
        "console": {
            "status": event.console_status,
            "source": event.console_source,
            "line_count": _count_lines(console_text),
        },
        "analysis": event.analysis,
        "proposal": event.proposal,
        "github_result": event.github_result,
    }


def _preview_text(text: str, limit: int = 280) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[:limit].rstrip()}..."


@app.get("/tester", response_class=HTMLResponse)
def tester_dashboard() -> HTMLResponse:
    return HTMLResponse(
        """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Non-AI Flow Tester</title>
  <style>
    :root {
      --bg: #f4f5f1;
      --panel: #ffffff;
      --line: #d7ddd4;
      --ink: #1b1d1f;
      --muted: #5e646b;
      --accent: #21543d;
      --danger: #a3362b;
      --code: #111315;
      --code-ink: #eef2ef;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--ink);
    }
    .shell {
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }
    h1, h2, p { margin: 0; }
    h1 { font-size: 32px; margin-bottom: 8px; }
    p { color: var(--muted); line-height: 1.5; }
    .topbar {
      display: grid;
      gap: 12px;
      margin-bottom: 20px;
    }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      padding: 8px 12px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel);
      font-size: 13px;
    }
    .layout {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }
    .card {
      display: grid;
      gap: 12px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: var(--panel);
    }
    .wide { grid-column: 1 / -1; }
    .row {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    label {
      display: grid;
      gap: 6px;
      font-size: 13px;
      color: var(--muted);
    }
    input, textarea {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 12px;
      font: inherit;
      color: var(--ink);
      background: #fbfcfa;
    }
    textarea {
      min-height: 110px;
      resize: vertical;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    button {
      padding: 10px 14px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #fff;
      font: inherit;
      cursor: pointer;
    }
    button.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }
    .status {
      font-size: 13px;
      color: var(--muted);
    }
    .error { color: var(--danger); }
    pre {
      margin: 0;
      min-height: 120px;
      padding: 14px;
      border-radius: 12px;
      background: var(--code);
      color: var(--code-ink);
      overflow: auto;
      font: 12px/1.5 Consolas, "Courier New", monospace;
    }
    @media (max-width: 900px) {
      .layout, .row { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="topbar">
      <div>
        <h1>Non-AI Flow Tester</h1>
        <p>Minimal page for Jenkins failure webhook capture, GitHub repo fetch by branch, and pushing a new vulnerability-fix branch.</p>
      </div>
      <div class="meta">
        <div class="chip">Health: <strong id="health-status">checking</strong></div>
        <div class="chip">Events: <strong id="event-count">0</strong></div>
        <div class="chip">Latest Event: <strong id="latest-event-id">none</strong></div>
      </div>
    </section>

    <section class="layout">
      <div class="card">
        <h2>1. Jenkins Failure Webhook</h2>
        <p>Post a failed build payload and store the console output.</p>
        <label>
          Payload JSON
          <textarea id="webhook-payload"></textarea>
        </label>
        <div class="actions">
          <button class="primary" id="send-webhook">Send Payload</button>
          <button id="load-sample">Load Sample</button>
          <button id="clear-events">Clear Events</button>
        </div>
        <div class="status" id="webhook-status">Idle</div>
        <pre id="webhook-output">No webhook sent yet.</pre>
      </div>

      <div class="card">
        <h2>2. Latest Event / Fix Flow</h2>
        <p>Inspect the latest captured event, prepare the fix, and run the apply flow.</p>
        <div class="actions">
          <button class="primary" id="refresh-latest">Refresh Latest</button>
          <button id="prepare-fix">Prepare Fix</button>
          <button id="apply-fix">Apply Fix</button>
        </div>
        <div class="status" id="latest-status">Idle</div>
        <pre id="latest-output">No event loaded yet.</pre>
      </div>

      <div class="card">
        <h2>3. GitHub Fetch By Repo And Branch</h2>
        <div class="row">
          <label>
            Repo
            <input id="fetch-repo" value="owner/repo">
          </label>
          <label>
            Branch
            <input id="fetch-branch" value="qa">
          </label>
        </div>
        <div class="actions">
          <button class="primary" id="fetch-files">Fetch Files</button>
        </div>
        <div class="status" id="fetch-status">Requires GitHub token.</div>
        <pre id="fetch-output">No fetch executed yet.</pre>
      </div>

      <div class="card">
        <h2>4. Push New Fix Branch To GitHub</h2>
        <div class="row">
          <label>
            Repo
            <input id="push-repo" value="owner/repo">
          </label>
          <label>
            Base branch
            <input id="push-base-branch" value="qa">
          </label>
        </div>
        <div class="row">
          <label>
            New branch
            <input id="push-new-branch" value="auto-fix/test-branch">
          </label>
          <label>
            Target file
            <input id="push-target-file" value="Dockerfile">
          </label>
        </div>
        <label>
          Target path (optional)
          <input id="push-target-path" value="">
        </label>
        <label>
          Commit message
          <input id="push-commit-message" value="Apply vulnerability fix">
        </label>
        <label>
          Updated file content
          <textarea id="push-content">FROM eclipse-temurin:21</textarea>
        </label>
        <div class="actions">
          <button class="primary" id="push-file">Push Branch</button>
        </div>
        <div class="status" id="push-status">Requires GitHub token.</div>
        <pre id="push-output">No push executed yet.</pre>
      </div>

      <div class="card wide">
        <h2>Latest Console Output</h2>
        <pre id="console-output">No console text loaded yet.</pre>
      </div>
    </section>
  </div>

  <script>
    const samplePayload = {
      job_name: "demo-payment-service",
      build_number: 17,
      build_url: "http://jenkins.example/job/demo-payment-service/17/",
      repo: "acme/payment-service",
      branch: "qa",
      status: "FAILED",
      console_text:
        "2026-04-28T09:00:00Z CRITICAL CVE-2026-1111 pkg=openssl installed version 1.1.1 fixed version 3.0.14 target=Dockerfile\\n" +
        "2026-04-28T09:00:01Z ERROR Deployment blocked."
    };

    const state = { latestEventId: null };

    function pretty(value) {
      return JSON.stringify(value, null, 2);
    }

    function setStatus(id, message, isError = false) {
      const node = document.getElementById(id);
      node.textContent = message;
      node.className = isError ? "status error" : "status";
    }

    function setOutput(id, value) {
      document.getElementById(id).textContent = typeof value === "string" ? value : pretty(value);
    }

    async function requestJson(url, options = {}) {
      const response = await fetch(url, options);
      const text = await response.text();
      const payload = text ? JSON.parse(text) : {};
      if (!response.ok) {
        throw new Error(payload.detail || text || `Request failed with ${response.status}`);
      }
      return payload;
    }

    async function refreshSummary() {
      const [health, events] = await Promise.all([
        requestJson("/api/v1/health"),
        requestJson("/api/events?limit=1")
      ]);
      document.getElementById("health-status").textContent = health.status;
      document.getElementById("event-count").textContent = String(health.event_count);
      state.latestEventId = events.events[0]?.event_id || null;
      document.getElementById("latest-event-id").textContent = state.latestEventId || "none";
    }

    async function loadLatestEvent() {
      await refreshSummary();
      if (!state.latestEventId) {
        setStatus("latest-status", "No events captured yet.");
        setOutput("latest-output", "No event loaded yet.");
        setOutput("console-output", "No console text loaded yet.");
        return;
      }
      const event = await requestJson(`/api/events/${state.latestEventId}`);
      setStatus("latest-status", `Loaded ${state.latestEventId}`);
      setOutput("latest-output", event);
      setOutput("console-output", event.console?.raw_text || "No console text found.");
    }

    document.getElementById("load-sample").addEventListener("click", () => {
      document.getElementById("webhook-payload").value = pretty(samplePayload);
    });

    document.getElementById("send-webhook").addEventListener("click", async () => {
      try {
        const payload = JSON.parse(document.getElementById("webhook-payload").value);
        const result = await requestJson("/api/v1/webhooks/jenkins/failure", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        setStatus("webhook-status", "Webhook accepted.");
        setOutput("webhook-output", result);
        await loadLatestEvent();
      } catch (error) {
        setStatus("webhook-status", error.message || "Webhook request failed.", true);
      }
    });

    document.getElementById("clear-events").addEventListener("click", async () => {
      try {
        const result = await requestJson("/api/events", { method: "DELETE" });
        setStatus("webhook-status", "Event feed cleared.");
        setOutput("webhook-output", result);
        await loadLatestEvent();
      } catch (error) {
        setStatus("webhook-status", error.message, true);
      }
    });

    document.getElementById("refresh-latest").addEventListener("click", async () => {
      try {
        await loadLatestEvent();
      } catch (error) {
        setStatus("latest-status", error.message, true);
      }
    });

    document.getElementById("prepare-fix").addEventListener("click", async () => {
      try {
        if (!state.latestEventId) {
          throw new Error("No latest event to prepare.");
        }
        const result = await requestJson(`/api/events/${state.latestEventId}/prepare-fix`, { method: "POST" });
        setStatus("latest-status", "Fix proposal prepared.");
        setOutput("latest-output", result);
      } catch (error) {
        setStatus("latest-status", error.message, true);
      }
    });

    document.getElementById("apply-fix").addEventListener("click", async () => {
      try {
        if (!state.latestEventId) {
          throw new Error("No latest event to apply.");
        }
        const result = await requestJson(`/api/events/${state.latestEventId}/apply-fix`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ base_branch: "qa" }),
        });
        setStatus("latest-status", "Fix flow executed.");
        setOutput("latest-output", result);
      } catch (error) {
        setStatus("latest-status", error.message, true);
      }
    });

    document.getElementById("fetch-files").addEventListener("click", async () => {
      try {
        const result = await requestJson("/api/github/fetch-files", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repo_name: document.getElementById("fetch-repo").value.trim(),
            branch_name: document.getElementById("fetch-branch").value.trim(),
          }),
        });
        setStatus("fetch-status", "Fetch completed.");
        setOutput("fetch-output", result);
      } catch (error) {
        setStatus("fetch-status", error.message, true);
      }
    });

    document.getElementById("push-file").addEventListener("click", async () => {
      try {
        const result = await requestJson("/api/github/push-file", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repo_name: document.getElementById("push-repo").value.trim(),
            base_branch: document.getElementById("push-base-branch").value.trim(),
            new_branch: document.getElementById("push-new-branch").value.trim(),
            target_file: document.getElementById("push-target-file").value.trim(),
            target_path: document.getElementById("push-target-path").value.trim() || null,
            updated_content: document.getElementById("push-content").value,
            commit_message: document.getElementById("push-commit-message").value.trim(),
          }),
        });
        setStatus("push-status", "Push request completed.");
        setOutput("push-output", result);
      } catch (error) {
        setStatus("push-status", error.message, true);
      }
    });

    document.getElementById("webhook-payload").value = pretty(samplePayload);
    loadLatestEvent().catch((error) => setStatus("latest-status", error.message, true));
  </script>
</body>
</html>
        """
    )


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    return HTMLResponse(
        """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Jenkins Failure Log Monitor</title>
  <style>
    :root {
      --bg: #f6f0e5;
      --panel: rgba(255, 252, 247, 0.88);
      --panel-strong: rgba(255, 255, 255, 0.96);
      --ink: #1b2833;
      --muted: #5f6d78;
      --line: rgba(27, 40, 51, 0.12);
      --accent: #bf5a21;
      --danger: #a3362b;
      --console-bg: #13212b;
      --console-ink: #edf6f8;
      --shadow: 0 22px 70px rgba(65, 44, 15, 0.14);
      --radius: 22px;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Aptos, "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(191, 90, 33, 0.16), transparent 27%),
        radial-gradient(circle at 78% 12%, rgba(29, 122, 84, 0.10), transparent 21%),
        linear-gradient(180deg, #fbf7f0 0%, #f3eadc 100%);
      min-height: 100vh;
    }

    a {
      color: inherit;
      text-decoration: none;
    }

    button {
      font: inherit;
    }

    .shell {
      width: min(1450px, calc(100vw - 32px));
      margin: 20px auto;
      padding: 20px;
      border-radius: 30px;
      border: 1px solid rgba(255, 255, 255, 0.55);
      background: rgba(255, 250, 244, 0.74);
      box-shadow: var(--shadow);
      backdrop-filter: blur(16px);
    }

    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(280px, 0.75fr);
      gap: 18px;
      margin-bottom: 18px;
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 22px;
    }

    h1, h2, h3 {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      letter-spacing: 0.01em;
    }

    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.85);
      border: 1px solid var(--line);
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 14px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .subtitle {
      margin-top: 12px;
      color: var(--muted);
      line-height: 1.6;
      max-width: 760px;
    }

    .route-chip {
      display: inline-flex;
      margin-top: 14px;
      padding: 10px 14px;
      border-radius: 14px;
      background: #182731;
      color: #eef6f8;
      font-family: Consolas, "Courier New", monospace;
      font-size: 13px;
    }

    .stats {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid var(--line);
      color: var(--muted);
      font-size: 14px;
    }

    .badge strong {
      color: var(--ink);
    }

    .controls {
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-end;
      align-items: flex-start;
      gap: 10px;
      height: 100%;
    }

    .button {
      border: 0;
      border-radius: 999px;
      padding: 12px 18px;
      cursor: pointer;
      transition: transform 0.16s ease, box-shadow 0.16s ease, background 0.16s ease;
    }

    .button:hover {
      transform: translateY(-1px);
    }

    .button.primary {
      color: white;
      background: linear-gradient(135deg, #bf5a21 0%, #de7832 100%);
      box-shadow: 0 12px 26px rgba(191, 90, 33, 0.24);
    }

    .button.secondary {
      color: var(--ink);
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid var(--line);
    }

    .layout {
      display: grid;
      grid-template-columns: 360px minmax(0, 1fr);
      gap: 18px;
      min-height: 72vh;
    }

    .feed {
      display: flex;
      flex-direction: column;
      gap: 12px;
      max-height: 72vh;
      overflow-y: auto;
      padding-right: 4px;
    }

    .event-card {
      width: 100%;
      text-align: left;
      border: 1px solid rgba(191, 90, 33, 0.14);
      border-radius: 18px;
      padding: 16px;
      background: rgba(255, 255, 255, 0.76);
      cursor: pointer;
      transition: border-color 0.16s ease, background 0.16s ease, transform 0.16s ease;
    }

    .event-card:hover {
      transform: translateY(-1px);
      border-color: rgba(191, 90, 33, 0.34);
    }

    .event-card.active {
      border-color: rgba(191, 90, 33, 0.42);
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(191, 90, 33, 0.08));
    }

    .event-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
    }

    .event-title {
      font-size: 16px;
      font-weight: 700;
      line-height: 1.35;
    }

    .status-pill {
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 12px;
      white-space: nowrap;
      color: var(--danger);
      background: rgba(163, 54, 43, 0.12);
      border: 1px solid rgba(163, 54, 43, 0.18);
    }

    .meta {
      margin-top: 10px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }

    .detail-shell {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .detail-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 14px;
      padding-bottom: 4px;
      border-bottom: 1px solid var(--line);
    }

    .detail-subtitle {
      margin-top: 8px;
      color: var(--muted);
      line-height: 1.5;
    }

    .status-tag {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 12px;
      border-radius: 999px;
      font-size: 13px;
      color: var(--danger);
      background: rgba(163, 54, 43, 0.12);
      border: 1px solid rgba(163, 54, 43, 0.18);
      white-space: nowrap;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }

    .detail-box,
    .section-card {
      background: var(--panel-strong);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 16px;
    }

    .detail-label {
      color: var(--muted);
      font-size: 12px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-bottom: 8px;
    }

    .detail-value {
      font-size: 15px;
      line-height: 1.5;
      word-break: break-word;
      white-space: pre-wrap;
    }

    .section-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }

    .section-title p {
      margin: 0;
      color: var(--muted);
      font-size: 14px;
    }

    .link-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }

    .link-chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 12px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid var(--line);
      color: var(--ink);
      font-size: 14px;
    }

    pre {
      margin: 0;
      padding: 18px;
      overflow: auto;
      background: var(--console-bg);
      color: var(--console-ink);
      font: 13px/1.65 Consolas, "Courier New", monospace;
      border-radius: 18px;
      max-height: 560px;
    }

    .empty-state {
      display: grid;
      place-items: center;
      min-height: 56vh;
      color: var(--muted);
      text-align: center;
      padding: 24px;
      border: 1px dashed rgba(27, 40, 51, 0.18);
      border-radius: 24px;
      background: rgba(255, 255, 255, 0.52);
    }

    .error-banner {
      display: none;
      margin-bottom: 16px;
      padding: 14px 16px;
      border-radius: 18px;
      background: rgba(163, 54, 43, 0.1);
      border: 1px solid rgba(163, 54, 43, 0.18);
      color: var(--danger);
    }

    .error-banner.show {
      display: block;
    }

    @media (max-width: 1080px) {
      .grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 980px) {
      .hero,
      .layout,
      .grid {
        grid-template-columns: 1fr;
      }

      .controls {
        justify-content: flex-start;
      }

      .detail-header {
        flex-direction: column;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div id="error-banner" class="error-banner"></div>

    <section class="hero">
      <div class="panel">
        <div class="eyebrow">Payload Only</div>
        <h1>Jenkins Failure Log Monitor</h1>
        <p class="subtitle">
          Lightweight monitor for failed builds. It does not fetch or analyze extra Jenkins data.
          It only stores the console log text that arrives in the webhook payload and makes that
          failure log easy to copy or consume.
        </p>
        <div class="route-chip">POST /api/v1/webhooks/jenkins/failure</div>
        <div class="stats">
          <div class="badge">App status <strong id="health-status">checking</strong></div>
          <div class="badge">Stored requests <strong id="event-count">0</strong></div>
          <div class="badge">Latest refresh <strong id="last-refresh">never</strong></div>
        </div>
      </div>

      <div class="panel">
        <div class="eyebrow">Operator Controls</div>
        <div class="controls">
          <button class="button secondary" id="clear-button">Clear Feed</button>
          <button class="button primary" id="refresh-button">Refresh Now</button>
        </div>
        <p class="subtitle">
          The monitor only uses the `console_text` value that Jenkins sends in the webhook body.
        </p>
      </div>
    </section>

    <section class="layout">
      <div class="panel">
        <h2>Incoming Failures</h2>
        <p class="subtitle">
          Newest first. Select a failure to view the raw console log that came in the webhook.
        </p>
        <div class="feed" id="event-list"></div>
      </div>

      <div class="panel" id="detail-panel">
        <div class="empty-state">
          <div>
            <h2>No failure logs yet</h2>
            <p class="subtitle">
              Trigger a failed Jenkins build and the webhook payload log will appear here.
            </p>
          </div>
        </div>
      </div>
    </section>
  </div>

  <script>
    const state = {
      events: [],
      selectedId: null,
      selectedEvent: null,
    };

    async function fetchJson(url, options = {}) {
      const response = await fetch(url, options);
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Request failed with ${response.status}`);
      }
      return response.json();
    }

    function showError(message) {
      const banner = document.getElementById("error-banner");
      if (!message) {
        banner.className = "error-banner";
        banner.textContent = "";
        return;
      }
      banner.className = "error-banner show";
      banner.textContent = message;
    }

    function formatTime(isoString) {
      if (!isoString) {
        return "n/a";
      }

      const date = new Date(isoString);
      if (Number.isNaN(date.getTime())) {
        return isoString;
      }

      return new Intl.DateTimeFormat([], {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(date);
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function formatNumber(value) {
      const numeric = Number(value ?? 0);
      if (!Number.isFinite(numeric)) {
        return "0";
      }
      return numeric.toLocaleString();
    }

    function renderList() {
      const container = document.getElementById("event-list");
      container.innerHTML = "";

      if (!state.events.length) {
        container.innerHTML = `
          <div class="empty-state">
            <div>
              <h3>No payloads captured</h3>
              <p class="subtitle">Run the Jenkins job and let the webhook hit this app.</p>
            </div>
          </div>
        `;
        return;
      }

      for (const event of state.events) {
        const card = document.createElement("button");
        card.className = `event-card${event.event_id === state.selectedId ? " active" : ""}`;
        card.type = "button";
        card.innerHTML = `
          <div class="event-head">
            <div class="event-title">${escapeHtml(event.summary.job_name || event.path)}</div>
            <div class="status-pill">${escapeHtml(event.summary.status || "captured")}</div>
          </div>
          <div class="meta">
            <div><strong>${escapeHtml(formatTime(event.received_at))}</strong></div>
            <div>${escapeHtml(event.summary.repo || "repo not provided")}</div>
            <div>${escapeHtml(event.summary.branch || "branch unknown")} / build ${escapeHtml(event.summary.build_number || "n/a")}</div>
            <div>${escapeHtml(formatNumber(event.console?.line_count))} log lines</div>
          </div>
        `;
        card.addEventListener("click", () => selectEvent(event.event_id));
        container.appendChild(card);
      }
    }

    function renderLinkChip(label, url) {
      if (!url) {
        return "";
      }
      return `
        <a class="link-chip" href="${escapeHtml(url)}" target="_blank" rel="noreferrer">
          ${escapeHtml(label)}
        </a>
      `;
    }

    function renderDetail() {
      const panel = document.getElementById("detail-panel");
      if (!state.selectedEvent) {
        panel.innerHTML = `
          <div class="empty-state">
            <div>
              <h2>No request selected</h2>
              <p class="subtitle">Choose a request from the left to inspect its raw failure log.</p>
            </div>
          </div>
        `;
        return;
      }

      const event = state.selectedEvent;
      const consoleInfo = event.console || {};

      panel.innerHTML = `
        <div class="detail-shell">
          <div class="detail-header">
            <div>
              <h2>${escapeHtml(event.summary.job_name || "Captured failure")}</h2>
              <div class="detail-subtitle">
                Received ${escapeHtml(formatTime(event.received_at))} from ${escapeHtml(event.client || "unknown client")}.
              </div>
            </div>
            <div class="status-tag">${escapeHtml(event.summary.status || "captured")}</div>
          </div>

          <div class="grid">
            <div class="detail-box">
              <div class="detail-label">Repository</div>
              <div class="detail-value">${escapeHtml(event.summary.repo || "not provided")}</div>
            </div>
            <div class="detail-box">
              <div class="detail-label">Branch / Build</div>
              <div class="detail-value">${escapeHtml(event.summary.branch || "unknown")} / ${escapeHtml(event.summary.build_number || "n/a")}</div>
            </div>
            <div class="detail-box">
              <div class="detail-label">Failure Log Size</div>
              <div class="detail-value">${escapeHtml(formatNumber(consoleInfo.line_count))} lines / ${escapeHtml(formatNumber(consoleInfo.char_count))} chars</div>
            </div>
            <div class="detail-box">
              <div class="detail-label">Event ID</div>
              <div class="detail-value">${escapeHtml(event.event_id)}</div>
            </div>
          </div>

          <div class="section-card">
            <div class="section-title">
              <div>
                <h3>Log Access</h3>
                <p>Open the build or pull the raw failure log directly as plain text.</p>
              </div>
            </div>
            <div class="link-row">
              ${renderLinkChip("Open Jenkins Build", event.build_url)}
              ${renderLinkChip("Open Raw Failure Log", `/api/events/${encodeURIComponent(event.event_id)}/console.txt`)}
              ${renderLinkChip("Open Latest Failure Log", "/api/events/latest/console.txt")}
            </div>
          </div>

          <div class="section-card">
            <div class="section-title">
              <div>
                <h3>Failure Log</h3>
                <p>The raw console text exactly as it was posted in the webhook payload.</p>
              </div>
            </div>
            <pre>${escapeHtml(consoleInfo.raw_text || "No console_text was provided in the webhook payload.")}</pre>
          </div>

          <div class="grid">
            <div class="detail-box">
              <div class="detail-label">Headers</div>
              <pre>${escapeHtml(JSON.stringify(event.headers, null, 2))}</pre>
            </div>
            <div class="detail-box">
              <div class="detail-label">Payload Preview</div>
              <pre>${escapeHtml(event.pretty_payload)}</pre>
            </div>
          </div>
        </div>
      `;
    }

    async function loadEventDetail(eventId) {
      state.selectedId = eventId;
      renderList();
      state.selectedEvent = await fetchJson(`/api/events/${eventId}`);
      renderDetail();
    }

    async function selectEvent(eventId) {
      showError("");
      try {
        await loadEventDetail(eventId);
      } catch (error) {
        showError(error.message);
      }
    }

    async function refresh(forceDetail = false) {
      showError("");

      try {
        const [health, payload] = await Promise.all([
          fetchJson("/api/v1/health"),
          fetchJson("/api/events?limit=50"),
        ]);

        state.events = payload.events;

        if (!state.selectedId && state.events.length) {
          state.selectedId = state.events[0].event_id;
        }

        if (state.selectedId) {
          const selectedStillExists = state.events.some((event) => event.event_id === state.selectedId);
          if (!selectedStillExists) {
            state.selectedId = state.events[0]?.event_id || null;
            state.selectedEvent = null;
          }
        }

        document.getElementById("health-status").textContent = health.status;
        document.getElementById("event-count").textContent = String(health.event_count);
        document.getElementById("last-refresh").textContent = new Date().toLocaleTimeString();

        renderList();

        const shouldLoadDetail = Boolean(state.selectedId) && (
          forceDetail ||
          !state.selectedEvent ||
          state.selectedEvent.event_id !== state.selectedId
        );

        if (shouldLoadDetail) {
          state.selectedEvent = await fetchJson(`/api/events/${state.selectedId}`);
        }

        if (!state.selectedId) {
          state.selectedEvent = null;
        }

        renderDetail();
      } catch (error) {
        showError(error.message);
      }
    }

    async function clearFeed() {
      showError("");
      try {
        await fetchJson("/api/events", { method: "DELETE" });
        state.events = [];
        state.selectedId = null;
        state.selectedEvent = null;
        await refresh(true);
      } catch (error) {
        showError(error.message);
      }
    }

    document.getElementById("refresh-button").addEventListener("click", () => refresh(true));
    document.getElementById("clear-button").addEventListener("click", clearFeed);

    refresh(true);
    setInterval(() => refresh(false), 4000);
  </script>
</body>
</html>
        """
    )


@app.get("/api/v1/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "event_count": store.count()}


@app.post("/api/v1/webhooks/jenkins/failure", status_code=202)
async def ingest_jenkins_failure(request: Request) -> dict[str, Any]:
    body = await request.body()
    raw_body = body.decode("utf-8", errors="replace")

    payload: Any | None = None
    if raw_body.strip():
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            payload = None

    headers = _sanitize_headers(dict(request.headers))
    content_length = len(body)
    console_text = _extract_payload_console_text(payload, raw_body)

    event = StoredEvent(
        event_id=f"evt_{uuid4().hex[:10]}",
        received_at=datetime.now(timezone.utc).isoformat(),
        method=request.method,
        path=request.url.path,
        client=request.client.host if request.client else None,
        content_type=request.headers.get("content-type"),
        content_length=content_length,
        headers=headers,
        payload=payload,
        raw_body=raw_body,
        summary=_build_summary(payload, raw_body, request, content_length, console_text),
        build_url=_resolve_build_url(payload),
        console_text=console_text,
        console_source="payload",
        console_status="payload-only" if console_text else "missing",
        local_repo_path=payload.get("local_repo_path") if isinstance(payload, dict) else None,
    )
    event.analysis = _analyze_event(event)
    store.add(event)

    return {
        "status": "accepted",
        "event_id": event.event_id,
        "received_at": event.received_at,
        "console_status": event.console_status,
        "analysis_supported": bool(event.analysis and event.analysis.get("supported")),
    }


@app.get("/api/events")
def list_events(limit: int = 50) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    events = store.list_events(limit=limit)
    return {"events": [_list_item(event) for event in events]}


@app.get("/api/events/latest/console.txt", response_class=PlainTextResponse)
async def latest_console_text() -> PlainTextResponse:
    events = store.list_events(limit=1)
    if not events:
        raise HTTPException(status_code=404, detail="No events captured yet.")

    event = events[0]
    console_text = event.console_text or _extract_payload_console_text(event.payload, event.raw_body)
    if not console_text:
        raise HTTPException(status_code=404, detail="No console log is available for the latest event.")

    return PlainTextResponse(console_text)


@app.get("/api/events/{event_id}/console.txt", response_class=PlainTextResponse)
async def event_console_text(event_id: str) -> PlainTextResponse:
    event = store.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    console_text = event.console_text or _extract_payload_console_text(event.payload, event.raw_body)
    if not console_text:
        raise HTTPException(status_code=404, detail="No console log is available for this event.")

    return PlainTextResponse(console_text)


@app.get("/api/events/{event_id}")
async def get_event(event_id: str) -> dict[str, Any]:
    event = store.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    return {
        "event_id": event.event_id,
        "received_at": event.received_at,
        "method": event.method,
        "path": event.path,
        "client": event.client,
        "content_type": event.content_type,
        "content_length": event.content_length,
        "headers": event.headers,
        "summary": event.summary,
        "build_url": event.build_url,
        "pretty_payload": _pretty_payload(event),
        "console": _build_console_view(event),
        "analysis": event.analysis,
        "proposal": event.proposal,
        "github_result": event.github_result,
    }


@app.post("/api/events/{event_id}/analyze")
def analyze_event(event_id: str) -> dict[str, Any]:
    event = store.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    event.analysis = _analyze_event(event)
    store.save(event)
    return event.analysis


@app.post("/api/events/{event_id}/prepare-fix")
def prepare_fix(event_id: str) -> dict[str, Any]:
    event = store.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    analysis = event.analysis or _analyze_event(event)
    if not analysis.get("supported"):
        raise HTTPException(
            status_code=400,
            detail="The payload was captured, but the failure pattern is not specific enough for a safe automatic patch.",
        )

    event.analysis = analysis
    event.proposal = _prepare_fix(event, analysis)
    store.save(event)
    return event.proposal


@app.post("/api/events/{event_id}/apply-fix")
def apply_fix(event_id: str, payload: FixApplyRequest | None = None) -> dict[str, Any]:
    event = store.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    analysis = event.analysis or _analyze_event(event)
    if not analysis.get("supported"):
        raise HTTPException(
            status_code=400,
            detail="The current analysis does not support automatic remediation for this payload.",
        )

    proposal = event.proposal or _prepare_fix(event, analysis)
    if proposal.get("status") == "manual-review-required":
        raise HTTPException(
            status_code=400,
            detail="A BOM-friendly or dependency-managed review is required before applying this change automatically.",
        )

    requested_branch = payload.base_branch if payload and payload.base_branch else None
    base_branch = requested_branch or str(_event_payload_value(event, "branch") or "") or DEFAULT_BASE_BRANCH

    event.analysis = analysis
    event.proposal = proposal
    event.github_result = _apply_fix_to_github(event, proposal, base_branch=base_branch)
    store.save(event)
    return event.github_result


@app.post("/api/github/fetch-files")
def github_fetch_files(payload: GitHubFetchRequest) -> dict[str, Any]:
    try:
        files = github_branch_ops.fetch_analysis_files(payload.repo_name, payload.branch_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub fetch failed: {exc.response.status_code}") from exc

    return {
        "repo_name": payload.repo_name,
        "branch_name": payload.branch_name,
        "file_count": len(files),
        "files": [
            {
                "path": path,
                "preview": _preview_text(content),
            }
            for path, content in sorted(files.items())
        ],
    }


@app.post("/api/github/push-file")
def github_push_file(payload: GitHubPushRequest) -> dict[str, Any]:
    try:
        return github_branch_ops.create_branch_and_push_file(
            repo_name=payload.repo_name,
            base_branch=payload.base_branch,
            new_branch=payload.new_branch,
            target_file=(payload.target_path or payload.target_file),
            updated_content=payload.updated_content,
            commit_message=payload.commit_message,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub push failed: {exc.response.status_code}") from exc


@app.delete("/api/events")
def clear_events() -> dict[str, str]:
    store.clear()
    return {"status": "cleared"}
