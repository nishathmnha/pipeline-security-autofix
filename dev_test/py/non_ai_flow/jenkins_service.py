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
from fastapi import HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

try:
    from .app import app
    from .env_loader import load_project_env
    from . import github_service
except ImportError:  # pragma: no cover - support direct module execution
    from app import app
    from env_loader import load_project_env
    import github_service

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


class FixApplyRequest(BaseModel):
    base_branch: str | None = None


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


@app.delete("/api/events")
def clear_events() -> dict[str, str]:
    store.clear()
    return {"status": "cleared"}
