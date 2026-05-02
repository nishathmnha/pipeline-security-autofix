from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class JenkinsFailurePayload(BaseModel):
    job_name: str = ""
    build_number: int | None = None
    build_url: str = ""
    repo: str = ""
    branch: str = "main"
    target_branch: str | None = None
    status: str = "FAILED"
    console_text: str | None = None
    console_output: str | None = None
    dependency_file_paths: list[str] = Field(default_factory=list)
    docker_file_paths: list[str] = Field(default_factory=list)
    local_repo_path: str | None = None

    @field_validator(
        "job_name",
        "build_url",
        "repo",
        "branch",
        "target_branch",
        "status",
        "console_text",
        "console_output",
        "local_repo_path",
        mode="before",
    )
    @classmethod
    def _clean_str(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("dependency_file_paths", "docker_file_paths", mode="before")
    @classmethod
    def _clean_paths(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise TypeError("File path fields must be arrays of strings.")
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                continue
            normalized = item.strip().replace("\\", "/").strip("/")
            if normalized and normalized not in seen:
                seen.add(normalized)
                cleaned.append(normalized)
        return cleaned

    @model_validator(mode="after")
    def _default_target_branch(self) -> "JenkinsFailurePayload":
        if not self.target_branch:
            self.target_branch = self.branch or "main"
        if not self.branch:
            self.branch = "main"
        if not self.status:
            self.status = "FAILED"
        return self

    def normalized_console_text(self) -> str:
        text = self.console_output or self.console_text or ""
        return text.replace("\r\n", "\n").replace("\r", "\n")

    def normalized_local_repo_path(self) -> str | None:
        return self.local_repo_path or None

    def to_payload_dict(self) -> dict[str, Any]:
        payload = self.model_dump(exclude_none=True)
        payload["console_text"] = self.normalized_console_text()
        payload["console_output"] = self.normalized_console_text()
        return payload
