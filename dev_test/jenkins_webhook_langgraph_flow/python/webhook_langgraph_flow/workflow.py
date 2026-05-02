from __future__ import annotations

import difflib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from . import github_service


BOX_BAR = "\u2502"
BOX_TOP_LEFT = "\u250c"
BOX_BOTTOM_LEFT = "\u2514"
BOX_TEE_LEFT = "\u251c"
SPRING_BOOT_PARENT = ("org.springframework.boot", "spring-boot-starter-parent")
DEFAULT_SPRING_BOOT_3_TARGET = "3.4.5"
SPRING_BOOT_BOM_PREFIXES = (
    "ch.qos.logback:",
    "com.fasterxml.jackson.",
    "org.apache.tomcat.embed:",
    "org.springframework:",
    "org.springframework.boot:",
)


class FlowState(TypedDict, total=False):
    payload: dict[str, Any]
    console_text: str
    local_repo_path: str | None
    push_enabled: bool
    repo: str | None
    branch: str
    file_paths: list[str]
    issues: list[dict[str, Any]]
    files: dict[str, str]
    source_files: dict[str, str]
    resolved_paths: list[dict[str, Any]]
    plan: dict[str, Any]
    branch_name: str
    push_result: dict[str, Any]
    iteration_count: int
    remaining_issues: list[dict[str, Any]]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        item = value.strip()
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _payload_repo(payload: dict[str, Any]) -> str | None:
    for key in ("target_repository", "repo", "repository", "github_repository"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _payload_branch(payload: dict[str, Any]) -> str:
    for key in ("target_branch", "branch", "base_branch", "CHANGE_TARGET", "ghprbTargetBranch"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "main"


def _payload_paths(payload: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("dependency_file_paths", "docker_file_paths"):
        raw = payload.get(key)
        if isinstance(raw, list):
            values.extend(str(item).strip() for item in raw if isinstance(item, str) and item.strip())
    return _unique(values)


def _fixed_versions(value: str) -> list[str]:
    return _unique([part.strip() for part in value.split(",") if part.strip()])


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value) or ["0"])


def _payload_console_text(payload: dict[str, Any]) -> str:
    for key in ("console_output", "console_text"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.replace("\r\n", "\n").replace("\r", "\n")
    return ""


def _effective_local_repo_path(payload: dict[str, Any], local_repo_path: str | None) -> str | None:
    if isinstance(local_repo_path, str) and local_repo_path.strip():
        return local_repo_path.strip()
    payload_value = payload.get("local_repo_path")
    if isinstance(payload_value, str) and payload_value.strip():
        return payload_value.strip()
    return None


def _repo_name(repo: str | None) -> str:
    if not isinstance(repo, str) or "/" not in repo:
        return ""
    return repo.split("/", 1)[1].strip()


def _local_candidate_paths(root: Path, repo: str | None, file_path: str) -> list[Path]:
    normalized = file_path.replace("\\", "/").strip("/")
    pure_path = PurePosixPath(normalized)
    parts = pure_path.parts
    repo_dir_name = _repo_name(repo)

    candidates: list[Path] = [root.joinpath(*parts)]
    if parts and parts[0] == root.name:
        candidates.append(root.joinpath(*parts[1:]))
    if parts and repo_dir_name and parts[0] == repo_dir_name:
        candidates.append(root.joinpath(*parts[1:]))

    basename = pure_path.name
    if basename:
        basename_matches = [path for path in root.rglob(basename) if path.is_file()]
        if len(basename_matches) == 1:
            candidates.append(basename_matches[0])

    unique_candidates: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate.resolve(strict=False))
        if key not in seen:
            seen.add(key)
            unique_candidates.append(candidate)
    return unique_candidates


def _table_border(line: str) -> bool:
    return line.startswith(BOX_TOP_LEFT) or line.startswith(BOX_BOTTOM_LEFT) or line.startswith(BOX_TEE_LEFT)


def _issue_counts(issues: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"VA": 0, "OTHER": 0}
    for issue in issues:
        category = str(issue.get("issue_category", "") or "").upper()
        if category in counts:
            counts[category] += 1
    return counts


def extract_issues_node(state: FlowState) -> FlowState:
    payload = state.get("payload", {})
    console_text = state.get("console_text", "")
    issues: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    other_lines: list[str] = []
    current_target = ""
    current_package = ""
    current_installed = ""
    current_severity = "UNKNOWN"
    in_table = False
    target_pattern = re.compile(r"^(?P<target>[A-Za-z0-9_./-]+)\s+\((?P<kind>[^)]+)\)$")

    for raw_line in console_text.splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()

        target_match = target_pattern.match(stripped)
        if target_match:
            current_target = target_match.group("target")
            continue

        if stripped.startswith(BOX_BAR):
            cells = [cell.strip() for cell in line.split(BOX_BAR)[1:-1]]
            if len(cells) == 7 and cells[0].lower() == "library" and cells[1].lower() == "vulnerability":
                in_table = True
                current_package = ""
                current_installed = ""
                current_severity = "UNKNOWN"
                continue
            if in_table and len(cells) == 7:
                library, vulnerability, severity, _status, installed_version, fixed_version, title = cells
                if library:
                    current_package = library
                if installed_version:
                    current_installed = installed_version
                if severity:
                    current_severity = severity.upper()
                if vulnerability:
                    key = (current_target or "unknown-target", current_package or "unknown-package", current_installed or "")
                    item = grouped.setdefault(
                        key,
                        {
                            "issue_category": "VA",
                            "target_file": current_target,
                            "package_name": current_package,
                            "severity": current_severity,
                            "installed_version": current_installed or None,
                            "fixed_versions": [],
                            "cve_ids": [],
                            "vulnerabilities": [],
                        },
                    )
                    item["fixed_versions"].extend(_fixed_versions(fixed_version))
                    item["cve_ids"].append(vulnerability.upper())
                    item["vulnerabilities"].append(
                        {
                            "cve_id": vulnerability.upper(),
                            "severity": current_severity,
                            "fixed_versions": _fixed_versions(fixed_version),
                        }
                    )
                    continue

        if stripped and not _table_border(stripped):
            if any(token in stripped.lower() for token in ("error", "exception", "failed", "blocked")):
                other_lines.append(stripped)

    for item in grouped.values():
        issues.append(
            {
                "issue_category": "VA",
                "package_name": item["package_name"],
                "target_file_hint": item["target_file"] or "",
                "installed_version": item["installed_version"],
                "fixed_versions": _unique(item["fixed_versions"]),
                "cve_ids": _unique(item["cve_ids"]),
                "severity": item["severity"],
                "vulnerabilities": item["vulnerabilities"],
                "detailed_issue": f"{item['package_name']} in {item['target_file']} is vulnerable.",
                "initial_fix": "Prefer the parent/BOM/property owner over scattered direct overrides.",
            }
        )

    for line in _unique(other_lines):
        issues.append(
            {
                "issue_category": "OTHER",
                "package_name": "",
                "target_file_hint": "",
                "installed_version": None,
                "fixed_versions": [],
                "cve_ids": [],
                "detailed_issue": line,
                "initial_fix": "Review the Jenkins failure detail.",
            }
        )

    return {
        "repo": _payload_repo(payload),
        "branch": _payload_branch(payload),
        "file_paths": _payload_paths(payload),
        "issues": issues,
    }


def fetch_repo_context_node(state: FlowState) -> FlowState:
    file_paths = state.get("file_paths", [])
    issues = state.get("issues", [])
    repo = state.get("repo")
    branch = state.get("branch", "main")
    local_repo_path = state.get("local_repo_path")

    if not file_paths:
        guessed = [issue.get("target_file_hint", "") for issue in issues if issue.get("target_file_hint")]
        file_paths = _unique(guessed)

    files: dict[str, str] = {}
    if local_repo_path:
        root = Path(local_repo_path)
        if root.exists():
            for file_path in file_paths:
                for candidate in _local_candidate_paths(root, repo, file_path):
                    if candidate.exists() and candidate.is_file():
                        files[file_path.replace("\\", "/")] = candidate.read_text(encoding="utf-8")
                        break

    if not files and repo == "owner/repo":
        raise ValueError(
            "No local files were found, and payload['repo'] is still the sample placeholder 'owner/repo'. "
            "Set payload['local_repo_path'] to your checkout root or replace payload['repo'] with the real owner/repo."
        )

    if not files and repo:
        files = (
            github_service.fetch_repo_files_by_paths(repo, branch, file_paths)
            if file_paths
            else github_service.fetch_analysis_files(repo, branch)
        )

    resolved_paths = _resolve_issue_paths(issues, file_paths, files)
    return {"files": files, "source_files": dict(files), "resolved_paths": resolved_paths}


def _parse_pom(content: str) -> dict[str, Any]:
    root = ET.fromstring(content)
    for node in root.iter():
        if "}" in node.tag:
            node.tag = node.tag.split("}", 1)[1]
    properties = {child.tag: (child.text or "").strip() for child in root.findall("./properties/*")}
    parent: dict[str, Any] | None = None
    parent_node = root.find("./parent")
    if parent_node is not None:
        parent_version = (parent_node.findtext("version") or "").strip()
        property_match = re.fullmatch(r"\$\{([^}]+)\}", parent_version)
        parent = {
            "group_id": (parent_node.findtext("groupId") or "").strip(),
            "artifact_id": (parent_node.findtext("artifactId") or "").strip(),
            "version": parent_version or None,
            "version_property": property_match.group(1) if property_match else None,
        }
    dependencies: list[dict[str, Any]] = []
    for dependency in root.findall("./dependencies/dependency"):
        version = (dependency.findtext("version") or "").strip()
        property_match = re.fullmatch(r"\$\{([^}]+)\}", version)
        dependencies.append(
            {
                "group_id": (dependency.findtext("groupId") or "").strip(),
                "artifact_id": (dependency.findtext("artifactId") or "").strip(),
                "version": version or None,
                "version_property": property_match.group(1) if property_match else None,
            }
        )
    return {"properties": properties, "dependencies": dependencies, "parent": parent}


def _pick_target_version(current_version: str | None, fixed_versions: list[str]) -> str | None:
    if not fixed_versions:
        return None

    ordered = sorted(_unique(fixed_versions), key=_version_key)
    if not current_version:
        return ordered[-1]

    current_key = _version_key(current_version)
    current_major = re.match(r"(\d+)", current_version)

    same_major_greater = [
        version
        for version in ordered
        if current_major
        and (version_major := re.match(r"(\d+)", version))
        and version_major.group(1) == current_major.group(1)
        and _version_key(version) > current_key
    ]
    if same_major_greater:
        return same_major_greater[-1]

    any_greater = [version for version in ordered if _version_key(version) > current_key]
    if any_greater:
        return any_greater[-1]

    same_major = [
        version
        for version in ordered
        if current_major
        and (version_major := re.match(r"(\d+)", version))
        and version_major.group(1) == current_major.group(1)
    ]
    if same_major:
        return same_major[-1]

    return ordered[-1]


def _pick_target_version_for_issue(issue: dict[str, Any]) -> str | None:
    current_version = issue.get("installed_version")
    fixed_versions = list(issue.get("fixed_versions", []))
    vulnerabilities = list(issue.get("vulnerabilities", []))
    current_major = _version_major(current_version)

    if not vulnerabilities or not current_major:
        return _pick_target_version(current_version, fixed_versions)

    required_same_major: list[str] = []
    for vulnerability in vulnerabilities:
        same_major_candidates = [
            version
            for version in vulnerability.get("fixed_versions", [])
            if _version_major(version) == current_major
        ]
        if not same_major_candidates:
            return sorted(_unique(fixed_versions), key=_version_key)[-1] if fixed_versions else None
        required_same_major.append(sorted(_unique(same_major_candidates), key=_version_key)[-1])

    if not required_same_major:
        return _pick_target_version(current_version, fixed_versions)

    return sorted(_unique(required_same_major), key=_version_key)[-1]


def _version_major(value: str | None) -> str | None:
    if not value:
        return None
    match = re.match(r"(\d+)", value)
    return match.group(1) if match else None


def _requires_major_upgrade(current_version: str | None, target_version: str | None) -> bool:
    current_major = _version_major(current_version)
    target_major = _version_major(target_version)
    return bool(current_major and target_major and current_major != target_major)


def _replace_property(content: str, property_name: str, old: str, new: str) -> str:
    pattern = re.compile(rf"(<{re.escape(property_name)}>\s*){re.escape(old)}(\s*</{re.escape(property_name)}>)")
    return pattern.sub(rf"\g<1>{new}\g<2>", content, count=1)


def _replace_dependency_version(content: str, group_id: str, artifact_id: str, old: str, new: str) -> str:
    dependency_pattern = re.compile(r"<dependency>.*?</dependency>", flags=re.DOTALL)
    group_pattern = re.compile(rf"<groupId>\s*{re.escape(group_id)}\s*</groupId>")
    artifact_pattern = re.compile(rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>")
    version_pattern = re.compile(rf"(<version>\s*){re.escape(old)}(\s*</version>)")
    for match in dependency_pattern.finditer(content):
        block = match.group(0)
        if not group_pattern.search(block) or not artifact_pattern.search(block):
            continue
        updated, replacements = version_pattern.subn(rf"\g<1>{new}\g<2>", block, count=1)
        if replacements:
            return f"{content[:match.start()]}{updated}{content[match.end():]}"
    return content


def _add_dependency_version(content: str, group_id: str, artifact_id: str, new: str) -> str:
    dependency_pattern = re.compile(r"<dependency>.*?</dependency>", flags=re.DOTALL)
    group_pattern = re.compile(rf"<groupId>\s*{re.escape(group_id)}\s*</groupId>")
    artifact_pattern = re.compile(rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>")
    closing_pattern = re.compile(r"(\n?)(\s*)</dependency>")
    for match in dependency_pattern.finditer(content):
        block = match.group(0)
        if not group_pattern.search(block) or not artifact_pattern.search(block) or "<version>" in block:
            continue
        closing_match = closing_pattern.search(block)
        if not closing_match:
            continue
        indent = closing_match.group(2)
        version_line = f"\n{indent}<version>{new}</version>"
        updated = f"{block[:closing_match.start()]}{version_line}{block[closing_match.start():]}"
        return f"{content[:match.start()]}{updated}{content[match.end():]}"
    return content


def _append_dependency_override(content: str, group_id: str, artifact_id: str, version: str) -> str:
    dependencies_pattern = re.compile(r"(<dependencies>\s*)(.*?)(\s*</dependencies>)", flags=re.DOTALL)
    match = dependencies_pattern.search(content)
    if not match:
        return content
    insertion = (
        "\n        <dependency>\n"
        f"            <groupId>{group_id}</groupId>\n"
        f"            <artifactId>{artifact_id}</artifactId>\n"
        f"            <version>{version}</version>\n"
        "        </dependency>"
    )
    updated = f"{match.group(1)}{match.group(2)}{insertion}{match.group(3)}"
    return f"{content[:match.start()]}{updated}{content[match.end():]}"


def _replace_parent_version(content: str, group_id: str, artifact_id: str, old: str, new: str) -> str:
    parent_pattern = re.compile(r"<parent>.*?</parent>", flags=re.DOTALL)
    group_pattern = re.compile(rf"<groupId>\s*{re.escape(group_id)}\s*</groupId>")
    artifact_pattern = re.compile(rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>")
    version_pattern = re.compile(rf"(<version>\s*){re.escape(old)}(\s*</version>)")
    for match in parent_pattern.finditer(content):
        block = match.group(0)
        if not group_pattern.search(block) or not artifact_pattern.search(block):
            continue
        updated, replacements = version_pattern.subn(rf"\g<1>{new}\g<2>", block, count=1)
        if replacements:
            return f"{content[:match.start()]}{updated}{content[match.end():]}"
    return content


def _spring_boot_parent_upgrade(pom: dict[str, Any], issues: list[dict[str, Any]]) -> dict[str, str] | None:
    parent = pom.get("parent") or {}
    if (
        parent.get("group_id"),
        parent.get("artifact_id"),
    ) != SPRING_BOOT_PARENT:
        return None

    current_version = str(parent.get("version") or "")
    if not current_version:
        return None

    owner_issue = next(
        (
            issue
            for issue in issues
            if str(issue.get("package_name", "") or "") == "org.springframework.boot:spring-boot"
        ),
        None,
    )
    if owner_issue and owner_issue.get("installed_version") == current_version:
        target_version = _pick_target_version_for_issue(owner_issue)
        if target_version and target_version != current_version:
            return {"current_version": current_version, "target_version": target_version}

    current_parent_major = _version_major(current_version)
    if current_parent_major != "2":
        return None

    for issue in issues:
        package_name = str(issue.get("package_name", "") or "")
        target_dependency_version = _pick_target_version_for_issue(issue)
        if (
            package_name.startswith("org.springframework:")
            and _version_major(target_dependency_version) == "6"
            and DEFAULT_SPRING_BOOT_3_TARGET != current_version
        ):
            return {"current_version": current_version, "target_version": DEFAULT_SPRING_BOOT_3_TARGET}

    return None


def _is_spring_boot_bom_managed_issue(package_name: str, dependency: dict[str, Any] | None) -> bool:
    if not package_name.startswith(SPRING_BOOT_BOM_PREFIXES):
        return False
    if not dependency:
        return True
    return not dependency.get("version") and not dependency.get("version_property")


def _resolve_issue_paths(
    issues: list[dict[str, Any]],
    file_paths: list[str],
    files: dict[str, str],
) -> list[dict[str, Any]]:
    resolved_paths: list[dict[str, Any]] = []
    available = list(files.keys())
    for index, issue in enumerate(issues):
        hint = str(issue.get("target_file_hint", "") or "")
        name = PurePosixPath(hint).name if hint else ""
        match = next((path for path in available if name and PurePosixPath(path).name == name), "")
        if not match and hint in files:
            match = hint
        if not match and file_paths:
            match = file_paths[0]
        resolved_paths.append({"issue_index": index, "path": match})
    return resolved_paths


def _effective_dependency_version(pom: dict[str, Any], dependency: dict[str, Any] | None) -> str | None:
    if not dependency:
        return None
    version = dependency.get("version")
    if version:
        return str(version)
    property_name = dependency.get("version_property")
    if property_name:
        return str(pom.get("properties", {}).get(property_name) or "") or None
    return None


def _issue_is_resolved_in_pom(pom: dict[str, Any], issue: dict[str, Any]) -> bool:
    package_name = str(issue.get("package_name", "") or "")
    target_version = _pick_target_version_for_issue(issue)
    if ":" not in package_name or not target_version:
        return False

    group_id, artifact_id = package_name.split(":", 1)
    parent = pom.get("parent") or {}
    dependency = next(
        (
            item
            for item in pom.get("dependencies", [])
            if item.get("group_id") == group_id and item.get("artifact_id") == artifact_id
        ),
        None,
    )

    effective_version: str | None = None
    if package_name == "org.springframework.boot:spring-boot":
        effective_version = str(parent.get("version") or "") or None
    else:
        effective_version = _effective_dependency_version(pom, dependency)

    if effective_version:
        if _version_major(effective_version) == _version_major(target_version):
            return _version_key(effective_version) >= _version_key(target_version)
        return _version_key(effective_version) >= _version_key(target_version)

    if (
        (parent.get("group_id"), parent.get("artifact_id")) == SPRING_BOOT_PARENT
        and _is_spring_boot_bom_managed_issue(package_name, dependency)
        and _version_major(str(parent.get("version") or "")) == "3"
        and _version_major(target_version) == "6"
    ):
        return True

    return False


def simulate_rescan_node(state: FlowState) -> FlowState:
    files = state.get("files", {})
    file_paths = state.get("file_paths", [])
    issues = state.get("issues", [])
    plan = dict(state.get("plan", {}))
    iteration_count = int(state.get("iteration_count", 0) or 0) + 1

    remaining_issues: list[dict[str, Any]] = []
    for item in state.get("resolved_paths", []):
        issue_index = int(item.get("issue_index", -1))
        path = str(item.get("path", "") or "")
        if not (0 <= issue_index < len(issues)) or not path or path not in files:
            continue
        issue = issues[issue_index]
        if str(issue.get("issue_category", "")).upper() != "VA":
            continue
        if PurePosixPath(path).name.lower() != "pom.xml":
            remaining_issues.append(issue)
            continue
        try:
            pom = _parse_pom(files[path])
        except ET.ParseError:
            remaining_issues.append(issue)
            continue
        if not _issue_is_resolved_in_pom(pom, issue):
            remaining_issues.append(issue)

    current_va_issues = [issue for issue in issues if str(issue.get("issue_category", "")).upper() == "VA"]
    retry_requested = bool(remaining_issues) and len(remaining_issues) < len(current_va_issues) and iteration_count < 3

    simulation = dict(plan.get("simulation", {}))
    passes = list(simulation.get("passes", []))
    passes.append(
        {
            "pass_index": iteration_count,
            "remaining_va_count": len(remaining_issues),
            "remaining_packages": [str(issue.get("package_name", "") or "") for issue in remaining_issues],
            "retry_requested": retry_requested,
        }
    )
    simulation["passes"] = passes
    simulation["final_remaining_va_count"] = len(remaining_issues)
    plan["simulation"] = simulation

    return {
        "plan": plan,
        "iteration_count": iteration_count,
        "remaining_issues": remaining_issues,
        "issues": remaining_issues if retry_requested else issues,
        "resolved_paths": _resolve_issue_paths(remaining_issues, file_paths, files) if retry_requested else state.get("resolved_paths", []),
    }


def validate_and_prepare_changes_node(state: FlowState) -> FlowState:
    files = dict(state.get("files", {}))
    source_files = dict(state.get("source_files", files))
    issues = state.get("issues", [])
    resolved_paths = state.get("resolved_paths", [])
    notes: list[str] = []
    path_issue_map: dict[str, list[int]] = {}
    for item in resolved_paths:
        path = str(item.get("path", "") or "")
        index = int(item.get("issue_index", -1))
        if path and 0 <= index < len(issues):
            path_issue_map.setdefault(path, []).append(index)

    for path, issue_indexes in path_issue_map.items():
        if PurePosixPath(path).name.lower() != "pom.xml":
            continue

        original = files.get(path, "")
        if not original:
            continue
        try:
            pom = _parse_pom(original)
        except ET.ParseError:
            notes.append(f"{path}: could not parse pom.xml")
            continue

        updated = original
        parent = pom.get("parent") or {}
        has_spring_boot_parent = (
            parent.get("group_id"),
            parent.get("artifact_id"),
        ) == SPRING_BOOT_PARENT
        path_issues = [issues[index] for index in issue_indexes if issues[index].get("issue_category") == "VA"]
        spring_boot_parent_upgrade = _spring_boot_parent_upgrade(pom, path_issues)
        if spring_boot_parent_upgrade:
            if parent.get("version_property"):
                property_name = str(parent["version_property"])
                property_value = pom["properties"].get(property_name)
                if property_value == spring_boot_parent_upgrade["current_version"]:
                    updated = _replace_property(
                        updated,
                        property_name,
                        spring_boot_parent_upgrade["current_version"],
                        spring_boot_parent_upgrade["target_version"],
                    )
            else:
                updated = _replace_parent_version(
                    updated,
                    str(parent.get("group_id") or ""),
                    str(parent.get("artifact_id") or ""),
                    spring_boot_parent_upgrade["current_version"],
                    spring_boot_parent_upgrade["target_version"],
                )

        for issue in path_issues:
            package_name = str(issue.get("package_name", "") or "")
            if ":" not in package_name:
                continue

            current_version = issue.get("installed_version")
            target_version = _pick_target_version_for_issue(issue)
            if not current_version or not target_version:
                continue

            group_id, artifact_id = package_name.split(":", 1)
            dependency = next(
                (
                    dependency
                    for dependency in pom["dependencies"]
                    if dependency.get("group_id") == group_id and dependency.get("artifact_id") == artifact_id
                ),
                None,
            )

            if package_name == "org.springframework.boot:spring-boot" and spring_boot_parent_upgrade:
                continue

            if (
                spring_boot_parent_upgrade
                and has_spring_boot_parent
                and _is_spring_boot_bom_managed_issue(package_name, dependency)
                and _requires_major_upgrade(current_version, target_version)
            ):
                continue

            if (
                has_spring_boot_parent
                and _is_spring_boot_bom_managed_issue(package_name, dependency)
                and _requires_major_upgrade(current_version, target_version)
                and not spring_boot_parent_upgrade
            ):
                notes.append(
                    f"{path}: {package_name} requires a Spring Boot/Spring Framework major upgrade "
                    f"({current_version} -> {target_version}); automatic leaf override skipped."
                )
                continue

            next_updated = updated
            if dependency and dependency.get("version_property"):
                property_name = str(dependency["version_property"])
                if pom["properties"].get(property_name) == current_version:
                    next_updated = _replace_property(next_updated, property_name, current_version, target_version)
            elif dependency and dependency.get("version") == current_version:
                next_updated = _replace_dependency_version(next_updated, group_id, artifact_id, current_version, target_version)
            elif dependency and not dependency.get("version") and not dependency.get("version_property"):
                next_updated = _add_dependency_version(next_updated, group_id, artifact_id, target_version)
            elif dependency is None:
                next_updated = _append_dependency_override(next_updated, group_id, artifact_id, target_version)

            if next_updated == updated:
                notes.append(f"{path}: no safe edit point for {package_name}")
                continue

            updated = next_updated

        files[path] = updated

    file_changes: list[dict[str, Any]] = []
    for path, original in source_files.items():
        updated = files.get(path, original)
        if updated == original:
            continue
        diff = []
        for line in difflib.unified_diff(original.splitlines(), updated.splitlines(), fromfile="before", tofile="after", lineterm=""):
            if line.startswith(("---", "+++")):
                continue
            if line.startswith("-") or line.startswith("+"):
                diff.append(line)
        file_changes.append({"path": path, "updated_content": updated, "diff_preview": diff[:20]})

    existing_plan = dict(state.get("plan", {}))
    simulation = existing_plan.get("simulation")
    plan = {"file_changes": file_changes, "notes": notes}
    if simulation is not None:
        plan["simulation"] = simulation

    return {
        "files": files,
        "plan": plan,
        "branch_name": f"ai-va-fix/{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
    }


def push_changes_to_branch_node(state: FlowState) -> FlowState:
    plan = state.get("plan", {})
    file_changes = plan.get("file_changes", [])
    if not state.get("push_enabled"):
        return {"push_result": {"status": "skipped", "message": "Push disabled."}}
    if not file_changes:
        return {"push_result": {"status": "skipped", "message": "No file changes."}}
    repo = state.get("repo")
    if not repo:
        return {"push_result": {"status": "skipped", "message": "Repo missing."}}

    push_result = github_service.create_branch_and_push_files(
        repo_name=repo,
        base_branch=state.get("branch", "main"),
        new_branch=state.get("branch_name", "ai-va-fix/manual"),
        files=file_changes,
        commit_message="Apply validated remediation",
    )
    pr_result = github_service.create_pull_request(
        repo_name=repo,
        base_branch=state.get("branch", "main"),
        new_branch=state.get("branch_name", "ai-va-fix/manual"),
        title="Apply validated remediation",
        body="Generated by the minimal Jenkins webhook LangGraph flow.",
    )
    push_result["pull_request_url"] = pr_result["pull_request_url"]
    return {"push_result": push_result}


def _next_step_after_rescan(state: FlowState) -> str:
    simulation = dict(state.get("plan", {}).get("simulation", {}))
    passes = list(simulation.get("passes", []))
    if passes and passes[-1].get("retry_requested"):
        return "validate_and_prepare_changes"
    return "push_changes_to_branch"


def build_graph():
    graph = StateGraph(FlowState)
    graph.add_node("extract_issues", extract_issues_node)
    graph.add_node("fetch_repo_context", fetch_repo_context_node)
    graph.add_node("validate_and_prepare_changes", validate_and_prepare_changes_node)
    graph.add_node("simulate_rescan", simulate_rescan_node)
    graph.add_node("push_changes_to_branch", push_changes_to_branch_node)
    graph.add_edge(START, "extract_issues")
    graph.add_edge("extract_issues", "fetch_repo_context")
    graph.add_edge("fetch_repo_context", "validate_and_prepare_changes")
    graph.add_edge("validate_and_prepare_changes", "simulate_rescan")
    graph.add_conditional_edges(
        "simulate_rescan",
        _next_step_after_rescan,
        {
            "validate_and_prepare_changes": "validate_and_prepare_changes",
            "push_changes_to_branch": "push_changes_to_branch",
        },
    )
    graph.add_edge("push_changes_to_branch", END)
    return graph.compile()


def _base_state(payload: dict[str, Any], local_repo_path: str | None, push_enabled: bool) -> FlowState:
    return {
        "payload": payload,
        "console_text": _payload_console_text(payload),
        "local_repo_path": _effective_local_repo_path(payload, local_repo_path),
        "push_enabled": push_enabled,
        "iteration_count": 0,
    }


def run_analysis(payload: dict[str, Any], *, event_id: str, local_repo_path: str | None = None) -> dict[str, Any]:
    state = extract_issues_node(_base_state(payload, local_repo_path, False))
    counts = _issue_counts(state.get("issues", []))
    return {
        "event_id": event_id,
        "created_at": _now(),
        "repo": state.get("repo"),
        "branch": state.get("branch"),
        "file_paths": state.get("file_paths", []),
        "issues": state.get("issues", []),
        "issue_counts": counts,
        "supported": counts["VA"] > 0,
        "summary": f"Detected {counts['VA']} vulnerability issue group(s) and {counts['OTHER']} other issue(s).",
    }


def run_prepare_fix(payload: dict[str, Any], *, event_id: str, local_repo_path: str | None = None) -> dict[str, Any]:
    state = build_graph().invoke(_base_state(payload, local_repo_path, False))
    return {
        "event_id": event_id,
        "created_at": _now(),
        "repo": state.get("repo"),
        "branch": state.get("branch"),
        "file_paths": state.get("file_paths", []),
        "resolved_paths": state.get("resolved_paths", []),
        "plan": state.get("plan", {}),
        "branch_name": state.get("branch_name", ""),
    }


def run_apply_fix(
    payload: dict[str, Any],
    *,
    event_id: str,
    local_repo_path: str | None = None,
    push_enabled: bool = True,
) -> dict[str, Any]:
    state = build_graph().invoke(_base_state(payload, local_repo_path, push_enabled))
    return {
        "event_id": event_id,
        "created_at": _now(),
        "branch_name": state.get("branch_name", ""),
        "plan": state.get("plan", {}),
        "push_result": state.get("push_result", {}),
    }
