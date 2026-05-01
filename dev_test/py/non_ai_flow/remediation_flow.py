from __future__ import annotations

import difflib
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

try:
    from . import github_service
except ImportError:  # pragma: no cover - support direct module execution
    import github_service


IssueCategory = Literal["VA", "OTHER"]

TARGET_FILE_CANDIDATES = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
    "settings.gradle",
    "settings.gradle.kts",
    "Dockerfile",
)

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

OTHER_ISSUE_PATTERNS = (
    re.compile(r"\berror\b", flags=re.IGNORECASE),
    re.compile(r"\bexception\b", flags=re.IGNORECASE),
    re.compile(r"\bfailed\b", flags=re.IGNORECASE),
    re.compile(r"\bblocked\b", flags=re.IGNORECASE),
)


@dataclass
class WorkflowIssue:
    issue_id: str
    issue_category: IssueCategory
    detailed_issue: str
    initial_fix: str
    target_file: str | None = None
    package_name: str | None = None
    severity: str = "UNKNOWN"
    cve_ids: list[str] = field(default_factory=list)
    installed_version: str | None = None
    fixed_versions: list[str] = field(default_factory=list)
    titles: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    solution_type: str | None = None


@dataclass
class ChangeInstruction:
    instruction_id: str
    file_path: str
    change_type: str
    package_name: str
    from_version: str
    to_version: str
    rationale: str
    property_name: str | None = None
    group_id: str | None = None
    artifact_id: str | None = None


@dataclass
class WorkflowState:
    event_id: str
    console_text: str
    payload: dict[str, Any]
    local_repo_path: str | None = None
    target_repository: str | None = None
    target_branch: str | None = None
    scan_targets: list[str] = field(default_factory=list)
    issue_list: list[WorkflowIssue] = field(default_factory=list)
    repo_files: dict[str, str] = field(default_factory=dict)
    manifest_context: dict[str, Any] = field(default_factory=dict)
    remediation_candidates: list[ChangeInstruction] = field(default_factory=list)
    validated_change_plan: dict[str, Any] = field(default_factory=dict)
    validation_notes: list[str] = field(default_factory=list)
    validation_passed: bool = False
    manual_review_required: bool = False


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _repo_branch_from_payload(payload: dict[str, Any], default_branch: str) -> tuple[str | None, str]:
    repo_candidates = (
        payload.get("target_repository"),
        payload.get("repo"),
        payload.get("repository"),
        payload.get("github_repository"),
    )
    branch_candidates = (
        payload.get("target_branch"),
        payload.get("branch"),
        payload.get("base_branch"),
        payload.get("target"),
        payload.get("CHANGE_TARGET"),
        payload.get("ghprbTargetBranch"),
    )

    repo = next((str(value).strip() for value in repo_candidates if isinstance(value, str) and value.strip()), None)
    branch = next(
        (str(value).strip() for value in branch_candidates if isinstance(value, str) and value.strip()),
        default_branch,
    )
    return repo, branch


def _severity_max(left: str, right: str) -> str:
    return left if SEVERITY_ORDER.get(left, 0) >= SEVERITY_ORDER.get(right, 0) else right


def _infer_solution_type(target_file: str | None) -> str | None:
    lower_name = (target_file or "").lower()
    if lower_name.endswith("pom.xml"):
        return "bom-friendly-upgrade"
    if lower_name.endswith("build.gradle") or lower_name.endswith("build.gradle.kts"):
        return "platform-or-property-upgrade"
    if lower_name.endswith("dockerfile"):
        return "docker-base-or-package-upgrade"
    return None


def _split_fixed_versions(raw_text: str) -> list[str]:
    return _dedupe_keep_order([part.strip() for part in raw_text.split(",") if part.strip()])


def _parse_version_key(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    if not parts:
        return (0,)
    return tuple(int(part) for part in parts)


def _pick_target_version(current_version: str | None, fixed_versions: list[str]) -> str | None:
    if not fixed_versions:
        return None

    if not current_version:
        return fixed_versions[0]

    current_major_match = re.match(r"(\d+)", current_version)
    current_major = current_major_match.group(1) if current_major_match else None
    same_major = [
        version
        for version in fixed_versions
        if current_major and re.match(r"(\d+)", version) and re.match(r"(\d+)", version).group(1) == current_major
    ]
    candidates = same_major or fixed_versions
    return min(candidates, key=_parse_version_key)


def _is_table_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("│") or stripped.startswith("├") or stripped.startswith("└") or stripped.startswith("┌")


def _is_other_issue_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith("http://") or stripped.startswith("https://"):
        return False
    if stripped.startswith("=====") or stripped.startswith("Report Summary") or stripped.startswith("Legend:"):
        return False
    if _is_table_line(stripped):
        return False
    return any(pattern.search(stripped) for pattern in OTHER_ISSUE_PATTERNS)


def _build_other_issue(line: str) -> WorkflowIssue:
    return WorkflowIssue(
        issue_id=f"iss_{uuid4().hex[:10]}",
        issue_category="OTHER",
        detailed_issue=line.strip(),
        initial_fix="Review the failing Jenkins step and validate whether the non-vulnerability error is a downstream effect of the security gate.",
        evidence=[line.strip()],
    )


def _extract_scan_targets(console_text: str, issues: list[WorkflowIssue]) -> list[str]:
    targets = [issue.target_file for issue in issues if issue.target_file]
    if "pom.xml" in console_text:
        targets.append("pom.xml")
    if "build.gradle.kts" in console_text:
        targets.append("build.gradle.kts")
    if "build.gradle" in console_text:
        targets.append("build.gradle")
    if re.search(r"(^|\s)Dockerfile(\s|$)", console_text, flags=re.IGNORECASE):
        targets.append("Dockerfile")
    return _dedupe_keep_order([target for target in targets if target])


def run_node_01(state: WorkflowState) -> WorkflowState:
    current_target: str | None = None
    in_vulnerability_table = False
    current_package = ""
    current_installed = ""
    current_severity = "UNKNOWN"
    grouped_findings: dict[tuple[str, str, str], dict[str, Any]] = {}
    other_issue_lines: list[str] = []

    target_pattern = re.compile(r"^(?P<target>[A-Za-z0-9_./-]+)\s+\((?P<kind>[^)]+)\)$")

    for raw_line in state.console_text.splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        target_match = target_pattern.match(stripped)
        if target_match:
            current_target = target_match.group("target")
            continue

        if stripped.startswith("│"):
            cells = [cell.strip() for cell in line.split("│")[1:-1]]
            if len(cells) == 7 and cells[0].lower() == "library" and cells[1].lower() == "vulnerability":
                in_vulnerability_table = True
                current_package = ""
                current_installed = ""
                current_severity = "UNKNOWN"
                continue

            if in_vulnerability_table and len(cells) == 7:
                library, vulnerability, severity, _status, installed_version, fixed_version, title = cells
                if library:
                    current_package = library
                if severity:
                    current_severity = severity.upper()
                if installed_version:
                    current_installed = installed_version

                if vulnerability:
                    finding_key = (
                        current_target or "unknown-target",
                        current_package or "unknown-package",
                        current_installed or "",
                    )
                    bucket = grouped_findings.setdefault(
                        finding_key,
                        {
                            "target_file": current_target,
                            "package_name": current_package,
                            "severity": current_severity,
                            "installed_version": current_installed or None,
                            "cve_ids": [],
                            "fixed_versions": [],
                            "titles": [],
                            "evidence": [],
                        },
                    )
                    bucket["severity"] = _severity_max(bucket["severity"], current_severity)
                    bucket["cve_ids"].append(vulnerability.upper())
                    bucket["fixed_versions"].extend(_split_fixed_versions(fixed_version))
                    if title and not title.lower().startswith("http"):
                        bucket["titles"].append(title)
                    bucket["evidence"].append(stripped)
                    continue

                if grouped_findings and title and not title.lower().startswith("http"):
                    last_bucket = next(reversed(grouped_findings.values()))
                    last_bucket["titles"].append(title)
                continue

        if _is_other_issue_line(line):
            other_issue_lines.append(stripped)

    issues: list[WorkflowIssue] = []
    for finding in grouped_findings.values():
        cve_ids = _dedupe_keep_order(finding["cve_ids"])
        fixed_versions = _dedupe_keep_order(finding["fixed_versions"])
        titles = _dedupe_keep_order(finding["titles"])
        issue = WorkflowIssue(
            issue_id=f"iss_{uuid4().hex[:10]}",
            issue_category="VA",
            detailed_issue=(
                f"{finding['package_name']} in {finding['target_file']} has {len(cve_ids)} vulnerability finding(s): "
                f"{', '.join(cve_ids)}."
            ),
            initial_fix=(
                "Prefer the owning BOM, parent, platform, or version property over adding a direct inline override."
            ),
            target_file=finding["target_file"],
            package_name=finding["package_name"],
            severity=finding["severity"],
            cve_ids=cve_ids,
            installed_version=finding["installed_version"],
            fixed_versions=fixed_versions,
            titles=titles,
            evidence=_dedupe_keep_order(finding["evidence"]),
            solution_type=_infer_solution_type(finding["target_file"]),
        )
        issues.append(issue)

    issues.extend(_build_other_issue(line) for line in _dedupe_keep_order(other_issue_lines))
    state.issue_list = issues
    state.scan_targets = _extract_scan_targets(state.console_text, issues)
    return state


def _read_local_repo_files(local_repo_path: str, scan_targets: list[str]) -> dict[str, str]:
    repo_root = Path(local_repo_path)
    files: dict[str, str] = {}
    if not repo_root.exists():
        return files

    for target in scan_targets or list(TARGET_FILE_CANDIDATES):
        normalized = target.lower()
        for candidate in repo_root.rglob("*"):
            if not candidate.is_file():
                continue
            if candidate.name.lower() != normalized:
                continue
            try:
                relative_path = candidate.relative_to(repo_root).as_posix()
                files[relative_path] = candidate.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
    return files


def _filter_repo_files(repo_files: dict[str, str], scan_targets: list[str]) -> dict[str, str]:
    if not scan_targets:
        return repo_files
    allowed = {target.lower() for target in scan_targets}
    filtered = {
        path: content
        for path, content in repo_files.items()
        if Path(path).name.lower() in allowed or path.lower() in allowed
    }
    return filtered or repo_files


def _strip_xml_namespaces(element: ET.Element) -> None:
    for node in element.iter():
        if "}" in node.tag:
            node.tag = node.tag.split("}", 1)[1]


def _parse_pom_manifest(content: str) -> dict[str, Any]:
    root = ET.fromstring(content)
    _strip_xml_namespaces(root)

    properties = {child.tag: (child.text or "").strip() for child in root.findall("./properties/*")}

    parent_node = root.find("./parent")
    parent = None
    if parent_node is not None:
        parent = {
            "group_id": (parent_node.findtext("groupId") or "").strip(),
            "artifact_id": (parent_node.findtext("artifactId") or "").strip(),
            "version": (parent_node.findtext("version") or "").strip(),
        }

    def collect_dependencies(base_path: str) -> list[dict[str, Any]]:
        dependencies: list[dict[str, Any]] = []
        for dependency in root.findall(base_path):
            version_text = (dependency.findtext("version") or "").strip()
            property_match = re.fullmatch(r"\$\{([^}]+)\}", version_text)
            dependencies.append(
                {
                    "group_id": (dependency.findtext("groupId") or "").strip(),
                    "artifact_id": (dependency.findtext("artifactId") or "").strip(),
                    "version": version_text or None,
                    "version_property": property_match.group(1) if property_match else None,
                    "type": (dependency.findtext("type") or "").strip() or None,
                    "scope": (dependency.findtext("scope") or "").strip() or None,
                }
            )
        return dependencies

    return {
        "kind": "maven",
        "parent": parent,
        "properties": properties,
        "dependencies": collect_dependencies("./dependencies/dependency"),
        "dependency_management": collect_dependencies("./dependencyManagement/dependencies/dependency"),
    }


def _parse_manifest_context(repo_files: dict[str, str]) -> dict[str, Any]:
    context: dict[str, Any] = {}
    for path, content in repo_files.items():
        name = Path(path).name.lower()
        if name == "pom.xml":
            try:
                context[path] = _parse_pom_manifest(content)
            except ET.ParseError:
                context[path] = {"kind": "maven", "parse_error": True}
        else:
            context[path] = {"kind": "raw-text"}
    return context


def run_node_02(state: WorkflowState, default_branch: str) -> WorkflowState:
    repo, branch = _repo_branch_from_payload(state.payload, default_branch)
    state.target_repository = repo
    state.target_branch = branch

    repo_files: dict[str, str] = {}
    if state.local_repo_path:
        repo_files = _read_local_repo_files(state.local_repo_path, state.scan_targets)

    if not repo_files and repo and branch:
        try:
            repo_files = github_service.fetch_analysis_files(repo, branch)
        except Exception:
            repo_files = {}

    state.repo_files = _filter_repo_files(repo_files, state.scan_targets)
    state.manifest_context = _parse_manifest_context(state.repo_files)
    return state


def _find_maven_dependency(manifest: dict[str, Any], group_id: str, artifact_id: str) -> tuple[str, dict[str, Any] | None]:
    for collection_name in ("dependencies", "dependency_management"):
        for dependency in manifest.get(collection_name, []):
            if dependency.get("group_id") == group_id and dependency.get("artifact_id") == artifact_id:
                return collection_name, dependency
    return "missing", None


def _property_matches_package(property_name: str, artifact_id: str) -> bool:
    simplified = property_name.lower().replace(".", "-").replace("_", "-")
    artifact_key = artifact_id.lower().replace(".", "-").replace("_", "-")
    return artifact_key in simplified or simplified.endswith("-version") or simplified == "version"


def _build_property_instruction(
    file_path: str,
    package_name: str,
    property_name: str,
    current_version: str,
    target_version: str,
    rationale: str,
) -> ChangeInstruction:
    return ChangeInstruction(
        instruction_id=f"chg_{uuid4().hex[:10]}",
        file_path=file_path,
        change_type="maven-property-upgrade",
        package_name=package_name,
        from_version=current_version,
        to_version=target_version,
        rationale=rationale,
        property_name=property_name,
    )


def _build_dependency_instruction(
    file_path: str,
    package_name: str,
    group_id: str,
    artifact_id: str,
    current_version: str,
    target_version: str,
    rationale: str,
) -> ChangeInstruction:
    return ChangeInstruction(
        instruction_id=f"chg_{uuid4().hex[:10]}",
        file_path=file_path,
        change_type="maven-direct-dependency-upgrade",
        package_name=package_name,
        from_version=current_version,
        to_version=target_version,
        rationale=rationale,
        group_id=group_id,
        artifact_id=artifact_id,
    )


def _plan_maven_change(issue: WorkflowIssue, file_path: str, manifest: dict[str, Any]) -> tuple[ChangeInstruction | None, str | None]:
    if not issue.package_name or ":" not in issue.package_name:
        return None, "Package coordinates were incomplete, so Maven ownership could not be resolved safely."

    group_id, artifact_id = issue.package_name.split(":", 1)
    target_version = _pick_target_version(issue.installed_version, issue.fixed_versions)
    if not target_version or not issue.installed_version:
        return None, "The vulnerability report did not provide enough version detail to build a safe Maven change."

    location, dependency = _find_maven_dependency(manifest, group_id, artifact_id)
    if dependency:
        if dependency.get("version_property"):
            property_name = str(dependency["version_property"])
            property_value = manifest.get("properties", {}).get(property_name)
            if property_value == issue.installed_version:
                return (
                    _build_property_instruction(
                        file_path=file_path,
                        package_name=issue.package_name,
                        property_name=property_name,
                        current_version=issue.installed_version,
                        target_version=target_version,
                        rationale=(
                            f"{issue.package_name} is controlled by the `{property_name}` property in {location}, "
                            "so the property is the BOM-safe edit point."
                        ),
                    ),
                    None,
                )

        if dependency.get("version") == issue.installed_version:
            return (
                _build_dependency_instruction(
                    file_path=file_path,
                    package_name=issue.package_name,
                    group_id=group_id,
                    artifact_id=artifact_id,
                    current_version=issue.installed_version,
                    target_version=target_version,
                    rationale=(
                        f"{issue.package_name} has an explicit version in {location}, so a direct dependency bump is the narrowest safe change."
                    ),
                ),
                None,
            )

        if dependency.get("version") is None:
            parent = manifest.get("parent") or {}
            imported_boms = [
                dep
                for dep in manifest.get("dependency_management", [])
                if dep.get("scope") == "import" and dep.get("type") == "pom"
            ]
            if parent.get("artifact_id") or imported_boms:
                return (
                    None,
                    (
                        f"{issue.package_name} is managed by a Maven parent or imported BOM in {file_path}. "
                        "The console log alone is not enough to choose a safe BOM version automatically."
                    ),
                )

    for property_name, property_value in manifest.get("properties", {}).items():
        if property_value != issue.installed_version:
            continue
        if _property_matches_package(property_name, artifact_id):
            return (
                _build_property_instruction(
                    file_path=file_path,
                    package_name=issue.package_name,
                    property_name=property_name,
                    current_version=issue.installed_version,
                    target_version=target_version,
                    rationale=(
                        f"{issue.package_name} aligns with the `{property_name}` property value, so the property is the safest control point."
                    ),
                ),
                None,
            )

    return (
        None,
        (
            f"No safe BOM/property/direct edit point was found for {issue.package_name} in {file_path}. "
            "Manual review is required."
        ),
    )


def _apply_property_change(content: str, instruction: ChangeInstruction) -> tuple[str, bool]:
    if not instruction.property_name:
        return content, False
    pattern = re.compile(
        rf"(<{re.escape(instruction.property_name)}>\s*){re.escape(instruction.from_version)}(\s*</{re.escape(instruction.property_name)}>)"
    )
    updated_content, replacements = pattern.subn(
        rf"\g<1>{instruction.to_version}\g<2>",
        content,
        count=1,
    )
    return updated_content, replacements > 0


def _apply_dependency_change(content: str, instruction: ChangeInstruction) -> tuple[str, bool]:
    if not instruction.group_id or not instruction.artifact_id:
        return content, False

    dependency_pattern = re.compile(r"<dependency>.*?</dependency>", flags=re.DOTALL)
    group_pattern = re.compile(rf"<groupId>\s*{re.escape(instruction.group_id)}\s*</groupId>")
    artifact_pattern = re.compile(rf"<artifactId>\s*{re.escape(instruction.artifact_id)}\s*</artifactId>")
    version_pattern = re.compile(rf"(<version>\s*){re.escape(instruction.from_version)}(\s*</version>)")

    for match in dependency_pattern.finditer(content):
        block = match.group(0)
        if not group_pattern.search(block) or not artifact_pattern.search(block):
            continue
        updated_block, replacements = version_pattern.subn(
            rf"\g<1>{instruction.to_version}\g<2>",
            block,
            count=1,
        )
        if replacements:
            return f"{content[:match.start()]}{updated_block}{content[match.end():]}", True
    return content, False


def _build_diff_preview(original_content: str, updated_content: str) -> list[str]:
    lines: list[str] = []
    for line in difflib.unified_diff(
        original_content.splitlines(),
        updated_content.splitlines(),
        fromfile="before",
        tofile="after",
        lineterm="",
    ):
        if line.startswith(("---", "+++")):
            continue
        if line.startswith("-") or line.startswith("+"):
            lines.append(line)
    return lines[:40]


def run_node_03(state: WorkflowState) -> WorkflowState:
    file_changes: list[dict[str, Any]] = []
    unresolved_va_issues: list[str] = []

    for issue in state.issue_list:
        if issue.issue_category != "VA" or not issue.target_file:
            continue

        matched_file_path = next(
            (path for path in state.repo_files if Path(path).name.lower() == issue.target_file.lower()),
            None,
        )
        if not matched_file_path:
            unresolved_va_issues.append(
                f"{issue.package_name or issue.detailed_issue}: no matching repo file was available for {issue.target_file}."
            )
            continue

        manifest = state.manifest_context.get(matched_file_path, {})
        if manifest.get("kind") != "maven":
            unresolved_va_issues.append(
                f"{issue.package_name or issue.detailed_issue}: automatic planning is only implemented for Maven manifests right now."
            )
            continue

        instruction, note = _plan_maven_change(issue, matched_file_path, manifest)
        if note:
            unresolved_va_issues.append(note)
        if not instruction:
            continue

        original_content = state.repo_files[matched_file_path]
        if instruction.change_type == "maven-property-upgrade":
            updated_content, changed = _apply_property_change(original_content, instruction)
        else:
            updated_content, changed = _apply_dependency_change(original_content, instruction)

        if not changed or updated_content == original_content:
            unresolved_va_issues.append(
                f"{instruction.package_name}: the planned {instruction.change_type} could not be applied cleanly to {matched_file_path}."
            )
            continue

        state.repo_files[matched_file_path] = updated_content
        state.remediation_candidates.append(instruction)
        file_changes.append(
            {
                "path": matched_file_path,
                "change_type": instruction.change_type,
                "package_name": instruction.package_name,
                "from_version": instruction.from_version,
                "to_version": instruction.to_version,
                "rationale": instruction.rationale,
                "updated_content": updated_content,
                "diff_preview": _build_diff_preview(original_content, updated_content),
            }
        )

    state.validation_notes = unresolved_va_issues
    state.manual_review_required = bool(unresolved_va_issues)
    state.validation_passed = bool(file_changes) and not state.manual_review_required
    state.validated_change_plan = {
        "validation_passed": state.validation_passed,
        "manual_review_required": state.manual_review_required,
        "validation_notes": unresolved_va_issues,
        "file_changes": file_changes,
    }
    return state


def build_analysis_response(state: WorkflowState) -> dict[str, Any]:
    issue_counts = {"VA": 0, "OTHER": 0}
    for issue in state.issue_list:
        issue_counts[issue.issue_category] += 1

    return {
        "analysis_id": f"an_{uuid4().hex[:10]}",
        "event_id": state.event_id,
        "created_at": _utc_now(),
        "supported": issue_counts["VA"] > 0,
        "va_detected": issue_counts["VA"] > 0,
        "issue_counts": issue_counts,
        "target_repository": state.target_repository,
        "target_branch": state.target_branch,
        "scan_targets": state.scan_targets,
        "issue_list": [asdict(issue) for issue in state.issue_list],
        "summary": (
            f"Detected {issue_counts['VA']} vulnerability issue group(s) and {issue_counts['OTHER']} other issue(s)."
            if state.issue_list
            else "No actionable issues were extracted from the Jenkins console text."
        ),
    }


def _build_branch_name(state: WorkflowState) -> str:
    va_packages = [issue.package_name for issue in state.issue_list if issue.issue_category == "VA" and issue.package_name]
    package_stub = (va_packages[0] if va_packages else "vulnerability-fix").replace(":", "-").replace(".", "-")
    return f"auto-fix/{package_stub}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"


def build_proposal_response(state: WorkflowState, analysis_id: str | None) -> dict[str, Any]:
    status = "ready" if state.validation_passed else "manual-review-required"
    return {
        "proposal_id": f"fp_{uuid4().hex[:10]}",
        "event_id": state.event_id,
        "analysis_id": analysis_id,
        "created_at": _utc_now(),
        "status": status,
        "target_repository": state.target_repository,
        "target_branch": state.target_branch,
        "branch_name": _build_branch_name(state),
        "scan_targets": state.scan_targets,
        "issue_list": [asdict(issue) for issue in state.issue_list],
        "manifest_context": state.manifest_context,
        "remediation_candidates": [asdict(candidate) for candidate in state.remediation_candidates],
        "validated_change_plan": state.validated_change_plan,
        "pr_title": (
            f"Apply BOM-safe remediation for {len(state.validated_change_plan.get('file_changes', []))} file(s)"
        ),
        "pr_body": (
            "This automated remediation updates the owning Maven control points that were safe to patch from the Jenkins failure log.\n\n"
            f"- Target repository: {state.target_repository or 'unknown'}\n"
            f"- Base branch: {state.target_branch or 'unknown'}\n"
            f"- Manual review required: {'yes' if state.manual_review_required else 'no'}\n"
            f"- Validation notes: {len(state.validation_notes)}"
        ),
    }


def build_state_from_event(
    *,
    event_id: str,
    console_text: str,
    payload: dict[str, Any] | None,
    local_repo_path: str | None,
) -> WorkflowState:
    return WorkflowState(
        event_id=event_id,
        console_text=console_text,
        payload=payload or {},
        local_repo_path=local_repo_path,
    )
