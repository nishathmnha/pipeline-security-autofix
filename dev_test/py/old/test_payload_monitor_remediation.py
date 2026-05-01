from __future__ import annotations

import base64
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient

from non_ai_flow import github_service as github_branch_ops
from non_ai_flow import jenkins_service as monitor_app


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def _json_response(method: str, url: str, payload: dict[str, object], status_code: int = 200) -> httpx.Response:
    request = httpx.Request(method, f"https://api.github.test{url}")
    return httpx.Response(status_code, json=payload, request=request)


class FakeHttpClient:
    def __init__(self, responses: dict[tuple[str, str], httpx.Response]) -> None:
        self.responses = responses
        self.calls: list[dict[str, object]] = []

    def __enter__(self) -> FakeHttpClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def _request(
        self,
        method: str,
        url: str,
        params: dict[str, str] | None = None,
        json: dict[str, object] | None = None,
    ) -> httpx.Response:
        self.calls.append({"method": method, "url": url, "params": params, "json": json})
        try:
            return self.responses[(method, url)]
        except KeyError as exc:
            raise AssertionError(f"Unexpected {method} request to {url}") from exc

    def get(self, url: str, params: dict[str, str] | None = None) -> httpx.Response:
        return self._request("GET", url, params=params)

    def post(self, url: str, json: dict[str, object] | None = None) -> httpx.Response:
        return self._request("POST", url, json=json)

    def put(self, url: str, json: dict[str, object] | None = None) -> httpx.Response:
        return self._request("PUT", url, json=json)


class NonAiFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        workspace_tmp_root = Path(__file__).resolve().parent / ".test_tmp"
        workspace_tmp_root.mkdir(parents=True, exist_ok=True)
        self.temp_dir = workspace_tmp_root / f"pm-{uuid4().hex[:8]}"
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.events_file = self.temp_dir / "requests.jsonl"
        self.original_store = monitor_app.store
        self.original_remediation_dir = monitor_app.REMEDIATION_DIR
        monitor_app.store = monitor_app.EventStore(self.events_file)
        monitor_app.REMEDIATION_DIR = self.temp_dir / "remediation"
        self.client = TestClient(monitor_app.app)

    def tearDown(self) -> None:
        self.client.close()
        monitor_app.store = self.original_store
        monitor_app.REMEDIATION_DIR = self.original_remediation_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_jenkins_failure_console_text_is_retrievable(self) -> None:
        console_text = "line one\nline two\nline three"
        payload = {
            "job_name": "demo-job",
            "build_number": 17,
            "build_url": "http://jenkins.example/job/demo-job/17/",
            "repo": "acme/payment-service",
            "branch": "qa",
            "status": "FAILED",
            "console_text": console_text,
        }

        webhook_response = self.client.post("/api/v1/webhooks/jenkins/failure", json=payload)
        self.assertEqual(webhook_response.status_code, 202)
        event_id = webhook_response.json()["event_id"]

        latest_console = self.client.get("/api/events/latest/console.txt")
        self.assertEqual(latest_console.status_code, 200)
        self.assertEqual(latest_console.text, console_text)

        event_console = self.client.get(f"/api/events/{event_id}/console.txt")
        self.assertEqual(event_console.status_code, 200)
        self.assertEqual(event_console.text, console_text)

        event_detail = self.client.get(f"/api/events/{event_id}")
        self.assertEqual(event_detail.status_code, 200)
        detail_json = event_detail.json()
        self.assertEqual(detail_json["summary"]["repo"], "acme/payment-service")
        self.assertEqual(detail_json["summary"]["branch"], "qa")
        self.assertEqual(detail_json["console"]["line_count"], 3)
        self.assertEqual(detail_json["console"]["raw_text"], console_text)

    def test_analyze_event_categorizes_va_and_other_issues(self) -> None:
        console_text = """
===== scan-dependencies.log =====

pom.xml (pom)
=============
│                  Library                  │  Vulnerability   │ Severity │ Status │ Installed Version │        Fixed Version        │                            Title                             │
│ org.apache.logging.log4j:log4j-core       │ CVE-2021-44228   │ CRITICAL │ fixed  │ 2.14.1            │ 2.17.1                      │ log4j-core remote code execution                             │
ERROR Deployment blocked.
""".strip()
        payload = {
            "job_name": "demo-job",
            "build_number": 18,
            "build_url": "http://jenkins.example/job/demo-job/18/",
            "repo": "acme/payment-service",
            "branch": "qa",
            "status": "FAILED",
            "console_text": console_text,
        }

        webhook_response = self.client.post("/api/v1/webhooks/jenkins/failure", json=payload)
        self.assertEqual(webhook_response.status_code, 202)
        event_id = webhook_response.json()["event_id"]

        analyze_response = self.client.post(f"/api/events/{event_id}/analyze")
        self.assertEqual(analyze_response.status_code, 200)
        analysis = analyze_response.json()

        self.assertTrue(analysis["supported"])
        self.assertEqual(analysis["issue_counts"]["VA"], 1)
        self.assertEqual(analysis["issue_counts"]["OTHER"], 1)
        self.assertEqual(analysis["issue_list"][0]["issue_category"], "VA")
        self.assertEqual(analysis["issue_list"][0]["package_name"], "org.apache.logging.log4j:log4j-core")
        self.assertIn("CVE-2021-44228", analysis["issue_list"][0]["cve_ids"])

    def test_minimal_tester_ui_renders(self) -> None:
        response = self.client.get("/tester")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Non-AI Flow Tester", response.text)
        self.assertIn("GitHub Fetch By Repo And Branch", response.text)
        self.assertIn("Push New Fix Branch To GitHub", response.text)
        self.assertIn("Target path (optional)", response.text)

    def test_prepare_fix_builds_bom_safe_property_plan(self) -> None:
        pom_path = self.temp_dir / "repo" / "pom.xml"
        pom_path.parent.mkdir(parents=True, exist_ok=True)
        pom_path.write_text(
            """
<project>
  <properties>
    <log4j2.version>2.14.1</log4j2.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j2.version}</version>
    </dependency>
  </dependencies>
</project>
""".strip(),
            encoding="utf-8",
        )

        console_text = """
===== scan-dependencies.log =====

pom.xml (pom)
=============
│                  Library                  │  Vulnerability   │ Severity │ Status │ Installed Version │        Fixed Version        │                            Title                             │
│ org.apache.logging.log4j:log4j-core       │ CVE-2021-44228   │ CRITICAL │ fixed  │ 2.14.1            │ 2.17.1                      │ log4j-core remote code execution                             │
ERROR Deployment blocked.
""".strip()
        payload = {
            "job_name": "demo-job",
            "build_number": 19,
            "build_url": "http://jenkins.example/job/demo-job/19/",
            "repo": "acme/payment-service",
            "branch": "qa",
            "status": "FAILED",
            "local_repo_path": str(pom_path.parent),
            "console_text": console_text,
        }

        webhook_response = self.client.post("/api/v1/webhooks/jenkins/failure", json=payload)
        self.assertEqual(webhook_response.status_code, 202)
        event_id = webhook_response.json()["event_id"]

        prepare_response = self.client.post(f"/api/events/{event_id}/prepare-fix")
        self.assertEqual(prepare_response.status_code, 200)
        proposal = prepare_response.json()

        self.assertEqual(proposal["status"], "ready")
        self.assertTrue(proposal["validated_change_plan"]["validation_passed"])
        self.assertFalse(proposal["validated_change_plan"]["manual_review_required"])
        self.assertEqual(len(proposal["validated_change_plan"]["file_changes"]), 1)
        file_change = proposal["validated_change_plan"]["file_changes"][0]
        self.assertEqual(file_change["change_type"], "maven-property-upgrade")
        self.assertEqual(file_change["path"], "pom.xml")
        self.assertIn("<log4j2.version>2.17.1</log4j2.version>", file_change["updated_content"])

    def test_fetch_analysis_files_reads_expected_files_from_repo_branch(self) -> None:
        fake_client = FakeHttpClient(
            {
                ("GET", "/repos/acme/payment-service/git/trees/qa"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/git/trees/qa",
                    {
                        "tree": [
                            {"path": "Dockerfile", "type": "blob"},
                            {"path": "pom.xml", "type": "blob"},
                            {"path": "docs/readme.md", "type": "blob"},
                            {"path": "src/app.py", "type": "blob"},
                            {"path": "gradle.properties", "type": "blob"},
                        ]
                    },
                ),
                ("GET", "/repos/acme/payment-service/contents/Dockerfile"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/contents/Dockerfile",
                    {"encoding": "base64", "content": _b64("FROM eclipse-temurin:21")},
                ),
                ("GET", "/repos/acme/payment-service/contents/pom.xml"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/contents/pom.xml",
                    {"encoding": "base64", "content": _b64("<project />")},
                ),
                ("GET", "/repos/acme/payment-service/contents/gradle.properties"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/contents/gradle.properties",
                    {"encoding": "base64", "content": _b64("org.gradle.jvmargs=-Xmx1g")},
                ),
            }
        )

        with patch.object(github_branch_ops, "GITHUB_TOKEN", "test-token"), patch.object(
            github_branch_ops.httpx, "Client", return_value=fake_client
        ):
            files = github_branch_ops.fetch_analysis_files("acme/payment-service", "qa")

        self.assertEqual(
            files,
            {
                "Dockerfile": "FROM eclipse-temurin:21",
                "pom.xml": "<project />",
                "gradle.properties": "org.gradle.jvmargs=-Xmx1g",
            },
        )
        self.assertEqual(fake_client.calls[0]["params"], {"recursive": "1"})
        self.assertEqual(fake_client.calls[1]["params"], {"ref": "qa"})
        self.assertEqual(fake_client.calls[2]["params"], {"ref": "qa"})
        self.assertEqual(fake_client.calls[3]["params"], {"ref": "qa"})

    def test_github_fetch_endpoint_returns_preview_data(self) -> None:
        with patch.object(
            monitor_app.github_branch_ops,
            "fetch_analysis_files",
            return_value={
                "Dockerfile": "FROM eclipse-temurin:21\nRUN apk add openssl",
                "pom.xml": "<project><dependencies /></project>",
            },
        ) as fetch_mock:
            response = self.client.post(
                "/api/github/fetch-files",
                json={"repo_name": "acme/payment-service", "branch_name": "qa"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["repo_name"], "acme/payment-service")
        self.assertEqual(payload["branch_name"], "qa")
        self.assertEqual(payload["file_count"], 2)
        self.assertEqual(payload["files"][0]["path"], "Dockerfile")
        self.assertIn("RUN apk add openssl", payload["files"][0]["preview"])
        fetch_mock.assert_called_once_with("acme/payment-service", "qa")

    def test_create_branch_and_push_file_updates_repo_contents(self) -> None:
        fake_client = FakeHttpClient(
            {
                ("GET", "/repos/acme/payment-service/git/ref/heads/qa"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/git/ref/heads/qa",
                    {"object": {"sha": "base-sha-123"}},
                ),
                ("POST", "/repos/acme/payment-service/git/refs"): _json_response(
                    "POST",
                    "/repos/acme/payment-service/git/refs",
                    {"ref": "refs/heads/va-fix-cve-2026-1111"},
                    status_code=201,
                ),
                ("GET", "/repos/acme/payment-service/git/trees/qa"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/git/trees/qa",
                    {"tree": [{"path": "Dockerfile", "type": "blob"}]},
                ),
                ("GET", "/repos/acme/payment-service/contents/Dockerfile"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/contents/Dockerfile",
                    {"sha": "file-sha-456"},
                ),
                ("PUT", "/repos/acme/payment-service/contents/Dockerfile"): _json_response(
                    "PUT",
                    "/repos/acme/payment-service/contents/Dockerfile",
                    {"commit": {"sha": "commit-sha-789"}},
                ),
            }
        )

        with patch.object(github_branch_ops, "GITHUB_TOKEN", "test-token"), patch.object(
            github_branch_ops.httpx, "Client", return_value=fake_client
        ):
            result = github_branch_ops.create_branch_and_push_file(
                repo_name="acme/payment-service",
                base_branch="qa",
                new_branch="va-fix-cve-2026-1111",
                target_file="Dockerfile",
                updated_content="FROM eclipse-temurin:21.0.3_9-jre",
                commit_message="Fix vulnerable base image",
            )

        self.assertEqual(result["status"], "pushed")
        self.assertEqual(result["branch_name"], "va-fix-cve-2026-1111")
        self.assertEqual(result["target_file"], "Dockerfile")
        self.assertEqual(
            result["compare_url"],
            "https://github.com/acme/payment-service/compare/qa...va-fix-cve-2026-1111",
        )
        self.assertEqual(fake_client.calls[1]["json"], {"ref": "refs/heads/va-fix-cve-2026-1111", "sha": "base-sha-123"})
        put_payload = fake_client.calls[4]["json"]
        self.assertIsNotNone(put_payload)
        self.assertEqual(put_payload["message"], "Fix vulnerable base image")
        self.assertEqual(put_payload["branch"], "va-fix-cve-2026-1111")
        self.assertEqual(base64.b64decode(put_payload["content"]).decode("utf-8"), "FROM eclipse-temurin:21.0.3_9-jre")

    def test_github_push_endpoint_calls_branch_push_helper(self) -> None:
        with patch.object(
            monitor_app.github_branch_ops,
            "create_branch_and_push_file",
            return_value={
                "status": "pushed",
                "branch_name": "auto-fix/test-branch",
                "compare_url": "https://github.com/acme/payment-service/compare/qa...auto-fix/test-branch",
            },
        ) as push_mock:
            response = self.client.post(
                "/api/github/push-file",
                json={
                    "repo_name": "acme/payment-service",
                    "base_branch": "qa",
                    "new_branch": "auto-fix/test-branch",
                    "target_file": "Dockerfile",
                    "target_path": "services/api/Dockerfile",
                    "updated_content": "FROM eclipse-temurin:21",
                    "commit_message": "Apply vulnerability fix",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "pushed")
        push_mock.assert_called_once_with(
            repo_name="acme/payment-service",
            base_branch="qa",
            new_branch="auto-fix/test-branch",
            target_file="services/api/Dockerfile",
            updated_content="FROM eclipse-temurin:21",
            commit_message="Apply vulnerability fix",
        )

    def test_create_branch_and_push_file_reuses_existing_branch(self) -> None:
        fake_client = FakeHttpClient(
            {
                ("GET", "/repos/acme/payment-service/git/ref/heads/qa"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/git/ref/heads/qa",
                    {"object": {"sha": "base-sha-123"}},
                ),
                ("POST", "/repos/acme/payment-service/git/refs"): _json_response(
                    "POST",
                    "/repos/acme/payment-service/git/refs",
                    {
                        "message": "Reference already exists",
                        "errors": [{"code": "already_exists", "message": "Reference already exists"}],
                    },
                    status_code=422,
                ),
                ("GET", "/repos/acme/payment-service/git/trees/auto-fix/test-branch"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/git/trees/auto-fix/test-branch",
                    {"tree": [{"path": "Dockerfile", "type": "blob"}]},
                ),
                ("GET", "/repos/acme/payment-service/contents/Dockerfile"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/contents/Dockerfile",
                    {"sha": "existing-branch-file-sha"},
                ),
                ("PUT", "/repos/acme/payment-service/contents/Dockerfile"): _json_response(
                    "PUT",
                    "/repos/acme/payment-service/contents/Dockerfile",
                    {"commit": {"sha": "commit-sha-789"}},
                ),
            }
        )

        with patch.object(github_branch_ops, "GITHUB_TOKEN", "test-token"), patch.object(
            github_branch_ops.httpx, "Client", return_value=fake_client
        ):
            result = github_branch_ops.create_branch_and_push_file(
                repo_name="acme/payment-service",
                base_branch="qa",
                new_branch="auto-fix/test-branch",
                target_file="Dockerfile",
                updated_content="FROM eclipse-temurin:21.0.3_9-jre",
                commit_message="Fix vulnerable base image",
            )

        self.assertEqual(result["status"], "pushed")
        self.assertFalse(result["branch_created"])
        self.assertEqual(fake_client.calls[3]["params"], {"ref": "auto-fix/test-branch"})

    def test_create_branch_and_push_file_resolves_target_file_case(self) -> None:
        fake_client = FakeHttpClient(
            {
                ("GET", "/repos/acme/payment-service/git/ref/heads/main"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/git/ref/heads/main",
                    {"object": {"sha": "base-sha-123"}},
                ),
                ("POST", "/repos/acme/payment-service/git/refs"): _json_response(
                    "POST",
                    "/repos/acme/payment-service/git/refs",
                    {"ref": "refs/heads/auto-fix/test-branch"},
                    status_code=201,
                ),
                ("GET", "/repos/acme/payment-service/git/trees/main"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/git/trees/main",
                    {"tree": [{"path": "Dockerfile", "type": "blob"}]},
                ),
                ("GET", "/repos/acme/payment-service/contents/Dockerfile"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/contents/Dockerfile",
                    {"sha": "file-sha-456"},
                ),
                ("PUT", "/repos/acme/payment-service/contents/Dockerfile"): _json_response(
                    "PUT",
                    "/repos/acme/payment-service/contents/Dockerfile",
                    {"commit": {"sha": "commit-sha-789"}},
                ),
            }
        )

        with patch.object(github_branch_ops, "GITHUB_TOKEN", "test-token"), patch.object(
            github_branch_ops.httpx, "Client", return_value=fake_client
        ):
            result = github_branch_ops.create_branch_and_push_file(
                repo_name="acme/payment-service",
                base_branch="main",
                new_branch="auto-fix/test-branch",
                target_file="DockerFile",
                updated_content="FROM eclipse-temurin:21.0.3_9-jre",
                commit_message="Fix vulnerable base image",
            )

        self.assertEqual(result["target_file"], "Dockerfile")
        self.assertEqual(fake_client.calls[4]["url"], "/repos/acme/payment-service/contents/Dockerfile")

    def test_apply_fix_endpoint_pushes_branch_and_creates_pull_request(self) -> None:
        event = monitor_app.StoredEvent(
            event_id="evt_livepush1",
            received_at="2026-04-28T00:00:00+00:00",
            method="POST",
            path="/api/v1/webhooks/jenkins/failure",
            client="127.0.0.1",
            content_type="application/json",
            content_length=0,
            headers={},
            payload={"repo": "acme/payment-service", "branch": "qa"},
            raw_body="{}",
            summary={"repo": "acme/payment-service", "branch": "qa"},
            analysis={"supported": True},
            proposal={
                "proposal_id": "fp_livepush1",
                "status": "ready",
                "branch_name": "va-fix-cve-2026-1111",
                "pr_title": "Fix vulnerability in Dockerfile",
                "pr_body": "Automated remediation proposal.",
                "validated_change_plan": {
                    "validation_passed": True,
                    "manual_review_required": False,
                    "validation_notes": [],
                    "file_changes": [
                        {
                            "path": "Dockerfile",
                            "updated_content": "FROM eclipse-temurin:21.0.3_9-jre",
                        }
                    ],
                },
            },
        )
        monitor_app.store.add(event)

        fake_client = FakeHttpClient(
            {
                ("GET", "/repos/acme/payment-service/git/ref/heads/qa"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/git/ref/heads/qa",
                    {"object": {"sha": "base-sha-123"}},
                ),
                ("POST", "/repos/acme/payment-service/git/refs"): _json_response(
                    "POST",
                    "/repos/acme/payment-service/git/refs",
                    {"ref": "refs/heads/va-fix-cve-2026-1111"},
                    status_code=201,
                ),
                ("GET", "/repos/acme/payment-service/git/trees/qa"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/git/trees/qa",
                    {"tree": [{"path": "Dockerfile", "type": "blob"}]},
                ),
                ("GET", "/repos/acme/payment-service/contents/Dockerfile"): _json_response(
                    "GET",
                    "/repos/acme/payment-service/contents/Dockerfile",
                    {"sha": "file-sha-456"},
                ),
                ("PUT", "/repos/acme/payment-service/contents/Dockerfile"): _json_response(
                    "PUT",
                    "/repos/acme/payment-service/contents/Dockerfile",
                    {"commit": {"sha": "commit-sha-789"}},
                ),
                ("POST", "/repos/acme/payment-service/pulls"): _json_response(
                    "POST",
                    "/repos/acme/payment-service/pulls",
                    {"html_url": "https://github.com/acme/payment-service/pull/91"},
                    status_code=201,
                ),
            }
        )

        with patch.object(monitor_app, "GITHUB_DRY_RUN", False), patch.object(
            monitor_app, "GITHUB_TOKEN", "test-token"
        ), patch.object(github_branch_ops, "GITHUB_TOKEN", "test-token"), patch.object(
            github_branch_ops.httpx, "Client", return_value=fake_client
        ):
            response = self.client.post("/api/events/evt_livepush1/apply-fix", json={"base_branch": "qa"})

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["base_branch"], "qa")
        self.assertEqual(result["branch_name"], "va-fix-cve-2026-1111")
        self.assertEqual(result["pull_request_url"], "https://github.com/acme/payment-service/pull/91")
        self.assertEqual(result["changed_files"], ["Dockerfile"])

        artifact_path = Path(result["artifact_file_paths"][0])
        self.assertTrue(artifact_path.exists())
        self.assertEqual(artifact_path.read_text(encoding="utf-8"), "FROM eclipse-temurin:21.0.3_9-jre")

        pr_payload = fake_client.calls[-1]["json"]
        self.assertEqual(pr_payload["head"], "va-fix-cve-2026-1111")
        self.assertEqual(pr_payload["base"], "qa")
        self.assertEqual(pr_payload["title"], "Fix vulnerability in Dockerfile")


if __name__ == "__main__":
    unittest.main()
