from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

import payload_monitor.app as monitor_app


ROOT = Path(__file__).resolve().parents[1]


class PayloadMonitorRemediationTests(unittest.TestCase):
    def setUp(self) -> None:
        workspace_temp_root = ROOT / ".test_tmp"
        workspace_temp_root.mkdir(parents=True, exist_ok=True)
        self.temp_dir = workspace_temp_root / f"pm-{uuid4().hex[:8]}"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.events_file = self.temp_dir / "requests.jsonl"
        self.original_store = monitor_app.store
        monitor_app.store = monitor_app.EventStore(self.events_file)
        self.client = TestClient(monitor_app.app)

        self.sample_docker_repo = self.temp_dir / "docker"
        shutil.copytree(ROOT / "OLD-REMOVE" / "sample_docker_repo", self.sample_docker_repo)

        self.sample_java_repo = self.temp_dir / "java"
        shutil.copytree(ROOT / "demo-springboot-vuln-service", self.sample_java_repo)

    def tearDown(self) -> None:
        self.client.close()
        monitor_app.store = self.original_store
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_docker_payload_can_be_analyzed_and_prepared(self) -> None:
        payload = json.loads(
            (ROOT / "OLD-REMOVE" / "examples" / "jenkins_failure_payload.json").read_text(encoding="utf-8")
        )
        payload["repo"] = "acme/payment-service"
        payload["branch"] = "qa"
        payload["local_repo_path"] = str(self.sample_docker_repo)
        payload["console_text"] = (
            ROOT / "OLD-REMOVE" / "examples" / "docker_vulnerability_console.log"
        ).read_text(encoding="utf-8")

        webhook_response = self.client.post("/api/v1/webhooks/jenkins/failure", json=payload)
        self.assertEqual(webhook_response.status_code, 202)
        self.assertTrue(webhook_response.json()["analysis_supported"])
        event_id = webhook_response.json()["event_id"]

        event_response = self.client.get(f"/api/events/{event_id}")
        self.assertEqual(event_response.status_code, 200)
        analysis = event_response.json()["analysis"]
        self.assertEqual(analysis["target_file"], "Dockerfile")
        self.assertEqual(analysis["recommended_version"], "1.3.2-r0")

        proposal_response = self.client.post(f"/api/events/{event_id}/prepare-fix")
        self.assertEqual(proposal_response.status_code, 200)
        proposal = proposal_response.json()
        self.assertEqual(proposal["status"], "ready")
        self.assertEqual(proposal["patch_strategy"], "direct-version-bump")
        self.assertTrue(any("1.3.2-r0" in line for line in proposal["diff_preview"]))

        apply_response = self.client.post(
            f"/api/events/{event_id}/apply-fix",
            json={"base_branch": "qa"},
        )
        self.assertEqual(apply_response.status_code, 200)
        apply_result = apply_response.json()
        self.assertEqual(apply_result["status"], "dry-run")
        self.assertEqual(apply_result["base_branch"], "qa")
        self.assertTrue(Path(apply_result["artifact_file_path"]).exists())

    def test_maven_payload_gets_bom_friendly_recommendation(self) -> None:
        payload = {
            "job_name": "demo-springboot-vuln-service",
            "build_number": 9,
            "build_url": "http://jenkins.example/job/demo-springboot-vuln-service/9/",
            "branch": "qa",
            "repo": "acme/demo-springboot-vuln-service",
            "status": "FAILED",
            "local_repo_path": str(self.sample_java_repo),
            "console_text": (
                "2026-04-27T12:00:00Z CRITICAL CVE-2026-99999 "
                "pkg=org.yaml:snakeyaml installed version 1.30 fixed version 2.0 target=pom.xml\n"
                "2026-04-27T12:00:00Z ERROR Deployment blocked."
            ),
        }

        webhook_response = self.client.post("/api/v1/webhooks/jenkins/failure", json=payload)
        self.assertEqual(webhook_response.status_code, 202)
        event_id = webhook_response.json()["event_id"]

        event_response = self.client.get(f"/api/events/{event_id}")
        analysis = event_response.json()["analysis"]
        self.assertEqual(analysis["solution_kind"], "bom-friendly-upgrade")
        self.assertEqual(analysis["target_file"], "pom.xml")

        proposal_response = self.client.post(f"/api/events/{event_id}/prepare-fix")
        self.assertEqual(proposal_response.status_code, 200)
        proposal = proposal_response.json()
        self.assertEqual(proposal["status"], "ready")
        self.assertIn(proposal["patch_strategy"], {"direct-dependency-version-bump", "bom-property-version-bump"})
        self.assertTrue(any("2.0" in line for line in proposal["diff_preview"]))


if __name__ == "__main__":
    unittest.main()
