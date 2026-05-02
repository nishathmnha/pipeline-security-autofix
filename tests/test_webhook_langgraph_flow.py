from __future__ import annotations

import shutil
import unittest
from importlib import import_module
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from pipeline_security_autofix.core import workflow
from pipeline_security_autofix.storage.event_store import EventStore


BOX = "\u2502"
TRIVY_CONSOLE = (
    "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml (pom)\n"
    "│                  Library                  │  Vulnerability   │ Severity │ Status │ Installed Version │        Fixed Version        │                            Title                             │\n"
    "│ org.apache.logging.log4j:log4j-core       │ CVE-2021-44228   │ CRITICAL │ fixed  │ 2.14.1            │ 2.17.1                      │ log4j-core remote code execution                             │\n"
)


TRIVY_CONSOLE = (
    "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml (pom)\n"
    f"{BOX}                  Library                  {BOX}  Vulnerability   {BOX} Severity {BOX} Status {BOX} Installed Version {BOX}        Fixed Version        {BOX}                            Title                             {BOX}\n"
    f"{BOX} org.apache.logging.log4j:log4j-core       {BOX} CVE-2021-44228   {BOX} CRITICAL {BOX} fixed  {BOX} 2.14.1            {BOX} 2.17.1                      {BOX} log4j-core remote code execution                             {BOX}\n"
)


class WebhookLangGraphFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path("tmp_jlgf_tests")
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.events_file = self.temp_dir / "requests.jsonl"
        app_module = import_module("pipeline_security_autofix.api.app")

        self.old_store = app_module.store
        self.old_secret = app_module.os.environ.get("PAYLOAD_MONITOR_JENKINS_WEBHOOK_SECRET")
        app_module.store = EventStore(self.events_file)
        app_module.os.environ.pop("PAYLOAD_MONITOR_JENKINS_WEBHOOK_SECRET", None)
        self.client = TestClient(app_module.app)

    def tearDown(self) -> None:
        self.client.close()
        app_module = import_module("pipeline_security_autofix.api.app")

        app_module.store = self.old_store
        if self.old_secret is None:
            app_module.os.environ.pop("PAYLOAD_MONITOR_JENKINS_WEBHOOK_SECRET", None)
        else:
            app_module.os.environ["PAYLOAD_MONITOR_JENKINS_WEBHOOK_SECRET"] = self.old_secret
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_webhook_accepts_explicit_dependency_and_docker_paths(self) -> None:
        repo_root = self.temp_dir / "repo"
        service_dir = repo_root / "jenkins-webhook-and-github-setup" / "demo-springboot-vuln-service"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
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
        (service_dir / "Dockerfile").write_text("FROM eclipse-temurin:17-jre", encoding="utf-8")

        payload = {
            "job_name": "spring-boot-backend",
            "build_number": 10,
            "build_url": "http://localhost:8080/job/spring-boot-backend/10/",
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "status": "FAILED",
            "local_repo_path": str(repo_root),
            "console_output": TRIVY_CONSOLE,
            "dependency_file_paths": ["jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml"],
            "docker_file_paths": ["jenkins-webhook-and-github-setup/demo-springboot-vuln-service/Dockerfile"],
        }

        ingest = self.client.post("/api/v1/webhooks/jenkins/failure", json=payload)
        self.assertEqual(ingest.status_code, 202)
        event_id = ingest.json()["event_id"]

        prepare = self.client.post(f"/api/events/{event_id}/prepare-fix")
        self.assertEqual(prepare.status_code, 200)
        proposal = prepare.json()
        self.assertIn(
            "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml",
            [item["path"] for item in proposal["resolved_paths"]],
        )
        self.assertEqual(
            proposal["plan"]["file_changes"][0]["path"],
            "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml",
        )

        stored_event = self.client.get(f"/api/events/{event_id}").json()
        self.assertIn("log4j-core", stored_event["console_text"])

    def test_run_prepare_fix_uses_payload_local_repo_path_when_argument_is_missing(self) -> None:
        service_dir = self.temp_dir / "jenkins-webhook-and-github-setup" / "demo-springboot-vuln-service"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
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

        payload = {
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "local_repo_path": str(service_dir),
            "console_output": TRIVY_CONSOLE,
            "dependency_file_paths": ["jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml"],
        }

        proposal = workflow.run_prepare_fix(payload, event_id="payload-local-repo")
        self.assertEqual(
            proposal["resolved_paths"][0]["path"],
            "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml",
        )
        self.assertEqual(
            proposal["plan"]["file_changes"][0]["path"],
            "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml",
        )

    def test_run_prepare_fix_accumulates_multiple_edits_in_one_pom(self) -> None:
        service_dir = self.temp_dir / "demo-springboot-vuln-service"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
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
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.30</version>
    </dependency>
  </dependencies>
</project>
""".strip(),
            encoding="utf-8",
        )

        payload = {
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "local_repo_path": str(service_dir),
            "console_output": (
                "pom.xml (pom)\n"
                "â”‚                  Library                  â”‚  Vulnerability   â”‚ Severity â”‚ Status â”‚ Installed Version â”‚        Fixed Version        â”‚                            Title                             â”‚\n"
                "â”‚ org.apache.logging.log4j:log4j-core       â”‚ CVE-2021-44228   â”‚ CRITICAL â”‚ fixed  â”‚ 2.14.1            â”‚ 2.17.1                      â”‚ log4j-core remote code execution                             â”‚\n"
                "â”‚ org.yaml:snakeyaml                        â”‚ CVE-2022-1471    â”‚ HIGH     â”‚ fixed  â”‚ 1.30              â”‚ 2.0, 1.31                  â”‚ snakeyaml unsafe deserialization                             â”‚\n"
            ),
            "dependency_file_paths": ["pom.xml"],
        }
        payload["console_output"] = "\n".join(
            [
                "pom.xml (pom)",
                f"{BOX}                  Library                  {BOX}  Vulnerability   {BOX} Severity {BOX} Status {BOX} Installed Version {BOX}        Fixed Version        {BOX}                            Title                             {BOX}",
                f"{BOX} org.apache.logging.log4j:log4j-core       {BOX} CVE-2021-44228   {BOX} CRITICAL {BOX} fixed  {BOX} 2.14.1            {BOX} 2.17.1                      {BOX} log4j-core remote code execution                             {BOX}",
                f"{BOX} org.yaml:snakeyaml                        {BOX} CVE-2022-1471    {BOX} HIGH     {BOX} fixed  {BOX} 1.30              {BOX} 2.0, 1.31                  {BOX} snakeyaml unsafe deserialization                             {BOX}",
            ]
        )

        proposal = workflow.run_prepare_fix(payload, event_id="multi-edit-pom")
        updated_content = proposal["plan"]["file_changes"][0]["updated_content"]
        simulation = proposal["plan"]["simulation"]

        self.assertIn("<log4j2.version>2.17.1</log4j2.version>", updated_content)
        self.assertIn("<version>1.31</version>", updated_content)
        self.assertNotIn("<version>1.30</version>", updated_content)
        self.assertEqual(simulation["final_remaining_va_count"], 0)
        self.assertEqual(len(simulation["passes"]), 1)
        self.assertFalse(simulation["passes"][0]["retry_requested"])

    def test_run_prepare_fix_uses_spring_boot_parent_as_bom_owner(self) -> None:
        service_dir = self.temp_dir / "demo-springboot-vuln-service-parent"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
            """
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
  </parent>
  <properties>
    <java.version>17</java.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.30</version>
    </dependency>
  </dependencies>
</project>
""".strip(),
            encoding="utf-8",
        )

        payload = {
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "local_repo_path": str(service_dir),
            "console_output": (
                "pom.xml (pom)\n"
                "â”‚                  Library                  â”‚  Vulnerability   â”‚ Severity â”‚ Status â”‚ Installed Version â”‚        Fixed Version        â”‚                            Title                             â”‚\n"
                "â”‚ org.springframework.boot:spring-boot      â”‚ CVE-2025-22235   â”‚ HIGH     â”‚ fixed  â”‚ 2.7.18            â”‚ 3.3.11, 3.4.5              â”‚ spring boot parent                                             â”‚\n"
                "â”‚ org.springframework:spring-web            â”‚ CVE-2024-22262   â”‚ HIGH     â”‚ fixed  â”‚ 5.3.31            â”‚ 5.3.34, 6.1.6              â”‚ spring web                                                    â”‚\n"
                "â”‚ org.apache.logging.log4j:log4j-core       â”‚ CVE-2021-45105   â”‚ HIGH     â”‚ fixed  â”‚ 2.14.1            â”‚ 2.17.0                      â”‚ log4j-core                                                    â”‚\n"
                "â”‚ org.yaml:snakeyaml                        â”‚ CVE-2022-1471    â”‚ HIGH     â”‚ fixed  â”‚ 1.30              â”‚ 2.0, 1.31                  â”‚ snakeyaml                                                     â”‚\n"
            ),
            "dependency_file_paths": ["pom.xml"],
        }
        payload["console_output"] = "\n".join(
            [
                "pom.xml (pom)",
                f"{BOX}                  Library                  {BOX}  Vulnerability   {BOX} Severity {BOX} Status {BOX} Installed Version {BOX}        Fixed Version        {BOX}                            Title                             {BOX}",
                f"{BOX} org.springframework.boot:spring-boot      {BOX} CVE-2025-22235   {BOX} HIGH     {BOX} fixed  {BOX} 2.7.18            {BOX} 3.3.11, 3.4.5              {BOX} spring boot parent                                             {BOX}",
                f"{BOX} org.springframework:spring-web            {BOX} CVE-2024-22262   {BOX} HIGH     {BOX} fixed  {BOX} 5.3.31            {BOX} 5.3.34, 6.1.6              {BOX} spring web                                                    {BOX}",
                f"{BOX} org.apache.logging.log4j:log4j-core       {BOX} CVE-2021-45105   {BOX} HIGH     {BOX} fixed  {BOX} 2.14.1            {BOX} 2.17.0                      {BOX} log4j-core                                                    {BOX}",
                f"{BOX} org.yaml:snakeyaml                        {BOX} CVE-2022-1471    {BOX} HIGH     {BOX} fixed  {BOX} 1.30              {BOX} 2.0, 1.31                  {BOX} snakeyaml                                                     {BOX}",
            ]
        )

        proposal = workflow.run_prepare_fix(payload, event_id="spring-boot-parent-owner")
        updated_content = proposal["plan"]["file_changes"][0]["updated_content"]
        notes_text = "\n".join(proposal["plan"]["notes"])

        self.assertIn("<version>3.4.5</version>", updated_content)
        self.assertIn("<artifactId>log4j-core</artifactId>", updated_content)
        self.assertIn("<version>2.17.0</version>", updated_content)
        self.assertIn("<artifactId>snakeyaml</artifactId>", updated_content)
        self.assertIn("<version>2.0</version>", updated_content)
        self.assertNotIn("org.springframework.boot:spring-boot", notes_text)
        self.assertNotIn("org.springframework:spring-web", notes_text)

    def test_run_prepare_fix_adds_overrides_for_remaining_bom_managed_packages(self) -> None:
        service_dir = self.temp_dir / "demo-springboot-vuln-service-bom-fallback"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
            """
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.4.5</version>
  </parent>
  <properties>
    <java.version>17</java.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.17.0</version>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>2.0</version>
    </dependency>
  </dependencies>
</project>
""".strip(),
            encoding="utf-8",
        )

        payload = {
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "ai-va-fix/example",
            "local_repo_path": str(service_dir),
            "console_output": "\n".join(
                [
                    "pom.xml (pom)",
                    f"{BOX}                  Library                  {BOX}  Vulnerability   {BOX} Severity {BOX} Status {BOX} Installed Version {BOX}        Fixed Version        {BOX}                            Title                             {BOX}",
                    f"{BOX} org.apache.tomcat.embed:tomcat-embed-core {BOX} CVE-2026-29145 {BOX} CRITICAL {BOX} fixed  {BOX} 10.1.40           {BOX} 9.0.116, 10.1.53, 11.0.20 {BOX} tomcat                                                      {BOX}",
                    f"{BOX} org.springframework:spring-core           {BOX} CVE-2025-41249 {BOX} HIGH     {BOX} fixed  {BOX} 6.2.6             {BOX} 6.2.11                    {BOX} spring core                                                 {BOX}",
                ]
            ),
            "dependency_file_paths": ["pom.xml"],
        }

        proposal = workflow.run_prepare_fix(payload, event_id="spring-boot-bom-fallback")
        updated_content = proposal["plan"]["file_changes"][0]["updated_content"]
        notes_text = "\n".join(proposal["plan"]["notes"])

        self.assertIn("<artifactId>tomcat-embed-core</artifactId>", updated_content)
        self.assertIn("<version>10.1.53</version>", updated_content)
        self.assertIn("<artifactId>spring-core</artifactId>", updated_content)
        self.assertIn("<version>6.2.11</version>", updated_content)
        self.assertNotIn("org.apache.tomcat.embed:tomcat-embed-core", notes_text)
        self.assertNotIn("org.springframework:spring-core", notes_text)

    def test_run_prepare_fix_upgrades_boot_parent_for_cross_major_spring_web_issue(self) -> None:
        service_dir = self.temp_dir / "demo-springboot-vuln-service-cross-major"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
            """
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
  </parent>
  <properties>
    <java.version>17</java.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.31</version>
    </dependency>
  </dependencies>
</project>
""".strip(),
            encoding="utf-8",
        )

        payload = {
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "local_repo_path": str(service_dir),
            "console_output": "\n".join(
                [
                    "pom.xml (pom)",
                    f"{BOX}                  Library                  {BOX}  Vulnerability   {BOX} Severity {BOX} Status {BOX} Installed Version {BOX}        Fixed Version        {BOX}                            Title                             {BOX}",
                    f"{BOX} org.springframework:spring-web            {BOX} CVE-2016-1000027 {BOX} CRITICAL {BOX} fixed  {BOX} 5.3.34            {BOX} 6.0.0                       {BOX} spring web                                                    {BOX}",
                    f"{BOX} org.yaml:snakeyaml                        {BOX} CVE-2022-1471    {BOX} HIGH     {BOX}        {BOX} 1.31              {BOX} 2.0                         {BOX} snakeyaml                                                     {BOX}",
                ]
            ),
            "dependency_file_paths": ["pom.xml"],
        }

        proposal = workflow.run_prepare_fix(payload, event_id="spring-web-cross-major")
        updated_content = proposal["plan"]["file_changes"][0]["updated_content"]
        notes_text = "\n".join(proposal["plan"]["notes"])

        self.assertIn("<artifactId>spring-boot-starter-parent</artifactId>", updated_content)
        self.assertIn("<version>3.4.5</version>", updated_content)
        self.assertIn("<artifactId>snakeyaml</artifactId>", updated_content)
        self.assertIn("<version>2.0</version>", updated_content)
        self.assertNotIn("<artifactId>spring-web</artifactId>", updated_content)
        self.assertEqual(notes_text, "")

    def test_run_prepare_fix_handles_spring_web_spring_core_and_snakeyaml_together(self) -> None:
        service_dir = self.temp_dir / "demo-springboot-vuln-service-mixed-spring"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
            """
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
  </parent>
  <properties>
    <java.version>17</java.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.31</version>
    </dependency>
  </dependencies>
</project>
""".strip(),
            encoding="utf-8",
        )

        payload = {
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "local_repo_path": str(service_dir),
            "console_output": "\n".join(
                [
                    "pom.xml (pom)",
                    f"{BOX}             Library             {BOX}  Vulnerability   {BOX} Severity {BOX} Status {BOX} Installed Version {BOX} Fixed Version {BOX} Title {BOX}",
                    f"{BOX} org.springframework:spring-core {BOX} CVE-2025-41249   {BOX} HIGH     {BOX} fixed  {BOX} 6.2.6             {BOX} 6.2.11        {BOX} spring-core {BOX}",
                    f"{BOX} org.springframework:spring-web  {BOX} CVE-2016-1000027 {BOX} CRITICAL {BOX}        {BOX} 5.3.34            {BOX} 6.0.0         {BOX} spring-web {BOX}",
                    f"{BOX} org.yaml:snakeyaml              {BOX} CVE-2022-1471    {BOX} HIGH     {BOX}        {BOX} 1.31              {BOX} 2.0           {BOX} snakeyaml {BOX}",
                ]
            ),
            "dependency_file_paths": ["pom.xml"],
        }

        proposal = workflow.run_prepare_fix(payload, event_id="mixed-spring-remediation")
        updated_content = proposal["plan"]["file_changes"][0]["updated_content"]
        notes_text = "\n".join(proposal["plan"]["notes"])

        self.assertIn("<artifactId>spring-boot-starter-parent</artifactId>", updated_content)
        self.assertIn("<version>3.4.5</version>", updated_content)
        self.assertIn("<artifactId>snakeyaml</artifactId>", updated_content)
        self.assertIn("<version>2.0</version>", updated_content)
        self.assertIn("<artifactId>spring-core</artifactId>", updated_content)
        self.assertIn("<version>6.2.11</version>", updated_content)
        self.assertNotIn("<artifactId>spring-web</artifactId>", updated_content)
        self.assertEqual(notes_text, "")

    def test_run_prepare_fix_resolves_tomcat_and_spring_core_after_boot3_upgrade(self) -> None:
        service_dir = self.temp_dir / "demo-springboot-vuln-service-iterative-boot3"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
            """
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
  </parent>
  <properties>
    <java.version>17</java.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.30</version>
    </dependency>
  </dependencies>
</project>
""".strip(),
            encoding="utf-8",
        )

        payload = {
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "local_repo_path": str(service_dir),
            "console_output": "\n".join(
                [
                    "pom.xml (pom)",
                    f"{BOX}                  Library                  {BOX}  Vulnerability   {BOX} Severity {BOX} Status {BOX} Installed Version {BOX}        Fixed Version        {BOX}                            Title                             {BOX}",
                    f"{BOX} org.apache.logging.log4j:log4j-core       {BOX} CVE-2021-44228   {BOX} CRITICAL {BOX}        {BOX} 2.14.1            {BOX} 2.15.0, 2.3.1, 2.12.2       {BOX} log4j-core {BOX}",
                    f"{BOX}                                           {BOX} CVE-2021-45046   {BOX} CRITICAL {BOX}        {BOX}                   {BOX} 2.16.0, 2.12.2              {BOX} log4j-core {BOX}",
                    f"{BOX}                                           {BOX} CVE-2021-45105   {BOX} HIGH     {BOX}        {BOX}                   {BOX} 2.12.3, 2.17.0, 2.3.1       {BOX} log4j-core {BOX}",
                    f"{BOX} org.apache.tomcat.embed:tomcat-embed-core {BOX} CVE-2025-24813   {BOX} CRITICAL {BOX}        {BOX} 9.0.83            {BOX} 11.0.3, 10.1.35, 9.0.99    {BOX} tomcat {BOX}",
                    f"{BOX}                                           {BOX} CVE-2026-29145   {BOX} CRITICAL {BOX}        {BOX}                   {BOX} 9.0.116, 10.1.53, 11.0.20   {BOX} tomcat {BOX}",
                    f"{BOX} org.springframework:spring-core           {BOX} CVE-2025-41249   {BOX} HIGH     {BOX}        {BOX} 5.3.31            {BOX} 6.2.11                      {BOX} spring-core {BOX}",
                    f"{BOX} org.springframework:spring-web            {BOX} CVE-2016-1000027 {BOX} CRITICAL {BOX}        {BOX} 5.3.31            {BOX} 6.0.0                       {BOX} spring-web {BOX}",
                    f"{BOX}                                           {BOX} CVE-2024-22262   {BOX} HIGH     {BOX}        {BOX}                   {BOX} 5.3.34, 6.1.6               {BOX} spring-web {BOX}",
                    f"{BOX} org.yaml:snakeyaml                        {BOX} CVE-2022-1471    {BOX} HIGH     {BOX}        {BOX} 1.30              {BOX} 2.0                         {BOX} snakeyaml {BOX}",
                    f"{BOX}                                           {BOX} CVE-2022-25857   {BOX} HIGH     {BOX}        {BOX}                   {BOX} 1.31                        {BOX} snakeyaml {BOX}",
                ]
            ),
            "dependency_file_paths": ["pom.xml"],
        }

        proposal = workflow.run_prepare_fix(payload, event_id="iterative-boot3-remediation")
        updated_content = proposal["plan"]["file_changes"][0]["updated_content"]
        simulation = proposal["plan"]["simulation"]

        self.assertIn("<artifactId>spring-boot-starter-parent</artifactId>", updated_content)
        self.assertIn("<version>3.4.5</version>", updated_content)
        self.assertIn("<artifactId>log4j-core</artifactId>", updated_content)
        self.assertIn("<version>2.17.0</version>", updated_content)
        self.assertIn("<artifactId>snakeyaml</artifactId>", updated_content)
        self.assertIn("<version>2.0</version>", updated_content)
        self.assertIn("<artifactId>spring-core</artifactId>", updated_content)
        self.assertIn("<version>6.2.11</version>", updated_content)
        self.assertIn("<artifactId>tomcat-embed-core</artifactId>", updated_content)
        self.assertIn("<version>10.1.53</version>", updated_content)
        self.assertEqual(simulation["final_remaining_va_count"], 0)

    def test_run_prepare_fix_uses_cross_major_target_when_grouped_cves_need_it(self) -> None:
        service_dir = self.temp_dir / "demo-springboot-vuln-service-grouped-cves"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
            """
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
  </parent>
  <properties>
    <java.version>17</java.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.30</version>
    </dependency>
  </dependencies>
</project>
""".strip(),
            encoding="utf-8",
        )

        payload = {
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "local_repo_path": str(service_dir),
            "console_output": "\n".join(
                [
                    "pom.xml (pom)",
                    f"{BOX}             Library             {BOX}  Vulnerability   {BOX} Severity {BOX} Status {BOX} Installed Version {BOX} Fixed Version {BOX} Title {BOX}",
                    f"{BOX} org.springframework:spring-web  {BOX} CVE-2016-1000027 {BOX} CRITICAL {BOX}        {BOX} 5.3.31            {BOX} 6.0.0         {BOX} spring-web {BOX}",
                    f"{BOX}                               {BOX} CVE-2024-22262   {BOX} HIGH     {BOX}        {BOX}                   {BOX} 5.3.34, 6.1.6 {BOX} spring-web {BOX}",
                    f"{BOX} org.yaml:snakeyaml           {BOX} CVE-2022-1471    {BOX} HIGH     {BOX}        {BOX} 1.30              {BOX} 2.0           {BOX} snakeyaml {BOX}",
                    f"{BOX}                               {BOX} CVE-2022-25857   {BOX} HIGH     {BOX}        {BOX}                   {BOX} 1.31          {BOX} snakeyaml {BOX}",
                ]
            ),
            "dependency_file_paths": ["pom.xml"],
        }

        proposal = workflow.run_prepare_fix(payload, event_id="grouped-cves-cross-major")
        updated_content = proposal["plan"]["file_changes"][0]["updated_content"]
        simulation = proposal["plan"]["simulation"]

        self.assertIn("<artifactId>spring-boot-starter-parent</artifactId>", updated_content)
        self.assertIn("<version>3.4.5</version>", updated_content)
        self.assertIn("<artifactId>snakeyaml</artifactId>", updated_content)
        self.assertIn("<version>2.0</version>", updated_content)
        self.assertEqual(simulation["final_remaining_va_count"], 0)

    def test_run_prepare_fix_raises_clear_error_for_sample_repo_without_local_files(self) -> None:
        payload = {
            "repo": "owner/repo",
            "branch": "main",
            "console_output": "",
            "dependency_file_paths": ["jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml"],
        }

        with self.assertRaisesRegex(ValueError, "sample placeholder 'owner/repo'"):
            workflow.run_prepare_fix(payload, event_id="missing-local-repo")

    def test_run_prepare_fix_reports_remaining_unresolved_issues_in_simulation(self) -> None:
        service_dir = self.temp_dir / "demo-springboot-vuln-service-unresolved"
        service_dir.mkdir(parents=True, exist_ok=True)
        (service_dir / "pom.xml").write_text(
            """
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
  </parent>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</project>
""".strip(),
            encoding="utf-8",
        )

        payload = {
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "local_repo_path": str(service_dir),
            "console_output": "\n".join(
                [
                    "pom.xml (pom)",
                    f"{BOX}             Library             {BOX}  Vulnerability   {BOX} Severity {BOX} Status {BOX} Installed Version {BOX} Fixed Version {BOX} Title {BOX}",
                    f"{BOX} org.apache.logging.log4j:log4j-core {BOX} CVE-2021-44228 {BOX} CRITICAL {BOX} fixed  {BOX} 2.14.1            {BOX} 2.17.1        {BOX} log4j-core {BOX}",
                ]
            ),
            "dependency_file_paths": ["pom.xml"],
        }

        proposal = workflow.run_prepare_fix(payload, event_id="unresolved-simulation")
        simulation = proposal["plan"]["simulation"]

        self.assertEqual(simulation["final_remaining_va_count"], 1)
        self.assertEqual(simulation["passes"][0]["remaining_packages"], ["org.apache.logging.log4j:log4j-core"])
        self.assertFalse(simulation["passes"][0]["retry_requested"])

    def test_sample_payload_falls_back_to_github_fetch_and_pushes_a_branch(self) -> None:
        payload = {
            "job_name": "spring-boot-backend",
            "build_number": 10,
            "build_url": "http://localhost:8080/job/spring-boot-backend/10/",
            "repo": "nishathmnha/demo-springboot-vuln-service",
            "branch": "main",
            "target_branch": "main",
            "status": "FAILED",
            "console_output": f"{TRIVY_CONSOLE}ERROR Deployment blocked.\n",
            "dependency_file_paths": ["jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml"],
            "docker_file_paths": ["jenkins-webhook-and-github-setup/demo-springboot-vuln-service/Dockerfile"],
            "local_repo_path": "D:/path/to/demo-springboot-vuln-service",
        }
        repo_files = {
            "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml": """
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
            "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/Dockerfile": "FROM eclipse-temurin:17-jre\nRUN java -version\n",
        }

        with patch.object(workflow.github, "fetch_repo_files_by_paths", return_value=repo_files) as fetch_mock, patch.object(
            workflow.github,
            "create_branch_and_push_files",
            return_value={
                "status": "pushed",
                "branch_name": "ai-va-fix/test-branch",
                "branch_created": True,
                "changed_files": [{"path": "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml"}],
                "compare_url": "https://github.com/nishathmnha/demo-springboot-vuln-service/compare/main...ai-va-fix/test-branch",
            },
        ) as push_mock, patch.object(
            workflow.github,
            "create_pull_request",
            return_value={"pull_request_url": "https://github.com/nishathmnha/demo-springboot-vuln-service/pull/1"},
        ) as pr_mock:
            ingest = self.client.post("/api/v1/webhooks/jenkins/failure", json=payload)
            self.assertEqual(ingest.status_code, 202)
            event_id = ingest.json()["event_id"]

            stored_event = self.client.get(f"/api/events/{event_id}")
            self.assertEqual(stored_event.status_code, 200)
            analysis = stored_event.json()["analysis"]
            self.assertTrue(analysis["supported"])
            self.assertEqual(analysis["issue_counts"]["VA"], 1)
            self.assertEqual(analysis["issue_counts"]["OTHER"], 1)
            self.assertEqual(analysis["issues"][0]["issue_category"], "VA")

            prepare = self.client.post(f"/api/events/{event_id}/prepare-fix")
            self.assertEqual(prepare.status_code, 200)
            proposal = prepare.json()
            self.assertEqual(
                proposal["file_paths"],
                [
                    "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml",
                    "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/Dockerfile",
                ],
            )
            self.assertEqual(
                proposal["plan"]["file_changes"][0]["path"],
                "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml",
            )
            self.assertIn(
                "<log4j2.version>2.17.1</log4j2.version>",
                proposal["plan"]["file_changes"][0]["updated_content"],
            )
            fetch_mock.assert_any_call(
                "nishathmnha/demo-springboot-vuln-service",
                "main",
                [
                    "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml",
                    "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/Dockerfile",
                ],
            )

            push_mock.reset_mock()
            pr_mock.reset_mock()
            apply = self.client.post(f"/api/events/{event_id}/apply-fix", json={"push_enabled": True})
            self.assertEqual(apply.status_code, 200)
            apply_result = apply.json()
            self.assertEqual(apply_result["push_result"]["status"], "pushed")
            self.assertEqual(
                apply_result["push_result"]["pull_request_url"],
                "https://github.com/nishathmnha/demo-springboot-vuln-service/pull/1",
            )
            push_mock.assert_called_once()
            pr_mock.assert_called_once()
            pushed_files = push_mock.call_args.kwargs["files"]
            self.assertEqual(len(pushed_files), 1)
            self.assertEqual(
                pushed_files[0]["path"],
                "jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml",
            )
            self.assertIn("2.17.1", pushed_files[0]["updated_content"])

    def test_ingest_rejects_invalid_webhook_secret_when_configured(self) -> None:
        app_module = import_module("pipeline_security_autofix.api.app")
        app_module.os.environ["PAYLOAD_MONITOR_JENKINS_WEBHOOK_SECRET"] = "expected-secret"

        response = self.client.post(
            "/api/v1/webhooks/jenkins/failure",
            json={
                "repo": "nishathmnha/demo-springboot-vuln-service",
                "branch": "main",
                "console_output": "sample console",
            },
            headers={"x-webhook-secret": "wrong-secret"},
        )

        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
