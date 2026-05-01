# Jenkins Webhook LangGraph Flow

This folder is a self-contained backend prototype for:

- Jenkins failure webhook ingestion
- payload normalization for Jenkins scan logs
- GitHub manifest and Dockerfile fetch
- 4-node LangGraph remediation flow
- validated branch push and PR creation

## Folder layout

- `python/webhook_langgraph_flow/`
  - FastAPI app and webhook contract
  - GitHub fetch and push helpers
  - 4-node LangGraph workflow
- `payloads/sample_webhook_payload.json`
  - example Jenkins webhook body with explicit dependency and Docker paths
- `jenkins/jenkins_webhook_pipeline.groovy`
  - sandbox-friendly Jenkins pipeline snippet for posting the webhook
- `tests/`
  - focused tests for the new flow

## Run locally

From the repo root:

```powershell
$env:PYTHONPATH='dev_test/jenkins_webhook_langgraph_flow/python'
$env:PAYLOAD_MONITOR_JENKINS_WEBHOOK_SECRET='your-shared-secret' # optional but recommended
python -m uvicorn webhook_langgraph_flow.app:app --reload
```

Open:

- `http://127.0.0.1:8000/docs`

## Run tests

```powershell
$env:PYTHONPATH='dev_test/jenkins_webhook_langgraph_flow/python'
python -m unittest discover -s dev_test/jenkins_webhook_langgraph_flow/tests -p "test_*.py"
```

## Payload design

The normalized Jenkins payload for this backend is:

- `repo`
- `branch`
- `target_branch`
- `status`
- `console_output`
- `dependency_file_paths`
- `docker_file_paths`
- `local_repo_path` for local dry runs and notebook experiments

The main simplification in this version is that Jenkins provides:

- `dependency_file_paths`
- `docker_file_paths`

That lets the remediation flow trust the build context first, then fall back to discovery only if those paths are missing.

`console_output` is treated as the source-of-truth scan log. `console_text` is still accepted for backward compatibility.

If `local_repo_path` points at the repo checkout itself, the workflow can still resolve repo-prefixed webhook paths such as `jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml`.
If `local_repo_path` is omitted or points to a placeholder path that does not exist locally, the workflow falls back to GitHub file fetch.

## Main API flow

1. Jenkins posts the failure payload to `POST /api/v1/webhooks/jenkins/failure`.
2. The backend validates the optional `x-webhook-secret` header if `PAYLOAD_MONITOR_JENKINS_WEBHOOK_SECRET` is configured.
3. The event is normalized and stored in `python/webhook_langgraph_flow/runtime/requests.jsonl`.
4. `POST /api/events/{event_id}/prepare-fix` loads local or GitHub files and builds a remediation plan.
5. `POST /api/events/{event_id}/apply-fix` creates the branch and PR, or dry-runs when GitHub dry-run is enabled.
