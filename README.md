# Pipeline Security Autofix

FastAPI + LangGraph service for ingesting Jenkins failure webhooks, extracting dependency vulnerabilities from scan logs, preparing Maven remediation changes, and optionally pushing validated fix branches to GitHub.

## Project Structure

```text
pipeline-security-autofix/
├── pipeline_security_autofix/
│   ├── api/
│   │   └── app.py
│   ├── core/
│   │   ├── env.py
│   │   ├── models.py
│   │   └── workflow.py
│   ├── services/
│   │   └── github.py
│   ├── storage/
│   │   └── event_store.py
│   ├── runtime/
│   └── main.py
├── tests/
│   └── test_webhook_langgraph_flow.py
├── jenkins/
│   └── *.groovy
├── payloads/
│   └── sample_webhook_payload.json
├── linkedin content/
└── system_design/
```

## Run Locally

Install dependencies and start the FastAPI app:

```powershell
pip install -r requirements.txt
$env:PAYLOAD_MONITOR_JENKINS_WEBHOOK_SECRET='your-shared-secret'
python -m uvicorn pipeline_security_autofix.api.app:app --reload
```

Open `http://127.0.0.1:8000/docs`.

## Run Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

## Notes

- `pipeline_security_autofix` is the canonical package.
- `webhook_langgraph_flow` remains as a compatibility shim for older imports.
- Jenkins scripts live in the top-level `jenkins/` folder.
- Example webhook payloads live in the top-level `payloads/` folder.
