from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ValidationError

from ..core import workflow
from ..core.env import load_project_env
from ..core.models import JenkinsFailurePayload
from ..services import github
from ..storage.event_store import EventStore, StoredEvent


load_project_env()


APP_DIR = Path(__file__).resolve().parents[1]
RUNTIME_DIR = APP_DIR / "runtime"
EVENTS_FILE = RUNTIME_DIR / "requests.jsonl"


store = EventStore(EVENTS_FILE)


class FixApplyRequest(BaseModel):
    push_enabled: bool = True


class GitHubFetchRequest(BaseModel):
    repo_name: str
    branch_name: str
    file_paths: list[str]


class GitHubPushRequest(BaseModel):
    repo_name: str
    base_branch: str
    new_branch: str
    files: list[dict[str, str]]
    commit_message: str


app = FastAPI(title="Pipeline Security Autofix", version="0.1.0")


def _webhook_secret() -> str:
    return os.getenv("PAYLOAD_MONITOR_JENKINS_WEBHOOK_SECRET", "").strip()


def _validate_webhook_secret(header_secret: str | None) -> None:
    expected_secret = _webhook_secret()
    if not expected_secret:
        return
    provided_secret = (header_secret or "").strip()
    if not provided_secret or not secrets.compare_digest(provided_secret, expected_secret):
        raise HTTPException(status_code=401, detail="Webhook secret was missing or invalid.")


def _raw_to_payload(raw_body: str) -> JenkinsFailurePayload:
    if not raw_body.strip():
        raise HTTPException(status_code=400, detail="Webhook body was empty.")
    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Webhook body was not valid JSON: {exc.msg}") from exc
    try:
        return JenkinsFailurePayload.model_validate(parsed)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_or_empty(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _event_summary(event: StoredEvent) -> dict[str, Any]:
    payload = _dict_or_empty(event.payload)
    analysis = _dict_or_empty(event.analysis)
    proposal = _dict_or_empty(event.proposal)
    apply_result = _dict_or_empty(event.apply_result)
    push_result = _dict_or_empty(apply_result.get("push_result"))
    issues = _list_or_empty(analysis.get("issues"))
    counts = _dict_or_empty(analysis.get("issue_counts"))
    va_issues = [issue for issue in issues if str(issue.get("issue_category", "")).upper() == "VA"]
    other_issues = [issue for issue in issues if str(issue.get("issue_category", "")).upper() != "VA"]
    file_changes = _list_or_empty(_dict_or_empty(proposal.get("plan")).get("file_changes"))
    note_count = len(_list_or_empty(_dict_or_empty(proposal.get("plan")).get("notes")))
    proposed_branch = str(proposal.get("branch_name", "") or "")
    fixed_branch = str(push_result.get("branch_name") or apply_result.get("branch_name") or proposed_branch)

    return {
        "event_id": event.event_id,
        "received_at": event.received_at,
        "job_name": payload.get("job_name", ""),
        "build_number": payload.get("build_number"),
        "build_url": payload.get("build_url", ""),
        "repo": payload.get("repo", ""),
        "branch": payload.get("branch", ""),
        "status": payload.get("status", ""),
        "summary": analysis.get("summary", "Awaiting analysis."),
        "supported": bool(analysis.get("supported")),
        "issue_counts": {
            "VA": int(counts.get("VA", 0) or 0),
            "OTHER": int(counts.get("OTHER", 0) or 0),
        },
        "va_issue_preview": [
            {
                "package_name": issue.get("package_name", ""),
                "cve_ids": _list_or_empty(issue.get("cve_ids")),
                "fixed_versions": _list_or_empty(issue.get("fixed_versions")),
            }
            for issue in va_issues[:3]
        ],
        "other_issue_count": len(other_issues),
        "proposal_ready": bool(file_changes),
        "proposal_change_count": len(file_changes),
        "proposal_note_count": note_count,
        "proposed_branch": proposed_branch,
        "push_status": str(push_result.get("status", "") or ""),
        "fixed_branch": fixed_branch,
        "compare_url": push_result.get("compare_url", ""),
        "pull_request_url": push_result.get("pull_request_url", ""),
        "changed_files": len(_list_or_empty(push_result.get("changed_files"))),
    }


def _dashboard_payload() -> dict[str, Any]:
    events = [_event_summary(event) for event in store.list_events()]
    return {
        "metrics": {
            "total_events": len(events),
            "fix_previews": sum(1 for event in events if event["proposal_ready"]),
            "total_va_issues": sum(event["issue_counts"]["VA"] for event in events),
            "needs_review": sum(1 for event in events if not event["proposal_ready"]),
        },
        "events": events,
    }


def _dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Pipeline Security Autofix Monitor</title>
  <style>
    :root {
      --bg: #f5f1ea;
      --bg-accent: #e9f0ec;
      --panel: rgba(255, 255, 255, 0.82);
      --panel-strong: #ffffff;
      --border: rgba(24, 39, 34, 0.12);
      --text: #17211d;
      --muted: #61706a;
      --accent: #0f766e;
      --accent-soft: rgba(15, 118, 110, 0.12);
      --danger: #b9382f;
      --danger-soft: rgba(185, 56, 47, 0.12);
      --warning: #b7791f;
      --warning-soft: rgba(183, 121, 31, 0.12);
      --success: #2f7d4f;
      --success-soft: rgba(47, 125, 79, 0.12);
      --shadow: 0 18px 40px rgba(31, 41, 36, 0.08);
      --radius: 22px;
      --radius-sm: 14px;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI Variable Text", Aptos, "Trebuchet MS", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(15, 118, 110, 0.12), transparent 30%),
        radial-gradient(circle at top right, rgba(191, 219, 205, 0.45), transparent 28%),
        linear-gradient(180deg, #fbf8f3 0%, var(--bg) 100%);
    }

    .shell {
      width: min(1400px, calc(100% - 32px));
      margin: 24px auto;
    }

    .hero,
    .panel,
    .metric {
      background: var(--panel);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
    }

    .hero {
      border-radius: 28px;
      padding: 26px 28px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
      margin-bottom: 18px;
    }

    h1,
    h2,
    h3,
    p {
      margin: 0;
    }

    .eyebrow {
      font-size: 12px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: 8px;
      font-weight: 700;
    }

    .hero h1 {
      font-size: clamp(28px, 4vw, 44px);
      line-height: 1.02;
      max-width: 860px;
    }

    .hero p {
      margin-top: 12px;
      color: var(--muted);
      max-width: 860px;
      font-size: 15px;
      line-height: 1.6;
    }

    .hero-status {
      min-width: 220px;
      display: grid;
      gap: 12px;
    }

    .chip,
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border-radius: 999px;
      padding: 8px 12px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.02em;
    }

    .chip {
      background: var(--accent-soft);
      color: var(--accent);
      justify-content: center;
    }

    .chip::before {
      content: "";
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: currentColor;
    }

    .hero-note {
      padding: 14px 16px;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.7);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }

    .metric {
      border-radius: 22px;
      padding: 18px;
    }

    .metric-label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      margin-bottom: 8px;
      font-weight: 700;
    }

    .metric-value {
      font-size: 34px;
      font-weight: 800;
      letter-spacing: -0.04em;
    }

    .layout {
      display: grid;
      grid-template-columns: 360px minmax(0, 1fr);
      gap: 18px;
      align-items: start;
    }

    .panel {
      border-radius: 26px;
      padding: 18px;
    }

    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 14px;
    }

    .panel-title {
      font-size: 18px;
      font-weight: 800;
      letter-spacing: -0.02em;
    }

    .panel-subtitle {
      color: var(--muted);
      font-size: 13px;
    }

    .event-list {
      display: grid;
      gap: 12px;
      max-height: calc(100vh - 300px);
      overflow: auto;
      padding-right: 4px;
    }

    .event-card {
      border-radius: 20px;
      padding: 16px;
      background: rgba(255, 255, 255, 0.75);
      border: 1px solid transparent;
      cursor: pointer;
      transition: transform 0.18s ease, border-color 0.18s ease, background 0.18s ease;
    }

    .event-card:hover {
      transform: translateY(-1px);
      border-color: rgba(15, 118, 110, 0.24);
      background: rgba(255, 255, 255, 0.95);
    }

    .event-card.active {
      border-color: rgba(15, 118, 110, 0.4);
      background: #ffffff;
    }

    .event-topline,
    .detail-meta,
    .split {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }

    .repo-name {
      font-size: 15px;
      font-weight: 800;
      letter-spacing: -0.02em;
      word-break: break-word;
    }

    .build-ref {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }

    .event-summary {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
      margin: 10px 0 14px;
    }

    .badge {
      padding: 6px 10px;
      font-size: 11px;
    }

    .badge.accent {
      background: var(--accent-soft);
      color: var(--accent);
    }

    .badge.danger {
      background: var(--danger-soft);
      color: var(--danger);
    }

    .badge.warning {
      background: var(--warning-soft);
      color: var(--warning);
    }

    .badge.success {
      background: var(--success-soft);
      color: var(--success);
    }

    .badge.neutral {
      background: rgba(24, 39, 34, 0.07);
      color: var(--muted);
    }

    .badge-row,
    .section-stack {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .detail-scroll {
      display: grid;
      gap: 14px;
      max-height: calc(100vh - 300px);
      overflow: auto;
      padding-right: 4px;
    }

    .hero-card,
    .section {
      border-radius: 22px;
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid var(--border);
      padding: 18px;
    }

    .hero-card h2 {
      font-size: clamp(22px, 3vw, 34px);
      line-height: 1.05;
      margin: 8px 0 12px;
      letter-spacing: -0.04em;
    }

    .hero-card p,
    .section p,
    .line-item,
    .detail-list li {
      color: var(--muted);
      font-size: 14px;
      line-height: 1.6;
    }

    .section-title {
      font-size: 16px;
      font-weight: 800;
      letter-spacing: -0.02em;
      margin-bottom: 12px;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .kv {
      padding: 14px;
      border-radius: 18px;
      background: rgba(15, 23, 42, 0.03);
      border: 1px solid rgba(24, 39, 34, 0.08);
    }

    .kv-label {
      font-size: 11px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 6px;
      font-weight: 700;
    }

    .kv-value {
      font-size: 15px;
      font-weight: 700;
      word-break: break-word;
    }

    .issue-list,
    .change-list {
      display: grid;
      gap: 12px;
    }

    .issue-card,
    .change-card {
      border-radius: 18px;
      border: 1px solid rgba(24, 39, 34, 0.1);
      background: var(--panel-strong);
      padding: 16px;
    }

    .issue-title {
      font-weight: 800;
      letter-spacing: -0.02em;
      margin-bottom: 8px;
      word-break: break-word;
    }

    .issue-meta {
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 10px;
    }

    .pre {
      margin: 0;
      padding: 14px;
      border-radius: 16px;
      background: #13201c;
      color: #d9efe2;
      font: 12px/1.55 Consolas, "SFMono-Regular", Menlo, monospace;
      overflow: auto;
      max-height: 420px;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .btn-secondary {
      background: rgba(15, 118, 110, 0.1);
      color: var(--accent);
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      font: inherit;
      font-weight: 800;
      cursor: pointer;
    }

    .btn-ghost {
      background: rgba(24, 39, 34, 0.08);
      color: var(--text);
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      font: inherit;
      font-weight: 800;
      cursor: pointer;
    }

    a {
      color: var(--accent);
      text-decoration: none;
      font-weight: 700;
    }

    a:hover {
      text-decoration: underline;
    }

    .empty {
      padding: 28px;
      text-align: center;
      color: var(--muted);
      border: 1px dashed rgba(24, 39, 34, 0.18);
      border-radius: 20px;
    }

    .change-header {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: center;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }

    .file-preview-label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      margin: 14px 0 8px;
      font-weight: 700;
    }

    .branch-highlight {
      margin-bottom: 14px;
      padding: 16px 18px;
      border-radius: 18px;
      background: linear-gradient(135deg, rgba(15, 118, 110, 0.14), rgba(15, 118, 110, 0.06));
      border: 1px solid rgba(15, 118, 110, 0.22);
    }

    .branch-highlight-label {
      color: var(--accent);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      margin-bottom: 8px;
      font-weight: 800;
    }

    .branch-highlight-value {
      color: var(--text);
      font: 700 20px/1.35 Consolas, "SFMono-Regular", Menlo, monospace;
      word-break: break-word;
    }

    .footer-note {
      margin-top: 18px;
      color: var(--muted);
      font-size: 12px;
      text-align: right;
    }

    @media (max-width: 980px) {
      .metrics,
      .layout,
      .detail-grid {
        grid-template-columns: 1fr;
      }

      .event-list {
        max-height: none;
      }

      .detail-scroll {
        max-height: none;
      }

      .hero {
        padding: 22px;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div>
        <div class="eyebrow">Jenkins Failure Monitor</div>
        <h1>Focused view of failed builds and BOM-friendly remediation previews.</h1>
        <p>Incoming webhook failures are listed on the left. The selected run shows the extracted vulnerability issues and the full proposed file updates, without branch-push actions or extra controls.</p>
      </div>
      <div class="hero-status">
        <div class="chip">Manual refresh</div>
        <div class="hero-note" id="last-updated">Waiting for the first refresh...</div>
      </div>
    </section>

    <section class="metrics">
      <article class="metric">
        <div class="metric-label">Total Events</div>
        <div class="metric-value" id="metric-total">0</div>
      </article>
      <article class="metric">
        <div class="metric-label">Fix Previews</div>
        <div class="metric-value" id="metric-preview">0</div>
      </article>
      <article class="metric">
        <div class="metric-label">VA Issues</div>
        <div class="metric-value" id="metric-va">0</div>
      </article>
      <article class="metric">
        <div class="metric-label">Needs Review</div>
        <div class="metric-value" id="metric-review">0</div>
      </article>
    </section>

    <section class="layout">
      <aside class="panel">
        <div class="panel-header">
          <div>
            <div class="panel-title">Recent Failures</div>
            <div class="panel-subtitle">Newest webhook deliveries first.</div>
          </div>
          <div class="section-stack">
            <button class="btn-ghost" id="refresh-button" type="button">Refresh</button>
            <button class="btn-ghost" id="clear-button" type="button">Clear</button>
          </div>
        </div>
        <div class="event-list" id="event-list"></div>
      </aside>

      <main class="panel">
        <div class="panel-header">
          <div>
            <div class="panel-title">Failure Detail</div>
            <div class="panel-subtitle">Issue breakdown and full BOM-friendly file previews.</div>
          </div>
        </div>
        <div class="detail-scroll" id="detail-view"></div>
      </main>
    </section>

    <div class="footer-note">BOM-friendly means the proposed change prefers property or owner-version updates over scattered direct overrides whenever the pom structure allows it.</div>
  </div>

  <script>
    const state = {
      selectedEventId: null,
      events: [],
    };

    const refreshButton = document.getElementById("refresh-button");
    const clearButton = document.getElementById("clear-button");
    const eventListEl = document.getElementById("event-list");
    const detailViewEl = document.getElementById("detail-view");

    refreshButton.addEventListener("click", () => loadDashboard(true));
    clearButton.addEventListener("click", async () => {
      const confirmed = window.confirm("Clear all stored failures from the dashboard?");
      if (!confirmed) return;
      clearButton.disabled = true;
      try {
        const response = await fetch("/api/dashboard/events", { method: "DELETE" });
        if (!response.ok) {
          throw new Error(`Clear failed with status ${response.status}`);
        }
        state.selectedEventId = null;
        await loadDashboard(true);
      } catch (error) {
        detailViewEl.innerHTML = `<div class="empty">${escapeHtml(error.message || String(error))}</div>`;
      } finally {
        clearButton.disabled = false;
      }
    });

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function formatTime(value) {
      if (!value) return "Unknown time";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
    }

    function renderMetrics(metrics) {
      document.getElementById("metric-total").textContent = metrics.total_events ?? 0;
      document.getElementById("metric-preview").textContent = metrics.fix_previews ?? 0;
      document.getElementById("metric-va").textContent = metrics.total_va_issues ?? 0;
      document.getElementById("metric-review").textContent = metrics.needs_review ?? 0;
    }

    function badgeClass(name) {
      if (name === "success") return "badge success";
      if (name === "danger") return "badge danger";
      if (name === "warning") return "badge warning";
      if (name === "accent") return "badge accent";
      return "badge neutral";
    }

    function renderEventList() {
      if (!state.events.length) {
        eventListEl.innerHTML = '<div class="empty">No webhook failures have been captured yet.</div>';
        return;
      }

      eventListEl.innerHTML = state.events.map((event) => {
        const isActive = event.event_id === state.selectedEventId;
        const supportBadgeName = event.proposal_ready ? "accent" : "warning";
        const preview = (event.va_issue_preview || []).map((issue) => issue.package_name).filter(Boolean).join(", ");

        return `
          <article class="event-card ${isActive ? "active" : ""}" data-event-id="${escapeHtml(event.event_id)}">
            <div class="event-topline">
              <div class="repo-name">${escapeHtml(event.repo || event.job_name || "Unnamed build")}</div>
              <div class="build-ref">#${escapeHtml(event.build_number ?? "–")}</div>
            </div>
            <div class="event-summary">${escapeHtml(event.summary || "Awaiting analysis.")}</div>
            <div class="badge-row">
              <span class="badge danger">VA ${escapeHtml(event.issue_counts?.VA ?? 0)}</span>
              <span class="badge warning">Other ${escapeHtml(event.issue_counts?.OTHER ?? 0)}</span>
              <span class="${badgeClass(supportBadgeName)}">${event.proposal_ready ? "Fix preview ready" : "Needs review"}</span>
            </div>
            ${preview ? `<div class="event-summary" style="margin-top:12px;">${escapeHtml(preview)}</div>` : ""}
          </article>
        `;
      }).join("");

      for (const card of eventListEl.querySelectorAll(".event-card")) {
        card.addEventListener("click", () => {
          state.selectedEventId = card.dataset.eventId;
          renderEventList();
          renderSelectedEvent();
        });
      }
    }

    function renderIssueCard(issue) {
      const cves = (issue.cve_ids || []).join(", ");
      const fixes = (issue.fixed_versions || []).join(", ");
      return `
        <article class="issue-card">
          <div class="split">
            <div class="issue-title">${escapeHtml(issue.package_name || "General issue")}</div>
            <span class="badge danger">${escapeHtml(issue.issue_category || "Issue")}</span>
          </div>
          <div class="issue-meta">
            ${cves ? `CVE: ${escapeHtml(cves)}<br />` : ""}
            ${issue.installed_version ? `Installed: ${escapeHtml(issue.installed_version)}<br />` : ""}
            ${fixes ? `Fixed versions: ${escapeHtml(fixes)}<br />` : ""}
            ${issue.target_file_hint ? `File hint: ${escapeHtml(issue.target_file_hint)}` : ""}
          </div>
          <p>${escapeHtml(issue.detailed_issue || issue.initial_fix || "No extra detail.")}</p>
        </article>
      `;
    }

    function renderOtherIssueCard(issue) {
      return `
        <article class="issue-card">
          <div class="split">
            <div class="issue-title">${escapeHtml(issue.detailed_issue || "Other failure detail")}</div>
            <span class="badge warning">${escapeHtml(issue.issue_category || "OTHER")}</span>
          </div>
          <p>${escapeHtml(issue.initial_fix || "Review the Jenkins output for this failure.")}</p>
        </article>
      `;
    }

    function renderChangeCard(change) {
      const diffPreview = Array.isArray(change.diff_preview) ? change.diff_preview.join("\\n") : "";
      return `
        <article class="change-card">
          <div class="change-header">
            <div class="issue-title">${escapeHtml(change.path || "Updated file")}</div>
            <span class="badge accent">BOM-friendly fix</span>
          </div>
          <div class="issue-meta">Preview of the exact file content generated by the remediation flow.</div>
          <div class="file-preview-label">Diff Preview</div>
          <pre class="pre">${escapeHtml(diffPreview || "No diff preview available.")}</pre>
          <div class="file-preview-label">Full Updated File</div>
          <pre class="pre">${escapeHtml(change.updated_content || "No updated content available.")}</pre>
        </article>
      `;
    }

    async function renderSelectedEvent() {
      if (!state.selectedEventId) {
        detailViewEl.innerHTML = '<div class="empty">Select a failure to inspect its issues and remediation preview.</div>';
        return;
      }

      detailViewEl.innerHTML = '<div class="empty">Loading selected failure...</div>';
      const response = await fetch(`/api/events/${state.selectedEventId}`);
      if (!response.ok) {
        detailViewEl.innerHTML = '<div class="empty">The selected event could not be loaded.</div>';
        return;
      }

      const event = await response.json();
      const payload = event.payload || {};
      const analysis = event.analysis || {};
      const proposal = event.proposal || {};
      const issues = Array.isArray(analysis.issues) ? analysis.issues : [];
      const vaIssues = issues.filter((issue) => String(issue.issue_category || "").toUpperCase() === "VA");
      const otherIssues = issues.filter((issue) => String(issue.issue_category || "").toUpperCase() !== "VA");
      const fileChanges = Array.isArray(proposal.plan?.file_changes) ? proposal.plan.file_changes : [];
      const planNotes = Array.isArray(proposal.plan?.notes) ? proposal.plan.notes : [];
      const buildLink = payload.build_url ? `<a href="${escapeHtml(payload.build_url)}" target="_blank" rel="noreferrer">Open Jenkins build</a>` : "No build URL";

      detailViewEl.innerHTML = `
        <section class="hero-card">
          <div class="detail-meta">
            <span class="badge accent">${escapeHtml(payload.status || "FAILED")}</span>
            <span class="badge neutral">${escapeHtml(formatTime(event.received_at))}</span>
          </div>
          <h2>${escapeHtml(payload.repo || payload.job_name || "Unnamed event")}</h2>
          <p>${escapeHtml(analysis.summary || "This failure has not been analyzed yet.")}</p>
        </section>

        <section class="section">
          <div class="section-title">Build Context</div>
          <div class="detail-grid">
            <div class="kv">
              <div class="kv-label">Job</div>
              <div class="kv-value">${escapeHtml(payload.job_name || "Unknown")}</div>
            </div>
            <div class="kv">
              <div class="kv-label">Source Branch</div>
              <div class="kv-value">${escapeHtml(payload.branch || "main")}</div>
            </div>
            <div class="kv">
              <div class="kv-label">VA Issues</div>
              <div class="kv-value">${escapeHtml(analysis.issue_counts?.VA ?? vaIssues.length)}</div>
            </div>
            <div class="kv">
              <div class="kv-label">Other Issues</div>
              <div class="kv-value">${escapeHtml(analysis.issue_counts?.OTHER ?? otherIssues.length)}</div>
            </div>
          </div>
          <div class="line-item" style="margin-top:14px;">${buildLink}</div>
        </section>

        <section class="section">
          <div class="section-title">VA Issues</div>
          <div class="issue-list">
            ${vaIssues.length ? vaIssues.map(renderIssueCard).join("") : '<div class="empty">No vulnerability issues were extracted from this Jenkins output.</div>'}
          </div>
        </section>

        <section class="section">
          <div class="section-title">Other Failure Signals</div>
          <div class="issue-list">
            ${otherIssues.length ? otherIssues.map(renderOtherIssueCard).join("") : '<div class="empty">No extra non-VA failure lines were captured.</div>'}
          </div>
        </section>

        <section class="section">
          <div class="section-title">BOM-friendly Fix Plan</div>
          <p style="margin-bottom:12px;">This preview favors Maven property or owner-version edits before direct dependency overrides when the pom structure supports it.</p>
          ${proposal.branch_name ? `
            <div class="branch-highlight">
              <div class="branch-highlight-label">Proposed Branch</div>
              <div class="branch-highlight-value">${escapeHtml(proposal.branch_name)}</div>
            </div>
          ` : ""}
          <div class="change-list">
            ${fileChanges.length ? fileChanges.map(renderChangeCard).join("") : '<div class="empty">No fix preview is available for this failure yet.</div>'}
          </div>
          ${planNotes.length ? `<div class="section-stack" style="margin-top:12px;">${planNotes.map((note) => `<span class="badge warning">${escapeHtml(note)}</span>`).join("")}</div>` : ""}
        </section>

        <section class="section">
          <div class="section-title">Pushed Branch</div>
          ${event.apply_result?.push_result?.branch_name || event.apply_result?.branch_name ? `
            <div class="section-stack" style="margin-bottom:12px;">
              ${event.apply_result?.push_result?.status ? `<span class="${badgeClass(event.apply_result.push_result.status === "pushed" || event.apply_result.push_result.status === "dry-run" ? "success" : "warning")}">${escapeHtml(event.apply_result.push_result.status)}</span>` : ""}
              ${(event.apply_result?.push_result?.branch_name || event.apply_result?.branch_name) ? `<span class="badge neutral">${escapeHtml(event.apply_result?.push_result?.branch_name || event.apply_result?.branch_name)}</span>` : ""}
            </div>
            <div class="section-stack">
              ${event.apply_result?.push_result?.compare_url ? `<a href="${escapeHtml(event.apply_result.push_result.compare_url)}" target="_blank" rel="noreferrer">Open compare view</a>` : ""}
              ${event.apply_result?.push_result?.pull_request_url ? `<a href="${escapeHtml(event.apply_result.push_result.pull_request_url)}" target="_blank" rel="noreferrer">Open pull request</a>` : ""}
            </div>
          ` : '<div class="empty">No pushed branch has been recorded for this failure yet.</div>'}
        </section>

        <section class="section">
          <div class="section-title">Jenkins Console Output</div>
          <pre class="pre">${escapeHtml(event.console_text || "No console text captured.")}</pre>
        </section>
      `;
    }

    async function loadDashboard(updateSelection) {
      refreshButton.disabled = true;
      try {
        const response = await fetch("/api/dashboard/events");
        const payload = await response.json();
        state.events = Array.isArray(payload.events) ? payload.events : [];
        renderMetrics(payload.metrics || {});

        if (!state.selectedEventId || updateSelection) {
          state.selectedEventId = state.events[0]?.event_id ?? null;
        } else if (!state.events.some((event) => event.event_id === state.selectedEventId)) {
          state.selectedEventId = state.events[0]?.event_id ?? null;
        }

        renderEventList();
        await renderSelectedEvent();
        document.getElementById("last-updated").textContent = `Last refreshed ${formatTime(new Date().toISOString())}`;
      } catch (error) {
        eventListEl.innerHTML = `<div class="empty">${escapeHtml(error.message || String(error))}</div>`;
        detailViewEl.innerHTML = '<div class="empty">Refresh failed. Check the API server logs.</div>';
      } finally {
        refreshButton.disabled = false;
      }
    }

    loadDashboard(true);
  </script>
</body>
</html>
"""


def _proposal_error_payload(payload: dict[str, Any], event_id: str, local_repo_path: str | None, exc: Exception) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "repo": payload.get("repo"),
        "branch": payload.get("branch"),
        "file_paths": workflow._payload_paths(payload),
        "resolved_paths": [],
        "plan": {
            "file_changes": [],
            "notes": [f"Fix preview unavailable: {exc}"],
        },
        "branch_name": "",
        "local_repo_path": local_repo_path,
    }


def _prepare_fix_preview(payload: dict[str, Any], *, event_id: str, local_repo_path: str | None) -> dict[str, Any]:
    try:
        return workflow.run_prepare_fix(payload, event_id=event_id, local_repo_path=local_repo_path)
    except Exception as exc:
        return _proposal_error_payload(payload, event_id, local_repo_path, exc)


def _apply_error_payload(payload: dict[str, Any], event_id: str, exc: Exception) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "branch_name": "",
        "plan": {
            "file_changes": [],
            "notes": [f"Auto-apply failed: {exc}"],
        },
        "push_result": {
            "status": "failed",
            "message": str(exc),
        },
    }


def _apply_fix_now(payload: dict[str, Any], *, event_id: str, local_repo_path: str | None) -> dict[str, Any]:
    try:
        return workflow.run_apply_fix(
            payload,
            event_id=event_id,
            local_repo_path=local_repo_path,
            push_enabled=True,
        )
    except Exception as exc:
        return _apply_error_payload(payload, event_id, exc)


def _proposal_from_apply_result(apply_result: dict[str, Any], payload: dict[str, Any], local_repo_path: str | None) -> dict[str, Any]:
    return {
        "event_id": apply_result.get("event_id", ""),
        "created_at": apply_result.get("created_at", ""),
        "repo": payload.get("repo"),
        "branch": payload.get("branch"),
        "file_paths": workflow._payload_paths(payload),
        "resolved_paths": [],
        "plan": _dict_or_empty(apply_result.get("plan")),
        "branch_name": str(apply_result.get("branch_name", "") or ""),
        "local_repo_path": local_repo_path,
    }


@app.get("/api/v1/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "event_count": len(store.list_events())}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard() -> HTMLResponse:
    return HTMLResponse(_dashboard_html())


@app.get("/api/dashboard/events")
def dashboard_events() -> dict[str, Any]:
    return _dashboard_payload()


@app.delete("/api/dashboard/events")
def clear_dashboard_events() -> dict[str, Any]:
    store.clear()
    return {"status": "cleared"}


@app.post("/api/v1/webhooks/jenkins/failure", status_code=202)
async def ingest_jenkins_failure(request: Request, x_webhook_secret: str | None = Header(default=None)) -> dict[str, Any]:
    _validate_webhook_secret(x_webhook_secret)
    raw_body = (await request.body()).decode("utf-8", errors="replace")
    payload_model = _raw_to_payload(raw_body)
    payload = payload_model.to_payload_dict()
    event_id = f"evt_{uuid4().hex[:10]}"
    event = StoredEvent(
        event_id=event_id,
        received_at=datetime.now(timezone.utc).isoformat(),
        payload=payload,
        raw_body=raw_body,
        console_text=payload_model.normalized_console_text(),
        local_repo_path=payload_model.normalized_local_repo_path(),
    )
    event.analysis = workflow.run_analysis(payload, event_id=event_id, local_repo_path=event.local_repo_path)
    event.apply_result = _apply_fix_now(payload, event_id=event_id, local_repo_path=event.local_repo_path)
    event.proposal = _proposal_from_apply_result(event.apply_result, payload, event.local_repo_path)
    store.add(event)
    return {
        "status": "accepted",
        "event_id": event_id,
        "push_status": _dict_or_empty(event.apply_result.get("push_result")).get("status", ""),
        "branch_name": event.apply_result.get("branch_name", ""),
    }


@app.get("/api/events")
def list_events() -> dict[str, Any]:
    return {
        "events": [
            {
                "event_id": event.event_id,
                "received_at": event.received_at,
                "repo": event.payload.get("repo"),
                "branch": event.payload.get("branch"),
            }
            for event in store.list_events()
        ]
    }


@app.get("/api/events/{event_id}")
def get_event(event_id: str) -> dict[str, Any]:
    event = store.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    return asdict(event)


@app.post("/api/events/{event_id}/analyze")
def analyze_event(event_id: str) -> dict[str, Any]:
    event = store.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    event.analysis = workflow.run_analysis(event.payload, event_id=event.event_id, local_repo_path=event.local_repo_path)
    event.proposal = _prepare_fix_preview(event.payload, event_id=event.event_id, local_repo_path=event.local_repo_path)
    store.save(event)
    return event.analysis


@app.post("/api/events/{event_id}/prepare-fix")
def prepare_fix(event_id: str) -> dict[str, Any]:
    event = store.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    event.proposal = _prepare_fix_preview(event.payload, event_id=event.event_id, local_repo_path=event.local_repo_path)
    store.save(event)
    return event.proposal


@app.post("/api/events/{event_id}/apply-fix")
def apply_fix(event_id: str, payload: FixApplyRequest) -> dict[str, Any]:
    event = store.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    event.apply_result = workflow.run_apply_fix(
        dict(event.payload),
        event_id=event.event_id,
        local_repo_path=event.local_repo_path,
        push_enabled=payload.push_enabled,
    )
    store.save(event)
    return event.apply_result


@app.post("/api/github/fetch-files")
def github_fetch_files(payload: GitHubFetchRequest) -> dict[str, Any]:
    files = github.fetch_repo_files_by_paths(payload.repo_name, payload.branch_name, payload.file_paths)
    return {
        "repo_name": payload.repo_name,
        "branch_name": payload.branch_name,
        "file_count": len(files),
        "files": [{"path": path, "preview": content[:240]} for path, content in files.items()],
    }


@app.post("/api/github/push-branch")
def github_push_branch(payload: GitHubPushRequest) -> dict[str, Any]:
    push_result = github.create_branch_and_push_files(
        repo_name=payload.repo_name,
        base_branch=payload.base_branch,
        new_branch=payload.new_branch,
        files=payload.files,
        commit_message=payload.commit_message,
    )
    pr_result = github.create_pull_request(
        repo_name=payload.repo_name,
        base_branch=payload.base_branch,
        new_branch=payload.new_branch,
        title=payload.commit_message,
        body="Created from the Jenkins Webhook LangGraph Flow scaffold.",
    )
    push_result["pull_request_url"] = pr_result["pull_request_url"]
    return push_result
