from __future__ import annotations

from fastapi.responses import HTMLResponse

try:
    from .app import app
except ImportError:  # pragma: no cover - support direct module execution
    from app import app

TESTER_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Non-AI Flow Tester</title>
  <style>
    :root {
      --bg: #f4f5f1;
      --panel: #ffffff;
      --line: #d7ddd4;
      --ink: #1b1d1f;
      --muted: #5e646b;
      --accent: #21543d;
      --danger: #a3362b;
      --code: #111315;
      --code-ink: #eef2ef;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--ink);
    }
    .shell {
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }
    h1, h2, p { margin: 0; }
    h1 { font-size: 32px; margin-bottom: 8px; }
    p { color: var(--muted); line-height: 1.5; }
    .topbar {
      display: grid;
      gap: 12px;
      margin-bottom: 20px;
    }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      padding: 8px 12px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel);
      font-size: 13px;
    }
    .layout {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }
    .card {
      display: grid;
      gap: 12px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: var(--panel);
    }
    .wide { grid-column: 1 / -1; }
    .row {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    label {
      display: grid;
      gap: 6px;
      font-size: 13px;
      color: var(--muted);
    }
    input, textarea {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 12px;
      font: inherit;
      color: var(--ink);
      background: #fbfcfa;
    }
    textarea {
      min-height: 110px;
      resize: vertical;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    button {
      padding: 10px 14px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #fff;
      font: inherit;
      cursor: pointer;
    }
    button.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }
    .status {
      font-size: 13px;
      color: var(--muted);
    }
    .error { color: var(--danger); }
    pre {
      margin: 0;
      min-height: 120px;
      padding: 14px;
      border-radius: 12px;
      background: var(--code);
      color: var(--code-ink);
      overflow: auto;
      font: 12px/1.5 Consolas, "Courier New", monospace;
    }
    @media (max-width: 900px) {
      .layout, .row { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="topbar">
      <div>
        <h1>Non-AI Flow Tester</h1>
        <p>Minimal page for Jenkins failure webhook capture, GitHub repo fetch by branch, and pushing a new vulnerability-fix branch.</p>
      </div>
      <div class="meta">
        <div class="chip">Health: <strong id="health-status">checking</strong></div>
        <div class="chip">Events: <strong id="event-count">0</strong></div>
        <div class="chip">Latest Event: <strong id="latest-event-id">none</strong></div>
      </div>
    </section>

    <section class="layout">
      <div class="card">
        <h2>1. Jenkins Failure Webhook</h2>
        <p>Post a failed build payload and store the console output.</p>
        <label>
          Payload JSON
          <textarea id="webhook-payload"></textarea>
        </label>
        <div class="actions">
          <button class="primary" id="send-webhook">Send Payload</button>
          <button id="load-sample">Load Sample</button>
          <button id="clear-events">Clear Events</button>
        </div>
        <div class="status" id="webhook-status">Idle</div>
        <pre id="webhook-output">No webhook sent yet.</pre>
      </div>

      <div class="card">
        <h2>2. Latest Event / Fix Flow</h2>
        <p>Inspect the latest captured event, prepare the fix, and run the apply flow.</p>
        <div class="actions">
          <button class="primary" id="refresh-latest">Refresh Latest</button>
          <button id="prepare-fix">Prepare Fix</button>
          <button id="apply-fix">Apply Fix</button>
        </div>
        <div class="status" id="latest-status">Idle</div>
        <pre id="latest-output">No event loaded yet.</pre>
      </div>

      <div class="card">
        <h2>3. GitHub Fetch By Repo And Branch</h2>
        <div class="row">
          <label>
            Repo
            <input id="fetch-repo" value="owner/repo">
          </label>
          <label>
            Branch
            <input id="fetch-branch" value="qa">
          </label>
        </div>
        <div class="actions">
          <button class="primary" id="fetch-files">Fetch Files</button>
        </div>
        <div class="status" id="fetch-status">Requires GitHub token.</div>
        <pre id="fetch-output">No fetch executed yet.</pre>
      </div>

      <div class="card">
        <h2>4. Push New Fix Branch To GitHub</h2>
        <div class="row">
          <label>
            Repo
            <input id="push-repo" value="owner/repo">
          </label>
          <label>
            Base branch
            <input id="push-base-branch" value="qa">
          </label>
        </div>
        <div class="row">
          <label>
            New branch
            <input id="push-new-branch" value="auto-fix/test-branch">
          </label>
        </div>
        <label>
          Target path (optional)
          <input id="push-target-path" value="" placeholder="jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml">
        </label>
        <label>
          Commit message
          <input id="push-commit-message" value="Apply vulnerability fix">
        </label>
        <label>
          Updated file content
          <textarea id="push-content">FROM eclipse-temurin:21</textarea>
        </label>
        <div class="actions">
          <button class="primary" id="push-file">Push Branch</button>
        </div>
        <div class="status" id="push-status">Requires GitHub token.</div>
        <pre id="push-output">No push executed yet.</pre>
      </div>

      <div class="card wide">
        <h2>Latest Console Output</h2>
        <pre id="console-output">No console text loaded yet.</pre>
      </div>
    </section>
  </div>

  <script>
    const samplePayload = {
      job_name: "demo-payment-service",
      build_number: 17,
      build_url: "http://jenkins.example/job/demo-payment-service/17/",
      repo: "acme/payment-service",
      branch: "qa",
      status: "FAILED",
      console_text:
        "2026-04-28T09:00:00Z CRITICAL CVE-2026-1111 pkg=openssl installed version 1.1.1 fixed version 3.0.14 target=Dockerfile\\n" +
        "2026-04-28T09:00:01Z ERROR Deployment blocked."
    };

    const state = { latestEventId: null };

    function pretty(value) {
      return JSON.stringify(value, null, 2);
    }

    function setStatus(id, message, isError = false) {
      const node = document.getElementById(id);
      node.textContent = message;
      node.className = isError ? "status error" : "status";
    }

    function setOutput(id, value) {
      document.getElementById(id).textContent = typeof value === "string" ? value : pretty(value);
    }

    async function requestJson(url, options = {}) {
      const response = await fetch(url, options);
      const text = await response.text();
      const payload = text ? JSON.parse(text) : {};
      if (!response.ok) {
        throw new Error(payload.detail || text || `Request failed with ${response.status}`);
      }
      return payload;
    }

    async function refreshSummary() {
      const [health, events] = await Promise.all([
        requestJson("/api/v1/health"),
        requestJson("/api/events?limit=1")
      ]);
      document.getElementById("health-status").textContent = health.status;
      document.getElementById("event-count").textContent = String(health.event_count);
      state.latestEventId = events.events[0]?.event_id || null;
      document.getElementById("latest-event-id").textContent = state.latestEventId || "none";
    }

    async function loadLatestEvent() {
      await refreshSummary();
      if (!state.latestEventId) {
        setStatus("latest-status", "No events captured yet.");
        setOutput("latest-output", "No event loaded yet.");
        setOutput("console-output", "No console text loaded yet.");
        return;
      }
      const event = await requestJson(`/api/events/${state.latestEventId}`);
      setStatus("latest-status", `Loaded ${state.latestEventId}`);
      setOutput("latest-output", event);
      setOutput("console-output", event.console?.raw_text || "No console text found.");
    }

    document.getElementById("load-sample").addEventListener("click", () => {
      document.getElementById("webhook-payload").value = pretty(samplePayload);
    });

    document.getElementById("send-webhook").addEventListener("click", async () => {
      try {
        const payload = JSON.parse(document.getElementById("webhook-payload").value);
        const result = await requestJson("/api/v1/webhooks/jenkins/failure", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        setStatus("webhook-status", "Webhook accepted.");
        setOutput("webhook-output", result);
        await loadLatestEvent();
      } catch (error) {
        setStatus("webhook-status", error.message || "Webhook request failed.", true);
      }
    });

    document.getElementById("clear-events").addEventListener("click", async () => {
      try {
        const result = await requestJson("/api/events", { method: "DELETE" });
        setStatus("webhook-status", "Event feed cleared.");
        setOutput("webhook-output", result);
        await loadLatestEvent();
      } catch (error) {
        setStatus("webhook-status", error.message, true);
      }
    });

    document.getElementById("refresh-latest").addEventListener("click", async () => {
      try {
        await loadLatestEvent();
      } catch (error) {
        setStatus("latest-status", error.message, true);
      }
    });

    document.getElementById("prepare-fix").addEventListener("click", async () => {
      try {
        if (!state.latestEventId) {
          throw new Error("No latest event to prepare.");
        }
        const result = await requestJson(`/api/events/${state.latestEventId}/prepare-fix`, { method: "POST" });
        setStatus("latest-status", "Fix proposal prepared.");
        setOutput("latest-output", result);
      } catch (error) {
        setStatus("latest-status", error.message, true);
      }
    });

    document.getElementById("apply-fix").addEventListener("click", async () => {
      try {
        if (!state.latestEventId) {
          throw new Error("No latest event to apply.");
        }
        const result = await requestJson(`/api/events/${state.latestEventId}/apply-fix`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ base_branch: "qa" }),
        });
        setStatus("latest-status", "Fix flow executed.");
        setOutput("latest-output", result);
      } catch (error) {
        setStatus("latest-status", error.message, true);
      }
    });

    document.getElementById("fetch-files").addEventListener("click", async () => {
      try {
        const result = await requestJson("/api/github/fetch-files", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repo_name: document.getElementById("fetch-repo").value.trim(),
            branch_name: document.getElementById("fetch-branch").value.trim(),
          }),
        });
        setStatus("fetch-status", "Fetch completed.");
        setOutput("fetch-output", result);
      } catch (error) {
        setStatus("fetch-status", error.message, true);
      }
    });

    document.getElementById("push-file").addEventListener("click", async () => {
      try {
        const result = await requestJson("/api/github/push-file", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repo_name: document.getElementById("push-repo").value.trim(),
            base_branch: document.getElementById("push-base-branch").value.trim(),
            new_branch: document.getElementById("push-new-branch").value.trim(),
            target_path: document.getElementById("push-target-path").value.trim() || null,
            updated_content: document.getElementById("push-content").value,
            commit_message: document.getElementById("push-commit-message").value.trim(),
          }),
        });
        setStatus("push-status", "Push request completed.");
        setOutput("push-output", result);
      } catch (error) {
        setStatus("push-status", error.message, true);
      }
    });

    document.getElementById("webhook-payload").value = pretty(samplePayload);
    loadLatestEvent().catch((error) => setStatus("latest-status", error.message, true));
  </script>
</body>
</html>
"""

MONITOR_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Jenkins Failure Log Monitor</title>
  <style>
    :root {
      --bg: #f6f0e5;
      --panel: rgba(255, 252, 247, 0.88);
      --panel-strong: rgba(255, 255, 255, 0.96);
      --ink: #1b2833;
      --muted: #5f6d78;
      --line: rgba(27, 40, 51, 0.12);
      --accent: #bf5a21;
      --danger: #a3362b;
      --console-bg: #13212b;
      --console-ink: #edf6f8;
      --shadow: 0 22px 70px rgba(65, 44, 15, 0.14);
      --radius: 22px;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Aptos, "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(191, 90, 33, 0.16), transparent 27%),
        radial-gradient(circle at 78% 12%, rgba(29, 122, 84, 0.10), transparent 21%),
        linear-gradient(180deg, #fbf7f0 0%, #f3eadc 100%);
      min-height: 100vh;
    }

    a {
      color: inherit;
      text-decoration: none;
    }

    button {
      font: inherit;
    }

    .shell {
      width: min(1450px, calc(100vw - 32px));
      margin: 20px auto;
      padding: 20px;
      border-radius: 30px;
      border: 1px solid rgba(255, 255, 255, 0.55);
      background: rgba(255, 250, 244, 0.74);
      box-shadow: var(--shadow);
      backdrop-filter: blur(16px);
    }

    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(280px, 0.75fr);
      gap: 18px;
      margin-bottom: 18px;
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 22px;
    }

    h1, h2, h3 {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      letter-spacing: 0.01em;
    }

    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.85);
      border: 1px solid var(--line);
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 14px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .subtitle {
      margin-top: 12px;
      color: var(--muted);
      line-height: 1.6;
      max-width: 760px;
    }

    .route-chip {
      display: inline-flex;
      margin-top: 14px;
      padding: 10px 14px;
      border-radius: 14px;
      background: #182731;
      color: #eef6f8;
      font-family: Consolas, "Courier New", monospace;
      font-size: 13px;
    }

    .stats {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid var(--line);
      color: var(--muted);
      font-size: 14px;
    }

    .badge strong {
      color: var(--ink);
    }

    .controls {
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-end;
      align-items: flex-start;
      gap: 10px;
      height: 100%;
    }

    .button {
      border: 0;
      border-radius: 999px;
      padding: 12px 18px;
      cursor: pointer;
      transition: transform 0.16s ease, box-shadow 0.16s ease, background 0.16s ease;
    }

    .button:hover {
      transform: translateY(-1px);
    }

    .button.primary {
      color: white;
      background: linear-gradient(135deg, #bf5a21 0%, #de7832 100%);
      box-shadow: 0 12px 26px rgba(191, 90, 33, 0.24);
    }

    .button.secondary {
      color: var(--ink);
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid var(--line);
    }

    .layout {
      display: grid;
      grid-template-columns: 360px minmax(0, 1fr);
      gap: 18px;
      min-height: 72vh;
    }

    .feed {
      display: flex;
      flex-direction: column;
      gap: 12px;
      max-height: 72vh;
      overflow-y: auto;
      padding-right: 4px;
    }

    .event-card {
      width: 100%;
      text-align: left;
      border: 1px solid rgba(191, 90, 33, 0.14);
      border-radius: 18px;
      padding: 16px;
      background: rgba(255, 255, 255, 0.76);
      cursor: pointer;
      transition: border-color 0.16s ease, background 0.16s ease, transform 0.16s ease;
    }

    .event-card:hover {
      transform: translateY(-1px);
      border-color: rgba(191, 90, 33, 0.34);
    }

    .event-card.active {
      border-color: rgba(191, 90, 33, 0.42);
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(191, 90, 33, 0.08));
    }

    .event-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
    }

    .event-title {
      font-size: 16px;
      font-weight: 700;
      line-height: 1.35;
    }

    .status-pill {
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 12px;
      white-space: nowrap;
      color: var(--danger);
      background: rgba(163, 54, 43, 0.12);
      border: 1px solid rgba(163, 54, 43, 0.18);
    }

    .meta {
      margin-top: 10px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }

    .detail-shell {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .detail-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 14px;
      padding-bottom: 4px;
      border-bottom: 1px solid var(--line);
    }

    .detail-subtitle {
      margin-top: 8px;
      color: var(--muted);
      line-height: 1.5;
    }

    .status-tag {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 12px;
      border-radius: 999px;
      font-size: 13px;
      color: var(--danger);
      background: rgba(163, 54, 43, 0.12);
      border: 1px solid rgba(163, 54, 43, 0.18);
      white-space: nowrap;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }

    .detail-box,
    .section-card {
      background: var(--panel-strong);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 16px;
    }

    .detail-label {
      color: var(--muted);
      font-size: 12px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-bottom: 8px;
    }

    .detail-value {
      font-size: 15px;
      line-height: 1.5;
      word-break: break-word;
      white-space: pre-wrap;
    }

    .section-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }

    .section-title p {
      margin: 0;
      color: var(--muted);
      font-size: 14px;
    }

    .link-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }

    .link-chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 12px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid var(--line);
      color: var(--ink);
      font-size: 14px;
    }

    pre {
      margin: 0;
      padding: 18px;
      overflow: auto;
      background: var(--console-bg);
      color: var(--console-ink);
      font: 13px/1.65 Consolas, "Courier New", monospace;
      border-radius: 18px;
      max-height: 560px;
    }

    .empty-state {
      display: grid;
      place-items: center;
      min-height: 56vh;
      color: var(--muted);
      text-align: center;
      padding: 24px;
      border: 1px dashed rgba(27, 40, 51, 0.18);
      border-radius: 24px;
      background: rgba(255, 255, 255, 0.52);
    }

    .error-banner {
      display: none;
      margin-bottom: 16px;
      padding: 14px 16px;
      border-radius: 18px;
      background: rgba(163, 54, 43, 0.1);
      border: 1px solid rgba(163, 54, 43, 0.18);
      color: var(--danger);
    }

    .error-banner.show {
      display: block;
    }

    @media (max-width: 1080px) {
      .grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 980px) {
      .hero,
      .layout,
      .grid {
        grid-template-columns: 1fr;
      }

      .controls {
        justify-content: flex-start;
      }

      .detail-header {
        flex-direction: column;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div id="error-banner" class="error-banner"></div>

    <section class="hero">
      <div class="panel">
        <div class="eyebrow">Payload Only</div>
        <h1>Jenkins Failure Log Monitor</h1>
        <p class="subtitle">
          Lightweight monitor for failed builds. It does not fetch or analyze extra Jenkins data.
          It only stores the console log text that arrives in the webhook payload and makes that
          failure log easy to copy or consume.
        </p>
        <div class="route-chip">POST /api/v1/webhooks/jenkins/failure</div>
        <div class="stats">
          <div class="badge">App status <strong id="health-status">checking</strong></div>
          <div class="badge">Stored requests <strong id="event-count">0</strong></div>
          <div class="badge">Latest refresh <strong id="last-refresh">never</strong></div>
        </div>
      </div>

      <div class="panel">
        <div class="eyebrow">Operator Controls</div>
        <div class="controls">
          <button class="button secondary" id="clear-button">Clear Feed</button>
          <button class="button primary" id="refresh-button">Refresh Now</button>
        </div>
        <p class="subtitle">
          The monitor only uses the `console_text` value that Jenkins sends in the webhook body.
        </p>
      </div>
    </section>

    <section class="layout">
      <div class="panel">
        <h2>Incoming Failures</h2>
        <p class="subtitle">
          Newest first. Select a failure to view the raw console log that came in the webhook.
        </p>
        <div class="feed" id="event-list"></div>
      </div>

      <div class="panel" id="detail-panel">
        <div class="empty-state">
          <div>
            <h2>No failure logs yet</h2>
            <p class="subtitle">
              Trigger a failed Jenkins build and the webhook payload log will appear here.
            </p>
          </div>
        </div>
      </div>
    </section>
  </div>

  <script>
    const state = {
      events: [],
      selectedId: null,
      selectedEvent: null,
    };

    async function fetchJson(url, options = {}) {
      const response = await fetch(url, options);
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Request failed with ${response.status}`);
      }
      return response.json();
    }

    function showError(message) {
      const banner = document.getElementById("error-banner");
      if (!message) {
        banner.className = "error-banner";
        banner.textContent = "";
        return;
      }
      banner.className = "error-banner show";
      banner.textContent = message;
    }

    function formatTime(isoString) {
      if (!isoString) {
        return "n/a";
      }

      const date = new Date(isoString);
      if (Number.isNaN(date.getTime())) {
        return isoString;
      }

      return new Intl.DateTimeFormat([], {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(date);
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function formatNumber(value) {
      const numeric = Number(value ?? 0);
      if (!Number.isFinite(numeric)) {
        return "0";
      }
      return numeric.toLocaleString();
    }

    function renderList() {
      const container = document.getElementById("event-list");
      container.innerHTML = "";

      if (!state.events.length) {
        container.innerHTML = `
          <div class="empty-state">
            <div>
              <h3>No payloads captured</h3>
              <p class="subtitle">Run the Jenkins job and let the webhook hit this app.</p>
            </div>
          </div>
        `;
        return;
      }

      for (const event of state.events) {
        const card = document.createElement("button");
        card.className = `event-card${event.event_id === state.selectedId ? " active" : ""}`;
        card.type = "button";
        card.innerHTML = `
          <div class="event-head">
            <div class="event-title">${escapeHtml(event.summary.job_name || event.path)}</div>
            <div class="status-pill">${escapeHtml(event.summary.status || "captured")}</div>
          </div>
          <div class="meta">
            <div><strong>${escapeHtml(formatTime(event.received_at))}</strong></div>
            <div>${escapeHtml(event.summary.repo || "repo not provided")}</div>
            <div>${escapeHtml(event.summary.branch || "branch unknown")} / build ${escapeHtml(event.summary.build_number || "n/a")}</div>
            <div>${escapeHtml(formatNumber(event.console?.line_count))} log lines</div>
          </div>
        `;
        card.addEventListener("click", () => selectEvent(event.event_id));
        container.appendChild(card);
      }
    }

    function renderLinkChip(label, url) {
      if (!url) {
        return "";
      }
      return `
        <a class="link-chip" href="${escapeHtml(url)}" target="_blank" rel="noreferrer">
          ${escapeHtml(label)}
        </a>
      `;
    }

    function renderDetail() {
      const panel = document.getElementById("detail-panel");
      if (!state.selectedEvent) {
        panel.innerHTML = `
          <div class="empty-state">
            <div>
              <h2>No request selected</h2>
              <p class="subtitle">Choose a request from the left to inspect its raw failure log.</p>
            </div>
          </div>
        `;
        return;
      }

      const event = state.selectedEvent;
      const consoleInfo = event.console || {};

      panel.innerHTML = `
        <div class="detail-shell">
          <div class="detail-header">
            <div>
              <h2>${escapeHtml(event.summary.job_name || "Captured failure")}</h2>
              <div class="detail-subtitle">
                Received ${escapeHtml(formatTime(event.received_at))} from ${escapeHtml(event.client || "unknown client")}.
              </div>
            </div>
            <div class="status-tag">${escapeHtml(event.summary.status || "captured")}</div>
          </div>

          <div class="grid">
            <div class="detail-box">
              <div class="detail-label">Repository</div>
              <div class="detail-value">${escapeHtml(event.summary.repo || "not provided")}</div>
            </div>
            <div class="detail-box">
              <div class="detail-label">Branch / Build</div>
              <div class="detail-value">${escapeHtml(event.summary.branch || "unknown")} / ${escapeHtml(event.summary.build_number || "n/a")}</div>
            </div>
            <div class="detail-box">
              <div class="detail-label">Failure Log Size</div>
              <div class="detail-value">${escapeHtml(formatNumber(consoleInfo.line_count))} lines / ${escapeHtml(formatNumber(consoleInfo.char_count))} chars</div>
            </div>
            <div class="detail-box">
              <div class="detail-label">Event ID</div>
              <div class="detail-value">${escapeHtml(event.event_id)}</div>
            </div>
          </div>

          <div class="section-card">
            <div class="section-title">
              <div>
                <h3>Log Access</h3>
                <p>Open the build or pull the raw failure log directly as plain text.</p>
              </div>
            </div>
            <div class="link-row">
              ${renderLinkChip("Open Jenkins Build", event.build_url)}
              ${renderLinkChip("Open Raw Failure Log", `/api/events/${encodeURIComponent(event.event_id)}/console.txt`)}
              ${renderLinkChip("Open Latest Failure Log", "/api/events/latest/console.txt")}
            </div>
          </div>

          <div class="section-card">
            <div class="section-title">
              <div>
                <h3>Failure Log</h3>
                <p>The raw console text exactly as it was posted in the webhook payload.</p>
              </div>
            </div>
            <pre>${escapeHtml(consoleInfo.raw_text || "No console_text was provided in the webhook payload.")}</pre>
          </div>

          <div class="grid">
            <div class="detail-box">
              <div class="detail-label">Headers</div>
              <pre>${escapeHtml(JSON.stringify(event.headers, null, 2))}</pre>
            </div>
            <div class="detail-box">
              <div class="detail-label">Payload Preview</div>
              <pre>${escapeHtml(event.pretty_payload)}</pre>
            </div>
          </div>
        </div>
      `;
    }

    async function loadEventDetail(eventId) {
      state.selectedId = eventId;
      renderList();
      state.selectedEvent = await fetchJson(`/api/events/${eventId}`);
      renderDetail();
    }

    async function selectEvent(eventId) {
      showError("");
      try {
        await loadEventDetail(eventId);
      } catch (error) {
        showError(error.message);
      }
    }

    async function refresh(forceDetail = false) {
      showError("");

      try {
        const [health, payload] = await Promise.all([
          fetchJson("/api/v1/health"),
          fetchJson("/api/events?limit=50"),
        ]);

        state.events = payload.events;

        if (!state.selectedId && state.events.length) {
          state.selectedId = state.events[0].event_id;
        }

        if (state.selectedId) {
          const selectedStillExists = state.events.some((event) => event.event_id === state.selectedId);
          if (!selectedStillExists) {
            state.selectedId = state.events[0]?.event_id || null;
            state.selectedEvent = null;
          }
        }

        document.getElementById("health-status").textContent = health.status;
        document.getElementById("event-count").textContent = String(health.event_count);
        document.getElementById("last-refresh").textContent = new Date().toLocaleTimeString();

        renderList();

        const shouldLoadDetail = Boolean(state.selectedId) && (
          forceDetail ||
          !state.selectedEvent ||
          state.selectedEvent.event_id !== state.selectedId
        );

        if (shouldLoadDetail) {
          state.selectedEvent = await fetchJson(`/api/events/${state.selectedId}`);
        }

        if (!state.selectedId) {
          state.selectedEvent = null;
        }

        renderDetail();
      } catch (error) {
        showError(error.message);
      }
    }

    async function clearFeed() {
      showError("");
      try {
        await fetchJson("/api/events", { method: "DELETE" });
        state.events = [];
        state.selectedId = null;
        state.selectedEvent = null;
        await refresh(true);
      } catch (error) {
        showError(error.message);
      }
    }

    document.getElementById("refresh-button").addEventListener("click", () => refresh(true));
    document.getElementById("clear-button").addEventListener("click", clearFeed);

    refresh(true);
    setInterval(() => refresh(false), 4000);
  </script>
</body>
</html>
"""


@app.get("/tester", response_class=HTMLResponse)
def tester_dashboard() -> HTMLResponse:
    return HTMLResponse(TESTER_DASHBOARD_HTML)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    return HTMLResponse(MONITOR_DASHBOARD_HTML)
