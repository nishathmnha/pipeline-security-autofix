# System Design Pack

This folder contains implementation-ready design notes for evolving the current webhook-driven non-AI flow into a LangGraph-based vulnerability remediation pipeline.

Documents:

- `current-state-analysis.md`: what the current code already does, what is reusable, and where the real gaps are.
- `proposed-langgraph-design.md`: target architecture, node responsibilities, state model, and integration points.
- `high-level-development-guide.md`: phased build guide for implementing the design without disrupting the current flow.
- `implementation-backlog.md`: concrete work items, acceptance criteria, and recommended order.
- `ULM diagrams/current-and-target-flow.md`: current and target sequence/component diagrams in Mermaid.
- `ULM diagrams/langgraph-state-and-nodes.md`: graph/state diagrams for the proposed four-node pipeline.

Design intent:

- Keep the existing FastAPI webhook entrypoint.
- Reuse the current GitHub fetch/push service patterns where they still fit.
- Replace the current regex-only single-issue analysis path with a structured LangGraph workflow that can parse full Trivy-style outputs and reason about BOM-friendly remediation.
- Add a validation gate before creating and pushing remediation branches.
