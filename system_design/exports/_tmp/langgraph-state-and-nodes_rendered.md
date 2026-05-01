# LangGraph State And Nodes

## Graph flow

![diagram](./langgraph-state-and-nodes_png\langgraph-state-and-nodes_rendered-1.png)

## State transition view

![diagram](./langgraph-state-and-nodes_png\langgraph-state-and-nodes_rendered-2.png)

## Node I/O contract

![diagram](./langgraph-state-and-nodes_png\langgraph-state-and-nodes_rendered-3.png)

## Recommended state slices by node

### Node 01 writes

- `va_detected`
- `issue_list`
- `issue_summary`
- `general_solutions`
- `scan_targets`

### Node 02 writes

- `repo_files`
- `manifest_context`
- `remediation_candidates`
- `selected_change_plan_draft`

### Node 03 writes

- `validated_change_plan`
- `validation_passed`
- `validation_notes`
- `manual_review_required`

### Node 04 writes

- `branch_name`
- `changed_files`
- `pull_request_url`
- `final_status`
