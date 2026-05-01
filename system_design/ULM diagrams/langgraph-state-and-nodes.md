# LangGraph State And Nodes

## Graph flow

```mermaid
flowchart TD
    Start([Webhook event stored])
    N1[Node01: detect VA and extract all issues]
    N2[Node02: fetch repo files and plan BOM-friendly fixes]
    N3[Node03: validate BOM safety and finalize change plan]
    Decision{Validation passed?}
    N4[Node04: create branch, push files, create PR]
    Review[Manual review required]
    End([Run completed])

    Start --> N1
    N1 --> N2
    N2 --> N3
    N3 --> Decision
    Decision -- Yes --> N4
    Decision -- No --> Review
    N4 --> End
    Review --> End
```

## State transition view

```mermaid
stateDiagram-v2
    [*] --> received
    received --> parsed_issues
    parsed_issues --> manifests_fetched
    manifests_fetched --> plan_drafted
    plan_drafted --> validated
    plan_drafted --> manual_review_required
    validated --> pushed
    validated --> push_failed
    manual_review_required --> [*]
    pushed --> [*]
    push_failed --> [*]
```

## Node I/O contract

```mermaid
flowchart LR
    In[Graph input state]
    N1[Node01]
    N2[Node02]
    N3[Node03]
    N4[Node04]
    Out[Final state]

    In -->|console_text event metadata| N1
    N1 -->|issue_list general_solutions| N2
    N2 -->|repo_files remediation_candidates| N3
    N3 -->|validated_change_plan validation_passed| N4
    N4 -->|branch_name PR URL final_status| Out
```

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
