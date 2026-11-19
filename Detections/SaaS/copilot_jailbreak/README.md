# Copilot Jailbreak & Cross-Prompt Injection Detection

Microsoft Defender XDR custom detection that alerts on Microsoft 365 Copilot interactions where Microsoft's built-in Copilot safety telemetry flagged a **jailbreak attempt** or a **cross-prompt injection attack (XPIA)**. Only flagged interactions are returned.

**File:** `copilot_jailbreak.kql`

## MITRE ATLAS Mapping

| Technique | Name | How this query covers it |
|---|---|---|
| [AML.T0054](https://atlas.mitre.org/techniques/AML.T0054) | LLM Jailbreak | `JailbreakDetected` on user prompt messages |
| [AML.T0051.000](https://atlas.mitre.org/techniques/AML.T0051.000) | LLM Prompt Injection: Direct | Direct injection attempts in the prompt are surfaced through the same message-level jailbreak flag |
| [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) | LLM Prompt Injection: Indirect | `XPIADetected` on resources Copilot accessed (documents, emails, sites) |

## Data Source & Requirements

- **Table:** `CloudAppEvents` (Defender for Cloud Apps / Microsoft 365 connector)
- **ActionType:** `CopilotInteraction`
- **Prerequisites:** Microsoft 365 Copilot in use, Microsoft Purview audit logging enabled, and the Microsoft 365 app connector in Defender for Cloud Apps so Copilot audit events flow into `CloudAppEvents`.
- **Fields used:** nested properties under `RawEventData.CopilotEventData` (`Messages`, `AccessedResources`, `AISystemPlugin`, `AppHost`, `ConversationId`, `GuardrailDetails`).

If the rule never fires, confirm the events exist first:

```kql
CloudAppEvents
| where ActionType == "CopilotInteraction"
| take 10
```

## What Is Cross-Prompt Injection?

Cross-prompt injection (XPI, or XPIA when Microsoft refers to the attack) is Microsoft's term for what MITRE ATLAS calls **indirect prompt injection**, technique [AML.T0051.001 – LLM Prompt Injection: Indirect](https://atlas.mitre.org/techniques/AML.T0051.001).

In a direct prompt injection or jailbreak, the attacker *is* the user: they type the malicious instructions into the chat. In a cross-prompt injection, the attacker never talks to the model. Instead, they plant instructions inside content the assistant will later read on behalf of a legitimate user, such as:

- a document shared to the victim's OneDrive or a SharePoint site
- an inbound email that Copilot summarizes
- a Teams message, meeting transcript, or calendar invite
- a web page or plugin/connector response

When the victim asks Copilot something ordinary ("summarize my unread email"), Copilot retrieves that content into its context, and the hidden instructions compete with the user's actual request. Typical goals are exfiltrating data the victim can access, steering Copilot into giving the victim false information or malicious links, or triggering actions through plugins. The "cross" refers to the instructions crossing from untrusted data into the prompt.

This is why the query looks for XPIA flags on **accessed resources** rather than on the user's own messages: the user is usually the victim, not the attacker, and the resource URL is the lead for finding the source of the payload.

## How the Detection Works

### 1. Scope to Copilot interactions

```kql
CloudAppEvents
| where ActionType == "CopilotInteraction"
```

Pulls Copilot interaction audit events. The `ActionType` filter is an exact match, so it is cheap and applied early. There is no `Timestamp` filter because the custom detection service sets the lookback window from the rule's run frequency.

### 2. Project and flatten the fields needed

```kql
| project
    Timestamp, Application,
    AppHost = tostring(RawEventData.CopilotEventData.AppHost),
    ...
    Messages = RawEventData.CopilotEventData.Messages,
    ResourceEvents = RawEventData.CopilotEventData.AccessedResources,
    ...
```

Copilot details live in the nested `RawEventData` JSON. This step promotes them to top-level columns: scalar values (host app, user, conversation ID) are cast with `tostring()`, while `Messages` and `AccessedResources` stay as dynamic arrays because they are evaluated in the next step. `AccessedResources` is projected twice: once to keep in the alert for the analyst, and once as `ResourceEvents` for processing. `Timestamp` and `ReportId` are kept because custom detections require them.

### 3. Evaluate messages and resources per interaction (`mv-apply`)

```kql
| mv-apply Msg = Messages, Resource = ResourceEvents on (
    summarize
        JailbreakHits = countif(tobool(Msg.JailbreakDetected) == true),
        JailbreakFlagsReported = countif(isnotnull(Msg.JailbreakDetected)),
        XPIAHits = countif(tobool(Resource.XPIADetected) == true),
        XPIAFlagsReported = countif(isnotnull(Resource.XPIADetected)),
        ResourceURLs = make_set_if(tostring(Resource.SiteUrl), isnotempty(tostring(Resource.SiteUrl)))
)
```

A single interaction can contain several messages and touch several resources. `mv-apply` expands both arrays **within each row**, runs the `summarize` on just that row's elements, and collapses the result back to one row per interaction. This avoids a full `mv-expand` followed by a re-aggregation across the whole table.

When two arrays are given, `mv-apply` expands them side by side (element 1 with element 1, and so on), padding the shorter one with nulls. That is why each `countif` checks only its own column: message counts are unaffected by resource padding and vice versa.

For each interaction it computes:

- **`JailbreakHits`** – messages where Microsoft's classifier set `JailbreakDetected` to true.
- **`JailbreakFlagsReported`** – messages that carried a `JailbreakDetected` value at all (true *or* false).
- **`XPIAHits`** – accessed resources where `XPIADetected` is true.
- **`XPIAFlagsReported`** – accessed resources that carried an `XPIADetected` value at all.
- **`ResourceURLs`** – the distinct, non-empty `SiteUrl` values of accessed resources, which is where an analyst starts looking for an injected payload.

### 4. Keep only flagged interactions

```kql
| where JailbreakHits > 0 or XPIAHits > 0
```

This is the line that turns the query into a detection: any interaction without at least one jailbreak or XPIA hit is dropped. Filtering on the raw counts here, before the `extend` and final `project`, means the remaining steps only run on rows that will become alerts.

### 5. Label each attack type (`Yes` / `No` / `Not reported`)

```kql
| extend
    JailbreakDetected = case(JailbreakHits > 0, "Yes", JailbreakFlagsReported > 0, "No", "Not reported"),
    PromptInjectionDetected = case(XPIAHits > 0, "Yes", XPIAFlagsReported > 0, "No", "Not reported")
```

Every alert has `Yes` in at least one of the two columns. The other column tells the analyst whether the second attack type was also checked:

| Value | Meaning |
|---|---|
| `Yes` | At least one message/resource was flagged by Microsoft's classifier. This is why the alert fired. |
| `No` | The classifier ran and reported a result for this attack type, and nothing was flagged. |
| `Not reported` | No detection result was present in the telemetry for this attack type, so it was not evaluated (or the field wasn't logged). This is a visibility gap, not a clean result. |

For example, an alert with `JailbreakDetected = Yes` and `PromptInjectionDetected = Not reported` means a jailbreak was caught, but there is no evidence either way on whether the resources Copilot read were checked for injection.

### 6. Final output

The last `project` returns the columns below, newest first. The `order by` only affects how results display when the query is run manually in Advanced Hunting; it has no effect on the rule.

## Output Columns

| Column | Description |
|---|---|
| `Timestamp` | Time of the Copilot interaction (required for custom detections) |
| `Application` | Cloud app recorded for the event |
| `AppHost` | Where Copilot was used (e.g., Teams, Word, Outlook, BizChat) |
| `AppIdentity` | Identity of the Copilot app/agent |
| `UserUPN` / `UserDisplayName` | User who interacted with Copilot |
| `IPAddress` | Source IP of the interaction |
| `JailbreakDetected` | `Yes` / `No` / `Not reported` |
| `PromptInjectionDetected` | `Yes` / `No` / `Not reported` (XPIA) |
| `Plugins` | AI system plugins invoked |
| `AccessedResources` | Full array of resources Copilot read |
| `ResourceURLs` | Distinct resource URLs, for pivoting to the payload source |
| `ConversationId` | Groups interactions in the same Copilot conversation |
| `GuardrailDetails` | Additional guardrail/safety details from Copilot telemetry |
| `ReportId` | Event identifier linking the alert back to the raw record (required for custom detections) |

## Deploying as a Custom Detection

In the Defender portal, open **Advanced Hunting**, run the query, then choose **Create detection rule**. Suggested settings:

| Setting | Suggested value |
|---|---|
| Frequency | Every hour (adjust to your alert-handling capacity) |
| Alert title | e.g., `Copilot jailbreak or prompt injection flagged for {{UserUPN}}` |
| Severity | Medium to start; raise after reviewing true-positive rate |
| Category | Initial access or Execution, per your taxonomy |
| Impacted entities | User → `UserUPN` |
| Automated actions | None (alert only) until the rule has a proven low false-positive rate |

`CloudAppEvents` rows do not need `DeviceId`; the user is the impacted entity.

Before enabling, run the query manually over the last 30 days to estimate alert volume and confirm it stays well under the per-run alert cap.

## Triage Guidance

**Jailbreak = Yes.** The user (or someone using their session) tried to override Copilot's safety rules. Review the conversation via `ConversationId`, check whether it was an isolated attempt or repeated, and consider whether the account may be compromised, especially if the `IPAddress` is unusual for the user.

**PromptInjectionDetected = Yes.** Treat the user as a likely victim. Use `ResourceURLs` and `AccessedResources` to identify the document, email, or site holding the payload, find who created or shared it, and check whether the same resource was accessed by other users' Copilot sessions. Review `Plugins` to see whether Copilot could have taken actions as a result.

## Notes & Limitations

- **Detection depends on Microsoft's classifiers.** The query reports Microsoft's verdicts and does not inspect prompt or resource content itself, so novel attacks missed by those classifiers will not alert.
- **Coverage gaps are not alerted on.** Interactions where no jailbreak or XPIA result was reported are filtered out. To measure how much Copilot activity goes unevaluated, run the query without the `where JailbreakHits > 0 or XPIAHits > 0` line as a separate hunting query and look at the share of `Not reported` rows by `AppHost` or plugin.
- **Schema drift.** Field names under `CopilotEventData` come from the Purview audit schema and may change. If the rule goes silent, check the raw event structure.

## References

- MITRE ATLAS – [AML.T0051.001 LLM Prompt Injection: Indirect](https://atlas.mitre.org/techniques/AML.T0051.001)
- MITRE ATLAS – [AML.T0051 LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)
- MITRE ATLAS – [AML.T0054 LLM Jailbreak](https://atlas.mitre.org/techniques/AML.T0054)
