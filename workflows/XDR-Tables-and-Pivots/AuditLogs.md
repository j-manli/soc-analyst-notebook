# `AuditLogs`

## What this table answers

Use `AuditLogs` to answer:

**“What administrative or directory change happened in Entra ID, who or what initiated it, what resource was changed, and did it succeed?”**

This table is for **tenant-level administrative activity**, not sign-in activity.

Important: `InitiatedBy`, `TargetResources`, and `AdditionalDetails` are dynamic fields. For quick triage, use `tostring()` or dot notation to inspect them.

---

## Use this table when

Use `AuditLogs` when investigating:

* User account creation, modification, or deletion
* Group membership changes
* Admin role assignments
* Privileged Identity Management activity
* Application registrations
* OAuth app permission grants
* Service principal creation or credential changes
* Conditional Access policy changes
* Password resets
* MFA changes
* License assignment changes
* Tenant or directory configuration changes
* Suspicious administrative activity
* Administrative actions performed by users, apps, or service principals

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql id="zddp6o"
let lookback = 7d;
let alertActivity = "";
let alertOperationName = "";
let alertResult = "";
let alertInitiatedBy = "";
let alertTarget = "";
let alertOperationType = "";
let alertLoggedByService = "";
let alertCorrelationId = "";
let alertAdditionalDetail = "";

AuditLogs
| where TimeGenerated >= ago(lookback)
| where isempty(alertActivity) or ActivityDisplayName contains alertActivity
| where isempty(alertOperationName) or OperationName contains alertOperationName
| where isempty(alertResult) or Result =~ alertResult or ResultType =~ alertResult
| where isempty(alertInitiatedBy) or Identity contains alertInitiatedBy or tostring(InitiatedBy) contains alertInitiatedBy
| where isempty(alertTarget) or tostring(TargetResources) contains alertTarget
| where isempty(alertOperationType) or AADOperationType =~ alertOperationType
| where isempty(alertLoggedByService) or LoggedByService contains alertLoggedByService
| where isempty(alertCorrelationId) or CorrelationId == alertCorrelationId
| where isempty(alertAdditionalDetail) or tostring(AdditionalDetails) contains alertAdditionalDetail
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend InitiatedByIpAddress = tostring(InitiatedBy.user.ipAddress)
| extend TargetResourcesText = tostring(TargetResources)
| extend AdditionalDetailsText = tostring(AdditionalDetails)
| project-reorder TimeGenerated, ActivityDateTime, ActivityDisplayName, OperationName, AADOperationType, Result, ResultType, ResultReason, Identity, InitiatedByUser, InitiatedByApp, InitiatedByIpAddress, TargetResourcesText, AdditionalDetailsText, LoggedByService, CorrelationId, Id
| order by TimeGenerated desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `ActivityDisplayName` or `OperationName` when investigating a specific administrative action. Use `InitiatedBy`, `TargetResources`, or `CorrelationId` when tracking who performed the change, what was changed, or related activity.

```kql id="varkjq"
AuditLogs
| where TimeGenerated >= ago(7d)
| where ActivityDisplayName contains "<activity name>"
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName), InitiatedByApp = tostring(InitiatedBy.app.displayName), InitiatedByIpAddress = tostring(InitiatedBy.user.ipAddress), TargetResourcesText = tostring(TargetResources), AdditionalDetailsText = tostring(AdditionalDetails)
| project-reorder TimeGenerated, ActivityDisplayName, OperationName, AADOperationType, Result, ResultReason, Identity, InitiatedByUser, InitiatedByApp, InitiatedByIpAddress, TargetResourcesText, AdditionalDetailsText, LoggedByService, CorrelationId
| order by TimeGenerated desc
```

Alternative `where` lines you can swap in:

```kql id="15usmm"
| where OperationName contains "<operation name>"
| where Result =~ "<success/failure>"
| where ResultType =~ "<Success/Failure>"
| where AADOperationType =~ "<Add/Update/Delete/Other>"
| where Identity contains "<actor>"
| where tostring(InitiatedBy) contains "<user, app, or service principal>"
| where tostring(TargetResources) contains "<target user, group, app, role, or policy>"
| where tostring(AdditionalDetails) contains "<detail keyword>"
| where LoggedByService contains "<service name>"
| where CorrelationId == "<CorrelationId>"
```

```kql id="63s42b"
// Purpose: Shows Entra ID audit activity so I can confirm what admin/directory action occurred, who or what initiated it, what resource changed, whether it succeeded, and what related details/correlation ID to pivot from.
```

---

## Key fields

| Field                                | Why it matters                                                                                                                     |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `ActivityDisplayName`                | Friendly name of the action, such as adding a user, updating an app, or adding a group member. Start here for most investigations. |
| `OperationName`                      | Operation identifier. Useful for filtering specific administrative actions.                                                        |
| `Result` / `ResultType`              | Shows whether the operation succeeded, failed, timed out, or had another result.                                                   |
| `InitiatedBy`                        | Dynamic field showing the user, app, or service principal that initiated the activity.                                             |
| `TargetResources`                    | Dynamic field showing what was modified, such as a user, group, app, role, policy, or service principal.                           |
| `Category`                           | Activity category. Usually `AuditLogs`.                                                                                            |
| `ActivityDateTime` / `TimeGenerated` | Shows when the activity occurred. Useful for timeline reconstruction.                                                              |
| `AADOperationType`                   | Categorizes the action as add, update, delete, or other.                                                                           |
| `LoggedByService`                    | Shows which Microsoft service logged the activity, such as Core Directory or Privileged Identity Management.                       |
| `CorrelationId`                      | Groups related operations. Useful for tracking multi-step admin changes.                                                           |
| `ResultReason`                       | Explains why an operation failed or timed out.                                                                                     |
| `AdditionalDetails`                  | Dynamic field with extra context about the activity.                                                                               |

---

## Do not use this table for

| What you need                                                | Use this instead                                     |
| ------------------------------------------------------------ | ---------------------------------------------------- |
| User sign-in attempts and authentication results             | `SigninLogs`                                         |
| Risky sign-in detections                                     | `SigninLogs` risk fields or Identity Protection logs |
| Endpoint process, file, network, registry, or logon activity | `Device*` tables                                     |
| Email threats, delivery, URLs, or attachments                | `Email*` tables                                      |
| Safe Links clicks                                            | `UrlClickEvents`                                     |
| Cloud app user activity after sign-in                        | `CloudAppEvents`                                     |

---

## Pivot next

| Starting point                                 | Pivot to     | Why                                                                      |
| ---------------------------------------------- | ------------ | ------------------------------------------------------------------------ |
| `InitiatedBy` / `Identity`                     | `SigninLogs` | Check whether the actor had suspicious sign-ins before the admin action. |
| `TargetResources`                              | `AuditLogs`  | Review all changes to the same user, group, app, role, or policy.        |
| `CorrelationId`                                | `AuditLogs`  | Group related administrative actions from the same operation flow.       |
| `ActivityDisplayName` / `OperationName`        | `AuditLogs`  | Hunt for the same activity across the tenant.                            |
| App or service principal in `TargetResources`  | `AuditLogs`  | Review app registration, credential, and permission changes.             |
| User in `TargetResources`                      | `SigninLogs` | Check whether the affected user signed in after the change.              |
| Group or role in `TargetResources`             | `AuditLogs`  | Review membership or role assignment history.                            |
| Conditional Access policy in `TargetResources` | `SigninLogs` | Check authentication behavior before and after the policy change.        |
| `InitiatedByIpAddress`                         | `SigninLogs` | Review sign-ins from the same source IP.                                 |

---

## Common activity areas

| Activity area                | What to look for                                                                               |
| ---------------------------- | ---------------------------------------------------------------------------------------------- |
| User management              | User creation, deletion, updates, password resets, account enable/disable actions.             |
| Group management             | Members added or removed from groups, especially privileged or security groups.                |
| Role management              | Admin role assignments, eligible role changes, or PIM activations.                             |
| Application management       | App registration creation, app updates, redirect URI changes, permission grants.               |
| Service principal management | Service principal creation, credential additions, certificate additions, app role assignments. |
| Conditional Access           | Policy creation, update, disablement, deletion, or exclusions added.                           |
| Authentication methods       | MFA method changes, authentication method registration, or security info changes.              |
| Tenant configuration         | Directory settings, domain changes, federation changes, or security defaults changes.          |

---

## Helpful result filters

| Goal                               | KQL filter |                                                                                                              |
| ---------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------ |
| Successful admin actions           | `          | where Result =~ "success" or ResultType =~ "Success"`                                                        |
| Failed admin actions               | `          | where Result =~ "failure" or ResultType =~ "Failure"`                                                        |
| Added objects or assignments       | `          | where AADOperationType =~ "Add"`                                                                             |
| Updated objects or policies        | `          | where AADOperationType =~ "Update"`                                                                          |
| Deleted objects or assignments     | `          | where AADOperationType =~ "Delete"`                                                                          |
| Activity by a specific actor       | `          | where tostring(InitiatedBy) contains "<actor>"`                                                              |
| Changes to a specific target       | `          | where tostring(TargetResources) contains "<target>"`                                                         |
| Related activity by correlation ID | `          | where CorrelationId == "<CorrelationId>"`                                                                    |
| App or service principal activity  | `          | where tostring(TargetResources) has_any ("Application", "ServicePrincipal", "appId")`                        |
| Conditional Access activity        | `          | where ActivityDisplayName contains "conditional access" or tostring(TargetResources) contains "conditional"` |

---

## Quick triage workflow

1. Start with `ActivityDisplayName`, `OperationName`, `InitiatedBy`, `TargetResources`, or `CorrelationId`.
2. Check `Result` and `ResultType` to confirm whether the action succeeded.
3. Review `ActivityDisplayName` and `AADOperationType` to understand what kind of change occurred.
4. Inspect `InitiatedBy` to identify the actor: user, app, or service principal.
5. Inspect `TargetResources` to identify what was changed.
6. Review `AdditionalDetails` for extra change context.
7. Use `CorrelationId` to find related operations.
8. Pivot to `SigninLogs` for the actor’s authentication activity.
9. If an app, service principal, policy, group, or role was changed, search `AuditLogs` for more activity against the same target.
10. Treat privilege, app credential, OAuth consent, and Conditional Access changes as higher priority.

---

## Watch for

* Admin role assignments to unexpected users
* Group membership changes involving privileged groups
* New app registrations created by unusual users
* Service principal credentials or certificates added
* OAuth permission grants or admin consent activity
* Conditional Access policies disabled, deleted, or weakened
* Users excluded from Conditional Access policies
* Password resets performed by unexpected actors
* New users created and quickly assigned privileges
* Bulk user or group modifications
* Guest users added to sensitive groups
* Changes performed by service principals instead of expected admins
* Successful admin changes shortly after suspicious sign-ins
* Repeated failed administrative actions followed by a successful one
* Suspicious `CorrelationId` chains with multiple related changes

---

## Mental model

Use `AuditLogs` when your main question is:

**“What changed in Entra ID, who or what changed it, what object was affected, and was the change suspicious?”**
