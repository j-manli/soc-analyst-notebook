# `OfficeActivity`

## What this table answers

Use `OfficeActivity` to answer:

**“What did this user, admin, app, or service do inside Microsoft 365, against what object, from where, and in which workload?”**

This table is useful for Microsoft 365 audit activity across workloads such as Exchange, SharePoint, OneDrive, Teams, and other Office 365 services.

Important: `OfficeActivity` is broad. The most useful fields can change depending on the workload and operation.

---

## Use this table when

Use `OfficeActivity` when investigating:

* SharePoint or OneDrive file access
* File downloads, uploads, deletes, moves, or sharing activity
* External sharing activity
* Exchange mailbox activity
* Mailbox permission changes
* Inbox rule changes
* SendAs or SendOnBehalf activity
* Teams activity
* Microsoft 365 admin or user activity
* Suspicious access to sensitive files
* Suspicious activity after a successful cloud sign-in
* Data exfiltration from Microsoft 365
* Unusual user activity across Office workloads
* Activity from suspicious IP addresses
* Activity involving guests or external users

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql id="s5mx6r"
let lookback = 7d;
let alertUser = "";
let alertClientIP = "";
let alertWorkload = "";
let alertOperation = "";
let alertObjectId = "";
let alertFileName = "";
let alertSiteUrl = "";
let alertMailboxOwner = "";
let alertUserSharedWith = "";
let alertTargetUserOrGroup = "";
let alertRecordType = "";

OfficeActivity
| where TimeGenerated >= ago(lookback)
| where isempty(alertUser) or UserId =~ alertUser or Actor =~ alertUser or LogonUserDisplayName contains alertUser
| where isempty(alertClientIP) or ClientIP == alertClientIP or Client_IPAddress == alertClientIP or ActorIpAddress == alertClientIP
| where isempty(alertWorkload) or OfficeWorkload =~ alertWorkload
| where isempty(alertOperation) or Operation contains alertOperation or Activity contains alertOperation
| where isempty(alertObjectId) or OfficeObjectId contains alertObjectId or Item contains alertObjectId
| where isempty(alertFileName) or SourceFileName contains alertFileName or DestinationFileName contains alertFileName or ItemName contains alertFileName
| where isempty(alertSiteUrl) or Site_Url contains alertSiteUrl
| where isempty(alertMailboxOwner) or MailboxOwnerUPN =~ alertMailboxOwner
| where isempty(alertUserSharedWith) or UserSharedWith =~ alertUserSharedWith
| where isempty(alertTargetUserOrGroup) or TargetUserOrGroupName contains alertTargetUserOrGroup
| where isempty(alertRecordType) or RecordType contains alertRecordType
| project-reorder TimeGenerated, UserId, Operation, Activity, OfficeWorkload, ResultStatus, ClientIP, Client_IPAddress, ActorIpAddress, UserAgent, OfficeObjectId, SourceFileName, DestinationFileName, Site_Url, SourceRelativeUrl, MailboxOwnerUPN, UserSharedWith, SharingType, TargetUserOrGroupName, Parameters, OperationProperties, RecordType, OfficeId
| order by TimeGenerated desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `UserId` when investigating a specific account. Use `ClientIP` for source infrastructure, `Operation` for the activity type, `OfficeWorkload` for the Microsoft 365 service, and `OfficeObjectId` or `SourceFileName` when investigating a specific file, mailbox item, or object.

```kql id="a6q0xb"
OfficeActivity
| where TimeGenerated >= ago(7d)
| where UserId =~ "<user@domain.com>"
| project-reorder TimeGenerated, UserId, Operation, OfficeWorkload, ResultStatus, ClientIP, OfficeObjectId, SourceFileName, Site_Url, MailboxOwnerUPN, UserSharedWith, SharingType, TargetUserOrGroupName, UserAgent, Parameters
| order by TimeGenerated desc
```

Alternative `where` lines you can swap in:

```kql id="gr6nk9"
| where ClientIP == "<source IP>"
| where Client_IPAddress == "<source IP>"
| where ActorIpAddress == "<source IP>"
| where OfficeWorkload =~ "<Exchange/SharePoint/OneDrive/Teams>"
| where Operation contains "<operation name>"
| where Activity contains "<activity keyword>"
| where OfficeObjectId contains "<object, file, folder, mailbox, or URL>"
| where SourceFileName contains "<file name>"
| where Site_Url contains "<SharePoint or OneDrive site>"
| where MailboxOwnerUPN =~ "<mailbox owner>"
| where UserSharedWith =~ "<external or internal recipient>"
| where TargetUserOrGroupName contains "<target user or group>"
| where RecordType contains "<record type>"
```

```kql id="hiprjl"
// Purpose: Shows Microsoft 365 audit activity so I can confirm the user, workload, operation, source IP, affected object/file/mailbox, sharing target, result, and user-agent context.
```

---

## Key fields  

> OfficeActivity schemas can vary by tenant, workload, and lab environment. Fields like SourceFileName may appear in some environments but not others.
> When in doubt, use OfficeObjectId as the primary object field and run `OfficeActivity | getschema` to confirm available columns.

| Field                                              | Why it matters                                                                                                                  |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `TimeGenerated`                                    | When the Microsoft 365 audit activity occurred. Use this for timeline reconstruction.                                           |
| `UserId`                                           | User who performed the action. Start here for user-focused investigations.                                                      |
| `Operation`                                        | The action performed, such as file access, sharing, mailbox action, Teams action, or admin operation.                           |
| `OfficeWorkload`                                   | Microsoft 365 workload where the activity occurred, such as Exchange, SharePoint, OneDrive, or Teams.                           |
| `ResultStatus`                                     | Whether the action succeeded, failed, or partially succeeded.                                                                   |
| `ClientIP` / `Client_IPAddress` / `ActorIpAddress` | Source IP fields. Field usage can vary by workload, so check all three when needed.                                             |
| `UserAgent`                                        | Browser, client, or app context. Useful for spotting unusual clients or automation.                                             |
| `OfficeObjectId`                                   | Object affected by the action. Often useful for SharePoint/OneDrive files, folders, sites, or Exchange objects.                 |
| `SourceFileName` / `DestinationFileName`           | File name involved in SharePoint or OneDrive file activity.                                                                     |
| `Site_Url`                                         | SharePoint or OneDrive site URL. Useful for scoping file activity.                                                              |
| `MailboxOwnerUPN`                                  | Mailbox owner for Exchange mailbox activity. Useful when someone accesses or acts on another mailbox.                           |
| `UserSharedWith` / `SharingType`                   | Sharing target and sharing method. Important for external sharing or data exposure investigations.                              |
| `TargetUserOrGroupName`                            | User or group affected by an action, often useful in sharing or group-related activity.                                         |
| `Parameters` / `OperationProperties`               | Extra operation details. Useful for Exchange admin cmdlets, mailbox rule changes, policy changes, or workload-specific context. |
| `RecordType`                                       | Audit record category. Helps identify the type/source of audit event.                                                           |
| `OfficeId`                                         | Unique audit record identifier. Useful for precise event tracking.                                                              |

---

## Do not use this table for

| What you need                                                                                   | Use this instead                                     |
| ----------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Entra ID sign-in attempts and MFA/Conditional Access results                                    | `SigninLogs`                                         |
| Entra ID directory changes such as role assignments, app changes, and user/group admin activity | `AuditLogs`                                          |
| Endpoint process, file, network, registry, or logon activity                                    | `Device*` tables                                     |
| Email delivery, sender, recipient, attachments, or URLs                                         | `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` |
| Safe Links clicks                                                                               | `UrlClickEvents`                                     |
| Detailed endpoint file activity                                                                 | `DeviceFileEvents`                                   |
| Live cloud app activity normalized by Defender for Cloud Apps                                   | `CloudAppEvents`                                     |

---

## Pivot next

| Starting point    | Pivot to         | Why                                                                          |
| ----------------- | ---------------- | ---------------------------------------------------------------------------- |
| `UserId`          | `SigninLogs`     | Check whether the user had suspicious sign-ins before the activity.          |
| `UserId`          | `CloudAppEvents` | Review broader cloud app activity by the same user.                          |
| `ClientIP`        | `SigninLogs`     | Find other users signing in from the same IP.                                |
| `ClientIP`        | `OfficeActivity` | Find other Microsoft 365 activity from the same source IP.                   |
| `OfficeObjectId`  | `OfficeActivity` | Review all actions against the same file, mailbox object, site, or resource. |
| `SourceFileName`  | `OfficeActivity` | Track access, download, delete, move, or sharing activity for the same file. |
| `Site_Url`        | `OfficeActivity` | Scope activity to a specific SharePoint or OneDrive site.                    |
| `MailboxOwnerUPN` | `OfficeActivity` | Review mailbox activity against a specific mailbox.                          |
| `UserSharedWith`  | `OfficeActivity` | Review what else was shared with the same recipient.                         |
| `Operation`       | `OfficeActivity` | Hunt for the same suspicious operation across users or workloads.            |

---

## Common activity areas

| Area                              | What to look for                                                                                                      |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| SharePoint / OneDrive file access | File accessed, downloaded, uploaded, deleted, moved, renamed, synced, or shared.                                      |
| External sharing                  | Files or folders shared with external users, anonymous links, organization-wide links, or guest users.                |
| Exchange mailbox activity         | Mail items accessed, mailbox permissions changed, inbox rules created or modified, messages sent as another user.     |
| Admin activity                    | Exchange admin cmdlets, SharePoint admin changes, policy changes, mailbox changes, or workload configuration changes. |
| Teams activity                    | Team creation, channel activity, member changes, meeting or chat-related audit events.                                |
| Data exposure                     | Bulk file downloads, sensitive file access, external sharing, anonymous links, or unusual access from suspicious IPs. |
| Post-compromise activity          | Mailbox rule creation, email forwarding, mass file download, unusual sharing, or activity after suspicious sign-in.   |

---

## Helpful workload filters

| Goal                    | KQL filter |                                                                                                          |
| ----------------------- | ---------- | -------------------------------------------------------------------------------------------------------- |
| Exchange activity       | `          | where OfficeWorkload =~ "Exchange"`                                                                      |
| SharePoint activity     | `          | where OfficeWorkload =~ "SharePoint"`                                                                    |
| OneDrive activity       | `          | where OfficeWorkload =~ "OneDrive"`                                                                      |
| Teams activity          | `          | where OfficeWorkload =~ "MicrosoftTeams" or OfficeWorkload =~ "Teams"`                                   |
| Activity by user        | `          | where UserId =~ "[user@domain.com](mailto:user@domain.com)"`                                             |
| Activity from IP        | `          | where ClientIP == "<source IP>" or Client_IPAddress == "<source IP>" or ActorIpAddress == "<source IP>"` |
| Activity against object | `          | where OfficeObjectId contains "<object, file, URL, mailbox, or folder>"`                                 |
| Activity involving file | `          | where SourceFileName contains "<file name>" or DestinationFileName contains "<file name>"`               |
| Activity involving site | `          | where Site_Url contains "<site URL or site keyword>"`                                                    |
| Sharing activity        | `          | where Operation contains "Sharing" or isnotempty(UserSharedWith) or isnotempty(SharingType)`             |
| Mailbox activity        | `          | where isnotempty(MailboxOwnerUPN) or OfficeWorkload =~ "Exchange"`                                       |

---

## Quick triage workflow

1. Start with `UserId`, `ClientIP`, `OfficeWorkload`, `Operation`, `OfficeObjectId`, or `SourceFileName`.
2. Check `OfficeWorkload` to understand which Microsoft 365 service generated the event.
3. Review `Operation` to understand what action occurred.
4. Check `ResultStatus` to confirm whether the action succeeded.
5. Review source IP fields: `ClientIP`, `Client_IPAddress`, and `ActorIpAddress`.
6. Review `UserAgent` for browser, client, automation, or suspicious tooling context.
7. For SharePoint/OneDrive, review `OfficeObjectId`, `SourceFileName`, `Site_Url`, and sharing fields.
8. For Exchange, review `MailboxOwnerUPN`, `Parameters`, `OperationProperties`, and send/delegation fields.
9. Pivot to `SigninLogs` to determine whether the user had suspicious authentication before the activity.
10. Pivot back into `OfficeActivity` using the same file, mailbox, site, IP, or operation to scope impact.

---

## Watch for

* Successful activity shortly after suspicious sign-ins
* File downloads from unusual IPs or countries
* Bulk file access or downloads
* Sensitive files accessed by unusual users
* External sharing of sensitive files
* Anonymous or organization-wide sharing links
* Mailbox rule creation after suspicious sign-in
* Forwarding, SendAs, or SendOnBehalf activity
* Mailbox permission changes
* SharePoint or OneDrive activity from unfamiliar user agents
* Admin operations from unexpected users or IPs
* Operations performed by service principals or apps when a user action was expected
* Activity involving guest users or external domains
* Repeated access to many files or sites in a short time
* Failed actions followed by successful actions
* Unusual Teams member or channel changes

---

## Mental model

Use `OfficeActivity` when your main question is:

**“What did this identity do inside Microsoft 365 after authentication, and what file, mailbox, site, team, or object was affected?”**
