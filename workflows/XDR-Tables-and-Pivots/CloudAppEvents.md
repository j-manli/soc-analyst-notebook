# `CloudAppEvents`

## What this table is for

Use `CloudAppEvents` to investigate **user activity, admin activity, file activity, app activity, and security events across cloud applications** connected to Microsoft Defender for Cloud Apps.

This table is useful when you need to understand:

* What a user did in a cloud app
* Which application was involved
* What IP address and location the activity came from
* Whether the activity involved files, folders, users, apps, or configuration objects
* Whether the activity was unusual for that user
* Whether an external user or administrator was involved
* Whether OAuth apps or third-party apps were used
* Whether data may have been downloaded, shared, deleted, or exposed

Think of this as the **cloud app activity and SaaS investigation table**.

---

## Use this table when investigating

Use `CloudAppEvents` when the alert or investigation involves:

* Suspicious activity in cloud apps
* Compromised account activity across SaaS apps
* Insider threat or possible data exfiltration
* Mass file downloads, uploads, deletions, or sharing
* SharePoint or OneDrive file activity
* Teams or collaboration activity
* Mailbox rule creation or suspicious forwarding behavior
* OAuth app abuse or suspicious third-party app access
* Power Automate, Power BI, or Power Platform abuse
* Administrative privilege misuse
* Role changes, policy changes, or tenant configuration changes
* External sharing of sensitive files
* Guest user activity
* Anonymous proxy usage
* Unusual country, city, ISP, or IP activity
* Shadow IT or unsanctioned app usage
* Activity that is uncommon for a specific user

---

## Kickoff KQL query

Use this as your first-pass query for `CloudAppEvents`.

Fill in whichever alert artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertAccount = "";
let alertAccountObjectId = "";
let alertIPAddress = "";
let alertApplication = "";
let alertActionType = "";
let alertObjectName = "";
let alertOAuthAppId = "";
let alertCountryCode = "";

CloudAppEvents
| where Timestamp >= ago(lookback)
| where isempty(alertAccount) or AccountId =~ alertAccount or AccountDisplayName contains alertAccount
| where isempty(alertAccountObjectId) or AccountObjectId == alertAccountObjectId
| where isempty(alertIPAddress) or IPAddress == alertIPAddress
| where isempty(alertApplication) or Application =~ alertApplication
| where isempty(alertActionType) or ActionType =~ alertActionType or ActivityType =~ alertActionType
| where isempty(alertObjectName) or ObjectName contains alertObjectName or tostring(ActivityObjects) contains alertObjectName
| where isempty(alertOAuthAppId) or OAuthAppId == alertOAuthAppId
| where isempty(alertCountryCode) or CountryCode =~ alertCountryCode
| project-reorder
    Timestamp,
    AccountId,
    AccountObjectId,
    AccountDisplayName,
    AccountType,
    Application,
    ActionType,
    ActivityType,
    IPAddress,
    IsAnonymousProxy,
    CountryCode,
    City,
    Isp,
    IPCategory,
    IsExternalUser,
    IsAdminOperation,
    IsImpersonated,
    ObjectName,
    ObjectType,
    ObjectId,
    ActivityObjects,
    OAuthAppId,
    UncommonForUser,
    LastSeenForUser,
    DeviceType,
    OSPlatform,
    UserAgent,
    UserAgentTags,
    AuditSource,
    SessionData,
    ReportId,
    AdditionalFields
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when you need to paste the KQL you used into a Sentinel incident comment.

Prioritize `AccountObjectId` or `AccountId` when investigating a specific user. Use `IPAddress` when the alert is source-IP based. Use `Application` + `ActionType` when investigating a specific cloud behavior, such as file downloads, external sharing, inbox rule creation, or admin changes. Use `OAuthAppId` when investigating third-party app consent or OAuth abuse.

```kql
CloudAppEvents
| where Timestamp >= ago(7d)
| where AccountId =~ "<user@domain.com>"
| project-reorder Timestamp, AccountId, AccountObjectId, AccountDisplayName, AccountType, Application, ActionType, ActivityType, IPAddress, IsAnonymousProxy, CountryCode, City, IsExternalUser, IsAdminOperation, ObjectName, ObjectType, ActivityObjects, OAuthAppId, UncommonForUser, LastSeenForUser, ReportId
| order by Timestamp desc
```

Alternative `where` lines you can swap in depending on the alert artifact:

```kql id="h0qg92"
| where AccountObjectId == "<AccountObjectId>"
| where AccountId =~ "<user@domain.com>"
| where IPAddress == "<IP address>"
| where Application =~ "<Application>"
| where ActionType =~ "<ActionType>"
| where ActivityType =~ "<ActivityType>"
| where ObjectName contains "<file or object name>"
| where tostring(ActivityObjects) contains "<file, folder, user, or object keyword>"
| where OAuthAppId == "<OAuthAppId>"
| where CountryCode =~ "<country code>"
| where IsAnonymousProxy == true
| where IsExternalUser == true
| where IsAdminOperation == true
```

Field priority for this table:

| Priority | Artifact                         | Why                                                                                                             |
| -------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| 1        | `AccountObjectId` / `AccountId`  | Best for investigating activity tied to a specific user or suspected compromised account.                       |
| 2        | `Application`                    | Helps scope activity to SharePoint, OneDrive, Teams, Exchange, Power Automate, Power BI, or another SaaS app.   |
| 3        | `ActionType`                     | Best for behavior-based investigation, such as file download, file share, inbox rule creation, or admin action. |
| 4        | `IPAddress`                      | Useful for suspicious source IPs, proxy use, impossible travel, or infrastructure correlation.                  |
| 5        | `ObjectName` / `ActivityObjects` | Useful when investigating a specific file, folder, user, mailbox rule, app, or resource.                        |
| 6        | `OAuthAppId`                     | Best for OAuth app abuse, suspicious app consent, or third-party application investigation.                     |
| 7        | `CountryCode` / `City`           | Useful for geographic anomalies or impossible travel-style review.                                              |

---

## Do not use this table for

`CloudAppEvents` is for cloud app activity. It is not always the best table for email delivery, endpoint activity, or raw sign-in telemetry.

| What you need to investigate                                      | Better table to use              |
| ----------------------------------------------------------------- | -------------------------------- |
| Email delivery, routing, sender, recipient, subject, or mail flow | `EmailEvents`                    |
| Email attachment hashes, names, or verdicts                       | `EmailAttachmentInfo`            |
| URLs inside emails                                                | `EmailUrlInfo`                   |
| Post-delivery email remediation or ZAP                            | `EmailPostDeliveryEvents`        |
| Endpoint file activity                                            | `DeviceFileEvents`               |
| Endpoint network connections                                      | `DeviceNetworkEvents`            |
| Endpoint logons                                                   | `DeviceLogonEvents`              |
| Cloud app sign-in events and authentication details               | `SignInLogs`                     |
| Identity-focused suspicious logons                                | Identity or Entra sign-in tables |

---

## Questions this table helps answer

Use this table to answer:

* What did the user do in the cloud app?
* Which cloud app was involved?
* Was the activity performed by a regular user, admin, external user, or application?
* Did the activity come from a suspicious IP address?
* Was the IP associated with an anonymous proxy?
* What country, city, or ISP did the activity come from?
* Was the behavior uncommon for the user?
* What file, folder, object, or user was affected?
* Did the user download, upload, delete, share, or modify data?
* Did an admin make suspicious changes?
* Was a third-party OAuth app involved?
* Was the action part of possible exfiltration, persistence, or privilege misuse?
* Did activity occur across multiple cloud apps?

---

## First fields to check

When starting triage, look at these fields first:

| Field                  | Why it matters                                                                                              |
| ---------------------- | ----------------------------------------------------------------------------------------------------------- |
| `Timestamp`            | Shows when the cloud activity occurred. Useful for timeline building.                                       |
| `AccountId`            | Account identifier. Often useful for tracking activity by user.                                             |
| `AccountObjectId`      | Microsoft Entra ID object ID. Stronger than display name or UPN when available.                             |
| `AccountDisplayName`   | Human-readable user display name. Useful for quick review.                                                  |
| `AccountType`          | Shows whether the account is regular, system, admin, or application.                                        |
| `Application`          | Shows which cloud app was involved, such as SharePoint, Teams, Exchange, or OneDrive.                       |
| `ActionType`           | Shows the specific activity performed. This is one of the most important fields in the table.               |
| `ActivityType`         | Another activity descriptor that may provide useful context.                                                |
| `IPAddress`            | Source IP address. Useful for suspicious access or infrastructure review.                                   |
| `IsAnonymousProxy`     | Quickly identifies known anonymous proxy usage.                                                             |
| `CountryCode` / `City` | Shows geolocation for the source IP. Useful for unusual location review.                                    |
| `Isp`                  | ISP associated with the source IP. Useful for identifying hosting providers, VPNs, or residential networks. |
| `IPCategory`           | Categorizes the IP address, such as corporate, administrative, or residential.                              |
| `IsExternalUser`       | Shows whether the user is external to the organization.                                                     |
| `IsAdminOperation`     | Shows whether the activity was administrative.                                                              |
| `IsImpersonated`       | Shows whether activity was performed by one user on behalf of another.                                      |
| `ObjectName`           | Shows the affected object, such as a file, folder, user, rule, or setting.                                  |
| `ObjectType`           | Shows the type of object affected.                                                                          |
| `ActivityObjects`      | Lists files, folders, users, or other objects involved in the event.                                        |
| `OAuthAppId`           | Identifies OAuth applications involved in the activity.                                                     |
| `UncommonForUser`      | Shows attributes that are unusual for this user. Useful for anomaly detection.                              |
| `LastSeenForUser`      | Shows how recently specific attributes were last seen for the user. Useful for baseline comparison.         |

---

## Important field groups

### Event identification fields

| Field          | Description                                                              |
| -------------- | ------------------------------------------------------------------------ |
| `Timestamp`    | Date and time the event was recorded.                                    |
| `ReportId`     | Unique identifier for the event.                                         |
| `ActionType`   | Type of activity that triggered the event.                               |
| `ActivityType` | Type of activity that triggered the event. May differ from `ActionType`. |

### Application context fields

| Field           | Description                                                                                                                 |
| --------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `Application`   | Application where the recorded action occurred, such as SharePoint, Teams, Exchange, OneDrive, Power Automate, or Power BI. |
| `ApplicationId` | Unique identifier for the application.                                                                                      |
| `AppInstanceId` | Unique identifier for the instance of an application.                                                                       |

### Account fields

| Field                | Description                                                                                                |
| -------------------- | ---------------------------------------------------------------------------------------------------------- |
| `AccountObjectId`    | Unique identifier for the account in Microsoft Entra ID.                                                   |
| `AccountId`          | Account identifier as found by Defender for Cloud Apps. This may be an Entra ID, UPN, or other identifier. |
| `AccountDisplayName` | Display name for the account user.                                                                         |
| `AccountType`        | Type of account, such as regular, system, admin, or application.                                           |
| `IsExternalUser`     | Indicates whether the user is outside the organization’s domain.                                           |
| `IsAdminOperation`   | Indicates whether the activity was performed by an administrator.                                          |
| `IsImpersonated`     | Indicates whether activity was performed by one user on behalf of another user.                            |

### Network and location fields

| Field              | Description                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------------------ |
| `IPAddress`        | IP address assigned to the device during communication.                                          |
| `IsAnonymousProxy` | Indicates whether the IP belongs to a known anonymous proxy.                                     |
| `CountryCode`      | Two-letter country code for the geolocated client IP.                                            |
| `City`             | City associated with the geolocated client IP.                                                   |
| `Isp`              | Internet service provider associated with the IP address.                                        |
| `IPCategory`       | Additional classification for the IP address, such as corporate, administrative, or residential. |
| `IPTags`           | Customer-defined tags applied to specific IP addresses or ranges.                                |

### Device and client fields

| Field           | Description                                                                                                 |
| --------------- | ----------------------------------------------------------------------------------------------------------- |
| `DeviceType`    | Type of device, such as workstation, server, mobile, or network device.                                     |
| `OSPlatform`    | Operating system platform and version details.                                                              |
| `UserAgent`     | User agent from the browser or client application.                                                          |
| `UserAgentTags` | Defender for Cloud Apps tags, such as native client, outdated browser, outdated operating system, or robot. |

### Activity detail fields

| Field             | Description                                                                       |
| ----------------- | --------------------------------------------------------------------------------- |
| `ActivityObjects` | List of objects involved in the activity, such as files, folders, users, or apps. |
| `ObjectName`      | Name of the object the action was applied to.                                     |
| `ObjectType`      | Type of object, such as file, folder, user, app, or configuration object.         |
| `ObjectId`        | Unique identifier of the object the action was applied to.                        |

### OAuth and application fields

| Field        | Description                                                                                                           |
| ------------ | --------------------------------------------------------------------------------------------------------------------- |
| `OAuthAppId` | Unique identifier for OAuth 2.0 registered applications in Microsoft Entra ID. Useful for OAuth abuse investigations. |

### Anomaly detection fields

| Field             | Description                                                                                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UncommonForUser` | Lists attributes in the event that are uncommon for the user. Useful for anomaly detection.                                                                                     |
| `LastSeenForUser` | Number of days since the attribute was last seen for the user. `0` means today, a negative value can indicate first time seen, and a positive value shows days since last seen. |

### Audit and session fields

| Field         | Description                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------------- |
| `AuditSource` | Audit data source, such as Defender for Cloud Apps access control, session control, or app connector. |
| `SessionData` | Defender for Cloud Apps session ID for access or session control.                                     |

### Raw and additional data fields

| Field              | Description                                                       |
| ------------------ | ----------------------------------------------------------------- |
| `RawEventData`     | Raw event information from the source application in JSON format. |
| `AdditionalFields` | Additional information about the entity or event.                 |

---

## Common pivots from this table

| Starting point                  | Pivot to                  | Why                                                                                                      |
| ------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------- |
| `AccountId` / `AccountObjectId` | `CloudAppEvents`          | Review all cloud activity by the same account.                                                           |
| `AccountId` / `AccountObjectId` | `SignInLogs`              | Review sign-in activity, MFA results, conditional access, location, and authentication details.          |
| `IPAddress`                     | `CloudAppEvents`          | Find other cloud app activity from the same IP.                                                          |
| `IPAddress`                     | `SignInLogs`              | Check whether the same IP was used for suspicious authentication.                                        |
| `Application`                   | `CloudAppEvents`          | Scope activity to a specific SaaS app, such as SharePoint, OneDrive, Teams, Exchange, or Power Automate. |
| `ActionType`                    | `CloudAppEvents`          | Hunt for similar behavior, such as mass downloads, sharing, inbox rule creation, or admin changes.       |
| `ObjectName` / `ObjectId`       | `CloudAppEvents`          | Track activity involving a specific file, folder, user, app, rule, or configuration object.              |
| `OAuthAppId`                    | `CloudAppEvents`          | Investigate activity tied to a suspicious OAuth app.                                                     |
| `AccountId`                     | `EmailEvents`             | Check whether the same user sent or received suspicious emails.                                          |
| `AccountId`                     | `EmailPostDeliveryEvents` | Check whether emails tied to the user were remediated after delivery.                                    |
| `AccountId`                     | `DeviceLogonEvents`       | Check endpoint logons for the same user.                                                                 |
| `AccountId`                     | `DeviceProcessEvents`     | Review endpoint process activity if compromise is suspected.                                             |
| `ObjectName`                    | `DeviceFileEvents`        | Check whether a cloud file also appeared on an endpoint, if applicable.                                  |

---

## Simple triage workflow

### 1. Start with the alert artifacts

Identify what the alert gives you:

* User account
* Account object ID
* Application
* Action type
* Source IP
* Country or location
* Object name
* OAuth app ID
* Whether the activity was admin, external, or anonymous proxy related

Use those values in the kickoff query.

---

### 2. Identify the account and application

Review:

* `AccountId`
* `AccountObjectId`
* `AccountDisplayName`
* `AccountType`
* `Application`

Ask yourself:

* Which user or account performed the activity?
* Was this a regular user, admin, system account, or application?
* Which cloud app was involved?
* Is this app expected for the user’s role?

---

### 3. Understand the action

Review:

* `ActionType`
* `ActivityType`
* `ObjectName`
* `ObjectType`
* `ActivityObjects`

Ask yourself:

* What exactly did the user or app do?
* Was a file downloaded, uploaded, deleted, shared, or modified?
* Was an inbox rule created?
* Was a permission or role changed?
* Was a Power Automate flow or connector involved?
* What object was affected?

This is the core of the investigation: **user + app + action + object**.

---

### 4. Check source IP and location context

Review:

* `IPAddress`
* `IsAnonymousProxy`
* `CountryCode`
* `City`
* `Isp`
* `IPCategory`
* `IPTags`

Ask yourself:

* Is the IP expected for this user?
* Is the IP a known anonymous proxy?
* Is the country or city unusual?
* Is the ISP suspicious, residential, hosting, VPN, or corporate?
* Does this activity line up with normal user behavior?

Pivot to sign-in logs if authentication context is needed.

---

### 5. Check user and privilege context

Review:

* `IsExternalUser`
* `IsAdminOperation`
* `IsImpersonated`
* `AccountType`

Ask yourself:

* Was this done by an external or guest user?
* Was this an administrative action?
* Was another user impersonated?
* Should this account have permission to perform this action?

Admin activity, external user activity, and impersonated activity usually deserve closer review.

---

### 6. Look for anomaly indicators

Review:

* `UncommonForUser`
* `LastSeenForUser`
* `UserAgent`
* `UserAgentTags`
* `DeviceType`
* `OSPlatform`

Ask yourself:

* Is this action uncommon for the user?
* Is the IP, country, app, or user agent new for this user?
* Is the browser or operating system unusual or outdated?
* Does the user agent look automated or scripted?

These fields can help separate normal activity from suspicious behavior.

---

### 7. Determine whether the activity suggests compromise or exfiltration

For possible compromised account activity, look for:

* New or unusual IPs
* Anonymous proxy use
* Unusual countries
* Uncommon user agent
* Suspicious inbox rules
* OAuth app activity
* Large file downloads
* External sharing
* Admin actions the user does not normally perform

For possible insider threat or exfiltration, look for:

* Mass downloads
* File sharing to external users
* Public link creation
* Sensitive file access
* File deletions
* OneDrive sync activity
* Activity outside normal working hours
* Activity before termination or role change

---

### 8. Pivot based on what you find

If you see suspicious cloud activity:

* Pivot to `SignInLogs` for authentication details.
* Pivot to more `CloudAppEvents` for surrounding activity by the same user.
* Pivot to `EmailEvents` if mailbox compromise or phishing is suspected.
* Pivot to `DeviceLogonEvents` and `DeviceProcessEvents` if endpoint compromise is suspected.
* Pivot on `IPAddress` to find other users using the same suspicious source.
* Pivot on `OAuthAppId` if a third-party app may be malicious.
* Pivot on `ObjectName` or `ObjectId` to track file or resource access.

---

## Common things to watch for

Pay attention to:

* `IsAnonymousProxy == true`
* Unusual countries or cities for the user
* New or uncommon IP addresses
* `UncommonForUser` showing unusual app, IP, location, or user agent
* Admin actions by accounts that should not be performing admin activity
* External users accessing sensitive data
* Mass file downloads
* External sharing or public link creation
* File deletions after downloads
* Suspicious inbox rule creation
* Email forwarding behavior
* OAuth app activity with broad permissions
* Power Automate flows that move, forward, export, or delete data
* User agents marked as robot, outdated browser, or unusual client
* Activity from guest users in Teams, SharePoint, or OneDrive
* Activity across multiple apps in a short time window
* Cloud activity shortly after suspicious sign-ins

---

## Apps and services covered

`CloudAppEvents` can include activity from Microsoft cloud services and connected SaaS applications, depending on what is integrated with Microsoft Defender for Cloud Apps.

Common Microsoft services include:

* Exchange Online
* SharePoint Online
* OneDrive for Business
* Microsoft Teams
* Dynamics 365
* Skype for Business
* Viva Engage
* Power Automate
* Power BI
* Microsoft Forms
* Microsoft Planner

Common third-party SaaS apps may include:

* Dropbox
* Salesforce
* Box
* GitHub
* Atlassian apps such as Jira and Confluence
* Google Workspace
* Slack
* Zoom
* ServiceNow

Defender for Cloud Apps can also provide visibility into many other discoverable cloud apps, depending on tenant configuration and connected data sources.

---

## Beginner mental model

Use `CloudAppEvents` when your main question is:

**“What did this user or app do inside a cloud application, from where, to what object, and was it unusual or risky?”**

Then pivot based on what you need next:

* Need sign-in and authentication details? Go to `SignInLogs`.
* Need more activity by the same user? Stay in `CloudAppEvents`.
* Need email context? Go to `EmailEvents`.
* Need mailbox remediation context? Go to `EmailPostDeliveryEvents`.
* Need endpoint activity? Go to `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, or other `Device*` tables.
* Need OAuth app investigation? Pivot on `OAuthAppId`.
* Need data access or exfiltration scope? Pivot on `AccountId`, `Application`, `ActionType`, `ObjectName`, and `ActivityObjects`.
