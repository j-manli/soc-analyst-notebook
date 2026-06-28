# `UrlClickEvents`

## What this table is for

Use `UrlClickEvents` to investigate **user clicks on URLs protected by Safe Links** across email, Microsoft Teams, and Office 365 applications.

This table is useful when you need to understand:

* Who clicked a suspicious or malicious link
* What URL was clicked
* Whether Safe Links allowed or blocked the click
* Whether the user clicked through a warning
* What the threat verdict was at click time
* Whether the URL redirected through multiple sites
* Whether the click came from Email, Teams, or Office
* Whether the clicked URL can be tied back to an email message

Think of this as the **user URL-click and Safe Links exposure table**.

---

## Use this table when investigating

Use `UrlClickEvents` when the alert or investigation involves:

* A user clicking a phishing link
* A user clicking a malicious or suspicious URL
* Credential harvesting links
* Safe Links blocks or allows
* Users clicking through security warnings
* URL-based phishing campaigns
* Click-through rates for a campaign
* Suspicious links in email, Teams, or Office documents
* Redirection chains used to evade detection
* URL threats detected at click time
* Possible compromised accounts after a malicious click
* Repeated risky clicking behavior by the same user
* Safe Links policy effectiveness

---

## Kickoff KQL query

Use this as your first-pass query for `UrlClickEvents`.

Fill in whichever alert artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertAccountUpn = "";
let alertNetworkMessageId = "";
let alertUrl = "";
let alertIPAddress = "";
let alertWorkload = "";
let alertActionType = "";
let alertThreatType = "";

UrlClickEvents
| where Timestamp >= ago(lookback)
| where isempty(alertAccountUpn) or AccountUpn =~ alertAccountUpn
| where isempty(alertNetworkMessageId) or NetworkMessageId == alertNetworkMessageId
| where isempty(alertUrl) or Url contains alertUrl or tostring(UrlChain) contains alertUrl
| where isempty(alertIPAddress) or IPAddress == alertIPAddress
| where isempty(alertWorkload) or Workload =~ alertWorkload
| where isempty(alertActionType) or ActionType =~ alertActionType
| where isempty(alertThreatType) or ThreatTypes contains alertThreatType
| project-reorder
    Timestamp,
    AccountUpn,
    Url,
    ActionType,
    IsClickedThrough,
    ThreatTypes,
    DetectionMethods,
    Workload,
    IPAddress,
    NetworkMessageId,
    UrlChain,
    ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when you need to paste the KQL you used into a Sentinel incident comment.

Prioritize `AccountUpn` when investigating whether a specific user clicked a link. Use `NetworkMessageId` when tying the click back to a specific email. Use `Url` or `UrlChain` when investigating a known malicious URL or redirect chain. Use `IPAddress` when the alert is source-IP based.

```kql
UrlClickEvents
| where Timestamp >= ago(7d)
| where AccountUpn =~ "<user@domain.com>"
| project-reorder Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, ThreatTypes, DetectionMethods, Workload, IPAddress, NetworkMessageId, UrlChain, ReportId
| order by Timestamp desc
```

Alternative `where` lines you can swap in depending on the alert artifact:

```kql
| where NetworkMessageId == "<NetworkMessageId>"
| where Url contains "<full or partial URL>"
| where tostring(UrlChain) contains "<domain or redirect keyword>"
| where IPAddress == "<IP address>"
| where Workload =~ "<Email>"
| where Workload =~ "<Teams>"
| where Workload =~ "<Office>"
| where ActionType =~ "<Allowed or Blocked action>"
| where IsClickedThrough == true
| where ThreatTypes contains "<threat type>"
```

Field priority for this table:

| Priority | Artifact           | Why                                                                |
| -------- | ------------------ | ------------------------------------------------------------------ |
| 1        | `AccountUpn`       | Best for confirming whether a specific user clicked a link.        |
| 2        | `Url`              | Best when investigating a known malicious or suspicious URL.       |
| 3        | `NetworkMessageId` | Best for tying the click back to a specific email, when available. |
| 4        | `ActionType`       | Shows whether Safe Links or policy allowed or blocked the click.   |
| 5        | `IsClickedThrough` | Identifies whether the user bypassed a warning.                    |
| 6        | `UrlChain`         | Useful for redirect and evasion analysis.                          |
| 7        | `IPAddress`        | Useful for identifying where the click came from.                  |
| 8        | `Workload`         | Shows whether the click came from Email, Teams, or Office.         |

Important limitation: clicks from Draft and Sent folders may not have a valid `NetworkMessageId`, which can prevent correlation with `EmailEvents`, `EmailUrlInfo`, and other email tables.

---

## Do not use this table for

`UrlClickEvents` tells you about **clicked URLs protected by Safe Links**. It does not show every URL that existed in an email or every web connection from an endpoint.

| What you need to investigate                                    | Better table to use         |
| --------------------------------------------------------------- | --------------------------- |
| URLs present in emails but not clicked                          | `EmailUrlInfo`              |
| Email sender, recipient, subject, delivery action, or mail flow | `EmailEvents`               |
| Email attachments                                               | `EmailAttachmentInfo`       |
| Teams messages without user clicks                              | `MessageEvents`             |
| Endpoint network connections                                    | `DeviceNetworkEvents`       |
| General web browsing not protected by Safe Links                | Not available in this table |

---

## Questions this table helps answer

Use this table to answer:

* Did the user click the link?
* What URL did the user click?
* Was the click allowed or blocked?
* Did the user click through a warning?
* What was the threat verdict at click time?
* Was the URL detected as phishing, malware, or another threat?
* What detection method identified the threat?
* Did the URL redirect through other URLs?
* Did multiple users click the same URL?
* Did the click come from Email, Teams, or Office?
* Can the click be tied back to a specific email?
* What IP address did the click come from?
* Should the user or device be investigated further?

---

## First fields to check

When starting triage, look at these fields first:

| Field              | Why it matters                                                                                                   |
| ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `Timestamp`        | Shows when the user clicked the link. Useful for timeline building and checking what happened after the click.   |
| `AccountUpn`       | Shows which user clicked the link. This is one of the most important fields for exposure analysis.               |
| `Url`              | Full clicked URL. Useful for IOC matching, threat intelligence, and campaign scoping.                            |
| `ActionType`       | Shows whether the click was allowed or blocked by Safe Links or tenant policy.                                   |
| `IsClickedThrough` | Shows whether the user bypassed a warning to continue to the original URL. High-risk behavior.                   |
| `ThreatTypes`      | Shows the threat verdict at click time, such as phishing or malware.                                             |
| `DetectionMethods` | Shows how the threat was detected at click time.                                                                 |
| `Workload`         | Shows where the click came from, such as Email, Teams, or Office.                                                |
| `IPAddress`        | Public IP address of the device used to click the link. Useful for location and compromise review.               |
| `NetworkMessageId` | Email identifier for the message containing the clicked link, when available. Use this to pivot to email tables. |
| `UrlChain`         | Shows URLs in the redirection chain. Useful for redirector and evasion analysis.                                 |
| `ReportId`         | Unique click event identifier. Same value may appear for click and click-through events in the same scenario.    |

---

## Important field groups

### Event identification fields

| Field       | Description                                                                                                                    |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `Timestamp` | Date and time when the user clicked the link.                                                                                  |
| `ReportId`  | Unique identifier for the click event. The same value may be used for the click and click-through events in the same scenario. |

### URL information fields

| Field      | Description                                                 |
| ---------- | ----------------------------------------------------------- |
| `Url`      | Full URL clicked by the user.                               |
| `UrlChain` | URLs in the redirection chain, when redirects are involved. |

### Action and threat fields

| Field              | Description                                                                    |
| ------------------ | ------------------------------------------------------------------------------ |
| `ActionType`       | Shows whether the click was allowed or blocked by Safe Links or tenant policy. |
| `IsClickedThrough` | Shows whether the user clicked through to the original URL despite a warning.  |
| `ThreatTypes`      | Threat verdict at click time, such as malware or phishing.                     |
| `DetectionMethods` | Detection technology or method used to identify the threat at click time.      |

### User and context fields

| Field        | Description                                                       |
| ------------ | ----------------------------------------------------------------- |
| `AccountUpn` | User Principal Name of the account that clicked the link.         |
| `Workload`   | Application source of the click, such as Email, Office, or Teams. |
| `IPAddress`  | Public IP address of the device from which the user clicked.      |

### Email correlation fields

| Field              | Description                                                                                                                        |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `NetworkMessageId` | Unique identifier for the email containing the clicked link, when available. May be missing for clicks from Draft or Sent folders. |

---

## Common pivots from this table

| Starting point     | Pivot to                        | Why                                                                                                      |
| ------------------ | ------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `NetworkMessageId` | `EmailEvents`                   | Get sender, recipient, subject, delivery action, delivery location, authentication, and threat verdicts. |
| `NetworkMessageId` | `EmailUrlInfo`                  | Compare clicked URL with URLs found in the original email.                                               |
| `NetworkMessageId` | `EmailAttachmentInfo`           | Check whether the same email also had attachments.                                                       |
| `NetworkMessageId` | `EmailPostDeliveryEvents`       | Check whether the email was remediated after delivery.                                                   |
| `Url`              | `EmailUrlInfo`                  | Find other emails containing the same URL.                                                               |
| `Url` / `UrlChain` | `UrlClickEvents`                | Find other users who clicked the same URL or redirect chain.                                             |
| `AccountUpn`       | `UrlClickEvents`                | Review other suspicious clicks by the same user.                                                         |
| `AccountUpn`       | `CloudAppEvents`                | Check for suspicious cloud activity after the click.                                                     |
| `AccountUpn`       | `SignInLogs`                    | Check for suspicious sign-ins after the click.                                                           |
| `AccountUpn`       | `DeviceProcessEvents`           | Review endpoint execution after the click, if compromise is suspected.                                   |
| `AccountUpn`       | `DeviceNetworkEvents`           | Check whether the endpoint connected to the clicked domain or related infrastructure.                    |
| `IPAddress`        | `SignInLogs` / `CloudAppEvents` | Check whether the same IP appears in sign-in or cloud app activity.                                      |

---

## Simple triage workflow

### 1. Start with the alert artifacts

Identify what the alert gives you:

* User account
* URL
* URL domain or redirect
* `NetworkMessageId`
* Source IP
* Workload
* Threat type
* Safe Links action

Use those values in the kickoff query.

---

### 2. Confirm who clicked and when

Review:

* `Timestamp`
* `AccountUpn`
* `IPAddress`
* `Workload`

Ask yourself:

* Who clicked the URL?
* When did the click happen?
* Did the click come from Email, Teams, or Office?
* Was the source IP expected for the user?
* Does the timing align with the alert or email delivery?

---

### 3. Review the clicked URL

Review:

* `Url`
* `UrlChain`

Ask yourself:

* What exact URL was clicked?
* Did the click redirect through other URLs?
* Does the domain look suspicious, misspelled, or impersonating a trusted brand?
* Is there a URL shortener, redirector, encoded string, or unusual path?
* Is the final destination different from the original link?

---

### 4. Check Safe Links action and user behavior

Review:

* `ActionType`
* `IsClickedThrough`

Ask yourself:

* Was the click allowed or blocked?
* Did Safe Links stop the user from reaching the destination?
* Did the user click through a warning?
* Was this a policy block, warning, or successful access?
* Does the user need follow-up or awareness coaching?

A blocked click usually means exposure may be lower. An allowed click or click-through may require deeper investigation.

---

### 5. Review threat verdicts at click time

Review:

* `ThreatTypes`
* `DetectionMethods`

Ask yourself:

* Was the URL classified as phishing, malware, or another threat?
* Was the threat identified at click time?
* Did the threat verdict change after initial email delivery?
* Does this suggest a time-of-check/time-of-use issue where the URL became malicious later?

---

### 6. Pivot back to the original email

If `NetworkMessageId` is available, pivot to:

* `EmailEvents`
* `EmailUrlInfo`
* `EmailAttachmentInfo`
* `EmailPostDeliveryEvents`

Ask yourself:

* Who sent the email?
* Who received it?
* Was the email delivered to the Inbox?
* Did other users receive the same link?
* Was the email remediated after delivery?
* Did the email also contain attachments?

Remember: `NetworkMessageId` may not be available for some clicks, especially clicks from Draft or Sent folders.

---

### 7. Scope additional users and campaign activity

Hunt by:

* Same `Url`
* Same `UrlChain`
* Same domain inside the URL
* Same `NetworkMessageId`
* Same `ThreatTypes`
* Similar timestamps

Ask yourself:

* Did multiple users click the same URL?
* Did other users receive but not click the same URL?
* Was this part of a broader phishing campaign?
* Did Safe Links block some users but allow others?
* Are certain users repeatedly clicking risky links?

---

### 8. Check for post-click compromise indicators

If the click was allowed or the user clicked through, pivot to:

* `SignInLogs` for suspicious sign-ins after the click
* `CloudAppEvents` for suspicious cloud activity
* `DeviceNetworkEvents` for connections to related infrastructure
* `DeviceProcessEvents` for suspicious execution
* `DeviceFileEvents` for downloaded files

Ask yourself:

* Did the user authenticate to a suspicious site after the click?
* Did suspicious sign-ins occur after the click?
* Did the endpoint connect to the clicked domain?
* Did any suspicious files download or execute?
* Is account containment or endpoint investigation needed?

---

## Common things to watch for

Pay attention to:

* `IsClickedThrough == true`
* Allowed clicks to phishing or malware URLs
* Blocked clicks with multiple repeat attempts
* Multiple users clicking the same URL
* URL shorteners and redirector chains
* Redirect chains ending on credential harvesting pages
* Clicks from Teams or Office that are not tied to email
* Clicks from unusual IP addresses
* Clicks followed by suspicious sign-ins
* Clicks followed by suspicious cloud activity
* Clicks followed by endpoint network connections or file downloads
* Repeated risky clicking behavior by the same user
* Safe Links blocks that indicate users were targeted but protected
* Clicks where `NetworkMessageId` is missing, limiting email correlation

---

## Beginner mental model

Use `UrlClickEvents` when your main question is:

**“Did a user click the suspicious link, was the click blocked or allowed, and what should I check after the click?”**

Then pivot based on what you need next:

* Need the original email? Go to `EmailEvents` using `NetworkMessageId`, if available.
* Need URLs present in the email? Go to `EmailUrlInfo`.
* Need remediation details? Go to `EmailPostDeliveryEvents`.
* Need other users who clicked? Stay in `UrlClickEvents` and hunt by `Url` or `UrlChain`.
* Need sign-in impact? Go to `SignInLogs`.
* Need cloud account activity after the click? Go to `CloudAppEvents`.
* Need endpoint impact? Go to `DeviceNetworkEvents`, `DeviceProcessEvents`, or `DeviceFileEvents`.
