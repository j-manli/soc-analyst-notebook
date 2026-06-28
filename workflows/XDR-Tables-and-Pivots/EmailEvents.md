# `EmailEvents`

## What this table is for

Use `EmailEvents` to investigate **email message activity** processed by Microsoft Defender for Office 365.

This table gives you the main email context:

* Who sent the email
* Who received it
* What the subject was
* Whether the email was inbound, outbound, or internal
* Whether it was delivered, blocked, junked, or quarantined
* Whether Microsoft identified it as phishing, malware, spam, or another threat
* Whether SPF, DKIM, or DMARC passed or failed
* Which policy or action affected the email
* Whether similar emails were grouped into the same campaign cluster

Think of `EmailEvents` as the **main email investigation table**.

---

## Use this table when investigating

Use `EmailEvents` when the alert or investigation involves:

* Phishing emails
* Business email compromise, also called BEC
* Impersonation attempts
* Suspicious or user-reported emails
* Spam or bulk email activity
* Email authentication failures such as SPF, DKIM, or DMARC failures
* Email delivery questions
* Mail flow analysis
* Emails that were delivered, junked, blocked, quarantined, or remediated
* Suspicious sender infrastructure
* Malicious emails sent from a potentially compromised internal account
* Coordinated email campaigns
* Email-based initial access attempts

---

## Kickoff KQL query

Use this as your first-pass query for `EmailEvents`.

Fill in whichever alert artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertNetworkMessageId = "";
let alertInternetMessageId = "";
let alertEmailClusterId = "";
let alertSender = "";
let alertRecipient = "";
let alertSenderIP = "";
let alertSubjectKeyword = "";
let alertThreatName = "";

EmailEvents
| where Timestamp >= ago(lookback)
| where isempty(alertNetworkMessageId) or NetworkMessageId == alertNetworkMessageId
| where isempty(alertInternetMessageId) or InternetMessageId == alertInternetMessageId
| where isempty(alertEmailClusterId) or EmailClusterId == alertEmailClusterId
| where isempty(alertSender) or SenderFromAddress =~ alertSender or SenderMailFromAddress =~ alertSender
| where isempty(alertRecipient) or RecipientEmailAddress =~ alertRecipient
| where isempty(alertSenderIP) or SenderIPv4 == alertSenderIP or SenderIPv6 == alertSenderIP
| where isempty(alertSubjectKeyword) or Subject contains alertSubjectKeyword
| where isempty(alertThreatName) or ThreatNames contains alertThreatName
| project-reorder
    Timestamp,
    NetworkMessageId,
    EmailDirection,
    SenderFromAddress,
    SenderMailFromAddress,
    SenderDisplayName,
    SenderIPv4,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    DeliveryLocation,
    LatestDeliveryAction,
    LatestDeliveryLocation,
    ThreatTypes,
    ThreatNames,
    DetectionMethods,
    AuthenticationDetails,
    EmailClusterId,
    AttachmentCount,
    UrlCount,
    EmailAction,
    EmailActionPolicy,
    ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when you need to paste the KQL you used into a Sentinel incident comment.

Prioritize `NetworkMessageId` when available because it usually gives the cleanest match to the exact email. If `NetworkMessageId` is not available, adjust the `where` line to use another alert artifact such as `InternetMessageId`, `EmailClusterId`, `SenderFromAddress`, `RecipientEmailAddress`, `SenderIPv4`, `Subject`, or `ThreatNames`.

```kql
EmailEvents
| where Timestamp >= ago(7d)
| where NetworkMessageId == "<NetworkMessageId>"
| project-reorder Timestamp, NetworkMessageId, EmailDirection, SenderFromAddress, SenderMailFromAddress, SenderDisplayName, SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, LatestDeliveryAction, LatestDeliveryLocation, ThreatTypes, ThreatNames, DetectionMethods, AuthenticationDetails, EmailClusterId, AttachmentCount, UrlCount, EmailAction, EmailActionPolicy, ReportId
| order by Timestamp desc
```

Alternative `where` lines you can swap in depending on the alert artifact:

```kql
| where InternetMessageId == "<InternetMessageId>"
| where EmailClusterId == "<EmailClusterId>"
| where SenderFromAddress =~ "<sender@example.com>"
| where SenderMailFromAddress =~ "<sender@example.com>"
| where RecipientEmailAddress =~ "<user@example.com>"
| where SenderIPv4 == "<sender IP>"
| where Subject contains "<subject keyword>"
| where ThreatNames contains "<threat name>"
```


---

## Do not use this table for

`EmailEvents` gives you the main email metadata and delivery context, but not every detail.

| What you need to investigate                                    | Better table to use       |
| --------------------------------------------------------------- | ------------------------- |
| Attachment names, hashes, file types, or attachment verdicts    | `EmailAttachmentInfo`     |
| URLs inside the email                                           | `EmailUrlInfo`            |
| User clicks, ZAP actions, remediation, or post-delivery changes | `EmailPostDeliveryEvents` |
| Endpoint file, process, registry, logon, or network activity    | `Device*` tables          |
| Cloud app activity                                              | `CloudAppEvents`          |

---

## Questions this table helps answer

Use this table to answer:

* Who sent the email?
* Who received the email?
* What was the subject?
* Was the email inbound, outbound, or internal?
* Was the email delivered, blocked, junked, or quarantined?
* Where did the email end up?
* Was the email later moved or remediated?
* Did Microsoft classify it as phishing, malware, spam, or another threat?
* What detection method identified the threat?
* Did SPF, DKIM, or DMARC pass or fail?
* Was the sender address spoofed?
* Did the sender use a different visible From address and envelope sender?
* Was this email part of a larger campaign?
* Did multiple users receive similar emails?
* Did an internal account send suspicious outbound email?

---

## First fields to check

When starting triage, look at these fields first:

| Field                               | Why it matters                                                                                                                          |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `Timestamp`                         | Shows when the email event was recorded. Useful for building the timeline.                                                              |
| `NetworkMessageId`                  | Unique Microsoft 365 message identifier. Use this to pivot into attachment, URL, and post-delivery tables.                              |
| `InternetMessageId`                 | Public-facing message ID from the sending system. Useful when reviewing headers.                                                        |
| `EmailDirection`                    | Shows whether the email was inbound, outbound, or internal. Important for identifying external attacks or compromised internal senders. |
| `SenderFromAddress`                 | Visible sender address shown to the recipient. Important for phishing and impersonation analysis.                                       |
| `SenderMailFromAddress`             | Envelope sender or return-path address. Compare this with `SenderFromAddress` to spot spoofing.                                         |
| `SenderDisplayName`                 | Display name shown to the recipient. Useful for detecting executive impersonation or brand impersonation.                               |
| `SenderIPv4` / `SenderIPv6`         | Sending mail server IP. Useful for infrastructure tracking.                                                                             |
| `RecipientEmailAddress`             | Shows who received the email after distribution list expansion.                                                                         |
| `Subject`                           | Helps identify phishing lures, campaign themes, and social engineering tactics.                                                         |
| `DeliveryAction`                    | Shows whether the email was delivered, blocked, junked, or replaced.                                                                    |
| `DeliveryLocation`                  | Shows where the email was placed, such as Inbox, Junk, or Quarantine.                                                                   |
| `LatestDeliveryAction`              | Shows the latest known action attempted on the email.                                                                                   |
| `LatestDeliveryLocation`            | Shows the latest known location of the email.                                                                                           |
| `ThreatTypes`                       | Shows the threat category, such as phishing, malware, or spam.                                                                          |
| `ThreatNames`                       | Shows the specific detection name. Useful for campaign tracking.                                                                        |
| `DetectionMethods`                  | Shows how the threat was detected. Useful for understanding detection coverage.                                                         |
| `AuthenticationDetails`             | Shows SPF, DKIM, and DMARC results. Useful for spoofing and impersonation analysis.                                                     |
| `EmailClusterId`                    | Groups similar emails. Useful for campaign investigation.                                                                               |
| `AttachmentCount`                   | Shows how many attachments were included. Pivot to `EmailAttachmentInfo` if greater than zero.                                          |
| `UrlCount`                          | Shows how many URLs were included. Pivot to `EmailUrlInfo` if greater than zero.                                                        |
| `EmailAction` / `EmailActionPolicy` | Shows what action was taken and what policy caused it. Useful for policy effectiveness review.                                          |

---

## Important field groups

### Event identification fields

| Field               | Description                                             |
| ------------------- | ------------------------------------------------------- |
| `Timestamp`         | Date and time the event was recorded.                   |
| `NetworkMessageId`  | Unique identifier for the email in Microsoft 365.       |
| `InternetMessageId` | Public-facing email identifier from the sending system. |
| `ReportId`          | Event identifier for unique event tracking.             |

### Sender fields

| Field                   | Description                                                                               |
| ----------------------- | ----------------------------------------------------------------------------------------- |
| `SenderFromAddress`     | Sender address in the visible From header.                                                |
| `SenderFromDomain`      | Domain from the visible From header.                                                      |
| `SenderMailFromAddress` | Sender address from the MAIL FROM header, also called the envelope sender or return-path. |
| `SenderMailFromDomain`  | Domain from the MAIL FROM header.                                                         |
| `SenderDisplayName`     | Display name shown for the sender.                                                        |
| `SenderObjectId`        | Sender’s Microsoft Entra ID object ID, if available.                                      |
| `SenderIPv4`            | IPv4 address of the last detected sending mail server.                                    |
| `SenderIPv6`            | IPv6 address of the last detected sending mail server.                                    |

### Recipient fields

| Field                   | Description                                                |
| ----------------------- | ---------------------------------------------------------- |
| `RecipientEmailAddress` | Recipient email address after distribution list expansion. |
| `RecipientObjectId`     | Recipient’s Microsoft Entra ID object ID.                  |

### Email content fields

| Field             | Description                                                           |
| ----------------- | --------------------------------------------------------------------- |
| `Subject`         | Email subject line. Useful for identifying lures and phishing themes. |
| `EmailLanguage`   | Detected language of the email content.                               |
| `AttachmentCount` | Number of attachments in the email.                                   |
| `UrlCount`        | Number of embedded URLs in the email.                                 |

### Email flow fields

| Field            | Description                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------------- |
| `EmailDirection` | Direction of the email relative to the organization, such as inbound, outbound, or intra-org. |
| `Connectors`     | Custom mail flow routing instructions.                                                        |
| `EmailClusterId` | Identifier for similar emails grouped by heuristic analysis. Useful for campaign clustering.  |

### Delivery fields

| Field                    | Description                                                        |
| ------------------------ | ------------------------------------------------------------------ |
| `DeliveryAction`         | Delivery action, such as delivered, junked, blocked, or replaced.  |
| `DeliveryLocation`       | Where the email was delivered, such as Inbox, Junk, or Quarantine. |
| `LatestDeliveryAction`   | Latest known action attempted on the email.                        |
| `LatestDeliveryLocation` | Latest known location of the email.                                |

### Threat detection fields

| Field                | Description                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------- |
| `ThreatTypes`        | Threat classification, such as malware, phishing, or spam.                               |
| `ThreatNames`        | Detection name for identified threats.                                                   |
| `DetectionMethods`   | Methods used to detect the threat.                                                       |
| `ConfidenceLevel`    | Spam confidence level or phishing confidence.                                            |
| `BulkComplaintLevel` | Bulk complaint level. Higher values are more likely to represent bulk or spam-like mail. |

### Action and policy fields

| Field                   | Description                                                                    |
| ----------------------- | ------------------------------------------------------------------------------ |
| `EmailAction`           | Final action taken, such as move to junk, delete, or quarantine.               |
| `EmailActionPolicy`     | Policy type that took effect, such as antispam, anti-phishing, or antimalware. |
| `EmailActionPolicyGuid` | Unique identifier for the policy.                                              |
| `OrgLevelAction`        | Action from an organization-level policy.                                      |
| `OrgLevelPolicy`        | Organization-level policy that triggered the action.                           |
| `UserLevelAction`       | Action from a mailbox-level policy.                                            |
| `UserLevelPolicy`       | End-user mailbox policy that triggered the action.                             |

### Authentication fields

| Field                   | Description                                                                                        |
| ----------------------- | -------------------------------------------------------------------------------------------------- |
| `AuthenticationDetails` | SPF, DKIM, and DMARC verdicts. Useful for spoofing, impersonation, and sender validation analysis. |

### Additional context fields

| Field              | Description                                                                                                          |
| ------------------ | -------------------------------------------------------------------------------------------------------------------- |
| `AdditionalFields` | Extra event data in JSON format. Review this when you need more detail that is not captured in the standard columns. |

---

## Common pivots from this table

| Starting point                     | Pivot to                                    | Why                                                                                 |
| ---------------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------- |
| `NetworkMessageId`                 | `EmailAttachmentInfo`                       | Check attachment names, file types, hashes, and attachment threat verdicts.         |
| `NetworkMessageId`                 | `EmailUrlInfo`                              | Check URLs included in the email.                                                   |
| `NetworkMessageId`                 | `EmailPostDeliveryEvents`                   | Check whether the email was moved, deleted, remediated, or affected after delivery. |
| `SenderFromAddress`                | `EmailEvents`                               | Find other emails from the same visible sender.                                     |
| `SenderMailFromAddress`            | `EmailEvents`                               | Find other emails from the same envelope sender.                                    |
| `SenderIPv4` / `SenderIPv6`        | `EmailEvents`                               | Track email infrastructure used by the sender.                                      |
| `RecipientEmailAddress`            | `EmailEvents`                               | Review other suspicious email activity targeting the same user.                     |
| `Subject`                          | `EmailEvents`                               | Find similar lure themes across the organization.                                   |
| `EmailClusterId`                   | `EmailEvents`                               | Identify coordinated or similar emails in the same campaign.                        |
| `ThreatNames`                      | `EmailEvents`                               | Find other emails tied to the same detection or malware family.                     |
| `RecipientEmailAddress`            | `DeviceLogonEvents` / `IdentityLogonEvents` | Check for suspicious sign-ins after the email was delivered.                        |
| `RecipientEmailAddress` + timeline | `DeviceProcessEvents`                       | Check for suspicious execution after a user may have interacted with the email.     |

---

## Simple triage workflow

### 1. Start with the alert artifacts

Identify what the alert gives you:

* `NetworkMessageId`
* `InternetMessageId`
* Sender
* Recipient
* Subject
* Sender IP
* Threat name
* Email cluster ID

Use those values in the kickoff query.

---

### 2. Confirm the email basics

Review:

* `Timestamp`
* `EmailDirection`
* `SenderFromAddress`
* `SenderMailFromAddress`
* `SenderDisplayName`
* `RecipientEmailAddress`
* `Subject`

Ask yourself:

* Who sent the email?
* Who received it?
* Was it inbound, outbound, or internal?
* Does the sender look suspicious?
* Does the subject look like a phishing lure?
* Is there a mismatch between the visible sender and envelope sender?

---

### 3. Check delivery and exposure

Review:

* `DeliveryAction`
* `DeliveryLocation`
* `LatestDeliveryAction`
* `LatestDeliveryLocation`

Ask yourself:

* Was the email delivered to the user?
* Was it blocked?
* Was it sent to Junk?
* Was it quarantined?
* Did the location change after delivery?
* Is the user likely to have been exposed to the email?

This is one of the most important triage steps because a delivered phish usually has higher urgency than a blocked one.

---

### 4. Check threat verdicts and detection details

Review:

* `ThreatTypes`
* `ThreatNames`
* `DetectionMethods`
* `ConfidenceLevel`
* `BulkComplaintLevel`

Ask yourself:

* Was this classified as phishing, malware, spam, or something else?
* Was there a specific detection name?
* How confident was the detection?
* Was this a known detection or a suspicious pattern?
* Did the email look suspicious even if no threat was detected?

---

### 5. Check authentication results

Review:

* `AuthenticationDetails`
* `SenderFromDomain`
* `SenderMailFromDomain`

Ask yourself:

* Did SPF pass or fail?
* Did DKIM pass or fail?
* Did DMARC pass or fail?
* Does the visible From domain match the envelope sender domain?
* Is this likely spoofing or impersonation?

---

### 6. Determine whether attachments or URLs exist

Review:

* `AttachmentCount`
* `UrlCount`

Then pivot:

* If `AttachmentCount` is greater than zero, go to `EmailAttachmentInfo`.
* If `UrlCount` is greater than zero, go to `EmailUrlInfo`.

This helps you move from email-level triage into attachment or URL-specific analysis.

---

### 7. Determine whether this is a campaign

Use these fields to hunt for related emails:

* `EmailClusterId`
* `Subject`
* `SenderFromAddress`
* `SenderMailFromAddress`
* `SenderIPv4`
* `SenderIPv6`
* `ThreatNames`
* Similar timestamps

Ask yourself:

* Did multiple users receive similar emails?
* Are the subject lines the same or similar?
* Did the same sender target multiple users?
* Did the same infrastructure send multiple suspicious emails?
* Is there a shared threat name or detection method?

---

### 8. Check for signs of account compromise

Pay close attention to `EmailDirection`.

If the email is `Outbound` or `Intra-org`, ask:

* Is an internal user sending suspicious emails?
* Did the user recently have suspicious sign-ins?
* Did the user send similar messages to many recipients?
* Is this possible mailbox compromise or internal phishing?

Pivot to identity, sign-in, and endpoint tables if needed.

---

## Common things to watch for

Pay attention to:

* Delivered phishing emails
* Emails delivered to Inbox with a threat verdict
* `SenderFromAddress` and `SenderMailFromAddress` mismatches
* Display-name impersonation of executives, vendors, HR, payroll, IT, or finance
* SPF, DKIM, or DMARC failures
* External senders pretending to be internal users
* Outbound suspicious emails from internal accounts
* Same subject sent to many users
* Same sender IP sending multiple suspicious emails
* Same `EmailClusterId` across many recipients
* High `BulkComplaintLevel`
* Suspicious emails with both attachments and URLs
* Empty threat fields on emails that still look suspicious
* Emails that were initially delivered but later remediated

---

## Beginner mental model

Use `EmailEvents` when your main question is:

**“What happened to this email, who sent it, who received it, was it delivered, and did Microsoft think it was suspicious?”**

Then pivot based on what you need next:

* Need attachment details? Go to `EmailAttachmentInfo`.
* Need URL details? Go to `EmailUrlInfo`.
* Need post-delivery remediation or user-impact details? Go to `EmailPostDeliveryEvents`.
* Need endpoint activity after the email? Go to `Device*` tables.
* Need sign-in or identity activity after the email? Go to identity or logon tables.
