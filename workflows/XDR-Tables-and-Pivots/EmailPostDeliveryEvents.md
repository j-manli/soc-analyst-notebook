# `EmailPostDeliveryEvents`

## What this table is for

Use `EmailPostDeliveryEvents` to investigate **actions taken on emails after they were already delivered** to a user mailbox.

This table is mainly useful when you need to understand:

* Whether an email was removed after delivery
* Whether Zero-hour Auto Purge, also called ZAP, acted on the email
* Whether an administrator manually remediated the email
* Whether the remediation action succeeded or failed
* Where the email was located when action was taken
* How long a user may have been exposed before the email was removed

Think of this as the **post-delivery remediation and exposure table**.

---

## Use this table when investigating

Use `EmailPostDeliveryEvents` when the alert or investigation involves:

* Zero-hour Auto Purge, or ZAP, activity
* Manual remediation by a security analyst or administrator
* Emails that were initially delivered but later identified as malicious
* Phishing emails that bypassed initial filtering
* Malware emails that were delivered before detection was available
* Post-delivery movement, deletion, quarantine, or purge actions
* Whether remediation succeeded or failed
* How long a malicious email remained in a mailbox
* User exposure before email removal
* Measuring response time between detection and remediation
* Determining whether a security team action removed emails during incident response

---

## Kickoff KQL query

Use this as your first-pass query for `EmailPostDeliveryEvents`.

Fill in whichever alert artifact you have and leave the others blank.

```kql id="v71xsg"
let lookback = 7d;
let alertNetworkMessageId = "";
let alertInternetMessageId = "";
let alertRecipient = "";
let alertActionType = "";
let alertAction = "";
let alertActionTrigger = "";
let alertThreatType = "";

EmailPostDeliveryEvents
| where Timestamp >= ago(lookback)
| where isempty(alertNetworkMessageId) or NetworkMessageId == alertNetworkMessageId
| where isempty(alertInternetMessageId) or InternetMessageId == alertInternetMessageId
| where isempty(alertRecipient) or RecipientEmailAddress =~ alertRecipient
| where isempty(alertActionType) or ActionType =~ alertActionType
| where isempty(alertAction) or Action =~ alertAction
| where isempty(alertActionTrigger) or ActionTrigger =~ alertActionTrigger
| where isempty(alertThreatType) or ThreatTypes contains alertThreatType
| project-reorder
    Timestamp,
    NetworkMessageId,
    InternetMessageId,
    RecipientEmailAddress,
    ActionType,
    Action,
    ActionTrigger,
    ActionResult,
    DeliveryLocation,
    ThreatTypes,
    DetectionMethods,
    ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when you need to paste the KQL you used into a Sentinel incident comment.

Prioritize `NetworkMessageId` when available because it ties the post-delivery action back to the exact email. If `NetworkMessageId` is not available, adjust the `where` line to use another alert artifact such as `InternetMessageId`, `RecipientEmailAddress`, `ActionType`, `ActionTrigger`, or `ThreatTypes`.

```kql id="6z38rw"
EmailPostDeliveryEvents
| where Timestamp >= ago(7d)
| where NetworkMessageId == "<NetworkMessageId>"
| project-reorder Timestamp, NetworkMessageId, InternetMessageId, RecipientEmailAddress, ActionType, Action, ActionTrigger, ActionResult, DeliveryLocation, ThreatTypes, DetectionMethods, ReportId
| order by Timestamp desc
```

Alternative `where` lines you can swap in depending on the alert artifact:

```kql id="v2hu5d"
| where InternetMessageId == "<InternetMessageId>"
| where RecipientEmailAddress =~ "<user@example.com>"
| where ActionType =~ "<ActionType>"
| where ActionTrigger =~ "<ActionTrigger>"
| where Action =~ "<Action>"
| where ThreatTypes contains "<threat type>"
| where DetectionMethods contains "<detection method>"
```

Field priority for this table:

| Priority | Artifact                | Why                                                                            |
| -------- | ----------------------- | ------------------------------------------------------------------------------ |
| 1        | `NetworkMessageId`      | Best for tying the remediation event to the exact email in Microsoft 365.      |
| 2        | `InternetMessageId`     | Useful when working from raw headers or external message identifiers.          |
| 3        | `RecipientEmailAddress` | Useful for checking whether a specific user had emails remediated.             |
| 4        | `ActionType`            | Useful for reviewing ZAP, manual remediation, or other post-delivery activity. |
| 5        | `ActionTrigger`         | Useful for separating automated action from administrator action.              |
| 6        | `ThreatTypes`           | Useful for finding post-delivery actions tied to phishing, malware, or spam.   |

---

## Do not use this table for

`EmailPostDeliveryEvents` tells you what happened **after delivery**. It is not the best table for the original email content or initial delivery decision.

| What you need to investigate                                               | Better table to use            |
| -------------------------------------------------------------------------- | ------------------------------ |
| Original sender, subject, delivery action, delivery location, or mail flow | `EmailEvents`                  |
| Attachment names, hashes, file types, or attachment verdicts               | `EmailAttachmentInfo`          |
| URLs inside the email                                                      | `EmailUrlInfo`                 |
| User clicks on malicious links                                             | `UrlClickEvents`, if available |
| Endpoint activity after email interaction                                  | `Device*` tables               |

---

## Questions this table helps answer

Use this table to answer:

* Was the email acted on after delivery?
* Was the email removed by ZAP?
* Was the email remediated manually by an administrator?
* What action was taken on the email?
* Did the remediation action succeed or fail?
* What triggered the action?
* What threat type was identified after delivery?
* Where was the email located when the action occurred?
* Which users had the email in their mailbox before removal?
* Was the user exposed before the email was removed?
* Did the email bypass initial filtering and get caught later?
* Was remediation part of an automated process or manual incident response?

---

## First fields to check

When starting triage, look at these fields first:

| Field                   | Why it matters                                                                                                                     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `Timestamp`             | Shows when the post-delivery event happened. Compare with the original delivery time from `EmailEvents` to estimate user exposure. |
| `NetworkMessageId`      | Unique Microsoft 365 email identifier. Use this to pivot back to `EmailEvents`, `EmailAttachmentInfo`, or `EmailUrlInfo`.          |
| `InternetMessageId`     | Public-facing email identifier from the sending system. Useful when correlating with headers or other systems.                     |
| `RecipientEmailAddress` | Shows which mailbox was affected. Useful for identifying exposed users.                                                            |
| `ActionType`            | Shows the type of post-delivery activity, such as manual remediation, Phish ZAP, or Malware ZAP.                                   |
| `Action`                | Shows the specific action taken, such as move, delete, quarantine, or purge.                                                       |
| `ActionTrigger`         | Shows what initiated the action, such as ZAP, an administrator, or another mechanism.                                              |
| `ActionResult`          | Shows whether the action succeeded or failed. This is critical for confirming remediation.                                         |
| `DeliveryLocation`      | Shows where the email was located when the action occurred, such as Inbox, Junk, or Quarantine.                                    |
| `ThreatTypes`           | Shows the threat category identified at remediation time, such as phishing, malware, or spam.                                      |
| `DetectionMethods`      | Shows how the threat was identified after delivery. Useful for understanding detection gaps or late detection.                     |

---

## Important field groups

### Event identification fields

| Field               | Description                                              |
| ------------------- | -------------------------------------------------------- |
| `Timestamp`         | Date and time when the post-delivery event was recorded. |
| `NetworkMessageId`  | Unique identifier for the email in Microsoft 365.        |
| `InternetMessageId` | Public-facing email identifier from the sending system.  |
| `ReportId`          | Event identifier for unique event tracking.              |

### Action fields

| Field           | Description                                                                             |
| --------------- | --------------------------------------------------------------------------------------- |
| `Action`        | Specific action taken on the email entity.                                              |
| `ActionType`    | Activity type, such as manual remediation, Phish ZAP, or Malware ZAP.                   |
| `ActionTrigger` | What initiated the action, such as an administrator, ZAP, or another special mechanism. |
| `ActionResult`  | Result of the remediation action. Use this to confirm whether cleanup succeeded.        |

### Email context fields

| Field                   | Description                                                                               |
| ----------------------- | ----------------------------------------------------------------------------------------- |
| `RecipientEmailAddress` | Email address of the recipient after distribution list expansion.                         |
| `DeliveryLocation`      | Where the email was located when the action occurred, such as Inbox, Junk, or Quarantine. |

### Threat information fields

| Field              | Description                                                |
| ------------------ | ---------------------------------------------------------- |
| `ThreatTypes`      | Threat classification, such as malware, phishing, or spam. |
| `DetectionMethods` | Methods used to detect the threat after delivery.          |

---

## Common pivots from this table

| Starting point          | Pivot to                  | Why                                                                                                               |
| ----------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `NetworkMessageId`      | `EmailEvents`             | Review original sender, subject, delivery action, delivery location, email direction, and authentication results. |
| `NetworkMessageId`      | `EmailAttachmentInfo`     | Check whether the remediated email had suspicious attachments.                                                    |
| `NetworkMessageId`      | `EmailUrlInfo`            | Check whether the remediated email had suspicious URLs.                                                           |
| `RecipientEmailAddress` | `EmailEvents`             | Review other suspicious emails sent to the same user.                                                             |
| `RecipientEmailAddress` | `UrlClickEvents`          | Check whether the user clicked links before remediation, if the table is available.                               |
| `RecipientEmailAddress` | `DeviceProcessEvents`     | Check endpoint activity after possible email interaction.                                                         |
| `RecipientEmailAddress` | `DeviceFileEvents`        | Check whether an attachment or payload appeared on the endpoint.                                                  |
| `ActionType`            | `EmailPostDeliveryEvents` | Review other ZAP or manual remediation actions in the same time window.                                           |
| `ThreatTypes`           | `EmailPostDeliveryEvents` | Find similar post-delivery remediation events tied to the same threat category.                                   |

---

## Simple triage workflow

### 1. Start with the alert artifacts

Identify what the alert gives you:

* `NetworkMessageId`
* `InternetMessageId`
* Recipient
* Threat type
* Action type
* Action trigger

Use those values in the kickoff query.

---

### 2. Confirm whether post-delivery action occurred

Review:

* `ActionType`
* `Action`
* `ActionTrigger`
* `ActionResult`

Ask yourself:

* Was this ZAP or manual remediation?
* What action was taken?
* Who or what initiated it?
* Did the remediation succeed or fail?

This is the most important first step because this table is mainly about confirming cleanup.

---

### 3. Identify the affected user and mailbox location

Review:

* `RecipientEmailAddress`
* `DeliveryLocation`

Ask yourself:

* Which user had the email?
* Was the email in the Inbox, Junk, Quarantine, or another location?
* Was the email likely visible to the user before remediation?

---

### 4. Compare delivery time to remediation time

Pivot to `EmailEvents` using `NetworkMessageId`.

Compare:

* `EmailEvents.Timestamp` or original delivery time
* `EmailPostDeliveryEvents.Timestamp`

Ask yourself:

* When was the email originally delivered?
* When was it removed or remediated?
* How long was the user exposed?
* Was the exposure window minutes, hours, or days?

This helps you explain risk and user impact.

---

### 5. Review threat and detection context

Review:

* `ThreatTypes`
* `DetectionMethods`

Ask yourself:

* Was the email later classified as phishing, malware, or spam?
* How was the threat detected after delivery?
* Was this likely an initial detection miss?
* Did the detection improve later due to updated intelligence, ZAP, or manual investigation?

---

### 6. Check whether the user interacted with the email

If the email was delivered before remediation, pivot based on the email contents.

Check:

* `EmailUrlInfo` if the email had URLs
* `EmailAttachmentInfo` if the email had attachments
* `UrlClickEvents` if URL click data is available
* `DeviceFileEvents` if an attachment may have been downloaded or saved
* `DeviceProcessEvents` if an attachment or payload may have executed

Ask yourself:

* Did the user click anything before remediation?
* Did an attachment land on the endpoint?
* Did suspicious execution occur after delivery?
* Is user follow-up or endpoint review needed?

---

### 7. Look for broader remediation activity

Hunt by:

* Same `ActionType`
* Same `ThreatTypes`
* Same time window
* Same `RecipientEmailAddress`
* Related `NetworkMessageId` values from the same campaign

Ask yourself:

* Was this a one-off remediation event?
* Were many users affected?
* Did ZAP remove similar messages across the organization?
* Did manual remediation cover all known recipients?

---

## Common things to watch for

Pay attention to:

* `ActionResult` showing failure or partial failure
* Emails that were delivered to Inbox before remediation
* Long gaps between delivery and post-delivery action
* ZAP actions occurring hours after delivery
* Manual remediation during active phishing campaigns
* Users who had malicious emails before removal
* Phishing or malware emails that bypassed initial filtering
* Multiple remediation actions for the same campaign
* Recipients with related URL clicks or endpoint activity before cleanup
* Emails that were moved but not fully removed
* Threats repeatedly caught after delivery instead of during initial filtering

---

## Beginner mental model

Use `EmailPostDeliveryEvents` when your main question is:

**“Was this email cleaned up after delivery, who or what removed it, did removal succeed, and how long was the user exposed?”**

Then pivot based on what you need next:

* Need original sender, subject, and delivery details? Go to `EmailEvents`.
* Need attachment details? Go to `EmailAttachmentInfo`.
* Need URL details? Go to `EmailUrlInfo`.
* Need to know whether the user clicked? Go to `UrlClickEvents`, if available.
* Need endpoint impact after interaction? Go to `DeviceFileEvents`, `DeviceProcessEvents`, or other `Device*` tables.
