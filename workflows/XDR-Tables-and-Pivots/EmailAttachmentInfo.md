# `EmailAttachmentInfo`

## What this table is for

Use `EmailAttachmentInfo` to investigate **attachments sent through email** that were processed by Microsoft Defender for Office 365.

This table is mainly useful when you need to understand:

* What file was attached to an email
* Who sent it
* Who received it
* Whether Microsoft identified it as malicious or suspicious
* Whether the same attachment was sent to multiple users
* Whether a known file hash appeared in email traffic

Think of this as the **email attachment investigation table**.

---

## Use this table when investigating

Use `EmailAttachmentInfo` when the alert or investigation involves:

* Phishing emails with attachments
* Malware or weaponized documents delivered by email
* Email-based initial access attempts
* A suspicious or known-malicious file hash
* Attachment-based phishing campaigns
* Multiple users receiving the same file
* Suspicious attachment types such as `.exe`, `.zip`, `.iso`, `.vbs`, `.hta`, macro-enabled Office files, or scripts
* Business email compromise involving suspicious attachments
* Users or departments repeatedly targeted with attachment-based attacks
* Sender patterns tied to malicious attachments
* Malware families or threat names delivered through email
--- 
## Kickoff KQL query

Use this as your first-pass query for `EmailAttachmentInfo`.

Fill in whichever alert artifact you have and leave the others blank.

```kql id="d4rjpt"
let lookback = 7d;
let alertNetworkMessageId = "";
let alertSHA256 = "";
let alertSender = "";
let alertRecipient = "";
let alertFileName = "";

EmailAttachmentInfo
| where Timestamp >= ago(lookback)
| where isempty(alertNetworkMessageId) or NetworkMessageId == alertNetworkMessageId
| where isempty(alertSHA256) or SHA256 =~ alertSHA256
| where isempty(alertSender) or SenderFromAddress =~ alertSender
| where isempty(alertRecipient) or RecipientEmailAddress =~ alertRecipient
| where isempty(alertFileName) or FileName =~ alertFileName
| project-reorder
    Timestamp,
    NetworkMessageId,
    SenderFromAddress,
    SenderDisplayName,
    RecipientEmailAddress,
    FileName,
    FileType,
    SHA256,
    FileSize,
    ThreatTypes,
    ThreatNames,
    DetectionMethods,
    SenderObjectId,
    RecipientObjectId,
    ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when you need to paste the KQL you used into a Sentinel incident comment.

Prioritize `NetworkMessageId` when available because it ties the attachment back to the exact email message. If `NetworkMessageId` is not available, use `SHA256` next because it can show where the same attachment appeared across multiple emails. If neither is available, adjust the `where` line to use another alert artifact such as `SenderFromAddress`, `RecipientEmailAddress`, or `FileName`.

```kql id="9j9itx"
EmailAttachmentInfo
| where Timestamp >= ago(7d)
| where NetworkMessageId == "<NetworkMessageId>"
| project-reorder Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, FileName, FileType, SHA256, FileSize, ThreatTypes, ThreatNames, DetectionMethods, SenderObjectId, RecipientObjectId, ReportId
| order by Timestamp desc
```

Alternative `where` lines you can swap in depending on the alert artifact:

```kql id="33qvqf"
| where SHA256 =~ "<SHA256>"
| where SenderFromAddress =~ "<sender@example.com>"
| where RecipientEmailAddress =~ "<user@example.com>"
| where FileName =~ "<filename.ext>"
| where FileName contains "<filename keyword>"
| where ThreatNames contains "<threat name>"
```

---

## Do not use this table for

This table only tells you about **email attachments**. For other parts of the investigation, pivot elsewhere.

| What you need to investigate                                           | Better table to use                        |
| ---------------------------------------------------------------------- | ------------------------------------------ |
| Email subject, sender, delivery status, direction, or message metadata | `EmailEvents`                              |
| URLs inside the email                                                  | `EmailUrlInfo`                             |
| User clicks, opens, ZAP, remediation, or post-delivery actions         | `EmailPostDeliveryEvents`                  |
| File activity on an endpoint                                           | `DeviceFileEvents`                         |
| File downloads from the internet                                       | `DeviceNetworkEvents` + `DeviceFileEvents` |
| Process execution after the attachment was opened                      | `DeviceProcessEvents`                      |

---

## Questions this table helps answer

Use this table to answer:

* Was there an attachment?
* What was the attachment called?
* What type of file was it?
* What is the file hash?
* Who sent it?
* Who received it?
* Was it detected as malware, phishing, or another threat type?
* What detection method caught it?
* Did the same attachment go to multiple users?
* Is this part of a larger phishing campaign?
* Are certain users or departments being repeatedly targeted?
* Did this attachment later show up on an endpoint?

---

## First fields to check

When starting triage, look at these fields first:

| Field                   | Why it matters                                                                                                              |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `Timestamp`             | Shows when the email attachment was processed. Useful for timeline building.                                                |
| `NetworkMessageId`      | Unique email identifier. Use this to pivot to `EmailEvents`, `EmailUrlInfo`, or other email tables.                         |
| `SenderFromAddress`     | Shows the sender address visible to the recipient. Useful for sender reputation and phishing analysis.                      |
| `SenderDisplayName`     | Helps identify display-name spoofing or social engineering.                                                                 |
| `RecipientEmailAddress` | Shows who received the attachment. Useful for identifying targeted users.                                                   |
| `FileName`              | Shows the attachment name. Useful for spotting social engineering lures.                                                    |
| `FileType`              | Shows the attachment extension/type. Useful for identifying risky file types.                                               |
| `SHA256`                | File hash. Use this for threat intelligence lookups and hunting across email or endpoint data.                              |
| `FileSize`              | File size in bytes. Very small or unusually large files may indicate evasion or abnormal behavior.                          |
| `ThreatTypes`           | Shows the threat category, such as malware or phishing.                                                                     |
| `ThreatNames`           | Shows the specific detection or malware family name. Useful for campaign tracking.                                          |
| `DetectionMethods`      | Shows how the threat was detected. Helps distinguish between signature, detonation, reputation, or other detection methods. |

---

## Important field groups

### Event identification fields

| Field              | Description                                                                |
| ------------------ | -------------------------------------------------------------------------- |
| `Timestamp`        | Date and time the event was recorded.                                      |
| `NetworkMessageId` | Unique identifier for the email. Use this to correlate with `EmailEvents`. |
| `ReportId`         | Event identifier used for unique event tracking.                           |

### Sender fields

| Field               | Description                                                                                   |
| ------------------- | --------------------------------------------------------------------------------------------- |
| `SenderFromAddress` | Sender email address visible to the recipient.                                                |
| `SenderDisplayName` | Sender display name shown in the email.                                                       |
| `SenderObjectId`    | Sender’s Microsoft Entra ID object ID, if available. Useful for identifying internal senders. |

### Recipient fields

| Field                   | Description                                                                        |
| ----------------------- | ---------------------------------------------------------------------------------- |
| `RecipientEmailAddress` | Recipient email address after distribution list expansion.                         |
| `RecipientObjectId`     | Recipient’s Microsoft Entra ID object ID. Useful for identifying the user account. |

### Attachment fields

| Field      | Description                      |
| ---------- | -------------------------------- |
| `FileName` | Name of the attached file.       |
| `FileType` | File extension or file type.     |
| `SHA256`   | SHA-256 hash of the attachment.  |
| `FileSize` | Size of the attachment in bytes. |

### Threat detection fields

| Field              | Description                                   |
| ------------------ | --------------------------------------------- |
| `ThreatTypes`      | Threat category, such as malware or phishing. |
| `ThreatNames`      | Specific detection name or malware family.    |
| `DetectionMethods` | Methods used to detect the threat.            |

---

## Common pivots from this table

| Starting point          | Pivot to                                   | Why                                                                                                         |
| ----------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `NetworkMessageId`      | `EmailEvents`                              | Get full email metadata such as subject, delivery action, sender IP, direction, and authentication details. |
| `NetworkMessageId`      | `EmailUrlInfo`                             | Check whether the same email also contained suspicious links.                                               |
| `NetworkMessageId`      | `EmailPostDeliveryEvents`                  | Check whether the email was remediated, moved, deleted, or affected after delivery.                         |
| `SHA256`                | `DeviceFileEvents`                         | Check whether the attachment was written, created, renamed, deleted, or observed on an endpoint.            |
| `SHA256`                | `DeviceProcessEvents`                      | Check whether the file executed or caused child processes.                                                  |
| `RecipientEmailAddress` | `EmailEvents`                              | Look for other suspicious emails sent to the same user.                                                     |
| `SenderFromAddress`     | `EmailEvents` / `EmailAttachmentInfo`      | Find other emails or attachments from the same sender.                                                      |
| `ThreatNames`           | `EmailAttachmentInfo`                      | Find other messages tied to the same malware family or detection name.                                      |
| `FileName`              | `EmailAttachmentInfo` / `DeviceFileEvents` | Look for repeated attachment names or evidence of the file on endpoints.                                    |

---

## Simple triage workflow

### 1. Start with the alert details

Identify the attachment-related indicators from the alert:

* Sender
* Recipient
* File name
* File type
* SHA256 hash
* Threat name
* Network message ID

---

### 2. Check the attachment details

In `EmailAttachmentInfo`, review:

* `FileName`
* `FileType`
* `SHA256`
* `FileSize`
* `ThreatTypes`
* `ThreatNames`
* `DetectionMethods`

Ask yourself:

* Is the file type commonly abused?
* Does the file name look like a lure?
* Was it detected as malware or phishing?
* Was the detection based on reputation, malware family, or another method?
* Is the file size unusual?

---

### 3. Identify sender and recipient scope

Review:

* `SenderFromAddress`
* `SenderDisplayName`
* `RecipientEmailAddress`
* `SenderObjectId`
* `RecipientObjectId`

Ask yourself:

* Was the sender internal or external?
* Does the display name appear spoofed?
* How many users received the same attachment?
* Were specific departments or high-value users targeted?
* Has this sender sent other suspicious attachments?

---

### 4. Determine whether this is a campaign

Hunt for related messages using:

* Same `SHA256`
* Same `FileName`
* Same `ThreatNames`
* Same `SenderFromAddress`
* Same `FileType`
* Similar timestamps

Ask yourself:

* Did multiple users receive the same attachment?
* Did the same sender send different malicious files?
* Are the file names similar?
* Are the attachments part of the same phishing wave?

---

### 5. Pivot to email context

Use `NetworkMessageId` to pivot to `EmailEvents`.

Look for:

* Subject
* Sender IP
* Delivery action
* Delivery location
* Email direction
* Authentication results
* Whether the message was delivered, blocked, junked, or remediated

This helps you understand whether the attachment actually reached the user.

---

### 6. Pivot to endpoint activity

Use `SHA256` to pivot to endpoint tables.

Check:

* `DeviceFileEvents` to see whether the file appeared on a device
* `DeviceProcessEvents` to see whether the file executed or launched child processes
* `DeviceNetworkEvents` to see whether related network activity occurred
* `DeviceLogonEvents` if user compromise or lateral movement is suspected

This helps you determine whether the email attachment led to endpoint execution or compromise.

---

## Common things to watch for

Pay attention to:

* Dangerous file types such as `.exe`, `.iso`, `.img`, `.vbs`, `.hta`, `.js`, `.lnk`, `.zip`, `.rar`, and macro-enabled Office files
* File names using urgency or finance themes, such as invoices, payroll, benefits, shipping, resumes, or password notices
* Empty `ThreatTypes` where the file was later found to be malicious
* Same `SHA256` sent to many users
* Same sender targeting multiple users
* Attachments with unusual file sizes
* Display-name spoofing
* External senders using trusted brand names
* Attachments sent shortly before suspicious endpoint activity

---

## Beginner mental model

Use `EmailAttachmentInfo` when your main question is:

**“What attachment came through email, who received it, was it malicious, and where else did it appear?”**

Then pivot based on what you need next:

* Need full email context? Go to `EmailEvents`.
* Need URLs in the message? Go to `EmailUrlInfo`.
* Need post-delivery remediation details? Go to `EmailPostDeliveryEvents`.
* Need to know whether the file touched an endpoint? Go to `DeviceFileEvents`.
* Need to know whether it executed? Go to `DeviceProcessEvents`.
* Need to know whether it caused network traffic? Go to `DeviceNetworkEvents`.
