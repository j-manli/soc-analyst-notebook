# `EmailUrlInfo`

## What this table is for

Use `EmailUrlInfo` to investigate **URLs found in emails and email attachments** processed by Microsoft Defender for Office 365.

This table is useful when you need to understand:

* What URLs were found in an email
* What domain or hostname was used
* Where the URL appeared in the message
* Whether the same URL or domain appeared across multiple emails
* Whether a phishing campaign used links, redirects, QR codes, or suspicious domains

Think of this as the **email URL investigation table**.

---

## Use this table when investigating

Use `EmailUrlInfo` when the alert or investigation involves:

* Phishing emails with suspicious links
* Credential harvesting links
* URL-based initial access attempts
* QR code phishing, also called quishing
* Malicious links inside email bodies, subjects, or attachments
* Suspicious domains or lookalike domains
* Typosquatting domains
* URL shorteners or redirector abuse
* Malware download links sent by email
* Business email compromise involving fraudulent payment links
* Campaign tracking using repeated URLs or domains across multiple emails

---

## Kickoff KQL query

Use this as your first-pass query for `EmailUrlInfo`.

Fill in whichever alert artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertNetworkMessageId = "";
let alertUrl = "";
let alertUrlDomain = "";
let alertUrlLocation = "";

EmailUrlInfo
| where Timestamp >= ago(lookback)
| where isempty(alertNetworkMessageId) or NetworkMessageId == alertNetworkMessageId
| where isempty(alertUrl) or Url contains alertUrl
| where isempty(alertUrlDomain) or UrlDomain =~ alertUrlDomain
| where isempty(alertUrlLocation) or UrlLocation =~ alertUrlLocation
| project-reorder
    Timestamp,
    NetworkMessageId,
    Url,
    UrlDomain,
    UrlLocation,
    ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when you need to paste the KQL you used into a Sentinel incident comment.

Prioritize `NetworkMessageId` when available because it ties the URL back to the exact email. If `NetworkMessageId` is not available, adjust the `where` line to use the full URL, URL domain, or URL location.

```kql
EmailUrlInfo
| where Timestamp >= ago(7d)
| where NetworkMessageId == "<NetworkMessageId>"
| project-reorder Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation, ReportId
| order by Timestamp desc
```

Alternative `where` lines you can swap in depending on the alert artifact:

```kql
| where Url contains "<full or partial URL>"
| where UrlDomain =~ "<domain.com>"
| where UrlLocation =~ "<Body>"
| where UrlLocation =~ "<Attachment>"
| where UrlLocation =~ "<QRCode>"
```

Field priority for this table:

| Priority | Artifact           | Why                                                                                           |
| -------- | ------------------ | --------------------------------------------------------------------------------------------- |
| 1        | `NetworkMessageId` | Best for finding URLs tied to the exact email.                                                |
| 2        | `Url`              | Best when the alert gives you a full or partial URL.                                          |
| 3        | `UrlDomain`        | Best for finding all emails containing links to the same domain.                              |
| 4        | `UrlLocation`      | Useful for identifying where the URL appeared, such as body, attachment, subject, or QR code. |

---

## Do not use this table for

`EmailUrlInfo` tells you what URLs were present in an email, but not the full email story or whether a user clicked.

| What you need to investigate                                    | Better table to use            |
| --------------------------------------------------------------- | ------------------------------ |
| Email sender, recipient, subject, delivery action, or mail flow | `EmailEvents`                  |
| Email attachment names, hashes, file types, or verdicts         | `EmailAttachmentInfo`          |
| Post-delivery remediation, ZAP, or email removal                | `EmailPostDeliveryEvents`      |
| User clicks on URLs                                             | `UrlClickEvents`, if available |
| Endpoint network connections to a URL or domain                 | `DeviceNetworkEvents`          |

---

## Questions this table helps answer

Use this table to answer:

* Did the email contain URLs?
* What was the full URL?
* What domain or hostname was used?
* Where did the URL appear in the email?
* Was the URL in the body, subject, attachment, or QR code?
* Did multiple emails contain the same URL?
* Did multiple emails contain the same domain?
* Is this part of a phishing campaign?
* Is the domain suspicious, newly observed, misspelled, or impersonating a trusted brand?
* Should I pivot to click data or endpoint network activity?

---

## First fields to check

When starting triage, look at these fields first:

| Field              | Why it matters                                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `Timestamp`        | Shows when the email URL event was recorded. Useful for timeline and campaign analysis.                                         |
| `NetworkMessageId` | Unique Microsoft 365 email identifier. Use this to pivot to `EmailEvents`, `EmailAttachmentInfo`, or `EmailPostDeliveryEvents`. |
| `Url`              | Full URL found in the email. Useful for IOC matching and threat intelligence lookups.                                           |
| `UrlDomain`        | Domain or hostname from the URL. Useful for domain reputation and campaign hunting.                                             |
| `UrlLocation`      | Shows where the URL appeared, such as subject, body, attachment, or QR code.                                                    |
| `ReportId`         | Event identifier for tracking the specific event.                                                                               |

---

## Important field groups

### Event identification fields

| Field              | Description                                       |
| ------------------ | ------------------------------------------------- |
| `Timestamp`        | Date and time when the event was recorded.        |
| `NetworkMessageId` | Unique identifier for the email in Microsoft 365. |
| `ReportId`         | Event identifier for unique event tracking.       |

### URL information fields

| Field         | Description                                                                               |
| ------------- | ----------------------------------------------------------------------------------------- |
| `Url`         | Full URL found in the email subject, body, attachment, or QR code.                        |
| `UrlDomain`   | Domain name or hostname from the URL.                                                     |
| `UrlLocation` | Part of the email where the URL was found, such as subject, body, attachment, or QR code. |

---

## Common pivots from this table

| Starting point                     | Pivot to                  | Why                                                                                                      |
| ---------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------- |
| `NetworkMessageId`                 | `EmailEvents`             | Get sender, recipient, subject, delivery action, delivery location, authentication, and threat verdicts. |
| `NetworkMessageId`                 | `EmailAttachmentInfo`     | Check whether the same email also had attachments.                                                       |
| `NetworkMessageId`                 | `EmailPostDeliveryEvents` | Check whether the email was remediated after delivery.                                                   |
| `Url`                              | `EmailUrlInfo`            | Find other emails containing the same URL.                                                               |
| `UrlDomain`                        | `EmailUrlInfo`            | Find other emails containing links to the same domain.                                                   |
| `Url` / `UrlDomain`                | `UrlClickEvents`          | Check whether users clicked the link, if click data is available.                                        |
| `UrlDomain`                        | `DeviceNetworkEvents`     | Check whether endpoints connected to the domain.                                                         |
| `NetworkMessageId` → `EmailEvents` | `RecipientEmailAddress`   | Identify users who received the email containing the URL.                                                |

---

## Simple triage workflow

### 1. Start with the alert artifacts

Identify what the alert gives you:

* `NetworkMessageId`
* Full URL
* URL domain
* URL location
* Related email subject or recipient from `EmailEvents`

Use those values in the kickoff query.

---

### 2. Confirm what URLs were present

Review:

* `Url`
* `UrlDomain`
* `UrlLocation`

Ask yourself:

* What exact URL was in the email?
* What domain was used?
* Was the URL in the body, subject, attachment, or QR code?
* Does the URL look like a login page, file download, redirect, or payment link?
* Does the domain impersonate a trusted brand?

---

### 3. Pivot to email context

Use `NetworkMessageId` to pivot to `EmailEvents`.

Review:

* Sender
* Recipient
* Subject
* Delivery action
* Delivery location
* Threat verdicts
* Authentication results
* `AttachmentCount`
* `UrlCount`

Ask yourself:

* Who received the email?
* Was it delivered to the Inbox, Junk, or Quarantine?
* Was the sender suspicious?
* Was this email blocked or did the user have exposure?

---

### 4. Scope the URL campaign

Hunt for related emails using:

* Same `Url`
* Same `UrlDomain`
* Similar timestamps
* Same `NetworkMessageId` group from related email events

Ask yourself:

* Did multiple users receive this URL?
* Did the same domain appear in multiple emails?
* Were different URLs using the same suspicious domain?
* Does this look like a coordinated phishing campaign?

---

### 5. Check for QR code phishing

Review:

* `UrlLocation`

If `UrlLocation` shows `QRCode`, treat it as possible quishing.

Ask yourself:

* Was the URL embedded in a QR code?
* Was the email trying to move the user from corporate email to a mobile device?
* Does the URL lead to credential harvesting or payment fraud?

---

### 6. Check whether users clicked or devices connected

If the URL was delivered to users, pivot to:

* `UrlClickEvents`, if available, to check user clicks
* `DeviceNetworkEvents` to check endpoint connections to the domain
* `CloudAppEvents` or sign-in logs if the URL may have led to account compromise

Ask yourself:

* Did any user click the URL?
* Did any endpoint connect to the domain?
* Did suspicious sign-in activity happen after the email was delivered?
* Is user follow-up or password reset needed?

---

## Common things to watch for

Pay attention to:

* URLs pointing to credential harvesting pages
* Lookalike or typosquatting domains
* URL shorteners
* Redirector URLs
* Links to file-sharing or download sites
* QR code phishing links
* Links hidden in attachments
* Same `UrlDomain` appearing across many emails
* Domains that imitate Microsoft, DocuSign, Adobe, payroll, HR, finance, banks, or shipping companies
* Emails with URLs that were delivered to Inbox
* URLs that were not detected initially but later appear in phishing campaigns
* Multiple recipients receiving the same URL in a short time window

---

## Beginner mental model

Use `EmailUrlInfo` when your main question is:

**“What link was in this email, where was it placed, what domain does it point to, and who else received it?”**

Then pivot based on what you need next:

* Need sender, recipient, subject, and delivery status? Go to `EmailEvents`.
* Need attachment details? Go to `EmailAttachmentInfo`.
* Need remediation details? Go to `EmailPostDeliveryEvents`.
* Need to know whether users clicked? Go to `UrlClickEvents`, if available.
* Need endpoint connections to the domain? Go to `DeviceNetworkEvents`.
