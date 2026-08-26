# Potential AiTM Phishing / Session Token Theft

## Detection Intent

Investigate potential Adversary-in-the-Middle (AiTM) phishing where an attacker may have proxied a legitimate authentication flow, captured credentials/session tokens, and reused the resulting authenticated session.

---

## Core Decision

> Did the suspicious authentication succeed, and is there evidence that the resulting account/session was subsequently used from an unexpected context or for suspicious activity?

Do **not** attempt to reverse-engineer the entire authentication flow unless required.

### Critical Path

```text
Authentication success
        ↓
Session / context correlation
        ↓
Post-authentication activity
        ↓
Disposition
```

---

# Fast Triage Checklist

## Required

1. Did the suspicious authentication succeed?
2. What IP, location, user agent, device, and `SessionId` were associated with it?
3. Does the same `SessionId` appear in unexpected authentication context?
4. Did suspicious workload/account activity occur afterward?

## Decision-Changing

- New/unusual IP or ASN
- Major geographic change
- Different/unfamiliar user agent
- Different or unregistered device context
- Same `SessionId` associated with materially different context
- Suspicious non-interactive authentication after the event
- Inbox rule or forwarding changes
- Authentication-method changes
- OAuth/application consent
- Unusual SharePoint/OneDrive activity
- Suspicious email activity

## Optional Enrichment

- Full token lifecycle reconstruction
- Extensive 30-day authentication analysis
- Individual token (`UniqueTokenIdentifier`) tracing
- Broad OSINT on every IP/domain
- Every Conditional Access field

Only perform these when they could change the disposition.

---

# Step 1 — Find the Suspicious Authentication

## Question

> Did the authentication associated with the alert succeed?

### Sentinel

```kusto
let user = "user@domain.com";
let alertTime = datetime(2026-01-01 12:00:00);
SigninLogs
| where UserPrincipalName =~ user
| where TimeGenerated between (alertTime-15m .. alertTime+30m)
| project TimeGenerated,
          ResultType,
          ResultDescription,
          IsInteractive,
          IPAddress,
          LocationDetails,
          AppDisplayName,
          ResourceDisplayName,
          UserAgent,
          DeviceDetail,
          AuthenticationRequirement,
          AuthenticationDetails,
          ConditionalAccessStatus,
          SessionId,
          UniqueTokenIdentifier
| order by TimeGenerated asc
```

## Fields That Matter

### `ResultType`

Commonly:

- `0` = successful authentication
- Non-zero = failure or interruption

Also inspect `ResultDescription` and `AuthenticationDetails` when needed.

### `IsInteractive`

- `true` = user actively interacted with authentication
- `false` = silent/background authentication such as token refresh activity

A non-interactive sign-in is **not inherently suspicious**.

### `IPAddress`

Record the source IP associated with the suspicious authentication.

### `LocationDetails`

Use for comparison with surrounding authentication.

Do not treat geography alone as proof of compromise.

VPNs, proxies, mobile carriers, and secure web gateways can change apparent location.

### `UserAgent`

Record it for comparison.

User-agent values can be spoofed, so treat this as supporting context rather than proof.

### `DeviceDetail`

Pay attention to:

- Device ID
- Operating system
- Browser
- Managed/registered status if populated

Missing device information does not automatically indicate compromise.

### `AppDisplayName` / `ResourceDisplayName`

Answers:

> What application or resource was being accessed?

---

# Decision Gate 1

## Authentication Failed

Check briefly for another suspicious successful authentication around the same time.

If there is:

- no suspicious successful authentication
- no suspicious session activity
- no suspicious follow-on activity

the event may represent an unsuccessful phishing attempt.

### Stop Condition

Stop unless another alert or piece of evidence indicates compromise.

---

## Authentication Succeeded

Continue to Step 2.

---

# Step 2 — Understand the MFA Evidence

Inspect:

```text
AuthenticationDetails
```

You are answering:

> Was MFA performed, previously satisfied, or otherwise handled during this authentication?

You may see methods such as:

- Password
- Microsoft Authenticator
- SMS
- FIDO/security key

You may also see:

```text
MFA requirement satisfied by claim in the token
```

## Important

This does **not** mean the token was stolen.

It generally means Entra accepted an existing MFA claim instead of requiring another MFA prompt.

Do **not** use this logic:

```text
No new MFA prompt
=
Token theft
```

That is not reliable.

---

# Step 3 — Record the Suspicious Session

From the suspicious successful authentication, record:

```text
Timestamp:
User:
IPAddress:
Location:
UserAgent:
Device:
SessionId:
UniqueTokenIdentifier:
Application:
```

## `SessionId`

Use `SessionId` first when correlating related authentication activity.

Think of it broadly as:

```text
Root authentication
       ↓
SessionId
       ↓
Subsequent authentication/session activity
```

## `UniqueTokenIdentifier`

This is more granular and can help identify an individual token.

Do not start here unless token-level tracing is decision-changing.

---

# Step 4 — Check Other Interactive Activity From the Same Session

```kusto
let sid = "SESSION-ID";
SigninLogs
| where SessionId == sid
| project TimeGenerated,
          ResultType,
          IsInteractive,
          IPAddress,
          LocationDetails,
          AppDisplayName,
          ResourceDisplayName,
          UserAgent,
          DeviceDetail,
          UniqueTokenIdentifier
| order by TimeGenerated asc
```

## Lower Concern Example

```text
09:10  IP-A  Hawaii  Chrome  Microsoft Office
09:12  IP-A  Hawaii  Chrome  Exchange Online
09:14  IP-A  Hawaii  Chrome  SharePoint
```

The same session accessing several Microsoft services can be normal.

## Needs Attention

```text
09:10  IP-A  Hawaii       Chrome
09:13  IP-B  Netherlands  Different UA
```

In an AiTM investigation, the same root session appearing almost immediately in a materially different context is significant.

However:

> Same `SessionId` + different IP does **not** automatically prove token theft.

Consider:

- VPN
- Corporate proxy
- Secure web gateway
- Mobile network
- Known customer egress infrastructure

---

# Step 5 — Check Non-Interactive Authentication

This is an important AiTM pivot.

```kusto
let sid = "SESSION-ID";
AADNonInteractiveUserSignInLogs
| where SessionId == sid
| project TimeGenerated,
          ResultType,
          IPAddress,
          LocationDetails,
          AppDisplayName,
          ResourceDisplayName,
          UserAgent,
          DeviceDetail,
          UniqueTokenIdentifier
| order by TimeGenerated asc
```

## Normal Pattern

```text
Interactive authentication
        ↓
Successful authentication / MFA
        ↓
Non-interactive Exchange / Graph / Office authentication
```

The user does not need to perform MFA for every non-interactive event.

## Concerning Pattern

```text
09:10
Interactive
IP: Known-US-IP
UA: Chrome
SID: ABC123

09:12
Non-interactive
IP: Unknown-IP
Location: different country
UA: materially different
SID: ABC123

09:13
Non-interactive
Exchange Online
Unknown-IP
SID: ABC123
```

This supports the hypothesis that authentication artifacts associated with the original session are appearing from unexpected context.

It still requires corroboration.

---

# What Is NOT Automatically Suspicious?

Do not escalate solely because:

- A non-interactive sign-in occurred
- No new MFA challenge occurred
- The same `SessionId` accessed multiple Microsoft services
- The IP changed once
- `DeviceDetail` is blank
- `UserAgent` changed slightly
- An existing MFA claim was reused

These are context indicators, not proof of compromise.

---

# Step 6 — Determine Whether the Context Is Actually Unusual

Only baseline if it is still needed.

```kusto
let user = "user@domain.com";
SigninLogs
| where UserPrincipalName =~ user
| where TimeGenerated > ago(30d)
| summarize Signins=count(),
            FirstSeen=min(TimeGenerated),
            LastSeen=max(TimeGenerated)
          by IPAddress, UserAgent
| order by Signins desc
```

## Supports Expected Activity

- Same IP frequently used by user
- Known corporate/VPN/proxy infrastructure
- Same or closely related user agent
- Known device
- Geography is historically established

## Raises Concern

- IP never previously observed
- Hosting/VPS infrastructure
- Unusual ASN
- Abrupt geography change
- Device inconsistent with history
- Different client context immediately after suspicious authentication

## Important

IP reputation is enrichment.

```text
Behavior > Reputation
```

A clean reputation does not outweigh suspicious authentication behavior.

---

# Step 7 — Check Post-Authentication Activity

## Core Question

> What did the account do after the suspicious authentication?

Start with approximately:

```text
Alert time → +1 to 2 hours
```

Do not review the user's entire Microsoft 365 history.

### OfficeActivity

```kusto
let user = "user@domain.com";
let alertTime = datetime(2026-01-01 12:00:00);
OfficeActivity
| where UserId =~ user
| where TimeGenerated between (alertTime .. alertTime+2h)
| project TimeGenerated,
          OfficeWorkload,
          Operation,
          ClientIP,
          UserAgent,
          AppAccessContext,
          OfficeObjectId,
          Site_Url,
          SourceFileName,
          Parameters
| order by TimeGenerated asc
```

## Pay Attention To

### Exchange

- Inbox rule creation/modification
- Forwarding changes
- Email sending
- Mailbox access/search
- Message deletion

### SharePoint / OneDrive

- File downloads
- Mass downloads
- Sensitive file access
- File deletion
- Sharing changes

### Other M365

- Unexpected Teams activity
- Graph/API activity
- Application activity inconsistent with user history

---

# Step 8 — Check Mailbox Rules

```kusto
let user = "user@domain.com";
let alertTime = datetime(2026-01-01 12:00:00);
OfficeActivity
| where UserId =~ user
| where TimeGenerated between (alertTime-30m .. alertTime+2h)
| where Operation in ("New-InboxRule",
                      "Set-InboxRule",
                      "Remove-InboxRule",
                      "UpdateInboxRules")
| project TimeGenerated,
          Operation,
          ClientIP,
          UserAgent,
          Parameters
| order by TimeGenerated asc
```

Operation names can vary depending on the underlying Exchange audit activity and connector.

## Higher-Concern Rule Behavior

- Forward externally
- Redirect externally
- Delete messages
- Move security/payment/password-related messages
- Hide replies/security notifications
- Stop processing additional rules

---

# Step 9 — Check Authentication-Method Changes

```kusto
let user = "user@domain.com";
let alertTime = datetime(2026-01-01 12:00:00);
AuditLogs
| where TimeGenerated between (alertTime-30m .. alertTime+2h)
| where TargetResources has user
| where OperationName has_any ("security info",
                               "authentication method",
                               "password")
| project TimeGenerated,
          OperationName,
          Result,
          InitiatedBy,
          TargetResources
| order by TimeGenerated asc
```

Pay attention to:

- Authentication-method additions
- Authentication-method deletions
- Security-info registration
- Password reset/change
- MFA-method modification

Exact `OperationName` values can vary, so inspect the tenant's actual audit records rather than assuming an exact name.

---

# Step 10 — Check Related Security Alerts

Prioritize related detections such as:

- Attacker in the Middle
- Anomalous token
- Unfamiliar sign-in properties
- Impossible/improbable travel
- Malicious IP
- Suspicious inbox rule
- OAuth consent
- Mass download
- Suspicious email sending
- Password spray
- Risky user/sign-in

Do not investigate unrelated historical alerts merely because they exist.

---

# Disposition

## Security Escalation

Escalate when evidence materially supports unauthorized account/session use.

Strong pattern:

```text
AiTM signal
+
successful authentication
+
unusual session/context
+
suspicious post-authentication activity
```

Examples of strong follow-on evidence:

- Suspicious inbox rule
- External forwarding
- Authentication-method modification
- Unusual email sending
- Unusual file access/download
- OAuth consent
- Other account-takeover behavior

Once strong compromise evidence exists, you do not need to fully reconstruct the token theft mechanism.

---

## Verification Escalation

Use when:

- Authentication succeeded
- Context is unusual but technically plausible
- No material suspicious follow-on activity is identified
- Customer network/business context is required to determine whether the activity was expected

Do not verification-escalate merely because complete certainty is unavailable.

---

## Close / Unsuccessful Attempt

Potentially appropriate when:

- Suspicious phishing/AiTM activity occurred
- Associated authentication did not succeed
- No other suspicious successful authentication was identified
- No suspicious session behavior was identified
- No suspicious downstream activity occurred

Follow provider/customer procedures for unsuccessful attack attempts.

---

# Stop Conditions

## Stop and Security Escalate

If you have:

```text
Successful suspicious authentication
+
session/context anomaly
+
malicious or clearly suspicious follow-on activity
```

You have enough.

Do not spend additional time reverse-engineering MFA or token internals.

---

## Stop and Verification Escalate

If you have:

```text
Successful authentication
+
plausible but unusual context
+
no malicious follow-on
+
remaining question is customer-owned context
```

The context boundary has been reached.

---

## Stop / Close

If you have:

```text
No successful suspicious authentication
+
no suspicious session behavior
+
no suspicious follow-on activity
```

Further hunting is unlikely to change the disposition.

---

# Common Analyst Traps

## "No MFA Prompt = Stolen Token"

Incorrect.

Legitimate authentication sessions can reuse previously satisfied MFA claims.

---

## "Same SessionId From Two IPs = Token Theft"

Too strong.

It is decision-relevant, but IP changes can result from:

- VPNs
- Proxies
- Mobile networks
- Secure web gateways
- Cloud infrastructure

Corroborate it.

---

## Reviewing Every SigninLogs Field

Do not.

Prioritize:

```text
TimeGenerated
ResultType
IsInteractive
IPAddress
LocationDetails
UserAgent
DeviceDetail
AppDisplayName
ResourceDisplayName
AuthenticationDetails
SessionId
UniqueTokenIdentifier
```

Ignore other fields unless one of these gives you a reason to investigate further.

---

## Requiring MFA Before Every Successful Event

Do not.

Non-interactive authentication and reuse of existing authentication claims are normal.

---

## Spending Too Long on IP Reputation

Do not.

```text
Authentication behavior > IP reputation
```

A clean IP can still be attacker infrastructure.

---

# 5-Minute Mental Model

When overwhelmed, return to:

```text
1. AUTH
Did suspicious authentication succeed?

2. SESSION
Did the session/context become materially unusual?

3. IMPACT
Did suspicious account/workload activity follow?
```

Do not move outside these questions unless one creates a reason to.

---

# Analyst Scratch Notes

```text
Alert:
User:
Alert time:

Suspicious authentication:
- Result:
- IP:
- Location:
- UA:
- Device:
- SessionId:
- MFA/auth details:

Session correlation:
- Same SID elsewhere:
- Non-interactive activity:
- Context change:

Post-authentication:
- Mail:
- Rules/forwarding:
- Files:
- Auth-method changes:
- Related alerts:

Supports compromise:
-

Supports expected:
-

Limitation:
-

Decision:
-
```

---

# Final Investigation Note Template

## Overview

Potential AiTM phishing activity was identified involving `<user>`. Review focused on authentication success, session context, and activity performed following the suspicious authentication.

## Alert Details

- User:
- Alert time:
- Suspicious IP:
- Application/resource:
- Authentication result:
- SessionId:

## Analysis

- `<Authentication result and relevant MFA context>`
- `<IP/location/device/session correlation>`
- `<Relevant non-interactive authentication findings>`
- `<Relevant Exchange/SharePoint/cloud activity>`
- `<Related detections or absence of suspicious follow-on>`
- `<Material telemetry limitation if applicable>`

## Conclusion / Recommendation

### Security Escalation Example

The suspicious authentication was successful and was followed by activity inconsistent with the user's established authentication context. Additional post-authentication activity involving `<activity>` was identified. The combined evidence is consistent with potential unauthorized session use. Recommend containment and further account-impact review in accordance with customer procedures.

### Verification Escalation Example

The authentication was successful and showed unusual session/network context; however, no additional suspicious account activity was identified in the reviewed telemetry. The observed infrastructure or session behavior could not be validated from available telemetry. Recommend customer confirmation of the authentication and associated access.

### Unsuccessful Attempt Example

Review identified the suspected AiTM authentication attempt; however, no successful authentication associated with the suspicious activity was identified. No suspicious session reuse or follow-on account activity was identified in the reviewed telemetry. The available evidence is consistent with an unsuccessful phishing attempt.

## Queries

Include only queries that materially contributed to the decision.

## OSINT

Include only IP/domain/campaign research that materially affected the assessment.

Do not add OSINT simply to make the investigation appear more complete.
