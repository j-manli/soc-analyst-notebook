# Tier 1 Entra ID / MFA Alert Runbook

A compact Microsoft Sentinel runbook for Tier 1 triage of Entra ID, MFA, travel, token, and suspicious sign-in alerts.

This is for **triage**, not full incident response or forensics.

---

## Core Questions

For every alert, answer:

```text
1. Did it succeed?
2. Is it normal for this user?
3. Did MFA or Conditional Access protect, fail, or allow it?
4. Did anything suspicious happen afterward?
5. Did the same IP, user, or app affect anyone else?
```

---

## Common Variables

Update these values before running querylets.

```kql
let User = tolower("user@company.com");
let AlertTime = datetime(2026-06-26T12:00:00Z);
let IP = "1.2.3.4";
```

Use the alert time in UTC if Sentinel displays UTC.

---

# Default Investigation Flow

Run only what you need.

```text
1. Q1 - Who is the user?
2. Q2 - What auth happened around alert time?
3. Q3 - What do Entra SigninLogs show?
4. Q4 - Is this normal for the user?
5. Q5 - What happened with MFA?
6. Q6 - Did the same IP hit other users?
7. Q7 - Did anything change afterward?
8. Q8 - Did the user do anything in M365 afterward?
9. Classify: benign, tuning candidate, or escalate.
```

---

# Core Queries

## Q1 — Who Is the User?

**Why:** Determines whether the alert involves a privileged, risky, guest, service, or high-blast-radius identity.

```kql
let User = tolower("user@company.com");
IdentityInfo
| where tolower(AccountUPN) == User
| summarize arg_max(TimeGenerated, *) by AccountUPN
| project TimeGenerated, AccountUPN, AccountDisplayName, AccountName,
          Department, JobTitle, BlastRadius, RiskLevel, RiskState,
          InvestigationPriority, EntityRiskScore
```

### Look For

```text
Privileged user
High blast radius
High investigation priority
High entity risk score
Risky user
Guest account
Service account
Executive/VIP user
```

### Pivot

```text
High-value identity + suspicious success = escalate faster.
Normal user + failed-only activity + no suspicious follow-up = lower concern.
```

### If Q1 Errors

Run this to see available fields:

```kql
IdentityInfo
| getschema
```

Or use the quick search version:

```kql
let User = "user@company.com";
IdentityInfo
| search User
| take 10
```

---

## Q2 — Quick Auth Timeline with `imAuthentication`

**Why:** Fast normalized authentication overview.

```kql
let User = tolower("user@company.com");
let AlertTime = datetime(2026-06-26T12:00:00Z);
let IP = "1.2.3.4";
imAuthentication
| where TimeGenerated between ((AlertTime - 1h) .. (AlertTime + 1h))
| where tolower(tostring(TargetUsername)) has User or SrcIpAddr == IP
| project TimeGenerated, TargetUsername, SrcIpAddr, SrcGeoCountry,
          TargetAppName, EventResult, EventResultDetails,
          LogonMethod, HttpUserAgent
| order by TimeGenerated asc
```

### Look For

```text
Success or failure
Same IP as alert
Unexpected country
Unexpected app
Repeated failures
Failure followed by success
Odd user agent
```

### Pivot

```text
If imAuthentication shows success, validate details in SigninLogs.
If only failures, check whether MFA or Conditional Access blocked it.
If same IP appears across multiple users, run Q6.
```

---

## Q3 — Entra Sign-In Details

**Why:** Source of truth for Entra sign-in result, MFA, Conditional Access, risk, device, browser, app, and location.

```kql
let User = tolower("user@company.com");
let AlertTime = datetime(2026-06-26T12:00:00Z);
let IP = "1.2.3.4";
SigninLogs
| where TimeGenerated between ((AlertTime - 1h) .. (AlertTime + 1h))
| where tolower(UserPrincipalName) == User or IPAddress == IP
| extend Country = tostring(LocationDetails.countryOrRegion),
         City = tostring(LocationDetails.city),
         OS = tostring(DeviceDetail.operatingSystem),
         Browser = tostring(DeviceDetail.browser),
         Details = tostring(Status.additionalDetails)
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName,
          IPAddress, Country, City, OS, Browser, UserAgent,
          ResultType, ResultDescription, Details,
          AuthenticationRequirement, AuthenticationMethodsUsed,
          ConditionalAccessStatus, RiskEventTypes_V2,
          RiskLevelAggregated, RiskState, CorrelationId
| order by TimeGenerated asc
```

### Look For

```text
ResultType == 0 means success
ResultType != 0 means failed/interrupted/blocked
New IP/country/device/browser
RiskLevelAggregated medium/high
RiskState atRisk or confirmedCompromised
ConditionalAccessStatus failure/notApplied
MFA satisfied from suspicious IP
```

### Pivot

```text
Successful suspicious sign-in → run Q7 and Q8.
Failed-only + CA blocked/MFA denied → usually lower risk unless repeated or user denies.
Medium/high risk or atRisk → escalate or validate with user.
```

---

## Q4 — User Baseline

**Why:** Most of these alerts are about behavior being unusual for the user. This checks whether it is actually unusual.

```kql
let User = tolower("user@company.com");
SigninLogs
| where TimeGenerated between (ago(30d) .. ago(1d))
| where tolower(UserPrincipalName) == User
| extend Country = tostring(LocationDetails.countryOrRegion),
         OS = tostring(DeviceDetail.operatingSystem),
         Browser = tostring(DeviceDetail.browser)
| summarize Count = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
          by IPAddress, Country, AppDisplayName, OS, Browser
| order by Count desc
```

### Look For

```text
Has this IP been seen before?
Has this country been seen before?
Has this app been seen before?
Has this device/browser been seen before?
```

### Pivot

```text
Seen often before → supports benign/tuning.
Never seen before + success → suspicious.
Never seen before + MFA success → more suspicious.
Never seen before + follow-on changes → escalate.
```

---

## Q5 — MFA Details

**Why:** Determines whether MFA was denied, spammed, satisfied, or fraud-reported.

```kql
let User = tolower("user@company.com");
let AlertTime = datetime(2026-06-26T12:00:00Z);
SigninLogs
| where TimeGenerated between ((AlertTime - 30m) .. (AlertTime + 30m))
| where tolower(UserPrincipalName) == User
| mv-expand Auth = todynamic(AuthenticationDetails)
| extend Method = tostring(Auth.authenticationMethod),
         StepResult = tostring(Auth.authenticationStepResultDetail),
         StepSucceeded = tostring(Auth.succeeded),
         Details = tostring(Status.additionalDetails)
| project TimeGenerated, AppDisplayName, IPAddress, ResultType,
          ResultDescription, Details, Method, StepResult, StepSucceeded,
          AuthenticationRequirement, AuthenticationMethodsUsed,
          ConditionalAccessStatus, UserAgent
| order by TimeGenerated asc
```

### Look For

```text
MFA denied
User declined
Fraud reported
Multiple prompts
Eventual MFA success
Password accepted before MFA
```

### Pivot

```text
MFA denied only + no success = likely attempted compromise or user mistake.
Multiple denials + later success = possible MFA fatigue compromise.
Fraud reported / user says “not me” = escalate.
```

---

## Q6 — Same IP Against Other Users

**Why:** Determines whether this is one-user activity or broader attack activity.

```kql
let IP = "1.2.3.4";
imAuthentication
| where TimeGenerated > ago(24h)
| where SrcIpAddr == IP
| summarize Users = dcount(TargetUsername),
            Successes = countif(tolower(tostring(EventResult)) has "success"),
            Failures = countif(tolower(tostring(EventResult)) has "fail"),
            UserSample = make_set(TargetUsername, 20),
            Apps = make_set(TargetAppName, 10)
          by SrcIpAddr
```

If `EventResult` values differ in your workspace, use this broader version:

```kql
let IP = "1.2.3.4";
imAuthentication
| where TimeGenerated > ago(24h)
| where SrcIpAddr == IP
| summarize Users = dcount(TargetUsername),
            Results = make_set(EventResult, 10),
            Details = make_set(EventResultDetails, 10),
            UserSample = make_set(TargetUsername, 20),
            Apps = make_set(TargetAppName, 10)
          by SrcIpAddr
```

### Look For

```text
Many users
Many failures
Any successes
Same app targeted
Same IP across multiple users
```

### Pivot

```text
One user only = individual triage.
Many users + failures = spray/brute force behavior.
Many users + success = escalate.
```

---

## Q7 — Audit Changes After Alert

**Why:** Catches persistence and privilege changes.

```kql
let User = tolower("user@company.com");
let AlertTime = datetime(2026-06-26T12:00:00Z);
AuditLogs
| where TimeGenerated between ((AlertTime - 2h) .. (AlertTime + 24h))
| where tostring(InitiatedBy) has User or tostring(TargetResources) has User
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
         ActorIP = tostring(InitiatedBy.user.ipAddress),
         Target = tostring(TargetResources[0].userPrincipalName),
         TargetName = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Category, Actor, ActorIP,
          Target, TargetName, Result, ResultReason
| order by TimeGenerated asc
```

### Look For

```text
User registered security info
User changed default security info
User deleted security info
Admin registered security info
Reset password
Add member to role
Add member to group
Consent to application
Add service principal
Add service principal credentials
Update application
Update conditional access policy
Disable conditional access policy
```

### Pivot

```text
Suspicious login + MFA/security info change = escalate.
Suspicious login + role/group/app/policy change = escalate hard.
No changes supports benign, but does not fully clear suspicious success.
```

---

## Q8 — M365 Activity After Alert

**Why:** Determines whether the account did anything after login.

```kql
let User = tolower("user@company.com");
let AlertTime = datetime(2026-06-26T12:00:00Z);
let IP = "1.2.3.4";
OfficeActivity
| where TimeGenerated between ((AlertTime - 1h) .. (AlertTime + 24h))
| where tolower(UserId) == User
    or tolower(MailboxOwnerUPN) == User
    or ClientIP == IP
| project TimeGenerated, OfficeWorkload, Operation, UserId,
          ClientIP, UserAgent, ResultStatus, OfficeObjectId,
          MailboxOwnerUPN, ItemName
| order by TimeGenerated asc
```

### Look For

```text
MailItemsAccessed
Send
New-InboxRule
Set-InboxRule
Set-Mailbox
FileAccessed
FileDownloaded
FileDeleted
SharingSet
AddedToSecureLink
Teams message/activity anomalies
```

### Pivot

```text
Suspicious login + mailbox rule/file access/send activity = escalate.
No OfficeActivity afterward supports lower impact.
```

---

# Alert-Specific Runbooks

## 1. Anomalous Token Involving One User

### Run

```text
Q1, Q2, Q3, Q4, Q7, Q8
```

### Look For

```text
Successful sign-in
New IP/location/user agent
Non-interactive activity after alert
Token-related risk in RiskEventTypes_V2
Same user/session seen from unusual IPs
Post-login changes or M365 activity
```

### Benign

```text
Known IP/device/app
No successful suspicious activity
No follow-on changes
User confirms activity
```

### Tuning Candidate

```text
Known VPN/ZTNA/proxy
Known app causing token/location weirdness
Repeated low-risk pattern with no impact
```

### Escalate

```text
Successful unfamiliar sign-in
User denies activity
Non-interactive activity continues from suspicious IP
MFA/security info changed
OfficeActivity shows mail/file access
Privileged user
```

---

## 2. Anonymous IP Address

### Run

```text
Q1, Q2, Q3, Q4, Q6, Q8
```

### Look For

```text
Did it succeed?
Was MFA satisfied?
Was CA blocked or not applied?
Known VPN/Tor/proxy/corporate egress?
Same IP against other users?
Post-login M365 activity?
```

### Benign

```text
Failed only
CA blocked
Known VPN/corporate proxy
User confirms
No follow-on activity
```

### Tuning Candidate

```text
Sanctioned VPN misclassified
Security team or privacy role expected to use anonymous IP
Repeated known approved IP range
```

### Escalate

```text
Successful login from anonymous IP
New country/device/browser
MFA satisfied unexpectedly
Same IP targets multiple users
Post-login activity
Privileged user
```

---

## 3. Atypical Travel

### Run

```text
Q1, Q2, Q3, Q4, Q8
```

### Look For

```text
Two distant locations
Both sign-ins successful?
VPN/proxy/mobile carrier/corporate egress?
Same device/browser or different?
Known travel?
Post-login activity from suspicious side?
```

### Benign

```text
One side failed
Known VPN/corporate egress
User confirms travel
Same familiar device/browser
No follow-on activity
```

### Tuning Candidate

```text
Frequent traveler
Mobile carrier location noise
Known ZTNA/VPN not allowlisted
```

### Escalate

```text
Both locations successful
User denies one location
Different device/browser
MFA satisfied unexpectedly
Sensitive app or OfficeActivity after login
Privileged user
```

---

## 4. Impossible Travel Activity

### Run

```text
Q1, Q2, Q3, Q4, Q8
```

### Look For

```text
Both locations/IPs in alert
Both successful?
Impossible time gap?
VPN/corporate/mobile explanation?
Different device/browser/user agent?
Activity after suspicious location?
```

### Benign

```text
Known VPN/corporate IP
Known travel
One event failed only
No post-auth activity
```

### Tuning Candidate

```text
Known VPN range missing from named locations
Frequent traveler repeatedly triggers
Corporate egress geo-location mismatch
```

### Escalate

```text
Both sign-ins successful
User denies suspicious location
MFA succeeded unexpectedly
Device/browser changed
Follow-on M365/audit activity
Privileged user
```

---

## 5. Unfamiliar Sign-In Properties

### Run

```text
Q1, Q2, Q3, Q4, Q7, Q8
```

### Look For

```text
What is unfamiliar: IP, country, ASN, device, browser, app?
Did it succeed?
Interactive or non-interactive?
MFA/CA result?
Any related risk events?
Follow-on changes/activity?
```

### Benign

```text
User confirms new device/location
Known travel
New managed device
Known VPN/corporate egress
Failed only
No follow-on activity
```

### Tuning Candidate

```text
New office IP
New ZTNA/VPN rollout
New device/browser rollout
Frequent traveler group
```

### Escalate

```text
Successful unfamiliar sign-in
Non-interactive unfamiliar sign-in
User denies activity
MFA satisfied unexpectedly
Related anonymous IP/atypical travel/impossible travel alert
Audit or OfficeActivity after login
Privileged user
```

---

## 6. Excessive Failed Logins Followed by Successful Login

### Run

```text
Q1, Q2, Q3, Q5, Q6, Q7, Q8
```

### Look For

```text
Many failures before success
Same IP/country/app/user agent?
Failure reason: bad password, MFA denied, CA blocked?
Did MFA eventually succeed?
Same IP hitting other users?
Post-success changes/activity?
```

### Benign

```text
User mistyped password
Cached credentials after password change
Known app retrying old password
Success from normal IP/device
No follow-on activity
```

### Tuning Candidate

```text
Known misconfigured app
Stale mobile mail client
Threshold too sensitive for normal retry behavior
```

### Escalate

```text
Failures followed by success from suspicious IP
Same IP targets multiple users
Success from new country/device
MFA satisfied unexpectedly
User denies activity
Audit or OfficeActivity after success
Privileged user
```

---

## 7. MFA Rejected by User

### Run

```text
Q1, Q2, Q3, Q5, Q6
```

### Look For

```text
ResultType 500121 or MFA denied detail
User declined vs fraud reported
One prompt or many?
Password accepted before MFA?
New IP/location/app?
Later success from same IP?
```

### Benign

```text
User confirms they caused and denied the prompt
Normal IP/app/device
Single denial
No later success
No follow-on activity
```

### Tuning Candidate

```text
Known app causing confusing MFA prompts
Known CA/session issue
Repeated benign denials from approved locations
```

### Escalate

```text
User says “not me”
Fraud reported
Multiple prompts
New country/IP/app
Later success after denial
Privileged user
```

---

## 8. MFA Spamming Followed by Success

### Run

```text
Q1, Q2, Q3, Q5, Q6, Q7, Q8
```

### Look For

```text
Repeated MFA failures/denials
Eventual successful MFA
Same IP/app/location?
User approved or denies approving?
Post-success activity?
Same IP against other users?
```

### Benign

```text
User confirms repeated prompts from own login issue
Success from normal IP/device
No suspicious follow-on activity
Known helpdesk ticket
```

### Tuning Candidate

```text
Known app causes repeated prompts
CA/session lifetime issue
Device enrollment issue
```

### Escalate

```text
Multiple denials followed by success
User denies approving
New IP/country/device/app
Success after push fatigue pattern
Audit or OfficeActivity after success
Privileged user
```

---

## 9. SMS MFA Modification

### Run

```text
Q1, Q7, Q3, Q4
```

### Look For

```text
What changed: SMS phone added, changed, removed, or default changed?
Who changed it: user, admin, app?
Actor IP?
Was there suspicious sign-in before the change?
Did a successful sign-in happen after the change?
Was the target privileged?
```

### Benign

```text
User confirms phone change
Helpdesk/admin ticket confirms
Actor expected
Normal IP/device/location
No suspicious sign-in before or after
```

### Tuning Candidate

```text
MFA registration campaign
Bulk migration
Expected helpdesk workflow
Onboarding/change window
```

### Escalate

```text
MFA/SMS changed after suspicious sign-in
User denies change
Unknown actor/admin
Actor IP suspicious
New sign-in after SMS change
Multiple users modified by same actor/IP
Privileged user
```

---

## 10. Multiple Denied MFA Attempts

### Run

```text
Q1, Q2, Q3, Q5, Q6
```

### Look For

```text
How many denials?
Time window?
Same IP/app/location?
Did password pass before MFA?
Fraud reported?
Any later success?
Same IP against other users?
```

### Benign

```text
User confirms attempts
Normal IP/app/device
No later success
No suspicious follow-on activity
```

### Tuning Candidate

```text
Known app repeatedly prompting
User setup/enrollment issue
CA/session policy causing repeated prompts
```

### Escalate

```text
User says “not me”
New country/IP/app
High number of prompts
Later success from same IP
Risk medium/high
Privileged user
Same IP targets others
```

---

# Classification Guide

## Benign / Close

Use when most are true:

```text
No successful suspicious sign-in
Known IP/location/device/app
Conditional Access blocked the attempt
MFA denied and never later succeeded
No suspicious audit changes
No suspicious OfficeActivity
User confirms activity
```

---

## Positive but Tuning Candidate

Use when the detection fired correctly, but activity is expected:

```text
Known VPN/ZTNA/corporate proxy
Known traveler
Known MFA enrollment campaign
Known helpdesk/admin workflow
Known app causing repeated prompts
Known IP range missing from allowlist/named location
```

---

## True Positive / Escalate

Escalate when any are true:

```text
Suspicious sign-in succeeded
User denies activity
MFA spam followed by success
MFA/security info changed after suspicious login
Same IP targeted multiple users and got a success
Privileged/high-blast-radius user involved
RiskState atRisk or confirmedCompromised
RiskLevelAggregated medium/high
Suspicious OfficeActivity after login
Role/group/app/service principal/CA policy changed
```

---

# Fast Write-Up Template

```text
Alert:
- Alert name:
- User:
- Alert time:
- Source:
- IP/location:
- App/resource:

Triage:
- User context:
- Auth result:
- MFA/CA result:
- Baseline:
- Same IP scope:
- Audit changes:
- M365 activity:

Findings:
- Suspicious indicators:
- Benign indicators:
- Unknowns:

Classification:
- Benign / tuning candidate / true positive escalation

Recommendation:
- Close / tune / validate with user / escalate to Tier 2
```

---

# One-Line Mental Model

```text
User context → auth timeline → Entra details → baseline → MFA/CA → same IP scope → audit changes → M365 activity → classify.
```

---

# Notes

* `imAuthentication` is useful for a quick normalized authentication timeline.
* `SigninLogs` is better for Entra-specific MFA, Conditional Access, risk, device, browser, and location details.
* `AuditLogs` answers: who changed what?
* `OfficeActivity` answers: what did the user do after authentication?
* `IdentityInfo` answers: how important or risky is this identity?
* Use this as a Tier 1 triage guide, not a replacement for escalation or full incident response.
