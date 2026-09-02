# Identity Anomaly Triage Runbook

**Platform:** Microsoft Defender XDR / Microsoft Sentinel / Microsoft Entra ID
**Audience:** Tier 1 SOC Analysts
**Purpose:** Rapid triage of Microsoft identity anomaly and suspicious sign-in alerts
**Status:** Operational Runbook

---

## Scope

Use this runbook for identity alerts and Entra ID Protection risk detections such as:

| Alert / Risk Detection        | `RiskEventType`           | What Microsoft is flagging                                                          |
| ----------------------------- | ------------------------- | ----------------------------------------------------------------------------------- |
| Anomalous Token               | `anomalousToken`          | Token/session characteristics that may indicate replay                              |
| Unfamiliar Sign-in Properties | `unfamiliarFeatures`      | Sign-in properties that differ from the user's history                              |
| Atypical Travel               | `unlikelyTravel`          | Geographically distant sign-ins inconsistent with expected travel                   |
| Impossible Travel             | `mcasImpossibleTravel`    | Activity from locations that cannot reasonably be traveled between                  |
| Anonymous IP Address          | `anonymizedIPAddress`     | Sign-in through anonymization infrastructure                                        |
| Activity from Anonymous IP    | `riskyIPAddress`          | Activity observed from an anonymous proxy                                           |
| Malicious IP Address          | `maliciousIPAddress`      | Sign-in from infrastructure Microsoft considers malicious                           |
| New Country                   | `newCountry`              | Sign-in from a country not normally associated with the user                        |
| Suspicious Browser            | `suspiciousBrowser`       | Browser/session behavior Microsoft considers suspicious                             |
| Token Issuer Anomaly          | `tokenIssuerAnomaly`      | Unexpected characteristics involving the token issuer                               |
| Suspicious MFA Approval       | `authenticatorPhishing`   | MFA activity containing characteristics associated with social engineering/phishing |
| Attacker in the Middle        | varies by surfaced signal | Authentication session associated with malicious reverse-proxy infrastructure       |

---

# 30-Second Mental Model

You are **not expected to reproduce Microsoft's detection algorithm**.

For example, with **Anomalous Token**, you normally do not hunt for a token string and determine whether the token itself "looks malicious."

Microsoft already detected something abnormal about the session or token.

Your job is to determine:

> **Does the authentication/session and the activity around it make sense for the legitimate user?**

Use this investigation flow:

```text
ALERT
  |
  v
1. Identify the user and trigger
  |
  v
2. Establish who the user is
  |
  v
3. Locate the relevant sign-in/session
  |
  v
4. Compare it against normal user behavior
  |
  v
5. Look for another suspicious signal
  |
  v
6. Look BEFORE the event for initial compromise
  |
  v
7. Look AFTER the event for attacker activity
  |
  v
BENIGN / ESCALATE / LIKELY COMPROMISE
```

---

# Data Sources You Need to Know

You do **not** need every table for every alert.

Start with the first three.

| Priority   | Table                                  | Query Surface                 | Why You Care                                                             |
| ---------- | -------------------------------------- | ----------------------------- | ------------------------------------------------------------------------ |
| 1          | `AlertInfo`                            | Defender XDR                  | What alert fired?                                                        |
| 1          | `AlertEvidence`                        | Defender XDR                  | Which user, IP, device, app, etc. is associated with it?                 |
| 1          | `EntraIdSignInEvents`                  | Defender XDR Advanced Hunting | Authentication/session activity                                          |
| Alternate  | `SigninLogs`                           | Sentinel / Log Analytics      | Detailed Entra sign-in telemetry                                         |
| Alternate  | `AADNonInteractiveUserSignInLogs`      | Sentinel / Log Analytics      | Token-driven/non-interactive sign-ins                                    |
| 2          | `AADUserRiskEvents`                    | Sentinel / Log Analytics      | Entra ID Protection risk detections                                      |
| 2          | `IdentityInfo` / `IdentityAccountInfo` | Defender XDR                  | User role, department, account context                                   |
| 3          | `CloudAppEvents`                       | Defender XDR                  | What the authenticated account did in cloud applications                 |
| 3          | `AuditLogs`                            | Sentinel / Log Analytics      | Entra configuration, authentication, device, role, and directory changes |
| 3          | `UrlClickEvents`                       | Defender XDR                  | Safe Links click activity before compromise                              |
| Supporting | `EmailEvents`                          | Defender XDR                  | Phishing/email context                                                   |
| Supporting | Endpoint tables                        | Defender XDR                  | Malware or endpoint compromise                                           |
| Supporting | `AlertInfo` / `AlertEvidence`          | Defender XDR                  | Other alerts involving the same account                                  |

### `EntraIdSignInEvents` vs `SigninLogs`

These contain related Entra authentication telemetry but are **not the same table**.

Use:

```text
Defender XDR Advanced Hunting
→ EntraIdSignInEvents

Sentinel / Log Analytics
→ SigninLogs
→ AADNonInteractiveUserSignInLogs
```

The methodology is the same regardless of which table your environment provides.

---

# STEP 1: Identify What Fired

## Question

> **What detection brought this user into the queue?**

Do not start hunting blindly.

Record:

```text
Alert:
Alert ID:
Incident ID:
User:
Alert timestamp:
Severity:
Detection source:
Source IP:
Location:
Application:
```

### Defender XDR Query

```kusto
let User = "user@contoso.com";

AlertInfo
| where Timestamp > ago(2d)
| join kind=leftouter (
    AlertEvidence
    | where AccountUpn =~ User
) on AlertId
| project
    Timestamp,
    AlertId,
    Title,
    Severity,
    Category,
    ServiceSource,
    DetectionSource,
    AccountUpn,
    EntityType,
    EvidenceRole,
    RemoteIP,
    DeviceName,
    Application,
    OAuthApplicationId
| order by Timestamp desc
```

## Fields to Understand

### `ServiceSource`

**Meaning:** Which Microsoft security service supplied the alert.

Examples may include:

```text
Microsoft Defender for Identity
Microsoft Defender for Office 365
Microsoft Defender for Endpoint
Microsoft Defender for Cloud Apps
Microsoft Sentinel
```

Do not disposition based on this field.

It simply tells you where the signal originated.

---

### `DetectionSource`

**Meaning:** Detection technology or sensor responsible for identifying the activity.

Use this for context, especially when you are unsure whether the alert originated from Entra, Defender for Cloud Apps, Defender for Office 365, etc.

---

### `EvidenceRole`

Indicates how the entity relates to the alert.

Pay attention to whether the user/IP/device is:

```text
Impacted
Related
```

An entity appearing in `AlertEvidence` does **not automatically mean that entity is malicious**.

---

# STEP 2: Establish Identity Context

## Question

> **Who is this account?**

This should happen **before** deeper sign-in hunting.

A sign-in can look very different depending on whether the account belongs to:

```text
Help desk administrator
Finance employee
Developer
Executive
Service account
Guest user
Standard employee
Global Administrator
```

### Defender XDR

If available:

```kusto
let User = "user@contoso.com";

IdentityInfo
| where AccountUpn =~ User
| summarize arg_max(Timestamp, *) by AccountUpn
| project
    AccountUpn,
    AccountDisplayName,
    Department,
    JobTitle,
    Type,
    IsAccountEnabled,
    CreatedDateTime,
    AssignedRoles,
    CriticalityLevel,
    BlastRadius,
    RiskLevel
```

Depending on your environment, similar account information may be available through `IdentityAccountInfo`.

## What to Ask

| Question                                 | Why                                            |
| ---------------------------------------- | ---------------------------------------------- |
| Is this a human user?                    | Service accounts behave differently            |
| What department are they in?             | Helps establish expected applications/activity |
| Are they an administrator?               | Compromise has greater impact                  |
| Is the account new?                      | Limited baseline may exist                     |
| Is the user a guest/external user?       | Authentication behavior can differ             |
| Does the account have privileged roles?  | May justify faster escalation                  |
| Is the account already considered risky? | Could indicate a broader incident              |

### Example

```text
Account: jane@contoso.com
Department: Human Resources
Role: Standard User
Account Age: 4 years
Privileged Roles: None
```

Later you discover:

```text
Linux
PowerShell-heavy cloud administration
Azure management
Multiple new enterprise applications
```

Those activities deserve different scrutiny than they would for an Azure administrator.

---

# STEP 3: Get the Entra Risk Event

If your environment sends Entra ID Protection data into Sentinel/Log Analytics, use:

```text
AADUserRiskEvents
```

## Query

```kusto
let User = "user@contoso.com";

AADUserRiskEvents
| where UserPrincipalName =~ User
| where ActivityDateTime > ago(7d)
| project
    ActivityDateTime,
    DetectedDateTime,
    UserPrincipalName,
    Activity,
    RiskEventType,
    RiskLevel,
    RiskState,
    RiskDetail,
    IpAddress,
    Location,
    CorrelationId,
    RequestId,
    DetectionTimingType,
    TokenIssuerType
| order by ActivityDateTime desc
```

---

## Fields You Need to Understand

### `ActivityDateTime`

**This is important.**

This is:

> When the risky activity occurred.

Use this as your investigation pivot.

---

### `DetectedDateTime`

This is:

> When Microsoft detected the risk.

These times may differ because some risk detections are calculated offline.

Do **not** assume:

```text
DetectedDateTime == attacker activity time
```

---

### `RiskEventType`

This tells you what Microsoft detected.

Examples:

```text
anomalousToken
unfamiliarFeatures
unlikelyTravel
anonymizedIPAddress
riskyIPAddress
maliciousIPAddress
newCountry
suspiciousBrowser
tokenIssuerAnomaly
authenticatorPhishing
passwordSpray
```

Use this field to determine the initial hypothesis.

---

### `RiskLevel`

Possible values include:

```text
none
low
medium
high
hidden
unknownFutureValue
```

Think of this as Microsoft's confidence/risk assessment.

Do not translate:

```text
Low = benign
Medium = compromised
High = confirmed compromised
```

The analyst still needs context.

---

### `RiskState`

Possible values include:

```text
none
confirmedSafe
remediated
dismissed
atRisk
confirmedCompromised
unknownFutureValue
```

Important distinction:

```text
RiskLevel = strength/confidence of risk

RiskState = current state of that risk
```

---

### `RiskDetail`

Possible values may include:

```text
none
adminConfirmedSigninSafe
aiConfirmedSigninSafe
userPassedMFADrivenByRiskBasedPolicy
adminDismissedAllRiskForUser
adminConfirmedSigninCompromised
adminConfirmedUserCompromised
hidden
```

Do not treat `RiskDetail` as:

> "Why Microsoft's detection algorithm fired."

For example:

```text
RiskEventType = anomalousToken
RiskDetail = none
```

does **not** mean Microsoft found nothing.

The actual detection is still `anomalousToken`.

---

### `CorrelationId`

Very useful.

This may connect the risk event with the associated sign-in.

If present, record it.

---

### `RequestId`

Another identifier associated with the sign-in request.

If you cannot correlate using time/IP alone, use this as an additional pivot.

---

# STEP 4: Locate the Relevant Authentication

## Question

> **What authentication/session was occurring when Microsoft detected the risk?**

Start narrowly.

Do **not** immediately examine seven days of activity.

Start with approximately:

```text
Risk event time ± 30 minutes
```

---

# Option A: Defender XDR

## `EntraIdSignInEvents`

```kusto
let User = "user@contoso.com";
let RiskTime = datetime(2026-09-02T18:30:00Z);

EntraIdSignInEvents
| where AccountUpn =~ User
| where Timestamp between ((RiskTime - 30m) .. (RiskTime + 30m))
| project
    Timestamp,
    AccountUpn,
    ErrorCode,
    Application,
    ResourceDisplayName,
    IPAddress,
    Country,
    State,
    City,
    UserAgent,
    Browser,
    ClientAppUsed,
    OSPlatform,
    DeviceName,
    EntraIdDeviceId,
    DeviceTrustType,
    IsManaged,
    IsCompliant,
    AuthenticationRequirement,
    TokenIssuerType,
    ConditionalAccessStatus,
    RiskEventTypes,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    RiskState,
    LogonType,
    SessionId,
    UniqueTokenId,
    CorrelationId,
    RequestId
| order by Timestamp asc
```

---

# What Each Sign-in Field Means

## `ErrorCode`

```text
0
```

generally indicates a successful sign-in.

Non-zero values indicate a sign-in/authentication error.

For identity anomaly alerts, successful activity often matters more because you are trying to establish whether unauthorized authenticated access occurred.

---

# `IPAddress`

Ask:

```text
Have I seen this IP for this user before?
Is it corporate infrastructure?
VPN?
SASE?
Mobile provider?
Residential ISP?
Cloud/VPS provider?
Tor/proxy?
```

### More reassuring

```text
Previously used IP
Known corporate VPN
Known corporate security proxy
Consistent residential/mobile provider
```

### More concerning

```text
First-seen IP
Hosting/VPS network
Anonymizer
IP associated with other compromised users
Unexpected geographic region
```

**Do not disposition from IP reputation alone.**

---

# `Country`, `State`, `City`

Use geography comparatively.

Do not ask:

> Is Virginia suspicious?

Ask:

> Is Virginia normal for this user?

### More reassuring

```text
Same country/region historically
Known travel
Corporate VPN exit node
Organization-wide proxy
```

### More concerning

```text
New country
Rapid geographic transition
Location incompatible with surrounding sessions
Location paired with new device + new browser + new IP
```

---

# `DeviceName`

### Reassuring

```text
Known corporate workstation
Previously observed device
```

### Concerning

```text
Unknown device
First-seen device
Unexpectedly blank when historical sessions normally identify the device
```

Blank does **not automatically mean malicious**.

Some authentication flows provide limited device information.

---

# `EntraIdDeviceId`

Unique Entra device identifier.

This is often stronger than relying only on `DeviceName`.

Ask:

> Has this user authenticated from this same device ID previously?

---

# `IsManaged`

Values:

```text
1 = managed
0 = not managed
```

### Example

Normal history:

```text
IsManaged = 1
```

Alert:

```text
IsManaged = 0
```

That difference matters if the user's normal activity consistently originates from managed corporate devices.

It is **not automatically malicious**.

---

# `IsCompliant`

Values:

```text
1 = compliant
0 = non-compliant
```

Again, use context.

```text
Normal = always compliant
Alert = non-compliant
```

is more interesting than:

```text
User routinely uses unmanaged BYOD
Alert = unmanaged
```

---

# `DeviceTrustType`

Possible values can include:

```text
Workplace
AzureAd
ServerAd
```

Use this mainly to understand the device's trust relationship.

Do not use it alone for disposition.

---

# `OSPlatform`

Examples:

```text
Windows 11
Windows 10
macOS
iOS
Android
Linux
```

Ask:

> Is this OS normally used by this account?

Example:

```text
7-day history:
Windows 11 only

Alert:
Linux
```

This is an anomaly worth explaining.

It is not automatically compromise.

---

# `Browser`

Example:

```text
History:
Edge

Alert:
Chrome
```

Weak by itself.

More meaningful when combined:

```text
New browser
+
new OS
+
new IP
+
unknown device
```

---

# `UserAgent`

The User-Agent identifies characteristics of the requesting application/browser.

Do **not** expect a junior analyst to memorize User-Agent strings.

Compare them instead.

Ask:

```text
Is this User-Agent present in the user's history?
Did it abruptly change?
Does the same suspicious User-Agent appear for other users?
```

---

# `Application`

The application performing the authentication.

Examples might include:

```text
Microsoft Office
Microsoft Teams
OfficeHome
Azure Portal
Outlook
```

Ask:

> Does this user normally authenticate to this application?

---

# `ResourceDisplayName`

This is the resource being accessed.

Application and resource are related but not identical.

Think:

```text
Application = client/requesting application

Resource = service the token is being used to access
```

---

# `ClientAppUsed`

Examples can include:

```text
Browser
Mobile Apps and Desktop clients
Exchange ActiveSync
IMAP
POP
SMTP
```

Legacy protocols deserve additional scrutiny when they are unexpected.

---

# `AuthenticationRequirement`

Values can include:

```text
multiFactorAuthentication
singleFactorAuthentication
```

This tells you the **authentication level required**.

It does **not prove that the current person using a session personally performed MFA at that moment**.

This matters for token theft.

A stolen authenticated session may already contain authentication state established by the legitimate user.

Therefore:

```text
AuthenticationRequirement = multiFactorAuthentication
```

does **not clear Anomalous Token**.

---

# `ConditionalAccessStatus`

In `EntraIdSignInEvents`:

```text
0 = policies applied
1 = attempt to apply policies failed
2 = policies not applied
```

Be careful.

This field does **not mean**:

```text
0 = safe
1 = attacker
```

It describes Conditional Access processing.

---

# `RiskLevelAggregated`

Values:

```text
0   = risk level not set
1   = none
10  = low
50  = medium
100 = high
```

---

# `RiskState`

Values:

```text
0 = none
1 = confirmed safe
2 = remediated
3 = dismissed
4 = at risk
5 = confirmed compromised
```

---

# `SessionId`

One of the most useful investigation fields.

This identifies an authentication session.

Use it to ask:

> What else happened in this same session?

Example:

```kusto
let Session = "<SESSION-ID>";

EntraIdSignInEvents
| where SessionId == Session
| project
    Timestamp,
    AccountUpn,
    IPAddress,
    Country,
    City,
    Application,
    ResourceDisplayName,
    OSPlatform,
    Browser,
    UserAgent,
    DeviceName,
    IsManaged,
    IsCompliant,
    UniqueTokenId
| order by Timestamp asc
```

### What you are looking for

Coherent:

```text
08:01 California  Windows 11  Edge  Device-A
08:05 California  Windows 11  Edge  Device-A
08:09 California  Windows 11  Edge  Device-A
```

Potentially concerning:

```text
08:01 California  Windows 11  Edge    Device-A
08:05 California  Windows 11  Edge    Device-A
08:11 Virginia    Linux       Chrome  Unknown
08:14 Virginia    Linux       Chrome  Unknown
```

The second timeline may indicate that authenticated context is appearing from two significantly different environments.

**Important:** Do not conclude token theft solely because an IP or location changes. VPNs, proxies, mobile infrastructure, application architecture, and other legitimate factors can affect session telemetry.

Look for **multiple incompatible characteristics together**.

---

# `UniqueTokenId`

This is a unique identifier associated with the token presented during sign-in.

Use it to trace activity associated with the same token identifier.

Example:

```kusto
let Token = "<UNIQUE-TOKEN-ID>";

EntraIdSignInEvents
| where UniqueTokenId == Token
| project
    Timestamp,
    AccountUpn,
    IPAddress,
    Country,
    Application,
    ResourceDisplayName,
    UserAgent,
    SessionId
| order by Timestamp asc
```

Do not interpret the token ID itself.

You care about:

> **Where and how is this token identifier being observed?**

---

# Option B: Sentinel / Log Analytics

## `SigninLogs`

If you use Sentinel, query:

```kusto
let User = "user@contoso.com";
let RiskTime = datetime(2026-09-02T18:30:00Z);

SigninLogs
| where UserPrincipalName =~ User
| where TimeGenerated between ((RiskTime - 30m) .. (RiskTime + 30m))
| extend
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    DeviceBrowser = tostring(DeviceDetail.browser),
    City = tostring(LocationDetails.city),
    State = tostring(LocationDetails.state),
    Country = tostring(LocationDetails.countryOrRegion)
| project
    TimeGenerated,
    UserPrincipalName,
    ResultType,
    ResultDescription,
    IPAddress,
    Country,
    State,
    City,
    AppDisplayName,
    ResourceDisplayName,
    ClientAppUsed,
    UserAgent,
    DeviceId,
    DeviceOS,
    DeviceBrowser,
    IsInteractive,
    AuthenticationRequirement,
    AuthenticationMethodsUsed,
    AuthenticationDetails,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    RiskState,
    SessionId,
    UniqueTokenIdentifier,
    CorrelationId
| order by TimeGenerated asc
```

---

# Important `SigninLogs` Values

## `ResultType`

```text
0 = successful sign-in
```

Other values indicate errors/failures.

Look at:

```text
ResultDescription
Status
```

for additional context.

---

# `IsInteractive`

Think:

```text
true
→ interactive sign-in involving the user

false
→ authentication occurred without the user actively entering a credential
   or completing an authentication step at that moment
```

### Important

```text
IsInteractive = false
```

does **not mean malicious**.

Non-interactive authentication is normal and common.

It becomes interesting when paired with:

```text
Unfamiliar IP
+
unknown device
+
unusual geography
+
risk detection
+
unexpected application activity
```

---

# `AuthenticationMethodsUsed`

Can contain methods such as:

```text
Password
Authenticator App
SMS
FIDO
PTA
PHS
```

Use this to understand how authentication was performed.

---

# `AuthenticationDetails`

This can provide step-by-step authentication information.

This is often more useful than simply seeing:

```text
AuthenticationRequirement = multiFactorAuthentication
```

when you need to determine what actually happened during authentication.

---

# `ConditionalAccessStatus`

In `SigninLogs`, values commonly include:

```text
success
failure
notApplied
```

Do not confuse these with the integer values used by `EntraIdSignInEvents`.

---

# Non-Interactive Sign-ins

If you are working in Sentinel and need to specifically investigate token-driven activity, check:

```text
AADNonInteractiveUserSignInLogs
```

Example:

```kusto
let User = "user@contoso.com";
let RiskTime = datetime(2026-09-02T18:30:00Z);

AADNonInteractiveUserSignInLogs
| where UserPrincipalName =~ User
| where TimeGenerated between ((RiskTime - 1h) .. (RiskTime + 1h))
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    ClientAppUsed,
    UserAgent,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    RiskState,
    ConditionalAccessStatus,
    SessionId,
    UniqueTokenIdentifier,
    SignInEventTypes,
    TokenIssuerType,
    TokenProtectionStatusDetails
| order by TimeGenerated asc
```

### `SignInEventTypes`

Examples may include:

```text
interactive
refreshToken
managedIdentity
continuousAccessEvaluation
```

A `refreshToken` event is not malicious by itself.

It tells you what kind of authentication/token event occurred.

---

# STEP 5: Compare Against the User's Baseline

Now expand the timeframe.

Recommended starting point:

```text
7 days
```

Increase if needed.

## Defender XDR

```kusto
let User = "user@contoso.com";

EntraIdSignInEvents
| where AccountUpn =~ User
| where Timestamp > ago(7d)
| where ErrorCode == 0
| project
    Timestamp,
    IPAddress,
    Country,
    State,
    City,
    Application,
    ResourceDisplayName,
    ClientAppUsed,
    OSPlatform,
    Browser,
    UserAgent,
    DeviceName,
    EntraIdDeviceId,
    IsManaged,
    IsCompliant,
    SessionId
| order by Timestamp desc
```

---

# Compare These Properties

| Property    | Ask                                              |
| ----------- | ------------------------------------------------ |
| IP          | Has the user used it before?                     |
| ASN / ISP   | Is this their normal provider/corporate network? |
| Country     | Has the user authenticated here before?          |
| City/State  | Is the location consistent?                      |
| Device ID   | Is this a known device?                          |
| Managed     | Does the user normally use managed devices?      |
| Compliant   | Is compliance state different?                   |
| OS          | Is the operating system normal?                  |
| Browser     | Is the browser normal?                           |
| User-Agent  | Has this string/pattern appeared before?         |
| Application | Does the user normally access it?                |
| Client      | Browser/mobile/legacy client normal?             |

---

# Do Not Look at One Field in Isolation

### Weak anomaly

```text
New IP
```

Could simply be:

```text
DHCP
mobile carrier
VPN
travel
home network
```

### Stronger anomaly

```text
New IP
+
new country
+
new OS
+
new browser
+
unknown unmanaged device
```

You now have several independent properties indicating a different user environment.

---

# STEP 6: Look for a Second Signal

## Question

> **Is anything else independently suggesting account compromise?**

### Risk Events

```kusto
let User = "user@contoso.com";
let RiskTime = datetime(2026-09-02T18:30:00Z);

AADUserRiskEvents
| where UserPrincipalName =~ User
| where ActivityDateTime between ((RiskTime - 1d) .. (RiskTime + 1d))
| project
    ActivityDateTime,
    RiskEventType,
    RiskLevel,
    RiskState,
    IpAddress,
    Location,
    CorrelationId
| order by ActivityDateTime asc
```

Look for convergence such as:

```text
anomalousToken
+
unfamiliarFeatures
```

or:

```text
anomalousToken
+
anonymizedIPAddress
```

or:

```text
authenticatorPhishing
+
anomalousToken
```

One anomalous signal can be noisy.

Multiple independent signals telling a compatible story increase concern.

---

# STEP 7: Look BEFORE the Alert

## Question

> **How could unauthorized access have been obtained?**

Start with approximately:

```text
Alert time -24 hours
```

You do not need to investigate every possible attack vector.

Check the highest-value evidence first.

---

# Phishing / URL Click

## `UrlClickEvents`

```kusto
let User = "user@contoso.com";
let RiskTime = datetime(2026-09-02T18:30:00Z);

UrlClickEvents
| where AccountUpn =~ User
| where Timestamp between ((RiskTime - 1d) .. RiskTime)
| project
    Timestamp,
    Url,
    UrlChain,
    ActionType,
    ThreatTypes,
    DetectionMethods,
    IsClickedThrough,
    IPAddress,
    Workload,
    NetworkMessageId
| order by Timestamp desc
```

Important fields:

| Field              | Meaning                                   |
| ------------------ | ----------------------------------------- |
| `Url`              | URL clicked by the user                   |
| `UrlChain`         | Redirect chain                            |
| `ThreatTypes`      | Microsoft threat classification           |
| `ActionType`       | Action taken by Safe Links                |
| `IsClickedThrough` | Whether the user continued past a warning |
| `NetworkMessageId` | Pivot back to the originating email       |

### Concerning

```text
Phishing URL clicked
       ↓
Suspicious authentication
       ↓
Anomalous Token
```

That creates a plausible compromise sequence.

---

# Email Context

If a suspicious click exists:

```kusto
let MessageId = "<NETWORK-MESSAGE-ID>";

EmailEvents
| where NetworkMessageId == MessageId
| project
    Timestamp,
    SenderFromAddress,
    SenderDisplayName,
    SenderIPv4,
    RecipientEmailAddress,
    Subject,
    EmailDirection,
    DeliveryAction,
    DeliveryLocation,
    ThreatTypes,
    ThreatNames,
    DetectionMethods
```

Check:

```text
Who sent it?
Was it delivered?
Was it classified as phishing/malware?
Did the URL click come from this message?
```

---

# Endpoint Context

If the user's device is known, check Defender alerts involving it.

Look for:

```text
Infostealer
Browser credential theft
Suspicious PowerShell
Credential dumping
Malware
Suspicious browser process
Session-cookie theft
PRT-related suspicious activity
```

Do not perform a full endpoint hunt unless evidence justifies it.

The purpose is to answer:

> **Is there evidence explaining how credentials or session material could have been stolen?**

---

# STEP 8: Look AFTER the Alert

## Question

> **What did the authenticated account do after the suspicious activity?**

This is often where possible compromise becomes clearer.

Start with:

```text
Alert time → +24 hours
```

---

# Cloud Activity

## `CloudAppEvents`

```kusto
let User = "user@contoso.com";
let RiskTime = datetime(2026-09-02T18:30:00Z);

CloudAppEvents
| where AccountId =~ User
    or AccountDisplayName =~ User
| where Timestamp between (RiskTime .. (RiskTime + 1d))
| project
    Timestamp,
    ActionType,
    ActivityType,
    Application,
    AccountId,
    IPAddress,
    CountryCode,
    City,
    ISP = Isp,
    IsAnonymousProxy,
    DeviceType,
    OSPlatform,
    UserAgent,
    IsAdminOperation,
    ObjectType,
    ObjectName,
    RawEventData
| order by Timestamp asc
```

---

# High-Value Activity to Look For

Do not memorize every `ActionType`.

Look for behavior involving:

```text
Inbox rule creation/modification
Mailbox forwarding
OAuth consent
Application consent
New application
New device registration
Authentication method changes
Large file access
Mass downloads
SharePoint activity
OneDrive activity
Privilege changes
Administrative operations
```

These actions matter because they can indicate:

```text
Persistence
Collection
Data access
Account takeover
Privilege manipulation
```

---

# Entra Audit Activity

## `AuditLogs`

Use this when investigating:

```text
MFA changes
Authentication methods
Device registration
Role changes
Application consent
Account changes
```

```kusto
let User = "user@contoso.com";
let RiskTime = datetime(2026-09-02T18:30:00Z);

AuditLogs
| where TimeGenerated between (RiskTime .. (RiskTime + 1d))
| where InitiatedBy has User
    or TargetResources has User
| project
    TimeGenerated,
    OperationName,
    ActivityDisplayName,
    Result,
    ResultDescription,
    Identity,
    InitiatedBy,
    TargetResources,
    AdditionalDetails,
    CorrelationId
| order by TimeGenerated asc
```

Important fields:

| Field                 | Purpose                      |
| --------------------- | ---------------------------- |
| `OperationName`       | What changed                 |
| `ActivityDisplayName` | Human-readable activity      |
| `Result`              | Whether it succeeded         |
| `InitiatedBy`         | Who performed the action     |
| `TargetResources`     | Account/object affected      |
| `CorrelationId`       | Correlate related operations |

Pay particular attention to successful changes involving:

```text
Authentication methods
Devices
Application consent
Roles
Account properties
```

---

# Critical Fallback: What If You Cannot Find the Sign-in?

This is particularly important for **Anomalous Token**.

Do **not** conclude:

```text
No SigninLogs entry
=
False positive
```

Some risk detections do not always map cleanly to an obvious interactive `SigninLogs` row.

If the expected sign-in is missing, check:

```text
AADUserRiskEvents
EntraIdSignInEvents
AADNonInteractiveUserSignInLogs
CloudAppEvents
AuditLogs
AlertInfo
AlertEvidence
Microsoft 365/cloud activity
```

Your question becomes:

> **Can I identify activity associated with this user, IP, session, token identifier, correlation ID, or time window elsewhere?**

Also document the evidence gap.

Absence of a particular log entry is not proof that activity did not occur.

---

# Normal vs Abnormal Quick Reference

## Usually More Reassuring

```text
Known device
Known Entra device ID
Managed = 1 when expected
Compliant = 1 when expected
Previously observed IP
Known corporate VPN
Known corporate proxy/SASE infrastructure
Expected geography
Expected browser/OS
Expected application
No other identity-risk detections
No suspicious activity before/after
```

These reduce concern.

They do not individually prove legitimacy.

---

# Requires More Investigation

```text
First-seen IP
New country
New ASN/provider
New browser
New operating system
Unknown device
Unmanaged device
Non-compliant device
Previously unseen application
Unusual non-interactive activity
Hosting/VPS IP
Anonymous proxy
```

One may be explainable.

Several together matter much more.

---

# Strong Escalation Signals

```text
User denies activity

Phishing click
+
Anomalous Token

AiTM signal
+
authenticated activity

Anomalous Token
+
new MFA method

Anomalous Token
+
mailbox forwarding

Anomalous Token
+
OAuth persistence

Unknown session
+
mass file download

Session/token activity
+
multiple incompatible environment characteristics

Multiple independent risk detections
+
no legitimate explanation
```

---

# Things That Do NOT Clear an Identity Alert

Do not close only because:

```text
MFA succeeded
IP reputation is clean
Location is geographically plausible
Application is Microsoft-owned
Alert severity is Medium
Conditional Access succeeded
Device field is blank
The sign-in is non-interactive
```

Each is context.

None is sufficient by itself.

---

# Universal Tier 1 Decision Tree

```text
                    IDENTITY ALERT
                          |
                          v
               Identify user + trigger
                          |
                          v
                 Identity context
                          |
                          v
                Find sign-in/session
                          |
                          v
             Compare against user history
                          |
              +-----------+-----------+
              |                       |
      Clearly expected             Abnormal /
       environment                  unexplained
              |                       |
              v                       v
       Check supporting       Search second signals
          activity                    |
              |                       v
              |                Check before/after
              |                       |
              +-----------+-----------+
                          |
                          v
                 Is there evidence
                 of compromise?
                    /          \
                  YES          NO
                   |            |
                   v            v
              ESCALATE      Is benign
              / COMPROMISE  explanation
                            verified?
                            /       \
                          YES       NO
                           |         |
                           v         v
                        CLOSE     ESCALATE
```

---

# Tier 1 Stopping Criteria

## Close as Benign / Expected

You should be able to state **why** the anomaly occurred.

Example:

```text
The IP belongs to the organization's sanctioned VPN.
The device ID matches the user's normal managed workstation.
OS/browser/application characteristics match historical activity.
No related identity-risk detections or suspicious post-authentication
activity were identified.
```

Do not write:

```text
Looks benign.
```

---

# Escalate as Suspicious

Escalate when:

```text
You cannot establish a legitimate explanation

OR

multiple independent properties are abnormal

OR

critical telemetry is unavailable

OR

behavior exceeds Tier 1 scope
```

You are **not required to prove compromise** before escalating.

A defensible Tier 1 conclusion can simply be:

> Activity cannot currently be attributed to the legitimate user with sufficient confidence.

---

# Escalate as Likely Compromise

Examples:

```text
User confirms activity is unauthorized

Phishing/AiTM precedes anomalous authentication

Suspicious session followed by persistence

Authentication-method manipulation occurs

Suspicious OAuth consent appears

Mailbox forwarding/rules appear

Large/unusual data access occurs

Endpoint compromise supports token/credential theft
```

---

# Tier 1 Investigation Worksheet

Copy this into your investigation notes.

```text
IDENTITY ALERT TRIAGE

Alert:
Incident:
User:
Alert Time:
Risk Activity Time:
Risk Event Type:
Risk Level:
Risk State:

IDENTITY CONTEXT
Department:
Job Title:
Admin / Privileged:
Account Age:
Account Type:
Known Risk:

TRIGGERING ACTIVITY
IP:
Country:
State/City:
Application:
Resource:
Client:
OS:
Browser:
User-Agent:
Device:
Entra Device ID:
Managed:
Compliant:
Interactive / Non-interactive:
Authentication Requirement:
Conditional Access:
Session ID:
Unique Token ID:
Correlation ID:

BASELINE COMPARISON
IP previously seen:
Location previously seen:
Device previously seen:
OS/browser normal:
Application normal:
Network/provider normal:

OTHER RISK SIGNALS
Related Entra risk detections:
Related Defender alerts:

BEFORE
Phishing/email:
URL click:
Endpoint compromise:
Suspicious authentication:

AFTER
MFA/authentication changes:
Device changes:
OAuth/app changes:
Mailbox rules/forwarding:
File access/download:
Other cloud activity:

ASSESSMENT
Benign explanation:
Supporting evidence:
Outstanding uncertainty:

Disposition:
Confidence:
```

---

# Five-Minute Queue Version

When you already understand the methodology, use this:

```text
1. ALERT
   User + time + IP + detection

2. IDENTITY
   Who is this account?
   Admin? Department? New account?

3. SESSION
   EntraIdSignInEvents / SigninLogs
   IP + geo + device + OS + browser + app + SessionId

4. BASELINE
   Have those properties appeared before?

5. CORROBORATE
   Other risks / alerts?

6. BEFORE
   Phish? AiTM? Malware?

7. AFTER
   MFA? OAuth? Inbox rule? Data access?

8. DECIDE
   Explained       → Close
   Unexplained     → Escalate
   Corroborated    → Likely compromise
```

---

# Alert-Specific Starting Questions

Once you understand the universal workflow, the alert name mainly tells you **what to emphasize first**.

| Detection                     | First Analyst Question                                                         |
| ----------------------------- | ------------------------------------------------------------------------------ |
| Anomalous Token               | Does this token/session behave like the legitimate user's session?             |
| Unfamiliar Sign-in Properties | Which IP/device/browser/location properties differ from baseline?              |
| Atypical Travel               | Are both locations legitimate and explainable?                                 |
| Impossible Travel             | Are these genuinely different user environments or VPN/proxy artifacts?        |
| Anonymous IP                  | Is anonymized infrastructure expected for this user/organization?              |
| New Country                   | Has legitimate travel/VPN activity been established?                           |
| Suspicious MFA Approval       | Did the legitimate user initiate and approve this authentication?              |
| AiTM                          | Is there evidence of phishing followed by unauthorized authenticated activity? |

---

# Core Analyst Principle

Do not ask:

> **How do I prove Microsoft's alert algorithm is correct?**

Ask:

> **What hypothesis is Microsoft giving me, and what evidence would validate or refute it?**

For Anomalous Token:

```text
Microsoft hypothesis:
The authenticated token/session may have been replayed.

Tier 1 task:
Determine whether the session characteristics and resulting activity
are consistent with the legitimate user.
```

For Unfamiliar Sign-in Properties:

```text
Microsoft hypothesis:
This authentication differs from the user's established behavior.

Tier 1 task:
Determine which properties changed and whether those changes have
a legitimate explanation.
```

For travel alerts:

```text
Microsoft hypothesis:
The observed geographic sequence may indicate two different users.

Tier 1 task:
Determine whether both locations belong to legitimate activity or
whether VPN/proxy/mobile infrastructure explains the difference.
```

The detection supplies the **hypothesis**.

The analyst supplies the **context, evidence, and decision**.
