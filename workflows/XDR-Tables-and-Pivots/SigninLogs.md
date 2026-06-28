# `SigninLogs`

## What this table answers

Use `SigninLogs` to answer:

**“Who signed in to Entra ID, from where, to what app, did it succeed, and how did MFA, Conditional Access, and risk evaluate the attempt?”**

This table is for **cloud authentication** and Microsoft Entra ID sign-in activity.

---

## Use this table when

Use `SigninLogs` when investigating:

* Cloud sign-in attempts
* Successful or failed Entra ID authentication
* MFA success, failure, or bypass questions
* Conditional Access policy results
* Risky sign-ins
* Impossible travel
* Credential stuffing or password spraying
* Successful sign-in after multiple failures
* Sign-ins from suspicious IPs, countries, or anonymous networks
* Legacy authentication usage
* Application access attempts
* OAuth or token-based authentication activity
* Guest/B2B user sign-ins
* Service principal or managed identity authentication, if present in your environment

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql id="xdwruh"
let lookback = 7d;
let alertUserPrincipalName = "";
let alertIPAddress = "";
let alertResultType = "";
let alertAppDisplayName = "";
let alertConditionalAccessStatus = "";
let alertAuthenticationRequirement = "";
let alertRiskState = "";
let alertRiskLevel = "";
let alertLocation = "";
let alertIsInteractive = "";
let alertClientAppUsed = "";
let alertCorrelationId = "";

SigninLogs
| where TimeGenerated >= ago(lookback)
| where isempty(alertUserPrincipalName) or UserPrincipalName =~ alertUserPrincipalName
| where isempty(alertIPAddress) or IPAddress == alertIPAddress
| where isempty(alertResultType) or tostring(ResultType) == alertResultType
| where isempty(alertAppDisplayName) or AppDisplayName contains alertAppDisplayName
| where isempty(alertConditionalAccessStatus) or ConditionalAccessStatus =~ alertConditionalAccessStatus
| where isempty(alertAuthenticationRequirement) or AuthenticationRequirement =~ alertAuthenticationRequirement
| where isempty(alertRiskState) or RiskState =~ alertRiskState
| where isempty(alertRiskLevel) or RiskLevelDuringSignIn =~ alertRiskLevel or RiskLevelAggregated =~ alertRiskLevel or RiskLevel =~ alertRiskLevel
| where isempty(alertLocation) or Location =~ alertLocation or tostring(LocationDetails) contains alertLocation
| where isempty(alertIsInteractive) or tostring(IsInteractive) =~ alertIsInteractive
| where isempty(alertClientAppUsed) or ClientAppUsed contains alertClientAppUsed
| where isempty(alertCorrelationId) or CorrelationId == alertCorrelationId
| project-reorder TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription, ConditionalAccessStatus, AuthenticationRequirement, AuthenticationMethodsUsed, RiskState, RiskLevelDuringSignIn, AppDisplayName, Location, LocationDetails, IsInteractive, ClientAppUsed, AuthenticationDetails, ConditionalAccessPolicies, DeviceDetail, UserAgent, CorrelationId
| order by TimeGenerated desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `UserPrincipalName` when investigating a specific account. Use `IPAddress` for source infrastructure, `ResultType` for success/failure filtering, and `AppDisplayName` when the alert is tied to a specific cloud application.

```kql id="5u4nis"
SigninLogs
| where TimeGenerated >= ago(7d)
| where UserPrincipalName =~ "<user@domain.com>"
| project-reorder TimeGenerated, UserPrincipalName, IPAddress, ResultType, ConditionalAccessStatus, AuthenticationRequirement, RiskState, RiskLevelDuringSignIn, AppDisplayName, Location, LocationDetails, IsInteractive, AuthenticationDetails, ConditionalAccessPolicies, DeviceDetail
| order by TimeGenerated desc
```

Alternative `where` lines you can swap in:

```kql id="00kk8p"
| where IPAddress == "<source IP>"
| where tostring(ResultType) == "0"
| where tostring(ResultType) != "0"
| where AppDisplayName contains "<application name>"
| where ConditionalAccessStatus =~ "<success/failure/notApplied>"
| where AuthenticationRequirement =~ "<singleFactorAuthentication/multiFactorAuthentication>"
| where RiskState =~ "<atRisk/confirmedCompromised/confirmedSafe/none>"
| where RiskLevelDuringSignIn =~ "<low/medium/high/none>"
| where Location =~ "<country code>"
| where tostring(LocationDetails) contains "<city/state/country>"
| where IsInteractive == true
| where IsInteractive == false
| where ClientAppUsed contains "<client app>"
| where CorrelationId == "<CorrelationId>"
```

```kql id="jilyq5"
// Purpose: Shows Entra ID sign-ins so I can confirm the user, source IP/location, app accessed, success/failure result, MFA requirement, Conditional Access outcome, risk state, and device context.
```

---

## Key fields

| Field                                 | Why it matters                                                                                                  |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `UserPrincipalName`                   | User identity. Start here when investigating a suspected compromised account.                                   |
| `IPAddress`                           | Source IP address. Useful for attack infrastructure, VPNs, impossible travel, and repeated failures.            |
| `ResultType`                          | Sign-in result code. `0` usually means success; non-zero values usually indicate failure or interruption.       |
| `ConditionalAccessStatus`             | Shows whether Conditional Access succeeded, failed, or did not apply.                                           |
| `AuthenticationRequirement`           | Shows whether single-factor or multi-factor authentication was required.                                        |
| `RiskState` / `RiskLevelDuringSignIn` | Identity Protection risk context. Helps prioritize risky sign-ins.                                              |
| `AppDisplayName`                      | Application accessed. Useful for identifying targeted apps like Office 365, Azure Portal, SharePoint, or Teams. |
| `Location` / `LocationDetails`        | Geographic location. Useful for impossible travel and foreign access review.                                    |
| `IsInteractive`                       | Distinguishes user-driven sign-ins from non-interactive/token-based activity.                                   |
| `AuthenticationDetails`               | Details of authentication steps and methods. Useful for MFA analysis.                                           |
| `ConditionalAccessPolicies`           | Shows which CA policies evaluated the sign-in.                                                                  |
| `DeviceDetail`                        | Device, OS, browser, and compliance-style context when available.                                               |

---

## Do not use this table for

| What you need                                                       | Use this instead                                     |
| ------------------------------------------------------------------- | ---------------------------------------------------- |
| On-prem Windows logons                                              | `SecurityEvent` or `DeviceLogonEvents`               |
| Endpoint process execution                                          | `DeviceProcessEvents`                                |
| Endpoint network connections                                        | `DeviceNetworkEvents`                                |
| Endpoint file activity                                              | `DeviceFileEvents`                                   |
| Email delivery, attachments, or URLs                                | `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` |
| User clicks on Safe Links URLs                                      | `UrlClickEvents`                                     |
| Cloud app activity after sign-in                                    | `CloudAppEvents`                                     |
| Audit changes such as user creation, app consent, or policy changes | `AuditLogs`                                          |

---

## Pivot next

| Starting point                    | Pivot to                               | Why                                                                   |
| --------------------------------- | -------------------------------------- | --------------------------------------------------------------------- |
| `UserPrincipalName`               | `SigninLogs`                           | Review full sign-in history for the account.                          |
| `UserPrincipalName`               | `CloudAppEvents`                       | Check what the user did after signing in.                             |
| `UserPrincipalName`               | Email tables                           | Check whether the account received phishing or sent suspicious email. |
| `IPAddress`                       | `SigninLogs`                           | Find other users authenticating from the same IP.                     |
| `IPAddress`                       | `DeviceNetworkEvents`                  | Check whether endpoints communicated with the same IP.                |
| `AppDisplayName`                  | `CloudAppEvents`                       | Review activity inside the targeted app.                              |
| `CorrelationId`                   | `SigninLogs` / related Entra logs      | Group related authentication events from the same flow.               |
| `DeviceDetail`                    | `DeviceInfo`                           | Match sign-in device context to endpoint inventory if possible.       |
| `ConditionalAccessPolicies`       | Entra Conditional Access policy review | Determine which policy allowed, blocked, or did not apply.            |
| `RiskState` / `RiskEventTypes_V2` | Identity Protection alerts             | Review why the sign-in was risky.                                     |

---

## Quick triage workflow

1. Start with `UserPrincipalName`, `IPAddress`, `AppDisplayName`, or `ResultType`.
2. Check `ResultType` to separate successful sign-ins from failed or interrupted attempts.
3. Review `IPAddress`, `Location`, and `LocationDetails` for unusual source context.
4. Check `AppDisplayName` to identify what application was accessed.
5. Review `AuthenticationRequirement` and `AuthenticationDetails` to confirm MFA behavior.
6. Review `ConditionalAccessStatus` and `ConditionalAccessPolicies` to understand policy decisions.
7. Check `RiskState`, `RiskLevelDuringSignIn`, and `RiskEventTypes_V2` for Identity Protection risk.
8. Use `IsInteractive` to separate actual user sign-ins from non-interactive/token activity.
9. Review `DeviceDetail`, `ClientAppUsed`, and `UserAgent` for device and client context.
10. Pivot to `CloudAppEvents` to determine what happened after successful access.

---

## Watch for

* Many failed sign-ins followed by a successful sign-in
* Multiple users failing from the same IP
* Successful sign-ins from unusual countries or locations
* `ResultType == 0` from suspicious IPs
* `ConditionalAccessStatus == "notApplied"` when a policy should have applied
* `AuthenticationRequirement == "singleFactorAuthentication"` for sensitive apps
* Risky sign-ins marked `atRisk` or `confirmedCompromised`
* Legacy or unusual `ClientAppUsed`
* Repeated non-interactive sign-ins after a suspicious interactive sign-in
* Sign-ins to sensitive apps such as Azure Portal, Exchange, SharePoint, Teams, or admin portals
* Guest users signing in from unexpected tenants or locations
* Unfamiliar devices, browsers, or user agents
* Token-related anomalies or unusual `TokenProtectionStatusDetails`
* Impossible travel patterns for the same user

---

## Helpful result filters

| Goal                           | KQL filter |                                                                  |
| ------------------------------ | ---------- | ---------------------------------------------------------------- |
| Successful sign-ins            | `          | where tostring(ResultType) == "0"`                               |
| Failed or interrupted sign-ins | `          | where tostring(ResultType) != "0"`                               |
| Interactive user activity      | `          | where IsInteractive == true`                                     |
| Non-interactive/token activity | `          | where IsInteractive == false`                                    |
| MFA required                   | `          | where AuthenticationRequirement =~ "multiFactorAuthentication"`  |
| Single-factor only             | `          | where AuthenticationRequirement =~ "singleFactorAuthentication"` |
| Risky sign-ins                 | `          | where IsRisky == true or RiskState =~ "atRisk"`                  |
| Conditional Access failure     | `          | where ConditionalAccessStatus =~ "failure"`                      |
| Conditional Access not applied | `          | where ConditionalAccessStatus =~ "notApplied"`                   |
| Specific app                   | `          | where AppDisplayName contains "<application name>"`              |
| Specific IP                    | `          | where IPAddress == "<source IP>"`                                |

---

## Mental model

Use `SigninLogs` when your main question is:

**“Did this identity successfully authenticate to the cloud, from where, to what app, with what MFA/Conditional Access/risk result?”**
