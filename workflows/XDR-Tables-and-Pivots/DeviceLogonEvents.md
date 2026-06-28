# `DeviceLogonEvents`

## What this table answers

Use `DeviceLogonEvents` to answer:

**“Who logged on to this endpoint, from where, how did they authenticate, did it succeed or fail, and was it suspicious?”**

This table helps investigate endpoint logons, failed logons, RDP activity, network logons, service logons, lateral movement, brute force, and compromised credential usage.

---

## Use this table when

Use `DeviceLogonEvents` when investigating:

* Successful or failed endpoint logons
* RDP or remote interactive logons
* Network logons that may indicate lateral movement
* Brute force or password spraying
* Successful logon after multiple failures
* Compromised credential usage
* Suspicious admin account usage
* Service account interactive logons
* After-hours access
* Public IP logon attempts
* NTLM usage or possible pass-the-hash activity
* Logon sessions that need to be correlated with process, file, or network activity

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql id="r6y0vs"
let lookback = 7d;
let alertDeviceName = "";
let alertAccount = "";
let alertActionType = "";
let alertLogonType = "";
let alertRemoteIP = "";
let alertRemoteDeviceName = "";
let alertProtocol = "";
let alertLogonId = "";
let alertFailureReason = "";
let alertInitiatingProcess = "";

DeviceLogonEvents
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertAccount) or AccountName =~ alertAccount or InitiatingProcessAccountName =~ alertAccount or InitiatingProcessAccountUpn =~ alertAccount
| where isempty(alertActionType) or ActionType =~ alertActionType
| where isempty(alertLogonType) or LogonType =~ alertLogonType
| where isempty(alertRemoteIP) or RemoteIP == alertRemoteIP
| where isempty(alertRemoteDeviceName) or RemoteDeviceName =~ alertRemoteDeviceName
| where isempty(alertProtocol) or Protocol =~ alertProtocol
| where isempty(alertLogonId) or LogonId == alertLogonId
| where isempty(alertFailureReason) or FailureReason contains alertFailureReason
| where isempty(alertInitiatingProcess) or InitiatingProcessFileName =~ alertInitiatingProcess
| project-reorder Timestamp, DeviceName, ActionType, LogonType, AccountName, AccountDomain, IsLocalAdmin, RemoteIP, RemoteIPType, RemoteDeviceName, RemotePort, Protocol, FailureReason, LogonId, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `DeviceName` + `AccountName` when investigating a specific user on a specific endpoint. Use `RemoteIP`, `RemoteDeviceName`, `LogonType`, or `ActionType` when investigating lateral movement, RDP, brute force, or failed logon activity.

```kql id="jj51kd"
DeviceLogonEvents
| where Timestamp >= ago(7d)
| where DeviceName =~ "<device-name>"
| where AccountName =~ "<account-name>"
| project-reorder Timestamp, DeviceName, ActionType, LogonType, AccountName, AccountDomain, RemoteIP, RemoteDeviceName, FailureReason, IsLocalAdmin, LogonId, Protocol, RemoteIPType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

Alternative `where` lines you can swap in:

```kql id="yi5oav"
| where ActionType =~ "<LogonSuccess or LogonFailed>"
| where LogonType =~ "<Interactive/RemoteInteractive/Network/Batch/Service>"
| where RemoteIP == "<remote IP>"
| where RemoteDeviceName =~ "<remote device>"
| where RemoteIPType =~ "<Public/Private/Loopback>"
| where Protocol =~ "<Kerberos/NTLM/Negotiate>"
| where FailureReason contains "<failure reason>"
| where IsLocalAdmin == true
| where LogonId == "<LogonId>"
| where InitiatingProcessFileName =~ "<process.exe>"
| where InitiatingProcessCommandLine contains "<command keyword>"
```

```kql id="6f81l6"
// Purpose: Shows endpoint logon activity so I can confirm who authenticated, from where, how they logged on, whether it succeeded or failed, and what session or process context to pivot from.
```

---

## Key fields

| Field                           | Why it matters                                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `ActionType`                    | Shows logon outcome, such as success or failure. Start here to separate access from attempts.                                  |
| `LogonType`                     | Shows how the logon occurred, such as interactive, RDP, network, batch, or service. Critical for lateral movement review.      |
| `AccountName` / `AccountDomain` | Shows the account involved. Use this to track suspected compromised credentials.                                               |
| `RemoteIP` / `RemoteDeviceName` | Shows the source of the logon. Important for RDP, lateral movement, and external access attempts.                              |
| `FailureReason`                 | Explains why a logon failed. Helps distinguish brute force from normal user mistakes or expired passwords.                     |
| `IsLocalAdmin`                  | Shows whether the account had local admin rights. Prioritize admin logons during triage.                                       |
| `LogonId`                       | Session identifier. Use this to correlate process, file, network, and system activity in the same session.                     |
| `Protocol`                      | Shows authentication protocol, such as Kerberos, NTLM, or Negotiate. NTLM may be important in lateral movement investigations. |
| `RemoteIPType`                  | Classifies the source IP, such as public, private, loopback, or reserved. Public IPs may indicate external access attempts.    |
| `Timestamp`                     | Shows when the authentication event occurred. Essential for timeline reconstruction.                                           |
| `InitiatingProcessFileName`     | Shows the process that triggered authentication. Useful for identifying tools like RDP, PsExec, scripts, or services.          |
| `InitiatingProcessCommandLine`  | Shows the command that initiated the logon, when available. Useful for context and suspicious tool usage.                      |

---

## Do not use this table for

| What you need                                                       | Use this instead                                                           |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Process execution and parent/child process chains                   | `DeviceProcessEvents`                                                      |
| File creation, modification, deletion, or rename activity           | `DeviceFileEvents`                                                         |
| Network connections from the endpoint                               | `DeviceNetworkEvents`                                                      |
| Registry changes, scheduled tasks, services, WMI, or system changes | `DeviceEvents`                                                             |
| Cloud or Entra ID sign-in activity                                  | `IdentityLogonEvents`, `AADSignInEventsBeta`, or sign-in logs if available |

---

## Pivot next

| Starting point                                               | Pivot to                                    | Why                                                  |
| ------------------------------------------------------------ | ------------------------------------------- | ---------------------------------------------------- |
| `LogonId`                                                    | `DeviceProcessEvents`                       | Find processes executed in the same logon session.   |
| `LogonId`                                                    | `DeviceFileEvents`                          | Find file activity tied to the same session.         |
| `LogonId`                                                    | `DeviceNetworkEvents`                       | Find network activity tied to the same session.      |
| `DeviceName`                                                 | `DeviceProcessEvents`                       | Review what happened on the device after the logon.  |
| `AccountName`                                                | `DeviceLogonEvents`                         | Track the account across other devices.              |
| `AccountName`                                                | Identity/sign-in tables                     | Check cloud or identity logons for the same account. |
| `RemoteIP`                                                   | `DeviceLogonEvents`                         | Find other devices accessed from the same source IP. |
| `RemoteIP`                                                   | `DeviceNetworkEvents`                       | Review network connections involving the same IP.    |
| `RemoteDeviceName`                                           | `DeviceLogonEvents` / `DeviceNetworkEvents` | Investigate lateral movement from a source host.     |
| `InitiatingProcessFileName` / `InitiatingProcessCommandLine` | `DeviceProcessEvents`                       | Review tool execution or parent process context.     |

---

## Quick triage workflow

1. Start with `DeviceName`, `AccountName`, `RemoteIP`, `LogonType`, or `ActionType`.
2. Check `ActionType` to determine success vs failure.
3. Review `LogonType` to understand how the account authenticated.
4. Check `RemoteIP`, `RemoteDeviceName`, and `RemoteIPType` for source context.
5. Review `AccountName`, `AccountDomain`, and `IsLocalAdmin`.
6. If failed logons are involved, review `FailureReason` and count repeated attempts.
7. If successful logon occurred after failures, treat it as higher priority.
8. Use `LogonId` to pivot into process, file, network, and system activity.
9. Review `Protocol`, especially for NTLM or unusual authentication patterns.
10. Check `InitiatingProcessFileName` and `InitiatingProcessCommandLine` for tool or service context.

---

## Watch for

* `LogonSuccess` after many `LogonFailed` events
* `RemoteInteractive` logons from unusual systems or public IPs
* `Network` logons from unexpected hosts
* NTLM usage in suspicious lateral movement scenarios
* Public `RemoteIPType`
* Service accounts performing interactive or RDP logons
* Admin accounts logging into unusual devices
* Logons outside normal working hours
* Multiple devices accessed by the same account in a short period
* Same `RemoteIP` attempting logons across multiple devices
* Failed logons with bad password or account locked reasons
* `IsLocalAdmin == true` for unexpected accounts
* Suspicious initiating processes tied to remote access tools

---

## Mental model

Use `DeviceLogonEvents` when your main question is:

**“Did this account access this endpoint, from where, by what logon method, and what did that session do next?”**
