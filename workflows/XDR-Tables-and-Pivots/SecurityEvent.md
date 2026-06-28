# `SecurityEvent`

## What this table answers

Use `SecurityEvent` to answer:

**“What Windows security event happened, on which host, which account was involved, and what was the result?”**

This table is useful for Windows Security Event Logs, authentication activity, account changes, privilege events, service installs, log clearing, and audit-related events.

---

## Use this table when

Use `SecurityEvent` when investigating:

* Successful or failed Windows logons
* RDP logons
* Network logons
* Brute force or password spraying
* Account creation, deletion, or password changes
* Account lockouts
* Group membership changes
* Special privilege assignments
* Explicit credential usage
* Security log clearing
* Service installation events
* Audit policy changes
* Kerberos or NTLM authentication details

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertComputer = "";
let alertEventID = "";
let alertAccount = "";
let alertTargetUser = "";
let alertSubjectUser = "";
let alertIpAddress = "";
let alertWorkstationName = "";
let alertLogonType = "";
let alertServiceName = "";
let alertProcess = "";

SecurityEvent
| where TimeGenerated >= ago(lookback)
| where isempty(alertComputer) or Computer =~ alertComputer
| where isempty(alertEventID) or EventID == toint(alertEventID)
| where isempty(alertAccount) or Account contains alertAccount
| where isempty(alertTargetUser) or TargetUserName contains alertTargetUser
| where isempty(alertSubjectUser) or SubjectUserName contains alertSubjectUser
| where isempty(alertIpAddress) or IpAddress == alertIpAddress
| where isempty(alertWorkstationName) or WorkstationName contains alertWorkstationName
| where isempty(alertLogonType) or tostring(LogonType) == alertLogonType
| where isempty(alertServiceName) or ServiceName contains alertServiceName
| where isempty(alertProcess) or Process contains alertProcess
| project-reorder TimeGenerated, Computer, EventID, Activity, Account, AccountType, LogonType, IpAddress, WorkstationName, Status, SubStatus, FailureReason, TargetUserName, SubjectUserName, Process, ServiceName, ServiceFileName, EventRecordId
| order by TimeGenerated desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `Computer` + `EventID` when investigating a specific Windows event type on a host. Use `Account`, `TargetUserName`, `SubjectUserName`, `IpAddress`, or `LogonType` depending on whether the investigation is focused on authentication, account changes, or administrative activity.

```kql
SecurityEvent
| where TimeGenerated >= ago(7d)
| where Computer =~ "<device-name>"
| where EventID == <EventID>
| project-reorder TimeGenerated, Computer, EventID, Activity, Account, AccountType, LogonType, IpAddress, WorkstationName, Status, SubStatus, TargetUserName, SubjectUserName, Process, ServiceName
| order by TimeGenerated desc
```

Alternative `where` lines you can swap in:

```kql
| where Account contains "<account-name>"
| where TargetUserName contains "<target-user>"
| where SubjectUserName contains "<acting-user>"
| where IpAddress == "<source IP>"
| where WorkstationName contains "<source workstation>"
| where LogonType == 3
| where LogonType == 10
| where ServiceName contains "<service name>"
| where Process contains "<process name>"
| where EventID in (4624, 4625, 4648, 4672)
```

```kql
// Purpose: Shows Windows security events so I can confirm the event type, host, account, logon method, source IP/workstation, result, and any related process or service context.
```

---

## Key fields

| Field                  | Why it matters                                                                              |
| ---------------------- | ------------------------------------------------------------------------------------------- |
| `EventID`              | Windows Event ID. Start here to identify the event type.                                    |
| `Account`              | Main account associated with the event.                                                     |
| `AccountType`          | Shows whether the account is a user or machine account.                                     |
| `Computer`             | Host where the event occurred.                                                              |
| `TimeGenerated`        | Event timestamp. Useful for timeline reconstruction.                                        |
| `Activity`             | Human-readable event description.                                                           |
| `LogonType`            | Authentication method. Important values include `2` interactive, `3` network, and `10` RDP. |
| `IpAddress`            | Source IP for logon events.                                                                 |
| `WorkstationName`      | Source workstation for network logons.                                                      |
| `Status` / `SubStatus` | Status codes for logon results and failures.                                                |
| `TargetUserName`       | Account being accessed, changed, or targeted.                                               |
| `SubjectUserName`      | Account performing the action.                                                              |
| `Process`              | Process associated with the event, when available.                                          |
| `ServiceName`          | Service involved in service installation or service-related events.                         |

---

## Common Event IDs

| Event ID | Meaning                     | Why it matters                                                                      |
| -------: | --------------------------- | ----------------------------------------------------------------------------------- |
|   `4624` | Successful logon            | Confirms access. Check `LogonType`, `IpAddress`, and `Account`.                     |
|   `4625` | Failed logon                | Useful for brute force, password spraying, and access attempts.                     |
|   `4648` | Explicit credential logon   | Can indicate `runas`, PsExec, lateral movement, or credential misuse.               |
|   `4672` | Special privileges assigned | Important for admin or privileged logon review.                                     |
|   `4720` | User account created        | Possible persistence or unauthorized account creation.                              |
|   `4723` | Password change attempt     | Useful for account management review.                                               |
|   `4724` | Password reset attempt      | Important for admin account activity or compromise review.                          |
|   `4738` | User account changed        | Tracks account modifications.                                                       |
|   `4697` | Service installed           | Security log service installation event.                                            |
|   `7045` | New service installed       | System log service installation event. Useful for persistence and lateral movement. |
|   `1102` | Security audit log cleared  | High-priority evidence tampering indicator.                                         |
|     `21` | RDP session logon           | Terminal Services session activity, if collected.                                   |

---  

## Logon Types

| LogonType | Name                    | What it usually means                                                                                                                                      | Why it matters in triage                                                                                                  |
| --------: | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
|       `2` | Interactive             | User logged on locally at the keyboard or console.                                                                                                         | Normal for users at their own workstation, but suspicious on servers or sensitive systems.                                |
|       `3` | Network                 | Access over the network, such as SMB, file shares, remote service access, or lateral movement.                                                             | Very important for lateral movement investigations. Watch for unusual source IPs or accounts.                             |
|       `4` | Batch                   | Logon used by scheduled tasks or batch jobs.                                                                                                               | Can be normal, but review if tied to suspicious scheduled tasks or unexpected accounts.                                   |
|       `5` | Service                 | Logon used by a Windows service.                                                                                                                           | Normal for service accounts, but suspicious if an unusual account is used as a service.                                   |
|       `7` | Unlock                  | User unlocked an existing logged-on session.                                                                                                               | Useful for timeline context, especially around physical or interactive access.                                            |
|       `8` | NetworkCleartext        | Network logon where credentials may be sent in cleartext to the authentication package.                                                                    | Higher-risk. Review carefully, especially if seen from unusual systems or accounts.                                       |
|       `9` | NewCredentials          | Credentials were specified using a tool like `runas /netonly`. Local session remains the same, but outbound network connections use different credentials. | Important for credential misuse and lateral movement review.                                                              |
|      `10` | RemoteInteractive       | Remote interactive logon, usually RDP.                                                                                                                     | Very important for RDP investigations. Watch for unusual source IPs, public IPs, admin accounts, or after-hours activity. |
|      `11` | CachedInteractive       | User logged on using cached domain credentials, usually when a domain controller was unavailable.                                                          | Can be normal for laptops, but useful when checking offline or disconnected logons.                                       |
|      `12` | CachedRemoteInteractive | Cached credentials used for a remote interactive logon.                                                                                                    | Less common. Review carefully if seen during suspicious remote access activity.                                           |
|      `13` | CachedUnlock            | Unlock of a session using cached credentials.                                                                                                              | Usually timeline/context data, but may help confirm user activity when domain connectivity was unavailable.               |

### Quick triage notes

| Focus                            | Logon types to review                                                     |
| -------------------------------- | ------------------------------------------------------------------------- |
| Local console activity           | `2`, `7`, `11`, `13`                                                      |
| Lateral movement                 | `3`, `9`, `10`                                                            |
| RDP activity                     | `10`                                                                      |
| Scheduled task activity          | `4`                                                                       |
| Service account activity         | `5`                                                                       |
| Suspicious credential usage      | `8`, `9`, `10`                                                            |
| Brute force or password spraying | Usually `4625` events with repeated `LogonType` values, often `3` or `10` |

### Beginner reminder

For most SOC triage, pay closest attention to:

**`3` = Network logon**
**`10` = RDP / RemoteInteractive logon**
**`9` = NewCredentials / possible alternate credential use**
**`5` = Service logon**
**`4` = Scheduled task or batch logon**

--- 

## Do not use this table for

| What you need                       | Use this instead       |
| ----------------------------------- | ---------------------- |
| Process execution and command lines | `DeviceProcessEvents`  |
| Network connections                 | `DeviceNetworkEvents`  |
| File activity                       | `DeviceFileEvents`     |
| Registry activity                   | `DeviceRegistryEvents` |
| Sysmon telemetry                    | `WindowsEvent`         |
| Device inventory or asset context   | `DeviceInfo`           |

---

## Pivot next

| Starting point                    | Pivot to                                    | Why                                                               |
| --------------------------------- | ------------------------------------------- | ----------------------------------------------------------------- |
| `Computer`                        | `DeviceInfo`                                | Get device context, asset value, OS, exposure, and sensor health. |
| `Computer` + `TimeGenerated`      | `DeviceProcessEvents`                       | Check what processes ran around the event.                        |
| `Computer` + `TimeGenerated`      | `DeviceNetworkEvents`                       | Check network activity around the event.                          |
| `Account` / `TargetUserName`      | `DeviceLogonEvents`                         | Review endpoint logons for the same account.                      |
| `IpAddress`                       | `DeviceLogonEvents` / `DeviceNetworkEvents` | Find other activity from the same source IP.                      |
| `ServiceName` / `ServiceFileName` | `DeviceEvents` / `DeviceProcessEvents`      | Investigate service installation and execution.                   |
| `EventID == 1102`                 | `DeviceProcessEvents` / `DeviceEvents`      | Investigate possible log clearing or anti-forensics.              |
| `EventID == 4648`                 | `DeviceLogonEvents` / `DeviceProcessEvents` | Investigate explicit credential usage and lateral movement.       |

---

## Quick triage workflow

1. Start with `Computer`, `EventID`, `Account`, or `IpAddress`.
2. Check `EventID` and `Activity` to understand the event type.
3. For logons, review `LogonType`, `IpAddress`, `WorkstationName`, `Status`, and `SubStatus`.
4. For account changes, compare `SubjectUserName` and `TargetUserName`.
5. For service events, review `ServiceName` and `ServiceFileName`.
6. For failures, review `FailureReason`, `Status`, and `SubStatus`.
7. Pivot to `DeviceProcessEvents` to see what happened before or after the event.
8. Pivot to `DeviceLogonEvents` for richer endpoint logon context if available.
9. Treat `1102`, suspicious `4648`, unexpected `4672`, and service installs as higher priority.

---

## Watch for

* Many `4625` failures followed by a `4624` success
* `4624` with `LogonType == 10` from unusual IPs or workstations
* `4624` with `LogonType == 3` across multiple systems
* `4648` explicit credential usage from unusual processes or hosts
* `4672` for unexpected accounts
* `4720` new account creation
* `4724` password resets by unusual users
* `7045` or `4697` service installation with suspicious paths
* `1102` security audit log clearing
* Failed logons from public or unusual IPs
* Admin account use outside normal patterns
* Service accounts used interactively

---

## Mental model

Use `SecurityEvent` when your main question is:

**“What did Windows audit logging record, which account was involved, and does the event suggest suspicious access, account change, privilege use, or tampering?”**
