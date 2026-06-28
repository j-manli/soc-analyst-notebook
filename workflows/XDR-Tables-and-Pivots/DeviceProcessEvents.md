# `DeviceProcessEvents`

## What this table answers

Use `DeviceProcessEvents` to answer:

**“What process ran, who ran it, where did it run from, what command line was used, and what spawned it?”**

This is the primary endpoint table for process execution, command-line analysis, and parent/child process investigation.

---

## Use this table when

Use `DeviceProcessEvents` when investigating:

* Malware execution
* Suspicious command lines
* Encoded or obfuscated PowerShell
* Suspicious scripts such as `.ps1`, `.vbs`, `.js`, `.hta`, or batch files
* LOLBin abuse such as `powershell.exe`, `cmd.exe`, `wmic.exe`, `certutil.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, or `bitsadmin.exe`
* Parent/child process relationships
* Webshell behavior, such as `w3wp.exe` spawning `cmd.exe` or PowerShell
* Credential dumping tools
* Remote execution using PsExec, WMI, WinRM, or remote PowerShell
* Processes running from unusual paths
* Privilege escalation or suspicious elevated execution
* Process activity after phishing, file download, or suspicious logon events

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql id="z235lz"
let lookback = 7d;
let alertDeviceName = "";
let alertFileName = "";
let alertFolderPath = "";
let alertSHA1 = "";
let alertAccount = "";
let alertCommandLineKeyword = "";
let alertParentProcess = "";
let alertParentCommandLineKeyword = "";
let alertLogonId = "";
let alertProcessId = "";

DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertFileName) or FileName =~ alertFileName
| where isempty(alertFolderPath) or FolderPath contains alertFolderPath
| where isempty(alertSHA1) or SHA1 =~ alertSHA1
| where isempty(alertAccount) or AccountName =~ alertAccount or AccountUpn =~ alertAccount
| where isempty(alertCommandLineKeyword) or ProcessCommandLine contains alertCommandLineKeyword
| where isempty(alertParentProcess) or InitiatingProcessFileName =~ alertParentProcess
| where isempty(alertParentCommandLineKeyword) or InitiatingProcessCommandLine contains alertParentCommandLineKeyword
| where isempty(alertLogonId) or LogonId == alertLogonId or InitiatingProcessLogonId == alertLogonId
| where isempty(alertProcessId) or ProcessId == toint(alertProcessId) or InitiatingProcessId == toint(alertProcessId)
| project-reorder Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA1, AccountName, AccountDomain, AccountUpn, LogonId, ProcessId, ProcessTokenElevation, ProcessIntegrityLevel, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessId, InitiatingProcessLogonId, ProcessVersionInfoCompanyName, ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `DeviceName` + `FileName` or `ProcessCommandLine` when investigating a specific process on an endpoint. Use `SHA1` when investigating a known malicious binary. Use `LogonId` when tying process execution to a specific user session.

```kql id="zxsmr8"
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where DeviceName =~ "<device-name>"
| where FileName =~ "<process.exe>"
| project-reorder Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA1, AccountName, AccountDomain, ProcessTokenElevation, ProcessIntegrityLevel, ProcessId, InitiatingProcessId, LogonId, ProcessVersionInfoCompanyName
| order by Timestamp desc
```

Alternative `where` lines you can swap in:

```kql id="6dj1zc"
| where SHA1 =~ "<SHA1>"
| where FolderPath contains "<path keyword>"
| where ProcessCommandLine contains "<command keyword>"
| where InitiatingProcessFileName =~ "<parent-process.exe>"
| where InitiatingProcessCommandLine contains "<parent command keyword>"
| where AccountName =~ "<username>"
| where AccountUpn =~ "<user@domain.com>"
| where LogonId == "<LogonId>"
| where ProcessId == <PID>
| where ProcessTokenElevation =~ "<Full/Limited/Default>"
| where ProcessIntegrityLevel =~ "<Low/Medium/High/System>"
```

```kql id="pivnae"
// Purpose: Shows process execution so I can confirm what ran, who ran it, the full command line, parent process context, hash, privilege level, and session identifiers for pivoting.
```

---

## Key fields

| Field                                                        | Why it matters                                                                                                    |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `ProcessCommandLine`                                         | Full command line with arguments. Critical for encoded commands, malicious parameters, scripts, and LOLBin abuse. |
| `FileName` / `FolderPath`                                    | Shows the executable name and path. Useful for spotting masquerading or execution from suspicious locations.      |
| `InitiatingProcessFileName` / `InitiatingProcessCommandLine` | Shows the parent process and parent command line. Critical for abnormal parent/child relationships.               |
| `SHA1`                                                       | Process file hash. Useful for threat intelligence and finding the same binary elsewhere.                          |
| `AccountName` / `AccountDomain`                              | Shows the user context. Useful for identifying compromised or abused accounts.                                    |
| `ProcessTokenElevation`                                      | Shows UAC elevation status. Useful for identifying elevated execution or possible UAC bypass.                     |
| `ProcessIntegrityLevel`                                      | Shows process integrity level, such as Low, Medium, High, or System. Useful for privilege context.                |
| `InitiatingProcessParentFileName`                            | Shows the grandparent process. Helpful for building process ancestry.                                             |
| `Timestamp`                                                  | Shows process creation time. Essential for timeline reconstruction.                                               |
| `ProcessId` / `InitiatingProcessId`                          | Process IDs. Useful for correlation with related events.                                                          |
| `LogonId`                                                    | Session identifier. Useful for correlating process, file, network, and logon activity in the same session.        |
| `ProcessVersionInfoCompanyName`                              | Company metadata. Useful for spotting unsigned, suspicious, or masquerading processes.                            |

---

## Do not use this table for

| What you need                                                             | Use this instead            |
| ------------------------------------------------------------------------- | --------------------------- |
| Network connections from a process                                        | `DeviceNetworkEvents`       |
| File creation, modification, deletion, or rename activity                 | `DeviceFileEvents`          |
| Endpoint logons and authentication events                                 | `DeviceLogonEvents`         |
| Registry modifications, scheduled tasks, services, WMI, or system changes | `DeviceEvents`              |
| DLL loads or module loading                                               | `DeviceImageLoadEvents`     |
| File signature/certificate trust                                          | `DeviceFileCertificateInfo` |

---

## Pivot next

| Starting point                      | Pivot to                                                    | Why                                                                             |
| ----------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `DeviceName` + `Timestamp`          | `DeviceFileEvents`                                          | Check files created, modified, downloaded, or deleted around process execution. |
| `DeviceName` + `Timestamp`          | `DeviceNetworkEvents`                                       | Check network connections made around the same time.                            |
| `DeviceName` + `Timestamp`          | `DeviceLogonEvents`                                         | Check who logged on before or during execution.                                 |
| `DeviceName` + `Timestamp`          | `DeviceEvents`                                              | Check registry, scheduled task, service, WMI, or tampering activity.            |
| `SHA1`                              | `DeviceProcessEvents`                                       | Hunt for the same process hash across devices.                                  |
| `SHA1`                              | `DeviceFileCertificateInfo`                                 | Check whether the executable is signed and trusted.                             |
| `FileName` / `FolderPath`           | `DeviceFileEvents`                                          | Check file creation or movement history.                                        |
| `ProcessId` / `InitiatingProcessId` | `DeviceNetworkEvents` / `DeviceFileEvents`                  | Correlate related activity from the same process.                               |
| `LogonId`                           | `DeviceFileEvents` / `DeviceNetworkEvents` / `DeviceEvents` | Correlate activity in the same user session.                                    |
| `AccountName`                       | `DeviceLogonEvents`                                         | Review authentication activity for the same account.                            |

---

## Quick triage workflow

1. Start with `DeviceName`, `FileName`, `ProcessCommandLine`, `SHA1`, `AccountName`, or `LogonId`.
2. Review `FileName` and `FolderPath` to identify what ran and from where.
3. Review `ProcessCommandLine` for suspicious arguments, encoded content, scripts, or LOLBin abuse.
4. Check `InitiatingProcessFileName` and `InitiatingProcessCommandLine` to understand the parent process.
5. Check `InitiatingProcessParentFileName` for grandparent context.
6. Review `AccountName`, `AccountDomain`, and `LogonId` to understand user/session context.
7. Review `ProcessTokenElevation` and `ProcessIntegrityLevel` for privilege context.
8. Pivot to `DeviceFileEvents` to see file activity caused by or near the process.
9. Pivot to `DeviceNetworkEvents` to see network activity caused by or near the process.
10. Pivot to `DeviceEvents` for persistence, registry, scheduled task, service, or tampering activity.

---

## Watch for

* Encoded PowerShell
* PowerShell with download, execution, bypass, hidden window, or encoded command flags
* `cmd.exe` spawning scripting tools
* Office apps spawning PowerShell, `cmd.exe`, `mshta.exe`, or `wscript.exe`
* Browsers spawning scripts or executables
* `w3wp.exe` spawning command shells
* `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, `wmic.exe`, or `schtasks.exe` with unusual arguments
* Processes running from `Temp`, `AppData`, `Downloads`, `Desktop`, or other user-writable paths
* Suspicious parent/child process relationships
* Credential dumping tools such as `procdump.exe` targeting `lsass.exe`
* High or System integrity processes launched unexpectedly
* Same suspicious SHA1 executing on multiple devices
* Missing or unusual company metadata
* Execution shortly after a suspicious email, URL click, download, or logon

---

## Mental model

Use `DeviceProcessEvents` when your main question is:

**“What ran, what launched it, what command was used, and what did I need to pivot to next?”**
