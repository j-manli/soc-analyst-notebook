# `DeviceFileEvents`

## What this table answers

Use `DeviceFileEvents` to answer:

**“What happened to this file on the endpoint, where did it come from, what process touched it, and did it move, change, or get deleted?”**

This table helps investigate file creation, modification, deletion, rename, movement, download, staging, and remote file activity.

---

## Use this table when

Use `DeviceFileEvents` when investigating:

* Malware drops or suspicious file creation
* Files downloaded from the internet
* Suspicious files in `Downloads`, `Desktop`, `Temp`, `AppData`, startup folders, or system directories
* File deletion or evidence tampering
* Ransomware-style mass file modification or renaming
* Data staging before exfiltration
* Archives created for possible exfiltration
* Remote file copies over SMB or NFS
* Lateral movement artifacts such as PsExec-style file drops
* Sensitive documents copied, moved, renamed, or deleted
* USB or removable-media file activity, depending on available path data

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql id="4v8g6d"
let lookback = 7d;
let alertDeviceName = "";
let alertActionType = "";
let alertFileName = "";
let alertFolderPath = "";
let alertSHA1 = "";
let alertOriginUrl = "";
let alertOriginIP = "";
let alertInitiatingProcess = "";
let alertCommandLineKeyword = "";
let alertRequestSourceIP = "";
let alertRequestAccount = "";

DeviceFileEvents
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertActionType) or ActionType contains alertActionType
| where isempty(alertFileName) or FileName =~ alertFileName
| where isempty(alertFolderPath) or FolderPath contains alertFolderPath
| where isempty(alertSHA1) or SHA1 =~ alertSHA1
| where isempty(alertOriginUrl) or FileOriginUrl contains alertOriginUrl or FileOriginReferrerUrl contains alertOriginUrl
| where isempty(alertOriginIP) or FileOriginIP == alertOriginIP
| where isempty(alertInitiatingProcess) or InitiatingProcessFileName =~ alertInitiatingProcess
| where isempty(alertCommandLineKeyword) or InitiatingProcessCommandLine contains alertCommandLineKeyword
| where isempty(alertRequestSourceIP) or RequestSourceIP == alertRequestSourceIP
| where isempty(alertRequestAccount) or RequestAccountName =~ alertRequestAccount or InitiatingProcessAccountName =~ alertRequestAccount or InitiatingProcessAccountUpn =~ alertRequestAccount
| project-reorder Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, FileSize, FileOriginUrl, FileOriginIP, RequestProtocol, RequestSourceIP, RequestAccountName, ShareName, PreviousFileName, PreviousFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `SHA1` when investigating a known file hash. Use `DeviceName` + `FileName` or `FolderPath` when investigating a file on a specific endpoint. Use `ActionType` when investigating behavior such as creation, deletion, modification, or rename activity.

```kql id="xfieqo"
DeviceFileEvents
| where Timestamp >= ago(7d)
| where DeviceName =~ "<device-name>"
| where FileName =~ "<file-name>"
| project-reorder Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, FileOriginUrl, FileOriginIP, RequestProtocol, RequestSourceIP, RequestAccountName, ShareName, PreviousFileName, PreviousFolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, FileSize
| order by Timestamp desc
```

Alternative `where` lines you can swap in:

```kql id="6i9bkd"
| where SHA1 =~ "<SHA1>"
| where ActionType contains "<FileCreated/FileDeleted/FileRenamed/FileModified>"
| where FolderPath contains "<path keyword>"
| where FileOriginUrl contains "<download URL or domain>"
| where FileOriginIP == "<origin IP>"
| where RequestProtocol =~ "<SMB>"
| where RequestSourceIP == "<remote source IP>"
| where RequestAccountName =~ "<remote account>"
| where InitiatingProcessFileName =~ "<process.exe>"
| where InitiatingProcessCommandLine contains "<command keyword>"
```

---

## Key fields

| Field                                     | Why it matters                                                                                                    |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `ActionType`                              | Shows the file operation, such as created, deleted, renamed, or modified. Start here to understand what happened. |
| `FileName` / `FolderPath`                 | Shows the file and its location. Essential for identifying suspicious paths and tracking files.                   |
| `SHA1`                                    | File hash. Use this for threat intelligence and to find the same file on other devices.                           |
| `FileOriginUrl` / `FileOriginIP`          | Shows where a downloaded file came from. Important for phishing, drive-by downloads, and initial access.          |
| `RequestProtocol` / `RequestSourceIP`     | Helps identify remote file operations, such as SMB or NFS activity. Useful for lateral movement.                  |
| `PreviousFileName` / `PreviousFolderPath` | Shows original file name or location before rename/move. Useful for ransomware, evasion, and staging.             |
| `InitiatingProcessCommandLine`            | Shows the command that caused the file operation. Important for scripts, tools, and malicious parameters.         |
| `RequestAccountName`                      | Shows the account involved in remote file operations. Useful for identifying compromised accounts.                |
| `Timestamp`                               | Shows when the file event occurred. Essential for timeline reconstruction.                                        |
| `InitiatingProcessFileName`               | Shows the process that performed the file operation. Helps separate legitimate tools from malware.                |
| `FileSize`                                | Helps identify suspicious file sizes, such as tiny executables or large archives.                                 |
| `ShareName`                               | Shows SMB share name for remote operations. Useful for tracking lateral movement paths.                           |

---

## Do not use this table for

| What you need                                                              | Use this instead            |
| -------------------------------------------------------------------------- | --------------------------- |
| Process execution, parent/child relationships, or full command-line chains | `DeviceProcessEvents`       |
| Network connections                                                        | `DeviceNetworkEvents`       |
| Registry modifications, scheduled tasks, services, WMI, or system changes  | `DeviceEvents`              |
| File certificate or signature validation                                   | `DeviceFileCertificateInfo` |
| Authentication or logon activity                                           | `DeviceLogonEvents`         |

---

## Pivot next

| Starting point                                               | Pivot to                                    | Why                                                              |
| ------------------------------------------------------------ | ------------------------------------------- | ---------------------------------------------------------------- |
| `SHA1`                                                       | `DeviceProcessEvents`                       | Check whether the file executed.                                 |
| `SHA1`                                                       | `DeviceFileCertificateInfo`                 | Check whether the file is signed and trusted.                    |
| `SHA1`                                                       | `DeviceImageLoadEvents`                     | Check whether the file was loaded as a DLL or image.             |
| `DeviceName`                                                 | `DeviceProcessEvents`                       | Review process activity around the same time.                    |
| `DeviceName`                                                 | `DeviceNetworkEvents`                       | Check whether the device connected to suspicious infrastructure. |
| `DeviceName`                                                 | `DeviceLogonEvents`                         | Review who was logged on before or during the file activity.     |
| `InitiatingProcessFileName` / `InitiatingProcessCommandLine` | `DeviceProcessEvents`                       | Build process lineage for the file operation.                    |
| `FileOriginUrl` / `FileOriginIP`                             | `DeviceNetworkEvents`                       | Check related network activity or downloads.                     |
| `RequestSourceIP` / `RequestAccountName`                     | `DeviceLogonEvents` / `DeviceNetworkEvents` | Investigate remote file operations and lateral movement.         |
| `FolderPath` / `FileName`                                    | `DeviceFileEvents`                          | Hunt for the same file path or name across devices.              |

---

## Quick triage workflow

1. Start with `DeviceName`, `FileName`, `FolderPath`, or `SHA1`.
2. Check `ActionType` to understand what happened to the file.
3. Review `FolderPath` for suspicious locations like `Temp`, `AppData`, `Downloads`, startup folders, or system directories.
4. Review `SHA1` and `FileSize` to identify and scope the file.
5. Check `FileOriginUrl` and `FileOriginIP` to see whether the file was downloaded.
6. Check `InitiatingProcessFileName` and `InitiatingProcessCommandLine` to understand what caused the file event.
7. Check `PreviousFileName` and `PreviousFolderPath` for renames, moves, or ransomware-style behavior.
8. Check `RequestProtocol`, `RequestSourceIP`, `RequestAccountName`, and `ShareName` for remote file operations.
9. Pivot to process, network, certificate, and logon tables based on what you find.

---

## Watch for

* Executables, DLLs, scripts, archives, or ISO/IMG files created in user-writable paths
* Files created in `Temp`, `AppData`, `Downloads`, `Desktop`, startup folders, or system directories
* Suspicious file drops followed by process execution
* Files downloaded from suspicious URLs or IPs
* Mass file rename or modification activity
* File extensions associated with ransomware
* Large archives created before possible exfiltration
* Sensitive file names containing terms like `password`, `credential`, `finance`, `payroll`, or `confidential`
* Log or security tool files deleted
* Remote file copies over SMB
* PsExec-style service or file drops
* Files renamed shortly before or after execution

---

## Mental model

Use `DeviceFileEvents` when your main question is:

**“What happened to this file, where is it, where did it come from, and what process or user caused the file activity?”**
