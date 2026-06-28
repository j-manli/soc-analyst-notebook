# `DeviceImageLoadEvents`

## What this table answers

Use `DeviceImageLoadEvents` to answer:

**“What DLL or image was loaded, where was it loaded from, and what process loaded it?”**

This table helps investigate DLL loading, sideloading, suspicious module loads, and possible injection-related activity.

---

## Use this table when

Use `DeviceImageLoadEvents` when investigating:

* DLL sideloading
* DLL search order hijacking
* Suspicious DLLs loaded from unusual paths
* Unsigned or untrusted DLLs loaded into important processes
* DLL injection or suspicious module loading
* Credential dumping indicators involving sensitive DLLs
* Browser plugins, extensions, or helper objects
* Rare DLL loads across endpoints
* DLLs loaded from `Temp`, `AppData`, `Downloads`, or user-writable paths
* Suspicious modules loaded by browsers, Office apps, `explorer.exe`, `svchost.exe`, or other trusted processes

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql id="h7mq0t"
let lookback = 7d;
let alertDeviceName = "";
let alertFileName = "";
let alertFolderPath = "";
let alertSHA1 = "";
let alertInitiatingProcess = "";
let alertCommandLineKeyword = "";
let alertAccount = "";
let alertActionType = "";

DeviceImageLoadEvents
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertFileName) or FileName =~ alertFileName
| where isempty(alertFolderPath) or FolderPath contains alertFolderPath
| where isempty(alertSHA1) or SHA1 =~ alertSHA1
| where isempty(alertInitiatingProcess) or InitiatingProcessFileName =~ alertInitiatingProcess
| where isempty(alertCommandLineKeyword) or InitiatingProcessCommandLine contains alertCommandLineKeyword
| where isempty(alertAccount) or InitiatingProcessAccountName =~ alertAccount or InitiatingProcessAccountUpn =~ alertAccount
| where isempty(alertActionType) or ActionType contains alertActionType
| project-reorder Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessIntegrityLevel, InitiatingProcessVersionInfoCompanyName, ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `SHA1` when investigating a known DLL or image hash. Use `DeviceName` + `FileName` or `FolderPath` when investigating a module loaded on a specific endpoint. Use `InitiatingProcessFileName` when investigating what a suspicious process loaded.

```kql id="y3gmb1"
DeviceImageLoadEvents
| where Timestamp >= ago(7d)
| where DeviceName =~ "<device-name>"
| where FileName =~ "<dll-or-image-name>"
| project-reorder Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessFolderPath, InitiatingProcessIntegrityLevel, InitiatingProcessVersionInfoCompanyName, InitiatingProcessAccountName
| order by Timestamp desc
```

Alternative `where` lines you can swap in:

```kql id="yveqrh"
| where SHA1 =~ "<SHA1>"
| where FolderPath contains "<path keyword>"
| where InitiatingProcessFileName =~ "<process.exe>"
| where InitiatingProcessCommandLine contains "<command keyword>"
| where InitiatingProcessAccountName =~ "<username>"
| where InitiatingProcessAccountUpn =~ "<user@domain.com>"
| where InitiatingProcessIntegrityLevel =~ "<High/System/Medium/Low>"
```

---

## Key fields

| Field                                     | Why it matters                                                                                           |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `FileName` / `FolderPath`                 | Shows the DLL or image and where it was loaded from. Critical for spotting sideloading or unusual paths. |
| `SHA1`                                    | Hash of the loaded image. Use this for threat intelligence and finding the same module elsewhere.        |
| `InitiatingProcessFileName`               | Shows the process that loaded the DLL. Helps identify the target or host process.                        |
| `InitiatingProcessCommandLine`            | Shows how the loading process was started. Useful for understanding context and suspicious parameters.   |
| `ActionType`                              | Shows the type of image load event. Useful for filtering load behavior.                                  |
| `Timestamp`                               | Shows when the DLL or image was loaded. Useful for timeline reconstruction.                              |
| `InitiatingProcessId`                     | Process ID of the loading process. Use with `DeviceProcessEvents` to build the process tree.             |
| `InitiatingProcessFolderPath`             | Shows where the loading process is located. Helps identify masquerading or suspicious paths.             |
| `InitiatingProcessIntegrityLevel`         | Shows the integrity level of the process. Useful for privilege context.                                  |
| `InitiatingProcessVersionInfoCompanyName` | Company metadata for the loading process. Useful for checking whether the process looks legitimate.      |
| `InitiatingProcessAccountName`            | Account context for the process that loaded the DLL.                                                     |

---

## Do not use this table for

| What you need                                                            | Use this instead            |
| ------------------------------------------------------------------------ | --------------------------- |
| Process creation, parent/child process chains, or command-line execution | `DeviceProcessEvents`       |
| File creation, deletion, rename, or modification                         | `DeviceFileEvents`          |
| Network connections                                                      | `DeviceNetworkEvents`       |
| Registry modifications, scheduled tasks, services, or system changes     | `DeviceEvents`              |
| General endpoint events                                                  | `DeviceEvents`              |
| File signature or certificate trust                                      | `DeviceFileCertificateInfo` |

---

## Pivot next

| Starting point                 | Pivot to                                     | Why                                                                     |
| ------------------------------ | -------------------------------------------- | ----------------------------------------------------------------------- |
| `SHA1`                         | `DeviceFileCertificateInfo`                  | Check whether the loaded DLL or image is signed and trusted.            |
| `SHA1`                         | `DeviceFileEvents`                           | Check where the file was created, modified, downloaded, or deleted.     |
| `SHA1`                         | `DeviceProcessEvents`                        | Check whether the same file executed as a process.                      |
| `DeviceName` + `Timestamp`     | `DeviceProcessEvents`                        | Build process timeline around the DLL load.                             |
| `InitiatingProcessId`          | `DeviceProcessEvents`                        | Find process creation and parent/child context for the loading process. |
| `InitiatingProcessFileName`    | `DeviceImageLoadEvents`                      | Review other DLLs loaded by the same process.                           |
| `FolderPath`                   | `DeviceImageLoadEvents` / `DeviceFileEvents` | Hunt for other modules loaded from suspicious paths.                    |
| `InitiatingProcessAccountName` | `DeviceLogonEvents`                          | Review account logons before or during the suspicious load.             |

---

## Quick triage workflow

1. Start with `DeviceName`, `FileName`, `FolderPath`, `SHA1`, or `InitiatingProcessFileName`.
2. Check the loaded image path using `FileName` and `FolderPath`.
3. Look for suspicious locations like `Temp`, `AppData`, `Downloads`, user profile folders, or unexpected app directories.
4. Identify the process that loaded it using `InitiatingProcessFileName`.
5. Review `InitiatingProcessCommandLine` and `InitiatingProcessFolderPath`.
6. Check whether the loading process should normally load that DLL.
7. Pivot on `SHA1` to `DeviceFileCertificateInfo` to check signature and trust.
8. Pivot to `DeviceProcessEvents` to understand the loading process and parent/child chain.
9. Pivot to `DeviceFileEvents` to see how the DLL arrived on disk.

---

## Watch for

* DLLs loaded from `Temp`, `AppData`, `Downloads`, `Desktop`, or other user-writable paths
* DLLs loaded by trusted processes from unusual directories
* Unsigned or untrusted DLLs loaded into system processes
* Suspicious DLLs loaded by browsers, Office apps, `explorer.exe`, `svchost.exe`, or security tools
* Sensitive DLLs associated with credential access, such as `vaultcli.dll`, `samlib.dll`, or `wdigest.dll`
* Empty or unusual `FolderPath` values
* Rare DLL names or DLLs seen on only one endpoint
* DLL loads shortly after suspicious file creation
* DLL loads shortly after suspicious process execution
* DLLs with names similar to legitimate Windows DLLs but located outside expected paths

---

## Mental model

Use `DeviceImageLoadEvents` when your main question is:

**“What module was loaded into this process, where did it come from, and does that load look normal for this process?”**
