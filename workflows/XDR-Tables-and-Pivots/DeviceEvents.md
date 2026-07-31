# `DeviceEvents`

## What this table is for

Use `DeviceEvents` to investigate **endpoint activity that does not fit cleanly into the more specialized device tables**.

This table is useful for system-level activity such as:

* Registry modifications
* Scheduled task creation
* Service installation or modification
* Security setting changes
* Defender or security tool tampering
* Firewall changes
* WMI activity
* User or group changes
* Remote system activity
* Other endpoint events that are not purely process, file, network, or logon events

Think of this as the **endpoint system activity and “catch-all” behavior table**.

---

## Use this table when investigating

Use `DeviceEvents` when the alert or investigation involves:

* Persistence mechanisms
* Scheduled task creation
* Registry Run key modifications
* Service installation or modification
* WMI activity or WMI persistence
* User account creation or modification
* Group membership changes
* Security policy changes
* Audit policy changes
* Firewall rule changes
* Event log clearing
* Microsoft Defender or EDR tampering
* Remote registry changes
* Remote scheduled task activity
* Suspicious system configuration changes
* Certificate store changes
* Driver loads or suspicious system manipulation

---

## Kickoff KQL query

Use this as your first-pass query for `DeviceEvents`.

Fill in whichever alert artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertDeviceName = "";
let alertActionType = "";
let alertAccount = "";
let alertInitiatingProcess = "";
let alertCommandLineKeyword = "";
let alertRegistryKeyword = "";
let alertRemoteIP = "";
let alertRemoteDeviceName = "";
let alertInitiatingProcessSHA1 = "";

DeviceEvents
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertActionType) or ActionType contains alertActionType
| where isempty(alertAccount) or AccountName =~ alertAccount or InitiatingProcessAccountName =~ alertAccount or InitiatingProcessAccountUpn =~ alertAccount
| where isempty(alertInitiatingProcess) or InitiatingProcessFileName =~ alertInitiatingProcess
| where isempty(alertCommandLineKeyword) or InitiatingProcessCommandLine contains alertCommandLineKeyword or ProcessCommandLine contains alertCommandLineKeyword
| where isempty(alertRegistryKeyword) or RegistryKey contains alertRegistryKeyword or RegistryValueName contains alertRegistryKeyword or RegistryValueData contains alertRegistryKeyword
| where isempty(alertRemoteIP) or RemoteIP == alertRemoteIP or InitiatingProcessRemoteSessionIP == alertRemoteIP
| where isempty(alertRemoteDeviceName) or RemoteDeviceName =~ alertRemoteDeviceName or InitiatingProcessRemoteSessionDeviceName =~ alertRemoteDeviceName
| where isempty(alertInitiatingProcessSHA1) or InitiatingProcessSHA1 =~ alertInitiatingProcessSHA1
| project-reorder
    Timestamp,
    DeviceName,
    DeviceId,
    ActionType,
    AccountDomain,
    AccountName,
    AccountSid,
    LogonId,
    FileName,
    FolderPath,
    SHA1,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    RemoteDeviceName,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA1,
    InitiatingProcessAccountName,
    InitiatingProcessAccountUpn,
    InitiatingProcessLogonId,
    ProcessTokenElevation,
    ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when you need to paste the KQL you used into a Sentinel incident comment.

Prioritize `DeviceName` + `ActionType` when you know what device and behavior you are investigating. If the alert is process-driven, use `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, or `InitiatingProcessSHA1`. If the alert is persistence-related, prioritize `ActionType`, `RegistryKey`, `RegistryValueName`, scheduled task actions, or service-related actions.

```kql
DeviceEvents
| where Timestamp >= ago(7d)
| where DeviceName =~ "<device-name>"
| where ActionType contains "<action type or keyword>"
| project-reorder Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine, RemoteDeviceName, RemoteIP, AccountName, AccountDomain, InitiatingProcessFileName, InitiatingProcessSHA1, LogonId, InitiatingProcessLogonId, ProcessTokenElevation
| order by Timestamp desc
```

Alternative `where` lines you can swap in depending on the alert artifact:

```kql id="31ebke"
| where DeviceName =~ "<device-name>"
| where ActionType contains "<ScheduledTaskCreated>"
| where ActionType contains "<RegistryValueSet>"
| where AccountName =~ "<username>"
| where InitiatingProcessAccountUpn =~ "<user@domain.com>"
| where InitiatingProcessFileName =~ "<process.exe>"
| where InitiatingProcessCommandLine contains "<command keyword>"
| where InitiatingProcessSHA1 =~ "<SHA1>"
| where RegistryKey contains "<registry path or keyword>"
| where RegistryValueName contains "<registry value>"
| where RegistryValueData contains "<registry data>"
| where RemoteIP == "<remote IP>"
| where RemoteDeviceName =~ "<remote device>"
| where ProcessTokenElevation =~ "<Full>"
```

## Network Protection Blocks and User Bypass

Microsoft Defender may record both an initial Network Protection block and a later user bypass for the same destination. A block event alone does not always mean access remained prevented.

```kusto
DeviceEvents
| where DeviceName has "HOSTNAME"
| where ActionType contains "NetworkProtection"
| project
    Timestamp,
    ActionType,
    RemoteUrl,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp asc
```

### Events to Review

* `ExploitGuardNetworkProtectionBlocked` — Network Protection blocked or warned on the connection.
* `NetworkProtectionUserBypassEvent` — the user selected an option to bypass the warning and continue.
* Subsequent browser or network activity — helps determine whether the destination was accessed after the bypass.

### Triage Notes

Confirm the following before concluding that access was prevented:

* Destination URL or domain
* Initiating process and command line
* Network Protection response category
* Whether a user-bypass event occurred
* Whether additional connections occurred after the bypass

> A Network Protection block may be followed by a user bypass. Review the full event sequence before determining whether access remained blocked.


Field priority for this table:

| Priority | Artifact                                                     | Why                                                                                                            |
| -------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| 1        | `DeviceName`                                                 | Best for scoping activity to the affected endpoint.                                                            |
| 2        | `ActionType`                                                 | Best for identifying the behavior type, such as registry change, scheduled task, service change, or tampering. |
| 3        | `InitiatingProcessFileName` / `InitiatingProcessCommandLine` | Best for understanding what caused the activity.                                                               |
| 4        | `AccountName` / `InitiatingProcessAccountUpn`                | Best for identifying the user or account context.                                                              |
| 5        | `RegistryKey` / `RegistryValueName` / `RegistryValueData`    | Best for persistence, policy, and configuration investigations.                                                |
| 6        | `RemoteIP` / `RemoteDeviceName`                              | Best for lateral movement or remote activity investigations.                                                   |
| 7        | `InitiatingProcessSHA1`                                      | Best for hunting activity caused by the same binary across devices.                                            |
| 8        | `LogonId` / `InitiatingProcessLogonId`                       | Best for tying activity to the same logon session.                                                             |

---

## Do not use this table for

`DeviceEvents` is broad, but it is not the best table for every endpoint question.

| What you need to investigate                                    | Better table to use     |
| --------------------------------------------------------------- | ----------------------- |
| Process execution chains, parent/child processes, command lines | `DeviceProcessEvents`   |
| Network connections from the endpoint                           | `DeviceNetworkEvents`   |
| File creation, modification, deletion, or rename activity       | `DeviceFileEvents`      |
| User logons and authentication events                           | `DeviceLogonEvents`     |
| DLL loads, module loads, or image load activity                 | `DeviceImageLoadEvents` |

---

## Questions this table helps answer

Use this table to answer:

* What system-level action occurred on the device?
* What type of activity was recorded?
* Which account was involved?
* What process caused the activity?
* Was a registry key or value modified?
* Was a scheduled task created or changed?
* Was a service installed or modified?
* Was Defender, firewall, logging, or security policy tampered with?
* Was remote activity involved?
* Was the activity performed with elevated privileges?
* Can this activity be tied to the same logon session as other suspicious events?
* Did the same binary cause similar activity on other devices?

---

## First fields to check

When starting triage, look at these fields first:

| Field                                                          | Why it matters                                                                                                         |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `Timestamp`                                                    | Shows when the event occurred. Useful for timeline reconstruction.                                                     |
| `DeviceName`                                                   | Shows which endpoint the activity occurred on.                                                                         |
| `DeviceId`                                                     | Unique device identifier. Useful when device names change or duplicate names exist.                                    |
| `ActionType`                                                   | Categorizes the event. Start here to understand what kind of activity occurred.                                        |
| `AccountDomain` / `AccountName`                                | Shows the account associated with the activity.                                                                        |
| `LogonId`                                                      | Helps correlate activity within the same logon session.                                                                |
| `RegistryKey`                                                  | Shows the registry path involved. Important for persistence and policy changes.                                        |
| `RegistryValueName`                                            | Shows the registry value modified. Useful for understanding what setting changed.                                      |
| `RegistryValueData`                                            | Shows the data written to the registry. Important for spotting payloads, paths, or commands.                           |
| `RemoteDeviceName` / `RemoteIP`                                | Helps identify remote systems involved in lateral movement or remote administration.                                   |
| `InitiatingProcessFileName`                                    | Shows the process that caused the event.                                                                               |
| `InitiatingProcessFolderPath`                                  | Shows where the initiating process was located. Useful for spotting suspicious paths.                                  |
| `InitiatingProcessCommandLine`                                 | Shows the command line used by the initiating process. Critical for suspicious scripts, LOLBins, and encoded commands. |
| `InitiatingProcessSHA1`                                        | File hash of the initiating process. Useful for hunting the same binary across the environment.                        |
| `InitiatingProcessAccountName` / `InitiatingProcessAccountUpn` | Shows the account context of the initiating process.                                                                   |
| `InitiatingProcessLogonId`                                     | Helps connect the initiating process to other activity in the same session.                                            |
| `ProcessTokenElevation`                                        | Shows whether the activity was performed with elevated privileges.                                                     |

---

## Important field groups

### Event identification fields

| Field        | Description                                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------------------ |
| `Timestamp`  | Event date and time in UTC.                                                                                  |
| `DeviceId`   | Unique device identifier.                                                                                    |
| `DeviceName` | Fully qualified domain name of the device.                                                                   |
| `ActionType` | Event category, such as scheduled task creation, registry value set, service installation, or policy change. |
| `ReportId`   | Event identifier. Use with `DeviceName` and `Timestamp` for uniqueness.                                      |

### File fields

| Field           | Description                                           |
| --------------- | ----------------------------------------------------- |
| `FileName`      | File name only.                                       |
| `FolderPath`    | Full directory path.                                  |
| `SHA1`          | SHA-1 file hash. Usually more populated than SHA-256. |
| `SHA256`        | SHA-256 file hash. May be less commonly populated.    |
| `MD5`           | MD5 file hash.                                        |
| `FileSize`      | File size in bytes.                                   |
| `FileOriginUrl` | Source URL where the file originated, if available.   |
| `FileOriginIP`  | Source IP where the file originated, if available.    |

### Account context fields

| Field           | Description                                                        |
| --------------- | ------------------------------------------------------------------ |
| `AccountDomain` | Domain of the account performing the action.                       |
| `AccountName`   | Username associated with the action. May show an Entra ID UPN.     |
| `AccountSid`    | Security identifier for the account.                               |
| `LogonId`       | Logon session identifier. Useful for correlating related activity. |

### Created process fields

| Field                            | Description                                                         |
| -------------------------------- | ------------------------------------------------------------------- |
| `ProcessId`                      | Process ID.                                                         |
| `ProcessCommandLine`             | Full command line of the created process, if relevant to the event. |
| `ProcessCreationTime`            | Time the process started.                                           |
| `ProcessTokenElevation`          | Privilege level, such as limited, default, or full.                 |
| `ProcessUniqueId`                | Unique process identifier, also called Process Start Key.           |
| `CreatedProcessSessionId`        | Windows session ID of the created process.                          |
| `IsProcessRemoteSession`         | Indicates whether the process ran in a remote session.              |
| `ProcessRemoteSessionDeviceName` | Source device for the remote session.                               |
| `ProcessRemoteSessionIP`         | Source IP for the remote session.                                   |

### Registry fields

| Field               | Description                         |
| ------------------- | ----------------------------------- |
| `RegistryKey`       | Full registry path.                 |
| `RegistryValueName` | Registry value name.                |
| `RegistryValueData` | Data written to the registry value. |

### Network and remote activity fields

| Field              | Description                                                    |
| ------------------ | -------------------------------------------------------------- |
| `RemoteUrl`        | URL or FQDN connected to, when relevant.                       |
| `RemoteDeviceName` | Remote system name. Useful for lateral movement investigation. |
| `RemoteIP`         | Remote IP address.                                             |
| `RemotePort`       | Remote TCP port.                                               |
| `LocalIP`          | Local device IP address.                                       |
| `LocalPort`        | Local TCP port.                                                |

### Initiating process fields

| Field                                      | Description                                                                  |
| ------------------------------------------ | ---------------------------------------------------------------------------- |
| `InitiatingProcessFileName`                | Process executable name that initiated the event.                            |
| `InitiatingProcessFolderPath`              | Full path of the initiating process.                                         |
| `InitiatingProcessId`                      | Process ID of the initiating process.                                        |
| `InitiatingProcessCommandLine`             | Full command line of the initiating process.                                 |
| `InitiatingProcessCreationTime`            | Time the initiating process started.                                         |
| `InitiatingProcessParentId`                | Parent process ID of the initiating process.                                 |
| `InitiatingProcessParentFileName`          | Parent process name or path.                                                 |
| `InitiatingProcessParentCreationTime`      | Parent process start time.                                                   |
| `InitiatingProcessUniqueId`                | Unique identifier for the initiating process, also called Process Start Key. |
| `InitiatingProcessSessionId`               | Windows session ID.                                                          |
| `IsInitiatingProcessRemoteSession`         | Indicates whether the initiating process ran in a remote session.            |
| `InitiatingProcessRemoteSessionDeviceName` | Source device for the initiating process remote session.                     |
| `InitiatingProcessRemoteSessionIP`         | Source IP for the initiating process remote session.                         |

### Initiating process hash fields

| Field                       | Description                                                             |
| --------------------------- | ----------------------------------------------------------------------- |
| `InitiatingProcessSHA1`     | SHA-1 hash of the initiating process. Usually more populated.           |
| `InitiatingProcessSHA256`   | SHA-256 hash of the initiating process. May be less commonly populated. |
| `InitiatingProcessMD5`      | MD5 hash of the initiating process.                                     |
| `InitiatingProcessFileSize` | Executable size in bytes.                                               |

### Initiating process account fields

| Field                              | Description                                            |
| ---------------------------------- | ------------------------------------------------------ |
| `InitiatingProcessAccountDomain`   | Domain of the account running the initiating process.  |
| `InitiatingProcessAccountName`     | Username running the initiating process.               |
| `InitiatingProcessAccountSid`      | Security identifier of the initiating process account. |
| `InitiatingProcessAccountUpn`      | User Principal Name of the initiating process account. |
| `InitiatingProcessAccountObjectId` | Entra ID object ID of the initiating process account.  |
| `InitiatingProcessLogonId`         | Logon session identifier for the initiating process.   |

### Initiating process version info fields

| Field                                          | Description                           |
| ---------------------------------------------- | ------------------------------------- |
| `InitiatingProcessVersionInfoCompanyName`      | Company name from file metadata.      |
| `InitiatingProcessVersionInfoProductName`      | Product name from file metadata.      |
| `InitiatingProcessVersionInfoProductVersion`   | Product version from file metadata.   |
| `InitiatingProcessVersionInfoInternalFileName` | Internal filename from file metadata. |
| `InitiatingProcessVersionInfoOriginalFileName` | Original filename from file metadata. |
| `InitiatingProcessVersionInfoFileDescription`  | File description from file metadata.  |

### Additional context fields

| Field                 | Description                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------- |
| `AppGuardContainerId` | Application Guard container ID.                                                                   |
| `AdditionalFields`    | Extra event data in JSON format. Review when the standard columns do not explain the event fully. |

---

## Common pivots from this table

| Starting point                                | Pivot to                                                           | Why                                                                       |
| --------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| `DeviceName`                                  | `DeviceProcessEvents`                                              | Review process execution around the same time.                            |
| `DeviceName`                                  | `DeviceFileEvents`                                                 | Check related file creation, modification, deletion, or rename activity.  |
| `DeviceName`                                  | `DeviceNetworkEvents`                                              | Check related outbound or inbound network connections.                    |
| `DeviceName`                                  | `DeviceLogonEvents`                                                | Review logons before or during the suspicious activity.                   |
| `InitiatingProcessFileName`                   | `DeviceProcessEvents`                                              | Build the process chain for the process that caused the event.            |
| `InitiatingProcessCommandLine`                | `DeviceProcessEvents`                                              | Search for similar suspicious command lines.                              |
| `InitiatingProcessSHA1`                       | `DeviceProcessEvents` / `DeviceEvents`                             | Hunt for the same binary executing or causing changes across devices.     |
| `AccountName` / `InitiatingProcessAccountUpn` | `DeviceLogonEvents`                                                | Check whether the same account logged into the device or other systems.   |
| `LogonId` / `InitiatingProcessLogonId`        | `DeviceProcessEvents` / `DeviceFileEvents` / `DeviceNetworkEvents` | Correlate activity within the same logon session.                         |
| `RegistryKey` / `RegistryValueName`           | `DeviceEvents`                                                     | Hunt for the same registry persistence or policy change across endpoints. |
| `RemoteIP` / `RemoteDeviceName`               | `DeviceNetworkEvents` / `DeviceLogonEvents`                        | Investigate lateral movement or remote access.                            |
| `FileName` / `FolderPath` / `SHA1`            | `DeviceFileEvents`                                                 | Review file activity related to the event.                                |

---

## Simple triage workflow

### 1. Start with the alert artifacts

Identify what the alert gives you:

* Device name
* Action type
* Account
* Initiating process
* Command line
* Registry key or value
* Remote IP or remote device
* File name or hash
* Logon ID

Use those values in the kickoff query.

---

### 2. Identify the event type

Review:

* `ActionType`
* `Timestamp`
* `DeviceName`

Ask yourself:

* What kind of system activity happened?
* Was it registry, scheduled task, service, policy, firewall, account, WMI, or tampering related?
* Is this action expected on this device?

`ActionType` is usually the best starting point in this table.

---

### 3. Identify the account context

Review:

* `AccountDomain`
* `AccountName`
* `AccountSid`
* `LogonId`
* `InitiatingProcessAccountName`
* `InitiatingProcessAccountUpn`
* `InitiatingProcessLogonId`

Ask yourself:

* Which account was involved?
* Was it a user, admin, service account, or system account?
* Does this account normally perform this type of action?
* Can the activity be tied to the same logon session as other suspicious events?

---

### 4. Identify the initiating process

Review:

* `InitiatingProcessFileName`
* `InitiatingProcessFolderPath`
* `InitiatingProcessCommandLine`
* `InitiatingProcessSHA1`
* `InitiatingProcessParentFileName`
* `ProcessTokenElevation`

Ask yourself:

* What process caused the event?
* Was it a normal admin tool or a suspicious executable?
* Did the command line contain encoded PowerShell, suspicious scripts, or unusual parameters?
* Was the process running from a suspicious path?
* Was it elevated?

If process lineage matters, pivot to `DeviceProcessEvents`.

---

### 5. Review registry or configuration changes

For registry-related events, review:

* `RegistryKey`
* `RegistryValueName`
* `RegistryValueData`

Ask yourself:

* Is this a Run key or autostart location?
* Is this a policy modification?
* Is the registry value launching a script, binary, or LOLBin?
* Is this related to Defender tampering, firewall changes, logging changes, or persistence?

---

### 6. Check for remote activity

Review:

* `RemoteDeviceName`
* `RemoteIP`
* `RemotePort`
* `IsInitiatingProcessRemoteSession`
* `InitiatingProcessRemoteSessionDeviceName`
* `InitiatingProcessRemoteSessionIP`

Ask yourself:

* Was another system involved?
* Does this look like remote administration or lateral movement?
* Was a scheduled task, WMI action, or registry change performed remotely?
* Does the remote source match expected admin infrastructure?

---

### 7. Pivot to surrounding endpoint activity

Use the same `DeviceName`, `Timestamp`, `AccountName`, `LogonId`, or `InitiatingProcessLogonId` to pivot to:

* `DeviceProcessEvents`
* `DeviceFileEvents`
* `DeviceNetworkEvents`
* `DeviceLogonEvents`

Ask yourself:

* What ran before and after this event?
* Were files created or modified?
* Did the device connect to suspicious infrastructure?
* Did a suspicious user log on before the event?
* Is this part of a larger attack chain?

---

## Common things to watch for

Pay attention to:

* Scheduled task creation by suspicious processes
* Registry Run key modifications
* Registry values launching PowerShell, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, or `regsvr32.exe`
* New or modified services
* Defender or EDR tampering
* Firewall rule changes
* Event log clearing
* Audit policy changes
* User account creation
* Group membership changes
* WMI event subscriptions
* Remote registry modifications
* Remote scheduled task creation
* Suspicious activity with `ProcessTokenElevation` showing full elevation
* Suspicious initiating processes running from `Temp`, `AppData`, `Downloads`, or user-writable paths
* Remote session indicators
* Same initiating process hash causing similar changes on multiple devices

---

## Beginner mental model

Use `DeviceEvents` when your main question is:

**“What system-level change happened on this endpoint, what process caused it, and does it suggest persistence, tampering, privilege abuse, or lateral movement?”**

Then pivot based on what you need next:

* Need process execution or parent/child chain? Go to `DeviceProcessEvents`.
* Need file creation, modification, or deletion? Go to `DeviceFileEvents`.
* Need network connections? Go to `DeviceNetworkEvents`.
* Need logon activity? Go to `DeviceLogonEvents`.
* Need DLL or image load details? Go to `DeviceImageLoadEvents`.
* Need to hunt the same registry change? Stay in `DeviceEvents` and pivot on `RegistryKey`, `RegistryValueName`, or `RegistryValueData`.
* Need to hunt the same binary? Pivot on `InitiatingProcessSHA1`.
