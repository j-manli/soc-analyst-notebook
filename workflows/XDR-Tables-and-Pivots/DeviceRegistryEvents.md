# `DeviceRegistryEvents`

## What this table answers

Use `DeviceRegistryEvents` to answer:

**“What registry key or value changed, what data was written, and what process or account made the change?”**

This table helps investigate registry-based persistence, defense evasion, malware configuration, security setting changes, and registry tampering.

---

## Use this table when

Use `DeviceRegistryEvents` when investigating:

* Registry Run or RunOnce persistence
* Startup-related registry changes
* Defender, firewall, UAC, or security policy tampering
* Malware storing configuration in the registry
* WDigest or credential-related registry changes
* UAC bypass registry modifications
* Image File Execution Options abuse
* AppInit_DLLs persistence
* COM object hijacking
* Shell extension or CLSID changes
* Remote registry modifications
* Registry keys or values created, modified, deleted, moved, or renamed

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql id="t6lgyv"
let lookback = 7d;
let alertDeviceName = "";
let alertRegistryKey = "";
let alertRegistryValueName = "";
let alertRegistryValueData = "";
let alertActionType = "";
let alertInitiatingProcess = "";
let alertCommandLineKeyword = "";
let alertAccount = "";

DeviceRegistryEvents
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertRegistryKey) or RegistryKey contains alertRegistryKey or PreviousRegistryKey contains alertRegistryKey
| where isempty(alertRegistryValueName) or RegistryValueName contains alertRegistryValueName or PreviousRegistryValueName contains alertRegistryValueName
| where isempty(alertRegistryValueData) or RegistryValueData contains alertRegistryValueData or PreviousRegistryValueData contains alertRegistryValueData
| where isempty(alertActionType) or ActionType contains alertActionType
| where isempty(alertInitiatingProcess) or InitiatingProcessFileName =~ alertInitiatingProcess
| where isempty(alertCommandLineKeyword) or InitiatingProcessCommandLine contains alertCommandLineKeyword
| where isempty(alertAccount) or InitiatingProcessAccountName =~ alertAccount or InitiatingProcessAccountUpn =~ alertAccount
| project-reorder Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, RegistryValueType, PreviousRegistryKey, PreviousRegistryValueName, PreviousRegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessIntegrityLevel, ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `DeviceName` + `RegistryKey` when investigating a specific endpoint and registry path. Use `RegistryValueName` or `RegistryValueData` when investigating a specific setting, executable path, persistence value, or tampering indicator.

```kql id="vztrhl"
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where DeviceName =~ "<device-name>"
| where RegistryKey contains "<registry path or keyword>"
| project-reorder Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryValueType, InitiatingProcessAccountName, InitiatingProcessIntegrityLevel, PreviousRegistryKey
| order by Timestamp desc
```

Alternative `where` lines you can swap in:

```kql id="r8w826"
| where ActionType contains "<RegistryValueSet/RegistryKeyCreated/RegistryKeyDeleted>"
| where RegistryValueName contains "<value name>"
| where RegistryValueData contains "<value data, path, or command>"
| where PreviousRegistryValueData contains "<previous value>"
| where InitiatingProcessFileName =~ "<process.exe>"
| where InitiatingProcessCommandLine contains "<command keyword>"
| where InitiatingProcessAccountName =~ "<username>"
| where InitiatingProcessAccountUpn =~ "<user@domain.com>"
| where InitiatingProcessIntegrityLevel =~ "<High/System/Medium/Low>"
```

```kql id="1p1d8n"
// Purpose: Shows registry changes so I can confirm what key/value changed, what data was written, what it changed from, and what process/account made the change.
```

---

## Key fields

| Field                             | Why it matters                                                                                                           |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `RegistryKey`                     | Full registry path. Identifies the key that was modified, such as Run keys, Defender settings, or policy locations.      |
| `RegistryValueName`               | Name of the modified registry value. Shows the exact setting or persistence value.                                       |
| `RegistryValueData`               | Data written to the registry. Often reveals executable paths, commands, disabled settings, or malware configuration.     |
| `ActionType`                      | Shows the registry operation, such as value set, key created, or key deleted.                                            |
| `PreviousRegistryValueData`       | Shows the original value before modification. Useful for understanding what changed.                                     |
| `InitiatingProcessFileName`       | Process that made the registry change. Helps separate legitimate installers/admin tools from malware.                    |
| `InitiatingProcessCommandLine`    | Command line that modified the registry. Useful for detecting `reg.exe`, PowerShell, scripts, and suspicious parameters. |
| `RegistryValueType`               | Data type such as `REG_SZ`, `REG_DWORD`, or `REG_BINARY`. Helps interpret the registry data correctly.                   |
| `Timestamp`                       | Shows when the registry change occurred. Important for timeline reconstruction.                                          |
| `InitiatingProcessAccountName`    | Account context for the process that modified the registry.                                                              |
| `InitiatingProcessIntegrityLevel` | Privilege context of the modifying process. Useful for suspicious elevated or low-integrity behavior.                    |
| `PreviousRegistryKey`             | Original key location before move or rename operations.                                                                  |

---

## Do not use this table for

| What you need                                             | Use this instead      |
| --------------------------------------------------------- | --------------------- |
| Process execution and parent/child process chains         | `DeviceProcessEvents` |
| File creation, modification, deletion, or rename activity | `DeviceFileEvents`    |
| Network connections                                       | `DeviceNetworkEvents` |
| Logons and authentication events                          | `DeviceLogonEvents`   |
| Scheduled tasks, services, WMI, and broader system events | `DeviceEvents`        |

---

## Pivot next

| Starting point                                               | Pivot to                                   | Why                                                                             |
| ------------------------------------------------------------ | ------------------------------------------ | ------------------------------------------------------------------------------- |
| `InitiatingProcessFileName` / `InitiatingProcessCommandLine` | `DeviceProcessEvents`                      | Build the process chain that made the registry change.                          |
| `DeviceName` + `Timestamp`                                   | `DeviceProcessEvents`                      | Review processes around the registry modification.                              |
| `DeviceName` + `Timestamp`                                   | `DeviceFileEvents`                         | Check whether files referenced in registry values were created or modified.     |
| `RegistryValueData`                                          | `DeviceFileEvents` / `DeviceProcessEvents` | If the value contains a file path or command, investigate that file or command. |
| `DeviceName`                                                 | `DeviceEvents`                             | Check related system events such as services, scheduled tasks, or tampering.    |
| `DeviceName`                                                 | `DeviceLogonEvents`                        | Identify who was logged on before or during the change.                         |
| `RegistryKey` / `RegistryValueName`                          | `DeviceRegistryEvents`                     | Hunt for the same persistence or tampering pattern across devices.              |
| `InitiatingProcessAccountName`                               | `DeviceLogonEvents`                        | Review account access and possible compromised credential use.                  |

---

## Quick triage workflow

1. Start with `DeviceName`, `RegistryKey`, `RegistryValueName`, or `RegistryValueData`.
2. Check `ActionType` to understand whether the key/value was created, modified, deleted, moved, or renamed.
3. Review `RegistryKey` and `RegistryValueName` to identify the affected setting or persistence location.
4. Review `RegistryValueData` for suspicious paths, commands, disabled settings, or payload references.
5. Compare `PreviousRegistryValueData` to understand what changed.
6. Identify the modifying process with `InitiatingProcessFileName`.
7. Review `InitiatingProcessCommandLine` for `reg.exe`, PowerShell, scripts, or suspicious parameters.
8. Check `InitiatingProcessAccountName` and `InitiatingProcessIntegrityLevel` for user and privilege context.
9. Pivot to `DeviceProcessEvents` to build process lineage.
10. Pivot to `DeviceFileEvents` if the registry value references a file path.

---

## Watch for

* Run and RunOnce key modifications
* Registry values pointing to `Temp`, `AppData`, `Downloads`, or unusual executable paths
* `reg.exe` or PowerShell modifying security settings
* Defender tampering registry values
* UAC-related registry changes
* WDigest `UseLogonCredential` changes
* Image File Execution Options debugger values
* AppInit_DLLs changes
* COM/CLSID hijacking patterns
* Shell extension persistence
* Policy changes that weaken logging or security
* Registry changes followed by suspicious process execution
* Registry changes made by unusual processes or accounts
* Registry changes made with high or system integrity unexpectedly

---

## Mental model

Use `DeviceRegistryEvents` when your main question is:

**“What registry setting changed, what data was written, and does that change suggest persistence, tampering, or credential access preparation?”**
