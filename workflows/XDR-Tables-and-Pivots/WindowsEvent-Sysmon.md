# `WindowsEvent`

## What this table answers

Use `WindowsEvent` to answer:

**“What did Sysmon record on this endpoint, and what event-specific details are inside `EventData`?”**

This table contains Sysmon telemetry. Most useful investigation details are nested inside `EventData`, so you usually query fields like:

```kql
EventData.CommandLine
EventData.Image
EventData.ParentImage
EventData.DestinationIp
EventData.TargetFilename
EventData.TargetObject
```

---

## Use this table when

Use `WindowsEvent` when investigating:

* Sysmon-specific endpoint telemetry
* Process creation from Sysmon Event ID `1`
* Network connections from Sysmon Event ID `3`
* Image/DLL loads from Sysmon Event ID `7`
* CreateRemoteThread or injection behavior from Sysmon Event ID `8`
* Process access events from Sysmon Event ID `10`
* File creation or deletion from Sysmon Event IDs `11`, `23`, or `26`
* Registry changes from Sysmon Event IDs `12`, `13`, or `14`
* Named pipe activity from Sysmon Event IDs `17` or `18`
* WMI activity from Sysmon Event IDs `19`, `20`, or `21`
* DNS queries from Sysmon Event ID `22`
* Clipboard capture from Sysmon Event ID `24`
* Cases where Sysmon has richer detail than standard `Device*` tables

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertComputer = "";
let alertEventID = "";
let alertUser = "";
let alertImage = "";
let alertCommandLineKeyword = "";
let alertParentImage = "";
let alertDestinationIp = "";
let alertDestinationPort = "";
let alertTargetFilename = "";
let alertTargetObject = "";
let alertHashKeyword = "";

WindowsEvent
| where TimeGenerated >= ago(lookback)
| where Provider == "Microsoft-Windows-Sysmon"
| where isempty(alertComputer) or Computer =~ alertComputer
| where isempty(alertEventID) or EventID == toint(alertEventID)
| where isempty(alertUser) or tostring(EventData.User) contains alertUser
| where isempty(alertImage) or tostring(EventData.Image) contains alertImage or tostring(EventData.ImageLoaded) contains alertImage
| where isempty(alertCommandLineKeyword) or tostring(EventData.CommandLine) contains alertCommandLineKeyword
| where isempty(alertParentImage) or tostring(EventData.ParentImage) contains alertParentImage
| where isempty(alertDestinationIp) or tostring(EventData.DestinationIp) == alertDestinationIp
| where isempty(alertDestinationPort) or tostring(EventData.DestinationPort) == alertDestinationPort
| where isempty(alertTargetFilename) or tostring(EventData.TargetFilename) contains alertTargetFilename
| where isempty(alertTargetObject) or tostring(EventData.TargetObject) contains alertTargetObject
| where isempty(alertHashKeyword) or tostring(EventData.Hashes) contains alertHashKeyword
| project-reorder TimeGenerated, Computer, EventID, EventRecordId, EventData, Provider, Channel
| order by TimeGenerated desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `Computer` + `EventID` first. After that, filter on the relevant `EventData` field for the Sysmon event type you are investigating.

```kql
WindowsEvent
| where TimeGenerated >= ago(7d)
| where Provider == "Microsoft-Windows-Sysmon"
| where Computer =~ "<device-name>"
| where EventID == <Sysmon Event ID>
| project-reorder TimeGenerated, Computer, EventID, EventData
| order by TimeGenerated desc
```

Alternative `where` lines you can swap in:

```kql
| where tostring(EventData.User) contains "<user>"
| where tostring(EventData.Image) contains "<process.exe>"
| where tostring(EventData.CommandLine) contains "<command keyword>"
| where tostring(EventData.ParentImage) contains "<parent-process.exe>"
| where tostring(EventData.DestinationIp) == "<destination IP>"
| where tostring(EventData.DestinationPort) == "<port>"
| where tostring(EventData.QueryName) contains "<domain>"
| where tostring(EventData.TargetFilename) contains "<file path or name>"
| where tostring(EventData.TargetObject) contains "<registry key or value>"
| where tostring(EventData.Hashes) contains "<hash>"
```

```kql
// Purpose: Shows Sysmon events for a host and Event ID so I can inspect event-specific details inside EventData, such as process, command line, network, file, registry, DNS, pipe, or injection fields.
```

---

## Key fields

| Field                                                   | Why it matters                                                                                                 |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `TimeGenerated`                                         | Sysmon event timestamp. Use this for timeline reconstruction.                                                  |
| `Computer`                                              | Device that generated the Sysmon event.                                                                        |
| `EventID`                                               | Sysmon event type. Start here because it determines which `EventData` fields matter.                           |
| `EventData.CommandLine`                                 | Full command line for process creation events. Useful for malicious parameters, scripts, and encoded commands. |
| `EventData.Image`                                       | Process executable path. Helps identify the process involved.                                                  |
| `EventData.ParentImage`                                 | Parent process path. Useful for process ancestry.                                                              |
| `EventData.User`                                        | User context. Helps identify the account involved.                                                             |
| `EventData.DestinationIp` / `EventData.DestinationPort` | Network destination fields for Sysmon Event ID `3`.                                                            |
| `EventData.TargetFilename`                              | File path for file creation, stream creation, and deletion events.                                             |
| `EventData.TargetObject`                                | Registry path for registry events.                                                                             |
| `EventData.Hashes`                                      | File hashes, often with multiple algorithms. Useful for IOC correlation.                                       |
| `EventRecordId`                                         | Unique event record number on the host. Useful for precise event tracking.                                     |

---

## Do not use this table for

| What you need                        | Use this instead       |
| ------------------------------------ | ---------------------- |
| Standard Defender process telemetry  | `DeviceProcessEvents`  |
| Standard Defender network telemetry  | `DeviceNetworkEvents`  |
| Standard Defender file telemetry     | `DeviceFileEvents`     |
| Standard Defender registry telemetry | `DeviceRegistryEvents` |
| Standard Defender logon telemetry    | `DeviceLogonEvents`    |
| Device inventory or asset context    | `DeviceInfo`           |

---

## Pivot next

| Starting point                                          | Pivot to                                            | Why                                                              |
| ------------------------------------------------------- | --------------------------------------------------- | ---------------------------------------------------------------- |
| `Computer`                                              | `DeviceInfo`                                        | Get device context, exposure, OS, users, and sensor health.      |
| `EventData.Image`                                       | `DeviceProcessEvents`                               | Compare Sysmon process details with Defender process telemetry.  |
| `EventData.CommandLine`                                 | `DeviceProcessEvents`                               | Find matching suspicious command lines.                          |
| `EventData.DestinationIp` / `EventData.DestinationPort` | `DeviceNetworkEvents`                               | Correlate Sysmon network events with Defender network telemetry. |
| `EventData.TargetFilename`                              | `DeviceFileEvents`                                  | Correlate file creation or deletion with Defender file events.   |
| `EventData.TargetObject`                                | `DeviceRegistryEvents`                              | Correlate registry changes with Defender registry events.        |
| `EventData.QueryName`                                   | `DeviceNetworkEvents`                               | Correlate DNS activity with network connections.                 |
| `EventData.Hashes`                                      | `DeviceFileCertificateInfo` / `DeviceProcessEvents` | Check file reputation, execution, and signing context.           |

---

## Quick Sysmon Event ID reference

|   Event ID | Meaning                         | Useful fields                                                                                             |
| ---------: | ------------------------------- | --------------------------------------------------------------------------------------------------------- |
|        `1` | Process creation                | `EventData.Image`, `EventData.CommandLine`, `EventData.ParentImage`, `EventData.User`, `EventData.Hashes` |
|        `3` | Network connection              | `EventData.Image`, `EventData.DestinationIp`, `EventData.DestinationPort`, `EventData.User`               |
|        `5` | Process terminated              | `EventData.Image`, `EventData.ProcessId`                                                                  |
|        `7` | Image/DLL loaded                | `EventData.Image`, `EventData.ImageLoaded`, `EventData.Hashes`                                            |
|        `8` | CreateRemoteThread              | `EventData.SourceImage`, `EventData.TargetImage`                                                          |
|       `10` | Process access                  | `EventData.SourceImage`, `EventData.TargetImage`, `EventData.GrantedAccess`                               |
|       `11` | File created                    | `EventData.TargetFilename`, `EventData.Image`                                                             |
|       `12` | Registry object created/deleted | `EventData.TargetObject`, `EventData.Image`                                                               |
|       `13` | Registry value set              | `EventData.TargetObject`, `EventData.Details`, `EventData.Image`                                          |
|       `14` | Registry object renamed         | `EventData.TargetObject`, `EventData.NewName`                                                             |
|       `15` | File stream created             | `EventData.TargetFilename`, `EventData.Hash`                                                              |
|    `17/18` | Named pipe created/connected    | `EventData.PipeName`, `EventData.Image`                                                                   |
| `19/20/21` | WMI activity                    | `EventData.EventType`, `EventData.Operation`                                                              |
|       `22` | DNS query                       | `EventData.QueryName`, `EventData.QueryResults`, `EventData.Image`                                        |
|       `23` | File deleted                    | `EventData.TargetFilename`, `EventData.Image`                                                             |
|       `24` | Clipboard capture               | `EventData.ClientInfo`, `EventData.Image`                                                                 |
|       `25` | Process tampering               | `EventData.Image`, `EventData.Type`                                                                       |
|       `26` | File delete logged              | `EventData.TargetFilename`, `EventData.Image`                                                             |

---

## Quick triage workflow

1. Start with `Computer` and `EventID`.
2. Use the Sysmon Event ID to understand what kind of event you are looking at.
3. Query the matching `EventData` fields for that event type.
4. For process activity, review `EventData.Image`, `EventData.CommandLine`, `EventData.ParentImage`, and `EventData.User`.
5. For network activity, review `EventData.DestinationIp`, `EventData.DestinationPort`, and `EventData.Image`.
6. For file activity, review `EventData.TargetFilename`.
7. For registry activity, review `EventData.TargetObject` and `EventData.Details`.
8. Pivot to the matching `Device*` table to confirm or expand the investigation.

---

## Watch for

* Event ID `1` with suspicious command lines
* Event ID `3` connections to suspicious IPs or ports
* Event ID `8` CreateRemoteThread activity
* Event ID `10` process access involving `lsass.exe`
* Event ID `22` DNS queries to suspicious domains
* Event ID `23` or `26` suspicious file deletion
* Event ID `12`, `13`, or `14` registry persistence or tampering
* Event ID `17` or `18` suspicious named pipes
* Event ID `19`, `20`, or `21` WMI persistence or activity
* Event ID `24` clipboard capture
* Missing or unexpected `EventData` fields for the selected Event ID

---

## Mental model

Use `WindowsEvent` when your main question is:

**“What did Sysmon see, and which `EventData` fields explain the event?”**

Start with:

**`Computer` + `EventID` + the right `EventData.<FieldName>`**
