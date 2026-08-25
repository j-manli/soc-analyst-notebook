# Endpoint Context Timeline

## Purpose

Use this query to review endpoint activity immediately before and after an alert.

It helps answer:

> **What was happening on this device around the time the alert occurred?**

This is a good first hunting query after you understand why the alert fired.

## When to Use

Use this when you have:

* Alert time
* Device ID

It gives you one timeline containing:

* Process activity
* Network activity
* File activity
* Registry activity
* Logons
* General device events

This helps avoid running each Defender table separately.

## Query

Replace the values below with information from the alert.

```kusto
let AlertTime = datetime(<insert alert time>);
let AlertedDeviceId = "<insert device id>";
let StartTime = AlertTime - 10m;
let EndTime = AlertTime + 10m;

union
(
    DeviceProcessEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | project
        Timestamp,
        DeviceName,
        Category = "Process",
        ActionType,
        User = AccountName,
        Process = FileName,
        CommandLine = ProcessCommandLine,
        Remote = "",
        Artifact = strcat(FolderPath, "\\", FileName),
        Details = strcat(
            "PID: ", tostring(ProcessId),
            " | Parent: ", InitiatingProcessFileName
        )
),
(
    DeviceNetworkEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | project
        Timestamp,
        DeviceName,
        Category = "Network",
        ActionType,
        User = InitiatingProcessAccountName,
        Process = InitiatingProcessFileName,
        CommandLine = InitiatingProcessCommandLine,
        Remote = strcat(
            RemoteUrl,
            " | ",
            RemoteIP,
            ":",
            tostring(RemotePort)
        ),
        Artifact = "",
        Details = strcat(
            "Local: ",
            LocalIP,
            ":",
            tostring(LocalPort)
        )
),
(
    DeviceFileEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | project
        Timestamp,
        DeviceName,
        Category = "File",
        ActionType,
        User = InitiatingProcessAccountName,
        Process = InitiatingProcessFileName,
        CommandLine = InitiatingProcessCommandLine,
        Remote = FileOriginUrl,
        Artifact = strcat(FolderPath, "\\", FileName),
        Details = strcat("SHA1: ", SHA1)
),
(
    DeviceRegistryEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | project
        Timestamp,
        DeviceName,
        Category = "Registry",
        ActionType,
        User = InitiatingProcessAccountName,
        Process = InitiatingProcessFileName,
        CommandLine = InitiatingProcessCommandLine,
        Remote = "",
        Artifact = strcat(RegistryKey, "\\", RegistryValueName),
        Details = RegistryValueData
),
(
    DeviceLogonEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | project
        Timestamp,
        DeviceName,
        Category = "Logon",
        ActionType,
        User = AccountName,
        Process = InitiatingProcessFileName,
        CommandLine = InitiatingProcessCommandLine,
        Remote = RemoteIP,
        Artifact = "",
        Details = strcat("LogonType: ", tostring(LogonType))
),
(
    DeviceEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | project
        Timestamp,
        DeviceName,
        Category = "Device Event",
        ActionType,
        User = InitiatingProcessAccountName,
        Process = InitiatingProcessFileName,
        CommandLine = InitiatingProcessCommandLine,
        Remote = "",
        Artifact = "",
        Details = tostring(AdditionalFields)
)
| order by Timestamp asc
```

## What to Look For

Review activity before and after the alert for:

* Suspicious or unusual process creation
* Strange command lines
* Unexpected outbound connections
* Files being created or modified
* Registry changes
* Unexpected logons
* Activity that continues after the alert

A clean timeline can support a benign assessment, but it should not be treated as proof that nothing malicious occurred.

## Next Step

If the timeline identifies a suspicious process, the next query to use is:

**Process Activity Pivot**

That query will help answer:

> **What did this specific process do?**
