# Process Activity Pivot

## Purpose

Use this query when you identify a process that needs a closer look.

It helps answer:

> **What did this specific process do?**

The query searches across multiple Defender tables so you can review the process's:

* Child processes
* Network activity
* File activity
* Registry activity
* Other device events

This helps avoid checking each table separately.

## When to Use

Use this after the **Endpoint Context Timeline** identifies a suspicious or unusual process.

You will need:

* Device ID
* Process ID
* Process Creation Time

Using both the PID and Process Creation Time helps make sure you are tracking the correct process instance.

## Query

Replace the values below with information from the alert or timeline.

```kusto
let AlertedDeviceId = "<insert device id>";
let AlertedPID = <insert process id>;
let AlertedProcessCreationTime = datetime(<insert process creation time>);
let StartTime = AlertedProcessCreationTime - 1m;
let EndTime = AlertedProcessCreationTime + 30m;

union
(
    DeviceProcessEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | where ProcessId == AlertedPID
    | where ProcessCreationTime == AlertedProcessCreationTime
    | project
        Timestamp,
        DeviceName,
        Category = "Target Process",
        ActionType,
        Process = FileName,
        Details = strcat(
            "CommandLine: ", ProcessCommandLine,
            " | Parent: ", InitiatingProcessFileName,
            " | ParentCmd: ", InitiatingProcessCommandLine
        )
),
(
    DeviceProcessEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | where InitiatingProcessId == AlertedPID
    | where InitiatingProcessCreationTime == AlertedProcessCreationTime
    | project
        Timestamp,
        DeviceName,
        Category = "Child Process",
        ActionType,
        Process = FileName,
        Details = strcat(
            "CommandLine: ", ProcessCommandLine,
            " | PID: ", tostring(ProcessId)
        )
),
(
    DeviceNetworkEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | where InitiatingProcessId == AlertedPID
    | where InitiatingProcessCreationTime == AlertedProcessCreationTime
    | project
        Timestamp,
        DeviceName,
        Category = "Network",
        ActionType,
        Process = InitiatingProcessFileName,
        Details = strcat(
            RemoteUrl,
            " | ",
            RemoteIP,
            ":",
            tostring(RemotePort)
        )
),
(
    DeviceFileEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | where InitiatingProcessId == AlertedPID
    | where InitiatingProcessCreationTime == AlertedProcessCreationTime
    | project
        Timestamp,
        DeviceName,
        Category = "File",
        ActionType,
        Process = InitiatingProcessFileName,
        Details = strcat(
            FolderPath, "\\", FileName,
            " | SHA1: ", SHA1
        )
),
(
    DeviceRegistryEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | where InitiatingProcessId == AlertedPID
    | where InitiatingProcessCreationTime == AlertedProcessCreationTime
    | project
        Timestamp,
        DeviceName,
        Category = "Registry",
        ActionType,
        Process = InitiatingProcessFileName,
        Details = strcat(
            RegistryKey,
            "\\",
            RegistryValueName,
            " | ",
            RegistryValueData
        )
),
(
    DeviceEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | where InitiatingProcessId == AlertedPID
    | where InitiatingProcessCreationTime == AlertedProcessCreationTime
    | project
        Timestamp,
        DeviceName,
        Category = "Device Event",
        ActionType,
        Process = InitiatingProcessFileName,
        Details = tostring(AdditionalFields)
)
| order by Timestamp asc
```

## What to Look For

Review whether the process:

* Spawned unusual child processes
* Used suspicious command lines
* Connected to unexpected IPs or domains
* Created executables, scripts, DLLs, or archives
* Modified the registry
* Triggered additional Defender events

The goal is to understand the **behavior of the process**, not just whether the process name itself looks suspicious.

## Next Step

If you see a network connection followed by file creation, use:

**Network to File Correlation**

That query helps answer:

> **Did this process possibly download or create a file after making a network connection?**
