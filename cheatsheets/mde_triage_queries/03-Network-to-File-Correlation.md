# Network to File Correlation

## Purpose

Use this query when a process made a network connection and you want to determine whether it created a file shortly afterward.

It helps answer:

> **Did this process possibly download or create a file after making a network connection?**

This is useful for identifying possible payload downloads or follow-on file creation.

## When to Use

Use this when you already have a specific process you are investigating and you see both:

* Network activity
* File creation

You will need:

* Device ID
* Process ID
* Process Creation Time

## Query

Replace the values below with information from the alert or investigation.

```kusto
let AlertedDeviceId = "<insert device id>";
let AlertedPID = <insert process id>;
let AlertedProcessCreationTime = datetime(<insert process creation time>);

DeviceNetworkEvents
| where Timestamp > ago(1d)
| where DeviceId == AlertedDeviceId
| where InitiatingProcessId == AlertedPID
| where InitiatingProcessCreationTime == AlertedProcessCreationTime
| project
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessId,
    InitiatingProcessCreationTime,
    NetworkTimestamp = Timestamp,
    RemoteIP,
    RemoteUrl,
    RemotePort
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > ago(1d)
    | where ActionType == "FileCreated"
    | where DeviceId == AlertedDeviceId
    | where InitiatingProcessId == AlertedPID
    | where InitiatingProcessCreationTime == AlertedProcessCreationTime
    | project
        DeviceId,
        InitiatingProcessId,
        InitiatingProcessCreationTime,
        FileTimestamp = Timestamp,
        FileName,
        FolderPath,
        SHA1,
        FileOriginUrl,
        FileOriginIP
)
on DeviceId, InitiatingProcessId, InitiatingProcessCreationTime
| where FileTimestamp between (NetworkTimestamp .. NetworkTimestamp + 10m)
| extend SecondsAfterConnection =
    datetime_diff("second", FileTimestamp, NetworkTimestamp)
| project
    DeviceName,
    InitiatingProcessFileName,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    FileName,
    FolderPath,
    SHA1,
    FileOriginUrl,
    FileOriginIP,
    NetworkTimestamp,
    FileTimestamp,
    SecondsAfterConnection
| order by NetworkTimestamp asc
```

## What to Look For

Review:

* `RemoteIP` / `RemoteUrl`
* `FileName`
* `FolderPath`
* `SHA1`
* `FileOriginUrl`
* `FileOriginIP`
* Time between the network event and file creation

Pay particular attention to files such as:

* `.exe`
* `.dll`
* `.ps1`
* `.bat`
* `.cmd`
* `.js`
* `.vbs`
* Archives such as `.zip`

Also review whether the created file was later executed.

## Important Note

This query shows **timing correlation**.

A file being created after a network connection does not prove that the file was downloaded from that specific connection.

Use the destination, file origin fields, hash, process behavior, and surrounding telemetry to support your conclusion.

## Next Step

If the file or destination looks suspicious, the next useful query is:

**Indicator Environment Sweep**

That helps answer:

> **Does this hash, file, IP, or domain appear elsewhere in the environment?**
