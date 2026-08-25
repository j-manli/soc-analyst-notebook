# Process Network Connection to File Creation Triage

## Purpose

Use this query to determine whether a specific process made a network connection and then created a file within **10 minutes** of that connection.

This can help identify possible downloads or payload retrieval during alert triage.

## When to Use

Use this query when an alert or investigation provides:

* **Device ID**
* **Process ID (PID)**
* **Process Creation Time**

The Process Creation Time is important because PIDs can be reused. Using both the PID and creation time helps ensure the query is tracking the correct process instance.

---

## Query

Replace the values in the first three lines with information from the alert.

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
    RemoteUrl
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
        SHA1
)
on DeviceId, InitiatingProcessId, InitiatingProcessCreationTime
| where FileTimestamp between (NetworkTimestamp .. NetworkTimestamp + 10m)
| project
    DeviceName,
    InitiatingProcessFileName,
    RemoteIP,
    RemoteUrl,
    FileName,
    FolderPath,
    SHA1,
    NetworkTimestamp,
    FileTimestamp
| order by NetworkTimestamp asc
```

## What the Query Does

The query:

1. Finds network connections made by the alerted process.
2. Finds files created by that same process.
3. Matches the events using the Device ID, PID, and Process Creation Time.
4. Returns files created within **10 minutes after a network connection**.

## Reviewing the Results

Pay attention to:

| Field                       | What to Check                                   |
| --------------------------- | ----------------------------------------------- |
| `InitiatingProcessFileName` | Process responsible for the activity            |
| `RemoteIP` / `RemoteUrl`    | Destination contacted by the process            |
| `FileName`                  | File created after the connection               |
| `FolderPath`                | Where the file was written                      |
| `SHA1`                      | Hash to use for reputation or prevalence checks |
| `NetworkTimestamp`          | When the connection occurred                    |
| `FileTimestamp`             | When the file was created                       |

A result can indicate that the process **may have downloaded or created a file following network activity**.

> **Note:** This query shows correlation, not definitive proof that the file was downloaded from the listed IP or URL. Review the file, destination, process behavior, and surrounding telemetry before making a determination.

## Analyst Next Steps

If the activity looks suspicious:

* Check the reputation of the remote IP/domain.
* Check the file hash and file prevalence.
* Determine whether the created file was executed.
* Review child processes and follow-on network activity.
* Look for the same file or indicators on other devices.

## Adjusting the Time Range

The query searches the previous **1 day**:

```kusto
| where Timestamp > ago(1d)
```

Increase this if the alert is older, for example:

```kusto
| where Timestamp > ago(7d)
```

The network-to-file correlation window is currently **10 minutes**:

```kusto
| where FileTimestamp between (NetworkTimestamp .. NetworkTimestamp + 10m)
```

Adjust this window if needed for the investigation.
