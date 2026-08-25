# Inbound Connection Source Triage

## Purpose

Use this query to identify which Defender-monitored device likely initiated an inbound connection to an alerted endpoint.

This is useful when investigating possible **lateral movement** or unexpected remote access between devices.

Common examples include:

* SMB
* RDP
* WinRM
* Remote administration
* Suspicious workstation-to-server connections

---

## When to Use

Use this query when an alert shows that a device **accepted an inbound connection** and you want to determine:

> **What device initiated the connection, and what process/user was responsible?**

You will need:

* The **alert time**
* The **device name** that accepted the inbound connection

---

## Query

Replace the values below with information from the alert.

```kusto
let AlertTime = datetime(<insert alert time>);
let AlertedDevice = "<insert device name>";

DeviceNetworkEvents
| where Timestamp between ((AlertTime - 5m) .. (AlertTime + 5m))
| where DeviceName =~ AlertedDevice
| where ActionType == "InboundConnectionAccepted"
| project
    TargetDevice = DeviceName,
    InboundTimestamp = Timestamp,
    SourceIP = RemoteIP,
    SourcePort = RemotePort,
    TargetIP = LocalIP,
    TargetPort = LocalPort
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp between ((AlertTime - 5m) .. (AlertTime + 5m))
    | where ActionType == "ConnectionSuccess"
    | project
        SourceDevice = DeviceName,
        OutboundTimestamp = Timestamp,
        SourceLocalIP = LocalIP,
        SourceLocalPort = LocalPort,
        DestinationIP = RemoteIP,
        DestinationPort = RemotePort,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessAccountName,
        InitiatingProcessId
)
on
    $left.SourceIP == $right.SourceLocalIP,
    $left.SourcePort == $right.SourceLocalPort,
    $left.TargetIP == $right.DestinationIP,
    $left.TargetPort == $right.DestinationPort
| where abs(datetime_diff("second", InboundTimestamp, OutboundTimestamp)) <= 120
| project
    InboundTimestamp,
    OutboundTimestamp,
    SourceDevice,
    SourceIP,
    SourcePort,
    TargetDevice,
    TargetIP,
    TargetPort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessId
| order by InboundTimestamp asc
```

## What It Does

The query looks at both sides of the connection:

```text
SOURCE DEVICE                       TARGET DEVICE
ConnectionSuccess   ----------->    InboundConnectionAccepted
```

It matches the connection using:

* Source IP
* Source port
* Destination IP
* Destination port
* Event timestamps within 2 minutes of each other

This helps reduce false matches and identify the device, process, and user that initiated the connection.

---

## Reviewing the Results

Focus on:

| Field                          | What to Check                               |
| ------------------------------ | ------------------------------------------- |
| `SourceDevice`                 | Device that initiated the connection        |
| `TargetDevice`                 | Device that accepted the connection         |
| `TargetPort`                   | Service being accessed, such as 445 or 3389 |
| `InitiatingProcessFileName`    | Process that initiated the connection       |
| `InitiatingProcessCommandLine` | Command/process context                     |
| `InitiatingProcessAccountName` | User associated with the connection         |

Once you identify the source, determine whether the **device, user, process, and destination port make sense together**.

For example, an administrator using an approved management tool may be expected. A user workstation running an unusual process that connects to several servers over SMB may require further investigation.

---

## If No Results Are Returned

No result does **not necessarily mean the connection did not occur**.

The source could be:

* A device not onboarded into Defender
* Behind NAT or another network device
* A VPN, proxy, or gateway
* A system where the corresponding network telemetry was not available

In those cases, use the `RemoteIP` from the inbound event as a pivot into other available network or endpoint telemetry.
