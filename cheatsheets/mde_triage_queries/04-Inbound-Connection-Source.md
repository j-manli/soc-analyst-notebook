# Inbound Connection Source

## Purpose

Use this query when an endpoint accepted an inbound connection and you want to identify which Defender-monitored device likely initiated it.

It helps answer:

> **Which internal device and process connected to this endpoint?**

This is useful for investigating possible lateral movement or unexpected remote access.

## When to Use

Use this when you see:

* An inbound connection to an endpoint
* Unexpected SMB, RDP, WinRM, or other remote access
* Possible lateral movement between internal devices

You will need:

* Alert time
* Target device name

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

## What to Look For

Review:

* `SourceDevice`
* `SourceIP`
* `TargetPort`
* `InitiatingProcessFileName`
* `InitiatingProcessCommandLine`
* `InitiatingProcessAccountName`

Ask whether the source device, process, user, and destination port make sense together.

Examples of ports that may be relevant:

* `445` — SMB
* `3389` — RDP
* `5985` / `5986` — WinRM

## Important Note

No result does not necessarily mean the connection did not occur.

The source may be:

* A device not onboarded into Defender
* Behind NAT, VPN, or a proxy
* A network appliance
* A system where matching telemetry was unavailable

## Next Step

If you identify a suspicious source device, process, IP, or user, pivot into the relevant activity and scope it across the environment.

A common next query is:

**Indicator Environment Sweep**
