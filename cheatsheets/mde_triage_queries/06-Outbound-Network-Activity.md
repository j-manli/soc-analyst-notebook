# Outbound Network Activity

## Purpose

Use this query to review outbound network connections from an endpoint around the time of an alert.

It helps answer:

> **What did this device connect to, and which process/user initiated the connection?**

## When to Use

Use this when the **Endpoint Context Timeline** shows unexpected or suspicious network activity, or when the alert itself involves network communication.

You will need:

* Alert time
* Device ID

If you already know the exact suspicious process, use **Process Activity Pivot** instead, since that query already shows network activity for that specific process.

## Query

Replace the values below with information from the alert.

```kusto
let AlertTime = datetime(<insert alert time>);
let AlertedDeviceId = "<insert device id>";
let StartTime = AlertTime - 10m;
let EndTime = AlertTime + 10m;

DeviceNetworkEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceId == AlertedDeviceId
| where ActionType == "ConnectionSuccess"
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemoteIPType,
    RemoteUrl,
    RemotePort,
    Protocol,
    LocalIP,
    LocalPort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    InitiatingProcessId,
    InitiatingProcessCreationTime,
    InitiatingProcessParentFileName,
    InitiatingProcessSHA1
| order by Timestamp asc
```

## What to Look For

Review:

* Unexpected IP addresses or domains
* Connections from unusual processes
* Unusual destination ports
* Processes connecting immediately after execution
* Script interpreters or LOLBins making unexpected connections
* Connections associated with suspicious command lines
* Repeated connections to the same destination
* Internal connections that may represent lateral movement

Pay particular attention to the relationship between:

```text
Process
   ↓
Command Line
   ↓
Remote IP / Domain
   ↓
Destination Port
```

A connection is not suspicious just because the destination is unfamiliar. Determine whether the **process, user, destination, and purpose make sense together**.

## Public Internet Connections Only

If you specifically want to review connections to public IP addresses, add:

```kusto
| where RemoteIPType == "Public"
```

after the `ActionType` filter.

Do not use this filter when investigating possible lateral movement because internal/private connections would be excluded.

## Next Step

If you identify a suspicious destination:

**Indicator Environment Sweep**

Ask:

> **Are other devices communicating with this IP or domain?**

If you see a network connection followed by suspicious file creation:

**Network to File Correlation**

Ask:

> **Did this process potentially download or create a file after the connection?**

If the connection goes to another internal endpoint and appears suspicious:

**Inbound Connection Source**

can help correlate the connection from the other side.
