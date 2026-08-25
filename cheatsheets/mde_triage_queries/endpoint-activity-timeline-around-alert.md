# Endpoint Activity Timeline Around Alert

## Purpose

Use this query to quickly build a timeline of endpoint activity around the time an alert occurred.

It is useful as an **early investigation query** when you want to answer:

> **What was happening on this device immediately before and after the alert?**

The query combines several Microsoft Defender XDR tables and sorts the results chronologically.

---

## When to Use

Use this query when you have:

* An **alert timestamp**
* An **affected device name**
* An endpoint alert where you need additional context

This is especially useful at the beginning of an investigation when you are not yet sure which activity is important.

Examples include:

* Suspicious process execution
* PowerShell or command-line alerts
* Malware detections
* Suspicious logons
* Persistence alerts
* General endpoint alerts

---

## Query

Replace the values below with information from the alert.

```kusto
let AlertTime = datetime(<insert alert time>);
let AlertedDevice = "<insert device name>";

union withsource=TableName
    DeviceProcessEvents,
    DeviceLogonEvents,
    DeviceEvents,
    DeviceNetworkEvents,
    DeviceFileEvents,
    DeviceRegistryEvents
| where Timestamp between ((AlertTime - 5m) .. (AlertTime + 5m))
| where DeviceName =~ AlertedDevice
| sort by Timestamp asc
```

---

## What It Does

The query searches **5 minutes before and 5 minutes after the alert** and combines activity from:

| Table                  | Useful For                          |
| ---------------------- | ----------------------------------- |
| `DeviceProcessEvents`  | Process execution and command lines |
| `DeviceLogonEvents`    | User logons                         |
| `DeviceEvents`         | General endpoint/security activity  |
| `DeviceNetworkEvents`  | Network connections                 |
| `DeviceFileEvents`     | File creation and modification      |
| `DeviceRegistryEvents` | Registry activity                   |

The `TableName` column shows which Defender table each result came from.

---

## Reviewing the Results

Start at the alert time and review activity immediately before and after it.

Look for:

* Unexpected processes or command lines
* Suspicious PowerShell or scripting activity
* Unusual user logons
* Connections to unexpected IPs or domains
* Files created or modified
* Registry changes
* Activity that appears to continue after the alert

Use anything suspicious you find as a pivot into more targeted queries.

For example:

```text
Alert
  ↓
Review timeline
  ↓
Suspicious process found
  ↓
Investigate process activity
  ↓
Network/file/registry activity found
  ↓
Continue targeted triage
```

> **Note:** Because several tables are combined, some columns will be blank for certain rows. This is expected. Different event types contain different fields.

---

## Adjusting the Time Window

The default window is **5 minutes before and after the alert**.

For a wider investigation:

```kusto
| where Timestamp between ((AlertTime - 15m) .. (AlertTime + 15m))
```

Start with a small window to reduce noise, then expand it if you need more context.
