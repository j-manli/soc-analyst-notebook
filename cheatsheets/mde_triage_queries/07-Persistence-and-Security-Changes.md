# Persistence and Security Changes

## Purpose

Use this query to look for changes that may allow activity to **survive a reboot, run again later, or weaken endpoint security controls**.

It helps answer:

> **Did the activity establish persistence or make security-relevant changes to the endpoint?**

## When to Use

Use this when:

* The alert or surrounding activity appears suspicious
* A suspicious process executed successfully
* Malware or a payload may have run
* You are preparing to escalate an endpoint
* You want to make sure suspicious activity did not establish persistence

You will need:

* Alert time
* Device ID

This is generally a **follow-on check**, not something you need to run for every obviously benign alert.

---

## Query

Replace the values below with information from the alert.

```kusto
let AlertTime = datetime(<insert alert time>);
let AlertedDeviceId = "<insert device id>";
let StartTime = AlertTime - 10m;
let EndTime = AlertTime + 60m;

union
(
    // Common registry locations associated with persistence
    DeviceRegistryEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | where
        RegistryKey contains @"\CurrentVersion\Run"
        or RegistryKey contains @"\CurrentVersion\RunOnce"
        or RegistryKey contains @"\Winlogon"
        or RegistryKey contains @"\Image File Execution Options"
        or RegistryKey contains @"\CurrentControlSet\Services"
    | project
        Timestamp,
        DeviceName,
        Category = "Registry",
        ActionType,
        Process = InitiatingProcessFileName,
        CommandLine = InitiatingProcessCommandLine,
        User = InitiatingProcessAccountName,
        Target = strcat(
            RegistryKey,
            "\\",
            RegistryValueName
        ),
        Details = RegistryValueData
),
(
    // Device events that may involve persistence or security controls
    DeviceEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | where
        ActionType contains "ScheduledTask"
        or ActionType contains "Service"
        or ActionType contains "Defender"
        or ActionType contains "Tamper"
        or ActionType contains "Firewall"
    | project
        Timestamp,
        DeviceName,
        Category = "Device Event",
        ActionType,
        Process = InitiatingProcessFileName,
        CommandLine = InitiatingProcessCommandLine,
        User = InitiatingProcessAccountName,
        Target = strcat(FolderPath, "\\", FileName),
        Details = tostring(AdditionalFields)
),
(
    // Common tools that may be used to create persistence
    DeviceProcessEvents
    | where Timestamp between (StartTime .. EndTime)
    | where DeviceId == AlertedDeviceId
    | where FileName in~ (
        "schtasks.exe",
        "sc.exe",
        "reg.exe"
    )
    | project
        Timestamp,
        DeviceName,
        Category = "Persistence Tool",
        ActionType,
        Process = FileName,
        CommandLine = ProcessCommandLine,
        User = AccountName,
        Target = "",
        Details = strcat(
            "Parent: ",
            InitiatingProcessFileName,
            " | ",
            InitiatingProcessCommandLine
        )
)
| order by Timestamp asc
```

## What to Look For

Pay attention to:

### Scheduled Tasks

Look for unexpected task creation or modification.

Ask:

* What command does the task execute?
* Who created it?
* Is the task name expected?
* Does it run a suspicious script or executable?

### Services

Look for newly created or modified services.

Pay attention to services pointing to:

* User-writable directories
* `%TEMP%`
* `%APPDATA%`
* Downloads
* Unknown executables or scripts

### Registry Persistence

Pay particular attention to changes involving:

```text
...\CurrentVersion\Run
...\CurrentVersion\RunOnce
...\Winlogon
...\Image File Execution Options
...\CurrentControlSet\Services
```

Determine what executable or command the registry value points to.

### Security Changes

Review events involving:

* Microsoft Defender
* Tamper protection
* Firewall configuration
* Other endpoint security controls

Ask:

> **Did something attempt to weaken or modify security protections?**

---

## Important Note

A result is **not automatically malicious**.

Legitimate software installers, management tools, Windows updates, and administrators commonly create services, scheduled tasks, and registry entries.

Always review:

```text
Who made the change?
        ↓
Which process made it?
        ↓
What command was used?
        ↓
What will execute later?
        ↓
Does that behavior make sense?
```

This query is intended as a **high-value triage check**, not an exhaustive persistence hunt.

## Next Step

If you find a suspicious executable, DLL, script, or hash referenced by a persistence mechanism, investigate the file next.

Use:

**File Trust and Signature Check**

That query will help answer:

> **Is this file signed, trusted, and consistent with legitimate software?**
