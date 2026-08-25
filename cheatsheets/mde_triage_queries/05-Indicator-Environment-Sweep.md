# Indicator Environment Sweep

## Purpose

Use this query when you identify a suspicious indicator and want to determine whether it appears elsewhere in the environment.

It helps answer:

> **Is this activity isolated to one device, or is the same indicator present elsewhere?**

This is useful for scoping potentially malicious activity.

## When to Use

Use this after identifying a suspicious:

* SHA1 hash
* IP address
* Domain
* File name
* Command-line fragment

You can fill in one or more indicators.

Leave unused values blank.

## Query

```kusto
let StartTime = ago(7d);

// Fill in one or more indicators.
// Leave unused values as "".
let IOC_SHA1 = "";
let IOC_IP = "";
let IOC_Domain = "";
let IOC_FileName = "";
let IOC_CommandLine = "";

union
(
    DeviceProcessEvents
    | where Timestamp > StartTime
    | where
        (isnotempty(IOC_SHA1) and SHA1 =~ IOC_SHA1)
        or
        (isnotempty(IOC_FileName) and FileName =~ IOC_FileName)
        or
        (isnotempty(IOC_CommandLine) and ProcessCommandLine contains IOC_CommandLine)
    | project
        Timestamp,
        DeviceName,
        Category = "Process",
        MatchedItem = FileName,
        User = AccountName,
        Process = FileName,
        Details = strcat(
            ProcessCommandLine,
            " | SHA1: ",
            SHA1
        )
),
(
    DeviceNetworkEvents
    | where Timestamp > StartTime
    | where
        (isnotempty(IOC_IP) and RemoteIP == IOC_IP)
        or
        (isnotempty(IOC_Domain) and RemoteUrl contains IOC_Domain)
        or
        (isnotempty(IOC_SHA1) and InitiatingProcessSHA1 =~ IOC_SHA1)
        or
        (isnotempty(IOC_FileName) and InitiatingProcessFileName =~ IOC_FileName)
    | project
        Timestamp,
        DeviceName,
        Category = "Network",
        MatchedItem = coalesce(RemoteUrl, RemoteIP),
        User = InitiatingProcessAccountName,
        Process = InitiatingProcessFileName,
        Details = strcat(
            RemoteIP,
            ":",
            tostring(RemotePort),
            " | ",
            RemoteUrl
        )
),
(
    DeviceFileEvents
    | where Timestamp > StartTime
    | where
        (isnotempty(IOC_SHA1) and SHA1 =~ IOC_SHA1)
        or
        (isnotempty(IOC_FileName) and FileName =~ IOC_FileName)
        or
        (isnotempty(IOC_SHA1) and InitiatingProcessSHA1 =~ IOC_SHA1)
    | project
        Timestamp,
        DeviceName,
        Category = "File",
        MatchedItem = FileName,
        User = InitiatingProcessAccountName,
        Process = InitiatingProcessFileName,
        Details = strcat(
            FolderPath,
            "\\",
            FileName,
            " | SHA1: ",
            SHA1
        )
)
| order by Timestamp asc
```

## Example Inputs

### Search for a hash

```kusto
let IOC_SHA1 = "<insert sha1>";
let IOC_IP = "";
let IOC_Domain = "";
let IOC_FileName = "";
let IOC_CommandLine = "";
```

### Search for an IP

```kusto
let IOC_SHA1 = "";
let IOC_IP = "<insert ip>";
let IOC_Domain = "";
let IOC_FileName = "";
let IOC_CommandLine = "";
```

### Search for a domain

```kusto
let IOC_SHA1 = "";
let IOC_IP = "";
let IOC_Domain = "<insert domain>";
let IOC_FileName = "";
let IOC_CommandLine = "";
```

## What to Look For

Review:

* Number of affected devices
* Number of affected users
* Which processes are associated with the indicator
* Whether the activity occurs repeatedly
* Whether the same indicator appears across multiple endpoints
* Whether the activity is concentrated around the same time

The main question is:

> **Is this one isolated event or part of broader activity?**

## Important Note

A match does not automatically mean the activity is malicious.

Common software, shared infrastructure, internal tools, or legitimate domains may appear across many systems.

Use prevalence as context, not as the final verdict.

## Next Step

If the indicator appears on additional systems, investigate those systems and determine whether the same behavior is occurring there.

If the indicator is isolated, return to the original alert and use the full body of evidence to make the disposition.
