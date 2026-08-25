# File Trust and Prevalence Check

## Purpose

Use this query when you identify a file that needs additional validation.

It helps answer:

> **Is this file signed and trusted, and how common is it in our environment?**

The query checks:

* Digital signature status
* Certificate trust
* Signer and issuer
* Number of devices where the file was observed
* File locations
* Download origin information

## When to Use

Use this when you identify a suspicious or unknown:

* Executable
* DLL
* Script or tool
* Downloaded file
* SHA1 hash

You will need the file's **SHA1**.

---

## Query

Replace the SHA1 with the file you are investigating.

```kusto
let TargetSHA1 = "<insert sha1>";
let Lookback = 7d;

DeviceFileEvents
| where Timestamp > ago(Lookback)
| where SHA1 =~ TargetSHA1
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    DeviceCount = dcount(DeviceId),
    Devices = make_set(DeviceName, 25),
    FilePaths = make_set(FolderPath, 25),
    OriginUrls = make_set(FileOriginUrl, 10),
    OriginIPs = make_set(FileOriginIP, 10),
    InitiatingProcesses = make_set(InitiatingProcessFileName, 25)
    by SHA1, FileName
| join kind=leftouter (
    DeviceFileCertificateInfo
    | where SHA1 =~ TargetSHA1
    | summarize arg_max(Timestamp, *) by SHA1
)
on SHA1
| project
    FileName,
    SHA1,
    IsSigned,
    IsTrusted,
    SignatureType,
    Signer,
    Issuer,
    CertificateCreationTime,
    CertificateExpirationTime,
    DeviceCount,
    FirstSeen,
    LastSeen,
    Devices,
    FilePaths,
    InitiatingProcesses,
    OriginUrls,
    OriginIPs
```

## What to Look For

### Signature

Review:

* `IsSigned`
* `IsTrusted`
* `Signer`
* `Issuer`

Ask:

> Does the signer make sense for this file?

For example, a Microsoft binary signed by Microsoft is much easier to explain than an unexpected executable with no signature.

### Prevalence

Review:

* `DeviceCount`
* `Devices`
* `FirstSeen`
* `LastSeen`

Ask:

> Is this a common file in the environment or something rarely observed?

A file appearing across many expected systems may support legitimate software activity.

A newly observed file appearing on only one or a few systems may deserve additional investigation.

### File Location

Review `FilePaths`.

Pay attention to executables or DLLs running from locations such as:

```text
%TEMP%
%APPDATA%
Downloads
Public
User profile directories
```

The location should make sense for the software involved.

### Origin

Review:

* `OriginUrls`
* `OriginIPs`

If Defender captured download-origin information, determine whether the source is expected and consistent with the file.

---

## Important Note

Do not use any single result as your verdict.

```text
Signed ≠ automatically safe

Unsigned ≠ automatically malicious

Common ≠ automatically safe

Rare ≠ automatically malicious
```

Use signature, prevalence, origin, file path, process behavior, and surrounding telemetry together.

## Next Step

If the file remains suspicious:

* Review whether it executed using **Process Activity Pivot**
* Review possible download activity using **Network to File Correlation**
* Scope related IPs, domains, or hashes using **Indicator Environment Sweep**

If the file is part of a persistence mechanism, return to:

**Persistence and Security Changes**
