
# CrowdStrike Advanced Search

A practical collection of reusable CrowdStrike Falcon searches for alert triage, investigation, scoping, and basic threat hunting.

> **Query language:** These examples use CrowdStrike Query Language (CQL) in Falcon Next-Gen SIEM Advanced Event Search.  
> **Note:** Available fields and event names can vary by data source, Falcon configuration, platform, and product version. Validate queries in your environment before relying on them operationally.

---

## Table of Contents

- [Investigation Workflow](#investigation-workflow)
- [Reusable Placeholders](#reusable-placeholders)
- [1. Endpoint Process Timeline](#1-endpoint-process-timeline)
- [2. Process Parent and Child Activity](#2-process-parent-and-child-activity)
- [3. Activity Associated with a Process](#3-activity-associated-with-a-process)
- [4. Suspicious PowerShell](#4-suspicious-powershell)
- [5. Suspicious Office or Browser Child Processes](#5-suspicious-office-or-browser-child-processes)
- [6. Scope a SHA-256 Hash](#6-scope-a-sha-256-hash)
- [7. Investigate DNS Activity](#7-investigate-dns-activity)
- [8. Investigate Network Connections](#8-investigate-network-connections)
- [9. Review User Logons](#9-review-user-logons)
- [10. Scheduled Task Persistence](#10-scheduled-task-persistence)
- [11. Service-Based Persistence](#11-service-based-persistence)
- [12. File Activity](#12-file-activity)
- [Core CQL Patterns](#core-cql-patterns)
- [Analyst Notes](#analyst-notes)
- [References](#references)

---

## Investigation Workflow

A useful investigation sequence is:

```text
Alert
  ↓
Endpoint AID
  ↓
Suspicious process
  ↓
Parent and child processes
  ↓
ContextProcessId
  ↓
DNS, network, and file activity
  ↓
Hash, domain, and IP scoping
  ↓
User logons
  ↓
Persistence checks
```

Do not investigate an alert in isolation. Your goal is to determine:

1. What happened?
2. What launched the suspicious activity?
3. What did it do next?
4. Which user and endpoint were involved?
5. Did the activity spread elsewhere?
6. Was persistence established?
7. Is the behavior malicious, suspicious, or expected?

---

## Reusable Placeholders

Replace these values before running a query:

| Placeholder | Meaning |
|---|---|
| `<AID>` | CrowdStrike agent ID for the endpoint |
| `<PID>` | `TargetProcessId`, `ParentProcessId`, or `ContextProcessId` |
| `<SHA256>` | SHA-256 file hash |
| `<DOMAIN>` | Domain name |
| `<IP>` | IPv4 address |
| `<USER>` | Username |
| `<HOSTNAME>` | Endpoint hostname |

> Use the Falcon time picker aggressively. Start with a narrow window around the alert, then expand as needed.

---

# Essential Queries

## 1. Endpoint Process Timeline

Use this to review process execution on a specific endpoint.

```text
#event_simpleName=ProcessRollup2
| aid="<AID>"
| table([
    @timestamp,
    ComputerName,
    UserName,
    ParentBaseFileName,
    ImageFileName,
    CommandLine,
    TargetProcessId,
    SHA256HashData
  ], limit=500)
```

### Look for

- Unexpected command-line arguments
- Processes running from temporary or user-writable directories
- Script interpreters
- Unusual parent-child relationships
- Execution under privileged accounts
- Recently downloaded or uncommon binaries

---

## 2. Process Parent and Child Activity

Use the suspicious process ID from an alert or process timeline.

```text
#event_simpleName=ProcessRollup2
| aid="<AID>"
| TargetProcessId="<PID>" OR ParentProcessId="<PID>"
| table([
    @timestamp,
    UserName,
    ParentBaseFileName,
    ImageFileName,
    CommandLine,
    ParentProcessId,
    TargetProcessId,
    SHA256HashData
  ], limit=500)
```

### Questions to answer

- What launched the suspicious process?
- What child processes did it create?
- Did it launch PowerShell, `cmd.exe`, `mshta.exe`, or another LOLBin?
- Did the process chain make sense for the application involved?

---

## 3. Activity Associated with a Process

Use `ContextProcessId` to pivot from a suspicious process into related telemetry.

```text
aid="<AID>"
| ContextProcessId="<PID>"
| table([
    @timestamp,
    #event_simpleName,
    DomainName,
    RemoteAddressIP4,
    RemotePort,
    TargetFileName,
    SHA256HashData
  ], limit=1000)
```

This can reveal:

- DNS lookups
- Network connections
- File writes
- File deletions
- Other process-linked activity

---

## 4. Suspicious PowerShell

### Common suspicious PowerShell indicators

```text
#event_simpleName=ProcessRollup2
| event_platform=Win
| ImageFileName=/\\(powershell|pwsh)\.exe$/i
| CommandLine=/(-enc|-encodedcommand|frombase64string|downloadstring|invoke-expression|\biex\b)/i
| table([
    @timestamp,
    ComputerName,
    UserName,
    ParentBaseFileName,
    ImageFileName,
    CommandLine,
    SHA256HashData
  ], limit=500)
```

### Encoded PowerShell commands

```text
#event_simpleName=ProcessRollup2
| CommandLine=/-e(nc|ncodedcommand)?\s+/i
| table([
    @timestamp,
    ComputerName,
    UserName,
    ParentBaseFileName,
    ImageFileName,
    CommandLine
  ], limit=500)
```

> These indicators are not automatically malicious. Administrators, deployment tools, and legitimate scripts may use encoded or obfuscated commands.

---

## 5. Suspicious Office or Browser Child Processes

Useful during phishing, malicious document, and drive-by download investigations.

```text
#event_simpleName=ProcessRollup2
| event_platform=Win
| ParentBaseFileName=/^(winword|excel|powerpnt|outlook|acrord32|chrome|msedge|firefox)\.exe$/i
| ImageFileName=/\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil)\.exe$/i
| table([
    @timestamp,
    ComputerName,
    UserName,
    ParentBaseFileName,
    ImageFileName,
    CommandLine,
    SHA256HashData
  ], limit=500)
```

### Investigate carefully when

- Word or Excel launches PowerShell
- Outlook launches a script interpreter
- A browser launches `cmd.exe`
- Adobe Reader launches a LOLBin
- A child process runs from `%TEMP%`, `Downloads`, or `AppData`

---

## 6. Scope a SHA-256 Hash

### Find process executions

```text
#event_simpleName=ProcessRollup2
| SHA256HashData="<SHA256>"
| groupBy([
    aid,
    ComputerName,
    UserName,
    ImageFileName,
    CommandLine
  ], limit=max)
```

### Find where the file was written

```text
#event_simpleName="*FileWritten"
| SHA256HashData="<SHA256>"
| groupBy([
    aid,
    ComputerName,
    TargetFileName
  ], limit=max)
```

### Scoping questions

- How many endpoints saw the hash?
- Was the file executed or only written?
- Which user accounts were involved?
- Did the file appear in the same path everywhere?
- Is the activity isolated or widespread?

---

## 7. Investigate DNS Activity

### Search for a specific domain

```text
#event_simpleName=DnsRequest
| DomainName="<DOMAIN>"
| groupBy(
    [aid, DomainName],
    function=[
      count(as=requests),
      min(@timestamp, as=firstSeen),
      max(@timestamp, as=lastSeen)
    ],
    limit=max
  )
```

### Review all DNS activity from an endpoint

```text
#event_simpleName=DnsRequest
| aid="<AID>"
| groupBy(DomainName, limit=500)
```

### Review DNS activity associated with one process

```text
#event_simpleName=DnsRequest
| aid="<AID>"
| ContextProcessId="<PID>"
| groupBy(DomainName, limit=500)
```

### Look for

- Newly registered or suspicious domains
- Dynamic DNS providers
- Repeated requests at regular intervals
- Domains with random-looking subdomains
- Unexpected country-code top-level domains
- DNS activity immediately after process execution

---

## 8. Investigate Network Connections

### Review external IPv4 connections from an endpoint

```text
#event_simpleName=NetworkConnectIP4
| aid="<AID>"
| !cidr(
    RemoteAddressIP4,
    subnet=[
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "127.0.0.0/8",
      "169.254.0.0/16"
    ]
  )
| groupBy([
    RemoteAddressIP4,
    RemotePort,
    ContextProcessId
  ], limit=max)
```

### Search for a specific external IP

```text
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4="<IP>"
| groupBy([
    aid,
    ComputerName,
    RemoteAddressIP4,
    RemotePort,
    ContextProcessId
  ], limit=max)
```

### Investigate

- Rare destination IPs
- Unexpected high-numbered ports
- Connections from unusual processes
- Repeated beacon-like activity
- Remote destinations shared across multiple endpoints
- Network activity shortly after a suspicious process starts

---

## 9. Review User Logons

### Find RDP logons on an endpoint

```text
#event_simpleName=UserLogon
| aid="<AID>"
| LogonType="10"
| table([
    @timestamp,
    ComputerName,
    UserName,
    LogonDomain,
    LogonType,
    UserIsAdmin
  ], limit=500)
```

### Scope activity for one user

```text
#event_simpleName=UserLogon
| UserName="<USER>"
| groupBy([
    aid,
    ComputerName,
    LogonDomain,
    LogonType,
    UserIsAdmin
  ], limit=max)
```

### Common Windows logon types

| Logon Type | Meaning |
|---|---|
| `2` | Interactive |
| `3` | Network |
| `5` | Service |
| `9` | New credentials |
| `10` | Remote Interactive / RDP |
| `11` | Cached interactive |

### Look for

- Logons outside expected hours
- Administrative logons to unusual endpoints
- One account authenticating to many systems
- RDP use by users who do not normally use RDP
- Service accounts used interactively
- New activity immediately after credential theft indicators

---

## 10. Scheduled Task Persistence

```text
#event_simpleName=ScheduledTaskRegistered
| aid="<AID>"
| table([
    @timestamp,
    ComputerName,
    UserName,
    TaskName,
    TaskExecCommand,
    TaskExecArguments
  ], limit=500)
```

### Suspicious indicators

- Tasks running from `%TEMP%`, `AppData`, or user profile folders
- Random or misleading task names
- PowerShell or script interpreter execution
- Network paths
- Hidden or recurring tasks
- Commands containing encoded content

---

## 11. Service-Based Persistence

```text
#event_simpleName=ServiceStarted
| event_platform=Win
| aid="<AID>"
| table([
    @timestamp,
    ComputerName,
    UserName,
    ServiceDisplayName,
    CommandLine
  ], limit=500)
```

### Suspicious indicators

- Services with random names
- Executables in user-writable locations
- PowerShell or command-shell service commands
- Recently created services
- Services running unsigned or uncommon binaries
- Service activity shortly after remote access or credential abuse

---

## 12. File Activity

### Review files written on an endpoint

```text
#event_simpleName="*FileWritten"
| aid="<AID>"
| table([
    @timestamp,
    #event_simpleName,
    TargetFileName,
    SHA256HashData,
    ContextProcessId
  ], limit=1000)
```

### Review file deletions

```text
#event_simpleName=FileDeleteInfo
| aid="<AID>"
| table([
    @timestamp,
    TargetFileName,
    ContextProcessId
  ], limit=500)
```

### Look for

- Executables written to temporary folders
- Scripts written shortly before execution
- Files placed in startup locations
- Payloads written by Office applications or browsers
- Rapid write-then-delete behavior
- Files with the same hash appearing across multiple endpoints

---

# Core CQL Patterns

## Exact match

```text
FieldName="value"
```

## Field exists

```text
FieldName=*
```

## Regular expression

```text
CommandLine=/pattern/i
```

The trailing `i` makes the expression case-insensitive.

## Multiple conditions

```text
FieldA="value" AND FieldB="value"
```

```text
FieldA="value1" OR FieldA="value2"
```

## Negation

```text
FieldName!="value"
```

## Display individual events

```text
| table([
    field1,
    field2,
    field3
  ], limit=500)
```

## Summarize repeated activity

```text
| groupBy([
    field1,
    field2
  ], limit=max)
```

## Count activity

```text
| groupBy(
    [field1],
    function=[count(as=total)],
    limit=max
  )
```

## Track first and last occurrence

```text
| groupBy(
    [field1],
    function=[
      count(as=total),
      min(@timestamp, as=firstSeen),
      max(@timestamp, as=lastSeen)
    ],
    limit=max
  )
```

---

# Analyst Notes

## Avoid treating every match as malicious

Most hunting queries identify unusual or potentially risky behavior, not confirmed compromise. Always validate findings using:

- Parent-child process relationships
- Full command lines
- User context
- File paths
- Hash reputation
- Network destinations
- Asset role
- Known administrative activity
- Change-management records

## Prefer AID over hostname when possible

Hostnames can be changed, duplicated, or reused. The CrowdStrike agent ID is usually a more reliable endpoint pivot.

## Preserve useful investigation values

Record these values in your case notes:

```text
AID:
Hostname:
Username:
Alert timestamp:
Suspicious process:
Parent process:
TargetProcessId:
ContextProcessId:
SHA-256:
Domains:
Remote IPs:
Files written:
Persistence found:
Other affected endpoints:
```

## Expand the time range gradually

A useful approach is:

1. Start 15–30 minutes before the alert.
2. Review the immediate process tree.
3. Expand to several hours.
4. Expand to 24 hours if persistence or lateral movement is suspected.
5. Search multiple days when scoping an IOC across the environment.

## Build a complete narrative

A strong investigation summary should explain:

```text
At <time>, <user> executed <process> on <host>.
The process was launched by <parent process> with command line <command>.
It contacted <domain/IP>, wrote <file>, and created <persistence mechanism>.
The same indicator was observed on <number> additional endpoints.
```
