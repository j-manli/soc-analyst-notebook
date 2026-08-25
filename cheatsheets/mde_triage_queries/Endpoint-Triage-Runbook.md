# Endpoint Alert Triage Runbook

## Purpose

Use this runbook as the default workflow for Microsoft Defender endpoint alerts.

The goal is to answer:

> **What happened, is it expected, did anything suspicious happen around it, and is the activity isolated or part of something larger?**

Follow the steps in order. Only branch into additional queries when the evidence gives you a reason.

---

# 1. Understand the Alert

Before running hunting queries, identify the important details from the alert.

```text
Alert Name:
Alert Time:
Device Name:
Device ID:
User:
Alerting Process:
Process ID:
Process Creation Time:
Command Line:
File / Hash:
IP / Domain:
```

## Ask

* What exactly triggered the alert?
* Which process or user caused it?
* What behavior did Defender consider suspicious?
* Could there be a legitimate explanation?
* Are there related alerts or affected entities?

## Why

You need to understand the alerting behavior before surrounding telemetry will be meaningful.

---

# 2. Review Surrounding Endpoint Activity

Run:

**[Endpoint Context Timeline](../Queries/01-Endpoint-Context-Timeline.md)**

This should usually be your first hunting query.

It provides a chronological view of:

* Process activity
* Network activity
* File activity
* Registry activity
* Logons
* General device events

## Ask

> **What was happening on this endpoint immediately before and after the alert?**

## Look For

### Process

* Unexpected process creation
* Suspicious parent/child relationships
* PowerShell, CMD, scripting, or LOLBin activity
* Encoded or obfuscated command lines
* Executables running from unusual locations

### Network

* Unexpected external connections
* Unusual domains or IP addresses
* Connections immediately after process execution
* Internal connections that may indicate lateral movement

### Files

* Executables, DLLs, scripts, or archives being created
* Files created in unusual locations
* Potential payload downloads

### Registry

* Run keys
* Startup changes
* Security-setting changes
* Other possible persistence

### Logons

* Unexpected accounts
* Remote logons
* Accounts that normally should not access the device

---

# 3. Decide Whether You Need to Pivot

After reviewing the timeline, ask:

> **Did I find anything that needs a closer look?**

## If No

If the alerting activity appears legitimate and surrounding telemetry is consistent with that explanation, continue toward disposition.

Example analyst note:

> Review of endpoint telemetry surrounding the alert did not identify suspicious process creation, command-line activity, network connections, file activity, logons, or registry changes within the reviewed time window.

Do not treat a clean timeline as proof that nothing malicious occurred. It is supporting evidence within the telemetry and time range reviewed.

---

## If Yes

Pivot based on the suspicious entity.

| Finding                              | Next Query                                                                  |
| ------------------------------------ | --------------------------------------------------------------------------- |
| Suspicious process                   | [Process Activity Pivot](../Queries/02-Process-Activity-Pivot.md)           |
| Network followed by file creation    | [Network to File Correlation](../Queries/03-Network-to-File-Correlation.md) |
| Suspicious inbound connection        | [Inbound Connection Source](../Queries/04-Inbound-Connection-Source.md)     |
| Suspicious IP, domain, hash, or file | [Indicator Environment Sweep](../Queries/05-Indicator-Environment-Sweep.md) |

Do not run every query automatically.

Run the query that answers your **next investigative question**.

---

# 4. Investigate Suspicious Processes

If a process appears suspicious, run:

**[Process Activity Pivot](../Queries/02-Process-Activity-Pivot.md)**

## Ask

> **What did this exact process do?**

Whenever possible, identify the process using:

```text
Device ID
Process ID
Process Creation Time
```

## Look For

* Parent process
* Child processes
* Command line
* Network connections
* Files created
* Registry modifications
* Additional device events

## Example

```text
WINWORD.EXE
     ↓
powershell.exe
     ↓
External connection
     ↓
payload.dll created
     ↓
rundll32.exe
```

A process name by itself may be benign.

The behavior surrounding it is often what determines whether it is suspicious.

---

# 5. Investigate Possible Downloads

If a process made a network connection and then created a suspicious file, run:

**[Network to File Correlation](../Queries/03-Network-to-File-Correlation.md)**

## Ask

> **Did this process make a network connection and create a possible downloaded file shortly afterward?**

## Look For

* Remote IP or domain
* File name
* File location
* File hash
* Time between network activity and file creation
* Whether the file was later executed

Remember that timing correlation supports a download hypothesis but does not prove that the file contents came from that specific connection.

---

# 6. Investigate Inbound Connections

If the alerted endpoint accepted an unexpected inbound connection, run:

**[Inbound Connection Source](../Queries/04-Inbound-Connection-Source.md)**

## Ask

> **Which internal device and process initiated this connection?**

This can be useful for investigating:

* SMB
* RDP
* WinRM
* Remote administration
* Potential lateral movement

## Look For

* Source device
* Source IP
* Destination port
* Initiating process
* Command line
* User account

Then determine whether the source device, user, process, and destination make sense together.

---

# 7. Scope Suspicious Indicators

If you identify a suspicious:

* Hash
* File
* IP
* Domain
* Command line
* Other IOC

run:

**[Indicator Environment Sweep](../Queries/05-Indicator-Environment-Sweep.md)**

## Ask

> **Is this activity isolated to this endpoint or present elsewhere in the environment?**

## Look For

* Other affected devices
* Other users
* Same file/hash elsewhere
* Other systems contacting the same infrastructure
* First and last observed activity
* Frequency of the activity

## Why

There is a major difference between:

```text
1 affected device
```

and:

```text
25 affected devices
```

Scoping helps determine whether you are dealing with an isolated event or potentially broader activity.

---

# 8. Reassess the Alert

After completing the relevant pivots, return to the original alert.

Ask:

* Can I explain why the alert fired?
* Does the explanation fit the surrounding telemetry?
* Did the alerting process perform suspicious follow-on activity?
* Did it communicate with suspicious infrastructure?
* Did it create or execute suspicious files?
* Was persistence observed?
* Was lateral movement observed?
* Does the activity exist elsewhere?
* Is there anything I still cannot explain?

If something remains unclear, identify the specific unanswered question and investigate that question.

---

# 9. Make the Disposition

## Likely Benign

You should generally be able to explain:

* Why the alert triggered
* Why the behavior is legitimate
* Which user/process caused it
* Why the surrounding activity is expected
* That no relevant suspicious follow-on activity was identified in the telemetry reviewed

Example:

> The alerting activity appears consistent with legitimate behavior. Review of surrounding endpoint telemetry did not identify additional suspicious process, network, file, logon, or registry activity within the reviewed time window.

---

## Needs Further Investigation

Use this when:

* The behavior cannot yet be explained
* Important telemetry is missing
* A destination, file, process, or account is unknown
* Activity is unusual but not clearly malicious
* Additional validation is required

Document the unanswered question.

Example:

> PowerShell activity remains unexplained. Additional investigation is required to determine the purpose of the observed outbound connection and subsequent file creation.

---

## Suspicious / Escalate

Examples of evidence that may support escalation include:

* Malicious or highly suspicious command lines
* Suspicious process chains
* Payload download followed by execution
* Credential access behavior
* Persistence
* Lateral movement
* Known malicious infrastructure
* Suspicious indicators appearing across multiple endpoints

Document the sequence of events and supporting evidence.

---

# Quick Reference

```text
START
  │
  ▼
Understand the alert
  │
  ▼
Run Endpoint Context Timeline
  │
  ▼
Anything suspicious?
  │
  ├── No
  │    │
  │    ▼
  │  Validate explanation
  │    │
  │    ▼
  │  Scope if warranted
  │
  └── Yes
       │
       ├── Process
       │      ↓
       │   Process Activity Pivot
       │
       ├── Network → File
       │      ↓
       │   Network to File Correlation
       │
       ├── Inbound Connection
       │      ↓
       │   Inbound Connection Source
       │
       └── IOC
              ↓
          Indicator Environment Sweep

              ↓
          Reassess evidence
              ↓
           DISPOSITION
```

---

# Core Rule

Do not ask:

> **Which Defender table should I search next?**

Ask:

> **What question do I need to answer next?**

Then use the query designed to answer that question.

```text
"What happened around the alert?"
→ Endpoint Context Timeline

"What did this process do?"
→ Process Activity Pivot

"Did this process possibly download something?"
→ Network to File Correlation

"Who connected to this device?"
→ Inbound Connection Source

"Is this indicator present elsewhere?"
→ Indicator Environment Sweep
```

Broad queries are used to **discover** interesting activity.

Targeted queries are used to **validate** it.

Environment-wide searches are used to **scope** it.

The evidence gathered from those steps is then used to make the final disposition.
