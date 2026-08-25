# Endpoint Triage Runbook

## Purpose

Use this runbook as the default workflow for Microsoft Defender for Endpoint alert triage.

The goal is to answer:

> **What happened, is it expected, did anything suspicious happen around it, and is the activity isolated or part of something larger?**

Follow the steps in order. Only open additional query pages when the evidence gives you a reason.

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
File / SHA1:
IP / Domain:
```

## Ask

* What exactly triggered the alert?
* Which process or user caused it?
* What behavior did Defender consider suspicious?
* Could there be a legitimate explanation?
* Are there related alerts or affected entities?

Do not start hunting blindly. First understand what you are trying to validate.

---

# 2. Review Surrounding Endpoint Activity

Run:

**[Endpoint Context Timeline](01-Endpoint-Context-Timeline.md)**

This should usually be your first hunting query.

It reviews:

* Process activity
* Network activity
* File activity
* Registry activity
* Logons
* General device events

## Ask

> **What was happening on this endpoint immediately before and after the alert?**

## Look For

* Suspicious or unusual processes
* Strange command lines
* Unexpected outbound connections
* File creation
* Registry changes
* Unexpected logons
* Follow-on activity after the alert

---

# 3. Decide Whether You Need to Pivot

After reviewing the timeline, ask:

> **Did I find anything that needs a closer look?**

### If No

If the alerting behavior can be explained and surrounding telemetry appears consistent with that explanation, continue toward disposition.

Example analyst note:

> Review of endpoint telemetry surrounding the alert did not identify suspicious process creation, command-line activity, network connections, file activity, logons, or registry changes within the reviewed time window.

A clean timeline supports your assessment but does not prove that nothing malicious occurred.

### If Yes

Use the suspicious activity to choose the next query.

| What You Found                                     | Next Query                                                                 |
| -------------------------------------------------- | -------------------------------------------------------------------------- |
| Suspicious or unusual process                      | [Process Activity Pivot](02-Process-Activity-Pivot.md)                     |
| Network connection followed by file creation       | [Network to File Correlation](03-Network-to-File-Correlation.md)           |
| Unexpected inbound connection                      | [Inbound Connection Source](04-Inbound-Connection-Source.md)               |
| Suspicious hash, IP, domain, file, or command line | [Indicator Environment Sweep](05-Indicator-Environment-Sweep.md)           |
| Suspicious outbound network activity               | [Outbound Network Activity](06-Outbound-Network-Activity.md)               |
| Possible persistence or security changes           | [Persistence and Security Changes](07-Persistence-and-Security-Changes.md) |
| Unknown or suspicious file                         | [File Trust and Prevalence Check](08-File-Trust-and-Prevalence-Check.md)   |

Do **not** run all of these automatically.

Ask:

> **What question do I need to answer next?**

Then use the query designed to answer it.

---

# 4. Investigate Suspicious Processes

If a process looks suspicious, run:

**[Process Activity Pivot](02-Process-Activity-Pivot.md)**

## Ask

> **What did this exact process do?**

Look for:

* Parent process
* Child processes
* Command line
* Network connections
* Files created
* Registry modifications
* Additional endpoint events

A process name by itself may be benign. Its behavior is usually more important.

---

# 5. Investigate Network Activity

If the timeline shows unusual outbound communication, run:

**[Outbound Network Activity](06-Outbound-Network-Activity.md)**

## Ask

> **What did this device connect to, and which process/user initiated it?**

Look for:

* Unexpected IP addresses or domains
* Unusual destination ports
* Suspicious processes making connections
* Script interpreters or LOLBins communicating externally
* Repeated connections to the same destination
* Internal connections that may represent lateral movement

If the destination looks suspicious, scope it with:

**[Indicator Environment Sweep](05-Indicator-Environment-Sweep.md)**

---

# 6. Investigate Possible Downloads

If a process made a network connection and created a file shortly afterward, run:

**[Network to File Correlation](03-Network-to-File-Correlation.md)**

## Ask

> **Did this process potentially download or create a file following network activity?**

Look for:

* Remote IP or domain
* Created file
* File path
* SHA1
* File origin
* Time between connection and file creation

Remember that timing correlation supports a download hypothesis but does not prove that a specific connection supplied the file.

---

# 7. Investigate Inbound Connections

If the device accepted an unexpected inbound connection, run:

**[Inbound Connection Source](04-Inbound-Connection-Source.md)**

## Ask

> **Which internal device and process initiated this connection?**

Useful for:

* SMB
* RDP
* WinRM
* Remote administration
* Potential lateral movement

Review:

* Source device
* Source IP
* Destination port
* Initiating process
* Command line
* User account

Determine whether the source device, process, user, and destination make sense together.

---

# 8. Check Suspicious Files

If you identify an unknown or suspicious file, run:

**[File Trust and Prevalence Check](08-File-Trust-and-Prevalence-Check.md)**

## Ask

> **Is this file signed and trusted, and how common is it in the environment?**

Review:

* Signature status
* Trust status
* Signer
* Issuer
* Device prevalence
* File paths
* First/last seen
* Download origin

Remember:

```text
Signed ≠ automatically safe
Unsigned ≠ automatically malicious
Common ≠ automatically safe
Rare ≠ automatically malicious
```

Use file reputation together with process behavior and surrounding telemetry.

---

# 9. Check for Persistence or Security Changes

If suspicious code executed successfully, or the alert appears significant enough to warrant a deeper check, run:

**[Persistence and Security Changes](07-Persistence-and-Security-Changes.md)**

## Ask

> **Did the activity establish persistence or weaken endpoint security?**

Look for:

* Scheduled tasks
* Services
* Registry autoruns
* Startup changes
* Defender changes
* Tamper-related events
* Firewall changes
* Suspicious use of `schtasks.exe`, `sc.exe`, or `reg.exe`

This is especially important when malware or attacker-controlled code may have executed.

---

# 10. Scope Suspicious Indicators

If you identify a suspicious:

* SHA1
* File name
* IP address
* Domain
* Command-line fragment

run:

**[Indicator Environment Sweep](05-Indicator-Environment-Sweep.md)**

## Ask

> **Is this activity isolated to this endpoint or present elsewhere?**

Look for:

* Other affected devices
* Other users
* Same hash/file elsewhere
* Other systems communicating with the same infrastructure
* Frequency
* First and last observed activity

The difference between one affected endpoint and many can significantly change the severity of the investigation.

---

# 11. Reassess the Alert

After completing the relevant pivots, return to the original alert.

Ask:

* Can I explain why the alert fired?
* Does that explanation fit the surrounding telemetry?
* Did the process perform suspicious follow-on activity?
* Did it communicate with suspicious infrastructure?
* Did it create or execute suspicious files?
* Was persistence observed?
* Were security controls modified?
* Was lateral movement observed?
* Does the same activity appear elsewhere?
* Is there anything I still cannot explain?

If something remains unclear, identify the **specific unanswered question** and investigate that question.

---

# 12. Make the Disposition

## Likely Benign

You should generally be able to explain:

* Why the alert triggered
* Why the behavior is legitimate
* Which user/process caused it
* Why surrounding activity is expected
* That no relevant suspicious follow-on activity was identified within the telemetry reviewed

Example:

> The alerting activity appears consistent with legitimate behavior. Review of surrounding endpoint telemetry did not identify additional suspicious process, network, file, logon, registry, persistence, or security-impacting activity within the reviewed time window.

---

## Needs Further Investigation

Use this when:

* The behavior cannot yet be explained
* Important telemetry is missing
* A destination, file, process, or account is unknown
* Activity is unusual but not clearly malicious
* Additional validation is required

Document the specific unanswered question.

---

## Suspicious / Escalate

Examples of evidence that may support escalation:

* Malicious or highly suspicious command lines
* Suspicious process chains
* Payload download followed by execution
* Suspicious external communication
* Credential activity
* Persistence
* Security-control modification
* Lateral movement
* Known malicious infrastructure
* Suspicious indicators across multiple endpoints

Document the sequence of events and supporting evidence.

---

# Quick Reference

```text
                         ALERT
                           │
                           ▼
                  Understand why it fired
                           │
                           ▼
                 Endpoint Context Timeline
                           │
                  Anything suspicious?
                     /            \
                   NO              YES
                   │                │
                   │                ├─ Process
                   │                │     ↓
                   │                │  Process Activity Pivot
                   │                │
                   │                ├─ Outbound network
                   │                │     ↓
                   │                │  Outbound Network Activity
                   │                │
                   │                ├─ Network → File
                   │                │     ↓
                   │                │  Network to File Correlation
                   │                │
                   │                ├─ Inbound connection
                   │                │     ↓
                   │                │  Inbound Connection Source
                   │                │
                   │                ├─ Suspicious file
                   │                │     ↓
                   │                │  File Trust / Prevalence
                   │                │
                   │                ├─ Persistence/security change
                   │                │     ↓
                   │                │  Persistence Check
                   │                │
                   │                └─ IOC
                   │                      ↓
                   │                 Environment Sweep
                   │
                   └───────────────┬───────────────
                                   ▼
                              Reassess
                                   │
                                   ▼
                               DISPOSITION
```

---

# Query Library

### 1. [Endpoint Context Timeline](01-Endpoint-Context-Timeline.md)

**Question:** What happened around the alert?

### 2. [Process Activity Pivot](02-Process-Activity-Pivot.md)

**Question:** What did this process do?

### 3. [Network to File Correlation](03-Network-to-File-Correlation.md)

**Question:** Did this process potentially download or create a file after network activity?

### 4. [Inbound Connection Source](04-Inbound-Connection-Source.md)

**Question:** Which internal device initiated this inbound connection?

### 5. [Indicator Environment Sweep](05-Indicator-Environment-Sweep.md)

**Question:** Does this indicator appear elsewhere?

### 6. [Outbound Network Activity](06-Outbound-Network-Activity.md)

**Question:** What did this endpoint connect to, and what initiated the connection?

### 7. [Persistence and Security Changes](07-Persistence-and-Security-Changes.md)

**Question:** Did this activity establish persistence or weaken security controls?

### 8. [File Trust and Prevalence Check](08-File-Trust-and-Prevalence-Check.md)

**Question:** Is this file signed/trusted, and how common is it?

---

# Core Rule

Do not ask:

> **Which Defender table should I search next?**

Ask:

> **What investigative question do I need to answer next?**

Then use the query designed to answer it.

```text
"What happened around the alert?"
→ Endpoint Context Timeline

"What did this process do?"
→ Process Activity Pivot

"What did this endpoint connect to?"
→ Outbound Network Activity

"Did this process potentially download something?"
→ Network to File Correlation

"Who connected to this endpoint?"
→ Inbound Connection Source

"Is this file legitimate or unusual?"
→ File Trust and Prevalence Check

"Did this establish persistence?"
→ Persistence and Security Changes

"Does this indicator exist elsewhere?"
→ Indicator Environment Sweep
```

Use broad queries to **discover**.

Use targeted queries to **validate**.

Use environment-wide searches to **scope**.

Use the combined evidence to make the final disposition.
