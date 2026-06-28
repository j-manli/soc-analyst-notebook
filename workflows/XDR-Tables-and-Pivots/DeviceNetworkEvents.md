# `DeviceNetworkEvents`

## What this table answers

Use `DeviceNetworkEvents` to answer:

**“What network connection happened, where did it go, what process made it, and does the destination look suspicious?”**

This table helps investigate endpoint network activity, C2, suspicious domains/IPs, lateral movement, beaconing, DNS activity, and connections made by suspicious processes.

---

## Use this table when

Use `DeviceNetworkEvents` when investigating:

* Command and control, also called C2
* Connections to malicious IPs, domains, or URLs
* Suspicious outbound traffic
* Beaconing behavior
* Lateral movement over SMB, RDP, WinRM, or other internal ports
* DNS queries to suspicious domains
* Endpoint connections after a phishing click
* Malware download or callback activity
* Internal reconnaissance or port scanning
* Cryptocurrency mining pool connections
* Network activity from suspicious processes or scripts

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertDeviceName = "";
let alertRemoteIP = "";
let alertRemoteUrl = "";
let alertRemotePort = "";
let alertProtocol = "";
let alertInitiatingProcess = "";
let alertCommandLineKeyword = "";
let alertAccount = "";
let alertInitiatingProcessSHA1 = "";
let alertRemoteIPType = "";

DeviceNetworkEvents
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertRemoteIP) or RemoteIP == alertRemoteIP
| where isempty(alertRemoteUrl) or RemoteUrl contains alertRemoteUrl
| where isempty(alertRemotePort) or RemotePort == toint(alertRemotePort)
| where isempty(alertProtocol) or Protocol =~ alertProtocol
| where isempty(alertInitiatingProcess) or InitiatingProcessFileName =~ alertInitiatingProcess
| where isempty(alertCommandLineKeyword) or InitiatingProcessCommandLine contains alertCommandLineKeyword
| where isempty(alertAccount) or InitiatingProcessAccountName =~ alertAccount or InitiatingProcessAccountUpn =~ alertAccount
| where isempty(alertInitiatingProcessSHA1) or InitiatingProcessSHA1 =~ alertInitiatingProcessSHA1
| where isempty(alertRemoteIPType) or RemoteIPType =~ alertRemoteIPType
| project-reorder Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, Protocol, RemoteIPType, LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA1, InitiatingProcessAccountName, InitiatingProcessIntegrityLevel, ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `RemoteIP` or `RemoteUrl` when investigating known infrastructure. Use `DeviceName` + `InitiatingProcessFileName` when investigating what a specific endpoint or process connected to. Use `RemotePort` when investigating lateral movement, such as SMB, RDP, or WinRM.

```kql
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where DeviceName =~ "<device-name>"
| where RemoteIP == "<remote IP>"
| project-reorder Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIPType, InitiatingProcessSHA1, InitiatingProcessAccountName, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

Alternative `where` lines you can swap in:

```kql
| where RemoteUrl contains "<domain or URL>"
| where RemotePort == <port>
| where Protocol =~ "<TCP/UDP/ICMP>"
| where RemoteIPType =~ "<Public/Private>"
| where InitiatingProcessFileName =~ "<process.exe>"
| where InitiatingProcessCommandLine contains "<command keyword>"
| where InitiatingProcessSHA1 =~ "<SHA1>"
| where InitiatingProcessAccountName =~ "<username>"
| where InitiatingProcessAccountUpn =~ "<user@domain.com>"
```

```kql
// Purpose: Shows endpoint network activity so I can confirm the destination, port, protocol, source process, command line, account context, and whether the traffic was internal or external.
```

---

## Key fields

| Field                             | Why it matters                                                                                                       |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `RemoteIP` / `RemoteUrl`          | Destination IP, domain, or URL. Critical for IOC matching and identifying suspicious infrastructure.                 |
| `RemotePort`                      | Destination port. Helps identify protocols such as SMB `445`, RDP `3389`, HTTP `80`, HTTPS `443`, WinRM `5985/5986`. |
| `Protocol`                        | Shows whether the connection used TCP, UDP, ICMP, etc.                                                               |
| `InitiatingProcessFileName`       | Shows the process that made the connection. Helps distinguish browsers, admin tools, scripts, and malware.           |
| `InitiatingProcessCommandLine`    | Shows the command line that initiated the connection. Useful for suspicious scripts, LOLBins, and encoded commands.  |
| `LocalIP` / `LocalPort`           | Shows the source IP and port on the endpoint. Helpful when devices have multiple interfaces.                         |
| `RemoteIPType`                    | Shows whether the destination is public, private, loopback, reserved, etc. Useful for external vs internal traffic.  |
| `Timestamp`                       | Shows when the connection occurred. Useful for timeline building and beaconing analysis.                             |
| `ActionType`                      | Shows the type of network activity. Useful for filtering connection behavior.                                        |
| `InitiatingProcessSHA1`           | Hash of the connecting process. Use this to hunt for the same binary across devices.                                 |
| `InitiatingProcessAccountName`    | Account context for the connecting process.                                                                          |
| `InitiatingProcessIntegrityLevel` | Process privilege level. Useful for understanding risk and execution context.                                        |

---

## Do not use this table for

| What you need                                                         | Use this instead      |
| --------------------------------------------------------------------- | --------------------- |
| Process execution and parent/child chains                             | `DeviceProcessEvents` |
| File creation, modification, deletion, or downloads on disk           | `DeviceFileEvents`    |
| Logons and authentication events                                      | `DeviceLogonEvents`   |
| Registry changes, scheduled tasks, services, or firewall rule changes | `DeviceEvents`        |
| Email URLs that were present but not clicked                          | `EmailUrlInfo`        |
| Safe Links user clicks                                                | `UrlClickEvents`      |

---

## Pivot next

| Starting point                                               | Pivot to                                   | Why                                                                 |
| ------------------------------------------------------------ | ------------------------------------------ | ------------------------------------------------------------------- |
| `InitiatingProcessFileName` / `InitiatingProcessCommandLine` | `DeviceProcessEvents`                      | Build the process chain that caused the connection.                 |
| `InitiatingProcessSHA1`                                      | `DeviceProcessEvents` / `DeviceFileEvents` | Hunt for the same binary executing or existing across devices.      |
| `RemoteIP` / `RemoteUrl`                                     | `DeviceNetworkEvents`                      | Find other devices connecting to the same infrastructure.           |
| `DeviceName` + `Timestamp`                                   | `DeviceProcessEvents`                      | Review process activity around the network connection.              |
| `DeviceName` + `Timestamp`                                   | `DeviceFileEvents`                         | Check for downloaded or dropped files around the connection time.   |
| `DeviceName`                                                 | `DeviceLogonEvents`                        | Review user logons before or during suspicious network activity.    |
| `RemoteIP` + lateral movement port                           | `DeviceLogonEvents`                        | Check whether the same source/destination relates to remote logons. |
| `RemoteUrl` / domain                                         | `EmailUrlInfo` / `UrlClickEvents`          | Check whether the domain came from a phishing email or user click.  |

---

## Quick triage workflow

1. Start with `DeviceName`, `RemoteIP`, `RemoteUrl`, `RemotePort`, or `InitiatingProcessFileName`.
2. Review `RemoteIP`, `RemoteUrl`, `RemotePort`, and `Protocol` to understand the destination and service.
3. Check `RemoteIPType` to determine whether traffic is internal or external.
4. Identify the process that made the connection using `InitiatingProcessFileName`.
5. Review `InitiatingProcessCommandLine` for suspicious scripts, LOLBins, encoded commands, or unusual parameters.
6. Check `InitiatingProcessAccountName` to identify the user or service context.
7. Use `Timestamp` to compare the connection with process, file, logon, or email activity.
8. Pivot on `RemoteIP` or `RemoteUrl` to see whether other devices connected to the same destination.
9. Pivot on the initiating process to understand whether the connection was expected.

---

## Watch for

* Suspicious processes making outbound connections
* PowerShell, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, or `regsvr32.exe` connecting externally
* Repeated connections at regular intervals
* Connections to known malicious IPs or domains
* Connections to newly observed or strange domains
* Internal connections to SMB `445`, RDP `3389`, WinRM `5985/5986`, or unusual admin ports
* One device connecting to many internal systems
* Connections to many ports on the same host
* Public IP connections from unusual processes
* Private IP connections that suggest lateral movement
* Network traffic shortly after suspicious email clicks, file creation, or process execution
* Connections from user-writable path executables
* Suspicious processes running with high or system integrity

---

## Mental model

Use `DeviceNetworkEvents` when your main question is:

**“What did this endpoint connect to, what process made the connection, and does the destination or behavior suggest C2, exfiltration, or lateral movement?”**
