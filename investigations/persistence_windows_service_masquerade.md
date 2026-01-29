# Persistence via Windows Service Masquerade

**MITRE ATT&CK Reference:** [T1543.003 – Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)

This scenario picks up where our [Ingress Tool Transfer](https://github.com/j-manli/soc-analyst-notebook/blob/main/investigations/ingress_c2_tool_transfer_via_bitsadmin.md) left off. After staging a payload using `bitsadmin`, the attacker establishes persistence by creating a masqueraded Windows service pointing to a Sliver C2 binary.

The service is registered as **Windows Update Service**, and the payload lives at `C:\ProgramData\Microsoft\Windows\updater.exe`.  
It's close enough to feel familiar, but just off enough to matter.

---

## Host Configuration

- **Attacker VM:** `HR-COMPLAINTS` (Sliver C2 on Ubuntu 22.04)  
  - **IP:** `10.1.0.51`
- **Target VM:** `CEO-LAPTOP` (Windows 10 with MDE onboarded)  
  - **IP:** `10.1.0.69`  
  - **Admin Username:** `TrustMeBro`

---

## Execution

On the target machine, the attacker (logged in as the admin, `TrustMeBro`) registers a new Windows service using `sc.exe`. The service is given a believable name and description to avoid suspicion during casual review:

```cmd
sc.exe create "Windows Update Service" binPath= "C:\ProgramData\Microsoft\Windows\updater.exe" start= auto DisplayName= "Windows Update Service"
sc.exe description "Windows Update Service" "Provides updates for your system."
```

This command sets the stage for persistence. By using the `start= auto` parameter, the service is configured to launch automatically on system boot, running as **SYSTEM** by default. A manual trigger was issued shortly after to test execution:

```cmd
sc.exe start "Windows Update Service"
```

From the attacker's perspective, the callback was immediate. Within the Sliver C2 interface, a session appeared, verifying that `updater.exe` executed successfully as a SYSTEM-level process.  
&nbsp;  
<img width="1125" height="177" alt="service_masquerade_create" src="https://github.com/user-attachments/assets/a3e4aad5-d4c8-4e45-96f0-51ed5c497e33" />  
 
<img width="1780" height="705" alt="service_masquerade_reverse_shell" src="https://github.com/user-attachments/assets/1ed46afc-098a-4152-bb5e-617944227bd9" />

---  

## Detection and Hunting

In Microsoft Defender for Endpoint, the attack chain leaves behind multiple high-signal artifacts.

### Timeline Observations

- At **8:59 PM**, `powershell.exe` spawned `sc.exe` with a command line that created the **Windows Update Service**.
- Immediately afterward, `services.exe` created the registry key `SYSTEM\ControlSet001\Services\Windows Update Service`, confirming service registration.
- At **9:39 PM**, another `powershell.exe` process launched `sc.exe` again, this time to start the service.
- Seconds later, `services.exe` spawned `updater.exe`.
- MDE flagged the activity as **Trojan:Win32/SuspGolang.AG**, catching the behavior despite the file being staged stealthily.
&nbsp;
<img width="1863" height="382" alt="device_timeline_sc_create_system_registry" src="https://github.com/user-attachments/assets/e8f78b1a-d725-41cd-a4e8-bc1cd5783709" />  

&nbsp;
<img width="1890" height="319" alt="starting_service_service_starts_updater_defender_detects" src="https://github.com/user-attachments/assets/d614ed0f-e2d1-4b16-b110-5b848e983266" />

---

### 🧠 Hunting with KQL

#### New Services (last 24h)
```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| sort by Timestamp desc
```

This query reveals the suspicious install path:
```
C:\ProgramData\Microsoft\Windows\updater.exe
```
&nbsp;
<img width="1654" height="570" alt="identifying_new_services_created_kql" src="https://github.com/user-attachments/assets/d69567f8-a6bc-4f6d-bc22-ad7866ea6b15" />


#### Services Installed Outside System32

For a more zoomed out approach, we can try to identify custom paths for services that exist outside of `C:\Windows\System32`. 
Although it's not uncommon for legitimate services to exist in other directories, it might be interesting to see what, if any, unique service paths there are.

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| where FolderPath !startswith "C:\\Windows\\System32"
| project Timestamp, DeviceName, FolderPath, InitiatingProcessCommandLine
```

&nbsp;
<img width="1682" height="565" alt="identifying_service_binary_paths_not_system32_kql" src="https://github.com/user-attachments/assets/a0bafbd4-aeae-4f07-899d-8430ceeeadd9" />


#### Service Execution Chain
```kql
DeviceProcessEvents
| where InitiatingProcessFileName == "services.exe"
| where FileName == "updater.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
```

This tied the `services.exe` execution directly to the callback binary, `updater.exe`.  
&nbsp;
<img width="1530" height="627" alt="confirming_service_exe_ran_updater_kql" src="https://github.com/user-attachments/assets/88ea3196-d2ba-4e52-9d9b-6ec48857591f" />

---  

## Network Visibility

To understand the binary's behavior beyond process execution, we pivoted to network telemetry.

Using this KQL query, we scoped outbound activity from `updater.exe` on the target host:

```kql
DeviceNetworkEvents
| where DeviceName == "ceo-laptop"
| where InitiatingProcessFileName == "updater.exe"
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, ReportId
```

This revealed outbound connections to the Sliver C2 listener hosted on `10.1.0.51`. Even without a domain or suspicious string in the command line, the binary established direct communication with a remote host.  
&nbsp;
<img width="1645" height="590" alt="evidence_outbound_connection_initiated_by_updater_kql" src="https://github.com/user-attachments/assets/ee2b3d35-658a-4078-b35c-7ab780f89098" />


Combined with process tree (`services.exe` → `updater.exe`) and non-standard binary path, this connection solidified the malicious chain.

---  

## Takeaways

This activity chain shows how easily a SYSTEM-level backdoor can blend in with built-in tooling and believable naming.

### Detection Ideas

- **Alert on new services** where:
  - The binary path is outside trusted locations
  - The initiating process is `powershell.exe`, `cmd.exe`, or a user context (rather than service account)
- **Hunt for service names** that impersonate legitimate Windows services (`Windows Update`, `Security Center`, etc.)
- **Monitor for outbound connections** from rarely seen or suspiciously named binaries like `updater.exe` to external IP addresses.

### Remediation Ideas

- Quarantine or delete the malicious binary (`updater.exe`)
- Remove the service:
  ```cmd
  sc.exe delete "Windows Update Service"
  ```
- Scope the environment for similar naming schemes and download paths
- Investigate for lateral movement or credential theft post-compromise
- Review Security logs for persistence attempts via other T1543.003 (service masquerade) attempts
