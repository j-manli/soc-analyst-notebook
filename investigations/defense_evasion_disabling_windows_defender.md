# Defense Evasion - Disabling or Modifying Windows Defender

**MITRE ATT&CK Reference:** [T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

Something I've seen in many threat reports is this priority to neutralize Microsoft Defender on the victim's machine. 
Whether it's adding a file path exclusion to allow their malware to run or shutting off antivirus completely, the goal is the same...to clear the way by turning off the alarms.

In this scenario, our attacker has local admin access and with that power, they proceed to disable Microsoft Defender.

The goal: quietly reduce detection before executing higher-risk actions like reconnaissance or memory dumping.

---

## Host Configuration

- **Target VM:** `CEO-LAPTOP` (Windows 10 with Microsoft Defender for Endpoint)
  - **IP:** `10.1.0.69`
  - **Admin Username:** `TrustMeBro`

---

## Execution

The attacker, logged in locally as the administrator (`TrustMeBro`), executed a series of PowerShell commands to weaken the host’s defenses prior to objectives.

### 1. Disable Real-Time Protection
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
This command was used to turn off Defender’s real-time monitoring, reducing the chance of payload interception or memory scan alerts.

### 2. Add Folder Exclusion
```powershell
Add-MpPreference -ExclusionPath "C:\ProgramData\Microsoft\Windows"
```
By excluding the ProgramData path, future binaries dropped there (like payloads or tools) will bypass local Defender scanning.

### 3. Attempt to Stop Defender Service
```powershell
sc.exe stop WinDefend
```
> Even with tamper protection disabled, this command failed with an `Access Denied` error, signaling that service-level protections remained enforced by the OS or endpoint policy.  

<img width="1125" height="445" alt="disable_defender_three_commands_PS_01" src="https://github.com/user-attachments/assets/d1294e6d-e280-4121-bdac-a91a4635568e" />  

---
## Detection and Hunting

Microsoft Defender flagged the tampering behavior in the Device Timeline but did not generate an alert. 
To investigate further, we can start with standard process-based queries, then pivot to the registry for confirmation.

### Device Timeline Observations

Two key events appeared in the Device Timeline during testing:

- `powershell.exe` executed a command to **disable real-time protection** using `Set-MpPreference -DisableRealtimeMonitoring $true`
- Shortly after, another PowerShell command to add a Defender exclusion triggered an **AMSI-based detection** for suspicious content.
  
Both actions *did* occurr, even though they weren't shown in the standard process or alert telemetry.  

<img width="1901" height="247" alt="exclusion_path_device_timeline_01" src="https://github.com/user-attachments/assets/2be8cd59-f180-4e04-9fe5-baed591b09d4" />

&nbsp;
<img width="1770" height="481" alt="disable_defender_device_timeline_01" src="https://github.com/user-attachments/assets/f5f15026-d3dd-41a3-a869-e1bc39467a25" />  


### Attempted Process-Based Detection (No Results)

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("Set-MpPreference", "DisableRealtimeMonitoring", "Add-MpPreference", "ExclusionPath")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

**Result:** No matching events were returned, despite the behavior being visible in the Device Timeline.
My guess is a possible delay in telemetry (time to detection) or a visibility limitation for certain PowerShell-based AMSI detections.

---

### Registry-Based Detection (Confirmed)

Pivoting to registry events, we can see high-confidence evidence of Defender tampering:

```kql
DeviceRegistryEvents
| where RegistryKey has "Microsoft\\Windows Defender\\Exclusions"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, ActionType, InitiatingProcessFileName
```

This revealed a registry change adding an suspicious exclusion for the RegistryValueName `C:\ProgramData\Microsoft\Windows`, along with the initiating process and timestamp.  


&nbsp;
<img width="1158" height="499" alt="exclusion_path_registry_event_kql" src="https://github.com/user-attachments/assets/7f182415-c201-4a21-ad54-7b73d1979f55" />  

---

## Takeaways

Tampering with Defender often precedes credential theft or malware staging. While some detections flagged the activity quietly, the lack of alerts shows how this technique can slip past default protections.

### Detection Recommendations

- Enable **PowerShell Script Block Logging** to increase visibility into command usage (was not available in this environment).
- Hunt for use of `Set-MpPreference` and `Add-MpPreference` in both process and registry contexts.
- Monitor for changes to Defender exclusion paths, especially involving non-standard or user-controlled locations.

### Remediation Actions

- Review and remove suspicious Defender exclusions.
- Investigate the initiating user account for further malicious activity.
- Re-enable Defender protections and validate the host’s security state:
  ```powershell
  Get-MpComputerStatus
  ```
