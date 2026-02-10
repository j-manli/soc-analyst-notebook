# Threat Hunt: Script Execution

> **Focus:** Stand-alone script execution via WScript and CScript  
> **Data:** Windows Event Logs (Sysmon)  
> **Tooling:** Event Viewer, Chainsaw, Sigma  

---

A recent macro-based initial access hunt surfaced a small but important blind spot in my own analysis. Sysmon recorded the download of a `.vbs` file, but the detection question I kept circling back to wasn’t about the macro itself, it was about execution.

In process trees, `wscript.exe` and `cscript.exe` show up often enough to feel familiar, yet unfamiliar enough to ignore. 
Once I started thinking about script execution as a detection surface, it became clear that understanding *how* Windows interprets and runs scripts (via `WScript.exe` and `CScript.exe`) is just as important as spotting the script artifact itself.

---

For example, when a user double-clicks a `.vbs`, what actually decides which host runs it?

I had been treating script execution as a single thing, but Windows actually makes a choice about which script host runs it. 
Seeing `wscript.exe` in the process tree (instead of `cscript.exe`) forced me to slow down and think about why. 
One is designed to run scripts with a GUI context, the other without, and that difference changes both how execution looks in the logs *and* how likely it is to involve user interaction. 

“Script execution” isn’t just *a script ran*. It’s **which host ran it, from where, and who launched the host**.

---

I was provided with event logs from a "compromised" system where a malicious stand-alone script had already executed. 
Rather than starting from an alert, the goal here was to work backward by understanding how the script was launched and identifying what evidence that execution left behind.

---

Taking a manual look at the Sysmon logs in Event Viewer, I filtered for process creation events (Event ID 1) and used `Find` to search for the term `script`. 
I wanted to see whether either `wscript.exe` or `cscript.exe` appeared as the initiating image.

One notably suspicious entry stood out:

- At `2024-04-01 16:41:12.856 UTC`, `wscript.exe` launched `downloader.js` from  
  `C:\ProgramData\downloader.js`

Just prior to that, I observed another relevant event:

- At `2024-04-01 16:40:00.740 UTC`, `notepad.exe` was used to open  
  `C:\ProgramData\downloader.js`

<insert image manual_check_script_1_notepad>
<insert image manual_check_script_1>
<img width="1106" height="521" alt="manual_check_script_1" src="https://github.com/user-attachments/assets/7a0c6364-4062-409c-ae02-4c730af4290f" /> 

![manual_check_script_1_notepad](https://github.com/user-attachments/assets/21919590-2b2d-4fd3-b2ab-8eebbb46c302)


---

> Something I learned here was that the `openwith.exe` process was used to initiate `wscript.exe`. From what I could dig up, `openwith.exe` is most commonly associated with the GUI interaction that appears when Windows is unsure how to interpret or present a file.
> This parent process is often absent when a script is executed via `cmd.exe`, `powershell.exe`, a scheduled task, a service, or other LOLBIN-driven execution paths.
> Seeing `openwith.exe` in the process tree gave me context that this execution path likely originated from user interaction rather than automation.

---

Based on this manual investigation, I modified a sample Sigma rule to capture script execution from user directories, shared writable locations such as `C:\ProgramData`, and an additional safety net for `C:\Windows\Temp`.

```yaml
title: Detecting Script Execution From User, Shared, and Temp Directories
id: e0b1d8d0-0000-0000-0000-000000000001
status: experimental
description: Detect execution of script files (js/jse/vbs/vbe/wsf/vba) launched by script hosts from user directories, shared writable directories (e.g., ProgramData, Temp).
author:
tags:
  - attack.execution
  - attack.t1059
  - sysmon
  - host
logsource:
  category: process_creation
  product: windows

detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
    CommandLine|re:
      - '.*\\Users\\.*\.js'
      - '.*\\Users\\.*\.jse'
      - '.*\\Users\\.*\.vba'
      - '.*\\Users\\.*\.vbe'
      - '.*\\Users\\.*\.vbs'
      - '.*\\Users\\.*\.wsf'

      - '.*\\ProgramData\\.*\.js'
      - '.*\\ProgramData\\.*\.jse'
      - '.*\\ProgramData\\.*\.vba'
      - '.*\\ProgramData\\.*\.vbe'
      - '.*\\ProgramData\\.*\.vbs'
      - '.*\\ProgramData\\.*\.wsf'

      - '.*\\Windows\\Temp\\.*\.js'
      - '.*\\Windows\\Temp\\.*\.jse'
      - '.*\\Windows\\Temp\\.*\.vba'
      - '.*\\Windows\\Temp\\.*\.vbe'
      - '.*\\Windows\\Temp\\.*\.vbs'
      - '.*\\Windows\\Temp\\.*\.wsf'

  condition: selection

falsepositives:
  - Administrative automation and legitimate scripts stored in ProgramData or Windows Temp (e.g., installers, IT scripts).
level: high
```

Although this rule is not exhaustive, writing it helped reinforce an important point: detection logic is as much about finding the indicator as it is about understanding the execution surface an attacker is likely to abuse. 

--- 

I then ran Chainsaw against the event logs using the updated Sigma rule. 

```cmd
.\chainsaw.exe hunt C:\Users\Administrator\Downloads\All-Files\Lab2\ -s .\myrules\script_execution.yml --mapping .\mappings\sigma-event-logs-all.yml
```

<img width="1518" height="305" alt="chainsaw_sigma_rule_script_execution" src="https://github.com/user-attachments/assets/d7afd058-abc3-4bb0-a474-924bba1c642a" /> 

Chainsaw successfully detected the suspicious script execution observed during manual review, validating my new Sigma rule. 

This workflow of combining manual log review with detection engineering has been a useful exercise. 
Starting with raw telemetry made it easier for me to reason out what actually happened, and translating that understanding into a Sigma rule helped me turn an observation into a repeatable detection. 

--- 

### Notes

- Reviewed Sysmon logs for script execution activity
- Extended detection logic to include user directories and shared writable locations such as `C:\ProgramData` and `C:\Windows\Temp`
- Validated the detection using `Chainsaw`
- Reinforced the importance of understanding script hosts (`wscript.exe`, `cscript.exe`) as part of execution analysis

