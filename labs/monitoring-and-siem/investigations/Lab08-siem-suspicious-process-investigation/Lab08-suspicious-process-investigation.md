# Lab 01 – SIEM Basics: Suspicious Process Investigation

## Overview
In this foundational SIEM lab, I practiced investigating an automatically triggered alert inside a security dashboard.  
The SIEM flagged a suspicious process execution (`customminer.exe`), requiring correlation with logs to determine the responsible user and host.  
The lab concluded by validating whether the detection was a **true positive** or **false positive**, mirroring incident investigation.

<p align="left">
  <img src="images/lab01-siem-foundational-figure.01-alert.png" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 1: Suspicious process in SIEM dashboard</em>
</p>

## Objectives
- Review SIEM alerts and pivot into underlying event data.  
- Identify the suspicious process (`customminer.exe`) that triggered the alert.  
- Attribute the event to a specific **user account** and **hostname**.  
- Compare the event to the SIEM detection rule that flagged it.  
- Assess whether the event should be classified as a **true positive**.  
- Document findings in a structured, analyst-style report.  

---

## Investigation Steps
1. Opened the SIEM dashboard and triggered suspicious activity.  
2. Observed the process flagged in the **Process Name panel**: `customminer.exe`.  
3. Drilled into the correlated event logs to identify the **responsible user account**.  
4. Confirmed the **hostname** of the suspect machine.  
5. Examined the detection rule against the suspicious process.  
6. Evaluated whether the event represented a **true positive** versus normal activity.  
7. Retrieved the lab flag to conclude the investigation.  

---

## Findings

- **Suspicious process:** `cudominer.exe`  
- **User account:** `Chris.fort`  
- **Hostname:** `HR_02`  
- **Rule match:** Matched SIEM detection for mining activity  
- **Classification:** **True Positive** – confirmed malicious crypto miner execution  

<p align="left">
  <img src="images/lab01-siem-foundational-figure.02-event-log.png" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 2 – Event Log Correlation for Suspicious Process</em>
</p>

The SIEM event logs display process creation activity from multiple hosts within the **cybertees.local** domain.  
Among the entries, the process `cudominer.exe` stands out as abnormal. Unlike standard processes such as `MicrosoftEdgeSH.exe`, `javaws.exe`, or `quicktime.exe`, the suspicious process was executed from a temporary directory:  

`C:\Users\Chris.Fort\temp\cudominer.exe`

## Detection Rule

The alert was triggered based on a predefined SIEM correlation rule.  
This rule monitors **process creation events** (`EventID 4688`) from `WindowsEventLogs` where the process name contains mining-related keywords (`miner` or `crypt`).  

<p align="left">
  <img src="images/lab01-siem-foundational-figure.03-rule.png" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 3 – SIEM Rule Used to Detect Potential CryptoMiner Activity</em>
</p>


## Key Takeaways
- SIEM alerts are **starting points**, not conclusions — analysts must pivot into logs for context.  
- Understanding **Windows Event IDs** is critical for accurate triage.  
- Even “basic” investigations involve correlating multiple artifacts (process, user, host).  
- Clear documentation of each step builds an audit trail and supports escalation.  

---

## Level
**Beginner / Foundational** – This lab was designed to practice SIEM fundamentals and build confidence before progressing into advanced log correlation, custom detection rules, and threat hunting scenarios.
