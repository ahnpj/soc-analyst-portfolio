# 🛡️ Labs

This repository contains a collection of hands-on cybersecurity labs I’ve built to practice **SIEM analysis, network traffic investigation, scanning/recon, and playbook documentation**.  
Each lab is designed to **increase in complexity and depth as the lab number goes up**. For example, `Lab01` focuses on introductory concepts, while `Lab02` and higher require more advanced investigation, correlation, and analysis skills.

<details>
<summary><strong>📂 Repository Structure</strong></summary>

```text
labs/
  siem/
    siem-basics/
      Lab01-suspicious-process-investigation/
    splunk/
      Lab01-splunk-vpn-log-analysis/
      Lab02-splunk-data-manipulation/
      Lab03-splunk-cyber-kill-chain-investigation/
  end-point-triage/
    powershell/
      Lab01-powershell-endpoint-triage-basics
    windows-cli
      Lab01-windows-cli-endpoint-triage-basics
  network-analysis/
    tcpdump/
      Lab01-tcpdump-packet-capture-and-filtering
    wireshark/
      Lab01-wireshark-packet-analysis-and-filtering
  playbooks/
```
</details>

---


## 🔎 Lab Highlights

### What’s Inside

<h3>Labs → (labs/)</h3> Hands-on labs where I dig into SIEM data, practice log analysis, and build investigation workflows. 
Currently includes:
<br/><br/>

<details>
<summary><b>SIEM</b></summary>

> <details>
> <summary>SIEM Basics</summary>
>
> - <a href="labs/siem/siem-basics/Lab01-intro-to-siem/Lab01-suspicious-process-investigation.md">Lab01 – Suspicious Process Investigation</a><br/>
>   <em>Level: Beginner</em> → Investigating abnormal process activity in logs, understanding correlation rules.
>
> </details>

> <details>
> <summary>Splunk</summary>
>
> - <a href="labs/siem/splunk/Lab01-splunk-vpn-log-analysis/Lab01-splunk-vpn-log-analysis-basics.md">Lab01 – Splunk VPN Log Analysis</a><br/>
>   <em>Level: Beginner</em> → Detecting unusual VPN login activity, analyzing login patterns by user and source country, and identifying suspicious travel or account compromise.
> - <a href="labs/siem/splunk/Lab02-splunk-data-manipulation/Lab02-splunk-data-manipulation-basics.md">Lab02 – Splunk Data Manipulation</a><br/>
>   <em>Level: Beginner</em> → Understanding how Splunk processes, parses, and manipulates machine-generated data using configuration files (inputs.conf, props.conf, transforms.conf) to ensure accurate field extraction and reliable analysis for security investigations.
>- <a href="labs/siem/splunk/Lab03-splunk-cyber-kill-chain-investigation/Lab03-splunk-cyber-kill-chain-investigation.md">Lab03 – Splunk Cyber Kill Chain Investigation</a><br/>
>   <em>Level: Intermediate</em> → Performing a complete investigation of a simulated web server defacement incident by tracing attacker activity through each phase of the Cyber Kill Chain. This includes identifying reconnaissance behavior, analyzing exploit attempts, verifying malware installation, and uncovering command-and-control (C2) communication using Splunk queries and network log data. The lab emphasizes the analytical workflow of a SOC analyst — from detecting the initial compromise to mapping adversary TTPs against frameworks like MITRE ATT&CK and NIST SP 800-61. Learners will gain hands-on experience correlating IDS alerts, HTTP traffic, and DNS records to produce actionable intelligence and document incident findings in a professional, report-ready format.
> </details>

</details>



<details>
<summary><b>Network Analysis</b></summary>

> <details>
> <summary>Tcpdump</summary>
>
> - <a href="labs/network-analysis/tcpdump/Lab01-tcpdump-packet-capture-and-filtering/Lab01-tcpdump-packet-capture-and-filtering.md">Lab01 – Tcpdump Packet Capture and Filtering</a><br/>
>   <em>Level: Beginner</em> → Capturing and analyzing network traffic using tcpdump to understand packet structures, apply filters, and identify key fields for basic network troubleshooting and security monitoring.
>
> </details>

> <details>
> <summary>Wireshark</summary>
>
> - <a href="labs/network-analysis/wireshark/Lab01-wireshark-packet-analysis-and-filtering/Lab01-wireshark-packet-analysis-and-filtering.md">Lab01 – Wireshark Packet Analysis and Filtering</a><br/>
>   <em>Level: Beginner</em> → Captured and analyzed network traffic using Wireshark to examine packet structures, apply filters, and identify key fields useful for basic network troubleshooting and security monitoring.
>
> </details>

</details>



<details>
<summary><b>Endpoint Analysis & Investigation</b></summary>

> <details>
> <summary>Windows CMD/CLI</summary>
>
> - <a href="labs/endpoint-triage/windows-cli/Lab01-windows-cli-endpoint-triage-basics/Lab01-windows-cli-endpoint-triage-basics.md">Lab01 – Windows CMD/CLI Basics</a><br/>
>   <em>Level: Beginner</em> → Using Windows command-line tools to investigate processes, review system information, and identify suspicious activity.
>
> </details>

> <details>
> <summary>PowerShell</summary>
>
> - <a href="labs/endpoint-triage/powershell/Lab01-powershell-endpoint-triage-basics/Lab01-powershell-endpoint-triage-basics.md">Lab01 – PowerShell Basics</a><br/>
>   <em>Level: Beginner</em> → Leveraging PowerShell commands to collect endpoint data, filter logs, and detect potential anomalies in process execution.
>
> </details>

</details>

---

## 🎯 Skills Demonstrated
- **Progression of difficulty**: Labs are numbered so complexity builds over time (Lab01 = fundamentals → Lab02+ = deeper, real-world investigations).  
- SIEM log analysis (Splunk, ELK concepts)  
- Threat detection & hunting (VPN anomalies, suspicious processes)  
- Network traffic analysis fundamentals  
- Documentation of repeatable **SOC playbooks**  
- Clear technical communication for both technical and non-technical audiences  

---

## 🚀 How to Use
- Browse the `labs/` folder to view individual exercises.  
- Each lab includes:
  - Step-by-step procedure  
  - Screenshots (`images/`)  
  - Findings & conclusions  
- To understand skill progression:
  - **Start with lower-numbered labs (Lab01)** for fundamentals.  
  - **Move to higher-numbered labs (Lab02, Lab03, …)** to see more advanced detection and analysis scenarios.  

---

## 📌 Next Steps
- Adding **Wireshark labs** (packet capture & analysis).  
- Expanding **Nmap labs** for recon & vulnerability scanning.  
- More advanced SOC scenarios (alert triage, correlation rules, incident response).  

---

## 💡 About
This repo is part of my ongoing transition into cybersecurity, showcasing practical hands-on experience that aligns with **SOC analyst / blue team roles**.  
By structuring labs in increasing difficulty, I aim to show not only **technical skills**, but also **progression and growth** in real-world SOC analyst workflows.
